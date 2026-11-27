//! What `raeva sync`, `--frozen` and the commands that check freshness
//! compare against raeva.lock: the platforms it records, the reactor's own
//! versions, the `-D` and `-P` options, SNAPSHOT builds and the store.

use std::fs;

use serde_json::Value;

use crate::common::{assert_status, assert_success, envelope, run_raeva};
use crate::offline_project::Project;

fn host() -> String {
    rv_lock::Platform::current().expect("platform").to_string()
}

/// A supported platform other than this machine's.
fn other() -> &'static str {
    if host() == "linux-x86_64" {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    }
}

fn locked_platforms(project: &Project) -> Vec<String> {
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).expect("read lock");
    (lock.platforms.iter())
        .map(|entry| entry.platform.to_string())
        .collect()
}

fn text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_lock_is_checked_and_rewritten_for_exactly_its_recorded_platforms() {
    let (host, other) = (host(), other());
    let project = Project::synced();
    assert_eq!(locked_platforms(&project), [host.as_str()], "no lock yet");

    let lock_path = project.root().join("raeva.lock");
    fs::remove_file(&lock_path).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", other]),
        "lock another platform",
    );
    let written = fs::read(&lock_path).unwrap();
    for args in [
        &["sync", "--offline"][..],
        &["sync"],
        &["sync", "--frozen", "--platforms", other],
        &["sync", "--frozen", "--offline", "--platforms", other],
    ] {
        let output = project.raeva(args);
        assert_success(&output, &format!("{args:?}"));
        assert!(
            text(&output).contains(&format!("for {other} in ")),
            "{args:?} names the checked platform: {}",
            text(&output)
        );
        assert_eq!(fs::read(&lock_path).unwrap(), written, "{args:?}");
    }
    let frozen = envelope(&project.raeva(&[
        "--json",
        "sync",
        "--frozen",
        "--offline",
        "--platforms",
        other,
    ]));
    assert_eq!(frozen["data"]["platforms"], serde_json::json!([other]));

    // The gate refuses a lock this machine cannot build from unless
    // `--platforms` names what to check.
    for args in [
        &["sync", "--frozen"][..],
        &["sync", "--frozen", "--offline"],
    ] {
        let mut json = vec!["--json"];
        json.extend(args);
        let output = project.raeva(&json);
        assert_status(&output, 3, &format!("{args:?} without a host section"));
        let failed = envelope(&output);
        assert_eq!(failed["code"], "PLATFORM_MISSING", "{failed}");
        let hints = failed["hints"].to_string();
        assert!(
            hints.contains(&format!("raeva sync --platforms {host}")),
            "{failed}"
        );
        assert!(
            hints.contains(&format!("raeva sync --frozen --platforms {other}")),
            "{failed}"
        );
        assert_eq!(fs::read(&lock_path).unwrap(), written, "{args:?}");
    }

    let checksums = project.raeva(&["export-checksums", "--offline"]);
    assert_success(&checksums, "export-checksums uses the recorded platform");
    assert!(
        text(&checksums).contains(&format!("raeva.lock is up to date for {other}")),
        "{}",
        text(&checksums)
    );

    // An export feeds a Maven build on this machine: it needs this
    // platform's own section, and never takes another's.
    let export = project.raeva(&["--json", "export-m2", "--offline", "--dry-run"]);
    assert_status(&export, 3, "export-m2 without a host section");
    let export = envelope(&export);
    assert_eq!(export["code"], "PLATFORM_MISSING", "{export}");
    let hints = export["hints"].to_string();
    assert!(
        hints.contains(&format!("raeva sync --platforms {host}")),
        "{hints}"
    );

    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", &host]),
        "add the host section",
    );
    let mut both = vec![host.clone(), other.to_string()];
    both.sort();
    let mut locked = locked_platforms(&project);
    locked.sort();
    assert_eq!(locked, both, "--platforms keeps the recorded platform");
    assert_success(
        &project.raeva(&["export-m2", "--offline", "--dry-run"]),
        "export-m2 with a host section",
    );
}

#[test]
fn lock_jdks_cross_the_recorded_platforms() {
    let other = other();
    let project = Project::synced();
    fs::write(
        project.root().join("raeva.toml"),
        "[lock]\njdks = [\"17\", \"21\"]\n",
    )
    .unwrap();
    let lock_path = project.root().join("raeva.lock");
    fs::remove_file(&lock_path).unwrap();
    let env = [("JAVA_VERSION", "21")];
    assert_success(
        &project.raeva_with(&env, &["sync", "--offline", "--platforms", other]),
        "lock another platform for two JDKs",
    );
    let expected = [format!("{other} (JDK 17)"), format!("{other} (JDK 21)")];
    assert_eq!(locked_platforms(&project), expected);
    for args in [
        &["sync", "--offline"][..],
        &["sync", "--frozen", "--offline", "--platforms", other],
    ] {
        let output = project.raeva_with(&env, args);
        assert_success(&output, &format!("{args:?}"));
        assert!(
            text(&output).contains(&format!("for {} and {} in ", expected[0], expected[1])),
            "{}",
            text(&output)
        );
        assert_eq!(locked_platforms(&project), expected, "{args:?}");
    }
}

#[test]
fn offline_frozen_counts_the_pinned_files_the_store_lacks() {
    let project = Project::synced();
    let checked = project.raeva(&["sync", "--frozen", "--offline"]);
    assert_success(&checked, "offline frozen with a full store");
    assert!(
        text(&checked).contains(
            "raeva.lock is up to date and its 2 pinned files are in the store \
             ('raeva lock verify' hashes them)"
        ),
        "{}",
        text(&checked)
    );

    // The check resolves again, and offline it reads the project's file
    // repository, which fills an empty store; without the repository the
    // resolution names what it cannot read.
    let empty = tempfile::TempDir::new().expect("empty home");
    let env = [("RAEVA_HOME", empty.path().to_str().expect("utf-8 path"))];
    let output = project.raeva_with(&env, &["--json", "sync", "--frozen", "--offline"]);
    assert_success(&output, "offline frozen with an empty store");
    let repository = project.root().join("repository");
    let moved = project.root().with_file_name("repository");
    fs::rename(&repository, &moved).unwrap();
    let emptier = tempfile::TempDir::new().expect("another empty home");
    let env = [("RAEVA_HOME", emptier.path().to_str().expect("utf-8 path"))];
    let output = project.raeva_with(&env, &["--json", "sync", "--frozen", "--offline"]);
    assert_status(
        &output,
        5,
        "offline frozen without the store or the repository",
    );
    let failed = envelope(&output);
    assert_eq!(failed["code"], "OFFLINE_NOT_CACHED", "{failed}");
    assert!(
        failed["error"]
            .as_str()
            .unwrap()
            .contains("org/test/lib/1.0/lib-1.0.pom not available in local cache"),
        "{failed}"
    );
    fs::rename(&moved, &repository).unwrap();

    // A stale lock reports the drift, not the store.
    let pom = project.root().join("pom.xml");
    let original = fs::read_to_string(&pom).unwrap();
    fs::write(
        &pom,
        original.replace(
            "<version>1.0</version>",
            "<version>1.0</version><scope>test</scope>",
        ),
    )
    .unwrap();
    let stale = project.raeva_with(&env, &["--json", "sync", "--frozen", "--offline"]);
    assert_status(&stale, 7, "offline frozen with a stale lock");
    let stale = envelope(&stale);
    assert!(
        !stale["error"].as_str().unwrap().contains("the store lacks"),
        "{stale}"
    );
}

/// Offline, a plain sync that keeps the lock restores it from the store and
/// the local repositories, so an empty home can build offline after it.
#[test]
fn an_offline_sync_that_keeps_the_lock_fills_the_store_from_local_repositories() {
    let project = Project::synced();
    let empty = tempfile::TempDir::new().expect("empty home");
    let env = [("RAEVA_HOME", empty.path().to_str().expect("utf-8 path"))];
    let lock = fs::read(project.root().join("raeva.lock")).unwrap();
    assert_success(
        &project.raeva_with(&env, &["sync", "--offline"]),
        "plain offline sync into an empty home",
    );
    assert_eq!(fs::read(project.root().join("raeva.lock")).unwrap(), lock);
    assert_success(
        &project.raeva_with(&env, &["sync", "--frozen", "--offline"]),
        "the store holds every pinned file",
    );
}

const REACTOR_ROOT: &str = r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>2.0</version>
  <packaging>pom</packaging>
  <modules><module>bom</module><module>a</module><module>b</module></modules>
</project>
"#;

const REACTOR_BOM: &str = r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>org.test</groupId><artifactId>root</artifactId><version>2.0</version></parent>
  <artifactId>bom</artifactId>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/../repository/</url></repository>
  </repositories><packaging>pom</packaging>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.test</groupId><artifactId>a</artifactId><version>${project.version}</version></dependency>
    <dependency><groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version></dependency>
  </dependencies></dependencyManagement>
</project>
"#;

const REACTOR_A: &str = r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>org.test</groupId><artifactId>root</artifactId><version>2.0</version></parent>
  <artifactId>a</artifactId>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/../repository/</url></repository>
  </repositories>
  <dependencies><dependency>
    <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>
  </dependency></dependencies>
</project>
"#;

const REACTOR_B: &str = r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>org.test</groupId><artifactId>root</artifactId><version>2.0</version></parent>
  <artifactId>b</artifactId>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/../repository/</url></repository>
  </repositories>
  <dependencyManagement><dependencies><dependency>
    <groupId>org.test</groupId><artifactId>bom</artifactId><version>${project.version}</version>
    <type>pom</type><scope>import</scope>
  </dependency></dependencies></dependencyManagement>
  <dependencies><dependency>
    <groupId>org.test</groupId><artifactId>a</artifactId>
  </dependency></dependencies>
</project>
"#;

fn reactor(extra_a_dependency: &str, extra_files: &[(String, String)]) -> Project {
    let a = REACTOR_A.replace(
        "</dependencies>",
        &format!("{extra_a_dependency}</dependencies>"),
    );
    let mut files = vec![
        ("pom.xml", REACTOR_ROOT),
        ("bom/pom.xml", REACTOR_BOM),
        ("a/pom.xml", a.as_str()),
        ("b/pom.xml", REACTOR_B),
    ];
    files.extend(
        extra_files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str())),
    );
    Project::synced_with(&files)
}

/// `org.test:ext` at each of `versions`, published in the project's
/// repository.
fn ext_releases(versions: &[&str]) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for version in versions {
        let dir = format!("repository/org/test/ext/{version}");
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>ext</artifactId><version>{version}</version></project>"
        );
        let jar = format!("ext {version} jar");
        for (name, text) in [
            (format!("ext-{version}.pom"), pom),
            (format!("ext-{version}.jar"), jar),
        ] {
            files.push((
                format!("{dir}/{name}.sha256"),
                crate::common::sha256_hex(text.as_bytes()),
            ));
            files.push((format!("{dir}/{name}"), text));
        }
    }
    files
}

/// What `mvn versions:set -DnewVersion=2.1` changes: the root's version and
/// every child's parent version.
fn set_reactor_version(project: &Project) {
    for path in ["pom.xml", "bom/pom.xml", "a/pom.xml", "b/pom.xml"] {
        let path = project.root().join(path);
        let text = fs::read_to_string(&path).unwrap();
        let bumped = text.replace(
            "<artifactId>root</artifactId><version>2.0</version>",
            "<artifactId>root</artifactId><version>2.1</version>",
        );
        assert_ne!(text, bumped, "{}", path.display());
        fs::write(path, bumped).unwrap();
    }
}

fn module_gavs(project: &Project) -> Vec<String> {
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).expect("read lock");
    (lock.platforms[0].modules.iter())
        .map(|module| module.gav.to_string())
        .collect()
}

#[test]
fn frozen_accepts_a_bump_of_the_reactors_own_versions() {
    let project = reactor("", &[]);
    let lock_path = project.root().join("raeva.lock");
    let written = fs::read(&lock_path).unwrap();
    assert!(
        String::from_utf8_lossy(&written).contains("org.test:a:2.0"),
        "b depends on a through the reactor BOM"
    );
    set_reactor_version(&project);

    for args in [
        &["sync", "--frozen"][..],
        &["sync", "--frozen", "--offline"],
        &["export-m2", "--offline", "--dry-run"],
        &["export-checksums", "--offline"],
    ] {
        let output = project.raeva(args);
        assert_success(&output, &format!("{args:?}"));
        assert_eq!(fs::read(&lock_path).unwrap(), written, "{args:?}");
    }

    // Reports name the modules as the POMs do now.
    let sbom = project.raeva(&["sbom", "--offline"]);
    assert_success(&sbom, "sbom after the bump");
    let sbom: Value = serde_json::from_slice(&sbom.stdout).expect("CycloneDX JSON");
    assert_eq!(sbom["metadata"]["component"]["version"], "2.1", "{sbom}");
    let sbom = sbom.to_string();
    assert!(
        sbom.contains("pkg:maven/org.test/a@2.1") && !sbom.contains("@2.0"),
        "{sbom}"
    );
    // vuln names modules by path and queries only external coordinates,
    // so its freshness check is what the bump could break.
    let (osv_url, _osv) = crate::common::spawn_osv(200, r#"{"results":[{"vulns":[]}]}"#);
    let vuln = project.raeva_with(&[("RAEVA_OSV_BASE_URL", &osv_url)], &["vuln"]);
    assert_success(&vuln, "vuln after the bump");
    assert_eq!(fs::read(&lock_path).unwrap(), written, "vuln");

    let synced = project.raeva(&["sync", "--offline"]);
    assert_success(&synced, "plain sync records the bump");
    assert_eq!(
        module_gavs(&project),
        [
            "org.test:a:2.1",
            "org.test:b:2.1",
            "org.test:bom:2.1",
            "org.test:root:2.1"
        ]
    );
    let locked = fs::read_to_string(&lock_path).unwrap();
    assert!(!locked.contains(":2.0"), "{locked}");
    assert!(locked.contains("org.test:lib:1.0"), "{locked}");
}

#[test]
fn frozen_fails_when_the_reactor_version_reaches_an_external_coordinate() {
    let project = reactor(
        "<dependency><groupId>org.test</groupId><artifactId>ext</artifactId>\
         <version>${project.version}</version></dependency>",
        &ext_releases(&["2.0", "2.1"]),
    );
    set_reactor_version(&project);
    let output = project.raeva(&["--json", "sync", "--frozen", "--offline"]);
    assert_status(&output, 7, "an external coordinate follows the bump");
    let failed = envelope(&output);
    assert_eq!(failed["code"], "LOCKFILE_MISMATCH", "{failed}");
    assert!(
        failed["error"].as_str().unwrap().contains("ext"),
        "{failed}"
    );
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=torutofu",
            "-c",
            "user.email=285838596+torutofu@users.noreply.github.com",
        ])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdout(std::process::Stdio::null())
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?}");
}

#[test]
fn a_conflicted_lock_is_regenerated_for_its_platforms_against_git_head() {
    let (host, other) = (host(), other());
    let project = Project::synced();
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    fs::remove_file(&lock_path).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", other]),
        "lock another platform",
    );
    git(&root, &["init", "-q"]);
    git(&root, &["add", "pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-q", "-m", "lock"]);

    // Their side adds this machine's platform and a pin no resolution gives.
    let ours = fs::read_to_string(&lock_path).unwrap();
    let theirs = ours
        .replace(&format!("\"{other}\""), &format!("\"{host}\""))
        .replace("org.test:lib:1.0", "org.test:lib:9.9");
    fs::write(
        &lock_path,
        format!("<<<<<<< HEAD\n{ours}=======\n{theirs}>>>>>>> theirs\n"),
    )
    .unwrap();
    let pom = root.join("pom.xml");
    let original = fs::read_to_string(&pom).unwrap();
    fs::write(
        &pom,
        original.replace(
            "<version>1.0</version>",
            "<version>1.0</version><scope>test</scope>",
        ),
    )
    .unwrap();

    let output = project.raeva(&["sync", "--offline"]);
    assert_success(&output, "regenerate the conflicted lock");
    let mut both = [host.clone(), other.to_string()];
    both.sort();
    let shown = text(&output);
    assert!(
        shown.contains(&format!(
            "keeping its platforms {} and {}",
            both[0], both[1]
        )) && shown.contains("the changes listed are against raeva.lock at git HEAD")
            && shown.contains("scope compile -> test"),
        "{shown}"
    );
    let mut locked = locked_platforms(&project);
    locked.sort();
    assert_eq!(locked, both);
    let regenerated = fs::read(&lock_path).unwrap();
    assert!(!String::from_utf8_lossy(&regenerated).contains("9.9"));

    // The same lock as a sync from nothing: no pin came from the conflict.
    fs::remove_file(&lock_path).unwrap();
    let list = both.join(",");
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", &list]),
        "sync from nothing",
    );
    assert_eq!(fs::read(&lock_path).unwrap(), regenerated);

    // A text with no pins to read and no lock at HEAD starts again only
    // once it is deleted or under --update. It has no conflict to resolve.
    fs::remove_dir_all(root.join(".git")).unwrap();
    fs::write(&lock_path, "not a lock\n").unwrap();
    let output = project.raeva(&["sync", "--offline"]);
    assert_status(&output, 3, "regenerate without git");
    assert!(
        text(&output).contains("a sync cannot keep its pins, since its rows do not read")
            && text(&output).contains(
                "Run 'raeva sync --update' to lock the bytes the repositories serve now, or \
                 delete raeva.lock to start again without its pins"
            )
            && !text(&output).contains("conflict")
            && text(&output).matches("line 1, column").count() == 1,
        "{}",
        text(&output)
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), "not a lock\n");
    let output = project.raeva(&["sync", "--offline", "--update"]);
    assert_success(&output, "regenerate under --update");
    assert!(
        text(&output).contains(
            "it names no platform this raeva supports; keeping none of its pins, as --update \
             asks; git has no readable raeva.lock at HEAD"
        ),
        "{}",
        text(&output)
    );
    assert_eq!(locked_platforms(&project), [host]);
}

/// A symlinked raeva.lock is read through the link, and a sync that would
/// rewrite it refuses and leaves both the link and the file it names.
#[cfg(unix)]
#[test]
fn a_sync_does_not_write_through_a_symlinked_lock() {
    let project = Project::synced();
    let root = project.root();
    let (lock_path, shared) = (root.join("raeva.lock"), root.join("shared.lock"));
    fs::rename(&lock_path, &shared).unwrap();
    std::os::unix::fs::symlink("shared.lock", &lock_path).unwrap();
    let locked = fs::read(&shared).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "reuse the linked lock",
    );
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen through the link",
    );
    let pom = root.join("pom.xml");
    let original = fs::read_to_string(&pom).unwrap();
    fs::write(
        &pom,
        original.replace(
            "<version>1.0</version>",
            "<version>1.0</version><scope>test</scope>",
        ),
    )
    .unwrap();
    let output = project.raeva(&["sync", "--offline"]);
    assert_status(&output, 1, "rewrite the linked lock");
    assert!(
        text(&output).contains("it is a symbolic link, which raeva does not write through"),
        "{}",
        text(&output)
    );
    assert!(fs::symlink_metadata(&lock_path).unwrap().is_symlink());
    assert_eq!(fs::read(&shared).unwrap(), locked);
}

#[test]
fn frozen_on_another_machine_names_the_options_added_and_removed() {
    let project = Project::synced();
    let pom = fs::read_to_string(project.root().join("pom.xml")).unwrap().replace("</project>", "<profiles><profile><id>flag</id><activation><property><name>lib.flag</name></property></activation><dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></profile></profiles></project>");
    fs::write(project.root().join("pom.xml"), pom).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "-Dlib.flag=secret-value", "-Pci,!dev"]),
        "sync with options",
    );
    let locked = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
    assert!(
        locked.contains("command_line = [\n    \"-Dlib.flag\",\n    \"-P!dev\",\n    \"-Pci\",\n]")
            && !locked.contains("secret-value"),
        "{locked}"
    );

    // Diagnostics use only the names recorded in the lock.
    let elsewhere = tempfile::TempDir::new().expect("other home");
    let env = [("RAEVA_HOME", elsewhere.path().to_str().expect("utf-8 path"))];
    let frozen = |options: &[&str]| {
        let mut args = vec!["--json", "sync", "--frozen"];
        args.extend_from_slice(options);
        project.raeva_with(&env, &args)
    };
    for (options, expected) in [
        (
            &[][..],
            "raeva.lock was written with -Dlib.flag, -P!dev and -Pci, which are not set here",
        ),
        (
            &["-Dlib.flag=other", "-Pci,!dev", "-DskipTests"],
            "the configuration changed since raeva.lock was written",
        ),
    ] {
        let output = frozen(options);
        assert_status(&output, 7, &format!("{options:?}"));
        let error = envelope(&output)["error"].as_str().unwrap().to_string();
        assert!(error.contains(expected), "{options:?}: {error}");
    }
    // The names match, so only the hash can tell the value changed.
    let output = frozen(&["-Dlib.flag=other", "-Pci,!dev"]);
    assert_status(&output, 7, "another value");
    assert!(
        !envelope(&output)["error"]
            .as_str()
            .unwrap()
            .contains("set here"),
        "{}",
        text(&output)
    );
    assert_success(
        &frozen(&["-Dlib.flag=secret-value", "-Pci,!dev"]),
        "the same options",
    );
}

/// `raeva sync` without `-C` in a module directory refuses to write a second
/// raeva.lock, naming the reactor root; `-C .` or a raeva.toml there locks the
/// module on its own.
#[test]
fn sync_in_a_module_directory_names_the_reactor() {
    let temp = tempfile::TempDir::new().expect("root");
    // A space and an apostrophe, which the suggested -C path quotes.
    let root = temp.path().join("it's a project");
    fs::create_dir_all(&root).expect("mkdir root");
    let home = tempfile::TempDir::new().expect("home");
    let pom = |artifact: &str, rest: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version>\
             <packaging>pom</packaging>{rest}</project>"
        )
    };
    // `modules/` has no pom.xml: the root lists `modules/io` itself, with
    // the separator reactor discovery accepts on every host.
    let module = root.as_path().join("modules/io");
    fs::create_dir_all(&module).expect("mkdir");
    fs::write(
        root.as_path().join("pom.xml"),
        pom("root", "<modules><module> modules\\io </module></modules>"),
    )
    .expect("root pom");
    fs::write(module.join("pom.xml"), pom("io", "")).expect("module pom");
    let raeva = |args: &[&str]| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_raeva"));
        command
            .env("RAEVA_HOME", home.path())
            .env("HOME", home.path());
        crate::common::isolate_maven_user_home(&mut command, home.path(), "");
        (command.current_dir(&module).args(args).output()).expect("run raeva")
    };
    let sync = |args: &[&str]| raeva(&[args, &["sync", "--offline"]].concat());
    let refused = sync(&[]);
    assert_status(&refused, 2, "sync in a module");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    let root_path = dunce::canonicalize(&root).expect("canonical root");
    let quoted = if cfg!(windows) {
        format!("'{}'", root_path.display().to_string().replace('\'', "''"))
    } else {
        format!(
            "'{}'",
            root_path.display().to_string().replace('\'', "'\\''")
        )
    };
    assert!(
        stderr.contains(&format!("raeva -C {quoted} sync")),
        "{stderr}"
    );
    assert!(!module.join("raeva.lock").exists());
    // A command that reads the lock points at the reactor's, not at sync.
    for command in ["tree", "vuln"] {
        let read = raeva(&[command]);
        let stderr = String::from_utf8_lossy(&read.stderr);
        assert!(
            stderr.contains(&format!("covers every module: add -C {quoted})")),
            "{command}: {stderr}"
        );
        assert!(!stderr.contains("Run 'raeva sync'"), "{command}: {stderr}");
    }
    let tree = raeva(&["-C", ".", "tree"]);
    let stderr = String::from_utf8_lossy(&tree.stderr);
    assert!(stderr.contains("Run 'raeva sync' to create it"), "{stderr}");
    assert_success(&sync(&["-C", "."]), "-C .");
    assert!(module.join("raeva.lock").exists());
    fs::remove_file(module.join("raeva.lock")).expect("remove lock");
    // A profile, even one active by default, and a property may be switched
    // off or overridden from outside the POM, so they do not refuse.
    for modules in [
        "<profiles><profile><id>all</id><activation><activeByDefault>true\
         </activeByDefault></activation><modules><module>modules/io</module></modules>\
         </profile></profiles>",
        "<modules><module>${dir}/io</module></modules><properties><dir>modules</dir>\
         </properties>",
    ] {
        fs::write(root.as_path().join("pom.xml"), pom("root", modules)).expect("root pom");
        assert_success(&sync(&[]), modules);
        fs::remove_file(module.join("raeva.lock")).expect("remove lock");
    }
    let literal = pom("root", "<modules><module>modules/io</module></modules>");
    fs::write(root.as_path().join("pom.xml"), literal).expect("root pom");
    assert_status(&sync(&[]), 2, "literal entry again");
    fs::write(module.join("raeva.toml"), "").expect("raeva.toml");
    assert_success(&sync(&[]), "raeva.toml");
}

/// The refusal follows a module entry that names an aggregator's POM file
/// under another name: the root lists `mid/agg.xml`, which lists the module.
/// A pom.xml beside a module file the root lists is no module, and locks on
/// its own.
#[test]
fn sync_in_a_module_directory_follows_a_named_module_file() {
    let temp = tempfile::TempDir::new().expect("root");
    let root = dunce::canonicalize(temp.path()).expect("canonical root");
    let home = tempfile::TempDir::new().expect("home");
    let pom = |artifact: &str, rest: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version>\
             <packaging>pom</packaging>{rest}</project>"
        )
    };
    let leaf = root.join("mid/leaf");
    fs::create_dir_all(&leaf).expect("mkdir");
    fs::write(leaf.join("pom.xml"), pom("leaf", "")).expect("leaf pom");
    fs::write(
        root.join("mid/agg.xml"),
        pom("mid", "<modules><module>leaf</module></modules>"),
    )
    .expect("aggregator");
    let raeva = |dir: &std::path::Path| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_raeva"));
        command
            .env("RAEVA_HOME", home.path())
            .env("HOME", home.path());
        crate::common::isolate_maven_user_home(&mut command, home.path(), "");
        let command = command.current_dir(dir).args(["sync", "--offline"]);
        command.output().expect("run raeva")
    };
    let root_pom = |modules: &str| {
        fs::write(
            root.join("pom.xml"),
            pom("root", &format!("<modules>{modules}</modules>")),
        )
        .expect("root pom")
    };
    root_pom("<module>mid/agg.xml</module>");
    let refused = raeva(&leaf);
    assert_status(&refused, 2, "sync in a module of a named aggregator");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("is a module of the Maven project in"),
        "{stderr}"
    );
    assert!(!leaf.join("raeva.lock").exists());
    fs::write(leaf.join("custom.xml"), pom("custom", "")).expect("custom pom");
    root_pom("<module>mid/leaf/custom.xml</module>");
    assert_success(&raeva(&leaf), "a pom.xml beside a listed module file");
    assert!(leaf.join("raeva.lock").exists());
}

/// A project depending on `libs` libraries that a stub central serves with
/// `.sha256` sidecars. The server stops when dropped.
fn stub_libraries(libs: usize) -> (rv_test_support::http::StubServer, tempfile::TempDir) {
    let mut files = std::collections::HashMap::from([(
        "/org/example/parent/1/parent-1.pom".to_string(),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>\
         <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
         </project>"
            .to_string(),
    )]);
    let mut dependencies = String::new();
    for lib in (0..libs).map(|n| format!("lib{n}")) {
        files.insert(
            format!("/org/example/{lib}/1/{lib}-1.pom"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.example\
                 </groupId><artifactId>parent</artifactId><version>1</version></parent>\
                 <artifactId>{lib}</artifactId></project>"
            ),
        );
        files.insert(
            format!("/org/example/{lib}/1/{lib}-1.jar"),
            format!("{lib} jar"),
        );
        dependencies.push_str(&format!(
            "<dependency><groupId>org.example</groupId><artifactId>{lib}</artifactId>\
             <version>1</version></dependency>"
        ));
    }
    let server = crate::common::sha256_repository(files);
    let project = tempfile::TempDir::new().unwrap();
    crate::common::write_repo_toml(
        project.path(),
        "central",
        &format!("http://{}/", server.addr()),
    );
    fs::write(
        project.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
             <artifactId>app</artifactId><version>1</version><dependencies>{dependencies}\
             </dependencies></project>"
        ),
    )
    .unwrap();
    (server, project)
}

/// Overwrites `len` bytes of the database file at `path` from `offset`, or
/// to its end for `None`.
fn damage(path: &std::path::Path, offset: u64, len: Option<u64>) {
    use std::io::{Seek, SeekFrom, Write};
    // A run can exit with its writes still in the WAL, as durable there;
    // move them into the file the damage is for.
    let busy: i64 = rusqlite::Connection::open(path)
        .unwrap()
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .unwrap();
    assert_eq!(busy, 0, "{}", path.display());
    let mut file = fs::File::options().write(true).open(path).unwrap();
    let size = file.metadata().unwrap().len();
    assert!(size > offset, "{}: {size}", path.display());
    file.seek(SeekFrom::Start(offset)).unwrap();
    let len = len.unwrap_or(size - offset);
    file.write_all(&vec![0x5a; len as usize]).unwrap();
}

/// A store index or metadata cache damaged past its schema page, as a CI
/// cache restore can bring back on every run, passes the check at open; the
/// first query that reads the damage recreates it, so this run and the next
/// succeed and the lock keeps its bytes.
#[test]
fn a_database_damaged_past_its_schema_page_is_recreated_mid_run() {
    let (_server, project) = stub_libraries(1);
    let lock_path = project.path().join("raeva.lock");
    for database in ["store/index.sqlite", "metadata.db"] {
        for args in [&["sync", "--frozen"][..], &["sync"]] {
            let home = tempfile::TempDir::new().unwrap();
            let run = || crate::common::run_raeva(project.path(), home.path(), args);
            let _ = fs::remove_file(&lock_path);
            assert_success(
                &crate::common::run_raeva(project.path(), home.path(), &["sync"]),
                "cold sync",
            );
            let locked = fs::read(&lock_path).unwrap();
            damage(&home.path().join(database), 4096, None);
            let first = run();
            let what = format!("{database} {args:?}");
            assert_success(&first, &what);
            assert!(
                text(&first).contains("DATABASE_RECREATED"),
                "{what}: {}",
                text(&first)
            );
            let second = run();
            assert_success(&second, &what);
            assert!(!text(&second).contains("DATABASE_RECREATED"), "{what}");
            assert_eq!(fs::read(&lock_path).unwrap(), locked, "{what}");
        }
    }
}

/// A store index or metadata cache that a newer raeva stamped with a later
/// generation fails the run with an error that names the file, and the
/// file keeps its bytes. The hint says to run the newer raeva, and to
/// delete only the metadata cache, which is not the store's index.
#[test]
fn a_database_a_newer_raeva_wrote_is_named_and_kept() {
    let (_server, project) = stub_libraries(1);
    for database in ["store/index.sqlite", "metadata.db"] {
        let home = tempfile::TempDir::new().unwrap();
        let sync = |args: &[&str]| crate::common::run_raeva(project.path(), home.path(), args);
        let _ = fs::remove_file(project.path().join("raeva.lock"));
        assert_success(&sync(&["sync"]), "cold sync");
        let path = database
            .split('/')
            .fold(home.path().to_path_buf(), |path, part| path.join(part));
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 99)
            .unwrap();
        let bytes = fs::read(&path).unwrap();
        for args in [&["sync", "--update"][..], &["--json", "sync", "--update"]] {
            let output = sync(args);
            let what = format!("{database} {args:?}");
            assert!(!output.status.success(), "{what}");
            // The JSON document escapes the backslashes of a Windows path.
            let text = if args.contains(&"--json") {
                let failed = envelope(&output);
                let hints = failed["hints"].as_array().expect("hints");
                (std::iter::once(&failed["error"]).chain(hints))
                    .map(|line| line.as_str().expect("a string"))
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                text(&output)
            };
            let name = fs::canonicalize(&path).unwrap_or(path.clone());
            assert!(
                text.contains("written by a newer raeva")
                    && (text.contains(&path.display().to_string())
                        || text.contains(&name.display().to_string())),
                "{what}: {text}"
            );
            assert!(text.contains("Run the newer raeva"), "{what}: {text}");
            let deletes = "and its -wal and -shm files while no raeva runs: it is a cache";
            assert_eq!(
                text.contains("delete"),
                database == "metadata.db" && text.contains(deletes),
                "{what}: {text}"
            );
        }
        assert_eq!(fs::read(&path).unwrap(), bytes, "{database}");
    }
}

/// Rows written before a query read the damage go with the recreated
/// database: the index rows of the files a restore found, which an offline
/// run needs, and the POMs it seeded into the metadata cache.
#[test]
fn a_database_recreated_mid_restore_keeps_what_the_restore_wrote_before() {
    let (_server, project) = stub_libraries(60);
    let parent = "org/example/parent/1/parent-1.pom";
    for (database, table) in [
        ("store/index.sqlite", "served_files"),
        ("metadata.db", "pom_cache_v5"),
    ] {
        let home = tempfile::TempDir::new().unwrap();
        let sync = |args: &[&str]| crate::common::run_raeva(project.path(), home.path(), args);
        let _ = fs::remove_file(project.path().join("raeva.lock"));
        assert_success(&sync(&["sync"]), "cold sync");
        let path = home.path().join(database);
        let leaves: Vec<i64> = rusqlite::Connection::open(&path)
            .unwrap()
            .prepare(&format!(
                "SELECT pageno FROM dbstat WHERE name = '{table}' AND pagetype = 'leaf' \
                 ORDER BY pageno"
            ))
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(leaves.len() > 1, "{database}: {leaves:?}");
        damage(
            &path,
            (leaves[leaves.len() - 1] as u64 - 1) * 4096,
            Some(4096),
        );
        let first = sync(&["sync", "--frozen"]);
        assert_success(&first, database);
        assert!(
            text(&first).contains("DATABASE_RECREATED"),
            "{}",
            text(&first)
        );
        assert_success(&sync(&["sync", "--frozen", "--offline"]), database);
        let cached: bool = rusqlite::Connection::open(home.path().join("metadata.db"))
            .unwrap()
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM pom_cache_v5 WHERE path = ?1)",
                [parent],
                |row| row.get(0),
            )
            .unwrap();
        assert!(cached, "{database}: {parent}");
    }
}

/// Two runs that start together on a damaged store index or metadata cache
/// both succeed: the first to find the damage recreates the file once the
/// other has closed it too, and the other opens the new one.
#[test]
fn runs_started_together_on_a_damaged_database_both_succeed() {
    let (_server, project) = stub_libraries(20);
    let twin = tempfile::TempDir::new().unwrap();
    let lock_path = project.path().join("raeva.lock");
    for database in ["store/index.sqlite", "metadata.db"] {
        for args in [&["sync", "--frozen"][..], &["sync"]] {
            let home = tempfile::TempDir::new().unwrap();
            let _ = fs::remove_file(&lock_path);
            assert_success(
                &crate::common::run_raeva(project.path(), home.path(), &["sync"]),
                "cold sync",
            );
            let locked = fs::read(&lock_path).unwrap();
            for file in ["pom.xml", "raeva.toml", "raeva.lock"] {
                fs::copy(project.path().join(file), twin.path().join(file)).unwrap();
            }
            damage(&home.path().join(database), 4096, None);
            let runs: Vec<_> = [project.path(), twin.path()]
                .map(|root| {
                    crate::common::raeva_command(root, home.path())
                        .args(args)
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .unwrap()
                })
                .into_iter()
                .collect();
            let what = format!("{database} {args:?}");
            for run in runs {
                assert_success(&run.wait_with_output().unwrap(), &what);
            }
            assert_eq!(fs::read(&lock_path).unwrap(), locked, "{what}");
            assert_eq!(
                fs::read(twin.path().join("raeva.lock")).unwrap(),
                locked,
                "{what}"
            );
        }
    }
}

/// A cached POM whose bytes changed after they were written is fetched
/// again, so a sync without a lock writes the one the repository's POMs
/// give, not one the changed bytes give.
#[test]
fn a_cached_pom_that_no_longer_matches_its_digest_is_fetched_again() {
    let (_server, project) = stub_libraries(1);
    let home = tempfile::TempDir::new().unwrap();
    let lock_path = project.path().join("raeva.lock");
    let sync = || crate::common::run_raeva(project.path(), home.path(), &["sync"]);
    let _ = fs::remove_file(&lock_path);
    assert_success(&sync(), "cold sync");
    let locked = fs::read(&lock_path).unwrap();
    fs::remove_file(&lock_path).unwrap();
    let edited = rusqlite::Connection::open(home.path().join("metadata.db"))
        .unwrap()
        .execute(
            "UPDATE pom_cache_v5 SET content = ?1 WHERE path = 'org/example/parent/1/parent-1.pom'",
            [
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>\
              <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
              <!-- edited --></project>"
                    .as_bytes(),
            ],
        )
        .unwrap();
    assert_eq!(edited, 1);
    let run = sync();
    assert_success(&run, "sync");
    assert!(text(&run).contains("CACHE_ENTRY_DAMAGED"), "{}", text(&run));
    assert_eq!(fs::read(&lock_path).unwrap(), locked);
}

/// A project whose `org.test:app` depends on `org.test:lib:1.0` and, through
/// a range, on `org.test:ext`, published at 1.0.
fn ranged_project() -> Project {
    let mut files = vec![("pom.xml".to_string(), RANGED_ROOT.to_string())];
    files.extend(ext_releases(&["1.0"]));
    files.push(ext_listing(&["1.0"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    Project::synced_with(&files)
}

/// The version listing of `org.test:ext` in the project's repository.
fn ext_listing(versions: &[&str]) -> (String, String) {
    let versions: String = (versions.iter())
        .map(|version| format!("<version>{version}</version>"))
        .collect();
    (
        "repository/org/test/ext/maven-metadata.xml".to_string(),
        format!(
            "<metadata><groupId>org.test</groupId><artifactId>ext</artifactId>\
             <versioning><versions>{versions}</versions></versioning></metadata>"
        ),
    )
}

fn is_lib(coordinate: &rv_maven_types::ArtifactCoord) -> bool {
    coordinate.gav.artifact.as_str() == "lib"
}

const RANGED_ROOT: &str = r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>app</artifactId><version>1</version>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>
  </repositories>
  <dependencies>
    <dependency><groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version></dependency>
    <dependency><groupId>org.test</groupId><artifactId>ext</artifactId><version>[1.0,2)</version></dependency>
  </dependencies>
</project>
"#;

/// `--frozen` resolves again also when the POMs match raeva.lock, so a lock
/// edited by hand fails, its graph digests recomputed as raeva writes them,
/// while a version published inside a range since the lock was written does
/// not move the range.
#[test]
fn frozen_resolves_again_and_refuses_a_lock_edited_alone() {
    use rv_lock::{LockEdge, LockPlatform, Lockfile, Scope};
    use rv_maven_types::ArtifactCoord;

    let project = ranged_project();
    let lock_path = project.root().join("raeva.lock");
    let written = fs::read_to_string(&lock_path).unwrap();
    for (path, text) in ext_releases(&["1.1"])
        .into_iter()
        .chain([ext_listing(&["1.0", "1.1"])])
    {
        let path = project.root().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let frozen = [
        &["sync", "--frozen"][..],
        &["sync", "--frozen", "--offline"],
    ];
    for args in frozen {
        assert_success(&project.raeva(args), &format!("{args:?} keeps ext 1.0"));
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), written, "{args:?}");
    }

    let lock = Lockfile::read(&lock_path).unwrap();
    type Edit = fn(&mut LockPlatform);
    let edits: [(&str, Edit); 4] = [
        ("a dropped dependency", |platform| {
            platform.artifacts.retain(|row| !is_lib(&row.coordinate));
            (platform.modules[0].packages).retain(|package| !is_lib(&package.coordinate));
        }),
        ("another version", |platform| {
            let rows = (platform.artifacts.iter_mut()).map(|row| &mut row.coordinate);
            let packages = (platform.modules[0].packages.iter_mut()).map(|row| &mut row.coordinate);
            for coordinate in rows.chain(packages).filter(|coordinate| is_lib(coordinate)) {
                *coordinate = ArtifactCoord::new("org.test", "lib", "1.1", "jar", None);
            }
        }),
        ("another scope", |platform| {
            for package in &mut platform.modules[0].packages {
                if is_lib(&package.coordinate) {
                    package.scope = Scope::Test;
                    package.direct_scope = package.direct_scope.map(|_| Scope::Test);
                }
            }
        }),
        ("an added edge", |platform| {
            (platform.modules[0].edges).push(LockEdge::new(0, 1, rv_lock::Scope::Compile, false));
        }),
    ];
    for (edit, change) in edits {
        let mut edited = lock.clone();
        change(&mut edited.platforms[0]);
        edited.write_atomic(&lock_path).unwrap();
        let text = fs::read_to_string(&lock_path).unwrap();
        assert_ne!(text, written, "{edit}");
        for args in frozen {
            let output = project.raeva(&[&["--json"][..], args].concat());
            assert_status(&output, 7, &format!("{edit}: {args:?}"));
            assert_eq!(
                envelope(&output)["code"],
                "LOCKFILE_MISMATCH",
                "{edit}: {args:?}"
            );
            assert_eq!(
                fs::read_to_string(&lock_path).unwrap(),
                text,
                "{edit}: {args:?}"
            );
        }
    }
}

/// `org.test:<artifact>:<version>` with `body` inside its `<project>`, and
/// a jar unless `body` sets the packaging, published with SHA-256 files.
fn release(artifact: &str, version: &str, body: &str) -> Vec<(String, String)> {
    let dir = format!("repository/org/test/{artifact}/{version}");
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion>{body}<groupId>org.test</groupId>\
         <artifactId>{artifact}</artifactId><version>{version}</version></project>"
    );
    let mut files = vec![(format!("{artifact}-{version}.pom"), pom)];
    if !body.contains("<packaging>") {
        files.push((
            format!("{artifact}-{version}.jar"),
            format!("{artifact} {version}"),
        ));
    }
    let mut published = Vec::new();
    for (name, text) in files {
        published.push((
            format!("{dir}/{name}.sha256"),
            crate::common::sha256_hex(text.as_bytes()),
        ));
        published.push((format!("{dir}/{name}"), text));
    }
    published
}

/// The version listing of `org.test:<artifact>`.
fn listing(artifact: &str, versions: &[&str]) -> (String, String) {
    let versions: String = (versions.iter())
        .map(|version| format!("<version>{version}</version>"))
        .collect();
    (
        format!("repository/org/test/{artifact}/maven-metadata.xml"),
        format!(
            "<metadata><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <versioning><versions>{versions}</versions></versioning></metadata>"
        ),
    )
}

fn dependency(artifact: &str, version: &str) -> String {
    format!(
        "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
         <version>{version}</version></dependency>"
    )
}

/// A losing range is listed under each id of a repository that listed it
/// where no list names a version in it: `m2` reads only `repo-a`, where the
/// range of the losing `c:2` on `lib` found `2.0`, and `m1` locks `lib:2.1`
/// from `repo-b` under `x-id`, which `m2` does not read. `m3` reads both and
/// records the range for each. `mvn -o` reads `m2`'s range in `repo-a`'s
/// list only, so the export lists `2.0` there and nowhere else.
#[test]
fn export_lists_a_losing_range_under_the_repository_that_listed_it() {
    let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
    let repos = |ids: &[(&str, &str)]| {
        let repos: String = (ids.iter())
            .map(|(id, dir)| {
                format!("<repository><id>{id}</id><url>file://${{project.basedir}}/../{dir}/</url></repository>")
            })
            .collect();
        format!("<repositories>{repos}</repositories>")
    };
    let module = |name: &str, body: String| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>\
             <parent><groupId>org.test</groupId><artifactId>root</artifactId><version>1</version></parent>\
             <artifactId>{name}</artifactId>{body}</project>"
        )
    };
    let in_repo = |repo: &str, files: Vec<(String, String)>| -> Vec<(String, String)> {
        (files.into_iter())
            .map(|(path, text)| (path.replacen("repository/", &format!("{repo}/"), 1), text))
            .collect()
    };
    let mut files = vec![
        (
            "pom.xml".to_string(),
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>m1</module><module>m2</module><module>m3</module></modules></project>"
                .to_string(),
        ),
        (
            "m1/pom.xml".to_string(),
            module(
                "m1",
                repos(&[("x-id", "repo-b"), ("repo-a", "repo-a")])
                    + &deps(&[dependency("lib", "2.1"), dependency("c", "2")]),
            ),
        ),
        (
            "m2/pom.xml".to_string(),
            module(
                "m2",
                repos(&[("repo-a", "repo-a")])
                    + &deps(&[dependency("x", "1"), dependency("y", "1")]),
            ),
        ),
        (
            "m3/pom.xml".to_string(),
            module(
                "m3",
                repos(&[("repo-b", "repo-b"), ("repo-a", "repo-a")])
                    + &deps(&[dependency("x", "1"), dependency("y", "1")]),
            ),
        ),
    ];
    let mut repo_a = release("x", "1", &deps(&[dependency("c", "2")]));
    repo_a.extend(release("y", "1", &deps(&[dependency("w", "1")])));
    repo_a.extend(release("w", "1", &deps(&[dependency("c", "[1]")])));
    repo_a.extend(release("c", "1", ""));
    repo_a.extend(release("c", "2", &deps(&[dependency("lib", "[2,3)")])));
    repo_a.extend(release("lib", "2.0", ""));
    repo_a.push(listing("lib", &["2.0"]));
    files.extend(in_repo("repo-a", repo_a));
    let mut repo_b = release("lib", "2.1", "");
    repo_b.push(listing("lib", &["2.1"]));
    files.extend(in_repo("repo-b", repo_b));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let evicted = |path: &str| {
        let module = (lock.platforms[0].modules.iter())
            .find(|module| module.path == path)
            .unwrap();
        (module.evicted_ranges.iter())
            .map(|r| {
                format!(
                    "{}:{} {} {}",
                    r.artifact,
                    r.range,
                    r.versions.join(" "),
                    r.origin
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(evicted("m2/pom.xml"), ["lib:[2,3) 2.0 ./repo-a/"]);
    assert_eq!(
        evicted("m3/pom.xml"),
        ["lib:[2,3) 2.0 ./repo-a/", "lib:[2,3) 2.1 ./repo-b/"]
    );

    let output = project.raeva(&[
        "--json",
        "export-m2",
        "--m2-path",
        project.m2().to_str().unwrap(),
    ]);
    assert_success(&output, "export-m2");
    let warnings = envelope(&output)["data"]["warnings"].clone();
    let warning = (warnings.as_array().unwrap().iter())
        .find(|warning| warning["code"] == "EXPORT_LOSING_RANGE_VERSIONS")
        .unwrap_or_else(|| panic!("{warnings}"));
    assert_eq!(warning["context"]["coordinates"], "org.test:lib:2.0");
    let versions = |id: &str| {
        let text = fs::read_to_string(
            project
                .m2()
                .join(format!("org/test/lib/maven-metadata-{id}.xml")),
        )
        .unwrap();
        (text.split("<version>").skip(1))
            .map(|rest| rest.split('<').next().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(versions("repo-a"), ["2.0"]);
    assert_eq!(versions("repo-b"), ["2.1"]);
    assert_eq!(versions("x-id"), ["2.1"]);
    assert!(versions("local").is_empty());
}

/// A reactor module with the range's `group:artifact` stands in for its
/// lists only when its version is in the range: `mvn -o` still reads the
/// lists of a range the reactor's `lib:1.0` is not in.
#[test]
fn a_losing_range_the_reactor_has_no_version_in_is_recorded() {
    let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
    let module = |name: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>\
             <parent><groupId>org.test</groupId><artifactId>root</artifactId><version>1</version></parent>\
             <artifactId>{name}</artifactId>{body}</project>"
        )
    };
    let mut files = vec![
        (
            "pom.xml".to_string(),
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>lib</module><module>app</module></modules></project>"
                .to_string(),
        ),
        (
            "lib/pom.xml".to_string(),
            module("lib", "<version>1.0</version>"),
        ),
        (
            "app/pom.xml".to_string(),
            module(
                "app",
                &format!(
                    "<repositories><repository><id>repo</id>\
                     <url>file://${{project.basedir}}/../repository/</url></repository></repositories>{}",
                    deps(&[dependency("x", "1"), dependency("y", "1")])
                ),
            ),
        ),
    ];
    files.extend(release("x", "1", &deps(&[dependency("c", "2")])));
    files.extend(release("y", "1", &deps(&[dependency("w", "1")])));
    files.extend(release("w", "1", &deps(&[dependency("c", "[1]")])));
    files.extend(release("c", "1", ""));
    files.extend(release("c", "2", &deps(&[dependency("lib", "[2,3)")])));
    files.extend(release("lib", "2.0", ""));
    files.push(listing("lib", &["2.0"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let app = (lock.platforms[0].modules.iter())
        .find(|module| module.path == "app/pom.xml")
        .unwrap();
    let evicted: Vec<_> = (app.evicted_ranges.iter())
        .map(|r| {
            format!(
                "{}:{} {} {}",
                r.artifact,
                r.range,
                r.origin,
                r.versions.join(" ")
            )
        })
        .collect();
    assert_eq!(evicted, ["lib:[2,3) ./repository/ 2.0"]);
}

/// The files of a project whose `x:1` declares `c:2`, which loses to the
/// nearer `c:1` and declares `range` on `z`, which lists `1.0` and `2.0`.
fn nearer_loser_files(mode: &str, range: &str) -> Vec<(String, String)> {
    let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
         </repository></repositories>{}</project>",
        deps(&[dependency("c", "1"), dependency("x", "1")])
    );
    let mut files = vec![
        ("pom.xml".to_string(), root),
        (
            "raeva.toml".to_string(),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        ),
    ];
    files.extend(release("x", "1", &deps(&[dependency("c", "2")])));
    files.extend(release("c", "1", ""));
    files.extend(release("c", "2", &deps(&[dependency("z", range)])));
    files.extend(release("z", "1.0", ""));
    files.extend(release("z", "2.0", ""));
    files.push(listing("z", &["1.0", "2.0"]));
    files
}

/// Maven 3.9 reads the whole tree before it mediates, so it lists the range
/// below a version that loses to a nearer one, and `mvn -o` reads that list
/// again. Maven 3.10 does not read below a loser.
#[test]
fn a_range_below_a_nearer_loser_is_recorded_as_maven_39_lists_it() {
    for (mode, expected) in [("3.9", &["z [1.0,3.0) 1.0 2.0"][..]), ("3.10", &[])] {
        let files = nearer_loser_files(mode, "[1.0,3.0)");
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::synced_with(&files);
        let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
        let evicted: Vec<_> = (lock.platforms[0].modules[0].evicted_ranges.iter())
            .map(|r| format!("{} {} {}", r.artifact, r.range, r.versions.join(" ")))
            .collect();
        assert_eq!(evicted, expected, "{mode}");
    }
}

/// Maven 3.9 fails on "No versions available" for a range below a version
/// that loses to a nearer one when no list names a version in it, and Maven
/// 3.10, which does not read below the loser, builds, as Maven 3.9 does with
/// its breadth-first collector.
#[test]
fn a_range_below_a_nearer_loser_with_no_version_fails_as_in_maven_39() {
    let files = nearer_loser_files("3.9", "[5.0,6.0)");
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::with(&files);
    let output = project.raeva(&["sync", "--offline"]);
    assert_status(&output, 5, "3.9 sync");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("org.test:z matching [5.0,6.0)")
            && stderr.contains("org.test:x:1 -> org.test:c:2"),
        "{stderr}"
    );
    assert!(!project.root().join("raeva.lock").exists());

    let files = nearer_loser_files("3.10", "[5.0,6.0)");
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    Project::synced_with(&files);

    // Maven 3.9's breadth-first collector does not read below the loser.
    let mut files = nearer_loser_files("3.9", "[5.0,6.0)");
    files.push((
        ".mvn/maven.config".to_string(),
        "-Daether.dependencyCollector.impl=bf\n".to_string(),
    ));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    Project::synced_with(&files);

    let mut files = nearer_loser_files("3.9", "[5.0,6.0)");
    files.push((
        ".mvn/jvm.config".to_string(),
        "-Daether.dependencyCollector.impl=bf\n".to_string(),
    ));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    Project::synced_with(&files);
}

/// Both Maven lines read the POM of the `c:2` that loses to the nearer
/// `c:1`, and Maven 3.9 those of `z:1.0` and `w:1` below it, so `mvn -o`
/// on the export warns of each one it does not find. A version a range
/// lists is read offline only where the export lists it, which is no
/// losing one, and nothing below it is read.
#[test]
fn the_poms_maven_reads_of_a_losing_dependency_are_exported() {
    for (mode, z, exports_z) in [
        ("3.9", "1.0", true),
        ("3.10", "1.0", false),
        ("3.9", "[1.0,3.0)", false),
    ] {
        let mut files = nearer_loser_files(mode, z);
        files.retain(|(path, _)| !path.contains("/z/1.0/"));
        files.extend(release(
            "z",
            "1.0",
            &format!("<dependencies>{}</dependencies>", dependency("w", "1")),
        ));
        files.extend(release("w", "1", ""));
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::synced_with(&files);
        let m2 = tempfile::tempdir().expect("m2");
        let output = project.raeva(&["export-m2", "--m2-path", m2.path().to_str().unwrap()]);
        assert_status(&output, 0, mode);
        let exported = |pom: &str| m2.path().join(format!("org/test/{pom}.pom")).exists();
        assert!(exported("c/2/c-2"), "{mode} {z}");
        assert_eq!(exported("z/1.0/z-1.0"), exports_z, "{mode} {z}");
        assert_eq!(exported("w/1/w-1"), exports_z, "{mode} {z}");
        assert!(!exported("z/2.0/z-2.0"), "{mode} {z}");
    }
}

/// `a:1` wins `a:[1,2]` for the `a:[1,1]` below `d`, and the `a:2` below
/// `f`, which excludes `n`, loses. The export lists `a:2` with its POM, so
/// `mvn -o` reads the range's `a:2` too, and the `n:1` below it.
#[test]
fn a_range_version_the_export_lists_is_read_offline_with_what_is_below_it() {
    let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
         </repository></repositories>{}</project>",
        deps(&[
            dependency("a", "[1,2]"),
            dependency("d", "1"),
            dependency("e", "1"),
        ])
    );
    let excluding = dependency("a", "2").replace(
        "</version>",
        "</version><exclusions><exclusion><groupId>org.test</groupId>\
         <artifactId>n</artifactId></exclusion></exclusions>",
    );
    let mut files = vec![
        ("pom.xml".to_string(), root),
        (
            "raeva.toml".to_string(),
            "[lock]\nmaven = \"3.9\"\n".to_string(),
        ),
    ];
    files.extend(release("a", "1", ""));
    files.extend(release("a", "2", &deps(&[dependency("n", "1")])));
    files.push(listing("a", &["1", "2"]));
    files.extend(release("n", "1", ""));
    files.extend(release("d", "1", &deps(&[dependency("a", "[1,1]")])));
    files.extend(release("e", "1", &deps(&[dependency("f", "1")])));
    files.extend(release("f", "1", &deps(&[excluding])));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let m2 = tempfile::tempdir().expect("m2");
    let output = project.raeva(&["export-m2", "--m2-path", m2.path().to_str().unwrap()]);
    assert_status(&output, 0, "export");
    assert!(m2.path().join("org/test/a/2/a-2.pom").exists());
    assert!(m2.path().join("org/test/n/1/n-1.pom").exists());
}

/// Breadth first, the `x:1` below `d` takes the descriptor the system
/// `x:1` below `s` asked for, so Maven reads no POM for it, and none is
/// pinned when it loses to `x:2`.
#[test]
fn a_loser_that_takes_a_system_declarations_descriptor_pins_no_pom() {
    let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
         </repository></repositories>{}</project>",
        deps(&[
            dependency("s", "1"),
            dependency("d", "1"),
            dependency("x", "2")
        ])
    );
    let mut files = vec![
        ("pom.xml".to_string(), root),
        (
            "raeva.toml".to_string(),
            "[lock]\nmaven = \"3.10\"\n".to_string(),
        ),
    ];
    let system = dependency("x", "1").replace(
        "</version>",
        "</version><scope>system</scope><systemPath>${java.home}/nowhere/x.jar</systemPath>",
    );
    files.extend(release("s", "1", &deps(&[system])));
    files.extend(release("d", "1", &deps(&[dependency("x", "1")])));
    files.extend(release("x", "1", ""));
    files.extend(release("x", "2", ""));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let support = &lock.platforms[0].modules[0].support_poms;
    assert!(
        !support.iter().any(|pom| pom.contains(":x:")),
        "{support:?}"
    );
}

/// A loser whose version equals the winner's but is spelled apart from it
/// is another POM, which Maven 3.9.12 and 3.10.0 read with either collector:
/// `target:1.0` below `lib` loses to the nearer `target:1.0.0`, and
/// `target:alpha` to `target:0`, also when `lib` asks for `[1.0,1.0]` or a
/// union of such ranges, which takes its bound without reading metadata. Only depth first do they
/// read `leaf:1.0` below the loser.
#[test]
fn a_loser_spelled_apart_from_an_equal_winner_pins_its_pom() {
    let cases = [
        ("1.0", "1.0", "1.0.0", "3.9"),
        ("1.0", "1.0", "1.0.0", "3.10"),
        ("alpha", "alpha", "0", "3.9"),
        ("alpha", "alpha", "0", "3.10"),
        ("1.0", "[1.0,1.0]", "1.0.0", "3.9"),
        ("1.0", "[1.0]", "1.0.0", "3.10"),
        ("alpha", "[alpha,alpha]", "0", "3.9"),
        ("1.0", "[1.0,1.0],[1.0.0,1.0.0]", "1.0.0", "3.9"),
        ("1.0", "[1.0][1.0]", "1.0.0", "3.10"),
    ];
    for (loser, requested, winner, mode) in cases {
        for (collector, depth_first) in [
            (None, mode == "3.9"),
            (Some(if mode == "3.9" { "bf" } else { "df" }), mode != "3.9"),
        ] {
            let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
            let root = format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>app</artifactId><version>1</version><repositories><repository>\
                 <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
                 </repository></repositories>{}</project>",
                deps(&[dependency("lib", "1"), dependency("target", winner)])
            );
            let mut files = vec![
                ("pom.xml".to_string(), root),
                (
                    "raeva.toml".to_string(),
                    format!("[lock]\nmaven = \"{mode}\"\n"),
                ),
            ];
            if let Some(collector) = collector {
                files.push((
                    ".mvn/maven.config".to_string(),
                    format!("-Daether.dependencyCollector.impl={collector}\n"),
                ));
            }
            files.extend(release(
                "lib",
                "1",
                &deps(&[dependency("target", requested)]),
            ));
            files.extend(release(
                "target",
                loser,
                &deps(&[dependency("leaf", "1.0")]),
            ));
            files.extend(release("target", winner, ""));
            files.extend(release("leaf", "1.0", ""));
            let files: Vec<_> = (files.iter())
                .map(|(path, text)| (path.as_str(), text.as_str()))
                .collect();
            let project = Project::synced_with(&files);
            let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
            let support = &lock.platforms[0].modules[0].support_poms;
            let case = format!("{requested} {mode} {collector:?}: {support:?}");
            let pinned = |pom: &str| support.iter().any(|pinned| *pinned == pom);
            assert!(pinned(&format!("org.test:target:{loser}")), "{case}");
            assert_eq!(pinned("org.test:leaf:1.0"), depth_first, "{case}");
            let m2 = tempfile::tempdir().expect("m2");
            let output = project.raeva(&["export-m2", "--m2-path", m2.path().to_str().unwrap()]);
            assert_status(&output, 0, &case);
            let pom = format!("org/test/target/{loser}/target-{loser}.pom");
            assert!(m2.path().join(pom).exists(), "{case}");
        }
    }
}

/// A module `1.0SNAPSHOT` that asks for `[1.0SNAPSHOT]` of itself takes
/// the build `1.020240101.010101-1` metadata names, which Maven 3.9.12
/// reads as a release, with the module's model: the build POM's `leaf` is
/// no dependency, and its parent no POM the lock pins, so the build's
/// component in the SBOM has no licenses.
#[test]
fn a_module_spelled_snapshot_without_a_hyphen_keeps_its_model() {
    let parent = "<parent><groupId>org.test</groupId><artifactId>corp</artifactId>\
                  <version>1</version></parent>";
    let corp = release(
        "corp",
        "1",
        "<packaging>pom</packaging><licenses><license><name>MIT</name></license></licenses>",
    );
    let project = no_hyphen_module(parent, "", corp);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let packages: Vec<String> = (lock.platforms[0].modules[0].packages.iter())
        .map(|package| package.coordinate.to_string())
        .collect();
    assert_eq!(
        packages,
        [format!("org.test:no-hyphen:{NO_HYPHEN_BUILD}:jar")]
    );
    assert_status(
        &project.raeva(&["sync", "--offline", "--frozen"]),
        0,
        "frozen",
    );
    let output = project.raeva(&["sbom", "--offline"]);
    assert_status(&output, 0, "sbom");
    let bom: Value = serde_json::from_slice(&output.stdout).unwrap();
    let build = (bom["components"].as_array().unwrap().iter())
        .find(|component| component["version"].as_str() == Some(NO_HYPHEN_BUILD))
        .unwrap();
    assert!(build.get("licenses").is_none(), "{build}");
}

/// Beside its own hyphenless build, the module asks for `other` at the
/// same version, a release whose POM names `real-leaf`. Maven 3.9.12 reads
/// that POM; `other`'s `1.0SNAPSHOT`, whose POM names `wrong-leaf`, is no
/// build of the module.
#[test]
fn another_artifact_at_a_modules_hyphenless_build_keeps_its_own_model() {
    let build = NO_HYPHEN_BUILD;
    let mut more = release(
        "other",
        build,
        &format!(
            "<dependencies>{}</dependencies>",
            dependency("real-leaf", "1")
        ),
    );
    more.extend(release(
        "other",
        "1.0SNAPSHOT",
        &format!(
            "<dependencies>{}</dependencies>",
            dependency("wrong-leaf", "1")
        ),
    ));
    more.extend(release("real-leaf", "1", ""));
    more.extend(release("wrong-leaf", "1", ""));
    let project = no_hyphen_module("", &dependency("other", build), more);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let packages: Vec<String> = (lock.platforms[0].modules[0].packages.iter())
        .map(|package| package.coordinate.to_string())
        .collect();
    assert_eq!(
        packages,
        [
            format!("org.test:no-hyphen:{build}:jar"),
            format!("org.test:other:{build}:jar"),
            "org.test:real-leaf:1:jar".to_string(),
        ]
    );
}

const NO_HYPHEN_BUILD: &str = "1.020240101.010101-1";

/// The module `org.test:no-hyphen:1.0SNAPSHOT`, which asks for
/// `[1.0SNAPSHOT]` of itself and `dependencies`, synced against a
/// repository with its build `1.020240101.010101-1`, whose POM names `leaf`
/// and holds `build_body`, and `more`.
fn no_hyphen_module(build_body: &str, dependencies: &str, more: Vec<(String, String)>) -> Project {
    let repository = "repository/org.test/no-hyphen".replace('.', "/");
    let build = NO_HYPHEN_BUILD;
    let build_pom = format!(
        "<project><modelVersion>4.0.0</modelVersion>{build_body}<groupId>org.test</groupId>\
         <artifactId>no-hyphen</artifactId><version>1.0SNAPSHOT</version>\
         <dependencies>{}</dependencies></project>",
        dependency("leaf", "1")
    );
    let jar = "no-hyphen build".to_string();
    let mut files = vec![
        (
            "pom.xml".to_string(),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>no-hyphen</artifactId><version>1.0SNAPSHOT</version>\
                 <repositories><repository><id>project-local</id>\
                 <url>file://${{project.basedir}}/repository/</url>\
                 <snapshots><enabled>true</enabled></snapshots></repository></repositories>\
                 <dependencies>{}</dependencies></project>",
                dependency("no-hyphen", "[1.0SNAPSHOT]") + dependencies
            ),
        ),
        (
            "raeva.toml".to_string(),
            "[lock]\nmaven = \"3.9\"\n".to_string(),
        ),
        (
            format!("{repository}/1.0SNAPSHOT/maven-metadata.xml"),
            "<metadata><groupId>org.test</groupId><artifactId>no-hyphen</artifactId>\
             <version>1.0SNAPSHOT</version><versioning><snapshot>\
             <timestamp>20240101.010101</timestamp><buildNumber>1</buildNumber></snapshot>\
             <lastUpdated>20240101010101</lastUpdated></versioning></metadata>"
                .to_string(),
        ),
    ];
    for (name, text) in [
        (format!("no-hyphen-{build}.pom"), build_pom),
        (format!("no-hyphen-{build}.jar"), jar),
    ] {
        files.push((
            format!("{repository}/{build}/{name}.sha256"),
            crate::common::sha256_hex(text.as_bytes()),
        ));
        files.push((format!("{repository}/{build}/{name}"), text));
    }
    files.extend(release("leaf", "1", ""));
    files.extend(more);
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    Project::synced_with(&files)
}

/// A reactor module that only another target's profile builds leaves the
/// SBOM of a module that takes the repository's artifact of those
/// coordinates on its own target: `app`, on Linux, depends on `lib:1`,
/// which only the Windows reactor builds. The SBOM of both targets lists
/// the module and the file, each with its own POM's license.
#[test]
fn a_module_another_target_builds_leaves_the_sbom_whole() {
    let profile = |id: &str, family: &str, module: &str| {
        format!(
            "<profile><id>{id}</id><activation><os><family>{family}</family></os></activation>\
             <modules><module>{module}</module></modules></profile>"
        )
    };
    let module = |artifact: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version>\
             <repositories><repository><id>project-local</id>\
             <url>file://${{project.basedir}}/../repository/</url></repository>\
             </repositories>{body}</project>"
        )
    };
    let mut files = vec![
        (
            "pom.xml".to_string(),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <profiles>{}{}</profiles></project>",
                profile("linux", "!windows", "app"),
                profile("windows", "windows", "lib")
            ),
        ),
        (
            "app/pom.xml".to_string(),
            module(
                "app",
                &format!("<dependencies>{}</dependencies>", dependency("lib", "1")),
            ),
        ),
        (
            "lib/pom.xml".to_string(),
            module("lib", &license("Apache-2.0")),
        ),
    ];
    let license = license("MIT");
    files.extend(release("lib", "1", &license));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::with(&files);
    assert_status(
        &project.raeva(&[
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64,windows-x86_64",
        ]),
        0,
        "sync",
    );
    let output = project.raeva(&["sbom", "--offline", "--module", "app/pom.xml"]);
    assert_status(&output, 0, "app sbom");
    let bom: Value = serde_json::from_slice(&output.stdout).unwrap();
    let lib = (bom["components"].as_array().unwrap().iter())
        .find(|component| component["name"].as_str() == Some("lib"))
        .unwrap();
    assert_eq!(lib["bom-ref"], lib["purl"], "{lib}");
    assert_eq!(
        lib["hashes"][0]["content"].as_str(),
        Some(crate::common::sha256_hex(b"lib 1").as_str()),
        "{lib}"
    );
    let output = project.raeva(&["sbom", "--offline"]);
    assert_status(&output, 0, "whole sbom");
    let bom: Value = serde_json::from_slice(&output.stdout).unwrap();
    let libs: Vec<(String, String)> = (bom["components"].as_array().unwrap().iter())
        .filter(|component| component["name"].as_str() == Some("lib"))
        .map(|component| {
            let reference = component["bom-ref"].as_str().unwrap();
            let purl = component["purl"].as_str().unwrap();
            let suffix = reference.strip_prefix(purl).unwrap().to_string();
            (suffix, component["licenses"].to_string())
        })
        .collect();
    assert_eq!(libs.len(), 2, "{libs:?}");
    assert!(
        libs[0].0.is_empty() && libs[0].1.contains("Apache-2.0"),
        "{libs:?}"
    );
    assert!(
        libs[1].0 == "#file" && libs[1].1.contains("MIT"),
        "{libs:?}"
    );
}

fn license(name: &str) -> String {
    format!("<licenses><license><name>{name}</name></license></licenses>")
}

/// A SNAPSHOT module that asks for `[1-SNAPSHOT]` of itself takes the newest
/// build any repository has, as Maven 3.9.12 and 3.10.0 do: `repo-b`'s, though
/// `repo-a` comes first. Its model is the module's, so the repository POM's
/// `y` is no dependency. Module `p` asks for its own POM, which the module
/// serves though no repository has snapshots enabled.
#[test]
fn a_snapshot_module_takes_its_newest_build_from_a_repository() {
    let build = |repo: &str, stamp: &str, number: u32| -> Vec<(String, String)> {
        let dir = format!("{repo}/org/test/selfs/1-SNAPSHOT");
        let value = format!("1-{stamp}-{number}");
        let updated = stamp.replace('.', "");
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>selfs</artifactId><version>1-SNAPSHOT</version>\
             <dependencies>{}</dependencies></project>",
            dependency("y", "1")
        );
        let metadata = format!(
            "<metadata modelVersion=\"1.1.0\"><groupId>org.test</groupId>\
             <artifactId>selfs</artifactId><version>1-SNAPSHOT</version><versioning>\
             <snapshot><timestamp>{stamp}</timestamp><buildNumber>{number}</buildNumber>\
             </snapshot><lastUpdated>{updated}</lastUpdated><snapshotVersions>\
             <snapshotVersion><extension>jar</extension><value>{value}</value>\
             <updated>{updated}</updated></snapshotVersion><snapshotVersion>\
             <extension>pom</extension><value>{value}</value><updated>{updated}</updated>\
             </snapshotVersion></snapshotVersions></versioning></metadata>"
        );
        let mut files = Vec::new();
        for (name, text) in [
            (format!("selfs-{value}.pom"), pom),
            (format!("selfs-{value}.jar"), format!("selfs {value}")),
        ] {
            files.push((
                format!("{dir}/{name}.sha256"),
                crate::common::sha256_hex(text.as_bytes()),
            ));
            files.push((format!("{dir}/{name}"), text));
        }
        files.push((format!("{dir}/maven-metadata.xml"), metadata));
        files
    };
    for mode in ["3.9", "3.10"] {
        let repositories: String = (["repo-a", "repo-b"].iter())
            .map(|id| {
                format!(
                    "<repository><id>{id}</id><url>file://${{project.basedir}}/../{id}/</url>\
                     <snapshots><enabled>true</enabled></snapshots></repository>"
                )
            })
            .collect();
        let mut files = vec![
            (
                "pom.xml".to_string(),
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>s</module><module>p</module></modules></project>"
                    .to_string(),
            ),
            (
                "s/pom.xml".to_string(),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>selfs</artifactId><version>1-SNAPSHOT</version>\
                     <repositories>{repositories}</repositories>\
                     <dependencies>{}</dependencies></project>",
                    dependency("selfs", "[1-SNAPSHOT]")
                ),
            ),
            (
                "p/pom.xml".to_string(),
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>selfp</artifactId><version>1-SNAPSHOT</version>\
                     <repositories><repository><id>repo-a</id>\
                     <url>file://${project.basedir}/../repo-a/</url>\
                     <snapshots><enabled>false</enabled></snapshots></repository></repositories>\
                     <dependencies><dependency><groupId>org.test</groupId>\
                     <artifactId>selfp</artifactId><version>[1-SNAPSHOT]</version>\
                     <type>pom</type></dependency></dependencies></project>"
                    .to_string(),
            ),
            (
                "raeva.toml".to_string(),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            ),
        ];
        files.extend(build("repo-a", "20260101.000000", 1));
        files.extend(build("repo-b", "20260102.000000", 2));
        for repo in ["repo-a", "repo-b"] {
            files.extend(
                (release("y", "1", "").into_iter())
                    .map(|(path, text)| (path.replacen("repository", repo, 1), text)),
            );
        }
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::synced_with(&files);
        let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
        let platform = &lock.platforms[0];
        let packages: Vec<String> = (platform.modules.iter())
            .filter(|module| module.path == "s/pom.xml")
            .flat_map(|module| &module.packages)
            .map(|package| package.coordinate.to_string())
            .collect();
        assert_eq!(packages, ["org.test:selfs:1-SNAPSHOT:jar"], "{mode}");
        let own_pom = (platform.modules.iter())
            .find(|module| module.path == "p/pom.xml")
            .map(|module| &module.packages[0]);
        assert_eq!(
            own_pom.and_then(|package| package.workspace_module.as_deref()),
            Some("p/pom.xml"),
            "{mode}"
        );
        let row = (platform.artifacts.iter())
            .find(|row| row.coordinate.gav.artifact.as_str() == "selfs")
            .unwrap();
        assert_eq!(
            row.snapshot.as_ref().map(ToString::to_string).as_deref(),
            Some("20260102.000000-2"),
            "{mode} {row:?}"
        );
        assert!(row.repo_url.ends_with("/repo-b/"), "{mode} {row:?}");
        let m2 = tempfile::tempdir().expect("m2");
        let output = project.raeva(&["export-m2", "--m2-path", m2.path().to_str().unwrap()]);
        assert_status(&output, 0, mode);
        let dir = m2.path().join("org/test/selfs/1-SNAPSHOT");
        let jars: Vec<String> = (fs::read_dir(&dir).unwrap())
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "jar"))
            .map(|path| fs::read_to_string(path).unwrap())
            .collect();
        assert!(!jars.is_empty(), "{mode}");
        assert!(
            jars.iter().all(|jar| jar == "selfs 1-20260102.000000-2"),
            "{mode} {jars:?}"
        );
        assert_status(&project.raeva(&["sync", "--offline", "--frozen"]), 0, mode);
    }
}

/// A module has built nothing when Maven resolves its own dependencies.
/// `selfe:1` asking for `selfe:[1,1]` takes the repository's jar, with the
/// module's own model, so not the `y:1` only the repository POM names,
/// while `app` takes the module. `selfs:2` asking for `selfs:[1,3)` takes
/// `1`, the one version the repository lists, over itself. Maven 3.9.12 and
/// 3.10.0 resolve these so.
#[test]
fn a_module_takes_its_own_jar_from_the_repository() {
    for mode in ["3.9", "3.10"] {
        let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
        let module = |artifact: &str, version: &str, list: &[String]| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>{artifact}</artifactId><version>{version}</version>\
                 <repositories><repository><id>project-local</id>\
                 <url>file://${{project.basedir}}/../repository/</url></repository>\
                 </repositories>{}</project>",
                deps(list)
            )
        };
        let mut files = vec![
            (
                "pom.xml".to_string(),
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>a</module><module>app</module><module>b</module></modules>\
                 </project>"
                    .to_string(),
            ),
            (
                "a/pom.xml".to_string(),
                module("selfe", "1", &[dependency("selfe", "[1,1]")]),
            ),
            (
                "app/pom.xml".to_string(),
                module("app", "1", &[dependency("selfe", "1")]),
            ),
            (
                "b/pom.xml".to_string(),
                module("selfs", "2", &[dependency("selfs", "[1,3)")]),
            ),
            (
                "raeva.toml".to_string(),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            ),
        ];
        files.extend(release("selfe", "1", &deps(&[dependency("y", "1")])));
        files.extend(release("y", "1", ""));
        files.extend(release("selfs", "1", ""));
        files.extend(release("selfs", "2", ""));
        files.push(listing("selfs", &["1"]));
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::synced_with(&files);
        let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
        let packages = |path: &str| -> Vec<(String, Option<String>)> {
            let module = (lock.platforms[0].modules.iter())
                .find(|module| module.path == path)
                .unwrap();
            (module.packages.iter())
                .map(|package| {
                    (
                        package.coordinate.to_string(),
                        package.workspace_module.clone(),
                    )
                })
                .collect()
        };
        assert_eq!(
            packages("a/pom.xml"),
            [("org.test:selfe:1:jar".to_string(), None)],
            "{mode}"
        );
        assert_eq!(
            packages("app/pom.xml"),
            [(
                "org.test:selfe:1:jar".to_string(),
                Some("a/pom.xml".to_string())
            )],
            "{mode}"
        );
        assert_eq!(
            packages("b/pom.xml"),
            [("org.test:selfs:1:jar".to_string(), None)],
            "{mode}"
        );
        let m2 = tempfile::tempdir().expect("m2");
        let output = project.raeva(&["export-m2", "--m2-path", m2.path().to_str().unwrap()]);
        assert_status(&output, 0, mode);
        for (jar, bytes) in [
            ("selfe/1/selfe-1.jar", "selfe 1"),
            ("selfs/1/selfs-1.jar", "selfs 1"),
        ] {
            let path = m2.path().join("org/test").join(jar);
            assert_eq!(fs::read_to_string(path).unwrap(), bytes, "{mode}");
        }
        assert_status(&project.raeva(&["sync", "--offline", "--frozen"]), 0, mode);
        // The module and the repository's jar of its coordinates share a
        // purl and are two components: the jar keeps its hash under a
        // bom-ref of its own, and the module depends on it.
        let jar = crate::common::sha256_hex(b"selfe 1");
        for args in [
            &["sbom", "--offline"][..],
            &["sbom", "--offline", "--module", "a/pom.xml"],
        ] {
            let output = project.raeva(args);
            assert_status(&output, 0, &format!("{mode} {args:?}"));
            assert_eq!(project.raeva(args).stdout, output.stdout, "{mode} {args:?}");
            let bom: Value = serde_json::from_slice(&output.stdout).unwrap();
            let entries = (bom["components"].as_array().unwrap().iter())
                .chain([&bom["metadata"]["component"]])
                .filter(|component| {
                    (component["purl"].as_str()).is_some_and(|purl| purl.contains("/selfe@1"))
                });
            let mut refs: Vec<(&str, Option<&str>)> = entries
                .map(|component| {
                    let hash = component["hashes"][0]["content"].as_str();
                    (component["bom-ref"].as_str().unwrap(), hash)
                })
                .collect();
            refs.sort();
            assert_eq!(refs.len(), 2, "{mode} {args:?} {refs:?}");
            let (module, file) = (refs[0].0, refs[1].0);
            assert_eq!(refs[0].1, None, "{mode} {args:?} {refs:?}");
            assert_eq!(refs[1].1, Some(jar.as_str()), "{mode} {args:?} {refs:?}");
            assert_ne!(module, file);
            let depends = (bom["dependencies"].as_array().unwrap().iter())
                .find(|entry| entry["ref"].as_str() == Some(module))
                .unwrap();
            assert!(
                (depends["dependsOn"].as_array().unwrap().iter())
                    .any(|target| target.as_str() == Some(file)),
                "{mode} {args:?} {depends}"
            );
        }
    }
}

/// A module that takes its own jar from a repository has two components of
/// its coordinates, each with the licenses of its own model: the module's
/// from its POM, the jar's from the repository's POM the lock pins. Maven
/// builds the jar with the module's model, so the lock holds no parent of
/// that POM, and a parent it does not pin for another use leaves the jar
/// without licenses.
#[test]
fn a_module_and_its_own_repository_jar_keep_their_own_licenses() {
    let licensed =
        |name: &str| format!("<licenses><license><name>{name}</name></license></licenses>");
    let parent = "<parent><groupId>org.test</groupId><artifactId>corp</artifactId>\
                  <version>1</version></parent>";
    let license = |id: &str| serde_json::json!([{"license": {"id": id}}]);
    for (body, expected) in [
        (licensed("MIT"), license("MIT")),
        (parent.to_string(), Value::Null),
    ] {
        let mut files = vec![
            (
                "pom.xml".to_string(),
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>lib</module></modules></project>"
                    .to_string(),
            ),
            (
                "lib/pom.xml".to_string(),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>lib</artifactId><version>2</version>{}\
                     <repositories><repository><id>project-local</id>\
                     <url>file://${{project.basedir}}/../repository/</url></repository>\
                     </repositories><dependencies>{}</dependencies></project>",
                    licensed("Apache-2.0"),
                    dependency("lib", "[2,2]")
                ),
            ),
        ];
        files.extend(release("lib", "2", &body));
        files.extend(release(
            "corp",
            "1",
            &format!("<packaging>pom</packaging>{}", licensed("MIT")),
        ));
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::synced_with(&files);
        for args in [
            &["sbom", "--offline"][..],
            &["sbom", "--offline", "--module", "lib/pom.xml"],
        ] {
            let output = project.raeva(args);
            assert_status(&output, 0, &format!("{args:?}"));
            let bom: Value = serde_json::from_slice(&output.stdout).unwrap();
            let mut licenses: Vec<(String, Value)> = (bom["components"].as_array().unwrap())
                .iter()
                .chain([&bom["metadata"]["component"]])
                .filter(|component| {
                    (component["purl"].as_str()).is_some_and(|purl| purl.contains("/lib@2"))
                })
                .map(|component| {
                    let reference = component["bom-ref"].as_str().unwrap().to_string();
                    (reference, component["licenses"].clone())
                })
                .collect();
            licenses.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(licenses.len(), 2, "{args:?} {licenses:?}");
            assert!(!licenses[0].0.ends_with("#file"), "{args:?} {licenses:?}");
            assert_eq!(
                licenses[0].1,
                license("Apache-2.0"),
                "{args:?} {licenses:?}"
            );
            assert!(licenses[1].0.ends_with("#file"), "{args:?} {licenses:?}");
            assert_eq!(licenses[1].1, expected, "{args:?} {licenses:?}");
        }
    }
}

/// A module that takes its own jar from a repository keeps a lock that
/// is current without resolving it again, as the lock of any other
/// repository file, and a VEX statement about that jar in the module's
/// graph is about the jar alone.
#[test]
fn a_module_that_takes_its_own_jar_keeps_its_lock_and_vex() {
    let mut files = vec![(
        "pom.xml".to_string(),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>lib</artifactId><version>2</version>\
             <repositories><repository><id>project-local</id>\
             <url>file://${{project.basedir}}/repository/</url></repository>\
             </repositories><dependencies>{}</dependencies></project>",
            dependency("lib", "[2,2]")
        ),
    )];
    files.extend(release("lib", "2", ""));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let sync = project.raeva(&["sync", "--offline"]);
    assert_status(&sync, 0, "sync again");
    let said = String::from_utf8_lossy(&sync.stderr);
    assert!(!said.contains("Resolving dependencies"), "{said}");
    // A statement about the module's own coordinates in its graph is about
    // the repository's jar, not the module.
    let purl = "pkg:maven/org.test/lib@2";
    let vex = serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "urn:uuid:fixture",
        "author": "Fixture",
        "timestamp": "2026-10-01T00:00:00Z",
        "version": 1,
        "statements": [{
            "vulnerability": {"name": "CVE-2024-0001"},
            "products": [{"@id": purl, "subcomponents": [{"@id": purl}]}],
            "status": "affected",
            "action_statement": "upgrade",
        }],
    });
    let path = project.root().join("vex.json");
    fs::write(&path, vex.to_string()).unwrap();
    let output = project.raeva(&["sbom", "--offline", "--vex", path.to_str().unwrap()]);
    assert_status(&output, 0, "sbom --vex");
    let bom: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        bom["vulnerabilities"][0]["affects"],
        serde_json::json!([{"ref": format!("{purl}#file")}]),
        "{}",
        bom["vulnerabilities"]
    );
}

/// A system file of a module's coordinates has no POM, so its component
/// has no licenses, though the module's component has the module's.
#[test]
fn a_system_file_of_a_modules_coordinates_has_no_licenses() {
    let module = |artifact: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>2</version>{body}</project>"
        )
    };
    let project = Project::synced_with(&[
        (
            "pom.xml",
            &module(
                "root",
                "<packaging>pom</packaging><modules><module>lib</module>\
                 <module>app</module></modules>",
            ),
        ),
        (
            "lib/pom.xml",
            &module(
                "lib",
                "<licenses><license><name>Apache-2.0</name></license></licenses>",
            ),
        ),
        (
            "app/pom.xml",
            &module(
                "app",
                "<dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>lib</artifactId><version>2</version><scope>system</scope>\
                 <systemPath>${project.basedir}/vendor/lib.jar</systemPath></dependency>\
                 </dependencies>",
            ),
        ),
        ("app/vendor/lib.jar", "vendored"),
    ]);
    let output = project.raeva(&["sbom", "--offline"]);
    assert_status(&output, 0, "sbom");
    let bom: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut licenses: Vec<(String, Value)> = (bom["components"].as_array().unwrap().iter())
        .filter(|component| {
            (component["purl"].as_str()).is_some_and(|purl| purl.contains("/lib@2"))
        })
        .map(|component| {
            let reference = component["bom-ref"].as_str().unwrap().to_string();
            (reference, component["licenses"].clone())
        })
        .collect();
    licenses.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        licenses,
        [
            (
                "pkg:maven/org.test/lib@2".to_string(),
                serde_json::json!([{"license": {"id": "Apache-2.0"}}])
            ),
            ("pkg:maven/org.test/lib@2#file".to_string(), Value::Null),
        ],
    );
}

/// In Maven 3.10.0 `[alpha,alpha]` takes `target:alpha` without reading a
/// listing and keeps it over the nearer `target:0`, whose POM is pinned as
/// the loser's. Only depth first is `leaf:1.0` below the winner kept.
#[test]
fn a_singleton_range_that_beats_a_nearer_equal_version_pins_the_nearer_pom() {
    for (collector, depth_first) in [(None, false), (Some("df"), true)] {
        let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
        let root = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><repositories><repository>\
             <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
             </repository></repositories>{}</project>",
            deps(&[dependency("lib", "1"), dependency("target", "0")])
        );
        let mut files = vec![
            ("pom.xml".to_string(), root),
            (
                "raeva.toml".to_string(),
                "[lock]\nmaven = \"3.10\"\n".to_string(),
            ),
        ];
        if let Some(collector) = collector {
            files.push((
                ".mvn/maven.config".to_string(),
                format!("-Daether.dependencyCollector.impl={collector}\n"),
            ));
        }
        let range = dependency("target", "[alpha,alpha]");
        files.extend(release("lib", "1", &deps(&[range])));
        files.extend(release(
            "target",
            "alpha",
            &deps(&[dependency("leaf", "1.0")]),
        ));
        files.extend(release("target", "0", ""));
        files.extend(release("leaf", "1.0", ""));
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::synced_with(&files);
        let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
        let module = &lock.platforms[0].modules[0];
        let case = format!("{collector:?}: {:?}", module.support_poms);
        let locked = |gav: &str| {
            (module.packages.iter()).any(|package| package.coordinate.gav.to_string() == gav)
        };
        assert!(locked("org.test:target:alpha"), "{case}");
        assert!(!locked("org.test:target:0"), "{case}");
        assert_eq!(locked("org.test:leaf:1.0"), depth_first, "{case}");
        assert_eq!(module.support_poms, ["org.test:target:0"], "{case}");
    }
}

/// Depth first, Maven 3.9 reads `b:1` below `a:1` first, a version of the
/// range that loses, and `a:2` takes the children read there. Offline only
/// `a:2` is listed, and its `b:1` reads the POM of `lose:1`, which loses to
/// the nearer `lose:2`.
#[test]
fn a_loser_in_children_first_read_below_a_losing_range_version_is_exported() {
    let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
         </repository></repositories>{}</project>",
        deps(&[dependency("a", "[1,2]"), dependency("lose", "2")])
    );
    let mut files = vec![
        ("pom.xml".to_string(), root),
        (
            "raeva.toml".to_string(),
            "[lock]\nmaven = \"3.9\"\n".to_string(),
        ),
    ];
    files.extend(release("a", "1", &deps(&[dependency("b", "1")])));
    files.extend(release("a", "2", &deps(&[dependency("b", "1")])));
    files.push(listing("a", &["1", "2"]));
    files.extend(release("b", "1", &deps(&[dependency("lose", "1")])));
    files.extend(release("lose", "1", ""));
    files.extend(release("lose", "2", ""));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let m2 = tempfile::tempdir().expect("m2");
    let output = project.raeva(&["export-m2", "--m2-path", m2.path().to_str().unwrap()]);
    assert_status(&output, 0, "export");
    assert!(m2.path().join("org/test/lose/1/lose-1.pom").exists());
}

/// Maven 3.9.12 and 3.10.0 fail on a descriptor they cannot read, whether
/// or not its node wins: the `c:2` below `x`, which loses to the nearer
/// `c:1`, names a parent no repository has.
#[test]
fn a_losing_dependency_whose_parent_is_missing_fails() {
    for mode in ["3.9", "3.10"] {
        let mut files = nearer_loser_files(mode, "[1.0,3.0)");
        let c2 = "repository/org/test/c/2/c-2.pom";
        let pom = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
                   <artifactId>nope</artifactId><version>1</version></parent>\
                   <artifactId>c</artifactId><version>2</version></project>";
        for (path, text) in files.iter_mut() {
            if path == c2 {
                *text = pom.to_string();
            } else if path == &format!("{c2}.sha256") {
                *text = crate::common::sha256_hex(pom.as_bytes());
            }
        }
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::with(&files);
        let output = project.raeva(&["sync", "--offline"]);
        assert_status(&output, 5, mode);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("org.test:nope:1") && stderr.contains("through org.test:x:1\n"),
            "{mode}: {stderr}"
        );
    }
}

/// An unchanged lock passes `--frozen` when a range it chose has a newer
/// release and so do ranges whose versions Maven read without choosing
/// one: `p`'s range on `a` lost to the nearer `a:1` and read `a:2` and its
/// parent, and `c:2`, which `w`'s `[1]` evicts, declares a range on `lib`
/// that the graph has no version of. The lock records those ranges, and
/// the replay offers them the versions they listed when it was written.
#[test]
fn frozen_replays_a_losing_range_at_the_versions_it_saw() {
    let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
    let root = format!(
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>app</artifactId><version>1</version>
  <repositories>
    <repository><id>project-local</id><url>file://${{project.basedir}}/repository/</url></repository>
  </repositories>
  {}
</project>
"#,
        deps(&[
            dependency("a", "1"),
            dependency("p", "1"),
            dependency("x", "1"),
            dependency("y", "1"),
            dependency("ext", "[1.0,2)"),
        ])
    );
    let parent = |artifact: &str| {
        format!(
            "<parent><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version></parent>"
        )
    };
    for mode in ["3.9", "3.10"] {
        let mut files = vec![
            ("pom.xml".to_string(), root.clone()),
            (
                "raeva.toml".to_string(),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            ),
        ];
        files.extend(ext_releases(&["1.0"]));
        files.push(ext_listing(&["1.0"]));
        files.extend(release("a", "1", ""));
        files.extend(release("a", "2", &parent("parent")));
        files.extend(release("parent", "1", "<packaging>pom</packaging>"));
        files.push(listing("a", &["1", "2"]));
        files.extend(release("p", "1", &deps(&[dependency("a", "[1,3)")])));
        files.extend(release("x", "1", &deps(&[dependency("c", "2")])));
        files.extend(release("y", "1", &deps(&[dependency("w", "1")])));
        files.extend(release("w", "1", &deps(&[dependency("c", "[1]")])));
        files.extend(release("c", "1", ""));
        files.extend(release("c", "2", &deps(&[dependency("lib", "[2,3)")])));
        files.extend(release("lib", "2.0", ""));
        files.push(listing("lib", &["1.0", "2.0"]));
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::synced_with(&files);
        let lock_path = project.root().join("raeva.lock");
        let written = fs::read_to_string(&lock_path).unwrap();
        let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
        let evicted: Vec<_> = (lock.platforms[0].modules[0].evicted_ranges.iter())
            .map(|range| {
                format!(
                    "{}:{} {} {}",
                    range.group,
                    range.artifact,
                    range.range,
                    range.versions.join(" ")
                )
            })
            .collect();
        assert_eq!(
            evicted,
            ["org.test:a [1,3) 1 2", "org.test:lib [2,3) 2.0"],
            "{mode}"
        );
        assert!(written.contains("org.test:c:1\\t"), "{mode}: {written}");
        let document: toml::Value = toml::from_str(&written).unwrap();
        crate::schemas::assert_schema_valid(
            &crate::schemas::validator(crate::schemas::RAEVA_LOCK_SCHEMA),
            &serde_json::to_value(document).unwrap(),
        );

        // Newer releases: `ext` moves its range unless replayed, and `a:2.5`
        // and `lib:2.1` name a parent no repository has.
        let mut newer = ext_releases(&["1.1"]);
        newer.push(ext_listing(&["1.0", "1.1"]));
        newer.extend(release("a", "2.5", &parent("gone")));
        newer.push(listing("a", &["1", "2", "2.5"]));
        newer.extend(release("lib", "2.1", &parent("gone")));
        newer.push(listing("lib", &["1.0", "2.0", "2.1"]));
        for (path, text) in newer {
            let path = project.root().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        for args in [
            &["sync", "--frozen"][..],
            &["sync", "--frozen", "--offline"],
        ] {
            let output = project.raeva(args);
            assert_success(&output, &format!("{mode} {args:?} keeps the lock"));
            assert_eq!(
                fs::read_to_string(&lock_path).unwrap(),
                written,
                "{mode} {args:?}"
            );
        }
    }
}

/// A reactor of `modules`, each `(name, dependencies)`, that read
/// `repository/` under the id `project-local`.
fn plain_reactor(modules: &[(&str, String)]) -> Vec<(String, String)> {
    let names: String = (modules.iter())
        .map(|(name, _)| format!("<module>{name}</module>"))
        .collect();
    let mut files = vec![(
        "pom.xml".to_string(),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules>{names}</modules></project>"
        ),
    )];
    for (name, dependencies) in modules {
        files.push((
            format!("{name}/pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version></parent>\
                 <artifactId>{name}</artifactId><repositories><repository>\
                 <id>project-local</id><url>file://${{project.basedir}}/../repository/</url>\
                 </repository></repositories><dependencies>{dependencies}</dependencies>\
                 </project>"
            ),
        ));
    }
    files
}

/// Maven 3.9.12 takes `RELEASE` from the `<release>` of the metadata, 1.0
/// here though 2.0 is listed, and `b` declares 2.0. raeva.lock records the
/// marker `a` read, and export-m2 writes it rather than the greatest
/// version it lists, which `mvn -o` would take for `a`. It lists no 2.0,
/// which `b` pins exactly.
#[test]
fn export_writes_the_release_marker_the_resolution_read() {
    let mut files = plain_reactor(&[
        ("a", dependency("lib", "RELEASE")),
        ("b", dependency("lib", "2.0")),
    ]);
    files.extend(release("lib", "2.0", ""));
    files.push((
        "repository/org/test/lib/maven-metadata.xml".to_string(),
        "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId><versioning>\
         <latest>1.0</latest><release>1.0</release><versions><version>1.0</version>\
         <version>2.0</version></versions><lastUpdated>20240101000000</lastUpdated>\
         </versioning></metadata>"
            .to_string(),
    ));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let read: Vec<String> = (lock.platforms[0].modules.iter())
        .flat_map(|module| {
            (module.metadata_versions.iter()).map(|read| {
                let kind = read.kind.as_str();
                format!(
                    "{} {}:{} {kind} {}",
                    module.path, read.group, read.artifact, read.version
                )
            })
        })
        .collect();
    assert_eq!(read, ["a/pom.xml org.test:lib release 1.0"]);

    let output = project.raeva(&["export-m2", "--m2-path", project.m2().to_str().unwrap()]);
    assert_success(&output, "export-m2");
    let list = project
        .m2()
        .join("org/test/lib/maven-metadata-project-local.xml");
    let list = fs::read_to_string(list).unwrap();
    assert!(list.contains("<release>1.0</release>"), "{list}");
    assert!(!list.contains("<latest>"), "{list}");
    assert!(!list.contains("<version>2.0</version>"), "{list}");
}

/// An unchanged lock passes `--frozen` after `<release>` moved: the replay
/// caps `a`'s RELEASE at the `1.0` the lock records, not at the `2.0` `b`
/// locks.
#[test]
fn frozen_caps_a_moved_release_at_the_recorded_marker() {
    let metadata = |release: &str, versions: &[&str]| {
        let versions: String = (versions.iter())
            .map(|version| format!("<version>{version}</version>"))
            .collect();
        (
            "repository/org/test/lib/maven-metadata.xml".to_string(),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId><versioning>\
                 <release>{release}</release><versions>{versions}</versions>\
                 <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
            ),
        )
    };
    let mut files = plain_reactor(&[
        ("a", dependency("lib", "RELEASE")),
        ("b", dependency("lib", "2.0")),
    ]);
    files.extend(release("lib", "1.0", ""));
    files.extend(release("lib", "2.0", ""));
    files.push(metadata("1.0", &["1.0", "2.0"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock_path = project.root().join("raeva.lock");
    let written = fs::read_to_string(&lock_path).unwrap();
    assert!(
        written.contains("org.test:lib\\trelease\\t1.0"),
        "{written}"
    );

    let mut newer = release("lib", "3.0", "");
    newer.push(metadata("3.0", &["1.0", "2.0", "3.0"]));
    for (path, text) in newer {
        let path = project.root().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let output = project.raeva(&["sync", "--frozen"]);
    assert_success(&output, "frozen after the release moved");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), written);
}

/// `a` and `b` read RELEASE in two repositories, `1.0` and `2.0`. After
/// `a`'s moves, `--frozen` caps it at the `1.0` its repository still lists,
/// not at `b`'s `2.0`, which it does not.
#[test]
fn frozen_caps_a_moved_release_at_the_marker_its_repository_lists() {
    let metadata = |release: &str, versions: &[&str]| {
        let versions: String = (versions.iter())
            .map(|version| format!("<version>{version}</version>"))
            .collect();
        format!(
            "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId><versioning>\
             <release>{release}</release><versions>{versions}</versions>\
             <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
        )
    };
    let mut files = plain_reactor(&[
        ("a", dependency("lib", "RELEASE")),
        ("b", dependency("lib", "RELEASE")),
    ]);
    for (path, text) in &mut files {
        if path == "b/pom.xml" {
            *text = text
                .replace("<id>project-local</id>", "<id>other</id>")
                .replace("../repository/", "../repository2/");
        }
    }
    files.extend(release("lib", "1.0", ""));
    files.push((
        "repository/org/test/lib/maven-metadata.xml".to_string(),
        metadata("1.0", &["1.0"]),
    ));
    for (path, text) in release("lib", "2.0", "") {
        files.push((path.replacen("repository/", "repository2/", 1), text));
    }
    files.push((
        "repository2/org/test/lib/maven-metadata.xml".to_string(),
        metadata("2.0", &["2.0"]),
    ));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock_path = project.root().join("raeva.lock");
    let written = fs::read_to_string(&lock_path).unwrap();

    let mut newer = release("lib", "1.5", "");
    newer.push((
        "repository/org/test/lib/maven-metadata.xml".to_string(),
        metadata("1.5", &["1.0", "1.5"]),
    ));
    for (path, text) in newer {
        let path = project.root().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let output = project.raeva(&["sync", "--frozen"]);
    assert_success(&output, "frozen after a's release moved");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), written);
}

/// RELEASE takes a `<release>` that names a SNAPSHOT, as Maven does, and
/// after `<release>` moves `--frozen` caps it at that recorded marker.
#[test]
fn frozen_caps_a_moved_release_at_a_recorded_snapshot_marker() {
    let metadata = |release: &str, versions: &str| {
        (
            "repository/org/test/lib/maven-metadata.xml".to_string(),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId><versioning>\
                 <release>{release}</release><versions>{versions}</versions>\
                 <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
            ),
        )
    };
    let mut files = plain_reactor(&[("a", dependency("lib", "RELEASE"))]);
    files.extend(release("lib", "1.0-SNAPSHOT", ""));
    files.push(metadata("1.0-SNAPSHOT", "<version>1.0-SNAPSHOT</version>"));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock_path = project.root().join("raeva.lock");
    let written = fs::read_to_string(&lock_path).unwrap();
    assert!(
        written.contains("org.test:lib\\trelease\\t1.0-SNAPSHOT"),
        "{written}"
    );

    let mut newer = release("lib", "2.0", "");
    newer.push(metadata(
        "2.0",
        "<version>1.0-SNAPSHOT</version><version>2.0</version>",
    ));
    for (path, text) in newer {
        let path = project.root().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let output = project.raeva(&["sync", "--frozen"]);
    assert_success(&output, "frozen after the release moved");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), written);
}

/// `a`'s LATEST finds no `<latest>` in its repository and takes its
/// `<release>` `1.0`; `b`'s finds `<latest>2.0</latest>` in another. Each is
/// recorded as the `<latest>` `mvn -o` reads for LATEST, so the two
/// conflict and export-m2 refuses, where writing `<release>1.0</release>`
/// beside `<latest>2.0</latest>` would give `a` `2.0` offline.
#[test]
fn export_refuses_a_latest_that_fell_back_to_release_beside_another_latest() {
    let mut files = plain_reactor(&[
        ("a", dependency("lib", "LATEST")),
        ("b", dependency("lib", "LATEST")),
    ]);
    for (path, text) in &mut files {
        if path == "b/pom.xml" {
            *text = text
                .replace("<id>project-local</id>", "<id>other</id>")
                .replace("../repository/", "../repository2/");
        }
    }
    let metadata = |markers: &str, version: &str| {
        format!(
            "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId><versioning>\
             {markers}<versions><version>{version}</version></versions>\
             <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
        )
    };
    files.extend(release("lib", "1.0", ""));
    files.push((
        "repository/org/test/lib/maven-metadata.xml".to_string(),
        metadata("<release>1.0</release>", "1.0"),
    ));
    for (path, text) in release("lib", "2.0", "") {
        files.push((path.replacen("repository/", "repository2/", 1), text));
    }
    files.push((
        "repository2/org/test/lib/maven-metadata.xml".to_string(),
        metadata("<latest>2.0</latest><release>2.0</release>", "2.0"),
    ));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let read: Vec<String> = (lock.platforms[0].modules.iter())
        .flat_map(|module| {
            (module.metadata_versions.iter())
                .map(|read| format!("{} {} {}", module.path, read.kind.as_str(), read.version))
        })
        .collect();
    assert_eq!(read, ["a/pom.xml latest 1.0", "b/pom.xml latest 2.0"]);

    let m2 = project.m2();
    let output = project.raeva(&["--json", "export-m2", "--m2-path", m2.to_str().unwrap()]);
    assert_status(&output, 3, "export-m2 over two LATEST markers");
    let envelope = envelope(&output);
    assert_eq!(envelope["code"], "LOCKFILE_INVALID", "{envelope}");
}

/// `a`'s range takes one of `1.0` and `1.0-ga`, which compare equal, in the
/// order of every version the repository lists, and `b` and `c` lock the
/// two exactly. raeva.lock does not record the listing that put them in
/// order, so `mvn -o` could take the other one for `a` from a list naming
/// both; the export lists only the one `a` took.
#[test]
fn export_lists_the_one_of_equal_spellings_a_range_took() {
    let mut files = plain_reactor(&[
        ("a", dependency("lib", "[1,2)")),
        ("b", dependency("lib", "1.0-ga")),
        ("c", dependency("lib", "1.0")),
    ]);
    files.extend(release("lib", "1.0-ga", ""));
    files.push(listing("lib", &["1.0", "1.0-ga"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let a = &lock.platforms[0].modules[0];
    assert_eq!(a.path, "a/pom.xml");
    assert!(
        (a.metadata_versions.iter())
            .any(|read| read.kind == rv_lock::MetadataVersionKind::Range && read.artifact == "lib"),
        "{:?}",
        a.metadata_versions
    );

    let took = (a.metadata_versions.iter())
        .find(|read| read.kind == rv_lock::MetadataVersionKind::Range)
        .map(|read| read.version.clone())
        .unwrap();
    let m2 = export_to_m2(&project);
    assert_eq!(
        export_listings(&m2, "lib"),
        [("project-local".to_string(), vec![took])].into()
    );
}

/// A reactor of `a` and `b` in `order`, resolved as Maven `maven`. `a`
/// reads `repo-a` and asks `s:2` and `w:1`, whose `s:1` loses; `repo-a`
/// serves `s:1` with a POM whose body is `s_body`. `b` reads `repo-b` and
/// asks `s:1`, whose jar `repo-b` serves with the POM `b_pom`, or without
/// one.
fn losing_pom_reactor(order: [&str; 2], maven: &str, s_body: &str, b_pom: Option<&str>) -> Project {
    let module = |name: &str, repo: &str, dependencies: &[String]| {
        (
            format!("{name}/pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version></parent>\
                 <artifactId>{name}</artifactId><repositories><repository><id>{repo}</id>\
                 <url>file://${{project.basedir}}/../{repo}/</url></repository></repositories>\
                 <dependencies>{}</dependencies></project>",
                dependencies.concat()
            ),
        )
    };
    let [first, second] = order;
    let mut files = vec![
        (
            "pom.xml".to_string(),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>{first}</module><module>{second}</module></modules></project>"
            ),
        ),
        (
            "raeva.toml".to_string(),
            format!("[lock]\nmaven = \"{maven}\"\n"),
        ),
        module("a", "repo-a", &[dependency("s", "2"), dependency("w", "1")]),
        module("b", "repo-b", &[dependency("s", "1")]),
    ];
    let in_repo = |repo: &str, published: Vec<(String, String)>| -> Vec<(String, String)> {
        let prefix = format!("{repo}/");
        (published.into_iter())
            .map(|(path, text)| (path.replacen("repository/", &prefix, 1), text))
            .collect()
    };
    let w = format!("<dependencies>{}</dependencies>", dependency("s", "1"));
    files.extend(in_repo("repo-a", release("s", "2", "")));
    files.extend(in_repo("repo-a", release("s", "1", s_body)));
    files.extend(in_repo("repo-a", release("w", "1", &w)));
    files.extend(in_repo("repo-a", release("x", "1", "")));
    files.extend(
        in_repo("repo-b", release("s", "1", b_pom.unwrap_or_default()))
            .into_iter()
            .filter(|(path, _)| b_pom.is_some() || !path.contains(".pom")),
    );
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    Project::with(&files)
}

/// `s:1` loses in `a`, which reads its POM from `repo-a`, and `b` resolves
/// it from `repo-b`, which serves no POM. Maven 3.9.12 and 3.10.0 build
/// `a = s:2, w:1` and `b = s:1` in either order and with `-T 2`. In either
/// mode, the lock pins the POM `a` read as a support POM beside `b`'s row,
/// which pins none, `--frozen` holds it, and the export labels the jar with
/// `repo-b` and the POM with `repo-a` alone, so `mvn -o` reads the POM only
/// for `a`, as Maven does online.
#[test]
fn a_losing_pom_beside_a_row_without_one_is_locked() {
    for maven in ["3.9", "3.10"] {
        for order in [["a", "b"], ["b", "a"]] {
            let project = losing_pom_reactor(order, maven, "", None);
            let case = format!("Maven {maven}, modules {order:?}");
            assert_success(&project.raeva(&["sync"]), &case);
            let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
            let platform = &lock.platforms[0];
            let row = (platform.artifacts.iter())
                .find(|row| row.coordinate.gav.to_string() == "org.test:s:1")
                .expect("s:1 row");
            assert_eq!(row.pom_sha256, None, "{case}");
            assert!(
                (platform.support_poms).contains_key("org.test:s:1"),
                "{case}: {:?}",
                platform.support_poms
            );
            assert_success(
                &project.raeva(&["sync", "--frozen"]),
                &format!("{case}: --frozen"),
            );
            let m2 = export_to_m2(&project);
            let mut labels: Vec<String> =
                (fs::read_to_string(m2.join("org/test/s/1/_remote.repositories")).unwrap())
                    .lines()
                    .filter(|line| !line.starts_with('#'))
                    .map(str::to_string)
                    .collect();
            labels.sort();
            assert_eq!(labels, ["s-1.jar>repo-b=", "s-1.pom>repo-a="], "{case}");
        }
    }
}

/// The losing `s:1`'s POM declares `x:1`. Maven 3.9 reuses one reading of
/// it for both modules, so the order of the build decides whether `b`
/// gets `x:1`, and the 3.9 mode refuses with exit 5, naming both modules.
/// Maven 3.10.0 reads each module's own and builds `b = s:1` in either
/// order and with `-T 2`, and the 3.10 mode locks that.
#[test]
fn a_losing_pom_with_dependencies_beside_a_row_without_one() {
    let body = format!("<dependencies>{}</dependencies>", dependency("x", "1"));
    for order in [["a", "b"], ["b", "a"]] {
        let project = losing_pom_reactor(order, "3.9", &body, None);
        let output = project.raeva(&["--json", "sync"]);
        assert_status(&output, 5, "Maven 3.9");
        let envelope = envelope(&output);
        assert_eq!(envelope["code"], "RESOLUTION", "{envelope}");
        let error = envelope["error"].as_str().unwrap();
        for module in ["module a/pom.xml", "module b/pom.xml"] {
            assert!(error.contains(module), "{error}");
        }

        let project = losing_pom_reactor(order, "3.10", &body, None);
        assert_success(&project.raeva(&["sync"]), "Maven 3.10");
        let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
        let b = (lock.platforms[0].modules.iter())
            .find(|module| module.path == "b/pom.xml")
            .unwrap();
        let held: Vec<String> = (b.packages.iter())
            .map(|package| package.coordinate.to_string())
            .collect();
        assert_eq!(held, ["org.test:s:1:jar"], "{order:?}");
        assert_success(&project.raeva(&["sync", "--frozen"]), "Maven 3.10 --frozen");

        // The support POM moved to `repo-b` would be labeled for `b`, which
        // would read `x:1` offline: --frozen refuses the edit.
        let path = project.root().join("raeva.lock");
        let text = fs::read_to_string(&path).unwrap();
        let block = text.find("[[platforms.support_poms]]").unwrap();
        let (head, tail) = text.split_at(block);
        let moved = tail.replacen("repo_url = \"./repo-a/\"", "repo_url = \"./repo-b/\"", 1);
        assert_ne!(moved, tail);
        fs::write(&path, format!("{head}{moved}")).unwrap();
        assert_status(
            &project.raeva(&["sync", "--frozen"]),
            7,
            "Maven 3.10 --frozen, support POM moved",
        );
    }
}

/// `repo-b` serves `s:1` with another POM than the one `a` read for the
/// losing `s:1` from `repo-a`. Both are POM files at one local-repository
/// path, so one lockfile cannot pin both: either mode refuses with exit 5,
/// naming both modules and no repository URL.
#[test]
fn a_losing_pom_beside_a_row_with_other_bytes_is_refused() {
    for maven in ["3.9", "3.10"] {
        for order in [["a", "b"], ["b", "a"]] {
            let project =
                losing_pom_reactor(order, maven, "", Some("<description>b</description>"));
            let output = project.raeva(&["--json", "sync"]);
            let case = format!("Maven {maven}, modules {order:?}");
            assert_status(&output, 5, &case);
            let envelope = envelope(&output);
            assert_eq!(envelope["code"], "RESOLUTION", "{case}: {envelope}");
            let error = envelope["error"].as_str().unwrap();
            for module in ["module a/pom.xml", "module b/pom.xml"] {
                assert!(error.contains(module), "{case}: {error}");
            }
            assert!(!error.contains("file:"), "{case}: {error}");
        }
    }
}

/// Beside `a`'s losing `s:1` and `b`'s row without a POM, `c` resolves
/// `s:1`'s jar from `repo-c`, which serves an empty POM with other bytes.
/// The refusal names `a` and `c`, which read the two POMs, not `b`.
#[test]
fn a_refused_pom_conflict_names_the_modules_that_read_each_pom() {
    for maven in ["3.9", "3.10"] {
        let project = losing_pom_reactor(["a", "b"], maven, "", None);
        let root = project.root();
        let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
        let pom = pom.replace("<module>b</module>", "<module>b</module><module>c</module>");
        fs::write(root.join("pom.xml"), pom).unwrap();
        let b = fs::read_to_string(root.join("b/pom.xml")).unwrap();
        fs::create_dir_all(root.join("c")).unwrap();
        let c = (b.replace("<artifactId>b</artifactId>", "<artifactId>c</artifactId>"))
            .replace("repo-b", "repo-c");
        fs::write(root.join("c/pom.xml"), c).unwrap();
        for (path, text) in release("s", "1", "<description>c</description>") {
            let path = root.join(path.replacen("repository/", "repo-c/", 1));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        let output = project.raeva(&["--json", "sync"]);
        assert_status(&output, 5, maven);
        let envelope = envelope(&output);
        let error = envelope["error"].as_str().unwrap();
        assert!(
            error.contains("module a/pom.xml") && error.contains("module c/pom.xml"),
            "{maven}: {error}"
        );
        assert!(!error.contains("module b/pom.xml"), "{maven}: {error}");
    }
}

/// `repo-a` and `repo-b` serve other bytes for `parent:1`, the parent of
/// `api:1`, which manages `lib` at 1.0 and 2.0. `lib:1.0`'s own parent,
/// `lp:1`, differs too. Maven 3.9.12 and 3.10.0 read a parent or an
/// imported BOM once for the whole build: the first module to read it, a
/// project build before any graph and graphs in the sorted order, decides
/// the bytes every module gets, though another module reads only the other
/// repository. raeva locks the same, and the lock stays as it is on a sync,
/// `--frozen` and `--offline`.
#[test]
fn a_parent_two_repositories_serve_differently_comes_from_the_first_reader() {
    let module = |name: &str, repo: &str, head: &str, dependencies: &str| {
        let head = match head {
            "" => "<parent><groupId>org.test</groupId><artifactId>root</artifactId>\
                   <version>1</version></parent>"
                .to_string(),
            head => head.to_string(),
        };
        (
            format!("{name}/pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion>{head}<artifactId>{name}</artifactId>\
                 <repositories><repository><id>{repo}</id>\
                 <url>file://${{project.basedir}}/../{repo}/</url></repository></repositories>\
                 <dependencies>{dependencies}</dependencies></project>"
            ),
        )
    };
    let in_repo = |repo: &str, published: Vec<(String, String)>| -> Vec<(String, String)> {
        (published.into_iter())
            .map(|(path, text)| (path.replacen("repository/", &format!("{repo}/"), 1), text))
            .collect()
    };
    let parent = |repo: &str| {
        let version = if repo == "repo-a" { "1.0" } else { "2.0" };
        format!(
            "<packaging>pom</packaging><dependencyManagement><dependencies>{}\
             </dependencies></dependencyManagement>",
            dependency("lib", version)
        )
    };
    let reactor = |maven: &str, order: [&str; 2], a: (&str, &str), b: (&str, &str)| {
        let [first, second] = order;
        let mut files = vec![
            (
                "pom.xml".to_string(),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                     <modules><module>{first}</module><module>{second}</module></modules></project>"
                ),
            ),
            (
                "raeva.toml".to_string(),
                format!("[lock]\nmaven = \"{maven}\"\n"),
            ),
            module("a", "repo-a", a.0, a.1),
            module("b", "repo-b", b.0, b.1),
        ];
        let api = "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
                   <version>1</version></parent><dependencies><dependency>\
                   <groupId>org.test</groupId><artifactId>lib</artifactId></dependency>\
                   </dependencies>";
        let lp = "<parent><groupId>org.test</groupId><artifactId>lp</artifactId>\
                  <version>1</version></parent>";
        for repo in ["repo-a", "repo-b"] {
            let described = format!("<packaging>pom</packaging><description>{repo}</description>");
            files.extend(in_repo(repo, release("parent", "1", &parent(repo))));
            files.extend(in_repo(repo, release("lp", "1", &described)));
            files.extend(in_repo(repo, release("api", "1", api)));
            files.extend(in_repo(repo, release("lib", "1.0", lp)));
            files.extend(in_repo(repo, release("lib", "2.0", "")));
        }
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        Project::with(&files)
    };
    let api = dependency("api", "1");
    let on_a = format!(
        "{api}<dependency><groupId>org.test</groupId><artifactId>a</artifactId>\
         <version>1</version><type>pom</type></dependency>"
    );
    let own_parent = "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
                      <version>1</version><relativePath/></parent><groupId>org.test</groupId>\
                      <version>1</version>";
    let a_pom = "<packaging>pom</packaging>";
    let import = "<parent><groupId>org.test</groupId><artifactId>root</artifactId>\
                  <version>1</version></parent><dependencyManagement><dependencies>\
                  <dependency><groupId>org.test</groupId><artifactId>parent</artifactId>\
                  <version>1</version><type>pom</type><scope>import</scope></dependency>\
                  </dependencies></dependencyManagement>";
    let lib = "<dependency><groupId>org.test</groupId><artifactId>lib</artifactId></dependency>";
    for maven in ["3.9", "3.10"] {
        for (case, order, a, b, winner) in [
            (
                "a first",
                ["a", "b"],
                ("", api.as_str()),
                ("", api.as_str()),
                "repo-a",
            ),
            (
                "b first",
                ["b", "a"],
                ("", api.as_str()),
                ("", api.as_str()),
                "repo-b",
            ),
            (
                "b on a",
                ["b", "a"],
                ("", api.as_str()),
                ("", on_a.as_str()),
                "repo-a",
            ),
            (
                "b's parent",
                ["a", "b"],
                ("", api.as_str()),
                (own_parent, api.as_str()),
                "repo-b",
            ),
            (
                "imports",
                ["a", "b"],
                (import, lib),
                (import, lib),
                "repo-a",
            ),
        ] {
            let case = format!("Maven {maven}, {case}");
            let project = reactor(maven, order, a, b);
            let edit = |module: &str, from: &str, to: &str| {
                let path = project.root().join(module).join("pom.xml");
                let pom = fs::read_to_string(&path).unwrap();
                fs::write(&path, pom.replace(from, to)).unwrap();
            };
            if case.ends_with("b on a") {
                let packaged = format!("<artifactId>a</artifactId>{a_pom}");
                edit("a", "<artifactId>a</artifactId>", &packaged);
            }
            // Maven looks a project's parent up in its repositories as
            // written, before `${project.basedir}` is set.
            if case.ends_with("b's parent") {
                let url = format!("file://{}/repo-b/", project.root().display());
                edit("b", "file://${project.basedir}/../repo-b/", &url);
            }
            assert_success(&project.raeva(&["sync"]), &case);
            let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
            let platform = &lock.platforms[0];
            let lib = if winner == "repo-a" { "1.0" } else { "2.0" };
            for module in &platform.modules {
                if module.path == "pom.xml" {
                    continue;
                }
                let held: Vec<String> = (module.packages.iter())
                    .map(|package| package.coordinate.gav.to_string())
                    .filter(|gav| gav.starts_with("org.test:lib:"))
                    .collect();
                assert_eq!(
                    held,
                    [format!("org.test:lib:{lib}")],
                    "{case}: {}",
                    module.path
                );
            }
            let read = |artifact: &str| {
                let path = project
                    .root()
                    .join(format!("{winner}/org/test/{artifact}/1/{artifact}-1.pom"));
                crate::common::sha256_hex(&fs::read(path).unwrap())
            };
            let pinned = |coordinate: &str| {
                (platform.support_poms.get(coordinate)).map(|pom| pom.sha256.to_string())
            };
            assert_eq!(pinned("org.test:parent:1"), Some(read("parent")), "{case}");
            if winner == "repo-a" {
                assert_eq!(pinned("org.test:lp:1"), Some(read("lp")), "{case}");
            }
            let written = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
            for args in [&["sync"][..], &["sync", "--frozen"], &["sync", "--offline"]] {
                assert_success(&project.raeva(args), &format!("{case}: {args:?}"));
                let again = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
                assert_eq!(again, written, "{case}: {args:?}");
            }
            let m2 = export_to_m2(&project);
            let labels =
                fs::read_to_string(m2.join("org/test/parent/1/_remote.repositories")).unwrap();
            assert!(
                labels.contains(&format!("parent-1.pom>{winner}=")),
                "{case}: {labels}"
            );
        }
    }
}

/// `a` asks `pick` `[1.0-alpha-1,3.0)`, and `other:1.0` pins
/// `[1.0-alpha-1]`. The repository lists `1.0-alpha-1`, `1.0-a1` and `2.0`,
/// and the first two compare equal. Maven 3.9.12 takes `1.0-a1` for `a`'s
/// range, which loses its highest version, and reads `1.0-alpha-1`'s POM on
/// the way, so the lock pins both POMs. The export lists the spelling the
/// lock holds for that range: `mvn -o` takes `1.0-a1` from it, and fails on
/// the missing jar of `1.0-alpha-1` from a list that names only that.
#[test]
fn export_lists_the_locked_spelling_for_a_losing_range() {
    let mut files = plain_reactor(&[(
        "a",
        [
            dependency("pick", "[1.0-alpha-1,3.0)"),
            dependency("other", "1.0"),
        ]
        .concat(),
    )]);
    let pin = format!(
        "<dependencies>{}</dependencies>",
        dependency("pick", "[1.0-alpha-1]")
    );
    files.extend(release("other", "1.0", &pin));
    for version in ["1.0-alpha-1", "1.0-a1", "2.0"] {
        files.extend(release("pick", version, ""));
    }
    files.push(listing("pick", &["1.0-alpha-1", "1.0-a1", "2.0"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let a = &lock.platforms[0].modules[0];
    assert_eq!(a.path, "a/pom.xml");
    let held: Vec<&str> = (a.packages.iter())
        .filter(|package| package.coordinate.artifact_id() == "pick")
        .map(|package| package.coordinate.version())
        .collect();
    assert_eq!(held, ["1.0-a1"]);
    assert_eq!(a.support_poms, ["org.test:pick:1.0-alpha-1"]);

    let m2 = export_to_m2(&project);
    assert_eq!(
        export_listings(&m2, "pick"),
        [("project-local".to_string(), vec!["1.0-a1".to_string()])].into()
    );
}

/// The losing range of [`export_lists_the_locked_spelling_for_a_losing_range`]
/// beside a module `b` that pins `pick:1.0-alpha-1` exactly, and with
/// `1.0-a1` published without a POM. In both, Maven 3.9.12 gives `a`
/// `1.0-a1` online, and `b` `1.0-alpha-1`. The export lists the spelling
/// `a`, which recorded the range, holds, whether or not it has a POM.
#[test]
fn export_lists_the_spelling_the_range_module_holds() {
    for (two, pom) in [(true, true), (false, false)] {
        let mut modules = vec![(
            "a",
            [
                dependency("pick", "[1.0-alpha-1,3.0)"),
                dependency("other", "1.0"),
            ]
            .concat(),
        )];
        if two {
            modules.push(("b", dependency("pick", "1.0-alpha-1")));
        }
        let mut files = plain_reactor(&modules);
        let pin = format!(
            "<dependencies>{}</dependencies>",
            dependency("pick", "[1.0-alpha-1]")
        );
        files.extend(release("other", "1.0", &pin));
        for version in ["1.0-alpha-1", "1.0-a1", "2.0"] {
            files.extend(
                (release("pick", version, "").into_iter())
                    .filter(|(path, _)| pom || !path.contains("pick-1.0-a1.pom")),
            );
        }
        files.push(listing("pick", &["1.0-alpha-1", "1.0-a1", "2.0"]));
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::with(&files);
        assert_success(&project.raeva(&["sync"]), "sync");
        let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
        let held = |path: &str| -> Vec<String> {
            let module = (lock.platforms[0].modules.iter())
                .find(|module| module.path == path)
                .unwrap();
            (module.packages.iter())
                .filter(|package| package.coordinate.artifact_id() == "pick")
                .map(|package| package.coordinate.version().to_string())
                .collect()
        };
        assert_eq!(held("a/pom.xml"), ["1.0-a1"], "two={two} pom={pom}");
        if two {
            assert_eq!(held("b/pom.xml"), ["1.0-alpha-1"]);
        }
        let m2 = export_to_m2(&project);
        assert_eq!(
            export_listings(&m2, "pick"),
            [("project-local".to_string(), vec!["1.0-a1".to_string()])].into(),
            "two={two} pom={pom}"
        );
    }
}

/// agy's MF-06 project: on linux a profile adds `repo-a`, which serves
/// `s:1`'s jar and no POM; on windows `repo-b` serves the same jar and a
/// POM, whose `<project>` holds `s_body`. Both serve `extra:1`.
fn mf06_project_with(s_body: &str) -> Project {
    let profile = |id: &str, family: &str, repo: &str| {
        format!(
            "<profile><id>{id}</id><activation><os><family>{family}</family></os></activation>\
             <repositories><repository><id>{repo}</id>\
             <url>file://${{project.basedir}}/{repo}/</url></repository></repositories></profile>"
        )
    };
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><dependencies>{}</dependencies>\
         <profiles>{}{}</profiles></project>",
        dependency("s", "1"),
        profile("unix", "unix", "repo-a"),
        profile("win", "windows", "repo-b"),
    );
    let in_repo = |repo: &str, published: Vec<(String, String)>| -> Vec<(String, String)> {
        let prefix = format!("{repo}/");
        (published.into_iter())
            .map(|(path, text)| (path.replacen("repository/", &prefix, 1), text))
            .collect()
    };
    let mut files = vec![("pom.xml".to_string(), root)];
    files.extend(in_repo("repo-b", release("s", "1", s_body)));
    files.extend(
        (in_repo("repo-a", release("s", "1", s_body)).into_iter())
            .filter(|(path, _)| !path.contains(".pom")),
    );
    for repo in ["repo-a", "repo-b"] {
        files.extend(in_repo(repo, release("extra", "1", "")));
    }
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    Project::with(&files)
}

/// A CI job that checks linux alone on a clean runner: `--frozen
/// --platforms linux-x86_64` on a fresh home fetches the POM the linux row
/// took from windows' read through `repo-b`, which only windows declares,
/// as a check of both platforms does. The files it stores save to a seed,
/// which restores into another fresh home for an offline check. A plain
/// sync of linux alone on a fresh home stores that POM too.
#[test]
fn a_platform_subset_check_on_a_fresh_home_fetches_the_pom_another_platform_read() {
    let project = mf06_project_with("");
    // A seed key names the host's platform, so the lock records it too.
    let host = rv_lock::Platform::current().unwrap().to_string();
    let mut platforms = vec!["linux-x86_64", "windows-x86_64"];
    if !platforms.contains(&host.as_str()) {
        platforms.push(&host);
    }
    let platforms = platforms.join(",");
    let both = ["sync", "--platforms", &platforms];
    assert_success(&project.raeva(&both), "sync the platforms");
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    let plain = tempfile::TempDir::new().unwrap();
    assert_success(
        &run_raeva(
            &project.root(),
            plain.path(),
            &["sync", "--platforms", "linux-x86_64"],
        ),
        "plain sync of linux on a fresh home",
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
    let offline = [
        "--offline",
        "sync",
        "--frozen",
        "--platforms",
        "linux-x86_64",
    ];
    assert_success(
        &run_raeva(&project.root(), plain.path(), &offline),
        "offline frozen linux after the plain sync",
    );
    let linux = ["sync", "--frozen", "--platforms", "linux-x86_64"];
    let clean = tempfile::TempDir::new().unwrap();
    assert_success(
        &run_raeva(&project.root(), clean.path(), &linux),
        "frozen linux on a fresh home",
    );
    let seed = tempfile::TempDir::new().unwrap();
    let seed_dir = seed.path().join("seed");
    let seed_arg = seed_dir.to_str().unwrap();
    assert_success(
        &run_raeva(&project.root(), clean.path(), &["seed", "save", seed_arg]),
        "seed save",
    );
    let restored = tempfile::TempDir::new().unwrap();
    assert_success(
        &run_raeva(
            &project.root(),
            restored.path(),
            &["seed", "restore", seed_arg],
        ),
        "seed restore",
    );
    assert_success(
        &run_raeva(&project.root(), restored.path(), &offline),
        "offline frozen linux on the restored home",
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
}

/// The same when only a remote parent's windows profile declares `repo-b`:
/// a check of both platforms learns it from windows' resolution, which a
/// check of linux alone does not run, so on a fresh home it stops (exit 3)
/// and names the full check, as a plain sync of linux alone does.
#[test]
fn a_platform_subset_check_stops_at_a_repository_only_a_remote_parent_declares() {
    let files = tempfile::TempDir::new().unwrap();
    let root = files.path().to_path_buf();
    let server = rv_test_support::http::StubServer::start(move |request| {
        crate::common::serve_sha256(&request.path, |path| {
            fs::read(root.join(path.trim_start_matches('/'))).ok()
        })
    });
    let url = |repo: &str| format!("http://{}/{repo}/", server.addr());
    let parent = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
         <profiles><profile><id>win</id><activation><os><family>windows</family></os>\
         </activation><repositories><repository><id>repo-b</id><url>{}</url>\
         </repository></repositories></profile></profiles></project>",
        url("repo-b")
    );
    let write = |path: String, text: &str| {
        let path = files.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    };
    write("parents/org/test/parent/1/parent-1.pom".into(), &parent);
    for (path, text) in release("s", "1", "") {
        if path.ends_with(".sha256") {
            continue;
        }
        write(path.replacen("repository/", "repo-b/", 1), &text);
        if !path.contains(".pom") {
            write(path.replacen("repository/", "repo-a/", 1), &text);
        }
    }
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
         <artifactId>parent</artifactId><version>1</version><relativePath/></parent>\
         <artifactId>root</artifactId><dependencies>{}</dependencies><profiles><profile>\
         <id>unix</id><activation><os><family>unix</family></os></activation>\
         <repositories><repository><id>repo-a</id><url>{}</url></repository>\
         </repositories></profile></profiles></project>",
        dependency("s", "1"),
        url("repo-a"),
    );
    let project = Project::with(&[("pom.xml", &pom)]);
    crate::common::write_repo_toml(&project.root(), "parents", &url("parents"));
    let both = ["sync", "--platforms", "linux-x86_64,windows-x86_64"];
    assert_success(&project.raeva(&both), "sync both platforms");
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    for platform in &lock.platforms {
        let row = (platform.artifacts.iter())
            .find(|row| row.coordinate.gav.to_string() == "org.test:s:1")
            .unwrap();
        assert!(row.pom_sha256.is_some(), "{}", platform.platform);
    }
    let all = tempfile::TempDir::new().unwrap();
    assert_success(
        &run_raeva(
            &project.root(),
            all.path(),
            &[
                "sync",
                "--frozen",
                "--platforms",
                "linux-x86_64,windows-x86_64",
            ],
        ),
        "frozen check of both platforms on a fresh home",
    );
    let linux = ["sync", "--frozen", "--platforms", "linux-x86_64"];
    let clean = tempfile::TempDir::new().unwrap();
    let output = run_raeva(&project.root(), clean.path(), &linux);
    assert_status(&output, 3, "frozen linux on a fresh home");
    let stderr = crate::common::stderr(&output);
    assert!(
        stderr.contains("pins a file of org.test:s:1")
            && stderr.contains("only the build of windows-x86_64 declares")
            && stderr.contains("without --platforms")
            && !stderr.contains("not in the current raeva.toml"),
        "{stderr}"
    );
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    for args in [
        &["--json", "sync", "--frozen", "--platforms", "linux-x86_64"][..],
        &["--json", "sync", "--platforms", "linux-x86_64"],
    ] {
        let fresh = tempfile::TempDir::new().unwrap();
        let output = run_raeva(&project.root(), fresh.path(), args);
        assert_status(&output, 3, &format!("{args:?} on a fresh home"));
        let failed = envelope(&output);
        assert_eq!(failed["code"], "OTHER_PLATFORM_ORIGIN", "{failed}");
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked, "{args:?}");
    }
}

/// After a check of linux alone, a seed, which holds every platform's
/// files, lacks `extra:1`, which only windows' graph takes, through the POM
/// of `s:1` from `repo-b`. Its hint names the check without `--platforms`
/// and the platform it restores.
#[test]
fn a_seed_after_a_platform_subset_check_names_the_platforms_it_lacks() {
    let project = mf06_project_with(&format!(
        "<dependencies>{}</dependencies>",
        dependency("extra", "1")
    ));
    // A seed key names the host's platform, so the lock records it too.
    let host = rv_lock::Platform::current().unwrap().to_string();
    let mut platforms = vec!["linux-x86_64", "windows-x86_64"];
    if !platforms.contains(&host.as_str()) {
        platforms.push(&host);
    }
    let platforms = platforms.join(",");
    assert_success(
        &project.raeva(&["sync", "--platforms", &platforms]),
        "sync the platforms",
    );
    let clean = tempfile::TempDir::new().unwrap();
    let linux = ["sync", "--frozen", "--platforms", "linux-x86_64"];
    assert_success(
        &run_raeva(&project.root(), clean.path(), &linux),
        "frozen linux on a fresh home",
    );
    let seed = tempfile::TempDir::new().unwrap();
    let seed_dir = seed.path().join("seed");
    let save = ["--json", "seed", "save", seed_dir.to_str().unwrap()];
    let output = run_raeva(&project.root(), clean.path(), &save);
    assert_status(&output, 7, "seed save after the linux check");
    let failed = envelope(&output);
    let (message, hints) = (failed["error"].to_string(), failed["hints"].to_string());
    assert!(message.contains("org.test:extra:1:jar"), "{failed}");
    assert!(
        hints.contains("without --platforms")
            && hints.contains("windows-x86_64")
            && !hints.contains("linux-x86_64"),
        "{failed}"
    );
    assert_success(
        &run_raeva(
            &project.root(),
            clean.path(),
            &["sync", "--frozen", "--platforms", &platforms],
        ),
        "frozen check of every platform",
    );
    assert_success(
        &run_raeva(&project.root(), clean.path(), &save[1..]),
        "seed save after it",
    );
}

/// The fetch through the other platform's repository is held to the pin:
/// once `repo-b` serves other bytes for the POM, the linux check and the
/// plain sync of linux on a fresh home refuse it (exit 7).
#[test]
fn a_platform_subset_check_refuses_other_bytes_from_another_platforms_repository() {
    let project = mf06_project_with("");
    let both = ["sync", "--platforms", "linux-x86_64,windows-x86_64"];
    assert_success(&project.raeva(&both), "sync both platforms");
    let pom = project.root().join("repo-b/org/test/s/1/s-1.pom");
    let other = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>s</artifactId><version>1</version><name>other</name></project>";
    fs::write(&pom, other).unwrap();
    fs::write(
        pom.with_extension("pom.sha256"),
        crate::common::sha256_hex(other.as_bytes()),
    )
    .unwrap();
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    for args in [
        &["sync", "--frozen", "--platforms", "linux-x86_64"][..],
        &["sync", "--platforms", "linux-x86_64"],
    ] {
        let clean = tempfile::TempDir::new().unwrap();
        let output = run_raeva(&project.root(), clean.path(), args);
        assert_status(&output, 7, &format!("{args:?} on a fresh home"));
        let stderr = crate::common::stderr(&output);
        assert!(stderr.contains("org.test:s:1:pom from file://"), "{stderr}");
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked, "{args:?}");
    }
}

/// The other platform's repositories serve a linux check only the files
/// raeva.lock pins: a plain sync of linux alone that must resolve a new
/// dependency, which only `repo-b` serves, does not find it there, also in
/// a home whose linux check fetched the pinned POM from `repo-b`.
#[test]
fn a_platform_subset_sync_resolves_nothing_through_another_platforms_repository() {
    let project = mf06_project_with("");
    let both = ["sync", "--platforms", "linux-x86_64,windows-x86_64"];
    assert_success(&project.raeva(&both), "sync both platforms");
    let fresh = tempfile::TempDir::new().unwrap();
    let frozen = ["sync", "--frozen", "--platforms", "linux-x86_64"];
    assert_success(
        &run_raeva(&project.root(), fresh.path(), &frozen),
        "frozen linux on a fresh home",
    );
    // A resolution after it reads s:1 from repo-a as before, not the POM
    // that check stored from repo-b.
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    let update = ["sync", "--update", "--platforms", "linux-x86_64"];
    assert_success(
        &run_raeva(&project.root(), fresh.path(), &update),
        "update of linux after it",
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
    for (path, text) in release("only", "1", "") {
        let path = project
            .root()
            .join(path.replacen("repository/", "repo-b/", 1));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let pom = project.root().join("pom.xml");
    let text = fs::read_to_string(&pom).unwrap();
    let dependencies = dependency("only", "1") + "</dependencies>";
    fs::write(&pom, text.replacen("</dependencies>", &dependencies, 1)).unwrap();
    let linux = ["sync", "--platforms", "linux-x86_64"];
    for home in [project.home().to_path_buf(), fresh.path().to_path_buf()] {
        let output = run_raeva(&project.root(), &home, &linux);
        assert_status(&output, 5, "plain sync of linux");
        assert!(
            crate::common::stderr(&output).contains("org.test:only"),
            "{}",
            crate::common::stderr(&output)
        );
    }
}

/// agy's MF-06: on linux a profile adds `repo-a`, which serves `s:1`'s jar
/// and no POM; on windows `repo-b` serves the same jar and a POM. One sync
/// of both pins the POM windows read on the linux row too, labelled with
/// `repo-b`. A sync or `--frozen` check of linux alone resolves linux
/// without the POM and must agree with that: the lock stays unchanged and
/// keeps windows.
#[test]
fn a_platform_subset_agrees_with_a_pom_another_platform_read() {
    let project = mf06_project_with("");
    let both = ["sync", "--platforms", "linux-x86_64,windows-x86_64"];
    assert_success(&project.raeva(&both), "sync both platforms");
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert_eq!(lock.platforms.len(), 2);
    for platform in &lock.platforms {
        let row = (platform.artifacts.iter())
            .find(|row| row.coordinate.gav.to_string() == "org.test:s:1")
            .unwrap();
        assert!(row.pom_sha256.is_some(), "{}", platform.platform);
    }
    for args in [
        &[
            "sync",
            "--frozen",
            "--platforms",
            "linux-x86_64,windows-x86_64",
        ][..],
        &["sync", "--frozen", "--platforms", "linux-x86_64"],
        &["sync", "--frozen", "--platforms", "windows-x86_64"],
        &["sync", "--platforms", "linux-x86_64"],
        &["sync", "--platforms", "windows-x86_64"],
    ] {
        assert_success(&project.raeva(args), &format!("{args:?}"));
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked, "{args:?}");
    }
}

/// The support-POM form of [`a_platform_subset_agrees_with_a_pom_another_platform_read`]:
/// on windows `s:1` loses to `s:2`, and its POM, from `repo-b`, is a support
/// POM; on linux the row `s:1` comes from `repo-a`, which serves no POM.
#[test]
fn a_platform_subset_agrees_with_a_losing_pom_another_platform_read() {
    let profile = |id: &str, family: &str, repos: &[&str], dependencies: &str| {
        let repos: String = (repos.iter())
            .map(|repo| {
                format!(
                    "<repository><id>{repo}</id>\
                     <url>file://${{project.basedir}}/{repo}/</url></repository>"
                )
            })
            .collect();
        format!(
            "<profile><id>{id}</id><activation><os><family>{family}</family></os></activation>\
             <repositories>{repos}</repositories>\
             <dependencies>{dependencies}</dependencies></profile>"
        )
    };
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><profiles>{}{}</profiles></project>",
        profile("unix", "unix", &["repo-a"], &dependency("s", "1")),
        profile(
            "win",
            "windows",
            &["repo-b", "repo-a"],
            &[dependency("s", "2"), dependency("w", "1")].concat()
        ),
    );
    let in_repo = |repo: &str, published: Vec<(String, String)>| -> Vec<(String, String)> {
        let prefix = format!("{repo}/");
        (published.into_iter())
            .map(|(path, text)| (path.replacen("repository/", &prefix, 1), text))
            .collect()
    };
    let w = format!("<dependencies>{}</dependencies>", dependency("s", "1"));
    let mut files = vec![("pom.xml".to_string(), root)];
    files.extend(in_repo("repo-b", release("s", "1", "")));
    files.extend(in_repo("repo-b", release("s", "2", "")));
    files.extend(in_repo("repo-b", release("w", "1", &w)));
    files.extend(
        (in_repo("repo-a", release("s", "1", "")).into_iter())
            .filter(|(path, _)| !path.contains(".pom")),
    );
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::with(&files);
    let both = ["sync", "--platforms", "linux-x86_64,windows-x86_64"];
    assert_success(&project.raeva(&both), "sync both platforms");
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert_eq!(lock.platforms.len(), 2);
    assert!(lock.support_poms().contains_key("org.test:s:1"), "{locked}");
    for args in [
        &[
            "sync",
            "--frozen",
            "--platforms",
            "linux-x86_64,windows-x86_64",
        ][..],
        &["sync", "--frozen", "--platforms", "linux-x86_64"],
        &["sync", "--frozen", "--platforms", "windows-x86_64"],
        &["sync", "--platforms", "linux-x86_64"],
        &["sync", "--platforms", "windows-x86_64"],
    ] {
        assert_success(&project.raeva(args), &format!("{args:?}"));
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked, "{args:?}");
    }
    // Moving windows' support POM to `repo-a`, which windows also declares,
    // would give linux's module the POM offline: drift.
    let moved = locked.replacen(
        "coordinate = \"org.test:s:1\"\nrepo_url = \"./repo-b/\"",
        "coordinate = \"org.test:s:1\"\nrepo_url = \"./repo-a/\"",
        1,
    );
    assert_ne!(moved, locked, "{locked}");
    fs::write(&lock_path, moved).unwrap();
    assert_status(
        &project.raeva(&[
            "sync",
            "--frozen",
            "--platforms",
            "linux-x86_64,windows-x86_64",
        ]),
        7,
        "moved support POM",
    );
}

/// agy's MF-12: `r` lists `pick` `1.0-alpha-1` and `2.0`, `r2` lists
/// `1.0-a1`. `a` reads both and takes `[1.0-alpha-1,3.0)` beside `other:1.0`,
/// which pins `[1.0-alpha-1]`; `b` reads `r2` alone and takes
/// `[1.0-a1,2.0)`. Maven 3.9.12 and 3.10.0 online give `a` `1.0-alpha-1`
/// in its graph but look for that jar in `r2` alone, and `mvn -o` on an
/// export that lists both spellings gives `a` `1.0-a1`. The export refuses
/// it (exit 3) in either mode.
#[test]
fn export_refuses_equal_spellings_a_module_reads_from_two_repositories() {
    for maven in ["3.9", "3.10"] {
        let module = |name: &str, repos: &[&str], dependencies: &[String]| {
            let repos: String = (repos.iter())
                .map(|repo| {
                    format!(
                        "<repository><id>{repo}</id>\
                         <url>file://${{project.basedir}}/../{repo}/</url></repository>"
                    )
                })
                .collect();
            (
                format!("{name}/pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test\
                     </groupId><artifactId>root</artifactId><version>1</version></parent>\
                     <artifactId>{name}</artifactId><repositories>{repos}</repositories>\
                     <dependencies>{}</dependencies></project>",
                    dependencies.concat()
                ),
            )
        };
        let in_repo = |repo: &str, published: Vec<(String, String)>| -> Vec<(String, String)> {
            let prefix = format!("{repo}/");
            (published.into_iter())
                .map(|(path, text)| (path.replacen("repository/", &prefix, 1), text))
                .collect()
        };
        let mut files = vec![
            (
                "pom.xml".to_string(),
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>a</module><module>b</module></modules></project>"
                    .to_string(),
            ),
            (
                "raeva.toml".to_string(),
                format!("[lock]\nmaven = \"{maven}\"\n"),
            ),
            module(
                "a",
                &["r", "r2"],
                &[
                    dependency("pick", "[1.0-alpha-1,3.0)"),
                    dependency("other", "1.0"),
                ],
            ),
            module("b", &["r2"], &[dependency("pick", "[1.0-a1,2.0)")]),
        ];
        let pin = format!(
            "<dependencies>{}</dependencies>",
            dependency("pick", "[1.0-alpha-1]")
        );
        files.extend(in_repo("r", release("other", "1.0", &pin)));
        files.extend(in_repo("r", release("pick", "1.0-alpha-1", "")));
        files.extend(in_repo("r", release("pick", "2.0", "")));
        files.extend(in_repo("r", vec![listing("pick", &["1.0-alpha-1", "2.0"])]));
        files.extend(in_repo("r2", release("pick", "1.0-a1", "")));
        files.extend(in_repo("r2", vec![listing("pick", &["1.0-a1"])]));
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::with(&files);
        assert_success(&project.raeva(&["sync"]), maven);
        let m2 = project.m2();
        let output = project.raeva(&["--json", "export-m2", "--m2-path", m2.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(3), "{maven}: {output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("LOCKFILE_INVALID") && stdout.contains("org.test:pick"),
            "{maven}: {stdout}"
        );
    }
}

/// `c:2`, which `w`'s `[1]` evicts, declares a range on `lib` that no
/// locked version satisfies. `mvn -o` reads that range before it mediates
/// and fails on "No versions available" unless a list of the repository
/// that listed it names a version inside it, so export-m2 lists the lowest
/// version the lock saw in that repository's list, as neither latest nor
/// release, and warns. Every range on `lib` there reads that list, so it
/// holds no more. Into the shared repository it lists nothing and says so.
#[test]
fn export_lists_the_versions_of_a_range_that_loses_mediation() {
    let root = format!(
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>app</artifactId><version>1</version>
  <repositories>
    <repository><id>project-local</id><url>file://${{project.basedir}}/repository/</url></repository>
  </repositories>
  <dependencies>{}</dependencies>
</project>
"#,
        [
            dependency("lib", "1.0"),
            dependency("x", "1"),
            dependency("y", "1"),
        ]
        .concat()
    );
    let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
    let mut files = vec![("pom.xml".to_string(), root)];
    files.extend(release("x", "1", &deps(&[dependency("c", "2")])));
    files.extend(release("y", "1", &deps(&[dependency("w", "1")])));
    files.extend(release("w", "1", &deps(&[dependency("c", "[1]")])));
    files.extend(release("c", "1", ""));
    files.extend(release("c", "2", &deps(&[dependency("lib", "[2,3)")])));
    files.extend(release("lib", "2.0", ""));
    files.extend(release("lib", "2.5", ""));
    files.push(listing("lib", &["1.0", "2.0", "2.5"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let evicted: Vec<_> = (lock.platforms[0].modules[0].evicted_ranges.iter())
        .map(|range| {
            format!(
                "{}:{} {} {}",
                range.artifact,
                range.range,
                range.versions.join(" "),
                range.origin
            )
        })
        .collect();
    assert_eq!(evicted, ["lib:[2,3) 2.0 2.5 ./repository/"]);

    let export = |m2: &std::path::Path| {
        let output = project.raeva(&["--json", "export-m2", "--m2-path", m2.to_str().unwrap()]);
        assert_success(&output, "export-m2");
        let warnings = envelope(&output)["data"]["warnings"].clone();
        (warnings.as_array().unwrap().iter())
            .find(|warning| warning["code"] == "EXPORT_LOSING_RANGE_VERSIONS")
            .unwrap_or_else(|| panic!("{warnings}"))
            .clone()
    };
    let warning = export(&project.m2());
    assert_eq!(warning["context"]["coordinates"], "org.test:lib:2.0");
    assert_eq!(warning["context"]["listed"], true);
    let listed = |path: std::path::PathBuf| {
        let text = fs::read_to_string(path).unwrap();
        let versions: Vec<String> = (text.split("<version>").skip(1))
            .map(|rest| rest.split('<').next().unwrap().to_string())
            .collect();
        (text, versions)
    };
    let lib = project.m2().join("org/test/lib");
    let (list, versions) = listed(lib.join("maven-metadata-project-local.xml"));
    assert_eq!(versions, ["2.0"], "{list}");
    assert!(
        !list.contains("<latest>") && !list.contains("<release>"),
        "{list}"
    );
    assert!(listed(lib.join("maven-metadata-local.xml")).1.is_empty());
    assert!(!lib.join("2.0").exists());

    let shared = project.raeva_home().join("shared");
    fs::write(
        project.m2_settings(),
        format!(
            "<settings><localRepository>{}</localRepository></settings>",
            shared.display()
        ),
    )
    .unwrap();
    let warning = export(&shared);
    assert_eq!(warning["context"]["listed"], false);
    assert!(
        !shared
            .join("org/test/lib/maven-metadata-local.xml")
            .exists()
    );
}

/// A conflicted lock regenerated for the platforms `--platforms` names
/// keeps the other platforms it names too, as the warning says: none of
/// them can be carried forward from a lock that does not read.
#[test]
fn a_conflicted_lock_regenerated_for_one_platform_keeps_the_others() {
    let (host, other) = (host(), other());
    let project = Project::synced();
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let both = format!("{host},{other}");
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", &both]),
        "lock two platforms",
    );
    let locked = fs::read_to_string(&lock_path).unwrap();
    let edited = locked.replace("config_hash = ", "config_hash = \"x\"\n#");
    fs::write(
        &lock_path,
        format!("<<<<<<< HEAD\n{locked}=======\n{edited}>>>>>>> theirs\n"),
    )
    .unwrap();
    let output = project.raeva(&["sync", "--offline", "--platforms", &host]);
    assert_success(&output, "regenerate for one platform");
    let mut expected = [host.clone(), other.to_string()];
    expected.sort();
    assert!(
        text(&output).contains(&format!(
            "keeping its platforms {} and {}",
            expected[0], expected[1]
        )),
        "{}",
        text(&output)
    );
    let mut platforms = locked_platforms(&project);
    platforms.sort();
    assert_eq!(platforms, expected);
}

/// The versions each `maven-metadata-<id>.xml` of `org.test:<artifact>`
/// under `m2` lists, by id.
fn export_listings(
    m2: &std::path::Path,
    artifact: &str,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let dir = m2.join(format!("org/test/{artifact}"));
    let mut listed = std::collections::BTreeMap::new();
    for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = (name.strip_prefix("maven-metadata-")).and_then(|n| n.strip_suffix(".xml"))
        else {
            continue;
        };
        let text = fs::read_to_string(entry.path()).unwrap();
        let versions: Vec<String> = (text.split("<version>").skip(1))
            .map(|rest| rest.split('<').next().unwrap().to_string())
            .collect();
        if !versions.is_empty() {
            listed.insert(id.to_string(), versions);
        }
    }
    listed
}

/// Each module's `range_versions` lines of `project`'s lock.
fn range_versions(root: &std::path::Path) -> Vec<String> {
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    (lock.platforms[0].modules.iter())
        .flat_map(|module| {
            (module.range_versions.iter()).map(|read| {
                let (group, artifact) = (&read.group, &read.artifact);
                format!(
                    "{} {group}:{artifact} {} {}",
                    module.path, read.version, read.origin
                )
            })
        })
        .collect()
}

fn export_to_m2(project: &Project) -> std::path::PathBuf {
    let m2 = project.m2();
    let output = project.raeva(&["export-m2", "--m2-path", m2.to_str().unwrap()]);
    assert_success(&output, "export-m2");
    m2
}

/// `a` takes `pick` `[1,3)` at `1`, all its repository's list names, while
/// `b` asks `2` exactly. Maven 3.9.12 and 3.10.0 resolve `a` to `1` online,
/// and `mvn -o` on an export that also lists `2` gives `a` `2`. raeva.lock
/// records the version `a`'s range took and the repository that listed it,
/// the export lists that alone, and `--frozen` refuses an edit of the
/// record.
#[test]
fn export_lists_a_range_version_and_not_an_exact_pin() {
    let mut files = plain_reactor(&[
        ("a", dependency("pick", "[1,3)")),
        ("b", dependency("pick", "2")),
    ]);
    files.extend(release("pick", "1", ""));
    files.extend(release("pick", "2", ""));
    files.push(listing("pick", &["1"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    assert_eq!(
        range_versions(&project.root()),
        ["a/pom.xml org.test:pick 1 ./repository/"]
    );
    let m2 = export_to_m2(&project);
    assert_eq!(
        export_listings(&m2, "pick"),
        [("project-local".to_string(), vec!["1".to_string()])].into()
    );
    assert!(m2.join("org/test/pick/2/pick-2.jar").exists());

    let lock_path = project.root().join("raeva.lock");
    let written = fs::read_to_string(&lock_path).unwrap();
    let line = "range_versions = \"org.test:pick\\t1\\t./repository/\"";
    assert!(written.contains(line), "{written}");
    for edited in [
        written.replace(
            line,
            "range_versions = \"org.test:pick\\t2\\t./repository/\"",
        ),
        written.replace(&format!("{line}\n"), ""),
    ] {
        fs::write(&lock_path, &edited).unwrap();
        let output = project.raeva(&["--json", "sync", "--frozen", "--offline"]);
        assert_status(&output, 7, "an edited range version");
        assert_eq!(envelope(&output)["code"], "LOCKFILE_MISMATCH");
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), edited);
    }
}

/// `a` takes `pick` `[1,4)` at `2`, the highest its list names, while `c`
/// holds `3` directly and loses `mid`'s `[1,4)`. Maven lists `2` for `a`
/// online, `mvn -o` takes `3` where the export lists it. The export lists
/// `2`, which also stands for `c`'s losing range.
#[test]
fn export_lists_a_range_version_beside_a_range_that_lost() {
    let mut files = plain_reactor(&[
        ("a", dependency("pick", "[1,4)")),
        ("c", dependency("pick", "3") + &dependency("mid", "1")),
    ]);
    for version in ["1", "2", "3"] {
        files.extend(release("pick", version, ""));
    }
    files.extend(release(
        "mid",
        "1",
        &format!(
            "<dependencies>{}</dependencies>",
            dependency("pick", "[1,4)")
        ),
    ));
    files.push(listing("pick", &["1", "2"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    assert_eq!(
        range_versions(&project.root()),
        ["a/pom.xml org.test:pick 2 ./repository/"]
    );
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let c = (lock.platforms[0].modules.iter())
        .find(|module| module.path == "c/pom.xml")
        .unwrap();
    assert_eq!(c.evicted_ranges.len(), 1, "{:?}", c.evicted_ranges);
    let m2 = export_to_m2(&project);
    assert_eq!(
        export_listings(&m2, "pick"),
        [("project-local".to_string(), vec!["2".to_string()])].into()
    );
}

/// `RELEASE` takes `1` and `LATEST` `2` from markers that lag the `3` that
/// `c` pins, and `d`'s `[1,4)` takes `2` from the list. Maven resolves the
/// same online and `mvn -o` on the export: the export lists the version the
/// range took, with the markers, and not `3`. A marker reads no list.
#[test]
fn export_lists_the_versions_markers_and_ranges_took() {
    let mut files = plain_reactor(&[
        ("a", dependency("pick", "RELEASE")),
        ("b", dependency("pick", "LATEST")),
        ("c", dependency("pick", "3")),
        ("d", dependency("pick", "[1,4)")),
    ]);
    for version in ["1", "2", "3"] {
        files.extend(release("pick", version, ""));
    }
    files.push((
        "repository/org/test/pick/maven-metadata.xml".to_string(),
        "<metadata><groupId>org.test</groupId><artifactId>pick</artifactId><versioning>\
         <latest>2</latest><release>1</release><versions><version>1</version>\
         <version>2</version></versions><lastUpdated>20240101000000</lastUpdated>\
         </versioning></metadata>"
            .to_string(),
    ));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    assert_eq!(
        range_versions(&project.root()),
        ["d/pom.xml org.test:pick 2 ./repository/"]
    );
    let m2 = export_to_m2(&project);
    assert_eq!(
        export_listings(&m2, "pick"),
        [("project-local".to_string(), vec!["2".to_string()])].into()
    );
    let list =
        fs::read_to_string(m2.join("org/test/pick/maven-metadata-project-local.xml")).unwrap();
    assert!(
        list.contains("<release>1</release>") && list.contains("<latest>2</latest>"),
        "{list}"
    );
}

/// A SNAPSHOT range: `a`'s `(0,3)` takes `1-SNAPSHOT`, all the list names,
/// while `b` asks `2-SNAPSHOT` exactly. The export lists `1-SNAPSHOT`
/// alone, as Maven 3.9.12 and 3.10.0 read the list online.
#[test]
fn export_lists_a_snapshot_range_version_and_not_an_exact_snapshot() {
    let mut files = plain_reactor(&[
        ("a", dependency("pick", "(0,3)")),
        ("b", dependency("pick", "2-SNAPSHOT")),
    ]);
    files.extend(release("pick", "1-SNAPSHOT", ""));
    files.extend(release("pick", "2-SNAPSHOT", ""));
    files.push(listing("pick", &["1-SNAPSHOT"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    assert_eq!(
        range_versions(&project.root()),
        ["a/pom.xml org.test:pick 1-SNAPSHOT ./repository/"]
    );
    let m2 = export_to_m2(&project);
    assert_eq!(
        export_listings(&m2, "pick"),
        [("project-local".to_string(), vec!["1-SNAPSHOT".to_string()])].into()
    );
}

/// `c`'s parent is `par:2` from the repository, named exactly, and `a`
/// asks `par` `[1,3)` as a POM, which takes `1`, all the list names. The
/// export lists `1` alone: a parent named exactly reads no list.
#[test]
fn export_lists_no_parent_named_exactly() {
    let mut files = plain_reactor(&[(
        "a",
        "<dependency><groupId>org.test</groupId><artifactId>par</artifactId>\
         <version>[1,3)</version><type>pom</type></dependency>"
            .to_string(),
    )]);
    files[0].1 = files[0]
        .1
        .replace("<module>a</module>", "<module>a</module><module>c</module>");
    files.extend(release("par", "1", "<packaging>pom</packaging>"));
    files.extend(release("par", "2", "<packaging>pom</packaging>"));
    files.push(listing("par", &["1"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::with(&files);
    // A remote parent is looked up before `${project.basedir}` is known.
    fs::create_dir_all(project.root().join("c")).unwrap();
    fs::write(
        project.root().join("c/pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>par</artifactId><version>2</version><relativePath/></parent>\
             <artifactId>c</artifactId><repositories><repository><id>project-local</id>\
             <url>file://{}/repository/</url></repository></repositories></project>",
            project.root().display()
        ),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "offline sync");
    let m2 = export_to_m2(&project);
    assert!(m2.join("org/test/par/2/par-2.pom").exists());
    assert_eq!(
        export_listings(&m2, "par"),
        [("project-local".to_string(), vec!["1".to_string()])].into()
    );
}

/// A list raeva cached within its update interval: `a` takes `pick`
/// `[1,3)` at `1`; then the repository publishes `2` and lists it, and `b`
/// asks `2` exactly. Maven, again with its local repository, keeps `a` at
/// `1`, and so does raeva with its home. The export lists `1` alone, which
/// `mvn -o` keeps `a` at.
#[test]
fn export_lists_a_cached_range_version_and_not_a_later_exact_pin() {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use rv_test_support::http::{Response, StubServer};

    let served: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
    let publish = |served: &Mutex<HashMap<String, Vec<u8>>>, versions: &[&str]| {
        let mut served = served.lock().unwrap();
        for version in versions {
            let dir = format!("org/test/pick/{version}");
            served.insert(
                format!("{dir}/pick-{version}.pom"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>pick</artifactId><version>{version}</version></project>"
                )
                .into_bytes(),
            );
            served.insert(
                format!("{dir}/pick-{version}.jar"),
                format!("pick {version}").into_bytes(),
            );
        }
        let listed: String = (versions.iter())
            .map(|version| format!("<version>{version}</version>"))
            .collect();
        served.insert(
            "org/test/pick/maven-metadata.xml".to_string(),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>pick</artifactId>\
                 <versioning><versions>{listed}</versions></versioning></metadata>"
            )
            .into_bytes(),
        );
    };
    publish(&served, &["1"]);
    let files = Arc::clone(&served);
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (file, sidecar) = match path.strip_suffix(".sha256") {
            Some(file) => (file, true),
            None => (path, false),
        };
        match files.lock().unwrap().get(file) {
            Some(body) if sidecar => Response::new(200, crate::common::sha256_hex(body)),
            Some(body) => Response::new(200, body.clone()),
            None => Response::new(404, ""),
        }
    });
    let url = format!("http://{}/", server.addr());
    let project = tempfile::TempDir::new().unwrap();
    let home = tempfile::TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>*</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    let write = |modules: &[(&str, String)]| {
        for (path, text) in plain_reactor(modules) {
            let path = project.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
    };
    let run = |args: &[&str]| crate::common::run_raeva(project.path(), home.path(), args);
    write(&[("a", dependency("pick", "[1,3)"))]);
    assert_success(&run(&["sync"]), "first sync");
    publish(&served, &["1", "2"]);
    write(&[
        ("a", dependency("pick", "[1,3)")),
        ("b", dependency("pick", "2")),
    ]);
    assert_success(&run(&["sync"]), "sync with b");
    // The stub mirrors both repositories `a` reads, each by its own URL.
    assert_eq!(
        range_versions(project.path()),
        [
            "a/pom.xml org.test:pick 1 ./repository/",
            "a/pom.xml org.test:pick 1 https://repo1.maven.org/maven2/"
        ]
    );
    let m2 = home.path().join("m2");
    assert_success(
        &run(&["export-m2", "--m2-path", m2.to_str().unwrap()]),
        "export-m2",
    );
    assert!(m2.join("org/test/pick/2/pick-2.jar").exists());
    let listed = export_listings(&m2, "pick");
    assert!(
        listed.values().all(|versions| versions == &["1"]) && !listed.is_empty(),
        "{listed:?}"
    );
}

/// The reactor builds `pick:1`, and the repository lists `pick:2`: Maven
/// takes `a`'s `[1,3)` from both, so `2`. The export lists `2`, without
/// which `mvn -o` takes the reactor's `1`.
#[test]
fn export_lists_a_range_version_beside_a_reactor_version() {
    let mut files = plain_reactor(&[("pick", String::new()), ("a", dependency("pick", "[1,3)"))]);
    files.extend(release("pick", "2", ""));
    files.push(listing("pick", &["2"]));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    assert_eq!(
        range_versions(&project.root()),
        ["a/pom.xml org.test:pick 2 ./repository/"]
    );
    let m2 = export_to_m2(&project);
    assert_eq!(
        export_listings(&m2, "pick"),
        [("project-local".to_string(), vec!["2".to_string()])].into()
    );
}

/// `a` imports `bom:1`, whose parent `par` `[1,3)` takes `1`; `c`'s parent
/// is `par:1`, named exactly, which reads no list. `c` records no range,
/// whichever module reads the list first.
#[test]
fn a_parent_named_exactly_records_no_range_another_module_read() {
    let mut files = plain_reactor(&[(
        "a",
        "<dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
         <version>1.0</version></dependency>"
            .to_string(),
    )]);
    files[0].1 = files[0]
        .1
        .replace("<module>a</module>", "<module>a</module><module>c</module>");
    files[1].1 = files[1].1.replace(
        "<dependencies>",
        "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>bom</artifactId><version>1</version><type>pom</type>\
         <scope>import</scope></dependency></dependencies></dependencyManagement>\
         <dependencies>",
    );
    files.extend(release("par", "1", "<packaging>pom</packaging>"));
    files.push(listing("par", &["1"]));
    files.extend(release(
        "bom",
        "1",
        "<parent><groupId>org.test</groupId><artifactId>par</artifactId>\
         <version>[1,3)</version><relativePath/></parent><packaging>pom</packaging>",
    ));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::with(&files);
    fs::create_dir_all(project.root().join("c")).unwrap();
    fs::write(
        project.root().join("c/pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>par</artifactId><version>1</version><relativePath/></parent>\
             <artifactId>c</artifactId><repositories><repository><id>project-local</id>\
             <url>file://{}/repository/</url></repository></repositories></project>",
            project.root().display()
        ),
    )
    .unwrap();
    for _ in 0..5 {
        fs::remove_file(project.root().join("raeva.lock")).ok();
        assert_success(&project.raeva(&["sync", "--offline"]), "offline sync");
        assert_eq!(
            range_versions(&project.root()),
            ["a/pom.xml org.test:par 1 ./repository/"]
        );
    }
}

/// `a` imports `bom:1`, whose parent is `par` `[1,3)`, which takes `1`, all
/// the list names; `c`'s parent is `par:2`, named exactly. Maven resolves
/// the BOM's parent range from the list offline too, so the export lists
/// `1` alone.
#[test]
fn export_lists_the_parent_range_of_an_imported_bom() {
    let mut files = plain_reactor(&[(
        "a",
        "<dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
         <version>1.0</version></dependency>"
            .to_string(),
    )]);
    files[0].1 = files[0]
        .1
        .replace("<module>a</module>", "<module>a</module><module>c</module>");
    files[1].1 = files[1].1.replace(
        "<dependencies>",
        "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>bom</artifactId><version>1</version><type>pom</type>\
         <scope>import</scope></dependency></dependencies></dependencyManagement>\
         <dependencies>",
    );
    files.extend(release("par", "1", "<packaging>pom</packaging>"));
    files.extend(release("par", "2", "<packaging>pom</packaging>"));
    files.push(listing("par", &["1"]));
    files.extend(release(
        "bom",
        "1",
        "<parent><groupId>org.test</groupId><artifactId>par</artifactId>\
         <version>[1,3)</version><relativePath/></parent><packaging>pom</packaging>",
    ));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::with(&files);
    fs::create_dir_all(project.root().join("c")).unwrap();
    fs::write(
        project.root().join("c/pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>par</artifactId><version>2</version><relativePath/></parent>\
             <artifactId>c</artifactId><repositories><repository><id>project-local</id>\
             <url>file://{}/repository/</url></repository></repositories></project>",
            project.root().display()
        ),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "offline sync");
    assert_eq!(
        range_versions(&project.root()),
        ["a/pom.xml org.test:par 1 ./repository/"]
    );
    let m2 = export_to_m2(&project);
    assert!(m2.join("org/test/par/2/par-2.pom").exists());
    assert_eq!(
        export_listings(&m2, "par"),
        [("project-local".to_string(), vec!["1".to_string()])].into()
    );
}

/// `--frozen` replays a range at the very spelling the lock took when
/// versions are published since: `1.0-ga`, which compares equal to the
/// locked `1.0`, and more versions in a list where `1.0-alpha-1` and
/// `1.0-a1` tie, whose order in Maven's hash map a larger table changes.
#[test]
fn frozen_replays_a_range_at_the_spelling_it_took() {
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
         </repository></repositories><dependencies>{}</dependencies></project>",
        dependency("lib", "[1.0-alpha-1,2.0)")
    );
    let fillers: Vec<String> = (1..=9).map(|minor| format!("0.{minor}")).collect();
    let fillers: Vec<&str> = fillers.iter().map(String::as_str).collect();
    let tied = [&["1.0-alpha-1", "1.0-a1"][..], &fillers].concat();
    for mode in ["3.9", "3.10"] {
        for (listed, newer) in [
            (&["1.0"][..], &["1.0-ga"][..]),
            (&tied[..], &["3.1", "3.2"][..]),
        ] {
            let mut files = vec![
                ("pom.xml".to_string(), root.clone()),
                (
                    "raeva.toml".to_string(),
                    format!("[lock]\nmaven = \"{mode}\"\n"),
                ),
            ];
            for version in listed.iter().chain(newer) {
                files.extend(release("lib", version, ""));
            }
            files.push(listing("lib", listed));
            let files: Vec<_> = (files.iter())
                .map(|(path, text)| (path.as_str(), text.as_str()))
                .collect();
            let project = Project::synced_with(&files);
            let lock_path = project.root().join("raeva.lock");
            let written = fs::read_to_string(&lock_path).unwrap();
            let (path, text) = listing("lib", &[listed, newer].concat());
            fs::write(project.root().join(path), text).unwrap();
            let output = project.raeva(&["sync", "--frozen"]);
            let case = format!("{mode} {newer:?}");
            assert_success(&output, &case);
            assert_eq!(fs::read_to_string(&lock_path).unwrap(), written, "{case}");
        }
    }
}

/// `--frozen` refuses a property name in `[resolution] ambient_inputs`
/// that no target lists as read, which no run records, and a plain sync
/// writes the lock again rather than keep it.
#[test]
fn frozen_refuses_an_ambient_property_no_target_read() {
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
         </repository></repositories><dependencies>{}</dependencies></project>",
        dependency("lib", "1.0")
    );
    let mut files = vec![("pom.xml".to_string(), root)];
    files.extend(release("lib", "1.0", ""));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock_path = project.root().join("raeva.lock");
    let written = fs::read_to_string(&lock_path).unwrap();
    assert!(!written.contains("[resolution]"), "{written}");
    let at = written.find("\n\n[[platforms]]").unwrap();
    for name in ["user-property:zzz", "settings-property:zzz", "env.ZZZ"] {
        let edited = format!(
            "{}\n\n[resolution]\nambient_inputs = [\"{name}\"]{}",
            &written[..at],
            &written[at..]
        );
        fs::write(&lock_path, edited).unwrap();
        let output = project.raeva(&["sync", "--frozen"]);
        assert_status(&output, 7, &format!("frozen with an added {name}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&format!("lists {name} under")), "{stderr}");
        assert_success(
            &project.raeva(&["sync"]),
            &format!("sync with an added {name}"),
        );
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), written, "{name}");
    }
}

/// `--frozen` refuses a `[resolution] command_line` the run would not
/// record, as it does other edits of what the resolution read, and a plain
/// sync writes it again. A `-P` from `.mvn/maven.config` counts as the
/// command line's.
#[test]
fn frozen_refuses_a_command_line_name_the_run_does_not_set() {
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
         </repository></repositories><dependencies>{}</dependencies></project>",
        dependency("lib", "1.0")
    );
    let mut files = vec![("pom.xml".to_string(), root)];
    files.extend(release("lib", "1.0", ""));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock_path = project.root().join("raeva.lock");
    let written = fs::read_to_string(&lock_path).unwrap();
    assert!(!written.contains("[resolution]"), "{written}");
    let at = written.find("\n\n[[platforms]]").unwrap();
    for name in ["-Dfake", "-Pfake"] {
        let edited = format!(
            "{}\n\n[resolution]\ncommand_line = [\"{name}\"]{}",
            &written[..at],
            &written[at..]
        );
        fs::write(&lock_path, edited).unwrap();
        let output = project.raeva(&["sync", "--frozen"]);
        assert_status(&output, 7, &format!("frozen with an added {name}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("not the text raeva writes"), "{stderr}");
        // A plain sync writes the lock again rather than keep it.
        assert_success(
            &project.raeva(&["sync"]),
            &format!("sync with an added {name}"),
        );
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), written, "{name}");
    }
    fs::write(&lock_path, &written).unwrap();
    assert_success(&project.raeva(&["sync", "-Pci"]), "sync -Pci");
    let locked = fs::read_to_string(&lock_path).unwrap();
    assert!(locked.contains("command_line = [\"-Pci\"]"), "{locked}");
    let reused = |output: &std::process::Output| {
        !String::from_utf8_lossy(&output.stderr).contains("Resolving dependencies")
    };
    let again = project.raeva(&["sync", "-Pci"]);
    assert!(reused(&again), "{}", String::from_utf8_lossy(&again.stderr));
    fs::create_dir_all(project.root().join(".mvn")).unwrap();
    fs::write(project.root().join(".mvn/maven.config"), "-Pci\n").unwrap();
    assert_success(
        &project.raeva(&["sync", "--frozen"]),
        "frozen with maven.config -Pci",
    );
    let again = project.raeva(&["sync"]);
    assert_success(&again, "sync with maven.config -Pci");
    assert!(reused(&again), "{}", String::from_utf8_lossy(&again.stderr));
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
}

/// `--frozen` keeps the spelling a `RELEASE` or `LATEST` took when the
/// marker moves since to another that compares equal.
#[test]
fn frozen_keeps_the_spelling_a_marker_took() {
    let marked = |listed: &[&str], marker: &str| {
        let versions: String = (listed.iter())
            .map(|version| format!("<version>{version}</version>"))
            .collect();
        (
            "repository/org/test/lib/maven-metadata.xml".to_string(),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId>\
                 <versioning><latest>{marker}</latest><release>{marker}</release>\
                 <versions>{versions}</versions></versioning></metadata>"
            ),
        )
    };
    for token in ["RELEASE", "LATEST"] {
        for mode in ["3.9", "3.10"] {
            let root = format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>app</artifactId><version>1</version><repositories><repository>\
                 <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
                 </repository></repositories><dependencies>{}</dependencies></project>",
                dependency("lib", token)
            );
            let mut files = vec![
                ("pom.xml".to_string(), root),
                (
                    "raeva.toml".to_string(),
                    format!("[lock]\nmaven = \"{mode}\"\n"),
                ),
            ];
            for version in ["1.0", "1.0-ga"] {
                files.extend(release("lib", version, ""));
            }
            files.push(marked(&["1.0"], "1.0"));
            let files: Vec<_> = (files.iter())
                .map(|(path, text)| (path.as_str(), text.as_str()))
                .collect();
            let project = Project::synced_with(&files);
            let lock_path = project.root().join("raeva.lock");
            let written = fs::read_to_string(&lock_path).unwrap();
            let (path, text) = marked(&["1.0", "1.0-ga"], "1.0-ga");
            fs::write(project.root().join(path), text).unwrap();
            let output = project.raeva(&["sync", "--frozen"]);
            let case = format!("{token} {mode}");
            assert_success(&output, &case);
            assert_eq!(fs::read_to_string(&lock_path).unwrap(), written, "{case}");
        }
    }
}

/// A range of one artifact used as a parent and as a dependency takes, of
/// equal spellings, the last as a parent and, depth first, the first as a
/// dependency: `--frozen` replays each use at its own spelling, also once
/// another range has a version published since.
#[test]
fn frozen_replays_a_parent_and_a_dependency_range_at_their_own_spellings() {
    for mode in ["3.9", "3.10"] {
        let module = format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>par</artifactId><version>[1.0,2.0)</version><relativePath/>\
             </parent><groupId>org.test</groupId><artifactId>app</artifactId>\
             <version>1</version><repositories><repository><id>project-local</id>\
             <url>file://${{project.basedir}}/repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>par</artifactId>\
             <version>[1.0,2.0)</version><type>pom</type></dependency>{}</dependencies>\
             </project>",
            dependency("lib", "[1,3)")
        );
        let mut files = vec![("pom.xml".to_string(), module)];
        for version in ["1.0", "1.0-ga"] {
            files.extend(release("par", version, "<packaging>pom</packaging>"));
        }
        files.push(listing("par", &["1.0", "1.0-ga"]));
        for version in ["1", "2"] {
            files.extend(release("lib", version, ""));
        }
        files.push(listing("lib", &["1"]));
        let files: Vec<_> = (files.iter())
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let project = Project::with(&files);
        fs::write(
            project.root().join("raeva.toml"),
            format!(
                "[lock]\nmaven = \"{mode}\"\n\n[[repositories]]\nid = \"central\"\n\
                 url = \"{}\"\n",
                url::Url::from_directory_path(project.root().join("repository")).unwrap()
            ),
        )
        .unwrap();
        assert_success(&project.raeva(&["sync", "--offline"]), "sync");
        let lock_path = project.root().join("raeva.lock");
        let written = fs::read_to_string(&lock_path).unwrap();
        let (path, text) = listing("lib", &["1", "2"]);
        fs::write(project.root().join(path), text).unwrap();
        assert_success(
            &project.raeva(&["sync", "--frozen"]),
            &format!("{mode} frozen"),
        );
        assert_success(&project.raeva(&["sync"]), &format!("{mode} sync"));
        assert_eq!(
            fs::read_to_string(&lock_path).unwrap(),
            written,
            "{mode}\n{written}"
        );
    }
}

/// `--frozen` replays a parent range at the spelling it took among equal
/// ones, `1.0-alpha-1` and `1.0-a1`, which another module names exactly,
/// when more versions listed since change their order in Maven's hash map.
#[test]
fn frozen_replays_a_parent_range_at_the_spelling_it_took() {
    let repos = "<repositories><repository><id>project-local</id>\
                 <url>file://${project.basedir}/../repository/</url></repository></repositories>";
    let child = |name: &str, version: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>par</artifactId><version>{version}</version><relativePath/>\
             </parent><groupId>org.test</groupId><artifactId>{name}</artifactId>\
             <version>1</version>{repos}</project>"
        )
    };
    let fillers: Vec<String> = (1..=9).map(|minor| format!("0.{minor}")).collect();
    let fillers: Vec<&str> = fillers.iter().map(String::as_str).collect();
    let tied = [&["1.0-alpha-1", "1.0-a1"][..], &fillers].concat();
    let more = [&tied[..], &["3.1", "3.2"]].concat();
    for mode in ["3.9", "3.10"] {
        for exact in ["1.0-alpha-1", "1.0-a1"] {
            let mut files = vec![
                (
                    "pom.xml".to_string(),
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>root</artifactId><version>1</version>\
                     <packaging>pom</packaging><modules><module>a</module>\
                     <module>b</module></modules></project>"
                        .to_string(),
                ),
                ("a/pom.xml".to_string(), child("a", "[1.0-alpha-1,2.0)")),
                ("b/pom.xml".to_string(), child("b", exact)),
            ];
            for version in &more {
                files.extend(release("par", version, "<packaging>pom</packaging>"));
            }
            files.push(listing("par", &tied));
            let files: Vec<_> = (files.iter())
                .map(|(path, text)| (path.as_str(), text.as_str()))
                .collect();
            let project = Project::with(&files);
            // The parent's versions are listed where Maven lists them.
            fs::write(
                project.root().join("raeva.toml"),
                format!(
                    "[lock]\nmaven = \"{mode}\"\n\n[[repositories]]\nid = \"central\"\n\
                     url = \"{}\"\n",
                    url::Url::from_directory_path(project.root().join("repository")).unwrap()
                ),
            )
            .unwrap();
            assert_success(&project.raeva(&["sync", "--offline"]), "sync");
            let lock_path = project.root().join("raeva.lock");
            let written = fs::read_to_string(&lock_path).unwrap();
            let (path, text) = listing("par", &more);
            fs::write(project.root().join(path), text).unwrap();
            let output = project.raeva(&["sync", "--frozen"]);
            let case = format!("{mode} b at {exact}");
            assert_success(&output, &case);
            assert_eq!(fs::read_to_string(&lock_path).unwrap(), written, "{case}");
        }
    }
}

/// A row holds the one SHA-256 a resolution records: `--frozen` refuses a
/// SHA-1 added beside it, and a plain sync writes the lock again rather
/// than keep it, so the next frozen check passes.
#[test]
fn a_plain_sync_writes_again_a_checksum_added_to_a_row() {
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
         </repository></repositories><dependencies>{}</dependencies></project>",
        dependency("lib", "1.0")
    );
    let mut files = vec![("pom.xml".to_string(), root)];
    files.extend(release("lib", "1.0", ""));
    let files: Vec<_> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock_path = project.root().join("raeva.lock");
    let written = fs::read_to_string(&lock_path).unwrap();
    let at = written.find("[[platforms.artifacts.checksums]]").unwrap();
    let sha1 = format!(
        "[[platforms.artifacts.checksums]]\nalgorithm = \"sha1\"\ndigest = \"{}\"\n\n",
        "0".repeat(40)
    );
    fs::write(
        &lock_path,
        format!("{}{sha1}{}", &written[..at], &written[at..]),
    )
    .unwrap();
    assert_status(
        &project.raeva(&["sync", "--frozen"]),
        7,
        "frozen with an added SHA-1",
    );
    assert_success(&project.raeva(&["sync"]), "plain sync");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), written);
    assert_success(&project.raeva(&["sync", "--frozen"]), "frozen");
}
