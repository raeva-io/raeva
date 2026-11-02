//! What `raeva sync`, `--frozen` and the commands that check freshness
//! compare against raeva.lock: the platforms it records, the reactor's own
//! versions, the `-D` and `-P` options, SNAPSHOT builds and the store.

use std::fs;

use serde_json::Value;

use crate::common::{assert_status, assert_success, envelope};
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

    let empty = tempfile::TempDir::new().expect("empty home");
    let env = [("RAEVA_HOME", empty.path().to_str().expect("utf-8 path"))];
    let output = project.raeva_with(&env, &["--json", "sync", "--frozen", "--offline"]);
    assert_status(&output, 7, "offline frozen with an empty store");
    let failed = envelope(&output);
    assert_eq!(failed["code"], "LOCKFILE_MISMATCH", "{failed}");
    assert_eq!(
        failed["error"],
        "raeva.lock is up to date, but the store lacks 2 of the 2 files it pins"
    );
    assert!(
        failed["hints"]
            .to_string()
            .contains("raeva lock verify --download"),
        "{failed}"
    );

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

    fs::remove_dir_all(root.join(".git")).unwrap();
    fs::write(&lock_path, "not a lock\n").unwrap();
    let output = project.raeva(&["sync", "--offline"]);
    assert_success(&output, "regenerate without git");
    assert!(
        text(&output).contains(
            "it names no platform this raeva supports; git has no readable raeva.lock at HEAD"
        ),
        "{}",
        text(&output)
    );
    assert_eq!(locked_platforms(&project), [host]);
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
    let root = tempfile::TempDir::new().expect("root");
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
    let module = root.path().join("modules/io");
    fs::create_dir_all(&module).expect("mkdir");
    fs::write(
        root.path().join("pom.xml"),
        pom("root", "<modules><module> modules\\io </module></modules>"),
    )
    .expect("root pom");
    fs::write(module.join("pom.xml"), pom("io", "")).expect("module pom");
    let raeva = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_raeva"))
            .env("RAEVA_HOME", home.path())
            .env("HOME", home.path())
            .env(rv_config::MAVEN_USER_HOME_TEST_ENV, home.path())
            .current_dir(&module)
            .args(args)
            .output()
            .expect("run raeva")
    };
    let sync = |args: &[&str]| raeva(&[args, &["sync", "--offline"]].concat());
    let refused = sync(&[]);
    assert_status(&refused, 2, "sync in a module");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    let root_path = dunce::canonicalize(root.path()).expect("canonical root");
    assert!(
        stderr.contains(&format!("raeva -C {} sync", root_path.display())),
        "{stderr}"
    );
    assert!(!module.join("raeva.lock").exists());
    // A command that reads the lock points at the reactor's, not at sync.
    for command in ["tree", "vuln"] {
        let read = raeva(&[command]);
        let stderr = String::from_utf8_lossy(&read.stderr);
        assert!(
            stderr.contains(&format!(
                "covers every module: add -C {})",
                root_path.display()
            )),
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
        fs::write(root.path().join("pom.xml"), pom("root", modules)).expect("root pom");
        assert_success(&sync(&[]), modules);
        fs::remove_file(module.join("raeva.lock")).expect("remove lock");
    }
    let literal = pom("root", "<modules><module>modules/io</module></modules>");
    fs::write(root.path().join("pom.xml"), literal).expect("root pom");
    assert_status(&sync(&[]), 2, "literal entry again");
    fs::write(module.join("raeva.toml"), "").expect("raeva.toml");
    assert_success(&sync(&[]), "raeva.toml");
}

/// A project depending on `libs` libraries that a stub central serves with
/// `.sha256` sidecars. The server stops when dropped.
fn stub_libraries(libs: usize) -> (rv_test_support::http::StubServer, tempfile::TempDir) {
    use rv_maven_types::BlobId;
    use rv_test_support::http::{Response, StubServer};

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
    let server = StubServer::start(move |request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        match files.get(path) {
            Some(body) if sidecar => {
                Response::new(200, BlobId::from_bytes(body.as_bytes()).to_string())
            }
            Some(body) => Response::new(200, body.clone()),
            None => Response::new(404, ""),
        }
    });
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
        ("metadata.db", "pom_cache_v3"),
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
                "SELECT EXISTS (SELECT 1 FROM pom_cache_v3 WHERE path = ?1)",
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
            "UPDATE pom_cache_v3 SET content = ?1 WHERE path = 'org/example/parent/1/parent-1.pom'",
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
