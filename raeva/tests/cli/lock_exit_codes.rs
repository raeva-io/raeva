//! Frozen sync, export, sbom, and vuln report a lock they refuse to read as
//! `LOCKFILE_INVALID` (exit 3) and a lock that is out of date as
//! `LOCKFILE_MISMATCH` (exit 7). `lock verify` uses the same codes for a
//! lock it refuses and for a pin the store does not match.

use std::fs;

use crate::common::{assert_status, assert_success, raeva_command, sha256_hex, write_repo_toml};
use crate::offline_project::Project;

/// The commands that re-check the project against raeva.lock, plus `lock
/// verify`, with arguments that keep them offline.
fn readers(project: &Project) -> Vec<Vec<String>> {
    let m2 = project.m2().to_str().expect("utf-8 path").to_string();
    [
        &["sync", "--frozen", "--offline"][..],
        &["lock", "verify"],
        &["export-m2", "--m2-path", &m2],
        &["export-checksums"],
        &["sbom"],
        &["vuln"],
    ]
    .iter()
    .map(|args| args.iter().map(|arg| arg.to_string()).collect())
    .collect()
}

/// Run `args` in JSON mode and check its exit status and envelope code.
fn assert_fails_with(project: &Project, args: &[String], status: i32, code: &str) {
    let mut json = vec!["--json"];
    json.extend(args.iter().map(String::as_str));
    // `raeva vuln` must fail before it queries anything; a closed port makes
    // a query fail differently.
    let output = project.raeva_with(&[("RAEVA_OSV_BASE_URL", "http://127.0.0.1:9/")], &json);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("{args:?}: not one JSON envelope ({err}): {stdout}"));
    assert_status(&output, status, &format!("{args:?}"));
    assert_eq!(envelope["exit_code"], status, "{args:?}: {envelope}");
    assert_eq!(envelope["code"], code, "{args:?}: {envelope}");
}

#[test]
fn a_lock_that_cannot_be_read_exits_3_with_lockfile_invalid() {
    let project = Project::synced();
    let lock_path = project.root().join("raeva.lock");
    let original = fs::read_to_string(&lock_path).expect("read lock");
    let edits = [
        (
            "repo_ids",
            original.replace("repo_ids = \"\"\"\n", "repo_ids = \"\"\"\nno-tab-here\n"),
        ),
        (
            "support_repo_ids",
            original.replace(
                "[metadata]\n",
                "[metadata]\nsupport_repo_ids = \"\"\"\norg.test:parent:1\\tnot-a-digest\"\"\"\n",
            ),
        ),
    ];
    for (label, edited) in edits {
        assert_ne!(edited, original, "{label}");
        fs::write(&lock_path, &edited).expect("write lock");
        for args in readers(&project) {
            assert_fails_with(&project, &args, 3, "LOCKFILE_INVALID");
        }
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), edited, "{label}");
    }
}

/// A lock a newer raeva wrote asks for that raeva, and no sync rewrites it
/// in this raeva's schema. An older one is still regenerated.
#[test]
fn a_lock_from_a_newer_raeva_asks_for_an_upgrade() {
    let project = Project::synced();
    let lock_path = project.root().join("raeva.lock");
    let original = fs::read_to_string(&lock_path).expect("read lock");
    let current = format!("schema_version = {}\n", rv_lock::LOCKFILE_SCHEMA_VERSION);
    let newer = format!(
        "schema_version = {}\n",
        rv_lock::LOCKFILE_SCHEMA_VERSION + 1
    );
    let edited = original.replace(&current, &newer);
    assert_ne!(edited, original);
    fs::write(&lock_path, &edited).expect("write lock");
    let mut readers = readers(&project);
    readers.push(vec!["sync".to_string(), "--offline".to_string()]);
    for args in readers {
        let mut json = vec!["--json"];
        json.extend(args.iter().map(String::as_str));
        let output = project.raeva_with(&[("RAEVA_OSV_BASE_URL", "http://127.0.0.1:9/")], &json);
        assert_status(&output, 3, &format!("{args:?}"));
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON envelope");
        assert_eq!(envelope["code"], "LOCKFILE_INVALID", "{args:?}: {envelope}");
        let text = envelope.to_string();
        let named = format!("schema version {}", rv_lock::LOCKFILE_SCHEMA_VERSION + 1);
        assert!(text.contains(&named), "{args:?}: {envelope}");
        assert!(text.contains("Upgrade raeva"), "{args:?}: {envelope}");
        assert!(!text.contains("raeva sync"), "{args:?}: {envelope}");
        assert!(!text.contains("scan failed"), "{args:?}: {envelope}");
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), edited, "{args:?}");
    }

    // A conflict with a newer schema on one side is refused too.
    let conflicted = original.replace(
        &current,
        &format!("<<<<<<< ours\n{current}=======\n{newer}>>>>>>> theirs\n"),
    );
    fs::write(&lock_path, &conflicted).expect("write lock");
    let output = project.raeva(&["--json", "sync", "--offline"]);
    assert_status(&output, 3, "plain sync on a conflict with a newer schema");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Upgrade raeva"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), conflicted);
    let output = project.raeva(&["--json", "sync", "--frozen", "--offline"]);
    assert_status(&output, 3, "frozen on a conflict with a newer schema");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Upgrade raeva"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // A newer --baseline names the upgrade too.
    let baseline = project.root().join("baseline.lock");
    fs::write(&baseline, &edited).expect("write baseline");
    fs::write(&lock_path, &original).expect("restore lock");
    let output = project.raeva_with(
        &[("RAEVA_OSV_BASE_URL", "http://127.0.0.1:9/")],
        &[
            "--json",
            "vuln",
            "--baseline",
            baseline.to_str().expect("utf-8 path"),
        ],
    );
    assert_status(&output, 3, "vuln with a newer baseline");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("upgrade raeva"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let older = format!(
        "schema_version = {}\n",
        rv_lock::LOCKFILE_SCHEMA_VERSION - 1
    );
    fs::write(&lock_path, original.replace(&current, &older)).expect("write lock");
    let frozen = project.raeva(&["sync", "--frozen", "--offline"]);
    assert_status(&frozen, 3, "frozen on an older lock");
    assert!(
        String::from_utf8_lossy(&frozen.stderr).contains("without --frozen to regenerate"),
        "{}",
        String::from_utf8_lossy(&frozen.stderr)
    );
    assert_success(&project.raeva(&["sync", "--offline"]), "regenerate");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), original);
}

#[test]
fn a_lock_that_is_out_of_date_exits_7_with_lockfile_mismatch() {
    let project = Project::synced();
    let pom = project.root().join("pom.xml");
    let original = fs::read_to_string(&pom).expect("read pom");
    fs::write(
        &pom,
        original.replace(
            "<version>1.0</version>",
            "<version>1.0</version><scope>test</scope>",
        ),
    )
    .expect("edit pom");
    for args in readers(&project) {
        // lock verify checks the lock against the store, not the project.
        if args[0] != "lock" {
            assert_fails_with(&project, &args, 7, "LOCKFILE_MISMATCH");
        }
    }
    // Configuration drift still fails before the store or metadata cache.
    // `sync --frozen` takes the lockfile guard under the cache dir first.
    let config_path = project.root().join("raeva.toml");
    fs::write(&config_path, "inactive_profiles = [\"ci\"]\n").expect("change config");
    let unused_home = project.root().with_file_name("unused-home");
    let env = [
        ("RAEVA_HOME", unused_home.to_str().expect("utf-8 path")),
        ("RAEVA_OSV_BASE_URL", "http://127.0.0.1:9/"),
    ];
    for args in readers(&project) {
        if args[0] == "lock" {
            continue;
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = project.raeva_with(&env, &args);
        assert_status(&output, 7, &format!("{args:?}"));
        assert!(
            !unused_home.join("store").exists(),
            "{args:?} opened the store"
        );
        assert!(
            !unused_home.join("metadata.db").exists(),
            "{args:?} opened metadata.db"
        );
        assert!(!project.m2().exists(), "{args:?} created the export target");
        if unused_home.exists() {
            assert_eq!(args[0], "sync", "{args:?} created raeva home");
            fs::remove_dir_all(&unused_home).expect("remove sync cache");
        }
    }

    fs::remove_file(config_path).expect("restore config");
    fs::write(&pom, &original).expect("restore pom");
    let lock_path = project.root().join("raeva.lock");
    let lock = fs::read_to_string(&lock_path).expect("read lock");
    let digest = sha256_hex(b"lib jar bytes");
    let edited = lock.replace(&digest, &"a".repeat(64));
    assert_ne!(edited, lock);
    fs::write(&lock_path, edited).expect("write lock");
    let verify = ["lock".to_string(), "verify".to_string()];
    assert_fails_with(&project, &verify, 7, "LOCKFILE_MISMATCH");
}

/// An offline sync that needs a file raeva never downloaded says how to get
/// it.
#[test]
fn an_offline_sync_with_an_empty_store_says_to_sync_online_first() {
    let base = tempfile::TempDir::new().expect("base");
    let home = tempfile::TempDir::new().expect("home");
    fs::write(
        base.path().join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <repositories>
    <repository><id>remote</id><url>http://127.0.0.1:9/repository/</url></repository>
  </repositories>
  <dependencies><dependency>
    <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>
  </dependency></dependencies>
</project>
"#,
    )
    .expect("write pom");
    let output = crate::common::raeva_command(base.path(), home.path())
        .args(["--json", "sync", "--offline"])
        .output()
        .expect("run raeva");
    assert_status(&output, 5, "offline without cache");
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["code"], "OFFLINE_NOT_CACHED", "{envelope}");
    assert!(
        envelope["hints"][0]
            .as_str()
            .is_some_and(|hint| hint.contains("sync' without --offline once")),
        "{envelope}"
    );
}

/// POM bytes are a reuse key, not the frozen contract. Use a file repository
/// so both resolution modes and the export run without sockets.
#[test]
fn frozen_and_exports_accept_pom_edits_that_preserve_pins() {
    let project = Project::synced();
    let pom = project.root().join("pom.xml");
    let original = fs::read_to_string(&pom).unwrap().replace(
        "</project>",
        "<build><plugins><plugin><groupId>org.apache.maven.plugins</groupId>\
         <artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version>\
         </plugin></plugins></build></project>",
    );
    fs::write(&pom, &original).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "record plugin");
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read(&lock_path).unwrap();
    let m2 = project.m2();
    let frozen = [
        &["sync", "--frozen"][..],
        &["sync", "--frozen", "--offline"],
    ];
    let commands = [
        frozen[0],
        frozen[1],
        &["export-m2", "--m2-path", m2.to_str().unwrap()],
        &["export-m2", "--m2-path", m2.to_str().unwrap(), "--offline"],
        &["export-checksums"],
        &["export-checksums", "--offline"],
        &["sbom"],
        &["sbom", "--offline"],
    ];
    for (edited, commands) in [
        (
            original.replace("</project>", "<!-- comment --></project>"),
            &commands[..],
        ),
        (
            original.replace("</project>", "<description>edited</description></project>"),
            &frozen[..],
        ),
        (original.replace("3.13.0", "3.14.0"), &frozen[..]),
    ] {
        fs::write(&pom, edited).unwrap();
        for args in commands {
            let output = project.raeva(args);
            assert_success(&output, &format!("{args:?}"));
            let stderr = String::from_utf8_lossy(&output.stderr);
            let note = "pom.xml changed since raeva.lock was written, without \
                        changing the dependencies; a plain 'raeva sync' records its new hash.";
            assert_eq!(stderr.matches(note).count(), 1, "{stderr}");
            assert_eq!(fs::read(&lock_path).unwrap(), locked);
        }
    }

    // A plain sync still records changed model hashes and restores the fast path.
    assert_success(&project.raeva(&["sync", "--offline"]), "record edited POM");
    assert_ne!(fs::read(&lock_path).unwrap(), locked);
    fs::write(&lock_path, &locked).unwrap();

    // This POM is already cached, so the new dependency reaches the entry
    // comparison in either mode rather than failing to fetch it.
    fs::write(
        &pom,
        original.replace(
            "</dependencies>",
            "<dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
         <version>1.0</version><type>pom</type></dependency></dependencies>",
        ),
    )
    .unwrap();
    for args in frozen {
        let output = project.raeva(args);
        assert_status(&output, 7, "frozen after packaging change");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("changes these entries:"), "{stderr}");
        assert!(
            stderr.contains("lib:pom") && stderr.contains("added"),
            "{stderr}"
        );
        assert_eq!(fs::read(&lock_path).unwrap(), locked);
    }
}

#[test]
fn changed_poms_need_cached_inputs_when_frozen_offline() {
    let project = Project::synced();
    let pom = project.root().join("pom.xml");
    let original = fs::read_to_string(&pom).unwrap();
    fs::write(
        &pom,
        original.replace("</project>", "<!-- edit --></project>"),
    )
    .unwrap();
    fs::remove_dir_all(project.root().join("repository")).unwrap();
    let home = tempfile::TempDir::new().unwrap();
    for args in [
        &["--json", "sync", "--frozen", "--offline"][..],
        &["--json", "export-m2", "--offline", "--dry-run"],
    ] {
        let output = project.raeva_with(&[("RAEVA_HOME", home.path().to_str().unwrap())], args);
        assert_status(&output, 5, &format!("{args:?}"));
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["code"], "OFFLINE_NOT_CACHED", "{envelope}");
    }
}

#[test]
fn accepted_parent_and_module_edits_are_named_once() {
    let project = Project::synced_with(&[
        (
            "parent/pom.xml",
            "<project><groupId>org.test</groupId><artifactId>parent</artifactId>\
         <version>1</version><packaging>pom</packaging></project>",
        ),
        (
            "pom.xml",
            "<project><parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
         <version>1</version><relativePath>parent/pom.xml</relativePath></parent>\
         <artifactId>root</artifactId></project>",
        ),
    ]);
    for path in ["parent/pom.xml", "pom.xml"] {
        let path = project.root().join(path);
        let original = fs::read_to_string(&path).unwrap();
        fs::write(
            path,
            original.replace("</project>", "<!-- edit --></project>"),
        )
        .unwrap();
    }
    for args in [
        &["sync", "--frozen"][..],
        &["sync", "--frozen", "--offline"],
        &["export-m2", "--offline", "--dry-run"],
    ] {
        let output = project.raeva(args);
        assert_success(&output, "accept parent and module edits");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.matches("parent/pom.xml, pom.xml changed").count(),
            1,
            "{stderr}"
        );
    }
}

#[test]
fn partial_frozen_checks_detect_removed_support_pins() {
    let current = rv_lock::Platform::current()
        .expect("host platform")
        .to_string();
    let other = if cfg!(windows) {
        "linux-x86_64"
    } else {
        "windows-x86_64"
    };
    let platforms = format!("{current},{other}");
    let project = Project::synced();
    let bom_dir = project.root().join("repository/org/test/bom/1");
    fs::create_dir_all(&bom_dir).unwrap();
    fs::write(
        bom_dir.join("bom-1.pom"),
        "<project><groupId>org.test</groupId><artifactId>bom</artifactId>\
         <version>1</version><packaging>pom</packaging></project>",
    )
    .unwrap();
    let pom = project.root().join("pom.xml");
    let original = fs::read_to_string(&pom).unwrap();
    let import = "<dependencyManagement><dependencies><dependency>\
        <groupId>org.test</groupId><artifactId>bom</artifactId><version>1</version>\
        <type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>";
    let importing = original.replace("</project>", &format!("{import}</project>"));
    fs::write(&pom, &importing).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", &platforms]),
        "lock both platforms and BOM",
    );
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read(&lock_path).unwrap();
    assert!(String::from_utf8_lossy(&locked).contains("org.test:bom:1"));

    fs::write(
        &pom,
        importing.replace("</project>", "<!-- edit --></project>"),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "a harmless edit still accepts a multi-platform lock",
    );
    for offline in [false, true] {
        let mut args = vec!["sync", "--frozen", "--platforms", &current];
        if offline {
            args.push("--offline");
        }
        let output = project.raeva(&args);
        assert_success(&output, &format!("a harmless edit under {args:?}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("PLATFORM_DROPPED"), "{stderr}");
    }
    fs::write(&pom, original).unwrap();
    for offline in [false, true] {
        for command in [
            vec!["sync", "--frozen"],
            vec!["sync", "--frozen", "--platforms", &current],
            vec!["export-m2", "--dry-run"],
            vec!["export-checksums"],
            vec!["sbom"],
        ] {
            let mut args = command;
            if offline {
                args.push("--offline");
            }
            let output = project.raeva(&args);
            assert_status(&output, 7, &format!("{args:?}"));
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("org.test:bom:1"), "{args:?}: {stderr}");
            assert_eq!(fs::read(&lock_path).unwrap(), locked);
        }
    }
    assert_success(&project.raeva(&["sync", "--offline"]), "remove BOM pin");
    let updated = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert!(!updated.support_poms().contains_key("org.test:bom:1"));
    assert_eq!(updated.platforms.len(), 2);
}

#[test]
fn frozen_detects_model_changes_confined_to_an_unselected_platform() {
    let child = "<project><groupId>org.test</groupId><artifactId>win</artifactId>\
        <version>1</version></project>";
    let project = Project::synced_with(&[
        ("windows/pom.xml", child),
        (
            "pom.xml",
            "<project><groupId>org.test</groupId><artifactId>root</artifactId>\
         <version>1</version><packaging>pom</packaging><profiles><profile><id>windows</id>\
         <activation><os><family>windows</family></os></activation>\
         <modules><module>windows</module></modules></profile></profiles></project>",
        ),
    ]);
    assert_success(
        &project.raeva(&[
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64,windows-x86_64",
        ]),
        "record platform-specific module",
    );
    let pom = project.root().join("windows/pom.xml");
    let frozen = [
        "sync",
        "--frozen",
        "--offline",
        "--platforms",
        "linux-x86_64",
    ];
    fs::write(&pom, child.replace("</project>", "<!-- edit --></project>")).unwrap();
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read(&lock_path).unwrap();
    assert_success(&project.raeva(&frozen), "accept unselected module comment");
    fs::write(
        &pom,
        child.replace(
            "<version>1</version>",
            "<version>1</version><packaging>pom</packaging>",
        ),
    )
    .unwrap();
    let online = ["sync", "--frozen", "--platforms", "linux-x86_64"];
    for args in [&frozen[..], &online, &["sbom", "--offline"]] {
        let output = project.raeva(args);
        assert_status(&output, 7, &format!("{args:?}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("windows"), "{args:?}: {stderr}");
        assert_eq!(fs::read(&lock_path).unwrap(), locked);
    }
}

#[test]
fn frozen_detects_system_file_changes_on_an_unselected_platform() {
    let project = Project::synced_with(&[
        ("lib/windows.jar", "original bytes"),
        (
            "pom.xml",
            "<project><groupId>org.test</groupId><artifactId>root</artifactId>\
             <version>1</version><profiles><profile><id>windows</id>\
             <activation><os><family>windows</family></os></activation>\
             <dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>windows</artifactId><version>1</version><scope>system</scope>\
             <systemPath>${project.basedir}/lib/windows.jar</systemPath>\
             </dependency></dependencies></profile></profiles></project>",
        ),
    ]);
    assert_success(
        &project.raeva(&[
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64,windows-x86_64",
        ]),
        "lock both platforms",
    );
    let frozen = [
        "sync",
        "--frozen",
        "--offline",
        "--platforms",
        "linux-x86_64",
    ];
    assert_success(&project.raeva(&frozen), "accept unchanged system file");
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read(&lock_path).unwrap();
    fs::write(project.root().join("lib/windows.jar"), "changed bytes").unwrap();
    for args in [&frozen[..], &["sbom", "--offline"]] {
        let output = project.raeva(args);
        assert_status(&output, 7, &format!("{args:?}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("lib/windows.jar changed"), "{stderr}");
        assert_eq!(fs::read(&lock_path).unwrap(), locked);
    }
    // The plain sync of the same selection acts on it, as `--frozen` asks.
    let plain = project.raeva(&["sync", "--offline", "--platforms", "linux-x86_64"]);
    assert_success(&plain, "drop the changed platform");
    let stderr = String::from_utf8_lossy(&plain.stderr);
    assert!(stderr.contains("PLATFORM_DROPPED"), "{stderr}");
    assert_success(&project.raeva(&frozen), "accept the selection's lock");
    fs::write(&lock_path, &locked).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "record changed system file",
    );
    assert_ne!(fs::read(&lock_path).unwrap(), locked);
    assert_success(&project.raeva(&frozen), "accept updated system pin");
}

#[test]
fn pom_repository_reordering_keeps_a_declared_frozen_origin() {
    let project = Project::synced();
    crate::offline_project::publish_lib(&project.root().join("other-repository"));
    let pom = project.root().join("pom.xml");
    let original = fs::read_to_string(&pom).unwrap();
    let first = "<repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>";
    let second = "<repository><id>other-local</id><url>file://${project.basedir}/other-repository/</url></repository>";
    fs::write(&pom, original.replace(first, &format!("{first}{second}"))).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "record both repositories",
    );
    let lock_path = project.root().join("raeva.lock");
    let locked = fs::read(&lock_path).unwrap();
    fs::write(&pom, original.replace(first, &format!("{second}{first}"))).unwrap();
    for offline in [false, true] {
        for mut args in [
            vec!["sync", "--frozen"],
            vec!["export-m2", "--dry-run"],
            vec!["export-checksums"],
            vec!["sbom"],
        ] {
            if offline {
                args.push("--offline");
            }
            assert_success(&project.raeva(&args), &format!("{args:?}"));
            assert_eq!(fs::read(&lock_path).unwrap(), locked);
        }
    }
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "record reordered origin",
    );
    let updated = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert_eq!(
        updated.platforms[0].artifacts[0].repo_url,
        "./other-repository/"
    );
}

#[test]
fn fresh_offline_commands_verify_an_unchecked_cached_parent_with_its_pin() {
    use rv_store::metadata_cache::{CacheTable, MetadataCache};
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let repository = "https://repo.example/";
    write_repo_toml(project.path(), "fixture", repository);
    let pom = project.path().join("pom.xml");
    let original = "<project><parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
        <version>1</version><relativePath/></parent><artifactId>app</artifactId></project>";
    fs::write(&pom, original).unwrap();
    let paths = rv_config::ResolvedPaths::from_raeva_home(home.path().to_path_buf());
    let cache = MetadataCache::new(&paths.metadata_db_path()).unwrap();
    let scope = format!("{repository}\u{1f}{repository}\u{1f}id=fixture");
    let parent_path = "org/test/parent/1/parent-1.pom";
    let parent = b"<project><groupId>org.test</groupId><artifactId>parent</artifactId>\
        <version>1</version><packaging>pom</packaging></project>";
    // Seed the entry an earlier --allow-missing-checksums fetch leaves.
    cache
        .insert_with_ttl(CacheTable::Pom, &scope, parent_path, parent, 86400, false)
        .unwrap();
    let run = |args: &[&str]| {
        raeva_command(project.path(), home.path())
            .args(args)
            .output()
            .unwrap()
    };
    assert_success(
        &run(&["sync", "--offline", "--allow-missing-checksums"]),
        "pin cached parent",
    );
    let lock_path = project.path().join("raeva.lock");
    let locked = fs::read(&lock_path).unwrap();
    fs::write(
        &pom,
        original.replace("</project>", "<!-- edit --></project>"),
    )
    .unwrap();
    for args in [
        &["export-m2", "--offline", "--dry-run"][..],
        &["export-checksums", "--offline"],
        &["sbom", "--offline"],
        &["sync", "--frozen", "--offline"],
    ] {
        assert_success(&run(args), &format!("{args:?}"));
        assert_eq!(fs::read(&lock_path).unwrap(), locked);
    }

    cache
        .insert_with_ttl(
            CacheTable::Pom,
            &scope,
            parent_path,
            b"changed bytes",
            86400,
            false,
        )
        .unwrap();
    let output = run(&["--json", "sbom", "--offline"]);
    assert_status(&output, 5, "sbom after cache rewrite");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["code"], "OFFLINE_NOT_CACHED", "{envelope}");
}

/// Maven refuses a `.mvn/maven.config` it cannot read or parse, and so does
/// every command that may contact a repository. A command that reads only
/// raeva.lock and the store still runs.
#[test]
fn an_invalid_maven_config_stops_only_commands_that_use_repositories() {
    let project = Project::synced();
    let path = project.root().join(".mvn/maven.config");
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir .mvn");
    let mut cases: Vec<(&str, &[u8], &str)> = vec![
        ("unrecognized", b"-Dx=1\ngarbage\n", "INVALID_PROJECT_INPUT"),
        ("not UTF-8", b"-Dx=1\n\xff\n", "CONFIG"),
    ];
    if cfg!(unix) {
        cases.push(("unreadable", b"-Dx=1\n", "CONFIG"));
    }
    let readers: [&[&str]; 4] = [
        &["tree"],
        &["why", "org.test:lib"],
        &["lock", "info"],
        &["lock", "verify"],
    ];
    let users: [&[&str]; 2] = [
        &["sync", "--frozen", "--offline"],
        &["lock", "verify", "--download", "--offline"],
    ];
    for (label, content, code) in cases {
        fs::write(&path, content).expect("write maven.config");
        #[cfg(unix)]
        if label == "unreadable" {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod");
            if fs::read(&path).is_ok() {
                // Running as root, which reads it anyway.
                continue;
            }
        }
        for args in readers {
            assert_success(&project.raeva(args), &format!("{label} {args:?}"));
        }
        for args in users {
            let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
            assert_fails_with(&project, &args, 3, code);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        }
    }
}
