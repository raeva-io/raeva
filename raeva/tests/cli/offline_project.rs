//! A project that locks its dependencies from a file repository inside the
//! project, so the tests run offline.

use std::fs;
use std::path::Path;
use std::process::Output;

use tempfile::TempDir;

use crate::common::{
    assert_status, assert_success, raeva_command, run_raeva, sha1_hex, sha256_hex,
    write_with_sha256,
};

pub(crate) fn publish_lib(repository: &Path) {
    let dir = repository.join("org/test/lib/1.0");
    let pom = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version></project>";
    write_with_sha256(&dir.join("lib-1.0.pom"), pom);
    write_with_sha256(&dir.join("lib-1.0.jar"), b"lib jar bytes");
}

/// A project at `<base>/project` that depends on `org.test:lib:1.0` from its
/// own `repository/` directory, synced offline, with its own Raeva home.
pub(crate) struct Project {
    base: TempDir,
    home: TempDir,
}

impl Project {
    /// A project whose files are `files`, paths relative to its root, with
    /// `org.test:lib:1.0` published in `repository/`, synced offline.
    pub(crate) fn synced_with(files: &[(&str, &str)]) -> Self {
        let project = Self::with(files);
        assert_success(&project.raeva(&["sync", "--offline"]), "offline sync");
        project
    }

    /// The same project, not synced.
    pub(crate) fn with(files: &[(&str, &str)]) -> Self {
        let project = Self {
            base: TempDir::new().expect("base"),
            home: TempDir::new().expect("home"),
        };
        publish_lib(&project.root().join("repository"));
        for (path, text) in files {
            let path = project.root().join(path);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(path, text).expect("write project file");
        }
        project
    }

    pub(crate) fn synced() -> Self {
        Self::synced_with(&[(
            "pom.xml",
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>
  </repositories>
  <dependencies><dependency>
    <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>
  </dependency></dependencies>
</project>
"#,
        )])
    }

    /// The `HOME` and `USERPROFILE` of its raeva runs.
    pub(crate) fn home(&self) -> &Path {
        self.home.path()
    }

    pub(crate) fn root(&self) -> std::path::PathBuf {
        self.base.path().join("project")
    }

    pub(crate) fn m2(&self) -> std::path::PathBuf {
        self.base.path().join("m2")
    }

    pub(crate) fn raeva_home(&self) -> &std::path::Path {
        self.home.path()
    }

    pub(crate) fn m2_settings(&self) -> std::path::PathBuf {
        let m2 = self.home.path().join(".m2");
        fs::create_dir_all(&m2).expect("create .m2");
        m2.join("settings.xml")
    }

    pub(crate) fn raeva_with(&self, env: &[(&str, &str)], args: &[&str]) -> Output {
        fs::create_dir_all(self.root()).expect("project dir");
        let mut command = raeva_command(&self.root(), self.home.path());
        for (name, value) in env {
            command.env(name, value);
        }
        command.args(args).output().expect("run raeva")
    }

    pub(crate) fn raeva(&self, args: &[&str]) -> Output {
        self.raeva_with(&[], args)
    }

    /// [`crate::common::publish`] into the project's `repository/`.
    pub(crate) fn publish(&self, coordinate: &str, body: &str) {
        crate::common::publish(&self.root().join("repository"), coordinate, body);
    }
}

/// A range lists its versions in every repository, Maven Central too,
/// which raeva adds after the project's. The test harness answers for
/// Central, so a sync that is not offline still never leaves the machine.
#[test]
fn central_answers_from_the_test_harness() {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>
  </repositories>
  <dependencies><dependency>
    <groupId>org.test</groupId><artifactId>lib</artifactId><version>[1.0,2)</version>
  </dependency></dependencies>
</project>
"#,
        ),
        (
            "repository/org/test/lib/maven-metadata.xml",
            "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <versioning><versions><version>1.0</version></versions></versioning></metadata>",
        ),
    ]);
    fs::remove_file(project.root().join("raeva.lock")).expect("remove lock");
    assert_success(&project.raeva(&["sync"]), "sync");
    let listing = "/maven2/org/test/lib/maven-metadata.xml";
    let requested: Vec<_> = (crate::common::central_stand_in().requests().into_iter())
        .map(|request| request.path)
        .collect();
    assert!(
        requested.iter().any(|path| path == listing),
        "{requested:?}"
    );
}

#[test]
fn the_first_lock_says_to_commit_it() {
    let project = Project::synced();
    fs::remove_file(project.root().join("raeva.lock")).expect("remove lock");
    let note = "Commit raeva.lock. CI checks it with 'raeva sync --frozen'.";
    let first = project.raeva(&["sync", "--offline"]);
    assert_success(&first, "first sync");
    let stderr = String::from_utf8_lossy(&first.stderr);
    assert!(stderr.contains(note), "{stderr}");
    let again = project.raeva(&["sync", "--offline"]);
    assert_success(&again, "second sync");
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(!stderr.contains(note), "{stderr}");
}

/// BOM imports nested as deep as a model allows, each BOM taking the next
/// import from its parent, resolve within the stack raeva gives its threads.
#[test]
fn the_deepest_bom_imports_fit_the_stack() {
    const BOMS: usize = 49;
    let import = |artifact: &str| {
        format!(
            "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>"
        )
    };
    let mut files = vec![(
        "pom.xml".to_string(),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><repositories><repository>\
             <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
             </repository></repositories>{}<dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>lib</artifactId></dependency>\
             </dependencies></project>",
            import("bom0")
        ),
    )];
    for level in 0..BOMS {
        let managed = if level + 1 < BOMS {
            import(&format!("bom{}", level + 1))
        } else {
            "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>\
             </dependencyManagement>"
                .to_string()
        };
        let parent = format!(
            "<parent><groupId>org.test</groupId><artifactId>bom-parent{level}</artifactId>\
             <version>1</version><relativePath/></parent>"
        );
        for (artifact, body) in [
            (format!("bom{level}"), parent),
            (format!("bom-parent{level}"), managed),
        ] {
            let path = format!("repository/org/test/{artifact}/1/{artifact}-1.pom");
            let pom = format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>{artifact}</artifactId><version>1</version>\
                 <packaging>pom</packaging>{body}</project>"
            );
            files.push((format!("{path}.sha256"), sha256_hex(pom.as_bytes())));
            files.push((path, pom));
        }
    }
    let files: Vec<(&str, &str)> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    let artifacts = &lock.platforms[0].artifacts;
    assert_eq!(artifacts.len(), 1, "{artifacts:?}");
}

/// A set variable outside the allowlist is named, never its value, whether
/// the model reads it as `${NAME}` or an activation as `env.NAME`; an unset
/// one reads the same in Maven and is not reported, nor are the host paths
/// `JAVA_HOME` and `PWD`.
#[test]
fn a_hidden_environment_variable_is_named() {
    let project = Project::synced_with(&[(
        "pom.xml",
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <profiles><profile><id>ci</id>
    <activation><property><name>env.RAEVA_TEST_HIDDEN</name></property></activation>
  </profile><profile><id>unset</id>
    <activation><property><name>env.RAEVA_TEST_UNSET</name></property></activation>
  </profile><profile><id>pwd</id>
    <activation><property><name>env.PWD</name></property></activation>
  </profile><profile><id>java</id>
    <activation><property><name>env.JAVA_HOME</name></property></activation>
  </profile></profiles>
  <dependencies><dependency>
    <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>
    <exclusions><exclusion>
      <groupId>${RAEVA_TEST_BARE}</groupId><artifactId>${env.RAEVA_TEST_UNSET}</artifactId>
    </exclusion></exclusions>
  </dependency></dependencies>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>
  </repositories>
</project>
"#,
    )]);
    fs::remove_file(project.root().join("raeva.lock")).expect("remove lock");
    let output = project.raeva_with(
        &[
            ("RAEVA_TEST_HIDDEN", "hidden-value-1234"),
            ("RAEVA_TEST_BARE", "bare-value-5678"),
            ("PWD", "/work"),
            ("JAVA_HOME", "/jdk"),
        ],
        &["--json", "sync", "--offline"],
    );
    assert_success(&output, "sync");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("hidden-value-1234") && !stdout.contains("bare-value-5678"),
        "{stdout}"
    );
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("JSON");
    let hidden: Vec<_> = (envelope["data"]["warnings"]
        .as_array()
        .into_iter()
        .flatten())
    .filter(|warning| warning["code"] == "ENV_VAR_HIDDEN")
    .collect();
    let variables: Vec<_> = hidden.iter().map(|w| &w["context"]["variable"]).collect();
    assert_eq!(
        variables,
        ["RAEVA_TEST_BARE", "RAEVA_TEST_HIDDEN"],
        "{envelope}"
    );
    let message = hidden[0]["message"].as_str().expect("message");
    assert!(
        message.contains(
            "allow_env_substitution in config.toml; this is part of raeva.lock's \
             configuration, so set it on every machine that syncs, or on none"
        ),
        "{message}"
    );
}

/// What module graphs log is shown in reactor order, up to the first graph
/// that fails: a later module resolving meanwhile stays quiet.
#[test]
fn a_failed_module_graph_hides_what_later_graphs_logged() {
    let module = |name: &str, dependency: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{name}</artifactId><version>1</version><repositories><repository>\
             <id>files</id><url>file://${{project.basedir}}/../repository/</url></repository>\
             </repositories><dependencies><dependency><groupId>org.test</groupId>{dependency}\
             </dependency></dependencies></project>"
        )
    };
    let lib = "<artifactId>lib</artifactId><version>1.0</version>";
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module><module>b</module></modules></project>",
        ),
        ("a/pom.xml", &module("a", lib)),
        ("b/pom.xml", &module("b", lib)),
    ]);
    let root = project.root();
    // Every repository answers offline, so a missing POM is not a failure.
    fs::write(
        root.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"central\"\nurl = \"{}\"\n",
            url::Url::from_directory_path(root.join("repository")).unwrap()
        ),
    )
    .unwrap();
    let jar = root.join("repository/org/test/nopom/1.0/nopom-1.0.jar");
    write_with_sha256(&jar, b"jar without a POM");
    for (name, dependency) in [
        (
            "a",
            "<artifactId>absent</artifactId><version>[5,6)</version>",
        ),
        ("b", "<artifactId>nopom</artifactId><version>1.0</version>"),
    ] {
        fs::write(root.join(name).join("pom.xml"), module(name, dependency)).unwrap();
    }
    let sync = project.raeva(&["sync", "--offline"]);
    let stderr = String::from_utf8_lossy(&sync.stderr);
    assert!(!sync.status.success(), "{stderr}");
    assert!(stderr.contains("absent"), "{stderr}");
    assert!(!stderr.contains("the POM is missing"), "{stderr}");
    fs::write(root.join("a/pom.xml"), module("a", lib)).unwrap();
    let sync = project.raeva(&["sync", "--offline"]);
    assert_success(&sync, "sync with a POM-less dependency");
    assert!(
        String::from_utf8_lossy(&sync.stderr).contains("the POM is missing"),
        "{}",
        String::from_utf8_lossy(&sync.stderr)
    );
}

/// A republished release file fails a sync that resolves again, after a POM
/// edit and with nothing cached, as its download fails without one. Only
/// `--update` locks the new bytes.
#[test]
fn a_republished_release_file_is_locked_again_only_by_update() {
    for (file, replaced) in [
        ("lib-1.0.jar", b"other jar bytes".as_slice()),
        (
            "lib-1.0.pom",
            b"<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
<artifactId>lib</artifactId><version>1.0</version><!-- republished --></project>",
        ),
    ] {
        let project = Project::synced();
        let root = project.root();
        let dir = root.join("repository/org/test/lib/1.0");
        write_with_sha256(&dir.join(file), replaced);
        let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
        fs::write(
            root.join("pom.xml"),
            pom.replace(
                "<version>1</version>",
                "<version>1</version><name>edited</name>",
            ),
        )
        .unwrap();
        let lock = fs::read(root.join("raeva.lock")).unwrap();
        for args in [
            &["sync", "--offline", "--frozen"][..],
            &["sync", "--offline"],
        ] {
            fs::remove_dir_all(project.home.path()).unwrap();
            let output = project.raeva(args);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(7), "{file} {args:?}: {stderr}");
            let mismatch = format!("org/test/lib/1.0/{file}: expected sha256");
            assert!(stderr.contains(&mismatch), "{stderr}");
            assert!(stderr.contains("raeva sync --update"), "{stderr}");
            assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), lock);
        }
        assert_success(&project.raeva(&["sync", "--offline", "--update"]), "update");
        let updated = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(updated.contains(&sha256_hex(replaced)), "{updated}");
    }
}

/// Other bytes a repository serves for a release file the lock pins are
/// refused before the store keeps them, so once the repository serves the
/// pinned bytes again, neither an update nor another project takes the
/// refused ones from the cache.
#[test]
fn a_refused_release_file_is_not_kept_for_a_later_sync() {
    for (file, replaced) in [
        ("lib-1.0.jar", b"other jar bytes".as_slice()),
        (
            "lib-1.0.pom",
            b"<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
<artifactId>lib</artifactId><version>1.0</version><!-- replaced --></project>",
        ),
    ] {
        let project = Project::synced();
        let root = project.root();
        let path = root.join("repository/org/test/lib/1.0").join(file);
        let sidecar = path.with_file_name(format!("{file}.sha256"));
        let original = fs::read(&path).unwrap();
        fs::write(&path, replaced).unwrap();
        fs::write(&sidecar, sha256_hex(replaced)).unwrap();
        let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
        let edited = pom.replace("<version>1</version>", "<version>1</version><name>e</name>");
        fs::write(root.join("pom.xml"), &edited).unwrap();
        fs::remove_dir_all(project.home.path()).unwrap();
        for args in [
            &["sync", "--offline", "--frozen"][..],
            &["sync", "--offline"],
        ] {
            let output = project.raeva(args);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(7), "{file} {args:?}: {stderr}");
        }
        fs::write(&path, &original).unwrap();
        fs::write(&sidecar, sha256_hex(&original)).unwrap();

        let other = project.base.path().join("other");
        fs::create_dir_all(&other).unwrap();
        let repository = format!("file://{}/repository/", root.display());
        let other_pom = edited
            .replace(
                "<artifactId>root</artifactId>",
                "<artifactId>other</artifactId>",
            )
            .replace("file://${project.basedir}/repository/", &repository);
        fs::write(other.join("pom.xml"), other_pom).unwrap();
        let output = run_raeva(&other, project.home.path(), &["sync", "--offline"]);
        assert_success(&output, "other project");
        let other_lock = fs::read_to_string(other.join("raeva.lock")).unwrap();
        assert!(
            other_lock.contains(&sha256_hex(&original)),
            "{file}: {other_lock}"
        );
        assert!(
            !other_lock.contains(&sha256_hex(replaced)),
            "{file}: {other_lock}"
        );

        assert_success(&project.raeva(&["sync", "--offline", "--update"]), "update");
        let updated = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(
            updated.contains(&sha256_hex(&original)),
            "{file}: {updated}"
        );
        assert!(
            !updated.contains(&sha256_hex(replaced)),
            "{file}: {updated}"
        );
    }
}

/// A repository the lock does not record for a file, searched first, is held
/// to the pin as the recorded one is.
#[test]
fn another_repository_is_held_to_the_pin() {
    let project = Project::synced_with(&[
        ("first/.keep", ""),
        (
            "pom.xml",
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <repositories>
    <repository><id>first</id><url>file://${project.basedir}/first/</url></repository>
    <repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>
  </repositories>
  <dependencies><dependency>
    <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>
  </dependency></dependencies>
</project>
"#,
        ),
    ]);
    let root = project.root();
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("/repository/"), "{lock}");
    publish_lib(&root.join("first"));
    let jar = root.join("first/org/test/lib/1.0/lib-1.0.jar");
    let original = fs::read(&jar).unwrap();
    let replaced = b"other jar bytes";
    write_with_sha256(&jar, replaced);
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    let edited = pom.replace("<version>1</version>", "<version>1</version><name>e</name>");
    fs::write(root.join("pom.xml"), edited).unwrap();
    fs::remove_dir_all(project.home.path()).unwrap();
    let output = project.raeva(&["sync", "--offline"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");

    write_with_sha256(&jar, &original);
    assert_success(&project.raeva(&["sync", "--offline", "--update"]), "update");
    let updated = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(updated.contains(&sha256_hex(&original)), "{updated}");
    assert!(!updated.contains(&sha256_hex(replaced)), "{updated}");
}

/// `export-m2 --with-sources` exports the pinned copy of a sources jar the
/// lock pins, which a restore stored without its checksum file, rather than
/// other bytes the repository now serves.
#[test]
fn a_pinned_sources_jar_is_exported_only_as_pinned() {
    let project = Project::synced_with(&[
        (
            "repository/org/test/lib/1.0/lib-1.0-sources.jar",
            "lib sources",
        ),
        (
            "repository/org/test/lib/1.0/lib-1.0-sources.jar.sha256",
            &sha256_hex(b"lib sources"),
        ),
        (
            "pom.xml",
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>
  </repositories>
  <dependencies>
    <dependency><groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version></dependency>
    <dependency><groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version><classifier>sources</classifier></dependency>
  </dependencies>
</project>
"#,
        ),
    ]);
    let root = project.root();
    let sources = root.join("repository/org/test/lib/1.0/lib-1.0-sources.jar");
    let sidecar = sources.with_extension("jar.sha256");
    fs::remove_file(&sidecar).unwrap();
    fs::remove_dir_all(project.home.path()).unwrap();
    assert_success(&project.raeva(&["sync", "--frozen"]), "restore");
    let replaced = b"other sources";
    fs::write(&sources, replaced).unwrap();
    fs::write(&sidecar, sha256_hex(replaced)).unwrap();
    let m2 = project.m2();
    let m2_path = m2.to_str().unwrap();
    let args = [
        "export-m2",
        "--offline",
        "--with-sources",
        "--m2-path",
        m2_path,
    ];
    assert_success(&project.raeva(&args), "export");
    let exported = m2.join("org/test/lib/1.0/lib-1.0-sources.jar");
    assert_eq!(fs::read(exported).unwrap(), b"lib sources");
    let other = sha256_hex(replaced);
    let blobs = project.home.path().join("store/blobs");
    assert!(
        !blobs
            .join(&other[..2])
            .join(&other[2..4])
            .join(&other)
            .exists()
    );
}

/// A sources jar `--with-sources` would refuse to replace stops the export,
/// and its dry run, before the locked jar is written.
#[test]
fn a_refused_sources_jar_stops_the_export_before_any_write() {
    let project = Project::synced_with(&[
        (
            "repository/org/test/lib/1.0/lib-1.0-sources.jar",
            "lib sources",
        ),
        (
            "repository/org/test/lib/1.0/lib-1.0-sources.jar.sha256",
            &sha256_hex(b"lib sources"),
        ),
        (
            "pom.xml",
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>
  </repositories>
  <dependencies><dependency>
    <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>
  </dependency></dependencies>
</project>
"#,
        ),
    ]);
    let m2 = project.m2();
    let directory = m2.join("org/test/lib/1.0");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("lib-1.0-sources.jar"), "other sources").unwrap();
    let m2_path = m2.to_str().unwrap();
    // The dry run goes first: it judges a jar no export has fetched yet.
    for dry_run in [&["--dry-run"][..], &[][..]] {
        let args = [
            &["export-m2", "--with-sources", "--m2-path", m2_path][..],
            dry_run,
        ]
        .concat();
        let output = project.raeva(&args);
        crate::common::assert_status(&output, 1, "refused sources jar");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("lib-1.0-sources.jar"), "{stderr}");
        let names: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["lib-1.0-sources.jar"], "{dry_run:?}");
    }
}

/// A row that pins only a SHA-1 digest binds the file as a SHA-256 pin does.
#[test]
fn a_sha1_pin_refuses_other_bytes() {
    let project = Project::synced();
    let root = project.root();
    let path = root.join("repository/org/test/lib/1.0/lib-1.0.jar");
    let original = fs::read(&path).unwrap();
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let sha256_row = format!(
        "algorithm = \"sha256\"\ndigest = \"{}\"",
        sha256_hex(&original)
    );
    let sha1_row = format!("algorithm = \"sha1\"\ndigest = \"{}\"", sha1_hex(&original));
    assert!(lock.contains(&sha256_row), "{lock}");
    fs::write(
        root.join("raeva.lock"),
        lock.replace(&sha256_row, &sha1_row),
    )
    .unwrap();
    let lock = fs::read(root.join("raeva.lock")).unwrap();
    let replaced = b"other jar bytes";
    write_with_sha256(&path, replaced);
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    let edited = pom.replace("<version>1</version>", "<version>1</version><name>e</name>");
    fs::write(root.join("pom.xml"), edited).unwrap();
    fs::remove_dir_all(project.home.path()).unwrap();
    let output = project.raeva(&["sync", "--offline"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert!(stderr.contains("raeva sync --update"), "{stderr}");
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), lock);
}

#[test]
fn a_reactor_module_dependency_ignores_the_module_relocation() {
    let module = |name: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{name}</artifactId><version>1</version>{body}</project>"
        )
    };
    let dependency = |artifact: &str, version: &str| {
        format!(
            "<repositories><repository><id>project-local</id>\
             <url>file://${{project.basedir}}/../repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version></dependency>\
             </dependencies>"
        )
    };
    let ext = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>ext</artifactId><version>1.0</version><dependencies><dependency>\
        <groupId>org.test</groupId><artifactId>a</artifactId><version>1</version>\
        </dependency></dependencies></project>";
    let ext_dir = "repository/org/test/ext/1.0";
    let files = [
        (
            "pom.xml".to_owned(),
            module(
                "root",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                 <module>c</module></modules>",
            ),
        ),
        (
            "a/pom.xml".to_owned(),
            module(
                "a",
                "<distributionManagement><relocation><artifactId>lib</artifactId>\
                 <version>1.0</version></relocation></distributionManagement>",
            ),
        ),
        ("b/pom.xml".to_owned(), module("b", &dependency("a", "1"))),
        (
            "c/pom.xml".to_owned(),
            module("c", &dependency("ext", "1.0")),
        ),
        (format!("{ext_dir}/ext-1.0.pom"), ext.to_owned()),
        (
            format!("{ext_dir}/ext-1.0.pom.sha256"),
            sha256_hex(ext.as_bytes()),
        ),
        (format!("{ext_dir}/ext-1.0.jar"), "ext jar".to_owned()),
        (
            format!("{ext_dir}/ext-1.0.jar.sha256"),
            sha256_hex(b"ext jar"),
        ),
    ];
    let files: Vec<(&str, &str)> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).unwrap();
    for path in ["b/pom.xml", "c/pom.xml"] {
        let consumer = (lock.platforms[0].modules.iter())
            .find(|module| module.path == path)
            .unwrap();
        let packages: Vec<String> = (consumer.packages.iter())
            .map(|package| package.coordinate.gav.to_string())
            .collect();
        assert!(
            packages.contains(&"org.test:a:1".to_owned()),
            "{packages:?}"
        );
        assert!(
            !packages.contains(&"org.test:lib:1.0".to_owned()),
            "{packages:?}"
        );
    }
}

/// The remote parent's `<groupId>` reads a property module `q` sets, so
/// `q`'s group is not the one its `<parent>` element names. A module that
/// depends on `q` keeps a lock that can be trusted.
#[test]
fn a_module_group_a_remote_parent_decides_keeps_its_consumers_trusted() {
    let project = Project::synced();
    let root = project.root();
    let remote = "<project><modelVersion>4.0.0</modelVersion><groupId>${g}</groupId>\
        <artifactId>remote</artifactId><version>1</version><packaging>pom</packaging>\
        <properties><g>org.test</g></properties></project>";
    let dir = root.join("repository/org/test/remote/1");
    fs::create_dir_all(&dir).unwrap();
    write_with_sha256(&dir.join("remote-1.pom"), remote.as_bytes());
    let repositories = format!(
        "<repositories><repository><id>project-local</id>\
         <url>file://{}/repository/</url></repository></repositories>",
        root.display()
    );
    fs::write(
        root.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
         <modules><module>q</module><module>b</module></modules></project>",
    )
    .unwrap();
    for (module, pom) in [
        (
            "q",
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
                 <artifactId>remote</artifactId><version>1</version><relativePath/></parent>\
                 <artifactId>q</artifactId><properties><g>org.other</g></properties>\
                 {repositories}</project>"
            ),
        ),
        (
            "b",
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>b</artifactId><version>1</version>{repositories}<dependencies>\
                 <dependency><groupId>org.other</groupId><artifactId>q</artifactId>\
                 <version>1</version></dependency></dependencies></project>"
            ),
        ),
    ] {
        fs::create_dir_all(root.join(module)).unwrap();
        fs::write(root.join(module).join("pom.xml"), pom).unwrap();
    }
    let both = [
        "sync",
        "--offline",
        "--platforms",
        "linux-x86_64,macos-aarch64",
    ];
    assert_success(&project.raeva(&both), "sync both platforms");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    let modules: Vec<String> = (lock.platforms[0].modules.iter())
        .map(|module| module.gav.to_string())
        .collect();
    assert!(modules.contains(&"org.other:q:1".to_owned()), "{modules:?}");
    let frozen = project.raeva(&[&both[..1], &["--frozen"], &both[1..]].concat());
    assert_success(&frozen, "frozen");
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(!stderr.contains("changed"), "{stderr}");
    let linux = project.raeva(&["sync", "--offline", "--platforms", "linux-x86_64"]);
    assert_success(&linux, "sync one platform");
    let stderr = String::from_utf8_lossy(&linux.stderr);
    assert!(!stderr.contains("Dropping stale platform"), "{stderr}");
}

#[test]
fn a_module_version_a_remote_parent_decides_keeps_the_lock_trusted() {
    let project = Project::synced();
    let root = project.root();
    let remote = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>remote</artifactId><version>1</version><packaging>pom</packaging>\
        <properties><p.version>2</p.version></properties></project>";
    let dir = root.join("repository/org/test/remote/1");
    fs::create_dir_all(&dir).unwrap();
    write_with_sha256(&dir.join("remote-1.pom"), remote.as_bytes());
    fs::write(
        root.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
         <modules><module>p</module></modules></project>",
    )
    .unwrap();
    fs::create_dir_all(root.join("p")).unwrap();
    fs::write(
        root.join("p/pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>remote</artifactId><version>1</version><relativePath/></parent>\
             <artifactId>p</artifactId><version>${{p.version}}</version>\
             <repositories><repository><id>project-local</id>\
             <url>file://{}/repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>1.0</version></dependency></dependencies></project>",
            root.display()
        ),
    )
    .unwrap();
    let both = [
        "sync",
        "--offline",
        "--platforms",
        "linux-x86_64,macos-aarch64",
    ];
    assert_success(&project.raeva(&both), "sync both platforms");
    let frozen = project.raeva(&[&both[..1], &["--frozen"], &both[1..]].concat());
    assert_success(&frozen, "frozen");
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(!stderr.contains("changed"), "{stderr}");
    let linux = project.raeva(&["sync", "--offline", "--platforms", "linux-x86_64"]);
    assert_success(&linux, "sync one platform");
    let stderr = String::from_utf8_lossy(&linux.stderr);
    assert!(!stderr.contains("Dropping stale platform"), "{stderr}");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    let modules: Vec<String> = (lock.platforms[0].modules.iter())
        .map(|module| module.gav.to_string())
        .collect();
    assert!(modules.contains(&"org.test:p:2".to_owned()), "{modules:?}");
    assert!(
        (lock.platforms.iter()).any(|entry| entry.platform.to_string().starts_with("macos")),
        "{:?}",
        lock.platforms
    );
}

/// Maven orders the spellings a range admits that compare equal by its map
/// of every version listed, in the range or not: with thirteen listed it
/// takes `1.0-ga` over `1.0`, with two it would take `1.0`.
#[test]
fn equal_spellings_in_a_range_follow_every_version_listed() {
    let listed: String = ["1.0", "1.0-ga"]
        .into_iter()
        .map(str::to_string)
        .chain((2..=12).map(|major| major.to_string()))
        .map(|version| format!("<version>{version}</version>"))
        .collect();
    let metadata = format!(
        "<metadata><groupId>g</groupId><artifactId>a</artifactId>\
         <versioning><versions>{listed}</versions></versioning></metadata>"
    );
    let project = Project::with(&[
        (
            "pom.xml",
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>
  </repositories>
  <dependencies><dependency>
    <groupId>g</groupId><artifactId>a</artifactId><version>[1,2)</version>
  </dependency></dependencies>
</project>
"#,
        ),
        ("repository/g/a/maven-metadata.xml", &metadata),
    ]);
    let on = |name: &str| {
        format!(
            "<dependencies><dependency><groupId>g</groupId><artifactId>{name}</artifactId>\
             <version>1</version></dependency></dependencies>"
        )
    };
    project.publish("g:a:1.0", &on("left"));
    project.publish("g:a:1.0-ga", &on("right"));
    project.publish("g:left:1", "");
    project.publish("g:right:1", "");
    assert_success(&project.raeva(&["sync", "--offline"]), "offline sync");
    let lock = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
    let packages = "packages = \"\"\"\ng:a:1.0-ga\\tjar\\tcompile\ng:right:1\\tjar\"\"\"";
    assert!(lock.contains(packages), "{lock}");
}

/// A parent range takes the last of the versions Maven sorts, so of two
/// spellings that compare equal it takes the one the map orders last,
/// `1.0.0`, whichever the metadata lists first.
#[test]
fn a_parent_range_takes_the_spelling_maven_sorts_last() {
    let project = Project::with(&[
        (
            "pom.xml",
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>g</groupId><artifactId>p</artifactId><version>[1,2)</version><relativePath/></parent>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>
  </repositories>
  <dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId></dependency></dependencies>
</project>
"#,
        ),
        (
            "repository/g/p/maven-metadata.xml",
            "<metadata><groupId>g</groupId><artifactId>p</artifactId><versioning><versions>\
             <version>1.0</version><version>1.0.0</version></versions></versioning></metadata>",
        ),
    ]);
    // The repository that serves the parent names its full path.
    let pom = project.root().join("pom.xml");
    let repository = format!("file://{}/repository/", project.root().display());
    let text = fs::read_to_string(&pom).unwrap();
    fs::write(
        &pom,
        text.replace("file://${project.basedir}/repository/", &repository),
    )
    .unwrap();
    for (parent, lib) in [("1.0", "1"), ("1.0.0", "2")] {
        project.publish(
            &format!("g:p:{parent}"),
            &format!(
                "<packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
                 <groupId>g</groupId><artifactId>lib</artifactId><version>{lib}</version>\
                 </dependency></dependencies></dependencyManagement>"
            ),
        );
        project.publish(&format!("g:lib:{lib}"), "");
    }
    assert_success(&project.raeva(&["sync", "--offline"]), "offline sync");
    let lock = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
    assert!(
        lock.contains("packages = \"g:lib:2\\tjar\\tcompile\""),
        "{lock}"
    );
    assert!(lock.contains("parents = \"g:p:1.0.0\""), "{lock}");
}

/// A reactor module's version counts among the versions a dependency's
/// parent range lists, in the range or not: with `p:par:12` in the reactor
/// thirteen are listed, and Maven 3.9.12 and 3.10.0 take `1.0` over
/// `1.0-ga`, which twelve would order the other way.
#[test]
fn a_parent_range_counts_the_reactor_versions() {
    let listed: String = ["1.0", "1.0-ga"]
        .into_iter()
        .map(str::to_string)
        .chain((2..=11).map(|major| major.to_string()))
        .map(|version| format!("<version>{version}</version>"))
        .collect();
    let metadata = format!(
        "<metadata><groupId>p</groupId><artifactId>par</artifactId>\
         <versioning><versions>{listed}</versions></versioning></metadata>"
    );
    let project = Project::with(&[
        (
            "pom.xml",
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <packaging>pom</packaging>
  <repositories>
    <repository><id>project-local</id><url>file://${project.basedir}/repository/</url></repository>
  </repositories>
  <modules><module>par</module><module>app</module></modules>
</project>
"#,
        ),
        (
            "par/pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>p</groupId>\
             <artifactId>par</artifactId><version>12</version><packaging>pom</packaging></project>",
        ),
        (
            "app/pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version></parent><artifactId>app</artifactId>\
             <dependencies><dependency><groupId>g</groupId><artifactId>wrapper</artifactId>\
             <version>1</version></dependency></dependencies></project>",
        ),
        ("repository/p/par/maven-metadata.xml", &metadata),
    ]);
    let pom = project.root().join("pom.xml");
    let repository = format!("file://{}/repository/", project.root().display());
    let text = fs::read_to_string(&pom).unwrap();
    fs::write(
        &pom,
        text.replace("file://${project.basedir}/repository/", &repository),
    )
    .unwrap();
    for (parent, leaf) in [("1.0", "1"), ("1.0-ga", "2")] {
        project.publish(
            &format!("p:par:{parent}"),
            &format!(
                "<packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
                 <groupId>p</groupId><artifactId>leaf</artifactId><version>{leaf}</version>\
                 </dependency></dependencies></dependencyManagement>"
            ),
        );
        project.publish(&format!("p:leaf:{leaf}"), "");
    }
    let wrapper = project.root().join("repository/g/wrapper/1/wrapper-1.pom");
    project.publish(
        "g:wrapper:1",
        "<dependencies><dependency><groupId>p</groupId><artifactId>leaf</artifactId>\
         </dependency></dependencies>",
    );
    let text = fs::read_to_string(&wrapper).unwrap().replacen(
        "<groupId>g</groupId>",
        "<parent><groupId>p</groupId><artifactId>par</artifactId><version>[1,2)</version>\
         <relativePath/></parent><groupId>g</groupId>",
        1,
    );
    crate::common::write_with_sha256(&wrapper, text.as_bytes());
    assert_success(&project.raeva(&["sync", "--offline"]), "offline sync");
    let lock = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
    assert!(lock.contains("p:leaf:1\\t"), "{lock}");
    assert!(!lock.contains("p:leaf:2"), "{lock}");
}

/// Maven 3.9.12 and 3.10.0 read the project's POMs, the reactor's and the
/// file at a `<relativePath>`, with the strict model reader and fail the
/// build with "Malformed POM" on `<profiles>` inside `<profiles>`, also
/// when the file there declares another parent than the one asked for. A
/// POM from a repository, as a dependency, a parent or an imported BOM, is
/// read leniently, which skips the element, and the project file its
/// parent's `<relativePath>` names is not read.
#[test]
fn a_project_pom_is_read_strictly_and_a_repository_pom_leniently() {
    const NESTED: &str = "<profiles><profiles><profile><id>p</id></profile></profiles></profiles>";
    let project = |parent: &str, body: &str, files: &[(&str, &str)]| {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion>{parent}<groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><repositories><repository>\
             <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
             </repository></repositories>{body}</project>"
        );
        Project::with(&[&[("pom.xml", pom.as_str())], files].concat())
    };
    let parent = |artifact: &str, path: &str| {
        format!(
            "<parent><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version><relativePath>{path}</relativePath></parent>"
        )
    };
    let local_parent = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
         {NESTED}</project>"
    );
    let module = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>m</artifactId><version>1</version>{NESTED}</project>"
    );
    let reactor = "<packaging>pom</packaging><modules><module>m</module></modules>";
    for (case, parent, body, files, file) in [
        ("root", String::new(), NESTED, &[][..], "pom.xml"),
        (
            "module",
            String::new(),
            reactor,
            &[("m/pom.xml", module.as_str())][..],
            "m/pom.xml",
        ),
        (
            "local parent",
            parent("parent", "p/pom.xml"),
            "",
            &[("p/pom.xml", local_parent.as_str())][..],
            "p/pom.xml",
        ),
        (
            "another project at the parent's path",
            parent("other", "p"),
            "",
            &[("p/pom.xml", local_parent.as_str())][..],
            "p/pom.xml",
        ),
    ] {
        let project = project(&parent, body, files);
        project.publish("org.test:other:1", "<packaging>pom</packaging>");
        let output = project.raeva(&["sync", "--offline"]);
        assert_status(&output, 3, case);
        let message = crate::common::stderr(&output);
        assert!(
            message.contains("Malformed POM")
                && message.contains("Unrecognised tag: 'profiles' at line 1")
                && message.replace('\\', "/").contains(file)
                && !message.contains(r"\\?\"),
            "{case}: {message}"
        );
    }

    let project = project("", "", &[]);
    for coordinate in ["org.test:dep:1", "org.test:bom:1", "org.test:base:1"] {
        let packaging = if coordinate.ends_with("dep:1") {
            ""
        } else {
            "<packaging>pom</packaging>"
        };
        project.publish(coordinate, &format!("{packaging}{NESTED}"));
    }
    // Maven never opens the project file a repository POM's parent names.
    project.publish("org.test:gp:1", "<packaging>pom</packaging>");
    project.publish(
        "org.test:dep:1",
        &format!(
            "<parent><groupId>org.test</groupId><artifactId>gp</artifactId><version>1</version>\
             <relativePath>sub/pom.xml</relativePath></parent>{NESTED}"
        ),
    );
    let bad_gp = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>gp</artifactId><version>1</version><packaging>pom</packaging>{NESTED}\
         </project>"
    );
    fs::create_dir_all(project.root().join("sub")).unwrap();
    fs::write(project.root().join("sub/pom.xml"), bad_gp).unwrap();
    let pom = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
         <artifactId>base</artifactId><version>1</version><relativePath/></parent>\
         <artifactId>root</artifactId><repositories><repository><id>project-local</id>\
         <url>file://${project.basedir}/repository/</url></repository></repositories>\
         <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>bom</artifactId><version>1</version><type>pom</type>\
         <scope>import</scope></dependency></dependencies></dependencyManagement>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>dep</artifactId>\
         <version>1</version></dependency></dependencies></project>";
    fs::write(project.root().join("pom.xml"), pom).unwrap();
    let url = url::Url::from_directory_path(project.root().join("repository")).unwrap();
    fs::write(
        project.root().join("raeva.toml"),
        format!("[[repositories]]\nid = \"project-local\"\nurl = \"{url}\"\n"),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "repository POMs");
    let lock = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
    assert!(lock.contains("org.test:dep:1"), "{lock}");
}
