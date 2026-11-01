//! A project that locks its dependencies from a file repository inside the
//! project, so the tests run offline.

use std::fs;
use std::path::Path;
use std::process::Output;

use tempfile::TempDir;

use crate::common::{assert_success, raeva_command, sha256_hex};

pub(crate) fn publish_lib(repository: &Path) {
    let dir = repository.join("org/test/lib/1.0");
    fs::create_dir_all(&dir).expect("create repository");
    let files: [(&str, &[u8]); 2] = [
        (
            "lib-1.0.pom",
            b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version></project>",
        ),
        ("lib-1.0.jar", b"lib jar bytes"),
    ];
    for (name, bytes) in files {
        fs::write(dir.join(name), bytes).expect("write file");
        fs::write(dir.join(format!("{name}.sha256")), sha256_hex(bytes)).expect("write sidecar");
    }
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
        assert_success(&project.raeva(&["sync", "--offline"]), "offline sync");
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
        message.contains("allow_env_substitution in config.toml"),
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
             <id>local</id><url>file://${{project.basedir}}/../repository/</url></repository>\
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
    fs::create_dir_all(jar.parent().unwrap()).unwrap();
    fs::write(&jar, b"jar without a POM").unwrap();
    fs::write(
        jar.with_extension("jar.sha256"),
        sha256_hex(b"jar without a POM"),
    )
    .unwrap();
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
        fs::write(dir.join(file), replaced).unwrap();
        fs::write(dir.join(format!("{file}.sha256")), sha256_hex(replaced)).unwrap();
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
    fs::write(dir.join("remote-1.pom"), remote).unwrap();
    fs::write(
        dir.join("remote-1.pom.sha256"),
        sha256_hex(remote.as_bytes()),
    )
    .unwrap();
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
    fs::write(dir.join("remote-1.pom"), remote).unwrap();
    fs::write(
        dir.join("remote-1.pom.sha256"),
        sha256_hex(remote.as_bytes()),
    )
    .unwrap();
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
