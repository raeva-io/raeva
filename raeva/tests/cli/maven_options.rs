//! The global `-D`, `-P` and `-s` options: what they select, how
//! `.mvn/maven.config` merges with them, and that `--frozen` fails when they
//! differ from the run that wrote raeva.lock.

use std::fs;
use std::path::Path;
use std::process::Output;

use crate::common::{
    assert_status, assert_success, raeva_command, sha256_hex, stderr, write_with_sha256,
};

/// A project whose dependency version is `${lib.version}`, 1.0 in the POM,
/// with a profile `extra` that adds `org.test:extra:1.0`, all served from
/// the project's `repository/`. The Raeva home and the Maven home are
/// `home`, which has no settings.xml.
struct Project {
    root: tempfile::TempDir,
    home: tempfile::TempDir,
}

fn publish(repository: &Path, artifact: &str, version: &str) {
    crate::common::publish(repository, &format!("org.test:{artifact}:{version}"), "");
}

impl Project {
    fn new() -> Self {
        let project = Self {
            root: tempfile::TempDir::new().expect("project"),
            home: tempfile::TempDir::new().expect("home"),
        };
        let repository = project.root.path().join("repository");
        for (artifact, version) in [("lib", "1.0"), ("lib", "2.0"), ("extra", "1.0")] {
            publish(&repository, artifact, version);
        }
        fs::write(
            project.root.path().join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version>\
             <properties><lib.version>1.0</lib.version></properties>\
             <repositories><repository><id>project-local</id>\
             <url>file://${project.basedir}/repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>${lib.version}</version></dependency></dependencies>\
             <profiles><profile><id>extra</id><dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>extra</artifactId><version>1.0</version>\
             </dependency></dependencies></profile></profiles></project>",
        )
        .expect("write pom.xml");
        project
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn raeva(&self, args: &[&str]) -> Output {
        raeva_command(self.path(), self.home.path())
            .args(args)
            .output()
            .expect("run raeva")
    }

    fn sync(&self, options: &[&str]) {
        let args = [options, &["sync", "--offline"]].concat();
        assert_success(&self.raeva(&args), &format!("sync {options:?}"));
    }

    fn frozen(&self, options: &[&str]) -> Output {
        self.raeva(&[options, &["sync", "--frozen", "--offline"]].concat())
    }

    fn write(&self, path: &str, text: &str) -> std::path::PathBuf {
        let path = self.path().join(path);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, text).expect("write");
        path
    }

    fn locked(&self) -> Vec<String> {
        let text = fs::read_to_string(self.path().join("raeva.lock")).expect("raeva.lock");
        let lock: toml::Value = toml::from_str(&text).expect("parse raeva.lock");
        let mut found: Vec<String> = lock["platforms"][0]["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .map(|row| {
                let c = &row["coordinate"];
                format!(
                    "{}:{}",
                    c["artifact"].as_str().expect("artifact"),
                    c["version"].as_str().expect("version")
                )
            })
            .collect();
        found.sort();
        found
    }
}

/// A settings file whose active profile sets `lib.version`.
fn settings(version: &str) -> String {
    format!(
        "<settings><profiles><profile><id>pin</id><properties>\
         <lib.version>{version}</lib.version></properties></profile></profiles>\
         <activeProfiles><activeProfile>pin</activeProfile></activeProfiles></settings>"
    )
}

#[test]
fn frozen_follows_the_define_option() {
    let project = Project::new();
    project.sync(&["-Dlib.version=2.0"]);
    assert_eq!(project.locked(), ["lib:2.0"]);
    assert_success(&project.frozen(&["--define", "lib.version=2.0"]), "same -D");

    for options in [&[][..], &["-Dlib.version=1.0"]] {
        let output = project.frozen(options);
        assert_status(&output, 7, &format!("frozen {options:?}"));
        assert!(
            stderr(&output).contains("the -D and -P options"),
            "{options:?}: {}",
            stderr(&output)
        );
    }
    assert_success(
        &project.frozen(&["-Dlib.version=2.0", "-Dother=1"]),
        "ignore an unread override",
    );
    project.write(".mvn/maven.config", "-Dlib.version=2.0\n");
    assert_success(
        &project.frozen(&[]),
        "same effective override from maven.config",
    );
    // Maven expands the values once they are merged, so a command-line -D
    // replaces a maven.config value that cannot expand.
    project.write(".mvn/maven.config", "-Dlib.version=${lib.version}\n");
    assert!(!project.raeva(&["sync", "--offline"]).status.success());
    project.sync(&["-Dlib.version=2.0"]);
    assert_eq!(project.locked(), ["lib:2.0"]);
}

#[test]
fn frozen_follows_the_profile_option() {
    let project = Project::new();
    project.sync(&["-Pextra"]);
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    assert_success(
        &project.frozen(&["--activate-profiles", "extra"]),
        "same -P",
    );
    assert_status(&project.frozen(&[]), 7, "no -P");
    assert_status(&project.frozen(&["-Pextra", "-P!extra"]), 7, "-P!extra");

    // A deselected profile that was off anyway still changes the input.
    project.sync(&["-P!extra"]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    assert_success(&project.frozen(&["-P!extra"]), "same -P!");
    assert_status(&project.frozen(&[]), 7, "-P! dropped");
}

/// raeva.lock names each `-P` id as Maven reads it, so two spellings of
/// one selection write the same raeva.lock.
#[test]
fn equivalent_profile_options_write_the_same_lock() {
    let project = Project::new();
    let lock = project.path().join("raeva.lock");
    project.sync(&["-Pextra", "-P!other"]);
    let written = fs::read_to_string(&lock).expect("raeva.lock");
    fs::remove_file(&lock).expect("remove raeva.lock");
    project.sync(&["-P +extra,,-other"]);
    assert_eq!(fs::read_to_string(&lock).expect("raeva.lock"), written);
}

/// `active_profiles` in raeva.toml adds to `<activeProfiles>`, as `-P`
/// does: the profile settings.xml names still sets `lib.version`.
#[test]
fn active_profiles_add_to_the_settings_active_profiles() {
    let project = Project::new();
    fs::create_dir_all(project.home.path().join(".m2")).expect("mkdir");
    fs::write(
        project.home.path().join(".m2/settings.xml"),
        settings("2.0"),
    )
    .expect("settings");
    project.write("raeva.toml", "active_profiles = [\"extra\"]\n");
    project.sync(&[]);
    assert_eq!(project.locked(), ["extra:1.0", "lib:2.0"]);
}

/// A profile `<activeProfiles>` names keeps its repositories in Maven's
/// request when `-P !id` turns it off, so they serve after Central what
/// nothing earlier has: the project's repository and Central's mirror keep
/// what they have.
#[test]
fn a_named_settings_profile_turned_off_keeps_its_repositories_after_central() {
    let project = Project::new();
    let corp = project.path().join("corp-repository");
    let central = project.path().join("central-mirror");
    for (artifact, version) in [("corp", "1.0"), ("lib", "1.0"), ("dual", "1.0")] {
        publish(&corp, artifact, version);
    }
    publish(&central, "dual", "1.0");
    let url = |dir: &Path| url::Url::from_directory_path(dir).expect("URL").to_string();
    fs::create_dir_all(project.home.path().join(".m2")).expect("mkdir");
    fs::write(
        project.home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>c</id><url>{}</url><mirrorOf>central</mirrorOf>\
             </mirror></mirrors><profiles><profile><id>corp</id><repositories><repository>\
             <id>corp-dep</id><url>{}</url></repository></repositories></profile>\
             </profiles><activeProfiles><activeProfile>corp</activeProfile>\
             </activeProfiles></settings>",
            url(&central),
            url(&corp)
        ),
    )
    .expect("settings");
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "</dependencies><profiles>",
            "<dependency><groupId>org.test</groupId><artifactId>corp</artifactId>\
             <version>1.0</version></dependency><dependency><groupId>org.test</groupId>\
             <artifactId>dual</artifactId><version>1.0</version></dependency>\
             </dependencies><profiles>",
        ),
    );
    project.sync(&["-P!corp"]);
    assert_eq!(project.locked(), ["corp:1.0", "dual:1.0", "lib:1.0"]);
    let text = fs::read_to_string(project.path().join("raeva.lock")).expect("raeva.lock");
    let lock: toml::Value = toml::from_str(&text).expect("parse raeva.lock");
    let origins: Vec<_> = (lock["platforms"][0]["artifacts"]
        .as_array()
        .expect("rows")
        .iter())
    .map(|row| {
        let artifact = row["coordinate"]["artifact"].as_str().expect("artifact");
        (artifact, row["repo_url"].as_str().expect("repo_url"))
    })
    .collect();
    assert_eq!(
        origins,
        [
            ("corp", "./corp-repository/"),
            ("dual", "https://repo1.maven.org/maven2/"),
            ("lib", "./repository/")
        ],
        "{text}"
    );
}

/// The project's own declaration of a repository that a profile turned off
/// by `-P !id` also names is searched before Central, as in Maven's model,
/// whose request copy under the same id is dropped.
#[test]
fn a_project_repository_a_turned_off_profile_also_names_precedes_central() {
    let project = Project::new();
    let corp = project.path().join("corp-repository");
    let central = project.path().join("central-mirror");
    for repository in [&corp, &central] {
        publish(repository, "corp", "1.0");
    }
    let url = |dir: &Path| url::Url::from_directory_path(dir).expect("URL").to_string();
    fs::create_dir_all(project.home.path().join(".m2")).expect("mkdir");
    fs::write(
        project.home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>c</id><url>{}</url><mirrorOf>central</mirrorOf>\
             </mirror></mirrors><profiles><profile><id>corp</id><repositories><repository>\
             <id>corp-dep</id><url>{}</url></repository></repositories></profile>\
             </profiles><activeProfiles><activeProfile>corp</activeProfile>\
             </activeProfiles></settings>",
            url(&central),
            url(&corp)
        ),
    )
    .expect("settings");
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "</repository></repositories>",
            "</repository><repository><id>corp-dep</id>\
             <url>file://${project.basedir}/corp-repository/</url></repository></repositories>",
        )
        .replace(
            "</dependencies><profiles>",
            "<dependency><groupId>org.test</groupId><artifactId>corp</artifactId>\
             <version>1.0</version></dependency></dependencies><profiles>",
        ),
    );
    project.sync(&["-P!corp"]);
    let text = fs::read_to_string(project.path().join("raeva.lock")).expect("raeva.lock");
    let lock: toml::Value = toml::from_str(&text).expect("parse raeva.lock");
    let rows = lock["platforms"][0]["artifacts"].as_array().expect("rows");
    let origin = (rows.iter())
        .find(|row| row["coordinate"]["artifact"].as_str() == Some("corp"))
        .map(|row| row["repo_url"].as_str().expect("repo_url").to_string());
    assert_eq!(origin.as_deref(), Some("./corp-repository/"), "{text}");
}

/// A `-P` value of `.mvn/maven.config` or `MAVEN_ARGS` that takes a
/// variable set here but outside `allow_env_substitution` names a profile
/// Maven reads and raeva cannot, so the sync refuses (exit 3), as a POM
/// activation on it does; 0.6.0 warned and locked without the profile.
/// Allowed, the variable is read, and `--frozen` fails once it changes.
#[test]
fn a_hidden_variable_in_a_profile_option_refuses() {
    let project = Project::new();
    let run = |args: &[&str], value: &str, maven_args: Option<&str>| {
        let mut command = raeva_command(project.path(), project.home.path());
        command.env("RAEVA_TEST_PROFILE", value).args(args);
        if let Some(maven_args) = maven_args {
            command.env("MAVEN_ARGS", maven_args);
        }
        command.output().expect("run raeva")
    };
    project.write(".mvn/maven.config", "-P${env.RAEVA_TEST_PROFILE}\n");
    let refused = run(&["sync", "--offline"], "extra", None);
    assert_status(&refused, 3, "maven.config");
    assert!(
        stderr(&refused).contains("${env.RAEVA_TEST_PROFILE}"),
        "{}",
        stderr(&refused)
    );
    fs::remove_file(project.path().join(".mvn/maven.config")).unwrap();
    let refused = run(
        &["sync", "--offline"],
        "extra",
        Some("-P${env.RAEVA_TEST_PROFILE}"),
    );
    assert_status(&refused, 3, "MAVEN_ARGS");
    assert!(!project.path().join("raeva.lock").exists());
    project.write(".mvn/maven.config", "-P${env.RAEVA_TEST_PROFILE}\n");
    fs::write(
        project.home.path().join("config.toml"),
        "[security]\nallow_env_substitution = [\"RAEVA_TEST_PROFILE\"]\n",
    )
    .unwrap();
    assert_success(&run(&["sync", "--offline"], "extra", None), "allowed");
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    assert_success(
        &run(&["sync", "--frozen", "--offline"], "extra", None),
        "frozen",
    );
    assert_status(
        &run(&["sync", "--frozen", "--offline"], "none", None),
        7,
        "changed",
    );
}

/// `-itr` in `.mvn/maven.config` is read, as Quarkus has it; in
/// `MAVEN_ARGS`, a host's own, it still refuses.
#[test]
fn ignoring_transitive_repositories_is_read_from_maven_config_only() {
    let project = Project::new();
    for option in ["-itr", "--ignore-transitive-repositories"] {
        project.write(".mvn/maven.config", &format!("{option}\n"));
        assert_success(&project.raeva(&["sync", "--offline"]), option);
        let mut command = raeva_command(project.path(), project.home.path());
        command
            .env("MAVEN_ARGS", option)
            .args(["sync", "--offline"]);
        let refused = command.output().expect("run raeva");
        assert_status(&refused, 3, option);
        assert!(stderr(&refused).contains(option), "{}", stderr(&refused));
    }
}

/// A Maven Wrapper script of the `script` type, as Maven Wrapper 3.1.1 to
/// 3.3.x write it, passes `MAVEN_CONFIG` to Maven before its own
/// arguments, where `mvn` and the `only-script` type pass none of it, so
/// with such a script in the project, or as the traced build's launcher,
/// raeva refuses a `MAVEN_CONFIG` that holds options Maven reads (exit 3),
/// but for a reactor selection, which it ignores as in `MAVEN_ARGS`, and
/// without one it is left out, as is a value such as the `maven` image's
/// `/root/.m2`.
#[test]
fn a_maven_config_a_wrapper_script_passes_refuses() {
    let project = Project::new();
    let run = |value: &str| {
        let mut command = raeva_command(project.path(), project.home.path());
        command
            .env("MAVEN_CONFIG", value)
            .args(["sync", "--offline"]);
        command.output().expect("run raeva")
    };
    assert_success(&run("-Pextra"), "no wrapper");
    assert_eq!(project.locked(), ["lib:1.0"]);
    let quiet = run("-pl app");
    assert_success(&quiet, "no wrapper, -pl");
    assert!(
        !stderr(&quiet).contains("SETTING_IGNORED"),
        "{}",
        stderr(&quiet)
    );
    project.write(
        "mvnw",
        "#!/bin/sh\nexec \"$JAVACMD\" $MAVEN_OPTS ${WRAPPER_LAUNCHER} $MAVEN_CONFIG \"$@\"\n",
    );
    for value in ["-Pextra", "-Dlib.version=2.0", "-B -s settings.xml"] {
        let refused = run(value);
        assert_status(&refused, 3, value);
        assert!(
            stderr(&refused).contains("MAVEN_CONFIG"),
            "{}",
            stderr(&refused)
        );
    }
    for value in ["/root/.m2", "-B -ntp", ""] {
        assert_success(&run(value), value);
    }
    // A reactor selection picks only the modules the build runs, and raeva
    // locks the whole reactor, so it is ignored, as in `MAVEN_ARGS`.
    let mut command = raeva_command(project.path(), project.home.path());
    command
        .env("MAVEN_CONFIG", "-B -pl app --also-make")
        .args(["--json", "sync", "--offline"]);
    let output = command.output().expect("run raeva");
    assert_success(&output, "MAVEN_CONFIG -pl -am");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let warnings = envelope["data"]["warnings"].as_array().expect("warnings");
    for option in ["-pl", "-am"] {
        let ignoring = format!("ignoring {option} in MAVEN_CONFIG; raeva locks the whole reactor");
        assert!(
            warnings.iter().any(|warning| {
                warning["code"] == "SETTING_IGNORED"
                    && (warning["message"].as_str())
                        .is_some_and(|message| message.contains(&ignoring))
            }),
            "{option}: {envelope}"
        );
    }
    assert_status(&run("-pl app -Dlib.version=2.0"), 3, "-pl with -D");
    // The same script as the traced build's launcher.
    let script = fs::read_to_string(project.path().join("mvnw")).unwrap();
    fs::remove_file(project.path().join("mvnw")).unwrap();
    project.write("tools/mvnw", &script);
    project.write(
        "raeva.toml",
        "[plugins]\nlock = true\ntrace = [\"validate\"]\nmvn = \"tools/mvnw\"\n",
    );
    assert_status(&run("-Pextra"), 3, "traced launcher");
}

/// A FIFO where a configuration file goes blocks the open that reads it.
/// `mvn` and `MavenCli` read `.mvn/jvm.config` and `.mvn/maven.config`
/// only when each is a regular file, so raeva skips such a one, and
/// refuses a settings.xml that is none (exit 3), without opening either.
#[cfg(unix)]
#[test]
fn a_configuration_fifo_is_not_opened() {
    let mkfifo = |path: &Path| {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let made = std::process::Command::new("mkfifo").arg(path).status();
        assert!(made.is_ok_and(|status| status.success()), "{path:?}");
    };
    let run = |project: &Project| {
        let mut child = raeva_command(project.path(), project.home.path())
            .args(["sync", "--offline"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("run raeva");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                panic!("raeva sync still runs after 120 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        child.wait_with_output().unwrap()
    };
    for file in [".mvn/jvm.config", ".mvn/maven.config"] {
        let project = Project::new();
        mkfifo(&project.path().join(file));
        assert_success(&run(&project), file);
        assert_eq!(project.locked(), ["lib:1.0"], "{file}");
    }
    let project = Project::new();
    mkfifo(&project.home.path().join(".m2/settings.xml"));
    let output = run(&project);
    assert_status(&output, 3, "settings.xml");
    assert!(
        stderr(&output).contains("not a regular file"),
        "{}",
        stderr(&output)
    );
}

/// A profile `.mvn/maven.config` turns on is named in the `--frozen` error,
/// which the lock's recorded command line cannot do.
#[test]
fn frozen_names_a_profile_maven_config_activates() {
    let project = Project::new();
    project.sync(&[]);
    project.write(".mvn/maven.config", "-Pextra\n");
    let output = project.frozen(&[]);
    assert_status(&output, 7, "maven.config -P");
    assert!(
        stderr(&output).contains("-Pextra is set here and was not when raeva.lock was written"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn jvm_config_activates_a_property_profile_and_invalidates_frozen() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<id>extra</id>",
            "<id>extra</id><activation><property><name>use.v2</name>\
             <value>true</value></property></activation>",
        ),
    );
    project.sync(&[]);
    project.write(".mvn/jvm.config", "-Xmx256m -Duse.v2=true\n-ea\n");
    let output = project.frozen(&[]);
    assert_status(&output, 7, "jvm.config activates a profile");
    assert!(
        stderr(&output).contains("jvm.config"),
        "{}",
        stderr(&output)
    );
    project.sync(&[]);
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    assert_success(&project.frozen(&[]), "unchanged jvm.config");
    project.write(".mvn/jvm.config", "-Duse.v2=false\n");
    assert_status(&project.frozen(&[]), 7, "changed jvm.config property");
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    project.write(".mvn/maven.config", "-Duse.v2=true\n");
    project.sync(&[]);
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    project.sync(&["-Duse.v2=false"]);
    assert_eq!(project.locked(), ["lib:1.0"]);
}

#[test]
fn jvm_config_system_properties_interpolate_below_pom_and_user_properties() {
    let project = Project::new();
    project.write(".mvn/jvm.config", "-Dlib.version=2.0\n");
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:1.0"]);

    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<properties><lib.version>1.0</lib.version></properties>",
            "",
        ),
    );
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:2.0"]);
    project.write(".mvn/jvm.config", "-Dlib.version=1.0\n");
    let output = project.frozen(&[]);
    assert_status(&output, 7, "jvm.config interpolation changed");
    assert!(
        stderr(&output).contains("jvm.config"),
        "{}",
        stderr(&output)
    );

    project.write(".mvn/maven.config", "-Dlib.version=2.0\n");
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:2.0"]);
    project.sync(&["-Dlib.version=1.0"]);
    assert_eq!(project.locked(), ["lib:1.0"]);
}

/// The JVM keeps its own value for `java.version` and the other names it
/// fixes, so a `-D` for one in jvm.config changes nothing.
#[test]
fn jvm_config_cannot_set_the_java_version() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<id>extra</id>",
            "<id>extra</id><activation><jdk>1.4</jdk></activation>",
        ),
    );
    project.write(
        ".mvn/jvm.config",
        "-Djava.version=1.4.2 -Djava.vm.version=1.4.2\n",
    );
    let output = raeva_command(project.path(), project.home.path())
        .env("JAVA_VERSION", "17")
        .args(["sync", "--offline"])
        .output()
        .expect("run raeva");
    assert_success(&output, "sync");
    assert_eq!(project.locked(), ["lib:1.0"]);
}

/// A settings.xml profile property ranks above jvm.config and below `-D`,
/// so `--frozen` checks it when only jvm.config set the name.
#[test]
fn frozen_checks_a_settings_property_that_shadows_jvm_config() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<properties><lib.version>1.0</lib.version></properties>",
            "",
        ),
    );
    project.write(".mvn/jvm.config", "-Dlib.version=1.0\n");
    let empty = project.write(
        "settings.xml",
        "<settings><profiles><profile><id>pin</id></profile></profiles>\
         <activeProfiles><activeProfile>pin</activeProfile></activeProfiles></settings>",
    );
    let empty = empty.to_str().expect("path").to_string();
    project.sync(&["-s", &empty]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    let pinned = project.write("pinned.xml", &settings("2.0"));
    let pinned = pinned.to_str().expect("path").to_string();
    assert_status(
        &project.frozen(&["-s", &pinned]),
        7,
        "settings property over jvm.config",
    );
    project.sync(&["-s", &pinned]);
    assert_eq!(project.locked(), ["lib:2.0"]);
}

/// B1: a JVM option's `-D` of a name the POM, an active settings profile
/// or an `activeByDefault` profile defines decides nothing, as the model's
/// own value ranks above a system property, so `--frozen` holds when it is
/// added or changes. A `-D` still overrides the model's value, and a
/// transitive POM that reads the name without defining it still takes it.
#[test]
fn a_jvm_option_a_model_property_hides_keeps_the_lock() {
    let project = Project::new();
    let opts = |value: &str| format!("-Dlib.version={value}");
    let frozen = |opts: &str, args: &[&str]| {
        project.raeva_opts(
            opts,
            &[],
            &[args, &["sync", "--frozen", "--offline"]].concat(),
        )
    };
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    project.write(".mvn/jvm.config", "-Dlib.version=2.0\n");
    assert_success(&frozen("", &[]), "a jvm.config value the POM hides");
    assert_success(
        &frozen(&opts("3.0"), &[]),
        "a MAVEN_OPTS value the POM hides",
    );
    let output = project.raeva_opts(
        "",
        &[("JAVA_TOOL_OPTIONS", "-Dlib.version=3.0")],
        &["sync", "--frozen", "--offline"],
    );
    assert_success(&output, "a JAVA_TOOL_OPTIONS value the POM hides");
    fs::remove_file(project.path().join(".mvn/jvm.config")).expect("rm jvm.config");

    project.sync(&["-Dlib.version=2.0"]);
    assert_eq!(project.locked(), ["lib:2.0"]);
    assert_status(
        &project.frozen(&["-Dlib.version=1.0"]),
        7,
        "a -D over the POM changed",
    );
    assert_status(&project.frozen(&[]), 7, "a -D over the POM removed");
    assert_success(
        &frozen(&opts("3.0"), &["-Dlib.version=2.0"]),
        "a JVM -D below the -D",
    );

    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    let unset = pom.replace(
        "<properties><lib.version>1.0</lib.version></properties>",
        "",
    );
    let by_default = unset.replace(
        "<profile><id>extra</id>",
        "<profile><id>pin</id><activation><activeByDefault>true</activeByDefault>\
         </activation><properties><lib.version>1.0</lib.version></properties></profile>\
         <profile><id>extra</id>",
    );
    project.write("pom.xml", &by_default);
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    assert_success(
        &frozen(&opts("2.0"), &[]),
        "an activeByDefault value hides it",
    );

    project.write("pom.xml", &unset);
    let pinned = project.write("pinned.xml", &settings("1.0"));
    let pinned = pinned.to_str().expect("path").to_string();
    project.sync(&["-s", &pinned]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    assert_success(
        &frozen(&opts("2.0"), &["-s", &pinned]),
        "a settings profile value hides it",
    );

    // The root reads its own value and a dependency reads the JVM's, so
    // the JVM's value decides the dependency's read.
    let lib = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>lib</artifactId><version>1.0</version><dependencies><dependency>\
               <groupId>org.test</groupId><artifactId>extra</artifactId>\
               <version>${extra.version}</version></dependency></dependencies></project>";
    let path = "repository/org/test/lib/1.0/lib-1.0.pom";
    fs::remove_file(project.path().join("raeva.lock")).expect("rm raeva.lock");
    project.write(path, lib);
    project.write(&format!("{path}.sha256"), &sha256_hex(lib.as_bytes()));
    project.write(
        "pom.xml",
        &pom.replace(
            "<lib.version>1.0</lib.version>",
            "<lib.version>1.0</lib.version><extra.version>1.0</extra.version>",
        )
        .replace(
            "<version>${lib.version}</version></dependency></dependencies>",
            "<version>${lib.version}</version></dependency><dependency>\
             <groupId>org.test</groupId><artifactId>extra</artifactId>\
             <version>${extra.version}</version></dependency></dependencies>",
        ),
    );
    let output = project.raeva_opts("-Dextra.version=1.0", &[], &["sync", "--offline"]);
    assert_success(&output, "a dependency reads the JVM value");
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    assert_success(&frozen("-Dextra.version=1.0", &[]), "unchanged");
    assert_status(
        &frozen("-Dextra.version=2.0", &[]),
        7,
        "the dependency's read changed",
    );
}

/// A project `app` whose `lib` version is `version`, with `lib.version` and
/// `app.version` 1.0 in a parent raeva fetches, so the lock cannot list
/// those POM properties.
fn with_fetched_parent(project: &Project, version: &str) {
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                  <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
                  <properties><lib.version>1.0</lib.version><app.version>1.0</app.version>\
                  </properties></project>";
    let path = "repository/org/test/parent/1/parent-1.pom";
    project.write(path, parent);
    project.write(&format!("{path}.sha256"), &sha256_hex(parent.as_bytes()));
    project.write(
        "pom.xml",
        &format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>parent</artifactId><version>1</version><relativePath/></parent>\
             <artifactId>app</artifactId><dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>{version}</version></dependency></dependencies></project>"
        ),
    );
    let url = url::Url::from_directory_path(project.path().join("repository")).expect("url");
    project.write(
        "raeva.toml",
        &format!("[[repositories]]\nid = \"local\"\nurl = \"{url}\"\n"),
    );
}

/// A POM property ranks below a `-D` and above `.mvn/jvm.config`, so the
/// same value moved from one to the other changes the dependencies.
#[test]
fn frozen_checks_a_jvm_config_value_moved_to_the_command_line() {
    let project = Project::new();
    with_fetched_parent(&project, "${lib.version}");
    project.write(".mvn/jvm.config", "-Dlib.version=2.0\n");
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    assert_status(&project.frozen(&["-Dlib.version=2.0"]), 7, "moved to -D");
    project.sync(&["-Dlib.version=2.0"]);
    assert_eq!(project.locked(), ["lib:2.0"]);
    assert_status(&project.frozen(&[]), 7, "moved back to jvm.config");
}

#[test]
fn jvm_config_properties_expand_maven_config_values() {
    let project = Project::new();
    project.write(".mvn/jvm.config", "-Dselected=1.0\t-Dselected=2.0\n");
    project.write(".mvn/maven.config", "-Dlib.version=${selected}\n");
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:2.0"]);
    assert_success(&project.frozen(&[]), "expanded jvm.config property");
    project.write(".mvn/jvm.config", "-Dselected=1.0\n");
    assert_status(&project.frozen(&[]), 7, "expanded jvm.config changed");
}

#[test]
fn jvm_config_activates_settings_profiles() {
    let project = Project::new();
    let file = project.write(
        "settings.xml",
        &settings("2.0")
            .replace(
                "<id>pin</id>",
                "<id>pin</id><activation><property><name>use.v2</name>\
             </property></activation>",
            )
            .replace(
                "<activeProfiles><activeProfile>pin</activeProfile></activeProfiles>",
                "",
            ),
    );
    project.write(".mvn/jvm.config", "-Duse.v2 -Dlib.version=1.0\n");
    project.sync(&["-s", file.to_str().expect("path")]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    project.write(".mvn/jvm.config", "-Duse.v2=true -Dlib.version=1.0\n");
    project.sync(&["-s", file.to_str().expect("path")]);
    assert_eq!(project.locked(), ["lib:2.0"]);
}

#[test]
fn jvm_config_reaches_dependency_models_as_system_properties() {
    let project = Project::new();
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>lib</artifactId><version>1.0</version>\
               <properties><extra.version>1.0</extra.version></properties>\
               <profiles><profile><id>extra</id><activation><property><name>use.v2</name>\
               </property></activation><dependencies><dependency><groupId>org.test</groupId>\
               <artifactId>extra</artifactId><version>${extra.version}</version>\
               </dependency></dependencies></profile></profiles></project>";
    let path = "repository/org/test/lib/1.0/lib-1.0.pom";
    project.write(path, pom);
    project.write(&format!("{path}.sha256"), &sha256_hex(pom.as_bytes()));
    project.write(".mvn/jvm.config", "-Duse.v2=true -Dextra.version=2.0\n");
    project.sync(&[]);
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    assert_success(&project.frozen(&[]), "dependency reads jvm.config");
}

/// A dependency model reads a `-D` as a system property, over the same name
/// in `.mvn/jvm.config`, so adding one there changes nothing.
#[test]
fn a_jvm_config_value_a_define_overrides_keeps_a_dependency_lookup() {
    let project = Project::new();
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>lib</artifactId><version>1.0</version><dependencies><dependency>\
               <groupId>org.test</groupId><artifactId>extra</artifactId>\
               <version>${lib.version}</version></dependency>\
               </dependencies></project>";
    let path = "repository/org/test/lib/1.0/lib-1.0.pom";
    project.write(path, pom);
    project.write(&format!("{path}.sha256"), &sha256_hex(pom.as_bytes()));
    project.sync(&["-Dlib.version=1.0"]);
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    project.write(".mvn/jvm.config", "-Dlib.version=2.0\n");
    assert_success(
        &project.frozen(&["-Dlib.version=1.0"]),
        "overridden jvm.config",
    );
}

/// As Maven 3.9 does, a requested profile that neither a POM nor
/// settings.xml has gets a warning, and a deselected one does not.
#[test]
fn an_unknown_profile_warns() {
    let project = Project::new();
    let warned = |output: &Output, id: &str| {
        assert_success(output, id);
        stderr(output).contains(&format!(
            "PROFILE_NOT_FOUND: requested profile '{id}' is not defined in any project POM"
        ))
    };
    let typo = project.raeva(&["-Pextra,extar,!nosuch", "sync", "--offline"]);
    assert!(warned(&typo, "extar"), "{}", stderr(&typo));
    assert!(!warned(&typo, "extra") && !warned(&typo, "nosuch"));
    let file = project.write("settings.xml", &settings("2.0"));
    project.write(".mvn/maven.config", "-Pghost\n");
    let file = file.to_str().expect("path");
    let settings = project.raeva(&["-s", file, "-Ppin", "sync", "--offline"]);
    assert!(warned(&settings, "ghost") && !warned(&settings, "pin"));
    // A parent from a repository, which discovery does not read, may have it.
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                  <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
                  <profiles><profile><id>inherited</id></profile></profiles></project>";
    project.write("repository/org/test/parent/1/parent-1.pom", parent);
    project.write(
        "repository/org/test/parent/1/parent-1.pom.sha256",
        &sha256_hex(parent.as_bytes()),
    );
    project.write(".mvn/maven.config", "");
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replacen(
            "<groupId>org.test</groupId>",
            "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><groupId>org.test</groupId>",
            1,
        ),
    );
    let url = url::Url::from_directory_path(project.path().join("repository")).expect("url");
    project.write(
        "raeva.toml",
        &format!("[[repositories]]\nid = \"local\"\nurl = \"{url}\"\n"),
    );
    let inherited = project.raeva(&["-Pinherited", "sync", "--offline"]);
    assert_success(&inherited, "remote parent");
    assert!(
        !stderr(&inherited).contains("PROFILE_NOT_FOUND"),
        "{}",
        stderr(&inherited)
    );
}

/// A `-D` without a property name is refused, as Maven refuses it.
#[test]
fn a_define_without_a_name_is_refused() {
    let project = Project::new();
    let output = project.raeva(&["-D=", "sync", "--offline"]);
    assert_status(&output, 2, "-D=");
    assert!(
        stderr(&output).contains("has no property name"),
        "{}",
        stderr(&output)
    );
    project.write(".mvn/maven.config", "-D=\n");
    assert_status(
        &project.raeva(&["sync", "--offline"]),
        3,
        "maven.config -D=",
    );
}

/// The options given before and after a command name all count, in order.
#[test]
fn options_join_across_command_levels() {
    let project = Project::new();
    let sync = project.raeva(&["-Pextra", "sync", "-Dlib.version=2.0", "--offline"]);
    assert_success(&sync, "split sync");
    assert_eq!(project.locked(), ["extra:1.0", "lib:2.0"]);
    let frozen = |args: &[&str]| project.raeva(&[args, &["--frozen", "--offline"]].concat());
    assert_success(
        &frozen(&["-Dlib.version=2.0", "sync", "-Pextra"]),
        "split the other way",
    );
    assert_status(&frozen(&["sync", "-Pextra"]), 7, "-D dropped");
    assert_success(
        &frozen(&["-Dlib.version=1.0", "sync", "-Pextra", "-Dlib.version=2.0"]),
        "ignore a replaced override",
    );
    // mvn reads `-P -extra` as `-P` missing its value, followed by `-e`.
    assert_status(&project.raeva(&["-P", "-extra", "sync"]), 2, "-P -extra");
    project.sync(&["-Pextra", "-P-extra"]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    // A quote mvn reads differently in `-D"a` and `-D "a` is refused.
    let quoted = project.raeva(&["-D\"lib.version=2.0", "sync", "--offline"]);
    assert_status(&quoted, 2, "quoted -D");
    assert!(stderr(&quoted).contains("drop them"), "{}", stderr(&quoted));
}

/// A `-s` file is read in place of `~/.m2/settings.xml`, and its content,
/// not its path, is what raeva.lock covers.
#[test]
fn frozen_follows_the_settings_content_not_its_path() {
    let project = Project::new();
    let first = project.write("ci/settings.xml", &settings("2.0"));
    let first = first.to_str().expect("UTF-8 path");
    project.sync(&["-s", first]);
    assert_eq!(project.locked(), ["lib:2.0"]);
    let lock = fs::read_to_string(project.path().join("raeva.lock")).expect("raeva.lock");
    assert!(!lock.contains("ci/settings.xml"), "{lock}");

    let copy = project.write("elsewhere/other.xml", &settings("2.0"));
    assert_success(
        &project.frozen(&["--settings", copy.to_str().expect("UTF-8 path")]),
        "same content at another path",
    );
    // Relative to the working directory, as mvn -s is.
    let relative = raeva_command(project.path(), project.home.path())
        .current_dir(project.path().join("elsewhere"))
        .args(["-s", "other.xml", "sync", "--frozen", "--offline"])
        .output()
        .expect("run raeva");
    assert_success(&relative, "relative -s");

    project.write("elsewhere/other.xml", &settings("1.0"));
    assert_status(
        &project.frozen(&["-s", copy.to_str().expect("UTF-8 path")]),
        7,
        "content",
    );
    assert_status(&project.frozen(&[]), 7, "no -s");
    // ~/.m2/settings.xml is not read when -s names a file.
    fs::create_dir_all(project.home.path().join(".m2")).expect(".m2");
    fs::write(
        project.home.path().join(".m2/settings.xml"),
        settings("1.0"),
    )
    .expect("write");
    assert_success(
        &project.frozen(&["-s", first]),
        "-s replaces ~/.m2/settings.xml",
    );
}

/// raeva locks the whole reactor, so the project selection of
/// `.mvn/maven.config` is ignored with `SETTING_IGNORED`.
#[test]
fn a_reactor_selection_in_maven_config_is_ignored() {
    let project = Project::new();
    project.write(".mvn/maven.config", "--projects=app\n-am\n-amd\n");
    let output = project.raeva(&["--json", "sync", "--offline"]);
    assert_success(&output, "maven.config -pl");
    assert_eq!(project.locked(), ["lib:1.0"]);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let warnings = envelope["data"]["warnings"].as_array().expect("warnings");
    for option in ["-pl", "-am", "-amd"] {
        let ignoring = format!("ignoring {option} in ");
        assert!(
            warnings.iter().any(|warning| {
                warning["code"] == "SETTING_IGNORED"
                    && warning["message"].as_str().is_some_and(|message| {
                        message.contains(&ignoring)
                            && message.contains(
                                "the whole reactor, whatever projects a build selects, so a \
                                 module this build skips can still fail the sync",
                            )
                    })
            }),
            "{option}: {envelope}"
        );
    }
}

/// On the command line, `-pl`, `-am` and `-amd` are usage errors (exit 2)
/// whose tip says why, where clap alone names an unknown `-p` or `-a`.
#[test]
fn a_reactor_selection_on_the_command_line_gets_a_tip() {
    let project = Project::new();
    for args in [
        &["sync", "-pl", "app"][..],
        &["tree", "-am"],
        &["sync", "--projects=app"],
    ] {
        let output = project.raeva(args);
        assert_status(&output, 2, &format!("{args:?}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(
                "raeva locks the whole reactor and takes no -pl, -am or -amd; tree, why, vuln, \
                 sbom and lock verify take --module to report on one module"
            ),
            "{args:?}: {stderr}"
        );
    }
    let stderr = String::from_utf8_lossy(&project.raeva(&["sync", "--bogus"]).stderr).into_owned();
    assert!(!stderr.contains("whole reactor"), "{stderr}");
}

/// `-s` in `.mvn/maven.config` picks the settings file, as Maven 3.9.12
/// and 3.10.0 read it: a `-s` of `MAVEN_ARGS` or of the command line wins
/// over it, either expands with the `-D` values of the file and of the
/// command line, and a relative one is taken from the working directory.
/// `-gs` there fails the load (exit 3), since raeva reads no global
/// settings file.
#[test]
fn a_settings_option_in_maven_config_is_read() {
    let project = Project::new();
    // As `mvn` runs in the project directory.
    let raeva = |args: &[&str], maven_args: &str| {
        raeva_command(project.path(), project.home.path())
            .current_dir(project.path())
            .env("MAVEN_ARGS", maven_args)
            .args(args)
            .args(["sync", "--offline"])
            .output()
            .expect("run raeva")
    };
    project.write(".mvn/ci.xml", &settings("2.0"));
    project.write(".mvn/other.xml", &settings("1.0"));
    project.write(".mvn/maven.config", "-s\n.mvn/ci.xml\n-Dchoice=other\n");
    let output = raeva(&["--json"], "");
    assert_success(&output, "maven.config -s");
    assert_eq!(project.locked(), ["lib:2.0"]);
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("SETTING_IGNORED"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let frozen = raeva_command(project.path(), project.home.path())
        .current_dir(project.path())
        .args(["sync", "--frozen", "--offline"])
        .output()
        .expect("run raeva");
    assert_success(&frozen, "frozen with the maven.config -s");

    let other = project.path().join(".mvn/other.xml");
    let other = other.to_str().expect("UTF-8 path");
    assert_success(&raeva(&["-s", other], ""), "-s");
    assert_eq!(project.locked(), ["lib:1.0"]);
    assert_success(&raeva(&[], &format!("-s {other}")), "MAVEN_ARGS -s");
    assert_eq!(project.locked(), ["lib:1.0"]);
    // A -D value of the file expands the command line's -s.
    let chosen = "${maven.multiModuleProjectDirectory}/.mvn/${choice}.xml";
    assert_success(&raeva(&["-s", chosen], ""), "-s with a maven.config -D");
    assert_eq!(project.locked(), ["lib:1.0"]);

    project.write(".mvn/maven.config", "-gs\n.mvn/ci.xml\n");
    let output = raeva(&[], "");
    assert_status(&output, 3, "maven.config -gs");
    assert!(
        stderr(&output).contains("-gs (--global-settings)"),
        "{}",
        stderr(&output)
    );
}

/// A secret the launcher's `.mvn/maven.config` defines stays out of the
/// message for the missing `-s` file it names, wherever `mvn` finds that
/// `.mvn`: in `MAVEN_BASEDIR`, or up from the directory `PWD` names.
#[test]
fn a_secret_in_the_launcher_maven_config_is_hidden() {
    let project = Project::new();
    let base = tempfile::TempDir::new().expect("base");
    fs::create_dir(base.path().join(".mvn")).expect(".mvn");
    let config = "-Dapi.token=zqQ12zq\n-s\n/nonexistent/${api.token}\n";
    fs::write(base.path().join(".mvn/maven.config"), config).expect("maven.config");
    let check = |output: &Output, how: &str| {
        assert_status(output, 3, how);
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            stderr(output)
        );
        assert!(
            shown.contains("does not exist") && shown.contains("***") && !shown.contains("zqQ12zq"),
            "{how}: {shown}"
        );
    };
    let mut raeva = raeva_command(project.path(), project.home.path());
    raeva
        .current_dir(project.path())
        .args(["sync", "--offline"]);
    let output = (raeva.env("MAVEN_BASEDIR", base.path()).output()).expect("run raeva");
    check(&output, "MAVEN_BASEDIR");
    #[cfg(unix)]
    {
        // `-C` names the working directory itself, as the kernel spells it
        // (macOS keeps temporary directories under the /var link), so raeva
        // takes `PWD` as the shell's name for it.
        let root = project.path().canonicalize().expect("canonical root");
        let link = base.path().join("app");
        std::os::unix::fs::symlink(&root, &link).expect("link");
        let mut raeva = raeva_command(&root, project.home.path());
        raeva.current_dir(&root).env("PWD", &link);
        check(
            &(raeva.args(["sync", "--offline"]).output()).expect("run raeva"),
            "PWD",
        );
    }
}

/// A `-s` file that is not a settings document, such as the project's
/// pom.xml, fails instead of reading as settings with no mirrors.
#[test]
fn a_settings_file_that_is_not_settings_fails() {
    let project = Project::new();
    let pom = project.path().join("pom.xml");
    let output = project.raeva(&["--json", "-s", pom.to_str().expect("UTF-8"), "sync"]);
    assert_status(&output, 3, "-s pom.xml");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let error = envelope["error"].as_str().expect("error");
    assert!(
        error.contains("pom.xml") && error.contains("root element is <project>, not <settings>"),
        "{error}"
    );
}

/// Maven fails with "The specified user settings file does not exist" and
/// exit 1 when `-s` names no file; raeva fails with a configuration error.
#[test]
fn a_missing_settings_file_fails() {
    let project = Project::new();
    let missing = project.path().join("missing.xml");
    let output = project.raeva(&["--json", "-s", missing.to_str().expect("UTF-8"), "sync"]);
    assert_status(&output, 3, "missing -s");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(envelope["code"], "CONFIG", "{envelope}");
    let error = envelope["error"].as_str().expect("error");
    let expected = format!(
        "The specified user settings file does not exist: {}",
        missing.display()
    );
    assert!(error.contains(&expected), "{error}");
    let directory = project.path().join("repository");
    let output = project.raeva(&["-s", directory.to_str().expect("UTF-8"), "sync"]);
    assert_status(&output, 3, "-s directory");

    // An error of the command line is the command line's.
    let given = project.write("given.xml", &settings("1.0"));
    let given = given.to_str().expect("UTF-8 path");
    let cycle = project.raeva(&["-s", given, "-Da=${a}", "sync", "--offline"]);
    assert_status(&cycle, 2, "cycle on the command line");
    project.write(".mvn/maven.config", "-Da=${a}\n");
    let cycle = project.raeva(&["-Da=1", "-Db=${b}", "sync", "--offline"]);
    assert_status(&cycle, 2, "cycle on the command line, a replaced");
    let cycle = project.raeva(&["-Db=1", "sync", "--offline"]);
    assert_status(&cycle, 3, "cycle in maven.config");
}

/// A coordinate that still holds a `${...}` names the property, the POM and
/// the `-D` that defines it; Maven reports the literal file as not found.
/// camel's `${nisse.os.classifier}` comes from a build extension.
#[test]
fn an_undefined_property_in_a_coordinate_names_it() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("read pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<version>${lib.version}</version>",
            "<version>${lib.version}</version><classifier>${nisse.os.classifier}</classifier>",
        ),
    );
    let output = project.raeva(&["--json", "sync", "--offline"]);
    assert_status(&output, 5, "undefined classifier property");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(envelope["code"], "RESOLUTION", "{envelope}");
    assert_eq!(
        envelope["error"],
        "property nisse.os.classifier is not defined: pom.xml declares \
         org.test:lib:1.0::${nisse.os.classifier}\n\n  In pom.xml",
        "{envelope}"
    );
    assert_eq!(
        envelope["location"],
        serde_json::json!({"module": "pom.xml", "via": []}),
        "{envelope}"
    );
    let hint = envelope["hints"][0].as_str().expect("hint");
    assert!(
        hint.contains("raeva sync -Dnisse.os.classifier=<value>")
            && hint.ends_with(
                "raeva resolves every reactor module, so one a build skips with -pl can \
                 still fail the sync"
            ),
        "{hint}"
    );

    // Declared by a dependency's POM: the location is the path to it.
    project.write("pom.xml", &pom);
    let lib = project
        .path()
        .join("repository/org/test/lib/2.0/lib-2.0.pom");
    let text = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                <artifactId>lib</artifactId><version>2.0</version><dependencies><dependency>\
                <groupId>org.test</groupId><artifactId>extra</artifactId><version>1.0</version>\
                <classifier>${nisse.os.classifier}</classifier></dependency></dependencies>\
                </project>";
    write_with_sha256(&lib, text.as_bytes());
    let output = project.raeva(&["--json", "-Dlib.version=2.0", "sync", "--offline"]);
    assert_status(
        &output,
        5,
        "undefined classifier property below a dependency",
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert!(
        envelope["error"].as_str().is_some_and(|error| error
            .starts_with("property nisse.os.classifier is not defined: org.test:lib:2.0 declares")),
        "{envelope}"
    );
    assert_eq!(
        envelope["location"],
        serde_json::json!({"module": "pom.xml", "via": ["org.test:lib:2.0"]}),
        "{envelope}"
    );
}

/// A module's own dependency is always kept, so an undefined property in
/// its classifier fails before anything is downloaded: on a cold camel
/// build the error came after every other module's jars.
#[test]
fn a_module_s_own_undefined_classifier_fails_before_any_download() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rv_test_support::http::{Response, StubServer};

    let requests = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&requests);
    let server = StubServer::start(move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
        Response::new(404, "")
    });
    let base = tempfile::TempDir::new().expect("base");
    let home = tempfile::TempDir::new().expect("home");
    crate::common::write_repo_toml(base.path(), "repo", &format!("http://{}/", server.addr()));
    fs::write(
        base.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies>\
         <dependency><groupId>org.test</groupId><artifactId>first</artifactId>\
         <version>1.0</version></dependency><dependency><groupId>org.test</groupId>\
         <artifactId>native</artifactId><version>1.0</version>\
         <classifier>${nisse.os.classifier}</classifier></dependency>\
         </dependencies></project>",
    )
    .expect("write pom.xml");
    let output = raeva_command(base.path(), home.path())
        .args(["--json", "sync"])
        .output()
        .expect("run raeva");
    assert_status(&output, 5, "undefined classifier property");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.starts_with(
                "property nisse.os.classifier is not defined: pom.xml declares \
             org.test:native:1.0::${nisse.os.classifier}"
            )),
        "{envelope}"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

/// Maven reads the POM of every version a range admits. An invalid one the
/// range does not select gets no `POM_PROBLEM`; once selected, it does.
#[test]
fn only_a_selected_invalid_pom_is_reported() {
    let project = Project::new();
    let dir = project.path().join("repository/org/test/lib");
    let invalid = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                   <artifactId>lib</artifactId><version>1.0</version><dependencies>\
                   <dependency><groupId>com.sun</groupId><artifactId>tools</artifactId>\
                   <version>1</version><scope>system</scope><systemPath>${tools.jar}</systemPath>\
                   </dependency></dependencies></project>";
    let metadata = "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId>\
                    <versioning><versions><version>1.0</version><version>2.0</version>\
                    </versions></versioning></metadata>";
    for (path, text) in [
        ("1.0/lib-1.0.pom", invalid),
        ("maven-metadata.xml", metadata),
    ] {
        write_with_sha256(&dir.join(path), text.as_bytes());
    }
    let problems = |version: &str| {
        let define = format!("-Dlib.version={version}");
        let output = project.raeva(&["--json", &define, "sync", "--offline"]);
        assert_success(&output, version);
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        (envelope["data"]["warnings"]
            .as_array()
            .into_iter()
            .flatten())
        .filter(|warning| warning["code"] == "POM_PROBLEM")
        .map(|warning| warning["context"]["coord"].to_string())
        .collect::<Vec<_>>()
    };
    assert_eq!(problems("[1.0,3.0)"), Vec::<String>::new());
    assert_eq!(problems("[1.0]"), ["\"org.test:lib:1.0\""]);
}

#[test]
fn a_range_skips_an_overlong_listed_version() {
    let project = Project::new();
    let version = format!("{}1", "2.".repeat(128));
    let metadata = format!(
        "<metadata><versioning><versions><version>1.0</version>\
         <version>{version}</version><version>2.0</version>\
         </versions></versioning></metadata>"
    );
    project.write("repository/org/test/lib/maven-metadata.xml", &metadata);
    project.write(
        "repository/org/test/lib/maven-metadata.xml.sha256",
        &sha256_hex(metadata.as_bytes()),
    );

    project.sync(&["-Dlib.version=[1.0,3.0)"]);
    assert_eq!(project.locked(), ["lib:2.0"]);
}

/// `<offline>true</offline>` in settings.xml makes the run offline, as
/// `--offline` does, so nothing is requested from Central and `vuln` is
/// refused.
#[test]
fn settings_offline_keeps_a_run_offline() {
    let project = Project::new();
    project.write(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>org.test</groupId><artifactId>absent</artifactId><version>1.0</version>\
         </dependency></dependencies></project>",
    );
    let online = project.raeva(&["sync"]);
    assert!(
        !stderr(&online).contains("offline mode"),
        "{}",
        stderr(&online)
    );
    fs::create_dir_all(project.home.path().join(".m2")).expect("mkdir");
    fs::write(
        project.home.path().join(".m2/settings.xml"),
        "<settings><offline> TRUE </offline></settings>",
    )
    .expect("settings");
    let offline = project.raeva(&["sync"]);
    assert!(
        stderr(&offline).contains("offline mode"),
        "{}",
        stderr(&offline)
    );
    let vuln = project.raeva(&["vuln"]);
    assert_eq!(vuln.status.code(), Some(2), "{}", stderr(&vuln));
    assert!(
        stderr(&vuln).contains("cannot run with offline mode set in settings.xml"),
        "{}",
        stderr(&vuln)
    );
}

/// Maven honours `-o` in `.mvn/maven.config`, so raeva's run is offline:
/// doctor probes no repository and vuln is refused.
#[test]
fn maven_config_offline_keeps_a_run_offline() {
    let project = Project::new();
    project.write(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version></project>",
    );
    project.write(".mvn/maven.config", "--offline\n");
    let doctor = project.raeva(&["doctor"]);
    let out = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        out.contains("not probed offline"),
        "{out}{}",
        stderr(&doctor)
    );
    let vuln = project.raeva(&["vuln"]);
    assert_eq!(vuln.status.code(), Some(2), "{}", stderr(&vuln));
    assert!(
        stderr(&vuln).contains("cannot run with offline mode"),
        "{}",
        stderr(&vuln)
    );
}

/// Maven keeps the whitespace a `-D` value brings into a dependency's
/// version and requests `1.0 `, which no repository holds, by Maven 3.9.12
/// and 3.10.0 runs; after a range's closing bracket it is ignored. raeva
/// refuses such a version instead of locking `1.0`.
#[test]
fn whitespace_a_define_brings_into_a_version_is_refused() {
    let project = Project::new();
    for value in ["1.0 ", " 1.0", "\t1.0", " [1.0,2.0)"] {
        let output = project.raeva(&[&format!("-Dlib.version={value}"), "sync", "--offline"]);
        assert_status(&output, 3, &format!("{value:?}"));
        assert!(
            stderr(&output).contains("'dependencies.dependency.version' for org.test:lib:jar"),
            "{value:?}: {}",
            stderr(&output)
        );
        assert!(!project.path().join("raeva.lock").exists(), "{value:?}");
    }
    project.sync(&["-Dlib.version=[2.0] "]);
    assert_eq!(project.locked(), ["lib:2.0"]);
}

/// A dependency's POM keeps its other dependencies when one it leaves out
/// of the graph takes a version with such whitespace, as Maven does.
#[test]
fn whitespace_in_a_dependency_pom_version_drops_nothing() {
    let project = Project::new();
    let repository = project.path().join("repository");
    publish(&repository, "good", "1.0");
    crate::common::publish(
        &repository,
        "org.test:mid:1.0",
        "<dependencies><dependency><groupId>org.test</groupId><artifactId>good</artifactId>\
         <version>1.0</version></dependency><dependency><groupId>org.test</groupId>\
         <artifactId>ignored</artifactId><version>${revision}</version><scope>test</scope>\
         </dependency></dependencies>",
    );
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    let pom = pom.replace(
        "<version>${lib.version}</version>",
        "<version>${lib.version}</version></dependency><dependency><groupId>org.test</groupId>\
         <artifactId>mid</artifactId><version>1.0</version>",
    );
    project.write("pom.xml", &pom);
    project.sync(&["-Drevision=1.0 "]);
    assert_eq!(project.locked(), ["good:1.0", "lib:1.0", "mid:1.0"]);
}

/// An active settings.xml profile repository whose URL does not parse, or
/// a mirror of nothing used whose URL does not parse, is skipped with a
/// warning, and the search goes on to the next repository, as Maven
/// 3.9.12 and 3.10.0 do. Neither the URL nor what it was expanded from is
/// shown, and `--frozen` reads the lock back.
#[test]
fn a_settings_url_that_does_not_parse_is_skipped_as_in_maven() {
    const SENTINEL: &str = "hostsentinel";
    let root = tempfile::TempDir::new().expect("project");
    let home = tempfile::TempDir::new().expect("home");
    let repository = root.path().join("repository");
    crate::common::publish(&repository, "org.test:lib:1.0", "");
    let url = url::Url::from_directory_path(&repository).expect("file URL");
    fs::write(
        root.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>\
         </dependency></dependencies></project>",
    )
    .expect("pom.xml");
    fs::create_dir_all(home.path().join(".m2")).expect(".m2");
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>unused</id><mirrorOf>nothing</mirrorOf>\
             <url>https://[${{env.RV_BAD_HOST}}</url></mirror></mirrors><profiles><profile>\
             <id>p</id><repositories><repository><id>bad</id>\
             <url>https://[${{env.RV_BAD_HOST}}</url></repository><repository><id>good</id>\
             <url>{url}</url></repository></repositories></profile></profiles>\
             <activeProfiles><activeProfile>p</activeProfile></activeProfiles></settings>"
        ),
    )
    .expect("settings.xml");
    let run = |args: &[&str]| {
        raeva_command(root.path(), home.path())
            .env("RV_BAD_HOST", SENTINEL)
            .args(args)
            .output()
            .expect("run raeva")
    };
    let sync = run(&["--json", "sync"]);
    assert_success(&sync, "sync");
    let warnings = crate::common::envelope(&sync)["data"]["warnings"].to_string();
    for entry in ["repository 'bad'", "mirror 'unused'"] {
        assert!(warnings.contains(entry), "{warnings}");
    }
    let lock = fs::read_to_string(root.path().join("raeva.lock")).expect("raeva.lock");
    assert!(lock.contains("org.test:lib:1.0"), "{lock}");
    let frozen = run(&["-v", "sync", "--frozen"]);
    assert_success(&frozen, "sync --frozen");
    assert_eq!(
        fs::read_to_string(root.path().join("raeva.lock")).expect("raeva.lock"),
        lock
    );
    for output in [&sync, &frozen] {
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!shown.contains(SENTINEL), "{shown}");
    }
}

/// The reactor selection of `MAVEN_ARGS` picks the modules a build runs,
/// not what they resolve, and raeva locks the whole reactor: it is read,
/// with its values, and ignored with `SETTING_IGNORED`, so the lock is the
/// one written without it, and `--frozen` takes it.
#[test]
fn a_reactor_selection_in_maven_args_is_ignored() {
    let project = Project::new();
    let run = |args: &str, sync: &[&str]| {
        raeva_command(project.path(), project.home.path())
            .env("MAVEN_ARGS", args)
            .args(sync)
            .output()
            .expect("run raeva")
    };
    project.sync(&[]);
    let lock = fs::read(project.path().join("raeva.lock")).expect("raeva.lock");
    fs::remove_file(project.path().join("raeva.lock")).expect("remove raeva.lock");
    let output = run("-pl app -am", &["--json", "sync", "--offline"]);
    assert_success(&output, "MAVEN_ARGS -pl -am");
    assert_eq!(
        fs::read(project.path().join("raeva.lock")).expect("raeva.lock"),
        lock
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let warnings = envelope["data"]["warnings"].as_array().expect("warnings");
    for option in ["-pl", "-am"] {
        let ignoring = format!("ignoring {option} in MAVEN_ARGS; raeva locks the whole reactor");
        assert!(
            warnings.iter().any(|warning| {
                warning["code"] == "SETTING_IGNORED"
                    && warning["message"]
                        .as_str()
                        .is_some_and(|message| message.contains(&ignoring))
            }),
            "{option}: {envelope}"
        );
    }
    for args in [
        "--projects=app --also-make-dependents",
        "-pl=app -rf app",
        "-N -B --resume-from app",
    ] {
        assert_success(&run(args, &["sync", "--frozen", "--offline"]), args);
    }
    let refused = run("-pl app -f other.xml", &["sync", "--offline"]);
    assert_status(&refused, 3, "MAVEN_ARGS -f");
    assert!(stderr(&refused).contains("-f"), "{}", stderr(&refused));
    let refused = run("-pl", &["sync", "--offline"]);
    assert_status(&refused, 3, "MAVEN_ARGS -pl without its value");
}

/// `mvn` puts the words of `MAVEN_ARGS` before its own arguments, so Maven
/// 3.9.12 and 3.10.0 take its `-D` and `-P` as ones on the command line
/// before the others, where raeva, which read none of it, locked lib 1.0
/// and left `extra` off. A later `-D` of raeva's command line wins, a
/// changed one makes `--frozen` fail as a changed `-D` there does, options
/// that change nothing resolved pass, and one raeva cannot read as `mvn`
/// does fails the load (exit 3), naming the option, never a value.
#[test]
fn maven_args_read_as_the_start_of_the_command_line() {
    let project = Project::new();
    let run = |args: &str, options: &[&str]| {
        raeva_command(project.path(), project.home.path())
            .env("MAVEN_ARGS", args)
            .args(options)
            .args(["sync", "--offline"])
            .output()
            .expect("run raeva")
    };
    let frozen = |args: &str| {
        raeva_command(project.path(), project.home.path())
            .env("MAVEN_ARGS", args)
            .args(["sync", "--frozen", "--offline"])
            .output()
            .expect("run raeva")
    };
    for mode in ["3.9", "3.10"] {
        project.write("raeva.toml", &format!("[lock]\nmaven = \"{mode}\"\n"));
        for (args, options, locked) in [
            ("-Dlib.version=2.0", &[][..], &["lib:2.0"][..]),
            ("--define lib.version=2.0", &[], &["lib:2.0"]),
            ("-Pextra", &[], &["extra:1.0", "lib:1.0"]),
            ("-Dlib.version=2.0", &["-Dlib.version=1.0"], &["lib:1.0"]),
            ("-DskipTests -B -T 4 -ntp -o -U", &[], &["lib:1.0"]),
        ] {
            let case = format!("{mode}: {args} {options:?}");
            assert_success(&run(args, options), &case);
            assert_eq!(project.locked(), locked, "{case}");
        }
        assert_success(&run("-Dlib.version=2.0", &[]), mode);
        assert_success(&frozen("-B -Dlib.version=2.0"), mode);
        assert_status(&frozen(""), 7, mode);
        assert_status(&frozen("-Dlib.version=1.0"), 7, mode);
        // `sh` reads `!` as written, and Maven 3.9.12 and 3.10.0 deactivate
        // the profile `.mvn/maven.config` activates; `mvn.cmd` drops it.
        if cfg!(unix) {
            project.write(".mvn/maven.config", "-Pextra\n");
            assert_success(&run("-P!extra", &[]), mode);
            assert_eq!(project.locked(), ["lib:1.0"], "{mode} -P!extra");
            fs::remove_file(project.path().join(".mvn/maven.config")).unwrap();
        }
    }
    let mut refused = vec![
        ("-gs other.xml", "-gs"),
        ("-f other.xml", "-f"),
        ("-t toolchains.xml", "-t"),
        (
            "--ignore-transitive-repositories",
            "--ignore-transitive-repositories",
        ),
        ("-Zsecret=zqSECRETzq", "-Z"),
        ("-Dlib.version=*", "'*'"),
    ];
    if cfg!(windows) {
        refused.extend([("\"-Dlib.version=2.0\"", "'\"'"), ("-P!extra", "'!'")]);
    }
    for (args, named) in refused {
        let output = run(args, &[]);
        assert_status(&output, 3, args);
        let said = stderr(&output);
        assert!(
            said.contains("MAVEN_ARGS") && said.contains(named),
            "{args}: {said}"
        );
        assert!(
            crate::common::markers_in(&said).next().is_none() && !said.contains("2.0"),
            "{args}: {said}"
        );
    }
}

impl Project {
    /// raeva with `MAVEN_OPTS` `opts` before the harness's `-Duser.home`,
    /// and the variables `env`.
    fn raeva_opts(&self, opts: &str, env: &[(&str, &str)], args: &[&str]) -> Output {
        let mut command = raeva_command(self.path(), self.home.path());
        crate::common::isolate_maven_user_home(&mut command, self.home.path(), opts);
        command.envs(env.iter().copied());
        command.args(args).output().expect("run raeva")
    }

    /// The settings.xml whose active profile sets `lib.version` to
    /// `${lv}`, which settings.xml takes from the system properties.
    fn settings_from_lv(&self) -> String {
        let file = self.write("settings.xml", &settings("${lv}"));
        file.to_str().expect("path").to_string()
    }
}

/// F1: a `-D` of `MAVEN_OPTS` or a JVM variable is a system property, as
/// `.mvn/jvm.config`'s is, which settings.xml takes; `--frozen` goes stale
/// when it changes, and the JVM's order decides between channels.
#[test]
fn a_jvm_option_variable_define_is_a_system_property() {
    let project = Project::new();
    let settings = project.settings_from_lv();
    let sync = |opts: &str, env: &[(&str, &str)]| {
        let output = project.raeva_opts(opts, env, &["-s", &settings, "sync", "--offline"]);
        assert_success(&output, &format!("{opts} {env:?}"));
        project.locked()
    };
    let frozen = |opts: &str, env: &[(&str, &str)]| {
        project.raeva_opts(
            opts,
            env,
            &["-s", &settings, "sync", "--frozen", "--offline"],
        )
    };
    assert_eq!(sync("-Dlv=2.0", &[]), ["lib:2.0"]);
    assert_success(&frozen("-Dlv=2.0", &[]), "the same MAVEN_OPTS");
    assert_success(&frozen("-Dlv=2.0 -Dunread=1", &[]), "a -D nothing reads");
    assert_status(&frozen("-Dlv=1.0", &[]), 7, "another MAVEN_OPTS value");
    assert_status(
        &frozen("", &[("JAVA_TOOL_OPTIONS", "-Dlv=1.0")]),
        7,
        "moved",
    );
    let text = fs::read_to_string(project.path().join("raeva.lock")).expect("raeva.lock");
    assert!(
        !text.contains("-Dlv") && !text.contains("MAVEN_OPTS"),
        "{text}"
    );
    assert_eq!(sync("", &[("JAVA_TOOL_OPTIONS", "-Dlv=2.0")]), ["lib:2.0"]);
    // `.mvn/jvm.config` comes after JAVA_TOOL_OPTIONS and before MAVEN_OPTS.
    project.write(".mvn/jvm.config", "-Dlv=1.0\n");
    assert_eq!(sync("-Dlv=2.0", &[]), ["lib:2.0"]);
    assert_eq!(sync("", &[("JAVA_TOOL_OPTIONS", "-Dlv=2.0")]), ["lib:1.0"]);
    assert_eq!(sync("", &[("_JAVA_OPTIONS", "-Dlv=2.0")]), ["lib:2.0"]);
}

/// A JVM option raeva cannot read exactly refuses where a read takes the
/// name it may set, and only there.
#[test]
fn an_unread_jvm_option_refuses_where_its_name_is_read() {
    let project = Project::new();
    let settings = project.settings_from_lv();
    // `mvn`'s shell may expand the pattern to the names of files.
    let glob = "-Dlv=2*";
    let output = project.raeva_opts(glob, &[], &["-s", &settings, "sync", "--offline"]);
    assert_status(&output, 3, "a pattern in MAVEN_OPTS");
    let output = project.raeva_opts(
        "-Dother=2* -Dlv=2.0",
        &[],
        &["-s", &settings, "sync", "--offline"],
    );
    assert_success(&output, "a pattern of a name nothing reads");
    assert_eq!(project.locked(), ["lib:2.0"]);
    // A later channel sets it exactly.
    let later = [("_JAVA_OPTIONS", "-Dlv=1.0")];
    let output = project.raeva_opts(glob, &later, &["-s", &settings, "sync", "--offline"]);
    assert_success(&output, "_JAVA_OPTIONS after the pattern");
    assert_eq!(project.locked(), ["lib:1.0"]);
    // Maven expands settings.xml before the POM's properties, so one of
    // them is no fallback there; a POM takes its own over the JVM's.
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    let with_lv = pom.replace("<properties>", "<properties><lv>1.0</lv>");
    project.write("pom.xml", &with_lv);
    let output = project.raeva_opts(glob, &[], &["-s", &settings, "sync", "--offline"]);
    assert_status(&output, 3, "a settings value a POM property would fill");
    project.write("pom.xml", &with_lv.replace("${lib.version}", "${lv}"));
    let output = project.raeva_opts(glob, &[], &["sync", "--offline"]);
    assert_success(&output, "a POM's own property");
    assert_eq!(project.locked(), ["lib:1.0"]);
    project.write("pom.xml", &pom);
    project.write(".mvn/maven.config", "-Dlib.version=${lv}\n");
    let output = project.raeva_opts(glob, &[], &["sync", "--offline"]);
    assert_status(&output, 3, "a maven.config value");
    project.write("pom.xml", &with_lv);
    let output = project.raeva_opts(glob, &[], &["sync", "--offline"]);
    assert_status(&output, 3, "a maven.config value a POM property would fill");
}

/// `mvn` passes `.mvn/jvm.config` on in its unquoted `$MAVEN_OPTS`, so a
/// pattern there that names a file in the directory `mvn` runs in may set
/// another value: a profile its name activates is not locked. A pattern
/// of a name nothing reads, such as `http.nonProxyHosts`, still syncs.
#[cfg(unix)]
#[test]
fn a_jvm_config_pattern_the_shell_may_expand_refuses_where_its_name_is_read() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<id>extra</id>",
            "<id>extra</id><activation><property><name>choice</name><value>*</value>\
             </property></activation>",
        ),
    );
    project.write("-Dchoice=2", "");
    let sync = || {
        let mut command = raeva_command(project.path(), project.home.path());
        (command
            .current_dir(project.path())
            .args(["sync", "--offline"]))
        .output()
        .expect("run raeva")
    };
    project.write(".mvn/jvm.config", "-Dchoice=*\n");
    let output = sync();
    assert_status(&output, 3, "a pattern in .mvn/jvm.config");
    assert!(
        stderr(&output).contains("depends on choice"),
        "{}",
        stderr(&output)
    );
    assert!(!project.path().join("raeva.lock").exists());
    project.write(".mvn/jvm.config", "-Dhttp.nonProxyHosts=*.corp|localhost\n");
    assert_success(&sync(), "a pattern of a name nothing reads");
    assert_eq!(project.locked(), ["lib:1.0"]);
}

/// A5: a `-D` of `MAVEN_OPTS` activates a POM profile, over the same name
/// in `.mvn/jvm.config`, which the JVM reads before it; the profile follows
/// it in `--frozen`.
#[test]
fn a_maven_opts_define_activates_a_profile() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<id>extra</id>",
            "<id>extra</id><activation><property><name>x</name><value>true</value>\
             </property></activation>",
        ),
    );
    let sync = |opts: &str| {
        let output = project.raeva_opts(opts, &[], &["sync", "--offline"]);
        assert_success(&output, opts);
        project.locked()
    };
    let frozen = |opts: &str| project.raeva_opts(opts, &[], &["sync", "--frozen", "--offline"]);
    assert_eq!(sync("-Dx=true"), ["extra:1.0", "lib:1.0"]);
    assert_success(&frozen("-Dx=true"), "the same MAVEN_OPTS");
    assert_status(&frozen(""), 7, "without the -D");
    project.write(".mvn/jvm.config", "-Dx=true\n");
    assert_eq!(sync("-Dx=1"), ["lib:1.0"]);
    assert_eq!(sync(""), ["extra:1.0", "lib:1.0"]);
}

/// A5 through a mavenrc file, which sets `MAVEN_OPTS` for `mvn`.
#[cfg(unix)]
#[test]
fn a_mavenrc_maven_opts_define_activates_a_profile() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<id>extra</id>",
            "<id>extra</id><activation><property><name>x</name><value>true</value>\
             </property></activation>",
        ),
    );
    let mavenrc = project.home.path().join(".mavenrc");
    fs::write(&mavenrc, "MAVEN_OPTS=\"$MAVEN_OPTS -Dx=true\"\n").expect("mavenrc");
    let output = project.raeva_opts("", &[], &["sync", "--offline"]);
    assert_success(&output, "a mavenrc -D");
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    fs::write(&mavenrc, "MAVEN_OPTS=\"$MAVEN_OPTS -Dx=false\"\n").expect("mavenrc");
    let output = project.raeva_opts("", &[], &["sync", "--frozen", "--offline"]);
    assert_status(&output, 7, "a mavenrc that changes the -D");
}

/// `mvn` runs in the project directory, so the mavenrc files are sourced
/// there, also for `raeva -C` from another: a file that reads one there
/// gives the lock what it gives `mvn`.
#[cfg(unix)]
#[test]
fn a_mavenrc_is_sourced_in_the_project_directory() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<id>extra</id>",
            "<id>extra</id><activation><property><name>x</name><value>true</value>\
             </property></activation>",
        ),
    );
    project.write("local.rc", "MAVEN_OPTS=\"$MAVEN_OPTS -Dx=true\"\n");
    let mavenrc = project.home.path().join(".mavenrc");
    fs::write(&mavenrc, "if [ -f ./local.rc ]; then . ./local.rc; fi\n").expect("mavenrc");
    let sync = |args: &[&str]| {
        let mut command = raeva_command(project.path(), project.home.path());
        crate::common::isolate_maven_user_home(&mut command, project.home.path(), "");
        (command.current_dir(project.home.path()).args(args))
            .output()
            .expect("run raeva")
    };
    assert_success(&sync(&["sync", "--offline"]), "sync from elsewhere");
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    fs::remove_file(project.path().join("local.rc")).expect("local.rc");
    let frozen = sync(&["sync", "--frozen", "--offline"]);
    assert_status(&frozen, 7, "a project without the file");
}

/// A mavenrc file that leaves the shell in another directory, from which
/// `mvn` then finds the project and the JVM reads a relative option file,
/// refuses the sync; one that goes back does not.
#[cfg(unix)]
#[test]
fn a_mavenrc_that_stays_in_another_directory_is_refused() {
    let project = Project::new();
    fs::create_dir_all(project.path().join("sub")).expect("sub");
    let mavenrc = project.home.path().join(".mavenrc");
    let sync = || {
        let mut command = raeva_command(project.path(), project.home.path());
        crate::common::isolate_maven_user_home(&mut command, project.home.path(), "");
        (command.args(["sync", "--offline"]))
            .output()
            .expect("run raeva")
    };
    fs::write(&mavenrc, "cd sub\n").expect("mavenrc");
    let moved = sync();
    assert_status(&moved, 3, "a mavenrc that stays in sub");
    let said = stderr(&moved);
    assert!(
        said.contains(".mavenrc") && said.contains("changes the directory"),
        "{said}"
    );
    fs::write(&mavenrc, "cd sub\ncd - >/dev/null\n").expect("mavenrc");
    assert_success(&sync(), "a mavenrc that goes back");
}

/// The directory a mavenrc file moves to may hold a secret, which the
/// refusal does not show.
#[cfg(unix)]
#[test]
fn the_directory_a_mavenrc_moves_to_is_not_shown() {
    let project = Project::new();
    fs::create_dir_all(project.path().join("zqMOVEDzq")).expect("secret directory");
    fs::write(
        project.home.path().join(".mavenrc"),
        "export REPO_TOKEN=zqMOVEDzq\ncd \"$REPO_TOKEN\"\n",
    )
    .expect("mavenrc");
    let mut command = raeva_command(project.path(), project.home.path());
    crate::common::isolate_maven_user_home(&mut command, project.home.path(), "");
    let moved = (command.args(["sync", "--offline"]))
        .output()
        .expect("run raeva");
    assert_status(&moved, 3, "a mavenrc that moves to a secret");
    assert!(!stderr(&moved).contains("zqMOVEDzq"), "{}", stderr(&moved));
}

/// `cmd` expands a `%` in the path of the script raeva sources the
/// mavenrc files with, so a temporary directory whose path has one leaves
/// it in raeva's own cache, and the sync refuses where that has one too.
#[cfg(windows)]
#[test]
fn a_temporary_directory_with_a_percent_sign_still_sources_mavenrc_pre() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<id>extra</id>",
            "<id>extra</id><activation><property><name>x</name><value>true</value>\
             </property></activation>",
        ),
    );
    let home = project.home.path();
    fs::write(
        home.join("mavenrc_pre.bat"),
        "@echo off\r\nset \"MAVEN_OPTS=%MAVEN_OPTS% -Dx=true\"\r\n",
    )
    .expect("mavenrc_pre.bat");
    let temp = home.join("t%USERNAME%p");
    fs::create_dir_all(&temp).expect("temp");
    let sync = |raeva_home: &Path| {
        let mut command = raeva_command(project.path(), home);
        crate::common::isolate_maven_user_home(&mut command, home, "");
        (command.env("TEMP", &temp).env("TMP", &temp))
            .env("USERNAME", "zqother")
            .env("RAEVA_HOME", raeva_home)
            .args(["sync", "--offline"])
            .output()
            .expect("run raeva")
    };
    assert_success(&sync(home), "sync with % in the temporary directory");
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    let refused = sync(&home.join("r%USERNAME%h"));
    assert_status(&refused, 3, "% in both directories");
    assert!(stderr(&refused).contains("% or !"), "{}", stderr(&refused));
}

/// A secret-named `-D` of `MAVEN_OPTS` that a profile reads decides it,
/// and its value reaches neither raeva.lock nor any message.
#[test]
fn a_secret_named_maven_opts_define_stays_hidden() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<id>extra</id>",
            "<id>extra</id><activation><property><name>deploy.token</name>\
             <value>!zqOTHERzq</value></property></activation>",
        ),
    );
    let hidden = |output: &Output| {
        let text = fs::read_to_string(project.path().join("raeva.lock")).expect("raeva.lock");
        let said = format!(
            "{}{}",
            stderr(output),
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            !said.contains("zqMARKzq") && !said.contains("zqTHIRDzq"),
            "{said}"
        );
        assert!(!text.contains("zqMARKzq"), "{text}");
    };
    let output = project.raeva_opts("-Ddeploy.token=zqMARKzq", &[], &["-v", "sync", "--offline"]);
    assert_success(&output, "a secret-named define");
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
    hidden(&output);
    let frozen = |value: &str| {
        let opts = format!("-Ddeploy.token={value}");
        project.raeva_opts(&opts, &[], &["-v", "sync", "--frozen", "--offline"])
    };
    assert_success(&frozen("zqMARKzq"), "the same value");
    for value in ["zqTHIRDzq", "zqOTHERzq"] {
        let output = frozen(value);
        assert_status(&output, 7, value);
        hidden(&output);
    }
}

/// A2 and B2: an option file reads as the JVM reads it beside a quoted
/// value, and an argument file with its `#` comments.
#[test]
fn option_files_read_beside_quotes_and_comments() {
    let project = Project::new();
    let settings = project.settings_from_lv();
    let vm = project.write("vm.options", "-Dlv=2.0\n");
    let args = project.write("jvm.args", "# CI settings\n-Xmx256m\n-Dlv=2.0 # read\n");
    let sync = |opts: &str, env: &[(&str, &str)]| {
        let output = project.raeva_opts(opts, env, &["-s", &settings, "sync", "--offline"]);
        assert_success(&output, &format!("{opts} {env:?}"));
        project.locked()
    };
    let quoted = format!("-XX:VMOptionsFile={} \"-Dq=a b\"", vm.display());
    assert_eq!(sync("-Dlv=3.0", &[("_JAVA_OPTIONS", &quoted)]), ["lib:2.0"]);
    // The harness's `mvn` runs no JDK raeva can tell, which may not read
    // JDK_JAVA_OPTIONS and its file.
    let launcher = format!("\"-Dq=a b\" @{}", args.display());
    let env = [
        ("JAVA_TOOL_OPTIONS", "-Dlv=3.0"),
        ("JDK_JAVA_OPTIONS", launcher.as_str()),
    ];
    let output = project.raeva_opts("", &env, &["-s", &settings, "sync", "--offline"]);
    assert_status(&output, 3, "JDK_JAVA_OPTIONS of an unknown JDK");
    assert_eq!(
        sync(&format!("-Dlv=3.0 @{}", args.display()), &[]),
        ["lib:2.0"]
    );
}

/// A1: a POM reads `.mvn/jvm.config`'s `user.home` only where the JVM
/// takes it last; one a later channel sets is the host's, which a lock
/// cannot follow.
#[test]
fn a_later_user_home_hides_the_jvm_config_one_from_a_pom() {
    let project = Project::new();
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<id>extra</id>",
            "<id>extra</id><activation><file><exists>${user.home}/marker</exists></file>\
             </activation>",
        ),
    );
    let config_home = project.path().join("j");
    project.write("j/marker", "");
    project.write(
        ".mvn/jvm.config",
        &format!("-Duser.home={}\n", config_home.display()),
    );
    // The harness's MAVEN_OPTS sets another user.home after jvm.config.
    let output = project.raeva(&["sync", "--offline"]);
    assert_status(&output, 3, "a POM reading a host user.home");
    let home = format!("-Duser.home={}", project.home.path().display());
    let output = raeva_command(project.path(), project.home.path())
        .env("MAVEN_OPTS", "")
        .env("JAVA_TOOL_OPTIONS", &home)
        .args(["sync", "--offline"])
        .output()
        .expect("run raeva");
    assert_success(&output, "jvm.config's user.home, read last");
    assert_eq!(project.locked(), ["extra:1.0", "lib:1.0"]);
}

/// B3: a `-Djava.specification.version` of the environment, which JDK 8
/// and 11 take and later JDKs ignore, fails only what reads it, naming its
/// channel; `.mvn/jvm.config`'s fails the load, as the project's.
#[test]
fn a_jdk_dependent_environment_define_fails_only_its_reads() {
    let project = Project::new();
    let spec = "-Djava.specification.version=17";
    let sync =
        |opts: &str, env: &[(&str, &str)]| project.raeva_opts(opts, env, &["sync", "--offline"]);
    assert_success(&sync(spec, &[]), "nothing reads it");
    assert_success(
        &sync("", &[("JAVA_TOOL_OPTIONS", spec)]),
        "nothing reads it",
    );
    let pom = fs::read_to_string(project.path().join("pom.xml")).expect("pom.xml");
    project.write(
        "pom.xml",
        &pom.replace(
            "<id>extra</id>",
            "<id>extra</id><activation><property><name>java.specification.version</name>\
             <value>17</value></property></activation>",
        ),
    );
    assert_status(&sync(spec, &[]), 3, "an activation reads it");
    project.write(
        "pom.xml",
        &pom.replace(
            "<lib.version>1.0</lib.version>",
            "<lib.version>${java.specification.version}</lib.version>",
        ),
    );
    let output = sync("", &[("JAVA_TOOL_OPTIONS", spec)]);
    assert_status(&output, 3, "a version reads it");
    assert!(
        stderr(&output).contains("JAVA_TOOL_OPTIONS"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("jvm.config"),
        "{}",
        stderr(&output)
    );
    project.write("pom.xml", &pom);
    project.write(".mvn/jvm.config", &format!("{spec}\n"));
    assert_status(&sync("", &[]), 3, "jvm.config's");
}
