//! The global `-D`, `-P` and `-s` options: what they select, how
//! `.mvn/maven.config` merges with them, and that `--frozen` fails when they
//! differ from the run that wrote raeva.lock.

use std::fs;
use std::path::Path;
use std::process::Output;

use crate::common::{assert_status, assert_success, raeva_command, sha256_hex};

/// A project whose dependency version is `${lib.version}`, 1.0 in the POM,
/// with a profile `extra` that adds `org.test:extra:1.0`, all served from
/// the project's `repository/`. The Raeva home and the Maven home are
/// `home`, which has no settings.xml.
struct Project {
    root: tempfile::TempDir,
    home: tempfile::TempDir,
}

fn publish(repository: &Path, artifact: &str, version: &str) {
    let dir = repository.join(format!("org/test/{artifact}/{version}"));
    fs::create_dir_all(&dir).expect("create repository");
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>{artifact}</artifactId><version>{version}</version></project>"
    );
    let files = [
        (format!("{artifact}-{version}.pom"), pom.into_bytes()),
        (format!("{artifact}-{version}.jar"), b"jar".to_vec()),
    ];
    for (name, bytes) in files {
        fs::write(dir.join(&name), &bytes).expect("write file");
        fs::write(dir.join(format!("{name}.sha256")), sha256_hex(&bytes)).expect("sidecar");
    }
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

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
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
        stderr(&output)
            .contains("the configuration changed: active Maven profiles changed for platform")
            && stderr(&output).contains("(locked: [], current: [extra])"),
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
    project.sync(&[]);
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

/// `config_hash` covers a jvm.config value of a name the build reads even
/// when a POM property hides it: adding one needs a sync, which locks the
/// same dependencies.
#[test]
fn a_jvm_config_value_a_pom_property_hides_relocks_to_the_same_dependencies() {
    let project = Project::new();
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    project.write(".mvn/jvm.config", "-Dlib.version=2.0\n");
    assert_status(&project.frozen(&[]), 7, "new jvm.config value");
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    assert_success(&project.frozen(&[]), "relocked");
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

/// As [`frozen_checks_a_jvm_config_value_moved_to_the_command_line`], for a
/// property whose name an expression computes.
#[test]
fn frozen_checks_a_computed_name_moved_to_jvm_config() {
    let project = Project::new();
    with_fetched_parent(&project, "${${project.artifactId}.version}");
    project.sync(&["-Dapp.version=2.0"]);
    assert_eq!(project.locked(), ["lib:2.0"]);
    project.write(".mvn/jvm.config", "-Dapp.version=2.0\n");
    assert_status(&project.frozen(&[]), 7, "moved to jvm.config");
    project.sync(&[]);
    assert_eq!(project.locked(), ["lib:1.0"]);
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
               <version>${${project.artifactId}.version}</version></dependency>\
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
        &pom.replace(
            "<groupId>org.test</groupId>",
            "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><groupId>org.test</groupId>",
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

/// A project cannot pick the settings file: a `-s` in `.mvn/maven.config`
/// would bring mirrors, proxies, every environment variable and the local
/// repository that the project's own files may not set, so it is ignored
/// with `SETTING_IGNORED`. A command-line `-s` expands with the command
/// line's `-D` values and the project directory.
#[test]
fn a_settings_option_in_maven_config_is_ignored() {
    let project = Project::new();
    project.write(".mvn/ci.xml", &settings("2.0"));
    project.write(".mvn/other.xml", &settings("1.0"));
    project.write(".mvn/maven.config", "-s\n.mvn/ci.xml\n-Dchoice=ci\n");
    let output = project.raeva(&["--json", "sync", "--offline"]);
    assert_success(&output, "maven.config -s");
    assert_eq!(project.locked(), ["lib:1.0"]);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let warnings = envelope["data"]["warnings"].as_array().expect("warnings");
    assert!(
        warnings
            .iter()
            .any(|warning| warning["code"] == "SETTING_IGNORED"
                && warning["message"].as_str().is_some_and(|m| m.contains("-s")
                    && m.ends_with("review the file and pass it as raeva -s <file> sync"))),
        "{envelope}"
    );

    let other = project.path().join(".mvn/other.xml");
    let other = other.to_str().expect("UTF-8 path");
    let ci = project.path().join(".mvn/ci.xml");
    project.sync(&["-s", ci.to_str().expect("UTF-8 path"), "-s", other]);
    assert_eq!(project.locked(), ["lib:2.0"]);
    project.sync(&["-s", "${session.rootDirectory}/.mvn/other.xml"]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    project.sync(&[
        "-Dchoice=other",
        "-s",
        "${maven.multiModuleProjectDirectory}/.mvn/${choice}.xml",
    ]);
    assert_eq!(project.locked(), ["lib:1.0"]);
    // A -D value of the file does not pick the command line's -s either.
    let output = project.raeva(&[
        "-s",
        "${maven.multiModuleProjectDirectory}/.mvn/${choice}.xml",
        "sync",
        "--offline",
    ]);
    assert_status(&output, 3, "-s expanded with a maven.config -D");
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
    fs::write(&lib, text).expect("write lib POM");
    fs::write(
        lib.with_extension("pom.sha256"),
        sha256_hex(text.as_bytes()),
    )
    .expect("sidecar");
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
        fs::write(dir.join(path), text).expect("write");
        fs::write(
            dir.join(format!("{path}.sha256")),
            sha256_hex(text.as_bytes()),
        )
        .expect("write");
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
