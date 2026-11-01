//! Where `export-m2` writes, and what it leaves alone in the Maven local
//! repository other builds share.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use crate::common::{assert_success, raeva_command, sha256_hex};

/// A project that depends on `org.test:lib:1.0` from its own `repository/`,
/// locked offline. The Maven home is `home`, whose settings.xml names
/// `home/shared` as the local repository, the one `mvn` writes.
struct Project {
    root: tempfile::TempDir,
    home: tempfile::TempDir,
}

impl Project {
    fn new() -> Self {
        let project = Self {
            root: tempfile::TempDir::new().expect("project"),
            home: tempfile::TempDir::new().expect("home"),
        };
        let dir = project.path().join("repository/org/test/lib/1.0");
        fs::create_dir_all(&dir).expect("create repository");
        let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                   <artifactId>lib</artifactId><version>1.0</version></project>";
        for (name, bytes) in [("lib-1.0.pom", pom.as_bytes()), ("lib-1.0.jar", b"jar")] {
            fs::write(dir.join(name), bytes).expect("write file");
            fs::write(dir.join(format!("{name}.sha256")), sha256_hex(bytes)).expect("sidecar");
        }
        fs::write(
            project.path().join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version>\
             <repositories><repository><id>project-local</id>\
             <url>file://${project.basedir}/repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>1.0</version></dependency></dependencies></project>",
        )
        .expect("write pom.xml");
        let m2 = project.home.path().join(".m2");
        fs::create_dir_all(&m2).expect("create .m2");
        fs::write(
            m2.join("settings.xml"),
            format!(
                "<settings><localRepository>{}</localRepository></settings>",
                project.shared().display()
            ),
        )
        .expect("write settings.xml");
        project
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn shared(&self) -> PathBuf {
        self.home.path().join("shared")
    }

    fn raeva(&self, args: &[&str]) -> Output {
        raeva_command(self.path(), self.home.path())
            .args(args)
            .output()
            .expect("run raeva")
    }

    fn sync(&self) {
        assert_success(&self.raeva(&["sync", "--offline"]), "sync");
    }

    /// `--json export-m2` with `args`, and the warning codes it reported.
    fn export(&self, args: &[&str]) -> Vec<String> {
        let output = self.raeva(&[&["--json", "export-m2"], args].concat());
        assert_success(&output, &format!("export-m2 {args:?}"));
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON envelope");
        (envelope["data"]["warnings"].as_array())
            .expect("warnings")
            .iter()
            .map(|warning| warning["code"].as_str().expect("code").to_string())
            .collect()
    }
}

fn listing(versions: &[&str]) -> String {
    let versions: String = (versions.iter())
        .map(|version| format!("<version>{version}</version>"))
        .collect();
    format!("<metadata><versioning><versions>{versions}</versions></versioning></metadata>")
}

/// The versions a `maven-metadata-*.xml` lists, in order.
fn listed(path: &Path) -> Vec<String> {
    let text = fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    (text.split("<version>").skip(1))
        .map(|rest| rest.split('<').next().expect("version").to_string())
        .collect()
}

/// Into the repository settings.xml names, however the path is spelled,
/// export adds the locked version to the lists, keeps what `mvn install`
/// wrote, and warns once with the commands of an isolated export. Elsewhere
/// it removes the other lists.
#[test]
fn the_shared_repository_keeps_other_metadata() {
    let project = Project::new();
    project.sync();
    let shared = project.shared();
    let lib = shared.join("org/test/lib");
    fs::create_dir_all(&lib).expect("create lib dir");
    fs::write(
        lib.join("maven-metadata-local.xml"),
        listing(&["2.0-SNAPSHOT"]),
    )
    .expect("local");
    fs::write(
        lib.join("maven-metadata-project-local.xml"),
        listing(&["0.9"]),
    )
    .expect("listing");

    let spelled = project.home.path().join("shared/org/../.");
    let codes = project.export(&["--m2-path", spelled.to_str().unwrap()]);
    assert_eq!(
        (codes.iter())
            .filter(|code| *code == "EXPORT_SHARED_REPOSITORY")
            .count(),
        1,
        "{codes:?}"
    );
    assert_eq!(
        listed(&lib.join("maven-metadata-local.xml")),
        ["2.0-SNAPSHOT"]
    );
    assert_eq!(
        listed(&lib.join("maven-metadata-project-local.xml")),
        ["0.9", "1.0"]
    );
    assert!(lib.join("1.0/lib-1.0.jar").is_file());

    let output = project.raeva(&["export-m2"]);
    assert_success(&output, "export-m2 to settings.xml's repository");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let isolated = project.path().join(".m2").join("repository");
    assert!(stderr.contains("EXPORT_SHARED_REPOSITORY"), "{stderr}");
    // A command word is quoted when the shell could read a character of it,
    // such as the `~` of a Windows short name.
    for (before, word) in [
        ("raeva export-m2 --m2-path ", isolated.display().to_string()),
        ("", format!("-Dmaven.repo.local={}", isolated.display())),
        ("", format!("-Dmaven.repo.local.tail={}", shared.display())),
    ] {
        assert!(
            stderr.contains(&format!("{before}{word}"))
                || stderr.contains(&format!("{before}'{word}'")),
            "{word}: {stderr}"
        );
    }
    assert_eq!(
        listed(&lib.join("maven-metadata-local.xml")),
        ["2.0-SNAPSHOT"]
    );

    let own = project.path().join("own");
    fs::create_dir_all(own.join("org/test/lib")).expect("create own");
    fs::write(
        own.join("org/test/lib/maven-metadata-local.xml"),
        listing(&["2.0-SNAPSHOT"]),
    )
    .expect("local");
    let codes = project.export(&["--m2-path", own.to_str().unwrap()]);
    assert!(!codes.iter().any(|code| code == "EXPORT_SHARED_REPOSITORY"));
    assert!(listed(&own.join("org/test/lib/maven-metadata-local.xml")).is_empty());
    assert_eq!(
        listed(&own.join("org/test/lib/maven-metadata-project-local.xml")),
        ["1.0"]
    );
}

/// The command line's `-Dmaven.repo.local` chooses the destination below
/// `--m2-path`, and leaves the lock current. The one `.mvn/maven.config`
/// gives is ignored, with a warning.
#[test]
fn the_command_line_local_repository_is_the_destination() {
    let project = Project::new();
    project.sync();
    let defined = project.path().join("defined");
    let define = format!("-Dmaven.repo.local={}", defined.display());
    let codes = project.export(&[&define]);
    assert!(codes.is_empty(), "{codes:?}");
    assert!(defined.join("org/test/lib/1.0/lib-1.0.jar").is_file());
    assert!(!project.shared().exists());
    assert_success(
        &project.raeva(&[&define, "sync", "--frozen", "--offline"]),
        "frozen sync with -Dmaven.repo.local",
    );

    let explicit = project.path().join("explicit");
    project.export(&[&define, "--m2-path", explicit.to_str().unwrap()]);
    assert!(explicit.join("org/test/lib/1.0/lib-1.0.jar").is_file());

    let config = project.path().join(".mvn");
    fs::create_dir_all(&config).expect("create .mvn");
    fs::write(
        config.join("maven.config"),
        format!(
            "-Dmaven.repo.local={}\n",
            project.path().join("cloned").display()
        ),
    )
    .expect("write maven.config");
    project.sync();
    let codes = project.export(&[]);
    assert!(
        codes
            .iter()
            .any(|code| code == "PROJECT_LOCAL_REPOSITORY_IGNORED"),
        "{codes:?}"
    );
    assert!(!project.path().join("cloned").exists());
    assert!(
        project
            .shared()
            .join("org/test/lib/1.0/lib-1.0.jar")
            .is_file()
    );
}

/// A local repository that cannot be created names its path and is a
/// configuration error, not a bare I/O error.
#[test]
fn an_unusable_local_repository_names_its_path() {
    let project = Project::new();
    project.sync();
    let file = project.path().join("not-a-directory");
    fs::write(&file, "x").expect("write file");
    let output = project.raeva(&["--json", "export-m2", "--m2-path", file.to_str().unwrap()]);
    crate::common::assert_status(&output, 3, "export-m2 into a file");
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["code"], "LOCAL_REPOSITORY", "{envelope}");
    let error = envelope["error"].as_str().expect("error");
    let expected = format!("cannot use the local repository {}: ", file.display());
    assert!(error.contains(&expected), "{error}");
}
