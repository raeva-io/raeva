//! `system`-scoped dependencies in `raeva sync`: where their files may live,
//! how a changed file affects kept platforms, and the errors for paths raeva
//! cannot use.

use std::fs;
use std::path::Path;

use crate::common::{assert_status, raeva_command, temp_project};

/// raeva.lock records a system file by its path inside the project, so a
/// `<systemPath>` that names a file elsewhere, directly or through a link
/// in the project, stops the sync with a configuration error and no lock.
#[test]
fn a_system_path_outside_the_project_is_refused() {
    let outside = tempfile::tempdir().expect("outside dir");
    let jar = outside.path().join("tools.jar");
    fs::write(&jar, b"outside").expect("write outside jar");
    let pom = |system_path: &str| {
        format!(
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>tools</artifactId>
      <version>1.0</version>
      <scope>system</scope>
      <systemPath>{system_path}</systemPath>
    </dependency>
  </dependencies>
</project>
"#
        )
    };
    let refused = |project: &Path, home: &Path| {
        let output = raeva_command(project, home)
            .args(["sync", "--offline"])
            .output()
            .expect("run raeva sync");
        assert_status(&output, 3, "system path outside the project");
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(stderr.contains("outside the project"), "{stderr}");
        assert!(!project.join("raeva.lock").exists());
    };

    let (project, home) = temp_project();
    fs::write(
        project.path().join("pom.xml"),
        pom(&jar.display().to_string()),
    )
    .expect("write pom.xml");
    refused(project.path(), home.path());

    #[cfg(unix)]
    {
        let (project, home) = temp_project();
        fs::create_dir_all(project.path().join("lib")).expect("create lib");
        std::os::unix::fs::symlink(&jar, project.path().join("lib/tools.jar"))
            .expect("link outside jar");
        fs::write(
            project.path().join("pom.xml"),
            pom("${project.basedir}/lib/tools.jar"),
        )
        .expect("write pom.xml");
        refused(project.path(), home.path());
    }
}

/// A missing, blank or relative `<systemPath>` in the project POM, its own
/// or one that dependency management supplies, is project input raeva
/// refuses: exit 3 with `INVALID_POM`, naming the file, and no lock.
#[test]
fn a_project_system_dependency_without_an_absolute_path_exits_3() {
    let dependency = |extra: &str| {
        format!(
            "<dependency><groupId>com.example</groupId><artifactId>tools</artifactId>\
             <version>1.0</version>{extra}</dependency>"
        )
    };
    let poms = [
        format!(
            "<dependencies>{}</dependencies>",
            dependency("<scope>system</scope>")
        ),
        format!(
            "<dependencies>{}</dependencies>",
            dependency("<scope>system</scope><systemPath> </systemPath>")
        ),
        format!(
            "<dependencies>{}</dependencies>",
            dependency("<scope>system</scope><systemPath>lib/tools.jar</systemPath>")
        ),
        format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
             <dependencies><dependency><groupId>com.example</groupId>\
             <artifactId>tools</artifactId></dependency></dependencies>",
            dependency("<scope>system</scope>")
        ),
    ];
    for body in poms {
        let (project, home) = temp_project();
        fs::write(
            project.path().join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                 <artifactId>demo</artifactId><version>1.0.0</version>{body}</project>\n"
            ),
        )
        .expect("write pom.xml");
        let output = raeva_command(project.path(), home.path())
            .args(["--json", "sync", "--offline"])
            .output()
            .expect("run raeva sync");
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("one JSON envelope");
        assert_status(&output, 3, &format!("systemPath without a file: {body}"));
        assert_eq!(envelope["code"], "INVALID_POM", "{body}: {envelope}");
        let error = envelope["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("<systemPath>") && error.contains("pom.xml"),
            "{body}: {envelope}"
        );
        assert!(!project.path().join("raeva.lock").exists(), "{body}");
    }
}
