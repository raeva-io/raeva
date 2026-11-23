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

/// Maven takes a `<systemPath>` for absolute as `java.io.File` does on the
/// OS it runs on: on Windows a drive path in either slash form, not `/opt`;
/// elsewhere a leading `/` only. Each locked platform is judged by its own
/// rule, whatever OS raeva runs on, and a refusal names the platform.
#[test]
fn a_system_path_is_judged_on_each_locked_platform() {
    let profile = |id: &str, family: &str, body: &str| {
        format!(
            "<profile><id>{id}</id><activation><os><family>{family}</family></os></activation>\
             {body}</profile>"
        )
    };
    let plugin = |path: &str| {
        format!(
            "<build><plugins><plugin><groupId>org.apache.maven.plugins</groupId>\
             <artifactId>maven-clean-plugin</artifactId><version>3.2.0</version><dependencies>\
             <dependency><groupId>com.example</groupId><artifactId>native</artifactId>\
             <version>1</version><scope>system</scope><systemPath>{path}</systemPath>\
             </dependency></dependencies></plugin></plugins></build>"
        )
    };
    let project_dependency = |path: &str| {
        format!(
            "<dependencies><dependency><groupId>com.example</groupId><artifactId>native\
             </artifactId><version>1</version><scope>system</scope><systemPath>{path}\
             </systemPath></dependency></dependencies>"
        )
    };
    let sync = |profiles: &str, platforms: &str| {
        let (project, home) = temp_project();
        fs::write(
            project.path().join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                 <artifactId>demo</artifactId><version>1.0.0</version><profiles>{profiles}\
                 </profiles></project>\n"
            ),
        )
        .expect("write pom.xml");
        fs::create_dir_all(project.path().join("lib")).expect("create lib");
        fs::write(project.path().join("lib/x.jar"), "jar").expect("write jar");
        let output = raeva_command(project.path(), home.path())
            .args(["sync", "--offline", "--platforms", platforms])
            .output()
            .expect("run raeva sync");
        (output, project, home)
    };
    let both = "linux-x86_64,windows-x86_64";
    let fine = [
        profile("w", "windows", &plugin("C:/x.jar")),
        profile("b", "windows", &plugin("C:\\x.jar")),
        profile("u", "unix", &plugin("/opt/x.jar")),
    ]
    .concat();
    let (output, ..) = sync(&fine, both);
    assert_status(&output, 0, "drive paths on Windows, /opt elsewhere");
    // The project directory is absolute wherever Maven runs.
    let inside = [
        profile(
            "w",
            "windows",
            &project_dependency("${project.basedir}/lib/x.jar"),
        ),
        profile("p", "windows", &plugin("${project.basedir}/lib/x.jar")),
        profile(
            "u",
            "unix",
            &project_dependency("${project.basedir}/lib/x.jar"),
        ),
    ]
    .concat();
    let (output, ..) = sync(&inside, both);
    assert_status(&output, 0, "a path in the project");
    for (profiles, platforms, platform) in [
        (
            profile("w", "windows", &plugin("/opt/x.jar")),
            both,
            "windows-x86_64",
        ),
        (
            profile("u", "unix", &plugin("C:/x.jar")),
            both,
            "linux-x86_64",
        ),
        (
            profile("a", "unix", &plugin("C:/x.jar")),
            "macos-aarch64",
            "macos-aarch64",
        ),
    ] {
        let (output, ..) = sync(&profiles, platforms);
        assert_status(&output, 3, &profiles);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("must specify an absolute path"), "{stderr}");
        assert!(stderr.contains(platform), "{platform}: {stderr}");
    }
    // A project dependency's file is read and recorded; one Maven takes for
    // absolute only on another OS cannot be, and the refusal says so.
    let (output, ..) = sync(
        &profile("w", "windows", &project_dependency("/opt/x.jar")),
        both,
    );
    assert_status(&output, 3, "/opt on Windows");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("windows-x86_64"), "{stderr}");
    assert!(stderr.contains("absolute"), "{stderr}");
    let foreign = if cfg!(windows) {
        "/opt/x.jar"
    } else {
        "C:/x.jar"
    };
    let family = if cfg!(windows) { "unix" } else { "windows" };
    let (output, ..) = sync(&profile("f", family, &project_dependency(foreign)), both);
    assert_status(&output, 3, foreign);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not a path on this host"), "{stderr}");
    let platform = if cfg!(windows) {
        "linux-x86_64"
    } else {
        "windows-x86_64"
    };
    assert!(stderr.contains(platform), "{stderr}");
}

/// A `<systemPath>` written as the project's own path on the host was
/// written for the host's OS, and Maven on another OS refuses it, as
/// `/home/me/app/lib/x.jar` on Windows. One written to start at the project
/// directory, directly or through a property, or at a build directory, is
/// absolute wherever Maven runs.
#[test]
fn a_host_path_in_the_project_is_judged_on_the_locked_platform() {
    let (family, platform) = if cfg!(windows) {
        ("unix", "linux-x86_64")
    } else {
        ("windows", "windows-x86_64")
    };
    let sync = |system_path: &dyn Fn(&Path) -> String, plugin: bool| {
        let (project, home) = temp_project();
        let root = dunce::canonicalize(project.path()).expect("canonical project");
        fs::create_dir_all(root.join("lib")).expect("create lib");
        fs::create_dir_all(root.join("target")).expect("create target");
        fs::write(root.join("lib/x.jar"), "jar").expect("write jar");
        let dependency = format!(
            "<dependency><groupId>com.example</groupId><artifactId>native</artifactId>\
             <version>1</version><scope>system</scope><systemPath>{}</systemPath>\
             </dependency>",
            system_path(&root)
        );
        let body = match plugin {
            true => format!(
                "<build><plugins><plugin><groupId>org.apache.maven.plugins</groupId>\
                 <artifactId>maven-clean-plugin</artifactId><version>3.2.0</version>\
                 <dependencies>{dependency}</dependencies></plugin></plugins></build>"
            ),
            false => format!("<dependencies>{dependency}</dependencies>"),
        };
        fs::write(
            root.join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                 <artifactId>demo</artifactId><version>1.0.0</version><profiles><profile>\
                 <id>p</id><activation><os><family>{family}</family></os></activation>\
                 <properties><lib>${{project.basedir}}/lib</lib><empty/>\
                 <out>${{project.build.directory}}</out>\
                 <build.outputDirectory>{lib}</build.outputDirectory>\
                 <reporting.outputDirectory>{lib}</reporting.outputDirectory></properties>\
                 {body}</profile></profiles></project>\n",
                lib = root.join("lib").display()
            ),
        )
        .expect("write pom.xml");
        fs::write(
            home.path().join("config.toml"),
            "[security]\nallow_env_substitution = [\"RAEVA_W3_EMPTY\"]\n",
        )
        .expect("write config.toml");
        let output = raeva_command(&root, home.path())
            .env("RAEVA_W3_EMPTY", "")
            .args(["sync", "--offline", "--platforms"])
            .arg("linux-x86_64,windows-x86_64")
            .output()
            .expect("run raeva sync");
        (output, project, home)
    };
    let literal = |root: &Path| root.join("lib").join("x.jar").display().to_string();
    for plugin in [false, true] {
        let (output, ..) = sync(&literal, plugin);
        assert_status(&output, 3, &format!("a host path, plugin {plugin}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("absolute"), "{stderr}");
        assert!(stderr.contains(platform), "{stderr}");
        for path in [
            "${project.basedir}/lib/x.jar",
            "${basedir}/lib/x.jar",
            "${lib}/x.jar",
            " ${project.properties.lib}/x.jar",
            "${out}/../lib/x.jar",
            "${empty}${project.basedir}/lib/x.jar",
            "${env.RAEVA_W3_EMPTY}${project.basedir}/lib/x.jar",
            "${RAEVA_W3_EMPTY}${project.basedir}/lib/x.jar",
            // Maven aligns these to the project directory.
            "${build.outputDirectory}/x.jar",
            "${reporting.outputDirectory}/x.jar",
        ] {
            let (output, ..) = sync(&|_| path.to_string(), plugin);
            assert_status(&output, 0, &format!("{path}, plugin {plugin}"));
        }
    }
}

/// Maven reads `${project.reporting.outputDirectory}` from the model, the
/// super POM's `${project.build.directory}/site` unless `<reporting>` sets
/// one, ahead of any property or `-D` value of that name, and aligns it to
/// the project directory. Each case below is what Maven 3.9.12 and 3.10.0
/// put on the classpath (`dependency:build-classpath`), in both modes and
/// for every locked platform.
#[test]
fn the_reporting_directory_is_read_from_the_model() {
    struct Case {
        system_path: &'static str,
        /// Extra elements of the project, after `<version>`.
        body: &'static str,
        args: &'static [&'static str],
        /// Where Maven finds the jar, relative to the project directory.
        locked: &'static str,
    }
    let cases = [
        Case {
            system_path: "${project.reporting.outputDirectory}/lib.jar",
            body: "",
            args: &[],
            locked: "target/site/lib.jar",
        },
        Case {
            system_path: "${pom.reporting.outputDirectory}/lib.jar",
            body: "",
            args: &[],
            locked: "target/site/lib.jar",
        },
        // The model field wins over a property and a `-D` value.
        Case {
            system_path: "${project.reporting.outputDirectory}/lib.jar",
            body: "<properties><project.reporting.outputDirectory>{ALT}\
                   </project.reporting.outputDirectory></properties>",
            args: &[],
            locked: "target/site/lib.jar",
        },
        Case {
            system_path: "${project.reporting.outputDirectory}/lib.jar",
            body: "",
            args: &["-Dproject.reporting.outputDirectory={ALT}"],
            locked: "target/site/lib.jar",
        },
        // Unprefixed, a property wins and is aligned; without one the model
        // gives the value.
        Case {
            system_path: "${reporting.outputDirectory}/lib.jar",
            body: "",
            args: &[],
            locked: "target/site/lib.jar",
        },
        Case {
            system_path: "${reporting.outputDirectory}/lib.jar",
            body: "<properties><reporting.outputDirectory>alternate\
                   </reporting.outputDirectory></properties>",
            args: &[],
            locked: "alternate/lib.jar",
        },
        Case {
            system_path: "${project.reporting.outputDirectory}/lib.jar",
            body: "<reporting><outputDirectory>alternate</outputDirectory></reporting>",
            args: &[],
            locked: "alternate/lib.jar",
        },
        Case {
            system_path: "${project.reporting.outputDirectory}/lib.jar",
            body: "<build><directory>out</directory></build>",
            args: &[],
            locked: "out/site/lib.jar",
        },
        Case {
            system_path: "${project.reporting.outputDirectory}/lib.jar",
            body: "<profiles><profile><id>p</id><activation><activeByDefault>true\
                   </activeByDefault></activation><reporting><outputDirectory>alternate\
                   </outputDirectory></reporting></profile></profiles>",
            args: &[],
            locked: "alternate/lib.jar",
        },
    ];
    for case in &cases {
        for mode in ["3.9", "3.10"] {
            let (project, home) = temp_project();
            let root = dunce::canonicalize(project.path()).expect("canonical project");
            let mut digests = Vec::new();
            for (dir, bytes) in [
                ("target/site", "site jar"),
                ("alternate", "alternate jar"),
                ("out/site", "out jar"),
            ] {
                fs::create_dir_all(root.join(dir)).expect("create jar dir");
                fs::write(root.join(dir).join("lib.jar"), bytes).expect("write jar");
                digests.push((dir, crate::common::sha256_hex(bytes.as_bytes())));
            }
            let alternate = root.join("alternate").display().to_string();
            let body = case.body.replace("{ALT}", &alternate);
            fs::write(
                root.join("pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                     <artifactId>demo</artifactId><version>1.0.0</version>{body}\
                     <dependencies><dependency><groupId>com.example</groupId>\
                     <artifactId>lib</artifactId><version>1</version><scope>system</scope>\
                     <systemPath>{}</systemPath></dependency></dependencies></project>\n",
                    case.system_path
                ),
            )
            .expect("write pom.xml");
            fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .expect("write raeva.toml");
            let args: Vec<String> = (case.args.iter())
                .map(|arg| arg.replace("{ALT}", &alternate))
                .collect();
            let what = format!("{} {body} {args:?} in {mode}", case.system_path);
            let output = raeva_command(&root, home.path())
                .args(&args)
                .args(["sync", "--offline", "--platforms"])
                .arg("linux-x86_64,windows-x86_64")
                .output()
                .expect("run raeva sync");
            assert_status(&output, 0, &what);
            let lock = fs::read_to_string(root.join("raeva.lock")).expect("lock");
            let digest = &digests
                .iter()
                .find(|(dir, _)| case.locked.starts_with(dir))
                .expect("a jar the case locks")
                .1;
            assert!(
                lock.contains(&format!("\\t{}\\t{digest}", case.locked)),
                "{what}\n{lock}"
            );
            let frozen = raeva_command(&root, home.path())
                .args(&args)
                .args(["sync", "--frozen", "--offline", "--platforms"])
                .arg("linux-x86_64,windows-x86_64")
                .output()
                .expect("run raeva sync --frozen");
            assert_status(&frozen, 0, &format!("frozen {what}"));
        }
    }
}

/// A module inherits its parent's `<reporting><outputDirectory>` as
/// written and aligns it to its own directory, as Maven 3.9.12 and 3.10.0
/// do (`dependency:build-classpath` gives `child/alternate/lib.jar`).
#[test]
fn the_reporting_directory_is_inherited() {
    for mode in ["3.9", "3.10"] {
        let (project, home) = temp_project();
        let root = dunce::canonicalize(project.path()).expect("canonical project");
        for (dir, bytes) in [
            ("child/alternate", "child alternate jar"),
            ("child/target/site", "child site jar"),
            ("alternate", "root alternate jar"),
        ] {
            fs::create_dir_all(root.join(dir)).expect("create jar dir");
            fs::write(root.join(dir).join("lib.jar"), bytes).expect("write jar");
        }
        fs::write(
            root.join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.0.0</version><packaging>pom</packaging>\
             <reporting><outputDirectory>alternate</outputDirectory></reporting>\
             <modules><module>child</module></modules></project>\n",
        )
        .expect("write pom.xml");
        fs::write(
            root.join("child/pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.0.0</version></parent>\
             <artifactId>child</artifactId><dependencies><dependency>\
             <groupId>com.example</groupId><artifactId>lib</artifactId><version>1</version>\
             <scope>system</scope>\
             <systemPath>${project.reporting.outputDirectory}/lib.jar</systemPath>\
             </dependency></dependencies></project>\n",
        )
        .expect("write child pom.xml");
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .expect("write raeva.toml");
        let output = raeva_command(&root, home.path())
            .args(["sync", "--offline"])
            .output()
            .expect("run raeva sync");
        assert_status(&output, 0, mode);
        let lock = fs::read_to_string(root.join("raeva.lock")).expect("lock");
        let digest = crate::common::sha256_hex(b"child alternate jar");
        assert!(
            lock.contains(&format!("\\tchild/alternate/lib.jar\\t{digest}")),
            "{mode}\n{lock}"
        );
    }
}

/// The plain text model fields Maven's interpolation reads ahead of a
/// property of the same name, inherited as Maven inherits them: `<name>`
/// and `<modelVersion>` not at all, `<description>` and `<inceptionYear>`
/// where the module sets none, `<organization>` whole where the module
/// declares none. A field the model leaves unset gives way to the property,
/// and the unprefixed `${name}` reads the properties first. Maven 3.9.12
/// and 3.10.0 resolve each `<systemPath>` below to the locked directory.
/// `<url>`, which Maven extends with the module's path, and a getter of a
/// field's text, such as `${project.name.empty}`, stay unresolved, so the
/// path is refused.
#[test]
fn the_plain_text_model_fields_are_read_from_the_model() {
    let cases = [
        (
            "",
            "<name>N</name>",
            "<project.name>P</project.name>",
            "${project.name}",
            Some("N"),
        ),
        (
            "",
            "<name>N</name>",
            "<pom.name>P</pom.name>",
            "${pom.name}",
            Some("N"),
        ),
        ("", "<name>N</name>", "<name>P</name>", "${name}", Some("P")),
        ("", "<name>N</name>", "", "${name}", Some("N")),
        (
            "<name>N</name>",
            "",
            "<project.name>P</project.name>",
            "${project.name}",
            Some("P"),
        ),
        (
            "<description>N</description>",
            "",
            "<project.description>P</project.description>",
            "${project.description}",
            Some("N"),
        ),
        (
            "",
            "<description>${project.artifactId}-N</description>",
            "",
            "${project.description}",
            Some("child-N"),
        ),
        (
            "<inceptionYear>N</inceptionYear>",
            "",
            "",
            "${project.inceptionYear}",
            Some("N"),
        ),
        (
            "<organization><name>N</name></organization>",
            "",
            "<project.organization.name>P</project.organization.name>",
            "${project.organization.name}",
            Some("N"),
        ),
        (
            "<organization><name>N</name></organization>",
            "<organization><url>u</url></organization>",
            "<project.organization.name>P</project.organization.name>",
            "${project.organization.name}",
            Some("P"),
        ),
        (
            "<organization><name>N</name></organization>",
            "<organization/>",
            "<project.organization.name>P</project.organization.name>",
            "${project.organization.name}",
            Some("P"),
        ),
        (
            "",
            "<organization><url>N</url></organization>",
            "",
            "${project.organization.url}",
            Some("N"),
        ),
        (
            "",
            "",
            "<project.modelVersion>P</project.modelVersion>",
            "${project.modelVersion}",
            Some("4.0.0"),
        ),
        (
            "<url>N</url>",
            "",
            "<project.url>P</project.url>",
            "${project.url}",
            None,
        ),
        (
            "",
            "<name xml:lang=\"en\">N</name>",
            "<project.name>P</project.name>",
            "${project.name}",
            Some("N"),
        ),
        // Maven reads `String.isEmpty`, which raeva does not.
        (
            "",
            "<name>N</name>",
            "<project.name.empty>P</project.name.empty>",
            "${project.name.empty}",
            None,
        ),
        // A name no getter of Maven's model reads is the property's.
        (
            "",
            "",
            "<project.build.sourceEncoding>P</project.build.sourceEncoding>",
            "${project.build.sourceEncoding}",
            Some("P"),
        ),
    ];
    for mode in ["3.9", "3.10"] {
        for (parent, module, properties, expression, locked) in cases {
            let (project, home) = temp_project();
            let root = dunce::canonicalize(project.path()).expect("canonical project");
            for dir in ["N", "P", "child-N", "4.0.0"] {
                let dir = root.join("child").join(dir);
                fs::create_dir_all(&dir).expect("create jar dir");
                fs::write(dir.join("lib.jar"), dir.display().to_string()).expect("write jar");
            }
            fs::write(
                root.join("pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                     <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
                     {parent}<modules><module>child</module></modules></project>\n"
                ),
            )
            .expect("write pom.xml");
            fs::write(
                root.join("child/pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><parent>\
                     <groupId>com.example</groupId><artifactId>parent</artifactId>\
                     <version>1</version></parent><artifactId>child</artifactId>{module}\
                     <properties>{properties}</properties><dependencies><dependency>\
                     <groupId>com.example</groupId><artifactId>lib</artifactId>\
                     <version>1</version><scope>system</scope>\
                     <systemPath>${{project.basedir}}/{expression}/lib.jar</systemPath>\
                     </dependency></dependencies></project>\n"
                ),
            )
            .expect("write child pom.xml");
            fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .expect("write raeva.toml");
            let output = raeva_command(&root, home.path())
                .args(["sync", "--offline"])
                .output()
                .expect("run raeva sync");
            let what = format!("{expression} with {parent:?} {module:?} {properties:?} in {mode}");
            let Some(locked) = locked else {
                assert_status(&output, 3, &what);
                continue;
            };
            assert_status(&output, 0, &what);
            let lock = fs::read_to_string(root.join("raeva.lock")).expect("lock");
            let dir = root.join("child").join(locked);
            let digest = crate::common::sha256_hex(dir.display().to_string().as_bytes());
            assert!(
                lock.contains(&format!("\\tchild/{locked}/lib.jar\\t{digest}")),
                "{what}\n{lock}"
            );
        }
    }
}
