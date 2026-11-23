use std::fs;
use std::path::Path;

use crate::common::{
    assert_status, assert_success, publish, raeva_command, run_raeva, toml_strings,
    write_with_sha256,
};
use crate::offline_project::Project;

/// A JDK `JAVA_VERSION` names, for a lock that reads the JDK version.
const JDK_17: &[(&str, &str)] = &[("JAVA_VERSION", "17")];

fn lock(root: &Path) -> toml::Value {
    toml::from_str(&fs::read_to_string(root.join("raeva.lock")).expect("read lock"))
        .expect("parse lock")
}

fn ambient(root: &Path) -> Vec<String> {
    lock(root)
        .get("resolution")
        .and_then(|resolution| resolution.get("ambient_inputs"))
        .map(toml_strings)
        .unwrap_or_default()
        .into_iter()
        .filter(|name| !name.starts_with("user-property:") && !name.starts_with("user-override:"))
        .collect()
}

fn model_profiles(root: &Path) -> Vec<String> {
    toml_strings(&lock(root)["inputs"][0]["profiles"])
}

const LIB: &str = "<dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
<version>1.0</version></dependency>";

fn pom(artifact: &str, repository: &str, extra: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>{artifact}</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${{project.basedir}}/{repository}</url></repository>\
         </repositories>{extra}</project>"
    )
}

fn file_profile(id: &str, file: &str, body: &str) -> String {
    format!(
        "<profile><id>{id}</id><activation><file><exists>{file}</exists></file></activation>\
         {body}</profile>"
    )
}

#[test]
fn an_inactive_jdk_profile_added_to_the_pom_passes_frozen() {
    let project = Project::synced();
    let pom_path = project.root().join("pom.xml");
    let original = fs::read_to_string(&pom_path).expect("read pom");
    let locked = fs::read(project.root().join("raeva.lock")).expect("read lock");
    let profile = "<profiles><profile><id>legacy</id><activation><jdk>1.8</jdk></activation>\
                   <dependencies><dependency><groupId>org.test</groupId>\
                   <artifactId>missing</artifactId><version>1</version></dependency>\
                   </dependencies></profile></profiles></project>";
    fs::write(&pom_path, original.replace("</project>", profile)).expect("write pom");
    for args in [
        &["sync", "--frozen"][..],
        &["sync", "--frozen", "--offline"],
    ] {
        assert_success(&project.raeva_with(JDK_17, args), &format!("{args:?}"));
        assert_eq!(fs::read(project.root().join("raeva.lock")).unwrap(), locked);
    }
    assert_success(
        &project.raeva_with(JDK_17, &["sync", "--offline"]),
        "record the profile",
    );
    assert_eq!(ambient(&project.root()), ["jdk:1.8 is false"]);
}

/// A `<file>` condition is recorded relative to the project, so the lock
/// passes after the project moves, and the file's appearance is drift. A
/// profile that only configures the build is neither recorded nor listed.
#[test]
fn file_profiles_record_project_relative_outcomes() {
    let profiles = format!(
        "<profiles>{}{}</profiles>",
        file_profile(
            "marked",
            "${project.basedir}/marker.txt",
            &format!("<dependencies>{LIB}</dependencies>")
        ),
        file_profile(
            "build-only",
            "${project.basedir}/build.txt",
            "<properties><skipTests>true</skipTests></properties>"
        ),
    );
    let project = Project::synced_with(&[
        ("pom.xml", &pom("root", "repository/", &profiles)),
        ("build.txt", "x"),
    ]);
    let root = project.root();
    assert_eq!(ambient(&root), ["file:marker.txt is false"]);
    assert!(model_profiles(&root).is_empty());
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!text.contains(root.to_str().unwrap()), "{text}");

    fs::write(root.join("marker.txt"), "x").unwrap();
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        7,
        "file appearance is drift",
    );
    assert_success(&project.raeva(&["sync", "--offline"]), "activate marked");
    assert_eq!(ambient(&root), ["file:marker.txt is true"]);
    assert_eq!(model_profiles(&root), ["marked"]);

    fs::remove_file(root.join("build.txt")).unwrap();
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "a build-only profile is not drift",
    );

    let moved = root.with_file_name("moved");
    fs::rename(&root, &moved).unwrap();
    let home = tempfile::TempDir::new().unwrap();
    assert_success(
        &raeva_command(&moved, home.path())
            .args(["sync", "--frozen"])
            .output()
            .unwrap(),
        "frozen after the project moved",
    );
}

/// Each module's `<file>` condition is its own, although the profile id is
/// the same in both. A path that climbs out of a module to the reactor
/// root is recorded as it climbs.
#[test]
fn a_file_profile_activates_per_module() {
    let dependencies = format!("<dependencies>{LIB}</dependencies>");
    let profile = format!(
        "<profiles>{}{}</profiles>",
        file_profile("marked", "${project.basedir}/marker.txt", &dependencies),
        file_profile("shared", "${project.basedir}/../shared.txt", &dependencies),
    );
    let root_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                    <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                    <modules><module>a</module><module>b</module></modules></project>";
    let project = Project::synced_with(&[
        ("pom.xml", root_pom),
        ("a/pom.xml", &pom("a", "../repository/", &profile)),
        ("b/pom.xml", &pom("b", "../repository/", &profile)),
        ("a/marker.txt", "x"),
    ]);
    let root = project.root();
    assert_eq!(
        ambient(&root),
        [
            "file:a/../shared.txt is false",
            "file:a/marker.txt is true",
            "file:b/../shared.txt is false",
            "file:b/marker.txt is false",
        ]
    );
    fs::write(root.join("b/marker.txt"), "x").unwrap();
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        7,
        "module file appearance is drift",
    );
}

/// A settings.xml condition is recorded as an opaque key and its outcome,
/// so a JDK patch update that keeps the outcome is not drift.
#[test]
fn a_settings_jdk_condition_records_its_outcome_only() {
    let project = Project::synced();
    let settings = project.m2_settings();
    let extra = tempfile::TempDir::new().unwrap();
    fs::write(
        &settings,
        format!(
            "<settings><profiles><profile><id>jdk17</id><activation><jdk>17</jdk></activation>\
         <repositories><repository><id>extra</id><url>file://{}/</url>\
         </repository></repositories></profile></profiles></settings>",
            extra.path().display()
        ),
    )
    .unwrap();
    let run = |version: &str, args: &[&str]| project.raeva_with(&[("JAVA_VERSION", version)], args);
    assert_success(&run("17.0.1", &["sync", "--offline"]), "record settings");
    let recorded = ambient(&project.root());
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert!(recorded[0].starts_with("settings:"), "{recorded:?}");
    assert!(recorded[0].ends_with(" is true"), "{recorded:?}");
    let text = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
    assert!(!text.contains("17.0.1"), "{text}");
    assert_success(
        &run("17.0.2", &["sync", "--frozen", "--offline"]),
        "a JDK patch update",
    );
    let output = run("21", &["sync", "--frozen", "--offline"]);
    assert_status(&output, 7, "frozen after JDK major change");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("settings.xml jdk:17"), "{stderr}");
}

/// Past 1024 conditions a lock records the JDK version instead of each
/// `<jdk>` condition. `<file>` conditions, which each module tests on its
/// own paths, have their own limit and stay recorded, so `--frozen` still
/// sees one flip.
#[test]
fn many_jdk_conditions_fall_back_and_file_conditions_stay() {
    let dependencies = format!("<dependencies>{LIB}</dependencies>");
    let jdk_profiles = |count| -> String {
        (0..count)
            .map(|i| {
                format!(
                    "<profile><id>jdk{i}</id><activation><jdk>[{i},)</jdk></activation>\
                     {dependencies}</profile>"
                )
            })
            .collect()
    };
    let file_profiles: String = (0..1100)
        .map(|i| file_profile(&format!("f{i}"), &format!("marker{i}"), &dependencies))
        .collect();
    let project = Project::with(&[(
        "pom.xml",
        &pom(
            "root",
            "repository/",
            &format!("<profiles>{}{file_profiles}</profiles>", jdk_profiles(1025)),
        ),
    )]);
    assert_success(&project.raeva_with(JDK_17, &["sync", "--offline"]), "sync");
    let recorded = ambient(&project.root());
    assert_eq!(recorded.len(), 1101, "{recorded:?}");
    assert!(recorded.contains(&"java.version".to_string()));
    assert!(recorded.contains(&"file:marker1099 is false".to_string()));

    fs::write(project.root().join("marker1099"), "").unwrap();
    assert_status(
        &project.raeva_with(JDK_17, &["sync", "--frozen", "--offline"]),
        7,
        "file condition past the jdk cap is still drift",
    );

    // Below the limit, `<jdk>` conditions stay beside as many files.
    fs::write(
        project.root().join("pom.xml"),
        pom(
            "root",
            "repository/",
            &format!("<profiles>{}{file_profiles}</profiles>", jdk_profiles(3)),
        ),
    )
    .unwrap();
    assert_success(&project.raeva_with(JDK_17, &["sync", "--offline"]), "sync");
    let recorded = ambient(&project.root());
    assert_eq!(recorded.len(), 1103, "{recorded:?}");
    assert!(recorded.contains(&"jdk:[2,) is true".to_string()));
    assert!(!recorded.contains(&"java.version".to_string()));
    assert!(recorded.contains(&"file:marker1099 is true".to_string()));
}

/// A project file whose path raeva.lock cannot hold fails the sync rather
/// than going untracked. A final `.` tests for a directory, which the
/// recorded path could not say; a `..` stays, as the filesystem resolves
/// it.
#[test]
fn a_file_path_raeva_lock_cannot_hold_fails() {
    let dependencies = format!("<dependencies>{LIB}</dependencies>");
    let project = Project::synced();
    let long = format!("d/{}", "x".repeat(254));
    for (path, recorded) in [
        (long.clone(), Some(long.as_str())),
        (format!("d/{}", "x".repeat(255)), None),
        ("${project.basedir}/gate/.".to_string(), None),
        ("${project.basedir}/gate/..".to_string(), Some("gate/..")),
    ] {
        let profile = file_profile("long", &path, &dependencies);
        fs::write(
            project.root().join("pom.xml"),
            pom(
                "root",
                "repository/",
                &format!("<profiles>{profile}</profiles>"),
            ),
        )
        .unwrap();
        let output = project.raeva(&["sync", "--offline"]);
        if let Some(recorded) = recorded {
            assert_success(&output, &path);
            // Windows resolves `gate/..` without `gate`.
            let exists = project.root().join(recorded).exists();
            assert_eq!(
                ambient(&project.root()),
                [format!("file:{recorded} is {exists}")]
            );
        } else {
            assert_status(&output, 3, &path);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("cannot record"), "{stderr}");
        }
    }
}

/// A path that leaves the project by name and comes back is recorded
/// without the detour, and one that a symlink leads out of the project is
/// not recorded, as a path outside it is not.
#[test]
fn a_file_path_is_recorded_where_it_lands() {
    let dependencies = format!("<dependencies>{LIB}</dependencies>");
    let project = Project::synced();
    let root = project.root();
    fs::write(root.join("marker.txt"), "x").unwrap();
    let name = root.file_name().unwrap().to_str().unwrap().to_string();
    let write_profile = |path: &str| {
        let profile = file_profile("marked", path, &dependencies);
        fs::write(
            root.join("pom.xml"),
            pom(
                "root",
                "repository/",
                &format!("<profiles>{profile}</profiles>"),
            ),
        )
        .unwrap();
    };
    write_profile(&format!("${{project.basedir}}/../{name}/marker.txt"));
    assert_success(&project.raeva(&["sync", "--offline"]), "re-entry path");
    assert_eq!(ambient(&root), ["file:marker.txt is true"]);
    // The `..` inside the project stays, as the filesystem resolves it.
    write_profile(&format!(
        "${{project.basedir}}/../{name}/gate/../marker.txt"
    ));
    assert_success(&project.raeva(&["sync", "--offline"]), "re-entry with ..");
    let exists = root.join("gate/../marker.txt").exists();
    assert_eq!(
        ambient(&root),
        [format!("file:gate/../marker.txt is {exists}")]
    );
    // A way out and back after a `..` inside the project keeps that `..`.
    fs::create_dir(root.join("gate")).unwrap();
    write_profile(&format!(
        "${{project.basedir}}/gate/../../{name}/marker.txt"
    ));
    assert_success(&project.raeva(&["sync", "--offline"]), "out and back");
    assert_eq!(ambient(&root), ["file:gate/../marker.txt is true"]);
    // The way back can pass a sibling of the project.
    fs::create_dir(root.with_file_name("sibling")).unwrap();
    write_profile(&format!(
        "${{project.basedir}}/../sibling/../{name}/marker.txt"
    ));
    assert_success(&project.raeva(&["sync", "--offline"]), "via a sibling");
    assert_eq!(ambient(&root), ["file:marker.txt is true"]);
    // A missing sibling is a way back only where `..` goes by name.
    write_profile(&format!(
        "${{project.basedir}}/../absent/../{name}/marker.txt"
    ));
    let output = project.raeva(&["sync", "--offline"]);
    assert_status(&output, 3, "via a missing sibling");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot record"), "{stderr}");

    #[cfg(unix)]
    {
        let outside = tempfile::TempDir::new().unwrap();
        fs::write(outside.path().join("marker.txt"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
        write_profile("${project.basedir}/link/marker.txt");
        assert_success(&project.raeva(&["sync", "--offline"]), "symlink out");
        assert!(ambient(&root).is_empty(), "{:?}", ambient(&root));

        // A way out and back that the filesystem does not resolve to where
        // the path stood, through a missing directory or a symlink, is not
        // dropped.
        fs::create_dir_all(root.join("sub/deep")).unwrap();
        std::os::unix::fs::symlink(root.join("sub/deep"), root.join("hop")).unwrap();
        for path in [
            format!("${{project.basedir}}/missing/../../{name}/marker.txt"),
            format!("${{project.basedir}}/hop/../../{name}/marker.txt"),
        ] {
            write_profile(&path);
            let output = project.raeva(&["sync", "--offline"]);
            assert_status(&output, 3, &path);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("cannot record"), "{stderr}");
        }
    }
}

#[test]
fn a_condition_whose_profile_is_gone_is_not_drift() {
    let marked = file_profile(
        "marked",
        "marker.txt",
        "<dependencies><dependency><groupId>org.test</groupId><artifactId>missing</artifactId>\
         <version>1</version></dependency></dependencies>",
    );
    let project = Project::synced_with(&[(
        "pom.xml",
        &pom(
            "root",
            "repository/",
            &format!("<profiles>{marked}</profiles><dependencies>{LIB}</dependencies>"),
        ),
    )]);
    let root = project.root();
    assert_eq!(ambient(&root), ["file:marker.txt is false"]);
    let locked = fs::read(root.join("raeva.lock")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "root",
            "repository/",
            &format!("<dependencies>{LIB}</dependencies>"),
        ),
    )
    .unwrap();
    fs::write(root.join("marker.txt"), "x").unwrap();
    for args in [
        &["sync", "--frozen"][..],
        &["sync", "--frozen", "--offline"],
    ] {
        assert_success(&project.raeva(args), &format!("{args:?}"));
        assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), locked);
    }
}

fn publish_artifact(repository: &Path, artifact: &str, version: &str, packaging: &str, body: &str) {
    let coordinate = format!("org.test:{artifact}:{version}");
    let body = format!("<packaging>{packaging}</packaging>{body}");
    crate::common::publish(repository, &coordinate, &body);
}

fn locked_artifacts(root: &Path) -> Vec<String> {
    lock(root)["platforms"][0]["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .map(|row| {
            let c = &row["coordinate"];
            format!(
                "{}:{}:{}",
                c["group"].as_str().unwrap(),
                c["artifact"].as_str().unwrap(),
                c["version"].as_str().unwrap()
            )
        })
        .collect()
}

#[test]
fn settings_profile_properties_reach_project_lineage_only_and_track_read_names() {
    let project = Project::synced();
    let root = project.root();
    let repo = root.join("repository");
    publish_artifact(&repo, "lib", "2.0", "jar", "");
    publish_artifact(&repo, "lib", "3.0", "jar", "");
    publish_artifact(&repo, "managed", "1.0", "jar", "");
    publish_artifact(&repo, "managed", "2.0", "jar", "");
    publish_artifact(&repo, "managed", "3.0", "jar", "");
    publish_artifact(&repo, "dep-leaf", "1.0", "jar", "");
    publish_artifact(&repo, "dep-leaf", "2.0", "jar", "");
    publish_artifact(
        &repo,
        "dep",
        "1.0",
        "jar",
        "<properties><dep.leaf.version>1.0</dep.leaf.version></properties>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>dep-leaf</artifactId>\
         <version>${dep.leaf.version}</version></dependency></dependencies>\
         <profiles><profile><id>dep-flag</id><activation><property><name>flag</name></property>\
         </activation><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>missing</artifactId><version>1.0</version></dependency></dependencies>\
         </profile></profiles>",
    );
    publish_artifact(
        &repo,
        "bom",
        "2.0",
        "pom",
        "<properties><lib.version>1.0</lib.version></properties>\
         <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>managed</artifactId><version>${lib.version}</version></dependency>\
         </dependencies></dependencyManagement>",
    );

    // The child inherits the repository, so it is absolute.
    let parent_pom = pom(
        "parent",
        "repository/",
        "<packaging>pom</packaging><modules><module>child</module></modules>\
             <properties><lib.version>1.0</lib.version></properties>\
             <profiles><profile><id>parent-flag</id>\
             <activation><property><name>flag</name></property></activation>\
             <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>bom</artifactId><version>${bom.version}</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>\
             </profile></profiles>",
    )
    .replace("${project.basedir}", &root.display().to_string());
    fs::write(root.join("pom.xml"), parent_pom).unwrap();
    fs::create_dir_all(root.join("child")).unwrap();
    fs::write(
        root.join("child/pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion>\
         <parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
         <version>1</version></parent><artifactId>child</artifactId>\
         <dependencies>\
           <dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>${lib.version}</version></dependency>\
           <dependency><groupId>org.test</groupId><artifactId>dep</artifactId>\
             <version>1.0</version></dependency>\
           <dependency><groupId>org.test</groupId><artifactId>managed</artifactId></dependency>\
         </dependencies></project>",
    )
    .unwrap();

    let write_settings = |lib_ver: &str, gpg: &str| {
        fs::write(
            project.m2_settings(),
            format!(
                "<settings><profiles><profile><id>ext</id>\
                 <activation><activeByDefault>true</activeByDefault></activation>\
                 <properties>\
                   <lib.version>{lib_ver}</lib.version>\
                   <dep.leaf.version>2.0</dep.leaf.version>\
                   <bom.version>2.0</bom.version>\
                   <flag>true</flag>\
                   <gpg.keyname>{gpg}</gpg.keyname>\
                 </properties></profile></profiles></settings>"
            ),
        )
        .unwrap();
    };
    write_settings("2.0", "ABC");
    assert_success(&project.raeva(&["sync", "--offline"]), "sync with settings");
    assert_eq!(
        locked_artifacts(&root),
        [
            "org.test:dep:1.0",
            "org.test:dep-leaf:1.0",
            "org.test:lib:2.0",
            "org.test:managed:1.0",
        ]
    );
    assert_eq!(model_profiles(&root), ["parent-flag"]);
    assert_eq!(
        ambient(&root),
        [
            "settings-property:bom.version",
            "settings-property:flag",
            "settings-property:lib.version",
        ]
    );

    // Changing an unread settings property is not drift.
    write_settings("2.0", "CHANGED_KEY");
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "unread settings property change",
    );

    // Changing a read settings property is drift.
    write_settings("3.0", "CHANGED_KEY");
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        7,
        "read settings property change",
    );

    // `-D` in `.mvn/maven.config` overrides settings profile properties,
    // and reaches the imported BOM too.
    write_settings("2.0", "ABC");
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/maven.config"), "-Dlib.version=3.0\n").unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync with -D");
    assert_eq!(
        locked_artifacts(&root),
        [
            "org.test:dep:1.0",
            "org.test:dep-leaf:1.0",
            "org.test:lib:3.0",
            "org.test:managed:3.0",
        ]
    );
}

/// raeva does not read user.home, user.name or user.dir from the host, so a
/// profile that resolution needs and that activates on one, or a coordinate
/// built from one, fails the sync instead of locking them as unset. A `-D`
/// value, a presence check, a condition the other conditions make moot or
/// a plugin parameter keeps working.
#[test]
fn user_properties_raeva_cannot_read_refuse_the_sync() {
    let project = Project::synced();
    let root = project.root();
    let lib = "<dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
               <version>1.0</version></dependency></dependencies>";
    let profile = |activation: &str, body: &str| {
        format!(
            "<profiles><profile><id>p</id><activation>{activation}</activation>{body}</profile></profiles>"
        )
    };
    let sync = |extra: &str, args: &[&str]| {
        fs::write(root.join("pom.xml"), pom("root", "repository/", extra)).unwrap();
        let _ = fs::remove_file(root.join("raeva.lock"));
        project.raeva(&[&["sync", "--offline"], args].concat())
    };
    for (extra, name) in [
        (
            profile(
                "<property><name>user.name</name><value>!root</value></property>",
                lib,
            ),
            "user.name",
        ),
        (
            profile("<file><exists>${user.home}/.m2</exists></file>", lib),
            "user.home",
        ),
        (
            format!(
                "<properties><d>${{user.dir}}</d></properties>{}",
                profile(
                    "<property><name>os.name</name><value>${d}</value></property>",
                    lib
                )
            ),
            "user.dir",
        ),
    ] {
        let output = sync(&extra, &[]);
        assert_status(&output, 3, name);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("depends on {name}, which raeva does not read")),
            "{stderr}"
        );
    }
    let refused = profile(
        "<property><name>user.name</name><value>!root</value></property>",
        lib,
    );
    assert_success(&sync(&refused, &["-Duser.name=ci"]), "a -D value");
    assert_success(
        &sync(
            &profile("<property><name>user.name</name></property>", lib),
            &[],
        ),
        "presence",
    );
    for (activation, case) in [
        (
            "<property><name>user.name</name><value/></property>",
            "an empty value",
        ),
        (
            "<property><name>never.set</name><value>x</value></property>\
             <file><exists>${user.home}/.m2</exists></file>",
            "another condition that fails",
        ),
        (
            if cfg!(windows) {
                "<os><family>unix</family><version>${user.name}</version></os>"
            } else {
                "<os><family>windows</family><version>${user.name}</version></os>"
            },
            "an os family that does not match",
        ),
        (
            "<file><exists>pom.xml</exists><missing>${user.home}/x</missing></file>",
            "a missing file that exists overrides",
        ),
    ] {
        assert_success(&sync(&profile(activation, lib), &[]), case);
    }
    let configured = "<build><plugins><plugin><artifactId>maven-surefire-plugin</artifactId>\
                      <configuration><argLine>-Dhome=${user.home}</argLine></configuration>\
                      </plugin></plugins></build>";
    assert_success(&sync(configured, &[]), "a plugin parameter");
    let output = sync(
        "<dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
         <version>${user.name}</version></dependency></dependencies>",
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Maven takes user.name from the JVM"),
        "{stderr}"
    );
}

/// Maven 3.9.12 and 3.10.0 activate an `activeByDefault` profile whose own
/// condition holds, and fall back to it when no profile of its POM is
/// activated, so a value raeva cannot read in its only unknown condition
/// leaves it active. Once another profile is activated, the value decides.
#[test]
fn a_default_profile_with_an_unread_condition_refuses_only_when_it_decides() {
    let project = Project::synced();
    let root = project.root();
    let default = |condition: &str| {
        format!(
            "<profile><id>d</id><activation><activeByDefault>true</activeByDefault>{condition}\
             </activation><dependencies>{LIB}</dependencies></profile>"
        )
    };
    let activated = "<profile><id>q</id><activation><property><name>!never.set</name></property>\
                     </activation></profile>";
    for mode in ["3.9", "3.10"] {
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .unwrap();
        for (condition, name) in [
            (
                "<property><name>java.vendor</name><value>Acme</value></property>",
                "java.vendor",
            ),
            (
                "<property><name>user.name</name><value>!ci</value></property>",
                "user.name",
            ),
            (
                "<file><exists>${user.home}/.m2</exists></file>",
                "user.home",
            ),
        ] {
            let sync = |profiles: &str| {
                let profiles = format!("<profiles>{profiles}</profiles>");
                fs::write(root.join("pom.xml"), pom("root", "repository/", &profiles)).unwrap();
                let _ = fs::remove_file(root.join("raeva.lock"));
                project.raeva(&["sync", "--offline"])
            };
            assert_success(&sync(&default(condition)), name);
            assert_eq!(
                locked_artifacts(&root),
                ["org.test:lib:1.0"],
                "{mode} {name}"
            );
            assert_success(&project.raeva(&["sync", "--offline", "--frozen"]), name);
            let output = sync(&[default(condition), activated.to_string()].concat());
            assert_status(&output, 3, name);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(&format!(
                    "profile d depends on {name}, which raeva does not read"
                )),
                "{stderr}"
            );
        }
    }
}

/// A `<property>` value test of `file.separator` or `path.separator` sees
/// the separator of each locked platform, written out or as `${...}`, in
/// the project's POM and in a dependency's, under both Maven lines, as
/// Maven's JVM on that OS would. A value raeva cannot know, such as
/// `java.vendor`, refuses the sync in either form, also through `${...}`,
/// in a `<file>` path and in settings.xml, instead of reading as absent.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Maven 3.9.12 and 3.10.0 launchers set `maven.multiModuleProjectDirectory`
/// to the nearest directory from the one `mvn` runs in up that holds a
/// `.mvn` directory, else to the directory itself, for every module and,
/// in 3.9, a dependency's model too.
#[test]
fn multi_module_project_directory_is_the_launchers_root() {
    let project = Project::with(&[]);
    let root = project.root();
    let above = root.parent().expect("parent").to_path_buf();
    let repository = root.join("repository");
    let profile = |id: &str, file: &str, artifact: &str| {
        format!(
            "<profile><id>{id}</id><activation><file><{file}>\
             ${{maven.multiModuleProjectDirectory}}/marker</{file}></file></activation>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>{artifact}\
             </artifactId><version>1.0</version></dependency></dependencies></profile>"
        )
    };
    for artifact in ["present", "absent", "transitive"] {
        publish_artifact(&repository, artifact, "1.0", "jar", "");
    }
    publish_artifact(
        &repository,
        "dep",
        "1.0",
        "jar",
        &format!(
            "<profiles>{}</profiles>",
            profile("d", "exists", "transitive")
        ),
    );
    fs::write(
        root.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
         <modules><module>m</module></modules></project>",
    )
    .unwrap();
    fs::create_dir_all(root.join("m")).unwrap();
    fs::write(
        root.join("m/pom.xml"),
        pom(
            "m",
            "../repository/",
            &format!(
                "<dependencies><dependency><groupId>org.test</groupId><artifactId>dep\
                 </artifactId><version>1.0</version></dependency></dependencies>\
                 <profiles>{}{}</profiles>",
                profile("e", "exists", "present"),
                profile("m", "missing", "absent")
            ),
        ),
    )
    .unwrap();
    for mode in ["3.9", "3.10"] {
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .unwrap();
        fs::write(root.join("marker"), "").unwrap();
        assert_success(&project.raeva(&["sync", "--offline"]), mode);
        let mut expected = vec!["org.test:dep:1.0", "org.test:present:1.0"];
        if mode == "3.9" {
            expected.push("org.test:transitive:1.0");
        }
        assert_eq!(locked_artifacts(&root), expected, "{mode}");
        let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(!text.contains(&*above.to_string_lossy()), "{text}");
        let frozen = ["sync", "--frozen", "--offline"];
        assert_success(&project.raeva(&frozen), mode);

        let moved = tempfile::TempDir::new().unwrap();
        let copy = moved.path().join("copy");
        copy_tree(&root, &copy);
        let output = raeva_command(&copy, project.home())
            .args(frozen)
            .output()
            .unwrap();
        assert_success(&output, "a copy at another path");

        fs::remove_file(root.join("marker")).unwrap();
        assert_status(&project.raeva(&frozen), 7, mode);
        // The launcher goes on above the project for a `.mvn` directory.
        fs::create_dir_all(above.join(".mvn")).unwrap();
        fs::write(above.join("marker"), "").unwrap();
        assert_success(&project.raeva(&frozen), mode);
        fs::create_dir_all(root.join(".mvn")).unwrap();
        assert_status(&project.raeva(&frozen), 7, mode);
        // `MAVEN_BASEDIR` names it ahead of the search.
        let above_text = above.to_string_lossy();
        let set = [("MAVEN_BASEDIR", &*above_text)];
        assert_success(&project.raeva_with(&set, &frozen), mode);
        fs::remove_dir(root.join(".mvn")).unwrap();
        fs::remove_dir(above.join(".mvn")).unwrap();
        fs::remove_file(above.join("marker")).unwrap();
    }
    // A `-D` value comes first, as in Maven.
    fs::write(above.join("marker"), "").unwrap();
    let define = format!("-Dmaven.multiModuleProjectDirectory={}", above.display());
    assert_success(&project.raeva(&["sync", "--offline", &define]), "-D");
    assert!(locked_artifacts(&root).contains(&"org.test:present:1.0".to_string()));
    // raeva.lock could not record what a `<property>` condition on it
    // tested, so one that adds a dependency refuses unless `-D` sets it.
    let condition = format!(
        "<profile><id>p</id><activation><property>\
         <name>maven.multiModuleProjectDirectory</name><value>{}</value></property>\
         </activation><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>present</artifactId><version>1.0</version></dependency>\
         </dependencies></profile>",
        root.display()
    );
    fs::write(
        root.join("m/pom.xml"),
        pom(
            "m",
            "../repository/",
            &format!("<profiles>{condition}</profiles>"),
        ),
    )
    .unwrap();
    let output = project.raeva(&["sync", "--offline"]);
    assert_status(&output, 3, "a property condition");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("depends on maven.multiModuleProjectDirectory"),
        "{stderr}"
    );
    assert_success(&project.raeva(&["sync", "--offline", &define]), "-D");
}

/// Every JVM sets `java.home`, so a presence test of it holds in Maven
/// 3.9.12 and 3.10.0 whichever JDK runs, and raeva.lock does not depend on
/// whether raeva found one.
#[test]
fn a_java_home_presence_test_holds_without_a_jdk() {
    let project = Project::with(&[]);
    let root = project.root();
    let jdks = root.parent().expect("parent").join("jdks");
    let repository = root.join("repository");
    for artifact in ["present", "absent"] {
        publish_artifact(&repository, artifact, "1.0", "jar", "");
    }
    let profile = |name: &str, artifact: &str| {
        format!(
            "<profile><id>{artifact}</id><activation><property><name>{name}</name>\
             </property></activation><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1.0</version></dependency>\
             </dependencies></profile>"
        )
    };
    let profiles = profile("java.home", "present") + &profile("!java.home", "absent");
    let body = format!("<profiles>{profiles}</profiles>");
    fs::write(root.join("pom.xml"), pom("app", "repository/", &body)).unwrap();
    fake_jdk(&jdks, "21");
    let home = jdks.join("21").to_string_lossy().into_owned();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync without a JDK");
    assert_eq!(locked_artifacts(&root), ["org.test:present:1.0"]);
    let frozen = ["sync", "--frozen", "--offline"];
    assert_success(
        &project.raeva_with(&[("JAVA_HOME", &home)], &frozen),
        "a JDK",
    );
    fs::remove_file(root.join("raeva.lock")).unwrap();
    let sync = ["sync", "--offline"];
    assert_success(
        &project.raeva_with(&[("JAVA_HOME", &home)], &sync),
        "with a JDK",
    );
    assert_success(&project.raeva(&frozen), "frozen without a JDK");
}

/// Maven 3.9.12 and 3.10.0 test `dos` and `unix` against the JVM's
/// `path.separator`, which `-D` sets. A lock without one lists nothing for
/// it, and a later `-D` makes the lock stale, also for a dependency's
/// profile.
#[test]
fn a_path_separator_define_moves_a_dependencys_os_family() {
    let project = Project::with(&[]);
    let root = project.root();
    let repository = root.join("repository");
    let profile = |family: &str, artifact: &str| {
        format!(
            "<profile><id>{family}</id><activation><os><family>{family}</family></os>\
             </activation><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1.0</version></dependency>\
             </dependencies></profile>"
        )
    };
    for artifact in ["on-unix", "on-dos"] {
        publish_artifact(&repository, artifact, "1.0", "jar", "");
    }
    let profiles = profile("unix", "on-unix") + &profile("dos", "on-dos");
    let body = format!("<profiles>{profiles}</profiles>");
    publish_artifact(&repository, "dep", "1.0", "jar", &body);
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>dep</artifactId><version>1.0</version></dependency>\
                      </dependencies>";
    fs::write(root.join("pom.xml"), pom("app", "repository/", dependency)).unwrap();
    let sync = |extra: &[&str]| {
        let mut args = vec!["sync", "--offline", "--platforms", "linux-x86_64"];
        args.extend_from_slice(extra);
        project.raeva(&args)
    };
    let define = "-Dpath.separator=;";
    assert_success(&sync(&[]), "sync");
    assert_eq!(
        locked_artifacts(&root),
        ["org.test:dep:1.0", "org.test:on-unix:1.0"]
    );
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!text.contains("path.separator"), "{text}");
    assert_status(&sync(&["--frozen", define]), 7, "frozen with a new -D");
    assert_success(&sync(&[define]), "sync with the -D");
    assert_eq!(
        locked_artifacts(&root),
        ["org.test:dep:1.0", "org.test:on-dos:1.0"]
    );
    assert_status(&sync(&["--frozen"]), 7, "frozen without the -D");
}

/// guava-parent's srczip profiles: a dependency's profile, on whether the
/// JDK has `lib/src.zip`, that adds an optional `system` dependency at that
/// path. Maven 3.9.12 and 3.10.0 only warn of an absolute path that names
/// no file, so the dependency's other dependencies stay either way, and the
/// lock does not depend on the JDK's layout.
#[test]
fn a_jdk_source_zip_profile_of_a_dependency_is_no_input() {
    let project = Project::with(&[]);
    let root = project.root();
    let repository = root.join("repository");
    let jdks = root.parent().expect("parent").join("jdks");
    publish_artifact(&repository, "good", "1.0", "jar", "");
    publish_artifact(
        &repository,
        "dep",
        "1.0",
        "jar",
        "<dependencies><dependency><groupId>org.test</groupId><artifactId>good</artifactId>\
         <version>1.0</version></dependency></dependencies><profiles><profile><id>srczip-lib\
         </id><activation><file><exists>${java.home}/lib/src.zip</exists></file></activation>\
         <dependencies><dependency><groupId>jdk</groupId><artifactId>srczip</artifactId>\
         <version>999</version><scope>system</scope><systemPath>${java.home}/lib/src.zip\
         </systemPath><optional>true</optional></dependency></dependencies></profile>\
         </profiles>",
    );
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>dep</artifactId><version>1.0</version></dependency>\
                      </dependencies>";
    fs::write(root.join("pom.xml"), pom("app", "repository/", dependency)).unwrap();
    fake_jdk(&jdks, "21");
    fake_jdk(&jdks, "27");
    fs::create_dir_all(jdks.join("27").join("lib")).unwrap();
    fs::write(jdks.join("27").join("lib").join("src.zip"), "zip").unwrap();
    let home = |name: &str| jdks.join(name).to_string_lossy().into_owned();
    let frozen = ["sync", "--frozen", "--offline"];
    let output = project.raeva_with(&[("JAVA_HOME", &home("21"))], &["sync", "--offline"]);
    assert_success(&output, "sync");
    let expected = ["org.test:dep:1.0", "org.test:good:1.0"];
    assert_eq!(locked_artifacts(&root), expected);
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!text.contains("src.zip"), "{text}");
    assert_success(
        &project.raeva_with(&[("JAVA_HOME", &home("27"))], &frozen),
        "a JDK with src.zip",
    );
    assert_success(&project.raeva(&frozen), "no JDK");
    // A `-D` can make the path relative, which makes the POM invalid.
    assert!(text.contains("\"user-property:java.home\""), "{text}");
    let output = project.raeva(&["sync", "--frozen", "--offline", "-Djava.home=rel"]);
    assert_status(&output, 7, "frozen with -Djava.home");
    fs::remove_file(root.join("raeva.lock")).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync without a JDK");
    assert_eq!(locked_artifacts(&root), expected);
    assert_success(
        &project.raeva_with(&[("JAVA_HOME", &home("27"))], &frozen),
        "a JDK with src.zip after a lock without one",
    );
    // Maven 3.10 never activates a dependency's `<file>` profile.
    fs::write(root.join("raeva.toml"), "[lock]\nmaven = \"3.10\"\n").unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync under 3.10");
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!text.contains("java.home"), "{text}");
}

/// As log4j's java8-tests profile, on `env.CI`: a dependency's parent
/// profile that configures a plugin and redeclares in test scope a
/// dependency the child declares `provided`, with the version the parent's
/// management gives it, changes nothing for the consumer, so a CI host that
/// sets the variable passes `--frozen` on a lock made without it. A profile
/// that adds a compile dependency still refuses there.
#[test]
fn a_dependency_parent_profile_on_a_hidden_variable_that_changes_nothing_is_no_input() {
    let anno = "<dependency><groupId>org.test</groupId><artifactId>anno</artifactId>\
                <version>${anno.version}</version><scope>test</scope></dependency>";
    let adds = "<dependency><groupId>org.test</groupId><artifactId>extra</artifactId>\
                <version>1.0</version></dependency>";
    for (dependencies, refuses) in [(anno, false), (adds, true)] {
        let project = Project::with(&[]);
        let root = project.root();
        let repository = root.join("repository");
        for artifact in ["anno", "extra"] {
            publish_artifact(&repository, artifact, "1.0", "jar", "");
        }
        publish_artifact(
            &repository,
            "parent",
            "1",
            "pom",
            &format!(
                "<properties><anno.version>1.0</anno.version></properties>\
                 <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>anno</artifactId><version>${{anno.version}}</version></dependency>\
                 </dependencies></dependencyManagement><profiles><profile><id>java8-tests</id>\
                 <activation><property><name>env.RAEVA_TEST_CI</name><value>true</value>\
                 </property></activation><build><plugins><plugin>\
                 <artifactId>maven-surefire-plugin</artifactId></plugin></plugins></build>\
                 <dependencies>{dependencies}</dependencies></profile></profiles>"
            ),
        );
        publish_artifact(
            &repository,
            "dep",
            "1.0",
            "jar",
            "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>anno</artifactId><scope>provided</scope></dependency></dependencies>",
        );
        let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                          <artifactId>dep</artifactId><version>1.0</version></dependency>\
                          </dependencies>";
        fs::write(root.join("pom.xml"), pom("app", "repository/", dependency)).unwrap();
        assert_success(&project.raeva(&["sync", "--offline"]), "sync");
        assert_eq!(locked_artifacts(&root), ["org.test:dep:1.0"]);
        let ci = [("RAEVA_TEST_CI", "true")];
        let output = project.raeva_with(&ci, &["sync", "--frozen", "--offline"]);
        if refuses {
            assert_status(&output, 3, "frozen on CI with a compile dependency");
        } else {
            assert_success(&output, "frozen on CI");
            let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
            assert!(!text.contains("RAEVA_TEST_CI"), "{text}");
        }
    }
}

/// A lock made where the variable a dependency's parent profile tests is
/// unset records that it read the variable, not a value, by name or, for a
/// name a `-D` gives, by the expression. Where the variable is set but
/// outside `allow_env_substitution`, a plain sync and export-m2 resolve
/// again, as `--frozen` does, and refuse where Maven 3.9.12 turns the
/// profile on and adds a dependency the lock lacks.
#[test]
fn a_hidden_variable_set_after_the_lock_is_checked_by_a_resolution() {
    for (name, define, recorded) in [
        (
            "env.RAEVA_TEST_CI",
            None,
            "\"user-property:env.RAEVA_TEST_CI\"",
        ),
        (
            "${flag}",
            Some("-Dflag=env.RAEVA_TEST_CI"),
            "'user-property-lookup:{\"expression\":\"${flag}\"",
        ),
    ] {
        let project = Project::with(&[]);
        let root = project.root();
        let repository = root.join("repository");
        publish_artifact(&repository, "extra", "1.0", "jar", "");
        publish_artifact(
            &repository,
            "parent",
            "1",
            "pom",
            &format!(
                "<profiles><profile><id>ci</id><activation><property><name>{name}</name>\
                 <value>true</value></property></activation><dependencies><dependency>\
                 <groupId>org.test</groupId><artifactId>extra</artifactId>\
                 <version>1.0</version></dependency></dependencies></profile></profiles>"
            ),
        );
        publish_artifact(
            &repository,
            "dep",
            "1.0",
            "jar",
            "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent>",
        );
        let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                          <artifactId>dep</artifactId><version>1.0</version></dependency>\
                          </dependencies>";
        fs::write(root.join("pom.xml"), pom("app", "repository/", dependency)).unwrap();
        let with_define = |args: &[&str]| {
            let mut args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
            args.extend(define.map(str::to_string));
            args
        };
        let sync = with_define(&["sync"]);
        let sync: Vec<&str> = sync.iter().map(String::as_str).collect();
        assert_success(&project.raeva(&sync), name);
        assert_eq!(locked_artifacts(&root), ["org.test:dep:1.0"]);
        let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(locked.contains(recorded), "{name}: {locked}");
        let m2 = root.join("m2");
        let export = with_define(&["export-m2", "--m2-path", m2.to_str().unwrap()]);
        let export: Vec<&str> = export.iter().map(String::as_str).collect();
        for args in [&sync, &export] {
            let output = project.raeva_with(&[("RAEVA_TEST_CI", "true")], args);
            assert_status(&output, 3, &format!("{args:?} where the profile turns on"));
            let said = String::from_utf8_lossy(&output.stderr);
            assert!(said.contains("allow_env_substitution"), "{said}");
            assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), locked);
        }
        assert!(!m2.exists());
    }
}

/// Maven 3.9.12 leaves a profile on `<value>true</value>` of a variable off
/// for `false` and `1`, as where the variable is unset. Where it is set to
/// such a value outside `allow_env_substitution`, in the project's POM or a
/// dependency's parent, raeva writes and accepts the lock it writes where
/// the variable is unset, byte for byte, in both Maven modes. `true` still
/// refuses, and so does any value of a test of presence.
#[test]
fn a_hidden_variable_whose_value_leaves_the_profile_off_reads_as_unset() {
    let profile = |condition: &str| {
        format!(
            "<profiles><profile><id>ci</id><activation><property>{condition}</property>\
             </activation><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>extra</artifactId><version>1.0</version></dependency>\
             </dependencies></profile></profiles>"
        )
    };
    let valued = profile("<name>env.RAEVA_TEST_CI</name><value>true</value>");
    let dependency = |artifact: &str| {
        format!(
            "<dependencies><dependency><groupId>org.test</groupId><artifactId>{artifact}\
             </artifactId><version>1.0</version></dependency></dependencies>"
        )
    };
    for mode in ["3.9", "3.10"] {
        for (layout, body) in [
            ("own POM", dependency("dep") + &valued),
            ("parent", dependency("child")),
        ] {
            let case = format!("{mode} {layout}");
            let project =
                Project::with(&[("raeva.toml", &format!("[lock]\nmaven = \"{mode}\"\n"))]);
            let root = project.root();
            let repository = root.join("repository");
            publish_artifact(&repository, "extra", "1.0", "jar", "");
            publish_artifact(&repository, "dep", "1.0", "jar", "");
            publish_artifact(&repository, "parent", "1", "pom", &valued);
            publish_artifact(
                &repository,
                "child",
                "1.0",
                "jar",
                "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
                 <version>1</version></parent>",
            );
            fs::write(root.join("pom.xml"), pom("app", "repository/", &body)).unwrap();
            assert_success(&project.raeva(&["sync"]), &case);
            let unset = fs::read_to_string(root.join("raeva.lock")).unwrap();
            assert!(
                unset.contains("\"user-property:env.RAEVA_TEST_CI\""),
                "{case}: {unset}"
            );
            let m2 = root.join("m2");
            let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
            for value in ["false", "1"] {
                let ci = [("RAEVA_TEST_CI", value)];
                let case = format!("{case} RAEVA_TEST_CI={value}");
                for args in [&["sync"][..], &["sync", "--frozen"], &export] {
                    let output = project.raeva_with(&ci, args);
                    assert_success(&output, &format!("{case} {args:?}"));
                    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
                    assert_eq!(lock, unset, "{case} {args:?}");
                }
                fs::remove_file(root.join("raeva.lock")).unwrap();
                assert_success(&project.raeva_with(&ci, &["sync"]), &case);
                let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
                assert_eq!(lock, unset, "{case} without a lock");
            }
            let ci = [("RAEVA_TEST_CI", "true")];
            for args in [&["sync", "--frozen"][..], &["sync"]] {
                let output = project.raeva_with(&ci, args);
                assert_status(&output, 3, &format!("{case} {args:?} with true"));
            }
            fs::remove_file(root.join("raeva.lock")).unwrap();
            assert_status(&project.raeva_with(&ci, &["sync"]), 3, &case);
        }
    }
    let project = Project::with(&[]);
    let root = project.root();
    publish_artifact(&root.join("repository"), "extra", "1.0", "jar", "");
    let presence = profile("<name>env.RAEVA_TEST_CI</name>");
    fs::write(root.join("pom.xml"), pom("app", "repository/", &presence)).unwrap();
    assert_success(&project.raeva(&["sync"]), "presence unset");
    for args in [&["sync"][..], &["sync", "--frozen"]] {
        let output = project.raeva_with(&[("RAEVA_TEST_CI", "false")], args);
        assert_status(&output, 3, &format!("presence {args:?}"));
    }
}

/// Maven 3.9.12 and 3.10.0 expand `java.home` in a `<file>` path to the
/// JDK's home, below a `-D` or POM value, in a dependency's model too in 3.9,
/// where 3.10 skips a dependency's `<file>` profiles. Plexus reads
/// `${.java.home}` as `${java.home}`, and the lock records both alike.
#[test]
fn a_java_home_file_condition_tests_the_jdk() {
    let inputs = ["java.home", ".java.home"].map(java_home_file_condition);
    assert_eq!(
        inputs[0],
        inputs[1].replace("${.java.home}", "${java.home}")
    );
}

/// [`a_java_home_file_condition_tests_the_jdk`] for `${spelling}`, which
/// returns the `ambient_inputs` of its first lock.
fn java_home_file_condition(spelling: &str) -> String {
    let project = Project::with(&[]);
    let root = project.root();
    let repository = root.join("repository");
    let jdks = root.parent().expect("parent").join("jdks");
    let profile = |artifact: &str| {
        format!(
            "<profiles><profile><id>{artifact}</id><activation><file><exists>\
             ${{{spelling}}}/release</exists></file></activation><dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <version>1.0</version></dependency></dependencies></profile></profiles>"
        )
    };
    for artifact in ["present", "transitive"] {
        publish_artifact(&repository, artifact, "1.0", "jar", "");
    }
    publish_artifact(&repository, "dep", "1.0", "jar", &profile("transitive"));
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>dep</artifactId><version>1.0</version></dependency>\
                      </dependencies>";
    let pom_text = pom(
        "app",
        "repository/",
        &format!("{dependency}{}", profile("present")),
    );
    fs::write(root.join("pom.xml"), &pom_text).unwrap();
    for version in ["21", "27"] {
        fake_jdk(&jdks, version);
    }
    let without = jdks.join("bare");
    fs::create_dir_all(&without).unwrap();
    let home = |name: &str| jdks.join(name).to_string_lossy().into_owned();
    let (jdk21, jdk27, bare) = (home("21"), home("27"), home("bare"));
    let frozen = ["sync", "--frozen", "--offline"];
    let mut inputs = String::new();
    for mode in ["3.9", "3.10"] {
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .unwrap();
        let output = project.raeva_with(&[("JAVA_HOME", &jdk21)], &["sync", "--offline"]);
        assert_success(&output, mode);
        let mut expected = vec!["org.test:dep:1.0", "org.test:present:1.0"];
        if mode == "3.9" {
            expected.push("org.test:transitive:1.0");
        }
        assert_eq!(locked_artifacts(&root), expected, "{spelling} {mode}");
        let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(!text.contains(&*jdks.to_string_lossy()), "{text}");
        if inputs.is_empty() {
            let start = text.find("ambient_inputs").expect("ambient_inputs");
            let end = start + text[start..].find("\n]").expect("end of ambient_inputs");
            inputs = text[start..end].to_string();
            assert!(inputs.contains("\"user-property:java.home\""), "{inputs}");
        }
        // The lock keeps what the path tested, not the JDK's home.
        assert_success(&project.raeva_with(&[("JAVA_HOME", &jdk27)], &frozen), mode);
        assert_status(
            &project.raeva_with(&[("JAVA_HOME", &bare)], &frozen),
            7,
            mode,
        );
        // A `-D` value comes first, as in Maven.
        let define = format!("-Djava.home={bare}");
        let output = project.raeva_with(&[("JAVA_HOME", &jdk21)], &["sync", "--offline", &define]);
        assert_success(&output, "-D");
        assert_eq!(locked_artifacts(&root), ["org.test:dep:1.0"], "{mode} -D");
        // Without a JDK the path keeps `${java.home}`, which names no file,
        // as before; frozen notices a JDK that has the file.
        assert_success(&project.raeva(&["sync", "--offline"]), mode);
        assert_eq!(
            locked_artifacts(&root),
            ["org.test:dep:1.0"],
            "{mode} no JDK"
        );
        assert_success(&project.raeva(&frozen), mode);
        assert_status(
            &project.raeva_with(&[("JAVA_HOME", &jdk27)], &frozen),
            7,
            mode,
        );
    }
    // So does a POM property of that name.
    let shadowed = pom_text.replace(
        "<dependencies>",
        &format!("<properties><java.home>{bare}</java.home></properties><dependencies>"),
    );
    fs::write(root.join("pom.xml"), shadowed).unwrap();
    let output = project.raeva_with(&[("JAVA_HOME", &jdk21)], &["sync", "--offline"]);
    assert_success(&output, "a POM property");
    assert_eq!(locked_artifacts(&root), ["org.test:dep:1.0"]);
    inputs
}

/// Maven 3.9.12 and 3.10.0 expand a JVM property in `<os>` and `<jdk>`
/// text too, so a condition that reads one raeva does not know refuses,
/// naming the `-D` that sets it, rather than comparing `${java.vendor}`
/// as written. With that `-D`, the lock is Maven's.
#[test]
fn an_os_condition_on_a_jvm_property_refuses_or_takes_the_define() {
    let project = Project::with(&[]);
    let root = project.root();
    publish_artifact(&root.join("repository"), "vendor", "1.0", "jar", "");
    let profiles = "<profiles><profile><id>v</id><activation><os><name>${.java.vendor}</name>\
                    </os></activation><dependencies><dependency><groupId>org.test</groupId>\
                    <artifactId>vendor</artifactId><version>1.0</version></dependency>\
                    </dependencies></profile></profiles>";
    fs::write(root.join("pom.xml"), pom("app", "repository/", profiles)).unwrap();
    for mode in ["3.9", "3.10"] {
        let config = format!("[lock]\nmaven = \"{mode}\"\n");
        fs::write(root.join("raeva.toml"), config).unwrap();
        let output = project.raeva(&["sync", "--offline", "-Dos.name=Acme"]);
        assert_status(&output, 3, mode);
        let said = crate::common::stderr(&output);
        assert!(said.contains("-Djava.vendor="), "{said}");
        let defines = ["sync", "--offline", "-Dos.name=Acme", "-Djava.vendor=Acme"];
        assert_success(&project.raeva(&defines), mode);
        assert_eq!(locked_artifacts(&root), ["org.test:vendor:1.0"], "{mode}");
    }
}

#[test]
fn separator_conditions_follow_each_locked_platform() {
    let project = Project::with(&[]);
    let root = project.root();
    let repository = root.join("repository");
    let profile = |id: &str, name: &str, value: &str, body: &str| {
        format!(
            "<profile><id>{id}</id><activation><property><name>{name}</name>\
             <value>{value}</value></property></activation>{body}</profile>"
        )
    };
    let dependency = |artifact: &str| {
        format!(
            "<dependencies><dependency><groupId>org.test</groupId><artifactId>{artifact}\
             </artifactId><version>1.0</version></dependency></dependencies>"
        )
    };
    for artifact in ["unix", "windows", "every"] {
        publish_artifact(&repository, artifact, "1.0", "jar", "");
    }
    publish_artifact(
        &repository,
        "dep",
        "1.0",
        "jar",
        &format!(
            "<profiles>{}</profiles>",
            profile("p", "path.separator", ";", &dependency("windows"))
        ),
    );
    let pom_text = |profiles: &str| {
        pom(
            "root",
            "repository/",
            &format!("{}<profiles>{profiles}</profiles>", dependency("dep")),
        )
    };
    let separators = [
        profile("unix", "file.separator", "/", &dependency("unix")),
        profile(
            "every",
            "path.separator",
            "${path.separator}",
            &dependency("every"),
        ),
    ]
    .concat();
    let platforms = ["--platforms", "linux-x86_64,macos-aarch64,windows-x86_64"];
    for mode in ["3.9", "3.10"] {
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .unwrap();
        fs::write(root.join("pom.xml"), pom_text(&separators)).unwrap();
        assert_success(
            &project.raeva(&[&["sync", "--offline"][..], &platforms].concat()),
            mode,
        );
        let parsed = lock(&root);
        let mut by_target = std::collections::BTreeMap::new();
        for section in parsed["platforms"].as_array().expect("platforms") {
            for target in toml_strings(&section["targets"]) {
                by_target.insert(target, section_artifacts(section));
            }
        }
        let with = |artifact: &str| {
            let mut artifacts =
                ["org.test:dep:1.0", "org.test:every:1.0", artifact].map(String::from);
            artifacts.sort();
            artifacts.to_vec()
        };
        assert_eq!(
            by_target["linux-x86_64"],
            with("org.test:unix:1.0"),
            "{mode}"
        );
        assert_eq!(
            by_target["macos-aarch64"],
            with("org.test:unix:1.0"),
            "{mode}"
        );
        assert_eq!(
            by_target["windows-x86_64"],
            with("org.test:windows:1.0"),
            "{mode}"
        );
        assert_success(
            &project.raeva(&[&["sync", "--frozen", "--offline"][..], &platforms].concat()),
            mode,
        );

        for (name, value, active) in [
            ("java.vendor", "Acme", true),
            ("java.vendor", "!Acme", false),
            // A name no one sets would decide the condition by itself.
            ("os.name", "${java.vendor}", false),
        ] {
            let vendor = profile("vendor", name, value, &dependency("unix"));
            fs::write(root.join("pom.xml"), pom_text(&vendor)).unwrap();
            let output = project.raeva(&["sync", "--offline"]);
            assert_status(&output, 3, value);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("depends on java.vendor, which raeva does not read"),
                "{stderr}"
            );
            let set = ["sync", "--offline", "-Djava.vendor=Acme"];
            assert_success(&project.raeva(&set), value);
            let locked = locked_artifacts(&root).contains(&"org.test:unix:1.0".to_string());
            assert_eq!(locked, active, "{mode} {name}={value}");
            assert_success(&project.raeva(&[&set[..], &["--frozen"]].concat()), value);
        }
        // Maven 3.9.12 and 3.10.0 test the path with the JVM's vendor in it.
        fs::write(root.join("m-Acme"), "").unwrap();
        for (file, active) in [("exists", true), ("missing", false)] {
            let path = format!(
                "<profile><id>path</id><activation><file><{file}>${{basedir}}/m-${{java.vendor}}\
                 </{file}></file></activation>{}</profile>",
                dependency("unix")
            );
            fs::write(root.join("pom.xml"), pom_text(&path)).unwrap();
            let output = project.raeva(&["sync", "--offline"]);
            assert_status(&output, 3, file);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("depends on java.vendor"), "{stderr}");
            let set = ["sync", "--offline", "-Djava.vendor=Acme"];
            assert_success(&project.raeva(&set), file);
            let locked = locked_artifacts(&root).contains(&"org.test:unix:1.0".to_string());
            assert_eq!(locked, active, "{mode} {file}");
            assert_success(&project.raeva(&[&set[..], &["--frozen"]].concat()), file);
        }
        fs::write(root.join("pom.xml"), pom_text("")).unwrap();
        let settings = |body: &str| {
            let vendor = profile("s", "java.vendor", "Acme", body);
            fs::write(
                project.m2_settings(),
                format!("<settings><profiles>{vendor}</profiles></settings>"),
            )
            .unwrap();
        };
        settings("<properties><v>2</v></properties>");
        let output = project.raeva(&["sync", "--offline"]);
        assert_status(&output, 3, "settings");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("settings.xml profile s depends on java.vendor"),
            "{stderr}"
        );
        assert_success(
            &project.raeva(&["sync", "--offline", "-Djava.vendor=Acme"]),
            "settings -D",
        );
        // A profile that sets nothing cannot change the lock.
        settings("");
        assert_success(&project.raeva(&["sync", "--offline"]), "inert settings");
        // Maven expands settings.xml from its system properties.
        let separator = profile(
            "s",
            "file.separator",
            "${file.separator}",
            "<properties><which>unix</which></properties>",
        );
        fs::write(
            project.m2_settings(),
            format!("<settings><profiles>{separator}</profiles></settings>"),
        )
        .unwrap();
        let which = pom(
            "root",
            "repository/",
            &format!(
                "<properties><which>windows</which></properties>{}",
                dependency("${which}")
            ),
        );
        fs::write(root.join("pom.xml"), which).unwrap();
        assert_success(&project.raeva(&["sync", "--offline"]), "settings separator");
        assert_eq!(locked_artifacts(&root), ["org.test:unix:1.0"], "{mode}");
        fs::remove_file(project.m2_settings()).unwrap();
    }
}

/// Maven 3.9.12 fails on a settings.xml activation error wherever it
/// occurs, so a profile that fails only on another OS fails a lock for it.
#[test]
fn a_settings_activation_error_on_a_locked_platform_fails_the_sync() {
    let project = Project::synced();
    let (family, platform) = if cfg!(windows) {
        ("unix", "linux-x86_64")
    } else {
        ("windows", "windows-x86_64")
    };
    fs::write(
        project.m2_settings(),
        format!(
            "<settings><profiles><profile><id>w</id><activation><os><family>{family}</family>\
             <version>regex:[</version></os></activation></profile></profiles></settings>"
        ),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync on the host");
    let output = project.raeva(&["sync", "--offline", "--platforms", platform]);
    assert_status(&output, 3, platform);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to determine activation for profile w"),
        "{stderr}"
    );
}

/// The failure holds for a locked Windows platform the run keeps or checks
/// without resolving it.
#[test]
fn a_settings_activation_error_on_a_kept_platform_fails() {
    let project = Project::synced();
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", "windows-x86_64"]),
        "sync for windows",
    );
    fs::write(
        project.m2_settings(),
        "<settings><profiles><profile><id>w</id><activation><os><family>windows</family>\
         <version>regex:[</version></os></activation></profile></profiles></settings>",
    )
    .unwrap();
    let host = rv_lock::Platform::current().unwrap().os_arch();
    for args in [
        &["sync", "--offline", "--platforms", &host][..],
        &["sync", "--frozen", "--offline", "--platforms", &host],
        &["sync", "--frozen", "--offline"],
        &["export-checksums", "--offline"],
    ] {
        let output = project.raeva(args);
        assert_status(&output, 3, &args.join(" "));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Failed to determine activation for profile w"),
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn settings_activation_reads_unallowlisted_env_and_refuses_unrecordable_property_names() {
    let project = Project::synced();
    let root = project.root();
    let extra = tempfile::TempDir::new().unwrap();
    fs::write(
        project.m2_settings(),
        format!(
            "<settings><profiles><profile><id>ci</id>\
             <activation>\
               <jdk>${{env.RAEVA_TEST_SETTINGS_JDK}}</jdk>\
               <property><name>env.RAEVA_TEST_SETTINGS_CI</name></property>\
             </activation>\
             <repositories><repository><id>ci-repo</id><url>file://{}/</url>\
             </repository></repositories></profile></profiles></settings>",
            extra.path().display()
        ),
    )
    .unwrap();
    let env = [
        ("JAVA_VERSION", "21"),
        ("RAEVA_TEST_SETTINGS_JDK", "[17,)"),
        ("RAEVA_TEST_SETTINGS_CI", "1"),
    ];
    assert_success(
        &project.raeva_with(&env, &["sync", "--offline"]),
        "sync with env-activated settings profile",
    );
    // The `<jdk>` and `<property>` conditions, and the outcome of the
    // activation on the platform, which an `${env.*}` in the `<jdk>` text
    // decides.
    let recorded = ambient(&root);
    assert_eq!(recorded.len(), 3, "{recorded:?}");
    assert!(
        recorded
            .iter()
            .all(|item| item.starts_with("settings:") && item.ends_with(" is true"))
    );
    assert_status(
        &project.raeva_with(
            &[("JAVA_VERSION", "21"), ("RAEVA_TEST_SETTINGS_JDK", "[17,)")],
            &["sync", "--frozen", "--offline"],
        ),
        7,
        "flipping unallowlisted settings env condition is drift",
    );

    let too_long = "p".repeat(129);
    fs::write(
        project.m2_settings(),
        format!(
            "<settings><profiles><profile><id>bad</id>\
             <activation><activeByDefault>true</activeByDefault></activation>\
             <properties><{too_long}>1.0</{too_long}></properties>\
             </profile></profiles></settings>"
        ),
    )
    .unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "root",
            "repository/",
            &format!(
                "<dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>lib</artifactId><version>${{{too_long}}}</version>\
                 </dependency></dependencies>"
            ),
        ),
    )
    .unwrap();
    let output = project.raeva(&["sync", "--offline"]);
    assert_status(&output, 3, "unrecordable settings property name");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot record"), "{stderr}");
}

/// A project depending on `org.test:lib:[1.0,3.0)`, which its own
/// repository lists at 1.0, with a settings.xml profile whose
/// `<activation>` holds `condition` and whose repository lists it at 2.0,
/// locked as Maven `maven` resolves.
fn settings_activation_project(maven: &str, condition: &str) -> (Project, tempfile::TempDir) {
    let project = Project::with(&[]);
    let root = project.root();
    let extra = tempfile::TempDir::new().unwrap();
    for (repository, version) in [
        (root.join("repository"), "1.0"),
        (extra.path().into(), "2.0"),
    ] {
        publish_artifact(&repository, "lib", version, "jar", "");
        let metadata = format!(
            "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId><versioning>\
             <release>{version}</release><versions><version>{version}</version></versions>\
             <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
        );
        let path = repository.join("org/test/lib/maven-metadata.xml");
        write_with_sha256(&path, metadata.as_bytes());
    }
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>lib</artifactId><version>[1.0,3.0)</version></dependency>\
                      </dependencies>";
    fs::write(root.join("pom.xml"), pom("app", "repository/", dependency)).unwrap();
    fs::write(
        root.join("raeva.toml"),
        format!("[lock]\nmaven = \"{maven}\"\n"),
    )
    .unwrap();
    fs::write(
        project.m2_settings(),
        format!(
            "<settings><profiles><profile><id>os</id><activation>{condition}\
             </activation><repositories><repository><id>extra</id><url>file://{}/</url>\
             </repository></repositories></profile></profiles></settings>",
            extra.path().display()
        ),
    )
    .unwrap();
    (project, extra)
}

fn locked_lib(root: &Path) -> String {
    let artifacts = locked_artifacts(root);
    let lib = artifacts
        .iter()
        .find(|artifact| artifact.starts_with("org.test:lib:"));
    lib.expect("lib locked").clone()
}

/// Maven 3.9.12 and 3.10.0 expand an `${env.*}` or a `-D` value in a
/// settings.xml `<os>` condition before they test it, so the variable
/// decides which repository serves the range. raeva.lock records the
/// outcome on each platform, keyed by the text as written: a plain sync
/// updates the lock once the outcome moves, `--frozen` refuses it, and
/// another value with the same outcome leaves the lock as it is.
#[test]
fn a_settings_os_condition_records_what_its_expansion_decides() {
    let sync = ["sync", "--offline", "--platforms", "linux-x86_64"];
    let frozen = [
        "sync",
        "--offline",
        "--frozen",
        "--platforms",
        "linux-x86_64",
    ];
    for maven in ["3.9", "3.10"] {
        let condition = "<os><family>${env.RAEVA_TEST_TARGET_OS}</family></os>";
        let (project, _extra) = settings_activation_project(maven, condition);
        let root = project.root();
        let target =
            |os: &str, args: &[&str]| project.raeva_with(&[("RAEVA_TEST_TARGET_OS", os)], args);
        assert_success(&target("windows", &sync), maven);
        assert_eq!(locked_lib(&root), "org.test:lib:1.0", "{maven}");
        assert_success(&target("mac", &frozen), &format!("{maven}: another value"));
        let output = target("unix", &frozen);
        assert_status(
            &output,
            7,
            &format!("{maven}: frozen once the outcome moves"),
        );
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(said.contains("settings.xml os:family=${env.RAEVA_TEST_TARGET_OS} on linux-x86_64 was false, now true"), "{maven}: {said}");
        assert_success(&target("unix", &sync), &format!("{maven}: plain sync"));
        assert_eq!(locked_lib(&root), "org.test:lib:2.0", "{maven}");
        assert_success(&target("unix", &frozen), &format!("{maven}: frozen after"));

        let condition = "<os><family>${target.os}</family></os>";
        let (project, _extra) = settings_activation_project(maven, condition);
        let root = project.root();
        let define = |os: &str, args: &[&str]| {
            let define = format!("-Dtarget.os={os}");
            project.raeva(&[args, &[define.as_str()]].concat())
        };
        assert_success(&define("windows", &sync), maven);
        assert_eq!(locked_lib(&root), "org.test:lib:1.0", "{maven}");
        assert_status(&define("unix", &frozen), 7, &format!("{maven}: -D frozen"));
        assert_success(&define("unix", &sync), &format!("{maven}: -D plain sync"));
        assert_eq!(locked_lib(&root), "org.test:lib:2.0", "{maven}");
    }
}

/// A settings.xml `<property>` condition whose name comes from an
/// `${env.*}` tests the property that variable names, in Maven 3.9.12 and
/// 3.10.0, so the lock records its outcome as for `<os>`: once the variable
/// names a property no `-D` sets, a plain sync drops the profile's
/// repository and `--frozen` refuses the lock it would change.
#[test]
fn a_settings_property_condition_records_what_its_expansion_decides() {
    let condition = "<property><name>${env.RAEVA_TEST_WHICH}</name></property>";
    for maven in ["3.9", "3.10"] {
        let (project, _extra) = settings_activation_project(maven, condition);
        let root = project.root();
        let which = |name: &str, frozen: bool| {
            let mut args = vec!["sync", "--offline", "-Dfoo=1"];
            if frozen {
                args.push("--frozen");
            }
            project.raeva_with(&[("RAEVA_TEST_WHICH", name)], &args)
        };
        assert_success(&which("foo", false), maven);
        assert_eq!(locked_lib(&root), "org.test:lib:2.0", "{maven}");
        assert_status(&which("bar", true), 7, &format!("{maven}: frozen"));
        assert_success(&which("bar", false), &format!("{maven}: plain sync"));
        assert_eq!(locked_lib(&root), "org.test:lib:1.0", "{maven}");
    }
}

/// A `-D` value in a settings.xml `<file>` or `<jdk>` condition decides
/// the profile as an `${env.*}` does, in Maven 3.9.12 and 3.10.0: an empty
/// `<exists>` holds for no file, and an unset `<jdk>` value holds for no
/// JDK. raeva.lock records the outcome where no value is recorded, the
/// empty value and the JDK `[lock] jdks` names, so `--frozen` refuses the
/// lock once the value moves it and a plain sync updates it.
#[test]
fn a_settings_file_or_jdk_condition_records_what_a_define_decides() {
    for maven in ["3.9", "3.10"] {
        let condition = "<file><exists>${marker.file}</exists></file>";
        let (project, extra) = settings_activation_project(maven, condition);
        let root = project.root();
        let marker = |path: &str, frozen: bool| {
            let define = format!("-Dmarker.file={path}");
            let mut args = vec!["sync", "--offline", define.as_str()];
            if frozen {
                args.push("--frozen");
            }
            project.raeva(&args)
        };
        assert_success(&marker("", false), maven);
        assert_eq!(locked_lib(&root), "org.test:lib:1.0", "{maven}");
        let present = extra.path().to_str().unwrap();
        assert_status(&marker(present, true), 7, &format!("{maven}: <file>"));
        assert_success(&marker(present, false), maven);
        assert_eq!(locked_lib(&root), "org.test:lib:2.0", "{maven}");

        let condition = "<jdk>${req.jdk}</jdk>";
        let (project, _extra) = settings_activation_project(maven, condition);
        let root = project.root();
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{maven}\"\njdks = [\"21\"]\n"),
        )
        .unwrap();
        let jdk = |args: &[&str]| project.raeva_with(&[("JAVA_VERSION", "21")], args);
        assert_success(&jdk(&["sync", "--offline"]), maven);
        assert_eq!(locked_lib(&root), "org.test:lib:1.0", "{maven}");
        let wanted = ["sync", "--offline", "-Dreq.jdk=[17,)"];
        assert_status(
            &jdk(&[&wanted[..], &["--frozen"]].concat()),
            7,
            &format!("{maven}: <jdk>"),
        );
        assert_success(&jdk(&wanted), maven);
        assert_eq!(locked_lib(&root), "org.test:lib:2.0", "{maven}");
    }
}

/// Maven activates a profile only when all its conditions hold, so a
/// variable in the `<property>` condition of a profile whose `<os>` never
/// holds on the locked platform changes nothing: the lock records the
/// outcome of the whole activation, and `--frozen` passes.
#[test]
fn a_settings_condition_beside_one_that_fails_changes_nothing() {
    let condition = "<os><family>windows</family></os>\
                     <property><name>${env.RAEVA_TEST_WANTED}</name></property>";
    for maven in ["3.9", "3.10"] {
        let (project, _extra) = settings_activation_project(maven, condition);
        let root = project.root();
        let wanted = |name: &str, frozen: bool| {
            let mut args = vec![
                "sync",
                "--offline",
                "--platforms",
                "linux-x86_64",
                "-Dfoo=1",
            ];
            if frozen {
                args.push("--frozen");
            }
            project.raeva_with(&[("RAEVA_TEST_WANTED", name)], &args)
        };
        assert_success(&wanted("bar", false), maven);
        assert_eq!(locked_lib(&root), "org.test:lib:1.0", "{maven}");
        assert_success(&wanted("foo", true), &format!("{maven}: frozen"));
    }
}

fn section_artifacts(section: &toml::Value) -> Vec<String> {
    section["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .map(|row| {
            let c = &row["coordinate"];
            format!(
                "{}:{}:{}",
                c["group"].as_str().unwrap(),
                c["artifact"].as_str().unwrap(),
                c["version"].as_str().unwrap()
            )
        })
        .collect()
}

/// A `<jdk>` profile that only configures plugins, as junit 4.13.2 has,
/// cannot change resolution, so reading the stand-in JDK for it is silent.
#[test]
fn a_jdk_profile_resolution_ignores_does_not_warn() {
    let project = Project::synced();
    let root = project.root();
    let pom_xml = pom(
        "root",
        "repository/",
        &format!(
            "<dependencies>{LIB}</dependencies>\
             <profiles><profile><id>jdk9</id><activation><jdk>[9,)</jdk></activation>\
             <build><plugins><plugin><artifactId>maven-compiler-plugin</artifactId>\
             <configuration><release>9</release></configuration></plugin></plugins></build>\
             </profile></profiles>"
        ),
    );
    fs::write(root.join("pom.xml"), &pom_xml).unwrap();
    let sync = project.raeva(&["sync", "--offline"]);
    assert_success(&sync, "sync with a plugin-only jdk profile");
    let stderr = String::from_utf8_lossy(&sync.stderr);
    assert!(!stderr.contains("JAVA_VERSION_DEFAULTED"), "{stderr}");
}

/// A `<jdk>` condition after an `<os>` one that fails is never decided by
/// the JDK, `-P` selects a profile without testing it, and Maven ignores
/// `<missing>` when `<exists>` is given, so none warns of the stand-in JDK,
/// though each profile can change resolution.
#[test]
fn a_jdk_condition_that_decides_nothing_does_not_warn() {
    let project = Project::synced();
    let root = project.root();
    let other_os = if cfg!(windows) { "unix" } else { "windows" };
    let pom_xml = pom(
        "root",
        "repository/",
        &format!(
            "<profiles><profile><id>elsewhere</id><activation><os><family>{other_os}</family>\
             </os><jdk>[1.8,)</jdk></activation><dependencies>{LIB}</dependencies></profile>\
             <profile><id>chosen</id><activation><jdk>[1.8,)</jdk></activation>\
             <dependencies>{LIB}</dependencies></profile>\
             <profile><id>exists</id><activation><file><exists>${{basedir}}/pom.xml</exists>\
             <missing>${{basedir}}/jdk-${{java.version}}</missing></file></activation>\
             <dependencies>{LIB}</dependencies></profile></profiles>"
        ),
    );
    fs::write(root.join("pom.xml"), &pom_xml).unwrap();
    let sync = project.raeva(&["sync", "--offline", "-P", "chosen"]);
    assert_success(&sync, "sync with undecided jdk conditions");
    let stderr = String::from_utf8_lossy(&sync.stderr);
    assert!(!stderr.contains("JAVA_VERSION_DEFAULTED"), "{stderr}");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("org.test:lib:"), "{lock}");
}

/// Where no JDK names its version (a `java` on `PATH` without a `release`
/// file, and no `JAVA_HOME` or `JAVA_VERSION`), a `<jdk>` condition of a POM
/// or settings.xml, a `java.specification.version` condition, and a
/// `.mvn/maven.config` `-D` value that expands `${java.version}` each
/// change what is resolved, so the sync warns that raeva stood in 17 and
/// fails (exit 3) instead of locking what 17 selects. With the JDK named,
/// each resolves.
#[test]
fn stand_in_jdk_reads_that_change_the_lock_refuse() {
    let refused = |output: &std::process::Output, what: &str| {
        assert_status(output, 3, what);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("JAVA_VERSION_DEFAULTED")
                && stderr.contains("the resolution depends on the JDK version"),
            "{what}: {stderr}"
        );
    };
    let shim = |project: &Project| {
        let bin = project.home().join("shim");
        fs::create_dir_all(&bin).unwrap();
        fs::write(
            bin.join(if cfg!(windows) { "java.exe" } else { "java" }),
            "",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(bin.join("java"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        bin.to_str().unwrap().to_string()
    };
    for condition in [
        "<jdk>[17,)</jdk>",
        "<property><name>java.specification.version</name><value>17</value></property>",
    ] {
        let project = Project::synced();
        let pom_xml = pom(
            "root",
            "repository/",
            &format!(
                "<profiles><profile><id>on17</id><activation>{condition}</activation>\
                 <dependencies>{LIB}</dependencies></profile></profiles>"
            ),
        );
        fs::write(project.root().join("pom.xml"), &pom_xml).unwrap();
        let path = shim(&project);
        let java_path = [(rv_maven_model::JAVA_PATH_TEST_ENV, path.as_str())];
        refused(
            &project.raeva_with(&java_path, &["sync", "--offline"]),
            condition,
        );
        assert_success(
            &project.raeva_with(JDK_17, &["sync", "--offline"]),
            &format!("{condition} with JAVA_VERSION"),
        );
        refused(
            &project.raeva_with(&java_path, &["sync", "--frozen", "--offline"]),
            &format!("{condition}, frozen"),
        );
    }

    let project = Project::synced();
    let extra = tempfile::TempDir::new().unwrap();
    fs::write(
        project.m2_settings(),
        format!(
            "<settings><profiles><profile><id>jdk17</id><activation><jdk>17</jdk></activation>\
             <repositories><repository><id>extra</id><url>file://{}/</url>\
             </repository></repositories></profile></profiles></settings>",
            extra.path().display()
        ),
    )
    .unwrap();
    refused(
        &project.raeva(&["sync", "--offline"]),
        "sync with a settings jdk profile",
    );

    let project = Project::synced();
    let root = project.root();
    let pom_xml = pom(
        "root",
        "repository/",
        &format!(
            "<profiles><profile><id>on17</id><activation><property><name>build.jdk</name>\
             <value>17</value></property></activation><dependencies>{LIB}</dependencies>\
             </profile></profiles>"
        ),
    );
    fs::write(root.join("pom.xml"), &pom_xml).unwrap();
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join(".mvn/maven.config"),
        "-Dbuild.jdk=${java.version}\n",
    )
    .unwrap();
    refused(
        &project.raeva(&["sync", "--offline"]),
        "sync with a -D value of java.version",
    );

    // A condition that reaches java.version through a `-D` value is
    // recorded as a lookup, and still warns.
    let project = Project::synced();
    let root = project.root();
    let pom_xml = pom(
        "root",
        "repository/",
        &format!(
            "<profiles><profile><id>on17</id><activation><file>\
             <exists>${{basedir}}/jdk-${{selector}}</exists></file></activation>\
             <dependencies>{LIB}</dependencies></profile></profiles>"
        ),
    );
    fs::write(root.join("pom.xml"), &pom_xml).unwrap();
    fs::write(root.join("jdk-17"), "").unwrap();
    let sync = project.raeva(&["sync", "--offline", "-Dselector=${java.version}"]);
    refused(&sync, "sync with a java.version lookup");
    let sync = project.raeva_with(JDK_17, &["sync", "--offline", "-Dselector=${java.version}"]);
    assert_success(&sync, "sync with a java.version lookup and JAVA_VERSION");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("org.test:lib:"), "{lock}");
}

/// A JDK `version` below `jdks`, with an empty `java` and a `release` file
/// naming the version. Returns its `bin` directory.
fn fake_jdk(jdks: &Path, version: &str) -> String {
    let bin = jdks.join(version).join("bin");
    fs::create_dir_all(&bin).unwrap();
    let java = bin.join(if cfg!(windows) { "java.exe" } else { "java" });
    fs::write(&java, "").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&java, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let release = format!("JAVA_VERSION=\"{version}\"\n");
    fs::write(jdks.join(version).join("release"), release).unwrap();
    bin.to_str().unwrap().to_string()
}

/// A build with the `testing` feature, as `cargo test` makes the binary,
/// finds the JDK where a release build does when the `java` lookup hook is
/// unset, so its raeva.lock is the release build's.
#[test]
fn without_the_java_hook_the_java_on_the_path_is_the_host_jdk() {
    let project = Project::synced();
    let root = project.root();
    publish_artifact(&root.join("repository"), "jdk21-only", "1.0", "jar", "");
    let profile = "<profiles><profile><id>jdk21</id><activation><jdk>[21,)</jdk></activation>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>jdk21-only</artifactId>\
         <version>1.0</version></dependency></dependencies></profile></profiles>";
    let pom_xml = pom(
        "root",
        "repository/",
        &format!("<dependencies>{LIB}</dependencies>{profile}"),
    );
    fs::write(root.join("pom.xml"), pom_xml).unwrap();
    let jdks = tempfile::TempDir::new().unwrap();
    let jdk21 = fake_jdk(jdks.path(), "21.0.4");
    let host_path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(std::path::PathBuf::from(&jdk21)).chain(std::env::split_paths(&host_path)),
    )
    .unwrap();
    let synced = raeva_command(&root, project.home())
        .env_remove(rv_maven_model::JAVA_PATH_TEST_ENV)
        .env("PATH", path)
        .args(["sync", "--offline"])
        .output()
        .expect("run raeva");
    assert_success(&synced, "sync with JDK 21 first on PATH");
    assert!(
        !String::from_utf8_lossy(&synced.stderr).contains("JAVA_VERSION_DEFAULTED"),
        "{synced:?}"
    );
    assert_eq!(ambient(&root), ["jdk:[21,) is true"]);
}

/// Without `JAVA_HOME`, the host JDK is the `java` on `PATH`, as `mvn` runs
/// it, so its `release` file gives `java.version`, and `--frozen` refuses a
/// lock made with another JDK there. `JAVA_HOME` still comes first.
#[test]
fn the_java_on_the_path_is_the_host_jdk() {
    let project = Project::synced();
    let root = project.root();
    publish_artifact(&root.join("repository"), "jdk21-only", "1.0", "jar", "");
    let profile = "<profiles><profile><id>jdk21</id><activation><jdk>[21,)</jdk></activation>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>jdk21-only</artifactId>\
         <version>1.0</version></dependency></dependencies></profile></profiles>";
    let pom_xml = pom(
        "root",
        "repository/",
        &format!("<dependencies>{LIB}</dependencies>{profile}"),
    );
    fs::write(root.join("pom.xml"), pom_xml).unwrap();
    let jdks = tempfile::TempDir::new().unwrap();
    let (jdk21, jdk17) = (
        fake_jdk(jdks.path(), "21.0.4"),
        fake_jdk(jdks.path(), "17.0.2"),
    );
    let run = |path: &str, env: &[(&str, &str)], args: &[&str]| {
        let mut env = env.to_vec();
        env.push((rv_maven_model::JAVA_PATH_TEST_ENV, path));
        project.raeva_with(&env, args)
    };

    let synced = run(&jdk21, &[], &["sync", "--offline"]);
    assert_success(&synced, "sync with JDK 21 on PATH");
    assert!(
        !String::from_utf8_lossy(&synced.stderr).contains("JAVA_VERSION_DEFAULTED"),
        "{synced:?}"
    );
    assert_eq!(ambient(&root), ["jdk:[21,) is true"]);
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(text.contains("org.test:jdk21-only:"), "{text}");
    assert!(!text.contains(jdks.path().to_str().unwrap()), "{text}");
    let frozen = ["sync", "--frozen", "--offline"];
    assert_success(&run(&jdk21, &[], &frozen), "the same JDK on PATH");
    assert_status(&run(&jdk17, &[], &frozen), 7, "JDK 17 on PATH");
    // JAVA_VERSION applies only when the JDK's release file names no version.
    let java_version = [("JAVA_VERSION", "17")];
    assert_success(&run(&jdk21, &java_version, &frozen), "JDK 21 on PATH");
    let jdk17_home = Path::new(&jdk17).parent().unwrap().to_str().unwrap();
    let java_home = [("JAVA_HOME", jdk17_home)];
    assert_status(
        &run(&jdk21, &java_home, &frozen),
        7,
        "JAVA_HOME before PATH",
    );

    // mvn sources a mavenrc file before it picks the JDK, even with JAVA_HOME
    // set, and raeva has the shell run it as mvn does.
    let mavenrc = if cfg!(windows) {
        "mavenrc_pre.cmd"
    } else {
        ".mavenrc"
    };
    let frozen_with = |env: &[(&str, &str)]| {
        let output = run(&jdk21, env, &frozen);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        (output, stderr)
    };
    let jdk21_home = Path::new(&jdk21).parent().unwrap().to_str().unwrap();
    // Not MAVEN_OPTS, which would replace the harness's -Duser.home.
    fs::write(project.home().join(mavenrc), "MAVEN_COLOR=false\n").unwrap();
    let (output, _) = frozen_with(&[]);
    assert_success(&output, "a mavenrc that leaves the JDK");
    let conditional = if cfg!(windows) {
        format!("if defined RAEVA_COND set JAVA_HOME={jdk17_home}\r\n")
    } else {
        format!("[ -n \"$RAEVA_COND\" ] && JAVA_HOME='{jdk17_home}'\n")
    };
    fs::write(project.home().join(mavenrc), conditional).unwrap();
    for env in [&[][..], &[("JAVA_HOME", jdk21_home)]] {
        assert_success(&frozen_with(env).0, "a mavenrc whose condition fails");
        let ci = [env, &[("RAEVA_COND", "1")]].concat();
        assert_status(&frozen_with(&ci).0, 7, "a mavenrc that picks JDK 17");
    }
    let (output, _) = frozen_with(&[("RAEVA_COND", "1"), ("MAVEN_SKIP_RC", "true")]);
    assert_success(&output, "MAVEN_SKIP_RC");
    // One that sets it gives the JDK mvn runs.
    let read = if cfg!(windows) {
        format!("set JAVA_HOME={jdk21_home}\r\n")
    } else {
        format!("export JAVA_HOME='{jdk21_home}'\n")
    };
    fs::write(project.home().join(mavenrc), read).unwrap();
    let (output, _) = frozen_with(&[("JAVA_HOME", "/opt/jdk-17")]);
    assert_success(&output, "a mavenrc that sets JAVA_HOME");
}

#[test]
fn lock_jdks_resolves_per_jdk_and_passes_frozen_across_matrix() {
    let project = Project::synced();
    let root = project.root();
    let repo = root.join("repository");
    publish_artifact(&repo, "jdk21-only", "1.0", "jar", "");

    let pom_xml = pom(
        "root",
        "repository/",
        &format!(
            "<dependencies>{LIB}</dependencies>\
             <profiles><profile><id>jdk21</id><activation><jdk>[21,)</jdk></activation>\
             <dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>jdk21-only</artifactId><version>1.0</version></dependency>\
             </dependencies></profile></profiles>"
        ),
    );
    fs::write(root.join("pom.xml"), &pom_xml).unwrap();

    let no_java_home = root.join("no-java-home");
    let no_java_home_str = no_java_home.to_str().unwrap();
    let run = |version: &str, args: &[&str]| {
        project.raeva_with(
            &[("JAVA_HOME", no_java_home_str), ("JAVA_VERSION", version)],
            args,
        )
    };

    // Without [lock] jdks, the host JDK condition is recorded and --frozen
    // fails under JDK 21.
    assert_success(&run("17", &["sync", "--offline"]), "sync under 17");
    assert_eq!(ambient(&root), ["jdk:[21,) is false"]);
    assert_success(&run("17", &["sync", "--frozen"]), "frozen under 17");
    let frozen = run("21", &["sync", "--frozen"]);
    assert_status(&frozen, 7, "frozen under 21 without [lock] jdks");
    // The hint names the condition that flipped and [lock] jdks.
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(
        stderr.contains("The JDK condition jdk:[21,) flipped on this JDK (21)")
            && stderr.contains("[lock] jdks in raeva.toml"),
        "{stderr}"
    );
    assert!(!stderr.contains("JAVA_VERSION_DEFAULTED"), "{stderr}");

    // Without JAVA_HOME or JAVA_VERSION, a lock that tests the JDK fails
    // the check (exit 3) where the stand-in 17 would pass it.
    let defaulted = project.raeva_with(&[], &["sync", "--frozen"]);
    assert_status(&defaulted, 3, "frozen with the stand-in JDK");
    let stderr = String::from_utf8_lossy(&defaulted.stderr);
    assert!(
        stderr.contains("JAVA_VERSION_DEFAULTED: the POM of org.test:root:1 reads")
            && stderr.contains("the resolution depends on the JDK version"),
        "{stderr}"
    );

    let before_jdks = root.join("before-jdks.lock");
    fs::copy(root.join("raeva.lock"), &before_jdks).unwrap();

    // With [lock] jdks = ["17", "21"], raeva.lock holds one section per JDK
    // and records no jdk: ambient input.
    fs::write(root.join("raeva.toml"), "[lock]\njdks = [\"17\", \"21\"]\n").unwrap();
    let sync_25 = run("25.0.1", &["sync", "--offline"]);
    assert_success(&sync_25, "sync under unlisted JDK warns and resolves list");
    let sync_25_stderr = String::from_utf8_lossy(&sync_25.stderr);
    assert!(
        sync_25_stderr.contains("JDK_NOT_LOCKED") && sync_25_stderr.contains("25.0.1"),
        "{sync_25_stderr}"
    );

    let parsed = lock(&root);
    let platforms = parsed["platforms"].as_array().expect("platforms");
    assert_eq!(platforms.len(), 2, "{parsed}");
    assert!(
        platforms[0]["targets"][0]
            .as_str()
            .unwrap()
            .ends_with("@17")
    );
    assert!(
        platforms[1]["targets"][0]
            .as_str()
            .unwrap()
            .ends_with("@21")
    );
    assert_eq!(section_artifacts(&platforms[0]), ["org.test:lib:1.0"]);
    assert_eq!(
        section_artifacts(&platforms[1]),
        ["org.test:jdk21-only:1.0", "org.test:lib:1.0"]
    );
    assert!(ambient(&root).is_empty(), "{parsed}");

    for jdk in ["17", "17.0.12", "21", "21.0.4_7"] {
        for args in [
            &["sync", "--frozen"][..],
            &["sync", "--frozen", "--offline"],
        ] {
            assert_success(&run(jdk, args), &format!("{args:?} under {jdk}"));
        }
    }

    let frozen_25 = run("25", &["sync", "--frozen"]);
    assert_status(&frozen_25, 7, "frozen under unlisted JDK 25");
    let frozen_25_stderr = String::from_utf8_lossy(&frozen_25.stderr);
    assert!(
        frozen_25_stderr
            .contains("raeva.lock covers the JDKs in [lock] jdks (17, 21), not this JDK (25)"),
        "{frozen_25_stderr}"
    );
    assert!(
        frozen_25_stderr.contains(
            "Run on a listed JDK, or add 25 to [lock] jdks in raeva.toml and run 'raeva sync'"
        ),
        "{frozen_25_stderr}"
    );
    assert!(
        !frozen_25_stderr.contains("to update raeva.lock"),
        "{frozen_25_stderr}"
    );
    // Doctor says so before CI does, on the JDK frozen refuses only.
    let platforms = |jdk: &str| {
        let output = run(jdk, &["--offline", "--json", "doctor"]);
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        let checks = envelope["data"]["checks"].as_array().expect("checks");
        let row = (checks.iter())
            .find(|row| row["check"] == "lock platforms")
            .expect("lock platforms row");
        (
            row["code"].as_str().unwrap_or("-").to_string(),
            row["details"].to_string(),
        )
    };
    let (code, details) = platforms("25");
    assert_eq!(code, "HOST_JDK_NOT_LOCKED", "{details}");
    assert!(
        details.contains(
            "not this JDK (25), so raeva sync --frozen fails here. Run on a listed JDK, or add \
             25 to [lock] jdks"
        ),
        "{details}"
    );
    let (code, details) = platforms("21");
    assert_ne!(code, "HOST_JDK_NOT_LOCKED", "{details}");
    let frozen_patch = run("25.0.1", &["sync", "--frozen"]);
    assert!(
        String::from_utf8_lossy(&frozen_patch.stderr).contains("or add 25 to [lock] jdks"),
        "{}",
        String::from_utf8_lossy(&frozen_patch.stderr)
    );
    // A JDK 8 version names its feature release after `1.`.
    let frozen_8 = run("1.8.0_442", &["sync", "--frozen"]);
    assert!(
        String::from_utf8_lossy(&frozen_8.stderr).contains("or add 1.8 to [lock] jdks"),
        "{}",
        String::from_utf8_lossy(&frozen_8.stderr)
    );

    // tree picks the section matching the host JDK, and warns on fallback.
    let tree_17 = run("17.0.2", &["--json", "tree"]);
    assert_success(&tree_17, "tree under 17");
    let tree_17_json: serde_json::Value = serde_json::from_slice(&tree_17.stdout).unwrap();
    assert_eq!(tree_17_json["data"]["jdk"].as_str(), Some("17"));
    assert!(
        !tree_17_json["data"]["modules"][0]["dependencies"]
            .to_string()
            .contains("jdk21-only"),
        "{tree_17_json}"
    );

    let tree_21 = run("21.0.1", &["--json", "tree"]);
    assert_success(&tree_21, "tree under 21");
    let tree_21_json: serde_json::Value = serde_json::from_slice(&tree_21.stdout).unwrap();
    assert_eq!(tree_21_json["data"]["jdk"].as_str(), Some("21"));
    assert!(
        tree_21_json["data"]["modules"][0]["dependencies"]
            .to_string()
            .contains("jdk21-only"),
        "{tree_21_json}"
    );

    // sbom selects an exact recorded target JDK.
    for (jdk, with_jdk21_only) in [("17.0.2", false), ("21.0.1", true)] {
        let target = jdk.split('.').next().unwrap();
        let sbom = run(jdk, &["sbom", "--jdk", target]);
        assert_success(&sbom, &format!("sbom under {jdk}"));
        let document = String::from_utf8_lossy(&sbom.stdout);
        assert_eq!(
            document.contains("jdk21-only"),
            with_jdk21_only,
            "{document}"
        );
    }

    // lock diff compares each JDK's section on its own.
    let diff = run(
        "17",
        &["--json", "lock", "diff", before_jdks.to_str().unwrap()],
    );
    assert_success(&diff, "lock diff");
    let diff: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    let names = |field: &str| -> Vec<String> {
        diff["data"][field]
            .as_array()
            .expect("platform list")
            .iter()
            .map(|name| name.as_str().unwrap().to_string())
            .collect()
    };
    let added = names("platforms_added");
    assert_eq!(added.len(), 2, "{diff}");
    assert!(
        added[0].ends_with(" (JDK 17)") && added[1].ends_with(" (JDK 21)"),
        "{diff}"
    );
    assert_eq!(names("platforms_removed").len(), 1, "{diff}");
    assert!(!names("platforms_removed")[0].contains("JDK"), "{diff}");

    let tree_25 = run("25", &["tree"]);
    assert_success(&tree_25, "tree fallback under 25");
    let tree_25_stderr = String::from_utf8_lossy(&tree_25.stderr);
    assert!(
        tree_25_stderr.contains("PLATFORM_FALLBACK")
            && tree_25_stderr.contains("(JDK 25)")
            && tree_25_stderr.contains("(JDK 17)"),
        "{tree_25_stderr}"
    );

    // --jdk and --platform pick a recorded target over the host's, and one
    // the lock does not record fails without a fallback.
    let host = rv_lock::Platform::current().unwrap().to_string();
    let other = if host == "windows-aarch64" {
        "linux-x86_64"
    } else {
        "windows-aarch64"
    };
    let tree = run("17.0.2", &["--json", "tree", "--jdk", "21"]);
    assert_success(&tree, "tree --jdk 21 under 17");
    let tree: serde_json::Value = serde_json::from_slice(&tree.stdout).unwrap();
    assert_eq!(tree["data"]["jdk"].as_str(), Some("21"));
    assert!(tree.to_string().contains("jdk21-only"), "{tree}");
    let why = |jdk: &str, flags: &[&str]| {
        let mut args = vec!["why", "org.test:jdk21-only"];
        args.extend_from_slice(flags);
        run(jdk, &args)
    };
    assert_success(
        &why("17", &["--platform", &host, "--jdk", "21"]),
        "why on the selected JDK 21 target",
    );
    assert_status(&why("21", &["--jdk", "17"]), 1, "why on the JDK 17 target");
    for flags in [
        &["--jdk", "25"][..],
        &["--platform", other],
        &["--platform", &host],
    ] {
        for output in [
            run("25", &[&["tree"][..], flags].concat()),
            why("25", flags),
        ] {
            assert_status(&output, 2, &format!("{flags:?}"));
            let stderr = String::from_utf8_lossy(&output.stderr);
            let expected = if flags[0] == "--platform" && flags[1] == host {
                format!("--platform {host} matches 2 recorded targets")
            } else {
                format!("no recorded target matches {} {};", flags[0], flags[1])
            };
            assert!(
                stderr.contains(&expected) && !stderr.contains("PLATFORM_FALLBACK"),
                "{stderr}"
            );
        }
    }
}

/// `export-m2` writes the repository of a build on this machine's JDK, so
/// it refuses one `[lock] jdks` does not list, as `--frozen` does, rather
/// than export a listed JDK's dependencies.
#[test]
fn export_m2_refuses_a_jdk_lock_jdks_does_not_list() {
    let project = Project::synced();
    let root = project.root();
    publish_artifact(&root.join("repository"), "jdk21-only", "1.0", "jar", "");
    fs::write(
        root.join("pom.xml"),
        pom(
            "root",
            "repository/",
            &format!(
                "<dependencies>{LIB}</dependencies>\
                 <profiles><profile><id>jdk21</id><activation><jdk>[21,)</jdk></activation>\
                 <dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>jdk21-only</artifactId><version>1.0</version></dependency>\
                 </dependencies></profile></profiles>"
            ),
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[lock]\njdks = [\"17\"]\n").unwrap();
    let run = |jdk: &str, args: &[&str]| project.raeva_with(&[("JAVA_VERSION", jdk)], args);
    assert_success(&run("17", &["sync", "--offline"]), "sync under 17");
    let m2 = root.join("m2");
    let export = ["--offline", "export-m2", "--m2-path", m2.to_str().unwrap()];
    for args in [&["--offline", "sync", "--frozen"][..], &export] {
        let refused = run("21", args);
        assert_status(&refused, 7, &format!("{args:?} under 21"));
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("raeva.lock covers the JDKs in [lock] jdks (17), not this JDK (21)")
                && stderr.contains("or add 21 to [lock] jdks"),
            "{args:?}: {stderr}"
        );
    }
    let unknown = project.raeva_with(&[], &export);
    assert_status(&unknown, 7, "export without a JDK version");
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains(
            "raeva.lock covers the JDKs in [lock] jdks (17), and the version of this JDK is unknown"
        ),
        "{}",
        String::from_utf8_lossy(&unknown.stderr)
    );
    assert!(!m2.exists());
    // A plan is for any machine.
    let plan = run("21", &["--offline", "export-m2", "--plan-json"]);
    assert_success(&plan, "plan under 21");
    assert_success(&run("17", &export), "export under 17");
    assert!(m2.join("org/test/lib/1.0/lib-1.0.jar").is_file());
}

/// Where neither the JDK nor `JAVA_VERSION` names the version, the stand-in
/// 17 cannot check a lock that reads it for a build, so `export-m2` refuses
/// it as `--frozen` does. The reports of the lock need no JDK and run on a
/// host without Java.
#[test]
fn only_a_build_refuses_a_jdk_condition_on_an_unnamed_jdk() {
    let project = Project::synced();
    let root = project.root();
    publish_artifact(&root.join("repository"), "jdk21-only", "1.0", "jar", "");
    fs::write(
        root.join("pom.xml"),
        pom(
            "root",
            "repository/",
            &format!(
                "<dependencies>{LIB}</dependencies>\
                 <profiles><profile><id>jdk21</id><activation><jdk>[21,)</jdk></activation>\
                 <dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>jdk21-only</artifactId><version>1.0</version></dependency>\
                 </dependencies></profile></profiles>"
            ),
        ),
    )
    .unwrap();
    assert_success(
        &project.raeva_with(JDK_17, &["sync", "--offline"]),
        "sync under 17",
    );
    let m2 = root.join("m2");
    let export = ["--offline", "export-m2", "--m2-path", m2.to_str().unwrap()];
    for args in [&["--offline", "sync", "--frozen"][..], &export] {
        let refused = project.raeva(args);
        assert_status(&refused, 3, &format!("{args:?} without a JDK version"));
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("the resolution depends on the JDK version"),
            "{args:?}: {stderr}"
        );
    }
    assert!(!m2.exists());

    let (osv_url, _osv) = crate::common::spawn_osv(200, r#"{"results":[{"vulns":[]}]}"#);
    let osv = [("RAEVA_OSV_BASE_URL", osv_url.as_str())];
    let reports = [
        (&[][..], &["--offline", "sbom"][..]),
        (&[], &["--offline", "export-checksums"]),
        (&osv, &["vuln"]),
    ]
    .map(|(env, args)| (args, project.raeva_with(env, args)));
    let failed: Vec<String> = (reports.iter())
        .filter(|(_, output)| !output.status.success())
        .map(|(args, output)| {
            let stderr = String::from_utf8_lossy(&output.stderr);
            format!("{args:?} without Java: {}: {stderr}", output.status)
        })
        .collect();
    assert!(failed.is_empty(), "{failed:#?}");
    let sbom = String::from_utf8_lossy(&reports[0].1.stdout);
    assert!(sbom.contains("pkg:maven/org.test/lib@1.0"), "{sbom}");
    assert!(root.join(".mvn/checksums").is_dir());

    assert_success(&project.raeva_with(JDK_17, &export), "export under 17");
}

/// With `[lock] jdks`, `--frozen` checks that the build's JDK is listed. On a
/// host where no JDK names its version, there is nothing to check, so it
/// fails and says where it looked, rather than taking the stand-in 17.
#[test]
fn lock_jdks_frozen_refuses_a_jdk_without_a_version() {
    let project = Project::synced();
    let root = project.root();
    fs::write(
        root.join("pom.xml"),
        pom(
            "root",
            "repository/",
            &format!("<dependencies>{LIB}</dependencies>"),
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[lock]\njdks = [\"17\", \"21\"]\n").unwrap();
    assert_success(
        &project.raeva_with(&[("JAVA_VERSION", "21")], &["sync", "--offline"]),
        "sync under 21",
    );
    let frozen = ["sync", "--frozen", "--offline"];
    assert_success(
        &project.raeva_with(&[("JAVA_VERSION", "21")], &frozen),
        "frozen under 21",
    );

    // No JAVA_HOME, no java on PATH and no JAVA_VERSION.
    let unknown = project.raeva_with(&[], &frozen);
    assert_status(&unknown, 7, "frozen without a JDK version");
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert!(
        stderr.contains("raeva.lock covers the JDKs in [lock] jdks (17, 21), and the version of this JDK is unknown")
            && stderr.contains("JAVA_HOME is unset")
            && stderr.contains("Set JAVA_HOME to the JDK the build uses"),
        "{stderr}"
    );

    // A JAVA_HOME without a release file is named.
    let bare = root.join("bare-jdk");
    fs::create_dir_all(&bare).unwrap();
    let unknown = project.raeva_with(&[("JAVA_HOME", bare.to_str().unwrap())], &frozen);
    assert_status(&unknown, 7, "frozen with a JDK that names no version");
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert!(stderr.contains(bare.to_str().unwrap()), "{stderr}");

    // tree and why take a section for an unknown JDK only with a warning.
    let tree = project.raeva_with(&[], &["tree"]);
    assert_success(&tree, "tree without a JDK version");
    let stderr = String::from_utf8_lossy(&tree.stderr);
    assert!(
        stderr.contains("PLATFORM_FALLBACK") && stderr.contains("(JDK unknown)"),
        "{stderr}"
    );

    // A plain sync resolves the listed JDKs and warns.
    let synced = project.raeva_with(&[], &["sync", "--offline"]);
    assert_success(&synced, "sync without a JDK version");
    let stderr = String::from_utf8_lossy(&synced.stderr);
    assert!(
        stderr.contains("JDK_NOT_LOCKED") && stderr.contains("the version of this JDK is unknown"),
        "{stderr}"
    );
}

/// Each JDK section records the scope each package resolves to there: `x`
/// is test scope below a test dependency on JDK 17 and compile on JDK 21,
/// where a profile adds a compile path to it.
#[test]
fn lock_jdk_sections_record_their_own_package_scopes() {
    let project = Project::synced();
    let root = project.root();
    let repo = root.join("repository");
    let dependency = |artifact: &str, scope: &str| {
        format!(
            "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <version>1.0</version>{scope}</dependency>"
        )
    };
    let on_x = format!("<dependencies>{}</dependencies>", dependency("x", ""));
    publish_artifact(&repo, "x", "1.0", "jar", "");
    publish_artifact(&repo, "t", "1.0", "jar", &on_x);
    publish_artifact(&repo, "a", "1.0", "jar", &on_x);
    let pom_xml = pom(
        "root",
        "repository/",
        &format!(
            "<dependencies>{}</dependencies>\
             <profiles><profile><id>jdk21</id><activation><jdk>[21,)</jdk></activation>\
             <dependencies>{}</dependencies></profile></profiles>",
            dependency("t", "<scope>test</scope>"),
            dependency("a", ""),
        ),
    );
    fs::write(root.join("pom.xml"), &pom_xml).unwrap();
    fs::write(root.join("raeva.toml"), "[lock]\njdks = [\"17\", \"21\"]\n").unwrap();
    let no_java_home = root.join("no-java-home");
    let run = |version: &str, args: &[&str]| {
        project.raeva_with(
            &[
                ("JAVA_HOME", no_java_home.to_str().unwrap()),
                ("JAVA_VERSION", version),
            ],
            args,
        )
    };
    assert_success(&run("17", &["sync", "--offline"]), "sync with [lock] jdks");

    let parsed = lock(&root);
    let packages = |section: usize| {
        parsed["platforms"][section]["modules"][0]["packages"]
            .as_str()
            .expect("packages")
            .to_string()
    };
    assert_eq!(
        packages(0),
        "org.test:t:1.0\tjar\ttest\norg.test:x:1.0\tjar\t\ttest",
        "{parsed}"
    );
    assert_eq!(
        packages(1),
        "org.test:a:1.0\tjar\tcompile\norg.test:t:1.0\tjar\ttest\norg.test:x:1.0\tjar",
        "{parsed}"
    );

    for (jdk, scope) in [("17", "test"), ("21", "compile")] {
        let tree = run(jdk, &["--json", "tree"]);
        assert_success(&tree, &format!("tree under {jdk}"));
        let tree: serde_json::Value = serde_json::from_slice(&tree.stdout).unwrap();
        let x = &tree["data"]["modules"][0]["dependencies"]
            .as_array()
            .expect("dependencies")
            .iter()
            .find(|dependency| dependency["coordinate"] == "org.test:t:1.0:jar")
            .expect("t")["children"][0];
        assert_eq!(x["coordinate"], "org.test:x:1.0:jar", "{tree}");
        assert_eq!(x["scope"], scope, "{tree}");
    }
}

/// A host value that reaches a POM activation through a POM property that
/// names a settings.xml property, by any name interpolation follows, or
/// that settings.xml expands into its own activation, stays out
/// of raeva.lock and out of the `--frozen` message.
#[test]
fn settings_values_from_the_environment_stay_out_of_the_lock_and_messages() {
    for (property, value) in [
        ("<alias>${secret}</alias>", "${alias}"),
        ("<alias>${secret}</alias>", "${project.properties.alias}"),
    ] {
        settings_values_stay_out_of_the_lock_and_messages(property, value);
    }
}

fn settings_values_stay_out_of_the_lock_and_messages(property: &str, value: &str) {
    const SECRET: &str = "canary-secret-7f3a";
    let project = Project::synced();
    let root = project.root();
    let extra = tempfile::TempDir::new().unwrap();
    fs::write(
        project.m2_settings(),
        format!(
            "<settings><profiles>\
             <profile><id>secret</id>\
               <activation><activeByDefault>true</activeByDefault></activation>\
               <properties><secret>${{env.RAEVA_TEST_TOKEN}}</secret></properties>\
             </profile>\
             <profile><id>switch</id>\
               <activation><property><name>env.RAEVA_TEST_SWITCH</name>\
                 <value>${{env.RAEVA_TEST_TOKEN}}</value></property></activation>\
               <repositories><repository><id>switch-repo</id><url>file://{}/</url>\
               </repository></repositories>\
             </profile></profiles></settings>",
            extra.path().display()
        ),
    )
    .unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "root",
            "repository/",
            &format!(
                "<properties>{property}</properties>\
                 <dependencies>{LIB}</dependencies>\
                 <profiles><profile><id>keyed</id><activation><property>\
                 <name>java.version</name><value>{value}</value></property></activation>\
                 <dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>missing</artifactId><version>1</version></dependency>\
                 </dependencies></profile></profiles>"
            ),
        ),
    )
    .unwrap();
    let both = [
        ("JAVA_VERSION", "17"),
        ("RAEVA_TEST_TOKEN", SECRET),
        ("RAEVA_TEST_SWITCH", SECRET),
    ];
    assert_success(&project.raeva_with(&both, &["sync", "--offline"]), "sync");
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!text.contains(SECRET), "{value}: {text}");
    assert!(
        ambient(&root)
            .iter()
            .any(|item| item.starts_with("settings:")),
        "{text}"
    );

    let output = project.raeva_with(
        &[("JAVA_VERSION", "17"), ("RAEVA_TEST_TOKEN", SECRET)],
        &["sync", "--frozen", "--offline"],
    );
    assert_status(&output, 7, "the settings condition flipped");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("${env.RAEVA_TEST_TOKEN}"), "{stderr}");
    assert!(!stderr.contains(SECRET), "{value}: {stderr}");
}

/// A `<file>` path's `${basedir}` is the project directory whatever a
/// settings.xml property of that name says, so the condition is recorded as
/// a project file and changing that property leaves the lock fresh.
#[test]
fn a_settings_basedir_does_not_change_a_file_condition() {
    let project = Project::synced();
    let root = project.root();
    fs::write(
        root.join("pom.xml"),
        pom(
            "root",
            "repository/",
            &format!(
                "<profiles><profile><id>marked</id><activation><file>\
                 <exists>${{project.properties.basedir}}/marker</exists></file></activation>\
                 <dependencies>{LIB}</dependencies></profile></profiles>"
            ),
        ),
    )
    .unwrap();
    fs::write(root.join("marker"), "").unwrap();
    let write_settings = |basedir: &str| {
        fs::write(
            project.m2_settings(),
            format!(
                "<settings><profiles><profile><id>ext</id>\
                 <activation><activeByDefault>true</activeByDefault></activation>\
                 <properties><basedir>{basedir}</basedir></properties>\
                 </profile></profiles></settings>"
            ),
        )
        .unwrap();
    };
    write_settings("unused-one");
    assert_success(&project.raeva(&["sync", "--offline"]), "sync");
    assert_eq!(locked_artifacts(&root), ["org.test:lib:1.0"]);
    assert_eq!(ambient(&root), ["file:marker is true"]);
    write_settings("unused-two");
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "a settings basedir changed",
    );
}

/// A `-D` value in `.mvn/maven.config` hides the settings.xml property of the
/// same name, in interpolation and in property activation, so changing that
/// settings value leaves the lock fresh.
#[test]
fn a_settings_property_that_maven_config_overrides_is_not_an_input() {
    let project = Project::synced();
    let root = project.root();
    fs::write(
        root.join("pom.xml"),
        pom(
            "root",
            "repository/",
            "<dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>${lib.version}</version></dependency></dependencies>\
             <profiles><profile><id>flagged</id><activation><property><name>flag</name>\
             <value>yes</value></property></activation><dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>${lib.version}</version></dependency></dependencies></profile></profiles>",
        ),
    )
    .unwrap();
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join(".mvn/maven.config"),
        "-Dlib.version=1.0\n-Dflag=yes\n",
    )
    .unwrap();
    let write_settings = |version: &str| {
        fs::write(
            project.m2_settings(),
            format!(
                "<settings><profiles><profile><id>ext</id>\
                 <activation><activeByDefault>true</activeByDefault></activation>\
                 <properties><lib.version>{version}</lib.version><flag>{version}</flag>\
                 </properties></profile></profiles></settings>"
            ),
        )
        .unwrap();
    };
    write_settings("2.0");
    assert_success(&project.raeva(&["sync", "--offline"]), "sync");
    assert_eq!(locked_artifacts(&root), ["org.test:lib:1.0"]);
    write_settings("3.0");
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "a shadowed settings property changed",
    );
}

/// A JDK profile that sets the classifier likes or a `<build>` value is an
/// input: recorded without `[lock] jdks`, and resolved once per JDK section
/// with it, where `${project.build.finalName}` takes each JDK's value.
#[test]
fn likes_and_build_profiles_follow_each_lock_jdk() {
    let project = Project::synced();
    let root = project.root();
    let repo = root.join("repository");
    publish_artifact(&repo, "named", "1.0", "jar", "");
    let dir = repo.join("org/test/named/1.0");
    for classifier in ["root-1", "fn21"] {
        let name = format!("named-1.0-{classifier}.jar");
        write_with_sha256(&dir.join(name), classifier.as_bytes());
    }
    let pom_xml = pom(
        "root",
        "repository/",
        "<dependencies><dependency><groupId>org.test</groupId><artifactId>named</artifactId>\
         <version>1.0</version><classifier>${project.build.finalName}</classifier>\
         </dependency></dependencies><profiles>\
         <profile><id>likes</id><activation><jdk>[20,)</jdk></activation><properties>\
         <os.detection.classifierWithLikes>debian</os.detection.classifierWithLikes>\
         </properties></profile>\
         <profile><id>named</id><activation><jdk>[21,)</jdk></activation>\
         <build><finalName>fn21</finalName></build></profile></profiles>",
    );
    fs::write(root.join("pom.xml"), &pom_xml).unwrap();
    let no_java_home = root.join("no-java-home");
    let no_java_home_str = no_java_home.to_str().unwrap();
    let run = |version: &str, args: &[&str]| {
        project.raeva_with(
            &[("JAVA_HOME", no_java_home_str), ("JAVA_VERSION", version)],
            args,
        )
    };
    let classifiers = |section: &toml::Value| {
        section["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .filter_map(|row| row["coordinate"].get("classifier")?.as_str())
            .map(str::to_string)
            .collect::<Vec<_>>()
    };

    assert_success(&run("17", &["sync", "--offline"]), "sync under 17");
    assert_eq!(ambient(&root), ["jdk:[20,) is false", "jdk:[21,) is false"]);
    assert_eq!(classifiers(&lock(&root)["platforms"][0]), ["root-1"]);
    assert_status(
        &run("21", &["sync", "--frozen"]),
        7,
        "frozen under 21 without [lock] jdks",
    );

    fs::write(root.join("raeva.toml"), "[lock]\njdks = [\"17\", \"21\"]\n").unwrap();
    assert_success(&run("17", &["sync", "--offline"]), "sync with [lock] jdks");
    let parsed = lock(&root);
    let platforms = parsed["platforms"].as_array().expect("platforms");
    assert_eq!(platforms.len(), 2, "{parsed}");
    assert_eq!(classifiers(&platforms[0]), ["root-1"]);
    assert_eq!(classifiers(&platforms[1]), ["fn21"]);
    assert!(ambient(&root).is_empty(), "{parsed}");
    for jdk in ["17", "21"] {
        for args in [
            &["sync", "--frozen"][..],
            &["sync", "--frozen", "--offline"],
        ] {
            assert_success(&run(jdk, args), &format!("{args:?} under {jdk}"));
        }
    }
}

/// A classifier that os-maven-plugin's likes suffix makes, and that the
/// repository does not publish, fails as in Maven, with the
/// `-Dos.detected.classifier` override as the hint; the override resolves.
/// The build machine's release is a Debian one, whose ID is the like.
#[test]
fn a_missing_likes_classifier_hints_at_the_override() {
    let like = "debian";
    let project = Project::synced();
    let root = project.root();
    let repo = root.join("repository");
    publish_artifact(&repo, "native", "1.0", "jar", "");
    let dir = repo.join("org/test/native/1.0");
    let name = "native-1.0-linux-x86_64.jar";
    write_with_sha256(&dir.join(name), b"native");
    let pom_xml = |classifier: &str| {
        pom(
            "root",
            "repository/",
            &format!(
                "<properties><os.detection.classifierWithLikes>{like}\
                 </os.detection.classifierWithLikes></properties><dependencies><dependency>\
                 <groupId>org.test</groupId><artifactId>native</artifactId>\
                 <version>1.0</version><classifier>{classifier}</classifier></dependency>\
                 </dependencies>"
            ),
        )
    };
    fs::write(root.join("pom.xml"), pom_xml("${os.detected.classifier}")).unwrap();
    // Only the local repository, in Central's place, so the missing file is
    // not found rather than not downloaded.
    fs::write(
        root.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"central\"\nurl = \"{}\"\n",
            url::Url::from_directory_path(&repo).unwrap()
        ),
    )
    .unwrap();
    let release = [(rv_maven_model::OS_RELEASE_TEST_ENV, "ID=debian\n")];
    let sync = |extra: &[&str]| {
        let mut args = vec!["sync", "--platforms", "linux-x86_64"];
        args.extend(extra);
        project.raeva_with(&release, &args)
    };
    let failed = sync(&[]);
    assert_status(&failed, 5, "the suffixed classifier is missing");
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        stderr.contains(&format!("org.test:native:1.0::linux-x86_64-{like}"))
            && stderr.contains("raeva sync -Dos.detected.classifier=linux-x86_64"),
        "{stderr}"
    );
    assert_success(
        &sync(&["-Dos.detected.classifier=linux-x86_64"]),
        "the override resolves",
    );
    // A classifier that only ends with the like, or holds the detected
    // classifier inside another, gets no hint the override could not fix.
    // One written as the suffixed classifier gets it, as a condition.
    for classifier in [
        format!("custom-{like}"),
        "x-${os.detected.classifier}".to_string(),
    ] {
        fs::write(root.join("pom.xml"), pom_xml(&classifier)).unwrap();
        let failed = sync(&[]);
        assert_status(&failed, 5, &classifier);
        let stderr = String::from_utf8_lossy(&failed.stderr);
        assert!(!stderr.contains("os.detected.classifier="), "{stderr}");
    }
    fs::write(
        root.join("pom.xml"),
        pom_xml(&format!("linux-x86_64-{like}")),
    )
    .unwrap();
    let stderr = String::from_utf8_lossy(&sync(&[]).stderr).into_owned();
    assert!(
        stderr.contains("If the dependency's classifier is ${os.detected.classifier}"),
        "{stderr}"
    );
}

/// os-maven-plugin's classifier likes are an input only of a build that
/// reads `${os.detected.classifier}`: a Linux lock of a project that never
/// reads it records them no more than a macOS one, and a `-D` value for
/// them is no drift. A project that reads it records them.
#[test]
fn classifier_likes_are_recorded_only_when_read() {
    const LIKES: &str = "user-property:os.detection.classifierWithLikes";
    let project = Project::synced();
    let root = project.root();
    let release = [(rv_maven_model::OS_RELEASE_TEST_ENV, "ID=debian\n")];
    let sync = |extra: &[&str]| {
        let mut args = vec!["sync", "--offline", "--platforms", "linux-x86_64"];
        args.extend(extra);
        project.raeva_with(&release, &args)
    };
    let inputs = || fs::read_to_string(root.join("raeva.lock")).expect("read lock");

    assert_success(&sync(&[]), "sync for Linux");
    assert!(!inputs().contains(LIKES), "{}", inputs());
    assert_success(
        &sync(&["--frozen", "-Dos.detection.classifierWithLikes=debian"]),
        "an unread -D value is no drift",
    );

    let pom_path = root.join("pom.xml");
    let original = fs::read_to_string(&pom_path).expect("read pom");
    fs::write(
        &pom_path,
        original.replace(
            "<artifactId>lib</artifactId><version>1.0</version>",
            "<artifactId>lib</artifactId><version>1.0</version>\
             <classifier>${os.detected.classifier}</classifier>",
        ),
    )
    .expect("write pom");
    let dir = root.join("repository/org/test/lib/1.0");
    let name = "lib-1.0-linux-x86_64.jar";
    write_with_sha256(&dir.join(name), b"native");
    assert_success(&sync(&[]), "sync a reader for Linux");
    assert!(inputs().contains(LIKES), "{}", inputs());
    assert_status(
        &sync(&["--frozen", "-Dos.detection.classifierWithLikes=debian"]),
        7,
        "a -D value a reader reads is drift",
    );
}

/// Classifier likes an active settings.xml profile sets are an input only
/// of a build that reads `${os.detected.classifier}`, as a `-D` value for
/// them is.
#[test]
fn settings_classifier_likes_are_recorded_only_when_read() {
    const LIKES: &str = "settings-property:os.detection.classifierWithLikes";
    let project = Project::synced();
    let root = project.root();
    let release = [(rv_maven_model::OS_RELEASE_TEST_ENV, "ID=debian\n")];
    let sync = |extra: &[&str]| {
        let mut args = vec!["sync", "--offline", "--platforms", "linux-x86_64"];
        args.extend(extra);
        project.raeva_with(&release, &args)
    };
    let write_settings = |likes: &str| {
        fs::write(
            project.m2_settings(),
            format!(
                "<settings><profiles><profile><id>likes</id>\
                 <activation><activeByDefault>true</activeByDefault></activation>\
                 <properties><os.detection.classifierWithLikes>{likes}\
                 </os.detection.classifierWithLikes></properties></profile></profiles>\
                 </settings>"
            ),
        )
        .unwrap();
    };
    let inputs = || fs::read_to_string(root.join("raeva.lock")).expect("read lock");

    write_settings("debian");
    assert_success(&sync(&[]), "sync for Linux");
    assert!(!inputs().contains(LIKES), "{}", inputs());
    write_settings("fedora");
    assert_success(&sync(&["--frozen"]), "unread likes are no drift");

    let pom_path = root.join("pom.xml");
    let original = fs::read_to_string(&pom_path).expect("read pom");
    fs::write(
        &pom_path,
        original.replace(
            "<artifactId>lib</artifactId><version>1.0</version>",
            "<artifactId>lib</artifactId><version>1.0</version>\
             <classifier>${os.detected.classifier}</classifier>",
        ),
    )
    .expect("write pom");
    let dir = root.join("repository/org/test/lib/1.0");
    let name = "lib-1.0-linux-x86_64.jar";
    write_with_sha256(&dir.join(name), b"native");
    assert_success(&sync(&[]), "sync a reader for Linux");
    assert!(inputs().contains(LIKES), "{}", inputs());
    write_settings("debian");
    assert_status(&sync(&["--frozen"]), 7, "likes a reader reads are drift");

    // A profile that sets them counts while inactive too: its likes win
    // over a `-D` value once it activates.
    let marker = root.join("marker");
    fs::write(
        project.m2_settings(),
        format!(
            "<settings><profiles><profile><id>likes</id>\
             <activation><file><exists>{}</exists></file></activation>\
             <properties><os.detection.classifierWithLikes>debian\
             </os.detection.classifierWithLikes></properties></profile></profiles>\
             </settings>",
            marker.display()
        ),
    )
    .unwrap();
    let user = "-Dos.detection.classifierWithLikes=fedora";
    assert_success(&sync(&[user]), "sync with the profile inactive");
    fs::write(&marker, "").unwrap();
    assert_status(&sync(&["--frozen", user]), 7, "the profile activates");
}

#[test]
fn explicit_target_jdks_do_not_record_host_reads_from_option_validation() {
    let (project, home) = crate::common::temp_project();
    fs::write(project.path().join("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>app</artifactId><version>1</version></project>").unwrap();
    fs::create_dir_all(project.path().join(".mvn")).unwrap();
    fs::write(
        project.path().join(".mvn/maven.config"),
        "-Dbuild.jdk=${java.version}\n",
    )
    .unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        "[lock]\njdks = [\"17\", \"21\"]\n",
    )
    .unwrap();
    let run = |jdk: &str, args: &[&str]| {
        raeva_command(project.path(), home.path())
            .env("JAVA_HOME", home.path().join("no-jdk"))
            .env("JAVA_VERSION", jdk)
            .args(args)
            .output()
            .unwrap()
    };
    assert_success(
        &run("17", &["sync", "--offline"]),
        "lock explicit target JDKs",
    );
    let before = fs::read(project.path().join("raeva.lock")).unwrap();
    assert_success(
        &run("21", &["sync", "--frozen", "--offline"]),
        "frozen under another host JDK",
    );
    assert_eq!(fs::read(project.path().join("raeva.lock")).unwrap(), before);
    assert!(!ambient(project.path()).contains(&"java.version".to_string()));
}

#[test]
fn interpolated_dependency_activation_values_still_track_the_tested_property() {
    let project = Project::synced();
    let root = project.root();
    let repository = root.join("repository");
    publish_artifact(&repository, "leaf", "1.0", "jar", "");
    publish_artifact(
        &repository,
        "lib",
        "1.0",
        "jar",
        "<profiles><profile><id>flag</id>\
        <activation><property><name>flag</name><value>${expected}</value></property></activation>\
        <dependencies><dependency><groupId>org.test</groupId><artifactId>leaf</artifactId>\
        <version>1.0</version></dependency></dependencies></profile></profiles>",
    );
    fs::remove_file(root.join("raeva.lock")).unwrap();
    let home = tempfile::TempDir::new().unwrap();
    let env = [("RAEVA_HOME", home.path().to_str().unwrap())];
    let run = |args: &[&str]| project.raeva_with(&env, args);
    assert_success(
        &run(&["sync", "--offline", "-Dexpected=yes", "-Dflag=yes"]),
        "activate dependency profile",
    );
    assert!(locked_artifacts(&root).contains(&"org.test:leaf:1.0".to_string()));
    let names = toml_strings(&lock(&root)["resolution"]["ambient_inputs"]);
    assert!(
        names.contains(&"user-property:flag".to_string()),
        "{names:?}"
    );
    assert!(
        names.contains(&"user-property:expected".to_string()),
        "{names:?}"
    );
    assert_success(
        &run(&[
            "sync",
            "--frozen",
            "--offline",
            "-Dexpected=yes",
            "-Dflag=yes",
            "-Dunread=${java.version}",
        ]),
        "ignore unread property expansion",
    );
    assert_status(
        &run(&[
            "sync",
            "--frozen",
            "--offline",
            "-Dexpected=yes",
            "-Dflag=no",
        ]),
        7,
        "changing the tested property is drift",
    );
    assert_success(
        &run(&["sync", "--offline", "-Dexpected=yes", "-Dflag=no"]),
        "deactivate dependency profile",
    );
    assert!(!locked_artifacts(&root).contains(&"org.test:leaf:1.0".to_string()));
}

#[test]
fn a_lookup_nothing_reads_leaves_the_lock() {
    let project = Project::synced();
    let root = project.root();
    let repository = root.join("repository");
    publish_artifact(&repository, "leaf", "1.0", "jar", "");
    publish_artifact(
        &repository,
        "lib",
        "1.0",
        "jar",
        "<profiles><profile><id>selected</id><activation><property>\
         <name>${selector}</name><value>yes</value></property></activation>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>leaf</artifactId>\
         <version>1.0</version></dependency></dependencies></profile></profiles>",
    );
    fs::remove_file(root.join("raeva.lock")).unwrap();
    let args = ["sync", "--offline", "-Dselector=key", "-Dkey=yes"];
    assert_success(&project.raeva(&args), "sync with a lookup");
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(text.contains("user-property-lookup:"), "{text}");
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    let start = pom.find("<dependencies>").unwrap();
    let end = pom.find("</dependencies>").unwrap() + "</dependencies>".len();
    fs::write(root.join("pom.xml"), [&pom[..start], &pom[end..]].concat()).unwrap();
    assert_success(&project.raeva(&args), "sync without a reader");
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!text.contains("user-property-lookup:"), "{text}");
}

/// A lookup raeva.lock records, whose replay reads a variable, does not
/// let a frozen check pass on this process's value where a mavenrc file
/// may set that variable in a way raeva does not read.
#[test]
fn a_lookup_of_a_variable_a_mavenrc_sets_goes_stale() {
    let project = Project::synced();
    let root = project.root();
    let repository = root.join("repository");
    publish_artifact(&repository, "leaf", "1.0", "jar", "");
    publish_artifact(
        &repository,
        "lib",
        "1.0",
        "jar",
        "<profiles><profile><id>selected</id><activation><property>\
         <name>${selector}</name><value>yes</value></property></activation>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>leaf</artifactId>\
         <version>1.0</version></dependency></dependencies></profile></profiles>",
    );
    fs::remove_file(root.join("raeva.lock")).unwrap();
    fs::write(
        project.raeva_home().join("config.toml"),
        "[security]\nallow_env_substitution = [\"RAEVA_KEY\"]\n",
    )
    .unwrap();
    let run_with = |env: &[(&str, &str)], args: &[&str]| {
        let mut args = args.to_vec();
        args.extend(["--offline", "-Dselector=env.RAEVA_KEY"]);
        project.raeva_with(&[&[("RAEVA_KEY", "yes")], env].concat(), &args)
    };
    let run = |args: &[&str]| run_with(&[], args);
    assert_success(&run(&["sync"]), "sync with a lookup");
    assert!(locked_artifacts(&root).contains(&"org.test:leaf:1.0".to_string()));
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(text.contains("user-property-lookup:"), "{text}");
    assert!(
        !text.contains("env:RAEVA_KEY") && !text.contains("env.RAEVA_KEY"),
        "{text}"
    );
    assert_success(&run(&["sync", "--frozen"]), "frozen without a mavenrc");
    let (mavenrc, conditional) = if cfg!(windows) {
        (
            "mavenrc_pre.cmd",
            "if defined RAEVA_COND set RAEVA_KEY=no\r\n",
        )
    } else {
        (
            ".mavenrc",
            "[ -n \"$RAEVA_COND\" ] && export RAEVA_KEY=no\n",
        )
    };
    fs::write(project.home().join(mavenrc), conditional).unwrap();
    assert_success(
        &run(&["sync", "--frozen"]),
        "a mavenrc that keeps the value",
    );
    let output = run_with(&[("RAEVA_COND", "1")], &["sync", "--frozen"]);
    assert_status(&output, 7, "a mavenrc that changes the value");
}

#[test]
fn indirect_dependency_activation_lookups_are_fresh_and_private() {
    for (name, properties, selector) in [
        ("${selector}", "", "private-activation-key"),
        (
            "${alias}",
            "<properties><alias>${selector}</alias></properties>",
            "private-activation-key",
        ),
        (
            "${selector}",
            "<properties><alias>${key}</alias></properties>",
            "${alias}",
        ),
    ] {
        let project = Project::synced();
        let root = project.root();
        let repository = root.join("repository");
        publish_artifact(&repository, "leaf", "1.0", "jar", "");
        publish_artifact(
            &repository,
            "lib",
            "1.0",
            "jar",
            &format!(
                "{properties}<profiles><profile><id>selected</id><activation><property>\
             <name>{name}</name><value>yes</value></property></activation>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>leaf</artifactId>\
             <version>1.0</version></dependency></dependencies></profile></profiles>"
            ),
        );
        fs::remove_file(root.join("raeva.lock")).unwrap();
        let home = tempfile::TempDir::new().unwrap();
        let selector = format!("-Dselector={selector}");
        let run = |args: &[&str]| {
            let mut args = args.to_vec();
            args.extend([selector.as_str(), "-Dkey=private-activation-key"]);
            project.raeva_with(&[("RAEVA_HOME", home.path().to_str().unwrap())], &args)
        };
        assert_success(
            &run(&["sync", "--offline", "-Dprivate-activation-key=yes"]),
            "activate indirect dependency profile",
        );
        assert!(locked_artifacts(&root).contains(&"org.test:leaf:1.0".to_string()));
        let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(text.contains("user-property-lookup:"));
        assert!(!text.contains("private-activation-key"));
        assert_success(
            &run(&[
                "sync",
                "--frozen",
                "--offline",
                "-Dprivate-activation-key=yes",
                "-Dunread=no",
            ]),
            "ignore unrelated property",
        );
        for values in [vec!["-Dprivate-activation-key=no"], Vec::new()] {
            let mut args = vec!["sync", "--frozen", "--offline"];
            args.extend(values);
            assert_status(&run(&args), 7, "indirect lookup change is drift");
        }
        assert_success(
            &run(&["sync", "--offline"]),
            "record absent indirect lookup",
        );
        assert!(!locked_artifacts(&root).contains(&"org.test:leaf:1.0".to_string()));
        assert_status(
            &run(&[
                "sync",
                "--frozen",
                "--offline",
                "-Dprivate-activation-key=yes",
            ]),
            7,
            "adding an absent indirect lookup is drift",
        );
        assert!(
            !fs::read_to_string(root.join("raeva.lock"))
                .unwrap()
                .contains("private-activation-key")
        );
    }
}

/// A dependency model gets `-D` values as system properties, below its own
/// properties: a `-D` of a name it defines changes nothing, and one of a
/// name it leaves undefined does.
#[test]
fn a_dependency_model_property_hides_a_define_of_its_name() {
    let project = Project::synced();
    let root = project.root();
    let repo = root.join("repository");
    publish_artifact(&repo, "leaf", "1.0", "jar", "");
    publish_artifact(&repo, "leaf", "2.0", "jar", "");
    let lib = |properties: &str| {
        publish_artifact(
            &repo,
            "lib",
            "1.0",
            "jar",
            &format!(
                "{properties}<dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>leaf</artifactId><version>${{leaf.version}}</version>\
                 </dependency></dependencies>"
            ),
        );
        fs::remove_file(root.join("raeva.lock")).unwrap();
    };
    lib("<properties><leaf.version>1.0</leaf.version></properties>");
    assert_success(&project.raeva(&["sync", "--offline"]), "lock");
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!text.contains("leaf.version"), "{text}");
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline", "-Dleaf.version=2.0"]),
        "lib's own property wins",
    );
    lib("");
    assert_success(
        &project.raeva(&["sync", "--offline", "-Dleaf.version=1.0"]),
        "lock with the define",
    );
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline", "-Dleaf.version=2.0"]),
        7,
        "the define decides leaf",
    );
}

/// `mid`, a parent of the dependency `lib`, names its version through
/// `parent.version`, which a system property replaces, so a `-D` of it
/// decides whether `lib` resolves.
#[test]
fn a_define_of_a_parent_field_counts_in_a_dependency_model() {
    let project = Project::synced();
    let root = project.root();
    let repo = root.join("repository");
    let write = |artifact: &str, body: &str| {
        let dir = repo.join(format!("org/test/{artifact}/1.0"));
        fs::create_dir_all(&dir).unwrap();
        let pom = format!("<project><modelVersion>4.0.0</modelVersion>{body}</project>");
        let name = format!("{artifact}-1.0.pom");
        write_with_sha256(&dir.join(name), pom.as_bytes());
    };
    write(
        "top",
        "<groupId>org.test</groupId><artifactId>top</artifactId><version>1.0</version>\
         <packaging>pom</packaging>",
    );
    write(
        "mid",
        "<parent><groupId>org.test</groupId><artifactId>top</artifactId>\
         <version>1.0</version></parent><artifactId>mid</artifactId>\
         <version>${parent.version}</version><packaging>pom</packaging>",
    );
    publish_artifact(&repo, "lib", "1.0", "jar", "");
    write(
        "lib",
        "<parent><groupId>org.test</groupId><artifactId>mid</artifactId>\
         <version>1.0</version></parent><artifactId>lib</artifactId><version>1.0</version>",
    );
    fs::remove_file(root.join("raeva.lock")).unwrap();
    let mut args = vec!["sync", "--offline"];
    assert_success(&project.raeva(&args), "lock");
    args.push("--frozen");
    assert_success(&project.raeva(&args), "unchanged");
    args.push("-Dparent.version=2.0");
    assert_status(&project.raeva(&args), 7, "a define of parent.version");
}

#[test]
fn dependency_file_replay_preserves_system_property_precedence() {
    for exists in [true, false] {
        let project = Project::synced();
        let root = project.root();
        let repo = root.join("repository");
        publish_artifact(&repo, "leaf", "1.0", "jar", "");
        let condition = if exists { "exists" } else { "missing" };
        publish_artifact(
            &repo,
            "lib",
            "1.0",
            "jar",
            &format!(
                "<profiles><profile><id>marker</id><activation><file><{condition}>\
             ${{activation.root}}/${{packaging}}</{condition}></file></activation>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>leaf</artifactId>\
             <version>1.0</version></dependency></dependencies></profile></profiles>"
            ),
        );
        fs::remove_file(root.join("raeva.lock")).unwrap();
        let home = tempfile::TempDir::new().unwrap();
        let directory = home.path().join("private-activation-root");
        fs::create_dir(&directory).unwrap();
        let property = format!("-Dactivation.root={}", directory.display());
        let run = |args: &[&str]| {
            let mut args = args.to_vec();
            args.extend([property.as_str(), "-Dpackaging=pom"]);
            project.raeva_with(&[("RAEVA_HOME", home.path().to_str().unwrap())], &args)
        };
        assert_success(
            &run(&["sync", "--offline"]),
            "record dependency packaging path",
        );
        assert_eq!(
            locked_artifacts(&root).contains(&"org.test:leaf:1.0".into()),
            !exists
        );
        assert_success(
            &run(&["sync", "--frozen", "--offline", "-Dunrelated=x"]),
            "unchanged dependency packaging path",
        );
        fs::write(directory.join("jar"), "x").unwrap();
        assert!(!directory.join("pom").exists());
        assert_status(
            &run(&["sync", "--frozen", "--offline"]),
            7,
            "dependency synthetic packaging path changed",
        );
        assert_success(
            &run(&["sync", "--offline"]),
            "record changed dependency packaging path",
        );
        assert_eq!(
            locked_artifacts(&root).contains(&"org.test:leaf:1.0".into()),
            exists
        );
        let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(!text.contains("private-activation-root"));
        fs::remove_file(directory.join("jar")).unwrap();
        assert_status(
            &run(&["sync", "--frozen", "--offline"]),
            7,
            "dependency packaging path disappeared",
        );
    }
}

#[test]
fn local_file_replay_preserves_user_property_precedence() {
    let project = Project::synced();
    let root = project.root();
    let home = tempfile::TempDir::new().unwrap();
    let directory = home.path().join("private-activation-root");
    fs::create_dir(&directory).unwrap();
    let profile = format!(
        "<profiles>{}</profiles>",
        file_profile(
            "marker",
            "${activation.root}/${packaging}",
            &format!("<dependencies>{LIB}</dependencies>")
        )
    );
    fs::write(root.join("pom.xml"), pom("root", "repository/", &profile)).unwrap();
    let property = format!("-Dactivation.root={}", directory.display());
    let run = |args: &[&str]| {
        let mut args = args.to_vec();
        args.extend([property.as_str(), "-Dpackaging=pom"]);
        project.raeva_with(&[("RAEVA_HOME", home.path().to_str().unwrap())], &args)
    };
    assert_success(
        &run(&["sync", "--offline"]),
        "record local user packaging path",
    );
    fs::write(directory.join("jar"), "x").unwrap();
    assert_success(
        &run(&["sync", "--frozen", "--offline"]),
        "local model ignores the synthetic packaging path",
    );
    fs::write(directory.join("pom"), "x").unwrap();
    assert_status(
        &run(&["sync", "--frozen", "--offline"]),
        7,
        "local model uses user packaging",
    );
}

#[test]
fn recursive_external_model_expressions_keep_lookup_names_private() {
    for (nested, dependency) in [(false, false), (true, false), (true, true)] {
        let project = Project::synced();
        let root = project.root();
        publish_artifact(&root.join("repository"), "lib", "2", "jar", "");
        let home = tempfile::TempDir::new().unwrap();
        let expression = if nested { "${selector}" } else { "${alias}" };
        let declarations = format!(
            "<dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>{expression}</version></dependency></dependencies>"
        );
        if dependency {
            publish_artifact(&root.join("repository"), "leaf", "2", "jar", "");
            publish_artifact(
                &root.join("repository"),
                "lib",
                "1.0",
                "jar",
                &declarations.replace(
                    "<artifactId>lib</artifactId>",
                    "<artifactId>leaf</artifactId>",
                ),
            );
            // The new lib 1.0 is another release than the one locked.
            fs::remove_file(root.join("raeva.lock")).unwrap();
        }
        let root_dependencies = if dependency {
            format!("<dependencies>{LIB}</dependencies>")
        } else {
            declarations
        };
        fs::write(
            root.join("pom.xml"),
            pom("root", "repository/", &root_dependencies),
        )
        .unwrap();
        fs::write(project.m2_settings(), "<settings><profiles><profile><id>external</id><activation><activeByDefault>true</activeByDefault></activation><properties><alias>${review-private-key}</alias></properties></profile></profiles></settings>").unwrap();
        let run = |args: &[&str]| {
            let mut args = args.to_vec();
            if nested {
                args.push("-Dselector=${review-private-key}");
            }
            project.raeva_with(&[("RAEVA_HOME", home.path().to_str().unwrap())], &args)
        };
        assert_success(
            &run(&["sync", "--offline", "-Dreview-private-key=2"]),
            "resolve recursive external version",
        );
        let selected = if dependency {
            "org.test:leaf:2"
        } else {
            "org.test:lib:2"
        };
        assert!(locked_artifacts(&root).contains(&selected.into()));
        assert!(
            !fs::read_to_string(root.join("raeva.lock"))
                .unwrap()
                .contains("review-private-key")
        );
        assert_success(
            &run(&[
                "sync",
                "--frozen",
                "--offline",
                "-Dreview-private-key=2",
                "-D2=unread",
                "-Dunrelated=x",
                "-Dpackaging=unread",
            ]),
            "interpolation result is not another lookup",
        );
        assert_status(
            &run(&["sync", "--frozen", "--offline", "-Dreview-private-key=1"]),
            7,
            "recursive version input changed",
        );
        assert_status(
            &run(&["sync", "--frozen", "--offline"]),
            7,
            "recursive version input removed",
        );
    }
}

#[test]
fn activation_comparison_probes_do_not_publish_external_expressions() {
    let project = Project::synced();
    let root = project.root();
    let profiles = format!(
        "<profiles><profile><id>selected</id><activation><property><name>flag</name>\
         <value>${{foo}}</value></property></activation><dependencies>{LIB}</dependencies>\
         </profile></profiles>"
    );
    fs::write(root.join("pom.xml"), pom("root", "repository/", &profiles)).unwrap();
    fs::write(project.m2_settings(), "<settings><profiles><profile><id>external</id><activation><activeByDefault>true</activeByDefault></activation><properties><private-alias>${private-key}</private-alias><private-key>2</private-key></properties></profile></profiles></settings>").unwrap();
    let home = tempfile::TempDir::new().unwrap();
    let run = |args: &[&str]| {
        let mut args = args.to_vec();
        args.extend(["-Dfoo=${private-alias}", "-Dflag=2"]);
        project.raeva_with(&[("RAEVA_HOME", home.path().to_str().unwrap())], &args)
    };
    assert_success(
        &run(&["sync", "--offline"]),
        "activate through external expressions",
    );
    assert!(locked_artifacts(&root).contains(&"org.test:lib:1.0".into()));
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for private in ["private-alias", "private-key", "\\u0000", "\0"] {
        assert!(!text.contains(private), "lock contains {private:?}");
    }
    assert_success(
        &run(&["sync", "--frozen", "--offline", "-Dunread=x"]),
        "ignore unrelated input",
    );
    assert_status(
        &run(&["sync", "--frozen", "--offline", "-Dprivate-key=3"]),
        7,
        "nested external input changed",
    );
}

#[test]
fn recursive_external_activation_values_track_private_overrides() {
    for dependency in [false, true] {
        let project = Project::synced();
        let root = project.root();
        publish_artifact(&root.join("repository"), "leaf", "1.0", "jar", "");
        let expression = if dependency {
            "${selector}"
        } else {
            "${alias}"
        };
        let profiles = format!(
            "<profiles><profile><id>selected</id><activation><property><name>flag</name>\
         <value>{expression}</value></property></activation><dependencies><dependency>\
         <groupId>org.test</groupId><artifactId>leaf</artifactId><version>1.0</version>\
         </dependency></dependencies></profile></profiles>"
        );
        if dependency {
            publish_artifact(&root.join("repository"), "lib", "1.0", "jar", &profiles);
            // The new lib 1.0 is another release than the one locked.
            fs::remove_file(root.join("raeva.lock")).unwrap();
        }
        let declarations = if dependency {
            format!("<dependencies>{LIB}</dependencies>")
        } else {
            profiles
        };
        fs::write(
            root.join("pom.xml"),
            pom("root", "repository/", &declarations),
        )
        .unwrap();
        let home = tempfile::TempDir::new().unwrap();
        fs::write(project.m2_settings(), "<settings><profiles><profile><id>external</id><activation><activeByDefault>true</activeByDefault></activation><properties><alias>${review-private-key}</alias></properties></profile></profiles></settings>").unwrap();
        let run = |args: &[&str]| {
            let mut args = args.to_vec();
            args.push("-Dflag=2");
            if dependency {
                args.push("-Dselector=${review-private-key}");
            }
            project.raeva_with(&[("RAEVA_HOME", home.path().to_str().unwrap())], &args)
        };
        assert_success(
            &run(&["sync", "--offline", "-Dreview-private-key=2"]),
            "activate recursive external value",
        );
        assert!(locked_artifacts(&root).contains(&"org.test:leaf:1.0".into()));
        assert!(
            !fs::read_to_string(root.join("raeva.lock"))
                .unwrap()
                .contains("review-private-key")
        );
        assert_success(
            &run(&[
                "sync",
                "--frozen",
                "--offline",
                "-Dreview-private-key=2",
                "-D2=unread",
                "-Dunrelated=x",
            ]),
            "ignore unrelated activation inputs",
        );
        assert_status(
            &run(&["sync", "--frozen", "--offline", "-Dreview-private-key=1"]),
            7,
            "recursive activation value changed",
        );
        assert_status(
            &run(&["sync", "--frozen", "--offline"]),
            7,
            "recursive activation override removed",
        );
        assert_success(
            &run(&["sync", "--offline"]),
            "record absent recursive activation override",
        );
        assert!(!locked_artifacts(&root).contains(&"org.test:leaf:1.0".into()));
        assert!(
            !fs::read_to_string(root.join("raeva.lock"))
                .unwrap()
                .contains("review-private-key")
        );
        assert_status(
            &run(&["sync", "--frozen", "--offline", "-Dreview-private-key=2"]),
            7,
            "absent recursive override was added",
        );
    }
}

#[test]
fn private_dependency_file_conditions_detect_existence_changes() {
    for (exists, from_env, indirect) in [
        (true, false, false),
        (false, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        let project = Project::synced();
        let root = project.root();
        let repository = root.join("repository");
        publish_artifact(&repository, "leaf", "1.0", "jar", "");
        let condition = if exists { "exists" } else { "missing" };
        let expression = if indirect {
            "${selector}"
        } else if from_env {
            "${env.RAEVA_PRIVATE_MARKER}"
        } else {
            "${activation.path}"
        };
        publish_artifact(
            &repository,
            "lib",
            "1.0",
            "jar",
            &format!(
                "<properties><path>{expression}</path></properties>\
             <profiles><profile><id>private-path</id><activation><file>\
             <{condition}>${{path}}</{condition}></file></activation>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>leaf</artifactId>\
             <version>1.0</version></dependency></dependencies></profile></profiles>"
            ),
        );
        fs::remove_file(root.join("raeva.lock")).unwrap();
        let home = tempfile::TempDir::new().unwrap();
        if from_env {
            fs::write(
                home.path().join("config.toml"),
                "[security]\nallow_env_substitution = ['RAEVA_PRIVATE_MARKER']\n",
            )
            .unwrap();
        }
        let marker = home.path().join("private-marker");
        let name = if indirect {
            "private-path-property"
        } else {
            "activation.path"
        };
        let property = format!("-D{name}={}", marker.display());
        let run = |args: &[&str]| {
            let mut args = args.to_vec();
            if !from_env {
                args.push(property.as_str());
            }
            if indirect {
                args.push("-Dselector=${private-path-property}");
            }
            project.raeva_with(
                &[
                    ("RAEVA_HOME", home.path().to_str().unwrap()),
                    ("RAEVA_PRIVATE_MARKER", marker.to_str().unwrap()),
                ],
                &args,
            )
        };
        let private = || {
            let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
            assert!(!text.contains("private-marker"));
            assert!(!text.contains("private-path-property"));
            assert!(!text.contains(home.path().to_str().unwrap()));
        };
        assert_success(
            &run(&["sync", "--offline"]),
            "record absent private dependency file",
        );
        assert_eq!(
            locked_artifacts(&root).contains(&"org.test:leaf:1.0".to_string()),
            !exists
        );
        private();
        assert_success(
            &run(&["sync", "--frozen", "--offline", "-Dunread=yes"]),
            "unchanged private dependency file",
        );
        fs::write(&marker, "x").unwrap();
        assert_status(
            &run(&["sync", "--frozen", "--offline"]),
            7,
            "private dependency file appearance is drift",
        );
        assert_success(
            &run(&["sync", "--offline"]),
            "record present private dependency file",
        );
        assert_eq!(
            locked_artifacts(&root).contains(&"org.test:leaf:1.0".to_string()),
            exists
        );
        private();
        fs::remove_file(&marker).unwrap();
        assert_status(
            &run(&["sync", "--frozen", "--offline"]),
            7,
            "private dependency file disappearance is drift",
        );
    }
}

#[test]
fn literal_user_property_file_paths_stay_private_and_detect_file_changes() {
    let project = Project::synced();
    let root = project.root();
    let home = tempfile::TempDir::new().unwrap();
    let profile = format!(
        "<profiles>{}</profiles>",
        file_profile(
            "private-path",
            "${activation.path}",
            &format!("<dependencies>{LIB}</dependencies>")
        )
    );
    fs::write(root.join("pom.xml"), pom("root", "repository/", &profile)).unwrap();
    let run = |args: &[&str]| {
        let mut args = args.to_vec();
        args.push("-Dactivation.path=private-file");
        project.raeva_with(&[("RAEVA_HOME", home.path().to_str().unwrap())], &args)
    };
    assert_success(
        &run(&["sync", "--offline"]),
        "record private file condition",
    );
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!text.contains("private-file"));
    assert_success(
        &run(&["sync", "--frozen", "--offline"]),
        "unchanged private file condition",
    );
    fs::write(root.join("private-file"), "x").unwrap();
    assert_status(
        &run(&["sync", "--frozen", "--offline"]),
        7,
        "private file appearance is drift",
    );
    assert_success(
        &run(&["sync", "--offline"]),
        "activate private file condition",
    );
    assert!(
        !fs::read_to_string(root.join("raeva.lock"))
            .unwrap()
            .contains("private-file")
    );
    let moved = root.with_file_name("moved");
    fs::rename(&root, &moved).unwrap();
    // Online: the store recorded the jar as served from the old directory,
    // which is not the project's repository any more, so it is copied again.
    assert_success(
        &raeva_command(&moved, home.path())
            .args(["sync", "--frozen", "-Dactivation.path=private-file"])
            .output()
            .unwrap(),
        "private file recipe survives project relocation",
    );
}

#[test]
fn explicit_target_profile_selections_are_stable_across_host_jdks() {
    for options in [
        "-P${java.specification.version}\n",
        "-Dselected=${java.specification.version}\n-Dunread=${java.version}\n-P${selected}\n",
    ] {
        let (project, home) = crate::common::temp_project();
        crate::offline_project::publish_lib(&project.path().join("repository"));
        let profiles = ["17", "21"]
            .into_iter()
            .map(|id| format!("<profile><id>{id}</id><dependencies>{LIB}</dependencies></profile>"))
            .collect::<String>();
        fs::write(
            project.path().join("pom.xml"),
            pom(
                "root",
                "repository/",
                &format!("<profiles>{profiles}</profiles>"),
            ),
        )
        .unwrap();
        fs::create_dir_all(project.path().join(".mvn")).unwrap();
        fs::write(project.path().join(".mvn/maven.config"), options).unwrap();
        fs::write(
            project.path().join("raeva.toml"),
            "[lock]\njdks = [\"17\", \"21\"]\n",
        )
        .unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        let settings = ["17", "21"].into_iter().map(|id| format!("<profile><id>{id}</id><repositories><repository><id>jdk{id}</id><url>file://{}/repository/</url></repository></repositories></profile>", project.path().display())).collect::<String>();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!("<settings><profiles>{settings}</profiles></settings>"),
        )
        .unwrap();
        let run = |jdk: &str, args: &[&str]| {
            raeva_command(project.path(), home.path())
                .env("JAVA_HOME", home.path().join("no-jdk"))
                .env("JAVA_VERSION", jdk)
                .args(args)
                .output()
                .unwrap()
        };
        assert_success(
            &run("17", &["sync", "--offline", "--platforms", "linux-x86_64"]),
            "lock target profile selections",
        );
        let before = fs::read(project.path().join("raeva.lock")).unwrap();
        assert!(
            !ambient(project.path()).contains(&"java.version".to_string()),
            "{options}"
        );
        assert_success(
            &run(
                "21",
                &[
                    "sync",
                    "--frozen",
                    "--offline",
                    "--platforms",
                    "linux-x86_64",
                ],
            ),
            "check target selections on another host JDK",
        );
        assert_success(
            &run("21", &["sync", "--offline"]),
            "rewrite target selections on another host JDK",
        );
        assert_eq!(
            fs::read(project.path().join("raeva.lock")).unwrap(),
            before,
            "{options}"
        );
        // Each 21.x host's `java.version` is its own, so a `-P` that takes
        // it names a profile raeva cannot know.
        fs::write(
            project.path().join(".mvn/maven.config"),
            "-P${java.version}\n",
        )
        .unwrap();
        let output = run("21", &["sync", "--offline"]);
        assert_eq!(output.status.code(), Some(3), "{options}");
    }
}

#[test]
fn literal_property_vectors_do_not_reuse_target_dependent_dependency_graphs() {
    let project = Project::synced();
    let root = project.root();
    let repository = root.join("repository");
    publish_artifact(&repository, "leaf", "1.0", "jar", "");
    publish_artifact(
        &repository,
        "lib",
        "1.0",
        "jar",
        "<profiles><profile><id>jdk17</id>\
        <activation><property><name>flag</name><value>17</value></property></activation>\
        <dependencies><dependency><groupId>org.test</groupId><artifactId>leaf</artifactId>\
        <version>1.0</version></dependency></dependencies></profile></profiles>",
    );
    fs::remove_file(root.join("raeva.lock")).unwrap();
    fs::create_dir_all(root.join(".mvn")).unwrap();
    let options = root.join(".mvn/maven.config");
    fs::write(&options, "-Dflag=${java.specification.version}\n").unwrap();
    fs::write(root.join("raeva.toml"), "[lock]\njdks = [\"17\", \"21\"]\n").unwrap();
    let home = tempfile::TempDir::new().unwrap();
    let env = [
        ("RAEVA_HOME", home.path().to_str().unwrap()),
        ("JAVA_VERSION", "21"),
    ];
    let run = |args: &[&str]| project.raeva_with(&env, args);
    let frozen = [
        "sync",
        "--frozen",
        "--offline",
        "--platforms",
        "linux-x86_64",
    ];
    assert_success(
        &run(&["sync", "--offline", "--platforms", "linux-x86_64"]),
        "lock different dependency graphs per JDK",
    );
    let before = fs::read(root.join("raeva.lock")).unwrap();
    let literal =
        serde_json::to_string(&(0..6).flat_map(|_| ["17", "21"]).collect::<Vec<_>>()).unwrap();
    fs::write(&options, format!("-Dflag={literal}\n")).unwrap();
    assert_status(
        &run(&frozen),
        7,
        "a literal vector differs from target-dependent values",
    );
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), before);
    fs::write(&options, "-Dflag=${java.specification.version}\n").unwrap();
    assert_success(&run(&frozen), "unchanged target-dependent values");
}

/// Maven pastes `${user.home}` and `${project.basedir}` into a `file:` URL
/// as they are, and its file transporter reads a `#` or `?` there as part
/// of the directory name, where a URL parser starts a fragment or query.
/// raeva refuses such a URL, naming the character, and reads the escaped
/// spelling as Maven does.
#[test]
fn a_hash_or_question_mark_in_a_file_url_is_refused() {
    // Windows refuses `?` in a file name.
    let names: &[(&str, &str)] = if cfg!(windows) {
        &[("c#dev", "%23")]
    } else {
        &[("c#dev", "%23"), ("c?dev", "%3F")]
    };
    for (name, escaped) in names {
        let found = &name[1..2];
        let base = tempfile::TempDir::new().unwrap();
        let home = base.path().join(name);
        let project = base.path().join("project");
        publish(&home.join("m2"), "org.example:lib:1.0", "");
        publish(&project.join("repo"), "org.example:other:1.0", "");
        let settings = |url: &str| {
            fs::create_dir_all(home.join(".m2")).unwrap();
            fs::write(
                home.join(".m2/settings.xml"),
                format!(
                    "<settings><mirrors><mirror><id>local</id><mirrorOf>central</mirrorOf>\
                     <url>{url}</url></mirror></mirrors></settings>"
                ),
            )
            .unwrap();
        };
        let write_pom = |repo: &str| {
            fs::write(
                project.join("pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>root</artifactId><version>1</version><repositories>\
                     <repository><id>here</id><url>{repo}</url></repository></repositories>\
                     <dependencies><dependency><groupId>org.example</groupId>\
                     <artifactId>lib</artifactId><version>1.0</version></dependency>\
                     <dependency><groupId>org.example</groupId><artifactId>other</artifactId>\
                     <version>1.0</version></dependency></dependencies></project>"
                ),
            )
            .unwrap();
        };
        let refused = |what: &str| {
            let output = run_raeva(&project, &home, &["sync"]);
            assert_status(&output, 3, what);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(&format!("has '{found}' in it, which Maven")),
                "{what}: {stderr}"
            );
        };
        settings("file://${user.home}/m2/");
        write_pom("file://${project.basedir}/repo/");
        refused(&format!("{name} in user.home"));

        let home_url = url::Url::from_directory_path(&home).unwrap();
        let escaped_home = home_url.as_str().replace(found, escaped);
        settings(&format!("{escaped_home}m2/"));
        assert_success(&run_raeva(&project, &home, &["sync"]), escaped);

        let in_project = project.join(name);
        publish(&in_project, "org.example:other:1.0", "");
        write_pom(&format!("file://${{project.basedir}}/{name}/"));
        refused(&format!("{name} in a POM repository"));
        let escaped_dir = name.replace(found, escaped);
        write_pom(&format!("file://${{project.basedir}}/{escaped_dir}/"));
        assert_success(&run_raeva(&project, &home, &["sync"]), &escaped_dir);
        let fresh = base.path().join("fresh");
        let restored = raeva_command(&project, &home)
            .env("RAEVA_HOME", &fresh)
            .args(["sync", "--frozen"])
            .output()
            .unwrap();
        assert_success(
            &restored,
            &format!("{escaped_dir}: restore into an empty store"),
        );
    }
}

/// A `<file>` path a symlink in the project leads out of it is not
/// tracked, as any path outside the project: one with a `..` after the
/// symlink, and one through a dangling symlink.
#[cfg(unix)]
#[test]
fn a_file_condition_a_symlink_leads_out_of_the_project_is_not_tracked() {
    let outside = tempfile::TempDir::new().unwrap();
    let dependencies = format!("<dependencies>{LIB}</dependencies>");
    let profiles = format!(
        "<profiles>{}{}</profiles>",
        file_profile(
            "climbed",
            "${project.basedir}/link/nonexistent/..",
            &dependencies
        ),
        file_profile("dangling", "${project.basedir}/sdk-marker", &dependencies),
    );
    let project = Project::with(&[("pom.xml", &pom("root", "repository/", &profiles))]);
    let root = project.root();
    std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("marker"), root.join("sdk-marker")).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync");
    assert!(ambient(&root).is_empty(), "{:?}", ambient(&root));
}

/// `raeva doctor` warns `HOST_JDK_JAVA4SHELL`, without failing, for a JDK
/// of 17.0.6 or later dated before the 2026-11-17 update on a CPU with
/// AVX-512 VBMI, and says nothing on a CPU without it.
#[test]
fn doctor_warns_of_java4shell_for_an_exposed_jdk_and_cpu() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    crate::common::write_empty_pom(&project.path().join("pom.xml"));
    let jdk = home.path().join("jdk-21");
    fs::create_dir_all(&jdk).unwrap();
    fs::write(
        jdk.join("release"),
        "JAVA_VERSION=\"21.0.9\"\nJAVA_VERSION_DATE=\"2026-10-21\"\n",
    )
    .unwrap();
    let doctor_with = |vbmi: &str, maven_opts: &str| {
        let mut command = raeva_command(project.path(), home.path());
        crate::common::isolate_maven_user_home(&mut command, home.path(), maven_opts);
        let output = command
            .env("JAVA_HOME", &jdk)
            .env(rv_maven_model::AVX512_VBMI_TEST_ENV, vbmi)
            .args(["--offline", "--json", "doctor"])
            .output()
            .expect("run raeva");
        assert_success(&output, "doctor");
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        let checks = envelope["data"]["checks"]
            .as_array()
            .expect("checks")
            .clone();
        checks.into_iter().find(|row| row["check"] == "JDK")
    };
    let doctor = |vbmi: &str| doctor_with(vbmi, "");
    let row = doctor("1").expect("JDK row");
    assert_eq!(row["status"], "warn", "{row}");
    assert_eq!(row["code"], "HOST_JDK_JAVA4SHELL", "{row}");
    let details = row["details"].as_str().unwrap();
    assert!(details.contains("CVE-2026-114938"), "{details}");
    assert!(details.contains("-XX:-UseBASE64Intrinsics"), "{details}");
    assert_eq!(doctor("0"), None);

    // The remedy the row names makes it `info`, from either place, unless
    // MAVEN_OPTS, which `mvn` passes last, turns the intrinsic back on.
    let remedy = "-Xmx1g -XX:-UseBASE64Intrinsics";
    let row = doctor_with("1", remedy).expect("JDK row");
    assert_eq!(row["status"], "info", "{row}");
    assert_eq!(row["code"], "HOST_JDK_JAVA4SHELL", "{row}");
    let details = row["details"].as_str().unwrap();
    assert!(
        details.contains("in MAVEN_OPTS turns the intrinsic off"),
        "{details}"
    );
    fs::create_dir_all(project.path().join(".mvn")).unwrap();
    fs::write(
        project.path().join(".mvn/jvm.config"),
        "-Xmx1g\n-XX:UseAVX=2\n",
    )
    .unwrap();
    let row = doctor("1").expect("JDK row");
    assert_eq!(row["status"], "info", "{row}");
    let details = row["details"].as_str().unwrap();
    assert!(
        details.contains("-XX:UseAVX=2 in .mvn/jvm.config"),
        "{details}"
    );
    let row = doctor_with("1", "-XX:UseAVX=3").expect("JDK row");
    assert_eq!(row["status"], "warn", "{row}");
    assert_eq!(doctor("0"), None);
    // HotSpot reads `_JAVA_OPTIONS` after the command line.
    let output = raeva_command(project.path(), home.path())
        .env("JAVA_HOME", &jdk)
        .env(rv_maven_model::AVX512_VBMI_TEST_ENV, "1")
        .env("_JAVA_OPTIONS", "-XX:UseAVX=3")
        .args(["--offline", "--json", "doctor"])
        .output()
        .expect("run raeva");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let checks = envelope["data"]["checks"].as_array().expect("checks");
    let row = checks
        .iter()
        .find(|row| row["check"] == "JDK")
        .expect("JDK row");
    assert_eq!(row["status"], "warn", "{row}");
}

/// A dependency's POM whose `toggle` profile adds an optional dependency
/// with a version that interpolates to nothing fails Maven's validation
/// there, and Maven 3.9.12 and 3.10.0 then drop its dependencies. Switching
/// the profile either way makes plain sync resolve again, and the frozen
/// check of the result passes.
#[test]
fn a_profile_that_empties_a_declaration_of_a_dependency_is_an_input() {
    let optional = "<dependency><groupId>org.test</groupId><artifactId>c</artifactId>\
                    <version>${empty}</version><optional>true</optional></dependency>";
    let profile = |properties: &str, dependencies: &str| {
        format!(
            "<profiles><profile><id>toggled</id><activation><property><name>toggle</name>\
             <value>on</value></property></activation><properties>{properties}</properties>\
             <dependencies>{dependencies}</dependencies></profile></profiles>"
        )
    };
    let b = "<dependency><groupId>org.test</groupId><artifactId>b</artifactId>\
             <version>1</version></dependency>";
    // The declaration in the profile, and one outside it whose version the
    // profile empties.
    for (properties, dependencies, profiles) in [
        ("<empty/>", b.to_string(), profile("", optional)),
        (
            "<v>1</v>",
            format!("{b}{}", optional.replace("${empty}", "${v}")),
            profile("<v/>", ""),
        ),
    ] {
        for maven in ["3.9", "3.10"] {
            let temp = tempfile::TempDir::new().expect("project");
            let root = temp.path();
            let repo = root.join("repo");
            publish_artifact(
                &repo,
                "a",
                "1",
                "jar",
                &format!(
                    "<properties>{properties}</properties><dependencies>{dependencies}\
                     </dependencies>{profiles}"
                ),
            );
            publish_artifact(&repo, "b", "1", "jar", "");
            let a = "<dependencies><dependency><groupId>org.test</groupId>\
                     <artifactId>a</artifactId><version>1</version></dependency></dependencies>";
            fs::write(root.join("pom.xml"), pom("app", "repo", a)).expect("pom");
            fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{maven}\"\n"),
            )
            .expect("raeva.toml");
            let home = tempfile::TempDir::new().expect("home");
            let case = format!("{properties} {maven}");
            let sync = |args: &[&str]| {
                let output = run_raeva(root, home.path(), &[&["sync"], args].concat());
                assert_success(&output, &format!("{case} {args:?}"));
            };
            let has_b = || locked_artifacts(root).iter().any(|row| row.contains(":b:"));
            sync(&[]);
            assert!(has_b(), "{case}");
            sync(&["-Dtoggle=on"]);
            assert!(!has_b(), "{case}: toggle=on keeps b");
            sync(&["--frozen", "-Dtoggle=on"]);
            sync(&["-Dtoggle=off"]);
            assert!(has_b(), "{case}: toggle=off drops b");
            sync(&["--frozen", "-Dtoggle=off"]);
        }
    }
}

/// A user property that holds the project directory, as `.mvn/maven.config`
/// writes it with `${project.basedir}` or a launcher directory name, or a
/// settings.xml profile does, ties neither raeva.lock nor its hash to the
/// checkout: a copy of the project at another path passes `--frozen` and a
/// fresh sync there writes the same lock. The directory a value names
/// still counts relative to the project, so a change there is drift.
#[test]
fn a_project_directory_in_a_user_property_is_recorded_relative() {
    const SYSTEM: &str = "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>\
         <version>1</version><scope>system</scope><systemPath>${vendor.dir}/a.jar</systemPath>\
         </dependency></dependencies>";
    let project_pom = |extra: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version>{extra}</project>"
        )
    };
    let reactor = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                   <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                   <modules><module>m</module></modules></project>";
    let module = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
                  <artifactId>root</artifactId><version>1</version></parent><artifactId>m</artifactId>\
                  <dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>\
                  <version>1</version><scope>system</scope><systemPath>${vendor.dir}/a.jar\
                  </systemPath></dependency></dependencies></project>";
    let by_url = project_pom(
        "<repositories><repository><id>local</id><url>${local.repo}</url></repository>\
         </repositories><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>",
    );
    let settings_property = "<settings><profiles><profile><id>vendor</id><activation>\
         <activeByDefault>true</activeByDefault></activation><properties>\
         <vendor.dir>${project.basedir}/lib</vendor.dir></properties></profile></profiles>\
         </settings>";
    let maven_310 = "[lock]\nmaven = \"3.10\"\n";
    let system = project_pom(SYSTEM);
    let launched = |directory: &str| project_pom(&SYSTEM.replace("${vendor.dir}", directory));
    let (by_launcher, by_variable) = (
        launched("${maven.multiModuleProjectDirectory}/lib"),
        launched("${env.MAVEN_PROJECTBASEDIR}/lib"),
    );
    let by_property = project_pom(
        "<repositories><repository><id>project-local</id>\
         <url>file://${project.basedir}/repository/</url></repository></repositories>\
         <profiles><profile><id>flagged</id><activation><property><name>${selector}</name>\
         </property></activation><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>\
         </profile></profiles>",
    );
    type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], Option<&'a str>);
    let cases: [Case<'_>; 14] = [
        (
            "basedir",
            &[
                (".mvn/maven.config", "-Dvendor.dir=${project.basedir}/lib\n"),
                ("pom.xml", &system),
                ("lib/a.jar", "jar"),
            ],
            None,
        ),
        (
            "session root",
            &[
                (
                    ".mvn/maven.config",
                    "-Dvendor.dir=${session.rootDirectory}/lib\n",
                ),
                ("pom.xml", &system),
                ("lib/a.jar", "jar"),
            ],
            None,
        ),
        (
            "launcher root",
            &[
                (
                    ".mvn/maven.config",
                    "-Dvendor.dir=${maven.multiModuleProjectDirectory}/lib\n",
                ),
                ("pom.xml", &system),
                ("lib/a.jar", "jar"),
            ],
            None,
        ),
        (
            "3.10 root directory",
            &[
                (
                    ".mvn/maven.config",
                    "-Dvendor.dir=${project.rootDirectory}/lib\n",
                ),
                ("raeva.toml", maven_310),
                ("pom.xml", &system),
                ("lib/a.jar", "jar"),
            ],
            None,
        ),
        (
            "module basedir",
            &[
                (".mvn/maven.config", "-Dvendor.dir=${project.basedir}/lib\n"),
                ("pom.xml", reactor),
                ("m/pom.xml", module),
                ("m/lib/a.jar", "jar"),
            ],
            None,
        ),
        (
            "base URI",
            &[
                (
                    ".mvn/maven.config",
                    "-Dlocal.repo=${project.baseUri}repository/\n",
                ),
                ("pom.xml", &by_url),
            ],
            None,
        ),
        (
            "settings property",
            &[("pom.xml", &system), ("lib/a.jar", "jar")],
            Some(settings_property),
        ),
        (
            "profile selection",
            &[
                (
                    ".mvn/maven.config",
                    "-Dvendor.dir=${project.basedir}/lib\n-P!x-${session.topDirectory}\n",
                ),
                ("pom.xml", &system),
                ("lib/a.jar", "jar"),
            ],
            None,
        ),
        (
            "3.10 jvm.config",
            &[
                (
                    ".mvn/jvm.config",
                    "-Dvendor.dir=${MAVEN_PROJECTBASEDIR}/lib\n",
                ),
                ("raeva.toml", maven_310),
                ("pom.xml", &system),
                ("lib/a.jar", "jar"),
            ],
            None,
        ),
        (
            "3.10 jvm.config variable",
            &[
                (
                    ".mvn/jvm.config",
                    "-Dvendor.dir=$MAVEN_PROJECTBASEDIR/lib\n",
                ),
                ("raeva.toml", maven_310),
                ("pom.xml", &system),
                ("lib/a.jar", "jar"),
            ],
            None,
        ),
        (
            // Maven 3.9's model reads the variable `mvn` exports.
            "3.9 jvm.config",
            &[
                (
                    ".mvn/jvm.config",
                    "-Dvendor.dir=${MAVEN_PROJECTBASEDIR}/lib\n",
                ),
                ("pom.xml", &system),
                ("lib/a.jar", "jar"),
            ],
            None,
        ),
        (
            "model launcher root",
            &[
                (".mvn/maven.config", ""),
                ("pom.xml", &by_launcher),
                ("lib/a.jar", "jar"),
            ],
            None,
        ),
        (
            "model launcher variable",
            &[("pom.xml", &by_variable), ("lib/a.jar", "jar")],
            None,
        ),
        (
            "property activation",
            &[
                (
                    ".mvn/maven.config",
                    "-Dselector=flag\n-Dflag=${session.topDirectory}\n",
                ),
                ("pom.xml", &by_property),
            ],
            None,
        ),
    ];
    for (case, files, settings) in cases {
        let project = Project::with(files);
        if let Some(settings) = settings {
            fs::write(project.m2_settings(), settings).unwrap();
        }
        assert_success(&project.raeva(&["sync", "--offline"]), case);
        let root = project.root();
        let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(!locked.contains(root.to_str().unwrap()), "{case}: {locked}");
        // A space in the new path is percent-encoded in `${project.baseUri}`.
        // `mvn` splits `.mvn/jvm.config` at it, after it writes the path in.
        let elsewhere = match case.contains("jvm.config") {
            true => "other-place/checkout",
            false => "other place/checkout",
        };
        let copy = root.parent().unwrap().join(elsewhere);
        copy_tree(&root, &copy);
        let raeva = |args: &[&str]| {
            raeva_command(&copy, project.home())
                .args(args)
                .output()
                .unwrap()
        };
        assert_success(&raeva(&["sync", "--frozen", "--offline"]), case);
        fs::remove_file(copy.join("raeva.lock")).unwrap();
        assert_success(&raeva(&["sync", "--offline"]), case);
        assert_eq!(
            fs::read_to_string(copy.join("raeva.lock")).unwrap(),
            locked,
            "{case}"
        );
    }

    // In a module that gains a `.mvn` directory, `${project.rootDirectory}`
    // is the module's own directory, so the same text names another file.
    let project = Project::with(&[
        (
            ".mvn/maven.config",
            "-Dvendor.dir=${project.rootDirectory}/lib\n",
        ),
        ("raeva.toml", maven_310),
        ("pom.xml", reactor),
        ("m/pom.xml", module),
        ("lib/a.jar", "jar"),
        ("m/lib/a.jar", "jar"),
    ]);
    assert_success(&project.raeva(&["sync", "--offline"]), "root directory");
    let copy = project.root().parent().unwrap().join("copy");
    copy_tree(&project.root(), &copy);
    let frozen = || {
        raeva_command(&copy, project.home())
            .args(["sync", "--frozen", "--offline"])
            .output()
            .unwrap()
    };
    assert_success(&frozen(), "root directory in a copy");
    fs::create_dir_all(copy.join("m/.mvn")).unwrap();
    assert_status(&frozen(), 7, "the module is its own root directory");
}

/// With the `.mvn` directory above the project, `mvn`'s
/// `${maven.multiModuleProjectDirectory}` is that directory, which the lock
/// hash records as the project's parent, so a copy of the tree passes
/// `--frozen`.
#[test]
fn a_launcher_directory_above_the_project_is_recorded_relative() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>project-local</id><url>file://${project.basedir}/repository/</url>\
               </repository></repositories><profiles><profile><id>flagged</id><activation>\
               <property><name>${selector}</name></property></activation><dependencies>\
               <dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
               <version>1.0</version></dependency></dependencies></profile></profiles>\
               </project>";
    let project = Project::with(&[(".mvn/jvm.config", ""), ("proj/pom.xml", pom)]);
    let root = project.root();
    copy_tree(&root.join("repository"), &root.join("proj/repository"));
    let args = [
        "sync",
        "--offline",
        "-Dselector=flag",
        "-Dflag=${maven.multiModuleProjectDirectory}/x",
    ];
    let sync = |tree: &Path, extra: &[&str]| {
        raeva_command(&tree.join("proj"), project.home())
            .args(args)
            .args(extra)
            .output()
            .unwrap()
    };
    assert_success(&sync(&root, &[]), "launcher above");
    let locked = fs::read_to_string(root.join("proj/raeva.lock")).unwrap();
    assert!(locked.contains("org.test:lib"), "{locked}");
    let copy = root.parent().unwrap().join("elsewhere/tree");
    copy_tree(&root, &copy);
    assert_success(&sync(&copy, &["--frozen"]), "launcher above in a copy");
}

/// A `-D` value that names the project in another letter case is another
/// value to a dependency's profile, even where the file system takes both
/// spellings for one directory, so a plain sync resolves again.
#[test]
fn a_user_property_naming_the_project_in_another_case_is_another_value() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>project-local</id><url>file://${project.basedir}/repository/</url>\
               </repository></repositories><dependencies><dependency><groupId>org.test\
               </groupId><artifactId>a</artifactId><version>1</version></dependency>\
               </dependencies></project>";
    let project = Project::with(&[("pom.xml", pom)]);
    let root = fs::canonicalize(project.root()).unwrap();
    let root = root.to_string_lossy().into_owned();
    project.publish(
        "org.test:a:1",
        &format!(
            "<profiles><profile><id>flagged</id><activation><property><name>flag</name>\
             <value>{root}</value></property></activation><dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>\
             </dependency></dependencies></profile></profiles>"
        ),
    );
    let locks_lib = |flag: &str| {
        let output = project.raeva(&["sync", "--offline", &format!("-Dflag={flag}")]);
        assert_success(&output, flag);
        fs::read_to_string(project.root().join("raeva.lock"))
            .unwrap()
            .contains("org.test:lib")
    };
    assert!(locks_lib(&root));
    let (at, letter) = (root.char_indices().rev())
        .find(|(_, c)| c.is_lowercase() != c.is_uppercase())
        .unwrap();
    let flipped: String = match letter.is_lowercase() {
        true => letter.to_uppercase().collect(),
        false => letter.to_lowercase().collect(),
    };
    let other = format!(
        "{}{flipped}{}",
        &root[..at],
        &root[at + letter.len_utf8()..]
    );
    assert!(!locks_lib(&other), "{other}");
}

/// `MAVEN_BASEDIR` names the project in another letter case: where the
/// file system takes both for one directory, the lock hash records it as
/// the project, so a copy passes `--frozen`; elsewhere it is another
/// directory, whose path is recorded as it is.
#[test]
fn a_launcher_directory_in_another_case_is_the_project_where_names_fold() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>project-local</id><url>file://${project.basedir}/repository/</url>\
               </repository></repositories><profiles><profile><id>flagged</id><activation>\
               <property><name>${selector}</name></property></activation><dependencies>\
               <dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
               <version>1.0</version></dependency></dependencies></profile></profiles>\
               </project>";
    let project = Project::with(&[("pom.xml", pom)]);
    let root = project.root();
    let copy = root.parent().unwrap().join("elsewhere/Checkout");
    copy_tree(&root, &copy);
    let upper = |dir: &Path| {
        let name = dir.file_name().unwrap().to_string_lossy().to_uppercase();
        dir.with_file_name(name)
    };
    let sync = |tree: &Path, extra: &[&str]| {
        raeva_command(tree, project.home())
            .env("MAVEN_BASEDIR", upper(tree))
            .args([
                "sync",
                "--offline",
                "-Dselector=flag",
                "-Dflag=${maven.multiModuleProjectDirectory}/x",
            ])
            .args(extra)
            .output()
            .unwrap()
    };
    assert_success(&sync(&root, &[]), "MAVEN_BASEDIR in capitals");
    fs::copy(root.join("raeva.lock"), copy.join("raeva.lock")).unwrap();
    let frozen = sync(&copy, &["--frozen"]);
    match upper(&copy).exists() {
        true => assert_success(&frozen, "a folding file system"),
        false => assert_status(&frozen, 7, "a file system that keeps case"),
    }
}

/// `mvn` reads `.mvn/maven.config`, `.mvn/jvm.config` and the wrapper's
/// properties in its project directory: `MAVEN_BASEDIR`, else the nearest
/// directory up from the one it runs in that holds `.mvn`. Maven 3.9.12 and
/// 3.10.0 take lib 2.0 there from a `-Dlibver=2.0` in `maven.config`, or a
/// `-Dflag` in `jvm.config` that turns on a profile setting it, and raeva
/// does too. The files are inputs of the lock: a copy of the project
/// without them, or of a project into a tree with them, fails `--frozen`.
#[test]
fn the_mvn_directory_of_the_launcher_is_read() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><properties><libver>1.0\
               </libver></properties><repositories><repository><id>project-local</id>\
               <url>file://${project.basedir}/repository/</url></repository></repositories>\
               <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
               <version>${libver}</version></dependency></dependencies><profiles><profile>\
               <id>p</id><activation><property><name>flag</name></property></activation>\
               <properties><libver>2.0</libver></properties></profile></profiles></project>";
    let project = Project::with(&[("proj/pom.xml", pom)]);
    project.publish("org.test:lib:2.0", "");
    let root = project.root();
    copy_tree(&root.join("repository"), &root.join("proj/repository"));
    let sync = |dir: &Path, env: &[(&str, &Path)], extra: &[&str]| {
        let mut command = raeva_command(dir, project.home());
        for (name, value) in env {
            command.env(name, value);
        }
        command
            .args(["sync", "--offline"])
            .args(extra)
            .output()
            .unwrap()
    };
    let locked = |dir: &Path| fs::read_to_string(dir.join("raeva.lock")).unwrap();
    let proj = root.join("proj");
    let alone = root.parent().unwrap().join("alone");
    let other = root.parent().unwrap().join("other");
    fs::create_dir_all(other.join(".mvn")).unwrap();
    fs::write(other.join(".mvn/maven.config"), "-Dlibver=2.0\n").unwrap();
    for (file, text, env) in [
        ("maven.config", "-Dlibver=2.0\n", None),
        ("jvm.config", "-Dflag=on\n", None),
        ("", "", Some(&other)),
    ] {
        let _ = fs::remove_dir_all(root.join(".mvn"));
        if !file.is_empty() {
            fs::create_dir_all(root.join(".mvn")).unwrap();
            fs::write(root.join(".mvn").join(file), text).unwrap();
        }
        let env: Vec<(&str, &Path)> = env
            .map(|dir| ("MAVEN_BASEDIR", dir.as_path()))
            .into_iter()
            .collect();
        let what = format!("{file} {env:?}");
        let _ = fs::remove_file(proj.join("raeva.lock"));
        assert_success(&sync(&proj, &env, &[]), &what);
        assert!(
            locked(&proj).contains("org.test:lib:2.0"),
            "{what}: {}",
            locked(&proj)
        );
        assert_success(&sync(&proj, &env, &["--frozen"]), &what);
        let _ = fs::remove_dir_all(&alone);
        copy_tree(&proj, &alone);
        if env.is_empty() {
            assert_status(
                &sync(&alone, &env, &["--frozen"]),
                7,
                &format!("{what} alone"),
            );
        }
    }
    // The other way: a project locked alone, then copied under `.mvn`.
    let _ = fs::remove_dir_all(root.join(".mvn"));
    let _ = fs::remove_dir_all(&alone);
    copy_tree(&proj, &alone);
    fs::remove_file(alone.join("raeva.lock")).unwrap();
    assert_success(&sync(&alone, &[], &[]), "alone");
    assert!(locked(&alone).contains("org.test:lib:1.0"));
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/maven.config"), "-Dlibver=2.0\n").unwrap();
    fs::copy(alone.join("raeva.lock"), proj.join("raeva.lock")).unwrap();
    assert_status(
        &sync(&proj, &[], &["--frozen"]),
        7,
        "a lock from alone under .mvn",
    );
    // The wrapper there selects the Maven line.
    fs::create_dir_all(root.join(".mvn/wrapper")).unwrap();
    fs::write(
        root.join(".mvn/wrapper/maven-wrapper.properties"),
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/\
         apache-maven/3.10.0/apache-maven-3.10.0-bin.zip\n",
    )
    .unwrap();
    fs::remove_file(proj.join("raeva.lock")).unwrap();
    assert_success(&sync(&proj, &[], &[]), "wrapper above");
    assert!(
        locked(&proj).contains("maven = \"3.10\""),
        "{}",
        locked(&proj)
    );
}

/// `mvn` searches for `.mvn` from the directory it runs in as the shell
/// names it, so through a symbolic link, a `.mvn` beside the link counts:
/// Maven 3.9.12 and 3.10.0 read `${maven.multiModuleProjectDirectory}` as
/// the link's parent there, and lib 2.0 from its repository, which the
/// link's target lacks.
/// `MavenCli` finds `${session.rootDirectory}` on the canonical path
/// instead, and fails the build without a `.mvn` there, as raeva does.
#[cfg(unix)]
#[test]
fn the_launcher_searches_up_the_path_it_was_given() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>r</id><url>file://${maven.multiModuleProjectDirectory}/repository/</url>\
               </repository></repositories><dependencies><dependency><groupId>org.test\
               </groupId><artifactId>lib</artifactId><version>2.0</version>\
               </dependency></dependencies></project>";
    let project = Project::with(&[("b/proj/pom.xml", pom), ("a/.mvn/jvm.config", "")]);
    let root = project.root();
    crate::common::publish(&root.join("a/repository"), "org.test:lib:2.0", "");
    copy_tree(&root.join("repository"), &root.join("b/proj/repository"));
    std::os::unix::fs::symlink(root.join("b/proj"), root.join("a/proj")).unwrap();
    let output = raeva_command(&root.join("a/proj"), project.home())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&output, "through the link");
    let lock = fs::read_to_string(root.join("b/proj/raeva.lock")).unwrap();
    assert!(lock.contains("org.test:lib:2.0"), "{lock}");
    // The launcher reads `a/.mvn/maven.config`, but `b/proj` has no `.mvn`
    // above it.
    fs::write(
        root.join("a/.mvn/maven.config"),
        "-Dr=${session.rootDirectory}\n",
    )
    .unwrap();
    let rooted = || {
        raeva_command(&root.join("a/proj"), project.home())
            .args(["sync", "--offline"])
            .output()
            .unwrap()
    };
    let output = rooted();
    assert_status(&output, 3, "no .mvn on the canonical path");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("session.rootDirectory"), "{stderr}");
    fs::create_dir_all(root.join("b/.mvn")).unwrap();
    assert_success(&rooted(), "a .mvn on the canonical path");
}

/// `mvn` passes `maven.multiModuleProjectDirectory` as a system property,
/// which Maven 3.9.12 and 3.10.0 expand in settings.xml: a repository of the
/// project's own `.mvn/settings.xml` there serves lib 1.0, and a copy of the
/// tree passes `--frozen`.
#[test]
fn settings_expand_the_launchers_directory() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><dependencies><dependency>\
               <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>\
               </dependency></dependencies></project>";
    let settings = "<settings><profiles><profile><id>d</id><repositories><repository>\
                    <id>prj</id><url>file://${maven.multiModuleProjectDirectory}/repository/\
                    </url></repository></repositories></profile></profiles><activeProfiles>\
                    <activeProfile>d</activeProfile></activeProfiles></settings>";
    let project = Project::with(&[("pom.xml", pom), (".mvn/settings.xml", settings)]);
    let sync = |dir: &Path, extra: &[&str]| {
        raeva_command(dir, project.home())
            .current_dir(dir)
            .args(["sync", "--offline", "-s", ".mvn/settings.xml"])
            .args(extra)
            .output()
            .unwrap()
    };
    let root = project.root();
    assert_success(&sync(&root, &[]), "settings repository");
    let copy = root.parent().unwrap().join("elsewhere/tree");
    copy_tree(&root, &copy);
    assert_success(&sync(&copy, &["--frozen"]), "a copy");
}

/// A `file://` URL of the project directory in a `-D` value names the same
/// directory as `${project.baseUri}` does, percent-encoded or not, so a
/// copy of the tree under a path with a space or a non-ASCII letter passes
/// `--frozen`, and the other way, as Maven 3.9.12 and 3.10.0 build both.
#[test]
fn a_file_url_of_the_project_is_portable_in_any_spelling() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>prj</id><url>${repo}</url></repository></repositories><dependencies>\
               <dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
               <version>1.0</version></dependency></dependencies></project>";
    let project = Project::with(&[("pom.xml", pom)]);
    let base = project.root().parent().unwrap().to_path_buf();
    let sync = |dir: &Path, extra: &[&str]| {
        raeva_command(dir, project.home())
            .args([
                "sync",
                "--offline",
                "-Drepo=file://${project.basedir}/repository/",
            ])
            .args(extra)
            .output()
            .unwrap()
    };
    for (from, to) in [("plain", "sp ace"), ("sp ace", "plain"), ("plain", "é")] {
        let (from, to) = (base.join(from).join("proj"), base.join(to).join("proj"));
        for dir in [&from, &to] {
            let _ = fs::remove_dir_all(dir);
        }
        copy_tree(&project.root(), &from);
        assert_success(&sync(&from, &[]), &format!("{}", from.display()));
        copy_tree(&from, &to);
        assert_success(&sync(&to, &["--frozen"]), &format!("{}", to.display()));
    }
}

/// Two users with the same settings.xml, whose repository is
/// `file://${user.home}/corp/`, and the project at the same place under
/// each home: the lock one writes passes the other's `--frozen`, as both
/// build it with Maven.
#[test]
fn a_repository_under_the_user_home_is_portable_between_users() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><dependencies><dependency>\
               <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>\
               </dependency></dependencies></project>";
    let settings = "<settings><profiles><profile><id>d</id><repositories><repository>\
                    <id>corp</id><url>file://${user.home}/corp/</url></repository>\
                    </repositories></profile></profiles><activeProfiles><activeProfile>d\
                    </activeProfile></activeProfiles></settings>";
    let base = tempfile::tempdir().unwrap();
    let homes = [base.path().join("ha/u"), base.path().join("hb/v")];
    for home in &homes {
        crate::offline_project::publish_lib(&home.join("corp"));
        fs::create_dir_all(home.join(".m2")).unwrap();
        fs::write(home.join(".m2/settings.xml"), settings).unwrap();
    }
    let project = |home: &Path| home.join("work/proj");
    fs::create_dir_all(project(&homes[0])).unwrap();
    fs::write(project(&homes[0]).join("pom.xml"), pom).unwrap();
    let sync = |home: &Path, extra: &[&str]| {
        raeva_command(&project(home), home)
            .args(["sync", "--offline"])
            .args(extra)
            .output()
            .unwrap()
    };
    assert_success(&sync(&homes[0], &[]), "user a");
    copy_tree(&project(&homes[0]), &project(&homes[1]));
    assert_success(&sync(&homes[1], &["--frozen"]), "user b");
}

/// A dependency's profile that compares `flag` with the checkout's path,
/// `-Dflag=${session.rootDirectory}`: the lock hash reads the directory as a
/// marker, so a copy keeps it, but Maven 3.9.12 there drops lib 1.0. A
/// plain sync in the copy resolves again and `export-m2` refuses the lock,
/// as `--frozen` does, while a plain sync where the lock was written keeps
/// it without resolving.
#[test]
fn a_plain_sync_in_a_copy_resolves_what_frozen_refuses() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>prj</id><url>file://${project.basedir}/repository/</url></repository>\
               </repositories><dependencies><dependency><groupId>org.test</groupId>\
               <artifactId>a</artifactId><version>1</version><type>pom</type></dependency>\
               </dependencies></project>";
    let project = Project::with(&[
        ("pom.xml", pom),
        (".mvn/maven.config", "-Dflag=${session.rootDirectory}\n"),
    ]);
    let root = dunce::canonicalize(project.root()).unwrap();
    project.publish(
        "org.test:a:1",
        &format!(
            "<packaging>pom</packaging><profiles><profile><id>p</id><activation><property>\
             <name>flag</name><value>{}</value></property></activation><dependencies>\
             <dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>1.0</version></dependency></dependencies></profile></profiles>",
            root.display()
        ),
    );
    let sync = |dir: &Path, extra: &[&str]| {
        raeva_command(dir, project.home())
            .args(["sync", "--offline"])
            .args(extra)
            .output()
            .unwrap()
    };
    let resolved = |output: &std::process::Output| {
        String::from_utf8_lossy(&output.stderr).contains("Resolving dependencies")
    };
    let locked = |dir: &Path| fs::read_to_string(dir.join("raeva.lock")).unwrap();
    assert_success(&sync(&root, &[]), "at a");
    assert!(locked(&root).contains("org.test:lib"), "{}", locked(&root));
    let again = sync(&root, &[]);
    assert_success(&again, "at a again");
    assert!(
        !resolved(&again),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let copy = root.parent().unwrap().join("b/proj");
    copy_tree(&root, &copy);
    assert_status(&sync(&copy, &["--frozen"]), 7, "the copy, frozen");
    let export = raeva_command(&copy, project.home())
        .args(["export-m2", "--offline", "--dry-run"])
        .output()
        .unwrap();
    assert_status(&export, 7, "the copy, exported");
    let plain = sync(&copy, &[]);
    assert_success(&plain, "the copy");
    assert!(
        resolved(&plain),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );
    assert!(!locked(&copy).contains("org.test:lib"), "{}", locked(&copy));
}

/// The markers hide only where the checkout is: a copy whose `.mvn` sits
/// at another level above the project, or whose `.mvn/maven.config` reads
/// otherwise, fails `--frozen` and a plain sync there resolves again, with
/// the home that wrote the lock. A project whose values name no host
/// directory keeps its lock on a fresh home without resolving.
#[test]
fn the_markers_keep_a_change_in_the_layout_or_the_bytes() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>project-local</id><url>file://${project.basedir}/repository/</url>\
               </repository></repositories><profiles><profile><id>flagged</id><activation>\
               <property><name>${selector}</name></property></activation><dependencies>\
               <dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
               <version>1.0</version></dependency></dependencies></profile></profiles>\
               </project>";
    let config = "-Dselector=flag\n-Dflag=${maven.multiModuleProjectDirectory}/x\n";
    let project = Project::with(&[("t/.mvn/maven.config", config), ("t/proj/pom.xml", pom)]);
    let root = project.root();
    copy_tree(&root.join("repository"), &root.join("t/proj/repository"));
    let sync = |dir: &Path, home: &Path, extra: &[&str]| {
        raeva_command(dir, home)
            .args(["sync", "--offline"])
            .args(extra)
            .output()
            .unwrap()
    };
    let resolved = |output: &std::process::Output| {
        String::from_utf8_lossy(&output.stderr).contains("Resolving dependencies")
    };
    let home = project.home();
    assert_success(&sync(&root.join("t/proj"), home, &[]), "written");
    let base = root.parent().unwrap();
    let deeper = base.join("deeper");
    copy_tree(&root.join("t/.mvn"), &deeper.join(".mvn"));
    copy_tree(&root.join("t/proj"), &deeper.join("t/proj"));
    let reads = base.join("reads");
    copy_tree(&root.join("t"), &reads);
    fs::write(reads.join(".mvn/maven.config"), config.replace("/x", "/y")).unwrap();
    for proj in [deeper.join("t/proj"), reads.join("proj")] {
        let what = proj.display().to_string();
        assert_status(&sync(&proj, home, &["--frozen"]), 7, &what);
        let plain = sync(&proj, home, &[]);
        assert_success(&plain, &what);
        assert!(
            resolved(&plain),
            "{what}: {}",
            String::from_utf8_lossy(&plain.stderr)
        );
    }
    let plain = Project::synced();
    let fresh = tempfile::tempdir().unwrap();
    let output = sync(&plain.root(), fresh.path(), &[]);
    assert_success(&output, "a fresh home");
    assert!(
        !resolved(&output),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Maven 3.10.0's `${project.rootDirectory}` is the nearest directory from
/// the project up that holds `.mvn`, above the directory `mvn` runs in
/// too, else the launcher's `maven.multiModuleProjectDirectory`, which
/// `MAVEN_BASEDIR` sets: there both serve lib 2.0 from `t/repository`.
#[test]
fn maven_310_finds_the_root_directory_above_the_project() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>r</id><url>file://${project.rootDirectory}/repository/</url></repository>\
               </repositories><dependencies><dependency><groupId>org.test</groupId>\
               <artifactId>lib</artifactId><version>2.0</version></dependency>\
               </dependencies></project>";
    let project = Project::with(&[
        ("t/proj/pom.xml", pom),
        ("t/proj/raeva.toml", "[lock]\nmaven = \"3.10\"\n"),
    ]);
    let root = project.root();
    crate::common::publish(&root.join("t/repository"), "org.test:lib:2.0", "");
    let proj = root.join("t/proj");
    let sync = |env: &[(&str, &Path)]| {
        let _ = fs::remove_file(proj.join("raeva.lock"));
        let mut command = raeva_command(&proj, project.home());
        for (name, value) in env {
            command.env(name, value);
        }
        command.args(["sync", "--offline"]).output().unwrap()
    };
    let t = root.join("t");
    assert_status(&sync(&[]), 5, "no .mvn: the project's own repository");
    assert_success(&sync(&[("MAVEN_BASEDIR", &t)]), "MAVEN_BASEDIR");
    fs::create_dir(t.join(".mvn")).unwrap();
    assert_success(&sync(&[]), ".mvn above");
    let lock = fs::read_to_string(proj.join("raeva.lock")).unwrap();
    assert!(lock.contains("org.test:lib:2.0"), "{lock}");
}

/// Doctor reads `.mvn/maven.config` where `mvn` does, above the project
/// too, and names the options raeva does not take from it.
#[test]
fn doctor_reads_the_launchers_maven_config() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version></project>";
    let project = Project::with(&[("t/.mvn/maven.config", "-pl\nx\n"), ("t/proj/pom.xml", pom)]);
    let output = raeva_command(&project.root().join("t/proj"), project.home())
        .args(["doctor", "--offline"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("raeva ignores -pl"), "{stdout}");
}

/// Through a link to a directory above the project, `mvn` names the
/// launcher's directory by the link, as `/tmp` is one to `/private/tmp` on
/// macOS: a repository there is recorded where the link leads, relative to
/// the project, so a copy of the tree passes `--frozen`.
#[cfg(unix)]
#[test]
fn a_repository_named_through_a_link_is_recorded_relative() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>r</id><url>file://${maven.multiModuleProjectDirectory}/repo/</url>\
               </repository></repositories><dependencies><dependency><groupId>org.test\
               </groupId><artifactId>lib</artifactId><version>1.0</version></dependency>\
               </dependencies></project>";
    let project = Project::with(&[("real/t/.mvn/jvm.config", ""), ("real/t/proj/pom.xml", pom)]);
    let root = project.root();
    copy_tree(&root.join("repository"), &root.join("real/t/repo"));
    std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
    let sync = |dir: &Path, extra: &[&str]| {
        raeva_command(dir, project.home())
            .args(["sync", "--offline"])
            .args(extra)
            .output()
            .unwrap()
    };
    assert_success(&sync(&root.join("link/t/proj"), &[]), "through the link");
    let lock = fs::read_to_string(root.join("real/t/proj/raeva.lock")).unwrap();
    assert!(lock.contains("repo_url = \"../repo/\""), "{lock}");
    let copy = root.parent().unwrap().join("elsewhere/t");
    copy_tree(&root.join("real/t"), &copy);
    assert_success(&sync(&copy.join("proj"), &["--frozen"]), "a copy");
}

/// `export-checksums` writes into the `.mvn` that `mvn` reads, above the
/// project too: one made in the project would move `mvn`'s project
/// directory there, away from the `.mvn/maven.config` the lock read.
#[test]
fn checksums_go_to_the_launchers_mvn_directory() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>project-local</id><url>file://${project.basedir}/repository/</url>\
               </repository></repositories><dependencies><dependency><groupId>org.test\
               </groupId><artifactId>lib</artifactId><version>1.0</version></dependency>\
               </dependencies></project>";
    let project = Project::with(&[("t/.mvn/maven.config", "-Dx=1\n"), ("t/proj/pom.xml", pom)]);
    let root = project.root();
    copy_tree(&root.join("repository"), &root.join("t/proj/repository"));
    let run = |args: &[&str]| {
        raeva_command(&root.join("t/proj"), project.home())
            .args(args)
            .output()
            .unwrap()
    };
    assert_success(&run(&["sync", "--offline"]), "sync");
    assert_success(&run(&["export-checksums", "--offline"]), "export");
    assert!(root.join("t/.mvn/checksums/checksums.sha256").is_file());
    assert!(!root.join("t/proj/.mvn").exists());
}

/// A frozen check of one platform in a copy vouches for that platform
/// only: where only Windows reads the checkout's path, a plain sync and an
/// export still resolve the Windows platform again after
/// `--frozen --platforms linux-x86_64` passed. A sync of the one platform
/// it checked keeps the lock.
#[test]
fn a_check_of_one_platform_does_not_vouch_for_another() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>prj</id><url>file://${project.basedir}/repository/</url></repository>\
               </repositories><dependencies><dependency><groupId>org.test</groupId>\
               <artifactId>a</artifactId><version>1</version><type>pom</type></dependency>\
               </dependencies></project>";
    let project = Project::with(&[
        ("pom.xml", pom),
        (".mvn/maven.config", "-Dflag=${session.rootDirectory}\n"),
    ]);
    let root = dunce::canonicalize(project.root()).unwrap();
    project.publish(
        "org.test:a:1",
        &format!(
            "<packaging>pom</packaging><profiles><profile><id>p</id><activation><os>\
             <family>windows</family></os><property><name>flag</name><value>{}</value>\
             </property></activation><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>\
             </profile></profiles>",
            root.display()
        ),
    );
    let raeva = |dir: &Path, args: &[&str]| {
        raeva_command(dir, project.home())
            .arg("--offline")
            .args(args)
            .output()
            .unwrap()
    };
    let platforms = "linux-x86_64,windows-x86_64";
    assert_success(&raeva(&root, &["sync", "--platforms", platforms]), "at a");
    let copy = root.parent().unwrap().join("b/proj");
    copy_tree(&root, &copy);
    let linux = ["sync", "--frozen", "--platforms", "linux-x86_64"];
    assert_success(&raeva(&copy, &linux), "linux, frozen");
    let export = raeva(&copy, &["export-m2", "--plan-json"]);
    assert_status(&export, 7, "the copy, exported");
    let plain = raeva(&copy, &["sync", "--platforms", platforms]);
    assert_success(&plain, "the copy");
    let stderr = String::from_utf8_lossy(&plain.stderr);
    assert!(stderr.contains("Resolving dependencies"), "{stderr}");
    let lock = fs::read_to_string(copy.join("raeva.lock")).unwrap();
    assert!(!lock.contains("org.test:lib"), "{lock}");
    // A sync of one platform, once checked, keeps that one again.
    let fresh = tempfile::tempdir().unwrap();
    let linux = || {
        raeva_command(&copy, fresh.path())
            .args(["--offline", "sync", "--platforms", "linux-x86_64"])
            .output()
            .unwrap()
    };
    assert_success(&linux(), "linux on a fresh home");
    let again = linux();
    assert_success(&again, "linux again");
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(!stderr.contains("Resolving dependencies"), "{stderr}");
}

/// `mvn` passes a relative `MAVEN_BASEDIR` on as written and reads `.mvn`
/// under it from the directory it runs in, which raeva does not model, so
/// it refuses one.
#[test]
fn a_relative_maven_basedir_is_refused() {
    let project = Project::synced();
    let output = project.raeva_with(&[("MAVEN_BASEDIR", "..")], &["sync", "--offline"]);
    assert_status(&output, 3, "relative MAVEN_BASEDIR");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MAVEN_BASEDIR"), "{stderr}");
    let root = project.root();
    let absolute = root.to_str().unwrap();
    let output = project.raeva_with(&[("MAVEN_BASEDIR", absolute)], &["sync", "--offline"]);
    assert_success(&output, "absolute MAVEN_BASEDIR");
}

/// A `file://` URL that names the original checkout by its path is no
/// marker in a copy, and a settings.xml repository at another place under
/// the user home is another input: each fails `--frozen` and a plain sync
/// resolves again.
#[test]
fn the_url_markers_keep_another_directory() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><repositories><repository>\
               <id>prj</id><url>${repo}</url></repository></repositories><dependencies>\
               <dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
               <version>1.0</version></dependency></dependencies></project>";
    let project = Project::with(&[("proj/pom.xml", pom)]);
    let base = project.root();
    copy_tree(&base.join("repository"), &base.join("proj/repository"));
    let proj = dunce::canonicalize(base.join("proj")).unwrap();
    let url = url::Url::from_directory_path(&proj).unwrap();
    let literal = format!("-Drepo={url}repository/");
    let sync = |dir: &Path, home: &Path, extra: &[&str]| {
        raeva_command(dir, home)
            .args(["sync", "--offline"])
            .args(extra)
            .output()
            .unwrap()
    };
    let resolved = |output: &std::process::Output| {
        String::from_utf8_lossy(&output.stderr).contains("Resolving dependencies")
    };
    let home = project.home();
    assert_success(&sync(&proj, home, &[&literal]), "a literal URL");
    let copy = base.join("copy");
    copy_tree(&proj, &copy);
    assert_status(&sync(&copy, home, &["--frozen", &literal]), 7, "the copy");
    let plain = sync(&copy, home, &[&literal]);
    assert_success(&plain, "the copy, plain");
    assert!(
        resolved(&plain),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );

    let settings = |tail: &str| {
        format!(
            "<settings><profiles><profile><id>d</id><repositories><repository><id>corp\
             </id><url>file://${{user.home}}/{tail}/</url></repository></repositories>\
             </profile></profiles><activeProfiles><activeProfile>d</activeProfile>\
             </activeProfiles></settings>"
        )
    };
    let homes = tempfile::tempdir().unwrap();
    let (a, b) = (homes.path().join("a"), homes.path().join("b"));
    for (home, tail) in [(&a, "corp"), (&b, "other")] {
        crate::offline_project::publish_lib(&home.join(tail));
        fs::create_dir_all(home.join(".m2")).unwrap();
        fs::write(home.join(".m2/settings.xml"), settings(tail)).unwrap();
        fs::create_dir_all(home.join("work/proj")).unwrap();
    }
    let lib = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>root</artifactId><version>1</version><dependencies><dependency>\
               <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>\
               </dependency></dependencies></project>";
    fs::write(a.join("work/proj/pom.xml"), lib).unwrap();
    assert_success(&sync(&a.join("work/proj"), &a, &[]), "user a");
    copy_tree(&a.join("work/proj"), &b.join("work/proj"));
    assert_status(&sync(&b.join("work/proj"), &b, &["--frozen"]), 7, "user b");
    let plain = sync(&b.join("work/proj"), &b, &[]);
    assert_success(&plain, "user b, plain");
    assert!(
        resolved(&plain),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );
}

/// `mvn` exports `MAVEN_PROJECTBASEDIR`, its project directory, and
/// `MAVEN_CMD_LINE_ARGS`, its own arguments, to Maven's JVM whether or not
/// the shell set them, so a profile of the POM or of settings.xml that
/// tests the first is on, as in Maven 3.9.12 and 3.10.0, whatever the
/// allowlist, and a profile that tests the second, which raeva cannot know,
/// fails the sync (exit 3) in both Maven modes.
#[test]
fn a_variable_mvn_sets_reads_as_mvn_sets_it() {
    let base = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let root = base.path();
    let repository = root.join("repository");
    for coordinate in ["org.test:lib:1.0", "org.test:lib:2.0", "org.test:extra:1.0"] {
        publish(&repository, coordinate, "");
    }
    let tested = |name: &str| {
        format!(
            "<profiles><profile><id>p</id><activation><property><name>{name}</name></property>\
             </activation><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>extra</artifactId><version>1.0</version></dependency></dependencies>\
             </profile></profiles>"
        )
    };
    let pom = |profiles: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version>\
             <properties><lib.version>1.0</lib.version></properties>\
             <repositories><repository><id>project-local</id>\
             <url>file://${{project.basedir}}/repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>${{lib.version}}</version></dependency></dependencies>{profiles}</project>"
        )
    };
    let sync = || {
        let _ = fs::remove_file(root.join("raeva.lock"));
        raeva_command(root, home.path())
            .args(["sync", "--offline"])
            .output()
            .expect("run raeva sync")
    };
    let locked = || {
        let mut found: Vec<String> = (lock(root)["platforms"][0]["artifacts"].as_array())
            .expect("artifacts")
            .iter()
            .map(|row| {
                let coordinate = &row["coordinate"];
                format!(
                    "{}:{}",
                    coordinate["artifact"].as_str().expect("artifact"),
                    coordinate["version"].as_str().expect("version")
                )
            })
            .collect();
        found.sort();
        found
    };
    for mode in ["3.9", "3.10"] {
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .unwrap();
        fs::write(
            root.join("pom.xml"),
            pom(&tested("env.MAVEN_PROJECTBASEDIR")),
        )
        .unwrap();
        assert_success(&sync(), mode);
        assert_eq!(locked(), ["extra:1.0", "lib:1.0"], "{mode}");

        fs::write(
            root.join("pom.xml"),
            pom(&tested("env.MAVEN_CMD_LINE_ARGS")),
        )
        .unwrap();
        let refused = sync();
        assert_status(&refused, 3, mode);
        let said = String::from_utf8_lossy(&refused.stderr);
        assert!(
            said.contains("mvn sets MAVEN_CMD_LINE_ARGS itself"),
            "{mode}: {said}"
        );

        fs::write(root.join("pom.xml"), pom("")).unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            "<settings><profiles><profile><id>s</id><activation><property>\
             <name>env.MAVEN_PROJECTBASEDIR</name></property></activation><properties>\
             <lib.version>2.0</lib.version></properties></profile></profiles></settings>",
        )
        .unwrap();
        assert_success(&sync(), mode);
        assert_eq!(locked(), ["lib:2.0"], "{mode}");
        fs::remove_file(home.path().join(".m2/settings.xml")).unwrap();
    }
}

/// On Windows Maven 3.9.12 and 3.10.0 hold each variable as `env.NAME`
/// in upper case (`EnvironmentUtils`), so a POM reads `Raeva_Case` as
/// `${env.RAEVA_CASE}` and as the condition `env.RAEVA_CASE`, and
/// `env.Raeva_Case` as unset, as measured with `Path`. The allowlist and
/// the refusal of a hidden variable take the upper-case name too.
#[cfg(windows)]
#[test]
fn a_windows_variable_reads_by_its_upper_case_name() {
    let base = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let root = base.path();
    let repository = root.join("repository");
    for coordinate in [
        "org.test:lib:1.0",
        "org.test:lib:2.0",
        "org.test:extra:1.0",
        "org.test:other:1.0",
    ] {
        publish(&repository, coordinate, "");
    }
    let profile = |name: &str, artifact: &str| {
        format!(
            "<profile><id>{artifact}</id><activation><property><name>{name}</name></property>\
             </activation><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1.0</version></dependency>\
             </dependencies></profile>"
        )
    };
    fs::write(
        root.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version>\
             <repositories><repository><id>project-local</id>\
             <url>file://${{project.basedir}}/repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>${{env.RAEVA_CASE_VERSION}}</version></dependency></dependencies>\
             <profiles>{}{}</profiles></project>",
            profile("env.RAEVA_CASE", "extra"),
            profile("env.Raeva_Case", "other"),
        ),
    )
    .unwrap();
    let sync = || {
        raeva_command(root, home.path())
            .env("Raeva_Case", "on")
            .env("Raeva_Case_Version", "2.0")
            .args(["sync", "--offline"])
            .output()
            .expect("run raeva sync")
    };
    let refused = sync();
    assert_status(&refused, 3, "hidden");
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(said.contains("RAEVA_CASE"), "{said}");
    fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_env_substitution = [\"RAEVA_CASE\", \"RAEVA_CASE_VERSION\"]\n",
    )
    .unwrap();
    assert_success(&sync(), "allowed");
    let mut found: Vec<String> = (lock(root)["platforms"][0]["artifacts"].as_array())
        .expect("artifacts")
        .iter()
        .map(|row| {
            let coordinate = &row["coordinate"];
            format!(
                "{}:{}",
                coordinate["artifact"].as_str().expect("artifact"),
                coordinate["version"].as_str().expect("version")
            )
        })
        .collect();
    found.sort();
    assert_eq!(found, ["extra:1.0", "lib:2.0"]);
}

/// A repository policy, or the activation of a profile that matters to
/// resolution, of the project or of a dependency's POM, that reads a set
/// variable outside `allow_env_substitution` fails the sync (exit 3),
/// naming it, in both Maven modes: Maven 3.9.12 and 3.10.0 read its value,
/// where raeva read it as unset, warned and locked another resolution.
/// Listed, the variable decides as in Maven.
#[test]
fn a_hidden_variable_that_decides_the_lock_refuses() {
    let base = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let root = base.path();
    let flag = "<activation><property><name>env.RAEVA_TEST_FLAG</name></property></activation>";
    let extra = "<dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>extra</artifactId><version>1.0</version></dependency></dependencies>";
    let repository = root.join("repository");
    publish(&repository, "org.test:lib:1.0", "");
    publish(&repository, "org.test:extra:1.0", "");
    publish(
        &repository,
        "org.test:flagged:1.0",
        &format!("<profiles><profile><id>ci</id>{flag}{extra}</profile></profiles>"),
    );
    let dependency = |artifact: &str| {
        format!(
            "<dependencies><dependency><groupId>org.test</groupId><artifactId>{artifact}\
             </artifactId><version>1.0</version></dependency></dependencies>"
        )
    };
    let repository = |policy: &str| {
        format!(
            "<repositories><repository><id>project-local</id>\
             <url>file://${{project.basedir}}/repository/</url>{policy}</repository>\
             </repositories>"
        )
    };
    let cases = [
        (
            repository("<releases><enabled>${env.RAEVA_TEST_FLAG}</enabled></releases>")
                + &dependency("lib"),
            vec!["lib:1.0"],
        ),
        (
            repository("") + &dependency("flagged"),
            vec!["extra:1.0", "flagged:1.0"],
        ),
        (
            repository("")
                + &dependency("lib")
                + &format!("<profiles><profile><id>ci</id>{flag}{extra}</profile></profiles>"),
            vec!["extra:1.0", "lib:1.0"],
        ),
        // Aligning the path to the project directory must not drop the
        // reference with the `..` after it.
        (
            repository("")
                + &dependency("lib")
                + &format!(
                    "<profiles><profile><id>ci</id><activation><file><exists>\
                     ${{env.RAEVA_TEST_FLAG}}/../enabled</exists></file></activation>{extra}\
                     </profile></profiles>"
                ),
            vec!["extra:1.0", "lib:1.0"],
        ),
    ];
    fs::write(root.join("enabled"), "").unwrap();
    let locked = || {
        let mut found: Vec<String> = (lock(root)["platforms"][0]["artifacts"].as_array())
            .expect("artifacts")
            .iter()
            .map(|row| {
                let coordinate = &row["coordinate"];
                format!(
                    "{}:{}",
                    coordinate["artifact"].as_str().expect("artifact"),
                    coordinate["version"].as_str().expect("version")
                )
            })
            .collect();
        found.sort();
        found
    };
    let config = home.path().join("config.toml");
    for mode in ["3.9", "3.10"] {
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .unwrap();
        for (body, expected) in &cases {
            let case = format!("{mode}: {body}");
            fs::write(
                root.join("pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>app</artifactId><version>1</version>{body}</project>"
                ),
            )
            .unwrap();
            let sync = || {
                raeva_command(root, home.path())
                    .env("RAEVA_TEST_FLAG", "true")
                    .arg("sync")
                    .output()
                    .expect("run raeva sync")
            };
            let _ = fs::remove_file(&config);
            let _ = fs::remove_file(root.join("raeva.lock"));
            let refused = sync();
            assert_status(&refused, 3, &case);
            let said = String::from_utf8_lossy(&refused.stderr);
            assert!(
                said.contains("RAEVA_TEST_FLAG") && said.contains("allow_env_substitution"),
                "{case}: {said}"
            );
            assert!(!root.join("raeva.lock").exists(), "{case}");
            fs::write(
                &config,
                "[security]\nallow_env_substitution = [\"RAEVA_TEST_FLAG\"]\n",
            )
            .unwrap();
            assert_success(&sync(), &case);
            assert_eq!(&locked(), expected, "{case}");
        }
    }
}
