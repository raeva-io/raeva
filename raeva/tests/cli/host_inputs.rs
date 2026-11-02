use std::fs;
use std::path::Path;

use crate::common::{assert_status, assert_success, raeva_command, toml_strings};
use crate::offline_project::Project;

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
        .filter(|name| !name.starts_with("user-property:"))
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
        assert_success(&project.raeva(args), &format!("{args:?}"));
        assert_eq!(fs::read(project.root().join("raeva.lock")).unwrap(), locked);
    }
    assert_success(&project.raeva(&["sync", "--offline"]), "record the profile");
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
    let project = Project::synced_with(&[(
        "pom.xml",
        &pom(
            "root",
            "repository/",
            &format!("<profiles>{}{file_profiles}</profiles>", jdk_profiles(1025)),
        ),
    )]);
    let recorded = ambient(&project.root());
    assert_eq!(recorded.len(), 1101, "{recorded:?}");
    assert!(recorded.contains(&"java.version".to_string()));
    assert!(recorded.contains(&"file:marker1099 is false".to_string()));

    fs::write(project.root().join("marker1099"), "").unwrap();
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline"]),
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
    assert_success(&project.raeva(&["sync", "--offline"]), "sync");
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
    let dir = repository.join(format!("org/test/{artifact}/{version}"));
    fs::create_dir_all(&dir).expect("create artifact dir");
    let pom_name = format!("{artifact}-{version}.pom");
    let pom_bytes = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>{artifact}</artifactId><version>{version}</version>\
         <packaging>{packaging}</packaging>{body}</project>"
    );
    fs::write(dir.join(&pom_name), &pom_bytes).unwrap();
    fs::write(
        dir.join(format!("{pom_name}.sha256")),
        crate::common::sha256_hex(pom_bytes.as_bytes()),
    )
    .unwrap();
    if packaging == "jar" {
        let jar_name = format!("{artifact}-{version}.jar");
        let jar_bytes = format!("{artifact}-{version}");
        fs::write(dir.join(&jar_name), &jar_bytes).unwrap();
        fs::write(
            dir.join(format!("{jar_name}.sha256")),
            crate::common::sha256_hex(jar_bytes.as_bytes()),
        )
        .unwrap();
    }
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
    let recorded = ambient(&root);
    assert_eq!(recorded.len(), 2, "{recorded:?}");
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

/// A settings.xml `<jdk>` condition and a `.mvn/maven.config` `-D` value
/// that expands `${java.version}` both change what is resolved, so each
/// warns that raeva stood in a JDK.
#[test]
fn settings_and_maven_config_reads_of_the_stand_in_jdk_warn() {
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
    let sync = project.raeva(&["sync", "--offline"]);
    assert_success(&sync, "sync with a settings jdk profile");
    let stderr = String::from_utf8_lossy(&sync.stderr);
    assert!(stderr.contains("JAVA_VERSION_DEFAULTED"), "{stderr}");

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
    let sync = project.raeva(&["sync", "--offline"]);
    assert_success(&sync, "sync with a -D value of java.version");
    let stderr = String::from_utf8_lossy(&sync.stderr);
    assert!(stderr.contains("JAVA_VERSION_DEFAULTED"), "{stderr}");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("org.test:lib:"), "{lock}");

    // A condition that reaches java.version through a nested name is
    // recorded as a lookup, and still warns.
    let project = Project::synced();
    let root = project.root();
    let pom_xml = pom(
        "root",
        "repository/",
        &format!(
            "<profiles><profile><id>on17</id><activation><file>\
             <exists>${{basedir}}/jdk-${{${{selector}}}}</exists></file></activation>\
             <dependencies>{LIB}</dependencies></profile></profiles>"
        ),
    );
    fs::write(root.join("pom.xml"), &pom_xml).unwrap();
    fs::write(root.join("jdk-17"), "").unwrap();
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/maven.config"), "-Dselector=java.version\n").unwrap();
    let sync = project.raeva(&["sync", "--offline"]);
    assert_success(&sync, "sync with a nested java.version lookup");
    let stderr = String::from_utf8_lossy(&sync.stderr);
    assert!(
        stderr.contains("JAVA_VERSION_DEFAULTED: the POM of org.test:root:1 reads"),
        "{stderr}"
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("org.test:lib:"), "{lock}");
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

    // Without JAVA_HOME or JAVA_VERSION, a POM that tests the JDK sees 17,
    // and the run says so.
    let defaulted = project.raeva_with(&[], &["sync", "--frozen"]);
    assert_success(&defaulted, "frozen with the stand-in JDK");
    let stderr = String::from_utf8_lossy(&defaulted.stderr);
    assert!(
        stderr.contains("JAVA_VERSION_DEFAULTED: the POM of org.test:root:1 reads")
            && stderr.contains("so raeva used 17"),
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
    let frozen_patch = run("25.0.1", &["sync", "--frozen"]);
    assert!(
        String::from_utf8_lossy(&frozen_patch.stderr).contains("or add 25 to [lock] jdks"),
        "{}",
        String::from_utf8_lossy(&frozen_patch.stderr)
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
/// names a settings.xml property, by any name or nesting interpolation
/// follows, or that settings.xml expands into its own activation, stays out
/// of raeva.lock and out of the `--frozen` message.
#[test]
fn settings_values_from_the_environment_stay_out_of_the_lock_and_messages() {
    for (property, value) in [
        ("<alias>${secret}</alias>", "${alias}"),
        ("<alias>${secret}</alias>", "${project.properties.alias}"),
        ("<selector>secret</selector>", "${${selector}}"),
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
        fs::write(dir.join(&name), classifier).unwrap();
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(classifier.as_bytes()),
        )
        .unwrap();
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
    fs::write(dir.join(name), "native").unwrap();
    fs::write(
        dir.join(format!("{name}.sha256")),
        crate::common::sha256_hex(b"native"),
    )
    .unwrap();
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
    fs::write(dir.join(name), "native").unwrap();
    fs::write(
        dir.join(format!("{name}.sha256")),
        crate::common::sha256_hex(b"native"),
    )
    .unwrap();
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
    fs::write(dir.join(name), "native").unwrap();
    fs::write(
        dir.join(format!("{name}.sha256")),
        crate::common::sha256_hex(b"native"),
    )
    .unwrap();
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
            "${${selector}}",
            "<properties><alias>${key}</alias></properties>",
            "alias",
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
/// `parent.version`, which a system property replaces, so a `-D` of it, or
/// of a name it forms, decides whether `lib` resolves.
#[test]
fn a_define_of_a_parent_field_counts_in_a_dependency_model() {
    for (version, defines, changed) in [
        ("${parent.version}", vec![], "-Dparent.version=2.0"),
        (
            "${${selector}}",
            vec!["-Dselector=parent.version"],
            "-Dparent.version=2.0",
        ),
        (
            "${${selector}.${parent.version}}",
            vec!["-Dselector=ver"],
            "-Dver.1.0=2.0",
        ),
    ] {
        let project = Project::synced();
        let root = project.root();
        let repo = root.join("repository");
        let write = |artifact: &str, body: &str| {
            let dir = repo.join(format!("org/test/{artifact}/1.0"));
            fs::create_dir_all(&dir).unwrap();
            let pom = format!("<project><modelVersion>4.0.0</modelVersion>{body}</project>");
            let name = format!("{artifact}-1.0.pom");
            fs::write(dir.join(&name), &pom).unwrap();
            fs::write(
                dir.join(format!("{name}.sha256")),
                crate::common::sha256_hex(pom.as_bytes()),
            )
            .unwrap();
        };
        write(
            "top",
            "<groupId>org.test</groupId><artifactId>top</artifactId><version>1.0</version>\
             <packaging>pom</packaging>",
        );
        write(
            "mid",
            &format!(
                "<parent><groupId>org.test</groupId><artifactId>top</artifactId>\
                 <version>1.0</version></parent><artifactId>mid</artifactId>\
                 <version>{version}</version><packaging>pom</packaging>"
            ),
        );
        publish_artifact(&repo, "lib", "1.0", "jar", "");
        write(
            "lib",
            "<parent><groupId>org.test</groupId><artifactId>mid</artifactId>\
             <version>1.0</version></parent><artifactId>lib</artifactId><version>1.0</version>",
        );
        fs::remove_file(root.join("raeva.lock")).unwrap();
        let mut args = vec!["sync", "--offline", "-Dver.1.0=1.0"];
        args.extend(&defines);
        assert_success(&project.raeva(&args), version);
        args.push("--frozen");
        assert_success(&project.raeva(&args), version);
        args.push(changed);
        assert_status(&project.raeva(&args), 7, version);
    }
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
        let expression = if nested { "${${selector}}" } else { "${alias}" };
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
                args.push("-Dselector=review-private-key");
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
            "${${selector}}"
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
                args.push("-Dselector=review-private-key");
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
            "${${selector}}"
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
                args.push("-Dselector=private-path-property");
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
        "-P${java.version}\n",
        "-Dselected=${java.version}\n-Dunread=${java.version}\n-P${selected}\n",
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
    fs::write(&options, "-Dflag=${java.version}\n").unwrap();
    fs::write(root.join("raeva.toml"), "[lock]\njdks = [\"17\", \"21\"]\n").unwrap();
    let home = tempfile::TempDir::new().unwrap();
    let env = [("RAEVA_HOME", home.path().to_str().unwrap())];
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
    fs::write(&options, "-Dflag=${java.version}\n").unwrap();
    assert_success(&run(&frozen), "unchanged target-dependent values");
}
