//! The Maven line `[lock] maven` or the Maven wrapper selects.

use std::fs;

use crate::common::{assert_status, assert_success, write_with_sha256};
use crate::offline_project::Project;

const CENTRAL: &str = "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven";

fn write_wrapper(project: &Project, version: &str) {
    let dir = project.root().join(".mvn/wrapper");
    fs::create_dir_all(&dir).expect("wrapper dir");
    fs::write(
        dir.join("maven-wrapper.properties"),
        format!("distributionUrl={CENTRAL}/{version}/apache-maven-{version}-bin.zip\n"),
    )
    .expect("write wrapper");
}

/// A 3.10 wrapper resolves as 3.10 and the lock records it. `--frozen`
/// refuses a lock resolved under the other line, and a plain sync resolves
/// again, back to the bytes of a project without a wrapper.
#[test]
fn a_maven_310_wrapper_is_recorded_and_frozen_refuses_the_other_line() {
    let project = Project::synced();
    let lock_path = project.root().join("raeva.lock");
    let maven39 = fs::read(&lock_path).expect("lock");
    assert!(!String::from_utf8_lossy(&maven39).contains("maven ="));
    write_wrapper(&project, "3.10.0");
    let frozen = project.raeva(&["sync", "--frozen", "--offline"]);
    assert_status(&frozen, 7, "frozen 3.9 lock under a 3.10 wrapper");
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    for part in [
        "raeva.lock was resolved as Maven 3.9, and ",
        "maven-wrapper.properties (Maven \"3.10.0\") selects Maven 3.10",
    ] {
        assert!(stderr.contains(part), "{stderr}");
    }
    assert_eq!(fs::read(&lock_path).expect("lock"), maven39);

    let output = project.raeva(&["--json", "sync", "--offline"]);
    assert_success(&output, "sync with a 3.10 wrapper");
    let maven310 = fs::read(&lock_path).expect("lock");
    let text = String::from_utf8_lossy(&maven310);
    assert_eq!(text.matches("\nmaven = \"3.10\"\n").count(), 1, "{text}");
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen 3.10 lock",
    );
    assert_success(&project.raeva(&["sync", "--offline"]), "sync 3.10 again");
    assert_eq!(fs::read(&lock_path).expect("lock"), maven310);

    write_wrapper(&project, "3.9.12");
    let frozen = project.raeva(&["sync", "--frozen", "--offline"]);
    assert_status(&frozen, 7, "frozen 3.10 lock under a 3.9 wrapper");
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(stderr.contains("resolved as Maven 3.10"), "{stderr}");
    let output = project.raeva(&["--json", "sync", "--offline"]);
    assert_success(&output, "sync with a 3.9 wrapper");
    assert_eq!(fs::read(&lock_path).expect("lock"), maven39);
}

/// A lock whose `maven` line names another line than the configuration's
/// is refused, though its `config_hash` matches, and a plain sync rewrites
/// it.
#[test]
fn a_lock_whose_maven_line_was_edited_is_refused() {
    let project = Project::synced();
    let lock_path = project.root().join("raeva.lock");
    let maven39 = fs::read_to_string(&lock_path).expect("lock");
    let (head, rest) = maven39.split_once("config_hash").expect("config_hash");
    fs::write(
        &lock_path,
        format!("{head}maven = \"3.10\"\nconfig_hash{rest}"),
    )
    .expect("edit");
    let output = project.raeva(&["sync", "--frozen", "--offline"]);
    assert_status(&output, 7, "frozen sync");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("resolved as Maven 3.10"), "{stderr}");
    assert_success(&project.raeva(&["sync", "--offline"]), "sync");
    assert_eq!(fs::read_to_string(&lock_path).expect("lock"), maven39);
}

/// A wrapper for a Maven raeva does not resolve as fails until raeva.toml
/// chooses a line, and only the project file may choose one.
#[test]
fn an_unsupported_wrapper_fails_until_the_project_chooses() {
    let project = Project::synced();
    write_wrapper(&project, "4.0.0");
    let output = project.raeva(&["sync", "--offline"]);
    assert_status(&output, 3, "sync with a Maven 4 wrapper");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"apache-maven-4.0.0-bin.zip\""),
        "{stderr}"
    );
    assert!(stderr.contains("under [lock] in raeva.toml"), "{stderr}");

    fs::write(
        project.root().join("raeva.toml"),
        "[lock]\nmaven = \"3.9\"\n",
    )
    .expect("toml");
    let output = project.raeva(&["--json", "sync", "--offline"]);
    assert_success(&output, "sync choosing 3.9");

    fs::write(
        project.root().join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n",
    )
    .expect("toml");
    let output = project.raeva(&["--json", "sync", "--offline"]);
    assert_success(&output, "sync choosing 3.10");
    let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
    assert!(lock.contains("\nmaven = \"3.10\"\n"), "{lock}");

    fs::remove_file(project.root().join("raeva.toml")).expect("remove toml");
    fs::write(
        project.raeva_home().join("config.toml"),
        "[lock]\nmaven = \"3.9\"\n",
    )
    .expect("user config");
    let output = project.raeva(&["sync", "--offline"]);
    assert_status(&output, 3, "lock.maven in config.toml");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lock.maven belongs in the project's raeva.toml"),
        "{stderr}"
    );
}

/// Writes `org.test:<artifact>:<version>` with `dependencies` into the
/// project's repository, and the versions of `org.test:<artifact>` listed in
/// its metadata.
fn release(project: &Project, artifact: &str, version: &str, dependencies: &[(&str, &str)]) {
    let dir = project
        .root()
        .join(format!("repository/org/test/{artifact}"));
    let dependencies: String = (dependencies.iter())
        .map(|(artifact, version)| {
            format!(
                "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
                 <version>{version}</version></dependency>"
            )
        })
        .collect();
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>{artifact}</artifactId><version>{version}</version>\
         <dependencies>{dependencies}</dependencies></project>"
    );
    let metadata = |versions: &str| {
        format!(
            "<metadata><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <versioning><versions>{versions}</versions></versioning></metadata>"
        )
    };
    let listed = fs::read_to_string(dir.join("maven-metadata.xml"))
        .ok()
        .and_then(|text| {
            let start = text.find("<versions>")? + "<versions>".len();
            Some(text[start..text.find("</versions>")?].to_string())
        })
        .unwrap_or_default();
    let metadata = metadata(&format!("{listed}<version>{version}</version>"));
    let release = dir.join(version);
    write_with_sha256(
        &release.join(format!("{artifact}-{version}.pom")),
        pom.as_bytes(),
    );
    write_with_sha256(
        &release.join(format!("{artifact}-{version}.jar")),
        artifact.as_bytes(),
    );
    write_with_sha256(&dir.join("maven-metadata.xml"), metadata.as_bytes());
}

/// The `range-winner-skipped` case of test-fixtures/maven-modes/cases.txt
/// through `raeva sync`: a hard range beats the nearer soft version, and
/// 3.10's breadth-first collection skips the range's subtree, so the two
/// lines lock different graphs and each lock records its line.
#[test]
fn the_maven_line_decides_the_locked_graph() {
    let project = Project::synced();
    for (artifact, version, dependencies) in [
        ("old", "1", &[][..]),
        ("new", "1", &[]),
        ("x", "1", &[("old", "1")]),
        ("x", "2", &[("new", "1")]),
        ("a", "1", &[("x", "1")]),
        ("b", "1", &[("x", "[2,3)")]),
    ] {
        release(&project, artifact, version, dependencies);
    }
    let pom = project.root().join("pom.xml");
    let text = fs::read_to_string(&pom).expect("pom");
    let dependency = |artifact: &str| {
        format!(
            "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version></dependency>"
        )
    };
    let text = text.replace(
        "<dependencies>",
        &format!("<dependencies>{}{}", dependency("a"), dependency("b")),
    );
    fs::write(&pom, text).expect("write pom");
    let locked = |line: &str| {
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{line}\"\n"),
        )
        .expect("toml");
        assert_success(&project.raeva(&["sync", "--offline"]), line);
        let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).expect("lock");
        let mut packages: Vec<String> = (lock.platforms[0].modules[0].packages.iter())
            .map(|package| package.coordinate.gav.to_string())
            .collect();
        packages.sort();
        (lock.maven.as_str().to_string(), packages)
    };
    let with = |names: &[&str]| -> Vec<String> {
        let mut names: Vec<String> = names
            .iter()
            .map(|name| format!("org.test:{name}"))
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        locked("3.9"),
        (
            "3.9".to_string(),
            with(&["a:1", "b:1", "lib:1.0", "new:1", "x:2"])
        )
    );
    assert_eq!(
        locked("3.10"),
        ("3.10".to_string(), with(&["a:1", "b:1", "lib:1.0", "x:2"]))
    );
}

/// In the 3.10 mode a sync refuses a plugin declared
/// twice in the project or its local parent, and a plugin repository named
/// `local`, as Maven 3.10.0 does. The 3.9 mode keeps them.
#[test]
fn the_maven_310_mode_refuses_duplicate_plugins_and_a_local_plugin_repository() {
    let project = Project::synced();
    let pom = fs::read_to_string(project.root().join("pom.xml")).expect("pom");
    let plugin =
        "<plugin><groupId>x</groupId><artifactId>p</artifactId><version>1</version></plugin>";
    let twice = format!("<build><plugins>{plugin}{plugin}</plugins></build>");
    let local = "<pluginRepositories><pluginRepository><id>local</id>\
                 <url>https://r.example/</url></pluginRepository></pluginRepositories>";
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                  <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>";
    let child = pom.replace(
        "<groupId>org.test</groupId><artifactId>root</artifactId>",
        "<parent><groupId>org.test</groupId><artifactId>parent</artifactId><version>1</version>\
         <relativePath>parent/pom.xml</relativePath></parent><artifactId>root</artifactId>",
    );
    let module = "<packaging>pom</packaging><modules><module>parent</module></modules>";
    let unique = "'build.plugins.plugin.(groupId:artifactId)' must be unique but found duplicate \
                  declaration of plugin x:p";
    let reserved = "'pluginRepositories.pluginRepository.id' must not be 'local'";
    for (root, parent, error) in [
        (
            pom.replace("</dependencies>", &format!("</dependencies>{twice}")),
            None,
            unique,
        ),
        (
            child.clone(),
            Some(format!("{parent}{twice}</project>")),
            unique,
        ),
        (
            pom.replace("</dependencies>", &format!("</dependencies>{local}")),
            None,
            reserved,
        ),
        (
            child.clone(),
            Some(format!("{parent}{local}</project>")),
            reserved,
        ),
        // A reactor module, and one that is also the root's parent.
        (
            pom.replace("</dependencies>", &format!("</dependencies>{module}")),
            Some(format!("{parent}{twice}</project>")),
            unique,
        ),
        (
            child.replace("</dependencies>", &format!("</dependencies>{module}")),
            Some(format!("{parent}{twice}</project>")),
            unique,
        ),
    ] {
        fs::write(project.root().join("pom.xml"), &root).expect("pom");
        if let Some(parent) = &parent {
            fs::create_dir_all(project.root().join("parent")).expect("parent dir");
            fs::write(project.root().join("parent/pom.xml"), parent).expect("parent pom");
        }
        fs::write(
            project.root().join("raeva.toml"),
            "[lock]\nmaven = \"3.9\"\n",
        )
        .expect("toml");
        let output = project.raeva(&["sync", "--offline"]);
        assert_success(&output, "the 3.9 mode keeps them");
        fs::remove_file(project.root().join("raeva.lock")).expect("remove lock");
        fs::write(
            project.root().join("raeva.toml"),
            "[lock]\nmaven = \"3.10\"\n",
        )
        .expect("toml");
        let output = project.raeva(&["sync", "--offline"]);
        assert_status(&output, 3, error);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(error), "{error}: {stderr}");
    }
}

/// A repository of the effective model named `local`, which Maven's local
/// repository names its own files by: Maven 3.10.0 refuses the build and
/// 3.9.12 warns, in the same words, and builds. That covers the project's
/// and its active profiles' repositories, plugin repositories and
/// `<distributionManagement>`'s, a parent's included, after interpolation; an inactive profile's do not
/// count.
#[test]
fn a_repository_named_local_is_refused_in_3_10_and_warned_of_in_3_9() {
    let project = Project::synced();
    let pom = fs::read_to_string(project.root().join("pom.xml")).expect("pom");
    let local = "<id>local</id><url>https://r.example/</url>";
    let profile = |active: bool, body: &str| {
        format!(
            "<profiles><profile><id>p</id><activation><activeByDefault>{active}\
             </activeByDefault></activation>{body}</profile></profiles>"
        )
    };
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                  <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>";
    let child = pom.replace(
        "<groupId>org.test</groupId><artifactId>root</artifactId>",
        "<parent><groupId>org.test</groupId><artifactId>parent</artifactId><version>1</version>\
         <relativePath>parent/pom.xml</relativePath></parent><artifactId>root</artifactId>",
    );
    let after = |text: &str| pom.replace("</dependencies>", &format!("</dependencies>{text}"));
    let repositories = "'repositories.repository.id'";
    let deployment = "'distributionManagement.repository.id'";
    let snapshots = "'distributionManagement.snapshotRepository.id'";
    let plugin_repository = "'pluginRepositories.pluginRepository.id'";
    let plugin_repositories = format!(
        "<pluginRepositories><pluginRepository>{local}</pluginRepository></pluginRepositories>"
    );
    for (root, parent, field) in [
        (
            pom.replace(
                "</repositories>",
                &format!("<repository>{local}</repository></repositories>"),
            ),
            None,
            Some(repositories),
        ),
        (
            after(&profile(
                true,
                &format!("<repositories><repository>{local}</repository></repositories>"),
            )),
            None,
            Some(repositories),
        ),
        (
            child.clone(),
            Some(format!(
                "{parent}<distributionManagement><repository>{local}</repository>\
                 </distributionManagement></project>"
            )),
            Some(deployment),
        ),
        (
            after(&profile(
                true,
                "<distributionManagement><snapshotRepository><id>${dist.id}</id>\
                 <url>https://r.example/</url></snapshotRepository></distributionManagement>",
            ))
            .replace(
                "</project>",
                "<properties><dist.id>local</dist.id></properties></project>",
            ),
            None,
            Some(snapshots),
        ),
        (
            after(&profile(
                false,
                &format!("<repositories><repository>{local}</repository></repositories>"),
            )),
            None,
            None,
        ),
        (after(&plugin_repositories), None, Some(plugin_repository)),
        (
            after(&profile(true, &plugin_repositories)),
            None,
            Some(plugin_repository),
        ),
        (
            child.clone(),
            Some(format!("{parent}{plugin_repositories}</project>")),
            Some(plugin_repository),
        ),
        (after(&profile(false, &plugin_repositories)), None, None),
    ] {
        fs::write(project.root().join("pom.xml"), &root).expect("pom");
        if let Some(parent) = &parent {
            fs::create_dir_all(project.root().join("parent")).expect("parent dir");
            fs::write(project.root().join("parent/pom.xml"), parent).expect("parent pom");
        }
        let error = field.map(|field| format!("{field} must not be 'local'"));
        for mode in ["3.9", "3.10"] {
            let _ = fs::remove_file(project.root().join("raeva.lock"));
            fs::write(
                project.root().join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .expect("toml");
            let output = project.raeva(&["sync", "--offline"]);
            let stderr = String::from_utf8_lossy(&output.stderr);
            match (&error, mode) {
                (Some(error), "3.10") => assert_status(&output, 3, error),
                _ => assert_success(&output, &format!("{field:?} in {mode}")),
            }
            let warned = error
                .as_ref()
                .is_some_and(|error| stderr.contains(error.as_str()));
            assert_eq!(warned, error.is_some(), "{field:?} in {mode}: {stderr}");
            if mode == "3.9" {
                assert_eq!(
                    stderr.matches("POM_PROBLEM").count(),
                    usize::from(error.is_some()),
                    "{field:?}: {stderr}"
                );
            }
        }
    }
    // The 3.9 mode reads only the ids of the plugin repositories of a build
    // that locks no plugins, so a policy that reads a hidden variable
    // refuses nothing.
    let policy = "<pluginRepositories><pluginRepository><id>pr</id><url>https://r.example/</url>\
                  <releases><enabled>${env.HOME}</enabled></releases></pluginRepository>\
                  </pluginRepositories>";
    fs::write(project.root().join("pom.xml"), after(policy)).expect("pom");
    fs::write(
        project.root().join("raeva.toml"),
        "[lock]\nmaven = \"3.9\"\n",
    )
    .expect("toml");
    let _ = fs::remove_file(project.root().join("raeva.lock"));
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "a hidden policy variable",
    );
}

/// In either mode, a sync refuses a plugin repository without an id and
/// plugin sections that do not parse, in the project or its local parent,
/// as Maven 3.9.12 and 3.10.0 both do.
#[test]
fn both_modes_refuse_an_incomplete_plugin_repository_and_unreadable_plugins() {
    let project = Project::synced();
    let pom = fs::read_to_string(project.root().join("pom.xml")).expect("pom");
    let no_id = "<pluginRepositories><pluginRepository><url>https://r.example/</url>\
                 </pluginRepository></pluginRepositories>";
    let twice = "<build><plugins><plugin><artifactId>p</artifactId><version>1</version>\
                 <version>2</version></plugin></plugins></build>";
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                  <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>";
    let child = pom.replace(
        "<groupId>org.test</groupId><artifactId>root</artifactId>",
        "<parent><groupId>org.test</groupId><artifactId>parent</artifactId><version>1</version>\
         <relativePath>parent/pom.xml</relativePath></parent><artifactId>root</artifactId>",
    );
    let missing = "'pluginRepositories.pluginRepository.id' is missing";
    let duplicate = "duplicate field `version`";
    for (root, parent, error) in [
        (
            pom.replace("</dependencies>", &format!("</dependencies>{no_id}")),
            None,
            missing,
        ),
        (
            child.clone(),
            Some(format!("{parent}{no_id}</project>")),
            missing,
        ),
        (
            pom.replace("</dependencies>", &format!("</dependencies>{twice}")),
            None,
            duplicate,
        ),
        (
            child.clone(),
            Some(format!("{parent}{twice}</project>")),
            duplicate,
        ),
    ] {
        fs::write(project.root().join("pom.xml"), &root).expect("pom");
        if let Some(parent) = &parent {
            fs::create_dir_all(project.root().join("parent")).expect("parent dir");
            fs::write(project.root().join("parent/pom.xml"), parent).expect("parent pom");
        }
        for mode in ["3.9", "3.10"] {
            fs::write(
                project.root().join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .expect("toml");
            let output = project.raeva_with(
                &[("RAEVA_TEST_UNRECORDED_MAVEN_MODE", "1")],
                &["sync", "--offline"],
            );
            assert_status(&output, 3, error);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(error), "{mode} {error}: {stderr}");
        }
    }
}

/// Maven validates a parent it reads from a repository as it validates a
/// local one, in either line.
#[test]
fn both_modes_refuse_an_incomplete_plugin_repository_of_a_remote_parent() {
    let project = Project::synced();
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                  <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
                  <pluginRepositories><pluginRepository><url>https://r.example/</url>\
                  </pluginRepository></pluginRepositories></project>";
    let dir = project.root().join("repository/org/test/parent/1");
    fs::create_dir_all(&dir).expect("parent dir");
    write_with_sha256(&dir.join("parent-1.pom"), parent.as_bytes());
    let pom = fs::read_to_string(project.root().join("pom.xml")).expect("pom");
    let child = pom.replace(
        "<groupId>org.test</groupId><artifactId>root</artifactId>",
        "<parent><groupId>org.test</groupId><artifactId>parent</artifactId><version>1</version>\
         <relativePath/></parent><artifactId>root</artifactId>",
    );
    fs::write(project.root().join("pom.xml"), child).expect("pom");
    let error = "'pluginRepositories.pluginRepository.id' is missing";
    let repository = url::Url::from_directory_path(project.root().join("repository")).unwrap();
    for mode in ["3.9", "3.10"] {
        fs::write(
            project.root().join("raeva.toml"),
            format!(
                "[lock]\nmaven = \"{mode}\"\n\n[[repositories]]\nid = \"files\"\n\
                 url = \"{repository}\"\n"
            ),
        )
        .expect("toml");
        let output = project.raeva_with(&[("RAEVA_TEST_UNRECORDED_MAVEN_MODE", "1")], &["sync"]);
        assert_status(&output, 5, error);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("org.test:parent:1"), "{mode}: {stderr}");
    }
}

/// In the 3.10 mode, `MAVEN_REPO_CENTRAL` or a POM's `maven.repo.central`
/// replaces Maven Central, as Maven 3.10.0 does; the 3.9 mode reads
/// neither.
#[test]
fn the_maven_310_mode_reads_central_from_maven_repo_central() {
    let project = Project::synced_with(&[(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version></project>",
    )]);
    let central = project.root().join("central");
    crate::offline_project::publish_lib(&central);
    let url = url::Url::from_directory_path(&central)
        .expect("url")
        .to_string();
    let pom = |properties: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version>{properties}<dependencies>\
             <dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>1.0</version></dependency></dependencies></project>"
        )
    };
    let property =
        format!("<properties><maven.repo.central>{url}</maven.repo.central></properties>");
    for (mode, pom, env, synced) in [
        ("3.9", pom(""), Some(url.as_str()), false),
        ("3.9", pom(&property), None, false),
        ("3.10", pom(""), None, false),
        ("3.10", pom(""), Some(url.as_str()), true),
        ("3.10", pom(&property), None, true),
    ] {
        fs::write(project.root().join("pom.xml"), &pom).expect("pom");
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .expect("toml");
        let _ = fs::remove_file(project.root().join("raeva.lock"));
        let env_vars: Vec<_> = env
            .map(|url| ("MAVEN_REPO_CENTRAL", url))
            .into_iter()
            .collect();
        let output = project.raeva_with(&env_vars, &["sync", "--offline"]);
        let label = format!("{mode} {env:?} {pom}");
        if synced {
            assert_success(&output, &label);
        } else {
            assert!(!output.status.success(), "{label}");
        }
    }
    // A settings.xml `central` wins over the super POM's, so a POM's
    // maven.repo.central goes unused, even one raeva could not read.
    fs::write(
        project.m2_settings(),
        format!(
            "<settings><profiles><profile><id>c</id><repositories><repository>\
             <id>central</id><url>{url}</url></repository></repositories></profile>\
             </profiles><activeProfiles><activeProfile>c</activeProfile></activeProfiles>\
             </settings>"
        ),
    )
    .expect("settings");
    fs::write(
        project.root().join("pom.xml"),
        pom(
            "<properties><maven.repo.central>ftp://unused.invalid/m2</maven.repo.central>\
             </properties>",
        ),
    )
    .expect("pom");
    let _ = fs::remove_file(project.root().join("raeva.lock"));
    let output = project.raeva(&["sync", "--offline"]);
    assert_success(&output, "settings central");
}

/// A Maven 3.10 Central on plain HTTP to a host that is not loopback is
/// what Maven's default HTTP blocker blocks: a mirror of it serves it,
/// another repository still serves what it has, and without either the
/// sync fails naming the blocker. No request goes to the Central URL.
#[test]
fn the_maven_310_mode_blocks_an_http_central_that_no_mirror_serves() {
    let project = Project::synced_with(&[(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version></project>",
    )]);
    let served = project.root().join("served");
    crate::offline_project::publish_lib(&served);
    let served = url::Url::from_directory_path(&served)
        .expect("url")
        .to_string();
    fs::write(
        project.root().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><dependencies><dependency>\
         <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>\
         </dependency></dependencies></project>",
    )
    .expect("pom");
    fs::write(
        project.root().join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n",
    )
    .expect("toml");
    let central = "http://central.invalid/m2/";
    let env = [("MAVEN_REPO_CENTRAL", central)];
    let mirror = format!(
        "<mirrors><mirror><id>corp</id><url>{served}</url><mirrorOf>central</mirrorOf>\
         </mirror></mirrors>"
    );
    let other = format!(
        "<profiles><profile><id>p</id><repositories><repository><id>other</id>\
         <url>{served}</url></repository></repositories></profile></profiles>\
         <activeProfiles><activeProfile>p</activeProfile></activeProfiles>"
    );
    for (settings, origin) in [(mirror.as_str(), central), (other.as_str(), "./served/")] {
        fs::write(
            project.m2_settings(),
            format!("<settings>{settings}</settings>"),
        )
        .expect("settings");
        let _ = fs::remove_file(project.root().join("raeva.lock"));
        let output = project.raeva_with(&env, &["sync"]);
        assert_success(&output, settings);
        let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
        assert!(
            lock.contains(&format!("repo_url = \"{origin}\"")),
            "{settings}\n{lock}"
        );
    }
    fs::write(project.m2_settings(), "<settings/>").expect("settings");
    let _ = fs::remove_file(project.root().join("raeva.lock"));
    let output = project.raeva_with(&env, &["sync"]);
    assert!(
        !output.status.success(),
        "no mirror and no other repository"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("maven-default-http-blocker"), "{stderr}");
    assert!(stderr.contains("HTTP_REPO_BLOCKED"), "{stderr}");
    // The doctor warns that Central gets no request, which is no failure.
    let output = project.raeva_with(&env, &["--json", "doctor"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("doctor JSON");
    let checks = envelope["data"]["checks"].as_array().expect("checks");
    let central = (checks.iter())
        .find(|check| (check["check"].as_str()).is_some_and(|name| name.starts_with("central")))
        .unwrap_or_else(|| panic!("no row for Central: {stdout}"));
    assert_eq!(central["status"], "warn", "{stdout}");
    assert!(
        (central["details"].as_str()).is_some_and(|details| details.contains("HTTP blocker")),
        "{stdout}"
    );
}

#[test]
fn either_mode_locks_compile_only() {
    let project = Project::synced_with(&[(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version></project>",
    )]);
    fs::write(
        project.root().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${project.basedir}/repository/</url>\
         </repository></repositories><dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
         <version>1.0</version><scope>compile-only</scope></dependency></dependencies>\
         </project>",
    )
    .expect("pom");
    let env = [];
    for mode in ["3.9", "3.10"] {
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .expect("toml");
        let _ = fs::remove_file(project.root().join("raeva.lock"));
        let output = project.raeva_with(&env, &["sync", "--offline"]);
        assert_success(&output, mode);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unknown dependency scope"),
            "{mode}\n{stderr}"
        );
        let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
        assert!(lock.contains("compile-only"), "{mode}\n{lock}");
        let output = project.raeva_with(&env, &["sync", "--frozen", "--offline"]);
        assert_success(&output, mode);
        // Maven 3's scope filters keep a scope they do not know, so a
        // compile-only artifact is on every classpath.
        for (scope, listed) in [
            ("compile-only", true),
            ("compile", true),
            ("provided", false),
        ] {
            let output = project.raeva_with(&env, &["tree", "--scope", scope]);
            assert_success(&output, mode);
            let shown = String::from_utf8_lossy(&output.stdout).contains("org.test:lib");
            assert_eq!(shown, listed, "{mode} {scope}");
        }
    }
}

/// The project with `org.test:a:1` and `org.test:d:1` in `scope`, `a`
/// depending on `b` in `below`, and `b` and `d` each on a jar of their own,
/// for the Maven line `mode`.
fn unknown_scope_project(mode: &str, scope: &str, below: &str) -> Project {
    let dependency = |artifact: &str, scope: &str| {
        format!(
            "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version><scope>{scope}</scope></dependency>"
        )
    };
    let project = Project::with(&[
        (
            "pom.xml",
            &format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><repositories><repository>\
                 <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
                 </repository></repositories><dependencies>{}{}</dependencies></project>",
                dependency("a", "compile"),
                dependency("d", scope),
            ),
        ),
        ("raeva.toml", &format!("[lock]\nmaven = \"{mode}\"\n")),
    ]);
    let dependencies = |artifact: &str, scope: &str| {
        format!(
            "<dependencies>{}</dependencies>",
            dependency(artifact, scope)
        )
    };
    project.publish("org.test:a:1", &dependencies("b", below));
    project.publish("org.test:b:1", &dependencies("c", "compile"));
    project.publish("org.test:c:1", "");
    project.publish("org.test:d:1", &dependencies("e", "compile"));
    project.publish("org.test:e:1", "");
    project
}

/// Maven 3.9.12 and 3.10.0 keep a scope they do not know as written, `:`
/// and `/` included, in the project and in a dependency's POM alike: they
/// only warn, and derive `runtime` below it (`dependency:tree` gives
/// `a:compile`, `b:foo:bar`, `c:runtime`, `d:foo:bar`, `e:runtime`). The
/// lock records it on every locked platform, and `--frozen`, `lock verify`,
/// `tree`, `why`, `sbom` and `export-m2` read it back.
#[test]
fn a_scope_with_a_colon_or_slash_is_locked_as_written() {
    // `export-m2` needs the host's platform in the lock.
    let host = rv_lock::Platform::current().unwrap().os_arch();
    let platforms = match host.as_str() {
        "linux-x86_64" | "windows-x86_64" => "linux-x86_64,windows-x86_64".to_string(),
        _ => format!("linux-x86_64,windows-x86_64,{host}"),
    };
    for scope in ["foo:bar", "x/y"] {
        for mode in ["3.9", "3.10"] {
            let what = format!("{scope} in {mode}");
            let project = unknown_scope_project(mode, scope, scope);
            let output = project.raeva(&["sync", "--offline", "--platforms", &platforms]);
            assert_success(&output, &what);
            let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
            let packages = format!(
                "packages = \"\"\"\norg.test:a:1\tjar\tcompile\norg.test:b:1\tjar\t\t{scope}\n\
                 org.test:c:1\tjar\t\truntime\norg.test:d:1\tjar\t{scope}\n\
                 org.test:e:1\tjar\t\truntime\"\"\"\n"
            )
            .replace('\t', "\\t");
            assert!(lock.contains(&packages), "{what}\n{lock}");
            let edges = format!("edges = \"\"\"\n0 1 {scope}\n1 2 runtime\n3 4 runtime\"\"\"");
            assert!(lock.contains(&edges), "{what}\n{lock}");
            assert_success(
                &project.raeva(&["sync", "--frozen", "--offline"]),
                &format!("frozen {what}"),
            );
            assert_success(
                &project.raeva(&["lock", "verify"]),
                &format!("verify {what}"),
            );
            let tree = project.raeva(&["tree"]);
            assert_success(&tree, &format!("tree {what}"));
            let stdout = String::from_utf8_lossy(&tree.stdout);
            for line in [
                format!("org.test:b:1 ({scope})"),
                "org.test:c:1 (runtime)".to_string(),
                format!("org.test:d:1 ({scope})"),
                "org.test:e:1 (runtime)".to_string(),
            ] {
                assert!(stdout.contains(&line), "{what}: {line}\n{stdout}");
            }
            // Maven's scope filters keep a scope they do not know, so javac
            // gets `b` and `d`, and not their runtime dependencies.
            let compile = project.raeva(&["tree", "--scope", "compile"]);
            let stdout = String::from_utf8_lossy(&compile.stdout);
            for (artifact, listed) in [("b", true), ("c", false), ("d", true), ("e", false)] {
                let shown = stdout.contains(&format!("org.test:{artifact}:1"));
                assert_eq!(shown, listed, "{what}: {artifact}\n{stdout}");
            }
            let why = project.raeva(&["why", "org.test:c"]);
            assert_success(&why, &format!("why {what}"));
            assert!(
                String::from_utf8_lossy(&why.stdout).contains("org.test:b:1"),
                "{what}"
            );
            let sbom = project.raeva(&["sbom"]);
            assert_success(&sbom, &format!("sbom {what}"));
            let sbom: serde_json::Value = serde_json::from_slice(&sbom.stdout).expect("sbom");
            let scope_of = |artifact: &str| {
                let component = (sbom["components"].as_array().expect("components").iter())
                    .find(|component| component["name"] == artifact)
                    .unwrap_or_else(|| panic!("{what}: no {artifact}"));
                (component["properties"].as_array().into_iter().flatten())
                    .find(|property| property["name"] == "raeva:maven:scope")
                    .map(|property| property["value"].as_str().unwrap_or_default().to_string())
            };
            assert_eq!(scope_of("b").as_deref(), Some(scope), "{what}");
            assert_eq!(scope_of("c").as_deref(), Some("runtime"), "{what}");
            let m2 = project.m2();
            let export = project.raeva(&["export-m2", "--m2-path", m2.to_str().expect("m2")]);
            assert_success(&export, &format!("export-m2 {what}"));
            assert!(m2.join("org/test/b/1/b-1.jar").exists(), "{what}");
        }
    }
}

/// Maven warns of a project dependency's scope it does not know, and of a
/// managed one's, in its own words, and builds: 3.10.0 knows
/// `compile-only`, 3.9.12 does not.
/// A dependency's POM is not validated so, and gets no warning.
#[test]
fn a_project_scope_maven_does_not_know_is_warned_of() {
    for (mode, known) in [
        ("3.9", "provided, compile, runtime, test, system"),
        (
            "3.10",
            "provided, compile, compile-only, runtime, test, system",
        ),
    ] {
        for (scope, warned) in [
            ("foo:bar", true),
            ("import", true),
            ("compile-only", mode == "3.9"),
            ("runtime", false),
        ] {
            let project = unknown_scope_project(mode, scope, "x/y");
            let output = project.raeva(&["sync", "--offline"]);
            assert_success(&output, &format!("{scope} in {mode}"));
            let stderr = String::from_utf8_lossy(&output.stderr);
            let warning = format!(
                "'dependencies.dependency.scope' for org.test:d:jar must be one of [{known}] \
                 but is '{scope}'."
            );
            assert_eq!(
                stderr.contains(&warning),
                warned,
                "{scope} in {mode}: {stderr}"
            );
            assert!(
                stderr.matches("POM_PROBLEM").count() <= 1,
                "{mode}: {stderr}"
            );
            assert!(!stderr.contains("x/y"), "{scope} in {mode}: {stderr}");
        }
        // A managed entry gets the warning too, `import` among the scopes.
        let project = unknown_scope_project(mode, "compile", "compile");
        let root = project.root().join("pom.xml");
        let pom = fs::read_to_string(&root).expect("pom");
        let pom = pom.replacen(
            "<dependencies>",
            "<dependencyManagement><dependencies><dependency><groupId>x</groupId>\
             <artifactId>y</artifactId><version>1</version><scope>bogus</scope></dependency>\
             </dependencies></dependencyManagement><dependencies>",
            1,
        );
        fs::write(&root, pom).expect("pom");
        let output = project.raeva(&["sync", "--offline"]);
        assert_success(&output, &format!("managed in {mode}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        let warning = format!(
            "'dependencyManagement.dependencies.dependency.scope' for x:y:jar must be one of \
             [{known}, import] but is 'bogus'."
        );
        assert!(stderr.contains(&warning), "managed in {mode}: {stderr}");
    }
}

/// A scope with whitespace, as manifold's `provided, test`, Maven keeps as
/// written and warns of, and so does raeva, in the project or in a
/// dependency's POM: raeva.lock writes it percent-encoded, `--frozen` reads
/// it back, and `raeva tree` shows it as written. A scope raeva.lock cannot
/// write, one with an invisible character, is refused with exit 3 naming
/// the dependency, where Maven would follow it: reading it as compile would
/// put the dependency's own dependencies on the compile classpath. Where
/// Maven does not follow it, it is not refused.
#[test]
fn a_scope_with_whitespace_is_locked_and_one_the_lock_cannot_write_refused() {
    for mode in ["3.9", "3.10"] {
        let project = unknown_scope_project(mode, "provided, test", "compile");
        let output = project.raeva(&["sync", "--offline"]);
        assert_success(&output, mode);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("'dependencies.dependency.scope' for org.test:d:jar must be one of")
                && stderr.contains("but is 'provided, test'."),
            "{mode}: {stderr}"
        );
        let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
        assert!(
            lock.contains(r"org.test:d:1\tjar\tprovided,%20test"),
            "{mode}\n{lock}"
        );
        assert_success(&project.raeva(&["sync", "--frozen", "--offline"]), mode);
        let tree = project.raeva(&["tree"]);
        let stdout = String::from_utf8_lossy(&tree.stdout);
        assert!(
            stdout.contains("org.test:d:1 (provided, test)"),
            "{mode}: {stdout}"
        );

        // Maven trims no interpolated value: ` compile ` from a property is
        // a scope it does not know, with `runtime` below it.
        let project = unknown_scope_project(mode, "${s}", "compile");
        let output = project.raeva(&["sync", "--offline", "-Ds= compile "]);
        assert_success(&output, &format!("interpolated {mode}"));
        let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
        assert!(
            lock.contains(r"org.test:d:1\tjar\t%20compile%20"),
            "{mode}\n{lock}"
        );

        let project = unknown_scope_project(mode, "compile", "two words");
        assert_success(
            &project.raeva(&["sync", "--offline"]),
            &format!("transitive {mode}"),
        );
        let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
        assert!(lock.contains(" two%20words"), "{mode}\n{lock}");
        assert_success(&project.raeva(&["sync", "--frozen", "--offline"]), mode);

        let hidden = "two\u{200b}words";
        let project = unknown_scope_project(mode, hidden, "compile");
        let output = project.raeva(&["sync", "--offline"]);
        assert_status(&output, 3, mode);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("'dependencies.dependency.scope' for org.test:d:jar"),
            "{mode}: {stderr}"
        );
        assert!(!project.root().join("raeva.lock").exists(), "{mode}");

        let project = unknown_scope_project(mode, "compile", hidden);
        let output = project.raeva(&["sync", "--offline"]);
        assert_status(&output, 3, &format!("transitive {mode}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("org.test:b:1"), "{mode}: {stderr}");
        assert!(!project.root().join("raeva.lock").exists(), "{mode}");

        // Below a test dependency Maven derives `test`, and an optional
        // dependency of a dependency is not followed at all.
        let optional = format!("{hidden}</scope><optional>true");
        for (scope, below, b) in [
            ("test", hidden, Some("org.test:b:1\\tjar\\t\\ttest")),
            ("compile", optional.as_str(), None),
        ] {
            let project = unknown_scope_project(mode, "compile", below);
            let root = project.root().join("pom.xml");
            let pom = fs::read_to_string(&root).expect("pom");
            let pom = pom.replacen(
                "<scope>compile</scope>",
                &format!("<scope>{scope}</scope>"),
                1,
            );
            fs::write(&root, pom).expect("pom");
            let output = project.raeva(&["sync", "--offline"]);
            assert_success(&output, &format!("{scope} {below} in {mode}"));
            let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
            match b {
                Some(row) => assert!(lock.contains(row), "{mode}\n{lock}"),
                None => assert!(!lock.contains("org.test:b:1"), "{mode}\n{lock}"),
            }
        }
    }
}

/// Maven keeps a scope it does not know as written, such as the invalid
/// `<scope>optional</scope>` some POMs write, so the lock records it and
/// `--frozen` reads it back.
#[test]
fn an_unknown_scope_is_locked_as_written() {
    let project = Project::with(&[(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${project.basedir}/repository/</url>\
         </repository></repositories><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>mid</artifactId><version>1</version></dependency></dependencies>\
         </project>",
    )]);
    let mid = "repository/org/test/mid/1/mid-1";
    write_with_sha256(
        &project.root().join(format!("{mid}.pom")),
        b"<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
          <artifactId>mid</artifactId><version>1</version><dependencies><dependency>\
          <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>\
          <scope>optional</scope></dependency></dependencies></project>",
    );
    write_with_sha256(&project.root().join(format!("{mid}.jar")), b"mid jar");
    let output = project.raeva(&["sync", "--offline"]);
    assert_success(&output, "sync");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("unknown dependency scope"), "{stderr}");
    let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
    // An edge line names its scope first, so `optional` there is the scope.
    assert!(
        lock.contains(r"org.test:lib:1.0\tjar\t\toptional"),
        "{lock}"
    );
    assert!(lock.contains("edges = \"1 0 optional\"\n"), "{lock}");
    assert_success(&project.raeva(&["sync", "--frozen", "--offline"]), "frozen");
    let output = project.raeva(&["tree"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("org.test:lib:1.0 (optional)"), "{stdout}");
}

/// A package reached only in two scopes Maven does not know gets the empty
/// scope from JavaScopeSelector, and its own dependencies keep their scopes
/// below it. The lock writes it as `?`, `--frozen` and `lock verify` read it
/// back, and Maven puts it on the compile classpath.
#[test]
fn a_package_reached_only_in_unknown_scopes_has_no_scope() {
    let project = Project::with(&[(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${project.basedir}/repository/</url>\
         </repository></repositories><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>a</artifactId><version>1</version></dependency><dependency>\
         <groupId>org.test</groupId><artifactId>b</artifactId><version>1</version>\
         </dependency></dependencies></project>",
    )]);
    let publish = |artifact: &str, dependencies: &str| {
        let base = format!("repository/org/test/{artifact}/1/{artifact}-1");
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version>\
             <dependencies>{dependencies}</dependencies></project>"
        );
        write_with_sha256(&project.root().join(format!("{base}.pom")), pom.as_bytes());
        write_with_sha256(
            &project.root().join(format!("{base}.jar")),
            artifact.as_bytes(),
        );
    };
    let x = |scope: &str| {
        format!(
            "<dependency><groupId>org.test</groupId><artifactId>x</artifactId>\
             <version>1</version><scope>{scope}</scope></dependency>"
        )
    };
    publish("a", &x("weird"));
    publish("b", &x("compile-only"));
    publish(
        "x",
        "<dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
         <version>1.0</version></dependency>",
    );
    assert_success(&project.raeva(&["sync", "--offline"]), "sync");
    let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
    assert!(lock.contains(r"org.test:x:1\tjar\t\t?"), "{lock}");
    assert!(lock.contains(r"org.test:lib:1.0\tjar"), "{lock}");
    assert_success(&project.raeva(&["sync", "--frozen", "--offline"]), "frozen");
    assert_success(&project.raeva(&["lock", "verify"]), "lock verify");
    let output = project.raeva(&["tree"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("org.test:x:1 (no scope)"), "{stdout}");
    assert!(stdout.contains("org.test:lib:1.0 (compile)"), "{stdout}");
    for (scope, listed) in [("compile", true), ("runtime", true), ("provided", false)] {
        let output = project.raeva(&["tree", "--scope", scope]);
        assert_success(&output, scope);
        let shown = String::from_utf8_lossy(&output.stdout).contains("org.test:x:1");
        assert_eq!(shown, listed, "{scope}");
    }
}

/// Outside management, Maven 3 keeps a dependency in the `import` scope, a
/// scope its JavaScopeDeriver does not know: the POM stays with its own
/// dependencies at `runtime`, and its scope filters keep it on every
/// classpath.
#[test]
fn a_dependency_in_the_import_scope_stays() {
    let project = Project::with(&[(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${project.basedir}/repository/</url>\
         </repository></repositories><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>imp</artifactId><version>1</version><type>pom</type>\
         <scope>import</scope></dependency></dependencies></project>",
    )]);
    write_with_sha256(
        &project.root().join("repository/org/test/imp/1/imp-1.pom"),
        b"<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
          <artifactId>imp</artifactId><version>1</version><packaging>pom</packaging>\
          <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
          <version>1.0</version></dependency></dependencies></project>",
    );
    assert_success(&project.raeva(&["sync", "--offline"]), "sync");
    let output = project.raeva(&["tree"]);
    assert_success(&output, "tree");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("org.test:imp:1:pom (import)"), "{stdout}");
    assert!(stdout.contains("org.test:lib:1.0 (runtime)"), "{stdout}");
    for (scope, listed) in [("compile", true), ("runtime", true), ("provided", false)] {
        let output = project.raeva(&["tree", "--scope", scope]);
        assert_success(&output, scope);
        let shown = String::from_utf8_lossy(&output.stdout).contains("org.test:imp");
        assert_eq!(shown, listed, "{scope}");
    }
}

/// Maven 3.10.0 relocates or bans what `maven.relocations.entries` names;
/// raeva does not, so the 3.10 mode refuses the property from
/// `.mvn/maven.config`, `.mvn/jvm.config` and a settings.xml profile
/// `<activeProfiles>` names, as Maven's session reads all three, and the 3.9
/// mode, whose Maven does not read it, takes no notice.
#[test]
fn the_maven_310_mode_refuses_maven_relocations_entries() {
    let project = Project::synced_with(&[(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version></project>",
    )]);
    fs::create_dir_all(project.root().join(".mvn")).expect("mvn");
    let settings = project.root().join("settings.xml");
    fs::write(&settings, "<settings/>").expect("settings");
    let property = "-Dmaven.relocations.entries=org.test:lib:*>org.test:other:*\n";
    for file in ["maven.config", "jvm.config", "settings.xml"] {
        let path = if file == "settings.xml" {
            fs::write(
                &settings,
                "<settings><profiles><profile><id>r</id><properties><maven.relocations.entries>\
                 org.test:lib:*&gt;org.test:other:*</maven.relocations.entries></properties>\
                 </profile></profiles><activeProfiles><activeProfile>r</activeProfile>\
                 </activeProfiles></settings>",
            )
            .expect("settings");
            settings.clone()
        } else {
            let path = project.root().join(".mvn").join(file);
            fs::write(&path, property).expect("config");
            path
        };
        for (mode, code) in [("3.9", 0), ("3.10", 3)] {
            fs::write(
                project.root().join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .expect("toml");
            let _ = fs::remove_file(project.root().join("raeva.lock"));
            let settings = settings.to_str().expect("utf-8");
            let output = project.raeva(&["-s", settings, "sync", "--offline"]);
            assert_status(&output, code, &format!("{mode} {file}"));
        }
        fs::remove_file(path).expect("remove");
    }
}

/// The 3.10 mode checks a local parent's `<relativePath>` as written, not
/// the path raeva resolves it to, which holds the checkout's own
/// directories and on Windows its drive letter.
#[test]
fn the_maven_310_mode_checks_a_relative_path_as_written() {
    let base = tempfile::TempDir::new().expect("base");
    let home = tempfile::TempDir::new().expect("home");
    let root = base
        .path()
        .join(if cfg!(windows) { "checkout" } else { "a:b" });
    let pom = |parent: Option<&str>, artifact_id: &str, module: &str| {
        let parent = parent.map_or_else(String::new, |parent| {
            format!(
                "<parent><groupId>g</groupId><artifactId>{parent}</artifactId>\
                 <version>1</version><relativePath>..</relativePath></parent>"
            )
        });
        let modules = if module.is_empty() {
            String::new()
        } else {
            format!("<packaging>pom</packaging><modules><module>{module}</module></modules>")
        };
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{parent}<groupId>g</groupId>\
             <artifactId>{artifact_id}</artifactId><version>1</version>{modules}</project>"
        )
    };
    for (path, text) in [
        ("pom.xml", pom(None, "parent", "child")),
        ("child/pom.xml", pom(Some("parent"), "child", "leaf")),
        ("child/leaf/pom.xml", pom(Some("child"), "leaf", "")),
        ("raeva.toml", "[lock]\nmaven = \"3.10\"\n".to_string()),
    ] {
        let path = root.join(path);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, text).expect("write project file");
    }
    let sync = |args: &[&str]| crate::common::run_raeva(&root, home.path(), args);
    assert_success(&sync(&["sync", "--offline"]), "3.10 sync");
    assert_success(&sync(&["sync", "--frozen", "--offline"]), "3.10 frozen");
}

/// Maven 3.10.0's super POM sets `project.build.sourceEncoding` and
/// `project.reporting.outputEncoding` to `UTF-8` below every model's own
/// properties, so a dependency POM's coordinates and the project's classifier
/// read them in the 3.10 mode, and so does a parent's own version. Maven
/// 3.9.12's sets none: the dependency's POM is invalid and its
/// dependencies are left out, and the classifier names no file.
#[test]
fn the_maven_310_super_pom_sets_the_encoding_properties() {
    let dependency = |artifact: &str, extra: &str| {
        format!(
            "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version>{extra}</dependency>"
        )
    };
    let project = Project::with(&[]);
    for artifact in [
        "leaf",
        "sub-UTF-8",
        "rep-UTF-8",
        "other",
        "sub-ISO-8859-1",
        "sub-US-ASCII",
    ] {
        project.publish(&format!("org.test:{artifact}:1"), "");
    }
    project.publish(
        "org.test:dep:1",
        &format!(
            "<dependencies>{}{}{}</dependencies>",
            dependency("sub-${project.build.sourceEncoding}", ""),
            dependency("rep-${project.reporting.outputEncoding}", ""),
            dependency("other", ""),
        ),
    );
    project.publish(
        "org.test:own:1",
        &format!(
            "<properties><project.build.sourceEncoding>ISO-8859-1\
             </project.build.sourceEncoding></properties><dependencies>{}</dependencies>",
            dependency("sub-${project.build.sourceEncoding}", "")
        ),
    );
    project.publish(
        "org.test:parent:1",
        "<packaging>pom</packaging><properties><project.build.sourceEncoding>US-ASCII\
         </project.build.sourceEncoding></properties>",
    );
    project.publish(
        "org.test:child:1",
        &format!(
            "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><dependencies>{}</dependencies>",
            dependency("sub-${project.build.sourceEncoding}", "")
        ),
    );
    // A parent whose version reads the property, as the child names it.
    write_with_sha256(
        &project
            .root()
            .join("repository/org/test/encoded/UTF-8/encoded-UTF-8.pom"),
        b"<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
          <artifactId>encoded</artifactId><version>${project.build.sourceEncoding}</version>\
          <packaging>pom</packaging></project>",
    );
    project.publish(
        "org.test:versioned:1",
        &format!(
            "<parent><groupId>org.test</groupId><artifactId>encoded</artifactId>\
             <version>UTF-8</version><relativePath/></parent><dependencies>{}</dependencies>",
            dependency("leaf", "")
        ),
    );
    project.publish("org.test:cl:1", "");
    for classifier in ["UTF-8", "X"] {
        let path = format!("repository/org/test/cl/1/cl-1-{classifier}.jar");
        write_with_sha256(&project.root().join(path), classifier.as_bytes());
    }
    let sync_with = |line: &str, dependencies: &str, options: &[&str]| {
        fs::write(
            project.root().join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><repositories><repository>\
                 <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
                 </repository></repositories><dependencies>{dependencies}</dependencies>\
                 </project>"
            ),
        )
        .expect("write pom");
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{line}\"\n"),
        )
        .expect("toml");
        let _ = fs::remove_file(project.root().join("raeva.lock"));
        project.raeva(&[options, &["sync", "--offline"]].concat())
    };
    let sync = |line: &str, dependencies: &str| sync_with(line, dependencies, &[]);
    let packages = || {
        let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).expect("lock");
        let mut packages: Vec<String> = (lock.platforms[0].modules[0].packages.iter())
            .map(|package| package.coordinate.to_string())
            .collect();
        packages.sort();
        packages
    };
    let transitive = [
        dependency("dep", ""),
        dependency("own", ""),
        dependency("child", ""),
    ]
    .concat();
    assert_success(&sync("3.10", &transitive), "3.10 dependency POMs");
    assert_eq!(
        packages(),
        [
            "org.test:child:1:jar",
            "org.test:dep:1:jar",
            "org.test:other:1:jar",
            "org.test:own:1:jar",
            "org.test:rep-UTF-8:1:jar",
            "org.test:sub-ISO-8859-1:1:jar",
            "org.test:sub-US-ASCII:1:jar",
            "org.test:sub-UTF-8:1:jar",
        ]
    );
    let classifier = dependency(
        "cl",
        "<classifier>${project.build.sourceEncoding}</classifier>",
    );
    assert_success(&sync("3.10", &classifier), "3.10 classifier");
    assert_eq!(packages(), ["org.test:cl:1:jar:UTF-8"]);
    let versioned = dependency("versioned", "");
    assert_success(&sync("3.10", &versioned), "3.10 parent version");
    assert_eq!(
        packages(),
        ["org.test:leaf:1:jar", "org.test:versioned:1:jar"]
    );
    // A `-D` value wins in the project's model; a dependency's model reads
    // its own properties and the super POM's only.
    let both = [classifier.clone(), dependency("dep", "")].concat();
    let define = ["-Dproject.build.sourceEncoding=X"];
    assert_success(&sync_with("3.10", &both, &define), "3.10 with a -D value");
    assert_eq!(
        packages(),
        [
            "org.test:cl:1:jar:X",
            "org.test:dep:1:jar",
            "org.test:other:1:jar",
            "org.test:rep-UTF-8:1:jar",
            "org.test:sub-UTF-8:1:jar",
        ]
    );

    assert_success(&sync("3.9", &transitive), "3.9 dependency POMs");
    assert_eq!(
        packages(),
        [
            "org.test:child:1:jar",
            "org.test:dep:1:jar",
            "org.test:own:1:jar",
            "org.test:sub-ISO-8859-1:1:jar",
            "org.test:sub-US-ASCII:1:jar",
        ]
    );
    assert_status(&sync("3.9", &classifier), 5, "3.9 classifier");
}

/// Maven 3.9.12 and 3.10.0 take a fetched parent or imported BOM whatever
/// coordinates it declares. raeva refuses one that declares others, but
/// not one whose coordinate is an expression its lineage leaves unresolved:
/// `${project.build.sourceEncoding}`, which only 3.10's super POM sets, or a
/// property nothing sets.
#[test]
fn an_unresolved_coordinate_of_a_fetched_parent_is_no_mismatch() {
    let project = Project::with(&[]);
    let pom = |artifact: &str, version: &str, body: &str| {
        let path = format!("repository/org/test/{artifact}/{version}/{artifact}-{version}.pom");
        let declared = match version {
            "UTF-8" => "${project.build.sourceEncoding}",
            "X1" => "${undefined.x}",
            "B1" => "${undefined.y}",
            "1" if artifact == "literal" => "9",
            "1" if artifact == "named" => "${project.artifactId}",
            _ => "${v}",
        };
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>{declared}</version>\
             <packaging>pom</packaging>{body}</project>"
        );
        write_with_sha256(&project.root().join(path), pom.as_bytes());
    };
    pom("encoded", "UTF-8", "");
    pom("unset", "X1", "");
    pom("literal", "1", "");
    pom("other", "1", "<properties><v>2</v></properties>");
    pom("named", "1", "");
    pom(
        "bom",
        "B1",
        "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>leaf</artifactId><version>1</version></dependency></dependencies>\
         </dependencyManagement>",
    );
    project.publish("org.test:leaf:1", "");
    for (child, parent, version) in [
        ("a", "encoded", "UTF-8"),
        ("b", "unset", "X1"),
        ("c", "literal", "1"),
        ("d", "other", "1"),
        ("e", "named", "1"),
    ] {
        project.publish(
            &format!("org.test:{child}:1"),
            &format!(
                "<parent><groupId>org.test</groupId><artifactId>{parent}</artifactId>\
                 <version>{version}</version><relativePath/></parent><dependencies>\
                 <dependency><groupId>org.test</groupId><artifactId>leaf</artifactId>\
                 <version>1</version></dependency></dependencies>"
            ),
        );
    }
    let sync = |line: &str, body: &str| {
        fs::write(
            project.root().join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><repositories><repository>\
                 <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
                 </repository></repositories>{body}</project>"
            ),
        )
        .expect("write pom");
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{line}\"\n"),
        )
        .expect("toml");
        let _ = fs::remove_file(project.root().join("raeva.lock"));
        project.raeva(&["sync", "--offline"])
    };
    let depend = |artifact: &str, version: &str| {
        format!(
            "<dependencies><dependency><groupId>org.test</groupId><artifactId>{artifact}\
             </artifactId>{version}</dependency></dependencies>"
        )
    };
    let packages = || {
        let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).expect("lock");
        let mut packages: Vec<String> = (lock.platforms[0].modules[0].packages.iter())
            .map(|package| package.coordinate.to_string())
            .collect();
        packages.sort();
        packages
    };
    let import = "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
                  <artifactId>bom</artifactId><version>B1</version><type>pom</type>\
                  <scope>import</scope></dependency></dependencies></dependencyManagement>";
    for line in ["3.9", "3.10"] {
        for child in ["a", "b"] {
            let body = depend(child, "<version>1</version>");
            assert_success(&sync(line, &body), &format!("{line} {child}"));
            let packages = packages();
            assert_eq!(
                packages,
                [
                    format!("org.test:{child}:1:jar"),
                    "org.test:leaf:1:jar".to_string()
                ],
                "{line}"
            );
        }
        let body = format!("{import}{}", depend("leaf", ""));
        assert_success(&sync(line, &body), &format!("{line} BOM"));
        assert_eq!(packages(), ["org.test:leaf:1:jar"], "{line}");
        // A parent that names another version is still refused, one named
        // by its own model too.
        for child in ["c", "d", "e"] {
            let output = sync(line, &depend(child, "<version>1</version>"));
            assert_status(&output, 5, &format!("{line} {child}"));
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("coordinate mismatch"), "{stderr}");
        }
    }
}

/// Publishes `org.test:lib:version` in the file repository `dir`, listed
/// alone in its metadata.
fn publish_lib_version(dir: &std::path::Path, version: &str) {
    let lib = dir.join("org/test/lib");
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>lib</artifactId><version>{version}</version></project>"
    );
    write_with_sha256(
        &lib.join(format!("{version}/lib-{version}.pom")),
        pom.as_bytes(),
    );
    write_with_sha256(
        &lib.join(format!("{version}/lib-{version}.jar")),
        version.as_bytes(),
    );
    let metadata = format!(
        "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId><versioning>\
         <versions><version>{version}</version></versions></versioning></metadata>"
    );
    write_with_sha256(&lib.join("maven-metadata.xml"), metadata.as_bytes());
}

/// Maven 3.10.0's file transporter reads a repository URL of
/// `symlink+file:` or `hardlink+file:` as the `file:` URL after the
/// prefix, and one without a scheme or whose scheme is an uppercase letter,
/// such as `C:/srv/repo`, as the path after the letter, `/srv/repo`, and
/// Maven 3.9.12 and 3.10.0 read a relative `file:` path under the
/// directory `mvn` runs in, here the project. The 3.10 mode reads them so,
/// in settings.xml and in the POM alike, locks their files under that
/// `file:` URL, and checks and exports the lock. Mirror patterns still read
/// the URL as written, so `external:*` takes it as Maven does. Maven 3.9.12
/// and `bundle:` read none: the repository is skipped with a warning.
#[test]
fn the_maven_310_mode_reads_the_file_transporters_urls() {
    let outside = tempfile::TempDir::new().expect("outside");
    let (r2, r3) = (outside.path().join("r2"), outside.path().join("r3"));
    publish_lib_version(&r2, "2.0");
    publish_lib_version(&r3, "2.5");
    let r2_url = url::Url::from_directory_path(&r2).unwrap().to_string();
    let r3_url = url::Url::from_directory_path(&r3).unwrap().to_string();
    let path = r2_url.strip_prefix("file://").unwrap();
    let project = Project::with(&[]);
    publish_lib_version(&project.root().join("r1"), "1.0");
    publish_lib_version(&project.root().join("rel"), "2.0");
    let sync = |in_pom: bool, line: &str, url: &str, mirror: Option<&str>| {
        let mirror = mirror.map_or(String::new(), |of| {
            format!(
                "<mirrors><mirror><id>m</id><mirrorOf>{of}</mirrorOf><url>{r3_url}</url>\
                 </mirror></mirrors>"
            )
        });
        let repository = format!("<repository><id>local-m2</id><url>{url}</url></repository>");
        let (in_settings, in_pom) = match in_pom {
            true => (String::new(), repository),
            false => (repository, String::new()),
        };
        fs::write(
            project.m2_settings(),
            format!(
                "<settings><profiles><profile><id>p</id><activation><activeByDefault>true\
                 </activeByDefault></activation><repositories>{in_settings}</repositories>\
                 </profile></profiles>{mirror}</settings>"
            ),
        )
        .unwrap();
        fs::write(
            project.root().join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><repositories><repository>\
                 <id>r1</id><url>file://${{project.basedir}}/r1/</url></repository>{in_pom}\
                 </repositories><dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>lib</artifactId><version>[1.0,3.0)</version></dependency>\
                 </dependencies></project>"
            ),
        )
        .unwrap();
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{line}\"\n"),
        )
        .unwrap();
        let _ = fs::remove_file(project.root().join("raeva.lock"));
        project.raeva(&["--json", "sync", "--offline"])
    };
    let locked = || {
        let lock = rv_lock::Lockfile::read(&project.root().join("raeva.lock")).expect("lock");
        let artifact = &lock.platforms[0].artifacts[0];
        (
            artifact.coordinate.version().to_string(),
            artifact.repo_url.clone(),
        )
    };
    let ignored = |in_pom: bool, output: &std::process::Output| {
        let code = match in_pom {
            true => "REPOSITORY_IGNORED",
            false => "SETTING_IGNORED",
        };
        String::from_utf8_lossy(&output.stdout).contains(code)
    };
    let mut read = vec![
        format!("symlink+{r2_url}"),
        format!("hardlink+{r2_url}"),
        format!("symlink+file:{path}"),
    ];
    if cfg!(unix) {
        read.push(format!("C:{path}"));
        read.push(format!("hardlink+Z:{path}"));
        read.push(path.to_string());
    } else {
        // `C:/dir` and `C:\dir`, as Maven 3.10.0 reads them on Windows: a
        // path on the drive `mvn` runs on, here the project's.
        let native = r2.to_str().unwrap();
        let (drive, rest) = native.split_at(2);
        read.push(format!("{}{rest}", drive.to_uppercase()));
        read.push(format!(
            "{}{}",
            drive.to_uppercase(),
            rest.replace('\\', "/")
        ));
    }
    let check = |what: &str, origin: &str, version: &str| {
        assert_eq!(
            locked(),
            (version.to_string(), origin.to_string()),
            "{what}"
        );
        let m2 = project.root().join("m2");
        for args in [
            &["sync", "--frozen", "--offline"][..],
            &["export-m2", "--m2-path", m2.to_str().unwrap()],
        ] {
            assert_success(&project.raeva(args), &format!("{what} {args:?}"));
        }
        let jar = format!("m2/org/test/lib/{version}/lib-{version}.jar");
        assert!(project.root().join(jar).is_file(), "{what}");
        fs::remove_dir_all(project.root().join("m2")).unwrap();
    };
    for in_pom in [false, true] {
        for url in &read {
            let what = format!("{url} in the POM: {in_pom}");
            let output = sync(in_pom, "3.10", url, None);
            assert_success(&output, &what);
            assert!(!ignored(in_pom, &output), "{what}");
            let origin = crate::common::recorded_origin(&project.root(), &r2_url);
            check(&what, &origin, "2.0");
            let external = Some("external:*,!central");
            assert_success(&sync(in_pom, "3.10", url, external), &what);
            assert_eq!(locked().0, "2.5", "{what} external:*,!central");
            let output = sync(in_pom, "3.9", url, None);
            assert_success(&output, &what);
            assert!(ignored(in_pom, &output), "{what}");
            assert_eq!(locked().0, "1.0", "{what} 3.9");
        }
        // A `file:` repository is no external one.
        let external = Some("external:*,!central");
        assert_success(&sync(in_pom, "3.10", &r2_url, external), "file:");
        assert_eq!(locked().0, "2.0");
        for url in [
            format!("bundle:{r2_url}"),
            format!("c:{path}"),
            "symlink+https://repo.example/".to_string(),
        ] {
            let output = sync(in_pom, "3.10", &url, None);
            assert_success(&output, &url);
            assert!(ignored(in_pom, &output), "{url}");
            assert_eq!(locked().0, "1.0", "{url}");
        }
        // A relative path is under the project, which records it so.
        for (line, url) in [
            ("3.10", "C:rel"),
            ("3.10", "symlink+file:rel"),
            ("3.10", "rel"),
            ("3.10", "file:rel"),
            ("3.9", "file:rel"),
            ("3.9", "file:./rel/"),
        ] {
            let what = format!("{url} {line} in the POM: {in_pom}");
            assert_success(&sync(in_pom, line, url, None), &what);
            check(&what, "./rel/", "2.0");
        }
    }
    // Maven 3.10's repository filters read the URL as written, so the lock
    // does too.
    assert_success(&sync(false, "3.10", &read[0], None), "symlink+file:");
    let settings = fs::read_to_string(project.m2_settings()).unwrap();
    fs::write(project.m2_settings(), settings.replace(&read[0], &r2_url)).unwrap();
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        7,
        "the URL as written changed",
    );
}

/// A settings.xml profile only another platform activates is read there as
/// one the host activates. Its `symlink+file:` repository serves lib 2.0,
/// which Maven 3.10.0 reads and Maven 3.9.12 has no transport for, and its
/// `https://[::1` one Maven 3.10.0 skips with a warning; Maven 3.9.12 fails
/// the build once a request reaches it, which raeva skips in both modes.
/// So a sync for that platform warns of each URL raeva does not read and
/// sends no request to one.
#[test]
fn another_platforms_settings_urls_are_checked_there() {
    let (other, family) = match cfg!(windows) {
        true => ("linux-x86_64", "unix"),
        false => ("windows-x86_64", "windows"),
    };
    let host = match cfg!(windows) {
        true => "windows-x86_64",
        false => "linux-x86_64",
    };
    let outside = tempfile::TempDir::new().expect("outside");
    let r2 = outside.path().join("r2");
    publish_lib_version(&r2, "2.0");
    let r2_url = url::Url::from_directory_path(&r2).unwrap().to_string();
    let project = Project::with(&[]);
    publish_lib_version(&project.root().join("r1"), "1.0");
    fs::write(
        project.root().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><repositories><repository>\
         <id>r1</id><url>file://${project.basedir}/r1/</url></repository></repositories>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
         <version>[1.0,3.0)</version></dependency></dependencies></project>",
    )
    .unwrap();
    fs::write(
        project.m2_settings(),
        format!(
            "<settings><profiles><profile><id>p</id><activation><os><family>{family}\
             </family></os></activation><repositories><repository><id>local-m2</id>\
             <url>symlink+{r2_url}</url></repository><repository><id>broken</id>\
             <url>https://[::1</url></repository></repositories></profile></profiles>\
             </settings>"
        ),
    )
    .unwrap();
    let sync = |line: &str, platform: &str| {
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{line}\"\n"),
        )
        .unwrap();
        let _ = fs::remove_file(project.root().join("raeva.lock"));
        let output = project.raeva(&["--json", "sync", "--platforms", platform]);
        assert_success(&output, &format!("{line} {platform}"));
        let frozen = project.raeva(&["sync", "--frozen", "--platforms", platform]);
        assert_success(&frozen, &format!("{line} {platform}, frozen"));
        output
    };
    let ignored = |output: &std::process::Output| {
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
        let mut entries: Vec<_> = (json["data"]["warnings"].as_array().into_iter().flatten())
            .filter(|warning| warning["code"] == "SETTING_IGNORED")
            .map(|warning| {
                let message = warning["message"].as_str().unwrap_or_default();
                ["'broken'", "'local-m2'"]
                    .into_iter()
                    .find(|id| message.contains(id))
                    .unwrap_or(message)
                    .to_string()
            })
            .collect();
        entries.sort();
        entries
    };
    let lib = || {
        let lock = fs::read_to_string(project.root().join("raeva.lock")).expect("lock");
        ["1.0", "2.0"]
            .into_iter()
            .find(|version| lock.contains(&format!("org.test:lib:{version}")))
            .unwrap_or("none")
    };

    let output = sync("3.10", other);
    assert_eq!(ignored(&output), ["'broken'"]);
    assert_eq!(lib(), "2.0");

    let output = sync("3.9", other);
    assert_eq!(ignored(&output), ["'broken'", "'local-m2'"]);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("builder error"));
    assert_eq!(lib(), "1.0");

    // On the host's platform the profile is inactive.
    for line in ["3.9", "3.10"] {
        let output = sync(line, host);
        assert!(ignored(&output).is_empty(), "{line}");
        assert_eq!(lib(), "1.0", "{line}");
    }
}

/// Maven 3.9 warns of a dependency a POM declares twice, in its words, and
/// builds with the last declaration; a parent that each module reads warns
/// once, and `--quiet` hides it, as `mvn -q` does.
#[test]
fn maven_39_warns_once_of_a_dependency_declared_twice() {
    use rv_test_support::http::{Response, StubServer};
    const LIB: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
                       <artifactId>lib</artifactId><version>1</version></project>";
    let server = StubServer::start(|request| match request.path.as_str() {
        "/test/lib/1/lib-1.pom" => Response::new(200, LIB),
        "/test/lib/1/lib-1.pom.sha1" => Response::new(200, crate::common::sha1_hex(LIB.as_bytes())),
        "/test/lib/1/lib-1.jar" => Response::new(200, "jar"),
        "/test/lib/1/lib-1.jar.sha1" => Response::new(200, crate::common::sha1_hex(b"jar")),
        _ => Response::new(404, ""),
    });
    let project = tempfile::TempDir::new().unwrap();
    let lib = "<dependency><groupId>test</groupId><artifactId>lib</artifactId>\
               <version>1</version></dependency>";
    fs::write(
        project.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module><module>b</module></modules>\
             <dependencies>{lib}{lib}</dependencies></project>"
        ),
    )
    .unwrap();
    for module in ["a", "b"] {
        fs::create_dir_all(project.path().join(module)).unwrap();
        fs::write(
            project.path().join(module).join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
                 <artifactId>parent</artifactId><version>1</version></parent>\
                 <artifactId>{module}</artifactId></project>"
            ),
        )
        .unwrap();
    }
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[lock]\nmaven = \"3.9\"\n\n[[repositories]]\nid = \"central\"\nurl = \"http://{}/\"\n",
            server.addr()
        ),
    )
    .unwrap();
    let home = tempfile::TempDir::new().unwrap();
    let warning = "'dependencies.dependency.(groupId:artifactId:type:classifier)' must be \
                   unique: test:lib:jar -> duplicate declaration of version 1";
    let synced = crate::common::run_raeva(project.path(), home.path(), &["sync"]);
    assert_success(&synced, "sync");
    let stderr = String::from_utf8_lossy(&synced.stderr);
    assert_eq!(stderr.matches(warning).count(), 1, "{stderr}");
    assert!(stderr.contains("warning: "), "{stderr}");

    fs::remove_file(project.path().join("raeva.lock")).unwrap();
    let quiet = crate::common::run_raeva(project.path(), home.path(), &["--quiet", "sync"]);
    assert_success(&quiet, "sync --quiet");
    let stderr = String::from_utf8_lossy(&quiet.stderr);
    assert!(!stderr.contains("must be unique"), "{stderr}");
}
