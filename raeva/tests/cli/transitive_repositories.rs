//! Repositories a dependency's POM declares.

use std::fs;

use crate::common::{
    assert_status, assert_success, pom, raeva_command, run_raeva, serve_sha256, with_sha1,
    write_repo_toml, write_with_sha256,
};
use rv_test_support::http::{Response, StubServer};

fn dependency(artifact: &str, extra: &str) -> String {
    format!(
        "<dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
<version>1</version>{extra}</dependency>"
    )
}

fn import(bom: &str) -> String {
    format!(
        "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
        dependency(bom, "<type>pom</type><scope>import</scope>")
    )
}

/// `/r1/` serves `a` and `d`; `/rx/` serves `a`'s parent `p` and `d`'s
/// dependency `b`. `a` declares `/rx/`, and its own dependency on a
/// `system` artifact has no `<systemPath>`, so its descriptor is invalid.
fn spawn_repositories() -> StubServer {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let rx = format!("http://{}/rx/", address.get().expect("address"));
        with_sha1(
            &request.path,
            [
                (
                    "/r1/t/a/1/a-1.pom",
                    pom(
                        "a",
                        &format!(
                            "<parent><groupId>t</groupId><artifactId>p</artifactId>\
<version>1</version></parent><repositories><repository><id>rx</id><url>{rx}</url>\
</repository></repositories><dependencies>{}</dependencies>",
                            dependency("sys", "<scope>system</scope>")
                        ),
                    ),
                ),
                ("/r1/t/a/1/a-1.jar", "a jar".to_string()),
                ("/rx/t/p/1/p-1.pom", pom("p", "<packaging>pom</packaging>")),
                (
                    "/r1/t/d/1/d-1.pom",
                    pom(
                        "d",
                        &format!("<dependencies>{}</dependencies>", dependency("b", "")),
                    ),
                ),
                ("/r1/t/d/1/d-1.jar", "d jar".to_string()),
                ("/rx/t/b/1/b-1.pom", pom("b", "")),
                ("/rx/t/b/1/b-1.jar", "b jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    server
}

/// Maven searches the repositories of a descriptor it finds invalid only
/// while building that descriptor: `a`'s parent comes from `/rx/`, but `b`
/// is not looked up there.
#[test]
fn an_invalid_descriptors_repositories_serve_only_its_own_build() {
    let server = spawn_repositories();
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_transitive_repositories = true\n",
    )
    .expect("write config.toml");
    std::fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dependency("a", ""),
                dependency("d", "")
            ),
        ),
    )
    .expect("write pom.xml");
    write_repo_toml(
        project.path(),
        "r1",
        &format!("http://{}/r1/", server.addr()),
    );

    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .arg("sync")
        .output()
        .expect("run raeva sync");
    assert_status(&output, 5, "invalid descriptor repositories");
    let requests: Vec<String> = server
        .requests()
        .into_iter()
        .map(|request| request.path)
        .collect();
    assert!(
        requests.iter().any(|path| path == "/rx/t/p/1/p-1.pom"),
        "{requests:?}"
    );
    assert!(
        !requests.iter().any(|path| path.starts_with("/rx/t/b/")),
        "{requests:?}"
    );
}

/// A dependency whose POM no repository has resolves without its
/// dependencies, as in Maven; when its jar is missing too, the error names
/// the ignored repository its declarer lists, which Maven would search.
#[test]
fn a_missing_pom_and_jar_name_the_ignored_repository_on_the_path() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let rx = format!("http://{}/rx/", address.get().expect("address"));
        with_sha1(
            &request.path,
            [
                (
                    "/r1/t/a/1/a-1.pom",
                    pom(
                        "a",
                        &format!(
                            "<repositories><repository><id>rx</id><url>{rx}</url>\
</repository></repositories><dependencies>{}</dependencies>",
                            dependency("b", "")
                        ),
                    ),
                ),
                ("/r1/t/a/1/a-1.jar", "a jar".to_string()),
                ("/rx/t/b/1/b-1.pom", pom("b", "")),
                ("/rx/t/b/1/b-1.jar", "b jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    let rx = format!("http://{}/rx/", server.addr());
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &format!("<dependencies>{}</dependencies>", dependency("a", "")),
        ),
    )
    .expect("write pom.xml");
    write_repo_toml(
        project.path(),
        "r1",
        &format!("http://{}/r1/", server.addr()),
    );

    let output = run_raeva(project.path(), home.path(), &["sync"]);
    assert_status(&output, 5, "missing POM and jar");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for expected in [
        "Dependency not found: t:b:1",
        "In pom.xml, through t:a:1\n",
        "Maven would search these for this artifact:",
        &format!("- {rx} (declared by t:a:1)"),
        "To use one, add it to raeva.toml.",
        &format!("url = \"{rx}\""),
    ] {
        assert!(stderr.contains(expected), "{expected}: {stderr}");
    }

    let output = run_raeva(project.path(), home.path(), &["--json", "sync"]);
    assert_status(&output, 5, "missing POM and jar, JSON");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(envelope["code"], "ARTIFACT_NOT_FOUND", "{envelope}");
    assert_eq!(
        envelope["location"],
        serde_json::json!({"module": "pom.xml", "via": ["t:a:1"]}),
        "{envelope}"
    );
    let error = envelope["error"].as_str().expect("error");
    for expected in [
        format!("- {rx} (declared by t:a:1)"),
        format!("url = \"{rx}\""),
    ] {
        assert!(error.contains(&expected), "{expected}: {error}");
    }
    assert!(
        !server
            .requests()
            .iter()
            .any(|request| request.path.starts_with("/rx/")),
        "an ignored repository is never searched"
    );
}

/// An admitted transitive repository serves the declaring POM's own
/// subtree, and not a sibling's dependencies, as in Maven.
#[test]
fn an_admitted_transitive_repository_serves_its_subtree_and_not_siblings() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let rx = format!("http://{}/rx/", address.get().expect("address"));
        with_sha1(
            &request.path,
            [
                (
                    "/r1/t/a/1/a-1.pom",
                    pom(
                        "a",
                        &format!(
                            "<repositories><repository><id>rx</id><url>{rx}</url>\
</repository></repositories><dependencies>{}</dependencies>",
                            dependency("x", "")
                        ),
                    ),
                ),
                ("/r1/t/a/1/a-1.jar", "a jar".to_string()),
                ("/rx/t/x/1/x-1.pom", pom("x", "")),
                ("/rx/t/x/1/x-1.jar", "x jar".to_string()),
                (
                    "/r1/t/b/1/b-1.pom",
                    pom(
                        "b",
                        &format!("<dependencies>{}</dependencies>", dependency("y", "")),
                    ),
                ),
                ("/r1/t/b/1/b-1.jar", "b jar".to_string()),
                ("/rx/t/y/1/y-1.pom", pom("y", "")),
                ("/rx/t/y/1/y-1.jar", "y jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    let rx = format!("http://{}/rx/", server.addr());
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        format!("[security]\ntransitive_repository_allowlist = [\"{rx}\"]\n"),
    )
    .expect("write config.toml");
    write_repo_toml(
        project.path(),
        "r1",
        &format!("http://{}/r1/", server.addr()),
    );

    std::fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dependency("a", ""),
                dependency("b", "")
            ),
        ),
    )
    .expect("write sibling pom.xml");
    let output = run_raeva(project.path(), home.path(), &["sync"]);
    assert_status(&output, 5, "sibling dependency in transitive repository");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Dependency not found: t:y:1"), "{stderr}");
    assert!(
        !server
            .requests()
            .iter()
            .any(|request| request.path.starts_with("/rx/t/y/")),
        "rx must not be searched for sibling's dependency y"
    );

    std::fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &format!("<dependencies>{}</dependencies>", dependency("a", "")),
        ),
    )
    .expect("write subtree pom.xml");
    let output = run_raeva(project.path(), home.path(), &["sync"]);
    assert_status(&output, 0, "subtree dependency in transitive repository");
    assert!(
        server
            .requests()
            .iter()
            .any(|request| request.path == "/rx/t/x/1/x-1.jar"),
        "rx must serve a's own dependency x"
    );
}

/// Maven 3.9 keeps the first descriptor it reads of an artifact, whatever
/// repositories a later path asks with. Depth first, `lib` is read below
/// `a2`, where no repository has its POM, so the `lib` that wins below `b`,
/// whose `rx` serves a POM declaring `m`, has no dependencies. Maven 3.10
/// reads the nearer `lib` below `b` first. Maven 3.9 reads a descriptor
/// per artifact type, so `lib` as a `maven-plugin` below `a2` leaves the
/// `lib` below `b` to be read from `rx`.
#[test]
fn maven_39_keeps_the_first_descriptor_of_an_artifact_it_reads() {
    for (lib_type, locks_m_39) in [("", false), ("<type>maven-plugin</type>", true)] {
        first_descriptor_of_an_artifact(lib_type, locks_m_39);
    }
}

fn first_descriptor_of_an_artifact(lib_type: &'static str, locks_m_39: bool) {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let rx = format!("http://{}/rx/", address.get().expect("address"));
        let depends = |artifact: &str, on: &str| {
            pom(
                artifact,
                &format!("<dependencies>{}</dependencies>", dependency(on, "")),
            )
        };
        with_sha1(
            &request.path,
            [
                ("/r1/t/a/1/a-1.pom", depends("a", "a2")),
                ("/r1/t/a/1/a-1.jar", "a jar".to_string()),
                (
                    "/r1/t/a2/1/a2-1.pom",
                    pom(
                        "a2",
                        &format!(
                            "<dependencies>{}</dependencies>",
                            dependency("lib", lib_type)
                        ),
                    ),
                ),
                ("/r1/t/a2/1/a2-1.jar", "a2 jar".to_string()),
                (
                    "/r1/t/b/1/b-1.pom",
                    pom(
                        "b",
                        &format!(
                            "<repositories><repository><id>rx</id><url>{rx}</url>\
</repository></repositories><dependencies>{}</dependencies>",
                            dependency("lib", "")
                        ),
                    ),
                ),
                ("/r1/t/b/1/b-1.jar", "b jar".to_string()),
                ("/rx/t/lib/1/lib-1.pom", depends("lib", "m")),
                ("/rx/t/lib/1/lib-1.jar", "lib jar".to_string()),
                ("/r1/t/m/1/m-1.pom", pom("m", "")),
                ("/r1/t/m/1/m-1.jar", "m jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    let rx = format!("http://{}/rx/", server.addr());
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        format!("[security]\ntransitive_repository_allowlist = [\"{rx}\"]\n"),
    )
    .expect("write config.toml");
    for (mode, locks_m) in [("3.9", locks_m_39), ("3.10", true)] {
        let project = tempfile::tempdir().expect("project");
        write_repo_toml(
            project.path(),
            "r1",
            &format!("http://{}/r1/", server.addr()),
        );
        let raeva_toml = project.path().join("raeva.toml");
        let mut config = fs::read_to_string(&raeva_toml).unwrap_or_default();
        config.push_str(&format!("\n[lock]\nmaven = \"{mode}\"\n"));
        fs::write(&raeva_toml, config).expect("write raeva.toml");
        fs::write(
            project.path().join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<dependencies>{}{}</dependencies>",
                    dependency("a", ""),
                    dependency("b", "")
                ),
            ),
        )
        .expect("write pom.xml");
        let output = run_raeva(project.path(), home.path(), &["sync"]);
        assert_status(&output, 0, mode);
        let lock = rv_lock::Lockfile::read(&project.path().join("raeva.lock")).unwrap();
        let artifacts: Vec<_> = (lock.platforms[0].modules[0].packages.iter())
            .map(|package| package.coordinate.artifact_id().to_string())
            .collect();
        assert_eq!(
            artifacts.contains(&"m".to_string()),
            locks_m,
            "{mode} {lib_type}: {artifacts:?}"
        );
        assert!(
            artifacts.contains(&"lib".to_string()),
            "{mode} {lib_type}: {artifacts:?}"
        );
    }
}

/// `b` declares `rb`, which alone has the parent of `x:1`, and `d`, where
/// `x` is asked for again, sees no `rb`. Whichever asks first reads `x`
/// with `rb`, and every collector builds: the breadth-first one keeps each
/// version a range read for a later declaration of it, and Maven's model
/// cache keeps the parent it read for every later build. It keeps the BOMs
/// it imported apart, so a `y` below `d` that imports that parent fails.
#[test]
fn a_model_read_through_one_path_serves_another() {
    for (below_b, below_d, status) in [("[1,2]", "1", 0), ("1", "[1,2]", 0), ("1", "import", 5)] {
        read_once(below_b, below_d, status);
    }
}

fn read_once(below_b: &'static str, below_d: &'static str, status: i32) {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let rb = format!("http://{}/rb/", address.get().expect("address"));
        let depends = |artifact: &str, on: &str, version: &str| {
            pom(
                artifact,
                &format!(
                    "<dependencies><dependency><groupId>t</groupId><artifactId>{on}</artifactId>\
<version>{version}</version></dependency></dependencies>"
                ),
            )
        };
        let b = depends("b", "x", below_b).replace(
            "<dependencies>",
            &format!("<repositories><repository><id>rb</id><url>{rb}</url></repository></repositories><dependencies>"),
        );
        with_sha1(
            &request.path,
            [
                ("/r1/t/b/1/b-1.pom", b),
                ("/r1/t/c/1/c-1.pom", depends("c", "d", "1")),
                (
                    "/r1/t/d/1/d-1.pom",
                    match below_d {
                        "import" => depends("d", "y", "1"),
                        _ => depends("d", "x", below_d),
                    },
                ),
                (
                    "/r1/t/y/1/y-1.pom",
                    pom(
                        "y",
                        "<dependencyManagement><dependencies><dependency><groupId>t</groupId>\
<artifactId>p</artifactId><version>1</version><type>pom</type><scope>import</scope>\
</dependency></dependencies></dependencyManagement>",
                    ),
                ),
                ("/r1/t/y/1/y-1.jar", "y jar".to_string()),
                (
                    "/r1/t/x/maven-metadata.xml",
                    "<metadata><groupId>t</groupId><artifactId>x</artifactId><versioning>\
<versions><version>1</version><version>2</version></versions></versioning></metadata>"
                        .to_string(),
                ),
                (
                    "/r1/t/x/1/x-1.pom",
                    "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
<artifactId>p</artifactId><version>1</version></parent><artifactId>x</artifactId></project>"
                        .to_string(),
                ),
                (
                    "/r1/t/x/2/x-2.pom",
                    pom("x", "").replace(">1</version>", ">2</version>"),
                ),
                ("/rb/t/p/1/p-1.pom", pom("p", "<packaging>pom</packaging>")),
                ("/r1/t/b/1/b-1.jar", "b jar".to_string()),
                ("/r1/t/c/1/c-1.jar", "c jar".to_string()),
                ("/r1/t/d/1/d-1.jar", "d jar".to_string()),
                ("/r1/t/x/1/x-1.jar", "x jar".to_string()),
                ("/r1/t/x/2/x-2.jar", "x jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "[security]\ntransitive_repository_allowlist = [\"http://{}/rb/\"]\n",
            server.addr()
        ),
    )
    .expect("write config.toml");
    for mode in ["3.9", "3.9-bf", "3.10"] {
        let project = tempfile::tempdir().expect("project");
        write_repo_toml(
            project.path(),
            "r1",
            &format!("http://{}/r1/", server.addr()),
        );
        let raeva_toml = project.path().join("raeva.toml");
        let mut config = fs::read_to_string(&raeva_toml).unwrap_or_default();
        let maven = mode.trim_end_matches("-bf");
        config.push_str(&format!("\n[lock]\nmaven = \"{maven}\"\n"));
        fs::write(&raeva_toml, config).expect("write raeva.toml");
        if mode.ends_with("-bf") {
            fs::create_dir_all(project.path().join(".mvn")).expect("mkdir .mvn");
            fs::write(
                project.path().join(".mvn/maven.config"),
                "-Daether.dependencyCollector.impl=bf\n",
            )
            .expect("write maven.config");
        }
        fs::write(
            project.path().join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<dependencies>{}{}</dependencies>",
                    dependency("b", ""),
                    dependency("c", "")
                ),
            ),
        )
        .expect("write pom.xml");
        let output = run_raeva(project.path(), home.path(), &["sync"]);
        assert_status(&output, status, &format!("{mode} {below_b} {below_d}"));
    }
}

/// The project imports `b`, which declares `rb` and has the parent `p` that
/// only `rb` has, and depends on `x`, whose parent is `p` too. Maven's model
/// cache serves `x` the parent the project's own build read.
#[test]
fn a_parent_the_projects_own_build_read_serves_its_dependencies() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let rb = format!("http://{}/rb/", address.get().expect("address"));
        let child = |artifact: &str, body: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
<artifactId>p</artifactId><version>1</version></parent><artifactId>{artifact}</artifactId>\
{body}</project>"
            )
        };
        let repositories = format!(
            "<packaging>pom</packaging><repositories><repository><id>rb</id><url>{rb}</url></repository></repositories>"
        );
        with_sha1(
            &request.path,
            [
                ("/r1/t/b/1/b-1.pom", child("b", &repositories)),
                ("/r1/t/x/1/x-1.pom", child("x", "")),
                ("/r1/t/x/1/x-1.jar", "x jar".to_string()),
                ("/rb/t/p/1/p-1.pom", pom("p", "<packaging>pom</packaging>")),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "[security]\ntransitive_repository_allowlist = [\"http://{}/rb/\"]\n",
            server.addr()
        ),
    )
    .expect("write config.toml");
    for mode in ["3.9", "3.10"] {
        let project = tempfile::tempdir().expect("project");
        write_repo_toml(
            project.path(),
            "r1",
            &format!("http://{}/r1/", server.addr()),
        );
        let raeva_toml = project.path().join("raeva.toml");
        let mut config = fs::read_to_string(&raeva_toml).unwrap_or_default();
        config.push_str(&format!("\n[lock]\nmaven = \"{mode}\"\n"));
        fs::write(&raeva_toml, config).expect("write raeva.toml");
        let import = dependency("b", "<type>pom</type><scope>import</scope>");
        fs::write(
            project.path().join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<dependencyManagement><dependencies>{import}</dependencies>\
</dependencyManagement><dependencies>{}</dependencies>",
                    dependency("x", "")
                ),
            ),
        )
        .expect("write pom.xml");
        let output = run_raeva(project.path(), home.path(), &["sync"]);
        assert_status(&output, 0, mode);
    }
}

/// Maven caches a parent by the version text its child names and looks
/// there before it resolves a range (DefaultModelBuilder:816). `x` and `y`
/// both name `p:[1,2]`. With `r1`, which lists `p:1`, and `rc`, which lists
/// `p:2` too, `x` is read first and `y` keeps `p:1`, so `p:2`'s `z` is not
/// locked. With `y` on `r1` alone, which lists no `p`, it takes `p:1` that
/// `x` read through `rb`, and so does `w` after it; the breadth-first 3.10
/// collector reads `y` before `x` and fails, as Maven 3.10.0 does.
///
/// The cache is the reactor's: with `x` in module `m1` and `c` in `m2`,
/// `y` keeps `p:1` when Maven sorts `m1` first and takes `p:2` otherwise.
#[test]
fn a_ranged_parent_keeps_the_version_the_module_read_first() {
    let (one, two): (&[&str], &[&str]) = (&["x"], &["c"]);
    for (through_b, modules, expected) in [
        (false, &[&["x", "c"][..]][..], [(0, false), (0, false)]),
        (true, &[&["b", "y", "w"]], [(0, false), (5, false)]),
        (false, &[one, two], [(0, false), (0, false)]),
        (false, &[two, one], [(0, true), (0, true)]),
    ] {
        ranged_parent(through_b, modules, expected);
    }
}

/// `modules` lists each module's dependencies; one is the root project.
fn ranged_parent(through_b: bool, modules: &[&[&str]], expected: [(i32, bool); 2]) {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let url = address.get().expect("address");
        let declares = |id: &str, on: &str| {
            format!(
                "<repositories><repository><id>{id}</id><url>http://{url}/{id}/</url>\
</repository></repositories><dependencies>{}</dependencies>",
                dependency(on, "")
            )
        };
        let child = |artifact: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
<artifactId>p</artifactId><version>[1,2]</version></parent><artifactId>{artifact}</artifactId>\
<version>1</version></project>"
            )
        };
        let metadata = |versions: &[&str]| {
            format!(
                "<metadata><groupId>t</groupId><artifactId>p</artifactId><versioning><versions>{}\
</versions></versioning></metadata>",
                (versions.iter())
                    .map(|version| format!("<version>{version}</version>"))
                    .collect::<String>()
            )
        };
        let p = pom("p", "<packaging>pom</packaging>");
        let p2 = pom(
            "p",
            &format!(
                "<packaging>pom</packaging><dependencies>{}</dependencies>",
                dependency("z", "")
            ),
        )
        .replace(">1</version><packaging>", ">2</version><packaging>");
        let files = vec![
            ("/r1/t/x/1/x-1.pom", child("x")),
            ("/r1/t/y/1/y-1.pom", child("y")),
            ("/r1/t/w/1/w-1.pom", child("w")),
            ("/r1/t/b/1/b-1.pom", pom("b", &declares("rb", "x"))),
            ("/r1/t/c/1/c-1.pom", pom("c", &declares("rc", "y"))),
            ("/r1/t/z/1/z-1.pom", pom("z", "")),
            ("/rb/t/p/maven-metadata.xml", metadata(&["1"])),
            ("/rb/t/p/1/p-1.pom", p.clone()),
            ("/rc/t/p/maven-metadata.xml", metadata(&["1", "2"])),
            ("/rc/t/p/1/p-1.pom", p.clone()),
            ("/rc/t/p/2/p-2.pom", p2),
        ];
        let mut files: Vec<(String, String)> = (files.into_iter())
            .map(|(path, body)| (path.to_string(), body))
            .collect();
        if !through_b {
            files.push(("/r1/t/p/maven-metadata.xml".to_string(), metadata(&["1"])));
            files.push(("/r1/t/p/1/p-1.pom".to_string(), p));
        }
        for artifact in ["x", "y", "w", "b", "c", "z"] {
            let path = format!("/r1/t/{artifact}/1/{artifact}-1.jar");
            files.push((path, "jar".to_string()));
        }
        with_sha1(&request.path, files)
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_transitive_repositories = true\n",
    )
    .expect("write config.toml");
    for (mode, (status, z)) in ["3.9", "3.10"].into_iter().zip(expected) {
        let project = tempfile::tempdir().expect("project");
        write_repo_toml(
            project.path(),
            "r1",
            &format!("http://{}/r1/", server.addr()),
        );
        let raeva_toml = project.path().join("raeva.toml");
        let mut config = fs::read_to_string(&raeva_toml).unwrap_or_default();
        config.push_str(&format!("\n[lock]\nmaven = \"{mode}\"\n"));
        fs::write(&raeva_toml, config).expect("write raeva.toml");
        let declares = |on: &[&str]| {
            let declared: String = on.iter().map(|on| dependency(on, "")).collect();
            format!("<dependencies>{declared}</dependencies>")
        };
        let root = match modules {
            [only] => declares(only),
            _ => {
                let mut listed = String::new();
                for (index, on) in modules.iter().enumerate() {
                    let module = format!("m{index}");
                    let dir = project.path().join(&module);
                    fs::create_dir_all(&dir).expect("mkdir module");
                    fs::write(dir.join("pom.xml"), pom(&module, &declares(on)))
                        .expect("write module");
                    listed.push_str(&format!("<module>{module}</module>"));
                }
                format!("<packaging>pom</packaging><modules>{listed}</modules>")
            }
        };
        fs::write(project.path().join("pom.xml"), pom("app", &root)).expect("write pom.xml");
        let output = run_raeva(project.path(), home.path(), &["sync"]);
        let case = format!("{mode} {through_b} {modules:?}");
        assert_status(&output, status, &case);
        if status == 0 {
            let lock = fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
            assert_eq!(lock.contains("t:z:1"), z, "{case}: {lock}");
        }
    }
}

/// A parent range that took the reactor module `p:1` keeps it for every
/// later child naming the range, as Maven's model cache does: `y`, below
/// `c`, whose `rc` lists `p:2` too, gets `p:1`, so `p:2`'s `z` is not locked.
#[test]
fn a_parent_range_that_took_a_reactor_module_keeps_it() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let rc = format!("http://{}/rc/", address.get().expect("address"));
        let child = |artifact: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
<artifactId>p</artifactId><version>[1,2]</version></parent><artifactId>{artifact}</artifactId>\
<version>1</version></project>"
            )
        };
        let p2 = pom(
            "p",
            &format!(
                "<packaging>pom</packaging><dependencies>{}</dependencies>",
                dependency("z", "")
            ),
        )
        .replace(">1</version><packaging>", ">2</version><packaging>");
        with_sha1(
            &request.path,
            [
                ("/r1/t/x/1/x-1.pom", child("x")),
                ("/r1/t/y/1/y-1.pom", child("y")),
                (
                    "/r1/t/c/1/c-1.pom",
                    pom(
                        "c",
                        &format!(
                            "<repositories><repository><id>rc</id><url>{rc}</url></repository>\
</repositories><dependencies>{}</dependencies>",
                            dependency("y", "")
                        ),
                    ),
                ),
                ("/r1/t/z/1/z-1.pom", pom("z", "")),
                (
                    "/rc/t/p/maven-metadata.xml",
                    "<metadata><groupId>t</groupId><artifactId>p</artifactId><versioning><versions>\
<version>1</version><version>2</version></versions></versioning></metadata>"
                        .to_string(),
                ),
                ("/rc/t/p/1/p-1.pom", pom("p", "<packaging>pom</packaging>")),
                ("/rc/t/p/2/p-2.pom", p2),
                ("/r1/t/x/1/x-1.jar", "jar".to_string()),
                ("/r1/t/y/1/y-1.jar", "jar".to_string()),
                ("/r1/t/c/1/c-1.jar", "jar".to_string()),
                ("/r1/t/z/1/z-1.jar", "jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_transitive_repositories = true\n",
    )
    .expect("write config.toml");
    for mode in ["3.9", "3.10"] {
        let project = tempfile::tempdir().expect("project");
        let root = project.path();
        write_repo_toml(root, "r1", &format!("http://{}/r1/", server.addr()));
        let raeva_toml = root.join("raeva.toml");
        let mut config = fs::read_to_string(&raeva_toml).unwrap_or_default();
        config.push_str(&format!("\n[lock]\nmaven = \"{mode}\"\n"));
        fs::write(&raeva_toml, config).expect("write raeva.toml");
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                "<packaging>pom</packaging><modules><module>p</module><module>m</module></modules>",
            ),
        )
        .expect("write pom.xml");
        for (module, body) in [
            ("p", "<packaging>pom</packaging>".to_string()),
            (
                "m",
                format!(
                    "<dependencies>{}{}</dependencies>",
                    dependency("x", ""),
                    dependency("c", "")
                ),
            ),
        ] {
            fs::create_dir_all(root.join(module)).expect("mkdir module");
            fs::write(root.join(module).join("pom.xml"), pom(module, &body)).expect("write module");
        }
        let output = run_raeva(root, home.path(), &["sync"]);
        assert_status(&output, 0, mode);
        let lock = fs::read_to_string(root.join("raeva.lock")).expect("lock");
        assert!(
            lock.contains("t:y:1") && !lock.contains("t:z:1"),
            "{mode}: {lock}"
        );
    }
}

/// Module `a` declares the repository `low`, which alone serves `three`.
/// As in Maven, `low` serves `a`'s own dependencies when `b` depends on
/// `a`, but not `b`'s.
#[test]
fn a_reactor_dependencys_repositories_serve_only_its_own_dependencies() {
    for (a_needs, b_needs, resolves) in [(true, false, true), (false, true, false)] {
        let base = tempfile::TempDir::new().expect("base");
        let root = base.path();
        let dir = root.join("low/t/three/1");
        fs::create_dir_all(&dir).expect("repository");
        for (name, bytes) in [
            ("three-1.pom", pom("three", "").into_bytes()),
            ("three-1.jar", b"jar".to_vec()),
        ] {
            write_with_sha256(&dir.join(name), &bytes);
        }
        let low = url::Url::from_directory_path(root.join("low")).expect("url");
        let needs = |needed: bool| match needed {
            true => dependency("three", ""),
            false => String::new(),
        };
        let project = root.join("project");
        for (path, text) in [
            (
                "pom.xml",
                pom(
                    "root",
                    "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                     </modules>",
                ),
            ),
            (
                "a/pom.xml",
                pom(
                    "a",
                    &format!(
                        "<repositories><repository><id>low</id><url>{low}</url></repository>\
                         </repositories><dependencies>{}</dependencies>",
                        needs(a_needs)
                    ),
                ),
            ),
            (
                "b/pom.xml",
                pom(
                    "b",
                    &format!(
                        "<dependencies>{}{}</dependencies>",
                        dependency("a", ""),
                        needs(b_needs)
                    ),
                ),
            ),
        ] {
            let path = project.join(path);
            fs::create_dir_all(path.parent().unwrap()).expect("module");
            fs::write(path, text).expect("pom");
        }
        let home = tempfile::TempDir::new().expect("home");
        let sync = run_raeva(&project, home.path(), &["sync", "--offline"]);
        let stderr = String::from_utf8_lossy(&sync.stderr);
        assert_eq!(sync.status.success(), resolves, "{stderr}");
        if !resolves {
            assert!(stderr.contains("t:three:1"), "{stderr}");
        }
    }
}

/// Module `c` declares a plain HTTP repository `low`, which is refused, and
/// `a` declares its own `low`, which alone serves `three`. `b` depends on
/// both: `c`'s refusal does not keep `a`'s repository from `a`'s subtree,
/// while a `low` of `b`'s own does, as Maven keeps the project's.
#[test]
fn a_refused_repository_of_one_module_leaves_anothers_of_that_id() {
    for own in [false, true] {
        assert_refused_repository_leaves_anothers(own);
    }
}

fn assert_refused_repository_leaves_anothers(own: bool) {
    let base = tempfile::TempDir::new().expect("base");
    let root = base.path();
    let dir = root.join("low/t/three/1");
    fs::create_dir_all(&dir).expect("repository");
    for (name, bytes) in [
        ("three-1.pom", pom("three", "").into_bytes()),
        ("three-1.jar", b"jar".to_vec()),
    ] {
        write_with_sha256(&dir.join(name), &bytes);
    }
    let low = url::Url::from_directory_path(root.join("low")).expect("url");
    fs::create_dir_all(root.join("empty")).expect("empty repository");
    let empty = url::Url::from_directory_path(root.join("empty")).expect("url");
    let repository = |url: &str| {
        format!(
            "<repositories><repository><id>low</id><url>{url}</url></repository></repositories>"
        )
    };
    let project = root.join("project");
    for (path, text) in [
        (
            "pom.xml",
            pom(
                "root",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                 <module>c</module></modules>",
            ),
        ),
        (
            "a/pom.xml",
            pom(
                "a",
                &format!(
                    "{}<dependencies>{}</dependencies>",
                    repository(low.as_str()),
                    dependency("three", "")
                ),
            ),
        ),
        (
            "b/pom.xml",
            pom(
                "b",
                &format!(
                    "{}<dependencies>{}{}</dependencies>",
                    if own {
                        repository(empty.as_str())
                    } else {
                        String::new()
                    },
                    dependency("c", ""),
                    dependency("a", "")
                ),
            ),
        ),
        (
            "c/pom.xml",
            pom("c", &repository("http://repo.invalid/low/")),
        ),
    ] {
        let path = project.join(path);
        fs::create_dir_all(path.parent().unwrap()).expect("module");
        fs::write(path, text).expect("pom");
    }
    let home = tempfile::TempDir::new().expect("home");
    let sync = run_raeva(&project, home.path(), &["sync", "--offline"]);
    assert_eq!(
        sync.status.success(),
        !own,
        "{}",
        String::from_utf8_lossy(&sync.stderr)
    );
}

/// A configured repository that answers 404 for everything, as one with a
/// wrong organization in its path does. As in Maven, a SNAPSHOT without
/// metadata is read at its base version, so both missing jars are reported,
/// the first declared first, and the hint points at the repository's URL
/// rather than at adding a repository.
#[test]
fn a_configured_repository_that_has_nothing_names_the_first_missing_artifact() {
    let server = StubServer::start(|_| rv_test_support::http::Response::new(404, ""));
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let url = format!("http://{}/maven/other/", server.addr());
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
<version>1</version></dependency><dependency><groupId>t</groupId><artifactId>slib</artifactId>\
<version>2-SNAPSHOT</version></dependency></dependencies>",
        ),
    )
    .expect("write pom.xml");
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"corp\"\nurl = \"{url}\"\nsnapshots = true\n\n\
[[repositories]]\nid = \"central\"\nurl = \"{url}\"\n"
        ),
    )
    .expect("write raeva.toml");

    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .arg("sync")
        .output()
        .expect("run raeva sync");
    assert_status(&output, 5, "nothing found");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lib = stderr.find("Dependency not found: t:lib:1\n");
    let slib = stderr.find("Also failed:\n    artifact not found: t:slib:2-SNAPSHOT\n");
    assert!(lib.is_some() && slib.is_some() && lib < slib, "{stderr}");
    assert!(
        stderr.contains("Check the URLs of the repositories searched"),
        "{stderr}"
    );
    assert!(!stderr.contains("add that repository"), "{stderr}");
}

/// Module `c` declares a plain HTTP repository `rx`, which is refused, and
/// `b` depends on `c` and on `a`, whose POM declares its own `rx`, which
/// alone serves `x`. As in Maven, `c`'s declaration stays in `c`'s subtree
/// and `a`'s `rx` serves `x`, whichever dependency comes first.
#[test]
fn a_modules_refused_repository_leaves_a_dependencys_of_that_id() {
    for c_first in [true, false] {
        let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
        let address = std::sync::Arc::clone(&own);
        let server = StubServer::start(move |request| {
            let rx = format!("http://{}/rx/", address.get().expect("address"));
            with_sha1(
                &request.path,
                [
                    (
                        "/r1/t/a/1/a-1.pom",
                        pom(
                            "a",
                            &format!(
                                "<repositories><repository><id>rx</id><url>{rx}</url>\
</repository></repositories><dependencies>{}</dependencies>",
                                dependency("x", "")
                            ),
                        ),
                    ),
                    ("/r1/t/a/1/a-1.jar", "a jar".to_string()),
                    ("/rx/t/x/1/x-1.pom", pom("x", "")),
                    ("/rx/t/x/1/x-1.jar", "x jar".to_string()),
                ],
            )
        });
        own.set(server.addr().to_string())
            .expect("address set once");
        let project = tempfile::tempdir().expect("project");
        let home = tempfile::tempdir().expect("home");
        fs::write(
            home.path().join("config.toml"),
            format!(
                "[security]\ntransitive_repository_allowlist = [\"http://{}/rx/\"]\n",
                server.addr()
            ),
        )
        .expect("write config.toml");
        write_repo_toml(
            project.path(),
            "r1",
            &format!("http://{}/r1/", server.addr()),
        );
        let (a, c) = (dependency("a", ""), dependency("c", ""));
        let dependencies = if c_first { c + &a } else { a + &c };
        for (path, text) in [
            (
                "pom.xml",
                pom(
                    "root",
                    "<packaging>pom</packaging><modules><module>b</module><module>c</module>\
                     </modules>",
                ),
            ),
            (
                "b/pom.xml",
                pom("b", &format!("<dependencies>{dependencies}</dependencies>")),
            ),
            (
                "c/pom.xml",
                pom(
                    "c",
                    "<repositories><repository><id>rx</id><url>http://repo.invalid/rx/</url>\
                     </repository></repositories>",
                ),
            ),
        ] {
            let path = project.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).expect("module");
            fs::write(path, text).expect("pom");
        }
        let output = run_raeva(project.path(), home.path(), &["sync"]);
        assert_status(&output, 0, "a dependency's repository after a refused one");
    }
}

/// Maven collects the reactor's modules in `ProjectSorter` order with one
/// model cache, so `x`'s parent, which only `rb` serves, is found when `m1`
/// is sorted before `m2`: `m1`'s dependency `b` declares `rb` and reads it
/// through `y`. Listed first, depended on by `m2` or named as its build
/// plugin, `m1` is; listed second with no edge, it is not, and Maven 3.9.12
/// and 3.10.0 fail on `m2`.
#[test]
fn a_parent_only_a_module_sorted_before_read_is_taken() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let rb = format!("http://{}/rb/", address.get().expect("address"));
        let child = |artifact: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
<artifactId>p</artifactId><version>1</version><relativePath/></parent>\
<artifactId>{artifact}</artifactId></project>"
            )
        };
        let b = format!(
            "<repositories><repository><id>rb</id><url>{rb}</url></repository></repositories>\
<dependencies>{}</dependencies>",
            dependency("y", "")
        );
        with_sha1(
            &request.path,
            [
                ("/r1/t/b/1/b-1.pom", pom("b", &b)),
                ("/r1/t/x/1/x-1.pom", child("x")),
                ("/r1/t/y/1/y-1.pom", child("y")),
                ("/rb/t/p/1/p-1.pom", pom("p", "<packaging>pom</packaging>")),
                ("/r1/t/b/1/b-1.jar", "jar".to_string()),
                ("/r1/t/x/1/x-1.jar", "jar".to_string()),
                ("/r1/t/y/1/y-1.jar", "jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_transitive_repositories = true\n",
    )
    .expect("write config.toml");
    let dependencies = |dependencies: &str| format!("<dependencies>{dependencies}</dependencies>");
    let m1 = ("m1", dependencies(&dependency("b", "")));
    let m2 = ("m2", dependencies(&dependency("x", "")));
    let m2_on_m1 = (
        "m2",
        dependencies(&(dependency("x", "") + &dependency("m1", ""))),
    );
    let plugin = "<build><plugins><plugin><groupId>t</groupId><artifactId>m1</artifactId>\
<version>1</version></plugin></plugins></build>";
    let m2_with_m1 = ("m2", m2.1.clone() + plugin);
    for mode in ["3.9", "3.10"] {
        for (modules, found) in [
            ([&m1, &m2], true),
            ([&m2_on_m1, &m1], true),
            ([&m2_with_m1, &m1], true),
            ([&m2, &m1], false),
        ] {
            let project = tempfile::tempdir().expect("project");
            let root = project.path();
            write_repo_toml(root, "r1", &format!("http://{}/r1/", server.addr()));
            let raeva_toml = root.join("raeva.toml");
            let mut config = fs::read_to_string(&raeva_toml).unwrap_or_default();
            config.push_str(&format!("\n[lock]\nmaven = \"{mode}\"\n"));
            fs::write(&raeva_toml, config).expect("write raeva.toml");
            let listed: String = (modules.iter())
                .map(|(module, _)| format!("<module>{module}</module>"))
                .collect();
            let body = format!("<packaging>pom</packaging><modules>{listed}</modules>");
            fs::write(root.join("pom.xml"), pom("app", &body)).expect("write pom.xml");
            for (module, body) in modules {
                fs::create_dir_all(root.join(module)).expect("mkdir module");
                fs::write(root.join(module).join("pom.xml"), pom(module, body))
                    .expect("write module");
            }
            let output = run_raeva(root, home.path(), &["sync"]);
            let case = format!("{mode} {listed}");
            if found {
                assert_status(&output, 0, &case);
                let lock = fs::read_to_string(root.join("raeva.lock")).expect("lock");
                assert!(lock.contains("t:x:1"), "{case}: {lock}");
            } else {
                assert_status(&output, 5, &case);
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stderr.contains("Parent POM not found: t:p:1"),
                    "{case}: {stderr}"
                );
            }
        }
    }
}

/// Maven 3.9 keeps the first build of an imported BOM in its session cache
/// for every later import of the coordinates. `bom` manages `lib` at
/// `${lib.version}`, 1 in `bom` and 2 in `.mvn/maven.config`: `a`'s project
/// build imports it with the user property, and `wrapper`, which `b`
/// depends on, takes that build, so Maven 3.9.12 locks `lib:2` whichever
/// module is listed first and 3.10.0, which builds the import again
/// without user properties, `lib:1`. `pbom` manages `lib2` at 2 under a
/// profile on the `pom` packaging: the pom-packaged `c` builds it first,
/// so `d` takes `lib2:2` in Maven 3.9.12, and so does `e` through `d`'s
/// model; 3.10.0 builds `d`'s own, `lib2:1`. The reactor BOM `rb` that
/// `wrapper3` imports is read through an external POM, so an edit to it
/// changes the record of `b2`, which depends on `wrapper3`.
#[test]
fn an_import_takes_the_first_build_of_its_bom_in_the_maven_39_mode() {
    let managed = |artifact: &str, version: &str| {
        format!(
            "<dependencyManagement><dependencies><dependency><groupId>t</groupId>\
<artifactId>{artifact}</artifactId><version>{version}</version></dependency></dependencies>\
</dependencyManagement>"
        )
    };
    let unversioned = |artifact: &str| {
        format!(
            "<dependencies><dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
</dependency></dependencies>"
        )
    };
    let server = StubServer::start(move |request| {
        let pbom = format!(
            "<packaging>pom</packaging><properties><v>1</v></properties>{}<profiles><profile>\
<id>pk</id><activation><property><name>packaging</name><value>pom</value></property>\
</activation><properties><v>2</v></properties></profile></profiles>",
            managed("lib2", "${v}")
        );
        let bom = format!(
            "<packaging>pom</packaging><properties><lib.version>1</lib.version></properties>{}",
            managed("lib", "${lib.version}")
        );
        let mut files = vec![
            ("/r1/t/bom/1/bom-1.pom".to_string(), pom("bom", &bom)),
            ("/r1/t/pbom/1/pbom-1.pom".to_string(), pom("pbom", &pbom)),
        ];
        for (wrapper, bom) in [("wrapper", "bom"), ("wrapper3", "rb")] {
            let body = format!("{}{}", import(bom), unversioned("lib"));
            let path = format!("/r1/t/{wrapper}/1/{wrapper}-1");
            files.push((format!("{path}.pom"), pom(wrapper, &body)));
            files.push((format!("{path}.jar"), "jar".to_string()));
        }
        for artifact in ["lib", "lib2"] {
            for version in ["1", "2"] {
                let path = format!("/r1/t/{artifact}/{version}/{artifact}-{version}");
                files.push((format!("{path}.pom"), pom(artifact, "")));
                files.push((format!("{path}.jar"), "jar".to_string()));
            }
        }
        with_sha1(&request.path, files)
    });
    let depends =
        |artifact: &str| format!("<dependencies>{}</dependencies>", dependency(artifact, ""));
    let a = ("a", import("bom"));
    let b = ("b", depends("wrapper"));
    let c = ("c", format!("<packaging>pom</packaging>{}", import("pbom")));
    let d = ("d", format!("{}{}", import("pbom"), unversioned("lib2")));
    let e = ("e", depends("d"));
    let rb = (
        "rb",
        format!(
            "<packaging>pom</packaging><properties><lib.version>1</lib.version></properties>{}",
            managed("lib", "${lib.version}")
        ),
    );
    let a2 = ("a2", import("rb"));
    let b2 = ("b2", depends("wrapper3"));
    let home = tempfile::tempdir().expect("home");
    let sync = |mode: &str, modules: &[&(&str, String)]| {
        let project = tempfile::tempdir().expect("project");
        let root = project.path();
        write_repo_toml(root, "r1", &format!("http://{}/r1/", server.addr()));
        let raeva_toml = root.join("raeva.toml");
        let mut config = fs::read_to_string(&raeva_toml).unwrap_or_default();
        config.push_str(&format!("\n[lock]\nmaven = \"{mode}\"\n"));
        fs::write(&raeva_toml, config).expect("write raeva.toml");
        fs::create_dir_all(root.join(".mvn")).expect("mkdir .mvn");
        fs::write(root.join(".mvn/maven.config"), "-Dlib.version=2\n").expect("maven.config");
        let listed: String = (modules.iter())
            .map(|(module, _)| format!("<module>{module}</module>"))
            .collect();
        let body = format!("<packaging>pom</packaging><modules>{listed}</modules>");
        fs::write(root.join("pom.xml"), pom("app", &body)).expect("write pom.xml");
        for (module, body) in modules {
            fs::create_dir_all(root.join(module)).expect("mkdir module");
            fs::write(root.join(module).join("pom.xml"), pom(module, body)).expect("write module");
        }
        let output = run_raeva(root, home.path(), &["sync"]);
        let case = format!("{mode} {listed}");
        assert_status(&output, 0, &case);
        let lock = fs::read_to_string(root.join("raeva.lock")).expect("lock");
        (project, case, lock)
    };
    for (mode, modules, locked, unlocked) in [
        ("3.9", &[&a, &b][..], "t:lib:2\\t", "t:lib:1\\t"),
        ("3.9", &[&b, &a], "t:lib:2\\t", "t:lib:1\\t"),
        ("3.10", &[&a, &b], "t:lib:1\\t", "t:lib:2\\t"),
        ("3.9", &[&c, &d, &e], "t:lib2:2\\t", "t:lib2:1\\t"),
        ("3.10", &[&c, &d, &e], "t:lib2:1\\t", "t:lib2:2\\t"),
        ("3.9", &[&rb, &a2, &b2], "t:lib:2\\t", "t:lib:1\\t"),
    ] {
        let (_project, case, lock) = sync(mode, modules);
        assert!(lock.contains(locked), "{case}: {lock}");
        assert!(!lock.contains(unlocked), "{case}: {lock}");
    }
    let (project, case, lock) = sync("3.9", &[&rb, &a2, &b2]);
    let record = |lock: &str| {
        let at = (lock.find("[[inputs.poms]]\npath = \"b2/pom.xml\"")).expect("b2's record");
        lock[at..].lines().nth(2).expect("its hash").to_string()
    };
    let rb_pom = project.path().join("rb/pom.xml");
    let edited = fs::read_to_string(&rb_pom).expect("rb").replace(
        "<packaging>",
        "<description>edited</description><packaging>",
    );
    fs::write(&rb_pom, edited).expect("edit rb");
    let output = run_raeva(project.path(), home.path(), &["sync"]);
    assert_status(&output, 0, &case);
    let resynced = fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
    assert_ne!(record(&lock), record(&resynced), "{case}: {resynced}");
}

/// `pbom` sets `v` to `${jar.v}` under a profile on packaging `jar`. In
/// Maven 3.9.12 `d` takes `c`'s build of it, so `jar.v` is never read: `d`
/// gets `lib2:2` with `-Djar.v=1` too. A cold sync checks `d`'s own
/// dependencies while the artifacts download, and a warm one does not, so
/// the check must not put the `jar.v` its own build reads in the lock.
#[test]
fn a_cold_and_a_warm_sync_record_the_same_inputs_for_a_taken_import() {
    let server = StubServer::start(move |request| {
        let pbom = "<packaging>pom</packaging><properties><v>1</v></properties>\
<dependencyManagement><dependencies><dependency><groupId>t</groupId><artifactId>lib2</artifactId>\
<version>${v}</version></dependency></dependencies></dependencyManagement><profiles><profile>\
<id>pk</id><activation><property><name>packaging</name><value>pom</value></property></activation>\
<properties><v>2</v></properties></profile><profile><id>jk</id><activation><property>\
<name>packaging</name><value>jar</value></property></activation><properties><v>${jar.v}</v>\
</properties></profile></profiles>";
        let mut files = vec![("/r1/t/pbom/1/pbom-1.pom".to_string(), pom("pbom", pbom))];
        let chained = |next: &str| format!("<dependencies>{}</dependencies>", dependency(next, ""));
        for (artifact, version, body) in [
            ("lib", "1", String::new()),
            ("lib2", "1", String::new()),
            ("lib2", "2", chained("t1")),
            ("t1", "1", chained("t2")),
            ("t2", "1", chained("t3")),
            ("t3", "1", chained("t4")),
            ("t4", "1", String::new()),
        ] {
            let path = format!("/r1/t/{artifact}/{version}/{artifact}-{version}");
            let pom = pom(artifact, &body).replacen(
                "<version>1</version>",
                &format!("<version>{version}</version>"),
                1,
            );
            files.push((format!("{path}.pom"), pom));
            files.push((format!("{path}.jar"), "jar".to_string()));
        }
        with_sha1(&request.path, files)
    });
    let project = tempfile::tempdir().expect("project");
    let root = project.path();
    write_repo_toml(root, "r1", &format!("http://{}/r1/", server.addr()));
    let raeva_toml = root.join("raeva.toml");
    let config = fs::read_to_string(&raeva_toml).unwrap_or_default();
    fs::write(&raeva_toml, config + "\n[lock]\nmaven = \"3.9\"\n").expect("write raeva.toml");
    fs::create_dir_all(root.join(".mvn")).expect("mkdir .mvn");
    fs::write(root.join(".mvn/maven.config"), "-Djar.v=2\n").expect("maven.config");
    let body = "<packaging>pom</packaging><modules><module>c</module><module>d</module></modules>";
    fs::write(root.join("pom.xml"), pom("app", body)).expect("write pom.xml");
    let unversioned = "<dependencies><dependency><groupId>t</groupId><artifactId>lib2</artifactId>\
</dependency></dependencies>";
    for (module, body) in [
        (
            "c",
            format!(
                "<packaging>pom</packaging>{}<dependencies>{}</dependencies>",
                import("pbom"),
                dependency("lib", "")
            ),
        ),
        ("d", format!("{}{unversioned}", import("pbom"))),
    ] {
        fs::create_dir_all(root.join(module)).expect("mkdir module");
        fs::write(root.join(module).join("pom.xml"), pom(module, &body)).expect("write module");
    }
    let home = tempfile::tempdir().expect("home");
    let sync = |run: &str| {
        let output = run_raeva(root, home.path(), &["sync"]);
        assert_status(&output, 0, run);
        let lock = fs::read_to_string(root.join("raeva.lock")).expect("lock");
        fs::remove_file(root.join("raeva.lock")).expect("remove lock");
        lock
    };
    let cold = sync("cold");
    assert!(cold.contains("t:lib2:2\\t"), "cold: {cold}");
    assert!(!cold.contains("jar.v"), "cold: {cold}");
    assert_eq!(cold, sync("warm"));
}

/// Maven reads every module's lineage, then every module's imports, with
/// one model cache (DefaultProjectBuilder phase 1 and 2). `m1` imports
/// `bom`, whose parent `bp` only `rp` serves: listed after `m1`, `m2` reads
/// it from `rp` as its own parent first. With `rp` on `m1` instead, `m2`'s
/// lineage is read before `m1`'s import, and Maven 3.9.12 and 3.10.0 fail
/// on `m2`, as they do when `m1` takes the import `m0` built.
#[test]
fn an_import_sees_the_lineages_of_every_module() {
    let server = StubServer::start(move |request| {
        let bp = "<parent><groupId>t</groupId><artifactId>bp</artifactId><version>1</version>\
<relativePath/></parent><artifactId>bom</artifactId><packaging>pom</packaging>";
        with_sha1(
            &request.path,
            [
                (
                    "/r1/t/bom/1/bom-1.pom",
                    format!("<project><modelVersion>4.0.0</modelVersion>{bp}</project>"),
                ),
                (
                    "/rp/t/bp/1/bp-1.pom",
                    pom("bp", "<packaging>pom</packaging>"),
                ),
            ],
        )
    });
    let rp = format!(
        "<repositories><repository><id>rp</id><url>http://{}/rp/</url></repository></repositories>",
        server.addr()
    );
    let import = format!(
        "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
        dependency("bom", "<type>pom</type><scope>import</scope>")
    );
    let bp = "<parent><groupId>t</groupId><artifactId>bp</artifactId><version>1</version>\
<relativePath/></parent>";
    let home = tempfile::tempdir().expect("home");
    for mode in ["3.9", "3.10"] {
        let own = format!("{rp}{import}");
        for (importers, m2_repositories, found) in [
            (&[import.as_str()][..], rp.as_str(), true),
            (&[own.as_str()], "", false),
            (&[own.as_str(), own.as_str()], "", false),
        ] {
            let project = tempfile::tempdir().expect("project");
            let root = project.path();
            write_repo_toml(root, "r1", &format!("http://{}/r1/", server.addr()));
            let raeva_toml = root.join("raeva.toml");
            let mut config = fs::read_to_string(&raeva_toml).unwrap_or_default();
            config.push_str(&format!("\n[lock]\nmaven = \"{mode}\"\n"));
            fs::write(&raeva_toml, config).expect("write raeva.toml");
            let m2 = format!(
                "<project><modelVersion>4.0.0</modelVersion>{bp}<groupId>t</groupId>\
<artifactId>m2</artifactId><version>1</version>{m2_repositories}</project>"
            );
            let first = 2 - importers.len();
            let mut modules: Vec<_> = (importers.iter().enumerate())
                .map(|(at, body)| {
                    let module = format!("m{}", first + at);
                    (module.clone(), pom(&module, body))
                })
                .collect();
            modules.push(("m2".to_string(), m2));
            let listed: String = (modules.iter())
                .map(|(module, _)| format!("<module>{module}</module>"))
                .collect();
            let body = format!("<packaging>pom</packaging><modules>{listed}</modules>");
            fs::write(root.join("pom.xml"), pom("app", &body)).expect("write pom.xml");
            for (module, pom_xml) in &modules {
                fs::create_dir_all(root.join(module)).expect("mkdir module");
                fs::write(root.join(module).join("pom.xml"), pom_xml).expect("write module");
            }
            let output = run_raeva(root, home.path(), &["sync"]);
            let case = format!("{mode} {} importers, found {found}", importers.len());
            if found {
                assert_status(&output, 0, &case);
            } else {
                assert_status(&output, 5, &case);
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stderr.contains("Parent POM not found: t:bp:1"),
                    "{case}: {stderr}"
                );
            }
        }
    }
}

/// Maven reads the lineages of the reactor's modules in turn with one model
/// cache, the effective GAV of each among them, so `m2`, which takes its
/// GAV from `pp` on `r1`, a repository without it, finds `pp` that `m1`
/// read from `rp`, whatever `m1` names itself. With no such parent on
/// `m1`, Maven 3.9.12 and 3.10.0 fail on `m2`.
#[test]
fn an_effective_gav_sees_the_lineages_before_it() {
    let server = StubServer::start(move |request| {
        with_sha1(
            &request.path,
            [(
                "/rp/t/pp/1/pp-1.pom",
                pom("pp", "<packaging>pom</packaging>"),
            )],
        )
    });
    let repositories = |id: &str| {
        format!(
            "<repositories><repository><id>{id}</id><url>http://{}/{id}/</url></repository>\
</repositories>",
            server.addr()
        )
    };
    let pp = "<parent><groupId>t</groupId><artifactId>pp</artifactId><version>1</version>\
<relativePath/></parent>";
    let module = |head: &str, body: &str| {
        format!("<project><modelVersion>4.0.0</modelVersion>{head}{body}</project>")
    };
    let m2 = module(
        &format!("{pp}<artifactId>m2</artifactId>"),
        &repositories("r1"),
    );
    let home = tempfile::tempdir().expect("home");
    for mode in ["3.9", "3.10"] {
        for (m1, found) in [
            (
                module(
                    &format!("{pp}<artifactId>m1</artifactId>"),
                    &repositories("rp"),
                ),
                true,
            ),
            (
                module(
                    &format!(
                        "{pp}<groupId>t</groupId><artifactId>m1</artifactId><version>1</version>"
                    ),
                    &repositories("rp"),
                ),
                true,
            ),
            (pom("m1", ""), false),
        ] {
            let project = tempfile::tempdir().expect("project");
            let root = project.path();
            fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .expect("write raeva.toml");
            let body = "<packaging>pom</packaging><modules><module>m1</module><module>m2</module></modules>";
            fs::write(root.join("pom.xml"), pom("app", body)).expect("write pom.xml");
            for (name, pom_xml) in [("m1", &m1), ("m2", &m2)] {
                fs::create_dir_all(root.join(name)).expect("mkdir module");
                fs::write(root.join(name).join("pom.xml"), pom_xml).expect("write module");
            }
            let output = run_raeva(root, home.path(), &["sync"]);
            let case = format!("{mode} {m1}");
            if found {
                assert_status(&output, 0, &case);
            } else {
                assert_status(&output, 5, &case);
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stderr.contains("Parent POM not found: t:pp:1"),
                    "{case}: {stderr}"
                );
            }
        }
    }
}

/// os-maven-plugin takes its likes from the project Maven sorts first,
/// built, as Maven builds every project, with what the lineages before it
/// read: `m1`'s parent `pp`, which sets them, comes from `rp`, which only
/// the root declares. Maven 3.9.12 and 3.10.0 lock the suffixed classifier.
#[test]
fn the_first_sorted_project_sees_the_lineages_before_it() {
    let server = StubServer::start(move |request| {
        let likes = "<packaging>pom</packaging><properties><os.detection.classifierWithLikes>\
debian</os.detection.classifierWithLikes></properties>";
        with_sha1(
            &request.path,
            [
                ("/rp/t/pp/1/pp-1.pom", pom("pp", likes)),
                ("/r1/t/nat/1/nat-1.pom", pom("nat", "")),
                ("/r1/t/nat/1/nat-1-linux-x86_64.jar", "jar".to_string()),
                (
                    "/r1/t/nat/1/nat-1-linux-x86_64-debian.jar",
                    "jar".to_string(),
                ),
            ],
        )
    });
    let repositories = |id: &str| {
        format!(
            "<repositories><repository><id>{id}</id><url>http://{}/{id}/</url></repository>\
</repositories>",
            server.addr()
        )
    };
    let project = |artifact: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
<artifactId>pp</artifactId><version>1</version><relativePath/></parent><groupId>t</groupId>\
<artifactId>{artifact}</artifactId><version>1</version>{body}</project>"
        )
    };
    let home = tempfile::tempdir().expect("home");
    let workspace = tempfile::tempdir().expect("project");
    let root = workspace.path();
    let modules = "<packaging>pom</packaging><modules><module>m1</module></modules>";
    fs::write(
        root.join("pom.xml"),
        project("app", &(modules.to_string() + &repositories("rp"))),
    )
    .expect("write pom.xml");
    let nat = "<dependencies><dependency><groupId>t</groupId><artifactId>nat</artifactId>\
<version>1</version><classifier>${os.detected.classifier}</classifier></dependency></dependencies>";
    fs::create_dir_all(root.join("m1")).expect("mkdir module");
    fs::write(
        root.join("m1/pom.xml"),
        project("m1", &(repositories("r1") + nat)),
    )
    .expect("write module");
    let output = raeva_command(root, home.path())
        .env(rv_maven_model::OS_RELEASE_TEST_ENV, "ID=debian\n")
        .args(["sync", "--platforms", "linux-x86_64"])
        .output()
        .expect("run raeva");
    assert_status(&output, 0, "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).expect("lock");
    assert!(lock.contains("jar:linux-x86_64-debian"), "{lock}");
}

/// Maven resolves a module's build plugins and extensions with the model
/// cache its project builds share, after every lineage: `m2`'s plugin or
/// extension `plug`, on `pr`, finds its parent `pp` that `m1`'s lineage read
/// from `rp`, in either listed order, and so does `m2`'s own parent from
/// `r1`. With no such parent on `m1`, Maven 3.9.12 and 3.10.0 fail on `plug`,
/// and raeva names `pp` and the plugin repositories it searched.
#[test]
fn a_plugin_sees_the_lineages_of_the_projects() {
    let server = StubServer::start(move |request| {
        if let Some(response) = central_plugin(&request.path) {
            return response;
        }
        let pp = "<parent><groupId>t</groupId><artifactId>pp</artifactId><version>1</version>\
<relativePath/></parent>";
        let plug = format!(
            "<project><modelVersion>4.0.0</modelVersion>{pp}<artifactId>plug</artifactId>\
<packaging>maven-plugin</packaging></project>"
        );
        with_sha1(
            &request.path,
            [
                (
                    "/rp/t/pp/1/pp-1.pom",
                    pom("pp", "<packaging>pom</packaging>").into_bytes(),
                ),
                ("/pr/t/plug/1/plug-1.pom", plug.into_bytes()),
                ("/pr/t/plug/1/plug-1.jar", EMPTY_JAR.to_vec()),
            ],
        )
    });
    let repository = |kind: &str, id: &str| {
        format!(
            "<{kind}ies><{kind}y><id>{id}</id><url>http://{}/{id}/</url></{kind}y></{kind}ies>",
            server.addr()
        )
    };
    let pp = "<parent><groupId>t</groupId><artifactId>pp</artifactId><version>1</version>\
<relativePath/></parent>";
    let module = |head: &str, body: &str| {
        format!("<project><modelVersion>4.0.0</modelVersion>{head}{body}</project>")
    };
    let plug = "<groupId>t</groupId><artifactId>plug</artifactId><version>1</version>";
    let m2s = [
        format!(
            "{}<build><plugins><plugin>{plug}</plugin></plugins></build>",
            repository("pluginRepositor", "pr")
        ),
        format!(
            "{}<build><extensions><extension>{plug}</extension></extensions></build>",
            repository("pluginRepositor", "pr")
        ),
    ];
    let home = plugin_home(&server);
    for mode in ["3.9", "3.10"] {
        for (m2, listed) in [
            (pom("m2", &m2s[0]), ["m1", "m2"]),
            (pom("m2", &m2s[0]), ["m2", "m1"]),
            (pom("m2", &m2s[1]), ["m1", "m2"]),
            (pom("m2", &m2s[1]), ["m2", "m1"]),
            (
                module(
                    &format!("{pp}<artifactId>m2</artifactId>"),
                    &repository("repositor", "r1"),
                ),
                ["m1", "m2"],
            ),
        ] {
            for found in [true, false] {
                let m1 = match found {
                    true => module(
                        &format!("{pp}<artifactId>m1</artifactId>"),
                        &repository("repositor", "rp"),
                    ),
                    false => pom("m1", ""),
                };
                let project = tempfile::tempdir().expect("project");
                let root = project.path();
                fs::write(
                    root.join("raeva.toml"),
                    format!("[lock]\nmaven = \"{mode}\"\n[plugins]\nlock = true\n"),
                )
                .expect("write raeva.toml");
                let modules: String = listed
                    .iter()
                    .map(|name| format!("<module>{name}</module>"))
                    .collect();
                let body = format!("<packaging>pom</packaging><modules>{modules}</modules>");
                fs::write(root.join("pom.xml"), pom("app", &body)).expect("write pom.xml");
                for (name, pom_xml) in [("m1", &m1), ("m2", &m2)] {
                    fs::create_dir_all(root.join(name)).expect("mkdir module");
                    fs::write(root.join(name).join("pom.xml"), pom_xml).expect("write module");
                }
                let output = run_raeva(root, home.path(), &["sync"]);
                let case = format!("{mode} {listed:?} {m1} {m2}");
                assert_status(&output, if found { 0 } else { 5 }, &case);
                if found && m2.contains("plug") {
                    let lock = fs::read_to_string(root.join("raeva.lock")).expect("lock");
                    assert!(lock.contains("t:plug:1"), "{case}: {lock}");
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !found && m2.contains("plug") {
                    let searched = format!(
                        "Parent POM not found: t:pp:1\n\n  In m2/pom.xml\n\n  This parent POM \
could not be resolved.\n\n  None of the repositories the plugin pass searched for this plugin \
has it:\n    - http://{}/pr/\n",
                        server.addr()
                    );
                    assert!(stderr.contains(&searched), "{case}: {stderr}");
                }
            }
        }
    }
}

/// A dependency of a type no core handler defines makes raeva read the
/// module's build extensions, building the project again: built, as Maven
/// builds it, with the model cache the module's own build left, `m2` finds
/// its parent `pp` that `m1`'s lineage read from `rp`. With no such parent
/// on `m1`, Maven 3.9.12 and 3.10.0 fail on `m2`.
#[test]
fn a_projects_extensions_are_read_with_its_model_cache() {
    let server = StubServer::start(move |request| {
        with_sha1(
            &request.path,
            [
                (
                    "/rp/t/pp/1/pp-1.pom",
                    pom("pp", "<packaging>pom</packaging>"),
                ),
                ("/r1/t/lib/1/lib-1.pom", pom("lib", "")),
                ("/r1/t/lib/1/lib-1.foo", "foo".to_string()),
            ],
        )
    });
    let repositories = |id: &str| {
        format!(
            "<repositories><repository><id>{id}</id><url>http://{}/{id}/</url></repository>\
</repositories>",
            server.addr()
        )
    };
    let pp = "<parent><groupId>t</groupId><artifactId>pp</artifactId><version>1</version>\
<relativePath/></parent>";
    let module = |head: &str, body: &str| {
        format!("<project><modelVersion>4.0.0</modelVersion>{head}{body}</project>")
    };
    let lib = "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
<version>1</version><type>foo</type></dependency></dependencies>";
    let m2 = module(
        &format!("{pp}<artifactId>m2</artifactId>"),
        &(repositories("r1") + lib),
    );
    let home = tempfile::tempdir().expect("home");
    for mode in ["3.9", "3.10"] {
        for found in [true, false] {
            let m1 = match found {
                true => module(
                    &format!("{pp}<artifactId>m1</artifactId>"),
                    &repositories("rp"),
                ),
                false => pom("m1", ""),
            };
            let project = tempfile::tempdir().expect("project");
            let root = project.path();
            fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .expect("write raeva.toml");
            let body = "<packaging>pom</packaging><modules><module>m1</module><module>m2</module></modules>";
            fs::write(root.join("pom.xml"), pom("app", body)).expect("write pom.xml");
            for (name, pom_xml) in [("m1", &m1), ("m2", &m2)] {
                fs::create_dir_all(root.join(name)).expect("mkdir module");
                fs::write(root.join(name).join("pom.xml"), pom_xml).expect("write module");
            }
            let output = run_raeva(root, home.path(), &["sync"]);
            let case = format!("{mode} {m1}");
            assert_status(&output, if found { 0 } else { 5 }, &case);
            if found {
                let lock = fs::read_to_string(root.join("raeva.lock")).expect("lock");
                assert!(lock.contains("lib:1\\tfoo"), "{case}: {lock}");
            }
        }
    }
}

/// The plugin pass builds each project with what its own repositories
/// miss: `m1` misses `pp` on `r1` and takes it from the cache `m0`'s lineage
/// filled, and `m2`, which declares `rp`, still fetches `pp` there for its
/// import. Maven 3.9.12 and 3.10.0 pass.
#[test]
fn a_parent_one_module_misses_is_fetched_for_another_in_the_plugin_pass() {
    let server = StubServer::start(move |request| {
        if let Some(response) = central_plugin(&request.path) {
            return response;
        }
        with_sha1(
            &request.path,
            [(
                "/rp/t/pp/1/pp-1.pom",
                pom("pp", "<packaging>pom</packaging>"),
            )],
        )
    });
    let repositories = |id: &str| {
        format!(
            "<repositories><repository><id>{id}</id><url>http://{}/{id}/</url></repository>\
</repositories>",
            server.addr()
        )
    };
    let pp = "<parent><groupId>t</groupId><artifactId>pp</artifactId><version>1</version>\
<relativePath/></parent>";
    let child = |artifact: &str, repository: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{pp}<groupId>t</groupId>\
<artifactId>{artifact}</artifactId><version>1</version>{}</project>",
            repositories(repository)
        )
    };
    let import = format!(
        "{}<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
        repositories("rp"),
        dependency("pp", "<type>pom</type><scope>import</scope>")
    );
    let home = plugin_home(&server);
    for mode in ["3.9", "3.10"] {
        let project = tempfile::tempdir().expect("project");
        let root = project.path();
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n[plugins]\nlock = true\n"),
        )
        .expect("write raeva.toml");
        let body = "<packaging>pom</packaging><modules><module>m0</module><module>m1</module>\
<module>m2</module></modules>";
        fs::write(root.join("pom.xml"), pom("app", body)).expect("write pom.xml");
        for (name, pom_xml) in [
            ("m0", child("m0", "rp")),
            ("m1", child("m1", "r1")),
            ("m2", pom("m2", &import)),
        ] {
            fs::create_dir_all(root.join(name)).expect("mkdir module");
            fs::write(root.join(name).join("pom.xml"), pom_xml).expect("write module");
        }
        let output = run_raeva(root, home.path(), &["sync"]);
        assert_status(&output, 0, mode);
    }
}

/// An empty zip.
const EMPTY_JAR: &[u8] = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// A home whose settings.xml mirrors Central to `/central/` on `server`,
/// which [`central_plugin`] answers: a plugin lock resolves the
/// lifecycle's plugins too.
fn plugin_home(server: &StubServer) -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("home");
    fs::create_dir_all(home.path().join(".m2")).expect("mkdir .m2");
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/central/</url>\
<mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .expect("write settings.xml");
    home
}

/// A plugin POM for every POM under `/central/` but group `t`'s, and the
/// empty jar for every jar.
fn central_plugin(path: &str) -> Option<Response> {
    let file = path.strip_prefix("/central/")?;
    let parts: Vec<&str> = file.trim_end_matches(".sha1").split('/').collect();
    let [group @ .., artifact, version, name] = parts.as_slice() else {
        return Some(Response::new(404, ""));
    };
    if group == ["t"] {
        return Some(Response::new(404, ""));
    }
    let body = if *name == format!("{artifact}-{version}.pom") {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
<artifactId>{artifact}</artifactId><version>{version}</version>\
<packaging>maven-plugin</packaging></project>",
            group.join(".")
        )
        .into_bytes()
    } else if *name == format!("{artifact}-{version}.jar") {
        EMPTY_JAR.to_vec()
    } else {
        return Some(Response::new(404, ""));
    };
    Some(with_sha1(path, [(path.trim_end_matches(".sha1"), body)]))
}

/// `x` reads `t:old` `[1,4)` through `ra` alone and takes 2; `mid`, which
/// declares `rb`, reads it through both and takes 3, which wins. Maven 3.9
/// still reads `ra`'s list for `x`, offline too, so the lock keeps it as an
/// evicted range, from which an export lists it under `ra`'s id. (Maven
/// 3.10 reads no list for `x` here, and neither does raeva.)
#[test]
fn a_range_read_through_fewer_repositories_keeps_its_list() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let rb = format!("http://{}/rb/", address.get().expect("address"));
        let old = "<dependencies><dependency><groupId>t</groupId><artifactId>old</artifactId>\
                   <version>[1,4)</version></dependency></dependencies>";
        let listing = |versions: &str| {
            format!(
                "<metadata><groupId>t</groupId><artifactId>old</artifactId><versioning>\
                 <versions>{versions}</versions></versioning></metadata>"
            )
        };
        let mut files = vec![
            ("/ra/t/x/1/x-1.pom".to_string(), pom("x", old)),
            (
                "/ra/t/mid/1/mid-1.pom".to_string(),
                pom(
                    "mid",
                    &format!(
                        "<repositories><repository><id>rb</id><url>{rb}</url></repository>\
                         </repositories>{old}"
                    ),
                ),
            ),
            (
                "/ra/t/old/maven-metadata.xml".to_string(),
                listing("<version>1</version><version>2</version>"),
            ),
            (
                "/rb/t/old/maven-metadata.xml".to_string(),
                listing("<version>3</version>"),
            ),
        ];
        for (repo, version) in [("ra", "1"), ("ra", "2"), ("rb", "3")] {
            let path = format!("/{repo}/t/old/{version}/old-{version}");
            let body = pom("old", "").replace(">1</version>", &format!(">{version}</version>"));
            files.push((format!("{path}.pom"), body));
            files.push((format!("{path}.jar"), format!("old {version}")));
        }
        for artifact in ["x", "mid"] {
            files.push((format!("/ra/t/{artifact}/1/{artifact}-1.jar"), "jar".into()));
        }
        serve_sha256(&request.path, |path| {
            (files.iter())
                .find(|(file, _)| file == path)
                .map(|(_, body)| body.clone())
        })
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "[security]\ntransitive_repository_allowlist = [\"http://{}/rb/\"]\n",
            server.addr()
        ),
    )
    .expect("write config.toml");
    let project = tempfile::tempdir().expect("project");
    let ra = format!("http://{}/ra/", server.addr());
    write_repo_toml(project.path(), "ra", &ra);
    let raeva_toml = project.path().join("raeva.toml");
    let config = fs::read_to_string(&raeva_toml).expect("raeva.toml");
    fs::write(&raeva_toml, format!("{config}\n[lock]\nmaven = \"3.9\"\n"))
        .expect("write raeva.toml");
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dependency("mid", ""),
                dependency("x", "")
            ),
        ),
    )
    .expect("write pom.xml");
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
    let evicted = format!("t:old\\t[1,4)\\t{ra}\\t1 2");
    assert!(lock.contains(&evicted), "{lock}");
    assert!(lock.contains("t:old:3"), "{lock}");
}

/// In the Maven 3.10 mode a settings.xml password goes to a repository a
/// dependency's POM declares for that POM's own parent, as Maven's model
/// resolver sends it, and not for the dependencies collected below that
/// POM, as Maven keeps it from a descriptor repository. `mid` declares
/// `corp`, which serves its parent `mpar` and its dependency `lib`.
#[test]
fn a_dependency_repository_gets_the_password_for_its_own_parent_only() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, bool)>::new()));
    let corp = {
        let seen = std::sync::Arc::clone(&seen);
        StubServer::start(move |request| {
            let auth = request.header("authorization").is_some();
            seen.lock().unwrap().push((request.path.clone(), auth));
            let mpar = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                        <artifactId>mpar</artifactId><version>1</version>\
                        <packaging>pom</packaging></project>";
            serve_sha256(&request.path, |path| match path {
                "/t/mpar/1/mpar-1.pom" => Some(mpar.to_string()),
                "/t/lib/1/lib-1.pom" => Some(pom("lib", "")),
                "/t/lib/1/lib-1.jar" => Some("lib jar".to_string()),
                _ => None,
            })
        })
    };
    let corp_url = format!("http://{}/", corp.addr());
    let mid = format!(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
         <artifactId>mpar</artifactId><version>1</version></parent><artifactId>mid</artifactId>\
         <version>1</version><repositories><repository><id>corp</id><url>{corp_url}</url>\
         </repository></repositories>{}</project>",
        "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
         <version>1</version></dependency></dependencies>"
    );
    let open = StubServer::start(move |request| {
        serve_sha256(&request.path, |path| match path {
            "/t/mid/1/mid-1.pom" => Some(mid.clone()),
            "/t/mid/1/mid-1.jar" => Some("mid jar".to_string()),
            _ => None,
        })
    });
    let home = tempfile::tempdir().expect("home");
    fs::write(
        home.path().join("config.toml"),
        format!("[security]\ntransitive_repository_allowlist = [\"{corp_url}\"]\n"),
    )
    .expect("write config.toml");
    fs::create_dir_all(home.path().join(".m2")).expect(".m2");
    fs::write(
        home.path().join(".m2/settings.xml"),
        "<settings><servers><server><id>corp</id><username>alice</username>\
         <password>fake-password</password></server></servers></settings>",
    )
    .expect("write settings.xml");
    let project = tempfile::tempdir().expect("project");
    write_repo_toml(project.path(), "r0", &format!("http://{}/", open.addr()));
    let raeva_toml = project.path().join("raeva.toml");
    let config = fs::read_to_string(&raeva_toml).expect("raeva.toml");
    fs::write(&raeva_toml, format!("{config}\n[lock]\nmaven = \"3.10\"\n")).expect("raeva.toml");
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &format!("<dependencies>{}</dependencies>", dependency("mid", "")),
        ),
    )
    .expect("write pom.xml");
    let cold = tempfile::tempdir().expect("cold home");
    for file in ["config.toml", ".m2/settings.xml"] {
        fs::create_dir_all(cold.path().join(".m2")).expect(".m2");
        fs::copy(home.path().join(file), cold.path().join(file)).expect("copy home file");
    }
    for (home, args) in [(&home, &["sync"][..]), (&cold, &["sync", "--frozen"][..])] {
        seen.lock().unwrap().clear();
        let output = run_raeva(project.path(), home.path(), args);
        assert_success(&output, &format!("{args:?}"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("fake-password"));
        let seen = seen.lock().unwrap().clone();
        let auths = |file: &str| -> Vec<bool> {
            (seen.iter())
                .filter(|(path, _)| path.ends_with(file))
                .map(|(_, auth)| *auth)
                .collect()
        };
        let lib: Vec<bool> = ["/lib-1.pom", "/lib-1.jar"]
            .iter()
            .flat_map(|f| auths(f))
            .collect();
        assert!(
            !lib.is_empty() && lib.iter().all(|auth| !auth),
            "{args:?}: {seen:?}"
        );
        assert!(
            auths("/mpar-1.pom").iter().all(|auth| *auth),
            "{args:?}: {seen:?}"
        );
        if args.len() == 1 {
            assert!(!auths("/mpar-1.pom").is_empty(), "{seen:?}");
        }
    }
}

/// `-itr` in `.mvn/maven.config`, as Quarkus has it: Maven 3.9.12 and
/// 3.10.0 then read no repository a dependency's POM declares, not even
/// for that POM's own parent, which they read from it without the flag.
/// raeva locks the same way, whatever `[security]` admits: with `rx`
/// allowlisted, `a`'s parent and dependency come from `rx` without the
/// flag, and with it `rx` is never asked and the parent is not found.
#[test]
fn ignore_transitive_repositories_in_maven_config_reads_no_descriptor_repository() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let rx = format!("http://{}/rx/", address.get().expect("address"));
        let declares = format!(
            "<repositories><repository><id>rx</id><url>{rx}</url></repository></repositories>"
        );
        let parent =
            "<parent><groupId>t</groupId><artifactId>p</artifactId><version>1</version></parent>";
        with_sha1(
            &request.path,
            [
                (
                    "/r1/t/a/1/a-1.pom",
                    pom(
                        "a",
                        &format!(
                            "{parent}{declares}<dependencies>{}</dependencies>",
                            dependency("x", "")
                        ),
                    ),
                ),
                ("/r1/t/a/1/a-1.jar", "a jar".to_string()),
                ("/rx/t/p/1/p-1.pom", pom("p", "<packaging>pom</packaging>")),
                ("/rx/t/x/1/x-1.pom", pom("x", "")),
                ("/rx/t/x/1/x-1.jar", "x jar".to_string()),
                ("/r1/t/q/1/q-1.pom", pom("q", &declares)),
                ("/r1/t/q/1/q-1.jar", "q jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    let rx = format!("http://{}/rx/", server.addr());
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    fs::write(
        home.path().join("config.toml"),
        format!("[security]\ntransitive_repository_allowlist = [\"{rx}\"]\n"),
    )
    .expect("write config.toml");
    write_repo_toml(
        project.path(),
        "r1",
        &format!("http://{}/r1/", server.addr()),
    );
    let write_pom = |artifact: &str| {
        fs::write(
            project.path().join("pom.xml"),
            pom(
                "app",
                &format!("<dependencies>{}</dependencies>", dependency(artifact, "")),
            ),
        )
        .expect("write pom.xml");
    };
    let asked_rx = || {
        (server.requests().iter())
            .filter(|r| r.path.starts_with("/rx/"))
            .count()
    };

    write_pom("a");
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "without -itr",
    );
    let lock = fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
    assert!(lock.contains("artifact = \"x\""), "{lock}");
    assert!(asked_rx() > 0);

    fs::create_dir_all(project.path().join(".mvn")).expect(".mvn");
    fs::write(project.path().join(".mvn/maven.config"), "-B\n-itr\n").expect("maven.config");
    let before = asked_rx();
    let stale = run_raeva(project.path(), home.path(), &["sync", "--frozen"]);
    assert_status(&stale, 7, "-itr makes the lock stale");
    let output = run_raeva(project.path(), home.path(), &["sync", "--update"]);
    assert_status(&output, 5, "the parent only rx holds");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("t:p:1"), "{stderr}");
    assert!(!stderr.contains("-itr"), "{stderr}");
    assert_eq!(asked_rx(), before, "rx is never asked under -itr");

    write_pom("q");
    let output = run_raeva(project.path(), home.path(), &["--json", "sync"]);
    assert_success(
        &output,
        "a dependency that declares rx and needs nothing from it",
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("TRANSITIVE_REPO_DROPPED"));
    assert_eq!(asked_rx(), before, "rx is never asked under -itr");
}
