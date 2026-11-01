//! Repositories a dependency's POM declares.

use std::fs;

use crate::common::{assert_status, pom, raeva_command, run_raeva, with_sha1, write_repo_toml};
use rv_test_support::http::StubServer;

fn dependency(artifact: &str, extra: &str) -> String {
    format!(
        "<dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
<version>1</version>{extra}</dependency>"
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
            fs::write(dir.join(name), &bytes).expect("write");
            fs::write(
                dir.join(format!("{name}.sha256")),
                crate::common::sha256_hex(&bytes),
            )
            .expect("write");
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
        fs::write(dir.join(name), &bytes).expect("write");
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(&bytes),
        )
        .expect("write");
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
