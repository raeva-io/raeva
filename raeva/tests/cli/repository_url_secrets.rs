//! A repository URL with userinfo, a query or a fragment would put what may
//! be a credential into raeva.lock. Configuration and the project's POMs with
//! one are refused with exit 3, a dependency's POM with one is ignored, and
//! the secret reaches no output, log or lockfile.

use std::path::Path;
use std::process::Output;

use crate::common::{
    assert_status, assert_success, local_central, pom, raeva_command, with_sha1, write_repo_toml,
};
use rv_test_support::http::StubServer;

const SECRET: &str = "s3cretpass";

/// How doctor and the fetched-POM warning refuse a URL whose path takes the
/// value of `-Dcs.token`, with the remedy a sync refusal gives.
const DOTTED_IN_PATH: &str = "has the value of -Dcs.token as one or more whole path segments, \
    which raeva.lock would record, and that name looks like a secret's; if the value is a token, \
    give the URL with it to a settings.xml <mirror> of the repository, whose URL raeva.lock does \
    not record, or put the credential in a <server> with the repository's id; if it is not a \
    secret, rename -Dcs.token";

fn pom_repository(url: &str) -> String {
    format!("<repositories><repository><id>leaky</id><url>{url}</url></repository></repositories>")
}

fn sync_twice(project: &Path, home: &Path) -> Vec<Output> {
    let mut runs = Vec::new();
    for json in [true, false] {
        let mut args = vec!["sync"];
        if json {
            args.insert(0, "--json");
        }
        let output = raeva_command(project, home)
            .env("RAEVA_RETRIES", "0")
            .env("RUST_LOG", "debug")
            .args(&args)
            .output()
            .expect("run raeva sync");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!text.contains(SECRET), "json={json}: {text}");
        if let Ok(lock) = std::fs::read_to_string(project.join("raeva.lock")) {
            assert!(!lock.contains(SECRET), "{lock}");
        }
        runs.push(output);
    }
    runs
}

fn assert_refused(runs: &[Output], names: &str) {
    for output in runs {
        assert_status(output, 3, names);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stderr.contains(names) || stdout.contains(names),
            "{names}: {stdout}{stderr}"
        );
    }
}

#[test]
fn configured_urls_with_a_secret_part_are_refused() {
    let leaky = format!("https://user:{SECRET}@repo.example/m2/");
    let query = format!("https://repo.example/m2/?token={SECRET}");
    let settings_mirror = format!(
        "<settings><mirrors><mirror><id>corp</id><mirrorOf>*</mirrorOf><url>{leaky}</url>\
</mirror></mirrors></settings>"
    );
    let settings_profile = format!(
        "<settings><profiles><profile><id>p</id><repositories><repository><id>corp</id>\
<url>{leaky}</url></repository></repositories></profile></profiles></settings>"
    );
    let cases = [
        (
            "raeva.toml",
            format!("[[repositories]]\nid = \"corp\"\nurl = \"{leaky}\"\n"),
            "repository 'corp' has userinfo",
        ),
        (
            "raeva.toml",
            format!("[[repositories]]\nid = \"corp\"\nurl = \"{query}\"\n"),
            "repository 'corp' has a query",
        ),
        (
            "config.toml",
            format!("[[mirrors]]\nid = \"corp\"\nurl = \"{leaky}\"\nmirror_of = [\"*\"]\n"),
            "mirror 'corp' has userinfo",
        ),
        (
            "config.toml",
            format!("[[repositories]]\nurl = \"{leaky}\"\n"),
            "a repository without an id has userinfo",
        ),
        (
            "settings.xml",
            settings_mirror,
            "mirror 'corp' has userinfo",
        ),
        (
            "settings.xml",
            settings_profile,
            "repository 'corp' has userinfo",
        ),
    ];
    for (file, contents, names) in cases {
        let project = tempfile::tempdir().expect("project");
        let home = tempfile::tempdir().expect("home");
        std::fs::write(project.path().join("pom.xml"), pom("app", "")).expect("pom.xml");
        let path = match file {
            "raeva.toml" => project.path().join("raeva.toml"),
            "config.toml" => home.path().join("config.toml"),
            _ => {
                std::fs::create_dir_all(home.path().join(".m2")).expect(".m2");
                home.path().join(".m2").join("settings.xml")
            }
        };
        std::fs::write(&path, contents).expect("write config");
        let runs = sync_twice(project.path(), home.path());
        assert_refused(&runs, names);
        let stderr = String::from_utf8_lossy(&runs[1].stderr);
        assert!(
            stderr.contains("[[auth]]") || !names.contains("userinfo"),
            "{stderr}"
        );
        assert!(
            !project.path().join("raeva.lock").exists(),
            "{file}: {names}"
        );
    }
}

#[test]
fn a_project_pom_url_with_a_secret_part_is_refused() {
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &pom_repository(&format!("https://user:{SECRET}@repo.example/m2/")),
        ),
    )
    .expect("pom.xml");
    let runs = sync_twice(project.path(), home.path());
    assert_refused(&runs, "has userinfo, which raeva.lock would record");
    assert!(!project.path().join("raeva.lock").exists());
}

/// A dependency's POM is not the user's to fix, so its repository is
/// ignored with a warning that does not show the URL, even where transitive
/// repositories are allowed, and the lock is written without it.
#[test]
fn a_dependency_pom_url_with_a_secret_part_is_ignored() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let leaky = format!(
            "http://user:{SECRET}@{}/r1/",
            address.get().expect("address")
        );
        with_sha1(
            &request.path,
            [
                ("/r1/t/a/1/a-1.pom", pom("a", &pom_repository(&leaky))),
                ("/r1/t/a/1/a-1.jar", "a jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");

    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_transitive_repositories = true\n",
    )
    .expect("config.toml");
    std::fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<dependencies><dependency><groupId>t</groupId><artifactId>a</artifactId>\
<version>1</version></dependency></dependencies>",
        ),
    )
    .expect("pom.xml");
    write_repo_toml(
        project.path(),
        "r1",
        &format!("http://{}/r1/", server.addr()),
    );

    let runs = sync_twice(project.path(), home.path());
    for output in &runs {
        assert_success(output, "sync with leaked dependency repo URL");
    }
    let json = String::from_utf8_lossy(&runs[0].stdout);
    assert!(json.contains("REPO_URL_SECRET_REFUSED"), "{json}");
    assert!(json.contains("\"repository\":\"leaky\""), "{json}");
    let lock = std::fs::read_to_string(project.path().join("raeva.lock")).expect("raeva.lock");
    assert!(
        !lock.contains("http://user:") && !lock.contains(SECRET),
        "{lock}"
    );
}

/// A repository serving `t:a:1` under `/{SECRET}/r1/`, as services such as
/// Cloudsmith take a token in the path, `/stage/{SECRET}/r1/` and
/// `/open/r1/`, with the
/// raeva.toml entry that points Central at a 404 stand-in.
fn token_path_repository() -> (StubServer, StubServer, String) {
    let server = StubServer::start(|request| {
        let staged = format!("stage/{SECRET}");
        let files = [SECRET, "open", &staged].into_iter().flat_map(|top| {
            let base = format!("/{top}/r1/t/a/1/a-1");
            [
                (format!("{base}.pom"), pom("a", "")),
                (format!("{base}.jar"), "a jar".to_string()),
            ]
        });
        with_sha1(&request.path, files)
    });
    let (central, entry) = local_central();
    (server, central, entry)
}

const DEPENDENCY: &str = "<dependencies><dependency><groupId>t</groupId><artifactId>a</artifactId>\
<version>1</version></dependency></dependencies>";

/// A `-D` value, on the command line or in `.mvn/maven.config`, a
/// settings.xml property or an allowlisted environment variable named like a
/// secret may not fill a project POM's repository URL path, where raeva.lock
/// would record it, also through another property or in a profile the
/// property activates. The error names the repository and the input, and
/// never the value.
#[test]
fn a_project_pom_url_path_taking_a_secret_named_input_is_refused() {
    let (server, _central, central) = token_path_repository();
    let repository = |url: &str| {
        format!(
            "<repositories><repository><id>leaky</id><url>http://{}/{url}/r1/</url>\
</repository></repositories>",
            server.addr()
        )
    };
    let settings_property = format!(
        "<settings><activeProfiles><activeProfile>p</activeProfile></activeProfiles>\
<profiles><profile><id>p</id><properties><cs.token>{SECRET}</cs.token></properties></profile>\
</profiles></settings>"
    );
    let by_property = format!(
        "<profiles><profile><id>cs</id><activation><property><name>cs.token</name></property>\
</activation>{}</profile></profiles>",
        repository("${cs.token}")
    );
    let through_property = format!(
        "<properties><repo.path>${{cs.token}}</repo.path></properties>{}",
        repository("${repo.path}")
    );
    let define = format!("-Dcs.token={SECRET}");
    let staged = format!("-Dcs.token=${{stage}}/{SECRET}");
    let cases = [
        (by_property, Some(define.as_str()), "", "", "-Dcs.token"),
        (
            repository("${cs.token}"),
            None,
            ".mvn/maven.config",
            define.as_str(),
            "-Dcs.token",
        ),
        // A POM property the value names stands for any text.
        (
            format!(
                "<properties><stage>stage</stage></properties>{}",
                repository("${cs.token}").replace("<id>leaky", "<id>id-${cs.token}")
            ),
            None,
            ".mvn/maven.config",
            staged.as_str(),
            "-Dcs.token",
        ),
        (
            through_property,
            None,
            "settings.xml",
            settings_property.as_str(),
            "settings.xml property cs.token",
        ),
        (
            // An id that holds the value is not shown either.
            repository("${env.CS_TOKEN}").replace("<id>leaky", "<id>id-${env.CS_TOKEN}"),
            None,
            "config.toml",
            "[security]\nallow_env_substitution = [\"CS_TOKEN\"]\n",
            "${env.CS_TOKEN}",
        ),
        // A model reads `${NAME}` as `${env.NAME}`.
        (
            repository("${cs.token}"),
            Some("-Dcs.token=${CI_VALUE}"),
            "config.toml",
            "[security]\nallow_env_substitution = [\"CI_VALUE\"]\n",
            "-Dcs.token",
        ),
        (
            repository("${cs.token}"),
            Some("-Dcs.token=${env.CI_VALUE}"),
            "config.toml",
            "[security]\nallow_env_substitution = [\"CI_VALUE\"]\n",
            "-Dcs.token",
        ),
        (
            repository("${repo.path}"),
            Some("-Drepo.path=${CS_TOKEN}"),
            "config.toml",
            "[security]\nallow_env_substitution = [\"CS_TOKEN\"]\n",
            "${env.CS_TOKEN}",
        ),
    ];
    for (body, define, file, contents, input) in cases {
        let project = tempfile::tempdir().expect("project");
        let home = tempfile::tempdir().expect("home");
        std::fs::write(
            project.path().join("pom.xml"),
            pom("app", &format!("{body}{DEPENDENCY}")),
        )
        .expect("pom.xml");
        std::fs::write(project.path().join("raeva.toml"), &central).expect("raeva.toml");
        let path = match file {
            "" => None,
            "config.toml" => Some(home.path().join("config.toml")),
            "settings.xml" => Some(home.path().join(".m2").join("settings.xml")),
            _ => Some(project.path().join(file)),
        };
        if let Some(path) = path {
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, contents).expect("write input");
        }
        for json in [true, false] {
            let mut command = raeva_command(project.path(), home.path());
            command
                .env("CS_TOKEN", SECRET)
                .env("CI_VALUE", SECRET)
                .env("RAEVA_RETRIES", "0")
                .env("RUST_LOG", "debug");
            if json {
                command.arg("--json");
            }
            command.arg("sync").args(define);
            let output = command.output().expect("run raeva sync");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!text.contains(SECRET), "{input}: {text}");
            let entry = if body.contains("<id>id-") {
                "repository '***'"
            } else {
                "repository 'leaky'"
            };
            assert_refused(
                std::slice::from_ref(&output),
                &format!(
                    "the URL of {entry} it declares or inherits has the value of {input} as one \
                     or more whole path segments, which raeva.lock would record, and that name \
                     looks like a secret's; if the value is a token, give the URL with it to a \
                     settings.xml <mirror>"
                ),
            );
            assert_refused(
                std::slice::from_ref(&output),
                &format!("if it is not a secret, rename {input}"),
            );
            assert!(!project.path().join("raeva.lock").exists(), "{input}");
        }
    }
}

/// A property with a harmless name may give a repository URL its host and
/// path, and one named like a secret its host, as in
/// `${nexus.url}/repository/releases`.
#[test]
fn a_harmless_input_in_a_project_pom_url_still_resolves() {
    let (server, _central, central) = token_path_repository();
    for (url, define) in [
        (
            "${nexus.url}/r1/".to_string(),
            format!("-Dnexus.url=http://{}/open", server.addr()),
        ),
        (
            "http://${nexus.auth.host}/open/r1/".to_string(),
            format!("-Dnexus.auth.host={}", server.addr()),
        ),
    ] {
        let project = tempfile::tempdir().expect("project");
        let home = tempfile::tempdir().expect("home");
        let body = format!(
            "<repositories><repository><id>nexus</id><url>{url}</url></repository>\
</repositories>{DEPENDENCY}"
        );
        std::fs::write(project.path().join("pom.xml"), pom("app", &body)).expect("pom.xml");
        std::fs::write(project.path().join("raeva.toml"), &central).expect("raeva.toml");
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(["sync", define.as_str()])
            .output()
            .expect("run raeva sync");
        assert_success(&output, &define);
        let lock = std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
        assert!(
            lock.contains(&format!("http://{}/open/r1/", server.addr())),
            "{lock}"
        );
    }
}

/// A remote parent's repository whose URL path takes the value of a `-D`
/// named like a secret is ignored, as one with userinfo is, so neither
/// raeva.lock nor any message holds the value, also where the id holds it.
#[test]
fn a_remote_parent_url_path_taking_a_secret_named_input_is_ignored() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let parent = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
<repositories><repository><id>${{cs.token}}</id><url>http://{}/${{cs.token}}/r1/</url>\
</repository></repositories></project>",
            address.get().expect("address")
        );
        with_sha1(
            &request.path,
            [
                ("/r0/t/parent/1/parent-1.pom".to_string(), parent),
                (format!("/{SECRET}/r1/t/a/1/a-1.pom"), pom("a", "")),
                (format!("/{SECRET}/r1/t/a/1/a-1.jar"), "a jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");

    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_transitive_repositories = true\n",
    )
    .expect("config.toml");
    std::fs::write(
        project.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
<artifactId>parent</artifactId><version>1</version><relativePath/></parent>\
<artifactId>app</artifactId>{DEPENDENCY}</project>"
        ),
    )
    .expect("pom.xml");
    write_repo_toml(
        project.path(),
        "r0",
        &format!("http://{}/r0/", server.addr()),
    );
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .env("RUST_LOG", "debug")
        .args(["--json", "sync", &format!("-Dcs.token={SECRET}")])
        .output()
        .expect("run raeva sync");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains(SECRET), "{text}");
    assert!(
        text.contains("REPO_URL_SECRET_REFUSED")
            && text.contains("\"repository\":\"***\"")
            && text.contains("ignoring repository '***'")
            && text.contains(DOTTED_IN_PATH),
        "{text}"
    );
    assert!(!output.status.success(), "{text}");
    assert!(!project.path().join("raeva.lock").exists());
}

/// `raeva doctor` does not probe a project repository whose URL path takes
/// the value of a `-D` named like a secret, and shows neither the value nor
/// an id that holds it.
#[test]
fn doctor_does_not_show_a_secret_named_input_in_a_url_path() {
    let (server, _central, central) = token_path_repository();
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let body = format!(
        "<repositories><repository><id>${{cs.token}}</id><url>http://{}/${{cs.token}}/r1/</url>\
</repository></repositories>",
        server.addr()
    );
    std::fs::write(project.path().join("pom.xml"), pom("app", &body)).expect("pom.xml");
    std::fs::write(project.path().join("raeva.toml"), &central).expect("raeva.toml");
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .env("RUST_LOG", "debug")
        .args(["--json", "doctor", &format!("-Dcs.token={SECRET}")])
        .output()
        .expect("run raeva doctor");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains(SECRET), "{text}");
    assert!(
        text.contains("*** (pom.xml)") && text.contains(DOTTED_IN_PATH),
        "{text}"
    );
}

/// A dependency's model reads a `-D` value without the settings.xml
/// properties, so a repository it declares that takes the value as written
/// into its path is ignored too, whatever the transitive policy, and
/// neither the lock nor the dropped-repository warning holds the value.
#[test]
fn a_dependency_pom_url_path_taking_a_secret_named_input_is_ignored() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let leaky = format!(
            "<repositories><repository><id>leaky</id><url>http://{}/${{cs.token}}/r1/</url>\
</repository></repositories>",
            address.get().expect("address")
        );
        with_sha1(
            &request.path,
            [
                ("/r0/t/a/1/a-1.pom", pom("a", &leaky)),
                ("/r0/t/a/1/a-1.jar", "a jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    for policy in ["", "[security]\nallow_transitive_repositories = true\n"] {
        let project = tempfile::tempdir().expect("project");
        let home = tempfile::tempdir().expect("home");
        std::fs::write(home.path().join("config.toml"), policy).expect("config.toml");
        std::fs::create_dir_all(home.path().join(".m2")).expect(".m2");
        std::fs::write(
            home.path().join(".m2/settings.xml"),
            "<settings><activeProfiles><activeProfile>p</activeProfile></activeProfiles>\
<profiles><profile><id>p</id><properties><stage>dev</stage></properties></profile>\
</profiles></settings>",
        )
        .expect("settings.xml");
        std::fs::create_dir_all(project.path().join(".mvn")).expect(".mvn");
        std::fs::write(
            project.path().join(".mvn/maven.config"),
            format!("-Dcs.token=${{stage}}/{SECRET}\n"),
        )
        .expect("maven.config");
        std::fs::write(project.path().join("pom.xml"), pom("app", DEPENDENCY)).expect("pom.xml");
        write_repo_toml(
            project.path(),
            "r0",
            &format!("http://{}/r0/", server.addr()),
        );
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .env("RUST_LOG", "debug")
            .args(["--json", "sync"])
            .output()
            .expect("run raeva sync");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!text.contains(SECRET), "{policy}: {text}");
        assert!(
            text.contains("REPO_URL_SECRET_REFUSED") && text.contains(DOTTED_IN_PATH),
            "{policy}: {text}"
        );
        assert_success(&output, policy);
        let lock = std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
        assert!(!lock.contains(SECRET), "{lock}");
    }
}

/// A settings.xml mirror may take a secret-named `${env.NAME}` into its URL
/// path, as a token service expects. Messages and logs show `***` there,
/// also in the list of searched repositories a failed sync prints.
#[test]
fn a_secret_in_a_mirror_url_path_is_hidden_in_output() {
    // A missing file, and a jar whose checksum file does not match it.
    for broken_jar in [false, true] {
        mirror_secret_case(broken_jar);
    }
}

fn mirror_secret_case(broken_jar: bool) {
    let server = StubServer::start(move |request| {
        let base = format!("/{SECRET}/m2/t/a/1/a-1");
        if !broken_jar {
            return rv_test_support::http::Response::new(404, "");
        }
        if request.path == format!("{base}.jar.sha1") {
            return rv_test_support::http::Response::new(200, "0".repeat(40));
        }
        with_sha1(
            &request.path,
            [
                (format!("{base}.pom"), pom("a", "")),
                (format!("{base}.jar"), "a jar".to_string()),
            ],
        )
    });
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(project.path().join("pom.xml"), pom("app", DEPENDENCY)).expect("pom.xml");
    std::fs::create_dir_all(home.path().join(".m2")).expect(".m2");
    std::fs::write(
        home.path().join(".m2").join("settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>corp</id><mirrorOf>*</mirrorOf>\
             <url>http://{}/${{env.RAEVA_MIRROR_TOKEN}}/m2/</url></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .expect("settings.xml");
    for json in [true, false] {
        let mut args = vec!["sync"];
        if json {
            args.insert(0, "--json");
        }
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_MIRROR_TOKEN", SECRET)
            .env("RAEVA_RETRIES", "0")
            .env("RUST_LOG", "debug")
            .args(&args)
            .output()
            .expect("run raeva sync");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{text}");
        assert!(
            !text.contains(SECRET),
            "json={json} jar={broken_jar}: {text}"
        );
        assert!(
            text.contains("/***/m2/"),
            "json={json} jar={broken_jar}: {text}"
        );
    }
}
