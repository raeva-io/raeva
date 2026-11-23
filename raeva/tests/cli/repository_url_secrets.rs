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

/// How doctor and the fetched-POM warning refuse a URL that takes
/// `-Dcs.token`, with the remedy a sync refusal gives.
const DOTTED_IN_PATH: &str = "takes -Dcs.token, \
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
            "mirror 'corp' has userinfo; raeva takes a mirror's credentials only from",
        ),
        (
            "config.toml",
            format!("[[mirrors]]\nid = \"corp\"\nurl = \"{query}\"\nmirror_of = [\"*\"]\n"),
            "mirror 'corp' has a query, which raeva drops as it appends artifact paths",
        ),
        (
            "config.toml",
            format!("[[repositories]]\nurl = \"{leaky}\"\n"),
            "a repository without an id has userinfo",
        ),
        (
            "settings.xml",
            settings_mirror,
            "mirror 'corp' has userinfo; raeva takes a mirror's credentials only from",
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
        // raeva.lock records no mirror's URL.
        assert!(
            !names.starts_with("mirror") || !stderr.contains("raeva.lock"),
            "{stderr}"
        );
        assert!(
            !project.path().join("raeva.lock").exists(),
            "{file}: {names}"
        );
    }
}

/// Also in `<pluginRepositories>`, which serve build extensions whether
/// or not the plugins are locked.
#[test]
fn a_project_pom_url_with_a_secret_part_is_refused() {
    let repository = pom_repository(&format!("https://user:{SECRET}@repo.example/m2/"));
    let plugin_repository = (repository.replace("<repositor", "<pluginRepositor"))
        .replace("</repositor", "</pluginRepositor");
    // One that does not parse, which a mirror could serve, is screened too.
    // raeva.lock records neither of these, so the refusal says why it holds.
    let unparsable = pom_repository(&format!("http://[::1?token={SECRET}"));
    let ftp = pom_repository(&format!("ftp://u:{SECRET}@repo.example/m2/"));
    let recorded = "which raeva.lock would record";
    let any = "which raeva refuses in a URL of any scheme, though raeva.lock records only http, \
               https and file URLs";
    for (body, entry, part, reason) in [
        (repository, "repository 'leaky'", "userinfo", recorded),
        (
            plugin_repository,
            "plugin repository 'leaky'",
            "userinfo",
            recorded,
        ),
        (unparsable, "repository 'leaky'", "a query", any),
        (ftp, "repository 'leaky'", "userinfo", any),
    ] {
        let project = tempfile::tempdir().expect("project");
        let home = tempfile::tempdir().expect("home");
        std::fs::write(project.path().join("pom.xml"), pom("app", &body)).expect("pom.xml");
        let runs = sync_twice(project.path(), home.path());
        assert_refused(
            &runs,
            &format!("{entry} it declares or inherits has {part}, {reason}"),
        );
        assert!(!project.path().join("raeva.lock").exists());
    }
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

/// A dependency's repository that the default configuration drops is
/// reported as dropped (`TRANSITIVE_REPO_DROPPED`), whatever else keeps
/// raeva from reading it: a layout Maven reaches only through a mirror, a
/// `file:` URL raeva does not read, or an id that takes a `${...}`. Once
/// the policy admits them, a layout raeva does not read is ignored as
/// `REPOSITORY_IGNORED`, and an id no mirror or credential tells apart from
/// its text as written is read. Only a URL that may hold a credential is
/// `REPO_URL_SECRET_REFUSED`, either way.
#[test]
fn a_dependency_repository_is_reported_by_why_raeva_does_not_read_it() {
    let declared = "<properties><p2id>eclipse</p2id><libid>libs</libid></properties>\
<repositories>\
<repository><id>java.net</id><url>https://legacy.example/m2/</url><layout>legacy</layout>\
</repository>\
<repository><id>${p2id}</id><url>https://p2.example/m2/</url><layout>p2</layout></repository>\
<repository><id>local-libs</id><url>file://${project.basedir}/lib/</url></repository>\
<repository><id>${libid}</id><url>https://libs.example/m2/</url></repository>\
<repository><id>query</id><url>https://query.example/m2/?page=1</url></repository>\
</repositories>";
    let server = StubServer::start(move |request| {
        with_sha1(
            &request.path,
            [
                ("/r1/t/a/1/a-1.pom", pom("a", declared)),
                ("/r1/t/a/1/a-1.jar", "a jar".to_string()),
            ],
        )
    });
    for (config, ignored) in [
        ("", "TRANSITIVE_REPO_DROPPED"),
        (
            "[security]\nallow_transitive_repositories = true\n",
            "REPOSITORY_IGNORED",
        ),
    ] {
        let project = tempfile::tempdir().expect("project");
        let home = tempfile::tempdir().expect("home");
        std::fs::write(home.path().join("config.toml"), config).expect("config.toml");
        std::fs::write(project.path().join("pom.xml"), pom("app", DEPENDENCY)).expect("pom.xml");
        write_repo_toml(
            project.path(),
            "r1",
            &format!("http://{}/r1/", server.addr()),
        );
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(["--json", "sync"])
            .output()
            .expect("run raeva sync");
        assert_success(&output, config);
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON output");
        let mut warned: Vec<(String, String)> = (json["data"]["warnings"].as_array())
            .into_iter()
            .flatten()
            .filter(|warning| {
                (warning["code"].as_str()).is_some_and(|code| code.starts_with("REPO"))
                    || warning["code"] == "TRANSITIVE_REPO_DROPPED"
            })
            .map(|warning| {
                let context = &warning["context"];
                let target = (context["repository"].as_str())
                    .or_else(|| context["url"].as_str())
                    .unwrap_or_default();
                (
                    warning["code"].as_str().unwrap_or_default().to_string(),
                    target.to_string(),
                )
            })
            .collect();
        warned.sort();
        let mut expected: Vec<(String, String)> = match ignored {
            "TRANSITIVE_REPO_DROPPED" => [
                "file://${project.basedir}/lib/",
                "https://legacy.example/m2/",
                "https://libs.example/m2/",
                "https://p2.example/m2/",
            ]
            .map(|url| (ignored.to_string(), url.to_string()))
            .to_vec(),
            // The policy reads no `file:` URL of a fetched POM, and the
            // lineage as written names the layout's id as written.
            _ => vec![
                (
                    "TRANSITIVE_REPO_DROPPED".to_string(),
                    "file://${project.basedir}/lib/".to_string(),
                ),
                (ignored.to_string(), "${p2id}".to_string()),
                (ignored.to_string(), "java.net".to_string()),
            ],
        };
        expected.push(("REPO_URL_SECRET_REFUSED".to_string(), "query".to_string()));
        expected.sort();
        assert_eq!(warned, expected, "{config}: {json}");
    }
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

/// A settings.xml profile property with a harmless name that takes the
/// variable `CS_API_KEY`, which no allowlist lets a POM read.
const SLUG_SETTINGS: &str = "<settings><activeProfiles><activeProfile>p</activeProfile>\
</activeProfiles><profiles><profile><id>p</id><properties>\
<cs.slug>${env.CS_API_KEY}</cs.slug></properties></profile></profiles></settings>";

/// A `-D` value, on the command line or in `.mvn/maven.config`, a
/// settings.xml property or an allowlisted environment variable named like a
/// secret may not fill a project POM's repository URL path, where raeva.lock
/// would record it, also through another property or in a profile the
/// property activates, nor may an input that takes a value from one. The
/// error names the repository and the input, and never the value.
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
    let alias = "${env.CS_API_KEY} (through settings.xml property cs.slug)";
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
            "${env.CS_TOKEN} (through -Drepo.path)",
        ),
        // settings.xml reads any variable, and a harmless name passes the
        // value on.
        (
            repository("${cs.slug}"),
            None,
            "settings.xml",
            SLUG_SETTINGS,
            alias,
        ),
        (
            format!(
                "<properties><repo.path>${{hop}}</repo.path></properties>{}",
                repository("${repo.path}")
            ),
            Some("-Dhop=${cs.slug}"),
            "settings.xml",
            SLUG_SETTINGS,
            alias,
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
                .env("CS_API_KEY", SECRET)
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
                    "the URL of {entry} it declares or inherits takes {input}, which raeva.lock \
                     would record, and that name \
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
/// path, as in `${nexus.url}/repository/releases`. One named like a secret
/// may not, even in the host and with a harmless value: the name decides.
#[test]
fn a_harmless_input_in_a_project_pom_url_still_resolves() {
    let (server, _central, central) = token_path_repository();
    for (url, define, refused) in [
        (
            "${nexus.url}/r1/".to_string(),
            format!("-Dnexus.url=http://{}/open", server.addr()),
            false,
        ),
        (
            "http://${nexus.auth.host}/open/r1/".to_string(),
            format!("-Dnexus.auth.host={}", server.addr()),
            true,
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
        if refused {
            assert_refused(
                std::slice::from_ref(&output),
                "takes -Dnexus.auth.host, which raeva.lock would record",
            );
            continue;
        }
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

/// raeva.lock records a project repository's id and messages show it, so
/// sync refuses one that holds the value of a `-D` named like a secret, and
/// doctor refuses it without the value.
#[test]
fn a_project_pom_repository_id_taking_a_secret_named_input_is_refused() {
    for (list, element) in [
        ("repositories", "repository"),
        ("pluginRepositories", "pluginRepository"),
    ] {
        let project = tempfile::tempdir().expect("project");
        let home = tempfile::tempdir().expect("home");
        let body = format!(
            "<{list}><{element}><id>${{cs.token}}</id><url>https://repo.example/m2/</url>\
             </{element}></{list}>"
        );
        std::fs::write(project.path().join("pom.xml"), pom("app", &body)).expect("pom.xml");
        let define = format!("-Dcs.token={SECRET}");
        for command in ["sync", "doctor"] {
            let output = raeva_command(project.path(), home.path())
                .env("RAEVA_RETRIES", "0")
                .args(["--json", command, &define])
                .output()
                .expect("run raeva");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!text.contains(SECRET), "{text}");
            assert!(
                text.contains("takes -Dcs.token, which raeva.lock"),
                "{text}"
            );
            assert_status(&output, 3, command);
        }
        assert!(!project.path().join("raeva.lock").exists());
    }
}

/// Nor may it hold the value of a settings.xml property that took a
/// secret-named variable.
#[test]
fn a_project_pom_repository_id_taking_an_alias_of_a_secret_is_refused() {
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let body = "<repositories><repository><id>${cs.slug}</id><url>https://repo.example/m2/</url>\
                </repository></repositories>";
    std::fs::write(project.path().join("pom.xml"), pom("app", body)).expect("pom.xml");
    let settings = home.path().join(".m2").join("settings.xml");
    std::fs::create_dir_all(settings.parent().expect("parent")).expect("mkdir");
    std::fs::write(&settings, SLUG_SETTINGS).expect("settings.xml");
    for command in ["sync", "doctor"] {
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .env("CS_API_KEY", SECRET)
            .args(["--json", command])
            .output()
            .expect("run raeva");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!text.contains(SECRET), "{text}");
        assert!(
            text.contains(
                "takes ${env.CS_API_KEY} (through settings.xml property cs.slug), which \
                 raeva.lock"
            ),
            "{text}"
        );
        assert_status(&output, 3, command);
    }
    assert!(!project.path().join("raeva.lock").exists());
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

/// A mirror whose URL path takes a token redirects to another origin, which
/// raeva rejects naming the target: a URL the server chose, with the token
/// in its path or in its userinfo. Each output hides the token's value,
/// however short, at every `-v` level, in `--json` and in each `doctor`.
#[test]
fn a_secret_in_a_rejected_redirect_target_is_hidden() {
    for (token, userinfo) in [("zqREDIRzq", false), ("zqREDIRzq", true), ("QzWj", false)] {
        let target = StubServer::start(|_| rv_test_support::http::Response::new(404, ""));
        let target_addr = target.addr();
        let mirror = StubServer::start(move |request| {
            let rest = request.path.trim_start_matches("/redir/");
            let location = match userinfo {
                true => format!("http://u:{token}@{target_addr}/{rest}"),
                false => format!("http://{target_addr}/{rest}?token=other"),
            };
            rv_test_support::http::Response::new(302, "").header("Location", location)
        });
        let project = tempfile::tempdir().expect("project");
        let home = tempfile::tempdir().expect("home");
        std::fs::write(project.path().join("pom.xml"), pom("app", DEPENDENCY)).expect("pom.xml");
        std::fs::create_dir_all(home.path().join(".m2")).expect(".m2");
        std::fs::write(
            home.path().join(".m2").join("settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>corp</id><mirrorOf>*</mirrorOf>\
                 <url>http://{}/redir/${{env.RAEVA_MIRROR_TOKEN}}/</url></mirror></mirrors>\
                 </settings>",
                mirror.addr()
            ),
        )
        .expect("settings.xml");
        for args in [
            &["sync"][..],
            &["-v", "sync"],
            &["-vv", "sync"],
            &["-vvv", "sync"],
            &["--json", "sync"],
            &["--json", "-vv", "sync"],
            &["doctor"],
            &["-vv", "doctor"],
            &["--json", "doctor"],
        ] {
            let output = raeva_command(project.path(), home.path())
                .env("RAEVA_MIRROR_TOKEN", token)
                .env("RAEVA_RETRIES", "0")
                .args(args)
                .output()
                .expect("run raeva");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let case = format!("{token} userinfo={userinfo} {args:?}");
            assert!(!output.status.success(), "{case}: {text}");
            assert!(!text.contains(token), "{case}: {text}");
            // The target, which doctor's probe and sync's fetch name.
            let rejected = format!("http://{target_addr}/***/");
            assert!(
                text.contains("cross-origin redirect rejected") && text.contains(&rejected),
                "{case}: {text}"
            );
        }
    }
}

/// A fetched POM's repository id that holds the value of a `-D` named like
/// a secret: from a dependency's POM, which the allowlist admits, and from
/// the project's remote parent. raeva.lock records an admitted
/// repository's id and messages show it, so the repository is ignored, as
/// one whose URL path holds such a value, and no output or lock holds the
/// value. A dependency's `b`, which only that repository has, is then not
/// found; the parent's declaration as written still lists it.
#[test]
fn a_fetched_pom_repository_id_taking_a_secret_named_input_is_ignored() {
    let own = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let address = std::sync::Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let declared = format!(
            "<repositories><repository><id>${{cs.token}}</id><url>http://{}/r1/</url>\
</repository></repositories>",
            address.get().expect("address")
        );
        let parent = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>{declared}</project>"
        );
        let below = "<dependencies><dependency><groupId>t</groupId><artifactId>b</artifactId>\
<version>1</version></dependency></dependencies>";
        with_sha1(
            &request.path,
            [
                ("/r0/t/parent/1/parent-1.pom".to_string(), parent),
                (
                    "/r0/t/a/1/a-1.pom".to_string(),
                    pom("a", &format!("{declared}{below}")),
                ),
                ("/r0/t/a/1/a-1.jar".to_string(), "a jar".to_string()),
                ("/r1/t/b/1/b-1.pom".to_string(), pom("b", "")),
                ("/r1/t/b/1/b-1.jar".to_string(), "b jar".to_string()),
            ],
        )
    });
    own.set(server.addr().to_string())
        .expect("address set once");
    for parent in [false, true] {
        let project = tempfile::tempdir().expect("project");
        let home = tempfile::tempdir().expect("home");
        std::fs::write(
            home.path().join("config.toml"),
            format!(
                "[security]\ntransitive_repository_allowlist = [\"http://{}/r1/\"]\n",
                server.addr()
            ),
        )
        .expect("config.toml");
        let pom_xml = match parent {
            true => "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
<artifactId>parent</artifactId><version>1</version><relativePath/></parent>\
<artifactId>app</artifactId><dependencies><dependency><groupId>t</groupId>\
<artifactId>b</artifactId><version>1</version></dependency></dependencies></project>"
                .to_string(),
            false => pom("app", DEPENDENCY),
        };
        std::fs::write(project.path().join("pom.xml"), pom_xml).expect("pom.xml");
        write_repo_toml(
            project.path(),
            "r0",
            &format!("http://{}/r0/", server.addr()),
        );
        let define = format!("-Dcs.token={SECRET}");
        let mut text = String::new();
        for args in [
            &["--json", "sync", &define][..],
            &["-v", "sync", &define],
            &["--json", "doctor", &define],
            &["doctor", &define],
        ] {
            let output = raeva_command(project.path(), home.path())
                .env("RAEVA_RETRIES", "0")
                .env("RUST_LOG", "debug")
                .args(args)
                .output()
                .expect("run raeva");
            text.push_str(&String::from_utf8_lossy(&output.stdout));
            text.push_str(&String::from_utf8_lossy(&output.stderr));
        }
        assert!(!text.contains(SECRET), "parent {parent}: {text}");
        assert!(
            text.contains("REPO_URL_SECRET_REFUSED")
                && text.contains("ignoring repository '***'")
                && text.contains("because its id takes -Dcs.token"),
            "parent {parent}: {text}"
        );
        let lock = std::fs::read_to_string(project.path().join("raeva.lock")).unwrap_or_default();
        assert!(!lock.contains(SECRET), "parent {parent}: {lock}");
        // The lineage still lists the parent's declaration as written.
        assert_eq!(lock.is_empty(), !parent, "parent {parent}: {lock}");
    }
}

/// Every file under `dir` that holds `value`.
fn files_holding(dir: &Path, value: &str) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if std::fs::read(&path).is_ok_and(|bytes| {
                bytes
                    .windows(value.len())
                    .any(|window| window == value.as_bytes())
            }) {
                found.push(path);
            }
        }
    }
    found
}

/// A `file:` repository's directory is recorded in raeva.lock as an https
/// URL's path is, so a secret-named input there is refused (exit 3) from
/// settings.xml, the project POM, `-D`, `.mvn/maven.config`, a settings
/// property and an allowlisted `${env.NAME}`, and its value reaches neither
/// output, the lock nor raeva's home. `${user.home}` and `${env.HOME}` there
/// still work.
#[test]
fn a_file_url_path_taking_a_secret_named_input_is_refused() {
    use crate::offline_project::Project;
    let lib = "<dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
               <version>1.0</version></dependency></dependencies>";
    let pom = |url: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><repositories><repository>\
             <id>prj</id><url>{url}</url></repository></repositories>{lib}</project>"
        )
    };
    let settings_repository = |url: &str| {
        format!(
            "<settings><profiles><profile><id>s</id><repositories><repository><id>srepo</id>\
             <url>{url}</url></repository></repositories></profile></profiles><activeProfiles>\
             <activeProfile>s</activeProfile></activeProfiles></settings>"
        )
    };
    let in_project = "file://${project.basedir}/repository/";
    let define = format!("-Dx.token={SECRET}");
    let settings_property = format!(
        "<settings><profiles><profile><id>s</id><properties><x.token>{SECRET}</x.token>\
         </properties></profile></profiles><activeProfiles><activeProfile>s</activeProfile>\
         </activeProfiles></settings>"
    );
    // (POM repository URL, settings.xml, .mvn/maven.config, config.toml, argument)
    let secret_dir = format!("{in_project}${{x.token}}/");
    let cases: Vec<(String, String, &str, &str, Option<&str>)> = vec![
        (secret_dir.clone(), String::new(), "", "", Some(&define)),
        (secret_dir.clone(), String::new(), &define, "", None),
        (secret_dir.clone(), settings_property, "", "", None),
        // Inside a segment.
        (
            format!("{in_project}repo-${{x.token}}/"),
            String::new(),
            "",
            "",
            Some(&define),
        ),
        (
            format!("{in_project}${{env.X_TOKEN}}/"),
            String::new(),
            "",
            "[security]\nallow_env_substitution = [\"X_TOKEN\"]\n",
            None,
        ),
        (
            in_project.to_string(),
            settings_repository("file:///srv/${env.X_TOKEN}/"),
            "",
            "",
            None,
        ),
        (
            in_project.to_string(),
            settings_repository("file:///srv/${X_TOKEN}/"),
            "",
            "",
            None,
        ),
        (
            in_project.to_string(),
            settings_repository("file:///srv/${x.token}/"),
            "",
            "",
            Some(&define),
        ),
    ];
    for mode in ["3.9", "3.10"] {
        for (url, settings, maven_config, config, argument) in &cases {
            let project = Project::with(&[]);
            let root = project.root();
            crate::common::publish(
                &root.join("repository").join(SECRET),
                "org.test:lib:1.0",
                "",
            );
            std::fs::write(root.join("pom.xml"), pom(url)).unwrap();
            std::fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .unwrap();
            if !settings.is_empty() {
                std::fs::write(project.m2_settings(), settings).unwrap();
            }
            if !maven_config.is_empty() {
                std::fs::create_dir_all(root.join(".mvn")).unwrap();
                std::fs::write(root.join(".mvn/maven.config"), maven_config).unwrap();
            }
            if !config.is_empty() {
                std::fs::create_dir_all(project.raeva_home()).unwrap();
                std::fs::write(project.raeva_home().join("config.toml"), config).unwrap();
            }
            let mut args = vec!["sync", "--offline"];
            args.extend(*argument);
            let output = project.raeva_with(&[("X_TOKEN", SECRET)], &args);
            let case = format!("{mode} {url} {settings} {maven_config} {config}");
            assert_status(&output, 3, &case);
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!text.contains(SECRET), "{case}: {text}");
            assert!(!root.join("raeva.lock").exists(), "{case}");
            let written = project.m2_settings();
            let held: Vec<_> = (files_holding(project.raeva_home(), SECRET).into_iter())
                .filter(|path| *path != written)
                .collect();
            assert!(held.is_empty(), "{case}: {held:?}");
        }
        let project = Project::with(&[]);
        let root = project.root();
        std::fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .unwrap();
        std::fs::write(root.join("pom.xml"), pom(in_project)).unwrap();
        for home in ["${user.home}", "${env.HOME}"] {
            std::fs::write(
                project.m2_settings(),
                settings_repository(&format!("file://{home}/corp/")),
            )
            .unwrap();
            assert_success(&project.raeva(&["sync", "--offline"]), home);
            let lock = std::fs::read_to_string(root.join("raeva.lock")).unwrap();
            assert!(lock.contains("srepo"), "{home}: {lock}");
        }
    }
}

/// A settings.xml mirror URL may take a secret, which raeva.lock does not
/// record, but the store index, a seed and output must not hold its value
/// either: not when the URL takes it through a `-D` alias of a secret-named
/// one, nor when it is a relative `file:` directory, which raeva reads as an
/// absolute one.
#[test]
fn a_file_mirror_taking_a_secret_keeps_it_out_of_the_store_and_seed() {
    use crate::offline_project::Project;
    let lib = "<dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
               <version>1.0</version></dependency></dependencies>";
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>prj</id><url>https://repo.invalid/</url></repository></repositories>{lib}</project>"
    );
    let token = format!("-Drepo.token={SECRET}");
    let cases: [(&str, &[&str]); 2] = [
        ("file:mirror/${alias}/", &["-Dalias=${repo.token}", &token]),
        ("file:mirror/${env.X_TOKEN}/", &[]),
    ];
    for mode in ["3.9", "3.10"] {
        for (url, defines) in &cases {
            let project = Project::with(&[]);
            let root = project.root();
            crate::common::publish(&root.join("mirror").join(SECRET), "org.test:lib:1.0", "");
            std::fs::write(root.join("pom.xml"), &pom).unwrap();
            std::fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .unwrap();
            std::fs::write(
                project.m2_settings(),
                format!(
                    "<settings><mirrors><mirror><id>m</id><url>{url}</url>\
                     <mirrorOf>*</mirrorOf></mirror></mirrors></settings>"
                ),
            )
            .unwrap();
            let mut args = vec!["sync"];
            args.extend(defines.iter());
            let case = format!("{mode} {url}");
            let sync = project.raeva_with(&[("X_TOKEN", SECRET)], &args);
            assert_success(&sync, &case);
            let seed = root.join("seed");
            let mut save_args = vec!["seed", "save", seed.to_str().unwrap()];
            save_args.extend(defines.iter());
            let save = project.raeva_with(&[("X_TOKEN", SECRET)], &save_args);
            assert_success(&save, &case);
            for output in [&sync, &save] {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(!text.contains(SECRET), "{case}: {text}");
            }
            let lock = std::fs::read_to_string(root.join("raeva.lock")).unwrap();
            assert!(!lock.contains(SECRET), "{case}: {lock}");
            let written = project.m2_settings();
            let held: Vec<_> = (files_holding(project.raeva_home(), SECRET).into_iter())
                .chain(files_holding(&seed, SECRET))
                .filter(|path| *path != written)
                .collect();
            assert!(held.is_empty(), "{case}: {held:?}");
        }
    }
}

/// A file a `file:` mirror cannot read is named by the mirror URL as
/// messages show it, not by its path, which holds the secret the URL takes.
#[cfg(unix)]
#[test]
fn an_unreadable_file_under_a_secret_file_mirror_keeps_the_secret_out_of_output() {
    use crate::offline_project::Project;
    use std::os::unix::fs::PermissionsExt;
    let project = Project::with(&[]);
    let root = project.root();
    let repo = root.join("mirror").join(SECRET);
    crate::common::publish(&repo, "org.test:lib:1.0", "");
    let pom = repo.join("org/test/lib/1.0/lib-1.0.pom");
    std::fs::set_permissions(&pom, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&pom).is_ok() {
        // Running as root reads it anyway.
        return;
    }
    std::fs::write(
        root.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>\
         </dependency></dependencies></project>",
    )
    .unwrap();
    std::fs::write(
        project.m2_settings(),
        "<settings><mirrors><mirror><id>m</id><url>file:mirror/${env.X_TOKEN}/</url>\
         <mirrorOf>*</mirrorOf></mirror></mirrors></settings>",
    )
    .unwrap();
    for mode in ["3.9", "3.10"] {
        std::fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .unwrap();
        let output = project.raeva_with(&[("X_TOKEN", SECRET)], &["sync", "-vv"]);
        assert!(!output.status.success(), "{mode}");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(text.contains("Permission denied"), "{mode}: {text}");
        assert!(!text.contains(SECRET), "{mode}: {text}");
    }
    std::fs::set_permissions(&pom, std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// A repository URL that takes a secret-named input, or a property that
/// takes a value from one, refuses by that name, whatever the value's
/// length and wherever it lands: the host, a path segment or part of one,
/// in settings.xml or a POM, from a `-D`, an alias or the allowlisted
/// environment. No lock is written, and neither the store nor `-vv` output
/// holds the value. A mirror's URL, which raeva.lock does not record, is
/// masked instead.
#[test]
fn a_url_taking_a_secret_named_input_refuses_whatever_its_value() {
    use crate::offline_project::Project;
    const SHORT: &str = "q7z4";
    let pom = |url: &str, properties: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><properties>{properties}\
             </properties><repositories><repository><id>prj</id><url>{url}</url>\
             </repository></repositories><dependencies><dependency><groupId>org.test\
             </groupId><artifactId>lib</artifactId><version>1.0</version></dependency>\
             </dependencies></project>"
        )
    };
    let settings = |url: &str, mirror: &str| {
        let mirrors = match mirror {
            "" => String::new(),
            url => format!(
                "<mirrors><mirror><id>m</id><url>{url}</url><mirrorOf>*</mirrorOf></mirror>\
                 </mirrors>"
            ),
        };
        format!(
            "<settings>{mirrors}<profiles><profile><id>s</id><repositories><repository>\
             <id>srepo</id><url>{url}</url></repository></repositories></profile></profiles>\
             <activeProfiles><activeProfile>s</activeProfile></activeProfiles></settings>"
        )
    };
    let in_project = "file://${project.basedir}/repository/";
    let token = format!("-Dx.token={SHORT}");
    let allow = "[security]\nallow_env_substitution = [\"API_TOKEN\"]\n";
    // (POM repository URL, POM properties, settings.xml, config.toml, arguments, refused)
    type Case<'a> = (String, &'a str, String, &'a str, Vec<&'a str>, bool);
    let cases: Vec<Case<'_>> = vec![
        (
            in_project.into(),
            "",
            settings("https://${repo.token}.example.invalid/m2/", ""),
            "",
            vec!["-Drepo.token=q7z4"],
            true,
        ),
        (
            "file://${project.basedir}/repo-${x.token}/".into(),
            "",
            String::new(),
            "",
            vec![&token],
            true,
        ),
        (
            "https://repo.invalid/repo-${env.API_TOKEN}/".into(),
            "",
            String::new(),
            allow,
            vec![],
            true,
        ),
        (
            in_project.into(),
            "",
            settings("https://repo.invalid/repo-${env.API_TOKEN}/", ""),
            "",
            vec![],
            true,
        ),
        (
            "file://${project.basedir}/repo-${alias}/".into(),
            "",
            String::new(),
            "",
            vec![&token, "-Dalias=${x.token}"],
            true,
        ),
        (
            "file://${project.basedir}/repo-${p}/".into(),
            "<p>${x.token}</p>",
            String::new(),
            "",
            vec![&token],
            true,
        ),
        (
            "https://${x.token}.example.invalid/m2/".into(),
            "",
            String::new(),
            "",
            vec![&token],
            true,
        ),
        // settings.xml expands twice, so a variable's value may name one.
        (
            in_project.into(),
            "",
            settings("https://repo.invalid/repo-${env.ROUTE}/", ""),
            "",
            vec![],
            true,
        ),
        // A coordinate is expanded before the URL that reads it.
        (
            "file://${project.basedir}/repo-${project.version}/".into(),
            "",
            String::new(),
            "",
            vec![&token],
            true,
        ),
        // The id `prj-${repo.token}` takes it too, with the URL or alone.
        (
            "https://repo.invalid/repo-${repo.token}/".into(),
            "<repo.token>${supplied}</repo.token>",
            String::new(),
            "",
            vec!["-Dsupplied=q7z4"],
            true,
        ),
        (
            in_project.into(),
            "<repo.token>${supplied}</repo.token>",
            String::new(),
            "",
            vec!["-Dsupplied=q7z4"],
            true,
        ),
        (
            "https://repo.invalid/m2/".into(),
            "",
            settings(
                "https://repo.invalid/s/",
                "https://${env.API_TOKEN}.example.invalid/m2/",
            ),
            "",
            vec![],
            false,
        ),
    ];
    for mode in ["3.9", "3.10"] {
        for (url, properties, settings, config, arguments, refused) in &cases {
            let project = Project::with(&[]);
            let root = project.root();
            crate::common::publish(&root.join("repository"), "org.test:lib:1.0", "");
            let mut text = pom(url, properties);
            if url.contains("${project.version}") {
                text = text.replacen("<version>1</version>", "<version>${x.token}</version>", 1);
            }
            if properties.contains("<repo.token>") {
                text = text.replacen("<id>prj</id>", "<id>prj-${repo.token}</id>", 1);
            }
            std::fs::write(root.join("pom.xml"), text).unwrap();
            std::fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .unwrap();
            if !settings.is_empty() {
                std::fs::write(project.m2_settings(), settings).unwrap();
            }
            if !config.is_empty() {
                std::fs::create_dir_all(project.raeva_home()).unwrap();
                std::fs::write(project.raeva_home().join("config.toml"), config).unwrap();
            }
            // A mirror is also tried, as the HTTP library logs each host
            // it connects to.
            let args: Vec<&str> = match refused {
                true => vec!["sync", "--offline", "-vv"],
                false => vec!["sync", "-vvv"],
            };
            let args = [&args[..], &arguments[..]].concat();
            let output = project.raeva_with(
                &[("API_TOKEN", SHORT), ("ROUTE", "${env.API_TOKEN}")],
                &args,
            );
            let case = format!("{mode} {url} {properties} {settings} {arguments:?}");
            if *refused {
                assert_status(&output, 3, &case);
                assert!(!root.join("raeva.lock").exists(), "{case}");
            }
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!text.contains(SHORT), "{case}: {text}");
            if let Ok(lock) = std::fs::read_to_string(root.join("raeva.lock")) {
                assert!(!lock.contains(SHORT), "{case}: {lock}");
            }
            let written = project.m2_settings();
            let held: Vec<_> = (files_holding(project.raeva_home(), SHORT).into_iter())
                .filter(|path| *path != written)
                .collect();
            assert!(held.is_empty(), "{case}: {held:?}");
        }
    }
}

/// Doctor names neither the directory of a `file:` mirror nor the host of
/// an http one when the mirror's URL takes a secret-named variable.
#[test]
fn doctor_masks_a_mirror_host_and_directory_that_take_a_secret() {
    use crate::offline_project::Project;
    const SHORT: &str = "q7z4";
    // Without a drive a file URL names no directory on Windows.
    let directory = match cfg!(windows) {
        true => "file:///C:/nonexistent-raeva-${env.API_TOKEN}/m2/",
        false => "file:///nonexistent-raeva-${env.API_TOKEN}/m2/",
    };
    for mirror in [directory, "http://${env.API_TOKEN}.example.invalid/m2/"] {
        let project = Project::with(&[]);
        std::fs::write(
            project.m2_settings(),
            format!(
                "<settings><mirrors><mirror><id>m</id><mirrorOf>*</mirrorOf><url>{mirror}</url>\
                 </mirror></mirrors><servers><server><id>m</id><username>u</username>\
                 <password>p</password></server></servers></settings>"
            ),
        )
        .unwrap();
        for json in [true, false] {
            let mut args = vec!["doctor", "-vv"];
            if json {
                args.insert(0, "--json");
            }
            let output = project.raeva_with(&[("API_TOKEN", SHORT), ("RAEVA_RETRIES", "0")], &args);
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!text.contains(SHORT), "{mirror} json={json}: {text}");
            if mirror.starts_with("file:") {
                let words = text.split_whitespace().collect::<Vec<_>>().join(" ");
                assert!(
                    words.contains("***/m2/ is not a directory"),
                    "{mirror}: {text}"
                );
            }
        }
    }
}

/// A value an input takes by a secret's name alone hides nothing when it is
/// a version or a word: `-Dapp.key=1.0` leaves `org.test:p1:1.0` as it is.
#[test]
fn an_ordinary_value_of_a_secret_named_define_masks_no_coordinate() {
    let project = crate::offline_project::Project::with(&[]);
    project.publish("org.test:p1:1.0", "");
    std::fs::write(
        project.root().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${project.basedir}/repository/</url></repository>\
         </repositories><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>p1</artifactId><version>1.0</version></dependency></dependencies></project>",
    )
    .unwrap();
    let defines = ["-Dapp.key=1.0", "-Dskip.key=true", "-Dsign.key=test"];
    let args = |command: &[&'static str]| [&defines[..], command].concat();
    assert_success(&project.raeva(&args(&["sync", "--offline"])), "sync");
    let tree = project.raeva(&args(&["tree"]));
    assert_success(&tree, "tree");
    let shown = String::from_utf8_lossy(&tree.stdout);
    assert!(
        shown.contains("org.test:p1:1.0") && !shown.contains("***"),
        "{shown}"
    );
}

/// A settings.xml that fails to load names what it holds, but not a secret
/// raeva took: a JVM option's `-D` value, a password the parser quotes, or
/// one a message escapes.
#[test]
fn a_settings_error_shows_no_secret() {
    // (case, settings.xml, MAVEN_OPTS, text no output may hold)
    let cases = [
        (
            "early",
            "<settings><pluginGroups><pluginGroup>bad:zqEARLYzq</pluginGroup></pluginGroups>\
             </settings>",
            "-Dapi.token=zqEARLYzq",
            "zqEARLYzq",
        ),
        (
            "parse",
            "<settings><servers><server><id>s</id><password>zqXMLzq</zqXMLzq></server>\
             </servers></settings>",
            "",
            "zqXMLzq",
        ),
        (
            "escaped",
            "<settings><servers><server><id>s</id><password>zqA&#10;zqB</password></server>\
             </servers><pluginGroups><pluginGroup>zqA&#10;zqB</pluginGroup></pluginGroups>\
             </settings>",
            "",
            "zqA",
        ),
    ];
    for (case, settings, opts, secret) in cases {
        let project = crate::offline_project::Project::with(&[]);
        std::fs::write(project.m2_settings(), settings).unwrap();
        for json in [false, true] {
            let mut command = raeva_command(&project.root(), project.home());
            crate::common::isolate_maven_user_home(&mut command, project.home(), opts);
            if json {
                command.arg("--json");
            }
            let output = command.args(["doctor", "--offline"]).output().unwrap();
            let shown = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!shown.contains(secret), "{case} {json}: {shown}");
            assert!(
                shown.contains("***") || shown.contains("settings"),
                "{case}: {shown}"
            );
        }
    }
}

/// `raeva doctor --offline` in a fresh project with `settings` and `env`,
/// after `args`: what it printed, and whether it ended within a minute.
fn doctor_shows(settings: &str, env: &[(&str, &str)], args: &[&str]) -> (String, bool) {
    let project = crate::offline_project::Project::with(&[]);
    std::fs::write(project.m2_settings(), settings).unwrap();
    let mut command = raeva_command(&project.root(), project.home());
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command
        .args(args)
        .args(["doctor", "--offline"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    let ended = loop {
        if child.try_wait().unwrap().is_some() {
            break true;
        }
        if started.elapsed() > std::time::Duration::from_secs(60) {
            child.kill().unwrap();
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let output = child.wait_with_output().unwrap();
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (shown, ended)
}

/// A credential element with white space in its tag is one too, to the
/// error a settings.xml that does not parse prints.
#[test]
fn a_spaced_credential_tag_keeps_its_text_out_of_a_parse_error() {
    for tag in ["password", "passphrase", "privateKey"] {
        let settings = format!(
            "<settings><servers><server><id>s</id><{tag} >zqXMLzq</zqXMLzq></server></servers>\
             </settings>"
        );
        let (shown, _) = doctor_shows(&settings, &[], &[]);
        assert!(!shown.contains("zqXMLzq"), "{tag}: {shown}");
    }
}

/// A password that takes a variable is hidden expanded before a settings
/// error that quotes the value can show it.
#[test]
fn an_expanded_password_is_hidden_from_an_earlier_settings_error() {
    let settings = "<settings><servers><server><id>s</id><password>${env.V}</password></server>\
                    </servers><mirrors><mirror><id>m</id><url>http://mirror.invalid/</url>\
                    <mirrorOf>*</mirrorOf><layout>${env.V}</layout></mirror></mirrors></settings>";
    let (shown, _) = doctor_shows(settings, &[("V", "zqPASSWORDzq")], &[]);
    assert!(!shown.contains("zqPASSWORDzq"), "{shown}");
}

/// A `-D` option raeva refuses names no secret value it holds.
#[test]
fn a_refused_define_shows_no_secret() {
    let (shown, _) = doctor_shows("<settings/>", &[], &["-D", "\"api.token=zqCLIzq"]);
    assert!(
        !shown.contains("zqCLIzq") && shown.contains("-D"),
        "{shown}"
    );
}

/// An option file that is not a regular file, such as a FIFO no one writes,
/// holds nothing raeva waits for.
#[cfg(unix)]
#[test]
fn an_option_fifo_does_not_hang_doctor() {
    let dir = tempfile::TempDir::new().unwrap();
    let fifo = dir.path().join("options.fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    for (name, option) in [
        ("JAVA_TOOL_OPTIONS", "@"),
        ("MAVEN_OPTS", "@"),
        ("JAVA_TOOL_OPTIONS", "-XX:VMOptionsFile="),
    ] {
        let opts = format!("{option}{}", fifo.display());
        let (shown, ended) = doctor_shows("<settings/>", &[(name, &opts)], &[]);
        assert!(ended, "{name} {option}: {shown}");
        // Skipped, as `mvn` would hand it to the JVM unread.
        assert!(
            !shown.contains("cannot be read"),
            "{name} {option}: {shown}"
        );
    }
}

/// A dependency coordinate that takes a secret-named `-D` value, from the
/// command line, `.mvn/maven.config` or `.mvn/jvm.config`, or a settings.xml
/// profile property, in the project's POM or a dependency's, is refused
/// before raeva.lock, the store or a repository request takes the value.
#[test]
fn a_dependency_coordinate_that_takes_a_secret_is_refused() {
    let settings = "<settings><profiles><profile><id>p</id><properties>\
                    <deploy.token>zqPROFzq</deploy.token></properties></profile></profiles>\
                    <activeProfiles><activeProfile>p</activeProfile></activeProfiles></settings>";
    // (case, the dependency's coordinates, a project file, raeva's arguments, input)
    type Case<'a> = (&'a str, &'a str, (&'a str, &'a str), &'a [&'a str], &'a str);
    let cases: [Case<'_>; 5] = [
        (
            "cli",
            "<version>1.0</version><classifier>${api.token}</classifier>",
            ("", ""),
            &["-Dapi.token=zqCLIzq"],
            "-Dapi.token",
        ),
        (
            "maven.config",
            "<version>${my.key}</version>",
            (".mvn/maven.config", "-Dmy.key=zqMCFGzq"),
            &[],
            "-Dmy.key",
        ),
        (
            "jvm.config",
            "<version>1.0</version><scope>${api.key}</scope>",
            (".mvn/jvm.config", "-Dapi.key=zqJVMCzq"),
            &[],
            "-Dapi.key",
        ),
        (
            "settings",
            "<version>${deploy.token}</version>",
            ("", ""),
            &[],
            "deploy.token",
        ),
        (
            "chain",
            "<version>${v}</version>",
            ("", ""),
            &["-Dv=${api.token}", "-Dapi.token=zqCHAINzq"],
            "-Dv",
        ),
    ];
    for (case, coordinates, (file, text), args, input) in cases {
        let project = crate::offline_project::Project::with(&[]);
        std::fs::write(project.m2_settings(), settings).unwrap();
        let mut skip = vec![project.m2_settings()];
        if !file.is_empty() {
            let path = project.root().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            skip.push(path);
        }
        std::fs::write(
            project.root().join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>app</artifactId><version>1</version><repositories><repository>\
                 <id>project-local</id><url>file://${{project.basedir}}/repository/</url>\
                 </repository></repositories><dependencies><dependency><groupId>org.test\
                 </groupId><artifactId>lib</artifactId>{coordinates}</dependency></dependencies>\
                 </project>"
            ),
        )
        .unwrap();
        let output = project.raeva(&[args, &["sync", "--offline"]].concat());
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.code(), Some(3), "{case}: {said}");
        assert!(
            said.contains(input) && crate::common::markers_in(&said).next().is_none(),
            "{case}: {said}"
        );
        let skip: Vec<&std::path::Path> = skip.iter().map(std::path::PathBuf::as_path).collect();
        let found = crate::common::markers_under(project.home(), &skip);
        let found = [found, crate::common::markers_under(&project.root(), &skip)].concat();
        assert!(found.is_empty(), "{case}: {found:?}");
    }
}

/// A dependency's POM whose dependency takes a secret-named `-D` value,
/// which Maven builds a dependency's model with, is refused before the
/// request for that dependency.
#[test]
fn a_fetched_dependency_coordinate_that_takes_a_secret_is_refused() {
    let project = crate::offline_project::Project::with(&[]);
    project.publish(
        "org.test:p1:1.0",
        "<dependencies><dependency><groupId>org.test</groupId><artifactId>p2</artifactId>\
         <version>${api.token}</version></dependency></dependencies>",
    );
    std::fs::write(
        project.root().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${project.basedir}/repository/</url></repository>\
         </repositories><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>p1</artifactId><version>1.0</version></dependency></dependencies></project>",
    )
    .unwrap();
    let output = project.raeva(&["-Dapi.token=zqFETCHzq", "sync", "--offline"]);
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(3), "{said}");
    assert!(
        said.contains("-Dapi.token") && crate::common::markers_in(&said).next().is_none(),
        "{said}"
    );
    let found = [
        crate::common::markers_under(project.home(), &[]),
        crate::common::markers_under(&project.root(), &[]),
    ]
    .concat();
    assert!(found.is_empty(), "{found:?}");
}

/// The project's own coordinates, which raeva.lock records, are refused
/// the same way when one takes a secret-named input.
#[test]
fn a_project_coordinate_that_takes_a_secret_is_refused() {
    let cases = [
        (
            "version",
            "<version>${my.key}</version>",
            "",
            "the version of project",
        ),
        (
            "groupId",
            "<version>1</version>",
            "<groupId>org.${my.key}</groupId>",
            "the groupId of project",
        ),
    ];
    for (case, version, group, refusal) in cases {
        let project = crate::offline_project::Project::with(&[]);
        std::fs::write(
            project.root().join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion>{group}<artifactId>app</artifactId>\
                 {version}<repositories><repository><id>project-local</id>\
                 <url>file://${{project.basedir}}/repository/</url></repository></repositories>\
                 </project>",
                group = if group.is_empty() {
                    "<groupId>org.test</groupId>"
                } else {
                    group
                }
            ),
        )
        .unwrap();
        let output = project.raeva(&["-Dmy.key=zqOWNzq", "sync", "--offline"]);
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.code(), Some(3), "{case}: {said}");
        assert!(
            said.contains(refusal) && crate::common::markers_in(&said).next().is_none(),
            "{case}: {said}"
        );
        let found = [
            crate::common::markers_under(project.home(), &[]),
            crate::common::markers_under(&project.root(), &[]),
        ]
        .concat();
        assert!(found.is_empty(), "{case}: {found:?}");
    }
}
