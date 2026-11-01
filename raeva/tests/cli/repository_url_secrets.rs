//! A repository URL with userinfo, a query or a fragment would put what may
//! be a credential into raeva.lock. Configuration and the project's POMs with
//! one are refused with exit 3, a dependency's POM with one is ignored, and
//! the secret reaches no output, log or lockfile.

use std::path::Path;
use std::process::Output;

use crate::common::{
    assert_status, assert_success, pom, raeva_command, with_sha1, write_repo_toml,
};
use rv_test_support::http::StubServer;

const SECRET: &str = "s3cretpass";

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
