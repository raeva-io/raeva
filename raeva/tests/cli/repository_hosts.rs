//! Repository host classification agrees with the request URL.

use crate::common::{assert_status, pom, raeva_command, serve_sha256, write_repo_toml};
use rv_test_support::http::{Response, StubServer};

/// A repository that serves `com.corp:lib:1.0` at any path, as a stand-in
/// for a URL raeva must not read as another.
fn lib_anywhere() -> StubServer {
    StubServer::start(|request| {
        serve_sha256(&request.path, |path| {
            match path.rsplit('/').next().unwrap_or_default() {
                "lib-1.0.pom" => Some(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>com.corp</groupId>\
                     <artifactId>lib</artifactId><version>1.0</version></project>",
                ),
                "lib-1.0.jar" => Some("jar"),
                _ => None,
            }
        })
    })
}

const LIB: &str = "<dependencies><dependency><groupId>com.corp</groupId>\
<artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>";

fn repositories(url: &str) -> String {
    format!("<repositories><repository><id>corp</id><url>{url}</url></repository></repositories>")
}

/// `pom.xml` with `body` and the dependency on `com.corp:lib:1.0`, the
/// Maven line `mode`, and `settings` as the user's settings.xml.
fn lib_project(body: &str, mode: &str, settings: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        project.path().join("pom.xml"),
        pom("app", &format!("{body}{LIB}")),
    )
    .expect("write pom.xml");
    std::fs::write(
        project.path().join("raeva.toml"),
        format!("[lock]\nmaven = \"{mode}\"\n"),
    )
    .expect("write raeva.toml");
    std::fs::create_dir_all(home.path().join(".m2")).unwrap();
    std::fs::write(
        home.path().join(".m2/settings.xml"),
        format!("<settings>{settings}</settings>"),
    )
    .unwrap();
    (project, home)
}

/// Maven's HTTP transport refuses a `\` in a repository or mirror URL:
/// Maven 3.9.12 and 3.10.0 fail each request to `http://host:port/sub\`,
/// and 3.9.12 the build on `http://host:port\sub/`, where raeva read the
/// `\` as `/` and locked what `/sub/` serves. raeva refuses the URL from a
/// POM, a settings.xml profile or a mirror, in both modes, before any
/// request, as it does one whose `\` would move the host past the blocker.
#[test]
fn a_backslash_in_an_http_url_is_refused() {
    let server = lib_anywhere();
    let base = format!("http://{}", server.addr());
    let profile = |url: &str| {
        format!(
            "<profiles><profile><id>p</id>{}</profile></profiles>\
             <activeProfiles><activeProfile>p</activeProfile></activeProfiles>",
            repositories(url)
        )
    };
    let mirror = format!(
        "<mirrors><mirror><id>m</id><mirrorOf>corp</mirrorOf><url>{base}/sub\\</url>\
         </mirror></mirrors>"
    );
    let cases = [
        (repositories(&format!("{base}/sub\\")), String::new()),
        (repositories(&format!("{base}/x\\y/..")), String::new()),
        (repositories(&format!("{base}\\sub/")), String::new()),
        (
            repositories(r"http://repo.invalid\@localhost/maven2/"),
            String::new(),
        ),
        (String::new(), profile(&format!("{base}/sub\\"))),
        (repositories(&format!("{base}/")), mirror),
    ];
    for mode in ["3.9", "3.10"] {
        for (body, settings) in &cases {
            let case = format!("{mode}: {body} {settings}");
            let (project, home) = lib_project(body, mode, settings);
            let output = raeva_command(project.path(), home.path())
                .arg("sync")
                .output()
                .expect("run raeva sync");
            assert_status(&output, 3, &case);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("has '\\' in it"), "{case}: {stderr}");
            assert!(!project.path().join("raeva.lock").exists(), "{case}");
        }
    }
    assert!(server.requests().is_empty(), "{:?}", server.requests());
}

/// Outside Windows, Maven's file transport keeps a `\` in a `file:` URL
/// as part of a directory name: Maven 3.9.12 and 3.10.0 find nothing in
/// a Windows-written `file://${project.basedir}\repo`, where raeva read
/// the `\` as `/` and locked what `repo/` holds. raeva refuses it.
#[cfg(unix)]
#[test]
fn a_backslash_in_a_file_url_is_refused() {
    for url in [
        "file://${project.basedir}\\repo",
        "file:${basedir}\\repo\\",
        "file:///${project.basedir}\\repo",
    ] {
        let (project, home) = lib_project(&repositories(url), "3.9", "");
        crate::common::publish(&project.path().join("repo"), "com.corp:lib:1.0", "");
        let output = raeva_command(project.path(), home.path())
            .arg("sync")
            .output()
            .expect("run raeva sync");
        assert_status(&output, 3, url);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("has '\\' in it"), "{url}: {stderr}");
    }
}

/// On Windows a `\` in a path Maven's file transporter reads is a
/// separator: Maven 3.9.12 and 3.10.0 find `com.corp:lib:1.0` in a
/// `file:` repository written with `\`, from the POM, as `${basedir}`
/// gives it there, or from a settings.xml profile or mirror, and the 3.10
/// mode reads a drive path without `file:` alike. raeva locks it.
#[cfg(windows)]
#[test]
fn a_backslash_in_a_file_url_is_a_separator_on_windows() {
    let lib = tempfile::tempdir().expect("lib");
    crate::common::publish(lib.path(), "com.corp:lib:1.0", "");
    let native = lib.path().to_str().unwrap().to_string();
    let mirrored = |url: &str| {
        format!(
            "<mirrors><mirror><id>m</id><mirrorOf>corp</mirrorOf><url>{url}</url></mirror>\
             </mirrors>"
        )
    };
    let profile = |url: &str| {
        format!(
            "<profiles><profile><id>p</id>{}</profile></profiles>\
             <activeProfiles><activeProfile>p</activeProfile></activeProfiles>",
            repositories(url)
        )
    };
    let mut cases = vec![
        (
            "3.9",
            repositories("file://${project.basedir}\\repo"),
            String::new(),
        ),
        (
            "3.9",
            repositories("file:${basedir}\\repo\\"),
            String::new(),
        ),
        (
            "3.9",
            repositories("file:///${project.basedir}\\repo"),
            String::new(),
        ),
        ("3.9", String::new(), profile(&format!("file:///{native}"))),
        ("3.9", String::new(), profile(&format!("file:{native}\\"))),
        ("3.10", String::new(), profile(&native)),
        (
            "3.9",
            repositories("https://repo.invalid/"),
            mirrored(&format!("file:///{native}")),
        ),
    ];
    cases.extend([("3.10", cases[0].1.clone(), String::new())]);
    for (mode, body, settings) in cases {
        let case = format!("{mode}: {body} {settings}");
        let (project, home) = lib_project(&body, mode, &settings);
        crate::common::publish(&project.path().join("repo"), "com.corp:lib:1.0", "");
        let output = raeva_command(project.path(), home.path())
            .args(["sync", "--offline"])
            .output()
            .expect("run raeva sync");
        assert_status(&output, 0, &case);
        let lock = std::fs::read_to_string(project.path().join("raeva.lock")).unwrap();
        assert!(lock.contains("artifact = \"lib\""), "{case}: {lock}");
    }
}

/// A dependency's POM that names `http://host:port\\sub/` and then a
/// repository that serves its dependency: Maven 3.9.12 reads the `\\` as
/// part of the port and fails the build once it searches the first, where
/// raeva skipped it and locked the second's copy; Maven 3.10.0 fails only
/// that request and takes the second's, as raeva does, warning of the
/// first by its own code.
#[test]
fn a_backslash_after_a_transitive_repositorys_port_fails_maven_39() {
    let server = lib_anywhere();
    let base = tempfile::tempdir().expect("base");
    let repository = base.path().join("repo");
    let empty = base.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    crate::common::publish(
        &repository,
        "com.corp:carrier:1.0",
        &format!(
            "<repositories><repository><id>z</id><url>http://{0}\\sub/</url></repository>\
             <repository><id>w</id><url>http://{0}/</url></repository></repositories>{LIB}",
            server.addr()
        ),
    );
    let local = url::Url::from_directory_path(&repository).unwrap();
    let central = url::Url::from_directory_path(&empty).unwrap();
    let carrier = "<dependencies><dependency><groupId>com.corp</groupId>\
                   <artifactId>carrier</artifactId><version>1.0</version></dependency>\
                   </dependencies>";
    for (mode, status) in [("3.9", 3), ("3.10", 0)] {
        let (project, home) = lib_project(
            &repositories(local.as_str()),
            mode,
            &format!(
                "<mirrors><mirror><id>c</id><mirrorOf>central</mirrorOf><url>{central}</url>\
                 </mirror></mirrors>"
            ),
        );
        let pom = std::fs::read_to_string(project.path().join("pom.xml")).unwrap();
        std::fs::write(project.path().join("pom.xml"), pom.replace(LIB, carrier)).unwrap();
        std::fs::write(
            home.path().join("config.toml"),
            "[security]\nallow_transitive_repositories = true\n",
        )
        .unwrap();
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(["--json", "sync"])
            .output()
            .expect("run raeva sync");
        assert_status(&output, status, mode);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lock = std::fs::read_to_string(project.path().join("raeva.lock")).unwrap_or_default();
        match status {
            3 => assert!(
                stdout.contains("'z' has '\\\\' after its port") && lock.is_empty(),
                "{stdout}"
            ),
            _ => assert!(
                stdout.contains("REPO_URL_BACKSLASH")
                    && lock.contains(&format!("repo_url = \"http://{}/\"", server.addr())),
                "{stdout}\n{lock}"
            ),
        }
    }
}

/// Maven's default HTTP blocker spares only `localhost` and `127.0.0.1` as
/// the URL spells them, in a settings.xml repository as in a POM's: Maven
/// 3.9.12 and 3.10.0 fail with "Blocked mirror" for a settings profile's
/// `http://127.1:<port>/` or `http://LOCALHOST:<port>/`, where raeva
/// fetched from it and wrote a lock.
#[test]
fn the_http_blocker_blocks_a_settings_repository() {
    let profile = |url: &str| {
        format!(
            "<profiles><profile><id>p</id>{}</profile></profiles>\
             <activeProfiles><activeProfile>p</activeProfile></activeProfiles>",
            repositories(url)
        )
    };
    for mode in ["3.9", "3.10"] {
        let server = lib_anywhere();
        let port = server.addr().port();
        for host in ["127.1", "LOCALHOST"] {
            let url = format!("http://{host}:{port}/");
            let (project, home) = lib_project("", mode, &profile(&url));
            let output = raeva_command(project.path(), home.path())
                .arg("sync")
                .output()
                .expect("run raeva sync");
            assert_status(&output, 3, &url);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("HTTP_REPO_BLOCKED") && stderr.contains("'corp'"),
                "{url}: {stderr}"
            );
            assert!(!project.path().join("raeva.lock").exists(), "{url}");
        }
        assert!(server.requests().is_empty(), "{:?}", server.requests());
        let url = format!("http://localhost:{port}/");
        let (project, home) = lib_project("", mode, &profile(&url));
        let output = raeva_command(project.path(), home.path())
            .arg("sync")
            .output()
            .expect("run raeva sync");
        assert_status(&output, 0, &url);
    }
}

/// A POM's plain-HTTP repository that a settings.xml profile of one
/// platform also names stays blocked on every platform, as Maven's blocker
/// blocks both, also when one sync resolves both platforms.
#[test]
fn a_settings_repository_does_not_admit_http_on_any_platform() {
    let url = "http://repo.invalid/maven2/";
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let repository = tempfile::tempdir().expect("empty repository");
    let central = url::Url::from_directory_path(repository.path()).expect("file URL");
    write_repo_toml(project.path(), "central", central.as_str());
    std::fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &format!(
                "<repositories><repository><id>corp</id><url>{url}</url></repository>\
</repositories><dependencies><dependency><groupId>com.corp</groupId>\
<artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>"
            ),
        ),
    )
    .expect("write pom.xml");
    std::fs::create_dir_all(home.path().join(".m2")).unwrap();
    std::fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><profiles><profile><id>w</id><activation><os><family>windows</family>\
             </os></activation><repositories><repository><id>corp</id><url>{url}</url>\
             </repository></repositories></profile></profiles></settings>"
        ),
    )
    .unwrap();
    let proxy = StubServer::start(|request| {
        serve_sha256(&request.path, |path| {
            match path.rsplit('/').next().unwrap_or_default() {
                "lib-1.0.pom" => Some(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>com.corp</groupId>\
                     <artifactId>lib</artifactId><version>1.0</version></project>",
                ),
                "lib-1.0.jar" => Some("jar"),
                _ => None,
            }
        })
    });
    let sync = |platforms: &str| {
        raeva_command(project.path(), home.path())
            .env("HTTP_PROXY", format!("http://{}", proxy.addr()))
            .env("RAEVA_RETRIES", "0")
            .args(["sync", "--platforms", platforms])
            .output()
            .expect("run raeva sync")
    };
    // The blocked request ends the windows search as a blocked mirror's does.
    for (platforms, status) in [("linux-x86_64,windows-x86_64", 5), ("windows-x86_64", 3)] {
        let output = sync(platforms);
        assert_status(&output, status, platforms);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("HTTP_REPO_BLOCKED"),
            "{platforms}: {stderr}"
        );
    }
    assert!(proxy.requests().is_empty(), "{:?}", proxy.requests());
}

/// Maven drops the host of a `file:` URL and reads its path on the machine
/// it runs on: on Windows, Maven 3.9.12 and 3.10.0 read
/// `file://127.0.0.1/x07/fix/r2/` as `C:\x07\fix\r2`, which raeva 0.6.0
/// skipped as a private host, so the two locked different versions. raeva
/// refuses such a URL
/// wherever the project or the configuration names it, in both modes, by
/// the repository's id and before it fetches anything or writes the lock.
/// `localhost` names this machine, as `file:///` does.
#[test]
fn a_file_url_with_a_host_is_refused() {
    for maven in ["3.9", "3.10"] {
        for host in ["server.invalid", "127.0.0.1"] {
            let central = StubServer::start(|_| Response::new(404, ""));
            let central_url = format!("http://{}/", central.addr());
            let base = tempfile::tempdir().expect("base");
            let (home, project) = (base.path().join("home"), base.path().join("project"));
            let repository = base.path().join("repo");
            crate::common::publish(&repository, "org.example:lib:1.0", "");
            std::fs::create_dir_all(home.join(".m2")).unwrap();
            std::fs::create_dir_all(&project).unwrap();
            let local = url::Url::from_directory_path(&repository)
                .unwrap()
                .to_string();
            let hosted = local.replacen("file://", &format!("file://{host}"), 1);
            let write = |toml: &str, settings: &str, repositories: &str| {
                std::fs::write(
                    project.join("raeva.toml"),
                    format!(
                        "[lock]\nmaven = \"{maven}\"\n\n[[repositories]]\nid = \"central\"\n\
                         url = \"{central_url}\"\n{toml}"
                    ),
                )
                .unwrap();
                std::fs::write(
                    home.join(".m2/settings.xml"),
                    format!("<settings>{settings}</settings>"),
                )
                .unwrap();
                // A remote parent, which only `central` serves.
                std::fs::write(
                    project.join("pom.xml"),
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><parent>\
                         <groupId>org.example</groupId><artifactId>parent</artifactId>\
                         <version>1</version></parent><artifactId>app</artifactId>\
                         {repositories}<dependencies><dependency>\
                         <groupId>org.example</groupId><artifactId>lib</artifactId>\
                         <version>1.0</version></dependency></dependencies></project>"
                    ),
                )
                .unwrap();
            };
            let settings_repository = format!(
                "<profiles><profile><id>p</id><activation><activeByDefault>true\
                 </activeByDefault></activation><repositories><repository><id>corp</id>\
                 <url>{hosted}</url></repository></repositories></profile></profiles>"
            );
            let mirror = format!(
                "<mirrors><mirror><id>corp</id><mirrorOf>central</mirrorOf><url>{hosted}</url>\
                 </mirror></mirrors>"
            );
            let toml_repository =
                format!("\n[[repositories]]\nid = \"corp\"\nurl = \"{hosted}\"\n");
            let pom_repository = format!(
                "<repositories><repository><id>corp</id><url>{hosted}</url></repository></repositories>"
            );
            // Maven reads this one as the directory named like the host.
            let bare_host = format!(
                "<repositories><repository><id>corp</id><url>file://{host}</url></repository>\
                 </repositories>"
            );
            let plugin_repository = format!(
                "<pluginRepositories><pluginRepository><id>corp</id><url>{hosted}</url>\
                 </pluginRepository></pluginRepositories>"
            );
            for (what, toml, settings, repositories) in [
                (
                    "settings.xml repository",
                    "",
                    settings_repository.as_str(),
                    "",
                ),
                ("settings.xml mirror", "", mirror.as_str(), ""),
                ("raeva.toml repository", toml_repository.as_str(), "", ""),
                ("POM repository", "", "", pom_repository.as_str()),
                ("POM repository with no path", "", "", bare_host.as_str()),
                ("POM plugin repository", "", "", plugin_repository.as_str()),
            ] {
                let what = format!("{maven} {host} {what}");
                write(toml, settings, repositories);
                let output = crate::common::run_raeva(&project, &home, &["sync"]);
                assert_status(&output, 3, &what);
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(stderr.contains("'corp'"), "{what}: {stderr}");
                assert!(stderr.contains("file:///"), "{what}: {stderr}");
                assert!(!stderr.contains(host), "{what}: {stderr}");
                assert!(!project.join("raeva.lock").exists(), "{what}");
                assert!(
                    central.requests().is_empty(),
                    "{what}: {:?}",
                    central.requests()
                );
            }

            let localhost = local.replacen("file://", "file://localhost", 1);
            write(
                "",
                "",
                &format!(
                    "<repositories><repository><id>corp</id><url>{localhost}</url>\
                     </repository></repositories>"
                ),
            );
            let pom = std::fs::read_to_string(project.join("pom.xml")).unwrap();
            // Without the remote parent, which `central` does not serve.
            let start = pom.find("<parent>").unwrap();
            let end = pom.find("</parent>").unwrap() + "</parent>".len();
            let pom = pom.replace(
                &pom[start..end],
                "<groupId>org.test</groupId><version>1</version>",
            );
            std::fs::write(project.join("pom.xml"), pom).unwrap();
            let output = crate::common::run_raeva(&project, &home, &["sync"]);
            crate::common::assert_success(&output, &format!("{maven} localhost"));
        }
    }
}

/// A `${...}` that raeva leaves as written in the host part of a `file:`
/// URL, such as `${user.dir}`, which Maven expands to a path, is refused for
/// that input, not as a host: the message names it and not its value.
#[test]
fn an_unread_input_in_a_file_url_host_is_named() {
    for maven in ["3.9", "3.10"] {
        let base = tempfile::tempdir().expect("base");
        let (home, project) = (base.path().join("home"), base.path().join("project"));
        std::fs::create_dir_all(home.join(".m2")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(home.join(".m2/settings.xml"), "<settings/>").unwrap();
        std::fs::write(
            project.join("raeva.toml"),
            format!("[lock]\nmaven = \"{maven}\"\n"),
        )
        .unwrap();
        for (url, message) in [
            (
                "file://${user.dir}/repo/",
                "takes ${user.dir}, which raeva does not read",
            ),
            (
                "file://${env.RV_TEST_REPO_DIR}/repo/",
                "takes ${env.RV_TEST_REPO_DIR}, which raeva does not read",
            ),
            (
                "file://${no.such.property}/repo/",
                "takes ${no.such.property}, which raeva does not read",
            ),
            (
                "file://server.invalid/repo/",
                "is a file: URL with a host, which Maven reads",
            ),
        ] {
            let what = format!("{maven} {url}");
            std::fs::write(
                project.join("pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>app</artifactId><version>1</version><repositories>\
                     <repository><id>corp</id><url>{url}</url></repository></repositories>\
                     </project>"
                ),
            )
            .unwrap();
            let output = crate::common::raeva_command(&project, &home)
                .env("RV_TEST_REPO_DIR", "/private-value")
                .arg("sync")
                .output()
                .expect("run raeva");
            assert_status(&output, 3, &what);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("'corp'"), "{what}: {stderr}");
            assert!(stderr.contains(message), "{what}: {stderr}");
            assert!(!stderr.contains("private-value"), "{what}: {stderr}");
            assert!(!project.join("raeva.lock").exists(), "{what}");
        }
    }
}

/// A project repository whose URL is `file://` and the project's directory
/// is read once interpolated; as written it names no host.
#[test]
fn a_file_repository_under_an_expression_is_read_once_interpolated() {
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let repository = tempfile::tempdir().expect("empty repository");
    let central = url::Url::from_directory_path(repository.path()).expect("file URL");
    write_repo_toml(project.path(), "central", central.as_str());
    let dir = project.path().join("com/corp/lib/1.0");
    std::fs::create_dir_all(&dir).expect("create repository");
    std::fs::write(dir.join("lib-1.0.pom"), pom("lib", "")).expect("write pom");
    std::fs::write(dir.join("lib-1.0.jar"), "lib").expect("write jar");
    std::fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<repositories><repository><id>local</id><url>file://${project.basedir}</url>\
</repository></repositories><dependencies><dependency><groupId>com.corp</groupId>\
<artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>",
        ),
    )
    .expect("write pom.xml");
    let output = raeva_command(project.path(), home.path())
        .arg("sync")
        .output()
        .expect("run raeva sync");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(!stderr.contains("project.basedir"), "{stderr}");
}
