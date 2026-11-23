//! What a first sync against a private repository declared in `pom.xml`
//! reports when the repository refuses credentials or is unavailable.

use crate::common::{
    assert_status, assert_success, raeva_command, run_raeva, with_sha256, write_repo_toml,
};
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

fn spawn_registry() -> (String, StubServer) {
    let server = StubServer::start(|request| {
        if request.path.starts_with("/maven/canary/") {
            Response::new(401, "")
        } else {
            Response::new(404, "")
        }
    });
    (format!("http://{}", server.addr()), server)
}

fn project(base: &str) -> TempDir {
    let dir = tempfile::tempdir().expect("project dir");
    std::fs::write(
        dir.path().join("pom.xml"),
        format!(
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <repositories>
    <repository><id>raeva</id><url>{base}/maven/canary/</url></repository>
  </repositories>
  <dependencies>
    <dependency><groupId>io.raeva</groupId><artifactId>lib</artifactId><version>1.0</version></dependency>
  </dependencies>
</project>
"#
        ),
    )
    .expect("write pom.xml");
    write_repo_toml(dir.path(), "local", &format!("{base}/empty/"));
    dir
}

#[test]
fn sync_names_the_pom_repository_that_needs_credentials() {
    let (base, _server) = spawn_registry();
    let project = project(&base);
    let home = tempfile::tempdir().expect("home");

    let output = run_raeva(project.path(), home.path(), &["sync"]);
    assert_status(&output, 3, "sync names pom repository");
    let stderr = String::from_utf8_lossy(&output.stderr);

    let url = format!("{base}/maven/canary/");
    assert!(
        stderr.contains(&format!("'raeva' at {url} (HTTP 401")),
        "{stderr}"
    );
    assert!(stderr.contains("<id>raeva</id>"), "{stderr}");
    assert!(stderr.contains("id = \"raeva\""), "{stderr}");
    assert!(!stderr.contains("\"private\""), "{stderr}");
}

/// Credentials from a settings.xml `<server>` that the repository refuses
/// are named by id and file, never by value, and the hints say what to
/// check instead of how to add a `<server>`. A `${env.X}` reference whose
/// variable is unset reaches the repository as written, and the hint and
/// doctor say so. The file named is the one read, `-s` included.
#[test]
fn sync_names_the_refused_settings_credentials() {
    const UNSET: &str = "RAEVA_TEST_AUTH_HINTS_UNSET_TOKEN";
    let (base, _server) = spawn_registry();
    let project = project(&base);
    for (password, settings, reason, hint, doctor) in [
        (
            "wrong-secret-123",
            ".m2/settings.xml",
            "credentials for id 'raeva' from {settings} were sent but rejected)",
            "Check the credentials for id 'raeva' in {settings}",
            "or token in {settings})",
        ),
        (
            "${env.RAEVA_TEST_AUTH_HINTS_UNSET_TOKEN}",
            "ci-settings.xml",
            "were sent but rejected; RAEVA_TEST_AUTH_HINTS_UNSET_TOKEN is not set, so the \
             repository received the literal text ${env.RAEVA_TEST_AUTH_HINTS_UNSET_TOKEN})",
            "Set RAEVA_TEST_AUTH_HINTS_UNSET_TOKEN in the environment; the credentials for id \
             'raeva' in {settings} read it",
            "RAEVA_TEST_AUTH_HINTS_UNSET_TOKEN is not set",
        ),
    ] {
        let home = tempfile::tempdir().expect("home");
        // Components, so that the path shows as raeva shows it on Windows too.
        let settings: std::path::PathBuf = home.path().join(settings).components().collect();
        std::fs::create_dir_all(settings.parent().expect("parent")).expect("settings dir");
        std::fs::write(
            &settings,
            format!(
                "<settings><servers><server><id>raeva</id><username>ci</username>\
                 <password>{password}</password></server></servers></settings>"
            ),
        )
        .expect("write settings.xml");
        let shown = settings.display().to_string();
        let [reason, hint, doctor] =
            [reason, hint, doctor].map(|text| text.replace("{settings}", &shown));
        let (reason, hint, doctor) = (reason.as_str(), hint.as_str(), doctor.as_str());
        let run = |args: &[&str]| {
            let mut command = raeva_command(project.path(), home.path());
            if !settings.ends_with(".m2/settings.xml") {
                command.arg("-s").arg(&settings);
            }
            command
                .env_remove(UNSET)
                .args(args)
                .output()
                .expect("run raeva")
        };

        let output = run(&["sync"]);
        assert_status(&output, 3, "sync names refused settings credentials");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(reason), "{stderr}");
        assert!(!stderr.contains("wrong-secret-123"), "{stderr}");
        assert!(!stderr.contains("Add a <server>"), "{stderr}");

        let output = run(&["--json", "sync"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("sync JSON");
        assert_eq!(envelope["code"], "AUTH", "{stdout}");
        let hints = envelope["hints"].as_array().expect("hints");
        assert!(
            hints[0].as_str().is_some_and(|text| text.starts_with(hint)),
            "{stdout}"
        );
        assert!(!stdout.contains("wrong-secret-123"), "{stdout}");
        assert!(!stdout.contains("Add a <server>"), "{stdout}");

        let output = run(&["--json", "doctor"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("doctor JSON");
        let checks = envelope["data"]["checks"].as_array().expect("checks");
        let row = checks
            .iter()
            .find(|check| check["check"] == "raeva (pom.xml)")
            .unwrap_or_else(|| panic!("no row for the POM repository: {stdout}"));
        let details = row["details"].as_str().expect("details");
        assert!(
            details.starts_with("401 (credentials for id 'raeva' were sent but rejected; ")
                && details.contains(doctor),
            "{details}"
        );
    }
}

/// A settings.xml mirror without an `<id>` is named `default`, as Maven's
/// settings model names it, so the `<server>` with that id gives it its
/// credentials. An empty `<id>` is refused, as Maven refuses it.
#[test]
fn a_mirror_without_an_id_takes_the_default_server() {
    let server = StubServer::start(|request| match request.header("authorization") {
        Some("Basic Y2k6czNjcmV0") => library_response(&request.path),
        _ => Response::new(401, ""),
    });
    let base = format!("http://{}", server.addr());
    let project = project(&base);
    for (id, status) in [("", 0), ("<id> </id>", 3)] {
        let home = tempfile::tempdir().expect("home");
        std::fs::create_dir_all(home.path().join(".m2")).expect("settings dir");
        std::fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror>{id}<url>{base}/mirror/</url>\
                 <mirrorOf>*</mirrorOf></mirror></mirrors><servers><server><id>default</id>\
                 <username>ci</username><password>s3cret</password></server></servers>\
                 </settings>"
            ),
        )
        .expect("write settings.xml");
        let output = run_raeva(project.path(), home.path(), &["sync"]);
        assert_status(&output, status, id);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("s3cret"), "{stderr}");
        if status != 0 {
            assert!(
                stderr.contains("a <mirror> has an empty <id>, which Maven refuses"),
                "{stderr}"
            );
        }
    }
}

#[test]
fn doctor_probes_the_pom_repository_that_needs_credentials() {
    let (base, _server) = spawn_registry();
    let project = project(&base);
    let home = tempfile::tempdir().expect("home");

    let output = run_raeva(project.path(), home.path(), &["--json", "doctor"]);
    assert_status(&output, 3, "doctor auth failure");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("doctor JSON");
    let checks = envelope["data"]["checks"].as_array().expect("checks");
    let raeva = checks
        .iter()
        .find(|check| check["check"] == "raeva (pom.xml)")
        .unwrap_or_else(|| panic!("no row for the POM repository: {stdout}"));
    assert_eq!(raeva["status"], "fail", "{stdout}");
    assert_eq!(raeva["class"], "auth", "{stdout}");
    let details = raeva["details"].as_str().expect("details");
    assert!(
        details.starts_with("401 (no credentials were sent"),
        "{details}"
    );
    assert!(details.contains("id 'raeva'"), "{details}");
    assert_eq!(
        envelope["exit_code"], 3,
        "an auth failure is a config error: {stdout}"
    );

    // Text mode shows the same status in the table and ends with an error
    // that counts the failed checks.
    let output = run_raeva(project.path(), home.path(), &["doctor"]);
    assert_status(&output, 3, "doctor text mode");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("raeva (pom.xml)") && line.contains(" fail ")),
        "{stdout}"
    );
    assert!(
        stderr
            .lines()
            .last()
            .is_some_and(|line| line.ends_with("1 check(s) failed")),
        "{stderr}"
    );
    // The repositories that answer 404 are inconclusive, which a note
    // under the table does not let pass for a success.
    assert!(
        stderr.lines().any(|line| line
            == "2 inconclusive, which is not a pass, though raeva doctor exits 0 when no check \
                fails"),
        "{stderr}"
    );
}

/// `io.raeva:lib:1.0` as a POM and jar, with SHA-256 sidecars.
const LIBRARY: [(&str, &[u8]); 2] = [
    (
        "/io/raeva/lib/1.0/lib-1.0.pom",
        b"<project><modelVersion>4.0.0</modelVersion><groupId>io.raeva</groupId>\
          <artifactId>lib</artifactId><version>1.0</version></project>",
    ),
    ("/io/raeva/lib/1.0/lib-1.0.jar", b"library bytes"),
];

/// Serve [`LIBRARY`] from a path that may sit under a repository prefix
/// (`/maven/canary/`, `/public/`).
fn library_response(path: &str) -> Response {
    let path = path
        .find("/io/raeva/")
        .map(|at| &path[at..])
        .unwrap_or(path);
    with_sha256(path, LIBRARY)
}

/// Lists the POM's repository on `first`, then `public` on `second`, in
/// `raeva.toml`, whose repositories are searched before the POM's.
fn fallback_repository(project: &TempDir, first: &StubServer, second: &StubServer) -> String {
    let url = format!("http://{}/public/", second.addr());
    std::fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"raeva\"\nurl = \"http://{}/maven/canary/\"\n\n\
             [[repositories]]\nid = \"public\"\nurl = \"{url}\"\n\n\
             [[repositories]]\nid = \"central\"\nurl = \"http://{}/central/\"\n",
            first.addr(),
            second.addr()
        ),
    )
    .expect("write fallback repository");
    url
}

fn check_repository_fallback(first: &str, reason: &str) {
    let second = tempfile::tempdir().expect("repository");
    for (name, bytes) in LIBRARY {
        crate::common::write_with_sha256(&second.path().join(name.trim_start_matches('/')), bytes);
    }
    let project = project(first);
    let url = url::Url::from_directory_path(second.path())
        .expect("repository URL")
        .to_string();
    std::fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"corp\"\nurl = \"{first}/maven/canary/\"\n\n\
             [[repositories]]\nid = \"central\"\nurl = \"{url}\"\n"
        ),
    )
    .expect("write fallback repository");
    let pom_path = project.path().join("pom.xml");
    let pom = std::fs::read_to_string(&pom_path).expect("pom");
    std::fs::write(pom_path, pom.replace("<id>raeva</id>", "<id>corp</id>"))
        .expect("write repository id");

    for json in [false, true] {
        let home = tempfile::tempdir().expect("home");
        let args: &[&str] = if json { &["--json", "sync"] } else { &["sync"] };
        let output = run_raeva(project.path(), home.path(), args);
        assert_success(&output, "repository fallback");
        let messages = if json {
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            envelope["data"]["warnings"]
                .as_array()
                .expect("warnings")
                .iter()
                .filter(|warning| warning["code"] == "REPOSITORY_FALLBACK")
                .map(|warning| warning["message"].as_str().expect("message").to_string())
                .collect::<Vec<_>>()
        } else {
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| line.contains("REPOSITORY_FALLBACK"))
                .map(str::to_string)
                .collect()
        };
        assert_eq!(messages.len(), 1, "{messages:?}");
        for expected in [
            "Repository `corp`",
            reason,
            "io.raeva:lib:1.0",
            "using the copy from `central`",
            "VPN",
            "before committing raeva.lock",
        ] {
            assert!(messages[0].contains(expected), "{messages:?}");
        }
        let lock = rv_lock::Lockfile::read(&project.path().join("raeva.lock")).expect("lock");
        let artifacts: Vec<_> = lock
            .platforms
            .iter()
            .flat_map(|platform| &platform.artifacts)
            .collect();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].repo_url,
            crate::common::recorded_origin(project.path(), &url)
        );
        std::fs::remove_file(project.path().join("raeva.lock")).expect("remove lock");
    }
}

#[test]
fn sync_warns_on_repository_fallback_after_dns_failure() {
    check_repository_fallback("https://corp.raeva.invalid", "host name did not resolve");
}

#[test]
fn sync_warns_on_repository_fallback_after_connection_refused() {
    let refusing = rv_test_support::net::RefusingPort::bind();
    check_repository_fallback(&format!("http://{}", refusing.addr()), "connection refused");
}

#[test]
fn sync_warns_on_repository_fallback_after_http_500() {
    for pom_in_first in [false, true] {
        let first = StubServer::start(move |request| {
            if pom_in_first && request.path.contains(".pom") {
                library_response(&request.path)
            } else {
                Response::new(500, "")
            }
        });
        check_repository_fallback(&format!("http://{}", first.addr()), "HTTP 500");
    }
}

/// The refusing repository precedes the one that serves the files. Exercise
/// both a refusal for every file and a refusal only when fetching the jar,
/// after the POM and artifact prefetch have selected the first repository.
#[test]
fn sync_tries_the_next_repository_after_an_auth_refusal() {
    for code in [401, 403] {
        for (pom_in_first, json) in [(false, false), (true, false), (false, true), (true, true)] {
            let first = StubServer::start(move |request| {
                if pom_in_first && request.path.contains(".pom") {
                    library_response(&request.path)
                } else {
                    Response::new(code, "")
                }
            });
            let second = StubServer::start(|request| library_response(&request.path));
            let project = project(&format!("http://{}", first.addr()));
            let url = fallback_repository(&project, &first, &second);
            let home = tempfile::tempdir().expect("home");

            let args: &[&str] = if json { &["--json", "sync"] } else { &["sync"] };
            let output = run_raeva(project.path(), home.path(), args);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_success(&output, &format!("{code}, pom_in_first={pom_in_first}"));
            let message = if json {
                let envelope: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("JSON");
                let warnings: Vec<_> = envelope["data"]["warnings"]
                    .as_array()
                    .expect("warnings")
                    .iter()
                    .filter(|warning| warning["code"] == "AUTH_FALLBACK")
                    .collect();
                assert_eq!(warnings.len(), 1, "{envelope}");
                warnings[0]["message"]
                    .as_str()
                    .expect("message")
                    .to_string()
            } else {
                assert_eq!(stderr.matches("AUTH_FALLBACK").count(), 1, "{stderr}");
                stderr.to_string()
            };
            for expected in [
                "Repository `raeva` refused io.raeva:lib:1.0",
                &format!("HTTP {code}"),
                "using the copy from `public`",
                "Check the credentials for `raeva`",
            ] {
                assert!(message.contains(expected), "{message}");
            }
            let lock = rv_lock::Lockfile::read(&project.path().join("raeva.lock")).expect("lock");
            let artifacts: Vec<_> = lock
                .platforms
                .iter()
                .flat_map(|platform| &platform.artifacts)
                .collect();
            assert_eq!(artifacts.len(), 1);
            assert_eq!(
                artifacts[0].repo_url,
                crate::common::recorded_origin(project.path(), &url)
            );
            assert!(
                first
                    .requests()
                    .iter()
                    .any(|request| request.path.ends_with("lib-1.0.pom"))
            );
            assert!(
                second
                    .requests()
                    .iter()
                    .any(|request| request.path.ends_with("lib-1.0.jar"))
            );
            // The jar and its checksum file are requested together, and a
            // refused checksum file can end the attempt before the jar
            // request goes out.
            if pom_in_first {
                assert!(
                    first
                        .requests()
                        .iter()
                        .any(|request| request.path.contains("lib-1.0.jar"))
                );
            }
            // A warm sync that resolves again takes the jar from the store
            // and still names the refusal.
            if pom_in_first && !json {
                let jars = || {
                    let requests = second.requests();
                    requests
                        .iter()
                        .filter(|request| request.path.ends_with("lib-1.0.jar"))
                        .count()
                };
                let downloads = jars();
                std::fs::remove_file(project.path().join("raeva.lock")).expect("remove lock");
                let warm = run_raeva(project.path(), home.path(), &["sync"]);
                assert_success(&warm, "warm sync");
                let stderr = String::from_utf8_lossy(&warm.stderr);
                assert_eq!(stderr.matches("AUTH_FALLBACK").count(), 1, "{stderr}");
                assert_eq!(jars(), downloads);
            }
        }
    }
}

#[test]
fn sync_counts_auth_fallback_files_once_per_repository_pair() {
    let first = StubServer::start(|request| {
        if request.path.contains(".pom") {
            library_response(&request.path)
        } else {
            Response::new(401, "")
        }
    });
    let second = StubServer::start(|request| {
        library_response(&request.path.replace("-sources.jar", ".jar"))
    });
    let project = project(&format!("http://{}", first.addr()));
    let pom_path = project.path().join("pom.xml");
    let pom = std::fs::read_to_string(&pom_path).expect("pom");
    std::fs::write(pom_path, pom.replace("</dependencies>",
        "<dependency><groupId>io.raeva</groupId><artifactId>lib</artifactId><version>1.0</version><classifier>sources</classifier></dependency></dependencies>"
    )).expect("second file");
    fallback_repository(&project, &first, &second);
    for json in [false, true] {
        let home = tempfile::tempdir().expect("home");
        let args: &[&str] = if json { &["--json", "sync"] } else { &["sync"] };
        let output = run_raeva(project.path(), home.path(), args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_success(&output, "auth fallback counts files once");
        let warnings = if json {
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            envelope["data"]["warnings"]
                .as_array()
                .expect("warnings")
                .iter()
                .filter(|warning| warning["code"] == "AUTH_FALLBACK")
                .map(|warning| warning["message"].as_str().expect("message").to_string())
                .collect::<Vec<_>>()
        } else {
            stderr
                .lines()
                .filter(|line| line.contains("AUTH_FALLBACK"))
                .map(str::to_string)
                .collect()
        };
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("and 1 more file"), "{warnings:?}");
        std::fs::remove_file(project.path().join("raeva.lock")).expect("remove lock");
    }
}

#[test]
fn sync_reports_all_auth_refusals_and_the_coordinate() {
    let first = StubServer::start(|_| Response::new(401, ""));
    let second = StubServer::start(|_| Response::new(403, ""));
    let project = project(&format!("http://{}", first.addr()));
    fallback_repository(&project, &first, &second);
    let home = tempfile::tempdir().expect("home");

    let output = run_raeva(project.path(), home.path(), &["--json", "sync"]);
    assert_status(&output, 3, "sync reports all auth refusals");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("sync JSON");
    assert_eq!(envelope["code"], "AUTH", "{stdout}");
    let error = envelope["error"].as_str().expect("error message");
    assert!(error.contains("io.raeva:lib:1.0"), "{error}");
    assert!(
        error.contains("'raeva' at") && error.contains("HTTP 401"),
        "{error}"
    );
    assert!(
        error.contains("'public' at") && error.contains("HTTP 403"),
        "{error}"
    );
    assert!(error.contains("no credentials were sent"), "{error}");
    assert!(
        envelope["hints"]
            .as_array()
            .is_some_and(|hints| !hints.is_empty()),
        "{stdout}"
    );
    assert!(!project.path().join("raeva.lock").exists());
}

/// A credential the repository rejects while raeva downloads the locked
/// files into a cold store, as an expired CI token does, is reported as
/// rejected, by id and file, never by value, not as a missing `<server>`.
/// A default credential names no id, and the repository is not called one
/// without an id.
#[test]
fn a_rejected_credential_on_download_is_named_rejected() {
    let server = StubServer::start(|request| {
        if !request.path.starts_with("/maven/canary/") {
            return Response::new(404, "");
        }
        match request.header("authorization") {
            Some("Basic Y2k6Z29vZA==") => library_response(&request.path),
            _ => Response::new(401, ""),
        }
    });
    let base = format!("http://{}", server.addr());
    let in_settings = |home: &TempDir, password: &str| {
        std::fs::create_dir_all(home.path().join(".m2")).expect("settings dir");
        std::fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><servers><server><id>raeva</id><username>ci</username>\
                 <password>{password}</password></server></servers></settings>"
            ),
        )
        .expect("write settings.xml");
    };
    let by_default = |home: &TempDir, password: &str| {
        std::fs::write(
            home.path().join("config.toml"),
            format!(
                "[[repositories]]\nid = \"corp\"\nurl = \"{base}/maven/canary/\"\n\n\
                 [[auth]]\nusername = \"ci\"\npassword = \"{password}\"\n"
            ),
        )
        .expect("write config.toml");
    };
    for default in [false, true] {
        let credential = |home: &TempDir, password: &str| match default {
            true => by_default(home, password),
            false => in_settings(home, password),
        };
        let named = match default {
            true => [
                "the repository at ",
                "default credentials from the user config.toml",
            ],
            false => ["'raeva' at ", "credentials for id 'raeva' from "],
        };
        let project = project(&base);
        let home = tempfile::tempdir().expect("home");
        credential(&home, "good");
        assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
        for args in [&["sync"][..], &["sync", "--frozen"]] {
            let cold = tempfile::tempdir().expect("cold home");
            credential(&cold, "expired-secret-123");
            let output = run_raeva(project.path(), cold.path(), args);
            assert_status(&output, 3, "rejected credential");
            let stderr = String::from_utf8_lossy(&output.stderr);
            for expected in named.into_iter().chain([
                "The repository refused the credentials raeva sent",
                "were sent but rejected",
                "the token expired or was revoked",
            ]) {
                assert!(stderr.contains(expected), "{args:?}: {stderr}");
            }
            for refused in ["Add a <server>", "expired-secret-123", "without an id"] {
                assert!(!stderr.contains(refused), "{args:?}: {stderr}");
            }
        }
    }
}

/// A `<server>` whose Maven-encrypted password raeva cannot decrypt (no
/// security file, or a wrong master) sends nothing for its id, as Maven
/// sends nothing to a repository that never asks, so one that allows
/// anonymous reads serves the sync.
#[test]
fn a_server_whose_password_is_dropped_reads_anonymously() {
    let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = asked.clone();
    let server = StubServer::start(move |request| {
        if let Some(value) = request.header("authorization") {
            seen.lock().unwrap().push(value.to_string());
        }
        library_response(&request.path)
    });
    let base = format!("http://{}", server.addr());
    for master in [None, Some("{jSMOWnoPFgsHVpMvz5VrIt5kRbzGpI8u+9EF1iFQyJQ=}")] {
        let project = project(&base);
        let home = tempfile::tempdir().expect("home");
        std::fs::create_dir_all(home.path().join(".m2")).expect("settings dir");
        std::fs::write(
            home.path().join(".m2/settings.xml"),
            "<settings><servers><server><id>raeva</id><username>ci</username>\
             <password>{COQLCE6DU6GtcS5P=}</password></server></servers></settings>",
        )
        .expect("write settings.xml");
        if let Some(master) = master {
            std::fs::write(
                home.path().join(".m2/settings-security.xml"),
                format!("<settingsSecurity><master>{master}</master></settingsSecurity>"),
            )
            .expect("write settings-security.xml");
        }
        let output = run_raeva(project.path(), home.path(), &["sync"]);
        let case = format!("master {master:?}");
        assert_success(&output, &case);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("CREDENTIAL_DROPPED"), "{case}: {stderr}");
        assert_eq!(*asked.lock().unwrap(), Vec::<String>::new(), "{case}");
    }
}

/// A repository that needs the credential of a `<server>` whose password
/// raeva could not decrypt: sync and doctor name the decryption, not a
/// missing `<server>`, which a second entry with the id would not fix.
#[test]
fn a_401_after_a_dropped_password_names_the_decryption() {
    let server = StubServer::start(|_| Response::new(401, ""));
    let base = format!("http://{}", server.addr());
    let project = project(&base);
    let home = tempfile::tempdir().expect("home");
    std::fs::create_dir_all(home.path().join(".m2")).expect("settings dir");
    std::fs::write(
        home.path().join(".m2/settings.xml"),
        "<settings><servers><server><id>raeva</id><username>ci</username>\
         <password>{COQLCE6DU6GtcS5P=}</password></server></servers></settings>",
    )
    .expect("write settings.xml");
    // No security file, one that does not parse, and one without a master.
    let security = home.path().join(".m2/settings-security.xml");
    for content in [
        None,
        Some("<settingsSecurity><master>"),
        Some("<settingsSecurity/>"),
    ] {
        if let Some(content) = content {
            std::fs::write(&security, content).expect("write settings-security.xml");
        }
        let output = run_raeva(project.path(), home.path(), &["sync"]);
        assert_status(&output, 3, "sync");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("the settings.xml password could not be decrypted")
                && stderr.contains("server 'raeva' could not be decrypted")
                && stderr.contains("as ~/.m2/settings-security.xml in the user home, or")
                && stderr.contains("-Dsettings.security names, which replaces that one")
                && stderr
                    .contains("reason=no settings-security.xml with a master password was read"),
            "{content:?}: {stderr}"
        );
        assert!(!stderr.contains("<id>raeva</id>"), "{stderr}");
    }
    let output = run_raeva(project.path(), home.path(), &["--json", "doctor"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("doctor JSON");
    let row = (envelope["data"]["checks"]
        .as_array()
        .expect("checks")
        .iter())
    .find(|check| check["check"] == "raeva (pom.xml)")
    .unwrap_or_else(|| panic!("no row: {stdout}"));
    let details = row["details"].as_str().expect("details");
    assert!(
        details.starts_with("401 (no credentials were sent; the encrypted password"),
        "{details}"
    );
}
