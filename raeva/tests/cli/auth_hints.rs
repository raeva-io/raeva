//! What a first sync against a private repository declared in `pom.xml`
//! reports when no credentials are configured, or when the repository
//! refuses the ones sent.

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
            assert_eq!(artifacts[0].repo_url, url);
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
