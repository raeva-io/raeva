//! `raeva doctor` never shows the userinfo or query of a repository URL.
//! Concrete failure shape: a `[[repositories]]` URL with embedded
//! `user:password@host?api_key=...` must not leak the password or the
//! `api_key` value into doctor's report. Configuration with such a URL is
//! refused when it loads, with exit 3, before any probe runs. So is a
//! `.mvn/maven.config` that Maven refuses, before doctor sends credentials.

use rv_test_support::http::{Response, StubServer};
use rv_test_support::net::RefusingPort;
use tempfile::tempdir;

use crate::common::{assert_status, raeva_command};

#[test]
fn doctor_refuses_a_repository_url_with_userinfo_or_a_query() {
    let dir = tempdir().expect("tempdir");
    // The URL embeds:
    //   * basic-auth userinfo:  alice:hunter2
    //   * a query parameter:    api_key=topsecretvalue
    // Both must be stripped from the reported error.
    let refusing = RefusingPort::bind();
    let port = refusing.addr().port();
    std::fs::write(
        dir.path().join("raeva.toml"),
        format!(
            r#"
[[repositories]]
id = "leaky"
url = "http://alice:hunter2@127.0.0.1:{port}/maven2?api_key=topsecretvalue"
"#
        ),
    )
    .expect("write raeva.toml");

    let output = raeva_command(dir.path(), dir.path())
        .args(["--json", "doctor"])
        .output()
        .expect("spawn raeva doctor");
    assert_status(&output, 3, "doctor refuses the configuration");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("not one JSON envelope ({err}): {stdout}"));
    assert_eq!(envelope["code"], "CONFIG", "{envelope}");

    // The entire wire output (stdout JSON envelope + stderr chatter) must
    // be free of the secrets.
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        !combined.contains("hunter2"),
        "password leaked into doctor output:\n{combined}"
    );
    assert!(
        !combined.contains("topsecretvalue"),
        "query-string secret leaked into doctor output:\n{combined}"
    );
}

/// Maven refuses a `.mvn/maven.config` it cannot parse before it activates
/// any profile, so `-P!public` in such a file never lets settings.xml profile
/// `public` and its credentialed repository through.
#[test]
fn doctor_sends_no_credentials_past_a_maven_config_maven_refuses() {
    let server = StubServer::start(|request| {
        if request.header("authorization").is_some() {
            Response::new(404, "")
        } else {
            Response::new(401, "").header("WWW-Authenticate", "Basic realm=\"test\"")
        }
    });
    let home = tempdir().expect("home");
    std::fs::create_dir(home.path().join(".m2")).expect("m2 dir");
    std::fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><servers><server><id>central</id><username>ci</username>\
             <password>dummy-secret</password></server></servers>\
             <profiles><profile><id>public</id><repositories><repository>\
             <id>central</id><url>http://{}/maven2/</url></repository>\
             </repositories></profile></profiles>\
             <activeProfiles><activeProfile>public</activeProfile></activeProfiles></settings>",
            server.addr()
        ),
    )
    .expect("write settings.xml");
    let project = tempdir().expect("project");
    let doctor = || {
        raeva_command(project.path(), home.path())
            .args(["--json", "doctor"])
            .output()
            .expect("spawn raeva doctor")
    };

    // Without maven.config the profile is active and doctor authenticates,
    // so the request count below would see a leak.
    doctor();
    assert!(
        server
            .requests()
            .iter()
            .any(|request| request.header("authorization").is_some()),
        "doctor never sent the credential: {:?}",
        server.requests()
    );

    let config = project.path().join(".mvn/maven.config");
    std::fs::create_dir(config.parent().expect("parent")).expect("mkdir .mvn");
    for (content, code) in [
        (&b"-P!public\ngarbage\n"[..], "INVALID_PROJECT_INPUT"),
        (b"-P!public\n\xff\n", "CONFIG"),
    ] {
        std::fs::write(&config, content).expect("write maven.config");
        let before = server.connections();
        let output = doctor();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let envelope: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|err| panic!("not one JSON envelope ({err}): {stdout}"));
        assert_status(&output, 3, "doctor refuses a broken maven.config");
        assert_eq!(envelope["code"], code, "{envelope}");
        assert_eq!(
            server.connections(),
            before,
            "doctor contacted the repository"
        );
        assert!(!stdout.contains("dummy-secret"), "{stdout}");
    }
    server.stop();
}
