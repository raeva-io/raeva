//! Repository host classification agrees with the request URL.

use crate::common::{assert_status, pom, raeva_command, write_repo_toml};
use rv_test_support::http::{Response, StubServer};

#[test]
fn a_backslash_before_localhost_does_not_bypass_the_http_blocker() {
    for url in [
        "http://repo.invalid/maven2/",
        r"http://repo.invalid\@localhost/maven2/",
    ] {
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
        let proxy = StubServer::start(|_| Response::new(404, ""));
        let output = raeva_command(project.path(), home.path())
            .env("HTTP_PROXY", format!("http://{}", proxy.addr()))
            .env("RAEVA_RETRIES", "0")
            .arg("sync")
            .output()
            .expect("run raeva sync");

        assert_status(&output, 5, url);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(proxy.requests().is_empty(), "{url}: {:?}", proxy.requests());
        assert_eq!(proxy.connections(), 0, "{url}: {stderr}");
        assert!(stderr.contains("HTTP_REPO_BLOCKED"), "{url}: {stderr}");
        assert!(!project.path().join("raeva.lock").exists(), "{url}");
    }
}
