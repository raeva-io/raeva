//! Regression tests for `raeva lock verify --download`.
//!
//! An in-process HTTP stub and a tempdir-rooted raeva home exercise the
//! repair path's trust boundary: which origins it contacts, and which bytes
//! the content store's coordinate index may point at.

use crate::common::{
    self, assert_status, assert_success, run_raeva, sha256_hex, temp_project, write_empty_pom,
    write_repo_toml,
};

use std::fs;
use std::path::Path;

use rv_test_support::http::{Request, Response, StubServer};

/// `raeva.toml` names `config_repo_url`; `raeva.lock` records `lock_repo_url`,
/// so a test can model a tampered lock that points at a repository the
/// project never trusted.
fn write_project_split(project: &Path, config_repo_url: &str, lock_repo_url: &str, sha256: &str) {
    write_repo_toml(project, "stub", config_repo_url);
    write_empty_pom(&project.join("pom.xml"));
    let mut demo = common::package("com.example", "demo", "1.0.0");
    demo.repo_url = lock_repo_url.to_string();
    demo.checksums = vec![rv_maven_types::Digest::parse("sha256", sha256).unwrap()];
    fs::write(
        project.join("raeva.lock"),
        common::lock_text("linux-x86_64", None, vec![demo]),
    )
    .expect("write raeva.lock");
}

/// Serve `body` as every jar and POM, with a matching `.sha256` sidecar; 404
/// everything else.
fn jar_routes(
    body: Vec<u8>,
    sha256: String,
) -> impl Fn(&Request) -> Response + Send + Sync + 'static {
    move |request: &Request| {
        if request.path.contains(".sha256") {
            Response::new(200, sha256.as_bytes())
        } else if request.path.contains(".jar") || request.path.contains(".pom") {
            Response::new(200, body.clone())
        } else {
            Response::new(404, "")
        }
    }
}

/// Security regression: `raeva lock verify --download` must apply the same trust
/// policy as `raeva sync`. A tampered `raeva.lock` that names a `repo_url` the
/// project's `raeva.toml` never declared must be refused as a verify finding,
/// and the attacker origin must not be contacted at all. Verify used to
/// synthesize a `Repository` for whatever URL the lockfile carried, so
/// `--download` would happily fetch from it (`raeva sync` refuses the very same
/// lockfile with `UntrustedRepoUrl` before any I/O).
#[test]
fn lock_verify_download_refuses_untrusted_lockfile_origin() {
    // The attacker rewrote both halves of the lockfile row: the origin *and*
    // the pin, so the pin check alone would wave these bytes through.
    let attacker_body: &[u8] = b"attacker-controlled-jar-bytes";
    let attacker_sha256 = sha256_hex(attacker_body);

    let server = StubServer::start(jar_routes(attacker_body.to_vec(), attacker_sha256.clone()));
    let addr = server.addr();

    let (project, home) = temp_project();
    let attacker_url = format!("http://{addr}/");
    // `raeva.toml` trusts an unrelated repository; the lockfile points at the
    // attacker's stub.
    write_project_split(
        project.path(),
        "https://repo.example/m2/",
        &attacker_url,
        &attacker_sha256,
    );

    let output = run_raeva(
        project.path(),
        home.path(),
        &["--json", "lock", "verify", "--download"],
    );
    assert_status(&output, 7, "verify untrusted origin");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|err| {
        panic!("stdout must be a single JSON envelope: {err}\nstdout: {stdout}\nstderr: {stderr}")
    });
    assert_eq!(
        parsed["data"]["untrusted_origin"],
        serde_json::json!(2),
        "the untrusted origin of the jar and its POM must surface as findings: {parsed}"
    );
    assert_eq!(
        parsed["data"]["untrusted_origin_artifacts"][0]["repo_url"],
        serde_json::json!(attacker_url),
        "the finding must name the refused origin: {parsed}"
    );
    assert_eq!(
        parsed["data"]["downloaded"],
        serde_json::json!(0),
        "nothing may be downloaded from an untrusted origin: {parsed}"
    );

    // The load-bearing assertion: the attacker origin was never contacted.
    assert_eq!(
        server.connections(),
        0,
        "verify must not open a connection to an origin outside the trust roots"
    );
}

/// An origin with userinfo, a query or a fragment, which may carry a
/// credential, makes the lock unreadable, and no output repeats it, in text
/// or JSON.
#[test]
fn lock_verify_refuses_an_origin_that_may_hold_a_credential() {
    let (project, home) = temp_project();
    write_project_split(
        project.path(),
        "https://repo.example/m2/",
        "https://user:s3cret@attacker.example/m2/?token=s3cret#s3cret",
        &"a".repeat(64),
    );

    for json in [false, true] {
        let mut args = vec!["lock", "verify", "--download"];
        if json {
            args.insert(0, "--json");
        }
        let output = run_raeva(project.path(), home.path(), &args);
        assert_status(&output, 3, "verify secret origin");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!text.contains("s3cret"), "json={json}: {text}");
        assert!(
            text.contains("has userinfo, which may hold a credential"),
            "json={json}: {text}"
        );
    }
}

/// Security regression: bytes that fail the lockfile pin must never be
/// indexed. `--download` used to route through
/// `fetch_artifact_to_store_and_index`, which repointed the artifact key at
/// the fetched blob *before* comparing it to the pin, so a failed pin check
/// still left the shared store's coordinate index aimed at whatever the
/// origin served.
///
/// Here the origin is declared in `raeva.toml` (so the trust gate passes and a
/// fetch really happens) but serves bytes that do not match the recorded
/// pin. The coordinate must still resolve to the blob it resolved to before.
#[tokio::test]
async fn lock_verify_download_leaves_index_alone_when_the_pin_fails() {
    // What the origin serves, with a self-consistent sidecar so the fetch
    // itself succeeds and only the lockfile pin comparison can reject it.
    let served_body: &[u8] = b"bytes-the-origin-actually-serves";
    let served_sha256 = sha256_hex(served_body);
    // What the lockfile pins: something else entirely.
    let pinned_sha256 = sha256_hex(b"the-bytes-the-lockfile-pins");

    let server = StubServer::start(jar_routes(served_body.to_vec(), served_sha256.clone()));
    let addr = server.addr();

    let (project, home) = temp_project();
    let repo_url = format!("http://{addr}/");
    write_project_split(project.path(), &repo_url, &repo_url, &pinned_sha256);

    // Seed the store so the coordinate already maps to a known blob; that
    // mapping is what a redirect would overwrite.
    let store_dir = home.path().join("store");
    fs::create_dir_all(&store_dir).expect("mkdir store");
    let key = rv_maven_types::ArtifactCoord::new("com.example", "demo", "1.0.0", "jar", None);
    let store = rv_store::Store::open(&store_dir).expect("open store");
    let original_blob = store
        .put_bytes(b"the-blob-the-store-already-had")
        .await
        .expect("put original bytes");
    store
        .add_artifact(&key, &original_blob)
        .await
        .expect("index original");
    drop(store);

    let output = run_raeva(
        project.path(),
        home.path(),
        &["--json", "lock", "verify", "--download"],
    );
    assert_status(&output, 7, "verify pin mismatch");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|err| {
        panic!("stdout must be a single JSON envelope: {err}\nstdout: {stdout}\nstderr: {stderr}")
    });
    assert_eq!(
        parsed["data"]["pin_mismatch"],
        serde_json::json!(2),
        "the mismatched jar and POM must surface as findings: {parsed}"
    );
    assert_eq!(
        parsed["data"]["downloaded"],
        serde_json::json!(0),
        "a download that fails the pin must not count as a repair: {parsed}"
    );

    // The origin really was contacted: this test exercises the pin gate, not
    // the trust gate.
    assert!(
        server.connections() > 0,
        "the configured origin should have been fetched from"
    );

    // The load-bearing assertion: the coordinate still maps to the blob it
    // mapped to before, not to the bytes the origin served.
    let store = rv_store::Store::open(&store_dir).expect("reopen store");
    let mapped = store
        .lookup_artifact(&key)
        .await
        .expect("lookup_artifact")
        .expect("the seeded mapping must survive a failed download");
    assert_eq!(
        mapped, original_blob,
        "a download that fails the lockfile pin must not repoint the artifact index"
    );
    assert_ne!(
        mapped.as_str(),
        served_sha256,
        "the index must not point at the bytes the origin served"
    );
}

/// Export needs the parent POMs and imported BOMs `support_poms` pins, which
/// have no artifact row. Verify used to skip them, so a store missing one
/// passed and `--download` left it missing for export to trip over.
#[tokio::test]
async fn lock_verify_download_restores_a_pinned_parent_pom() {
    let body = |path: &str| -> Vec<u8> { format!("bytes of {path}").into_bytes() };
    let sha256 = |path: &str| sha256_hex(&body(path));
    let jar = "com/example/demo/1.0.0/demo-1.0.0.jar";
    let pom = "com/example/demo/1.0.0/demo-1.0.0.pom";
    let parent = "com/example/parent/1.0.0/parent-1.0.0.pom";
    let server = StubServer::start(move |request: &Request| {
        let path = request.path.trim_start_matches('/');
        if [jar, pom, parent].contains(&path) {
            Response::new(200, body(path))
        } else {
            Response::new(404, "")
        }
    });

    let (project, home) = temp_project();
    let repo_url = format!("http://{}/", server.addr());
    write_repo_toml(project.path(), "stub", &repo_url);
    write_empty_pom(&project.path().join("pom.xml"));
    let mut demo = common::package("com.example", "demo", "1.0.0");
    demo.repo_url.clone_from(&repo_url);
    demo.checksums = vec![rv_maven_types::Digest::parse("sha256", &sha256(jar)).unwrap()];
    demo.pom_sha256 = Some(sha256(pom).parse().unwrap());
    let mut lock = rv_lock::Lockfile::new();
    lock.platforms.push(rv_lock::LockPlatform::single_module(
        "linux-x86_64".parse().unwrap(),
        rv_maven_types::Gav::new("com.example", "demo", "1.0.0"),
        "jar",
        vec![demo],
    ));
    lock.platforms[0].support_poms.insert(
        "com.example:parent:1.0.0".to_string(),
        rv_lock::SupportPom::new(repo_url, sha256(parent).parse().unwrap()),
    );
    fs::write(project.path().join("raeva.lock"), lock.to_toml().unwrap()).unwrap();

    let output = run_raeva(
        project.path(),
        home.path(),
        &["--json", "lock", "verify", "--download"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_success(&output, "lock verify --download");
    assert_eq!(
        parsed["data"]["downloaded"],
        serde_json::json!(3),
        "{parsed}"
    );
    let store = rv_store::Store::open(&home.path().join("store")).unwrap();
    assert!(store.exists_async(&sha256(parent).parse().unwrap()).await);
}

/// A parent two platforms pin with the same bytes is restored through the
/// platform whose recorded repository is declared, even when the first
/// platform records one that is not.
#[test]
fn lock_verify_download_tries_every_platform_that_pins_a_file() {
    let parent = "com/example/parent/1.0.0/parent-1.0.0.pom";
    let bytes = b"parent bytes".to_vec();
    let sha256 = sha256_hex(&bytes);
    let served = bytes.clone();
    let server = StubServer::start(move |request: &Request| {
        if request.path.trim_start_matches('/') == parent {
            Response::new(200, served.clone())
        } else {
            Response::new(404, "")
        }
    });

    let (project, home) = temp_project();
    let repo_url = format!("http://{}/", server.addr());
    write_repo_toml(project.path(), "stub", &repo_url);
    write_empty_pom(&project.path().join("pom.xml"));
    let mut lock = rv_lock::Lockfile::new();
    for (platform, origin) in [
        ("linux-x86_64", "https://gone.example/maven2/".to_string()),
        ("macos-aarch64", repo_url),
    ] {
        let mut entry = rv_lock::LockPlatform::single_module(
            platform.parse().unwrap(),
            rv_maven_types::Gav::new("com.example", "demo", "1.0.0"),
            "jar",
            Vec::new(),
        );
        entry.support_poms.insert(
            "com.example:parent:1.0.0".to_string(),
            rv_lock::SupportPom::new(origin, sha256.parse().unwrap()),
        );
        lock.platforms.push(entry);
    }
    fs::write(project.path().join("raeva.lock"), lock.to_toml().unwrap()).unwrap();

    let output = run_raeva(
        project.path(),
        home.path(),
        &["--json", "lock", "verify", "--download"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_success(&output, "lock verify --download");
    assert_eq!(
        parsed["data"]["downloaded"],
        serde_json::json!(1),
        "{parsed}"
    );
}

#[test]
fn lock_verify_download_falls_back_to_a_repository_the_pom_declares() {
    let bytes = b"parent bytes".to_vec();
    let sha256 = sha256_hex(&bytes);
    let served = bytes.clone();
    let server = StubServer::start(move |request: &Request| {
        if request.path == "/release/com/example/parent/1.0.0/parent-1.0.0.pom" {
            Response::new(200, served.clone())
        } else {
            Response::new(404, "")
        }
    });

    let (project, home) = temp_project();
    let staging = format!("http://{}/staging/", server.addr());
    write_repo_toml(project.path(), "stub", &staging);
    fs::write(
        project.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
             <artifactId>demo</artifactId><version>1.0.0</version><repositories>\
             <repository><id>release</id><url>http://{}/release/</url></repository>\
             </repositories></project>",
            server.addr()
        ),
    )
    .unwrap();
    let mut lock = rv_lock::Lockfile::new();
    let mut entry = rv_lock::LockPlatform::single_module(
        "linux-x86_64".parse().unwrap(),
        rv_maven_types::Gav::new("com.example", "demo", "1.0.0"),
        "jar",
        Vec::new(),
    );
    entry.support_poms.insert(
        "com.example:parent:1.0.0".to_string(),
        rv_lock::SupportPom::new(staging, sha256.parse().unwrap()),
    );
    lock.platforms.push(entry);
    fs::write(project.path().join("raeva.lock"), lock.to_toml().unwrap()).unwrap();

    let output = run_raeva(
        project.path(),
        home.path(),
        &["--json", "lock", "verify", "--download"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_success(&output, "lock verify --download");
    assert_eq!(
        parsed["data"]["downloaded"],
        serde_json::json!(1),
        "{parsed}"
    );
}
