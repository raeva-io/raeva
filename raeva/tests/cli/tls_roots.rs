//! `SSL_CERT_FILE` replaces the platform's trust roots on every OS. The
//! platform verifier raeva uses otherwise asks macOS and Windows directly and
//! would ignore the variable there, so each run is a separate process with
//! the variable set from the start.
//!
//! The certificates in `test-fixtures/tls` are test-only: `server.pem` is
//! valid for 127.0.0.1 and localhost until 2126 and is signed by `ca.pem`, and
//! `other-ca.pem` signs nothing used here.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Output;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tempfile::TempDir;

use rv_test_support::fixtures;

use crate::common::{assert_status, assert_success, raeva_command, write_repo_toml};
use crate::offline_project::Project;

fn spawn_tls_server() -> u16 {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = CertificateDer::pem_file_iter(fixtures::path("tls/server.pem"))
        .expect("read server.pem")
        .collect::<Result<Vec<_>, _>>()
        .expect("parse server.pem");
    let key = PrivateKeyDer::from_pem_file(fixtures::path("tls/server.key")).expect("server.key");
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("address").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = config.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let Ok(connection) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(connection, stream);
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = tls.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

fn doctor_with(project: &Path, variable: &str, value: &Path) -> (Output, serde_json::Value) {
    let output = raeva_command(project, project)
        .args(["--json", "doctor"])
        .env(variable, value)
        .output()
        .expect("run raeva doctor");
    let json = serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "doctor JSON: {err}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, json)
}

fn check<'a>(json: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    json["data"]["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["check"] == name)
        .unwrap_or_else(|| panic!("no {name} check in {json}"))
}

fn project_for(port: u16) -> TempDir {
    let project = TempDir::new().expect("project");
    write_repo_toml(
        project.path(),
        "private",
        &format!("https://127.0.0.1:{port}/maven2/"),
    );
    project
}

#[test]
fn ssl_cert_file_supplies_the_only_trusted_roots() {
    let port = spawn_tls_server();
    let project = project_for(port);

    let (output, json) = doctor_with(
        project.path(),
        "SSL_CERT_FILE",
        &fixtures::path("tls/ca.pem"),
    );
    assert_success(&output, "doctor with SSL_CERT_FILE CA");
    assert!(
        check(&json, "TLS trust roots")["details"]
            .as_str()
            .unwrap()
            .contains("1 certificate(s) from SSL_CERT_FILE"),
        "{json}"
    );
    assert!(
        check(&json, "private")["details"]
            .as_str()
            .unwrap()
            .starts_with("404"),
        "the handshake must succeed with the CA from SSL_CERT_FILE: {json}"
    );

    // The same server under roots that do not include its CA: the variable
    // replaces the system store rather than adding to it.
    let (output, json) = doctor_with(
        project.path(),
        "SSL_CERT_FILE",
        &fixtures::path("tls/other-ca.pem"),
    );
    assert_status(&output, 3, "doctor with untrusted SSL_CERT_FILE");
    let details = check(&json, "private")["details"].as_str().unwrap();
    assert!(details.contains("TLS failed"), "{json}");
    assert!(
        details.contains("certificate issuer is unknown or not trusted (UnknownIssuer)"),
        "{json}"
    );
    assert!(details.contains("add its CA to SSL_CERT_FILE"), "{json}");
}

#[test]
fn empty_ssl_cert_file_trusts_nothing() {
    let port = spawn_tls_server();
    let project = project_for(port);
    let (output, json) = doctor_with(project.path(), "SSL_CERT_FILE", Path::new(""));
    assert_status(&output, 3, "doctor with empty SSL_CERT_FILE");
    assert!(
        check(&json, "TLS trust roots")["details"]
            .as_str()
            .unwrap()
            .starts_with("0 certificate(s)"),
        "{json}"
    );
}

#[test]
fn ssl_cert_dir_alone_replaces_the_trusted_roots() {
    let port = spawn_tls_server();
    let project = project_for(port);
    let roots = TempDir::new().expect("roots");
    std::fs::copy(fixtures::path("tls/ca.pem"), roots.path().join("ca.pem")).expect("copy ca.pem");

    let (output, _) = doctor_with(project.path(), "SSL_CERT_DIR", roots.path());
    assert_success(&output, "doctor with SSL_CERT_DIR CA");

    // An empty value names no roots, and must not fall back to the system's.
    let (output, json) = doctor_with(project.path(), "SSL_CERT_DIR", Path::new(""));
    assert_status(&output, 3, "doctor with empty SSL_CERT_DIR");
    assert!(
        check(&json, "TLS trust roots")["details"]
            .as_str()
            .unwrap()
            .starts_with("0 certificate(s)"),
        "{json}"
    );
}

/// OSV queries trust the same roots as repository fetches.
#[test]
fn osv_queries_use_ssl_cert_file() {
    let port = spawn_tls_server();
    let project = Project::synced();
    let osv = format!("https://127.0.0.1:{port}/v1");
    let vuln = |cert_file: &str| {
        let cert = fixtures::path(&format!("tls/{cert_file}"));
        let output = project.raeva_with(
            &[
                ("RAEVA_OSV_BASE_URL", osv.as_str()),
                ("SSL_CERT_FILE", cert.to_str().expect("utf-8 cert path")),
            ],
            &["--json", "vuln"],
        );
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON envelope");
        assert_eq!(
            output.status.code(),
            envelope["exit_code"].as_i64().map(|code| code as i32)
        );
        (
            envelope["exit_code"].clone(),
            envelope["code"].clone(),
            envelope["error"].as_str().unwrap_or_default().to_string(),
        )
    };
    let (_, _, trusted) = vuln("ca.pem");
    assert!(
        trusted.contains("unexpected OSV status 404"),
        "the handshake must succeed: {trusted}"
    );
    let (exit_code, code, untrusted) = vuln("other-ca.pem");
    assert!(
        untrusted.contains("TLS: invalid peer certificate"),
        "the handshake must fail, without retries: {untrusted}"
    );
    // An untrusted certificate is configuration, as in every command.
    assert_eq!((exit_code, code), (3.into(), "TLS".into()));
}

/// A run that makes no request still warns about the roots the environment
/// names, as clients are built only for a request.
#[test]
fn an_offline_sync_warns_about_unusable_ssl_cert_file() {
    let project = Project::synced();
    for args in [
        &["--json", "sync", "--offline"][..],
        &["--json", "sync", "--frozen", "--offline"],
    ] {
        let output = project.raeva_with(&[("SSL_CERT_FILE", "")], args);
        assert_success(&output, "offline sync with empty SSL_CERT_FILE");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("ignoring an empty TLS roots path"),
            "{stdout}"
        );
        assert!(stdout.contains("no usable TLS roots"), "{stdout}");
    }
}

/// Files under `tls/` a `fixtures::path` call below opens. A new file must
/// fail here until a test names it.
fn tls_files() -> Vec<String> {
    let mut names: Vec<String> =
        fixtures::quoted_after(include_str!("tls_roots.rs"), concat!("path", "("))
            .into_iter()
            .filter_map(|path| path.strip_prefix("tls/").map(str::to_string))
            .filter(|name| !name.is_empty() && !name.contains(['/', '{']))
            .collect();
    names.sort();
    names.dedup();
    names
}

#[test]
fn every_tls_fixture_file_is_used() {
    let names = tls_files();
    let files: Vec<&str> = names.iter().map(String::as_str).collect();
    fixtures::assert_children(&fixtures::path("tls"), &[], &files);
}
