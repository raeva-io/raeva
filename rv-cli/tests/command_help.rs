mod common;

use common::{rv_command, temp_project};

#[test]
fn cli_version_uses_workspace_version() {
    let (project, home) = temp_project();
    let output = rv_command(project.path(), home.path())
        .arg("--version")
        .output()
        .expect("run rv --version");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 version"),
        format!("rv {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn vuln_help_documents_formats_flags_and_exit_codes() {
    let (project, home) = temp_project();
    let output = rv_command(project.path(), home.path())
        .args(["vuln", "--help"])
        .output()
        .expect("run rv vuln --help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    assert!(help.contains("--format <FORMAT>"));
    assert!(help.contains("--fail-on <SEVERITY>"));
    assert!(help.contains("sarif    SARIF 2.1.0"));
    assert!(help.contains("0  Scan completed with no findings"));
    assert!(help.contains("1  Scan completed with findings"));
    assert!(help.contains("2  Scan did not complete"));
    assert!(help.contains("Unknown severity meets every --fail-on threshold"));
}

#[test]
fn sbom_help_documents_formats_and_output() {
    let (project, home) = temp_project();
    let output = rv_command(project.path(), home.path())
        .args(["sbom", "--help"])
        .output()
        .expect("run rv sbom --help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    assert!(help.contains("cyclonedx    CycloneDX 1.5 JSON (default)"));
    assert!(help.contains("spdx         SPDX 2.3 JSON"));
    assert!(help.contains("-o, --output <FILE>"));
    assert!(help.contains("Writes the document to stdout"));
}

#[test]
fn lock_consumers_document_the_shared_module_selector() {
    let (project, home) = temp_project();
    for args in [
        &["tree", "--help"][..],
        &["why", "--help"][..],
        &["vuln", "--help"][..],
        &["sbom", "--help"][..],
        &["lock", "verify", "--help"][..],
    ] {
        let output = rv_command(project.path(), home.path())
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("run rv {args:?}: {error}"));
        assert!(
            output.status.success(),
            "rv {args:?} --help failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let help = String::from_utf8(output.stdout).expect("UTF-8 help");
        assert!(
            help.contains("--module <MODULE>"),
            "rv {args:?} omits the module selector:\n{help}"
        );
        assert!(
            help.contains("root-relative pom.xml path or unique groupId:artifactId"),
            "rv {args:?} omits selector matching rules:\n{help}"
        );
    }
}

#[test]
fn credential_command_help_documents_storage_and_input_behavior() {
    let (project, home) = temp_project();
    let login = rv_command(project.path(), home.path())
        .args(["login", "--help"])
        .output()
        .expect("run rv login --help");
    assert!(login.status.success());
    let login_help = String::from_utf8(login.stdout).expect("UTF-8 help");
    assert!(login_help.contains("<URL_OR_ID>"));
    assert!(login_help.contains("--auth-type <AUTH_TYPE>"));
    assert!(login_help.contains("basic"));
    assert!(login_help.contains("bearer"));
    assert!(login_help.contains("--username <USER>"));
    assert!(login_help.contains("--password-stdin"));
    assert!(login_help.contains("not remotely verified"));

    let auth = rv_command(project.path(), home.path())
        .args(["auth", "list", "--help"])
        .output()
        .expect("run rv auth list --help");
    assert!(auth.status.success());
    let auth_help = String::from_utf8(auth.stdout).expect("UTF-8 help");
    assert!(auth_help.contains("without reading or displaying secrets"));
}

#[test]
fn auth_list_reads_only_non_secret_index_metadata() {
    let (project, home) = temp_project();
    std::fs::write(
        home.path().join("credentials.json"),
        r#"{
  "version": 1,
  "entries": [{
    "endpoint": "https://repo.example/maven2/",
    "id": "corp",
    "username": "alice",
    "auth_type": "basic"
  }]
}"#,
    )
    .expect("write index");

    let output = rv_command(project.path(), home.path())
        .args(["auth", "list"])
        .output()
        .expect("run rv auth list");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("https://repo.example/maven2/"));
    assert!(stdout.contains("corp"));
    assert!(stdout.contains("alice"));
    assert!(stdout.contains("basic"));
    assert!(!stdout.contains("password"));
    assert!(!stdout.contains("token"));
}

#[test]
fn non_tty_login_requires_explicit_basic_username() {
    let (project, home) = temp_project();
    let mut child = rv_command(project.path(), home.path())
        .args(["login", "https://repo.example/maven2/", "--password-stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn rv login");
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(b"secret\n")
            .expect("write password");
    }
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
    assert!(stderr.contains("--username USER"));
    assert!(!stderr.contains("secret"));
}
