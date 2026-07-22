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
