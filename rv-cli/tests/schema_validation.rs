mod common;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;

use common::{rv_command, temp_project};
use jsonschema::{Retrieve, Uri, Validator};
use rv_config::{Checksum, LockPackage, Lockfile};
use serde_json::Value;

const CYCLONEDX_SCHEMA: &str = include_str!("fixtures/schemas/cyclonedx/bom-1.5.schema.json");
const CYCLONEDX_JSF_SCHEMA: &str = include_str!("fixtures/schemas/cyclonedx/jsf-0.82.schema.json");
const CYCLONEDX_SPDX_SCHEMA: &str = include_str!("fixtures/schemas/cyclonedx/spdx.schema.json");
const SPDX_SCHEMA: &str = include_str!("fixtures/schemas/spdx/spdx-2.3.schema.json");
const SARIF_SCHEMA: &str = include_str!("fixtures/schemas/sarif/sarif-2.1.0.schema.json");

struct BundledSchemas {
    schemas: HashMap<String, Value>,
}

impl Retrieve for BundledSchemas {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.schemas
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("schema is not bundled: {uri}").into())
    }
}

struct Documents {
    cyclonedx: Value,
    spdx: Value,
    sarif: Value,
}

#[test]
fn generated_documents_match_official_schemas() {
    let documents = generated_documents();
    assert_valid(&cyclonedx_validator(), &documents.cyclonedx);
    assert_valid(&validator(SPDX_SCHEMA), &documents.spdx);
    assert_valid(&validator(SARIF_SCHEMA), &documents.sarif);
}

#[test]
fn schema_validators_reject_broken_documents() {
    let documents = generated_documents();

    let mut cyclonedx = documents.cyclonedx;
    cyclonedx["bomFormat"] = Value::String("Broken".to_string());
    assert!(!cyclonedx_validator().is_valid(&cyclonedx));

    let mut spdx = documents.spdx;
    spdx.as_object_mut().unwrap().remove("SPDXID");
    assert!(!validator(SPDX_SCHEMA).is_valid(&spdx));

    let mut sarif = documents.sarif;
    sarif.as_object_mut().unwrap().remove("runs");
    assert!(!validator(SARIF_SCHEMA).is_valid(&sarif));
}

fn generated_documents() -> Documents {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());

    let cyclonedx = command_json(project.path(), home.path(), &["sbom"]);
    let spdx = command_json(project.path(), home.path(), &["sbom", "--format", "spdx"]);

    let body = r#"{
        "vulns": [{
            "id": "OSV-SCHEMA-TEST",
            "summary": "schema validation finding",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
            "affected": []
        }]
    }"#;
    let (base_url, server) = spawn_osv(body);
    let output = rv_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", base_url)
        .args(["vuln", "--format", "sarif"])
        .output()
        .expect("run SARIF scan");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let sarif = serde_json::from_slice(&output.stdout).expect("SARIF JSON");
    server.join().expect("OSV server");

    Documents {
        cyclonedx,
        spdx,
        sarif,
    }
}

fn write_fresh_lock(project_root: &Path, home: &Path) {
    fs::write(
        project_root.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
</project>
"#,
    )
    .expect("write pom.xml");
    let output = rv_command(project_root, home)
        .args(["--quiet", "sync", "--offline"])
        .output()
        .expect("run rv sync");
    assert!(
        output.status.success(),
        "sync failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let lock_path = project_root.join("rv.lock");
    let mut lock = Lockfile::read(&lock_path).expect("read generated lock");
    lock.platforms
        .first_mut()
        .expect("generated platform")
        .packages
        .push(LockPackage {
            group_id: "org.example".to_string(),
            artifact_id: "demo-lib".to_string(),
            version: "2.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2".to_string(),
            checksum: Some(Checksum::new(
                "sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )),
            system_path: None,
            direct_scope: Some("compile".to_string()),
            extra: BTreeMap::new(),
        });
    lock.write_atomic(&lock_path).expect("write fixture lock");
}

fn command_json(project_root: &Path, home: &Path, args: &[&str]) -> Value {
    let output = rv_command(project_root, home)
        .args(args)
        .output()
        .expect("run rv command");
    assert!(
        output.status.success(),
        "command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command JSON")
}

fn spawn_osv(response_body: &'static str) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind OSV mock");
    let address = listener.local_addr().expect("mock address");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept OSV request");
        let mut request = [0_u8; 8192];
        let size = stream.read(&mut request).expect("read OSV request");
        assert!(size > 0);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{response_body}",
            response_body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write OSV response");
    });
    (format!("http://{address}/v1"), handle)
}

fn cyclonedx_validator() -> Validator {
    let schema = parse_schema(CYCLONEDX_SCHEMA);
    let schemas = HashMap::from([
        (
            "http://cyclonedx.org/schema/jsf-0.82.schema.json".to_string(),
            parse_schema(CYCLONEDX_JSF_SCHEMA),
        ),
        (
            "http://cyclonedx.org/schema/spdx.schema.json".to_string(),
            parse_schema(CYCLONEDX_SPDX_SCHEMA),
        ),
    ]);
    jsonschema::options()
        .with_retriever(BundledSchemas { schemas })
        .build(&schema)
        .expect("compile CycloneDX schema")
}

fn validator(source: &str) -> Validator {
    jsonschema::validator_for(&parse_schema(source)).expect("compile schema")
}

fn parse_schema(source: &str) -> Value {
    serde_json::from_str(source).expect("parse vendored schema")
}

fn assert_valid(validator: &Validator, document: &Value) {
    let errors = validator
        .iter_errors(document)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors:\n{}", errors.join("\n"));
}
