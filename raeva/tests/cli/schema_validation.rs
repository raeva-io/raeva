use crate::schemas;

use std::fs;

use crate::common::{
    assert_status, assert_success, raeva_command, spawn_osv, temp_project, write_demo_lock,
};
use rv_lock::Scope;
use schemas::{
    RAEVA_LOCK_SCHEMA, SARIF_SCHEMA, assert_schema_valid, cyclonedx_validator, validator,
};
use serde_json::{Value, json};

const DEMO: &[(&str, &str, Option<&str>, Scope)] = &[("demo-lib", "jar", None, Scope::Compile)];

struct Documents {
    cyclonedx: Value,
    sarif: Value,
}

#[test]
fn generated_documents_match_official_schemas() {
    let documents = generated_documents();
    assert_schema_valid(&cyclonedx_validator(), &documents.cyclonedx);
    assert_schema_valid(&validator(SARIF_SCHEMA), &documents.sarif);
}

#[test]
fn generated_lock_matches_schema() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let raw =
        fs::read_to_string(project.path().join("raeva.lock")).expect("read generated raeva.lock");
    let document: toml::Value = toml::from_str(&raw).expect("parse generated raeva.lock");
    let document = serde_json::to_value(document).expect("convert lock to JSON value");
    assert_schema_valid(&validator(RAEVA_LOCK_SCHEMA), &document);
}

/// The published schema refuses what `Lockfile::read` refuses: unknown keys
/// in any table, an empty classifier, control characters or path separators
/// in a coordinate, a padded platform name, and support-POM rows the reader
/// refuses.
#[test]
fn lock_schema_rejects_hostile_rows() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let raw =
        fs::read_to_string(project.path().join("raeva.lock")).expect("read generated raeva.lock");
    let document: toml::Value = toml::from_str(&raw).expect("parse generated raeva.lock");
    let mut document = serde_json::to_value(document).expect("convert lock to JSON value");
    document["resolution"] = json!({
        "ambient_inputs": ["java.version"],
        "command_line": ["-DskipTests", "-P!dev"],
    });
    let schema = validator(RAEVA_LOCK_SCHEMA);
    assert!(schema.is_valid(&document));

    // Each row merges its fields into the table its JSON pointer names.
    let digest = "a".repeat(64);
    let support = |coordinate: &str, repo_url: &str, sha256: &str| json!({ "coordinate": coordinate, "repo_url": repo_url, "sha256": sha256 });
    let mutations = json!([
        ["/platforms/0/artifacts/0", { "classifer": "tests" }],
        ["/platforms/0/artifacts/0", { "pom_base": true }],
        ["/platforms/0/artifacts/0", { "pom_base": false }],
        ["/platforms/0", { "future": true }],
        ["/platforms/0/modules/0", { "edges": "0 0 compile future" }],
        ["/platforms/0/modules/0", { "gav": "com.example:demo" }],
        ["/platforms/0/modules/0", { "packages": "com.example:lib:1.0\tjar:" }],
        ["/platforms/0/modules/0", { "packages": "com.example:lib:1.0\tjar\tcompile\t\tx\u{1b}[31m/pom.xml" }],
        ["/platforms/0/artifacts/0/coordinate", { "classifier": "" }],
        ["/platforms/0/artifacts/0/coordinate", { "version": "1.0\n0000  x/y/1/y-1.jar" }],
        ["/platforms/0/artifacts/0/coordinate", { "artifact": "a\u{1b}[31m" }],
        ["/platforms/0/artifacts/0/coordinate", { "packaging": "jar;x" }],
        ["/platforms/0/artifacts/0", { "repo_url": "https://a.example/\u{202e}/" }],
        ["/platforms/0/modules/0", { "packages": "com.example:lib:1.0\tjar\tmerged" }],
        ["/platforms/0/modules/0", { "packages": "com.example:lib:1.0\tjar\t\tmerged" }],
        ["/inputs/0", { "profiles": ["ci\u{1b}]0;x"] }],
        ["/inputs/0", { "profiles": ["ci\u{3164}"] }],
        ["/platforms/0", { "targets": [" linux-x86_64"] }],
        ["", { "config_hash": "ab\u{ad}cd" }],
        ["", { "written_by_a_newer_raeva": true }],
        ["/resolution", { "future_setting": 1 }],
        ["", { "resolution": {} }],
        ["/resolution", { "command_line": ["-Xmx1g"] }],
        ["/resolution", { "command_line": ["-DskipTests=true"] }],
        ["/resolution", { "command_line": ["-D"] }],
        ["/resolution", { "command_line": ["-Pci\u{1b}[31m"] }],
        ["/resolution", { "command_line": ["-Pci\u{e0001}"] }],
        ["/resolution", { "command_line": ["-Da b"] }],
        ["", { "metadata": { "future_key": "x" } }],
        ["/resolution", { "ambient_inputs": ["jdk:[17,)"] }],
        ["/resolution", { "ambient_inputs": ["jdk:1\u{1b}[2J is true"] }],
        ["/resolution", { "ambient_inputs": ["property:env.CI=yes\u{202e} is true"] }],
        ["/resolution", { "ambient_inputs": ["property:os.name is true"] }],
        ["/resolution", { "ambient_inputs": ["file:../marker is true"] }],
        ["/resolution", { "ambient_inputs": ["file:/etc/marker is true"] }],
        ["/resolution", { "ambient_inputs": ["file:a//b is true"] }],
        ["/resolution", { "ambient_inputs": ["file:a\\b is true"] }],
        ["/resolution", { "ambient_inputs": ["file:C:/marker is true"] }],
        ["/resolution", { "ambient_inputs": ["settings:/home/u/.m2 is true"] }],
        ["/resolution", { "ambient_inputs": ["settings:0123456789ABCDEF is true"] }],
        ["/platforms/0", { "support_poms": [support("org..test:bom:1", "https://r.example/", &digest)] }],
        ["/platforms/0", { "support_poms": [support("org.test:bom.:1", "https://r.example/", &digest)] }],
        ["/platforms/0", { "support_poms": [support("org.test:bom:1", "https://r\u{202e}/", &digest)] }],
        ["/platforms/0", { "support_poms": [support("org.test:bom:1", "https://r.example/", &digest.to_uppercase())] }],
        ["/platforms/0", { "support_poms": [{
            "coordinate": "org.test:bom:1", "repo_url": "https://r.example/", "sha256": digest, "future": 1,
        }] }],
    ]);
    let range_mutations = json!([
        ["/platforms/0/modules/0", { "parent_ranges": [{ "model": "g:a:1", "parent": "g:p:[1,3)", "selected": "g:p:2", "future": true }] }],
        ["/platforms/0/modules/0", { "parent_ranges": [{ "model": "g:a:1", "parent": "g:p:[1,3)" }] }],
        ["/platforms/0/modules/0", { "parent_ranges": [{ "model": "g:a:1", "parent": "g:p:[1,3)", "selected": "g:parent.:2" }] }],
        ["/platforms/0/modules/0", { "parent_ranges": [{ "model": "g:a:1", "parent": "g:p:[1,\n3)", "selected": "g:p:2" }] }],
    ]);
    let read_mutations = json!([
        ["/inputs/0", { "ambient_inputs": ["java.version"] }],
        ["/inputs/0", { "ambient_inputs": ["env.CI", "env.CI"] }],
        ["/inputs/0", { "ambient_inputs": [] }],
        ["/inputs/0/poms/0", { "ambient_inputs": ["os-release"] }],
        ["/inputs/0", { "host_inputs": ["env.CI"] }],
        ["/inputs/0", { "host_inputs": ["settings-property:x"] }],
        ["/inputs/0", { "host_inputs": ["user-property:x"] }],
        ["/inputs/0", { "host_inputs": ["java.version", "java.version"] }],
    ]);
    let path = project.path().join("hostile.lock");
    for row in mutations
        .as_array()
        .expect("rows")
        .iter()
        .chain(range_mutations.as_array().expect("range rows"))
        .chain(read_mutations.as_array().expect("read rows"))
    {
        let (table, fields) = (row[0].as_str().expect("pointer"), &row[1]);
        let name = format!("{fields} at {table:?}");
        let mut hostile = document.clone();
        let target = hostile.pointer_mut(table).and_then(Value::as_object_mut);
        target
            .expect(table)
            .extend(fields.as_object().expect("fields").clone());
        assert!(!schema.is_valid(&hostile), "the schema must reject: {name}");
        let text = toml::to_string(&hostile).expect("hostile lock as TOML");
        fs::write(&path, text).expect("write hostile lock");
        rv_lock::Lockfile::read(&path).expect_err(&format!(
            "the reader must reject what the schema does: {name}"
        ));
    }
    // Both count the text of a condition in characters.
    for (count, valid) in [
        (rv_lock::MAX_CONDITION_TEXT_LEN, true),
        (rv_lock::MAX_CONDITION_TEXT_LEN + 1, false),
    ] {
        let mut lock = document.clone();
        lock["resolution"]["ambient_inputs"] =
            json!([format!("jdk:{} is true", "\u{e9}".repeat(count))]);
        assert_eq!(schema.is_valid(&lock), valid, "{count}");
        fs::write(&path, toml::to_string(&lock).expect("lock as TOML")).expect("write lock");
        assert_eq!(rv_lock::Lockfile::read(&path).is_ok(), valid, "{count}");
    }
    let mut lock = document.clone();
    lock["resolution"]["ambient_inputs"] = json!([
        "file:src/main/marker.txt is true",
        "file:module/../marker.txt is true",
        "settings:0123456789abcdef is false",
        "user-property-lookup:{\"expression\":\"${selector}\",\"properties\":{},\"source\":\"user\",\"mode\":\"property\"}"
    ]);
    assert!(
        schema.is_valid(&lock),
        "project files and settings conditions"
    );
    fs::write(&path, toml::to_string(&lock).expect("lock as TOML")).expect("write lock");
    rv_lock::Lockfile::read(&path).expect("project files and settings conditions");
    let settings = "settings:0123456789abcdef is false";
    for (ambient, host_inputs) in [
        (json!(["env.CI"]), json!([])),
        (json!([settings]), json!([settings])),
    ] {
        let mut target = document.clone();
        target["resolution"]["ambient_inputs"] = ambient;
        target["inputs"][0]["host_inputs"] = host_inputs;
        assert!(schema.is_valid(&target), "{target}");
        fs::write(&path, toml::to_string(&target).expect("lock as TOML")).expect("write lock");
        rv_lock::Lockfile::read(&path).expect("a target's host inputs");
    }
}

fn generated_documents() -> Documents {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());

    let cyclonedx_output = raeva_command(project.path(), home.path())
        .arg("sbom")
        .output()
        .expect("run raeva sbom");
    assert_success(&cyclonedx_output, "sbom");
    let cyclonedx = serde_json::from_slice(&cyclonedx_output.stdout).expect("CycloneDX JSON");

    let body = r#"{
        "vulns": [{
            "id": "OSV-SCHEMA-TEST",
            "summary": "schema validation finding",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
            "affected": []
        }]
    }"#;
    let (base_url, server) = spawn_osv(200, body);
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", base_url)
        .args(["vuln", "--format", "sarif"])
        .output()
        .expect("run SARIF scan");
    assert_status(&output, 1, "SARIF scan");
    assert!(String::from_utf8_lossy(&output.stderr).contains("known vulnerabilit"));
    let sarif = serde_json::from_slice(&output.stdout).expect("SARIF JSON");
    assert_eq!(server.answered(), 1);
    server.stop();

    Documents { cyclonedx, sarif }
}
