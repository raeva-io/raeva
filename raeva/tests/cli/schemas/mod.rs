use std::collections::{BTreeMap, HashMap};

use jsonschema::{Retrieve, Uri, Validator};
use rv_test_support::fixtures;
use serde_json::Value;

const CYCLONEDX_SCHEMA: &str = include_str!("../../fixtures/schemas/cyclonedx/bom-1.5.schema.json");
const CYCLONEDX_JSF_SCHEMA: &str =
    include_str!("../../fixtures/schemas/cyclonedx/jsf-0.82.schema.json");
const CYCLONEDX_SPDX_SCHEMA: &str =
    include_str!("../../fixtures/schemas/cyclonedx/spdx.schema.json");
pub(crate) const SARIF_SCHEMA: &str =
    include_str!("../../fixtures/schemas/sarif/sarif-2.1.0.schema.json");
pub(crate) const RAEVA_LOCK_SCHEMA: &str = include_str!("../../../../schemas/raeva-lock.json");

/// Serves the schemas the CycloneDX schema references from the vendored
/// copies, so validation never reaches the network.
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

fn parse_schema(source: &str) -> Value {
    serde_json::from_str(source).expect("parse vendored schema")
}

pub(crate) fn cyclonedx_validator() -> Validator {
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
        .build(&parse_schema(CYCLONEDX_SCHEMA))
        .expect("compile CycloneDX schema")
}

pub(crate) fn validator(source: &str) -> Validator {
    jsonschema::validator_for(&parse_schema(source)).expect("compile schema")
}

pub(crate) fn assert_schema_valid(validator: &Validator, document: &Value) {
    let errors = validator
        .iter_errors(document)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors:\n{}", errors.join("\n"));
}

fn embedded_paths(prefix: &str) -> Vec<String> {
    let mut paths: Vec<String> =
        fixtures::quoted_after(include_str!("mod.rs"), concat!("include_str!", "("))
            .into_iter()
            .filter_map(|path| path.strip_prefix(prefix).map(str::to_string))
            .collect();
    paths.sort();
    paths
}

/// Vendored schemas this module embeds. A new file must fail here until it
/// is listed in the README tables, `include_str!`'d, and present on disk.
/// A name that only appears in prose does not count.
#[test]
fn every_vendored_schema_file_is_used() {
    let root = fixtures::workspace_root().join("raeva/tests/fixtures/schemas");
    let readme = fixtures::workspace_file("raeva/tests/fixtures/schemas/README.md");
    let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let headings: Vec<String> = fixtures::markdown_prose_lines(&readme)
        .into_iter()
        .filter(|line| line.starts_with("## "))
        .map(str::to_string)
        .collect();
    assert!(!headings.is_empty(), "schema README has no ## headings");
    for heading in &headings {
        let section = fixtures::markdown_section(&readme, heading);
        if !fixtures::markdown_prose_lines(section)
            .iter()
            .any(|line| line.starts_with('|'))
        {
            continue;
        }
        for path in fixtures::markdown_first_column(&readme, heading) {
            let (dir, name) = path
                .split_once('/')
                .unwrap_or_else(|| panic!("schema table path {path}"));
            assert!(
                !name.contains('/'),
                "schema file must be a file in {dir}: {path}"
            );
            by_dir
                .entry(dir.to_string())
                .or_default()
                .push(name.to_string());
        }
    }
    let mut listed = Vec::new();
    for (dir, names) in &by_dir {
        for name in names {
            listed.push(format!("{dir}/{name}"));
        }
    }
    listed.sort();
    let embedded = embedded_paths("../../fixtures/schemas/");
    assert_eq!(
        embedded, listed,
        "include_str! paths and README schema tables differ"
    );
    let dirs: Vec<&str> = by_dir.keys().map(String::as_str).collect();
    fixtures::assert_children(&root, &dirs, &["README.md"]);
    for (dir, mut names) in by_dir {
        names.sort();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        fixtures::assert_children(&root.join(dir), &[], &names);
    }
}

/// `schemas/raeva-lock.json` is the lock schema this module embeds. A second
/// file must fail here until it is `include_str!`'d and present on disk.
#[test]
fn every_workspace_schema_file_is_used() {
    let files = embedded_paths("../../../../schemas/");
    for name in &files {
        assert!(
            !name.contains('/'),
            "workspace schema must be a file in schemas/: {name}"
        );
    }
    let files: Vec<&str> = files.iter().map(String::as_str).collect();
    fixtures::assert_children(&fixtures::workspace_root().join("schemas"), &[], &files);
}
