//! Forward-compatibility tests for [`rv_config::Lockfile`] and its nested
//! types.
//!
//! Each nested struct carries an `extra` map that captures unknown fields
//! so a newer Raeva's lockfile keys survive a read/write through this
//! version.

use std::fs;

use rv_config::Lockfile;

/// A lockfile carrying unknown fields at the platform, package, and edge
/// levels must round-trip through `Lockfile::read` -> `write_atomic`
/// without losing any of them.
#[test]
fn nested_unknown_fields_survive_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let in_path = dir.path().join("rv-in.lock");
    let out_path = dir.path().join("rv-out.lock");

    let raw = r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"
future_platform_field = "platform-extra-value"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/"
future_package_field = "package-extra-value"

[platforms.packages.checksum]
algorithm = "sha256"
digest = "0000000000000000000000000000000000000000000000000000000000000001"

[[platforms.edges]]
from = 0
to = 0
scope = "compile"
optional = false
future_edge_field = "edge-extra-value"
"#;
    fs::write(&in_path, raw).expect("write input");

    let lock = Lockfile::read(&in_path).expect("read with nested extras");

    assert_eq!(lock.platforms.len(), 1);
    assert_eq!(lock.platforms[0].packages.len(), 1);
    assert_eq!(lock.platforms[0].edges.len(), 1);

    assert!(
        lock.platforms[0]
            .extra
            .contains_key("future_platform_field"),
        "platform-level extras lost on read",
    );
    assert!(
        lock.platforms[0].packages[0]
            .extra
            .contains_key("future_package_field"),
        "package-level extras lost on read",
    );
    assert!(
        lock.platforms[0].edges[0]
            .extra
            .contains_key("future_edge_field"),
        "edge-level extras lost on read",
    );

    lock.write_atomic(&out_path).expect("write_atomic");
    let reread = Lockfile::read(&out_path).expect("re-read");

    assert_eq!(
        reread.platforms[0]
            .extra
            .get("future_platform_field")
            .and_then(|v| v.as_str()),
        Some("platform-extra-value"),
    );
    assert_eq!(
        reread.platforms[0].packages[0]
            .extra
            .get("future_package_field")
            .and_then(|v| v.as_str()),
        Some("package-extra-value"),
    );
    assert_eq!(
        reread.platforms[0].edges[0]
            .extra
            .get("future_edge_field")
            .and_then(|v| v.as_str()),
        Some("edge-extra-value"),
    );
}

/// Pre-v1 lockfiles carried a top-level `[variants]` table that the v1
/// schema no longer recognizes. The struct's flattened `extra` map must
/// absorb it on read and re-serialize it verbatim on write, so an upgrade
/// path that reads + writes the lockfile does not silently drop the
/// section. Without this, every user with a legacy `[variants]` table
/// would lose data on their first v1 `rv sync` re-write.
#[test]
fn legacy_variants_table_round_trips_as_extra() {
    let dir = tempfile::tempdir().expect("tempdir");
    let in_path = dir.path().join("rv-in.lock");
    let out_path = dir.path().join("rv-out.lock");

    let raw = r#"
schema_version = 3

[variants]
default = "linux-x86_64"
linux-x86_64 = { packages = ["a", "b"] }

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/"
"#;
    fs::write(&in_path, raw).expect("write input");

    let lock = Lockfile::read(&in_path).expect("legacy [variants] table must load");
    assert!(
        lock.extra.contains_key("variants"),
        "top-level [variants] table must land in Lockfile::extra"
    );

    lock.write_atomic(&out_path)
        .expect("write must preserve legacy table");
    let reread = Lockfile::read(&out_path).expect("re-read after round-trip");
    assert!(
        reread.extra.contains_key("variants"),
        "legacy [variants] table must survive a read/write round-trip"
    );

    // Validate the structured content survives, not just the key.
    let variants = reread.extra.get("variants").expect("variants key");
    let table = variants.as_table().expect("variants is a table");
    assert_eq!(
        table.get("default").and_then(|v| v.as_str()),
        Some("linux-x86_64"),
        "variants.default value must round-trip verbatim"
    );
}
