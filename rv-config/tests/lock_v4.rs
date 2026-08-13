use std::collections::BTreeMap;
use std::fs;

use rv_config::{
    Checksum, LOCKFILE_SCHEMA_VERSION, LockArtifact, LockCoordinate, LockEdge, LockGav, LockModule,
    LockModulePackage, LockPackage, LockPlatform, LockResolution, LockResolutionStrategy, Lockfile,
    Platform,
};

const MODEL_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn coordinate(artifact: &str) -> LockCoordinate {
    LockCoordinate::new("com.example", artifact, "1.0.0", "jar", None)
}

fn module_package(artifact: &str) -> LockModulePackage {
    LockModulePackage {
        coordinate: coordinate(artifact),
        direct_scope: None,
        workspace_module: None,
        system_path: None,
        extra: BTreeMap::new(),
    }
}

fn artifact(artifact: &str, digest_byte: char) -> LockArtifact {
    LockArtifact {
        coordinate: coordinate(artifact),
        repo_url: "https://repo.example/maven2/".to_string(),
        checksums: vec![Checksum::new(
            "sha256",
            std::iter::repeat_n(digest_byte, 64).collect::<String>(),
        )],
        snapshot: None,
        pom_sha256: None,
        extra: BTreeMap::new(),
    }
}

#[test]
fn write_read_write_is_byte_identical_and_canonically_ordered() {
    let root_workspace = LockModulePackage {
        coordinate: coordinate("z-module"),
        workspace_module: Some("z-module/pom.xml".to_string()),
        ..module_package("z-module")
    };
    let root_external = LockModulePackage {
        direct_scope: Some("compile".to_string()),
        ..module_package("alpha")
    };
    let platform = LockPlatform {
        platform: Platform::new("linux", "x86_64").expect("platform"),
        model_hash: MODEL_HASH.to_string(),
        artifacts: vec![artifact("beta", 'b'), artifact("alpha", 'a')],
        modules: vec![
            LockModule {
                path: "z-module/pom.xml".to_string(),
                gav: LockGav::new("com.example", "z-module", "1.0.0"),
                packaging: "jar".to_string(),
                packages: vec![module_package("beta")],
                edges: Vec::new(),
                extra: BTreeMap::new(),
            },
            LockModule {
                path: "pom.xml".to_string(),
                gav: LockGav::new("com.example", "root", "1.0.0"),
                packaging: "pom".to_string(),
                packages: vec![root_workspace, root_external],
                edges: vec![LockEdge {
                    from: 0,
                    to: 1,
                    scope: Some("compile".to_string()),
                    optional: false,
                    extra: BTreeMap::new(),
                }],
                extra: BTreeMap::new(),
            },
        ],
        extra: BTreeMap::new(),
    };
    let mut lock = Lockfile::new();
    lock.platforms.push(platform);

    let dir = tempfile::tempdir().expect("tempdir");
    let first = dir.path().join("first.lock");
    let second = dir.path().join("second.lock");
    lock.write_atomic(&first).expect("first write");
    let reread = Lockfile::read(&first).expect("read v4");
    reread.write_atomic(&second).expect("second write");

    assert_eq!(
        fs::read(&first).expect("first bytes"),
        fs::read(&second).expect("second bytes")
    );
    assert_eq!(reread.schema_version, LOCKFILE_SCHEMA_VERSION);
    assert_eq!(
        reread.platforms[0]
            .modules
            .iter()
            .map(|module| module.path.as_str())
            .collect::<Vec<_>>(),
        ["pom.xml", "z-module/pom.xml"]
    );
    assert_eq!(
        reread.platforms[0]
            .artifacts
            .iter()
            .map(|artifact| artifact.coordinate.artifact.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );
    assert_eq!(
        reread.platforms[0].modules[0]
            .packages
            .iter()
            .map(|package| package.coordinate.artifact.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "z-module"]
    );
    assert_eq!(
        (
            reread.platforms[0].modules[0].edges[0].from,
            reread.platforms[0].modules[0].edges[0].to,
        ),
        (1, 0),
        "package sorting must remap graph indexes"
    );

    let raw = fs::read_to_string(&first).expect("lock text");
    assert!(raw.contains("[[platforms.modules]]"));
    assert!(raw.contains("[[platforms.artifacts]]"));
    assert!(!raw.contains("[[platforms.packages]]"));
    assert!(!raw.contains("[[platforms.edges]]"));
}

#[test]
fn resolution_strategy_round_trips_and_defaults_to_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rv.lock");

    let mut lock = Lockfile::new();
    lock.platforms.push(LockPlatform::single_module(
        Platform::new("linux", "x86_64").expect("platform"),
        MODEL_HASH,
        "pom.xml",
        LockGav::new("com.example", "root", "1"),
        "pom",
        Vec::new(),
        Vec::new(),
    ));
    lock.resolution = Some(LockResolution::new(LockResolutionStrategy::Highest));
    lock.write_atomic(&path).expect("write lock");

    let raw = fs::read_to_string(&path).expect("lock text");
    assert!(
        raw.contains("[resolution]") && raw.contains("strategy = \"highest\""),
        "resolution table must be written explicitly, got:\n{raw}"
    );
    let reread = Lockfile::read(&path).expect("re-read lock");
    assert_eq!(
        reread.resolution.as_ref().map(|r| r.strategy),
        Some(LockResolutionStrategy::Highest)
    );

    // A lockfile predating the field reads back as "unknown", never as a
    // silently-defaulted `nearest`.
    lock.resolution = None;
    lock.write_atomic(&path).expect("rewrite lock");
    let raw = fs::read_to_string(&path).expect("lock text");
    assert!(!raw.contains("[resolution]"), "got:\n{raw}");
    assert_eq!(Lockfile::read(&path).expect("re-read").resolution, None);
}

#[test]
fn rejects_unknown_resolution_strategy() {
    assert_invalid(
        &format!(
            r#"
schema_version = 4

[resolution]
strategy = "random"

[[platforms]]
platform = "linux-x86_64"
model_hash = "{MODEL_HASH}"
artifacts = []

[[platforms.modules]]
path = "pom.xml"
packaging = "pom"
packages = []
edges = []
[platforms.modules.gav]
group = "com.example"
artifact = "root"
version = "1"
"#
        ),
        "failed to parse lockfile",
    );
}

#[test]
fn committed_v3_fixture_adapts_to_expected_one_module_model() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rv-lock-v3.lock");
    let actual = Lockfile::read(&fixture).expect("read committed v3 fixture");

    let packages = vec![
        LockPackage {
            group_id: "org.example".to_string(),
            artifact_id: "alpha".to_string(),
            version: "1.2.3".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(Checksum::new(
                "sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )),
            system_path: None,
            direct_scope: Some("compile".to_string()),
            extra: BTreeMap::new(),
        },
        LockPackage {
            group_id: "org.example".to_string(),
            artifact_id: "beta".to_string(),
            version: "2.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(Checksum::new(
                "sha1",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )),
            system_path: None,
            direct_scope: None,
            extra: BTreeMap::new(),
        },
    ];
    let expected_platform = LockPlatform::single_module(
        Platform::new("linux", "x86_64").expect("platform"),
        "",
        "pom.xml",
        LockGav::new("__legacy__", "__root__", "0"),
        "pom",
        packages,
        vec![LockEdge {
            from: 0,
            to: 1,
            scope: Some("runtime".to_string()),
            optional: false,
            extra: BTreeMap::new(),
        }],
    );
    let expected = Lockfile {
        schema_version: 3,
        config_hash: Some(
            "b90cbd61745cd63049dfe2b6e2d5a5efc43a04ad9e683a9799979a7c63421fb9".to_string(),
        ),
        resolution: None,
        platforms: vec![expected_platform],
        metadata: BTreeMap::new(),
        extra: BTreeMap::new(),
    };
    assert_eq!(actual, expected);
}

#[test]
fn rejects_duplicate_module_path() {
    assert_invalid(
        &format!(
            r#"
schema_version = 4

[[platforms]]
platform = "linux-x86_64"
model_hash = "{MODEL_HASH}"
artifacts = []

[[platforms.modules]]
path = "pom.xml"
packaging = "pom"
packages = []
edges = []
[platforms.modules.gav]
group = "com.example"
artifact = "root"
version = "1"

[[platforms.modules]]
path = "pom.xml"
packaging = "jar"
packages = []
edges = []
[platforms.modules.gav]
group = "com.example"
artifact = "other"
version = "1"
"#
        ),
        "duplicate module path",
    );
}

#[test]
fn rejects_dangling_workspace_module() {
    assert_invalid(
        &format!(
            r#"
schema_version = 4

[[platforms]]
platform = "linux-x86_64"
model_hash = "{MODEL_HASH}"
artifacts = []

[[platforms.modules]]
path = "pom.xml"
packaging = "pom"
edges = []
[platforms.modules.gav]
group = "com.example"
artifact = "root"
version = "1"

[[platforms.modules.packages]]
workspace_module = "missing/pom.xml"
[platforms.modules.packages.coordinate]
group = "com.example"
artifact = "missing"
version = "1"
packaging = "jar"
"#
        ),
        "does not resolve to a module row",
    );
}

#[test]
fn rejects_orphan_artifact_row() {
    assert_invalid(
        &format!(
            r#"
schema_version = 4

[[platforms]]
platform = "linux-x86_64"
model_hash = "{MODEL_HASH}"

[[platforms.artifacts]]
repo_url = "https://repo.example/maven2/"
checksums = []
[platforms.artifacts.coordinate]
group = "com.example"
artifact = "orphan"
version = "1"
packaging = "jar"

[[platforms.modules]]
path = "pom.xml"
packaging = "pom"
packages = []
edges = []
[platforms.modules.gav]
group = "com.example"
artifact = "root"
version = "1"
"#
        ),
        "orphan artifact row",
    );
}

#[test]
fn rejects_edge_index_out_of_range() {
    assert_invalid(
        &format!(
            r#"
schema_version = 4

[[platforms]]
platform = "linux-x86_64"
model_hash = "{MODEL_HASH}"
artifacts = []

[[platforms.modules]]
path = "pom.xml"
packaging = "pom"
packages = []
[platforms.modules.gav]
group = "com.example"
artifact = "root"
version = "1"

[[platforms.modules.edges]]
from = 0
to = 0
"#
        ),
        "out of bounds",
    );
}

/// The companion-POM pin round-trips, is optional, and is canonicalized to
/// lowercase the way the checksum digests are. `rv export-m2` addresses a
/// content-store blob with it, so a lockfile that survives a write/read cycle
/// with a different digest would export different bytes.
#[test]
fn companion_pom_digest_round_trips_and_is_optional() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rv.lock");
    let digest: String = std::iter::repeat_n('c', 64).collect();

    let mut lock = Lockfile::new();
    let mut platform = LockPlatform::single_module(
        Platform::new("linux", "x86_64").expect("platform"),
        MODEL_HASH,
        "pom.xml",
        LockGav::new("com.example", "root", "1"),
        "pom",
        vec![LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "alpha".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(Checksum::new(
                "sha256",
                std::iter::repeat_n('a', 64).collect::<String>(),
            )),
            system_path: None,
            direct_scope: Some("compile".to_string()),
            extra: BTreeMap::new(),
        }],
        Vec::new(),
    );
    // Uppercase on the way in: canonicalized like every other digest, since
    // the blob-id comparison downstream is byte-wise.
    platform.artifacts[0].pom_sha256 = Some(digest.to_uppercase());
    lock.platforms.push(platform);
    lock.write_atomic(&path).expect("write lock");

    let raw = fs::read_to_string(&path).expect("lock text");
    assert!(
        raw.contains(&format!("pom_sha256 = \"{digest}\"")),
        "the pin must be written in lowercase, got:\n{raw}"
    );
    let reread = Lockfile::read(&path).expect("re-read lock");
    assert_eq!(
        reread.platforms[0].artifacts[0].pom_sha256.as_deref(),
        Some(digest.as_str())
    );

    // A row with no companion POM omits the key entirely, which is how a
    // lockfile written before the field existed reads back.
    let mut without = reread;
    without.platforms[0].artifacts[0].pom_sha256 = None;
    without.write_atomic(&path).expect("rewrite lock");
    let raw = fs::read_to_string(&path).expect("lock text");
    assert!(!raw.contains("pom_sha256"), "got:\n{raw}");
    assert_eq!(
        Lockfile::read(&path).expect("re-read").platforms[0].artifacts[0].pom_sha256,
        None
    );
}

/// A malformed pin can never name a blob, so it is rejected at read time
/// rather than surfacing later as a missing-blob export failure.
#[test]
fn rejects_malformed_companion_pom_digest() {
    assert_invalid(
        &format!(
            r#"
schema_version = 4

[[platforms]]
platform = "linux-x86_64"
model_hash = "{MODEL_HASH}"

[[platforms.artifacts]]
repo_url = "https://repo.example/maven2/"
checksums = []
pom_sha256 = "nothex"
[platforms.artifacts.coordinate]
group = "com.example"
artifact = "alpha"
version = "1.0.0"
packaging = "jar"

[[platforms.modules]]
path = "pom.xml"
packaging = "pom"
edges = []
[platforms.modules.gav]
group = "com.example"
artifact = "root"
version = "1"
[[platforms.modules.packages]]
[platforms.modules.packages.coordinate]
group = "com.example"
artifact = "alpha"
version = "1.0.0"
packaging = "jar"
"#
        ),
        "must be 64 lowercase hex characters",
    );
}

fn assert_invalid(raw: &str, expected: &str) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rv.lock");
    fs::write(&path, raw).expect("write invalid lock");
    let error = Lockfile::read(&path).expect_err("lock must be rejected");
    assert!(
        error.to_string().contains(expected),
        "expected {expected:?} in {error}"
    );
}
