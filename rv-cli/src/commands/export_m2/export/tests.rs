use super::super::error::ExportError;
use super::super::link::LinkStrategy;
use super::{ExportOptions, Exporter, SupportPomPin, lexical_normalize};
use rv_config::{BlobId, Checksum, LockGav, LockPackage, LockPlatform, Lockfile, Platform};
use rv_store::{ArtifactKey, Store};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

/// Support-POM provenance with no recorded digest: what a lockfile written
/// before the digest existed carries, and the path that still resolves the
/// POM through the store's coordinate index.
fn unpinned_support(repo_id: &str) -> SupportPomPin {
    SupportPomPin {
        repo_id: repo_id.to_string(),
        sha256: None,
    }
}

/// Support-POM provenance pinning `bytes`, as a lockfile written by a
/// current `rv sync` carries it.
fn pinned_support(repo_id: &str, bytes: &[u8]) -> SupportPomPin {
    SupportPomPin {
        repo_id: repo_id.to_string(),
        sha256: Some(BlobId::from_bytes(bytes)),
    }
}

fn test_platform(platform: Platform, package: LockPackage) -> LockPlatform {
    test_platform_packages(platform, vec![package])
}

fn test_platform_packages(platform: Platform, packages: Vec<LockPackage>) -> LockPlatform {
    LockPlatform::single_module(
        platform,
        "",
        "pom.xml",
        LockGav::new("com.example", "root", "1"),
        "pom",
        packages,
        Vec::new(),
    )
}

/// Regression: a path that lexically contains `..` segments
/// must be collapsed before the containment check runs, otherwise
/// `dest.starts_with(root)` returns true for paths that resolve
/// outside the root once `..` is honoured.
#[test]
fn lexical_normalize_collapses_parent_dir() {
    let normalised = lexical_normalize(std::path::Path::new("/m2/com/example/../escape"));
    assert_eq!(normalised, std::path::Path::new("/m2/com/escape"));
    let still_inside = lexical_normalize(std::path::Path::new("/m2/com/./example"));
    assert_eq!(still_inside, std::path::Path::new("/m2/com/example"));
}

/// `read_support_refs` returns the `<parent>` and every import-scoped BOM
/// whose version resolves against the POM's own properties, and *omits* an
/// import whose version stays an unresolved `${property}` (the parent-only
/// -property residual, skipped with a warning rather than mis-resolved).
#[test]
fn read_support_refs_resolves_same_pom_props_and_skips_parent_only() {
    let dir = tempdir().expect("dir");
    let pom_path = dir.path().join("pom.xml");
    let pom = "<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>com.example</groupId><artifactId>the-parent</artifactId>\
<version>9.9.9</version></parent>\
<groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version>\
<properties><bom.version>2.2.2</bom.version></properties>\
<dependencyManagement><dependencies>\
<dependency><groupId>com.example</groupId><artifactId>resolvable-bom</artifactId>\
<version>${bom.version}</version><type>pom</type><scope>import</scope></dependency>\
<dependency><groupId>com.example</groupId><artifactId>parent-prop-bom</artifactId>\
<version>${parent.only.version}</version><type>pom</type><scope>import</scope></dependency>\
</dependencies></dependencyManagement></project>";
    fs::write(&pom_path, pom).expect("write pom");

    let refs = super::read_support_refs(&pom_path).expect("parse");

    assert!(
        refs.contains(&(
            "com.example".to_string(),
            "the-parent".to_string(),
            "9.9.9".to_string(),
        )),
        "parent must be a support ref: {refs:?}"
    );
    assert!(
        refs.contains(&(
            "com.example".to_string(),
            "resolvable-bom".to_string(),
            "2.2.2".to_string(),
        )),
        "same-POM-property import BOM must resolve: {refs:?}"
    );
    assert!(
        !refs.iter().any(|(_, a, _)| a == "parent-prop-bom"),
        "parent-only-property import BOM must be skipped: {refs:?}"
    );
}

#[tokio::test]
async fn export_rejects_pin_mismatch_against_indexed_blob_sha256() {
    // Shared global store. Project A's sync populated the index
    // with blob_a for key K; Project B's lockfile pins blob_b for K.
    // export-m2 must NOT silently ship A's bytes; it must fail with a
    // clear "run `rv sync` first" hint.
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let blob_a = store.put_bytes(b"project-a-bytes").await.expect("put a");
    let _blob_b = store
        .put_bytes(b"project-b-different-bytes")
        .await
        .expect("put b");

    let key = ArtifactKey::new("com.example", "shared", "1.0.0", "jar", None);
    // Index points at A's blob (as if `rv sync` ran for project A first).
    store.add_artifact(&key, &blob_a).await.expect("add a");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "shared".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            // Project B's lockfile pins B's digest, NOT A's.
            checksum: Some(Checksum::new(
                "sha256",
                rv_config::BlobId::from_bytes(b"project-b-different-bytes").as_str(),
            )),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2_dir.path().join("repository"),
    };
    let exporter = Exporter::new(options, &store);

    let err = exporter
        .export_lock(&lock, None)
        .await
        .expect_err("must reject pin mismatch");
    let msg = err.to_string();
    assert!(
        msg.contains("does not match") && msg.contains("rv sync"),
        "expected pin-mismatch hint, got: {msg}"
    );
}

#[tokio::test]
async fn export_rejects_pin_mismatch_against_indexed_blob_sha1() {
    // Same scenario as above, but the lockfile pins SHA-1.
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let blob_a = store.put_bytes(b"project-a-bytes").await.expect("put a");

    let key = ArtifactKey::new("com.example", "shared", "1.0.0", "jar", None);
    store.add_artifact(&key, &blob_a).await.expect("add a");

    // A bogus 40-char hex digest that cannot match SHA-1 of A's bytes.
    let bogus_sha1 = "0".repeat(40);

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "shared".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(Checksum::new("sha1", bogus_sha1)),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2_dir.path().join("repository"),
    };
    let exporter = Exporter::new(options, &store);

    let err = exporter
        .export_lock(&lock, None)
        .await
        .expect_err("must reject sha1 pin mismatch");
    let msg = err.to_string();
    assert!(
        msg.contains("does not match") && msg.contains("sha1"),
        "expected sha1 pin-mismatch hint, got: {msg}"
    );
}

#[test]
fn write_sidecar_atomic_writes_full_content_and_no_temp_leftover() {
    // The temp file must be opened, written, fsynced, then renamed.
    // Verifying the well-known idiom by asserting end-state: the final
    // file holds the full content and no `.tmp` leftovers remain.
    let dir = tempdir().expect("tempdir");
    let target = dir.path().join("artifact.jar.sha256");
    super::write_sidecar_atomic(&target, "deadbeef").expect("write sidecar");
    assert_eq!(
        fs::read_to_string(&target).expect("read"),
        "deadbeef",
        "sidecar must contain the exact digest"
    );
    let leftover = fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".sidecar."));
    assert!(!leftover, "no temp sidecar file should remain after rename");
}

#[tokio::test]
async fn export_lock_exports_jar_and_pom() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let jar_id = store.put_bytes(b"jar").await.expect("jar");
    let pom_id = store.put_bytes(b"pom").await.expect("pom");

    let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    store
        .add_artifact(&jar_key, &jar_id)
        .await
        .expect("add jar");

    let pom_key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
    store
        .add_artifact(&pom_key, &pom_id)
        .await
        .expect("add pom");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2_dir.path().join("repository"),
    };
    let exporter = Exporter::new(options, &store);

    let stats = exporter.export_lock(&lock, None).await.expect("export");
    assert_eq!(stats.exported_count, 2);
    assert_eq!(stats.copied_count, 2);
    assert_eq!(stats.linked_count, 0);
    assert_eq!(stats.skipped_count, 0);

    let jar_path = m2_dir
        .path()
        .join("repository")
        .join("com")
        .join("example")
        .join("demo")
        .join("1.0.0")
        .join("demo-1.0.0.jar");
    let pom_path = m2_dir
        .path()
        .join("repository")
        .join("com")
        .join("example")
        .join("demo")
        .join("1.0.0")
        .join("demo-1.0.0.pom");

    assert_eq!(fs::read(&jar_path).expect("jar read"), b"jar");
    assert_eq!(fs::read(&pom_path).expect("pom read"), b"pom");
}

#[tokio::test]
async fn export_lock_skips_identical_files() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let jar_id = store.put_bytes(b"jar").await.expect("jar");
    let pom_id = store.put_bytes(b"pom").await.expect("pom");

    let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    store
        .add_artifact(&jar_key, &jar_id)
        .await
        .expect("add jar");

    let pom_key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
    store
        .add_artifact(&pom_key, &pom_id)
        .await
        .expect("add pom");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2_dir.path().join("repository"),
    };
    let exporter = Exporter::new(options, &store);

    let stats = exporter.export_lock(&lock, None).await.expect("export");
    assert_eq!(stats.exported_count, 2);

    let stats = exporter.export_lock(&lock, None).await.expect("export");
    assert_eq!(stats.exported_count, 0);
    assert_eq!(stats.skipped_count, 2);
}

/// Build a `LockPackage` mirroring an `ArtifactKey` for use in tests that
/// exercise path-construction without an actual lockfile round-trip.
fn pkg_from_key(key: &ArtifactKey) -> LockPackage {
    LockPackage {
        group_id: key.group_id.clone(),
        artifact_id: key.artifact_id.clone(),
        version: key.version.clone(),
        snapshot_timestamp: None,
        packaging: key.packaging.clone(),
        classifier: key.classifier.clone(),
        repo_url: String::new(),
        checksum: None,
        system_path: None,
        direct_scope: None,
        extra: std::collections::BTreeMap::new(),
    }
}

#[tokio::test]
async fn rejects_path_traversal_in_group_id() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let m2_dir = tempdir().expect("m2 dir");
    fs::create_dir_all(m2_dir.path().join("repository")).expect("create m2");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2_dir.path().join("repository"),
    };
    let exporter = Exporter::new(options, &store);

    let cases = [
        ArtifactKey::new("../../etc", "passwd", "1.0.0", "jar", None),
        ArtifactKey::new("com/example", "demo", "1.0.0", "jar", None),
        ArtifactKey::new("com.example", "demo\\..\\etc", "1.0.0", "jar", None),
        ArtifactKey::new("com.example", "demo", "../../../etc", "jar", None),
        ArtifactKey::new("com.example", "demo", "1.0.0", "../evil", None),
        ArtifactKey::new(
            "com.example",
            "demo",
            "1.0.0",
            "jar",
            Some("foo/bar".to_string()),
        ),
    ];
    for key in &cases {
        let err = exporter
            .safe_artifact_path(key, &pkg_from_key(key))
            .expect_err("path traversal must be rejected");
        assert!(
            matches!(err, ExportError::InvalidCoordinate(_)),
            "expected InvalidCoordinate, got {err:?}"
        );
    }
}

#[tokio::test]
async fn accepts_valid_coordinates() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let m2_dir = tempdir().expect("m2 dir");
    fs::create_dir_all(m2_dir.path().join("repository")).expect("create m2");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2_dir.path().join("repository"),
    };
    let exporter = Exporter::new(options, &store);

    // Valid coordinate should work
    let valid_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    let path = exporter
        .safe_artifact_path(&valid_key, &pkg_from_key(&valid_key))
        .expect("valid coordinate must produce a path");
    let expected = m2_dir
        .path()
        .join("repository")
        .join("com")
        .join("example")
        .join("demo")
        .join("1.0.0")
        .join("demo-1.0.0.jar");
    assert_eq!(path, expected);

    // Dots in group_id are fine (they get converted to path separators)
    let valid_key = ArtifactKey::new("org.apache.maven", "maven-core", "3.9.0", "jar", None);
    let path = exporter
        .safe_artifact_path(&valid_key, &pkg_from_key(&valid_key))
        .expect("dotted group_id must produce a path");
    let expected = m2_dir
        .path()
        .join("repository")
        .join("org")
        .join("apache")
        .join("maven")
        .join("maven-core")
        .join("3.9.0")
        .join("maven-core-3.9.0.jar");
    assert_eq!(path, expected);
}

#[tokio::test]
async fn dry_run_does_not_create_directories() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let m2_dir = tempdir().expect("m2 dir");
    let m2_path = m2_dir.path().join("repository");
    // Do NOT pre-create the repository dir; dry_run must not create it.
    let options = ExportOptions {
        dry_run: true,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2_path.clone(),
    };
    // We need m2_path to exist for canonicalize to work; create only the root.
    fs::create_dir_all(&m2_path).expect("create m2 root");

    let exporter = Exporter::new(options, &store);
    let valid_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    let path = exporter
        .safe_artifact_path(&valid_key, &pkg_from_key(&valid_key))
        .expect("dry_run path resolution must succeed");
    let expected_parent = m2_path
        .join("com")
        .join("example")
        .join("demo")
        .join("1.0.0");
    assert_eq!(path, expected_parent.join("demo-1.0.0.jar"));
    // The artifact's parent directory must NOT have been created.
    assert!(
        !expected_parent.exists(),
        "dry_run must not create directories, but {:?} was created",
        expected_parent
    );
}

/// Cross-repo provenance: a support POM (parent/BOM) that resolved from a
/// DIFFERENT repository than its child must get its OWN source-repo id in
/// `_remote.repositories`, not the child's. `rv sync` records this
/// provenance (support_repo_ids); export must honour it over the guessed
/// child repo_url.
#[tokio::test]
async fn support_pom_marker_uses_its_own_source_repo_id() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let child_pom: &[u8] = br#"<project><modelVersion>4.0.0</modelVersion>
            <parent><groupId>com.example</groupId><artifactId>theparent</artifactId><version>2.0</version></parent>
            <artifactId>child</artifactId></project>"#;
    let parent_pom: &[u8] = br#"<project><modelVersion>4.0.0</modelVersion>
            <groupId>com.example</groupId><artifactId>theparent</artifactId><version>2.0</version><packaging>pom</packaging></project>"#;
    let jar_id = store.put_bytes(b"child-jar").await.expect("jar");
    let child_pom_id = store.put_bytes(child_pom).await.expect("child pom");
    let parent_pom_id = store.put_bytes(parent_pom).await.expect("parent pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "child", "1.0", "jar", None),
            &jar_id,
        )
        .await
        .unwrap();
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "child", "1.0", "pom", None),
            &child_pom_id,
        )
        .await
        .unwrap();
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "theparent", "2.0", "pom", None),
            &parent_pom_id,
        )
        .await
        .unwrap();

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        Platform::new("linux", "x86_64").unwrap(),
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "child".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo-a.example/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        },
    )];

    let m2_dir = tempdir().unwrap();
    let m2 = m2_dir.path().join("repository");
    fs::create_dir_all(&m2).unwrap();
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };

    let mut repo_ids = HashMap::new();
    repo_ids.insert("https://repo-a.example/".to_string(), "repo-a".to_string());
    let mut support = HashMap::new();
    support.insert(
        "com.example:theparent:2.0".to_string(),
        unpinned_support("repo-b"),
    );

    let exporter = Exporter::new(options, &store)
        .with_repo_ids(repo_ids)
        .with_support_poms(support);
    exporter.export_lock(&lock, None).await.expect("export");

    let parent_marker = m2.join("com/example/theparent/2.0/_remote.repositories");
    let body = fs::read_to_string(&parent_marker).expect("parent marker");
    assert!(
        body.contains("theparent-2.0.pom>repo-b="),
        "parent marker must use its OWN source repo id (repo-b), got: {body}"
    );

    let child_marker = m2.join("com/example/child/1.0/_remote.repositories");
    let cbody = fs::read_to_string(&child_marker).expect("child marker");
    assert!(
        cbody.contains(">repo-a="),
        "child marker must use the child's repo id (repo-a), got: {cbody}"
    );
}

/// Exporting a timestamped snapshot must:
///
/// 1. Place the jar at `<base-snapshot-version>/<artifact>-<timestamped>.jar`
///    (matching `mvn -o`'s expected layout).
/// 2. Write a `maven-metadata-local.xml` next to it that pins the
///    timestamp, build number, and snapshotVersion entries.
/// 3. Write a group-level `maven-metadata-local.xml` listing the
///    `<base-snapshot-version>` under `<versioning><versions>`.
#[tokio::test]
async fn export_lock_routes_timestamped_snapshot_to_base_dir() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let jar_bytes: &[u8] = b"jar-snapshot";
    let pom_bytes: &[u8] = b"pom-snapshot";
    let jar_id = store.put_bytes(jar_bytes).await.expect("jar");
    let pom_id = store.put_bytes(pom_bytes).await.expect("pom");

    let timestamped = "1.0-20240101.010101-7";
    let jar_key = ArtifactKey::new("com.example", "foo", timestamped, "jar", None);
    store.add_artifact(&jar_key, &jar_id).await.expect("add");
    let pom_key = ArtifactKey::new("com.example", "foo", timestamped, "pom", None);
    store.add_artifact(&pom_key, &pom_id).await.expect("add");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "foo".to_string(),
            version: timestamped.to_string(),
            snapshot_timestamp: Some("20240101.010101".to_string()),
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    fs::create_dir_all(&m2).expect("create repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let exporter = Exporter::new(options, &store);
    exporter.export_lock(&lock, None).await.expect("export");

    // Directory uses the base SNAPSHOT version.
    let base_dir = m2
        .join("com")
        .join("example")
        .join("foo")
        .join("1.0-SNAPSHOT");

    // Filename uses the timestamped form.
    let jar = base_dir.join("foo-1.0-20240101.010101-7.jar");
    let pom = base_dir.join("foo-1.0-20240101.010101-7.pom");
    assert!(jar.exists(), "expected jar at {:?}", jar);
    assert!(pom.exists(), "expected pom at {:?}", pom);
    assert_eq!(fs::read(&jar).expect("read jar"), jar_bytes);
    assert_eq!(fs::read(&pom).expect("read pom"), pom_bytes);

    // The OLD (buggy) layout must NOT exist.
    let buggy_dir = m2
        .join("com")
        .join("example")
        .join("foo")
        .join("1.0-20240101.010101-7");
    assert!(
        !buggy_dir.exists(),
        "timestamped directory must not be created at {:?}",
        buggy_dir
    );

    // Versioned maven-metadata-local.xml must be present and parseable.
    let versioned_meta = base_dir.join("maven-metadata-local.xml");
    let raw = fs::read_to_string(&versioned_meta).expect("read versioned meta");
    let parsed = parse_simple_xml(&raw);
    assert_eq!(
        parsed.get("groupId").map(String::as_str),
        Some("com.example")
    );
    assert_eq!(parsed.get("artifactId").map(String::as_str), Some("foo"));
    assert_eq!(
        parsed.get("version").map(String::as_str),
        Some("1.0-SNAPSHOT")
    );
    assert_eq!(
        parsed.get("timestamp").map(String::as_str),
        Some("20240101.010101")
    );
    assert_eq!(parsed.get("buildNumber").map(String::as_str), Some("7"));
    assert_eq!(parsed.get("localCopy").map(String::as_str), Some("true"));
    assert!(raw.contains("<value>1.0-20240101.010101-7</value>"));
    assert!(raw.contains("<extension>jar</extension>"));
    assert!(raw.contains("<extension>pom</extension>"));

    // Artifact-level metadata at <groupId>/<artifactId>/.
    let artifact_meta = m2
        .join("com")
        .join("example")
        .join("foo")
        .join("maven-metadata-local.xml");
    let raw = fs::read_to_string(&artifact_meta).expect("read artifact meta");
    assert!(raw.contains("<version>1.0-SNAPSHOT</version>"));
}

/// Mixing a release and a snapshot should generate the snapshot-style
/// metadata only for the snapshot. Releases must not get a
/// `maven-metadata-local.xml` inside their versioned directory.
#[tokio::test]
async fn export_lock_release_does_not_emit_snapshot_metadata() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let jar_id = store.put_bytes(b"jar").await.expect("jar");
    let pom_id = store.put_bytes(b"pom").await.expect("pom");

    let jar_key = ArtifactKey::new("com.example", "demo", "2.0.0", "jar", None);
    store.add_artifact(&jar_key, &jar_id).await.expect("add");
    let pom_key = ArtifactKey::new("com.example", "demo", "2.0.0", "pom", None);
    store.add_artifact(&pom_key, &pom_id).await.expect("add");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "2.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    fs::create_dir_all(&m2).expect("create");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let exporter = Exporter::new(options, &store);
    exporter.export_lock(&lock, None).await.expect("export");

    // No versioned maven-metadata-local.xml for releases.
    let versioned = m2
        .join("com")
        .join("example")
        .join("demo")
        .join("2.0.0")
        .join("maven-metadata-local.xml");
    assert!(
        !versioned.exists(),
        "releases must not get a versioned maven-metadata-local.xml"
    );

    // The artifact-level metadata still lists the release version.
    let artifact = m2
        .join("com")
        .join("example")
        .join("demo")
        .join("maven-metadata-local.xml");
    assert!(artifact.exists());
    let raw = fs::read_to_string(&artifact).expect("read");
    assert!(raw.contains("<version>2.0.0</version>"));
    assert!(raw.contains("<release>2.0.0</release>"));
}

/// Lockfile-only test: write a fixture that mirrors a `rv sync` output for
/// a snapshot, then call `Lockfile::read` + `export_lock` and verify the
/// resulting layout end-to-end. This exercises the read path of the
/// lockfile schema alongside the exporter.
#[tokio::test]
async fn lockfile_snapshot_round_trip_through_exporter() {
    use rv_config::Lockfile;

    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let jar_id = store.put_bytes(b"jar-bytes").await.expect("jar");
    let pom_id = store.put_bytes(b"pom-bytes").await.expect("pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "foo", "1.0-20240101.010101-7", "jar", None),
            &jar_id,
        )
        .await
        .expect("add jar");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "foo", "1.0-20240101.010101-7", "pom", None),
            &pom_id,
        )
        .await
        .expect("add pom");

    let lock_dir = tempdir().expect("lock dir");
    let lock_path = lock_dir.path().join("rv.lock");
    let toml_lock = format!(
        r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "foo"
version = "1.0-20240101.010101-7"
snapshot_timestamp = "20240101.010101"
packaging = "jar"
repo_url = "https://repo.example/maven2/"

[platforms.packages.checksum]
algorithm = "sha256"
digest = "{}"
"#,
        jar_id.as_str()
    );
    fs::write(&lock_path, toml_lock).expect("write lock");
    let lock = Lockfile::read(&lock_path).expect("read lockfile");

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    fs::create_dir_all(&m2).expect("create");
    let exporter = Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        },
        &store,
    );
    exporter.export_lock(&lock, None).await.expect("export");

    let jar = m2
        .join("com")
        .join("example")
        .join("foo")
        .join("1.0-SNAPSHOT")
        .join("foo-1.0-20240101.010101-7.jar");
    assert!(jar.exists());
}

/// Regression: a symlinked ancestor inside the m2 root that
/// points outside the m2 tree must be rejected by the containment
/// check. A purely lexical check would accept this and let the export
/// write into the symlink's real target.
#[cfg(unix)]
#[tokio::test]
async fn rejects_symlinked_ancestor_inside_m2_root() {
    use std::os::unix::fs::symlink;

    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let m2_dir = tempdir().expect("m2 dir");
    let outside_dir = tempdir().expect("outside dir");
    let m2_path = m2_dir.path().join("repository");
    fs::create_dir_all(&m2_path).expect("create m2");

    // The group_id resolves to com/example. Plant a symlink at
    // <m2>/com that points outside the m2 tree so a write at
    // <m2>/com/example/... would escape via the symlink.
    symlink(outside_dir.path(), m2_path.join("com")).expect("create symlink");

    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2_path.clone(),
    };
    let exporter = Exporter::new(options, &store);

    let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    let result = exporter.safe_artifact_path(&key, &pkg_from_key(&key));
    let err = result.expect_err("symlinked ancestor must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("path traversal") || msg.contains("Path traversal"),
        "expected path traversal error, got: {msg}"
    );
}

/// An m2 path whose ancestors don't yet exist must not be rejected by
/// the containment check (canonicalize would leave the root relative
/// while the dest was absolute, spuriously breaking lexical comparison).
#[tokio::test]
async fn accepts_nonexistent_m2_path() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let parent = tempdir().expect("parent");
    // Build/m2repo does NOT exist yet; the bug fired in exactly this
    // configuration when the path was passed in relative form.
    let m2 = parent.path().join("build").join("m2repo");
    assert!(!m2.exists());

    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let exporter = Exporter::new(options, &store);
    let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    let path = exporter
        .safe_artifact_path(&key, &pkg_from_key(&key))
        .expect("non-existent m2 path must succeed");
    // `safe_artifact_path` is now pure path math: it must NOT create
    // directories on the filesystem. The artifact-publish call site
    // does the `create_dir_all` only when it's about to write.
    assert!(
        !path.parent().expect("parent").exists(),
        "safe_artifact_path must not create directories"
    );
    // The returned path must end in the expected coordinate layout.
    assert!(path.ends_with("com/example/demo/1.0.0/demo-1.0.0.jar"));
}

/// Same regression but with a relative path, which is the form the
/// CLI actually passes through. We resolve it against the current
/// working directory rather than mutating cwd (which would race with
/// other parallel tests).
#[tokio::test]
async fn accepts_nonexistent_relative_m2_path_via_canonicalize_helper() {
    // Pick a name that's unlikely to exist beneath the current cwd.
    let relative = PathBuf::from("rv-m2-export-l2-nonexistent-xyz").join("repository");
    assert!(!relative.exists());
    let resolved = rv_config::canonicalize_existing_prefix(&relative).expect("resolve");
    // The helper must produce an absolute path even when nothing along
    // the chain exists yet.
    assert!(resolved.is_absolute(), "got: {:?}", resolved);
    // And the original tail components must still be present at the
    // end of the resolved path.
    assert!(resolved.ends_with(&relative), "got: {:?}", resolved);
}

/// Regression: if the JAR is already in place (e.g. a prior run
/// was Ctrl+C-killed between the artifact rename and the sidecar writes)
/// the export must still leave both `.sha1` and `.sha256` sidecars on
/// disk with the correct digests.
#[tokio::test]
async fn export_repairs_missing_sidecars_on_identical_skip() {
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let jar_bytes: &[u8] = b"jar-payload";
    let pom_bytes: &[u8] = b"pom-payload";
    let jar_id = store.put_bytes(jar_bytes).await.expect("jar");
    let pom_id = store.put_bytes(pom_bytes).await.expect("pom");

    let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    store
        .add_artifact(&jar_key, &jar_id)
        .await
        .expect("add jar");
    let pom_key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
    store
        .add_artifact(&pom_key, &pom_id)
        .await
        .expect("add pom");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };

    let jar_path = m2
        .join("com")
        .join("example")
        .join("demo")
        .join("1.0.0")
        .join("demo-1.0.0.jar");
    let sha1_path = jar_path.with_extension("jar.sha1");
    let sha256_path = jar_path.with_extension("jar.sha256");

    // Pre-populate the destination JAR (and its POM) so the exporter
    // takes the identical-skip path, but DELETE the sidecars to mimic
    // an interrupted previous run.
    fs::create_dir_all(jar_path.parent().unwrap()).expect("mkdir");
    fs::write(&jar_path, jar_bytes).expect("seed jar");
    let pom_path = jar_path.with_extension("pom");
    fs::write(&pom_path, pom_bytes).expect("seed pom");
    assert!(!sha1_path.exists());
    assert!(!sha256_path.exists());

    let exporter = Exporter::new(options, &store);
    let stats = exporter.export_lock(&lock, None).await.expect("export");
    // Both artifacts are reported as skipped, but the sidecars must
    // still be on disk now.
    assert_eq!(stats.skipped_count, 2);
    assert_eq!(stats.exported_count, 0);

    let sha1_content = fs::read_to_string(&sha1_path).expect("read sha1 sidecar");
    let sha256_content = fs::read_to_string(&sha256_path).expect("read sha256 sidecar");

    let mut hasher = Sha1::new();
    hasher.update(jar_bytes);
    let expected_sha1 = hex::encode(hasher.finalize());
    let mut hasher = Sha256::new();
    hasher.update(jar_bytes);
    let expected_sha256 = hex::encode(hasher.finalize());

    assert_eq!(sha1_content.trim(), expected_sha1);
    assert_eq!(sha256_content.trim(), expected_sha256);

    // A stale sidecar should also be repaired. Corrupt one and re-run.
    fs::write(&sha1_path, "deadbeef").expect("clobber sha1");
    let _ = exporter.export_lock(&lock, None).await.expect("export 2");
    let repaired = fs::read_to_string(&sha1_path).expect("read repaired sha1");
    assert_eq!(repaired.trim(), expected_sha1);
}

/// exporting an artifact must drop a `_remote.repositories` marker
/// next to it listing each materialized filename against its repository
/// id, so strict offline `mvn -o` treats the files as resolvable.
#[tokio::test]
async fn export_writes_remote_repositories_marker() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let jar_id = store.put_bytes(b"jar").await.expect("jar");
    // A real POM (no parent) so the parent walk is exercised and yields
    // nothing extra.
    let pom_xml = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>demo</artifactId>\
<version>1.0.0</version></project>";
    let pom_id = store.put_bytes(pom_xml).await.expect("pom");

    let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    store.add_artifact(&jar_key, &jar_id).await.expect("jar");
    let pom_key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
    store.add_artifact(&pom_key, &pom_id).await.expect("pom");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    // No repo-id map supplied: the URL falls back to `central`, the id
    // Maven itself records for Central.
    let exporter = Exporter::new(options, &store);
    exporter.export_lock(&lock, None).await.expect("export");

    let dir = m2.join("com").join("example").join("demo").join("1.0.0");
    let marker = fs::read_to_string(dir.join("_remote.repositories")).expect("read marker");
    assert!(
        marker.contains(
            "#NOTE: This is a Maven Resolver internal implementation file, \
its format can be changed without prior notice."
        ),
        "marker must carry Maven's NOTE header, got:\n{marker}"
    );
    assert!(
        marker.contains("demo-1.0.0.jar>central="),
        "jar must be tracked against central, got:\n{marker}"
    );
    assert!(
        marker.contains("demo-1.0.0.pom>central="),
        "pom must be tracked against central, got:\n{marker}"
    );
}

/// The repo-id map must override the `central` default when the lockfile
/// repo_url maps to a configured repository.
#[tokio::test]
async fn export_marker_uses_configured_repo_id() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let jar_id = store.put_bytes(b"jar").await.expect("jar");
    let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    store.add_artifact(&jar_key, &jar_id).await.expect("jar");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://nexus.corp.example/repo/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let mut repo_ids = HashMap::new();
    repo_ids.insert(
        rv_repo::normalize_repo_url("https://nexus.corp.example/repo/"),
        "corp".to_string(),
    );
    let exporter = Exporter::new(options, &store).with_repo_ids(repo_ids);
    exporter.export_lock(&lock, None).await.expect("export");

    let dir = m2.join("com").join("example").join("demo").join("1.0.0");
    let marker = fs::read_to_string(dir.join("_remote.repositories")).expect("read marker");
    assert!(
        marker.contains("demo-1.0.0.jar>corp="),
        "jar must be tracked against the configured id, got:\n{marker}"
    );
}

/// copied artifacts must be writable-by-owner (0644), not the
/// CAS blob's 0444, so strict offline Maven (and in-place rewriters) can
/// operate on the local-repo entry.
#[cfg(unix)]
#[tokio::test]
async fn exported_artifacts_are_owner_writable() {
    use std::os::unix::fs::PermissionsExt;

    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let jar_id = store.put_bytes(b"jar").await.expect("jar");
    let pom_id = store.put_bytes(b"pom").await.expect("pom");
    let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    store.add_artifact(&jar_key, &jar_id).await.expect("jar");
    let pom_key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
    store.add_artifact(&pom_key, &pom_id).await.expect("pom");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let exporter = Exporter::new(options, &store);
    exporter.export_lock(&lock, None).await.expect("export");

    let dir = m2.join("com").join("example").join("demo").join("1.0.0");
    for name in ["demo-1.0.0.jar", "demo-1.0.0.pom"] {
        let mode = fs::metadata(dir.join(name))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o644,
            "{name} must be 0644 (owner-writable, world-readable), got {mode:o}"
        );
    }
}

/// the `<parent>` ancestry of an exported POM must be materialized
/// so `mvn -o` does not fail with "Non-resolvable parent POM". Parent POMs
/// are not lockfile packages, so the exporter discovers them by parsing
/// the child POM and looking the parent up in the store.
#[tokio::test]
async fn export_materializes_parent_pom_chain() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let jar_id = store.put_bytes(b"jar").await.expect("jar");
    // Child POM references a parent; parent POM references a grandparent.
    let child_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>com.example</groupId><artifactId>parent</artifactId>\
<version>2.0.0</version></parent>\
<artifactId>demo</artifactId></project>";
    let parent_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>com.example</groupId><artifactId>grandparent</artifactId>\
<version>3.0.0</version></parent>\
<groupId>com.example</groupId><artifactId>parent</artifactId>\
<version>2.0.0</version><packaging>pom</packaging></project>";
    let grandparent_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>grandparent</artifactId>\
<version>3.0.0</version><packaging>pom</packaging></project>";

    let child_pom_id = store.put_bytes(child_pom).await.expect("child pom");
    let parent_pom_id = store.put_bytes(parent_pom).await.expect("parent pom");
    let grandparent_pom_id = store.put_bytes(grandparent_pom).await.expect("gp pom");

    store
        .add_artifact(
            &ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None),
            &jar_id,
        )
        .await
        .expect("jar");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None),
            &child_pom_id,
        )
        .await
        .expect("child");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "parent", "2.0.0", "pom", None),
            &parent_pom_id,
        )
        .await
        .expect("parent");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "grandparent", "3.0.0", "pom", None),
            &grandparent_pom_id,
        )
        .await
        .expect("grandparent");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let exporter = Exporter::new(options, &store);
    exporter.export_lock(&lock, None).await.expect("export");

    // The whole ancestry must be on disk.
    let parent = m2
        .join("com")
        .join("example")
        .join("parent")
        .join("2.0.0")
        .join("parent-2.0.0.pom");
    let grandparent = m2
        .join("com")
        .join("example")
        .join("grandparent")
        .join("3.0.0")
        .join("grandparent-3.0.0.pom");
    assert!(parent.exists(), "parent POM must be exported at {parent:?}");
    assert!(
        grandparent.exists(),
        "grandparent POM must be exported at {grandparent:?}"
    );
    assert_eq!(fs::read(&parent).expect("read parent"), parent_pom);
    assert_eq!(
        fs::read(&grandparent).expect("read grandparent"),
        grandparent_pom
    );

    // Parent dirs must also carry their own `_remote.repositories` markers.
    let parent_marker = m2
        .join("com")
        .join("example")
        .join("parent")
        .join("2.0.0")
        .join("_remote.repositories");
    let body = fs::read_to_string(&parent_marker).expect("parent marker");
    assert!(body.contains("parent-2.0.0.pom>central="));
}

/// An import-scoped BOM referenced by a transitive dependency, whose version
/// is a `${property}` defined only in that dependency's `<parent>`, must
/// still be exported.
///
/// `read_support_refs` interpolates an import BOM's version against the child
/// POM's own `<properties>` only, so a parent-defined version stays `${...}`
/// and gets skipped. But `rv sync` already resolved the BOM and recorded its
/// coordinate in the support-POM provenance, so the exporter seeds the
/// closure from that provenance and materializes the BOM. This is the
/// spring-petclinic shape: `thymeleaf-spring6` imports `spring-framework-bom`,
/// whose absence breaks offline `mvn -o`.
#[tokio::test]
async fn transitive_import_bom_with_parent_defined_version_is_exported() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let jar_id = store.put_bytes(b"mid-jar").await.expect("jar");
    // `mid` is a transitive dep. Its POM inherits `the-bom.version` from
    // `mid-parent` and imports `the-bom` with that (parent-defined)
    // property, so the raw child POM alone cannot resolve the coordinate.
    let mid_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>com.example</groupId><artifactId>mid-parent</artifactId>\
<version>1.0</version></parent>\
<artifactId>mid</artifactId>\
<dependencyManagement><dependencies>\
<dependency><groupId>com.example</groupId><artifactId>the-bom</artifactId>\
<version>${the-bom.version}</version><type>pom</type><scope>import</scope></dependency>\
</dependencies></dependencyManagement></project>";
    let mid_parent_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>mid-parent</artifactId>\
<version>1.0</version><packaging>pom</packaging>\
<properties><the-bom.version>2.0</the-bom.version></properties></project>";
    let the_bom_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>the-bom</artifactId>\
<version>2.0</version><packaging>pom</packaging></project>";

    let mid_pom_id = store.put_bytes(mid_pom).await.expect("mid pom");
    let mid_parent_pom_id = store.put_bytes(mid_parent_pom).await.expect("parent pom");
    let the_bom_pom_id = store.put_bytes(the_bom_pom).await.expect("bom pom");

    store
        .add_artifact(
            &ArtifactKey::new("com.example", "mid", "1.0", "jar", None),
            &jar_id,
        )
        .await
        .expect("jar");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "mid", "1.0", "pom", None),
            &mid_pom_id,
        )
        .await
        .expect("mid pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "mid-parent", "1.0", "pom", None),
            &mid_parent_pom_id,
        )
        .await
        .expect("parent pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "the-bom", "2.0", "pom", None),
            &the_bom_pom_id,
        )
        .await
        .expect("bom pom");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "mid".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    // Provenance `rv sync` records for the support POMs it fetched during
    // resolution (parent + import BOM), keyed on bare `g:a:v`.
    let mut support = HashMap::new();
    support.insert(
        "com.example:mid-parent:1.0".to_string(),
        unpinned_support("central"),
    );
    support.insert(
        "com.example:the-bom:2.0".to_string(),
        unpinned_support("central"),
    );

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let exporter = Exporter::new(options, &store).with_support_poms(support);
    exporter.export_lock(&lock, None).await.expect("export");

    // The import BOM must be materialized even though its version was a
    // parent-defined property the child POM alone could not resolve.
    let bom = m2
        .join("com")
        .join("example")
        .join("the-bom")
        .join("2.0")
        .join("the-bom-2.0.pom");
    assert!(
        bom.exists(),
        "transitive parent-versioned import BOM must be exported at {bom:?}"
    );
    assert_eq!(fs::read(&bom).expect("read bom"), the_bom_pom);

    // Its `_remote.repositories` marker must carry the recorded source id.
    let bom_marker = m2
        .join("com")
        .join("example")
        .join("the-bom")
        .join("2.0")
        .join("_remote.repositories");
    let body = fs::read_to_string(&bom_marker).expect("bom marker");
    assert!(
        body.contains("the-bom-2.0.pom>central="),
        "import BOM marker must use its recorded source repo id, got: {body}"
    );

    // The parent is still walked normally (read from the child POM).
    let parent = m2
        .join("com")
        .join("example")
        .join("mid-parent")
        .join("1.0")
        .join("mid-parent-1.0.pom");
    assert!(parent.exists(), "parent POM must be exported at {parent:?}");
}

/// A parent named by a POM but absent from the store must NOT fail the
/// export; it's logged and skipped, and the rest still ships.
#[tokio::test]
async fn missing_parent_pom_does_not_fail_export() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let jar_id = store.put_bytes(b"jar").await.expect("jar");
    let child_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>com.example</groupId><artifactId>absent</artifactId>\
<version>9.9.9</version></parent>\
<artifactId>demo</artifactId></project>";
    let child_pom_id = store.put_bytes(child_pom).await.expect("child pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None),
            &jar_id,
        )
        .await
        .expect("jar");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None),
            &child_pom_id,
        )
        .await
        .expect("child");

    let platform = Platform::new("linux", "x86_64").expect("platform");
    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        platform,
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let exporter = Exporter::new(options, &store);
    // The absent parent is skipped; the child jar + pom still export.
    let stats = exporter
        .export_lock(&lock, None)
        .await
        .expect("export must succeed");
    assert_eq!(stats.exported_count, 2);
    let jar = m2
        .join("com")
        .join("example")
        .join("demo")
        .join("1.0.0")
        .join("demo-1.0.0.jar");
    assert!(jar.exists());
}

#[test]
fn support_pom_node_limit_override_ignores_unusable_values() {
    assert_eq!(
        super::parse_max_support_pom_nodes(None),
        super::MAX_SUPPORT_POM_NODES
    );
    assert_eq!(super::parse_max_support_pom_nodes(Some(" 64 ")), 64);
    // A zero or unparseable override must not shrink the closure.
    assert_eq!(
        super::parse_max_support_pom_nodes(Some("0")),
        super::MAX_SUPPORT_POM_NODES
    );
    assert_eq!(
        super::parse_max_support_pom_nodes(Some("lots")),
        super::MAX_SUPPORT_POM_NODES
    );
}

/// Render import-scoped `<dependency>` entries for `com.example:bomN:1.0`.
fn import_block(indices: impl Iterator<Item = usize>) -> String {
    indices
        .map(|i| {
            format!(
                "<dependency><groupId>com.example</groupId><artifactId>bom{i}</artifactId>\
<version>1.0</version><type>pom</type><scope>import</scope></dependency>"
            )
        })
        .collect()
}

/// Store `com.example:bomN:1.0` POMs, each importing the BOMs named by
/// `imports_for`, so a closure walk can be given an arbitrary shape.
async fn store_boms(
    store: &Store,
    count: usize,
    imports_for: impl Fn(usize) -> String,
) -> Vec<Vec<u8>> {
    let mut bodies = Vec::new();
    for i in 0..count {
        let body = format!(
            "<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>bom{i}</artifactId><version>1.0</version>\
<packaging>pom</packaging>\
<dependencyManagement><dependencies>{}</dependencies></dependencyManagement></project>",
            imports_for(i)
        );
        let id = store.put_bytes(body.as_bytes()).await.expect("bom pom");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", format!("bom{i}"), "1.0", "pom", None),
                &id,
            )
            .await
            .expect("index bom pom");
        bodies.push(body.into_bytes());
    }
    bodies
}

/// Store `com.example:app:1.0` (jar + POM) where the POM imports every BOM
/// in `0..bom_count`, and return the matching single-package lockfile.
async fn app_lock_importing_boms(store: &Store, bom_count: usize) -> Lockfile {
    let jar_id = store.put_bytes(b"app-jar").await.expect("jar");
    let app_pom = format!(
        "<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>\
<dependencyManagement><dependencies>{}</dependencies></dependencyManagement></project>",
        import_block(0..bom_count)
    );
    let app_pom_id = store.put_bytes(app_pom.as_bytes()).await.expect("app pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "app", "1.0", "jar", None),
            &jar_id,
        )
        .await
        .expect("index jar");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "app", "1.0", "pom", None),
            &app_pom_id,
        )
        .await
        .expect("index app pom");

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        Platform::new("linux", "x86_64").expect("platform"),
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "app".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];
    lock
}

async fn export_with_limit(
    store: &Store,
    lock: &Lockfile,
    m2: &std::path::Path,
    limit: usize,
) -> super::Result<super::ExportStats> {
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.to_path_buf(),
    };
    Exporter::new(options, store)
        .with_max_support_pom_nodes(limit)
        .export_lock(lock, None)
        .await
}

/// A breadth-heavy support closure that exceeds the unique-node limit must
/// fail with an actionable error instead of returning success on a
/// truncated closure. A short export writes a `~/.m2` that looks complete
/// and then breaks `mvn -o` on a parent or BOM that never got written,
/// with nothing pointing back at the export that dropped it.
#[tokio::test]
async fn support_closure_over_node_limit_errors_instead_of_truncating() {
    const BOMS: usize = 12;
    const LIMIT: usize = 8;

    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    store_boms(&store, BOMS, |_| String::new()).await;
    let lock = app_lock_importing_boms(&store, BOMS).await;

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let err = export_with_limit(&store, &lock, &m2, LIMIT)
        .await
        .expect_err("an over-limit closure must not report success");

    assert!(
        matches!(err, ExportError::SupportClosureTooLarge { .. }),
        "expected SupportClosureTooLarge, got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains(&LIMIT.to_string()) && msg.contains(super::MAX_SUPPORT_POM_NODES_ENV),
        "error must name the limit and how to raise it, got: {msg}"
    );

    // The failure happens while queueing, before anything is materialized,
    // so no half-populated repository is left behind.
    assert!(
        !m2.join("com/example/app/1.0/app-1.0.jar").exists(),
        "a failed export must not leave artifacts behind"
    );
}

/// A support POM the lockfile's recorded provenance names but the store
/// does not hold is the same incomplete-repository condition as an
/// over-limit closure: `rv sync` reported it fetched that parent/BOM, so
/// its absence means the content-store write was lost. Exiting 0 here ships
/// a `~/.m2` that fails `mvn -o` with a non-resolvable parent/import POM,
/// so it must be a typed error raised before anything is materialized.
#[tokio::test]
async fn missing_recorded_support_pom_errors_before_writing() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    // No BOMs stored and none imported: the only support-POM coordinate in
    // play is the one the provenance names, which was never persisted.
    let lock = app_lock_importing_boms(&store, 0).await;

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let mut support = HashMap::new();
    support.insert(
        "com.example:lost-parent:4.0".to_string(),
        unpinned_support("central"),
    );

    let err = Exporter::new(options, &store)
        .with_support_poms(support)
        .export_lock(&lock, None)
        .await
        .expect_err("a recorded support POM missing from the store must not report success");

    match &err {
        ExportError::MissingSupportPom { coordinate, .. } => {
            assert_eq!(coordinate, "com.example:lost-parent:4.0");
        }
        other => panic!("expected MissingSupportPom, got {other:?}"),
    }
    let msg = err.to_string();
    assert!(
        msg.contains("com.example:lost-parent:4.0") && msg.contains("rv sync"),
        "error must name the coordinate and the repair, got: {msg}"
    );
    assert!(
        msg.contains("--frozen"),
        "the hint must steer away from a frozen sync, which does not repopulate, got: {msg}"
    );

    assert!(
        !m2.join("com/example/app/1.0/app-1.0.jar").exists(),
        "a failed export must not leave artifacts behind"
    );
    assert!(
        !m2.exists(),
        "nothing at all should be materialized, found {m2:?}"
    );
}

/// Two sets of bytes under one `(g, a, v, pom)` coordinate: the ones this
/// lockfile was resolved against, and the ones a later sync of a different
/// project (or a sibling reactor module) wrote afterwards. The store's
/// coordinate index keeps only the last writer, so an index lookup answers
/// with the replacement.
///
/// The recorded digest is what makes the difference: pinned, the export
/// ships the bytes the lockfile names; unpinned (an older lockfile), it
/// ships whatever the index now points at.
#[tokio::test]
async fn pinned_support_pom_beats_a_repointed_coordinate_index() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let lock = app_lock_importing_boms(&store, 0).await;

    let ours = b"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>theparent</artifactId><version>2.0</version></project>";
    let theirs = b"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>theparent</artifactId><version>2.0</version><packaging>pom</packaging></project>";
    let parent_key = ArtifactKey::new("com.example", "theparent", "2.0", "pom", None);
    for bytes in [ours.as_slice(), theirs.as_slice()] {
        let blob = store.put_bytes(bytes).await.expect("put parent pom");
        store
            .add_artifact(&parent_key, &blob)
            .await
            .expect("index parent pom");
    }

    let exported_pom = |m2: &std::path::Path| {
        fs::read(m2.join("com/example/theparent/2.0/theparent-2.0.pom")).expect("parent pom")
    };
    let export_to = |m2: PathBuf, pin: SupportPomPin| {
        let store = &store;
        let lock = &lock;
        async move {
            let mut support = HashMap::new();
            support.insert("com.example:theparent:2.0".to_string(), pin);
            Exporter::new(
                ExportOptions {
                    dry_run: false,
                    overwrite: false,
                    link_strategy: LinkStrategy::Copy,
                    m2_path: m2,
                },
                store,
            )
            .with_support_poms(support)
            .export_lock(lock, None)
            .await
            .expect("export");
        }
    };

    let pinned_dir = tempdir().expect("m2 dir");
    let pinned_m2 = pinned_dir.path().join("repository");
    export_to(pinned_m2.clone(), pinned_support("central", ours)).await;
    assert_eq!(
        exported_pom(&pinned_m2),
        ours,
        "a pinned support POM must be exported from the recorded bytes, \
             not from whatever the coordinate index points at now"
    );

    let unpinned_dir = tempdir().expect("m2 dir");
    let unpinned_m2 = unpinned_dir.path().join("repository");
    export_to(unpinned_m2.clone(), unpinned_support("central")).await;
    assert_eq!(
        exported_pom(&unpinned_m2),
        theirs,
        "without a digest the export still follows the index, which is the \
             pre-schema-4 behaviour a lockfile without the field keeps"
    );
}

/// A pinned support POM whose bytes are gone (pruned, or never written on
/// this machine) must fail typed instead of falling back to the coordinate
/// index: the index answer is exactly the substituted POM the pin exists to
/// refuse.
#[tokio::test]
async fn missing_pinned_support_pom_errors_before_writing() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let lock = app_lock_importing_boms(&store, 0).await;

    let substitute = b"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>theparent</artifactId><version>2.0</version></project>";
    let blob = store.put_bytes(substitute).await.expect("put");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "theparent", "2.0", "pom", None),
            &blob,
        )
        .await
        .expect("index");

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let mut support = HashMap::new();
    support.insert(
        "com.example:theparent:2.0".to_string(),
        pinned_support("central", b"the bytes rv sync recorded"),
    );

    let err = Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        },
        &store,
    )
    .with_support_poms(support)
    .export_lock(&lock, None)
    .await
    .expect_err("pinned bytes missing from the store must fail the export");

    match &err {
        ExportError::MissingPinnedPom {
            coordinate, digest, ..
        } => {
            assert_eq!(coordinate, "com.example:theparent:2.0");
            assert_eq!(
                digest,
                &BlobId::from_bytes(b"the bytes rv sync recorded").to_string()
            );
        }
        other => panic!("expected MissingPinnedPom, got {other:?}"),
    }
    let msg = err.to_string();
    assert!(
        msg.contains("com.example:theparent:2.0") && msg.contains("rv sync"),
        "error must name the coordinate and the repair, got: {msg}"
    );
    assert!(!m2.exists(), "nothing should be materialized, found {m2:?}");
}

/// The same guarantee for a companion POM, which is pinned by its artifact
/// row's `pom_sha256` rather than by the support-POM provenance.
#[tokio::test]
async fn pinned_companion_pom_beats_a_repointed_coordinate_index() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let jar = store.put_bytes(b"app-jar").await.expect("jar");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "app", "1.0", "jar", None),
            &jar,
        )
        .await
        .expect("index jar");

    let ours = b"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>app</artifactId><version>1.0</version></project>";
    let theirs = b"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>app</artifactId><version>1.0</version><name>replaced</name></project>";
    let pom_key = ArtifactKey::new("com.example", "app", "1.0", "pom", None);
    for bytes in [ours.as_slice(), theirs.as_slice()] {
        let blob = store.put_bytes(bytes).await.expect("put app pom");
        store
            .add_artifact(&pom_key, &blob)
            .await
            .expect("index app pom");
    }

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        Platform::new("linux", "x86_64").expect("platform"),
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "app".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let mut digests = HashMap::new();
    digests.insert(
        (
            "com.example".to_string(),
            "app".to_string(),
            "1.0".to_string(),
        ),
        BlobId::from_bytes(ours),
    );
    Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        },
        &store,
    )
    .with_pom_digests(digests)
    .export_lock(&lock, None)
    .await
    .expect("export");

    assert_eq!(
        fs::read(m2.join("com/example/app/1.0/app-1.0.pom")).expect("app pom"),
        ours,
        "the companion POM must come from the digest the artifact row pins"
    );
}

/// A `packaging = "pom"` row is exported as its own primary artifact, so
/// its payload pin and its `pom_sha256` name one file. A lockfile carrying
/// two digests for it would have the export write the payload while
/// claiming the other digest was resolved; export must refuse instead of
/// picking the one it happens to read first.
#[tokio::test]
async fn pom_packaged_row_with_two_pins_fails_before_writing() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let payload = b"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>bom</artifactId><version>1.0</version><packaging>pom</packaging></project>";
    let blob = store.put_bytes(payload).await.expect("put bom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "bom", "1.0", "pom", None),
            &blob,
        )
        .await
        .expect("index bom");

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        Platform::new("linux", "x86_64").expect("platform"),
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "bom".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "pom".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", blob.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let mut digests = HashMap::new();
    digests.insert(
        (
            "com.example".to_string(),
            "bom".to_string(),
            "1.0".to_string(),
        ),
        BlobId::from_bytes(b"a different pom entirely"),
    );

    let err = Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        },
        &store,
    )
    .with_pom_digests(digests)
    .export_lock(&lock, None)
    .await
    .expect_err("a pom package cannot pin two different files");

    assert!(
        matches!(&err, ExportError::ConflictingPomPackagedPin { coordinate, .. }
                if coordinate == "com.example:bom:1.0"),
        "expected ConflictingPomPackagedPin, got {err:?}"
    );
    assert!(!m2.exists(), "nothing should be materialized, found {m2:?}");
}

/// Negative control: one digest in both fields is the healthy shape and
/// exports the pom-packaged artifact normally.
#[tokio::test]
async fn pom_packaged_row_with_agreeing_pins_exports() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let payload = b"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>bom</artifactId><version>1.0</version><packaging>pom</packaging></project>";
    let blob = store.put_bytes(payload).await.expect("put bom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "bom", "1.0", "pom", None),
            &blob,
        )
        .await
        .expect("index bom");

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        Platform::new("linux", "x86_64").expect("platform"),
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "bom".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "pom".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", blob.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let mut digests = HashMap::new();
    digests.insert(
        (
            "com.example".to_string(),
            "bom".to_string(),
            "1.0".to_string(),
        ),
        blob.clone(),
    );

    Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        },
        &store,
    )
    .with_pom_digests(digests)
    .export_lock(&lock, None)
    .await
    .expect("export");

    assert_eq!(
        fs::read(m2.join("com/example/bom/1.0/bom-1.0.pom")).expect("bom pom"),
        payload,
        "the pom-packaged artifact must be materialized from its own bytes"
    );
}

/// A companion POM pinned to bytes the store no longer holds is fatal, for
/// the same reason the support-POM case is: the index would answer with the
/// substitute, and shipping it silently is the bug.
#[tokio::test]
async fn missing_pinned_companion_pom_errors_before_writing() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let lock = app_lock_importing_boms(&store, 0).await;

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let mut digests = HashMap::new();
    digests.insert(
        (
            "com.example".to_string(),
            "app".to_string(),
            "1.0".to_string(),
        ),
        BlobId::from_bytes(b"the app pom rv sync recorded"),
    );

    let err = Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        },
        &store,
    )
    .with_pom_digests(digests)
    .export_lock(&lock, None)
    .await
    .expect_err("pinned companion bytes missing from the store must fail the export");

    assert!(
        matches!(&err, ExportError::MissingPinnedPom { coordinate, .. }
                if coordinate == "com.example:app:1.0"),
        "expected MissingPinnedPom for the companion POM, got {err:?}"
    );
    assert!(!m2.exists(), "nothing should be materialized, found {m2:?}");
}

/// The corollary that keeps the new error narrow: a support-POM coordinate
/// only *inferred* from POM text is still best-effort. `read_support_refs`
/// names imports and parents that resolution may never have fetched (a
/// profile that was not active, say), and failing on those would break
/// exports whose offline build is fine.
#[tokio::test]
async fn missing_inferred_support_pom_still_warns_and_exports() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    // The app POM imports bom0, but bom0 was never stored and no
    // provenance vouches for it.
    let lock = app_lock_importing_boms(&store, 1).await;

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let stats = Exporter::new(options, &store)
        .export_lock(&lock, None)
        .await
        .expect("an inferred-only miss must stay best-effort");

    assert_eq!(stats.exported_count, 2, "app jar + app pom, got {stats:?}");
    assert!(m2.join("com/example/app/1.0/app-1.0.jar").exists());
}

/// A support POM served by a repository that declares no `<id>` is recorded
/// with an empty id, which has to mean two things at once: the coordinate
/// counts as provenance (its absence from the store fails the export, the
/// same as any other recorded support POM), and there is no repository id
/// to name, so the POM gets no `_remote.repositories` marker rather than a
/// fabricated `central` one.
#[tokio::test]
async fn idless_repo_support_pom_is_recorded_but_gets_no_marker() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let child_pom: &[u8] = br#"<project><modelVersion>4.0.0</modelVersion>
            <parent><groupId>com.example</groupId><artifactId>theparent</artifactId><version>2.0</version></parent>
            <artifactId>child</artifactId></project>"#;
    let parent_pom: &[u8] = br#"<project><modelVersion>4.0.0</modelVersion>
            <groupId>com.example</groupId><artifactId>theparent</artifactId><version>2.0</version><packaging>pom</packaging></project>"#;
    let jar_id = store.put_bytes(b"child-jar").await.expect("jar");
    let child_pom_id = store.put_bytes(child_pom).await.expect("child pom");
    let parent_pom_id = store.put_bytes(parent_pom).await.expect("parent pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "child", "1.0", "jar", None),
            &jar_id,
        )
        .await
        .unwrap();
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "child", "1.0", "pom", None),
            &child_pom_id,
        )
        .await
        .unwrap();
    let parent_key = ArtifactKey::new("com.example", "theparent", "2.0", "pom", None);
    store
        .add_artifact(&parent_key, &parent_pom_id)
        .await
        .unwrap();

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        Platform::new("linux", "x86_64").unwrap(),
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "child".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo-a.example/".to_string(),
            checksum: Some(Checksum::new("sha256", jar_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        },
    )];

    let mut repo_ids = HashMap::new();
    repo_ids.insert("https://repo-a.example/".to_string(), "repo-a".to_string());
    // The parent came from an id-less repository: coordinate recorded,
    // empty id.
    let mut support = HashMap::new();
    support.insert(
        "com.example:theparent:2.0".to_string(),
        unpinned_support(""),
    );

    let m2_dir = tempdir().unwrap();
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    Exporter::new(options, &store)
        .with_repo_ids(repo_ids.clone())
        .with_support_poms(support.clone())
        .export_lock(&lock, None)
        .await
        .expect("export");

    assert!(
        m2.join("com/example/theparent/2.0/theparent-2.0.pom")
            .exists(),
        "the support POM itself must still be materialized"
    );
    assert!(
        !m2.join("com/example/theparent/2.0/_remote.repositories")
            .exists(),
        "an id-less repository has no id to write into a marker"
    );
    let child_marker = fs::read_to_string(m2.join("com/example/child/1.0/_remote.repositories"))
        .expect("child marker");
    assert!(
        child_marker.contains(">repo-a="),
        "packages with a known repo id keep their markers, got: {child_marker}"
    );

    // Same provenance, but the POM is gone from the store: the empty id
    // must not exempt the coordinate from the completeness check.
    store
        .remove_artifact(&parent_key)
        .await
        .expect("drop the support POM");
    let second_m2_dir = tempdir().unwrap();
    let second_m2 = second_m2_dir.path().join("repository");
    let err = Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: second_m2.clone(),
        },
        &store,
    )
    .with_repo_ids(repo_ids)
    .with_support_poms(support)
    .export_lock(&lock, None)
    .await
    .expect_err("a recorded id-less support POM missing from the store must fail the export");

    match &err {
        ExportError::MissingSupportPom { coordinate, .. } => {
            assert_eq!(coordinate, "com.example:theparent:2.0");
        }
        other => panic!("expected MissingSupportPom, got {other:?}"),
    }
    assert!(
        !second_m2.exists(),
        "the failed export must not materialize anything"
    );
}

/// The budget counts unique nodes, not worklist entries.
///
/// `bom0..bom3` cross-reference each other and all name `bom4`, so the walk
/// pops eight re-references before it ever reaches `bom4`: five unique
/// nodes out of twenty references. A budget of five must export all five.
/// Counting references instead runs out mid-traversal, and which node falls
/// off the end is decided by how often the others happened to be named.
#[tokio::test]
async fn support_closure_budget_counts_unique_nodes_not_references() {
    // bom0..bom(SEEDED-1) are seeded from the app POM; bom(BOMS-1) is only
    // reachable through them, so it is the last unique node reached.
    const BOMS: usize = 5;
    const SEEDED: usize = 4;

    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let bodies = store_boms(&store, BOMS, |i| {
        if i == BOMS - 1 {
            String::new()
        } else {
            import_block((0..BOMS).filter(move |j| *j != i))
        }
    })
    .await;
    let lock = app_lock_importing_boms(&store, SEEDED).await;

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    export_with_limit(&store, &lock, &m2, BOMS)
        .await
        .expect("a closure of exactly BOMS unique nodes must fit the budget");
    for (i, body) in bodies.iter().enumerate() {
        let pom = m2.join(format!("com/example/bom{i}/1.0/bom{i}-1.0.pom"));
        assert!(pom.exists(), "bom{i} must be exported at {pom:?}");
        assert_eq!(&fs::read(&pom).expect("read bom"), body);
    }

    let tight_dir = tempdir().expect("m2 dir");
    let err = export_with_limit(
        &store,
        &lock,
        &tight_dir.path().join("repository"),
        BOMS - 1,
    )
    .await
    .expect_err("one node over budget must fail");
    assert!(
        matches!(err, ExportError::SupportClosureTooLarge { .. }),
        "expected SupportClosureTooLarge, got {err:?}"
    );
}

/// A POM that is both support metadata and an explicit lockfile package
/// must be exported exactly once. Two units for one coordinate resolve to
/// the same destination, so they used to race through `buffer_unordered`:
/// the file written twice, the stats doubled, and the
/// `_remote.repositories` marker decided by whichever finished last. The
/// surviving unit must carry the recorded support-POM repository id, not
/// the one derived from the lockfile `repo_url`.
#[tokio::test]
async fn dual_role_pom_exports_once_with_recorded_repo_id() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let the_bom_pom: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>the-bom</artifactId><version>2.0</version>\
<packaging>pom</packaging></project>";
    // The consumer imports the same BOM that the lockfile also pins
    // directly, so the coordinate is reached twice: once by the closure
    // walk and once by the package loop.
    let consumer_pom: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>consumer</artifactId><version>1.0</version>\
<dependencyManagement><dependencies>\
<dependency><groupId>com.example</groupId><artifactId>the-bom</artifactId>\
<version>2.0</version><type>pom</type><scope>import</scope></dependency>\
</dependencies></dependencyManagement></project>";

    let jar_id = store.put_bytes(b"consumer-jar").await.expect("jar");
    let consumer_pom_id = store.put_bytes(consumer_pom).await.expect("consumer pom");
    let the_bom_pom_id = store.put_bytes(the_bom_pom).await.expect("bom pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "consumer", "1.0", "jar", None),
            &jar_id,
        )
        .await
        .expect("index jar");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "consumer", "1.0", "pom", None),
            &consumer_pom_id,
        )
        .await
        .expect("index consumer pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "the-bom", "2.0", "pom", None),
            &the_bom_pom_id,
        )
        .await
        .expect("index bom pom");

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform_packages(
        Platform::new("linux", "x86_64").expect("platform"),
        vec![
            LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "consumer".to_string(),
                version: "1.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo-a.example/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: Default::default(),
            },
            LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "the-bom".to_string(),
                version: "2.0".to_string(),
                snapshot_timestamp: None,
                packaging: "pom".to_string(),
                classifier: None,
                repo_url: "https://repo-a.example/".to_string(),
                checksum: Some(Checksum::new("sha256", the_bom_pom_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: Default::default(),
            },
        ],
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let options = ExportOptions {
        dry_run: false,
        overwrite: false,
        link_strategy: LinkStrategy::Copy,
        m2_path: m2.clone(),
    };
    let mut repo_ids = HashMap::new();
    repo_ids.insert("https://repo-a.example/".to_string(), "repo-a".to_string());
    let mut support = HashMap::new();
    support.insert(
        "com.example:the-bom:2.0".to_string(),
        unpinned_support("repo-b"),
    );

    let stats = Exporter::new(options, &store)
        .with_repo_ids(repo_ids)
        .with_support_poms(support)
        .export_lock(&lock, None)
        .await
        .expect("export");

    // consumer jar + consumer pom + the-bom pom, and the-bom exactly once:
    // a second unit for it would either export or skip a fourth file.
    assert_eq!(
        (stats.exported_count, stats.skipped_count),
        (3, 0),
        "dual-role POM must be exported once, got {stats:?}"
    );

    let bom = m2.join("com/example/the-bom/2.0/the-bom-2.0.pom");
    assert_eq!(fs::read(&bom).expect("read bom"), the_bom_pom);

    let marker = m2.join("com/example/the-bom/2.0/_remote.repositories");
    let body = fs::read_to_string(&marker).expect("bom marker");
    assert!(
        body.contains("the-bom-2.0.pom>repo-b="),
        "recorded support-POM repo id must win over the lockfile repo_url, got: {body}"
    );
    assert!(
        !body.contains("repo-a="),
        "the losing provenance must not also be recorded, got: {body}"
    );
}

/// A BOM that the lockfile pins directly *and* the support-POM provenance
/// records, with the two naming different bytes. Both files exist in the
/// store, so neither missing-blob check fires: the only thing standing
/// between the lockfile and a silently substituted POM is the collision
/// check in `ExportQueue::push`. Whichever unit is queued first would
/// otherwise win, and here that is the support pin — shipping bytes the
/// package row attests are the wrong ones.
#[tokio::test]
async fn support_pin_disagreeing_with_a_pom_package_row_fails_before_writing() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let resolved: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>the-bom</artifactId><version>2.0</version>\
<packaging>pom</packaging></project>";
    let substitute: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>the-bom</artifactId><version>2.0</version>\
<packaging>pom</packaging><description>another sync</description></project>";
    let resolved_id = store.put_bytes(resolved).await.expect("resolved bom");
    let substitute_id = store.put_bytes(substitute).await.expect("substitute bom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "the-bom", "2.0", "pom", None),
            &resolved_id,
        )
        .await
        .expect("index bom");

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        Platform::new("linux", "x86_64").expect("platform"),
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "the-bom".to_string(),
            version: "2.0".to_string(),
            snapshot_timestamp: None,
            packaging: "pom".to_string(),
            classifier: None,
            repo_url: "https://repo-a.example/".to_string(),
            checksum: Some(Checksum::new("sha256", resolved_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let mut support = HashMap::new();
    support.insert(
        "com.example:the-bom:2.0".to_string(),
        pinned_support("repo-b", substitute),
    );

    let err = Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        },
        &store,
    )
    .with_support_poms(support)
    .export_lock(&lock, None)
    .await
    .expect_err("two pins for one Maven path cannot both be exported");

    assert!(
        matches!(&err, ExportError::ConflictingExportSources { coordinate, .. }
                if coordinate == "com.example:the-bom:2.0:pom"),
        "expected ConflictingExportSources, got {err:?}"
    );
    let message = err.to_string();
    for digest in [resolved_id.as_str(), substitute_id.as_str()] {
        assert!(
            message.contains(digest),
            "the error must name both digests, missing {digest} in: {message}"
        );
    }
    assert!(!m2.exists(), "nothing should be materialized, found {m2:?}");
}

/// Negative control for the collision check: the healthy shape is both
/// recordings naming the same bytes, which still collapses into one export
/// and still lets the recorded support-POM repository id win.
#[tokio::test]
async fn support_pin_agreeing_with_a_pom_package_row_exports_once() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");

    let resolved: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>the-bom</artifactId><version>2.0</version>\
<packaging>pom</packaging></project>";
    let resolved_id = store.put_bytes(resolved).await.expect("resolved bom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "the-bom", "2.0", "pom", None),
            &resolved_id,
        )
        .await
        .expect("index bom");

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        Platform::new("linux", "x86_64").expect("platform"),
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "the-bom".to_string(),
            version: "2.0".to_string(),
            snapshot_timestamp: None,
            packaging: "pom".to_string(),
            classifier: None,
            repo_url: "https://repo-a.example/".to_string(),
            checksum: Some(Checksum::new("sha256", resolved_id.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let mut repo_ids = HashMap::new();
    repo_ids.insert("https://repo-a.example/".to_string(), "repo-a".to_string());
    let mut support = HashMap::new();
    support.insert(
        "com.example:the-bom:2.0".to_string(),
        pinned_support("repo-b", resolved),
    );

    let stats = Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        },
        &store,
    )
    .with_repo_ids(repo_ids)
    .with_support_poms(support)
    .export_lock(&lock, None)
    .await
    .expect("agreeing pins export");

    assert_eq!(
        (stats.exported_count, stats.skipped_count),
        (1, 0),
        "one coordinate reached twice is still one file, got {stats:?}"
    );
    assert_eq!(
        fs::read(m2.join("com/example/the-bom/2.0/the-bom-2.0.pom")).expect("bom"),
        resolved,
    );
    let marker = fs::read_to_string(m2.join("com/example/the-bom/2.0/_remote.repositories"))
        .expect("marker");
    assert!(
        marker.contains("the-bom-2.0.pom>repo-b="),
        "recorded support-POM repo id must still win, got: {marker}"
    );
}

/// A jar whose companion POM is also a support POM (a parent that is
/// itself a dependency), with the row's `pom_sha256` and the recorded
/// support pin naming different bytes.
///
/// `Lockfile::read` rejects this shape, so the lock is built in memory to
/// reach the export layer directly. The support closure is queued first
/// and marks the coordinate as seen; gating the companion lookup on that
/// alone would drop the row's pin before `ExportQueue::push` ever compared
/// the two, and the export would ship the support bytes while the jar's
/// row attests the other digest.
#[tokio::test]
async fn support_pin_disagreeing_with_a_companion_pin_fails_before_writing() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let jar = store.put_bytes(b"app-jar").await.expect("jar");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "app", "1.0", "jar", None),
            &jar,
        )
        .await
        .expect("index jar");

    let resolved: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version></project>";
    let substitute: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>\
<name>another sync</name></project>";
    let resolved_id = store.put_bytes(resolved).await.expect("resolved pom");
    let substitute_id = store.put_bytes(substitute).await.expect("substitute pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "app", "1.0", "pom", None),
            &resolved_id,
        )
        .await
        .expect("index app pom");

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        Platform::new("linux", "x86_64").expect("platform"),
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "app".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo-a.example/".to_string(),
            checksum: Some(Checksum::new("sha256", jar.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let mut digests = HashMap::new();
    digests.insert(
        (
            "com.example".to_string(),
            "app".to_string(),
            "1.0".to_string(),
        ),
        resolved_id.clone(),
    );
    let mut support = HashMap::new();
    support.insert(
        "com.example:app:1.0".to_string(),
        pinned_support("repo-b", substitute),
    );

    let err = Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        },
        &store,
    )
    .with_pom_digests(digests)
    .with_support_poms(support)
    .export_lock(&lock, None)
    .await
    .expect_err("two pins for one Maven path cannot both be exported");

    assert!(
        matches!(&err, ExportError::ConflictingExportSources { coordinate, .. }
                if coordinate == "com.example:app:1.0:pom"),
        "expected ConflictingExportSources, got {err:?}"
    );
    let message = err.to_string();
    for digest in [resolved_id.as_str(), substitute_id.as_str()] {
        assert!(
            message.contains(digest),
            "the error must name both digests, missing {digest} in: {message}"
        );
    }
    assert!(!m2.exists(), "nothing should be materialized, found {m2:?}");
}

/// Negative control: the healthy shape is both recordings naming the same
/// bytes, which exports one POM next to the jar and still lets the
/// recorded support-POM repository id win the marker.
#[tokio::test]
async fn support_pin_agreeing_with_a_companion_pin_exports_once() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let jar = store.put_bytes(b"app-jar").await.expect("jar");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "app", "1.0", "jar", None),
            &jar,
        )
        .await
        .expect("index jar");

    let resolved: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version></project>";
    let resolved_id = store.put_bytes(resolved).await.expect("resolved pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "app", "1.0", "pom", None),
            &resolved_id,
        )
        .await
        .expect("index app pom");

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform(
        Platform::new("linux", "x86_64").expect("platform"),
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "app".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo-a.example/".to_string(),
            checksum: Some(Checksum::new("sha256", jar.as_str())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        },
    )];

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let mut digests = HashMap::new();
    digests.insert(
        (
            "com.example".to_string(),
            "app".to_string(),
            "1.0".to_string(),
        ),
        resolved_id.clone(),
    );
    let mut repo_ids = HashMap::new();
    repo_ids.insert("https://repo-a.example/".to_string(), "repo-a".to_string());
    let mut support = HashMap::new();
    support.insert(
        "com.example:app:1.0".to_string(),
        pinned_support("repo-b", resolved),
    );

    let stats = Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        },
        &store,
    )
    .with_pom_digests(digests)
    .with_repo_ids(repo_ids)
    .with_support_poms(support)
    .export_lock(&lock, None)
    .await
    .expect("agreeing pins export");

    assert_eq!(
        (stats.exported_count, stats.skipped_count),
        (2, 0),
        "the jar and one POM, not two POMs, got {stats:?}"
    );
    assert_eq!(
        fs::read(m2.join("com/example/app/1.0/app-1.0.pom")).expect("app pom"),
        resolved,
    );
    let marker =
        fs::read_to_string(m2.join("com/example/app/1.0/_remote.repositories")).expect("marker");
    assert!(
        marker.contains("app-1.0.pom>repo-b="),
        "recorded support-POM repo id must win for the POM, got: {marker}"
    );
    assert!(
        marker.contains("app-1.0.jar>repo-a="),
        "the jar keeps the id derived from its own repo_url, got: {marker}"
    );
}

/// Collect the `WARN`-level events emitted on this thread for as long as
/// the returned guard lives, each flattened to `" field=value"` pairs
/// (the log message rides along as the `message` field).
#[derive(Default)]
struct WarnFields(String);

impl tracing::field::Visit for WarnFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut fields = WarnFields::default();
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push(fields.0);
    }
}

/// A per-test warning sink. `set_default` is thread-local, so parallel
/// tests cannot see each other's events, and a `#[tokio::test]` runs its
/// future on the thread that installed the subscriber.
fn capture_warnings() -> (
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    tracing::subscriber::DefaultGuard,
) {
    use tracing_subscriber::layer::SubscriberExt;

    let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(WarnCapture(std::sync::Arc::clone(&sink)));
    (sink, rv_test_support::set_default(subscriber))
}

/// One ordinary jar dependency, optionally joined by a system-scoped one.
/// Indexes the jar and its POM so the export has something to materialize.
async fn system_scope_fixture(store: &Store, with_system: bool) -> Lockfile {
    let jar_id = store.put_bytes(b"app-jar").await.expect("jar");
    let pom: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version></project>";
    let pom_id = store.put_bytes(pom).await.expect("pom");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "app", "1.0", "jar", None),
            &jar_id,
        )
        .await
        .expect("index jar");
    store
        .add_artifact(
            &ArtifactKey::new("com.example", "app", "1.0", "pom", None),
            &pom_id,
        )
        .await
        .expect("index pom");

    let mut packages = vec![LockPackage {
        group_id: "com.example".to_string(),
        artifact_id: "app".to_string(),
        version: "1.0".to_string(),
        snapshot_timestamp: None,
        packaging: "jar".to_string(),
        classifier: None,
        repo_url: "https://repo1.maven.org/maven2/".to_string(),
        checksum: Some(Checksum::new("sha256", jar_id.as_str())),
        system_path: None,
        direct_scope: None,
        extra: Default::default(),
    }];
    if with_system {
        packages.push(LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "tools".to_string(),
            version: "9.9".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: String::new(),
            checksum: None,
            system_path: Some("/opt/jdk/lib/tools.jar".to_string()),
            direct_scope: Some("system".to_string()),
            extra: Default::default(),
        });
    }

    let mut lock = Lockfile::new();
    lock.platforms = vec![test_platform_packages(
        Platform::new("linux", "x86_64").expect("platform"),
        packages,
    )];
    lock
}

async fn export_to(store: &Store, lock: &Lockfile, m2: &std::path::Path) {
    Exporter::new(
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.to_path_buf(),
        },
        store,
    )
    .export_lock(lock, None)
    .await
    .expect("export");
}

/// A `systemPath` dependency cannot be exported: it has no bytes in the
/// content store and no artifact row to reach them by. The export must
/// still say so, naming the coordinate, or the `mvn -o` failure that
/// follows has nothing pointing back at what this `~/.m2` is missing. The
/// coordinates live only in the per-module package graphs, which is why
/// the aggregate view the export otherwise works from cannot see them.
#[tokio::test]
async fn system_scoped_dependency_warns_and_still_exports() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let lock = system_scope_fixture(&store, true).await;

    assert!(
        lock.platforms[0]
            .artifacts
            .iter()
            .all(|artifact| artifact.coordinate.artifact != "tools"),
        "a system-scoped dependency has no artifact row; the module graph is the only source"
    );

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let (warnings, _guard) = capture_warnings();
    export_to(&store, &lock, &m2).await;

    let captured = warnings.lock().unwrap_or_else(|err| err.into_inner());
    let system_warning = captured
        .iter()
        .find(|entry| entry.contains("system-scoped dependencies not exported"))
        .unwrap_or_else(|| panic!("expected a system-scope warning, got {captured:?}"));
    assert!(
        system_warning.contains("com.example:tools:9.9"),
        "the warning must name the coordinate, got: {system_warning}"
    );

    // The export still succeeds and still ships everything it can.
    assert!(m2.join("com/example/app/1.0/app-1.0.jar").exists());
    assert!(
        !m2.join("com/example/tools/9.9").exists(),
        "the system-scoped dependency has no bytes to export"
    );
}

/// Negative control: the same project without a `systemPath` dependency
/// must not warn about one.
#[tokio::test]
async fn export_without_system_scoped_dependencies_stays_quiet() {
    let store_dir = tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let lock = system_scope_fixture(&store, false).await;

    let m2_dir = tempdir().expect("m2 dir");
    let m2 = m2_dir.path().join("repository");
    let (warnings, _guard) = capture_warnings();
    export_to(&store, &lock, &m2).await;

    let captured = warnings.lock().unwrap_or_else(|err| err.into_inner());
    assert!(
        !captured
            .iter()
            .any(|entry| entry.contains("system-scoped dependencies not exported")),
        "no system-scoped dependency, no warning; got {captured:?}"
    );
}

/// Parse a flat collection of `<tag>text</tag>` occurrences out of a
/// well-formed XML document. Used only by the unit tests above; the
/// production code goes through quick-xml-friendly emission.
fn parse_simple_xml(xml: &str) -> std::collections::HashMap<String, String> {
    use quick_xml::Reader;
    use quick_xml::escape::unescape;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut out = std::collections::HashMap::new();
    let mut buf = Vec::new();
    let mut current: Option<String> = None;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                current = Some(String::from_utf8_lossy(e.name().as_ref()).into_owned());
            }
            Ok(Event::Text(t)) => {
                if let Some(name) = current.as_deref() {
                    let raw = String::from_utf8_lossy(t.as_ref());
                    let text = unescape(&raw).unwrap_or_default().into_owned();
                    out.entry(name.to_string()).or_insert(text);
                }
            }
            Ok(Event::End(_)) => current = None,
            Ok(Event::Eof) => break,
            Err(e) => panic!("xml parse error: {e}"),
            _ => {}
        }
        buf.clear();
    }
    out
}
