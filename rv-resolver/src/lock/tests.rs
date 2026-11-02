use std::collections::BTreeMap;
use std::path::Path;

use rv_config::{Config, RepoConfig, ResolvedPaths};
use rv_lock::Platform;
use rv_maven_types::{ArtifactCoord, BlobId, Coord, Gav};

use super::*;
use crate::graph::{Graph, Node};
use crate::output::{ModuleResolution, ResolvedArtifact, ResolvedPackage};
use crate::resolver::{SupportPomProvenance, WorkspaceModuleResolution, WorkspaceResolution};

fn config(root: &Path, repositories: &[&str]) -> Config {
    let repositories = repositories
        .iter()
        .map(|url| {
            let mut repo = RepoConfig::new(None, url);
            repo.releases = Some(true);
            repo.snapshots = Some(true);
            repo
        })
        .collect();
    Config::for_testing_with_repos(
        root.to_path_buf(),
        ResolvedPaths::for_testing().expect("paths"),
        repositories,
    )
}

fn linux() -> Platform {
    Platform::new("linux", "x86_64").expect("platform")
}

fn coordinate(artifact: &str, version: &str) -> ArtifactCoord {
    ArtifactCoord::new("com.example", artifact, version, "jar", None)
}

fn external(artifact: &str, repo_url: &str, blob: &[u8], pom: &[u8]) -> ResolvedPackage {
    ResolvedPackage {
        coordinate: coordinate(artifact, "1.0"),
        direct_scope: Some(rv_lock::Scope::Compile),
        scope: rv_lock::Scope::Compile,
        workspace_module: None,
        system_path: None,
        artifact: Some(ResolvedArtifact {
            version: "1.0".to_string(),
            snapshot: None,
            pom_snapshot: None,
            pom_base: false,
            pom_repo_url: None,
            repo_url: repo_url.to_string(),
            blob: BlobId::from_bytes(blob),
            companion_pom: Some(BlobId::from_bytes(pom)),
        }),
    }
}

fn module(pom_path: &str, packages: Vec<ResolvedPackage>) -> WorkspaceModuleResolution {
    let root = Node {
        coord: Coord::parse(&format!("com.example:{pom_path}:1")).expect("coord"),
        scope: rv_maven_model::Scope::Compile,
        repo_url: None,
        build_repo: None,
        checksum: None,
        workspace_module: None,
        local: false,
        system_path: None,
        repos: Default::default(),
        winner_parent: None,
    };
    WorkspaceModuleResolution {
        pom_path: pom_path.to_string(),
        resolution: ModuleResolution {
            graph: Graph::new(root),
            platform: linux(),
            packages,
            edges: Vec::new(),
            module_gav: Gav::new("com.example", pom_path, "1"),
            module_packaging: "jar".to_string(),
            repositories: Vec::new(),
            trusted_repositories: Vec::new(),
            parent_ranges: Vec::new(),
            support_pom_provenance: Vec::new(),
            host_reads: Default::default(),
        },
    }
}

fn assemble_modules(
    config: &Config,
    modules: Vec<WorkspaceModuleResolution>,
) -> Result<AssembledLock, AssembleError> {
    let pom_hashes = BTreeMap::new();
    let model = PlatformModel {
        active_profiles: &[],
        pom_hashes: &pom_hashes,
        whole_reactor_pom_hashes: &pom_hashes,
    };
    assemble(
        config,
        vec![(
            model,
            WorkspaceResolution {
                platform: linux(),
                modules,
                reactor_through_dependencies: false,
                host_reads: Default::default(),
            },
        )],
    )
}

/// Two modules that reach one artifact through different repositories share
/// one row, which names the repository configured first. Modules that
/// resolved different bytes for it cannot share raeva.lock's single row.
#[test]
fn modules_share_one_row_per_artifact() {
    let root = tempfile::tempdir().expect("tempdir");
    let first = "https://first.example/maven2/";
    let second = "https://second.example/maven2/";
    let config = config(root.path(), &[first, second]);
    let assemble_lib = |app: ResolvedPackage, web: ResolvedPackage| {
        assemble_modules(
            &config,
            vec![module("app", vec![app]), module("web", vec![web])],
        )
    };
    let assembled = assemble_lib(
        external("lib", second, b"jar", b"pom"),
        external("lib", first, b"jar", b"pom"),
    )
    .expect("assembled");
    let platform = &assembled.lock.platforms[0];
    assert_eq!(platform.artifacts.len(), 1);
    assert_eq!(platform.artifacts[0].repo_url, first);
    assert_eq!(
        platform.artifacts[0].pom_sha256,
        Some(BlobId::from_bytes(b"pom"))
    );
    assert_eq!(platform.modules.len(), 2);
    assert_eq!(
        platform.model_hash,
        rv_lock::inputs::model_records_hash(&[], &BTreeMap::new())
    );

    let error = assemble_lib(
        external("lib", first, b"one", b"pom"),
        external("lib", first, b"two", b"pom"),
    )
    .expect_err("one row cannot pin two files");
    assert!(
        matches!(&error, AssembleError::Resolve(error) if matches!(**error, ResolveError::ConflictingArtifactBytes { .. })),
        "{error:?}"
    );
}

#[test]
fn a_system_file_is_recorded_relative_to_the_project() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(root.path().join("lib")).expect("lib");
    std::fs::write(root.path().join("lib/vendor.jar"), b"vendor").expect("jar");
    let config = config(root.path(), &[]);
    let system = |path: String| ResolvedPackage {
        coordinate: coordinate("vendor", "1.0"),
        direct_scope: Some(rv_lock::Scope::System),
        scope: rv_lock::Scope::System,
        workspace_module: None,
        system_path: Some(path),
        artifact: None,
    };

    let inside = root.path().join("lib/vendor.jar").display().to_string();
    let assembled =
        assemble_modules(&config, vec![module("app", vec![system(inside)])]).expect("assembled");
    let package = &assembled.lock.platforms[0].modules[0].packages[0];
    assert_eq!(package.system_path.as_deref(), Some("lib/vendor.jar"));
    assert!(package.system_sha256.is_some());
    assert!(assembled.lock.platforms[0].artifacts.is_empty());

    let outside = tempfile::tempdir().expect("tempdir");
    std::fs::write(outside.path().join("vendor.jar"), b"vendor").expect("jar");
    let error = assemble_modules(
        &config,
        vec![module(
            "app",
            vec![system(
                outside.path().join("vendor.jar").display().to_string(),
            )],
        )],
    )
    .expect_err("a file outside the project");
    match error {
        AssembleError::SystemFile { path, reason } => {
            assert_eq!(path, root.path().join("app"));
            assert!(
                reason.contains("system-scoped dependency com.example:vendor:1.0:jar"),
                "{reason}"
            );
        }
        other => panic!("expected SystemFile, got {other:?}"),
    }
}

/// Support POMs merged across modules keep a known repository id over an
/// id-less record of the same bytes, in either order, so the exported POM
/// keeps its `_remote.repositories` marker; an id the lock cannot record
/// counts as id-less. Different bytes for one
/// coordinate fail the sync, naming the coordinate and both modules.
#[test]
fn aggregated_support_poms_keep_one_pin_per_coordinate() {
    let provenance = |repo_id: &str, digest: char| SupportPomProvenance {
        repo_id: repo_id.to_string(),
        repo_url: format!("https://{repo_id}.example/"),
        snapshot: None,
        sha256: digest.to_string().repeat(64),
    };
    for order in [
        ["", "corp"],
        ["corp", ""],
        ["co\trp", "corp"],
        ["corp", "co\nrp"],
    ] {
        let mut aggregate = BTreeMap::new();
        for (repo_id, module) in order.into_iter().zip(["a/pom.xml", "b/pom.xml"]) {
            merge_support_pom(&mut aggregate, "g:a:1.0", &provenance(repo_id, 'a'), module)
                .expect("agreeing bytes merge");
        }
        assert_eq!(aggregate["g:a:1.0"].provenance, provenance("corp", 'a'));
    }

    let mut aggregate = BTreeMap::new();
    merge_support_pom(
        &mut aggregate,
        "g:a:1.0",
        &provenance("corp", 'a'),
        "a/pom.xml",
    )
    .expect("first module");
    let message = merge_support_pom(
        &mut aggregate,
        "g:a:1.0",
        &provenance("corp", 'b'),
        "b/pom.xml",
    )
    .expect_err("different bytes must not be collapsed")
    .to_string();
    for part in ["g:a:1.0", "a/pom.xml", "b/pom.xml"] {
        assert!(message.contains(part), "{message}");
    }
}

/// Two freshly resolved modules (or platforms) that parsed different bytes
/// for one GAV's companion POM must fail the sync, naming both origins.
/// The lockfile pins one digest per coordinate, so silently keeping either
/// leaves the other module compiling against a POM it never resolved.
#[test]
fn fresh_companion_pom_conflict_names_both_origins() {
    let linux = linux();
    let darwin = Platform::new("darwin", "aarch64").expect("platform");
    let url = "https://repo.example/maven2/";
    let other = "https://other.example/maven2/";
    let first = external("lib", url, b"jar", b"<project>first</project>");
    let second = external("lib", other, b"jar", b"<project>second</project>");
    let first_artifact = first.artifact.as_ref().expect("artifact");
    let second_artifact = second.artifact.as_ref().expect("artifact");

    let mut aggregate = BTreeMap::new();
    merge_companion_pom(
        &mut aggregate,
        &first.coordinate,
        first_artifact,
        &linux,
        "app/pom.xml",
    )
    .expect("first observation");
    // Same bytes from another module is the normal case.
    merge_companion_pom(
        &mut aggregate,
        &first.coordinate,
        first_artifact,
        &linux,
        "lib/pom.xml",
    )
    .expect("agreeing observation");

    let message = merge_companion_pom(
        &mut aggregate,
        &second.coordinate,
        second_artifact,
        &darwin,
        "app/pom.xml",
    )
    .expect_err("differing bytes must fail the sync")
    .to_string();
    assert!(
        message.contains("com.example:lib:1.0")
            && message.contains(&format!("linux-x86_64/app/pom.xml from {url}"))
            && message.contains(&format!("darwin-aarch64/app/pom.xml from {other}")),
        "conflict must name the coordinate, both origins and their repositories, got: {message}"
    );
    for artifact in [first_artifact, second_artifact] {
        let digest = pom_digest_text(artifact.companion_pom.as_ref());
        assert!(message.contains(&digest), "{digest}: {message}");
    }
}

/// Two modules that read different bytes for one parent or BOM name the
/// repository each read it from.
#[test]
fn support_pom_conflict_names_both_repositories() {
    let provenance = |repo: &str, bytes: &[u8]| SupportPomProvenance {
        repo_id: "id".to_string(),
        repo_url: repo.to_string(),
        snapshot: None,
        sha256: BlobId::from_bytes(bytes).to_string(),
    };
    let (url, other) = (
        "https://repo.example/maven2/",
        "https://other.example/maven2/",
    );
    let mut aggregate = BTreeMap::new();
    let coord = "com.example:parent:1";
    merge_support_pom(
        &mut aggregate,
        coord,
        &provenance(url, b"first"),
        "a/pom.xml",
    )
    .expect("first observation");
    let message = merge_support_pom(
        &mut aggregate,
        coord,
        &provenance(other, b"second"),
        "b/pom.xml",
    )
    .expect_err("differing bytes must fail the sync")
    .to_string();
    assert!(
        message.contains(&format!("a/pom.xml from {url} ("))
            && message.contains(&format!("b/pom.xml from {other} (")),
        "{message}"
    );
}

/// A timestamped snapshot's row keeps the `-SNAPSHOT` coordinate and records
/// the build it resolved to, which is what reads back as its version.
#[test]
fn timestamped_snapshot_row_records_its_build() {
    let timestamped = "1.0-20260720.123253-28";
    let pom = BlobId::from_bytes(b"<project/>");
    let artifact = lock_artifact(
        coordinate("demo", "1.0-SNAPSHOT"),
        ResolvedArtifact {
            version: timestamped.to_string(),
            snapshot: rv_maven_types::SnapshotStamp::of_version(timestamped),
            pom_snapshot: None,
            pom_base: false,
            pom_repo_url: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            blob: BlobId::from_bytes(b"jar"),
            companion_pom: Some(pom.clone()),
        },
    );
    assert_eq!(
        artifact.snapshot.as_ref().map(|value| value.build()),
        Some(28)
    );
    assert_eq!(artifact.file_version(), timestamped);
    assert_eq!(artifact.pom_sha256.as_ref(), Some(&pom));
}
