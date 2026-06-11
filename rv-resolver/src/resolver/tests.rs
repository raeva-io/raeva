//! Tests for the resolver module.

use super::fetcher::RepoTrust;
use super::{RepoBackend, RepoParentResolver, ResolutionResult};
use crate::context::ResolveContext;
use crate::graph::{Edge, Graph, Node};
use rv_config::{Checksum, Config, Platform, ResolvedPaths};
use rv_maven_model::{Parent, Pom, Scope};
use rv_store::Store;
use rv_version::Coord;
use std::fs;
use std::path::Path;
use std::sync::Arc;

fn write_pom(path: &Path, group_id: &str, artifact_id: &str, version: &str) {
    let contents = format!(
        r"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>{group_id}</groupId>
  <artifactId>{artifact_id}</artifactId>
  <version>{version}</version>
</project>
"
    );
    fs::write(path, contents).unwrap();
}

fn test_context(project_root: &Path, store_dir: &Path) -> ResolveContext {
    let paths = ResolvedPaths::discover().expect("paths");
    let config = Config::for_testing_with_repos(project_root.to_path_buf(), paths, Vec::new());
    let store = Arc::new(Store::open(store_dir).expect("store"));
    let platform = Platform::new("linux", "x86_64").unwrap();
    ResolveContext::new(config, Vec::new(), store, platform, None)
}

#[test]
fn resolution_result_builds_lockfile() {
    let root = Node {
        coord: Coord::parse("com.example:root:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: None,
        checksum: None,
        local: false,
        system_path: None,
    };
    let mut graph = Graph::new(root);
    let dep = Node {
        coord: Coord::parse("com.example:dep:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: Some(Arc::from("https://repo.example/")),
        checksum: Some(Checksum::new("sha256", "deadbeef")),
        local: false,
        system_path: None,
    };
    let dep_idx = graph.insert_node(dep);
    graph.add_edge(
        graph.root(),
        dep_idx,
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: Some("1.0".to_string()),
        },
    );

    let result = ResolutionResult {
        graph,
        platform: Platform::new("linux", "x86_64").unwrap(),
        packages: vec![rv_config::LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "dep".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/".to_string(),
            checksum: Some(Checksum::new("sha256", "deadbeef")),
            system_path: None,
            direct_scope: Some("compile".to_string()),
            extra: std::collections::BTreeMap::new(),
        }],
        edges: Vec::new(),
        repositories: Vec::new(),
        support_repo_ids: Vec::new(),
    };

    let lock = result.to_lockfile();
    assert_eq!(lock.platforms.len(), 1);
    assert_eq!(lock.platforms[0].packages.len(), 1);
}

/// Test that build_lock_data correctly includes transitive dependency edges.
#[test]
fn build_lock_data_includes_transitive_edges() {
    use super::build_lock_data;

    // Create a graph: root -> A -> B (transitive dependency)
    let root = Node {
        coord: Coord::parse("com.example:root:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: None,
        checksum: None,
        local: false,
        system_path: None,
    };
    let mut graph = Graph::new(root);

    // Add node A (direct dependency)
    let a = Node {
        coord: Coord::parse("com.example:a:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: Some(Arc::from("https://repo.example/")),
        checksum: Some(Checksum::new("sha256", "aaaaaa")),
        local: false,
        system_path: None,
    };
    let a_idx = graph.insert_node(a);
    graph.add_edge(
        graph.root(),
        a_idx,
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: Some("1.0".to_string()),
        },
    );

    // Add node B (transitive dependency of A)
    let b = Node {
        coord: Coord::parse("com.example:b:2.0").unwrap(),
        scope: Scope::Compile,
        repo_url: Some(Arc::from("https://repo.example/")),
        checksum: Some(Checksum::new("sha256", "bbbbbb")),
        local: false,
        system_path: None,
    };
    let b_idx = graph.insert_node(b);
    graph.add_edge(
        a_idx,
        b_idx,
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: Some("2.0".to_string()),
        },
    );

    let (packages, edges) = build_lock_data(&graph).unwrap();

    // Should have 2 packages: A and B
    assert_eq!(packages.len(), 2, "Expected 2 packages");

    // Should have 1 edge: A -> B (the root->A edge is skipped)
    assert_eq!(
        edges.len(),
        1,
        "Expected 1 edge (A->B), got {}",
        edges.len()
    );

    // Find the index of A and B in packages
    let a_pkg_idx = packages
        .iter()
        .position(|p| p.artifact_id == "a")
        .expect("package A not found");
    let b_pkg_idx = packages
        .iter()
        .position(|p| p.artifact_id == "b")
        .expect("package B not found");

    // Verify the edge is from A to B
    assert_eq!(edges[0].from, a_pkg_idx, "Edge should be from A");
    assert_eq!(edges[0].to, b_pkg_idx, "Edge should be to B");
}

/// Test that diamond dependencies create correct edges.
#[test]
fn build_lock_data_handles_diamond_deps() {
    use super::build_lock_data;

    // Create a diamond: root -> A -> C, root -> B -> C
    let root = Node {
        coord: Coord::parse("com.example:root:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: None,
        checksum: None,
        local: false,
        system_path: None,
    };
    let mut graph = Graph::new(root);

    // A
    let a = Node {
        coord: Coord::parse("com.example:a:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: Some(Arc::from("https://repo.example/")),
        checksum: Some(Checksum::new("sha256", "aaaaaa")),
        local: false,
        system_path: None,
    };
    let a_idx = graph.insert_node(a);
    graph.add_edge(
        graph.root(),
        a_idx,
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: Some("1.0".to_string()),
        },
    );

    // B
    let b = Node {
        coord: Coord::parse("com.example:b:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: Some(Arc::from("https://repo.example/")),
        checksum: Some(Checksum::new("sha256", "bbbbbb")),
        local: false,
        system_path: None,
    };
    let b_idx = graph.insert_node(b);
    graph.add_edge(
        graph.root(),
        b_idx,
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: Some("1.0".to_string()),
        },
    );

    // C (shared dependency)
    let c = Node {
        coord: Coord::parse("com.example:c:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: Some(Arc::from("https://repo.example/")),
        checksum: Some(Checksum::new("sha256", "cccccc")),
        local: false,
        system_path: None,
    };
    let c_idx = graph.insert_node(c);

    // A -> C
    graph.add_edge(
        a_idx,
        c_idx,
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: Some("1.0".to_string()),
        },
    );

    // B -> C
    graph.add_edge(
        b_idx,
        c_idx,
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: Some("1.0".to_string()),
        },
    );

    let (packages, edges) = build_lock_data(&graph).unwrap();

    // Should have 3 packages: A, B, C
    assert_eq!(packages.len(), 3, "Expected 3 packages");

    // Should have 2 edges: A -> C and B -> C (root edges are skipped)
    assert_eq!(
        edges.len(),
        2,
        "Expected 2 edges (A->C and B->C), got {}",
        edges.len()
    );
}

/// Test that direct-only dependencies result in no edges (expected behavior).
#[test]
fn build_lock_data_direct_only_has_no_edges() {
    use super::build_lock_data;

    // Create a graph with only direct dependencies: root -> A, root -> B
    let root = Node {
        coord: Coord::parse("com.example:root:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: None,
        checksum: None,
        local: false,
        system_path: None,
    };
    let mut graph = Graph::new(root);

    // A (direct dependency)
    let a = Node {
        coord: Coord::parse("com.example:a:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: Some(Arc::from("https://repo.example/")),
        checksum: Some(Checksum::new("sha256", "aaaaaa")),
        local: false,
        system_path: None,
    };
    let a_idx = graph.insert_node(a);
    graph.add_edge(
        graph.root(),
        a_idx,
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: Some("1.0".to_string()),
        },
    );

    // B (also direct dependency, no relation to A)
    let b = Node {
        coord: Coord::parse("com.example:b:2.0").unwrap(),
        scope: Scope::Compile,
        repo_url: Some(Arc::from("https://repo.example/")),
        checksum: Some(Checksum::new("sha256", "bbbbbb")),
        local: false,
        system_path: None,
    };
    let b_idx = graph.insert_node(b);
    graph.add_edge(
        graph.root(),
        b_idx,
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: Some("2.0".to_string()),
        },
    );

    let (packages, edges) = build_lock_data(&graph).unwrap();

    // Should have 2 packages: A and B
    assert_eq!(packages.len(), 2, "Expected 2 packages");

    // Should have 0 edges (both edges are from root, which is correctly skipped)
    assert_eq!(
        edges.len(),
        0,
        "Direct-only deps should have no edges in lock (root edges are not serialized)"
    );

    // Both packages should be marked as direct dependencies
    assert!(
        packages.iter().all(|p| p.direct_scope.is_some()),
        "All direct deps should have direct_scope set"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn load_local_project_from_rv_toml() {
    let root_tmp = tempfile::tempdir().unwrap();
    let root = root_tmp.path();
    let store_tmp = tempfile::tempdir().unwrap();
    // Parent resolution follows relative_path (defaults to ../pom.xml from child_dir),
    // so we need an actual pom.xml in root for the resolver to find.
    write_pom(&root.join("pom.xml"), "com.example", "parent", "1.0");

    let ctx = test_context(root, store_tmp.path());
    let backend = RepoBackend::new(&ctx, Vec::new(), false);
    let child_dir = root.join("child");
    fs::create_dir_all(&child_dir).unwrap();
    // Pass `project_root = root` so that the default `../pom.xml` traversal
    // (child_dir/../pom.xml = root/pom.xml) passes the containment check.
    // The workspace root encompasses both the child module and its parent POM.
    let resolver = RepoParentResolver::with_strict_and_trust(
        backend,
        Some(child_dir),
        Some(root.to_path_buf()),
        false,
        RepoTrust::Root,
    );

    let parent = Parent {
        group_id: "com.example".to_string(),
        artifact_id: "parent".to_string(),
        version: "1.0".to_string(),
        relative_path: None,
    };

    let pom = resolver.load_local_parent(&parent).expect("local parent");
    assert_eq!(pom.artifact_id.as_deref(), Some("parent"));
}

#[test]
fn empty_relative_path_skips_local_lookup() {
    let root_tmp = tempfile::tempdir().unwrap();
    let root = root_tmp.path();
    let store_tmp = tempfile::tempdir().unwrap();
    let child_dir = root.join("child");
    fs::create_dir_all(&child_dir).unwrap();
    write_pom(&root.join("pom.xml"), "com.example", "parent", "1.0");

    let ctx = test_context(root, store_tmp.path());
    let backend = RepoBackend::new(&ctx, Vec::new(), false);
    let resolver = RepoParentResolver::with_strict(backend, Some(child_dir), false);
    let parent = Parent {
        group_id: "com.example".to_string(),
        artifact_id: "parent".to_string(),
        version: "1.0".to_string(),
        relative_path: Some(String::new()),
    };

    assert!(resolver.load_local_parent(&parent).is_none());
}

/// Regression: parent POM `<repositories>` must propagate into the solver
/// backend's repo set. `load_root_project` resolves the parent chain on a
/// temporary backend; if the repos that backend observes are not returned to
/// the caller, a transitive dep hosted only on a parent-declared repo is
/// unresolvable once that backend is dropped.
#[tokio::test(flavor = "multi_thread")]
async fn parent_pom_repositories_propagate_to_resolver() {
    use crate::ResolutionStrategy;

    let root_tmp = tempfile::tempdir().unwrap();
    let root = root_tmp.path();
    let store_tmp = tempfile::tempdir().unwrap();

    // Parent POM declares a custom repository.
    fs::write(
        root.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0</version>
  <packaging>pom</packaging>
  <repositories>
    <repository>
      <id>parent-only</id>
      <url>https://parent-only.example/repo/</url>
    </repository>
  </repositories>
</project>
"#,
    )
    .unwrap();

    // Child POM in a subdirectory inherits via relativePath.
    let child_dir = root.join("child");
    fs::create_dir_all(&child_dir).unwrap();
    fs::write(
        child_dir.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0</version>
    <relativePath>../pom.xml</relativePath>
  </parent>
  <artifactId>child</artifactId>
</project>
"#,
    )
    .unwrap();

    let ctx = test_context(&child_dir, store_tmp.path());
    let resolver = crate::Resolver::with_strategy(ctx, ResolutionStrategy::NearestWins);

    let (_coord, project, observed, _support) = resolver
        .load_root_project(&child_dir.join("pom.xml"), &[])
        .await
        .expect("load_root_project");

    let has_in_observed = observed
        .iter()
        .any(|r| r.url == "https://parent-only.example/repo/");
    let has_in_project = project
        .repositories
        .iter()
        .any(|r| r.url == "https://parent-only.example/repo/");
    assert!(
        has_in_observed || has_in_project,
        "parent-declared repository must surface to the solver backend either \
         via observed_repos (root-POM trusted observe) or via project.repositories \
         (inherited from parent). observed urls: {:?}, project repo urls: {:?}",
        observed.iter().map(|r| &r.url).collect::<Vec<_>>(),
        project
            .repositories
            .iter()
            .map(|r| &r.url)
            .collect::<Vec<_>>(),
    );
}

/// #2: the ROOT project's own parent must fail closed even in normal
/// (non-`--frozen`) mode. A root pom declaring a parent that cannot be
/// resolved (no local `../pom.xml` match, no remote client) must error rather
/// than silently producing a lock from a model Maven itself cannot build.
/// Transitive parents stay lenient; only the root contract is strict.
#[tokio::test]
async fn root_parent_resolution_is_strict_even_when_not_frozen() {
    let proj_tmp = tempfile::tempdir().unwrap();
    let proj = proj_tmp.path();
    fs::write(
        proj.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>nonexistent-parent</artifactId>
    <version>9.9.9</version>
  </parent>
  <artifactId>child</artifactId>
</project>
"#,
    )
    .unwrap();

    let store_tmp = tempfile::tempdir().unwrap();
    let ctx = test_context(proj, store_tmp.path());
    // Non-frozen / non-strict Resolver: the leniency that governs transitive
    // resolution must NOT extend to the root's own parent.
    let resolver = crate::Resolver::with_strategy(ctx, crate::ResolutionStrategy::NearestWins)
        .with_strict(false);

    let result = resolver.load_root_project(&proj.join("pom.xml"), &[]).await;
    assert!(
        result.is_err(),
        "an unresolvable ROOT parent must fail closed even without --frozen"
    );
}

/// `.mvn/maven.config` `-D` entries must override same-named POM
/// `<properties>` because Maven treats user properties as sitting above POM
/// properties in the precedence chain. This test mirrors the merge step
/// performed by `Resolver::load_root_project` so that a regression in the
/// merge ordering is caught without setting up a full Resolver run.
#[test]
fn maven_config_properties_override_pom_properties() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path();
    let mvn_dir = project_dir.join(".mvn");
    std::fs::create_dir_all(&mvn_dir).unwrap();
    std::fs::write(
        mvn_dir.join("maven.config"),
        "-Drevision=2.0\n-Dchangelist=\n",
    )
    .unwrap();

    let pom_xml = r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>cfg</artifactId>
  <version>${revision}</version>
  <properties>
    <revision>1.0</revision>
  </properties>
</project>
"#;
    let mut pom = Pom::parse(pom_xml).unwrap();

    // Same merge step as Resolver::load_root_project (Option A in the bug
    // write-up): maven.config overwrites pom.properties.
    let maven_config = crate::parent_resolver::parse_maven_config(project_dir);
    for (key, value) in maven_config {
        pom.properties.insert(key, value);
    }

    assert_eq!(
        pom.properties.get("revision").map(String::as_str),
        Some("2.0"),
        "maven.config -Drevision=2.0 must override POM <revision>1.0</revision>"
    );
}

/// Verifies the URL-dedup behaviour of `RepoBackend::extend_repos` when the
/// operator has opted in to accepting transitive `<repositories>` (the
/// default-deny path is covered by tests in `backend.rs`).
#[test]
fn repo_backend_extend_repos_accumulates_unique_urls() {
    use rv_repo::Repository;
    let tmp = tempfile::tempdir().unwrap();
    let project_root = tmp.path();
    let store_dir = project_root.join("store");
    std::fs::create_dir_all(&store_dir).unwrap();
    let mut ctx = test_context(project_root, &store_dir);
    // Opt in so transitive repos are merged (default policy ignores them).
    ctx.config.security.allow_transitive_repositories = true;

    let initial = vec![Repository::new(
        Some("central".to_string()),
        "https://repo.example/central/",
        true,
        false,
    )];
    let backend = RepoBackend::new(&ctx, initial, false);

    assert_eq!(backend.repos_snapshot().len(), 1);

    // Extending with a new URL appends; duplicate URLs are ignored.
    backend.extend_repos(vec![
        Repository::new(
            Some("private".to_string()),
            "https://repo.example/private/",
            true,
            false,
        ),
        Repository::new(
            Some("central-dup".to_string()),
            "https://repo.example/central/",
            true,
            false,
        ),
    ]);

    let snapshot = backend.repos_snapshot();
    assert_eq!(snapshot.len(), 2, "duplicate URL should not be added");
    assert!(
        snapshot
            .iter()
            .any(|r| r.url == "https://repo.example/central/")
    );
    assert!(
        snapshot
            .iter()
            .any(|r| r.url == "https://repo.example/private/")
    );
}

/// Regression: when `populate_artifacts` finds a cached blob in the store,
/// it must re-verify the on-disk SHA-256 of that blob (and of every other
/// cache hit) instead of trusting the index row. The previous implementation
/// random-sampled 1% of cache hits, so a single corrupted blob outside the
/// sample silently flowed downstream into the resolved graph as a trusted
/// artifact.
///
/// This test exercises the primitive the populate hot loop relies on:
/// `Store::verify_blobs` MUST return only the blobs whose on-disk bytes
/// hash back to their index `BlobId`. `populate_artifacts` then pushes
/// anything missing from the verified set into `to_fetch` (a refetch), so a
/// tampered cache entry can never be approved.
#[tokio::test]
async fn verify_blobs_rejects_tampered_blob_so_populate_refetches() {
    use rv_config::{ArtifactKey, BlobId};
    use std::collections::HashSet;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("open");

    // Two intact blobs and one that will be corrupted in place. The
    // populate_artifacts loop sees all three as cache candidates.
    let good_payload_a = b"good-bytes-A".to_vec();
    let good_a = store.put_bytes(&good_payload_a).await.expect("put a");
    let key_a = ArtifactKey::new("com.ex", "a", "1.0.0", "jar", None);
    store.add_artifact(&key_a, &good_a).await.expect("add a");

    let good_payload_b = b"good-bytes-B".to_vec();
    let good_b = store.put_bytes(&good_payload_b).await.expect("put b");
    let key_b = ArtifactKey::new("com.ex", "b", "1.0.0", "jar", None);
    store.add_artifact(&key_b, &good_b).await.expect("add b");

    let bad_payload = b"will-be-tampered".to_vec();
    let bad_id = store.put_bytes(&bad_payload).await.expect("put bad");
    let key_bad = ArtifactKey::new("com.ex", "bad", "1.0.0", "jar", None);
    store
        .add_artifact(&key_bad, &bad_id)
        .await
        .expect("add bad");

    // Tamper with the on-disk blob without touching the index row.
    // Published blobs are read-only (0o444); restore write permission for
    // the simulated corruption.
    let bad_path = store.get_path(&bad_id);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&bad_path).expect("stat").permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&bad_path, perms).expect("chmod");
    }
    fs::write(&bad_path, b"different-bytes").expect("tamper");

    // Drive verify_blobs over the full set, mirroring the
    // `verify_blobs(&all_ids)` call site in populate_artifacts.
    let all = vec![good_a.clone(), good_b.clone(), bad_id.clone()];
    let verified: HashSet<BlobId> = store
        .verify_blobs(&all, rv_store::Store::default_verification_parallelism())
        .await
        .expect("verify");

    assert!(
        verified.contains(&good_a),
        "intact blob A must remain in the verified set"
    );
    assert!(
        verified.contains(&good_b),
        "intact blob B must remain in the verified set"
    );
    assert!(
        !verified.contains(&bad_id),
        "tampered blob MUST be excluded from the verified set so populate_artifacts \
         refetches it instead of silently trusting the index row"
    );
    // The "missing from verified" filter is what populate_artifacts uses to
    // route a candidate into the `to_fetch` queue. Assert the contract holds:
    // every candidate NOT in verified is treated as a cache miss.
    let to_refetch: Vec<&BlobId> = all.iter().filter(|id| !verified.contains(id)).collect();
    assert_eq!(to_refetch, vec![&bad_id]);
}
