//! Tests for the resolver module.

use super::fetcher::RepoTrust;
use super::{RepoBackend, RepoParentResolver, ResolutionResult, SupportPomProvenance};
use crate::Workspace;
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

mod workspace_resolution {
    use std::collections::HashMap;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, Once};

    use rv_config::{Config, Platform, RepoConfig, ResolvedPaths};
    use rv_repo::{RepoClient, Repository};
    use rv_store::Store;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::ResolveContext;
    use crate::{ResolutionStrategy, ResolveError, Resolver, Workspace};

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("test-fixtures")
            .join("reactor-resolution")
            .join(name)
    }

    fn ensure_crypto_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn response(status: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    async fn spawn_repository() -> (String, Arc<Mutex<Vec<String>>>) {
        spawn_repository_with_routes(repository_routes()).await
    }

    async fn spawn_repository_with_routes(
        routes: HashMap<String, Vec<u8>>,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let routes = Arc::new(routes);

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let routes = Arc::clone(&routes);
                let request_log = Arc::clone(&request_log);
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let mut buffer = [0_u8; 4096];
                    loop {
                        let Ok(read) = socket.read(&mut buffer).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&buffer[..read]);
                        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let path = std::str::from_utf8(&bytes)
                        .ok()
                        .and_then(|request| request.lines().next())
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    request_log
                        .lock()
                        .expect("request log poisoned")
                        .push(path.clone());
                    let payload = routes
                        .get(&path)
                        .map(|body| response("200 OK", body))
                        .unwrap_or_else(|| response("404 Not Found", b""));
                    let _ = socket.write_all(&payload).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        (format!("http://{address}/"), requests)
    }

    /// Like [`spawn_repository_with_routes`], but every `.jar` request is
    /// accepted and then never answered: the socket stays open and the client
    /// waits. That is a genuinely wedged artifact download, which is what the
    /// stall watchdog exists to name.
    async fn spawn_repository_hanging_on_jars(
        routes: HashMap<String, Vec<u8>>,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let routes = Arc::new(routes);

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let routes = Arc::clone(&routes);
                let request_log = Arc::clone(&request_log);
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let mut buffer = [0_u8; 4096];
                    loop {
                        let Ok(read) = socket.read(&mut buffer).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&buffer[..read]);
                        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let path = std::str::from_utf8(&bytes)
                        .ok()
                        .and_then(|request| request.lines().next())
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    request_log
                        .lock()
                        .expect("request log poisoned")
                        .push(path.clone());
                    if path.ends_with(".jar") {
                        // Hold the connection open and never reply. The test
                        // ends long before this elapses.
                        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                        return;
                    }
                    let payload = routes
                        .get(&path)
                        .map(|body| response("200 OK", body))
                        .unwrap_or_else(|| response("404 Not Found", b""));
                    let _ = socket.write_all(&payload).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        (format!("http://{address}/"), requests)
    }

    fn repository_routes() -> HashMap<String, Vec<u8>> {
        let metadata = br#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>lib</artifactId>
  <versioning>
    <latest>2</latest>
    <release>2</release>
    <versions><version>2</version></versions>
  </versioning>
</metadata>"#;
        let dynamic_metadata = br#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>dynamic-lib</artifactId>
  <versioning>
    <latest>2</latest>
    <release>2</release>
    <versions><version>2</version></versions>
  </versioning>
</metadata>"#;
        let leaf_pom = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.external</groupId>
  <artifactId>leaf</artifactId>
  <version>1</version>
</project>"#;
        let lib_pom = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>lib</artifactId>
  <version>2</version>
</project>"#;
        let dynamic_lib_pom = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>dynamic-lib</artifactId>
  <version>2</version>
</project>"#;
        let vendor_pom = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.vendor</groupId>
  <artifactId>only-here</artifactId>
  <version>1</version>
</project>"#;

        HashMap::from([
            (
                "/com/example/lib/maven-metadata.xml".to_string(),
                metadata.to_vec(),
            ),
            (
                "/com/example/dynamic-lib/maven-metadata.xml".to_string(),
                dynamic_metadata.to_vec(),
            ),
            (
                "/org/external/leaf/1/leaf-1.pom".to_string(),
                leaf_pom.to_vec(),
            ),
            (
                "/org/external/leaf/1/leaf-1.jar".to_string(),
                b"external-leaf".to_vec(),
            ),
            ("/com/example/lib/2/lib-2.pom".to_string(), lib_pom.to_vec()),
            (
                "/com/example/lib/2/lib-2.jar".to_string(),
                b"repository-lib".to_vec(),
            ),
            (
                "/com/example/dynamic-lib/2/dynamic-lib-2.pom".to_string(),
                dynamic_lib_pom.to_vec(),
            ),
            (
                "/com/example/dynamic-lib/2/dynamic-lib-2.jar".to_string(),
                b"repository-dynamic-lib".to_vec(),
            ),
            (
                "/org/vendor/only-here/1/only-here-1.pom".to_string(),
                vendor_pom.to_vec(),
            ),
            (
                "/org/vendor/only-here/1/only-here-1.jar".to_string(),
                b"vendor-only".to_vec(),
            ),
        ])
    }

    fn repo_config(url: &str) -> RepoConfig {
        RepoConfig {
            id: Some("fixture".to_string()),
            url: url.to_string(),
            releases: Some(true),
            snapshots: Some(true),
            snapshots_update_policy: None,
        }
    }

    async fn resolver(
        project_root: &Path,
        repo_url: Option<&str>,
        offline: bool,
        initial_repositories: bool,
    ) -> (Resolver, tempfile::TempDir) {
        ensure_crypto_provider();
        let paths = ResolvedPaths::discover().expect("paths");
        let repositories = repo_url
            .map(|url| vec![repo_config(url)])
            .unwrap_or_default();
        let config =
            Config::for_testing_with_repos(project_root.to_path_buf(), paths, repositories);
        let client = if repo_url.is_some() || offline {
            Some(
                RepoClient::new(&config)
                    .await
                    .expect("repo client")
                    .with_allow_missing_checksums(true)
                    .with_offline(offline),
            )
        } else {
            None
        };
        let repos = if initial_repositories {
            config.repositories().iter().map(Repository::from).collect()
        } else {
            Vec::new()
        };
        let store_dir = tempfile::tempdir().expect("store tempdir");
        let store = Arc::new(Store::open(store_dir.path()).expect("store"));
        let platform = Platform::new("linux", "x86_64").expect("platform");
        let context = ResolveContext::new(config, repos, store, platform, client);
        (
            Resolver::with_strategy(context, ResolutionStrategy::NearestWins),
            store_dir,
        )
    }

    async fn resolve_module(
        resolver: &Resolver,
        workspace: &Workspace,
        pom_path: &str,
    ) -> Result<super::ResolutionResult, ResolveError> {
        resolver
            .resolve_internal(
                &workspace.root().join(pom_path),
                Some(Arc::new(workspace.clone())),
                None,
            )
            .await
    }

    fn copy_tree(source: &Path, destination: &Path) -> io::Result<()> {
        std::fs::create_dir_all(destination)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_tree(&source_path, &destination_path)?;
            } else {
                std::fs::copy(source_path, destination_path)?;
            }
        }
        Ok(())
    }

    fn node_by_artifact<'a>(
        graph: &'a crate::Graph,
        artifact_id: &str,
    ) -> (petgraph::graph::NodeIndex, &'a crate::Node) {
        graph
            .node_indices()
            .find_map(|index| {
                graph
                    .node(index)
                    .filter(|node| node.coord.artifact_id.as_str() == artifact_id)
                    .map(|node| (index, node))
            })
            .unwrap_or_else(|| panic!("missing graph node {artifact_id}"))
    }

    #[tokio::test]
    async fn workspace_parent_short_circuits_repository_fetch() {
        let workspace = Workspace::discover(fixture("basic")).expect("workspace");
        let (resolver, _store) = resolver(workspace.root(), None, false, false).await;

        let result = resolve_module(&resolver, &workspace, "remote-parent-child/pom.xml")
            .await
            .expect("workspace parent must resolve without a repo client");

        assert_eq!(result.module_gav.version, "1");
    }

    #[tokio::test]
    async fn exact_sibling_keeps_outgoing_external_edges() {
        let workspace = Workspace::discover(fixture("basic")).expect("workspace");
        let (url, _) = spawn_repository().await;
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let result = resolve_module(&resolver, &workspace, "app/pom.xml")
            .await
            .expect("resolve app");
        let (lib_index, lib) = node_by_artifact(&result.graph, "lib");
        let (_, leaf) = node_by_artifact(&result.graph, "leaf");

        assert_eq!(lib.workspace_module.as_deref(), Some("lib/pom.xml"));
        assert!(lib.repo_url.is_none());
        assert!(lib.checksum.is_none());
        assert!(leaf.workspace_module.is_none());
        assert!(leaf.repo_url.is_some());
        assert!(
            result.graph.edges(lib_index).any(|(_, target, _)| result
                .graph
                .node(target)
                .is_some_and(|node| node.coord.artifact_id.as_str() == "leaf")),
            "the sibling model's outgoing edge to its external dependency must survive"
        );
    }

    #[tokio::test]
    async fn exact_sibling_version_mismatch_falls_back_and_errors_offline() {
        let workspace = Workspace::discover(fixture("basic")).expect("workspace");
        let (resolver, _store) = resolver(workspace.root(), None, true, true).await;

        let error = resolve_module(&resolver, &workspace, "mismatch-app/pom.xml")
            .await
            .expect_err("workspace lib:1 must not satisfy exact lib:2");

        assert!(error.to_string().contains("offline mode"), "{error}");
    }

    #[tokio::test]
    async fn range_selects_workspace_or_higher_repository_candidate() {
        let workspace = Workspace::discover(fixture("basic")).expect("workspace");
        let (url, _) = spawn_repository().await;
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let sibling = resolve_module(&resolver, &workspace, "range-app/pom.xml")
            .await
            .expect("range selects sibling");
        let (_, sibling_lib) = node_by_artifact(&sibling.graph, "lib");
        assert_eq!(sibling_lib.workspace_module.as_deref(), Some("lib/pom.xml"));
        assert_eq!(sibling_lib.coord.version.as_str(), "1");

        let repository = resolve_module(&resolver, &workspace, "range-higher-app/pom.xml")
            .await
            .expect("higher repository version wins");
        let (_, repository_lib) = node_by_artifact(&repository.graph, "lib");
        assert!(repository_lib.workspace_module.is_none());
        assert_eq!(repository_lib.coord.version.as_str(), "2");
        assert!(repository_lib.repo_url.is_some());
    }

    #[tokio::test]
    async fn dynamic_selector_competes_workspace_and_repository_candidates() {
        let workspace = Workspace::discover(fixture("basic")).expect("workspace");
        let (workspace_only, _store) = resolver(workspace.root(), None, false, false).await;

        let sibling = resolve_module(&workspace_only, &workspace, "dynamic-app/pom.xml")
            .await
            .expect("LATEST selects the only workspace candidate");
        let (_, sibling_lib) = node_by_artifact(&sibling.graph, "dynamic-lib");
        assert_eq!(
            sibling_lib.workspace_module.as_deref(),
            Some("dynamic-lib/pom.xml")
        );
        assert_eq!(sibling_lib.coord.version.as_str(), "1");

        let (url, _) = spawn_repository().await;
        let (with_repository, _store) = resolver(workspace.root(), Some(&url), false, true).await;
        let repository = resolve_module(&with_repository, &workspace, "dynamic-app/pom.xml")
            .await
            .expect("LATEST selects the higher repository candidate");
        let (_, repository_lib) = node_by_artifact(&repository.graph, "dynamic-lib");
        assert!(repository_lib.workspace_module.is_none());
        assert_eq!(repository_lib.coord.version.as_str(), "2");
    }

    #[tokio::test]
    async fn sibling_bom_import_manages_external_dependency() {
        let workspace = Workspace::discover(fixture("basic")).expect("workspace");
        let (url, _) = spawn_repository().await;
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let result = resolve_module(&resolver, &workspace, "bom-app/pom.xml")
            .await
            .expect("resolve sibling BOM");
        let (_, leaf) = node_by_artifact(&result.graph, "leaf");

        assert_eq!(leaf.coord.version.as_str(), "1");
    }

    #[tokio::test]
    async fn exact_workspace_snapshot_needs_no_metadata_or_repo_client() {
        let workspace = Workspace::discover(fixture("basic")).expect("workspace");
        let (resolver, _store) = resolver(workspace.root(), None, false, false).await;

        let result = resolve_module(&resolver, &workspace, "snapshot-app/pom.xml")
            .await
            .expect("workspace snapshot must short-circuit metadata");
        let (_, snapshot) = node_by_artifact(&result.graph, "snapshot");

        assert_eq!(
            snapshot.workspace_module.as_deref(),
            Some("snapshot/pom.xml")
        );
        assert_eq!(snapshot.coord.version.as_str(), "1-SNAPSHOT");
    }

    #[tokio::test]
    async fn sibling_test_jar_keeps_requested_classifier_identity() {
        let workspace = Workspace::discover(fixture("basic")).expect("workspace");
        let (url, _) = spawn_repository().await;
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let result = resolve_module(&resolver, &workspace, "classifier-app/pom.xml")
            .await
            .expect("resolve classifier app");
        let (_, lib) = node_by_artifact(&result.graph, "lib");

        assert_eq!(lib.workspace_module.as_deref(), Some("lib/pom.xml"));
        assert_eq!(lib.coord.packaging.as_deref(), None);
        assert_eq!(lib.coord.classifier.as_deref(), Some("tests"));
    }

    #[tokio::test]
    async fn interpolated_sibling_gav_is_used_for_candidate_validation() {
        let workspace = Workspace::discover(fixture("basic")).expect("workspace");
        let (resolver, _store) = resolver(workspace.root(), None, false, false).await;

        let result = resolve_module(&resolver, &workspace, "revision-app/pom.xml")
            .await
            .expect("resolve CI-friendly sibling");
        let (_, child) = node_by_artifact(&result.graph, "revision-child");

        assert_eq!(
            child.workspace_module.as_deref(),
            Some("revision-child/pom.xml")
        );
        assert_eq!(child.coord.version.as_str(), "1.0");
    }

    #[tokio::test]
    async fn workspace_dependency_cycle_is_a_hard_readable_error() {
        let workspace = Workspace::discover(fixture("cycle")).expect("workspace");
        let (resolver, _store) = resolver(workspace.root(), None, false, false).await;

        let error = resolve_module(&resolver, &workspace, "a/pom.xml")
            .await
            .expect_err("dependency cycle must fail");

        assert!(matches!(
            error,
            ResolveError::WorkspaceDependencyCycle { .. }
        ));
        assert_eq!(
            error.to_string(),
            "workspace dependency cycle detected: com.example:a -> com.example:b -> com.example:a"
        );
    }

    #[tokio::test]
    async fn sibling_declared_repository_is_trusted() {
        let (url, requests) = spawn_repository().await;
        let workspace_dir = tempfile::tempdir().expect("workspace tempdir");
        copy_tree(&fixture("basic"), workspace_dir.path()).expect("copy fixture");
        let repo_owner = workspace_dir.path().join("repo-owner/pom.xml");
        let contents = std::fs::read_to_string(&repo_owner)
            .expect("read repo owner")
            .replace("__REPO_URL__", &url);
        std::fs::write(&repo_owner, contents).expect("rewrite repo URL");
        let workspace = Workspace::discover(workspace_dir.path()).expect("workspace");
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, false).await;

        let result = resolve_module(&resolver, &workspace, "repo-app/pom.xml")
            .await
            .expect("trusted sibling repo resolves vendor dependency");
        let (_, vendor) = node_by_artifact(&result.graph, "only-here");

        assert!(vendor.repo_url.is_some());
        assert!(
            requests
                .lock()
                .expect("request log")
                .iter()
                .any(|path| path == "/org/vendor/only-here/1/only-here-1.pom")
        );
    }

    #[tokio::test]
    async fn per_module_driver_resolves_in_discovery_order_with_bounded_budget() {
        let (url, _) = spawn_repository().await;
        let workspace_dir = tempfile::tempdir().expect("workspace tempdir");
        copy_tree(&fixture("basic"), workspace_dir.path()).expect("copy fixture");
        let repo_owner = workspace_dir.path().join("repo-owner/pom.xml");
        let contents = std::fs::read_to_string(&repo_owner)
            .expect("read repo owner")
            .replace("__REPO_URL__", &url);
        std::fs::write(&repo_owner, contents).expect("rewrite repo URL");
        let workspace = Workspace::discover(workspace_dir.path()).expect("workspace");
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let resolved = resolver
            .resolve_workspace(&workspace)
            .await
            .expect("resolve workspace");

        assert_eq!(resolved.modules.len(), workspace.len());
        assert_eq!(
            resolved
                .modules
                .iter()
                .map(|module| module.pom_path.as_str())
                .collect::<Vec<_>>(),
            workspace
                .modules()
                .iter()
                .map(|module| module.pom_path.as_str())
                .collect::<Vec<_>>()
        );
        assert!(
            resolved
                .modules
                .iter()
                .any(
                    |module| module.resolution.graph.node_indices().any(|index| {
                        module
                            .resolution
                            .graph
                            .node(index)
                            .is_some_and(|node| node.workspace_module.is_some())
                    })
                )
        );
    }

    #[test]
    fn module_concurrency_cap_is_documented_and_sane() {
        assert_eq!(crate::MAX_WORKSPACE_MODULE_CONCURRENCY, 4);
        assert_eq!(crate::MAX_WORKSPACE_NETWORK_CONCURRENCY, 4);
        assert_eq!(crate::MAX_WORKSPACE_ARTIFACT_POPULATIONS, 1);
    }

    /// Resolves the workspaces in the manually cloned acceptance corpus.
    ///
    /// The corpus is PINNED: the per-project module counts asserted below are
    /// properties of these exact refs, not of the projects' default branches
    /// (upstream trunk adds and removes modules, so an unpinned checkout drifts
    /// and fails here for reasons unrelated to resolution). Clone with:
    ///
    /// ```sh
    /// git clone --depth 1 --branch 3.0.5 https://github.com/apache/pdfbox.git pdfbox
    /// git clone --depth 1 --branch v5.0.2 https://github.com/dropwizard/dropwizard.git dropwizard
    /// ```
    ///
    /// Set `RV_ACCEPTANCE_CORPUS` to the directory that holds those two
    /// checkouts. The test skips when the variable is unset.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires the manually cloned acceptance corpus and network access"]
    async fn resolves_real_pdfbox_and_dropwizard_workspaces() {
        use crate::workspace::corpus::{
            DROPWIZARD_MODULE_COUNT, DROPWIZARD_REF, PDFBOX_MODULE_COUNT, PDFBOX_REF, clone_hint,
            corpus_drift_hint,
        };

        let Ok(corpus_root) = std::env::var("RV_ACCEPTANCE_CORPUS") else {
            println!(
                "skipping: set RV_ACCEPTANCE_CORPUS to the acceptance corpus directory to run \
                 this test ({})",
                clone_hint()
            );
            return;
        };
        let corpus_root = Path::new(&corpus_root);

        let _ = tracing_subscriber::fmt()
            .with_env_filter("rv_resolver::workspace=debug")
            .with_test_writer()
            .try_init();
        assert_eq!(
            std::env::var("JAVA_VERSION").as_deref(),
            Ok("21"),
            "run the corpus smoke with JAVA_VERSION=21"
        );
        ensure_crypto_provider();
        let store_dir = tempfile::tempdir().expect("corpus store");
        let store = Arc::new(Store::open(store_dir.path()).expect("store"));

        for (project_name, corpus_ref, expected_modules) in [
            ("pdfbox", PDFBOX_REF, PDFBOX_MODULE_COUNT),
            ("dropwizard", DROPWIZARD_REF, DROPWIZARD_MODULE_COUNT),
        ] {
            let project_root = corpus_root.join(project_name);
            let workspace = Workspace::discover(&project_root)
                .unwrap_or_else(|error| panic!("discover {project_name}: {error}"));
            assert_eq!(
                workspace.len(),
                expected_modules,
                "{}",
                corpus_drift_hint(project_name, corpus_ref)
            );
            let paths = ResolvedPaths::discover().expect("paths");
            let mut config =
                Config::for_testing_with_repos(project_root.clone(), paths, Vec::new());
            config.network.concurrency = 16;
            let client = RepoClient::new(&config)
                .await
                .expect("repo client")
                .with_allow_missing_checksums(true);
            let repositories = config.repositories().iter().map(Repository::from).collect();
            let platform = Platform::new("linux", "x86_64").expect("platform");
            let context = ResolveContext::new(
                config,
                repositories,
                Arc::clone(&store),
                platform,
                Some(client),
            );
            let resolver = Resolver::with_strategy(context, ResolutionStrategy::NearestWins);
            let resolved = resolver
                .resolve_workspace(&workspace)
                .await
                .unwrap_or_else(|error| panic!("resolve {project_name}: {error}"));

            println!("{project_name}: {} modules", resolved.modules.len());
            assert_eq!(
                resolved.modules.len(),
                expected_modules,
                "{}",
                corpus_drift_hint(project_name, corpus_ref)
            );
            for module in &resolved.modules {
                let mut workspace_nodes = 0;
                let mut external_nodes = 0;
                for index in module.resolution.graph.node_indices() {
                    let Some(node) = module.resolution.graph.node(index) else {
                        continue;
                    };
                    if node.workspace_module.is_some() {
                        workspace_nodes += 1;
                    } else if !node.local {
                        external_nodes += 1;
                    }
                }
                println!(
                    "{project_name}\t{}\texternal={external_nodes}\tworkspace={workspace_nodes}",
                    module.pom_path
                );
            }
        }
    }

    /// Regression: an all-reactor resolve of modules with heavily overlapping
    /// dependency sets must finish.
    ///
    /// This is the shape that hung `rv sync` on real reactors (slf4j, pdfbox,
    /// dropwizard, netty). More modules than `MAX_WORKSPACE_MODULE_CONCURRENCY`
    /// so the fan-out slots recycle, every module pulling the same external
    /// dependencies, and every one of those dependencies carrying a remote
    /// `<parent>` — which is what drives model resolution through the
    /// synchronous bridge in `sync_bridge`, where the lost wakeup lived.
    ///
    /// The stall watchdog is given a short window and passed in directly (no
    /// process-global env var, so this stays safe under a parallel test
    /// binary). A regression therefore surfaces as `WorkspaceStalled` rather
    /// than as a test binary that never exits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn overlapping_reactor_modules_resolve_without_stalling() {
        const MODULES: usize = 8;
        const SHARED_DEPS: usize = 6;

        let mut routes: HashMap<String, Vec<u8>> = HashMap::new();
        routes.insert(
            "/org/shared/shared-parent/1/shared-parent-1.pom".to_string(),
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.shared</groupId>
  <artifactId>shared-parent</artifactId>
  <version>1</version>
  <packaging>pom</packaging>
</project>"#
                .to_vec(),
        );
        for dep in 0..SHARED_DEPS {
            routes.insert(
                format!("/org/shared/dep-{dep}/1/dep-{dep}-1.pom"),
                format!(
                    r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.shared</groupId>
    <artifactId>shared-parent</artifactId>
    <version>1</version>
  </parent>
  <groupId>org.shared</groupId>
  <artifactId>dep-{dep}</artifactId>
  <version>1</version>
</project>"#
                )
                .into_bytes(),
            );
            routes.insert(
                format!("/org/shared/dep-{dep}/1/dep-{dep}-1.jar"),
                format!("shared-dep-{dep}").into_bytes(),
            );
        }
        let (url, _requests) = spawn_repository_with_routes(routes).await;

        let workspace_dir = tempfile::tempdir().expect("workspace tempdir");
        let module_names: Vec<String> = (0..MODULES).map(|m| format!("m{m}")).collect();
        let module_elements = module_names
            .iter()
            .map(|name| format!("    <module>{name}</module>"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            workspace_dir.path().join("pom.xml"),
            format!(
                r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>reactor</artifactId>
  <version>1</version>
  <packaging>pom</packaging>
  <modules>
{module_elements}
  </modules>
</project>"#
            ),
        )
        .expect("write root pom");

        let dependencies = (0..SHARED_DEPS)
            .map(|dep| {
                format!(
                    "    <dependency><groupId>org.shared</groupId>\
                     <artifactId>dep-{dep}</artifactId><version>1</version></dependency>"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        for name in &module_names {
            let dir = workspace_dir.path().join(name);
            std::fs::create_dir_all(&dir).expect("module dir");
            std::fs::write(
                dir.join("pom.xml"),
                format!(
                    r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>{name}</artifactId>
  <version>1</version>
  <dependencies>
{dependencies}
  </dependencies>
</project>"#
                ),
            )
            .expect("write module pom");
        }

        let workspace = Workspace::discover(workspace_dir.path()).expect("workspace");
        assert_eq!(workspace.len(), MODULES + 1, "root plus every module");
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let resolved = resolver
            .resolve_workspace_with_stall_timeout(
                &workspace,
                // Generous next to the milliseconds this takes against a
                // loopback stub, small enough that a regression fails fast.
                Some(std::time::Duration::from_secs(30)),
            )
            .await
            .expect("overlapping reactor modules must resolve");

        assert_eq!(resolved.modules.len(), MODULES + 1);
        for module in &resolved.modules {
            if module.pom_path == "pom.xml" {
                continue;
            }
            assert_eq!(
                module.resolution.packages.len(),
                SHARED_DEPS,
                "{} should pin every shared dependency",
                module.pom_path
            );
        }
    }

    /// A module is only in the watchdog's in-flight set while it builds its
    /// graph, but artifact population runs later, in its own serialized phase.
    /// A download wedged there used to produce a stall report that named
    /// nothing at all — the least useful moment to lose the label, since the
    /// phase and the module together are what point at the wedged work.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stall_during_artifact_population_names_the_module_and_phase() {
        let dep_pom = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.shared</groupId>
  <artifactId>hangs</artifactId>
  <version>1</version>
</project>"#;
        let routes = HashMap::from([(
            "/org/shared/hangs/1/hangs-1.pom".to_string(),
            dep_pom.to_vec(),
        )]);
        let (url, _requests) = spawn_repository_hanging_on_jars(routes).await;

        let workspace_dir = tempfile::tempdir().expect("workspace tempdir");
        std::fs::write(
            workspace_dir.path().join("pom.xml"),
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>reactor</artifactId>
  <version>1</version>
  <packaging>pom</packaging>
  <modules>
    <module>m0</module>
  </modules>
</project>"#,
        )
        .expect("write root pom");
        let module_dir = workspace_dir.path().join("m0");
        std::fs::create_dir_all(&module_dir).expect("module dir");
        std::fs::write(
            module_dir.join("pom.xml"),
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>m0</artifactId>
  <version>1</version>
  <dependencies>
    <dependency><groupId>org.shared</groupId>
      <artifactId>hangs</artifactId><version>1</version></dependency>
  </dependencies>
</project>"#,
        )
        .expect("write module pom");

        let workspace = Workspace::discover(workspace_dir.path()).expect("workspace");
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let error = resolver
            .resolve_workspace_with_stall_timeout(
                &workspace,
                // Well below rv-repo's request timeout, so the watchdog is
                // what ends the run.
                Some(std::time::Duration::from_secs(2)),
            )
            .await
            .expect_err("a download that never answers must be reported, not waited on");

        match error {
            ResolveError::WorkspaceStalled { modules, .. } => {
                assert_eq!(
                    modules, "m0/pom.xml (artifact population)",
                    "the stall must name the module and the phase it was in"
                );
            }
            other => panic!("expected WorkspaceStalled, got {other:?}"),
        }
    }
}

#[test]
fn resolution_result_builds_lockfile() {
    let root = Node {
        coord: Coord::parse("com.example:root:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: None,
        checksum: None,
        workspace_module: None,
        local: false,
        system_path: None,
    };
    let mut graph = Graph::new(root);
    let dep = Node {
        coord: Coord::parse("com.example:dep:1.0").unwrap(),
        scope: Scope::Compile,
        repo_url: Some(Arc::from("https://repo.example/")),
        checksum: Some(Checksum::new("sha256", "deadbeef")),
        workspace_module: None,
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
        module_gav: rv_config::LockGav::new("com.example", "root", "1.0"),
        module_packaging: "jar".to_string(),
        repositories: Vec::new(),
        trusted_repositories: Vec::new(),
        support_pom_provenance: Vec::new(),
        artifact_blobs: std::collections::BTreeMap::new(),
        companion_pom_blobs: std::collections::BTreeMap::new(),
    };

    let lock = result.to_lockfile();
    assert_eq!(lock.platforms.len(), 1);
    assert_eq!(lock.platforms[0].modules[0].packages.len(), 1);
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
        workspace_module: None,
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
        workspace_module: None,
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
        workspace_module: None,
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
        workspace_module: None,
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
        workspace_module: None,
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
        workspace_module: None,
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
        workspace_module: None,
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
        workspace_module: None,
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
        workspace_module: None,
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
        workspace_module: None,
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

#[tokio::test(flavor = "multi_thread")]
async fn selected_single_module_accepts_immediate_external_parent() {
    use crate::ResolutionStrategy;

    let checkout = tempfile::tempdir().unwrap();
    let child_dir = checkout.path().join("child");
    fs::create_dir_all(&child_dir).unwrap();
    fs::write(
        checkout.path().join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1-SNAPSHOT</version>
  <packaging>pom</packaging>
</project>
"#,
    )
    .unwrap();
    fs::write(
        child_dir.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1-SNAPSHOT</version>
    <relativePath>../pom.xml</relativePath>
  </parent>
  <artifactId>child</artifactId>
</project>
"#,
    )
    .unwrap();

    let workspace = Workspace::discover(&child_dir).expect("single-module workspace");
    assert_eq!(workspace.len(), 1);
    let store = tempfile::tempdir().unwrap();
    let ctx = test_context(&child_dir, store.path());
    let resolver = crate::Resolver::with_strategy(ctx, ResolutionStrategy::NearestWins);

    let (_, project, _, _) = resolver
        .load_root_project(
            &child_dir.join("pom.xml"),
            &[],
            Some(Arc::new(workspace)),
            None,
        )
        .await
        .expect("selected submodule resolves its immediate local parent");

    assert_eq!(project.group_id, "com.example");
    assert_eq!(project.version, "1-SNAPSHOT");
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
        .load_root_project(&child_dir.join("pom.xml"), &[], None, None)
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

    let result = resolver
        .load_root_project(&proj.join("pom.xml"), &[], None, None)
        .await;
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

/// The root `pom.xml` is a project input like any other: it goes through the
/// bounded read, so a file over `MAX_PROJECT_INPUT_SIZE` is rejected by size
/// instead of being pulled into memory whole. The typed error is what the
/// assertion pins down — an unbounded read would also fail here, but only
/// later, as a parse error, and only after allocating the whole file.
#[tokio::test]
async fn oversized_root_pom_is_rejected_before_parsing() {
    let proj_tmp = tempfile::tempdir().unwrap();
    let proj = proj_tmp.path();
    let store_tmp = tempfile::tempdir().unwrap();
    fs::write(
        proj.join("pom.xml"),
        vec![b'x'; rv_config::MAX_PROJECT_INPUT_SIZE + 1],
    )
    .unwrap();

    let ctx = test_context(proj, store_tmp.path());
    let resolver = crate::Resolver::with_strategy(ctx, crate::ResolutionStrategy::NearestWins);

    let error = resolver
        .load_root_project(&proj.join("pom.xml"), &[], None, None)
        .await
        .expect_err("an oversized root POM must be rejected");
    assert!(
        matches!(
            error,
            crate::ResolveError::Config(rv_config::ConfigError::ProjectInputTooLarge { .. })
        ),
        "expected the typed oversize error, got {error:?}"
    );
}

/// Reactor support POMs are buffered during the concurrent graph phase and
/// written to the shared store afterwards. That write is fatal: the provenance
/// `rv sync` records for these coordinates is recorded when they are buffered,
/// so swallowing the flush failure would produce a lock naming support POMs the
/// store never took — which only `rv export-m2` would discover.
///
/// The failure is injected the way `backend.rs` does it: the store's `tmp/`
/// staging directory is replaced with a regular file, and `put_bytes` starts
/// with a `create_dir_all` on it that no user can satisfy.
#[tokio::test]
async fn workspace_support_pom_flush_failure_is_fatal() {
    let proj_tmp = tempfile::tempdir().unwrap();
    let store_tmp = tempfile::tempdir().unwrap();
    let ctx = test_context(proj_tmp.path(), store_tmp.path());
    let resolver = crate::Resolver::with_strategy(ctx, crate::ResolutionStrategy::NearestWins);

    let buffered = crate::resolver::WorkspaceStoreState::for_testing(vec![(
        rv_config::ArtifactKey::new("com.example", "theparent", "2.0", "pom", None),
        b"<project/>".to_vec(),
    )]);

    let staging = store_tmp.path().join("tmp");
    fs::remove_dir_all(&staging).expect("remove staging dir");
    fs::write(&staging, b"not a directory").expect("occupy staging path");

    let error = resolver
        .flush_workspace_support_poms(&buffered)
        .await
        .expect_err("a failed support-POM flush must fail the resolve, not be swallowed");
    assert!(
        matches!(error, crate::ResolveError::Store(_)),
        "expected a store error, got {error:?}"
    );
}

mod pom_packaging_identity {
    use rv_config::{BlobId, LockPackage};

    use super::super::ensure_pom_packaging_identity;
    use crate::ResolveError;

    fn blob(digest: char) -> BlobId {
        std::iter::repeat_n(digest, 64)
            .collect::<String>()
            .parse()
            .expect("blob id")
    }

    fn package(packaging: &str, classifier: Option<&str>) -> LockPackage {
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "platform".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: packaging.to_string(),
            classifier: classifier.map(str::to_string),
            repo_url: "https://repo.example/maven2".to_string(),
            checksum: None,
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        }
    }

    /// For `packaging = "pom"` the artifact and the companion POM are one
    /// file. Two digests mean the lock would pin the payload to one and claim
    /// the other, which is what `rv export-m2` then ships.
    #[test]
    fn rejects_a_pom_package_whose_two_pins_disagree() {
        let error = ensure_pom_packaging_identity(&package("pom", None), &blob('a'), &blob('b'))
            .expect_err("a pom package cannot pin two files");
        match error {
            ResolveError::ConflictingPomPackagedBytes {
                coord,
                artifact_sha256,
                pom_sha256,
            } => {
                assert_eq!(coord, "com.example:platform:1.0:pom");
                assert_eq!(artifact_sha256, blob('a').to_string());
                assert_eq!(pom_sha256, blob('b').to_string());
            }
            other => panic!("expected ConflictingPomPackagedBytes, got {other:?}"),
        }
    }

    /// The normal case: one file, one digest, recorded twice.
    #[test]
    fn accepts_a_pom_package_whose_pins_agree() {
        ensure_pom_packaging_identity(&package("pom", None), &blob('a'), &blob('a'))
            .expect("agreeing pins are the healthy case");
    }

    /// A jar and its companion POM are two different files and must keep
    /// differing digests; the check must not reach them.
    #[test]
    fn ignores_non_pom_packaging() {
        ensure_pom_packaging_identity(&package("jar", None), &blob('a'), &blob('b'))
            .expect("a jar's payload is not its POM");
    }

    /// A classifier'd `.pom` (`a-v-classifier.pom`) is its own file, not the
    /// coordinate's companion POM, so it is not held to the identity.
    #[test]
    fn ignores_a_classified_pom_artifact() {
        ensure_pom_packaging_identity(&package("pom", Some("tests")), &blob('a'), &blob('b'))
            .expect("a classified .pom is a different file");
    }
}

fn support_provenance(repo_id: &str, digest: char) -> SupportPomProvenance {
    SupportPomProvenance {
        repo_id: repo_id.to_string(),
        sha256: std::iter::repeat_n(digest, 64).collect(),
    }
}

/// Support-POM provenance is merged from two backends, and a coordinate can
/// arrive twice: once from an id'd repository and once from an id-less one.
/// Sorted order puts the id-less form first, so the merge has to prefer the
/// known id explicitly or the coordinate loses its `_remote.repositories`
/// marker. The preference is only ever a choice between two records of the
/// SAME bytes, so it decides a label and never which POM gets exported.
#[test]
fn merged_support_provenance_prefers_a_known_repo_id() {
    let merged = super::merge_support_pom_provenance(vec![
        ("com.example:b:2.0".to_string(), support_provenance("", 'b')),
        (
            "com.example:a:1.0".to_string(),
            support_provenance("corp", 'a'),
        ),
        (
            "com.example:b:2.0".to_string(),
            support_provenance("corp", 'b'),
        ),
        ("com.example:c:3.0".to_string(), support_provenance("", 'd')),
    ])
    .expect("agreeing digests merge");

    assert_eq!(
        merged,
        vec![
            (
                "com.example:a:1.0".to_string(),
                support_provenance("corp", 'a')
            ),
            (
                "com.example:b:2.0".to_string(),
                support_provenance("corp", 'b')
            ),
            // Only ever seen from an id-less repository: the coordinate is
            // still recorded, which is what export-m2's completeness check
            // needs.
            ("com.example:c:3.0".to_string(), support_provenance("", 'd')),
        ]
    );
}

/// Two backends that fetched DIFFERENT bytes for one support POM must not be
/// collapsed by repository-id preference. The lockfile pins one digest per
/// coordinate and `rv export-m2` writes one `.pom`, so silently keeping the
/// id'd entry would export bytes the other half of the resolution never read —
/// and would hide the disagreement from `rv sync`'s reactor-wide check, whose
/// whole job is to catch it.
#[test]
fn merged_support_provenance_rejects_conflicting_bytes() {
    let error = super::merge_support_pom_provenance(vec![
        ("com.example:b:2.0".to_string(), support_provenance("", 'b')),
        (
            "com.example:b:2.0".to_string(),
            support_provenance("corp", 'c'),
        ),
    ])
    .expect_err("differing digests for one coordinate must not merge");

    match error {
        crate::ResolveError::ConflictingResolvedPomBytes { coord, .. } => {
            assert_eq!(coord, "com.example:b:2.0");
        }
        other => panic!("expected ConflictingResolvedPomBytes, got {other:?}"),
    }
}

/// Negative control for the check above: identical bytes from two id-less
/// observations are not a conflict, and stay one entry.
#[test]
fn merged_support_provenance_accepts_repeated_identical_observations() {
    let merged = super::merge_support_pom_provenance(vec![
        ("com.example:b:2.0".to_string(), support_provenance("", 'b')),
        ("com.example:b:2.0".to_string(), support_provenance("", 'b')),
    ])
    .expect("identical observations merge");

    assert_eq!(
        merged,
        vec![("com.example:b:2.0".to_string(), support_provenance("", 'b'))]
    );
}

mod stall_watchdog {
    use std::sync::Arc;
    use std::time::Duration;

    use super::super::{WorkPhase, WorkspaceProgress, watch_for_stall};
    use crate::ResolveError;

    #[tokio::test]
    async fn fires_when_nothing_makes_progress_and_names_the_stuck_modules() {
        let progress = Arc::new(WorkspaceProgress::new());
        progress.enter(1, "beta/pom.xml", WorkPhase::Graph);
        progress.enter(0, "alpha/pom.xml", WorkPhase::ArtifactPopulation);

        let stalled = tokio::time::timeout(
            Duration::from_secs(10),
            watch_for_stall(Arc::clone(&progress), Duration::from_millis(200)),
        )
        .await
        .expect("the watchdog must fire on its own");

        match stalled {
            ResolveError::WorkspaceStalled { modules, .. } => {
                // Ordered by module index, not by arrival, and each entry
                // says which phase it was wedged in.
                assert_eq!(
                    modules,
                    "alpha/pom.xml (artifact population), beta/pom.xml (graph)"
                );
            }
            other => panic!("expected WorkspaceStalled, got {other:?}"),
        }
    }

    /// The watchdog watches progress events, never elapsed time, so work that
    /// is slow but alive — a big reactor on a slow mirror — never trips it.
    #[tokio::test]
    async fn never_fires_while_progress_keeps_landing() {
        let progress = Arc::new(WorkspaceProgress::new());
        progress.enter(0, "alpha/pom.xml", WorkPhase::Graph);

        let window = Duration::from_millis(200);
        let ticker = {
            let progress = Arc::clone(&progress);
            tokio::spawn(async move {
                // Well past the window, one event per sub-window.
                for _ in 0..30 {
                    tokio::time::sleep(window / 4).await;
                    progress.note();
                }
            })
        };

        let fired = tokio::time::timeout(window * 6, watch_for_stall(progress, window)).await;
        assert!(
            fired.is_err(),
            "a resolution that keeps raising events must not be declared stalled: {fired:?}"
        );
        ticker.abort();
    }

    #[test]
    fn a_module_that_finishes_leaves_the_in_flight_set() {
        let progress = WorkspaceProgress::new();
        progress.enter(0, "alpha/pom.xml", WorkPhase::Graph);
        progress.enter(1, "beta/pom.xml", WorkPhase::Graph);
        progress.leave(0);
        assert_eq!(progress.stuck_modules(), "beta/pom.xml (graph)");
    }

    /// The support-POM flush belongs to the reactor, not to any one module,
    /// and runs between the graph phase and artifact population. It registers
    /// under a key that sorts after every module index, so a stall report that
    /// spans both reads in execution order.
    #[test]
    fn the_support_pom_flush_is_named_after_the_modules() {
        let progress = WorkspaceProgress::new();
        progress.enter(0, "alpha/pom.xml", WorkPhase::Graph);
        progress.enter(
            super::super::REACTOR_WIDE,
            "reactor",
            WorkPhase::SupportPomFlush,
        );
        assert_eq!(
            progress.stuck_modules(),
            "alpha/pom.xml (graph), reactor (support POM flush)"
        );
    }
}
