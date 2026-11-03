use crate::Workspace;
use crate::context::ResolveContext;
use rv_config::{Config, ResolvedPaths};
use rv_lock::Platform;
use rv_maven_types::{ArtifactCoord, BlobId, Coord};
use rv_store::Store;
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// The one-module reactor of the POM at `pom_path`, or, when discovery
/// refuses that POM, a reactor rooted at its directory with no modules, so
/// the resolver's own checks report the problem.
fn lone_module(pom_path: &Path) -> Arc<Workspace> {
    let directory = pom_path.parent().expect("POM directory");
    Arc::new(
        Workspace::discover(directory).unwrap_or_else(|_| Workspace::without_modules(directory)),
    )
}

fn offline_resolver(project_root: &Path, store_dir: &Path) -> super::PlatformResolver {
    let paths = ResolvedPaths::for_testing().expect("paths");
    let config = Config::for_testing_with_repos(project_root.to_path_buf(), paths, Vec::new());
    let store = Arc::new(Store::open(store_dir).expect("store"));
    let platform = Platform::new("linux", "x86_64").unwrap();
    let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
    super::PlatformResolver::new(ctx)
}

async fn load_root(
    pom: &str,
    files: &[(&str, &str)],
) -> (
    tempfile::TempDir,
    crate::error::Result<(Coord, rv_maven_model::Project, Vec<rv_repo::Repository>)>,
) {
    let dir = tempfile::tempdir().unwrap();
    for (path, contents) in files {
        let path = dir.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    let pom_path = dir.path().join("pom.xml");
    fs::write(&pom_path, pom).unwrap();
    let resolver = offline_resolver(dir.path(), &dir.path().join("store"));
    let loaded = resolver
        .load_root_project(&pom_path, &[], lone_module(&pom_path), None, None)
        .await
        .map(|(coord, project, repos, _)| (coord, project, repos));
    (dir, loaded)
}

mod workspace_resolution {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Once};

    use rv_config::{Config, RepoConfig, ResolvedPaths};
    use rv_lock::Platform;
    use rv_maven_types::BlobId;
    use rv_repo::{RepoClient, Repository};
    use rv_store::Store;
    use rv_test_support::fixtures;
    use rv_test_support::http::{Response, StubServer};

    use super::ResolveContext;
    use crate::resolver::PlatformResolver;
    use crate::resolver::pom_source::MemoryPomSource;
    use crate::{ResolveError, Workspace};

    fn fixture(name: &str) -> PathBuf {
        fixtures::path("reactor-resolution").join(name)
    }

    /// Directories a `fixture` call below opens. A new directory must fail
    /// here until a test names it.
    fn reactor_resolution_dirs() -> Vec<String> {
        let mut names = fixtures::quoted_after(include_str!("tests.rs"), concat!("fixture", "("));
        names.sort();
        names.dedup();
        names
    }

    #[test]
    fn every_reactor_resolution_directory_is_used() {
        let names = reactor_resolution_dirs();
        let dirs: Vec<&str> = names.iter().map(String::as_str).collect();
        let root = fixtures::path("reactor-resolution");
        fixtures::assert_children(&root, &dirs, &[]);
        for name in &names {
            assert!(
                root.join(name).join("pom.xml").is_file(),
                "{name}: pom.xml is missing"
            );
        }
    }

    fn ensure_crypto_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn spawn_repository_with_routes(routes: HashMap<String, Vec<u8>>) -> (String, StubServer) {
        let server = StubServer::start(move |request| {
            routes.get(&request.path).map_or_else(
                || Response::new(404, ""),
                |body| Response::new(200, body.clone()),
            )
        });
        (format!("http://{}/", server.addr()), server)
    }

    fn pom(group_id: &str, artifact_id: &str, version: &str, rest: &str) -> Vec<u8> {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>{group_id}</groupId>\
             <artifactId>{artifact_id}</artifactId><version>{version}</version>{rest}</project>"
        )
        .into_bytes()
    }

    fn metadata(artifact_id: &str) -> Vec<u8> {
        format!(
            "<metadata><groupId>com.example</groupId><artifactId>{artifact_id}</artifactId>\
             <versioning><latest>2</latest><release>2</release>\
             <versions><version>2</version></versions></versioning></metadata>"
        )
        .into_bytes()
    }

    fn repository_routes() -> HashMap<String, Vec<u8>> {
        let mut routes = HashMap::new();
        for (group, artifact, version) in [
            ("org.external", "leaf", "1"),
            ("com.example", "lib", "2"),
            ("com.example", "dynamic-lib", "2"),
            ("org.vendor", "only-here", "1"),
        ] {
            let base = format!(
                "/{}/{artifact}/{version}/{artifact}-{version}",
                group.replace('.', "/")
            );
            routes.insert(format!("{base}.pom"), pom(group, artifact, version, ""));
            routes.insert(
                format!("{base}.jar"),
                format!("{artifact} jar").into_bytes(),
            );
        }
        for artifact in ["lib", "dynamic-lib"] {
            routes.insert(
                format!("/com/example/{artifact}/maven-metadata.xml"),
                metadata(artifact),
            );
        }
        routes
    }

    fn spawn_repository() -> (String, StubServer) {
        spawn_repository_with_routes(repository_routes())
    }

    fn repo_config(url: &str) -> RepoConfig {
        let mut repo = RepoConfig::new(Some("fixture"), url);
        repo.releases = Some(true);
        repo.snapshots = Some(true);
        repo
    }

    async fn resolver(
        project_root: &Path,
        repo_url: Option<&str>,
        offline: bool,
        initial_repositories: bool,
    ) -> (PlatformResolver, tempfile::TempDir) {
        ensure_crypto_provider();
        let paths = ResolvedPaths::for_testing().expect("paths");
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
        (PlatformResolver::new(context), store_dir)
    }

    const MEMORY_REPO: &str = "https://repo.example/maven2/";

    fn memory_resolver(
        project_root: &Path,
        files: &HashMap<String, Vec<u8>>,
    ) -> (PlatformResolver, tempfile::TempDir) {
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config = Config::for_testing_with_repos(
            project_root.to_path_buf(),
            paths,
            vec![repo_config(MEMORY_REPO)],
        );
        let source = MemoryPomSource::new(config.security.clone()).with_files(MEMORY_REPO, files);
        let repos = config.repositories().iter().map(Repository::from).collect();
        let store_dir = tempfile::tempdir().expect("store tempdir");
        let store = Arc::new(Store::open(store_dir.path()).expect("store"));
        let platform = Platform::new("linux", "x86_64").expect("platform");
        let context = ResolveContext::new(config, repos, store, platform, None)
            .with_pom_source(Arc::new(source));
        (PlatformResolver::new(context), store_dir)
    }

    async fn resolve_graph(
        resolver: &PlatformResolver,
        workspace: &Workspace,
        pom_path: &str,
    ) -> Result<crate::graph::Graph, ResolveError> {
        resolver
            .resolve_graph_internal(
                &workspace.root().join(pom_path),
                Arc::new(workspace.clone()),
                None,
            )
            .await
            .map(|pending| pending.graph)
    }

    async fn resolve_module(
        resolver: &PlatformResolver,
        workspace: &Workspace,
        pom_path: &str,
    ) -> Result<crate::ModuleResolution, ResolveError> {
        resolver
            .resolve_internal(
                &workspace.root().join(pom_path),
                Arc::new(workspace.clone()),
                None,
            )
            .await
    }

    #[tokio::test]
    async fn classified_snapshot_resolves_and_restores_its_own_pom_build() {
        use crate::lock::{PlatformModel, assemble};
        use rv_lock::{LockResolution, Lockfile};
        use rv_maven_types::{ArtifactCoord, SnapshotStamp};

        for extra_pom in [false, true] {
            let (dir, workspace) = reactor(&[(
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>root</artifactId><version>1</version><dependencies>\
                <dependency><groupId>p</groupId><artifactId>nat</artifactId><version>1.0-SNAPSHOT</version></dependency>\
                <dependency><groupId>p</groupId><artifactId>nat</artifactId><version>1.0-SNAPSHOT</version><classifier>linux</classifier></dependency>\
                </dependencies></project>",
            )]);
            let repo = dir.path().join("repo/p/nat/1.0-SNAPSHOT");
            std::fs::create_dir_all(&repo).unwrap();
            let build1 = "1.0-20261012.010101-1";
            let build2 = "1.0-20261012.010101-2";
            let pom = pom("p", "nat", "1.0-SNAPSHOT", "");
            std::fs::write(repo.join(format!("nat-{build1}.pom")), &pom).unwrap();
            std::fs::write(repo.join(format!("nat-{build1}.jar")), b"main jar").unwrap();
            std::fs::write(repo.join(format!("nat-{build2}-linux.jar")), b"linux jar").unwrap();
            if extra_pom {
                std::fs::write(repo.join(format!("nat-{build2}.pom")), b"<project/>").unwrap();
            }
            std::fs::write(repo.join("maven-metadata.xml"), format!(
                "<metadata><version>1.0-SNAPSHOT</version><versioning><snapshotVersions>\
                 <snapshotVersion><extension>pom</extension><value>{build1}</value></snapshotVersion>\
                 <snapshotVersion><extension>jar</extension><value>{build1}</value></snapshotVersion>\
                 <snapshotVersion><extension>jar</extension><classifier>linux</classifier><value>{build2}</value></snapshotVersion>\
                 </snapshotVersions></versioning></metadata>"
            )).unwrap();
            // The workspace root is canonical, as the URL a project declares
            // through `${project.basedir}` is.
            let url = reqwest::Url::from_directory_path(workspace.root().join("repo"))
                .unwrap()
                .to_string();
            let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;
            let result = resolver.resolve_workspace(&workspace).await.unwrap();
            let hashes = Default::default();
            let mut lock = assemble(
                &resolver.ctx.config,
                vec![(
                    PlatformModel {
                        active_profiles: &[],
                        pom_hashes: &hashes,
                        whole_reactor_pom_hashes: &hashes,
                    },
                    result,
                )],
            )
            .unwrap()
            .lock;
            lock.config_hash = Some("b".repeat(64));
            lock.resolution = LockResolution::default();
            lock.relativize_origins(&rv_lock::LockOrigins::for_root(dir.path()))
                .unwrap();
            let path = dir.path().join("raeva.lock");
            lock.write_atomic(&path).unwrap();
            let lock = Lockfile::read(&path).unwrap();
            let rows = &lock.platforms[0].artifacts;
            assert_eq!(rows.len(), 2);
            for row in rows {
                assert_eq!(row.pom_gav().version(), build1);
                assert_eq!(row.pom_sha256, Some(BlobId::from_bytes(&pom)));
                if row.coordinate.classifier().is_some() {
                    assert_eq!(row.file_version(), build2);
                    assert_eq!(row.pom_snapshot, SnapshotStamp::of_version(build1));
                } else {
                    assert_eq!(row.file_version(), build1);
                    assert!(row.pom_snapshot.is_none());
                }
            }
            let pins = lock.pinned_paths();
            assert_eq!(
                pins.get(&format!("p/nat/1.0-SNAPSHOT/nat-{build1}.pom"))
                    .map(|(pin, _)| pin),
                Some(&rv_maven_types::Digest::Sha256(BlobId::from_bytes(&pom)))
            );
            assert!(!pins.contains_key(&format!("p/nat/1.0-SNAPSHOT/nat-{build2}.pom")));
            let empty = Store::open(&dir.path().join("restored")).unwrap();
            let client = RepoClient::new(&resolver.ctx.config).await.unwrap();
            let contexts = [rv_repo::RestoreContext {
                config: &resolver.ctx.config,
                client: &client,
                platforms: std::slice::from_ref(&lock.platforms[0].platform),
                trusted_repositories: &[],
            }];
            let restored = rv_repo::ensure_artifacts(&empty, &lock, &contexts)
                .await
                .unwrap();
            assert_eq!(restored.len(), 2);
            for result in restored {
                result.result.unwrap();
            }
            for (version, classifier, bytes) in [
                (build1, None, b"main jar".as_slice()),
                (build2, Some("linux"), b"linux jar".as_slice()),
            ] {
                let key = ArtifactCoord::new("p", "nat", version, "jar", classifier);
                assert_eq!(
                    empty.lookup_artifact(&key).await.unwrap(),
                    Some(BlobId::from_bytes(bytes))
                );
            }
            let key = ArtifactCoord::new("p", "nat", build1, "pom", None);
            assert_eq!(
                empty.lookup_artifact(&key).await.unwrap(),
                Some(BlobId::from_bytes(&pom))
            );
        }
    }

    fn node_by_artifact<'a>(
        graph: &'a crate::graph::Graph,
        artifact_id: &str,
    ) -> (petgraph::graph::NodeIndex, &'a crate::graph::Node) {
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

    fn has_artifact(graph: &crate::graph::Graph, artifact_id: &str) -> bool {
        graph.node_indices().any(|index| {
            graph
                .node(index)
                .is_some_and(|node| node.coord.artifact_id.as_str() == artifact_id)
        })
    }

    fn reactor(files: &[(&str, &str)]) -> (tempfile::TempDir, Workspace) {
        let dir = tempfile::tempdir().expect("tempdir");
        for (path, contents) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
            std::fs::write(path, contents).expect("write file");
        }
        let workspace = Workspace::discover(dir.path()).expect("workspace");
        (dir, workspace)
    }

    /// A POM for the classifier likes tests: `artifact` in group `t`, under
    /// the reactor parent `parent`, aggregating `modules`, with `likes` as
    /// its `os.detection.classifierWithLikes` and `body` after that.
    fn likes_pom(
        artifact: &str,
        parent: Option<&str>,
        modules: &[&str],
        likes: Option<&str>,
        body: &str,
    ) -> String {
        let parent = parent.map_or(String::new(), |parent| {
            format!(
                "<parent><groupId>t</groupId><artifactId>{parent}</artifactId><version>1</version>\
                 <relativePath>../pom.xml</relativePath></parent>"
            )
        });
        let modules: String = modules
            .iter()
            .map(|module| format!("<module>{module}</module>"))
            .collect();
        let likes = likes.map_or(String::new(), |likes| {
            format!(
                "<properties><os.detection.classifierWithLikes>{likes}\
                 </os.detection.classifierWithLikes></properties>"
            )
        });
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{parent}<groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version><packaging>pom</packaging>\
             <modules>{modules}</modules>{likes}{body}</project>"
        )
    }

    /// The classifier likes `resolver` finds for `workspace`.
    async fn likes_of(resolver: &PlatformResolver, workspace: &Arc<Workspace>) -> Option<String> {
        let likes = resolver
            .classifier_likes(workspace, &Arc::default())
            .await?;
        likes.likes.value().map(str::to_string)
    }

    fn reactor_dependency(artifact: &str, version: &str) -> String {
        format!(
            "<dependencies><dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version><type>pom</type></dependency></dependencies>"
        )
    }

    /// A resolver for `workspace` on `platform`, for the target `jdk` when
    /// set, on a Linux machine whose release is Ubuntu, like Debian, serving
    /// `files`.
    fn ubuntu_resolver(
        workspace: &Workspace,
        files: &HashMap<String, Vec<u8>>,
        platform: &str,
        jdk: Option<&str>,
    ) -> (PlatformResolver, tempfile::TempDir) {
        let host = rv_maven_model::HostSnapshot::for_testing(&[])
            .with_os_release("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=24.04\n");
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config = Config::for_testing_with_repos(
            workspace.root().to_path_buf(),
            paths,
            vec![repo_config(MEMORY_REPO)],
        )
        .with_host(host);
        let source = MemoryPomSource::new(config.security.clone()).with_files(MEMORY_REPO, files);
        let repos = config.repositories().iter().map(Repository::from).collect();
        let store_dir = tempfile::tempdir().expect("store tempdir");
        let store = Arc::new(Store::open(store_dir.path()).expect("store"));
        let (os, arch) = platform.split_once('-').expect("platform");
        let mut platform = Platform::new(os, arch).expect("platform");
        if let Some(jdk) = jdk {
            platform = platform.with_jdk(jdk);
        }
        let context = ResolveContext::new(config, repos, store, platform, None)
            .with_pom_source(Arc::new(source));
        (PlatformResolver::new(context), store_dir)
    }

    /// os-maven-plugin reads `os.detection.classifierWithLikes` from the
    /// project Maven 3.9.12 sorts first, else from the user properties, as
    /// recorded for these reactors: a module's own value counts only when it
    /// is that project. A project's value wins over a `-D` value, even when
    /// empty.
    #[tokio::test]
    async fn classifier_likes_come_from_the_first_sorted_project() {
        let user = ".mvn/maven.config";
        type Files<'a> = Vec<(&'a str, String)>;
        let cases: Vec<(&str, Files<'_>, Option<&str>)> = vec![
            (
                "the root parent is first",
                vec![
                    (
                        "pom.xml",
                        likes_pom("root", None, &["m1"], Some("root"), ""),
                    ),
                    (
                        "m1/pom.xml",
                        likes_pom("m1", Some("root"), &[], Some("m1"), ""),
                    ),
                ],
                Some("root"),
            ),
            (
                "a first module without a parent is first",
                vec![
                    (
                        "pom.xml",
                        likes_pom("root", None, &["bom", "m1"], Some("root"), ""),
                    ),
                    ("bom/pom.xml", likes_pom("bom", None, &[], None, "")),
                    ("m1/pom.xml", likes_pom("m1", Some("root"), &[], None, "")),
                ],
                None,
            ),
            (
                "the same module listed second is not",
                vec![
                    (
                        "pom.xml",
                        likes_pom("root", None, &["m1", "bom"], Some("root"), ""),
                    ),
                    ("bom/pom.xml", likes_pom("bom", None, &[], None, "")),
                    ("m1/pom.xml", likes_pom("m1", Some("root"), &[], None, "")),
                ],
                Some("root"),
            ),
            (
                "the first dependency leads before the parent",
                vec![
                    (
                        "pom.xml",
                        likes_pom("root", None, &["m1", "m2"], Some("root"), ""),
                    ),
                    (
                        "m1/pom.xml",
                        likes_pom(
                            "m1",
                            Some("root"),
                            &[],
                            None,
                            &reactor_dependency("m2", "[1,2)"),
                        ),
                    ),
                    ("m2/pom.xml", likes_pom("m2", None, &[], Some("m2"), "")),
                ],
                Some("m2"),
            ),
            (
                "the chain goes through nested modules",
                vec![
                    ("pom.xml", likes_pom("root", None, &["a"], Some("root"), "")),
                    (
                        "a/pom.xml",
                        likes_pom("a", Some("root"), &["a1"], Some("a"), ""),
                    ),
                    (
                        "a/a1/pom.xml",
                        likes_pom("a1", Some("a"), &[], Some("a1"), ""),
                    ),
                ],
                Some("root"),
            ),
            (
                "a user property stands in",
                vec![
                    ("pom.xml", likes_pom("root", None, &["m1"], None, "")),
                    (
                        "m1/pom.xml",
                        likes_pom("m1", Some("root"), &[], Some("m1"), ""),
                    ),
                    (
                        user,
                        "-Dos.detection.classifierWithLikes=user\n".to_string(),
                    ),
                ],
                Some("user"),
            ),
            (
                "the project wins over a user property",
                vec![
                    ("pom.xml", likes_pom("root", None, &["m1"], Some(""), "")),
                    ("m1/pom.xml", likes_pom("m1", Some("root"), &[], None, "")),
                    (
                        user,
                        "-Dos.detection.classifierWithLikes=user\n".to_string(),
                    ),
                ],
                Some(""),
            ),
        ];
        for (name, files, expected) in cases {
            let files: Vec<(&str, &str)> = files
                .iter()
                .map(|(path, text)| (*path, text.as_str()))
                .collect();
            let (_dir, workspace) = reactor(&files);
            let workspace = Arc::new(workspace);
            let (resolver, _store) =
                ubuntu_resolver(&workspace, &HashMap::new(), "linux-x86_64", None);
            assert_eq!(
                likes_of(&resolver, &workspace).await.as_deref(),
                expected,
                "{name}"
            );
            let (resolver, _store) =
                ubuntu_resolver(&workspace, &HashMap::new(), "macos-aarch64", None);
            assert!(
                (resolver.classifier_likes(&workspace, &Arc::default()).await).is_none(),
                "{name}"
            );
        }
    }

    /// The projects on the way to the first sorted one import the same BOM,
    /// which is built once for all of them unless its build logs, as each
    /// project then logs it as its own.
    #[test]
    fn the_first_sorted_project_search_builds_a_shared_bom_once() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let import = "<dependencyManagement><dependencies><dependency><groupId>t</groupId>\
                      <artifactId>bom</artifactId><version>1</version><type>pom</type>\
                      <scope>import</scope></dependency></dependencies></dependencyManagement>";
        let root = likes_pom("root", None, &["m1", "m2"], Some("root"), import);
        let m1 = likes_pom(
            "m1",
            Some("root"),
            &[],
            None,
            &reactor_dependency("m2", "1"),
        );
        let m2 = likes_pom("m2", Some("root"), &[], None, "");
        let (_dir, workspace) = reactor(&[
            ("pom.xml", root.as_str()),
            ("m1/pom.xml", m1.as_str()),
            ("m2/pom.xml", m2.as_str()),
        ]);
        let workspace = Arc::new(workspace);
        for (scope, builds, warnings) in [("test", 1, 0), ("weird", 3, 3)] {
            let bom = format!(
                "<project><groupId>t</groupId><artifactId>bom</artifactId><version>1</version>\
                 <packaging>pom</packaging><dependencies><dependency><groupId>t</groupId>\
                 <artifactId>x</artifactId><version>1</version><scope>{scope}</scope>\
                 </dependency></dependencies></project>"
            );
            let files = HashMap::from([("t/bom/1/bom-1.pom".to_string(), bom.into_bytes())]);
            let host = rv_maven_model::HostSnapshot::for_testing(&[])
                .with_os_release("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=24.04\n");
            let paths = ResolvedPaths::for_testing().expect("paths");
            let config = Config::for_testing_with_repos(
                workspace.root().to_path_buf(),
                paths,
                vec![repo_config(MEMORY_REPO)],
            )
            .with_host(host);
            let source = Arc::new(
                MemoryPomSource::new(config.security.clone()).with_files(MEMORY_REPO, &files),
            );
            let repos = config.repositories().iter().map(Repository::from).collect();
            let store_dir = tempfile::tempdir().expect("store tempdir");
            let store = Arc::new(Store::open(store_dir.path()).expect("store"));
            let platform = Platform::new("linux", "x86_64").expect("platform");
            let context = ResolveContext::new(config, repos, store, platform, None)
                .with_pom_source(source.clone());
            let resolver = PlatformResolver::new(context);
            let log = rv_test_support::capture_warnings(|| {
                let likes = runtime.block_on(likes_of(&resolver, &workspace));
                assert_eq!(likes.as_deref(), Some("root"));
            });
            let bom_reads = (source.requests().iter())
                .filter(|request| request.ends_with("bom-1.pom"))
                .count();
            assert_eq!(bom_reads, builds, "scope {scope}");
            let warned = log.matches("unknown dependency scope").count();
            assert_eq!(warned, warnings, "scope {scope}");
        }
    }

    /// A command-line `-D` list comes after `.mvn/maven.config`, so it wins
    /// where the first project sets none.
    #[tokio::test]
    async fn command_line_classifier_likes_win_over_maven_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        for (path, contents) in [
            ("pom.xml", likes_pom("root", None, &["m1"], None, "")),
            ("m1/pom.xml", likes_pom("m1", Some("root"), &[], None, "")),
            (
                ".mvn/maven.config",
                "-Dos.detection.classifierWithLikes=fedora\n".to_string(),
            ),
        ] {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
            std::fs::write(path, contents).expect("write file");
        }
        let mut command_line = rv_config::maven_config::CommandLine::default();
        command_line
            .defines
            .push("os.detection.classifierWithLikes=debian".to_string());
        let environment = rv_maven_model::ModelEnvironment::builder()
            .platform("linux", "x86_64")
            .build();
        let workspace = Arc::new(
            Workspace::discover_with_context(
                dir.path(),
                rv_maven_model::ActivationContext::new(environment),
                &command_line,
            )
            .expect("workspace"),
        );
        let (resolver, _store) = ubuntu_resolver(&workspace, &HashMap::new(), "linux-x86_64", None);
        assert_eq!(
            likes_of(&resolver, &workspace).await.as_deref(),
            Some("debian")
        );
    }

    /// Each JDK section reads the likes of the first project's profiles for
    /// its own JDK.
    #[tokio::test]
    async fn classifier_likes_follow_the_target_jdk() {
        let profile = "<profiles><profile><id>jdk21</id><activation><jdk>[21,)</jdk>\
                       </activation><properties><os.detection.classifierWithLikes>debian\
                       </os.detection.classifierWithLikes></properties></profile></profiles>";
        let files = [
            (
                "pom.xml",
                likes_pom("root", None, &["m1"], Some("none"), profile),
            ),
            ("m1/pom.xml", likes_pom("m1", Some("root"), &[], None, "")),
        ];
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, text)| (*path, text.as_str()))
            .collect();
        let (_dir, workspace) = reactor(&files);
        let workspace = Arc::new(workspace);
        for (jdk, expected) in [("17", "none"), ("21", "debian")] {
            let (resolver, _store) =
                ubuntu_resolver(&workspace, &HashMap::new(), "linux-x86_64", Some(jdk));
            assert_eq!(
                likes_of(&resolver, &workspace).await.as_deref(),
                Some(expected),
                "JDK {jdk}"
            );
        }
    }

    /// The first project's classifier likes give every module and every
    /// dependency's POM the classifier suffix, whatever list a module sets.
    #[tokio::test]
    async fn classifier_likes_apply_to_every_model_of_the_reactor() {
        let native = |artifact: &str| {
            format!(
                "<dependencies><dependency><groupId>g</groupId><artifactId>{artifact}</artifactId>\
                 <version>1</version><classifier>${{os.detected.classifier}}</classifier>\
                 </dependency><dependency><groupId>g</groupId><artifactId>lib</artifactId>\
                 <version>1</version></dependency></dependencies>"
            )
        };
        let files = [
            (
                "pom.xml",
                likes_pom("root", None, &["m1", "m2"], Some("fedora, debian"), ""),
            ),
            (
                "m1/pom.xml",
                likes_pom("m1", Some("root"), &[], None, &native("n1")),
            ),
            (
                "m2/pom.xml",
                likes_pom("m2", Some("root"), &[], Some("none"), &native("n2")),
            ),
        ];
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, text)| (*path, text.as_str()))
            .collect();
        let (_dir, workspace) = reactor(&files);
        let mut routes = HashMap::new();
        for artifact in ["n1", "n2", "n3"] {
            routes.insert(
                format!("/g/{artifact}/1/{artifact}-1.pom"),
                pom("g", artifact, "1", ""),
            );
        }
        routes.insert(
            "/g/lib/1/lib-1.pom".to_string(),
            pom(
                "g",
                "lib",
                "1",
                "<dependencies><dependency><groupId>g</groupId><artifactId>n3</artifactId>\
                 <version>1</version><classifier>${os.detected.classifier}</classifier>\
                 </dependency></dependencies>",
            ),
        );
        let workspace = Arc::new(workspace);
        let (resolver, _store) = ubuntu_resolver(&workspace, &routes, "linux-x86_64", None);
        let likes =
            (resolver.classifier_likes(&workspace, &Arc::default()).await).map(|likes| likes.likes);
        let module = PlatformResolver::new(resolver.ctx.clone().with_classifier_likes(likes));
        for (path, own) in [("m1/pom.xml", "n1"), ("m2/pom.xml", "n2")] {
            let graph = resolve_graph(&module, &workspace, path)
                .await
                .unwrap_or_else(|error| panic!("{path}: {error}"));
            for artifact in [own, "n3"] {
                let classifier = node_by_artifact(&graph, artifact)
                    .1
                    .coord
                    .classifier
                    .clone();
                assert_eq!(
                    classifier.as_deref(),
                    Some("linux-x86_64-debian"),
                    "{path} {artifact}"
                );
            }
        }
    }

    /// Maven 3.9 reads a reactor project's parents before it indexes the
    /// reactor, so a `<parent>` with an empty `<relativePath/>` is looked up
    /// in a repository even when another module has its coordinates. With no
    /// repository holding it, Maven fails with "Non-resolvable parent POM".
    #[tokio::test]
    async fn reactor_parent_is_not_taken_from_another_module() {
        let (_dir, workspace) = reactor(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>parent</module><module>child</module></modules></project>",
            ),
            (
                "parent/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
                 </project>",
            ),
            (
                "child/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
                 <artifactId>parent</artifactId><version>1</version><relativePath/></parent>\
                 <artifactId>child</artifactId></project>",
            ),
        ]);
        let (resolver, _store) = resolver(workspace.root(), None, true, false).await;

        let error = resolve_module(&resolver, &workspace, "child/pom.xml")
            .await
            .expect_err("the parent is in no repository");
        assert!(error.to_string().contains("t:parent:1"), "{error}");
    }

    /// How a dependency on a reactor module is answered: by the module when
    /// it satisfies the request, otherwise by a repository.
    #[tokio::test]
    async fn reactor_modules_compete_with_repository_candidates() {
        let workspace = Workspace::discover(fixture("basic")).expect("workspace");
        let (url, _server) = spawn_repository();
        let (online, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let app = resolve_module(&online, &workspace, "app/pom.xml")
            .await
            .expect("resolve app");
        let (lib_index, lib) = node_by_artifact(&app.graph, "lib");
        let (_, leaf) = node_by_artifact(&app.graph, "leaf");
        assert_eq!(lib.workspace_module.as_deref(), Some("lib/pom.xml"));
        assert!(lib.repo_url.is_none() && lib.checksum.is_none());
        assert!(leaf.workspace_module.is_none() && leaf.repo_url.is_some());
        assert!(
            app.graph.edges(lib_index).any(|(_, target, _)| app
                .graph
                .node(target)
                .is_some_and(|node| node.coord.artifact_id.as_str() == "leaf")),
            "the sibling model's outgoing edge to its external dependency must survive"
        );

        let bom_app = resolve_module(&online, &workspace, "bom-app/pom.xml")
            .await
            .expect("resolve sibling BOM");
        assert_eq!(
            node_by_artifact(&bom_app.graph, "leaf")
                .1
                .coord
                .version
                .as_str(),
            "1"
        );

        let classified = resolve_module(&online, &workspace, "classifier-app/pom.xml")
            .await
            .expect("resolve classifier app");
        let (_, lib) = node_by_artifact(&classified.graph, "lib");
        assert_eq!(lib.workspace_module.as_deref(), Some("lib/pom.xml"));
        assert_eq!(lib.coord.packaging.as_deref(), None);
        assert_eq!(lib.coord.classifier.as_deref(), Some("tests"));

        let (offline, _store) = resolver(workspace.root(), None, true, true).await;
        let error = resolve_module(&offline, &workspace, "mismatch-app/pom.xml")
            .await
            .expect_err("workspace lib:1 must not satisfy exact lib:2");
        assert!(error.to_string().contains("offline mode"), "{error}");

        // Without a client or metadata: `LATEST`, an exact snapshot and a
        // `${revision}` version find the module.
        let (local, _store) = resolver(workspace.root(), None, false, false).await;
        for (module, artifact, version) in [
            ("dynamic-app", "dynamic-lib", "1"),
            ("snapshot-app", "snapshot", "1-SNAPSHOT"),
            ("revision-app", "revision-child", "1.0"),
        ] {
            let graph = resolve_graph(&local, &workspace, &format!("{module}/pom.xml"))
                .await
                .unwrap_or_else(|error| panic!("{module}: {error}"));
            let (_, node) = node_by_artifact(&graph, artifact);
            let expected = format!("{artifact}/pom.xml");
            assert_eq!(node.workspace_module.as_deref(), Some(expected.as_str()));
            assert_eq!(node.coord.version.as_str(), version, "{module}");
        }

        // With repository candidates, a range or `LATEST` takes the highest.
        let (memory, _store) = memory_resolver(workspace.root(), &repository_routes());
        for (module, artifact, sibling, version) in [
            ("range-app", "lib", true, "1"),
            ("range-higher-app", "lib", false, "2"),
            ("dynamic-app", "dynamic-lib", false, "2"),
        ] {
            let graph = resolve_graph(&memory, &workspace, &format!("{module}/pom.xml"))
                .await
                .unwrap_or_else(|error| panic!("{module}: {error}"));
            let (_, node) = node_by_artifact(&graph, artifact);
            assert_eq!(node.workspace_module.is_some(), sibling, "{module}");
            assert_eq!(node.repo_url.is_some(), !sibling, "{module}");
            assert_eq!(node.coord.version.as_str(), version, "{module}");
        }
    }

    #[tokio::test]
    async fn workspace_dependency_cycle_is_a_hard_readable_error() {
        let workspace = Workspace::discover(fixture("cycle")).expect("workspace");
        let (resolver, _store) = resolver(workspace.root(), None, false, false).await;

        let error = resolve_module(&resolver, &workspace, "a/pom.xml")
            .await
            .expect_err("dependency cycle must fail");
        assert_eq!(
            error.to_string(),
            "workspace dependency cycle detected: com.example:a -> com.example:b -> com.example:a"
        );
    }

    /// Resolution reads module POMs through `\\?\` paths on Windows but must
    /// interpolate `${project.basedir}` in the plain form, or
    /// `${project.basedir}/marker.txt` names no file and the profile adding
    /// each dependency stays off. `app` is the module being resolved and
    /// `lib` a sibling reached as a dependency.
    #[tokio::test]
    async fn module_basedir_is_plain_for_file_activation() {
        let module = |artifact_id: &str, dependency: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>{artifact_id}</artifactId><version>1</version><profiles><profile>\
                 <id>marked</id><activation><file>\
                 <exists>${{project.basedir}}/marker.txt</exists></file></activation>\
                 <dependencies><dependency><groupId>t</groupId>\
                 <artifactId>{dependency}</artifactId><version>1</version></dependency>\
                 </dependencies></profile></profiles></project>"
            )
        };
        let (app, lib) = (module("app", "lib"), module("lib", "util"));
        let (_dir, workspace) = reactor(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>app</module><module>lib</module><module>util</module>\
                 </modules></project>",
            ),
            ("app/pom.xml", &app),
            ("app/marker.txt", ""),
            ("lib/pom.xml", &lib),
            ("lib/marker.txt", ""),
            (
                "util/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>util</artifactId><version>1</version></project>",
            ),
        ]);
        let (resolver, _store) = resolver(workspace.root(), None, false, false).await;

        let result = resolve_module(&resolver, &workspace, "app/pom.xml")
            .await
            .expect("resolve app");
        assert!(has_artifact(&result.graph, "lib") && has_artifact(&result.graph, "util"));
    }

    /// A reactor parent may import a sibling BOM through `${project.version}`.
    /// The BOM's parent uses `${revision}` from the root, so lookup needs its reactor identity.
    #[tokio::test]
    async fn sibling_bom_import_with_revision_parent_resolves() {
        let (url, _server) = spawn_repository();
        let parent = "<parent><groupId>t</groupId><artifactId>root</artifactId>\
                      <version>${revision}</version></parent>";
        let (bom, mid) = (
            format!(
                "<project><modelVersion>4.0.0</modelVersion>{parent}<artifactId>bom</artifactId>\
                 <packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
                 <groupId>com.example</groupId><artifactId>lib</artifactId><version>2</version>\
                 </dependency></dependencies></dependencyManagement></project>"
            ),
            format!(
                "<project><modelVersion>4.0.0</modelVersion>{parent}<artifactId>mid</artifactId>\
                 <packaging>pom</packaging><modules><module>leaf</module></modules>\
                 <dependencyManagement><dependencies><dependency><groupId>t</groupId>\
                 <artifactId>bom</artifactId><version>${{project.version}}</version>\
                 <type>pom</type><scope>import</scope></dependency></dependencies>\
                 </dependencyManagement></project>"
            ),
        );
        let (_dir, workspace) = reactor(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>root</artifactId><version>${revision}</version>\
                 <packaging>pom</packaging><properties><revision>1.0-SNAPSHOT</revision>\
                 </properties><modules><module>bom</module><module>mid</module></modules>\
                 </project>",
            ),
            ("bom/pom.xml", &bom),
            ("mid/pom.xml", &mid),
            (
                "mid/leaf/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
                 <artifactId>mid</artifactId><version>${revision}</version></parent>\
                 <artifactId>leaf</artifactId><dependencies><dependency>\
                 <groupId>com.example</groupId><artifactId>lib</artifactId></dependency>\
                 </dependencies></project>",
            ),
        ]);
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let result = resolve_module(&resolver, &workspace, "mid/leaf/pom.xml")
            .await
            .expect("sibling BOM with a ${revision} parent must resolve");
        assert_eq!(
            node_by_artifact(&result.graph, "lib")
                .1
                .coord
                .version
                .as_str(),
            "2"
        );
    }

    /// Maven's descriptor reader fails a dependency only when its parent or
    /// an imported BOM cannot be resolved. Any other model error keeps the
    /// artifact without its transitive dependencies, and a field Maven reads
    /// leniently, in an inactive profile or an exclusion, costs nothing.
    #[tokio::test]
    async fn an_invalid_dependency_pom_drops_its_transitives() {
        let leaf = "<dependency><groupId>org.external</groupId><artifactId>leaf</artifactId>\
                    <version>1</version></dependency>";
        let import = |artifact: &str, version: &str| {
            format!(
                "<dependencyManagement><dependencies><dependency><groupId>org.vendor</groupId>\
                 <artifactId>{artifact}</artifactId>{version}<type>pom</type>\
                 <scope>import</scope></dependency></dependencies></dependencyManagement>"
            )
        };
        let broken = |rest: &str| pom("org.vendor", "broken", "1", rest);
        let invalid = [
            broken(&format!(
                "<dependencies>{leaf}</dependencies><dependencies/>"
            )),
            broken(&format!(
                "<version>1</version><dependencies>{leaf}</dependencies>"
            )),
            broken(&format!(
                "<properties><a>${{b}}</a><b>${{a}}</b></properties><dependencies>{leaf}\
                 <dependency><groupId>o</groupId><artifactId>c</artifactId>\
                 <version>${{a}}</version></dependency></dependencies>"
            )),
            broken(&format!(
                "{}<dependencies>{leaf}</dependencies>",
                import("cycle", "<version>1</version>")
            )),
            broken(&format!(
                "{}<dependencies>{leaf}</dependencies>",
                import("cycle", "")
            )),
            broken(&format!(
                "<dependencies>{leaf}<dependency><groupId>o</groupId><artifactId>api</artifactId>\
                 </dependency></dependencies>"
            )),
            broken(&format!(
                "<properties><empty/></properties><dependencies>{leaf}<dependency>\
                 <groupId>o</groupId><artifactId>api</artifactId><version>${{empty}}</version>\
                 </dependency></dependencies>"
            )),
            broken(&format!(
                "<dependencies>{leaf}<dependency><groupId>jdk.tools</groupId>\
                 <artifactId>jdk.tools</artifactId><version>1.8</version><scope>system</scope>\
                 </dependency></dependencies>"
            )),
            b"<!DOCTYPE html><html><body>Sign in</body></html>".to_vec(),
        ];
        let managed_without_artifact = |activation: &str| {
            broken(&format!(
                "<dependencies>{leaf}</dependencies><profiles><profile><id>p</id>{activation}\
                 <dependencyManagement><dependencies><dependency><groupId>o</groupId>\
                 <version>1</version></dependency></dependencies></dependencyManagement>\
                 </profile></profiles>"
            ))
        };
        let invalid: Vec<Vec<u8>> = invalid
            .into_iter()
            .chain([
                managed_without_artifact(
                    "<activation><activeByDefault>true</activeByDefault></activation>",
                ),
                broken(&format!(
                    "{}<dependencies>{leaf}</dependencies>",
                    import("invalid", "<version>1</version>")
                )),
                broken(
                    "<dependencies><dependency><groupId>org.external</groupId>\
                     <artifactId>leaf</artifactId><version>1</version><type/></dependency>\
                     </dependencies>",
                ),
                broken(&format!(
                    "<dependencies>{leaf}<dependency><groupId>o</groupId>\
                     <artifactId>bad+id</artifactId><version>1</version></dependency>\
                     </dependencies>"
                )),
                broken(&format!(
                    "<dependencies>{leaf}<dependency><groupId>o</groupId><artifactId>t</artifactId>\
                     <version>1</version><systemPath>/opt/unused.jar</systemPath></dependency>\
                     </dependencies>"
                )),
                broken(&format!(
                    "<dependencyManagement><dependencies><dependency><groupId>o</groupId>\
                     <artifactId>t</artifactId><version>1</version>\
                     <systemPath>/opt/unused.jar</systemPath></dependency></dependencies>\
                     </dependencyManagement><dependencies>{leaf}</dependencies>"
                )),
                broken(&format!(
                    "<dependencies>{leaf}<dependency><groupId>o</groupId><artifactId>t</artifactId>\
                     <version>1</version><scope>SYSTEM</scope>\
                     <systemPath>/opt/unused.jar</systemPath></dependency></dependencies>"
                )),
                broken(&format!(
                    "<dependencies>{leaf}<dependency><groupId>o</groupId><artifactId>t</artifactId>\
                     <version>1</version><scope>system</scope>\
                     <systemPath>${{missing}}/x.jar</systemPath></dependency></dependencies>"
                )),
            ])
            .collect();
        let lenient = [
            managed_without_artifact(""),
            broken(&format!(
                "<dependencies>{leaf}<dependency><groupId>o</groupId><artifactId>t</artifactId>\
                 <version>1</version><scope>SYSTEM</scope></dependency></dependencies>"
            )),
            broken(&format!(
                "{}<dependencies>{leaf}</dependencies>",
                import(
                    "fine",
                    "<version>1</version><systemPath>/opt/unused.jar</systemPath>"
                )
            )),
            broken(
                "<dependencies><dependency><groupId>o</groupId><artifactId>t</artifactId>\
                 <version>1</version><exclusions><exclusion><groupId>org.external</groupId>\
                 </exclusion></exclusions></dependency></dependencies>",
            ),
            broken(&format!(
                "<dependencies>{leaf}</dependencies><profiles><profile><id>off</id>\
                 <repositories><repository><id>nowhere</id></repository></repositories>\
                 <dependencies><dependency><groupId>o</groupId></dependency></dependencies>\
                 </profile></profiles>"
            )),
        ];
        let failing = [
            broken(&format!(
                "<parent><groupId>org.vendor</groupId><artifactId>missing</artifactId>\
                 <version>1</version></parent><dependencies>{leaf}</dependencies>"
            )),
            broken(&format!(
                "{}<dependencies>{leaf}</dependencies>",
                import("missing", "<version>1</version>")
            )),
            broken(&format!(
                "{}<dependencies>{leaf}</dependencies>",
                import("missing", "<version>${undefined}</version>")
            )),
        ]
        .map(|pom| (pom, "org.vendor:missing:"));
        let both = |first: &str, second: &str| {
            let imports = format!(
                "{}{}",
                import(first, "<version>1</version>"),
                import(second, "<version>1</version>")
            )
            .replace(
                "</dependencies></dependencyManagement><dependencyManagement><dependencies>",
                "",
            );
            broken(&format!("{imports}<dependencies>{leaf}</dependencies>"))
        };
        let failing = failing.into_iter().chain([
            (both("invalid", "missing"), "org.vendor:missing:"),
            (both("missing", "invalid"), "org.vendor:missing:"),
            (
                broken(&format!(
                    "{}<dependencies>{leaf}</dependencies>",
                    import("missing", "<version>1</version>")
                        .replace("<groupId>org.vendor</groupId>", "<groupId>bad+g</groupId>")
                )),
                "bad+g:missing:1",
            ),
        ]);
        let failing = failing.chain([(
            broken(&format!(
                "<dependencyManagement><dependencies><dependency><groupId>o</groupId>\
                 <artifactId>unused</artifactId><version>1</version><type/></dependency>\
                 </dependencies></dependencyManagement><dependencies>{leaf}</dependencies>"
            )),
            "o:unused: declares an empty <type>",
        )]);
        let app = pom(
            "com.example",
            "app",
            "1",
            "<dependencies><dependency><groupId>org.vendor</groupId>\
             <artifactId>broken</artifactId><version>1</version></dependency></dependencies>",
        );
        let (_dir, workspace) = reactor(&[("pom.xml", std::str::from_utf8(&app).unwrap())]);
        let cases = invalid
            .into_iter()
            .map(|pom| (pom, Ok(false)))
            .chain(lenient.into_iter().map(|pom| (pom, Ok(true))))
            .chain(failing.map(|(pom, message)| (pom, Err(message))));
        for (broken_pom, outcome) in cases {
            let mut routes = HashMap::new();
            routes.insert(
                "/org/vendor/broken/1/broken-1.pom".to_string(),
                broken_pom.clone(),
            );
            for (artifact, rest) in [
                ("cycle", import("cycle", "<version>1</version>")),
                (
                    "invalid",
                    "<dependencies><dependency><groupId>o</groupId><version>1</version>\
                     </dependency></dependencies>"
                        .to_string(),
                ),
                ("t", format!("<dependencies>{leaf}</dependencies>")),
                ("fine", String::new()),
            ] {
                let group = if artifact == "t" { "o" } else { "org.vendor" };
                routes.insert(
                    format!(
                        "/{group}/{artifact}/1/{artifact}-1.pom",
                        group = group.replace('.', "/")
                    ),
                    pom(group, artifact, "1", &rest),
                );
            }
            routes.insert(
                "/org/external/leaf/1/leaf-1.pom".to_string(),
                pom("org.external", "leaf", "1", ""),
            );
            let (resolver, _store) = memory_resolver(workspace.root(), &routes);
            let text = String::from_utf8_lossy(&broken_pom);
            let result = resolve_graph(&resolver, &workspace, "pom.xml").await;
            match outcome {
                Ok(keeps_leaf) => {
                    let graph = result.unwrap_or_else(|error| panic!("{text}: {error}"));
                    assert!(has_artifact(&graph, "broken"), "{text}");
                    assert_eq!(has_artifact(&graph, "leaf"), keeps_leaf, "{text}");
                }
                Err(message) => {
                    let error = result.expect_err(&text);
                    assert!(error.to_string().contains(message), "{error}");
                }
            }
        }
    }

    /// A repository a dependency's POM declares is in the search of its own
    /// subtree, and not of its siblings, whichever POM arrives first.
    #[tokio::test]
    async fn an_admitted_repository_reaches_the_same_models_on_every_schedule() {
        const DECLARED: &str = "https://declared.example/maven2/";
        let app = pom(
            "t",
            "app",
            "1",
            "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>\
             <version>1</version></dependency><dependency><groupId>g</groupId>\
             <artifactId>b</artifactId><version>1</version></dependency></dependencies>",
        );
        let (_dir, workspace) = reactor(&[("pom.xml", std::str::from_utf8(&app).unwrap())]);
        let child_in_a = HashMap::from([
            (
                "/g/a/1/a-1.pom".to_string(),
                pom(
                    "g",
                    "a",
                    "1",
                    &format!(
                        "<repositories><repository><id>declared</id><url>{DECLARED}</url>\
                         </repository></repositories><dependencies><dependency>\
                         <groupId>g</groupId><artifactId>c</artifactId><version>1</version>\
                         </dependency></dependencies>"
                    ),
                ),
            ),
            (
                "/g/c/1/c-1.pom".to_string(),
                b"<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>\
                  <artifactId>p</artifactId><version>1</version></parent>\
                  <artifactId>c</artifactId></project>"
                    .to_vec(),
            ),
            ("/g/b/1/b-1.pom".to_string(), pom("g", "b", "1", "")),
        ]);
        let sibling_needs_declared = HashMap::from([
            (
                "/g/a/1/a-1.pom".to_string(),
                pom(
                    "g",
                    "a",
                    "1",
                    &format!(
                        "<repositories><repository><id>declared</id><url>{DECLARED}</url>\
                         </repository></repositories>"
                    ),
                ),
            ),
            (
                "/g/b/1/b-1.pom".to_string(),
                b"<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>\
                  <artifactId>p</artifactId><version>1</version></parent>\
                  <artifactId>b</artifactId></project>"
                    .to_vec(),
            ),
        ]);
        let declared = HashMap::from([(
            "/g/p/1/p-1.pom".to_string(),
            pom("g", "p", "1", "<packaging>pom</packaging>"),
        )]);
        for slow in ["g/a/1/a-1.pom", "g/b/1/b-1.pom"] {
            for (configured, succeeds) in [(&child_in_a, true), (&sibling_needs_declared, false)] {
                let mut config = Config::for_testing_with_repos(
                    workspace.root().to_path_buf(),
                    ResolvedPaths::for_testing().unwrap(),
                    vec![repo_config(MEMORY_REPO)],
                );
                config.security.transitive_repository_allowlist = vec![DECLARED.to_string()];
                let source = MemoryPomSource::new(config.security.clone())
                    .with_files(MEMORY_REPO, configured)
                    .with_files(DECLARED, &declared)
                    .with_delay(slow, std::time::Duration::from_millis(200));
                let repos = config.repositories().iter().map(Repository::from).collect();
                let store_dir = tempfile::tempdir().unwrap();
                let store = Arc::new(Store::open(store_dir.path()).unwrap());
                let context = ResolveContext::new(
                    config,
                    repos,
                    store,
                    Platform::new("linux", "x86_64").unwrap(),
                    None,
                )
                .with_pom_source(Arc::new(source));
                let result =
                    resolve_graph(&PlatformResolver::new(context), &workspace, "pom.xml").await;
                if succeeds {
                    let graph = result.unwrap_or_else(|error| panic!("{slow} first: {error}"));
                    assert!(has_artifact(&graph, "c"), "{slow} first");
                    assert!(has_artifact(&graph, "b"), "{slow} first");
                } else {
                    assert!(
                        result.is_err(),
                        "{slow} first: sibling must not see a's repo"
                    );
                }
            }
        }
    }

    /// A classifier found with its POM through a dependency's repository and
    /// the main artifact found without one through the root repositories
    /// cannot share one POM pin, whichever path is visited first.
    #[tokio::test]
    async fn classifier_winners_that_disagree_on_a_pom_fail() {
        ensure_crypto_provider();
        let dep = |artifact: &str, classifier: &str| {
            format!(
                "<dependency><groupId>fx</groupId><artifactId>{artifact}</artifactId>\
                 <version>1</version>{classifier}</dependency>"
            )
        };
        let own = Arc::new(std::sync::OnceLock::<String>::new());
        let addr_cell = Arc::clone(&own);
        let server = StubServer::start(move |request| {
            let addr = addr_cell.get().expect("addr");
            let base = |repo: &str, artifact: &str| format!("/{repo}/fx/{artifact}/1/{artifact}-1");
            let mut routes: HashMap<String, Vec<u8>> = HashMap::new();
            routes.insert(
                format!("{}.pom", base("repo1", "a")),
                pom(
                    "fx",
                    "a",
                    "1",
                    &format!(
                        "<repositories><repository><id>r2</id><url>http://{addr}/r2/</url>\
                         </repository></repositories><dependencies>{}</dependencies>",
                        dep("x", "<classifier>tests</classifier>")
                    ),
                ),
            );
            routes.insert(
                format!("{}.pom", base("repo1", "b")),
                pom(
                    "fx",
                    "b",
                    "1",
                    &format!("<dependencies>{}</dependencies>", dep("x", "")),
                ),
            );
            for artifact in ["a", "b", "x"] {
                routes.insert(format!("{}.jar", base("repo1", artifact)), b"jar".to_vec());
            }
            routes.insert(format!("{}.pom", base("r2", "x")), pom("fx", "x", "1", ""));
            routes.insert(format!("{}-tests.jar", base("r2", "x")), b"tests".to_vec());
            routes.get(&request.path).map_or_else(
                || Response::new(404, ""),
                |body| Response::new(200, body.clone()),
            )
        });
        own.set(server.addr().to_string()).unwrap();
        let repo1 = format!("http://{}/repo1/", server.addr());
        let r2 = format!("http://{}/r2/", server.addr());

        for deps_xml in [
            format!("{}{}", dep("a", ""), dep("b", "")),
            format!("{}{}", dep("b", ""), dep("a", "")),
        ] {
            let app = pom(
                "fx",
                "app",
                "1",
                &format!("<dependencies>{deps_xml}</dependencies>"),
            );
            let (dir, workspace) = reactor(&[("pom.xml", std::str::from_utf8(&app).unwrap())]);
            let mut config = Config::for_testing_with_repos(
                workspace.root().to_path_buf(),
                ResolvedPaths::for_testing().unwrap(),
                vec![repo_config(&repo1)],
            );
            config.security.transitive_repository_allowlist = vec![r2.clone()];
            let client = RepoClient::new(&config)
                .await
                .unwrap()
                .with_allow_missing_checksums(true);
            let repos = config.repositories().iter().map(Repository::from).collect();
            let store_dir = tempfile::tempdir().unwrap();
            let store = Arc::new(Store::open(store_dir.path()).unwrap());
            let context = ResolveContext::new(
                config,
                repos,
                store,
                Platform::new("linux", "x86_64").unwrap(),
                Some(client),
            );
            let resolver = PlatformResolver::new(context);
            let error = resolve_module(&resolver, &workspace, "pom.xml")
                .await
                .expect_err("the two winners disagree on the POM");
            drop(dir);
            assert!(
                matches!(&error, ResolveError::ConflictingResolvedPomBytes(pom)
                    if pom.coord == "fx:x:1"),
                "{deps_xml}: {error:?}"
            );
        }
    }

    /// Per-path repository contexts match Maven 3.9.12 across subtrees,
    /// siblings, ranges, nested contexts, and parent POMs.
    #[tokio::test]
    async fn transitive_repository_contexts_follow_dependency_paths() {
        ensure_crypto_provider();
        let dep = |artifact: &str, version: &str| {
            format!(
                "<dependency><groupId>fx</groupId><artifactId>{artifact}</artifactId>\
                 <version>{version}</version></dependency>"
            )
        };
        let repo_xml = |id: &str, url: &str| {
            format!(
                "<repositories><repository><id>{id}</id><url>{url}</url>\
                 </repository></repositories>"
            )
        };
        let meta = |versions: &[&str]| {
            let items: String = versions
                .iter()
                .map(|v| format!("<version>{v}</version>"))
                .collect();
            format!(
                "<metadata><groupId>fx</groupId><artifactId>z</artifactId>\
                 <versioning><versions>{items}</versions></versioning></metadata>"
            )
            .into_bytes()
        };

        let own = Arc::new(std::sync::OnceLock::<String>::new());
        let addr_cell = Arc::clone(&own);
        let server = StubServer::start(move |request| {
            let addr = addr_cell.get().expect("addr");
            let r2 = format!("http://{addr}/r2/");
            let r3 = format!("http://{addr}/r3/");
            let mut routes: HashMap<String, Vec<u8>> = HashMap::new();
            let add = |routes: &mut HashMap<String, Vec<u8>>,
                       repo: &str,
                       artifact: &str,
                       version: &str,
                       body: &str| {
                let base = format!("/{repo}/fx/{artifact}/{version}/{artifact}-{version}");
                routes.insert(format!("{base}.pom"), pom("fx", artifact, version, body));
                routes.insert(
                    format!("{base}.jar"),
                    format!("{repo}:{artifact}:{version}").into_bytes(),
                );
            };
            add(
                &mut routes,
                "repo1",
                "a",
                "1",
                &format!(
                    "{}<dependencies>{}{}</dependencies>",
                    repo_xml("r2", &r2),
                    dep("x", "1"),
                    dep("c", "1")
                ),
            );
            add(
                &mut routes,
                "repo1",
                "c",
                "1",
                &format!("<dependencies>{}</dependencies>", dep("d", "1")),
            );
            add(&mut routes, "r2", "x", "1", "");
            add(&mut routes, "r2", "d", "1", "");
            add(
                &mut routes,
                "repo1",
                "b",
                "1",
                &format!("<dependencies>{}</dependencies>", dep("y", "1")),
            );
            add(&mut routes, "r2", "y", "1", "");
            add(
                &mut routes,
                "repo1",
                "e",
                "1",
                &format!("<dependencies>{}</dependencies>", dep("z", "[1,)")),
            );
            add(
                &mut routes,
                "repo1",
                "f",
                "1",
                &format!(
                    "{}<dependencies>{}</dependencies>",
                    repo_xml("r2", &r2),
                    dep("z", "[1,)")
                ),
            );
            add(&mut routes, "repo1", "z", "1", "");
            add(&mut routes, "r2", "z", "2", "");
            routes.insert("/repo1/fx/z/maven-metadata.xml".to_string(), meta(&["1"]));
            routes.insert("/r2/fx/z/maven-metadata.xml".to_string(), meta(&["1", "2"]));
            add(
                &mut routes,
                "repo1",
                "g",
                "1",
                &format!(
                    "{}<dependencies>{}</dependencies>",
                    repo_xml("r3", &r3),
                    dep("h", "1")
                ),
            );
            add(
                &mut routes,
                "r3",
                "h",
                "1",
                &format!(
                    "{}<dependencies>{}</dependencies>",
                    repo_xml("r2", &r2),
                    dep("k", "1")
                ),
            );
            add(&mut routes, "r2", "k", "1", "");
            routes.insert(
                "/r2/fx/mp/1/mp-1.pom".to_string(),
                pom("fx", "mp", "1", "<packaging>pom</packaging>"),
            );
            add(
                &mut routes,
                "repo1",
                "m",
                "1",
                &format!(
                    "<parent><groupId>fx</groupId><artifactId>mp</artifactId>\
                     <version>1</version></parent>{}",
                    repo_xml("r2", &r2)
                ),
            );

            routes.get(&request.path).map_or_else(
                || Response::new(404, ""),
                |body| Response::new(200, body.clone()),
            )
        });
        own.set(server.addr().to_string()).unwrap();
        let repo1 = format!("http://{}/repo1/", server.addr());
        let r2 = format!("http://{}/r2/", server.addr());
        let r3 = format!("http://{}/r3/", server.addr());

        let run = |deps_xml: String| {
            let repo1 = repo1.clone();
            let r2 = r2.clone();
            let r3 = r3.clone();
            async move {
                let app = pom(
                    "fx",
                    "app",
                    "1",
                    &format!("<dependencies>{deps_xml}</dependencies>"),
                );
                let (dir, workspace) = reactor(&[("pom.xml", std::str::from_utf8(&app).unwrap())]);
                let mut config = Config::for_testing_with_repos(
                    workspace.root().to_path_buf(),
                    ResolvedPaths::for_testing().unwrap(),
                    vec![repo_config(&repo1)],
                );
                config.security.transitive_repository_allowlist = vec![r2, r3];
                let client = RepoClient::new(&config)
                    .await
                    .unwrap()
                    .with_allow_missing_checksums(true);
                let repos = config.repositories().iter().map(Repository::from).collect();
                let store_dir = tempfile::tempdir().unwrap();
                let store = Arc::new(Store::open(store_dir.path()).unwrap());
                let context = ResolveContext::new(
                    config,
                    repos,
                    store,
                    Platform::new("linux", "x86_64").unwrap(),
                    Some(client),
                );
                let resolver = PlatformResolver::new(context);
                let res = resolve_module(&resolver, &workspace, "pom.xml").await;
                drop(dir);
                res
            }
        };

        // (1) Subtree: app -> a (declares r2) -> x (only in r2), a -> c -> d (only in r2).
        let res = run(dep("a", "1")).await.expect("subtree resolves");
        for artifact in ["a", "c", "d", "x"] {
            assert!(has_artifact(&res.graph, artifact), "missing {artifact}");
        }

        // (2) Siblings: app -> a (declares r2), app -> b -> y (only in r2), in either order.
        for deps_xml in [
            format!("{}{}", dep("a", "1"), dep("b", "1")),
            format!("{}{}", dep("b", "1"), dep("a", "1")),
        ] {
            let err = run(deps_xml).await.expect_err("sibling y must fail");
            assert!(err.to_string().contains("fx:y:1"), "{err}");
        }
        assert!(
            !server
                .requests()
                .iter()
                .any(|req| req.path.starts_with("/r2/fx/y/")),
            "r2 must never be queried for sibling's dependency y"
        );

        // (3) Range on sibling: app -> a (declares r2), app -> e -> z:[1,) picks z 1.
        for deps_xml in [
            format!("{}{}", dep("a", "1"), dep("e", "1")),
            format!("{}{}", dep("e", "1"), dep("a", "1")),
        ] {
            let res = run(deps_xml).await.expect("sibling range resolves");
            assert_eq!(
                node_by_artifact(&res.graph, "z").1.coord.version.as_str(),
                "1"
            );
        }

        // (4) Range in subtree: app -> f (declares r2) -> z:[1,) picks z 2.
        let res = run(dep("f", "1")).await.expect("subtree range resolves");
        assert_eq!(
            node_by_artifact(&res.graph, "z").1.coord.version.as_str(),
            "2"
        );

        // (5) Nested contexts: app -> g (declares r3) -> h (only in r3, declares r2) -> k (only in r2).
        let res = run(dep("g", "1")).await.expect("nested contexts resolve");
        for artifact in ["g", "h", "k"] {
            assert!(has_artifact(&res.graph, artifact), "missing {artifact}");
        }

        // (6) Parent in own repo: app -> m (declares r2), m's parent mp only in r2.
        let res = run(dep("m", "1"))
            .await
            .expect("parent in own repo resolves");
        assert!(has_artifact(&res.graph, "m"));
    }

    /// Maven fails a project whose management holds a `<type/>` entry rather
    /// than letting it manage the jar a dependency brings.
    #[tokio::test]
    async fn a_managed_empty_type_fails_the_project() {
        let app = pom(
            "com.example",
            "app",
            "1",
            "<dependencyManagement><dependencies><dependency><groupId>g</groupId>\
             <artifactId>leaf</artifactId><version>2</version><type/></dependency>\
             </dependencies></dependencyManagement><dependencies><dependency>\
             <groupId>g</groupId><artifactId>middle</artifactId><version>1</version>\
             </dependency></dependencies>",
        );
        let (_dir, workspace) = reactor(&[("pom.xml", std::str::from_utf8(&app).unwrap())]);
        let routes = HashMap::from([
            (
                "/g/middle/1/middle-1.pom".to_string(),
                pom(
                    "g",
                    "middle",
                    "1",
                    "<dependencies><dependency><groupId>g</groupId><artifactId>leaf</artifactId>\
                     <version>1</version></dependency></dependencies>",
                ),
            ),
            (
                "/g/leaf/1/leaf-1.pom".to_string(),
                pom("g", "leaf", "1", ""),
            ),
            (
                "/g/leaf/2/leaf-2.pom".to_string(),
                pom("g", "leaf", "2", ""),
            ),
        ]);
        let (resolver, _store) = memory_resolver(workspace.root(), &routes);
        let error = resolve_graph(&resolver, &workspace, "pom.xml")
            .await
            .expect_err("an empty managed type must fail");
        assert!(
            error
                .to_string()
                .contains("g:leaf: declares an empty <type>"),
            "{error}"
        );
    }

    /// A dependency's parent is asked for as soon as the dependency's POM
    /// arrives, before its `.sha256` answers: a repository may take far
    /// longer for that 404 than for the POM. Here the 404s of the dependency
    /// and its parent wait up to five seconds for the grandparent to be
    /// asked for, so each hop must start before the last was verified.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_parent_is_fetched_while_the_child_checksum_is_pending() {
        use std::io::Write;
        use std::sync::{Condvar, Mutex};
        use std::time::Duration;

        let (_dir, workspace) = reactor(&[(
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>p</groupId>\
             <artifactId>root</artifactId><version>1</version><dependencies><dependency>\
             <groupId>org.ext</groupId><artifactId>lib</artifactId><version>1</version>\
             </dependency></dependencies></project>",
        )]);
        let lib = pom(
            "org.ext",
            "lib",
            "1",
            "<parent><groupId>org.ext</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent>",
        );
        let parent = pom(
            "org.ext",
            "parent",
            "1",
            "<packaging>pom</packaging><parent><groupId>org.ext</groupId>\
             <artifactId>grandparent</artifactId><version>1</version></parent>",
        );
        let grandparent = pom("org.ext", "grandparent", "1", "<packaging>pom</packaging>");
        // Whether the grandparent was asked for, and for each `.sha256`
        // answered, whether that came first.
        let state = Arc::new((Mutex::new((false, Vec::new())), Condvar::new()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}/", listener.local_addr().expect("addr"));
        let serving = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let (state, lib, parent, grandparent) = (
                    Arc::clone(&serving),
                    lib.clone(),
                    parent.clone(),
                    grandparent.clone(),
                );
                std::thread::spawn(move || {
                    let Some(head) = rv_test_support::http::read_request_head_blocking(&mut stream)
                    else {
                        return;
                    };
                    let head = String::from_utf8_lossy(&head);
                    let path = head.split_whitespace().nth(1).unwrap_or_default();
                    let (lock, asked) = &*state;
                    let body = match path {
                        "/org/ext/lib/1/lib-1.pom" => Some(lib),
                        "/org/ext/lib/1/lib-1.jar" => Some(b"jar".to_vec()),
                        "/org/ext/parent/1/parent-1.pom" => Some(parent),
                        "/org/ext/grandparent/1/grandparent-1.pom" => {
                            lock.lock().unwrap().0 = true;
                            asked.notify_all();
                            Some(grandparent)
                        }
                        "/org/ext/lib/1/lib-1.pom.sha256"
                        | "/org/ext/parent/1/parent-1.pom.sha256" => {
                            let guard = lock.lock().unwrap();
                            let (mut guard, _) = asked
                                .wait_timeout_while(guard, Duration::from_secs(5), |seen| !seen.0)
                                .unwrap();
                            let seen = guard.0;
                            guard.1.push(seen);
                            None
                        }
                        _ => None,
                    };
                    let response = match body {
                        Some(body) => {
                            let mut response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .into_bytes();
                            response.extend(body);
                            response
                        }
                        None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec(),
                    };
                    let _ = stream.write_all(&response);
                });
            }
        });
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;
        resolve_graph(&resolver, &workspace, "pom.xml")
            .await
            .expect("resolves");
        assert_eq!(
            state.0.lock().unwrap().1,
            [true, true],
            "the grandparent was not asked for before the .sha256 files answered"
        );
    }

    /// The parent of a repository POM comes from the repositories, even where
    /// its default `<relativePath>` from the project's directory names a
    /// local POM with its coordinates, as in Maven.
    #[tokio::test]
    async fn a_remote_bom_takes_its_parent_from_the_repositories() {
        let base = |lib: &str| {
            pom(
                "p",
                "base",
                "1",
                &format!(
                    "<packaging>pom</packaging><properties><lib.version>{lib}</lib.version></properties>"
                ),
            )
        };
        let local_base = String::from_utf8(base("2")).unwrap();
        let (_dir, workspace) = reactor(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>p</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>local/module</module></modules></project>",
            ),
            ("local/pom.xml", &local_base),
            (
                "local/module/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>p</groupId>\
                 <artifactId>base</artifactId><version>1</version></parent>\
                 <artifactId>module</artifactId><dependencyManagement><dependencies>\
                 <dependency><groupId>p</groupId><artifactId>bom</artifactId><version>1</version>\
                 <type>pom</type><scope>import</scope></dependency></dependencies>\
                 </dependencyManagement><dependencies><dependency><groupId>p</groupId>\
                 <artifactId>lib</artifactId></dependency></dependencies></project>",
            ),
        ]);
        let mut routes = HashMap::new();
        routes.insert("/p/base/1/base-1.pom".to_string(), base("1"));
        routes.insert(
            "/p/bom/1/bom-1.pom".to_string(),
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>p</groupId>\
             <artifactId>base</artifactId><version>1</version></parent>\
             <artifactId>bom</artifactId><packaging>pom</packaging><dependencyManagement>\
             <dependencies><dependency><groupId>p</groupId><artifactId>lib</artifactId>\
             <version>${lib.version}</version></dependency></dependencies>\
             </dependencyManagement></project>"
                .as_bytes()
                .to_vec(),
        );
        for version in ["1", "2"] {
            routes.insert(
                format!("/p/lib/{version}/lib-{version}.pom"),
                pom("p", "lib", version, ""),
            );
        }
        let (resolver, _store) = memory_resolver(workspace.root(), &routes);
        let graph = resolve_graph(&resolver, &workspace, "local/module/pom.xml")
            .await
            .expect("resolves");
        assert_eq!(
            node_by_artifact(&graph, "lib").1.coord.version.as_str(),
            "1"
        );
    }

    /// A reactor module standing in for a parent or BOM reads its own local
    /// parent from its own directory, whichever module imports it, also when
    /// that parent inherits `${revision}`.
    #[tokio::test]
    async fn a_reactor_bom_reads_its_parent_from_its_own_directory() {
        let project = |coords: &str, rest: &str| {
            format!("<project><modelVersion>4.0.0</modelVersion>{coords}{rest}</project>")
        };
        let parent = |artifact: &str, version: &str, path: &str| {
            format!(
                "<parent><groupId>p</groupId><artifactId>{artifact}</artifactId>\
                 <version>{version}</version><relativePath>{path}</relativePath></parent>"
            )
        };
        let import = |version: &str| {
            format!(
                "<dependencyManagement><dependencies><dependency><groupId>p</groupId>\
                 <artifactId>bom</artifactId><version>{version}</version><type>pom</type>\
                 <scope>import</scope></dependency></dependencies></dependencyManagement>\
                 <dependencies><dependency><groupId>p</groupId><artifactId>leaf</artifactId>\
                 </dependency></dependencies>"
            )
        };
        let manages = "<packaging>pom</packaging><dependencyManagement><dependencies>\
                       <dependency><groupId>p</groupId><artifactId>leaf</artifactId>\
                       <version>${leaf.version}</version></dependency></dependencies>\
                       </dependencyManagement>";
        let corp_with = |leaf: &str| {
            project(
                "<groupId>p</groupId><artifactId>corp</artifactId><version>1</version>",
                &format!(
                    "<packaging>pom</packaging><properties><leaf.version>{leaf}</leaf.version>\
                     </properties>"
                ),
            )
        };
        let corp = corp_with("1");
        let deep = [
            (
                "pom.xml",
                project(
                    "<groupId>p</groupId><artifactId>root</artifactId><version>1</version>",
                    "<packaging>pom</packaging>\
                     <modules><module>bom</module><module>services/deep/app</module></modules>",
                ),
            ),
            ("parents/corp/pom.xml", corp.clone()),
            (
                "bom/pom.xml",
                project(
                    &parent("corp", "1", "../parents/corp/pom.xml"),
                    &format!("<artifactId>bom</artifactId>{manages}"),
                ),
            ),
            (
                "services/deep/app/pom.xml",
                project(
                    "<groupId>p</groupId><artifactId>app</artifactId><version>1</version>",
                    &import("1"),
                ),
            ),
        ];
        let revision = [
            (
                "pom.xml",
                project(
                    &parent("corp", "1", "parent/pom.xml"),
                    "<artifactId>root</artifactId><version>${revision}</version>\
                     <packaging>pom</packaging><properties><revision>1.0</revision></properties>\
                     <modules><module>bom</module><module>app</module></modules>",
                ),
            ),
            ("parent/pom.xml", corp),
            (
                "bom/pom.xml",
                project(
                    &parent("root", "${revision}", "../pom.xml"),
                    &format!("<artifactId>bom</artifactId>{manages}"),
                ),
            ),
            (
                "app/pom.xml",
                project(
                    &parent("root", "${revision}", "../pom.xml"),
                    &format!("<artifactId>app</artifactId>{}", import("${revision}")),
                ),
            ),
        ];
        // The BOM's parent is remote, so the importer's `../parents/pom.xml`
        // with its coordinates is not read.
        let remote = [
            (
                "pom.xml",
                project(
                    "<groupId>p</groupId><artifactId>root</artifactId><version>1</version>",
                    "<packaging>pom</packaging>\
                     <modules><module>bom</module><module>apps/app</module></modules>",
                ),
            ),
            (
                "bom/pom.xml",
                project(
                    &parent("corp", "1", "../parents/pom.xml"),
                    &format!("<artifactId>bom</artifactId>{manages}"),
                ),
            ),
            ("apps/parents/pom.xml", corp_with("2")),
            (
                "apps/app/pom.xml",
                project(
                    "<groupId>p</groupId><artifactId>app</artifactId><version>1</version>",
                    &import("1"),
                ),
            ),
        ];
        let mut routes = HashMap::new();
        for leaf in ["1", "2"] {
            routes.insert(
                format!("/p/leaf/{leaf}/leaf-{leaf}.pom"),
                pom("p", "leaf", leaf, ""),
            );
        }
        routes.insert(
            "/p/corp/1/corp-1.pom".to_string(),
            corp_with("1").into_bytes(),
        );
        for (files, app) in [
            (&deep, "services/deep/app/pom.xml"),
            (&revision, "app/pom.xml"),
            (&remote, "apps/app/pom.xml"),
        ] {
            let files: Vec<(&str, &str)> = files
                .iter()
                .map(|(path, text)| (*path, text.as_str()))
                .collect();
            let (_dir, workspace) = reactor(&files);
            let (resolver, _store) = memory_resolver(workspace.root(), &routes);
            let graph = resolve_graph(&resolver, &workspace, app)
                .await
                .unwrap_or_else(|error| panic!("{app}: {error}"));
            assert_eq!(
                node_by_artifact(&graph, "leaf").1.coord.version.as_str(),
                "1"
            );
        }
    }

    /// A reactor module that a dependency's model reads as its parent
    /// brings its own local parent, but not the root's `.mvn/maven.config`
    /// `-D` values (MNG-7563).
    #[tokio::test]
    async fn maven_config_values_stay_out_of_a_dependency_model() {
        let (_dir, workspace) = reactor(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>p</groupId>\
                 <artifactId>corp</artifactId><version>1</version>\
                 <relativePath>corp/pom.xml</relativePath></parent>\
                 <artifactId>root</artifactId><packaging>pom</packaging>\
                 <modules><module>app</module></modules></project>",
            ),
            (
                "corp/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>p</groupId>\
                 <artifactId>corp</artifactId><version>1</version><packaging>pom</packaging>\
                 <properties><leaf.version>1</leaf.version></properties></project>",
            ),
            (
                "app/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>p</groupId>\
                 <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
                 <groupId>ext</groupId><artifactId>lib</artifactId><version>1</version>\
                 </dependency></dependencies></project>",
            ),
            (".mvn/maven.config", "-Dleaf.version=2\n"),
        ]);
        let mut routes = HashMap::new();
        routes.insert(
            "/ext/lib/1/lib-1.pom".to_string(),
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>p</groupId>\
             <artifactId>root</artifactId><version>1</version><relativePath/></parent>\
             <groupId>ext</groupId><artifactId>lib</artifactId><version>1</version>\
             <dependencies><dependency><groupId>p</groupId><artifactId>leaf</artifactId>\
             <version>${leaf.version}</version></dependency></dependencies></project>"
                .as_bytes()
                .to_vec(),
        );
        for version in ["1", "2"] {
            routes.insert(
                format!("/p/leaf/{version}/leaf-{version}.pom"),
                pom("p", "leaf", version, ""),
            );
        }
        let (resolver, _store) = memory_resolver(workspace.root(), &routes);
        let graph = resolve_graph(&resolver, &workspace, "app/pom.xml")
            .await
            .expect("resolves");
        assert_eq!(
            node_by_artifact(&graph, "leaf").1.coord.version.as_str(),
            "1"
        );
    }

    /// A dependency that inherits its version from a reactor module found
    /// by the version `.mvn/maven.config` gives it takes the module's version
    /// as written, expanded without the `-D` values (MNG-7563).
    #[tokio::test]
    async fn a_dependency_inherits_a_reactor_parents_version_as_written() {
        let (_dir, workspace) = reactor(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>p</groupId>\
                 <artifactId>root</artifactId><version>${revision}</version>\
                 <packaging>pom</packaging><properties><revision>1</revision></properties>\
                 <modules><module>app</module></modules></project>",
            ),
            (
                "app/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>p</groupId>\
                 <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
                 <groupId>p</groupId><artifactId>lib</artifactId><version>2</version>\
                 </dependency></dependencies></project>",
            ),
            (".mvn/maven.config", "-Drevision=2\n"),
        ]);
        let mut routes = HashMap::new();
        routes.insert(
            "/p/lib/2/lib-2.pom".to_string(),
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>p</groupId>\
             <artifactId>root</artifactId><version>2</version><relativePath/></parent>\
             <artifactId>lib</artifactId><dependencies><dependency><groupId>p</groupId>\
             <artifactId>leaf</artifactId><version>${project.version}</version></dependency>\
             </dependencies></project>"
                .as_bytes()
                .to_vec(),
        );
        for version in ["1", "2"] {
            routes.insert(
                format!("/p/leaf/{version}/leaf-{version}.pom"),
                pom("p", "leaf", version, ""),
            );
        }
        let (resolver, _store) = memory_resolver(workspace.root(), &routes);
        let graph = resolve_graph(&resolver, &workspace, "app/pom.xml")
            .await
            .expect("resolves");
        assert_eq!(
            node_by_artifact(&graph, "leaf").1.coord.version.as_str(),
            "1"
        );
    }

    /// A module version that a remote parent's property gives is the one
    /// other modules depend on and import, as Maven indexes the reactor by
    /// effective models.
    #[tokio::test]
    async fn module_versions_follow_remote_parent_properties() {
        let (_dir, workspace) = reactor(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>corp</groupId>\
                 <artifactId>parent</artifactId><version>1.0</version><relativePath/></parent>\
                 <artifactId>root</artifactId><version>${revision}</version>\
                 <packaging>pom</packaging><modules><module>a</module><module>b</module>\
                 </modules></project>",
            ),
            (
                "a/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>corp</groupId>\
                 <artifactId>root</artifactId><version>${revision}</version></parent>\
                 <artifactId>a</artifactId><packaging>pom</packaging><dependencyManagement>\
                 <dependencies><dependency><groupId>p</groupId><artifactId>leaf</artifactId>\
                 <version>1</version></dependency></dependencies></dependencyManagement>\
                 </project>",
            ),
            (
                "b/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>corp</groupId>\
                 <artifactId>root</artifactId><version>${revision}</version></parent>\
                 <artifactId>b</artifactId><dependencyManagement><dependencies><dependency>\
                 <groupId>corp</groupId><artifactId>a</artifactId><version>${revision}</version>\
                 <type>pom</type><scope>import</scope></dependency></dependencies>\
                 </dependencyManagement><dependencies><dependency><groupId>corp</groupId>\
                 <artifactId>a</artifactId><version>${revision}</version><type>pom</type>\
                 </dependency><dependency><groupId>p</groupId><artifactId>leaf</artifactId>\
                 </dependency></dependencies></project>",
            ),
        ]);
        let mut routes = HashMap::new();
        routes.insert(
            "/corp/parent/1.0/parent-1.0.pom".to_string(),
            pom(
                "corp",
                "parent",
                "1.0",
                "<packaging>pom</packaging><properties><revision>1.2.0</revision></properties>",
            ),
        );
        routes.insert(
            "/p/leaf/1/leaf-1.pom".to_string(),
            pom("p", "leaf", "1", ""),
        );
        routes.insert("/p/leaf/1/leaf-1.jar".to_string(), b"leaf".to_vec());
        let (url, _server) = spawn_repository_with_routes(routes);
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;
        let resolved = resolver
            .resolve_workspace(&workspace)
            .await
            .expect("resolves");
        let b = resolved
            .modules
            .iter()
            .find(|module| module.pom_path == "b/pom.xml")
            .expect("module b");
        assert_eq!(b.resolution.module_gav.to_string(), "corp:b:1.2.0");
        let a = node_by_artifact(&b.resolution.graph, "a").1;
        assert_eq!(a.coord.version.as_str(), "1.2.0");
        assert_eq!(
            node_by_artifact(&b.resolution.graph, "leaf")
                .1
                .coord
                .version
                .as_str(),
            "1"
        );
        assert_eq!(a.workspace_module.as_deref(), Some("a/pom.xml"));
    }

    /// Two modules that discovery sees with the same `${revision}` are told
    /// apart by the versions their remote parents give, and fail only when
    /// those are the same, as Maven's reactor does.
    #[tokio::test]
    async fn modules_are_compared_by_the_versions_their_remote_parents_give() {
        let module = |parent: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>corp</groupId>\
                 <artifactId>{parent}</artifactId><version>1.0</version><relativePath/>\
                 </parent><groupId>g</groupId><artifactId>lib</artifactId>\
                 <version>${{revision}}</version><packaging>pom</packaging></project>"
            )
        };
        let (x, y) = (module("px"), module("py"));
        let (_dir, workspace) = reactor(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>corp</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>x</module><module>y</module></modules></project>",
            ),
            ("x/pom.xml", &x),
            ("y/pom.xml", &y),
        ]);
        for (y_revision, distinct) in [("2", true), ("1", false)] {
            let mut routes = HashMap::new();
            for (parent, revision) in [("px", "1"), ("py", y_revision)] {
                routes.insert(
                    format!("/corp/{parent}/1.0/{parent}-1.0.pom"),
                    pom(
                        "corp",
                        parent,
                        "1.0",
                        &format!(
                            "<packaging>pom</packaging><properties><revision>{revision}\
                             </revision></properties>"
                        ),
                    ),
                );
            }
            let (url, _server) = spawn_repository_with_routes(routes);
            let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;
            let result = resolver.resolve_workspace(&workspace).await;
            if distinct {
                let resolved = result.expect("distinct modules resolve");
                let mut gavs: Vec<String> = resolved
                    .modules
                    .iter()
                    .map(|module| module.resolution.module_gav.to_string())
                    .collect();
                gavs.sort();
                assert_eq!(gavs, ["corp:root:1", "g:lib:1", "g:lib:2"]);
            } else {
                let error = result.expect_err("a collision fails").to_string();
                assert!(error.contains("g:lib:1"), "{error}");
            }
        }
    }

    /// A module that inherits its version from a remote parent takes the
    /// parent's `${revision}` with its own value, as Maven inherits the
    /// parent model's version, and is indexed and compared by it. A
    /// module's own version that names a platform value takes the parent's
    /// property of that name.
    #[tokio::test]
    async fn a_module_inherits_a_remote_parents_version_expression() {
        let module = |artifact: &str, own: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>\
                 <artifactId>parent</artifactId><version>1</version><relativePath/></parent>\
                 <artifactId>{artifact}</artifactId>{own}</project>"
            )
        };
        let lib =
            |artifact: &str| module(artifact, "<properties><revision>2</revision></properties>");
        let app = module(
            "app",
            "<dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId>\
             <version>2</version></dependency></dependencies>",
        );
        let routes = HashMap::from([(
            "/g/parent/1/parent-1.pom".to_string(),
            pom(
                "g",
                "parent",
                "${revision}",
                "<packaging>pom</packaging><properties><revision>1</revision>\
                 <os.arch>2</os.arch></properties>",
            ),
        )]);
        let (url, _server) = spawn_repository_with_routes(routes);
        let root = "<project><modelVersion>4.0.0</modelVersion><groupId>corp</groupId>\
                    <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                    <modules><module>a</module><module>b</module></modules></project>";
        let versioned = module("lib", "<version>1</version>");
        let distinct = Ok(["corp:root:1", "g:lib:1", "g:lib:2"]);
        let with_app = Ok(["corp:root:1", "g:app:1", "g:lib:2"]);
        let by_platform = module("lib", "<version>${os.arch}</version>");
        for (a, b, outcome) in [
            (lib("lib"), app.clone(), with_app),
            (by_platform, app.clone(), with_app),
            (lib("lib"), module("lib", ""), distinct),
            (lib("lib"), versioned.clone(), distinct),
            (versioned.clone(), lib("lib"), distinct),
            (lib("lib"), lib("lib"), Err("g:lib:2")),
        ] {
            let (_dir, workspace) =
                reactor(&[("pom.xml", root), ("a/pom.xml", &a), ("b/pom.xml", &b)]);
            let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;
            let result = resolver.resolve_workspace(&workspace).await;
            match outcome {
                Ok(expected) => {
                    let resolved = result.unwrap_or_else(|error| panic!("{b}: {error}"));
                    let mut gavs: Vec<String> = resolved
                        .modules
                        .iter()
                        .map(|module| module.resolution.module_gav.to_string())
                        .collect();
                    gavs.sort();
                    assert_eq!(gavs, expected);
                }
                Err(gav) => {
                    let error = result.expect_err("a collision fails").to_string();
                    assert!(error.contains(gav), "{error}");
                }
            }
        }
    }

    /// A local parent's version is checked against a range as written, an
    /// expression in it read as a qualifier: `${revision}` sorts below every
    /// number, whatever value its own properties or `.mvn/maven.config` give
    /// it, and `1.0${changelist}` between `1.0` and `1.0-custom`.
    #[tokio::test]
    async fn a_local_parent_with_an_expression_version_is_checked_as_written() {
        let root = |version: &str, properties: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>p</groupId>\
                 <artifactId>par</artifactId><version>{version}</version>\
                 <packaging>pom</packaging><properties>{properties}</properties>\
                 <modules><module>app</module></modules><dependencyManagement><dependencies>\
                 <dependency><groupId>p</groupId><artifactId>leaf</artifactId>\
                 <version>1</version></dependency></dependencies></dependencyManagement>\
                 </project>"
            )
        };
        let app = |range: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>p</groupId>\
                 <artifactId>par</artifactId><version>{range}</version></parent>\
                 <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
                 <groupId>p</groupId><artifactId>leaf</artifactId></dependency></dependencies>\
                 </project>"
            )
        };
        let mut routes = HashMap::new();
        routes.insert(
            "/p/leaf/1/leaf-1.pom".to_string(),
            pom("p", "leaf", "1", ""),
        );
        for (version, properties, config, range, found) in [
            ("${revision}", "<revision>1</revision>", "", "(,2]", true),
            ("${revision}", "<revision>3</revision>", "", "(,2]", true),
            ("${revision}", "", "-Drevision=1\n", "(,2]", true),
            ("${revision}", "<revision>1</revision>", "", "[1,2]", false),
            ("1.0${changelist}", "<changelist/>", "", "[1,2]", true),
            (
                "1.0${changelist}",
                "<changelist/>",
                "",
                "[1.0,1.0-custom]",
                true,
            ),
        ] {
            let (_dir, workspace) = reactor(&[
                ("pom.xml", &root(version, properties)),
                ("app/pom.xml", &app(range)),
                (".mvn/maven.config", config),
            ]);
            let (resolver, _store) = memory_resolver(workspace.root(), &routes);
            let result = resolve_graph(&resolver, &workspace, "app/pom.xml").await;
            let case = format!("{version} {properties} {range}");
            if found {
                let graph = result.unwrap_or_else(|error| panic!("{case}: {error}"));
                assert!(has_artifact(&graph, "leaf"), "{case}");
            } else {
                let error = result.expect_err(&case).to_string();
                assert!(error.contains("p:par:[1,2]"), "{error}");
            }
        }
    }

    /// A parent version range resolves to the highest version a repository
    /// lists in it, or to a local parent in it, for the project and for a
    /// dependency, `[1.5]` included. As in Maven, the range needs an upper
    /// bound and the child its own constant version, and the model keeps the
    /// range as its parent version. The POM served for the selected version
    /// must declare it, maybe through its own parent, a profile there or a
    /// user property. A range reads only the `<versions>` of a version list,
    /// a range of one version needs no list, and the project's range sees
    /// the repositories' versions, not the reactor's.
    #[tokio::test]
    async fn a_parent_version_range_takes_the_highest_version_in_it() {
        let parent = |range: &str, path: &str| {
            format!(
                "<parent><groupId>p</groupId><artifactId>par</artifactId>\
                 <version>{range}</version>{path}</parent>"
            )
        };
        let leaf = "<dependency><groupId>p</groupId><artifactId>leaf</artifactId></dependency>";
        let app = |parent: &str, version: &str, dependency: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion>{parent}<artifactId>app</artifactId>\
                 {version}<dependencies>{dependency}</dependencies></project>"
            )
        };
        let par = |version: &str, leaf: &str| {
            pom(
                "p",
                "par",
                version,
                &format!(
                    "<packaging>pom</packaging><modules><module>app</module></modules>\
                     <dependencyManagement><dependencies><dependency><groupId>p</groupId>\
                     <artifactId>leaf</artifactId><version>{leaf}</version></dependency>\
                     </dependencies></dependencyManagement>"
                ),
            )
        };
        let mut routes = HashMap::new();
        for (version, leaf) in [("1.0", "1"), ("1.5", "2"), ("2.0", "3")] {
            routes.insert(
                format!("/p/par/{version}/par-{version}.pom"),
                par(version, leaf),
            );
            routes.insert(
                format!("/p/leaf/{leaf}/leaf-{leaf}.pom"),
                pom("p", "leaf", leaf, ""),
            );
        }
        routes.insert("/p/par/3.5/par-3.5.pom".to_string(), par("3.0", "1"));
        for (version, expression, revision) in [
            (
                "2.5",
                "${revision}",
                "<properties><revision>2.5</revision></properties>",
            ),
            (
                "2.7",
                "${revision}",
                "<profiles><profile><id>on</id><activation><activeByDefault>true\
                 </activeByDefault></activation><properties><revision>2.7</revision>\
                 </properties></profile></profiles>",
            ),
            ("2.8", "${pom.parent.version}", ""),
            (
                "2.9",
                "${par.release}",
                "<properties><par.release>0</par.release></properties>",
            ),
        ] {
            routes.insert(
                format!("/p/top/{version}/top-{version}.pom"),
                pom("p", "top", version, revision),
            );
            let payload = String::from_utf8(par(expression, "3")).unwrap().replacen(
                "<groupId>p</groupId>",
                &format!(
                    "<parent><groupId>p</groupId><artifactId>top</artifactId>\
                     <version>{version}</version><relativePath/></parent>"
                ),
                1,
            );
            routes.insert(
                format!("/p/par/{version}/par-{version}.pom"),
                payload.into_bytes(),
            );
        }
        for (artifact, versions) in [("par", "1.5 2.0 2.5 2.7 2.8 2.9 3.5"), ("leaf", "1 2 3")] {
            let versions: String = versions
                .split(' ')
                .map(|version| format!("<version>{version}</version>"))
                .collect();
            routes.insert(
                format!("/p/{artifact}/maven-metadata.xml"),
                format!(
                    "<metadata><groupId>p</groupId><artifactId>{artifact}</artifactId>\
                     <versioning><versions>{versions}</versions></versioning></metadata>"
                )
                .into_bytes(),
            );
        }
        routes.insert(
            "/ext/lib/1/lib-1.pom".to_string(),
            format!(
                "<project><modelVersion>4.0.0</modelVersion>{}<groupId>ext</groupId>\
                 <artifactId>lib</artifactId><version>1</version><dependencies><dependency>\
                 <groupId>p</groupId><artifactId>leaf</artifactId></dependency></dependencies>\
                 </project>",
                parent("[1.0,2.0)", "")
            )
            .into_bytes(),
        );
        let remote = parent("[1.0,2.0)", "<relativePath/>");
        let local_root = String::from_utf8(par("1.0", "1")).unwrap();
        let lib = "<dependency><groupId>ext</groupId><artifactId>lib</artifactId>\
                   <version>1</version></dependency>";
        routes.insert(
            "/p/bare/maven-metadata.xml".to_string(),
            b"<metadata><groupId>p</groupId><artifactId>bare</artifactId><versioning>\
              <release>1.5</release><latest>1.5</latest></versioning></metadata>"
                .to_vec(),
        );
        routes.insert(
            "/p/bare/1.5/bare-1.5.pom".to_string(),
            pom("p", "bare", "1.5", "<packaging>pom</packaging>"),
        );
        let ranged_leaf = "<dependency><groupId>p</groupId><artifactId>leaf</artifactId>\
                           <version>${project.parent.version}</version></dependency>";
        let cases: [(&str, String, Result<&str, &str>); 19] = [
            (
                "exact",
                app(
                    &parent("[1.5]", "<relativePath/>"),
                    "<version>1</version>",
                    leaf,
                ),
                Ok("2"),
            ),
            (
                "local exact",
                app(&parent("[1.0]", ""), "<version>1</version>", leaf),
                Ok("1"),
            ),
            (
                "other payload",
                app(
                    &parent("[3.0,4.0)", "<relativePath/>"),
                    "<version>1</version>",
                    leaf,
                ),
                Err("expected p:par:3.5, got p:par:3.0"),
            ),
            (
                "remote",
                app(&remote, "<groupId>g</groupId><version>1</version>", leaf),
                Ok("2"),
            ),
            (
                "local",
                app(&parent("[1.0,2.0)", ""), "<version>1</version>", leaf),
                Ok("1"),
            ),
            (
                "unbounded",
                app(
                    &parent("[1.0,)", "<relativePath/>"),
                    "<version>1</version>",
                    leaf,
                ),
                Err("does not specify an upper bound"),
            ),
            (
                "no match",
                app(
                    &parent("[4.0,5.0)", "<relativePath/>"),
                    "<version>1</version>",
                    leaf,
                ),
                Err("p:par:[4.0,5.0)"),
            ),
            (
                "inherited version",
                app(&remote, "", leaf),
                Err("must be a constant"),
            ),
            (
                "parent version expression",
                app(&remote, "<version>${pom.parent.version}</version>", leaf),
                Err("must be a constant"),
            ),
            (
                "derived version",
                app(
                    &remote,
                    "<version>${project.parent.version}-app</version>",
                    leaf,
                ),
                Ok("2"),
            ),
            (
                "range in the model",
                app(&remote, "<version>1</version>", ranged_leaf),
                Ok("1"),
            ),
            (
                "expression payload",
                app(
                    &parent("[2.5,2.6)", "<relativePath/>"),
                    "<version>1</version>",
                    leaf,
                ),
                Ok("3"),
            ),
            (
                "profile payload",
                app(
                    &parent("[2.7]", "<relativePath/>"),
                    "<version>1</version>",
                    leaf,
                ),
                Ok("3"),
            ),
            (
                "parent alias payload",
                app(
                    &parent("[2.8]", "<relativePath/>"),
                    "<version>1</version>",
                    leaf,
                ),
                Ok("3"),
            ),
            (
                "user property payload",
                app(
                    &parent("[2.9]", "<relativePath/>"),
                    "<version>1</version>",
                    leaf,
                ),
                Ok("3"),
            ),
            (
                "exact without a list",
                app(
                    &parent("[1.0,1]", "<relativePath/>"),
                    "<version>1</version>",
                    leaf,
                ),
                Ok("1"),
            ),
            (
                "no version list",
                app(
                    &parent("[1.0,2.0)", "<relativePath/>")
                        .replace("<artifactId>par<", "<artifactId>bare<"),
                    "<version>1</version>",
                    leaf,
                ),
                Err("p:bare:[1.0,2.0)"),
            ),
            (
                "reactor not listed",
                app(
                    &parent("[1.0,1.2)", "<relativePath/>"),
                    "<version>1</version>",
                    leaf,
                ),
                Err("p:par:[1.0,1.2)"),
            ),
            (
                "dependency",
                app("", "<groupId>g</groupId><version>1</version>", lib),
                Ok("2"),
            ),
        ];
        for (name, app, expected) in cases {
            let (_dir, workspace) = reactor(&[
                ("pom.xml", &local_root),
                ("app/pom.xml", &app),
                (".mvn/maven.config", "-Dpar.release=2.9\n"),
            ]);
            let (resolver, _store) = memory_resolver(workspace.root(), &routes);
            let result = resolve_graph(&resolver, &workspace, "app/pom.xml").await;
            match expected {
                Ok(leaf) => {
                    let graph = result.unwrap_or_else(|error| panic!("{name}: {error}"));
                    let version = node_by_artifact(&graph, "leaf").1.coord.version.to_string();
                    assert_eq!(version, leaf, "{name}");
                }
                Err(part) => {
                    let error = result.expect_err(name).to_string();
                    assert!(error.contains(part), "{name}: {error}");
                }
            }
        }
    }

    /// The whole fixture reactor resolves in discovery order, and a
    /// sibling's declared repository is trusted for another module.
    #[tokio::test]
    async fn reactor_resolves_in_discovery_order_and_trusts_sibling_repositories() {
        let (url, requests) = spawn_repository();
        let workspace_dir = tempfile::tempdir().expect("workspace tempdir");
        fixtures::copy_tree_lf(&fixture("basic"), workspace_dir.path());
        let repo_owner = workspace_dir.path().join("repo-owner/pom.xml");
        let contents = std::fs::read_to_string(&repo_owner)
            .expect("read repo owner")
            .replace("__REPO_URL__", &url);
        std::fs::write(&repo_owner, contents).expect("rewrite repo URL");
        let workspace = Workspace::discover(workspace_dir.path()).expect("workspace");

        let (single, _store) = resolver(workspace.root(), Some(&url), false, false).await;
        let result = resolve_module(&single, &workspace, "repo-app/pom.xml")
            .await
            .expect("trusted sibling repo resolves vendor dependency");
        assert!(
            node_by_artifact(&result.graph, "only-here")
                .1
                .repo_url
                .is_some()
        );
        assert!(
            requests
                .requests()
                .iter()
                .any(|request| request.path == "/org/vendor/only-here/1/only-here-1.pom")
        );

        let (all, _store) = resolver(workspace.root(), Some(&url), false, true).await;
        let resolved = all.resolve_workspace(&workspace).await.expect("resolve");
        let paths = |paths: Vec<&str>| paths.join(" ");
        assert_eq!(
            paths(
                resolved
                    .modules
                    .iter()
                    .map(|m| m.pom_path.as_str())
                    .collect()
            ),
            paths(
                workspace
                    .modules()
                    .iter()
                    .map(|m| m.pom_path.as_str())
                    .collect()
            )
        );
        assert!(resolved.modules.iter().any(|module| {
            let graph = &module.resolution.graph;
            graph.node_indices().any(|index| {
                graph
                    .node(index)
                    .is_some_and(|node| node.workspace_module.is_some())
            })
        }));
    }

    /// A repository behind a blocked mirror gets no request, through the
    /// mirror or around it, and the search goes on to the next repository.
    #[tokio::test]
    async fn a_blocked_mirror_moves_the_search_on() {
        ensure_crypto_provider();
        let repositories = tempfile::tempdir().unwrap();
        let repository = |name: &str| {
            let root = repositories.path().join(name);
            let dir = root.join("lib/x/1");
            std::fs::create_dir_all(&dir).unwrap();
            for (extension, bytes) in [("pom", pom("lib", "x", "1", "")), ("jar", name.into())] {
                let path = dir.join(format!("x-1.{extension}"));
                std::fs::write(&path, &bytes).unwrap();
                std::fs::write(
                    path.with_extension(format!("{extension}.sha256")),
                    BlobId::from_bytes(&bytes).to_string(),
                )
                .unwrap();
            }
            reqwest::Url::from_directory_path(&root)
                .unwrap()
                .to_string()
        };
        let (first, second) = (repository("first"), repository("second"));
        let mut blocked = rv_config::MirrorConfig::new(Some("blocked"), &repository("mirror"));
        blocked.mirror_of = vec!["first".to_string()];
        blocked.blocked = true;
        let (_dir, workspace) = reactor(&[(
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>root</artifactId><version>1</version><dependencies><dependency>\
             <groupId>lib</groupId><artifactId>x</artifactId><version>1</version>\
             </dependency></dependencies></project>",
        )]);
        let config = Config::for_testing_with_repos(
            workspace.root().to_path_buf(),
            ResolvedPaths::for_testing().unwrap(),
            vec![
                rv_config::RepoConfig::new(Some("first"), &first),
                rv_config::RepoConfig::new(Some("second"), &second),
            ],
        )
        .with_mirrors(vec![blocked]);
        let client = RepoClient::new(&config).await.unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_dir.path()).unwrap());
        let context = ResolveContext::new(
            config.clone(),
            config.repositories().iter().map(Repository::from).collect(),
            store,
            Platform::new("linux", "x86_64").unwrap(),
            Some(client),
        );
        let resolved = PlatformResolver::new(context)
            .resolve_workspace(&workspace)
            .await
            .unwrap();
        let (_, node) = node_by_artifact(&resolved.modules[0].resolution.graph, "x");
        assert_eq!(node.checksum, Some(BlobId::from_bytes(b"second")));
        assert_eq!(node.repo_url.as_deref(), Some(second.as_str()));
    }

    #[tokio::test]
    async fn reactor_artifact_reuse_is_scoped_to_the_selected_endpoint() {
        ensure_crypto_provider();
        let repositories = tempfile::tempdir().unwrap();
        let repository = |name: &str, jar: &[u8]| {
            let root = repositories.path().join(name);
            let dir = root.join("lib/x/1");
            std::fs::create_dir_all(&dir).unwrap();
            for (extension, bytes) in [("pom", pom("lib", "x", "1", "")), ("jar", jar.to_vec())] {
                let path = dir.join(format!("x-1.{extension}"));
                std::fs::write(&path, &bytes).unwrap();
                std::fs::write(
                    path.with_extension(format!("{extension}.sha256")),
                    BlobId::from_bytes(&bytes).to_string(),
                )
                .unwrap();
            }
            format!("file://{}/", root.display())
        };
        let direct = repository("direct", b"direct jar");
        let mirror_url = repository("mirror", b"mirror jar");
        let module = |id: &str| {
            String::from_utf8(pom(
                "t",
                id,
                "1",
                &format!(
                    "<repositories><repository><id>{id}</id><url>{direct}</url>\
                     </repository></repositories><dependencies><dependency><groupId>lib</groupId>\
                     <artifactId>x</artifactId><version>1</version></dependency></dependencies>"
                ),
            ))
            .unwrap()
        };
        let (_dir, workspace) = reactor(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>a</module><module>b</module></modules></project>",
            ),
            ("a/pom.xml", &module("a")),
            ("b/pom.xml", &module("b")),
        ]);
        let mut mirror = rv_config::MirrorConfig::new(Some("mirror"), &mirror_url);
        mirror.mirror_of = vec!["a".to_string()];
        let config = Config::for_testing(
            workspace.root().to_path_buf(),
            ResolvedPaths::for_testing().unwrap(),
        )
        .with_mirrors(vec![mirror]);
        let client = RepoClient::new(&config).await.unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_dir.path()).unwrap());
        let context = ResolveContext::new(
            config.clone(),
            Vec::new(),
            store,
            Platform::new("linux", "x86_64").unwrap(),
            Some(client),
        );
        let resolver = PlatformResolver::new(context);
        // Exercise both downloaded and persisted-cache insertions into reactor reuse.
        for _ in 0..2 {
            let resolved = resolver.resolve_workspace(&workspace).await.unwrap();
            for (path, bytes) in [("a/pom.xml", b"mirror jar"), ("b/pom.xml", b"direct jar")] {
                let module = resolved
                    .modules
                    .iter()
                    .find(|module| module.pom_path == path)
                    .unwrap();
                assert_eq!(
                    node_by_artifact(&module.resolution.graph, "x").1.checksum,
                    Some(BlobId::from_bytes(bytes)),
                    "{path}"
                );
            }
            let hashes = Default::default();
            let model = crate::lock::PlatformModel {
                active_profiles: &[],
                pom_hashes: &hashes,
                whole_reactor_pom_hashes: &hashes,
            };
            let error = crate::lock::assemble(&config, vec![(model, resolved)]).unwrap_err();
            assert!(
                matches!(error, crate::lock::AssembleError::Resolve(error) if matches!(*error, ResolveError::ConflictingArtifactBytes { .. }))
            );
        }
    }

    /// A reactor pass indexes everything it downloaded once at its end,
    /// also when a later module fails, so a rerun reuses those files.
    #[tokio::test]
    async fn a_failed_module_leaves_the_earlier_downloads_indexed() {
        let mut routes = HashMap::new();
        routes.insert("/lib/ok/1/ok-1.pom".to_string(), pom("lib", "ok", "1", ""));
        routes.insert("/lib/ok/1/ok-1.jar".to_string(), b"ok jar".to_vec());
        routes.insert(
            "/lib/gone/1/gone-1.pom".to_string(),
            pom("lib", "gone", "1", ""),
        );
        let (url, _server) = spawn_repository_with_routes(routes);
        let module = |name: &str, dependency: &str| {
            String::from_utf8(pom(
                "t",
                name,
                "1",
                &format!(
                    "<dependencies><dependency><groupId>lib</groupId>\
                     <artifactId>{dependency}</artifactId><version>1</version></dependency>\
                     </dependencies>"
                ),
            ))
            .unwrap()
        };
        let (a, b) = (module("a", "ok"), module("b", "gone"));
        let (_dir, workspace) = reactor(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>a</module><module>b</module></modules></project>",
            ),
            ("a/pom.xml", &a),
            ("b/pom.xml", &b),
        ]);
        let (resolver, store_dir) = resolver(workspace.root(), Some(&url), false, true).await;

        let error = resolver
            .resolve_workspace(&workspace)
            .await
            .expect_err("lib:gone has no jar");
        assert!(error.to_string().contains("gone"), "{error}");

        let store = Store::open(store_dir.path()).expect("store");
        for extension in ["jar", "pom"] {
            let key = rv_maven_types::ArtifactCoord::new("lib", "ok", "1", extension, None);
            assert!(store.lookup_artifact(&key).await.unwrap().is_some());
        }
    }

    /// A module that fails its graph fails the pass before any module
    /// downloads a jar, also when it resolves after the modules before it
    /// have their graphs: on camel, the modules ahead of one with an
    /// undefined classifier downloaded theirs first.
    #[tokio::test]
    async fn a_failed_graph_downloads_no_jar_of_an_earlier_module() {
        let mut routes = HashMap::new();
        routes.insert("/lib/ok/1/ok-1.pom".to_string(), pom("lib", "ok", "1", ""));
        routes.insert("/lib/ok/1/ok-1.jar".to_string(), b"ok jar".to_vec());
        let (url, server) = spawn_repository_with_routes(routes);
        let module = |name: &str, classifier: &str| {
            String::from_utf8(pom(
                "t",
                name,
                "1",
                &format!(
                    "<dependencies><dependency><groupId>lib</groupId>\
                     <artifactId>ok</artifactId><version>1</version>{classifier}\
                     </dependency></dependencies>"
                ),
            ))
            .unwrap()
        };
        let names: Vec<String> = (0..12).map(|index| format!("m{index}")).collect();
        let mut files: Vec<(String, String)> = names
            .iter()
            .map(|name| (format!("{name}/pom.xml"), module(name, "")))
            .collect();
        files.push((
            "z/pom.xml".to_string(),
            module("z", "<classifier>${undefined.classifier}</classifier>"),
        ));
        let modules: String = (names.iter().chain([&"z".to_string()]))
            .map(|name| format!("<module>{name}</module>"))
            .collect();
        let root = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules>{modules}</modules></project>"
        );
        files.push(("pom.xml".to_string(), root));
        let files: Vec<(&str, &str)> = (files.iter())
            .map(|(path, contents)| (path.as_str(), contents.as_str()))
            .collect();
        let (_dir, workspace) = reactor(&files);
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let error = resolver
            .resolve_workspace(&workspace)
            .await
            .expect_err("z's classifier is undefined");
        assert!(
            (error.to_string()).starts_with("property undefined.classifier is not defined"),
            "{error}"
        );
        let jars: Vec<String> = (server.requests().into_iter())
            .map(|request| request.path)
            .filter(|path| path.ends_with(".jar"))
            .collect();
        assert!(jars.is_empty(), "{jars:?}");
    }

    /// A pom-packaged dependency's artifact is the POM its model was read
    /// from, so it is not downloaded again beside the resolution.
    #[tokio::test]
    async fn a_pom_typed_dependency_is_fetched_once() {
        let mut routes = HashMap::new();
        routes.insert(
            "/lib/bom/1/bom-1.pom".to_string(),
            pom("lib", "bom", "1", ""),
        );
        let (url, server) = spawn_repository_with_routes(routes);
        let app = String::from_utf8(pom(
            "t",
            "app",
            "1",
            "<dependencies><dependency><groupId>lib</groupId><artifactId>bom</artifactId>\
             <version>1</version><type>pom</type></dependency></dependencies>",
        ))
        .unwrap();
        let (_dir, workspace) = reactor(&[("pom.xml", &app)]);
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;
        resolver
            .resolve_workspace(&workspace)
            .await
            .expect("resolve");

        let reads = || {
            (server.requests().iter())
                .filter(|request| request.path == "/lib/bom/1/bom-1.pom")
                .count()
        };
        // A second read would come from a download still running.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while reads() < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert_eq!(reads(), 1);
    }

    /// A module whose own dependency has a version raeva cannot read fails
    /// the pass before any module downloads a jar, also when a slow POM it
    /// declares first keeps its graph from reaching that dependency.
    #[tokio::test]
    async fn an_unreadable_version_downloads_no_jar_of_an_earlier_module() {
        let mut routes = HashMap::new();
        routes.insert("/lib/ok/1/ok-1.pom".to_string(), pom("lib", "ok", "1", ""));
        routes.insert("/lib/ok/1/ok-1.jar".to_string(), b"ok jar".to_vec());
        let (url, server) = spawn_repository_with_routes(routes);
        // A server of its own, as its handler holds up every request to it.
        let slow = StubServer::start(|request| {
            std::thread::sleep(std::time::Duration::from_millis(500));
            match request.path.as_str() {
                "/lib/slow/1/slow-1.pom" => Response::new(200, pom("lib", "slow", "1", "")),
                _ => Response::new(404, ""),
            }
        });
        let module = |name: &str, rest: &str| String::from_utf8(pom("t", name, "1", rest)).unwrap();
        let dependency = |artifact: &str, version: &str| {
            format!(
                "<dependency><groupId>lib</groupId><artifactId>{artifact}</artifactId>\
                 <version>{version}</version></dependency>"
            )
        };
        let mut files: Vec<(String, String)> = (0..4)
            .map(|index| {
                let rest = format!("<dependencies>{}</dependencies>", dependency("ok", "1"));
                (
                    format!("m{index}/pom.xml"),
                    module(&format!("m{index}"), &rest),
                )
            })
            .collect();
        let rest = format!(
            "<repositories><repository><id>slow</id><url>http://{}/</url></repository>\
             </repositories><dependencies>{}{}</dependencies>",
            slow.addr(),
            dependency("slow", "1"),
            dependency("ok", "1.+"),
        );
        files.push(("z/pom.xml".to_string(), module("z", &rest)));
        files.push((
            "pom.xml".to_string(),
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>m0</module><module>m1</module><module>m2</module>\
             <module>m3</module><module>z</module></modules></project>"
                .to_string(),
        ));
        let files: Vec<(&str, &str)> = (files.iter())
            .map(|(path, contents)| (path.as_str(), contents.as_str()))
            .collect();
        let (_dir, workspace) = reactor(&files);
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let error = resolver
            .resolve_workspace(&workspace)
            .await
            .expect_err("z's version 1.+ is not a Maven version");
        assert_eq!(
            error.to_string(),
            "invalid version requirement for lib:ok: 1.+"
        );
        let jars: Vec<String> = (server.requests().into_iter())
            .map(|request| request.path)
            .filter(|path| path.ends_with(".jar"))
            .collect();
        assert!(jars.is_empty(), "{jars:?}");
    }

    /// The store is shared by every project, but a resolution reuses only
    /// bytes the same repository served with a checksum: another
    /// repository's jar for the coordinate, or one admitted without a
    /// checksum, is not taken. Its own copy is.
    #[tokio::test]
    async fn a_cached_jar_is_reused_only_from_the_repository_that_verified_it() {
        ensure_crypto_provider();
        let serve = |jar: &[u8], jar_sidecar: bool| {
            let mut routes = HashMap::new();
            let base = "/lib/x/1/x-1";
            for (extension, bytes) in [("pom", pom("lib", "x", "1", "")), ("jar", jar.to_vec())] {
                if extension == "pom" || jar_sidecar {
                    let sidecar = BlobId::from_bytes(&bytes).to_string();
                    routes.insert(format!("{base}.{extension}.sha256"), sidecar.into_bytes());
                }
                routes.insert(format!("{base}.{extension}"), bytes);
            }
            spawn_repository_with_routes(routes)
        };
        let (_project, workspace) = reactor(&[(
            "pom.xml",
            &String::from_utf8(pom(
                "t",
                "app",
                "1",
                "<dependencies><dependency><groupId>lib</groupId><artifactId>x</artifactId>\
                 <version>1</version></dependency></dependencies>",
            ))
            .unwrap(),
        )]);
        let store_dir = tempfile::tempdir().expect("store tempdir");
        let resolve = |url: String, allow_missing: bool| {
            let (root, store_dir) = (
                workspace.root().to_path_buf(),
                store_dir.path().to_path_buf(),
            );
            let workspace = workspace.clone();
            async move {
                let paths = ResolvedPaths::for_testing().expect("paths");
                let config = Config::for_testing_with_repos(root, paths, vec![repo_config(&url)]);
                let client = RepoClient::new(&config)
                    .await
                    .expect("repo client")
                    .with_allow_missing_checksums(allow_missing);
                let repos = config.repositories().iter().map(Repository::from).collect();
                let store = Arc::new(Store::open(&store_dir).expect("store"));
                let platform = Platform::new("linux", "x86_64").expect("platform");
                let context = ResolveContext::new(config, repos, store, platform, Some(client));
                let resolver = PlatformResolver::new(context);
                resolve_module(&resolver, &workspace, "pom.xml")
                    .await
                    .map(|resolution| node_by_artifact(&resolution.graph, "x").1.checksum.clone())
            }
        };

        let (a, a_server) = serve(b"jar from a", true);
        let (b, _b) = serve(b"jar from b", true);
        for (url, jar) in [
            (&a, b"jar from a"),
            (&b, b"jar from b"),
            (&a, b"jar from a"),
        ] {
            let blob = resolve(url.clone(), false).await.expect("resolve");
            assert_eq!(blob, Some(BlobId::from_bytes(jar)), "{url}");
        }
        // Back on repository a, its own copy is reused.
        let jar_requests = (a_server.requests().iter())
            .filter(|request| request.path == "/lib/x/1/x-1.jar")
            .count();
        assert_eq!(jar_requests, 1);

        let (unchecked, _unchecked) = serve(b"jar without a checksum", false);
        resolve(unchecked.clone(), true)
            .await
            .expect("allowed without a checksum");
        let err = resolve(unchecked, false)
            .await
            .expect_err("strict needs a checksum");
        assert!(err.to_string().contains("checksum"), "{err}");
    }

    /// Building the effective coordinates of modules whose remote parents give
    /// their `${revision}` counts as progress for the stall watchdog, fetch by
    /// fetch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn effective_module_coordinates_keep_the_watchdog_quiet() {
        const MODULES: usize = 3;
        // The server answers one POM at a time in 150ms, so the 18 parent
        // fetches take 2.7s, over twice the watchdog's window, and the window
        // leaves room for the slower steps of a loaded machine.
        const LEVELS: usize = 6;
        let mut routes = HashMap::new();
        let mut files = vec![(
            "pom.xml".to_string(),
            String::from_utf8(pom(
                "g",
                "root",
                "1",
                &format!(
                    "<packaging>pom</packaging><modules>{}</modules>",
                    (0..MODULES)
                        .map(|m| format!("<module>m{m}</module>"))
                        .collect::<String>()
                ),
            ))
            .unwrap(),
        )];
        for m in 0..MODULES {
            // A chain of remote parents, each one round trip.
            for level in 0..LEVELS {
                let parent = if level + 1 < LEVELS {
                    format!(
                        "<parent><groupId>corp</groupId><artifactId>p{m}-{}</artifactId>\
                         <version>1</version><relativePath/></parent>",
                        level + 1
                    )
                } else {
                    "<properties><revision>1</revision></properties>".to_string()
                };
                routes.insert(
                    format!("/corp/p{m}-{level}/1/p{m}-{level}-1.pom"),
                    pom(
                        "corp",
                        &format!("p{m}-{level}"),
                        "1",
                        &format!("<packaging>pom</packaging>{parent}"),
                    ),
                );
            }
            files.push((
                format!("m{m}/pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><parent><groupId>corp</groupId>\
                     <artifactId>p{m}-0</artifactId><version>1</version><relativePath/></parent>\
                     <groupId>g</groupId><artifactId>m{m}</artifactId>\
                     <version>${{revision}}</version><packaging>pom</packaging></project>"
                ),
            ));
        }
        let server = StubServer::start(move |request| {
            if request.path.ends_with(".pom") {
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            routes.get(&request.path).map_or_else(
                || Response::new(404, ""),
                |body| Response::new(200, body.clone()),
            )
        });
        let url = format!("http://{}/", server.addr());
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let (_dir, workspace) = reactor(&files);
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;
        let resolved = resolver
            .resolve_workspace_with_stall_timeout(
                &workspace,
                Some(std::time::Duration::from_millis(1_200)),
            )
            .await
            .expect("steady parent fetches are progress");
        assert_eq!(resolved.modules.len(), MODULES + 1);
    }

    /// An all-reactor resolve of more modules than run at once, all pulling
    /// the same dependencies with a remote parent, must finish; a hang shows
    /// as `WorkspaceStalled` under the short watchdog window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn overlapping_reactor_modules_resolve_without_stalling() {
        const MODULES: usize = 8;
        const SHARED_DEPS: usize = 6;
        let mut routes = HashMap::new();
        routes.insert(
            "/org/shared/shared-parent/1/shared-parent-1.pom".to_string(),
            pom(
                "org.shared",
                "shared-parent",
                "1",
                "<packaging>pom</packaging>",
            ),
        );
        let mut dependencies = String::new();
        for dep in 0..SHARED_DEPS {
            let base = format!("/org/shared/dep-{dep}/1/dep-{dep}-1");
            routes.insert(
                format!("{base}.pom"),
                pom(
                    "org.shared",
                    &format!("dep-{dep}"),
                    "1",
                    "<parent><groupId>org.shared</groupId><artifactId>shared-parent</artifactId>\
                     <version>1</version></parent>",
                ),
            );
            routes.insert(format!("{base}.jar"), format!("dep-{dep}").into_bytes());
            dependencies.push_str(&format!(
                "<dependency><groupId>org.shared</groupId><artifactId>dep-{dep}</artifactId>\
                 <version>1</version></dependency>"
            ));
        }
        let (url, _server) = spawn_repository_with_routes(routes);
        let names: Vec<String> = (0..MODULES).map(|m| format!("m{m}")).collect();
        let modules: String = names
            .iter()
            .map(|name| format!("<module>{name}</module>"))
            .collect();
        let root = pom(
            "com.example",
            "reactor",
            "1",
            &format!("<packaging>pom</packaging><modules>{modules}</modules>"),
        );
        let mut files = vec![("pom.xml".to_string(), String::from_utf8(root).unwrap())];
        for name in &names {
            let body = pom(
                "com.example",
                name,
                "1",
                &format!("<dependencies>{dependencies}</dependencies>"),
            );
            files.push((format!("{name}/pom.xml"), String::from_utf8(body).unwrap()));
        }
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        let (_dir, workspace) = reactor(&files);
        let (resolver, _store) = resolver(workspace.root(), Some(&url), false, true).await;

        let resolved = resolver
            .resolve_workspace_with_stall_timeout(
                &workspace,
                Some(std::time::Duration::from_secs(30)),
            )
            .await
            .expect("overlapping reactor modules must resolve");
        assert_eq!(resolved.modules.len(), MODULES + 1);
        for module in resolved.modules.iter().filter(|m| m.pom_path != "pom.xml") {
            assert_eq!(
                module.resolution.packages.len(),
                SHARED_DEPS,
                "{}",
                module.pom_path
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn root_project_reads_its_local_parent() {
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                  <artifactId>parent</artifactId><version>1-SNAPSHOT</version>\
                  <packaging>pom</packaging><repositories><repository><id>parent-only</id>\
                  <url>https://parent-only.example/repo/</url></repository></repositories>\
                  </project>";
    let checkout = tempfile::tempdir().unwrap();
    let child_dir = checkout.path().join("child");
    fs::create_dir_all(&child_dir).unwrap();
    fs::write(checkout.path().join("pom.xml"), parent).unwrap();
    fs::write(
        child_dir.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId>\
         <artifactId>parent</artifactId><version>1-SNAPSHOT</version>\
         <relativePath>../pom.xml</relativePath></parent><artifactId>child</artifactId>\
         </project>",
    )
    .unwrap();

    // A selected submodule is a one-module reactor whose parent lies outside it.
    let workspace = Workspace::discover(&child_dir).expect("single-module workspace");
    assert_eq!(workspace.len(), 1);
    let resolver = offline_resolver(&child_dir, &checkout.path().join("store"));
    let (_, project, observed, _) = resolver
        .load_root_project(
            &child_dir.join("pom.xml"),
            &[],
            Arc::new(workspace),
            None,
            None,
        )
        .await
        .expect("selected submodule resolves its immediate local parent");
    assert_eq!(project.group_id, "com.example");
    assert_eq!(project.version, "1-SNAPSHOT");
    // The parent's repositories reach the solver backend.
    let parent_only = "https://parent-only.example/repo/";
    assert!(
        observed.iter().any(|repo| repo.url == parent_only)
            || project
                .repositories
                .iter()
                .any(|repo| repo.url == parent_only),
        "{observed:?}"
    );
}

/// Root `file://${project.basedir}` repositories reach the solver after
/// interpolation. Unsupported schemes fail before resolution, and the error
/// does not show the URL's credentials.
#[tokio::test]
async fn root_repository_urls_are_interpolated_and_bad_schemes_fail_fast() {
    let pom_for = |url: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
             <artifactId>app</artifactId><version>1.0</version><repositories><repository>\
             <id>local</id><url>{url}</url></repository></repositories></project>"
        )
    };
    let (dir, loaded) = load_root(&pom_for("file:///${project.basedir}/lib"), &[]).await;
    let (_, _, observed) = loaded.expect("file repository is supported");
    let expected = rv_repo::normalize_repo_url(&format!("file:///{}/lib", dir.path().display()));
    assert!(
        observed
            .iter()
            .any(|repo| repo.is_local() && repo.url == expected),
        "{observed:?}"
    );
    assert!(observed.iter().all(|repo| !repo.url.contains("${")));

    let (_dir, loaded) = load_root(&pom_for("ftp://alice:s3cret@files.example/m2/"), &[]).await;
    let err = loaded.expect_err("ftp repositories are unsupported");
    assert!(
        err.to_string()
            .contains("unsupported URL 'ftp://files.example/m2/'"),
        "{err}"
    );
}

#[tokio::test]
async fn root_project_input_failures() {
    let (_dir, loaded) = load_root(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId>\
         <artifactId>nonexistent-parent</artifactId><version>9.9.9</version></parent>\
         <artifactId>child</artifactId></project>",
        &[],
    )
    .await;
    assert!(
        loaded.is_err(),
        "an unresolvable root parent must fail closed"
    );

    let oversized = "x".repeat(rv_config::MAX_PROJECT_INPUT_SIZE + 1);
    let (_dir, loaded) = load_root(&oversized, &[]).await;
    let error = loaded.expect_err("an oversized root POM must be rejected");
    assert!(
        matches!(
            error,
            crate::ResolveError::Config(rv_config::ConfigError::ProjectInputTooLarge { .. })
        ),
        "{error:?}"
    );
}

/// The reactor's support-POM flush is fatal: provenance for those POMs is
/// already recorded, so a swallowed failure would lock POMs the store never
/// took. The store's `tmp/` is made a file so `put_bytes` fails.
#[tokio::test]
async fn workspace_support_pom_flush_failure_is_fatal() {
    let proj_tmp = tempfile::tempdir().unwrap();
    let store_tmp = tempfile::tempdir().unwrap();
    let resolver = offline_resolver(proj_tmp.path(), store_tmp.path());
    let buffered = crate::resolver::WorkspaceStoreState::for_testing(vec![(
        ArtifactCoord::new("com.example", "theparent", "2.0", "pom", None),
        b"<project/>".to_vec(),
    )]);
    let staging = store_tmp.path().join("tmp");
    fs::remove_dir_all(&staging).expect("remove staging dir");
    fs::write(&staging, b"not a directory").expect("occupy staging path");

    let error = resolver
        .flush_workspace_support_poms(&buffered)
        .await
        .expect_err("a failed support-POM flush must fail the resolve");
    assert!(matches!(error, crate::ResolveError::Store(_)), "{error:?}");
}

/// For `packaging = "pom"` the artifact and its companion POM are one file,
/// so their two pins must agree; a jar or a classified `.pom` is another file.
#[test]
fn a_pom_package_pins_one_file() {
    let blob = |digest: char| -> BlobId {
        std::iter::repeat_n(digest, 64)
            .collect::<String>()
            .parse()
            .unwrap()
    };
    let package = |packaging: &str, classifier: Option<&str>| Coord {
        group_id: "com.example".into(),
        artifact_id: "platform".into(),
        version: rv_maven_types::Version::parse("1.0").unwrap(),
        packaging: Some(packaging.to_string()),
        classifier: classifier.map(str::to_string),
    };
    let check = super::utils::ensure_pom_packaging_identity;
    match check(&package("pom", None), &blob('a'), Some(&blob('b'))) {
        Err(crate::ResolveError::ConflictingPomPackagedBytes {
            coord,
            artifact_sha256,
            pom_sha256,
        }) => {
            assert_eq!(coord, "com.example:platform:1.0:pom");
            assert_eq!(artifact_sha256, blob('a').to_string());
            assert_eq!(pom_sha256, blob('b').to_string());
        }
        other => panic!("expected ConflictingPomPackagedBytes, got {other:?}"),
    }
    match check(&package("pom", None), &blob('a'), None) {
        Err(crate::ResolveError::ConflictingPomPackagedBytes { pom_sha256, .. }) => {
            assert_eq!(pom_sha256, "none");
        }
        other => panic!("expected ConflictingPomPackagedBytes, got {other:?}"),
    }
    check(&package("pom", None), &blob('a'), Some(&blob('a'))).unwrap();
    check(&package("jar", None), &blob('a'), Some(&blob('b'))).unwrap();
    check(&package("jar", None), &blob('a'), None).unwrap();
    check(&package("pom", Some("tests")), &blob('a'), None).unwrap();
}

mod stall_watchdog {
    use std::sync::Arc;
    use std::time::Duration;

    use super::super::{REACTOR_WIDE, WorkPhase, WorkspaceProgress, watch_for_stall};
    use crate::ResolveError;

    /// The report names what is in flight, by module index with the reactor
    /// flush last, and each with its phase.
    #[tokio::test]
    async fn fires_when_nothing_makes_progress_and_names_the_stuck_modules() {
        let progress = Arc::new(WorkspaceProgress::new());
        progress.enter(2, "gamma/pom.xml", WorkPhase::Graph);
        progress.enter(REACTOR_WIDE, "reactor", WorkPhase::SupportPomFlush);
        progress.enter(1, "beta/pom.xml", WorkPhase::Graph);
        progress.enter(0, "alpha/pom.xml", WorkPhase::ArtifactPopulation);
        progress.leave(2);

        let stalled = tokio::time::timeout(
            Duration::from_secs(10),
            watch_for_stall(Arc::clone(&progress), Duration::from_millis(200)),
        )
        .await
        .expect("the watchdog must fire on its own");
        match stalled {
            ResolveError::WorkspaceStalled { modules, .. } => assert_eq!(
                modules,
                "alpha/pom.xml (artifact population), beta/pom.xml (graph), \
                 reactor (support POM flush)"
            ),
            other => panic!("expected WorkspaceStalled, got {other:?}"),
        }
    }

    /// The watchdog watches progress events, never elapsed time.
    #[tokio::test(start_paused = true)]
    async fn never_fires_while_progress_keeps_landing() {
        let progress = Arc::new(WorkspaceProgress::new());
        progress.enter(0, "alpha/pom.xml", WorkPhase::Graph);
        let window = Duration::from_millis(200);
        let ticker = {
            let progress = Arc::clone(&progress);
            tokio::spawn(async move {
                for _ in 0..30 {
                    tokio::time::sleep(window / 4).await;
                    progress.note();
                }
            })
        };
        let fired = tokio::time::timeout(window * 6, watch_for_stall(progress, window)).await;
        assert!(fired.is_err(), "{fired:?}");
        ticker.abort();
    }
}
