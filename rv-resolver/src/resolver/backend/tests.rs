use super::*;
use rv_config::{Config, ResolvedPaths, SecurityConfig};
use rv_store::Store;
use std::str::FromStr;

/// A dependency build whose lineage declared `repos` as written.
fn declared_build(repos: impl IntoIterator<Item = Repository>) -> ModelBuild {
    let added = (repos.into_iter())
        .map(|repo| model_list::Added {
            repo,
            replace: false,
            reach: model_list::Reach::Read,
            implied: false,
        })
        .collect();
    ModelBuild {
        project: false,
        added,
    }
}

#[test]
fn equal_spellings_keep_mavens_hash_map_order() {
    // Maven 3.9.12's DefaultVersionRangeResolver gives these orders.
    let cases = [
        ("1.0 1", "1 1.0"),
        ("1.0.0 1.0 1", "1 1.0 1.0.0"),
        (
            "1 1.0 1.0.0 1-0 1.0-0 1.0.0.0",
            "1 1.0 1-0 1.0.0 1.0.0.0 1.0-0",
        ),
        (
            "1.0.0.0 1.0-0 1-0 1.0.0 1.0 1",
            "1 1.0 1-0 1.0.0.0 1.0.0 1.0-0",
        ),
        (
            "1-ga 1-final 1.ga 1.0.0 1.0 1 2 3 4 5 6 7 8 9 10 11 12 13",
            "1-ga 1.ga 1-final 1 1.0 1.0.0 2 3 4 5 6 7 8 9 10 11 12 13",
        ),
        // All eleven share a bin, which turns into a tree at a capacity of
        // 64 and iterates its root first.
        (
            "1-ga-ga.ga.0-0.ga.ga 1-ga-ga-0.ga-0.ga-0 1-ga-ga-0.ga-0-0-0 1-ga-ga-0-0-0.ga-0 \
             1-ga-ga-0-ga.ga.ga.ga 1-ga-ga.0.ga.0.ga-ga 1-ga-ga.0.0-ga-0.ga \
             1-ga-ga.0-ga.ga.ga-ga 1-ga-ga.0-ga.0-ga-0 1-ga-ga-ga.ga-0-ga-ga \
             1-ga-ga-ga.ga-ga.ga.ga",
            "1-ga-ga.0.0-ga-0.ga 1-ga-ga.ga.0-0.ga.ga 1-ga-ga-0.ga-0.ga-0 1-ga-ga-0.ga-0-0-0 \
             1-ga-ga-0-0-0.ga-0 1-ga-ga-0-ga.ga.ga.ga 1-ga-ga.0.ga.0.ga-ga \
             1-ga-ga.0-ga.ga.ga-ga 1-ga-ga.0-ga.0-ga-0 1-ga-ga-ga.ga-0-ga-ga \
             1-ga-ga-ga.ga-ga.ga.ga",
        ),
    ];
    for (listed, want) in cases {
        let mut versions: Vec<_> = listed
            .split(' ')
            .map(|v| Version::parse(v).unwrap())
            .collect();
        let spellings = (versions.iter())
            .map(|version| version.as_str().to_string())
            .collect();
        sort_as_maven_lists(&mut versions, &spellings, MavenMode::Maven39);
        let got: Vec<_> = versions.iter().map(Version::as_str).collect();
        assert_eq!(got.join(" "), want, "{listed}");
    }
}

#[tokio::test]
async fn snapshots_compare_all_repositories_and_keep_the_first_on_ties() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let same = [
        (Some("20261012010101"), Some("20261013010101"), 2),
        (Some("20261012010101"), Some("20261012010101"), 1),
        (None, Some("20261013010101"), 2),
        (Some("20261012010101"), None, 1),
    ];
    // A file's own entry in a later repository beats an earlier
    // repository's `<snapshot>` unless that one is newer.
    let mixed = [
        (Some("20261013010101"), Some("20261012010101"), 1),
        (Some("20261012010101"), Some("20261012010101"), 2),
        (None, Some("20261012010101"), 2),
    ];
    // An empty repository offers only the base version, which is no
    // candidate against a real build or a plain `<snapshot/>`.
    let empty = [(None, None, 2)];
    for (kinds, cases) in [
        (["entry", "entry"], &same[..]),
        (["legacy", "legacy"], &same[..]),
        (["plain", "plain"], &same[..]),
        (["plain", "legacy"], &same[..]),
        (["legacy", "entry"], &mixed[..]),
        (["empty", "legacy"], &empty[..]),
        (["empty", "plain"], &empty[..]),
    ] {
        for &(first_updated, second_updated, expected) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let mut repos = Vec::new();
            for (build, updated, legacy) in
                [(1, first_updated, kinds[0]), (2, second_updated, kinds[1])]
            {
                let root = tmp.path().join(format!("repo{build}"));
                let dir = root.join("test/demo/1-SNAPSHOT");
                std::fs::create_dir_all(&dir).unwrap();
                if legacy == "empty" {
                    repos.push(Repository::new(
                        None,
                        format!("file://{}/", root.display()),
                        true,
                        true,
                    ));
                    continue;
                }
                let last_updated = updated
                    .map(|value| format!("<lastUpdated>{value}</lastUpdated>"))
                    .unwrap_or_default();
                let metadata = if legacy == "legacy" {
                    format!(
                        "<snapshot><timestamp>20261012.010101</timestamp><buildNumber>{build}</buildNumber></snapshot>{last_updated}"
                    )
                } else if legacy == "plain" {
                    format!("<snapshot/>{last_updated}")
                } else {
                    format!(
                        "<snapshotVersions><snapshotVersion><extension>jar</extension><classifier>linux</classifier><value>1-20261012.010101-{build}</value>{}</snapshotVersion></snapshotVersions>",
                        updated
                            .map(|value| format!("<updated>{value}</updated>"))
                            .unwrap_or_default()
                    )
                };
                std::fs::write(dir.join("maven-metadata.xml"), format!("<metadata><version>1-SNAPSHOT</version><versioning>{metadata}</versioning></metadata>")).unwrap();
                repos.push(Repository::new(
                    None,
                    format!("file://{}/", root.display()),
                    true,
                    true,
                ));
            }
            let invalid = tmp.path().join("invalid/test/demo/1-SNAPSHOT");
            std::fs::create_dir_all(&invalid).unwrap();
            std::fs::write(invalid.join("maven-metadata.xml"), "invalid XML").unwrap();
            repos.push(Repository::new(
                None,
                format!("file://{}/invalid/", tmp.path().display()),
                true,
                true,
            ));
            let config = Config::for_testing_with_repos(
                tmp.path().to_owned(),
                ResolvedPaths::from_raeva_home(tmp.path().join("home")),
                Vec::new(),
            );
            let client = rv_repo::RepoClient::new(&config).await.unwrap();
            let ctx = ResolveContext::new(
                config,
                repos.clone(),
                Arc::new(Store::open(&tmp.path().join("store")).unwrap()),
                rv_lock::Platform::new("linux", "x86_64").unwrap(),
                Some(client),
            );
            let backend = ModelService::new(&ctx, repos.clone());
            let coord = Coord::parse("test:demo:1-SNAPSHOT:jar:linux").unwrap();
            let resolved = backend
                .resolve_snapshot_version_internal(&coord, &RepoContext::default())
                .await
                .unwrap();
            let version = if kinds[expected - 1] == "plain" {
                "1-SNAPSHOT".to_string()
            } else {
                format!("1-20261012.010101-{expected}")
            };
            assert_eq!(resolved.version.as_str(), version, "{kinds:?}");
            assert_eq!(resolved.repo, Some(RepoRef::of(&repos[expected - 1])));
        }
    }
}

/// A SNAPSHOT parent or BOM comes from the repository with the newest
/// build, not the first that has one.
#[tokio::test]
async fn snapshot_support_poms_take_the_newest_build_across_repositories() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempfile::tempdir().unwrap();
    let mut repos = Vec::new();
    for (build, updated) in [(1, "20261011010101"), (2, "20261012010101")] {
        let root = tmp.path().join(format!("repo{build}"));
        let dir = root.join("test/bom/1-SNAPSHOT");
        std::fs::create_dir_all(&dir).unwrap();
        let value = format!("1-2026101{build}.010101-{build}");
        std::fs::write(
            dir.join("maven-metadata.xml"),
            format!(
                "<metadata><version>1-SNAPSHOT</version><versioning><snapshotVersions>\
                 <snapshotVersion><extension>pom</extension><value>{value}</value>\
                 <updated>{updated}</updated></snapshotVersion></snapshotVersions>\
                 </versioning></metadata>"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join(format!("bom-{value}.pom")),
            format!(
                "<project><groupId>test</groupId><artifactId>bom</artifactId>\
                 <version>1-SNAPSHOT</version><description>{build}</description></project>"
            ),
        )
        .unwrap();
        repos.push(Repository::new(
            Some(format!("repo{build}")),
            format!("file://{}/", root.display()),
            true,
            true,
        ));
    }
    let config = Config::for_testing_with_repos(
        tmp.path().to_owned(),
        ResolvedPaths::from_raeva_home(tmp.path().join("home")),
        Vec::new(),
    );
    let client = rv_repo::RepoClient::new(&config).await.unwrap();
    let ctx = ResolveContext::new(
        config,
        repos.clone(),
        Arc::new(Store::open(&tmp.path().join("store")).unwrap()),
        rv_lock::Platform::new("linux", "x86_64").unwrap(),
        Some(client),
    );
    let backend = ModelService::new(&ctx, repos.clone());
    let coord = Coord::parse("test:bom:1-SNAPSHOT:pom").unwrap();
    let pom = backend
        .fetch_pom_bytes(
            &coord,
            &RepoContext::default(),
            &ModelBuild::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(pom.provenance.repo_id, "repo2");
    assert!(
        String::from_utf8_lossy(&pom.bytes).contains("<description>2</description>"),
        "{}",
        String::from_utf8_lossy(&pom.bytes)
    );

    // The newest build missing its POM fails rather than falling back
    // to an older one.
    std::fs::remove_file(
        tmp.path()
            .join("repo2/test/bom/1-SNAPSHOT/bom-1-20261012.010101-2.pom"),
    )
    .unwrap();
    let backend = ModelService::new(&ctx, repos.clone());
    assert!(
        backend
            .fetch_pom_bytes(
                &coord,
                &RepoContext::default(),
                &ModelBuild::default(),
                None
            )
            .await
            .is_err()
    );

    // Plain layouts compete by `lastUpdated` too. A dependency whose
    // newest build has no POM is used without one, as Maven does, not
    // with the older build's.
    for (artifact, build, updated) in [
        ("plain", 1, "20261011010101"),
        ("plain", 2, "20261012010101"),
        ("gone", 1, "20261011010101"),
        ("gone", 2, "20261012010101"),
    ] {
        let dir = tmp
            .path()
            .join(format!("repo{build}/test/{artifact}/1-SNAPSHOT"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("maven-metadata.xml"),
            format!(
                "<metadata><version>1-SNAPSHOT</version><versioning><snapshot/>\
                 <lastUpdated>{updated}</lastUpdated></versioning></metadata>"
            ),
        )
        .unwrap();
        if (artifact, build) == ("gone", 2) {
            continue;
        }
        std::fs::write(
            dir.join(format!("{artifact}-1-SNAPSHOT.pom")),
            format!(
                "<project><groupId>test</groupId><artifactId>{artifact}</artifactId>\
                 <version>1-SNAPSHOT</version></project>"
            ),
        )
        .unwrap();
    }
    let backend = ModelService::new(&ctx, repos.clone());
    let coord = Coord::parse("test:plain:1-SNAPSHOT:pom").unwrap();
    let pom = backend
        .fetch_pom_bytes(
            &coord,
            &RepoContext::default(),
            &ModelBuild::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(pom.provenance.repo_id, "repo2");
    let dependency = Coord::parse("test:plain:1-SNAPSHOT").unwrap();
    let project = backend
        .fetch_project_internal(&dependency, false, &RepoContext::default())
        .await
        .unwrap();
    assert_eq!(project.repo_url.as_deref(), Some(repos[1].url.as_str()));
    let gone = Coord::parse("test:gone:1-SNAPSHOT").unwrap();
    let missing = backend
        .fetch_project_internal(&gone, false, &RepoContext::default())
        .await
        .unwrap();
    assert_eq!(missing.repo_url, None);
}

/// A repository that refuses a SNAPSHOT parent's or BOM's metadata is
/// reported once a later one serves it.
#[test]
fn a_snapshot_support_pom_past_a_refusal_is_reported() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let refusing =
        rv_test_support::http::StubServer::start(|_| rv_test_support::http::Response::new(403, ""));
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("repo/test/bom/1-SNAPSHOT");
    std::fs::create_dir_all(&dir).unwrap();
    let value = "1-20261011.010101-1";
    std::fs::write(
        dir.join("maven-metadata.xml"),
        format!(
            "<metadata><version>1-SNAPSHOT</version><versioning><snapshotVersions>\
             <snapshotVersion><extension>pom</extension><value>{value}</value>\
             <updated>20261011010101</updated></snapshotVersion></snapshotVersions>\
             </versioning></metadata>"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join(format!("bom-{value}.pom")),
        "<project><groupId>test</groupId><artifactId>bom</artifactId>\
         <version>1-SNAPSHOT</version></project>",
    )
    .unwrap();
    let repos = vec![
        Repository::new(
            Some("refusing".to_string()),
            format!("http://{}/", refusing.addr()),
            true,
            true,
        ),
        Repository::new(
            Some("serving".to_string()),
            format!("file://{}/", tmp.path().join("repo").display()),
            true,
            true,
        ),
    ];
    // Configured, so the loopback address is reachable.
    let mut configured = rv_config::RepoConfig::new(Some("refusing"), &repos[0].url);
    configured.snapshots = Some(true);
    let config = Config::for_testing_with_repos(
        tmp.path().to_owned(),
        ResolvedPaths::from_raeva_home(tmp.path().join("home")),
        vec![configured],
    );
    let client = runtime.block_on(rv_repo::RepoClient::new(&config)).unwrap();
    let ctx = ResolveContext::new(
        config,
        repos.clone(),
        Arc::new(Store::open(&tmp.path().join("store")).unwrap()),
        rv_lock::Platform::new("linux", "x86_64").unwrap(),
        Some(client),
    );
    let backend = ModelService::new(&ctx, repos);
    let coord = Coord::parse("test:bom:1-SNAPSHOT:pom").unwrap();
    let logged = warnings(|| {
        let pom = runtime
            .block_on(backend.fetch_pom_bytes(
                &coord,
                &RepoContext::default(),
                &ModelBuild::default(),
                None,
            ))
            .unwrap();
        assert_eq!(pom.provenance.repo_id, "serving");
    });
    assert!(
        logged
            .iter()
            .any(|log| log.contains("a later repository served a file")),
        "{logged:?}"
    );
}

#[test]
fn snapshot_fallback_names_both_mirrors_and_requires_served_metadata() {
    use crate::resolver::pom_source::RepoPomSource;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for metadata_present in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let local = tmp.path().join("repo");
        let dir = local.join("g/a/1-SNAPSHOT");
        std::fs::create_dir_all(&dir).unwrap();
        if metadata_present {
            std::fs::write(dir.join("maven-metadata.xml"), "<metadata><version>1-SNAPSHOT</version><versioning><snapshot><timestamp>20261011.010101</timestamp><buildNumber>1</buildNumber></snapshot></versioning></metadata>").unwrap();
        }
        let local_url = format!("file://{}/", local.display());
        let mirrors = [
            ("corp-mirror", "https://mirror.example/", "internal"),
            ("public-mirror", local_url.as_str(), "public"),
        ]
        .map(|(id, url, origin)| {
            let mut mirror = rv_config::MirrorConfig::new(Some(id), url);
            mirror.mirror_of = vec![origin.into()];
            mirror
        });
        let config = Config::for_testing(
            tmp.path().to_owned(),
            ResolvedPaths::from_raeva_home(tmp.path().join("home")),
        )
        .with_mirrors(mirrors.to_vec());
        let source = RepoPomSource(runtime.block_on(rv_repo::RepoClient::new(&config)).unwrap());
        let refusing = Repository::new(
            Some("internal".into()),
            "https://internal.example/",
            true,
            true,
        );
        let serving = Repository::new(Some("public".into()), "https://public.example/", true, true);
        let coord = Coord::parse("g:a:1-SNAPSHOT").unwrap();
        let output = rv_test_support::capture_warnings(|| {
            runtime.block_on(async {
                let mut search = Search::default();
                search
                    .failed(
                        &source,
                        &refusing,
                        &coord,
                        RepoError::Unauthorized {
                            status: reqwest::StatusCode::UNAUTHORIZED,
                            url: "https://mirror.example/g/a/1-SNAPSHOT/maven-metadata.xml".into(),
                            sent: None,
                        },
                    )
                    .unwrap();
                let resolution = source.snapshot(&serving, &coord).await.unwrap();
                assert_eq!(resolution.metadata_served, metadata_present);
                search.snapshot_served(&source, &serving, &coord, &resolution);
            })
        });
        assert_eq!(
            output.contains("AUTH_FALLBACK"),
            metadata_present,
            "{output}"
        );
        if metadata_present {
            assert!(output.contains("refusing=\"corp-mirror\""), "{output}");
            assert!(output.contains("serving=\"public-mirror\""), "{output}");
        }
    }
}

#[test]
fn an_absent_and_an_empty_id_reach_the_resolution_once() {
    let repo = |id: Option<&str>, url: &str| {
        let mut repo = rv_maven_model::Repository::new(id, url);
        repo.snapshots_enabled = false;
        repo
    };
    let declared = [
        repo(Some(""), "https://empty.example/"),
        repo(Some("a"), "https://a.example/"),
        repo(None, "https://absent.example/"),
    ];
    let urls: Vec<String> = resolution_repositories(&declared)
        .map(|repo| repo.url)
        .collect();
    assert_eq!(urls, ["https://empty.example/", "https://a.example/"]);
}

#[tokio::test]
async fn offline_model_fetches_try_later_repository_caches() {
    use rv_repo::RepoClient;
    use rv_test_support::http::{Response, StubServer};

    const POM: &str = "\u{feff}<project><modelVersion>4.0.0</modelVersion>
            <groupId>test</groupId><artifactId>cached</artifactId><version>1</version>
            <properties><target>default</target></properties><profiles>
            <profile><id>x86</id><activation><os><arch>amd64</arch></os></activation>
            <properties><target>x86</target></properties></profile>
            <profile><id>arm</id><activation><os><arch>aarch64</arch></os></activation>
            <properties><target>arm</target></properties></profile>
            </profiles></project>";

    let _ = rustls::crypto::ring::default_provider().install_default();
    let server = StubServer::start(|request| {
        let path = &request.path;
        let (status, body) = if path.ends_with("maven-metadata.xml") {
            (
                200,
                "<metadata><version>1-SNAPSHOT</version><versioning><snapshot><timestamp>20261011.010101</timestamp><buildNumber>1</buildNumber></snapshot></versioning></metadata>",
            )
        } else if path.ends_with(".pom") {
            (200, POM)
        } else {
            (404, "")
        };
        Response::new(status, body)
    });
    let repo_url = format!("http://{}/", server.addr());
    let tmp = tempfile::tempdir().unwrap();
    let config = Config::for_testing_with_repos(
        tmp.path().to_owned(),
        ResolvedPaths::from_raeva_home(tmp.path().join("raeva")),
        Vec::new(),
    );
    let mut cached = Repository::new(None, &repo_url, true, true);
    cached.snapshots_update_policy = rv_config::UpdatePolicy::Interval(60);
    let missing = Repository::new(None, format!("{repo_url}missing/"), true, true);
    let online = RepoClient::new(&config)
        .await
        .unwrap()
        .with_allow_missing_checksums(true);
    online
        .policy()
        .admit([cached.clone()], rv_repo::Declaration::LocalPom);
    for version in ["1", "1-SNAPSHOT"] {
        online
            .fetch_pom(&cached, &ArtifactRequest::new("test", "cached", version))
            .await
            .unwrap();
    }
    server.stop();
    // The stub publishes no checksum files, so only a client that also
    // allows that may use what the online one cached.
    let offline = RepoClient::new(&config)
        .await
        .unwrap()
        .with_offline(true)
        .with_allow_missing_checksums(true);
    let store = Arc::new(Store::open(&tmp.path().join("store")).unwrap());
    let repos = vec![missing, cached.clone()];
    let ctx = ResolveContext::new(
        config,
        repos.clone(),
        store,
        rv_lock::Platform::new("linux", "x86_64").unwrap(),
        Some(offline),
    );
    let backend = ModelService::new(&ctx, repos);
    for version in ["1", "1-SNAPSHOT"] {
        let coord = Coord::parse(&format!("test:cached:{version}")).unwrap();
        backend
            .fetch_pom_bytes(
                &coord,
                &RepoContext::default(),
                &ModelBuild::default(),
                None,
            )
            .await
            .expect("cached parent/BOM in later repository");
        let project = backend
            .fetch_project_internal(&coord, false, &RepoContext::default())
            .await
            .expect("cached dependency in later repository");
        assert_eq!(project.repo_url.as_deref(), Some(cached.url.as_str()));
    }
    let coord = Coord::parse("test:cached:1-SNAPSHOT").unwrap();
    let snapshot = backend
        .resolve_snapshot_version_internal(&coord, &RepoContext::default())
        .await
        .unwrap();
    assert_eq!(snapshot.version.as_str(), "1-20261011.010101-1");
    let absent = Coord::parse("test:absent:1").unwrap();
    assert!(
        matches!(backend.fetch_pom_bytes(&absent, &RepoContext::default(), &ModelBuild::default(), None).await,
        Err(ResolveError::Repo { source, searched, .. }) if matches!(*source, RepoError::OfflineNotCached(_)) && searched.len() == 2)
    );

    for (arch, target) in [("x86_64", "x86"), ("aarch64", "arm")] {
        let platform_ctx = ResolveContext::from_config_with_state(
            ctx.config.clone(),
            Arc::clone(&ctx.store),
            rv_lock::Platform::new("linux", arch).unwrap(),
            ctx.client.clone(),
            ctx.state(),
        );
        for inactive in [false, true] {
            let mut config = platform_ctx.config.clone();
            if inactive {
                config.inactive_profiles = vec!["x86".into(), "arm".into()];
            }
            let module_ctx = platform_ctx.for_module(config);
            let module_backend = ModelService::new(&module_ctx, vec![cached.clone()]);
            let coord = Coord::parse("test:cached:1").unwrap();
            let result = module_backend
                .fetch_project_internal(&coord, false, &RepoContext::default())
                .await
                .unwrap();
            // Maven builds a dependency's model without the project's
            // inactive profile ids, so they do not change it.
            assert_eq!(
                result.project.properties.get("target").map(String::as_str),
                Some(target)
            );
            assert_eq!(result.repo_url.as_deref(), Some(cached.url.as_str()));
            assert_eq!(
                module_backend.companion_pom_blob(&pom_gav(&coord)),
                Some(Some(BlobId::from_bytes(POM.as_bytes())))
            );

            let raw = ModelScope::transitive(&module_backend, RepoContext::default())
                .parent(
                    &mut rv_maven_model::Parent {
                        group_id: "test".into(),
                        artifact_id: "cached".into(),
                        version: "1".into(),
                        relative_path: Some(String::new()),
                    },
                    rv_maven_model::ParentLookup::Project,
                )
                .await
                .unwrap()
                .unwrap();
            let mut expected = Pom::parse(POM).unwrap();
            expected.set_provenance(rv_maven_model::Provenance::Dependency);
            assert_eq!(raw, expected);
            let recorded = SupportPomProvenance {
                repo_url: cached.url.clone(),
                ..provenance("", POM.as_bytes())
            };
            assert_eq!(
                module_backend.support_pom_provenance_snapshot(),
                vec![("test:cached:1".into(), recorded)]
            );
        }
    }
}

/// A missing `systemPath` invalidates a system dependency's POM.
/// Maven keeps the artifact but discards all dependencies, including inherited ones.
#[tokio::test]
async fn invalid_remote_descriptor_discards_inherited_dependencies_without_retry() {
    use crate::resolver::pom_source::MemoryPomSource;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Resolver {
        parent: Pom,
        calls: AtomicUsize,
    }
    impl ModelSource for Resolver {
        type Error = ResolveError;

        async fn parent(
            &self,
            _: &mut rv_maven_model::Parent,
            _: rv_maven_model::ParentLookup,
        ) -> Result<Option<Pom>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.parent.clone()))
        }

        async fn import(&self, _: rv_maven_model::ImportCoord<'_>) -> Result<Option<Pom>> {
            Ok(None)
        }
    }

    for inherited in [false, true] {
        let invalid = "<dependency><groupId>g</groupId><artifactId>broken</artifactId>
                <version>1</version><scope>system</scope></dependency>";
        let parent = format!(
            "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>
                <dependencies><dependency><groupId>g</groupId><artifactId>x</artifactId>
                <version>1</version></dependency>{}</dependencies></project>",
            if inherited { invalid } else { "" },
        );
        let parent_xml = parent;
        let parent = Pom::parse(&parent_xml).unwrap();
        let pom_xml = format!(
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>
                <version>1</version></parent><artifactId>lib</artifactId>
                <dependencies>{}</dependencies>
                <profiles><profile><id>extra</id><activation><activeByDefault>true</activeByDefault></activation>
                <dependencies><dependency><groupId>g</groupId><artifactId>profile-dep</artifactId>
                <version>1</version></dependency></dependencies></profile></profiles></project>",
            if inherited { "" } else { invalid },
        );
        let pom = Pom::parse(&pom_xml).unwrap();
        let source = Resolver {
            parent,
            calls: AtomicUsize::new(0),
        };
        let coord = Coord::from_str("g:lib:1").unwrap();
        let error = build_remote_project(pom.clone(), &source, &ActivationContext::default())
            .await
            .expect("an invalid remote descriptor is no resolution error")
            .expect_err("the model is invalid");
        assert!(matches!(error, PomError::InvalidSystemPath(_)), "{error}");
        // What a dependency's fetch gives the solver.
        let files = std::collections::HashMap::from([
            (
                "g/parent/1/parent-1.pom".to_string(),
                parent_xml.into_bytes(),
            ),
            ("g/lib/1/lib-1.pom".to_string(), pom_xml.into_bytes()),
        ]);
        let served = MemoryPomSource::new(rv_config::SecurityConfig::default())
            .with_files("https://repo.example/", &files);
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(test_config(), Vec::new(), store, platform, None)
            .with_pom_source(Arc::new(served));
        let repo = Repository::new(None, "https://repo.example/", true, false);
        let backend = ModelService::new(&ctx, vec![repo]);
        let fetched = (backend.fetch_project_internal(&coord, false, &RepoContext::default()))
            .await
            .expect("an invalid descriptor is fetched");
        let project = &fetched.project;
        assert!(project.dependencies.is_empty(), "inherited={inherited}");
        assert!(project.dependency_management.dependencies.is_empty());
        assert!(project.repositories.is_empty());
        assert!(project.relocation.is_none());
        assert_eq!(
            (&*project.group_id, &*project.artifact_id, &*project.version),
            ("g", "lib", "1")
        );
        assert_eq!(
            source.calls.load(Ordering::SeqCst),
            1,
            "must not retry inheritance"
        );

        // The same invalid model remains an error for a reactor project.
        assert!(matches!(
            Project::build(
                pom,
                &source,
                ModelPolicy::PROJECT,
                &ActivationContext::default()
            )
            .await,
            Err(ResolveError::Pom(PomError::InvalidSystemPath(_)))
        ));
    }
}

/// A property cycle in a dependency POM makes it invalid, as Maven's
/// descriptor reader takes every model problem but a missing parent or
/// BOM, also when a model field or a `-D` value is part of the cycle.
#[tokio::test]
async fn a_property_cycle_makes_a_remote_descriptor_invalid() {
    struct NoModels;
    impl ModelSource for NoModels {
        type Error = ResolveError;

        async fn parent(
            &self,
            _: &mut rv_maven_model::Parent,
            _: rv_maven_model::ParentLookup,
        ) -> Result<Option<Pom>> {
            Ok(None)
        }

        async fn import(&self, _: rv_maven_model::ImportCoord<'_>) -> Result<Option<Pom>> {
            Ok(None)
        }
    }

    let field = "<build><finalName>${a}</finalName></build>\
        <properties><a>${project.build.finalName}</a></properties>";
    let user = "<properties><b>${a}</b></properties>";
    let mut defined = ActivationContext::default();
    defined.properties.insert("a".into(), "${b}".into());
    for (body, activation) in [(user, defined), (field, ActivationContext::default())] {
        let mut pom = Pom::parse(&format!(
            "<project><groupId>g</groupId><artifactId>lib</artifactId>\
             <version>1</version>{body}<dependencies><dependency><groupId>g</groupId>\
             <artifactId>x</artifactId><version>${{a}}</version></dependency>\
             </dependencies></project>"
        ))
        .unwrap();
        pom.set_provenance(rv_maven_model::Provenance::Dependency);
        let error = build_remote_project(pom, &NoModels, &activation)
            .await
            .expect("a property cycle is no resolution error")
            .expect_err("the model is invalid");
        assert!(error.to_string().contains("cycle"), "{error}");
    }
}

/// Every repository's SNAPSHOT metadata is read, so the reads go out
/// together: each one here is answered only once all have been asked.
#[tokio::test]
async fn snapshot_metadata_is_read_from_every_repository_at_once() {
    use crate::resolver::pom_source::{MemoryPomSource, PomSource};
    use rv_repo::{Admission, ArtifactRequest, Declaration, Metadata, RepoError};

    struct Gathered {
        inner: MemoryPomSource,
        barrier: tokio::sync::Barrier,
    }
    impl PomSource for Gathered {
        fn admit(&self, repos: Vec<Repository>, from: Declaration) -> Admission {
            self.inner.admit(repos, from)
        }
        fn effective_repository(&self, repo: &Repository) -> Repository {
            self.inner.effective_repository(repo)
        }
        fn pom<'a>(
            &'a self,
            repo: &'a Repository,
            request: &'a ArtifactRequest,
        ) -> crate::solver::BoxFuture<'a, std::result::Result<(Bytes, String), RepoError>> {
            self.inner.pom(repo, request)
        }
        fn metadata<'a>(
            &'a self,
            repo: &'a Repository,
            coord: &'a Coord,
        ) -> crate::solver::BoxFuture<'a, std::result::Result<Metadata, RepoError>> {
            self.inner.metadata(repo, coord)
        }
        fn snapshot<'a>(
            &'a self,
            repo: &'a Repository,
            coord: &'a Coord,
        ) -> crate::solver::BoxFuture<'a, std::result::Result<rv_repo::SnapshotResolution, RepoError>>
        {
            Box::pin(async move {
                self.barrier.wait().await;
                self.inner.snapshot(repo, coord).await
            })
        }
    }

    let hosts = ["first", "second", "third"];
    let inner = MemoryPomSource::new(rv_config::SecurityConfig::default());
    let source = Arc::new(Gathered {
        inner,
        barrier: tokio::sync::Barrier::new(hosts.len()),
    });
    let store_tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
    let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
    let ctx = ResolveContext::new(test_config(), Vec::new(), store, platform, None)
        .with_pom_source(source);
    let repos =
        hosts.map(|host| Repository::new(None, format!("https://{host}.example/"), true, true));
    let backend = ModelService::new(&ctx, repos.to_vec());
    let coord = Coord::from_str("g:a:1-SNAPSHOT").unwrap();
    let resolved = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        backend.resolve_snapshot_version_internal(&coord, &RepoContext::default()),
    )
    .await
    .expect("the metadata reads went out one after another");
    // The memory source serves no SNAPSHOT metadata, so, as in Maven, the
    // base version stands and no repository is preferred for its files.
    let resolved = resolved.expect("the base version");
    assert_eq!(resolved.version.as_str(), "1-SNAPSHOT");
    assert!(resolved.repo.is_none(), "{resolved:?}");
}

/// A POM comes from the first repository that has it, in declaration
/// order, and the repositories after it are not asked.
#[tokio::test]
async fn a_pom_comes_from_the_first_repository_that_has_it() {
    use crate::resolver::pom_source::MemoryPomSource;

    let pom =
        "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>";
    let files =
        std::collections::HashMap::from([("g/a/1/a-1.pom".to_string(), pom.as_bytes().to_vec())]);
    let source = Arc::new(
        MemoryPomSource::new(rv_config::SecurityConfig::default())
            .with_files("https://second.example/", &files)
            .with_files("https://third.example/", &files),
    );
    let store_tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
    let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
    let ctx = ResolveContext::new(test_config(), Vec::new(), store, platform, None)
        .with_pom_source(source.clone());
    let repos = ["first", "second", "third"]
        .map(|host| Repository::new(None, format!("https://{host}.example/"), true, false));
    let backend = ModelService::new(&ctx, repos.to_vec());

    let resolved = backend
        .fetch_project_internal(
            &Coord::from_str("g:a:1").unwrap(),
            false,
            &RepoContext::default(),
        )
        .await
        .expect("the second repository has the POM");
    assert_eq!(
        resolved.repo_url.as_deref(),
        Some("https://second.example/")
    );
    assert_eq!(
        source.requests(),
        [
            "https://first.example/g/a/1/a-1.pom",
            "https://second.example/g/a/1/a-1.pom"
        ]
    );
}

/// A [`ModelService`] over `repos`, whose files `source` serves, with a
/// prefetcher.
fn prefetching_backend(
    source: &Arc<crate::resolver::pom_source::MemoryPomSource>,
    store_root: &std::path::Path,
    repos: Vec<Repository>,
) -> ModelService {
    let store = Arc::new(Store::open(store_root).expect("store"));
    let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
    let ctx = ResolveContext::new(test_config(), Vec::new(), store, platform, None)
        .with_pom_source(Arc::clone(source) as Arc<dyn PomSource>);
    ModelService::new(&ctx, repos)
}

fn project(gav: &str, body: &str) -> (String, Vec<u8>) {
    let [group, artifact, version] = gav.split(':').collect::<Vec<_>>()[..] else {
        panic!("{gav}");
    };
    let path = format!("{group}/{artifact}/{version}/{artifact}-{version}.pom");
    let xml = format!(
        "<project><groupId>{group}</groupId><artifactId>{artifact}</artifactId>\
         <version>{version}</version>{body}</project>"
    );
    (path, xml.into_bytes())
}

fn pairs(files: &[(String, Vec<u8>)]) -> impl Iterator<Item = (&String, &Vec<u8>)> {
    files.iter().map(|(path, bytes)| (path, bytes))
}

/// A hinted POM's parent is prefetched from the repositories its own
/// version allows, not only from those that allow the hinted version: a
/// release's -SNAPSHOT parent comes from the snapshot repository.
#[tokio::test(start_paused = true)]
async fn a_hinted_release_prefetches_its_snapshot_parent() {
    use crate::resolver::pom_source::MemoryPomSource;

    let parent = "<parent><groupId>g</groupId><artifactId>par</artifactId>\
                  <version>1-SNAPSHOT</version></parent>";
    let source = Arc::new(
        MemoryPomSource::new(SecurityConfig::default())
            .prefetching()
            .with_files(
                "https://releases.example/",
                pairs(&[project("g:app:1", parent)]),
            )
            .with_files(
                "https://snapshots.example/",
                pairs(&[project("g:par:1-SNAPSHOT", "")]),
            ),
    );
    let store = tempfile::tempdir().unwrap();
    let repos = vec![
        Repository::new(None, "https://releases.example/", true, false),
        Repository::new(None, "https://snapshots.example/", false, true),
    ];
    let backend = prefetching_backend(&source, store.path(), repos);
    let app = Coord::from_str("g:app:1").unwrap();
    backend.prefetch_pom(&app, &RepoContext::default(), None, false);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let parent = "https://snapshots.example/g/par/1-SNAPSHOT/par-1-SNAPSHOT.pom";
    assert!(
        source.requests().iter().any(|url| url == parent),
        "{:?}",
        source.requests()
    );
}

/// A relocated coordinate's POM is recorded as a support POM, since
/// `mvn -o` reads it to follow the relocation and no lockfile row names
/// it; a POM without a relocation is not.
#[tokio::test]
async fn a_relocation_stub_is_recorded_as_a_support_pom() {
    use crate::resolver::pom_source::MemoryPomSource;

    let stub = "<project><groupId>old</groupId><artifactId>lib</artifactId><version>1</version>\
                <distributionManagement><relocation><groupId>new</groupId></relocation>\
                </distributionManagement></project>";
    let target =
        "<project><groupId>new</groupId><artifactId>lib</artifactId><version>1</version></project>";
    let files = std::collections::HashMap::from([
        ("old/lib/1/lib-1.pom".to_string(), stub.as_bytes().to_vec()),
        (
            "new/lib/1/lib-1.pom".to_string(),
            target.as_bytes().to_vec(),
        ),
    ]);
    let source = Arc::new(
        MemoryPomSource::new(rv_config::SecurityConfig::default())
            .with_files("https://repo.example/", &files),
    );
    let store_tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
    let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
    let ctx = ResolveContext::new(test_config(), Vec::new(), store, platform, None)
        .with_pom_source(source);
    let repo = Repository::new(Some("probe".into()), "https://repo.example/", true, false);
    let backend = ModelService::new(&ctx, vec![repo]);
    for coord in ["old:lib:1", "new:lib:1"] {
        backend
            .fetch_project_internal(
                &Coord::from_str(coord).unwrap(),
                false,
                &RepoContext::default(),
            )
            .await
            .expect(coord);
    }
    assert_eq!(
        backend.support_pom_provenance_snapshot(),
        vec![(
            "old:lib:1".into(),
            SupportPomProvenance {
                repo_url: "https://repo.example/".into(),
                ..provenance("probe", stub.as_bytes())
            }
        )]
    );
}

/// Exercise the real POM search without sockets, including support POMs
/// and the version-metadata listing path. Maven moves on after any
/// failed status.
#[tokio::test]
async fn refusals_do_not_hide_later_poms_or_metadata() {
    use crate::resolver::pom_source::MemoryPomSource;

    let files = std::collections::HashMap::from([
        ("g/a/1/a-1.pom".to_string(), b"<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>".to_vec()),
        ("g/a/maven-metadata.xml".to_string(), b"<metadata><versioning><versions><version>1</version></versions></versioning></metadata>".to_vec()),
    ]);
    for code in [401, 403, 407, 400, 410] {
        let source = Arc::new(
            MemoryPomSource::default()
                .with_refusal("https://first.example/", code)
                .with_files("https://second.example/", &files),
        );
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).unwrap());
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(test_config(), Vec::new(), store, platform, None)
            .with_pom_source(source.clone());
        let repos = ["first", "second"].map(|host| {
            Repository::new(
                Some(host.to_string()),
                format!("https://{host}.example/"),
                true,
                false,
            )
        });
        let backend = ModelService::new(&ctx, repos.to_vec());
        let coord = Coord::from_str("g:a:1").unwrap();
        let resolved = backend
            .fetch_project_internal(&coord, false, &RepoContext::default())
            .await
            .unwrap();
        assert_eq!(
            resolved.repo_url.as_deref(),
            Some("https://second.example/")
        );
        let support = backend
            .fetch_pom_bytes(
                &coord,
                &RepoContext::default(),
                &ModelBuild::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(support.provenance.repo_id, "second");
        let metadata = backend
            .listed_metadata(
                source.as_ref(),
                backend.effective_repos_snapshot(),
                "g",
                "a",
                false,
                false,
                rv_repo::MetadataReader::VersionRange,
            )
            .await
            .unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].0.url, "https://second.example/");
        assert!(
            source
                .requests()
                .iter()
                .any(|request| request.starts_with("https://first.example/"))
        );
    }
}

/// A version listing names a repository it left out while another
/// answered: through a fallback warning for an auth or server failure,
/// otherwise through `LISTING_REPO_SKIPPED`. A repository that failed a
/// retried request, such as a 502, fails the listing instead.
#[test]
fn listings_report_the_repositories_they_left_out() {
    use crate::resolver::pom_source::MemoryPomSource;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let files = std::collections::HashMap::from([(
        "g/a/maven-metadata.xml".to_string(),
        b"<metadata><versioning><versions><version>1</version></versions></versioning></metadata>"
            .to_vec(),
    )]);
    for (code, expected) in [
        (403, "AUTH_FALLBACK"),
        (500, "REPOSITORY_FALLBACK"),
        (501, "REPOSITORY_FALLBACK"),
        (
            418,
            "the versions of g:a were listed without repository 'first'",
        ),
        (502, ""),
    ] {
        let source = Arc::new(
            MemoryPomSource::default()
                .with_refusal("https://first.example/", code)
                .with_files("https://second.example/", &files),
        );
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).unwrap());
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(test_config(), Vec::new(), store, platform, None)
            .with_pom_source(source.clone());
        let repos = ["first", "second"].map(|host| {
            Repository::new(
                Some(host.to_string()),
                format!("https://{host}.example/"),
                true,
                false,
            )
        });
        let backend = ModelService::new(&ctx, repos.to_vec());
        let logged = warnings(|| {
            let listed = runtime.block_on(backend.listed_metadata(
                source.as_ref(),
                backend.effective_repos_snapshot(),
                "g",
                "a",
                false,
                false,
                rv_repo::MetadataReader::VersionRange,
            ));
            match code {
                502 => assert!(listed.is_err()),
                _ => assert_eq!(listed.unwrap().len(), 1),
            }
        });
        assert_eq!(logged.len(), usize::from(code != 502), "{logged:?}");
        assert!(
            logged.iter().all(|log| log.contains(expected)),
            "{logged:?}"
        );
    }

    // A workspace version keeps the range satisfiable when every listing
    // fails; the listing still names each repository it left out.
    let source = Arc::new(
        MemoryPomSource::default()
            .with_refusal("https://first.example/", 500)
            .with_refusal("https://second.example/", 403),
    );
    let store_tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(store_tmp.path()).unwrap());
    let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
    let ctx = ResolveContext::new(test_config(), Vec::new(), store, platform, None)
        .with_pom_source(source.clone());
    let repos = ["first", "second"].map(|host| {
        Repository::new(
            Some(host.to_string()),
            format!("https://{host}.example/"),
            true,
            false,
        )
    });
    let backend = ModelService::new(&ctx, repos.to_vec());
    let logged = warnings(|| {
        let listed = runtime.block_on(backend.listed_metadata(
            source.as_ref(),
            backend.effective_repos_snapshot(),
            "g",
            "a",
            false,
            true,
            rv_repo::MetadataReader::VersionRange,
        ));
        assert!(listed.unwrap().is_empty());
    });
    assert_eq!(logged.len(), 2, "{logged:?}");
    for (log, repository) in logged.iter().zip(["'first'", "'second'"]) {
        assert!(log.contains(repository), "{logged:?}");
    }
}

/// A repository whose version listing fails its checksum fails the range,
/// as a file that fails its checksum stops the search, rather than leave
/// the range to another repository's versions.
#[tokio::test]
async fn a_listing_that_fails_its_checksum_fails_the_range() {
    let tmp = tempfile::tempdir().unwrap();
    let mut repos = Vec::new();
    for (name, version, sha1) in [
        ("first", "2.0", Some("0".repeat(40))),
        ("second", "1.0", None),
    ] {
        let dir = tmp.path().join(name).join("com/example/lib");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("maven-metadata.xml"),
            format!(
                "<metadata><versioning><versions><version>{version}</version></versions>\
                 </versioning></metadata>"
            ),
        )
        .unwrap();
        if let Some(sha1) = sha1 {
            std::fs::write(dir.join("maven-metadata.xml.sha1"), sha1).unwrap();
        }
        let mut repo = Repository::new(
            Some(name.into()),
            reqwest::Url::from_directory_path(tmp.path().join(name))
                .unwrap()
                .to_string(),
            true,
            false,
        );
        repo.releases_checksum_policy = rv_config::ChecksumPolicy::Fail;
        repos.push(repo);
    }
    let config = Config::for_testing_with_repos(
        tmp.path().to_owned(),
        ResolvedPaths::from_raeva_home(tmp.path().join("home")),
        Vec::new(),
    );
    let client = rv_repo::RepoClient::new(&config).await.unwrap();
    let ctx = ResolveContext::new(
        config,
        repos.clone(),
        Arc::new(Store::open(&tmp.path().join("store")).unwrap()),
        rv_lock::Platform::new("linux", "x86_64").unwrap(),
        Some(client),
    );
    let backend = ModelService::new(&ctx, repos);
    let error = backend
        .resolve_versions_internal(
            "com.example",
            "lib",
            &VersionReq::parse("[1.0,3.0)").unwrap(),
            &RepoContext::default(),
            None,
        )
        .await
        .expect_err("the first listing fails its checksum");
    assert!(
        matches!(&error, ResolveError::Repo { source, .. }
            if matches!(source.cause(), RepoError::ChecksumMismatch { .. })),
        "{error:?}"
    );
}

/// A parent range lists the repositories the model being built declares,
/// as a fixed parent version is fetched from them.
#[tokio::test]
async fn parent_ranges_list_the_models_own_repositories() {
    use crate::resolver::pom_source::MemoryPomSource;

    let files = std::collections::HashMap::from([(
        "g/p/maven-metadata.xml".to_string(),
        b"<metadata><versioning><versions><version>1.5</version></versions></versioning></metadata>".to_vec(),
    )]);
    let source =
        Arc::new(MemoryPomSource::default().with_files("https://declared.example/", &files));
    let store_tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(store_tmp.path()).unwrap());
    let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
    let ctx = ResolveContext::new(test_config(), Vec::new(), store, platform, None)
        .with_pom_source(source.clone());
    let [root, declared] = ["root", "declared"].map(|host| {
        Repository::new(
            Some(host.to_string()),
            format!("https://{host}.example/"),
            true,
            false,
        )
    });
    let backend = ModelService::new(&ctx, vec![root]);
    let range = VersionReq::parse("[1,2)").unwrap();
    let found = backend
        .parent_range_version(
            "g",
            "p",
            &range,
            &RepoContext::default(),
            &declared_build([declared]),
            false,
        )
        .await
        .unwrap()
        .0;
    assert_eq!(found.map(|v| v.to_string()).as_deref(), Some("1.5"));
}

/// Maven 3.10 lists nothing from metadata that names a version with a
/// character no coordinate may hold; 3.9 lists the rest of it.
#[test]
fn maven_310_drops_metadata_with_an_invalid_version() {
    use crate::resolver::pom_source::MemoryPomSource;

    let listing = |versions: &str| {
        std::collections::HashMap::from([(
            "g/p/maven-metadata.xml".to_string(),
            format!(
                "<metadata><versioning><versions>{versions}</versions></versioning></metadata>"
            )
            .into_bytes(),
        )])
    };
    let found = |mode: MavenMode| {
        let source = MemoryPomSource::default()
            .with_files(
                "https://first.example/",
                &listing("<version>1.5</version><version>1:9</version>"),
            )
            .with_files(
                "https://second.example/",
                &listing("<version>1.2</version>"),
            );
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).unwrap());
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        let mut config = test_config();
        config.lock.maven.mode = mode;
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None)
            .with_pom_source(Arc::new(source));
        let repos = ["first", "second"].map(|host| repo(host, &format!("https://{host}.example/")));
        let backend = ModelService::new(&ctx, repos.to_vec());
        let range = VersionReq::parse("[1,2)").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(backend.parent_range_version(
                "g",
                "p",
                &range,
                &RepoContext::default(),
                &ModelBuild::default(),
                false,
            ))
            .unwrap()
            .0
            .map(|version| version.to_string())
    };
    assert_eq!(found(MavenMode::Maven39).as_deref(), Some("1.5"));
    assert_eq!(found(MavenMode::Maven310).as_deref(), Some("1.2"));
}

/// Maven 3.10 reads `RELEASE` through `DefaultVersionResolver`, which
/// refuses a control character in `<release>`, `<latest>` or a snapshot
/// field but not in `<versions>`, and a range through
/// `DefaultVersionRangeResolver`, the other way round. Metadata it refuses
/// reads as empty, so a range with no other listing names no version.
#[test]
fn maven_310_refuses_metadata_per_resolver() {
    use crate::resolver::pom_source::MemoryPomSource;

    let run = |mode: MavenMode, versioning: &str| {
        let metadata = format!("<metadata><versioning>{versioning}</versioning></metadata>");
        let files = std::collections::HashMap::from([(
            "g/p/maven-metadata.xml".to_string(),
            metadata.into_bytes(),
        )]);
        let source = MemoryPomSource::default().with_files("https://only.example/", &files);
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).unwrap());
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        let mut config = test_config();
        config.lock.maven.mode = mode;
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None)
            .with_pom_source(Arc::new(source));
        let backend = ModelService::new(&ctx, vec![repo("only", "https://only.example/")]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let repos = RepoContext::default();
            let release = backend
                .resolve_dynamic_version_internal("g", "p", DynamicVersionToken::Release, &repos)
                .await
                .map(|version| version.version.to_string());
            let range = VersionReq::parse("[1,2)").unwrap();
            let listed = match backend
                .resolve_versions_internal("g", "p", &range, &repos, None)
                .await
            {
                Ok(versions) => Ok(versions.len()),
                Err(ResolveError::VersionNotFound { .. }) => Err("no version"),
                Err(error) => panic!("{error}"),
            };
            (release.ok(), listed)
        })
    };
    let in_versions = "<release>1.5</release><versions><version>1.5</version>\
                       <version>1.\u{7}</version></versions>";
    let in_release = "<release>1.\u{7}</release><versions><version>1.5</version></versions>";
    let in_timestamp = "<release>1.5</release><versions><version>1.5</version></versions>\
                        <snapshot><timestamp>2024\u{7}</timestamp></snapshot>";
    for (versioning, maven_39, maven_310) in [
        (
            in_versions,
            (Some("1.5"), Ok(2)),
            (Some("1.5"), Err("no version")),
        ),
        (
            in_release,
            (Some("1.\u{7}"), Ok(1)),
            (None, Err("no version")),
        ),
        (in_timestamp, (Some("1.5"), Ok(1)), (None, Ok(1))),
    ] {
        let expect =
            |(release, listed): (Option<&str>, std::result::Result<usize, &'static str>)| {
                (release.map(str::to_string), listed)
            };
        assert_eq!(
            run(MavenMode::Maven39, versioning),
            expect(maven_39),
            "{versioning}"
        );
        assert_eq!(
            run(MavenMode::Maven310, versioning),
            expect(maven_310),
            "{versioning}"
        );
    }
}

#[test]
fn exhausted_auth_search_keeps_refusals_and_coordinate() {
    use crate::resolver::pom_source::MemoryPomSource;
    let source = MemoryPomSource::default();
    let coord = Coord::from_str("g:a:1").unwrap();
    for codes in [[401, 403], [403, 404], [404, 401]] {
        let mut search = Search::default();
        for (idx, code) in codes.into_iter().enumerate() {
            let repo = Repository::new(
                Some(format!("repo-{idx}")),
                format!("https://repo-{idx}.example/"),
                true,
                false,
            );
            let error = if code == 404 {
                RepoError::NotFound(repo.url.clone().into())
            } else {
                RepoError::Unauthorized {
                    status: reqwest::StatusCode::from_u16(code).unwrap(),
                    url: repo.url.clone(),
                    sent: None,
                }
            };
            search.failed(&source, &repo, &coord, error).unwrap();
        }
        let ResolveError::Repo {
            coord,
            source,
            searched,
        } = search.exhausted(&coord)
        else {
            panic!("expected auth failure");
        };
        assert_eq!(coord.as_deref(), Some("g:a:1"));
        assert!(matches!(source.status_code(), Some(401 | 403)));
        assert_eq!(searched.len(), 2);
        assert_eq!(
            searched
                .iter()
                .filter(|status| status.refused_by.is_some())
                .count(),
            codes.iter().filter(|code| **code != 404).count()
        );
    }
}

#[test]
fn an_auth_refusal_does_not_relax_checksum_enforcement() {
    use crate::resolver::pom_source::MemoryPomSource;
    use rv_maven_types::{Digest, HashAlgorithm};

    let source = MemoryPomSource::default();
    let repo = Repository::new(None, "https://repo.example/", true, false);
    let coord = Coord::from_str("g:a:1").unwrap();
    for check in [
        rv_repo::IntegritySource::Sidecar,
        rv_repo::IntegritySource::LockPin,
    ] {
        let mut search = Search::default();
        search
            .failed(
                &source,
                &repo,
                &coord,
                RepoError::Unauthorized {
                    status: reqwest::StatusCode::UNAUTHORIZED,
                    url: repo.url.clone(),
                    sent: None,
                },
            )
            .unwrap();
        let mismatch = RepoError::ChecksumMismatch {
            subject: coord.to_string().into(),
            artifact: None,
            expected: Digest::of_bytes(HashAlgorithm::Sha256, b"expected"),
            actual: Digest::of_bytes(HashAlgorithm::Sha256, b"wrong"),
            check,
        };
        let err = search.failed(&source, &repo, &coord, mismatch).unwrap_err();
        let ResolveError::Repo {
            source, searched, ..
        } = err
        else {
            panic!("expected checksum error");
        };
        assert!(
            matches!(*source, RepoError::ChecksumMismatch { check: actual, .. } if actual == check)
        );
        assert_eq!(searched.len(), 2);
    }
}

fn test_config() -> Config {
    let paths = ResolvedPaths::for_testing().expect("paths");
    Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new())
}

fn backend_in(
    store_root: &std::path::Path,
    secure: impl FnOnce(&mut SecurityConfig),
    initial: Vec<Repository>,
) -> ModelService {
    let mut config = test_config();
    secure(&mut config.security);
    let store = Arc::new(Store::open(store_root).expect("store"));
    let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
    let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
    ModelService::new(&ctx, initial)
}

fn backend(secure: impl FnOnce(&mut SecurityConfig)) -> ModelService {
    let store_tmp = tempfile::tempdir().unwrap();
    backend_in(store_tmp.path(), secure, Vec::new())
}

fn repo(id: &str, url: &str) -> Repository {
    Repository::new(Some(id.to_string()), url, true, false)
}

fn urls(backend: &ModelService) -> Vec<String> {
    backend
        .repos_snapshot()
        .into_iter()
        .map(|repo| repo.url)
        .collect()
}

/// The WARN events `f` emits, one line each. The `TRANSITIVE_REPO_DROPPED`
/// diagnostic is built from these events.
fn warnings(f: impl FnOnce()) -> Vec<String> {
    (rv_test_support::capture_warnings(f).lines())
        .filter(|line| line.split_whitespace().nth(1) == Some("WARN"))
        .map(String::from)
        .collect()
}

fn provenance(repo_id: &str, bytes: &[u8]) -> SupportPomProvenance {
    SupportPomProvenance {
        repo_id: repo_id.to_string(),
        repo_url: support_repo(Some(repo_id).filter(|id| !id.is_empty())).url,
        snapshot: None,
        sha256: BlobId::from_bytes(bytes).to_string(),
    }
}

fn support_repo(id: Option<&str>) -> Repository {
    let url = format!("https://{}.example/", id.unwrap_or("anonymous"));
    Repository::new(id.map(str::to_string), url, true, true)
}

const PARENT_PATH: &str = "com/example/theparent/2.0/theparent-2.0.pom";

/// A module records a reused support POM once while every coordinate in the
/// reactor's buffer has one blob, and on every reuse from the record that
/// gives one two, also partway through a reuse, since the order of
/// observations then decides that coordinate's index row.
#[tokio::test]
async fn a_reused_support_pom_is_recorded_once_until_a_coordinate_has_two_blobs() {
    let store_tmp = tempfile::tempdir().unwrap();
    let buffer = WorkspaceSupportPomBuffer::default();
    let backend = backend_in(store_tmp.path(), |_| {}, Vec::new())
        .with_workspace_support_poms(Arc::clone(&buffer));
    let coord = Coord {
        group_id: "com.example".into(),
        artifact_id: "theparent".into(),
        version: Version::parse("2.0").unwrap(),
        packaging: Some("pom".to_string()),
        classifier: None,
    };
    let pom = Arc::new(SupportPom::new(
        &coord,
        &support_repo(None),
        "https://endpoint.example/",
        PARENT_PATH,
        Bytes::from_static(b"<project/>"),
    ));
    let observations = || lock(&buffer.buffer).next_sequence;
    for _ in 0..3 {
        backend
            .record_kept_support_poms(&[Arc::clone(&pom)])
            .unwrap();
        backend
            .record_support_poms(&[Arc::clone(&pom)])
            .await
            .unwrap();
    }
    assert_eq!(observations(), 1);

    // Another module read a POM that this module then reads other bytes
    // for, ahead of the one it recorded, which is then recorded again.
    let sibling = Coord {
        artifact_id: "sibling".into(),
        ..coord
    };
    let sibling_path = "com/example/sibling/2.0/sibling-2.0.pom";
    let read = |bytes: &'static [u8]| {
        SupportPom::new(
            &sibling,
            &support_repo(None),
            "https://endpoint.example/",
            sibling_path,
            Bytes::from_static(bytes),
        )
    };
    let theirs = read(b"<project>theirs</project>");
    buffer.record(&theirs.key, &theirs.blob, &theirs.bytes, &theirs.route);
    let ours = Arc::new(read(b"<project>ours</project>"));
    backend
        .record_kept_support_poms(&[ours, Arc::clone(&pom)])
        .unwrap();
    assert_eq!(observations(), 4);
    let written = buffer.take_in_write_order();
    assert_eq!(written.last().map(|(_, blob, ..)| blob), Some(&pom.blob));
}

/// Support-POM provenance keys on the bare `g:a:v` the export side looks
/// up, pins the SHA-256 of the persisted bytes, lets a known repository id
/// replace an id-less record of the same bytes but not the reverse, and
/// refuses different bytes for one coordinate, since the lock pins one.
#[tokio::test]
async fn persist_support_pom_records_one_pin_per_coordinate() {
    let coord = Coord {
        group_id: "com.example".into(),
        artifact_id: "theparent".into(),
        version: Version::parse("2.0").unwrap(),
        packaging: Some("pom".to_string()),
        classifier: None,
    };
    let recorded = |repo_id: &str| {
        vec![(
            "com.example:theparent:2.0".to_string(),
            provenance(repo_id, b"<project/>"),
        )]
    };
    let store_tmp = tempfile::tempdir().unwrap();
    let backend = backend_in(store_tmp.path(), |_| {}, Vec::new());
    for (repo_id, expected) in [(None, ""), (Some("corp"), "corp"), (None, "corp")] {
        backend
            .persist_support_pom(&SupportPom::new(
                &coord,
                &support_repo(repo_id),
                "https://endpoint.example/",
                PARENT_PATH,
                Bytes::from_static(b"<project/>"),
            ))
            .await
            .expect("persist");
        assert_eq!(
            backend.support_pom_provenance_snapshot(),
            recorded(expected)
        );
    }
    let pinned = BlobId::from_str(&recorded("")[0].1.sha256).unwrap();
    assert!(backend.ctx.store.exists_async(&pinned).await);
    // Each repository that served it is kept as evidence for a restore.
    let mut served = (backend.ctx.store)
        .served_by(&pom_key(&coord), &pinned)
        .await
        .unwrap();
    served.sort();
    let route = |repo: &str| {
        (
            format!("https://{repo}.example/"),
            "https://endpoint.example/".into(),
        )
    };
    assert_eq!(served, [route("anonymous"), route("corp")]);

    let error = backend
        .persist_support_pom(&SupportPom::new(
            &coord,
            &support_repo(Some("corp")),
            "https://endpoint.example/",
            PARENT_PATH,
            Bytes::from_static(b"<project>second</project>"),
        ))
        .await
        .expect_err("different bytes for one coordinate must not be absorbed");
    assert!(
        matches!(&error, ResolveError::ConflictingResolvedPomBytes(pom)
            if pom.coord == "com.example:theparent:2.0"),
        "{error:?}"
    );
    assert_eq!(backend.support_pom_provenance_snapshot(), recorded("corp"));

    // A `-SNAPSHOT` parent records the deployed build it was read from.
    let snapshot = Coord::from_str("com.example:snap:1.0-SNAPSHOT").unwrap();
    let read = |file: &str| {
        SupportPom::new(
            &snapshot,
            &support_repo(Some("corp")),
            "https://endpoint.example/",
            &format!("com/example/snap/1.0-SNAPSHOT/snap-{file}.pom"),
            Bytes::from_static(b"<project/>"),
        )
        .provenance
        .snapshot
    };
    assert_eq!(
        read("1.0-20240101.010101-7"),
        rv_maven_types::SnapshotStamp::of_version("1.0-20240101.010101-7")
    );
    assert_eq!(read("1.0-SNAPSHOT"), None);
    // Its evidence is kept under the build read, as restore and export look
    // it up.
    let build = SupportPom::new(
        &snapshot,
        &support_repo(Some("corp")),
        "https://endpoint.example/",
        "com/example/snap/1.0-SNAPSHOT/snap-1.0-20240101.010101-7.pom",
        Bytes::from_static(b"<project>build</project>"),
    );
    backend.persist_support_pom(&build).await.expect("persist");
    let build_key = ArtifactCoord::new("com.example", "snap", "1.0-20240101.010101-7", "pom", None);
    let served = (backend.ctx.store).served_by(&build_key, &build.blob).await;
    assert_eq!(served.unwrap(), [route("corp")]);
    let served = (backend.ctx.store)
        .served_by(&pom_key(&snapshot), &build.blob)
        .await;
    assert_eq!(served.unwrap(), []);
    let plain = Coord::from_str("com.example:snap:1.0SNAPSHOT").unwrap();
    let plain = SupportPom::new(
        &plain,
        &support_repo(Some("corp")),
        "https://endpoint.example/",
        "com/example/snap/1.0SNAPSHOT/snap-1.020240101.010101-7.pom",
        Bytes::from_static(b"<project/>"),
    );
    assert_eq!(
        plain.provenance.snapshot,
        rv_maven_types::SnapshotStamp::of_version("1.0-20240101.010101-7")
    );
    // An explicitly timestamped version names its file itself.
    let pinned = Coord::from_str("com.example:snap:1.0-20240101.010101-7").unwrap();
    let explicit = SupportPom::new(
        &pinned,
        &support_repo(Some("corp")),
        "https://endpoint.example/",
        "com/example/snap/1.0-SNAPSHOT/snap-1.0-20240101.010101-7.pom",
        Bytes::from_static(b"<project/>"),
    );
    assert_eq!(explicit.provenance.snapshot, None);

    // A store write failure fails the resolve and records nothing. The
    // store's `tmp/` is made a file so `put_bytes` cannot create it.
    let store_tmp = tempfile::tempdir().unwrap();
    let backend = backend_in(store_tmp.path(), |_| {}, Vec::new());
    let staging = store_tmp.path().join("tmp");
    std::fs::remove_dir_all(&staging).expect("remove staging dir");
    std::fs::write(&staging, b"not a directory").expect("occupy staging path");
    let error = backend
        .persist_support_pom(&SupportPom::new(
            &coord,
            &support_repo(Some("corp")),
            "https://endpoint.example/",
            PARENT_PATH,
            Bytes::from_static(b"<project/>"),
        ))
        .await
        .expect_err("a store write failure must fail the resolve");
    assert!(matches!(error, ResolveError::Store(_)), "{error:?}");
    assert!(backend.support_pom_provenance_snapshot().is_empty());
}

/// A fetched POM's `<repositories>` are dropped by default, with one
/// warning each, so a hostile transitive package cannot add a repository
/// later fetches would query. The global opt-in or a URL-prefix allowlist
/// admits them.
#[test]
fn transitive_repositories_are_admitted_only_by_policy() {
    assert!(!test_config().security.allow_transitive_repositories);
    let allowed = "https://allowed.example/maven2/";
    let attacker = "https://attacker.example/maven2/";
    let fetched = [repo("vendor", allowed), repo("attacker", attacker)];
    for (allow_all, allowlist, admitted) in [
        (false, None, &[][..]),
        (true, None, &[allowed, attacker][..]),
        (false, Some("https://allowed.example/"), &[allowed][..]),
    ] {
        let backend = backend(|security| {
            security.allow_transitive_repositories |= allow_all;
            security
                .transitive_repository_allowlist
                .extend(allowlist.map(str::to_string));
        });
        let warned = warnings(|| backend.extend_repos(fetched.clone(), Some("g:a:1")));
        assert_eq!(urls(&backend), admitted, "{allow_all} {allowlist:?}");
        assert_eq!(warned.len(), fetched.len() - admitted.len(), "{warned:?}");
        assert!(
            warned
                .iter()
                .all(|message| message.contains("ignoring transitive repository declaration")),
            "{warned:?}"
        );
    }
}

/// Central under either name, and a snapshot-only repository that a release
/// declares, are dropped without a warning: Central is searched anyway, and
/// a release resolves no snapshot. A not-found error still names them.
#[test]
fn central_and_unusable_snapshot_repositories_drop_quietly() {
    let backend = backend(|_| {});
    let snapshots = "https://snapshots.example/maven2/";
    let fetched = [
        repo("c1", "https://repo1.maven.org/maven2/"),
        repo("c2", "https://REPO.maven.apache.org/maven2"),
        Repository::new(Some("snapshots".to_string()), snapshots, false, true),
    ];
    let warned = warnings(|| backend.extend_repos(fetched.clone(), Some("g:a:1")));
    assert!(warned.is_empty(), "{warned:?}");
    let warned = warnings(|| backend.extend_repos(fetched.clone(), Some("g:b:1-SNAPSHOT")));
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains(snapshots), "{warned:?}");
    assert_eq!(lock(&backend.dropped_repos).len(), 6);
}

/// The root project's own `<repositories>` merge even under the
/// default-deny policy, without a warning, and every extension
/// deduplicates by id and URL, also against the starting repositories.
/// A URL stays listed under each of its ids, as Maven lists it.
#[test]
fn root_repositories_bypass_policy_and_every_extension_deduplicates() {
    let central = "https://central.example/maven2/";
    let user = "https://user.example/maven2/";
    let store_tmp = tempfile::tempdir().unwrap();
    let backend = backend_in(store_tmp.path(), |_| {}, vec![repo("central", central)]);
    let warned = warnings(|| {
        backend.extend_root_repos([repo("user", user)]);
        for _ in 0..5 {
            backend.extend_root_repos([repo("central-again", central)]);
        }
    });
    assert!(warned.is_empty(), "{warned:?}");
    assert_eq!(urls(&backend), [central, user, central]);

    let dup = "https://dup.example/maven2/";
    let backend = backend_in(
        store_tmp.path(),
        |security| security.allow_transitive_repositories = true,
        vec![repo("central", central)],
    );
    backend.extend_repos([repo("central-again", central)], Some("g:a:1"));
    for _ in 0..1000 {
        backend.extend_repos([repo("dup", dup)], Some("g:a:1"));
    }
    assert_eq!(urls(&backend), [central, central, dup]);
}

/// The project's repositories are searched before the defaults, as Maven
/// searches the super POM's `central` last, and one under a default's id
/// replaces that default. A dependency's POM adds its own after them all.
#[test]
fn project_repositories_precede_the_defaults() {
    let central = "https://repo1.maven.org/maven2/";
    let corp = "https://corp.example/maven2/";
    let central_proxy = "https://proxy.example/central/";
    let fetched = "https://fetched.example/maven2/";
    let extra = "https://extra.example/maven2/";
    let store_tmp = tempfile::tempdir().unwrap();
    let config = test_config();
    let defaults = config.repositories().iter().map(Repository::from);
    let backend = backend_in(
        store_tmp.path(),
        |security| security.allow_transitive_repositories = true,
        defaults.chain([repo("corp", corp)]).collect(),
    );
    assert_eq!(urls(&backend), [corp, central]);
    backend.extend_repos([repo("fetched", fetched)], Some("g:a:1"));
    assert_eq!(urls(&backend), [corp, central, fetched]);
    backend.extend_root_lineage_repos([(repo("central", central_proxy), false)]);
    assert_eq!(urls(&backend), [corp, central_proxy, fetched]);
    backend.extend_root_lineage_repos([(repo("extra", extra), false)]);
    assert_eq!(urls(&backend), [corp, central_proxy, extra, fetched]);
}

/// The project's repositories are one per id, as Maven's model merges
/// them: a parent's repository under an id the child or the
/// configuration uses on another URL is not searched and gets none of
/// that id's credential. One URL under two ids stays listed under both.
#[test]
fn a_repository_id_names_one_project_repository() {
    let (configured, pom) = ("https://configured.example/", "https://pom.example/");
    let (new, old) = ("https://new.example/", "https://old.example/");
    let store_tmp = tempfile::tempdir().unwrap();
    let start = || {
        backend_in(
            store_tmp.path(),
            |_| {},
            vec![repo("configured", configured)],
        )
    };
    let listed = |backend: &ModelService| {
        let repos = backend.effective_repos_snapshot().into_iter();
        repos
            .map(|repo| (repo.id.unwrap(), repo.url))
            .collect::<Vec<_>>()
    };
    let pairs = |pairs: &[(&str, &str)]| {
        let pairs = pairs
            .iter()
            .map(|(id, url)| (id.to_string(), url.to_string()));
        pairs.collect::<Vec<_>>()
    };

    let backend = start();
    backend.extend_root_repos([repo("corp", new)]);
    backend
        .extend_root_lineage_repos([(repo("corp", old), false), (repo("configured", pom), false)]);
    backend.extend_root_effective_repos([repo("corp", new), repo("configured", pom)]);
    assert_eq!(
        listed(&backend),
        pairs(&[("configured", configured), ("corp", new)])
    );

    // A child declaring its URL through an expression leaves the
    // parent's entry to its parent lookups, until the effective model.
    let backend = start();
    backend.extend_root_lineage_repos([(repo("corp", old), false)]);
    assert_eq!(
        listed(&backend),
        pairs(&[("configured", configured), ("corp", old)])
    );
    backend.extend_root_effective_repos([repo("corp", new)]);
    assert_eq!(
        listed(&backend),
        pairs(&[("configured", configured), ("corp", new)])
    );

    let snapshots = Repository::new(Some("corp-snapshots".into()), new, false, true);
    backend.extend_root_repos([snapshots]);
    assert_eq!(
        listed(&backend),
        pairs(&[
            ("configured", configured),
            ("corp", new),
            ("corp-snapshots", new)
        ])
    );
}

/// A child's repository that raeva refuses, here by the HTTP blocker,
/// still overrides its parent's under the same id, as Maven's blocked
/// mirror does: the parent's URL is not searched in its place.
#[test]
fn a_refused_repository_keeps_its_id_from_the_parent() {
    let declared = |id: &str, url: &str| {
        let mut pom = Pom::parse(&format!(
            "<project><repositories><repository><id>{id}</id><url>{url}</url>\
             </repository></repositories></project>"
        ))
        .unwrap();
        pom.mark_root_repositories();
        Repository::from(&pom.repositories[0])
    };
    let (blocked, old) = ("http://new.example/", "https://old.example/");
    for child_first in [true, false] {
        let backend = backend(|_| {});
        if child_first {
            backend.extend_root_lineage_repos([(declared("corp", blocked), false)]);
        }
        backend.extend_root_lineage_repos([(declared("corp", old), false)]);
        backend.extend_root_effective_repos([declared("corp", blocked)]);
        assert!(
            urls(&backend).is_empty(),
            "{child_first} {:?}",
            urls(&backend)
        );
        backend.extend_repos([declared("corp", old)], Some("g:a:1"));
        assert!(urls(&backend).is_empty(), "{child_first}");
    }
}

/// A remote parent's `central` replaces the default Central. The child's
/// own `central`, which the effective model gives a plain HTTP URL that
/// Maven's blocker refuses, overrides the parent's, and Maven's request
/// Central is searched again, as Maven's blocked mirror keeps an id of its
/// own.
#[test]
fn a_refused_effective_central_brings_back_the_default() {
    let central = "https://repo1.maven.org/maven2/";
    let store_tmp = tempfile::tempdir().unwrap();
    let config = test_config();
    let defaults = config.repositories().iter().map(Repository::from);
    let backend = backend_in(store_tmp.path(), |_| {}, defaults.collect());
    let central_at = |url: &str, local: bool| {
        let mut pom = Pom::parse(&format!(
            "<project><repositories><repository><id>central</id><url>{url}</url>\
             </repository></repositories></project>"
        ))
        .unwrap();
        if local {
            pom.mark_root_repositories();
        }
        Repository::from(&pom.repositories[0])
    };
    let parent = central_at("https://proxy.example/central/", false);
    backend.extend_root_lineage_repos([(parent, false)]);
    assert_eq!(urls(&backend), ["https://proxy.example/central/"]);
    backend.extend_root_effective_repos([central_at("http://plain.example/m2/", true)]);
    assert_eq!(urls(&backend), [central]);
}

/// Maven dedupes the project's repositories against its request ones by
/// the ids mirrors give them. A POM `central` on plain HTTP that a mirror
/// of `external:http:*` serves keeps the default Central beside it; one
/// mirror over both leaves one entry, the POM's. The child's `central`
/// still holds the id against its parents', and an effective model's
/// `central` retires a parent's.
#[test]
fn a_mirror_of_one_central_keeps_the_other() {
    let central = "https://repo1.maven.org/maven2/";
    let legacy = "http://repo1.maven.org/maven2/";
    let custom = "https://custom.example/m2/";
    let backend_with = |mirror_of: &str| {
        let mut mirror = rv_config::MirrorConfig::new(Some("proxy"), "https://proxy.example/");
        mirror.mirror_of = vec![mirror_of.into()];
        let config = test_config().with_mirrors(vec![mirror]);
        let defaults = config.repositories().iter().map(Repository::from).collect();
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
        ModelService::new(&ctx, defaults)
    };
    let central_at = |url: &str, local: bool| {
        let mut pom = Pom::parse(&format!(
            "<project><repositories><repository><id>central</id><url>{url}</url>\
             </repository></repositories></project>"
        ))
        .unwrap();
        if local {
            pom.mark_root_repositories();
        }
        Repository::from(&pom.repositories[0])
    };
    for (mirror_of, listed) in [
        ("external:http:*", vec![legacy, central]),
        ("central", vec![legacy]),
    ] {
        let backend = backend_with(mirror_of);
        backend.extend_root_lineage_repos([(central_at(legacy, true), false)]);
        assert_eq!(urls(&backend), listed, "{mirror_of}");
        backend.extend_root_lineage_repos([(central_at(custom, false), false)]);
        assert_eq!(urls(&backend), listed, "{mirror_of}: a parent's central");
    }

    let backend = backend_with("external:http:*");
    backend.extend_root_lineage_repos([(central_at(legacy, false), false)]);
    assert_eq!(urls(&backend), [legacy, central]);
    backend.extend_root_effective_repos([central_at(custom, true)]);
    assert_eq!(urls(&backend), [custom]);

    let backend = backend_with("external:http:*");
    backend.extend_root_lineage_repos([(central_at(custom, false), false)]);
    assert_eq!(urls(&backend), [custom]);
    backend.extend_root_effective_repos([central_at(legacy, true)]);
    assert_eq!(urls(&backend), [legacy, central]);
}

/// A child's repository first listed by its effective model, as one whose
/// URL names a property its parent defines, is searched before the
/// parent's, in the effective model's order.
#[test]
fn an_effective_model_keeps_its_order() {
    let central = "https://repo1.maven.org/maven2/";
    let (child, parent) = ("https://child.example/", "https://parent.example/");
    let store_tmp = tempfile::tempdir().unwrap();
    let config = test_config();
    let defaults = config.repositories().iter().map(Repository::from);
    let backend = backend_in(store_tmp.path(), |_| {}, defaults.collect());
    backend.extend_root_lineage_repos([(repo("parent", parent), false)]);
    assert_eq!(urls(&backend), [parent, central]);
    backend.extend_root_effective_repos([repo("child", child), repo("parent", parent)]);
    assert_eq!(urls(&backend), [child, parent, central]);
}

#[test]
fn pom_http_repositories_do_not_enter_search_lists() {
    for local in [true, false] {
        let backend = backend(|security| security.allow_transitive_repositories = true);
        let mut pom = Pom::parse(
            "<project><repositories>
                   <repository><id>blocked</id><url>http://resolver.example/</url></repository>
                   <repository><id>secure</id><url>https://secure.example/</url></repository>
                   <repository><id>loopback</id><url>http://127.0.0.1:8080/</url></repository>
                 </repositories></project>",
        )
        .unwrap();
        if local {
            pom.mark_root_repositories();
        }
        let repositories: Vec<_> = pom.repositories.iter().map(Repository::from).collect();
        backend.extend_root_repos(repositories.clone());
        backend.extend_repos(repositories, Some("g:a:1"));
        assert_eq!(
            urls(&backend),
            ["https://secure.example/", "http://127.0.0.1:8080/"]
        );
        // Kept only so that a not-found error can name it.
        let dropped = backend.dropped_repos.lock().unwrap();
        assert_eq!(dropped.len(), 1);
        assert!(dropped[0].http_blocked && dropped[0].url == "http://resolver.example/");
    }
}

/// Only the project's own POM may point raeva at the local file system:
/// a remote parent's or a dependency's `file:` repository is refused,
/// also when XML character references put whitespace in its scheme
/// that the URL parser later strips.
#[test]
fn file_repositories_come_only_from_the_project_pom() {
    let hostile = |url: &str| {
        let xml = format!(
            "<project><repositories>
                   <repository><id>local</id><url>{url}</url></repository>
                   <repository><id>web</id><url>https://web.example/m2/</url></repository>
                 </repositories></project>"
        );
        let pom = Pom::parse(&xml).unwrap();
        assert!(Repository::from(&pom.repositories[0]).is_local(), "{url}");
        pom.repositories
            .iter()
            .map(Repository::from)
            .collect::<Vec<_>>()
    };
    let schemes = [
        "file:///etc/",
        "fi&#x9;le:///etc/",
        "fi&#xA;le:///etc/",
        "fi&#xD;le:///etc/",
    ];
    let transitive = backend(|security| security.allow_transitive_repositories = true);
    let parent = backend(|_| {});
    for url in schemes {
        transitive.extend_repos(hostile(url), Some("g:a:1"));
        parent.extend_root_repos(hostile(url));
    }
    assert_eq!(urls(&transitive), ["https://web.example/m2/"]);
    assert_eq!(urls(&parent), ["https://web.example/m2/"]);

    let mut pom = Pom::parse(
        "<project><repositories><repository><id>local</id>
               <url>file:///srv/maven/</url></repository></repositories></project>",
    )
    .unwrap();
    pom.mark_root_repositories();
    parent.extend_root_repos(pom.repositories.iter().map(Repository::from));
    assert!(parent.repos_snapshot().iter().any(Repository::is_local));
}

#[test]
fn only_an_effective_declaration_replaces_a_provisional_lineage_entry() {
    let backend = backend(|_| {});
    let repo = |url: &str, policy: rv_config::ChecksumPolicy| {
        let id = url.trim_start_matches("https://").split('.').next();
        let mut repo = Repository::new(id.map(str::to_string), url, true, true);
        repo.releases_checksum_policy = policy;
        repo
    };
    let read = |url: &str| {
        backend
            .repos_snapshot()
            .into_iter()
            .find(|known| known.url == url)
            .map(|known| known.releases_checksum_policy)
    };
    use rv_config::ChecksumPolicy::{Fail, Unsupported, Warn};

    backend.extend_root_lineage_repos([
        (repo("https://provisional.example/", Unsupported), true),
        (repo("https://settled.example/", Fail), false),
    ]);
    backend.extend_root_lineage_repos([(repo("https://settled.example/", Unsupported), true)]);
    backend.extend_root_lineage_repos([(repo("https://provisional.example/", Fail), true)]);
    assert_eq!(read("https://provisional.example/"), Some(Unsupported));
    assert_eq!(read("https://settled.example/"), Some(Fail));

    backend.extend_root_effective_repos([
        repo("https://provisional.example/", Warn),
        repo("https://settled.example/", Warn),
    ]);
    assert_eq!(read("https://provisional.example/"), Some(Warn));
    assert_eq!(read("https://settled.example/"), Some(Fail));

    backend.extend_root_effective_repos([repo("https://provisional.example/", Fail)]);
    backend.extend_root_effective_repos([repo("https://provisional.example/", Warn)]);
    assert_eq!(read("https://provisional.example/"), Some(Fail));

    backend.extend_root_lineage_repos([
        (repo("https://outside.example/", Unsupported), true),
        (repo("https://hidden.example/", Unsupported), true),
        (repo("https://shared.example/", Unsupported), true),
    ]);
    backend.extend_root_repos([
        repo("https://outside.example/", Fail),
        repo("https://shared.example/", Warn),
    ]);
    backend.extend_root_effective_repos([repo("https://outside.example/", Warn)]);
    assert_eq!(read("https://outside.example/"), Some(Fail));
    let effective: Vec<_> = backend
        .effective_repos_snapshot()
        .into_iter()
        .map(|known| (known.url, known.releases_checksum_policy))
        .collect();
    let policy = |url: &str| {
        effective
            .iter()
            .find(|(known, _)| known == url)
            .map(|(_, policy)| *policy)
    };
    assert_eq!(policy("https://hidden.example/"), None);
    assert_eq!(policy("https://shared.example/"), Some(Warn));
    assert_eq!(policy("https://provisional.example/"), Some(Fail));
}

/// A dependency's POM cannot take over a project repository: not by
/// relaxing a listed URL's checksum policy, and not by reusing the id on
/// another URL, which adds nothing, as in Maven, neither to the shared
/// list nor to its own parent lookups. Under a new id it still adds its
/// repository.
#[test]
fn a_fetched_pom_cannot_override_a_project_repository() {
    let backend = backend(|security| security.allow_transitive_repositories = true);
    let mut listed = repo("r", "https://r.example/");
    listed.releases_checksum_policy = rv_config::ChecksumPolicy::Warn;
    backend.extend_root_repos([listed.clone(), repo("corp", "https://corp.example/m2/")]);
    listed.releases_checksum_policy = rv_config::ChecksumPolicy::Unsupported;
    let mut hijack = Repository::new(
        Some("corp".to_string()),
        "https://elsewhere.example/m2/",
        true,
        true,
    );
    hijack.releases_checksum_policy = rv_config::ChecksumPolicy::Unsupported;
    backend.extend_repos(
        [
            listed,
            hijack,
            repo("vendor", "https://vendor.example/m2/"),
            repo("vendor", "https://vendor2.example/m2/"),
        ],
        Some("g:a:1"),
    );
    let known = backend.repos_snapshot();
    assert_eq!(
        known[0].releases_checksum_policy,
        rv_config::ChecksumPolicy::Warn
    );
    assert_eq!(
        urls(&backend),
        [
            "https://r.example/",
            "https://corp.example/m2/",
            "https://vendor.example/m2/",
            "https://vendor2.example/m2/"
        ]
    );
    let build = declared_build([
        repo("corp", "https://elsewhere.example/m2/"),
        repo("parent", "https://parent.example/m2/"),
    ]);
    let searched: Vec<String> = backend
        .parent_search_list(&RepoContext::default(), &build)
        .into_iter()
        .map(|repo| repo.url)
        .collect();
    assert_eq!(
        searched.last().map(String::as_str),
        Some("https://parent.example/m2/")
    );
    assert!(
        !searched.iter().any(|url| url.contains("elsewhere")),
        "{searched:?}"
    );
}

/// A parent lookup's missing-parent key holds every repository the lookup
/// searches. An import's interpolated declaration of the outer build's id
/// on another URL replaces it, so a build without that import must not
/// share its misses.
#[test]
fn parent_search_context_keys_every_searched_repository() {
    let backend = backend(|_| {});
    let ctx = RepoContext::default();
    let mut build = declared_build([repo("corp", "https://corp.example/m2/")]);
    build.added.push(model_list::Added {
        repo: repo("corp", "https://imported.example/m2/"),
        replace: true,
        reach: model_list::Reach::Read,
        implied: false,
    });
    let searched: Vec<String> = backend
        .parent_search_list(&ctx, &build)
        .into_iter()
        .map(|repo| repo.url)
        .collect();
    let keyed: Vec<String> = backend
        .parent_search_context(&ctx, &build)
        .as_slice()
        .iter()
        .map(|repo| repo.url.clone())
        .collect();
    assert_eq!(keyed, searched);
    assert!(
        keyed.ends_with(&["https://imported.example/m2/".to_string()]),
        "{keyed:?}"
    );
    assert!(
        !keyed.iter().any(|url| url.contains("corp.example")),
        "{keyed:?}"
    );
}

/// Not-found diagnostics retain ignored repositories with their declaring POMs.
/// Only unsearched repositories that a POM on the dependency path declares
/// and that serve the version qualify.
#[test]
fn dropped_repos_are_reported_only_for_declarers_on_the_path() {
    let backend = backend(|_| {});
    let snapshots = Repository::new(
        Some("snap".to_string()),
        "https://snap.example/snapshots/",
        false,
        true,
    );
    for (declared, declarer) in [
        (
            repo("jasper", "https://jasper.example/releases/"),
            Some("net.sf:jasper:6.0"),
        ),
        (snapshots, Some("net.sf:jasper:6.0")),
        (
            repo("other", "https://other.example/"),
            Some("org.other:sibling:1.0"),
        ),
        // Another version of a POM on the path is not on it.
        (
            repo("older", "https://older.example/"),
            Some("net.sf:jasper:5.0"),
        ),
        // A SNAPSHOT jar build selected from metadata can read another
        // build's POM; a build pinned on its own reads its own.
        (
            repo("snapdep", "https://snapdep.example/"),
            Some("org.snap:lib:1.0-20240101.010101-1"),
        ),
        (
            repo("pinned", "https://pinned.example/"),
            Some("org.snap:lib:1.0-20240101.010101-3"),
        ),
        // The parent-chain hook passes no declarer and must not record.
        (repo("anon", "https://anon.example/"), None),
    ] {
        backend.extend_repos([declared], declarer);
    }

    backend.companion_pom_origins.write().unwrap().insert(
        pom_gav(&Coord::parse("org.snap:lib:1.0-20240101.010101-2").unwrap()),
        CompanionPomOrigin {
            snapshot: rv_maven_types::SnapshotStamp::of_version("1.0-20240101.010101-1"),
            base: false,
            repo_url: None,
        },
    );
    let path = [
        "com.app:app:1".to_string(),
        "org.snap:lib:1.0-20240101.010101-2".to_string(),
        "net.sf:jasper:6.0".to_string(),
    ];
    let hits = |version: &str, searched: &[RepoSearchStatus]| {
        backend
            .collect_dropped_repos(&path, version, searched)
            .into_iter()
            .map(|hit| format!("{} {}", hit.url, hit.declared_by))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        hits("1.3.43", &[]),
        [
            "https://jasper.example/releases/ net.sf:jasper:6.0",
            "https://snapdep.example/ org.snap:lib:1.0-20240101.010101-1"
        ]
    );
    assert_eq!(
        hits("1.0-SNAPSHOT", &[]),
        ["https://snap.example/snapshots/ net.sf:jasper:6.0"]
    );
    let searched = [RepoSearchStatus::new(
        "https://jasper.example/releases",
        crate::error::RepoStatus::Http(404),
    )];
    assert_eq!(
        hits("1.3.43", &searched),
        ["https://snapdep.example/ org.snap:lib:1.0-20240101.010101-1"]
    );
}

/// Artifacts that share a missing POM, as a classifier does, each keep
/// the repositories on their own winning path.
#[test]
fn a_missing_poms_artifacts_keep_their_own_paths() {
    let backend = backend(|_| {});
    backend.extend_repos([repo("rx", "https://rx.example/")], Some("t:a:1"));
    backend.extend_repos([repo("ry", "https://ry.example/")], Some("t:c:1"));
    let coord = |text: &str| Coord::parse(text).unwrap();
    backend
        .record_companion_pom_blob(pom_gav(&coord("t:b:1")), None)
        .unwrap();
    let root = PathNode::root(&coord("t:app:1"));
    let jar = coord("t:b:1");
    let tests = coord("t:b:1:jar:tests");
    for (winner, declarer) in [(&jar, "t:a:1"), (&tests, "t:c:1"), (&jar, "t:a:1")] {
        let declarer = coord(declarer);
        let path = PathNode::extend(&root, &declarer, &declarer.version, RepoContext::default());
        backend.note_winner(winner, &path).unwrap();
    }
    let hits = |winner: &Coord| {
        backend
            .missing_pom_dropped_repos(winner, &[])
            .into_iter()
            .map(|hit| hit.url)
            .collect::<Vec<_>>()
    };
    assert_eq!(hits(&jar), ["https://rx.example/"]);
    assert_eq!(hits(&tests), ["https://ry.example/"]);
    assert!(hits(&coord("t:a:1")).is_empty());
}

/// A classifier whose repositories have the POM cannot share one POM pin
/// with a winner of the same coordinate whose repositories lack it.
#[test]
fn winners_that_disagree_on_a_pom_are_refused() {
    let backend = backend(|security| security.allow_transitive_repositories = true);
    let coord = |text: &str| Coord::parse(text).unwrap();
    let jar = coord("t:b:1");
    let tests = coord("t:b:1:jar:tests");
    let blob = BlobId::from_bytes(b"<project/>");
    backend
        .record_companion_pom_blob(pom_gav(&jar), None)
        .unwrap();
    lock(&backend.missing_poms).insert((ExactCoord(jar.clone()), RepoContext::default()));
    let served = (blob, Some("https://r.example/".into()));
    backend
        .record_companion_pom_blob(pom_gav(&tests), Some(served))
        .unwrap();
    let with_r = backend.extend_context(
        &RepoContext::default(),
        [repo("r", "https://r.example/")],
        Some("t:c:1"),
    );
    assert!(with_r != RepoContext::default());
    let root = PathNode::root(&coord("t:app:1"));
    let (a, c) = (coord("t:a:1"), coord("t:c:1"));
    let direct = PathNode::extend(&root, &a, &a.version, RepoContext::default());
    let through_r = PathNode::extend(&root, &c, &c.version, with_r);
    backend.note_winner(&jar, &direct).unwrap();
    let error = backend.note_winner(&tests, &through_r).unwrap_err();
    assert!(
        matches!(&error, ResolveError::ConflictingResolvedPomBytes(pom)
            if pom.coord == "t:b:1" && pom.first_sha256 == "none"),
        "{error:?}"
    );
    assert!(
        (error.to_string()).contains(" from https://r.example/); "),
        "{error}"
    );
    assert_eq!(backend.companion_pom_blob(&pom_gav(&jar)), Some(None));
}

/// A POM read twice with different bytes names the repository behind each
/// copy, a parent or BOM as well as a dependency's POM.
#[test]
fn pom_conflicts_name_the_repositories() {
    let mut first = provenance("a", b"<project>first</project>");
    let error = first
        .absorb("t:parent:1", &provenance("b", b"<project>second</project>"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(" from https://a.example/, ") && error.contains(" from https://b.example/)"),
        "{error}"
    );

    let backend = backend(|_| {});
    let gav = pom_gav(&Coord::parse("t:b:1").unwrap());
    let served = |bytes: &[u8], repo: &str| Some((BlobId::from_bytes(bytes), Some(repo.into())));
    (backend.record_companion_pom_blob(gav.clone(), served(b"first", "https://a.example/")))
        .unwrap();
    let error = backend
        .record_companion_pom_blob(gav, served(b"second", "https://b.example/"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(" from https://a.example/, ") && error.contains(" from https://b.example/)"),
        "{error}"
    );
}

/// Every runtime trust grant must reach the HTTP client's address screen,
/// or a root-POM or approved transitive repository is refused once its
/// hostname resolves onto a private network, which is how on-prem
/// registries are deployed. What the policy dropped stays screened.
#[tokio::test]
async fn runtime_repo_trust_reaches_the_http_client() {
    use rv_repo::RepoClient;

    let mut config = test_config();
    config
        .security
        .transitive_repository_allowlist
        .push("https://approved.internal/".to_string());
    let client = RepoClient::new(&config).await.expect("client");
    let store_tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
    let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
    let ctx = ResolveContext::new(config, Vec::new(), store, platform, Some(client.clone()));
    let declared = |url: &str| {
        let mut repo = rv_maven_model::Repository::new(None, url);
        repo.snapshots_enabled = false;
        repo.root_declared = true;
        Repository::from(repo)
    };

    let backend = ModelService::new(&ctx, vec![declared("https://root-pom.internal/maven2/")]);
    backend.extend_root_repos([declared("https://parent.internal/maven2/")]);
    backend.extend_repos(
        [
            Repository::new(None, "https://approved.internal/maven2/", true, false),
            Repository::new(None, "https://attacker.example/maven2/", true, false),
        ],
        Some("g:a:1"),
    );
    for (origin, trusted) in [
        ("https://root-pom.internal/", true),
        ("https://parent.internal/", true),
        ("https://approved.internal/", true),
        ("https://attacker.example/", false),
    ] {
        assert_eq!(client.trusts_origin(origin), trusted, "{origin}");
    }
}

#[tokio::test]
async fn release_and_range_listings_use_their_own_update_policies() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    let dir = root.join("com/example/lib");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("maven-metadata.xml");
    let metadata = |versions: &str| {
        format!(
            "<metadata><groupId>com.example</groupId><artifactId>lib</artifactId>\
             <versioning><release>1.0</release><versions>{versions}</versions>\
             </versioning></metadata>"
        )
    };
    std::fs::write(&path, metadata("<version>1.0</version>")).unwrap();
    let mut repo = Repository::new(
        Some("local".into()),
        reqwest::Url::from_directory_path(&root)
            .unwrap()
            .to_string(),
        true,
        true,
    );
    repo.releases_update_policy = rv_config::UpdatePolicy::Never;
    repo.snapshots_update_policy = rv_config::UpdatePolicy::Always;
    let config = Config::for_testing_with_repos(
        tmp.path().to_owned(),
        ResolvedPaths::from_raeva_home(tmp.path().join("home")),
        Vec::new(),
    );
    let client = rv_repo::RepoClient::new(&config).await.unwrap();
    let ctx = ResolveContext::new(
        config,
        vec![repo.clone()],
        Arc::new(Store::open(&tmp.path().join("store")).unwrap()),
        rv_lock::Platform::new("linux", "x86_64").unwrap(),
        Some(client),
    );
    let backend = ModelService::new(&ctx, vec![repo]);
    let repos = RepoContext::default();
    let release = backend
        .resolve_dynamic_version_internal(
            "com.example",
            "lib",
            DynamicVersionToken::Release,
            &repos,
        )
        .await
        .unwrap();
    assert_eq!(release.version.as_str(), "1.0");

    std::fs::write(
        &path,
        metadata("<version>1.0</version><version>1.1</version>"),
    )
    .unwrap();
    let versions = backend
        .resolve_versions_internal(
            "com.example",
            "lib",
            &VersionReq::parse("[1.1,2.0)").unwrap(),
            &repos,
            None,
        )
        .await
        .unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].version.as_str(), "1.1");
}

/// `RELEASE` considers each repository's versions only when that
/// repository serves releases, so a snapshots-only mirror advertising a
/// higher release in newer metadata cannot win.
#[tokio::test(flavor = "multi_thread")]
async fn dynamic_version_release_skips_snapshot_only_mirror() {
    use crate::context::MetadataKey;
    use rv_repo::{Metadata, RepoClient};

    let config = test_config();
    let store_tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
    let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
    let client = RepoClient::new(&config).await.expect("client");
    let releases = repo("releases", "https://releases.example/maven2/");
    let snapshots = Repository::new(
        Some("snapshots".to_string()),
        "https://snapshots.example/maven2/",
        false,
        true,
    );
    let repos = vec![releases.clone(), snapshots.clone()];
    let ctx = ResolveContext::new(config, repos.clone(), store, platform, Some(client));
    for (repo, version, stamp) in [
        (&snapshots, "2.0.0", "20240102000000"),
        (&releases, "1.0.0", "20240101000000"),
    ] {
        let mut metadata = Metadata::default();
        metadata.last_updated = Some(stamp.to_string());
        metadata.release = Some(version.to_string());
        metadata.versions = vec![version.to_string()];
        // Keyed as a listing that read the repository would key it.
        let listing = repo.version_listing(true).unwrap().unwrap();
        ctx.insert_metadata(
            MetadataKey::new(
                Arc::from(repo.url.as_str()),
                Arc::from("com.example"),
                Arc::from("lib"),
            )
            .with_repo_id(repo.id.as_deref())
            .with_checksum_policy(listing.releases_checksum_policy)
            .with_update_policy(listing.releases_update_policy),
            metadata,
        );
    }
    let backend = ModelService::new(&ctx, repos);

    let resolved = backend
        .resolve_dynamic_version_internal(
            "com.example",
            "lib",
            DynamicVersionToken::Release,
            &RepoContext::default(),
        )
        .await
        .expect("dynamic RELEASE resolves");
    assert_eq!(resolved.version.to_string(), "1.0.0");
}

/// RELEASE and LATEST take the `<release>` or `<latest>` of the metadata
/// updated last, not the highest listed version, and LATEST falls back
/// to `<release>`.
#[tokio::test(flavor = "multi_thread")]
async fn dynamic_versions_read_the_newest_marker() {
    use crate::context::MetadataKey;
    use rv_repo::{Metadata, RepoClient};

    let first = repo("first", "https://first.example/maven2/");
    let second = repo("second", "https://second.example/maven2/");
    let repos = vec![first.clone(), second.clone()];
    // `<release>`, `<latest>` and `<lastUpdated>` of each repository.
    type Markers = [(Option<&'static str>, Option<&'static str>, &'static str); 2];
    let cases: [(_, Markers, _); 3] = [
        (
            DynamicVersionToken::Release,
            [
                (Some("1.0"), Some("3.0"), "20240101000000"),
                (Some("2.0"), None, "20230101000000"),
            ],
            "1.0",
        ),
        (
            DynamicVersionToken::Release,
            [
                (Some("1.0"), None, "20240101000000"),
                (Some("2.0"), None, "20250101000000"),
            ],
            "2.0",
        ),
        (
            DynamicVersionToken::Integration,
            [
                (Some("1.0"), None, "20240101000000"),
                (Some("2.0"), None, "20230101000000"),
            ],
            "1.0",
        ),
    ];
    for (selector, markers, expected) in cases {
        let config = test_config();
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        let client = RepoClient::new(&config).await.expect("client");
        let ctx = ResolveContext::new(config, repos.clone(), store, platform, Some(client));
        for (repo, (release, latest, stamp)) in [&first, &second].into_iter().zip(markers) {
            let mut metadata = Metadata::default();
            metadata.release = release.map(str::to_string);
            metadata.latest = latest.map(str::to_string);
            metadata.versions = vec!["1.0".into(), "2.0".into(), "3.0".into(), "9.0".into()];
            metadata.last_updated = Some(stamp.to_string());
            ctx.insert_metadata(
                MetadataKey::new(
                    Arc::from(repo.url.as_str()),
                    Arc::from("com.example"),
                    Arc::from("lib"),
                )
                .with_repo_id(repo.id.as_deref()),
                metadata,
            );
        }
        let backend = ModelService::new(&ctx, repos.clone());
        let resolved = backend
            .resolve_dynamic_version_internal(
                "com.example",
                "lib",
                selector,
                &RepoContext::default(),
            )
            .await
            .expect("dynamic version resolves");
        assert_eq!(resolved.version.as_str(), expected, "{markers:?}");
    }
}

/// The newest metadata's marker wins though it names a SNAPSHOT for
/// `RELEASE`, or a SNAPSHOT for `LATEST` that its repository's policy
/// leaves out, as in Maven, which applies the policy to the files only.
#[tokio::test(flavor = "multi_thread")]
async fn dynamic_versions_take_the_newest_marker_whatever_it_names() {
    use crate::context::MetadataKey;
    use rv_repo::{Metadata, RepoClient};

    let cases = [
        (DynamicVersionToken::Release, true, "1.0-SNAPSHOT", "0.9"),
        (
            DynamicVersionToken::Integration,
            false,
            "1.2-SNAPSHOT",
            "1.0",
        ),
    ];
    for (token, snapshots, newer, older) in cases {
        let first = Repository::new(
            Some("first".to_string()),
            "https://first.example/maven2/",
            true,
            snapshots,
        );
        let second = Repository::new(
            Some("second".to_string()),
            "https://second.example/maven2/",
            true,
            true,
        );
        let repos = vec![first.clone(), second.clone()];
        let config = test_config();
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        let client = RepoClient::new(&config).await.expect("client");
        let ctx = ResolveContext::new(config, repos.clone(), store, platform, Some(client));
        for (repo, version, stamp) in [
            (&first, newer, "20240102000000"),
            (&second, older, "20200101000000"),
        ] {
            let mut metadata = Metadata::default();
            metadata.release = Some(version.to_string());
            metadata.latest = Some(version.to_string());
            metadata.versions = vec![version.to_string()];
            metadata.last_updated = Some(stamp.to_string());
            ctx.insert_metadata(
                MetadataKey::new(
                    Arc::from(repo.url.as_str()),
                    Arc::from("com.example"),
                    Arc::from("lib"),
                )
                .with_repo_id(repo.id.as_deref()),
                metadata,
            );
        }
        let backend = ModelService::new(&ctx, repos);
        let resolved = backend
            .resolve_dynamic_version_internal("com.example", "lib", token, &RepoContext::default())
            .await
            .expect("dynamic version resolves");
        assert_eq!(resolved.version.as_str(), newer, "{token:?}");
    }
}

/// A `LATEST` that names a SNAPSHOT takes its build from the repository
/// whose metadata named it, as Maven's version resolver does, though
/// another repository has a newer build.
#[tokio::test]
async fn a_latest_snapshot_takes_the_build_of_the_repository_that_named_it() {
    let tmp = tempfile::tempdir().unwrap();
    let mut repos = Vec::new();
    for (name, latest, stamp, build) in [
        (
            "first",
            "1.0-SNAPSHOT",
            "20240102000000",
            ("20240102.000000", 1),
        ),
        ("second", "0.9", "20200101000000", ("20240103.000000", 9)),
    ] {
        let dir = tmp.path().join(name).join("com/example/lib");
        std::fs::create_dir_all(dir.join("1.0-SNAPSHOT")).unwrap();
        std::fs::write(
            dir.join("maven-metadata.xml"),
            format!(
                "<metadata><groupId>com.example</groupId><artifactId>lib</artifactId>\
                 <versioning><latest>{latest}</latest><versions><version>{latest}</version>\
                 </versions><lastUpdated>{stamp}</lastUpdated></versioning></metadata>"
            ),
        )
        .unwrap();
        let (timestamp, number) = build;
        let updated = timestamp.replace('.', "");
        std::fs::write(
            dir.join("1.0-SNAPSHOT/maven-metadata.xml"),
            format!(
                "<metadata><groupId>com.example</groupId><artifactId>lib</artifactId>\
                 <version>1.0-SNAPSHOT</version><versioning><snapshot>\
                 <timestamp>{timestamp}</timestamp><buildNumber>{number}</buildNumber>\
                 </snapshot><lastUpdated>{updated}</lastUpdated><snapshotVersions>\
                 <snapshotVersion><extension>jar</extension>\
                 <value>1.0-{timestamp}-{number}</value><updated>{updated}</updated>\
                 </snapshotVersion></snapshotVersions></versioning></metadata>"
            ),
        )
        .unwrap();
        repos.push(Repository::new(
            Some(name.into()),
            reqwest::Url::from_directory_path(tmp.path().join(name))
                .unwrap()
                .to_string(),
            true,
            true,
        ));
    }
    let config = Config::for_testing_with_repos(
        tmp.path().to_owned(),
        ResolvedPaths::from_raeva_home(tmp.path().join("home")),
        Vec::new(),
    );
    let client = rv_repo::RepoClient::new(&config).await.unwrap();
    let ctx = ResolveContext::new(
        config,
        repos.clone(),
        Arc::new(Store::open(&tmp.path().join("store")).unwrap()),
        rv_lock::Platform::new("linux", "x86_64").unwrap(),
        Some(client),
    );
    let backend = ModelService::new(&ctx, repos.clone());
    let context = RepoContext::default();
    let latest = backend
        .resolve_dynamic_version_internal(
            "com.example",
            "lib",
            DynamicVersionToken::Integration,
            &context,
        )
        .await
        .unwrap();
    assert_eq!(latest.version.as_str(), "1.0-SNAPSHOT");
    let coord = Coord::from_str("com.example:lib:1.0-SNAPSHOT").unwrap();
    let build = backend
        .resolve_snapshot_version_internal(&coord, &context)
        .await
        .unwrap();
    assert_eq!(build.version.as_str(), "1.0-20240102.000000-1");
    assert!(build.repo.is_some_and(|repo| repo.is(&repos[0])));
}

/// With no marker in any repository, `RELEASE` and `LATEST` take the
/// reactor's greatest version in the mode's order: `alpha` in Maven 3.9,
/// `0.min` in 3.10.
#[test]
fn a_reactor_version_stands_in_for_a_marker_in_the_modes_order() {
    let dir = tempfile::tempdir().unwrap();
    let pom = |coords: &str, body: &str| {
        format!("<project><modelVersion>4.0.0</modelVersion>{coords}{body}</project>")
    };
    let files = [
        (
            "pom.xml",
            pom(
                "<groupId>g</groupId><artifactId>root</artifactId><version>1</version>",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
            ),
        ),
        (
            "a/pom.xml",
            pom(
                "<groupId>g</groupId><artifactId>lib</artifactId><version>alpha</version>",
                "",
            ),
        ),
        (
            "b/pom.xml",
            pom(
                "<groupId>g</groupId><artifactId>lib</artifactId><version>0.min</version>",
                "",
            ),
        ),
    ];
    for (path, text) in files {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let workspace = Arc::new(crate::Workspace::discover(dir.path()).unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (mode, expected) in [
        (MavenMode::Maven39, "alpha"),
        (MavenMode::Maven310, "0.min"),
    ] {
        for token in [
            DynamicVersionToken::Release,
            DynamicVersionToken::Integration,
        ] {
            let store_tmp = tempfile::tempdir().unwrap();
            let store = Arc::new(Store::open(store_tmp.path()).unwrap());
            let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
            let mut config = test_config();
            config.lock.maven.mode = mode;
            let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
            let backend =
                ModelService::new(&ctx, Vec::new()).with_workspace(Arc::clone(&workspace));
            let resolved = runtime
                .block_on(backend.resolve_dynamic_version_internal(
                    "g",
                    "lib",
                    token,
                    &RepoContext::default(),
                ))
                .unwrap();
            assert_eq!(resolved.version.as_str(), expected, "{mode:?} {token:?}");
        }
    }
}

#[test]
fn extend_context_aggregates_per_path_and_deduplicates_by_id() {
    let store_tmp = tempfile::tempdir().unwrap();
    let backend = backend_in(
        store_tmp.path(),
        |security| security.allow_transitive_repositories = true,
        vec![repo("central", "https://central.example/")],
    );
    let empty = RepoContext::default();
    assert!(empty.is_empty());

    let declared = |id: &str, url: &str| {
        let mut r = rv_maven_model::Repository::new(Some(id), url);
        r.snapshots_enabled = false;
        r
    };
    let a_repos = [
        declared("central", "https://override.example/"),
        declared("r2", "https://r2.example/"),
    ];
    let ctx_a = backend.extend_context(&empty, resolution_repositories(&a_repos), Some("g:a:1"));
    assert_eq!(
        ctx_a
            .as_slice()
            .iter()
            .map(|r| (r.id.as_deref(), r.url.as_str()))
            .collect::<Vec<_>>(),
        vec![(Some("r2"), "https://r2.example/")]
    );

    let b_repos = [
        declared("r2", "https://r2-other.example/"),
        declared("r3", "https://r3.example/"),
    ];
    let ctx_b = backend.extend_context(&ctx_a, resolution_repositories(&b_repos), Some("g:b:1"));
    assert_eq!(
        ctx_b
            .as_slice()
            .iter()
            .map(|r| (r.id.as_deref(), r.url.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (Some("r2"), "https://r2.example/"),
            (Some("r3"), "https://r3.example/")
        ]
    );
}

/// A module reports an invalid POM its graph selects though another
/// module's build read it, and a SNAPSHOT's under the coordinate it was asked
/// for, not that of the build whose POM was read.
#[tokio::test]
async fn a_selected_invalid_pom_is_reported_whoever_read_it() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    let invalid = |version: &str| {
        format!(
            "<project><groupId>test</groupId><artifactId>lib</artifactId>\
             <version>{version}</version><dependencies><dependency><groupId>g</groupId>\
             <artifactId>broken</artifactId><version>1</version><scope>system</scope>\
             </dependency></dependencies></project>"
        )
    };
    let release = root.join("test/lib/1");
    std::fs::create_dir_all(&release).unwrap();
    std::fs::write(release.join("lib-1.pom"), invalid("1")).unwrap();
    let snapshot = root.join("test/lib/2-SNAPSHOT");
    std::fs::create_dir_all(&snapshot).unwrap();
    let value = "2-20261012.010101-1";
    std::fs::write(
        snapshot.join("maven-metadata.xml"),
        format!(
            "<metadata><version>2-SNAPSHOT</version><versioning><snapshotVersions>\
             <snapshotVersion><extension>pom</extension><value>{value}</value>\
             <updated>20261012010101</updated></snapshotVersion></snapshotVersions>\
             </versioning></metadata>"
        ),
    )
    .unwrap();
    std::fs::write(
        snapshot.join(format!("lib-{value}.pom")),
        invalid("2-SNAPSHOT"),
    )
    .unwrap();
    let repos = vec![Repository::new(
        Some("repo".to_string()),
        format!("file://{}/", root.display()),
        true,
        true,
    )];
    let config = Config::for_testing_with_repos(
        tmp.path().to_owned(),
        ResolvedPaths::from_raeva_home(tmp.path().join("home")),
        Vec::new(),
    );
    let client = rv_repo::RepoClient::new(&config).await.unwrap();
    let ctx = ResolveContext::new(
        config,
        repos.clone(),
        Arc::new(Store::open(&tmp.path().join("store")).unwrap()),
        rv_lock::Platform::new("linux", "x86_64").unwrap(),
        Some(client),
    );
    let models = Arc::new(ReactorModels::default());
    let module = || ctx.for_module(ctx.config.clone());
    let reader =
        ModelService::new(&module(), repos.clone()).with_reactor_models(Arc::clone(&models));
    let selector = ModelService::new(&module(), repos).with_reactor_models(models);
    let release = Coord::parse("test:lib:1").unwrap();
    let snapshot = Coord::parse("test:lib:2-SNAPSHOT").unwrap();
    for (backend, coord) in [
        (&reader, &release),
        (&selector, &release),
        (&selector, &snapshot),
    ] {
        let project = backend
            .fetch_project_internal(coord, false, &RepoContext::default())
            .await
            .unwrap();
        assert!(project.project.dependencies.is_empty(), "{coord}");
    }
    let logged = warnings(|| {
        selector.report_pom_problem(&release);
        selector.report_pom_problem(&snapshot);
    });
    assert_eq!(logged.len(), 2, "{logged:?}");
}

/// Maven 3.10 sorts a version that starts with text below `0`, so a range
/// up to `0` lists it; Maven 3.9 takes it as `0`, which `(,0)` leaves out.
#[test]
fn a_range_lists_its_versions_in_the_modes_order() {
    use crate::resolver::pom_source::MemoryPomSource;

    let found = |mode: MavenMode| {
        let source = MemoryPomSource::default().with_files(
            "https://first.example/",
            &std::collections::HashMap::from([(
                "g/a/maven-metadata.xml".to_string(),
                b"<metadata><versioning><versions><version>alpha</version>\
                  <version>1</version></versions></versioning></metadata>"
                    .to_vec(),
            )]),
        );
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).unwrap());
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        let mut config = test_config();
        config.lock.maven.mode = mode;
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None)
            .with_pom_source(Arc::new(source));
        let backend = ModelService::new(&ctx, vec![repo("first", "https://first.example/")]);
        let range = VersionReq::parse("(,0)").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(backend.resolve_versions("g", "a", &range, &RepoContext::default()))
            .map(|versions| {
                (versions.into_iter())
                    .map(|found| found.version.to_string())
                    .collect::<Vec<_>>()
            })
            .ok()
    };
    assert_eq!(found(MavenMode::Maven39), None);
    assert_eq!(found(MavenMode::Maven310), Some(vec!["alpha".to_string()]));
}

/// Two modules of one reactor sharing their models: `m:1` reads `p:1`
/// from `rb`, as its parent or as a BOM it imports, and `x:1`, asked for
/// without `rb`, reads it alike.
fn cached_parent_modules(import: bool) -> (tempfile::TempDir, ModelService, ModelService) {
    use crate::resolver::pom_source::MemoryPomSource;

    let p = "<groupId>g</groupId><artifactId>p</artifactId><version>1</version>";
    let pom = |artifact: &str| {
        let (parent, management) = match import {
            false => (format!("<parent>{p}</parent>"), String::new()),
            true => (
                "<groupId>g</groupId>".to_string(),
                format!(
                    "<dependencyManagement><dependencies><dependency>{p}<type>pom</type>\
                     <scope>import</scope></dependency></dependencies></dependencyManagement>"
                ),
            ),
        };
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{parent}<artifactId>{artifact}\
             </artifactId><version>1</version><dependencies><dependency><groupId>g</groupId>\
             <artifactId>y</artifactId><version>1</version></dependency></dependencies>\
             {management}</project>"
        )
        .into_bytes()
    };
    let r = std::collections::HashMap::from([
        ("g/m/1/m-1.pom".to_string(), pom("m")),
        ("g/x/1/x-1.pom".to_string(), pom("x")),
    ]);
    let rb = std::collections::HashMap::from([(
        "g/p/1/p-1.pom".to_string(),
        b"<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
          <artifactId>p</artifactId><version>1</version><packaging>pom</packaging></project>"
            .to_vec(),
    )]);
    let source = MemoryPomSource::default()
        .with_files("https://r.example/", &r)
        .with_files("https://rb.example/", &rb);
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(tmp.path()).unwrap());
    let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
    let ctx = ResolveContext::new(test_config(), Vec::new(), store, platform, None)
        .with_pom_source(Arc::new(source));
    let models = Arc::new(ReactorModels::default());
    let module = || {
        ModelService::new(
            &ctx.for_module(ctx.config.clone()),
            vec![repo("r", "https://r.example/")],
        )
        .with_reactor_models(Arc::clone(&models))
    };
    (tmp, module(), module())
}

async fn dependencies(backend: &ModelService, artifact: &str, repos: &RepoContext) -> usize {
    let coord = Coord::parse(&format!("g:{artifact}:1")).unwrap();
    (backend.fetch_project_internal(&coord, false, repos).await)
        .map_or(0, |found| found.project.dependencies.len())
}

/// A module that takes `m:1` from another module's build takes the parent
/// that build read into its model cache, as a build of its own would, and
/// `x:1` finds it there.
#[tokio::test]
async fn a_reused_model_brings_the_parents_its_build_read() {
    let (_tmp, first, second) = cached_parent_modules(false);
    let rb = RepoContext::from_repos(vec![repo("rb", "https://rb.example/")]);
    assert_eq!(dependencies(&first, "m", &rb).await, 1);
    assert_eq!(dependencies(&second, "m", &rb).await, 1);
    assert_eq!(dependencies(&second, "x", &RepoContext::default()).await, 1);
}

/// A model built from a parent the module read on another path is kept from
/// the other modules, which have not read it.
#[tokio::test]
async fn a_model_built_from_the_model_cache_stays_with_its_module() {
    let (_tmp, first, second) = cached_parent_modules(false);
    let rb = RepoContext::from_repos(vec![repo("rb", "https://rb.example/")]);
    assert_eq!(dependencies(&first, "m", &rb).await, 1);
    assert_eq!(dependencies(&first, "x", &RepoContext::default()).await, 1);
    assert_eq!(dependencies(&second, "x", &RepoContext::default()).await, 0);
}

/// An imported BOM read from the model cache is kept from the other
/// modules too.
#[tokio::test]
async fn a_bom_imported_from_the_model_cache_stays_with_its_module() {
    let (_tmp, first, second) = cached_parent_modules(true);
    let rb = RepoContext::from_repos(vec![repo("rb", "https://rb.example/")]);
    assert_eq!(dependencies(&first, "m", &rb).await, 1);
    assert_eq!(dependencies(&first, "x", &RepoContext::default()).await, 1);
    assert_eq!(dependencies(&second, "x", &RepoContext::default()).await, 0);
}

/// One id refuses only two URLs whose listings a read of it takes
/// differently: Central's two names, one host in two cases, repositories
/// without an id, and a `lastUpdated` nothing picks by do not.
#[test]
fn split_listings_need_two_urls_of_one_id_read_differently() {
    let listing = |versions: &[&str], release: &str, stamp: &str| {
        let mut metadata = Metadata::default();
        metadata.versions = versions.iter().map(|v| v.to_string()).collect();
        metadata.release = Some(release.to_string()).filter(|r| !r.is_empty());
        metadata.last_updated = Some(stamp.to_string()).filter(|s| !s.is_empty());
        metadata
    };
    let refused = |reads: &[(Option<&str>, &str, ListingRead, &Metadata)]| {
        let listings = IdListings::default();
        for (id, url, read, metadata) in reads {
            let repo = Repository::new(id.map(str::to_string), *url, true, false);
            record_listing(&listings, &repo, ("g", "a"), *read, metadata);
        }
        refuse_split_listings(&listings, MavenMode::Maven39)
            .err()
            .map(|e| e.to_string())
    };
    let one = listing(&["1"], "1", "2024");
    let two = listing(&["1", "2"], "2", "2024");
    let two_later = listing(&["1", "2"], "2", "2025");
    let two_unstamped = listing(&["1", "2"], "2", "");
    let none = Metadata::default();
    let range = ListingRead::Range;
    let release = |among_others| ListingRead::Marker {
        latest: false,
        among_others,
    };
    let plugin = ListingRead::Plugin {
        among_others: false,
    };
    let (r, central) = (Some("r"), Some("central"));
    let (a, b) = ("https://a.example/", "https://b.example/");
    let kept = [
        [
            (
                central,
                "https://repo.maven.apache.org/maven2/",
                range,
                &one,
            ),
            (central, "https://repo1.maven.org/maven2/", range, &two),
        ],
        [
            (r, "https://Repo.Example/m2/", range, &one),
            (r, "https://repo.example/m2/", range, &two),
        ],
        [(None, a, range, &one), (None, b, range, &two)],
        [(r, a, range, &two), (r, b, range, &two_later)],
        [
            (r, a, release(false), &two),
            (r, b, release(false), &two_later),
        ],
        [(r, a, plugin, &two), (r, b, plugin, &two_later)],
        // A listing of no version and no marker is a 404's empty one,
        // whatever its `lastUpdated`.
        [
            (r, a, plugin, &none),
            (r, b, plugin, &listing(&[], "", "2024")),
        ],
        [
            (r, a, release(true), &none),
            (r, b, release(true), &listing(&[], "", "2024")),
        ],
    ];
    for reads in kept {
        assert_eq!(refused(&reads), None, "{reads:?}");
    }
    let split = [
        [(r, b, range, &two), (r, a, range, &one)],
        [
            (r, a, release(true), &two),
            (r, b, release(true), &two_later),
        ],
        [
            (r, a, range, &one),
            (r, b, release(false), &listing(&["1"], "2", "2024")),
        ],
        [(r, a, plugin, &two), (r, b, plugin, &two_unstamped)],
    ];
    for reads in split {
        let error = refused(&reads).expect("refused");
        assert!(
            error.contains("repository id r lists different versions of g:a at https://a.example/ and https://b.example/"),
            "{error}"
        );
    }
}
