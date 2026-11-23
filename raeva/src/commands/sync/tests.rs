use super::SyncArgs;
use super::drift::lock_requires_snapshot_refresh;
use clap::Parser;
use rv_lock::{LockArtifact, LockModulePackage, LockPlatform, Lockfile, Platform};
use rv_maven_types::{ArtifactCoord, Gav, SnapshotStamp};
use rv_store::metadata_cache::{RowsDue, SnapshotCheck};

/// A check made at `checked_at` that took no row from the cache.
fn check(checked_at: i64) -> SnapshotCheck {
    SnapshotCheck {
        checked_at,
        rows: RowsDue::default(),
    }
}

fn empty_platform(os: &str, arch: &str) -> LockPlatform {
    LockPlatform::single_module(
        Platform::new(os, arch).expect("platform"),
        Gav::new("com.example", "root", "1"),
        "pom",
        Vec::new(),
    )
}

fn push_package(platform: &mut LockPlatform, mut artifact: LockArtifact) {
    platform.modules[0]
        .packages
        .push(LockModulePackage::new(artifact.coordinate.clone(), None));
    artifact.pom_sha256 = Some(("e".repeat(64)).parse().unwrap());
    if artifact.checksums.is_empty() {
        artifact
            .checksums
            .push(rv_maven_types::Digest::parse("sha256", &"e".repeat(64)).unwrap());
    }
    platform.artifacts.push(artifact);
}

#[test]
fn a_shared_url_uses_the_first_snapshot_policy_of_each_id() {
    use rv_config::{Config, RepoConfig, ResolvedPaths, UpdatePolicy};
    use std::time::{Duration, SystemTime};

    let cases = [
        (Some(false), UpdatePolicy::Never, UpdatePolicy::Always),
        (None, UpdatePolicy::Never, UpdatePolicy::Always),
        (Some(true), UpdatePolicy::Never, UpdatePolicy::Always),
        (Some(false), UpdatePolicy::Always, UpdatePolicy::Never),
        (None, UpdatePolicy::Always, UpdatePolicy::Never),
        (Some(true), UpdatePolicy::Daily, UpdatePolicy::Interval(15)),
        (Some(true), UpdatePolicy::Daily, UpdatePolicy::Interval(30)),
    ];
    for (snapshots, first_policy, second_policy) in cases {
        for reverse in [false, true] {
            for (first_url, (first_id, second_id)) in
                ["https://shared.example/", "https://shared.example"]
                    .into_iter()
                    .flat_map(|url| {
                        [("first", "second"), ("shared", "shared")].map(|ids| (url, ids))
                    })
            {
                let temp = tempfile::tempdir().unwrap();
                let mut repos = vec![
                    {
                        let mut repo = RepoConfig::new(Some(first_id), first_url);
                        repo.releases = Some(true);
                        repo.snapshots = snapshots;
                        repo.snapshots_update_policy = Some(first_policy);
                        repo
                    },
                    {
                        let mut repo = RepoConfig::new(Some(second_id), "https://shared.example/");
                        repo.releases = Some(false);
                        repo.snapshots = Some(true);
                        repo.snapshots_update_policy = Some(second_policy);
                        repo
                    },
                ];
                if reverse {
                    repos.reverse();
                }
                let config = Config::for_testing_with_repos(
                    temp.path().to_path_buf(),
                    ResolvedPaths::for_testing().unwrap(),
                    repos,
                );
                let written = SystemTime::now() - Duration::from_secs(20 * 60);
                let checked = chrono::DateTime::<chrono::Local>::from(written).timestamp();
                let fresh = |policy| rv_repo::fresh_secs(policy, &written.into());
                let mut lock = Lockfile::new();
                let mut platform = empty_platform("linux", "x86_64");
                push_package(&mut platform, package("g", "a", "1-SNAPSHOT"));
                lock.platforms.push(platform);
                lock.platforms[0].artifacts[0].repo_url = "https://shared.example/".to_string();
                // Under one id the first declaration wins; under two ids
                // each enabled one counts and the shortest policy applies.
                let first_enabled = snapshots == Some(true);
                let ttl = if first_id == second_id {
                    fresh(if reverse {
                        second_policy
                    } else if first_enabled {
                        first_policy
                    } else {
                        UpdatePolicy::default()
                    })
                } else if first_enabled {
                    fresh(first_policy).min(fresh(second_policy))
                } else {
                    fresh(second_policy)
                };
                assert_eq!(
                    lock_requires_snapshot_refresh(&lock, &config, &[], |_| Some(check(checked))),
                    ttl <= 20 * 60,
                    "snapshots={snapshots:?}, first={first_policy:?}, second={second_policy:?}, reverse={reverse}, url={first_url}, ids={first_id}/{second_id}"
                );
            }
        }
    }
}

/// As Maven's update check, a `daily` check made before today's local
/// midnight is due, however recent it was. A platform never checked, or
/// checked in the future, is due; one checked now is not.
#[test]
fn a_daily_snapshot_check_from_before_midnight_is_due() {
    use rv_config::{Config, RepoConfig, ResolvedPaths, UpdatePolicy};

    let temp = tempfile::tempdir().unwrap();
    let mut repo = RepoConfig::new(Some("snapshots"), "https://snapshots.example/");
    repo.snapshots = Some(true);
    repo.snapshots_update_policy = Some(UpdatePolicy::Daily);
    let config = Config::for_testing_with_repos(
        temp.path().to_path_buf(),
        ResolvedPaths::for_testing().unwrap(),
        vec![repo],
    );
    let midnight = chrono::Local::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .and_then(|midnight| midnight.and_local_timezone(chrono::Local).earliest())
        .unwrap();
    let written = midnight - chrono::Duration::minutes(1);
    let mut lock = Lockfile::new();
    let mut platform = empty_platform("linux", "x86_64");
    push_package(&mut platform, package("g", "a", "1-SNAPSHOT"));
    lock.platforms.push(platform);
    lock.platforms[0].artifacts[0].repo_url = "https://snapshots.example/".to_string();
    let now = chrono::Local::now().timestamp();
    let due = |checked: Option<SnapshotCheck>| {
        lock_requires_snapshot_refresh(&lock, &config, &[], |_| checked)
    };
    assert!(due(Some(check(written.timestamp()))));
    assert!(due(None));
    assert!(due(Some(check(now + 3600))));
    assert!(!due(Some(check(now))));

    // A check made now that took from the cache a row fetched before
    // midnight, or one already expired, is due; one that expires later is
    // not.
    let took = |expire_at, daily_from| {
        Some(SnapshotCheck {
            checked_at: now,
            rows: RowsDue {
                expire_at,
                daily_from,
            },
        })
    };
    assert!(due(took(None, Some(written.timestamp()))));
    assert!(due(took(Some(now), None)));
    assert!(!due(took(Some(now + 60), Some(now))));
}

#[test]
fn snapshot_policies_are_scoped_to_the_platform_and_module() {
    use crate::commands::lock_inputs::discover_reactor_model;
    use rv_config::{Config, ResolvedPaths};
    use rv_lock::LockModule;

    let temp = tempfile::tempdir().unwrap();
    let repository = |policy: &str| {
        format!(
            "<repositories><repository><id>shared</id><url>https://repo.example/</url>\
         <snapshots><enabled>true</enabled><updatePolicy>{policy}</updatePolicy></snapshots>\
         </repository></repositories>"
        )
    };
    std::fs::write(temp.path().join("pom.xml"), format!(
        "<project><groupId>g</groupId><artifactId>root</artifactId><version>1</version>\
         <packaging>pom</packaging><modules><module>child</module></modules>\
         <properties><refresh>never</refresh></properties>{}\
         <profiles><profile><id>windows</id><activation><os><family>windows</family></os>\
         </activation><properties><refresh>always</refresh></properties></profile></profiles></project>",
        repository("${refresh}")
    )).unwrap();
    std::fs::create_dir(temp.path().join("child")).unwrap();
    std::fs::write(temp.path().join("child/pom.xml"), format!(
        "<project><groupId>g</groupId><artifactId>child</artifactId><version>1</version>{}</project>",
        repository("always")
    )).unwrap();
    let config = Config::for_testing_with_repos(
        temp.path().to_path_buf(),
        ResolvedPaths::for_testing().unwrap(),
        Vec::new(),
    );
    let models: Vec<_> = ["linux", "windows"]
        .into_iter()
        .map(|os| discover_reactor_model(&config, &Platform::new(os, "x86_64").unwrap()).unwrap())
        .collect();
    for (snapshot_os, snapshot_module, due) in [
        ("linux", "pom.xml", false),
        ("linux", "child/pom.xml", true),
        ("windows", "pom.xml", true),
    ] {
        let mut lock = Lockfile::new();
        for model in &models {
            let mut platform = LockPlatform::new(model.platform.clone(), &model.model_hash);
            for module in model.workspace.modules() {
                let snapshot =
                    model.platform.os() == snapshot_os && module.pom_path == snapshot_module;
                let artifact = package(
                    "g",
                    module.gav().artifact_id.as_str(),
                    if snapshot { "1-SNAPSHOT" } else { "1" },
                );
                let gav = module.gav();
                let mut locked = LockModule::new(
                    &module.pom_path,
                    Gav::new(&gav.group_id, &gav.artifact_id, &gav.version),
                    "pom",
                );
                locked
                    .packages
                    .push(LockModulePackage::new(artifact.coordinate.clone(), None));
                platform.modules.push(locked);
                platform.artifacts.push(artifact);
            }
            lock.platforms.push(platform);
        }
        assert_eq!(
            lock_requires_snapshot_refresh(&lock, &config, &models, |_| {
                Some(check(chrono::Local::now().timestamp()))
            }),
            due,
            "snapshot in {snapshot_os}/{snapshot_module}"
        );
    }
}

#[derive(Debug, Parser)]
struct Wrapper {
    #[command(flatten)]
    args: SyncArgs,
}

fn package(group: &str, artifact: &str, version: &str) -> LockArtifact {
    LockArtifact::new(
        ArtifactCoord::new(group, artifact, version, "jar", None),
        "https://repo.example/",
    )
}

/// The on-disk lock is sorted with remapped edge indices, while a fresh
/// resolution is still in traversal order. Frozen comparison must
/// canonicalize both while comparing the same top-level metadata.
/// The timestamped snapshot matches the shape seen in the Apache Maven
/// corpus.
#[test]
fn lock_resolution_matches_canonicalizes_package_order_and_edges() {
    use rv_lock::LockEdge;

    let mut selected = Lockfile::new();
    let mut platform = empty_platform("linux", "x86_64");
    let mut pkg = package("com.example", "demo", "1.0-SNAPSHOT");
    pkg.snapshot = SnapshotStamp::new("20240101.010101", 7);
    pkg.checksums = vec![rv_maven_types::Digest::parse("sha256", &"a".repeat(64)).unwrap()];
    push_package(&mut platform, pkg);
    push_package(&mut platform, package("com.example", "zeta", "1.0"));
    platform.modules[0]
        .edges
        .push(LockEdge::new(0, 1, rv_lock::Scope::Compile, false));
    selected.platforms.push(platform);
    selected.config_hash = Some("abc123".to_string());
    selected.repo_ids.insert(
        "https://repo.example/".to_string(),
        ["corp".to_string()].into(),
    );

    let mut resolved = Lockfile::new();
    let mut platform = empty_platform("linux", "x86_64");
    push_package(&mut platform, package("com.example", "zeta", "1.0"));
    let mut refreshed = package("com.example", "demo", "1.0-SNAPSHOT");
    refreshed.snapshot = SnapshotStamp::new("20240101.010101", 7);
    refreshed.checksums = vec![rv_maven_types::Digest::parse("sha256", &"a".repeat(64)).unwrap()];
    push_package(&mut platform, refreshed);
    platform.modules[0]
        .edges
        .push(LockEdge::new(1, 0, rv_lock::Scope::Compile, false));
    resolved.platforms.push(platform);
    resolved.config_hash = selected.config_hash.clone();
    resolved.repo_ids = selected.repo_ids.clone();

    assert!(
        selected
            .resolution_drift(&resolved, |_, _| true, |_, _, _| false)
            .is_none(),
        "traversal order and remapped edge indices must not register as drift"
    );
}

/// The diff a frozen drift error lists names each changed, added and
/// removed package.
#[test]
fn formats_the_frozen_diff_entries() {
    use crate::commands::sync::diff::format_frozen_diff;

    let mut old = Lockfile::new();
    let mut platform_old = empty_platform("linux", "x86_64");
    push_package(&mut platform_old, package("com.example", "lib", "1.0"));
    push_package(&mut platform_old, package("com.example", "other", "2.0"));
    old.platforms.push(platform_old);

    let mut new = Lockfile::new();
    let mut platform_new = empty_platform("linux", "x86_64");
    push_package(&mut platform_new, package("com.example", "lib", "1.1"));
    push_package(&mut platform_new, package("com.example", "new-dep", "3.0"));
    new.platforms.push(platform_new);

    let diff = format_frozen_diff(&old, &new);
    assert_eq!(
        diff,
        "  lib      1.0 -> 1.1\n  new-dep  3.0 (added)\n  other    2.0 (removed)\n"
    );
}

#[test]
fn frozen_local_excludes_unchanged_unrequested_repository_declarations() {
    use super::check_frozen_local;
    use crate::commands::lock_inputs::{discover_reactor_models, resolution_config_hash};
    use rv_config::{Config, ResolvedPaths};

    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("pom.xml"),
        "<project><groupId>g</groupId><artifactId>root</artifactId><version>1</version>\
         <profiles><profile><id>windows</id><activation><os><family>windows</family></os>\
         </activation><repositories><repository><id>excluded</id>\
         <url>https://excluded.example/</url></repository></repositories>\
         </profile></profiles></project>",
    )
    .unwrap();
    let config = Config::for_testing_with_repos(
        project.path().to_path_buf(),
        ResolvedPaths::for_testing().unwrap(),
        Vec::new(),
    );
    let platforms = [
        "linux-x86_64".parse().unwrap(),
        "windows-x86_64".parse().unwrap(),
    ];
    let models = discover_reactor_models(&config, &platforms).unwrap();
    let mut lock = Lockfile::new();
    for model in models {
        let mut entry = LockPlatform::single_module(
            model.platform.clone(),
            Gav::new("g", "root", "1"),
            "jar",
            Vec::new(),
        );
        entry.set_model_inputs(&model.active_profiles, &model.pom_hashes);
        lock.platforms.push(entry);
    }
    lock.config_hash = Some(resolution_config_hash(&config, &Default::default()).unwrap());
    lock.write_atomic(&config.lock_path).unwrap();
    let argv = ["sync", "--frozen", "--platforms", "linux-x86_64"];
    let args = Wrapper::parse_from(argv).args;
    let checked = check_frozen_local(&config, &args, true, true).unwrap();
    assert!(
        checked
            .models
            .iter()
            .flat_map(|model| model.declared_repositories())
            .all(|repo| repo.id.as_deref() != Some("excluded"))
    );
}

#[test]
fn with_origins_of_copies_support_pom_urls() {
    use rv_lock::SupportPom;

    let sha = |c: char| c.to_string().repeat(64).parse().unwrap();
    let mut lock = Lockfile::new();
    let mut platform = empty_platform("linux", "x86_64");
    platform.support_poms.insert(
        "com.example:parent:1".into(),
        SupportPom::new("https://stale.example/", sha('a')),
    );
    lock.platforms.push(platform);

    let mut fresh = Lockfile::new();
    let mut platform = empty_platform("linux", "x86_64");
    platform.support_poms.insert(
        "com.example:parent:1".into(),
        SupportPom::new("https://fresh.example/", sha('b')),
    );
    fresh.platforms.push(platform);

    let copied = super::with_origins_of(&lock, &fresh, false);
    let pin = &copied.platforms[0].support_poms["com.example:parent:1"];
    assert_eq!(pin.repo_url, "https://fresh.example/");
    assert_eq!(pin.sha256, sha('a'));
}

/// A file raeva.lock pins by SHA-1 alone is held to it: a resolution that
/// put other bytes in the store is refused, and the pinned bytes pass.
#[tokio::test]
async fn a_sha1_pin_is_checked_against_the_resolved_bytes() {
    use rv_maven_types::{BlobId, Digest, HashAlgorithm};

    let temp = tempfile::tempdir().unwrap();
    let store = rv_store::Store::open(temp.path()).unwrap();
    let lock_with = |checksum: Digest| {
        let mut lock = Lockfile::new();
        let mut platform = empty_platform("linux", "x86_64");
        let mut artifact = package("g", "a", "1");
        artifact.checksums = vec![checksum];
        push_package(&mut platform, artifact);
        lock.platforms.push(platform);
        lock
    };
    let served = store.put_bytes(b"served").await.unwrap();
    let fresh = lock_with(Digest::Sha256(served.clone()));
    let sha1_of = |bytes: &[u8]| Digest::of_reader(HashAlgorithm::Sha1, bytes).unwrap();

    let reviewed = lock_with(sha1_of(b"reviewed"));
    let err = super::download::check_repinned(&reviewed, &fresh, &store)
        .await
        .unwrap_err()
        .to_string();
    let expected = format!(
        "g/a/1/a-1.jar: expected sha1 {}, got {}",
        sha1_of(b"reviewed").hex(),
        sha1_of(b"served").hex()
    );
    assert!(err.contains(&expected), "{err}");

    let same = lock_with(sha1_of(b"served"));
    super::download::check_repinned(&same, &fresh, &store)
        .await
        .unwrap();
    let gone = lock_with(Digest::Sha256(BlobId::from_bytes(b"gone")));
    let missing = super::download::check_repinned(&same, &gone, &store).await;
    assert!(
        missing
            .unwrap_err()
            .to_string()
            .contains("not in the store"),
        "an unstored file cannot pass"
    );
}

#[test]
fn only_a_missing_listed_version_lets_a_failed_replay_report_drift() {
    use crate::error::CliError;
    use rv_resolver::ResolveError;
    let not_listed = || ResolveError::VersionNotFound {
        coord: "x:lib".into(),
        requirement: "[1.0,2.0)".into(),
    };
    let declared = || ResolveError::Declared {
        module: String::new(),
        via: Vec::new(),
        error: Box::new(not_listed()),
    };
    let plugin = ResolveError::Plugin {
        plugin: "build plugin p:p:1".into(),
        searched: Vec::new(),
        error: Box::new(declared()),
    };
    for err in [not_listed(), declared(), plugin] {
        assert!(super::resolve::no_locked_version(&CliError::Resolve(err)));
    }
    let other = ResolveError::InternalError("cancelled".into());
    assert!(!super::resolve::no_locked_version(&CliError::Resolve(
        other
    )));
}
