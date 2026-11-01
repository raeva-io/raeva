use super::SyncArgs;
use super::drift::lock_requires_snapshot_refresh;
use clap::Parser;
use rv_lock::{LockArtifact, LockModulePackage, LockPlatform, Lockfile, Platform};
use rv_maven_types::{ArtifactCoord, Gav, SnapshotStamp};

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
                let file = std::fs::File::create(&config.lock_path).unwrap();
                let written = SystemTime::now() - Duration::from_secs(20 * 60);
                file.set_modified(written).unwrap();
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
                    lock_requires_snapshot_refresh(&lock, &config, &[]),
                    ttl <= 20 * 60,
                    "snapshots={snapshots:?}, first={first_policy:?}, second={second_policy:?}, reverse={reverse}, url={first_url}, ids={first_id}/{second_id}"
                );
            }
        }
    }
}

/// As Maven's update check, a `daily` lock written before today's local
/// midnight is due, however recently it was written.
#[test]
fn a_daily_snapshot_lock_from_before_midnight_is_due() {
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
    let file = std::fs::File::create(&config.lock_path).unwrap();
    file.set_modified(written.into()).unwrap();
    let mut lock = Lockfile::new();
    let mut platform = empty_platform("linux", "x86_64");
    push_package(&mut platform, package("g", "a", "1-SNAPSHOT"));
    lock.platforms.push(platform);
    lock.platforms[0].artifacts[0].repo_url = "https://snapshots.example/".to_string();
    assert!(lock_requires_snapshot_refresh(&lock, &config, &[]));
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
    std::fs::File::create(&config.lock_path).unwrap();
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
            lock_requires_snapshot_refresh(&lock, &config, &models),
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

#[test]
fn partial_sync_preserves_other_platforms() {
    use std::collections::HashSet;

    let mut previous = Lockfile::new();
    let mut linux = empty_platform("linux", "x86_64");
    push_package(&mut linux, package("com.example", "lib", "1.0"));
    previous.platforms.push(linux);
    let mut darwin = empty_platform("darwin", "aarch64");
    push_package(&mut darwin, package("com.example", "lib", "1.0"));
    previous.platforms.push(darwin);

    let mut fresh = Lockfile::new();
    let mut linux_new = empty_platform("linux", "x86_64");
    push_package(&mut linux_new, package("com.example", "lib", "2.0"));
    fresh.platforms.push(linux_new);

    let resolved: HashSet<Platform> = fresh.platforms.iter().map(|p| p.platform.clone()).collect();
    for prev_platform in &previous.platforms {
        if !resolved.contains(&prev_platform.platform) {
            fresh.platforms.push(prev_platform.clone());
        }
    }

    assert_eq!(
        fresh.platforms.len(),
        2,
        "merged lockfile must carry both platforms"
    );
    let linux_entry = fresh
        .platforms
        .iter()
        .find(|p| p.platform.to_string() == "linux-x86_64")
        .expect("linux entry present");
    assert_eq!(
        linux_entry.modules[0].packages[0].coordinate.version(),
        "2.0",
        "linux platform must carry the freshly resolved version"
    );
    let darwin_entry = fresh
        .platforms
        .iter()
        .find(|p| p.platform.to_string() == "darwin-aarch64")
        .expect("darwin entry preserved");
    assert_eq!(
        darwin_entry.modules[0].packages[0].coordinate.version(),
        "1.0",
        "un-resolved platform must keep its previous pin"
    );
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
        .push(LockEdge::new(0, 1, Some(rv_lock::Scope::Compile), false));
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
        .push(LockEdge::new(1, 0, Some(rv_lock::Scope::Compile), false));
    resolved.platforms.push(platform);
    resolved.config_hash = selected.config_hash.clone();
    resolved.repo_ids = selected.repo_ids.clone();

    assert!(
        selected.resolution_drift(&resolved, |_, _| true).is_none(),
        "traversal order and remapped edge indices must not register as drift"
    );
}

#[test]
fn frozen_drift_error_includes_diff_entries() {
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
    let checked = check_frozen_local(&config, &args, true).unwrap();
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

    let copied = super::with_origins_of(&lock, &fresh);
    let pin = &copied.platforms[0].support_poms["com.example:parent:1"];
    assert_eq!(pin.repo_url, "https://fresh.example/");
    assert_eq!(pin.sha256, sha('a'));
}
