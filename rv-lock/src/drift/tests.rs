use super::*;
use crate::test_lock::{linux_lock, platform, set_support_pom};
use rv_maven_types::Digest;

#[test]
fn resolution_drift_names_what_changed() {
    let on_disk = linux_lock("1", '1');
    let drift = |fresh: &Lockfile| on_disk.resolution_drift(fresh, |_, _| true);
    assert_eq!(drift(&on_disk.clone()), None);

    let mut other_platform = on_disk.clone();
    other_platform.platforms[0].platform = platform("macos-aarch64");
    assert_eq!(drift(&other_platform), Some(ResolutionDrift::Platforms));
    assert_eq!(
        drift(&linux_lock("2", '1')).unwrap().to_string(),
        "the graph of module pom.xml changed on platform linux-x86_64"
    );
    assert_eq!(
        drift(&linux_lock("1", '2')).unwrap().to_string(),
        "artifact com.example:a:1:jar changed on platform linux-x86_64"
    );

    let mut fresh_support = on_disk.clone();
    set_support_pom(&mut fresh_support, "com.example:parent:1", 'e');
    let coord = "com.example:parent:1".to_string();
    let linux = platform("linux-x86_64");
    assert_eq!(
        drift(&fresh_support),
        Some(ResolutionDrift::SupportPom {
            platform: linux.clone(),
            coord: coord.clone()
        })
    );
    assert!(
        fresh_support
            .resolution_drift(&on_disk, |_, _| true)
            .is_some()
    );

    // A release POM with the same bytes from another declared repository is
    // the same file; a snapshot build or an undeclared origin is not.
    let mut moved = fresh_support.clone();
    moved.platforms[0]
        .support_poms
        .get_mut(&coord)
        .unwrap()
        .repo_url = "https://other/".into();
    assert_eq!(fresh_support.resolution_drift(&moved, |_, _| true), None);
    assert!(
        fresh_support
            .resolution_drift(&moved, |_, _| false)
            .is_some()
    );
    let mut snapshot = on_disk.clone();
    set_support_pom(&mut snapshot, "com.example:parent:1-SNAPSHOT", 'e');
    let mut moved_snapshot = snapshot.clone();
    let pin = moved_snapshot.platforms[0]
        .support_poms
        .values_mut()
        .next()
        .unwrap();
    pin.repo_url = "https://other/".into();
    assert!(
        snapshot
            .resolution_drift(&moved_snapshot, |_, _| true)
            .is_some()
    );
    let mut rebuilt = snapshot.clone();
    let pin = rebuilt.platforms[0]
        .support_poms
        .values_mut()
        .next()
        .unwrap();
    pin.snapshot = rv_maven_types::SnapshotStamp::new("20260101.120000", 2);
    assert!(snapshot.resolution_drift(&rebuilt, |_, _| true).is_some());
}

#[test]
fn a_changed_companion_pom_build_is_drift_even_with_the_same_bytes() {
    let on_disk = linux_lock("1-SNAPSHOT", '1');
    let mut fresh = on_disk.clone();
    fresh.platforms[0].artifacts[0].pom_snapshot =
        rv_maven_types::SnapshotStamp::new("20261012.010101", 1);
    assert!(matches!(
        on_disk.resolution_drift(&fresh, |_, _| true),
        Some(ResolutionDrift::Artifact { .. })
    ));
}

#[test]
fn changed_snapshot_origins_are_drift_with_identical_bytes_and_builds() {
    let mut on_disk = linux_lock("1-SNAPSHOT", '1');
    let artifact = &mut on_disk.platforms[0].artifacts[0];
    artifact.snapshot = rv_maven_types::SnapshotStamp::new("20261025.010101", 1);
    artifact.pom_snapshot = rv_maven_types::SnapshotStamp::new("20261025.020202", 2);
    artifact.pom_sha256 = Some("a".repeat(64).parse().unwrap());
    artifact.other_repo_urls = vec!["https://other.example/".into()];
    artifact.pom_repo_urls = vec!["https://pom.example/".into()];
    for url in [
        "https://repo.example/",
        "https://other.example/",
        "https://pom.example/",
        "https://moved.example/",
    ] {
        on_disk.repo_ids.insert(url.into(), [url.into()].into());
    }
    for pom in [false, true] {
        let mut fresh = on_disk.clone();
        let artifact = &mut fresh.platforms[0].artifacts[0];
        if pom {
            artifact.pom_repo_urls = vec!["https://moved.example/".into()];
        } else {
            artifact.other_repo_urls = vec!["https://moved.example/".into()];
        }
        for (left, right) in [(&on_disk, &fresh), (&fresh, &on_disk)] {
            assert!(
                matches!(
                    left.resolution_drift(right, |_, _| true),
                    Some(ResolutionDrift::Artifact { .. })
                ),
                "pom origins: {pom}"
            );
        }
    }
}

/// A mirror that serves several repositories answers for the first one
/// searched, so the same file can be recorded under another repository with
/// and without it. A release whose pins agree is the same file, so the
/// repository alone is not drift; a snapshot, or a pin that proves
/// nothing, still is.
#[test]
fn another_repository_is_drift_only_without_a_matching_pin() {
    let sha1 = || vec![Digest::parse("sha1", &"1".repeat(40)).expect("digest")];
    let moved = |version: &str, on_disk_sha1: bool, fresh_sha1: bool| {
        let mut on_disk = linux_lock(version, '1');
        if on_disk_sha1 {
            on_disk.platforms[0].artifacts[0].checksums = sha1();
        }
        let mut fresh = on_disk.clone();
        fresh.platforms[0].artifacts[0].repo_url = "https://other.example/".to_string();
        if fresh_sha1 {
            fresh.platforms[0].artifacts[0].checksums = sha1();
        }
        let declared = on_disk.resolution_drift(&fresh, |_, _| true);
        let undeclared = on_disk.resolution_drift(&fresh, |_, url| url != "https://repo.example/");
        assert!(undeclared.is_some(), "a recorded origin nothing declares");
        declared
    };
    assert_eq!(moved("1", false, false), None);
    assert_eq!(moved("1", true, true), None);
    assert!(moved("1", false, true).is_some());
    assert!(moved("1-SNAPSHOT", false, false).is_some());
}

#[test]
fn a_changed_model_keeps_a_matching_pin_under_a_declared_repository() {
    let on_disk = linux_lock("1", '1');
    let mut fresh = on_disk.clone();
    fresh.platforms[0].model_hash = "f".repeat(64);
    fresh.platforms[0].artifacts[0].repo_url = "https://other.example/".into();
    assert_eq!(on_disk.resolution_drift(&fresh, |_, _| true), None);
}

/// The same bytes of a release support POM from another repository are
/// the same file while the recorded repository is still declared. A
/// snapshot is identified by its build, not its bytes.
#[test]
fn a_support_pom_with_the_same_bytes_under_another_declared_repository_is_not_drift() {
    let moved = |coord: &str, declared: &str| {
        let mut on_disk = linux_lock("1", '1');
        set_support_pom(&mut on_disk, coord, 'e');
        let mut fresh = on_disk.clone();
        for platform in &mut fresh.platforms {
            platform.support_poms.get_mut(coord).unwrap().repo_url =
                "https://other.example/".into();
        }
        on_disk.resolution_drift(&fresh, |_, url| url == declared)
    };
    assert_eq!(moved("com.example:parent:1", "https://repo.example/"), None);
    assert!(moved("com.example:parent:1", "https://other.example/").is_some());
    assert!(moved("com.example:parent:1-SNAPSHOT", "https://repo.example/").is_some());
}

#[test]
fn host_inputs_only_one_side_consulted_are_not_drift() {
    let with = |inputs: &[&str], hash: char| {
        let mut lock = linux_lock("1", '1');
        lock.config_hash = Some(hash.to_string().repeat(64));
        lock.resolution.ambient_inputs =
            inputs.iter().map(|input| input.parse().unwrap()).collect();
        lock
    };
    let on_disk = with(&["jdk:[17,) is true"], 'c');
    let drift = |fresh: &Lockfile| on_disk.resolution_drift(fresh, |_, _| true);
    assert_eq!(
        drift(&with(&["jdk:[17,) is true", "jdk:99 is false"], 'd')),
        None
    );
    assert_eq!(drift(&with(&[], 'd')), None);
    assert_eq!(
        drift(&with(&["jdk:[17,) is false"], 'd')),
        Some(ResolutionDrift::Inputs)
    );
    assert_eq!(
        drift(&with(&["jdk:[17,) is true"], 'd')),
        Some(ResolutionDrift::Inputs)
    );
}

#[test]
fn undeclared_origins_and_ambiguous_tokens_are_reported() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = dunce::canonicalize(temp.path()).expect("root");
    let origins = LockOrigins::for_root(&root);
    let locked = linux_lock("1", '1');
    let url = || vec!["https://repo.example/".to_string()];
    let undeclared = |configured: &[String], per_platform: &[(Platform, Vec<String>)]| {
        locked.undeclared_origin(&origins, configured, per_platform)
    };
    assert_eq!(
        undeclared(&[], &[]).as_deref(),
        Some("https://repo.example/")
    );
    assert_eq!(undeclared(&["https://repo.example".to_string()], &[]), None);
    assert_eq!(undeclared(&[], &[(platform("linux-x86_64"), url())]), None);
    assert!(undeclared(&[], &[(platform("macos-aarch64"), url())]).is_some());

    let mut with_parent = locked.clone();
    set_support_pom(&mut with_parent, "com.example:parent:1", 'e');
    with_parent.platforms[0]
        .support_poms
        .get_mut("com.example:parent:1")
        .unwrap()
        .repo_url = "https://parent.example/".into();
    assert_eq!(
        with_parent
            .undeclared_origin(&origins, &url(), &[])
            .as_deref(),
        Some("https://parent.example/")
    );
    assert_eq!(
        with_parent.undeclared_origin(
            &origins,
            &url(),
            &[(
                platform("linux-x86_64"),
                vec!["https://parent.example/".into()]
            )]
        ),
        None
    );

    // Another origin of a row needs a declaration too.
    let mut shared = linux_lock("1", '1');
    shared.platforms[0].artifacts[0].other_repo_urls = vec!["https://other.example/".to_string()];
    assert_eq!(
        shared.undeclared_origin(&origins, &url(), &[]).as_deref(),
        Some("https://other.example/")
    );
}

#[test]
fn a_snapshot_is_due_once_the_lock_is_as_old_as_its_interval() {
    let temp = tempfile::tempdir().expect("tempdir");
    let origins = LockOrigins::for_root(temp.path());
    let snapshot = linux_lock("1-SNAPSHOT", '1');
    let policies = [
        ("https://repo.example/".to_string(), 100),
        ("https://repo.example".to_string(), 50),
    ];
    assert!(!snapshot.snapshot_refresh_due(&origins, 49, 10, &policies));
    assert!(snapshot.snapshot_refresh_due(&origins, 50, 10, &policies));
    assert!(
        snapshot.snapshot_refresh_due(&origins, 10, 10, &[]),
        "default interval"
    );
    // Another snapshot repository's shorter interval applies too.
    let other = [
        ("https://repo.example/".to_string(), 100),
        ("https://other.example/".to_string(), 30),
    ];
    assert!(!snapshot.snapshot_refresh_due(&origins, 29, 10, &other));
    assert!(snapshot.snapshot_refresh_due(&origins, 30, 10, &other));
    // A companion POM's own repository, which no policy names, adds the
    // default interval even when the row's repository never updates.
    let never = [("https://repo.example/".to_string(), i64::MAX)];
    assert!(!snapshot.snapshot_refresh_due(&origins, 10, 10, &never));
    let mut split = snapshot.clone();
    split.platforms[0].artifacts[0].other_repo_urls = vec!["https://pom.example/".into()];
    assert!(split.snapshot_refresh_due(&origins, 10, 10, &never));
    let release = linux_lock("1", '1');
    assert!(!release.snapshot_refresh_due(&origins, i64::MAX, 0, &[]));
    // Maven reads metadata only for a requested version ending in SNAPSHOT:
    // a timestamped one names its file, and `1.0SNAPSHOT` at a build does not.
    let explicit = linux_lock("1-20240101.010101-7", '1');
    assert!(!explicit.snapshot_refresh_due(&origins, i64::MAX, 0, &[]));
    let mut parent = release.clone();
    set_support_pom(&mut parent, "com.example:parent:1.0SNAPSHOT", 'e');
    let pin = parent.platforms[0]
        .support_poms
        .values_mut()
        .next()
        .unwrap();
    pin.snapshot = rv_maven_types::SnapshotStamp::new("20240101.010101", 7);
    assert!(parent.snapshot_refresh_due(&origins, 10, 10, &[]));
}

/// Hashes are fast-path keys, while every other recorded output is frozen.
#[test]
fn resolution_compares_recorded_outputs_except_local_hashes() {
    use rv_maven_types::{Gav, Sha256};
    let mut on_disk = linux_lock("1", '1');
    on_disk.platforms[0].set_model_inputs(&[], &BTreeMap::new());
    let drift = |fresh: &Lockfile| on_disk.resolution_drift(fresh, |_, _| true);
    let mut fresh = on_disk.clone();
    fresh.platforms[0].model_hash = "f".repeat(64);
    fresh.platforms[0]
        .model_inputs
        .as_mut()
        .unwrap()
        .pom_hashes
        .insert("pom.xml".into(), Sha256::from_bytes(b"edited"));
    assert_eq!(drift(&fresh), None);
    fresh.platforms[0]
        .model_inputs
        .as_mut()
        .unwrap()
        .profiles
        .push("ci".into());
    assert!(matches!(
        drift(&fresh),
        Some(ResolutionDrift::Profiles { .. })
    ));
    fresh = on_disk.clone();
    fresh.platforms[0].modules[0].gav = Gav::new("com.example", "renamed", "1");
    assert!(matches!(
        drift(&fresh),
        Some(ResolutionDrift::Module { .. })
    ));
    fresh = on_disk.clone();
    fresh
        .repo_ids
        .insert("https://repo.example/".into(), ["renamed".into()].into());
    assert_eq!(drift(&fresh), Some(ResolutionDrift::RepositoryIds));
    fresh = on_disk.clone();
    fresh.platforms[0].artifacts[0]
        .other_repo_urls
        .push("https://other.example/".into());
    assert!(matches!(
        drift(&fresh),
        Some(ResolutionDrift::Artifact { .. })
    ));
    fresh = on_disk.clone();
    fresh.platforms[0].artifacts[0].checksums =
        vec![Digest::parse("sha1", &"1".repeat(40)).unwrap()];
    assert!(matches!(
        drift(&fresh),
        Some(ResolutionDrift::Artifact { .. })
    ));
    fresh = on_disk.clone();
    fresh.config_hash = Some("a".repeat(64));
    assert_eq!(drift(&fresh), Some(ResolutionDrift::Inputs));
}

#[test]
fn an_empty_support_pom_origin_is_undeclared() {
    let temp = tempfile::tempdir().expect("tempdir");
    let origins = LockOrigins::for_root(temp.path());
    let mut locked = linux_lock("1", '1');
    set_support_pom(&mut locked, "com.example:parent:1", 'e');
    locked.platforms[0]
        .support_poms
        .get_mut("com.example:parent:1")
        .unwrap()
        .repo_url
        .clear();
    // Artifact rows may omit a repository (system scope). A support POM always
    // comes from a repository, so an empty origin grants nothing.
    assert_eq!(
        locked
            .undeclared_origin(&origins, &["https://repo.example/".into()], &[])
            .as_deref(),
        Some("")
    );
}

#[test]
fn system_file_drift_accepts_a_relative_lock_root() {
    let project = tempfile::tempdir().expect("project");
    let abs = dunce::canonicalize(project.path()).expect("abs");
    std::fs::write(abs.join("vendor.jar"), b"bytes").unwrap();
    let digest = rv_maven_types::Sha256::from_bytes(b"bytes");
    let mut lock = linux_lock("1", '1');
    let module = &mut lock.platforms[0].modules[0];
    let mut pkg = module.packages[0].clone();
    pkg.system_path = Some("vendor.jar".into());
    pkg.system_sha256 = Some(digest);
    module.packages = vec![pkg];
    assert_eq!(lock.system_file_drift(&abs), None);
    let prev = std::env::current_dir().unwrap();
    std::env::set_current_dir(&abs).unwrap();
    let drift = lock.system_file_drift(std::path::Path::new("."));
    std::env::set_current_dir(prev).unwrap();
    assert_eq!(drift, None, "unchanged file under a relative lock_root");
}

#[test]
fn only_a_release_file_with_other_bytes_is_repinned() {
    let repinned = |old: &str, new: &str| {
        let fresh = linux_lock(new, '2');
        let paths = linux_lock(old, '1').repinned_releases(&fresh);
        paths.into_iter().map(|(path, ..)| path).collect::<Vec<_>>()
    };
    assert_eq!(repinned("1", "1"), ["com/example/a/1/a-1.jar"]);
    assert!(repinned("1", "2").is_empty());
    for snapshot in ["1-SNAPSHOT", "1SNAPSHOT", "SNAPSHOT"] {
        assert!(repinned(snapshot, snapshot).is_empty(), "{snapshot}");
    }
}
