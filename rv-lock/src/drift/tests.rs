use super::*;
use crate::test_lock::{linux_lock, platform, set_support_pom};
use rv_maven_types::Digest;

#[test]
fn resolution_drift_names_what_changed() {
    let on_disk = linux_lock("1", '1');
    let drift = |fresh: &Lockfile| on_disk.resolution_drift(fresh, |_, _| true, |_, _, _| false);
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
            .resolution_drift(&on_disk, |_, _| true, |_, _, _| false)
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
    assert_eq!(
        fresh_support.resolution_drift(&moved, |_, _| true, |_, _, _| false),
        None
    );
    assert!(
        fresh_support
            .resolution_drift(&moved, |_, _| false, |_, _, _| false)
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
            .resolution_drift(&moved_snapshot, |_, _| true, |_, _, _| false)
            .is_some()
    );
    let mut rebuilt = snapshot.clone();
    let pin = rebuilt.platforms[0]
        .support_poms
        .values_mut()
        .next()
        .unwrap();
    pin.snapshot = rv_maven_types::SnapshotStamp::new("20260101.120000", 2);
    assert!(
        snapshot
            .resolution_drift(&rebuilt, |_, _| true, |_, _, _| false)
            .is_some()
    );
}

#[test]
fn a_changed_companion_pom_build_is_drift_even_with_the_same_bytes() {
    let on_disk = linux_lock("1-SNAPSHOT", '1');
    let mut fresh = on_disk.clone();
    fresh.platforms[0].artifacts[0].pom_snapshot =
        rv_maven_types::SnapshotStamp::new("20261012.010101", 1);
    assert!(matches!(
        on_disk.resolution_drift(&fresh, |_, _| true, |_, _, _| false),
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
                    left.resolution_drift(right, |_, _| true, |_, _, _| false),
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
/// repository alone is not drift, nor is it for a timestamped SNAPSHOT
/// build; a base SNAPSHOT file, or a pin that proves nothing, still is.
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
        let declared = on_disk.resolution_drift(&fresh, |_, _| true, |_, _, _| false);
        let undeclared = on_disk.resolution_drift(
            &fresh,
            |_, url| url != "https://repo.example/",
            |_, _, _| false,
        );
        assert!(undeclared.is_some(), "a recorded origin nothing declares");
        declared
    };
    assert_eq!(moved("1", false, false), None);
    assert_eq!(moved("1", true, true), None);
    assert!(moved("1", false, true).is_some());
    assert!(moved("1-SNAPSHOT", false, false).is_some());
    let mut on_disk = linux_lock("1-SNAPSHOT", '1');
    on_disk.platforms[0].artifacts[0].snapshot =
        rv_maven_types::SnapshotStamp::new("20261025.010101", 1);
    let mut fresh = on_disk.clone();
    fresh.platforms[0].artifacts[0].repo_url = "https://other.example/".to_string();
    assert_eq!(
        on_disk.resolution_drift(&fresh, |_, _| true, |_, _, _| false),
        None
    );
}

#[test]
fn a_changed_model_keeps_a_matching_pin_under_a_declared_repository() {
    let on_disk = linux_lock("1", '1');
    let mut fresh = on_disk.clone();
    fresh.platforms[0].model_hash = "f".repeat(64);
    fresh.platforms[0].artifacts[0].repo_url = "https://other.example/".into();
    assert_eq!(
        on_disk.resolution_drift(&fresh, |_, _| true, |_, _, _| false),
        None
    );
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
        on_disk.resolution_drift(&fresh, |_, url| url == declared, |_, _, _| false)
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
    let drift = |fresh: &Lockfile| on_disk.resolution_drift(fresh, |_, _| true, |_, _, _| false);
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

    // So does a repository that listed an evicted range.
    let mut evicted = linux_lock("1", '1');
    let mut module = crate::LockModule::new(
        "pom.xml",
        rv_maven_types::Gav::new("com.example", "app", "1"),
        "jar",
    );
    module.evicted_ranges.push(crate::EvictedRange {
        group: "com.example".into(),
        artifact: "lib".into(),
        range: "[1,2)".into(),
        origin: "https://listing.example/".into(),
        versions: vec!["1.5".into()],
    });
    evicted.platforms[0].modules.push(module);
    assert_eq!(
        evicted.undeclared_origin(&origins, &url(), &[]).as_deref(),
        Some("https://listing.example/")
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
    let drift = |fresh: &Lockfile| on_disk.resolution_drift(fresh, |_, _| true, |_, _, _| false);
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
fn only_a_fixed_file_with_other_bytes_is_repinned() {
    let repinned = |old: &str, new: &str| {
        let fresh = linux_lock(new, '2');
        let paths = linux_lock(old, '1').repinned_releases(&fresh);
        paths.into_iter().map(|(path, ..)| path).collect::<Vec<_>>()
    };
    assert_eq!(repinned("1", "1"), ["com/example/a/1/a-1.jar"]);
    assert!(repinned("1", "2").is_empty());
    let timestamped = "1-20260101.010101-1";
    assert_eq!(
        repinned(timestamped, timestamped),
        ["com/example/a/1-SNAPSHOT/a-1-20260101.010101-1.jar"]
    );
    assert!(repinned(timestamped, "1-20260101.010101-2").is_empty());
    for snapshot in ["1-SNAPSHOT", "1SNAPSHOT", "SNAPSHOT"] {
        assert!(repinned(snapshot, snapshot).is_empty(), "{snapshot}");
    }
    // A SHA-1 pin cannot be compared with a SHA-256 one, so it is listed
    // for the caller to check the bytes against.
    let mut sha1 = linux_lock("1", '1');
    let sha1_pin = Digest::parse("sha1", &"1".repeat(40)).unwrap();
    sha1.platforms[0].artifacts[0].checksums = vec![sha1_pin.clone()];
    let fresh = linux_lock("1", '1');
    let listed = sha1.repinned_releases(&fresh);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, "com/example/a/1/a-1.jar");
    assert_eq!(listed[0].1, sha1_pin);
    assert!(linux_lock("1", '1').repinned_releases(&fresh).is_empty());
}

#[test]
fn a_sha1_pin_is_listed_beside_a_sha256_pin_of_the_same_file() {
    // One platform, or one side of a merge conflict, pins the jar by SHA-1
    // alone and another by SHA-256: only the bytes can settle the SHA-1 one.
    let mut lock = linux_lock("1", '1');
    let mut sha1_platform = lock.platforms[0].clone();
    sha1_platform.platform = platform("macos-aarch64");
    let sha1_pin = Digest::parse("sha1", &"1".repeat(40)).unwrap();
    sha1_platform.artifacts[0].checksums = vec![sha1_pin.clone()];
    lock.platforms.push(sha1_platform);
    let listed = lock.repinned_releases(&linux_lock("1", '1'));
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0].0, "com/example/a/1/a-1.jar");
    assert_eq!(listed[0].1, sha1_pin);
}

/// An imported BOM's repositories serve only that BOM's parents and
/// imports, so a support POM recorded from one, as a star mirror records
/// it, keeps its pin while the resolution still declares the repository
/// for support POMs. Other bytes, or a repository no longer declared, are
/// drift.
#[test]
fn a_support_pom_under_a_repository_only_an_imported_bom_declares_keeps_its_pin() {
    let bom = "https://bom.example/";
    let moved = |sha: char, for_support_poms: &str| {
        let mut on_disk = linux_lock("1", '1');
        set_support_pom(&mut on_disk, "com.example:bom-parent:1", 'e');
        on_disk.platforms[0]
            .support_poms
            .get_mut("com.example:bom-parent:1")
            .unwrap()
            .repo_url = bom.into();
        let mut fresh = on_disk.clone();
        set_support_pom(&mut fresh, "com.example:bom-parent:1", sha);
        // Only the lock written behind the mirror records the repository.
        on_disk.repo_ids.insert(bom.into(), ["first".into()].into());
        on_disk.resolution_drift(
            &fresh,
            |_, url| url == "https://repo.example/",
            |_, coord, url| coord == "com.example:bom-parent:1" && url == for_support_poms,
        )
    };
    assert_eq!(moved('e', bom), None);
    assert!(matches!(
        moved('f', bom),
        Some(ResolutionDrift::SupportPom { .. })
    ));
    assert!(matches!(
        moved('e', "https://elsewhere.example/"),
        Some(ResolutionDrift::SupportPom { .. })
    ));

    // Other repository ids with no row moved are drift.
    let mut on_disk = linux_lock("1", '1');
    let fresh = on_disk.clone();
    on_disk.repo_ids.insert(bom.into(), ["first".into()].into());
    assert_eq!(
        on_disk.resolution_drift(&fresh, |_, _| true, |_, _, _| true),
        Some(ResolutionDrift::RepositoryIds)
    );
    let mut renamed = on_disk.clone();
    renamed.repo_ids.insert(bom.into(), ["other".into()].into());
    assert_eq!(
        on_disk.resolution_drift(&renamed, |_, _| true, |_, _, _| true),
        Some(ResolutionDrift::RepositoryIds)
    );

    // An artifact row takes no repository from that set.
    let mut on_disk = linux_lock("1", '1');
    on_disk.platforms[0].artifacts[0].repo_url = bom.into();
    let fresh = linux_lock("1", '1');
    assert!(matches!(
        on_disk.resolution_drift(&fresh, |_, url| url != bom, |_, _, _| true),
        Some(ResolutionDrift::Artifact { .. })
    ));

    // Nor does a support POM the BOM's build did not read through it, such
    // as the project's own parent.
    let mut on_disk = linux_lock("1", '1');
    set_support_pom(&mut on_disk, "com.example:parent:1", 'e');
    let fresh = on_disk.clone();
    on_disk.platforms[0]
        .support_poms
        .get_mut("com.example:parent:1")
        .unwrap()
        .repo_url = bom.into();
    assert!(matches!(
        on_disk.resolution_drift(
            &fresh,
            |_, url| url != bom,
            |_, coord, url| coord == "com.example:bom-parent:1" && url == bom,
        ),
        Some(ResolutionDrift::SupportPom { .. })
    ));
}

/// The ids label what the export writes from every row and list, so a
/// moved row excuses a missing id only where nothing else names the
/// repository.
#[test]
fn a_moved_row_excuses_no_id_another_record_needs() {
    let other = "https://other.example/";
    let mut fresh = with_range_reads("1.5", &[("1.5", other)]);
    fresh.repo_ids.insert(other.into(), ["other".into()].into());
    let mut on_disk = fresh.clone();
    on_disk.platforms[0].artifacts[0].repo_url = other.into();
    on_disk.repo_ids.remove(other);
    assert_eq!(
        on_disk.resolution_drift(&fresh, |_, _| true, |_, _, _| false),
        Some(ResolutionDrift::RepositoryIds)
    );
}

/// An export writes one list per repository from the lines of every
/// module, so lines that move a version between repositories across
/// modules could show a range another module's version.
#[test]
fn range_versions_moved_between_modules_repositories_are_drift() {
    let (first, second) = ("https://first.example/", "https://second.example/");
    let reactor = |a: &str, b: &str| {
        let mut lock = linux_lock("1", '1');
        let mut module = lock.platforms[0].modules[0].clone();
        module.path = "b/pom.xml".into();
        module.gav = Gav::new("com.example", "b", "1");
        module.range_versions = vec![range_read("2", b)];
        lock.platforms[0].modules[0].range_versions = vec![range_read("1", a)];
        lock.platforms[0].modules.push(module);
        lock
    };
    let fresh = reactor(first, second);
    let swapped = reactor(second, first);
    assert_eq!(
        fresh.resolution_drift(&fresh, |_, _| true, |_, _, _| false),
        None
    );
    assert!(matches!(
        swapped.resolution_drift(&fresh, |_, _| true, |_, _, _| false),
        Some(ResolutionDrift::Module { .. })
    ));
}

fn range_read(version: &str, origin: &str) -> RangeVersion {
    RangeVersion {
        group: "com.example".into(),
        artifact: "a".into(),
        version: version.into(),
        origin: origin.into(),
    }
}

fn with_range_reads(version: &str, reads: &[(&str, &str)]) -> Lockfile {
    let mut lock = linux_lock(version, '1');
    lock.platforms[0].modules[0].range_versions = reads
        .iter()
        .map(|(version, origin)| range_read(version, origin))
        .collect();
    lock.platforms[0].modules[0].range_versions.sort();
    lock
}

/// A star mirror answers each repository's version list, so a lock written
/// behind one records a range's version under every repository the range
/// searched, and one written without it only under those that list the
/// version. With the same graph the ranges took the same versions, and the
/// recorded lists still give an offline Maven that version while it
/// searches each repository they name.
#[test]
fn range_versions_under_other_repositories_are_drift_only_when_the_versions_differ() {
    let (file, central) = ("./repo/", "https://repo1.maven.org/maven2/");
    let behind_star = with_range_reads("1.5", &[("1.5", file), ("1.5", central)]);
    let without = with_range_reads("1.5", &[("1.5", file)]);
    let all = |_: &Platform, _: &str| true;
    for (left, right) in [(&behind_star, &without), (&without, &behind_star)] {
        assert_eq!(left.resolution_drift(right, all, |_, _, _| false), None);
    }

    // A repository only the lock names that the resolution no longer
    // searches leaves the export's list unread.
    assert!(matches!(
        behind_star.resolution_drift(&without, |_, url| url != central, |_, _, _| false),
        Some(ResolutionDrift::Module { .. })
    ));
    // A repository only the fresh resolution names needs nothing.
    assert_eq!(
        without.resolution_drift(&behind_star, |_, url| url != central, |_, _, _| false),
        None
    );

    // A listing that changes the pick changes the graph.
    let picked_otherwise = with_range_reads("1.6", &[("1.6", central)]);
    assert!(matches!(
        behind_star.resolution_drift(&picked_otherwise, all, |_, _, _| false),
        Some(ResolutionDrift::Module { .. })
    ));
    // So does another version through the same repositories, and bytes
    // other than the pins.
    let mut other_version = with_range_reads("1.6", &[("1.6", file)]);
    other_version.platforms[0].artifacts[0].repo_url = file.into();
    assert!(
        behind_star
            .resolution_drift(&other_version, all, |_, _, _| false)
            .is_some()
    );
    let other_bytes = {
        let mut lock = linux_lock("1.5", '2');
        lock.platforms[0].modules[0].range_versions = vec![range_read("1.5", file)];
        lock
    };
    assert!(matches!(
        behind_star.resolution_drift(&other_bytes, all, |_, _, _| false),
        Some(ResolutionDrift::Artifact { .. })
    ));

    // A line naming another version, as an edit of the lock makes, is
    // drift with the same graph: the export lists what the line says.
    let edited = with_range_reads("1.5", &[("1.5", file), ("2.0", central)]);
    assert!(matches!(
        edited.resolution_drift(&without, all, |_, _, _| false),
        Some(ResolutionDrift::Module { .. })
    ));

    // Another range read is drift, whatever the repositories.
    let mut another_range = without.clone();
    another_range.platforms[0].modules[0]
        .range_versions
        .push(RangeVersion {
            artifact: "b".into(),
            ..range_read("1.0", file)
        });
    assert!(matches!(
        without.resolution_drift(&another_range, all, |_, _, _| false),
        Some(ResolutionDrift::Module { .. })
    ));
    // As is a module that differs beside its range versions.
    let mut other_graph = without.clone();
    other_graph.platforms[0].modules[0].range_versions =
        behind_star.platforms[0].modules[0].range_versions.clone();
    other_graph.platforms[0].modules[0].packaging = "war".into();
    assert!(matches!(
        without.resolution_drift(&other_graph, all, |_, _, _| false),
        Some(ResolutionDrift::Module { .. })
    ));
}

/// A range that lost lists its versions under each repository a star
/// mirror answered for, and without one under those that hold them.
#[test]
fn ranges_that_lost_under_other_repositories_are_drift_only_when_they_offer_other_versions() {
    let (file, central) = ("./repo/", "https://repo1.maven.org/maven2/");
    let lost = |lists: &[(&str, &[&str])]| {
        let mut lock = linux_lock("1.0", '1');
        lock.platforms[0].modules[0].evicted_ranges = (lists.iter())
            .map(|(origin, versions)| EvictedRange {
                group: "com.example".into(),
                artifact: "a".into(),
                range: "[1.0,2.0)".into(),
                origin: (*origin).into(),
                versions: versions.iter().map(|version| (*version).into()).collect(),
            })
            .collect();
        lock
    };
    let behind_star = lost(&[(file, &["1.0", "1.5"]), (central, &["1.0", "1.5"])]);
    let without = lost(&[(file, &["1.0", "1.5"])]);
    let all = |_: &Platform, _: &str| true;
    assert_eq!(
        behind_star.resolution_drift(&without, all, |_, _, _| false),
        None
    );
    assert_eq!(
        without.resolution_drift(&behind_star, all, |_, _, _| false),
        None
    );
    assert!(matches!(
        behind_star.resolution_drift(&without, |_, url| url != central, |_, _, _| false),
        Some(ResolutionDrift::Module { .. })
    ));
    // A list that offers another version is drift.
    let more = lost(&[(file, &["1.0", "1.5"]), (central, &["1.0", "1.7"])]);
    assert!(matches!(
        more.resolution_drift(&without, all, |_, _, _| false),
        Some(ResolutionDrift::Module { .. })
    ));
    // Where another range took a version of the artifact, the export's
    // list from the lock-only repository would show it that range's
    // versions too.
    let taken = |mut lock: Lockfile| {
        lock.platforms[0].modules[0].range_versions = vec![range_read("1.0", file)];
        lock
    };
    assert!(matches!(
        taken(behind_star).resolution_drift(&taken(without), all, |_, _, _| false),
        Some(ResolutionDrift::Module { .. })
    ));
}
