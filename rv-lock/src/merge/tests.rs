use super::*;
use crate::test_lock::{linux_lock, lock, locked_platform, package, platform, set_support_pom};

fn verdicts(fresh: &Lockfile, previous: &Lockfile) -> Vec<(String, Option<String>)> {
    preservation(fresh, previous, &"c".repeat(64))
        .into_iter()
        .map(|candidate| {
            let reason = candidate.dropped.map(|reason| reason.to_string());
            (candidate.platform.to_string(), reason)
        })
        .collect()
}

fn fresh() -> Lockfile {
    linux_lock("1", '1')
}

/// The platforms of `previous` that `preservation` keeps for `fresh`.
fn kept(fresh: &Lockfile, previous: &Lockfile) -> Vec<Kept> {
    (preservation(fresh, previous, &"c".repeat(64)).into_iter())
        .filter_map(|candidate| candidate.keep(|_| None).ok())
        .collect()
}

/// Only a platform `preservation` keeps reaches `carry_forward`: one it
/// drops, here for a changed configuration, cannot be named.
#[test]
fn a_dropped_platform_cannot_be_carried_forward() {
    let previous = lock(vec![locked_platform("macos-aarch64", Vec::new(), '7')]);
    let candidates = preservation(&fresh(), &previous, &"d".repeat(64));
    let dropped = candidates[0].clone().keep(|_| None).unwrap_err();
    assert_eq!(
        dropped,
        (platform("macos-aarch64"), DropReason::Reconfigured)
    );
    // Agreeing pins keep a platform only when the caller's check does too.
    let agreeing = preservation(&fresh(), &previous, &"c".repeat(64));
    assert_eq!(
        agreeing[0].clone().keep(|_| Some(DropReason::ModelChanged)),
        Err((platform("macos-aarch64"), DropReason::ModelChanged))
    );
    let mut fresh = fresh();
    let kept = kept(&fresh, &previous);
    assert_eq!(kept.len(), 1);
    // A platform kept twice, or already resolved, is carried once.
    let twice = [kept[0].clone(), kept[0].clone()];
    carry_forward(&mut fresh, &previous, &twice).unwrap();
    carry_forward(&mut fresh, &previous, &twice).unwrap();
    assert_eq!(fresh.platforms.len(), 2);
}

/// One entry of reads per platform, or an error, not a panic.
#[test]
fn target_reads_for_other_platforms_are_refused() {
    let mut lock = fresh();
    let reads = lock.target_reads();
    lock.set_target_reads(&reads).unwrap();
    let err = lock.set_target_reads(&[]).unwrap_err();
    assert!(
        err.to_string().contains("0 target reads for 1 platforms"),
        "{err}"
    );
}

#[test]
fn an_agreeing_platform_is_a_candidate_and_a_resolved_one_is_not_listed() {
    let previous = lock(vec![
        locked_platform("linux-x86_64", vec![package("a", "0", '0')], '8'),
        locked_platform("macos-aarch64", vec![package("a", "1", '1')], '7'),
    ]);
    assert_eq!(
        verdicts(&fresh(), &previous),
        [("macos-aarch64".to_string(), None)]
    );
}

/// Maven reads one `.pom` and one file per coordinate, so a preserved
/// platform whose pins contradict this run in any of the two recordings
/// cannot be carried forward.
#[test]
fn every_drop_reason_is_reported_in_previous_order() {
    let other_pom = "it pins a different POM for com.example:a:1 than this run resolved, and \
                     Maven has one local-repository path per coordinate";
    let macos = |pom| locked_platform("macos-aarch64", vec![package("a", "1", '1')], pom);

    let mut reconfigured = lock(vec![macos('7')]);
    reconfigured.config_hash = Some("d".repeat(64));
    assert_eq!(
        verdicts(&fresh(), &reconfigured)[0].1.as_deref(),
        Some("resolution configuration changed since it was locked")
    );

    let previous = lock(vec![
        locked_platform("windows-x86_64", vec![package("a", "1", '1')], '9'),
        macos('7'),
    ]);
    assert_eq!(
        verdicts(&fresh(), &previous),
        [
            ("windows-x86_64".to_string(), Some(other_pom.to_string())),
            ("macos-aarch64".to_string(), None)
        ]
    );

    let other_bytes = lock(vec![locked_platform(
        "macos-aarch64",
        vec![package("a", "1", '2')],
        '7',
    )]);
    assert_eq!(
        verdicts(&fresh(), &other_bytes)[0].1.as_deref(),
        Some(
            "it pins different bytes or another snapshot build of com.example:a:1:jar than this \
             run resolved, and Maven has one local-repository path per coordinate"
        )
    );

    // A build extension jar is one file too.
    let jar = |digest: char| crate::lock::ExtensionJar {
        gav: Gav::new("t", "ext", "1"),
        classifier: None,
        sha256: digest.to_string().repeat(64).parse().unwrap(),
    };
    let mut fresh_jar = fresh();
    fresh_jar.platforms[0].modules[0].extensions = vec![jar('e')];
    let mut other_jar = lock(vec![macos('7')]);
    other_jar.platforms[0].modules[0].extensions = vec![jar('f')];
    assert_eq!(
        verdicts(&fresh_jar, &other_jar)[0].1.as_deref(),
        Some(
            "it pins different bytes or another snapshot build of t:ext:1 than this run \
             resolved, and Maven has one local-repository path per coordinate"
        )
    );

    // Two support pins, a carried support pin against a fresh row, and a
    // preserved row against a fresh support pin.
    let mut fresh_support = fresh();
    set_support_pom(&mut fresh_support, "com.example:parent:1", 'e');
    let mut previous_support = lock(vec![macos('7')]);
    set_support_pom(&mut previous_support, "com.example:parent:1", 'd');
    let mut carried = lock(vec![macos('7')]);
    set_support_pom(&mut carried, "com.example:a:1", '8');
    for (fresh, previous, coord) in [
        (&fresh_support, &previous_support, "com.example:parent:1"),
        (&fresh(), &carried, "com.example:a:1"),
    ] {
        let expected = other_pom.replace("com.example:a:1", coord);
        assert_eq!(verdicts(fresh, previous)[0].1, Some(expected), "{coord}");
    }

    // A `-SNAPSHOT` pin and a pin of its timestamped build name one file.
    let mut fresh_build = fresh();
    set_support_pom(
        &mut fresh_build,
        "com.example:snap:1-20240101.010101-3",
        'e',
    );
    let mut previous_snapshot = lock(vec![macos('7')]);
    set_support_pom(&mut previous_snapshot, "com.example:snap:1-SNAPSHOT", 'd');
    for platform in &mut previous_snapshot.platforms {
        let pin = platform
            .support_poms
            .get_mut("com.example:snap:1-SNAPSHOT")
            .unwrap();
        pin.snapshot = rv_maven_types::SnapshotStamp::new("20240101.010101", 3);
    }
    assert_eq!(
        verdicts(&fresh_build, &previous_snapshot)[0].1,
        Some(other_pom.replace("com.example:a:1", "com.example:snap:1-SNAPSHOT"))
    );

    // A `-SNAPSHOT` parent and a row of another build of it leave one plain
    // `-SNAPSHOT.pom`.
    let mut row = package("snap", "1-SNAPSHOT", '1');
    row.snapshot = rv_maven_types::SnapshotStamp::new("20240101.010101", 4);
    let fresh_row = lock(vec![locked_platform("linux-x86_64", vec![row], '7')]);
    assert_eq!(
        verdicts(&fresh_row, &previous_snapshot)[0].1,
        Some(other_pom.replace("com.example:a:1", "com.example:snap:1-SNAPSHOT"))
    );
    // So does a row without a POM, which export would give that one.
    let bare = |platform| {
        let mut entry = locked_platform(platform, vec![package("snap", "1-SNAPSHOT", '1')], '7');
        entry.artifacts[0].pom_sha256 = None;
        lock(vec![entry])
    };
    assert_eq!(
        verdicts(&bare("linux-x86_64"), &previous_snapshot)[0].1,
        Some(other_pom.replace("com.example:a:1", "com.example:snap:1-SNAPSHOT"))
    );
    let kept_bare = bare("macos-aarch64");
    let mut fresh_snapshot = lock(vec![locked_platform("linux-x86_64", Vec::new(), '7')]);
    set_support_pom(&mut fresh_snapshot, "com.example:snap:1-SNAPSHOT", 'd');
    for platform in &mut fresh_snapshot.platforms {
        let pin = (platform.support_poms)
            .get_mut("com.example:snap:1-SNAPSHOT")
            .unwrap();
        pin.snapshot = rv_maven_types::SnapshotStamp::new("20240101.010101", 3);
    }
    assert_eq!(
        verdicts(&fresh_snapshot, &kept_bare)[0].1,
        Some(other_pom.replace("com.example:a:1", "com.example:snap:1-SNAPSHOT"))
    );
    // A row that misses a timestamped POM build names that build in the
    // build list export writes per repository id, which mirrors and
    // configuration decide after the lock; from any repository it may
    // shadow the support POM's build.
    let mut kept_build = bare("macos-aarch64");
    kept_build.platforms[0].artifacts[0].snapshot =
        rv_maven_types::SnapshotStamp::new("20240101.010101", 1);
    for url in ["https://repo.example/", "https://other.example/"] {
        kept_build.platforms[0].artifacts[0].repo_url = url.to_string();
        assert_eq!(
            verdicts(&fresh_snapshot, &kept_build)[0].1,
            Some(other_pom.replace("com.example:a:1", "com.example:snap:1-SNAPSHOT")),
            "{url}"
        );
    }

    let preserved = lock(vec![macos('8')]);
    let mut fresh_support_a = lock(vec![locked_platform("linux-x86_64", Vec::new(), '7')]);
    set_support_pom(&mut fresh_support_a, "com.example:a:1", '7');
    assert_eq!(
        verdicts(&fresh_support_a, &preserved)[0].1.as_deref(),
        Some(other_pom)
    );
}

/// A platform locked with another SNAPSHOT POM build beside the same jar
/// build names a different `.pom` under one coordinate.
#[test]
fn another_companion_pom_build_drops_the_platform() {
    let stamp = |build| rv_maven_types::SnapshotStamp::new("20261012.010101", build);
    let snapshot = |platform: &str, pom_build, pom| {
        let mut entry = locked_platform(platform, vec![package("a", "1-SNAPSHOT", '1')], pom);
        entry.artifacts[0].snapshot = stamp(3);
        entry.artifacts[0].pom_snapshot = stamp(pom_build);
        entry
    };
    let previous = lock(vec![snapshot("macos-aarch64", 1, '8')]);
    // A build without a POM names its own path all the same.
    for pinned in [true, false] {
        let mut fresh = lock(vec![snapshot("linux-x86_64", 2, '7')]);
        if !pinned {
            fresh.platforms[0].artifacts[0].pom_sha256 = None;
        }
        assert_eq!(
            verdicts(&fresh, &previous)[0].1.as_deref(),
            Some(
                "it pins a different POM for com.example:a:1-SNAPSHOT than this run resolved, \
                 and Maven has one local-repository path per coordinate"
            ),
            "{pinned}"
        );
    }
}

/// A kept row without a POM pin names the same `.pom` path as a fresh one
/// with a pin, or as a support POM, so the two sides cannot both be kept:
/// the repository that lacked it may serve it now. A fresh row without one
/// takes the POM the kept platform read, as one resolution of both would.
#[test]
fn a_pom_pin_one_side_lacks_drops_the_platform() {
    let other_pom = "it pins a different POM for com.example:a:1 than this run resolved, and \
                     Maven has one local-repository path per coordinate";
    let unpinned = |platform: &str| {
        let mut entry = locked_platform(platform, vec![package("a", "1", '1')], '7');
        entry.artifacts[0].pom_sha256 = None;
        lock(vec![entry])
    };
    let pinned = |platform| {
        lock(vec![locked_platform(
            platform,
            vec![package("a", "1", '1')],
            '7',
        )])
    };
    let mut fresh_support = lock(vec![locked_platform("linux-x86_64", Vec::new(), '7')]);
    set_support_pom(&mut fresh_support, "com.example:a:1", '7');
    for (fresh, previous) in [
        (pinned("linux-x86_64"), unpinned("macos-aarch64")),
        (fresh_support, unpinned("macos-aarch64")),
    ] {
        assert_eq!(verdicts(&fresh, &previous)[0].1.as_deref(), Some(other_pom));
    }
    let (mut fresh, previous) = (unpinned("linux-x86_64"), pinned("macos-aarch64"));
    let kept = kept(&fresh, &previous);
    assert_eq!(kept.len(), 1);
    carry_forward(&mut fresh, &previous, &kept).unwrap();
    let pins: Vec<_> = (fresh.platforms.iter())
        .map(|platform| platform.artifacts[0].pom_sha256.clone())
        .collect();
    let read = &previous.platforms[0].artifacts[0].pom_sha256;
    assert_eq!(pins, [read.clone(), read.clone()]);
}

/// Kept platforms bring their own support POMs and the repository ids, with
/// the fresh side winning per key; without one nothing stale bleeds in.
#[test]
fn carry_forward_keeps_the_named_platforms_sorted_with_their_provenance() {
    let mut previous = lock(vec![
        locked_platform("windows-x86_64", Vec::new(), '7'),
        locked_platform("linux-x86_64", Vec::new(), '7'),
    ]);
    set_support_pom(&mut previous, "com.example:parent:1", 'e');
    previous.repo_ids = BTreeMap::from([
        ("https://old.example/".to_string(), ["old".into()].into()),
        (
            "https://shared.example/".to_string(),
            ["previous".into()].into(),
        ),
        ("https://win.example/".to_string(), ["win".into()].into()),
    ]);
    // Only the Windows graph used `win`.
    previous.platforms[0].repo_ids = Some(BTreeMap::from([(
        "https://win.example/".to_string(),
        ["win".into()].into(),
    )]));
    let mut linux = previous.repo_ids.clone();
    linux.remove("https://win.example/");
    previous.platforms[1].repo_ids = Some(linux);
    let mut fresh = lock(vec![locked_platform("macos-aarch64", Vec::new(), '7')]);
    fresh.repo_ids = BTreeMap::from([(
        "https://shared.example/".to_string(),
        ["fresh".into()].into(),
    )]);

    let mut alone = fresh.clone();
    carry_forward(&mut alone, &previous, &[]).unwrap();
    let kept = kept(&fresh, &previous);
    assert_eq!((alone.platforms.len(), alone.repo_ids.len()), (1, 1));
    assert!(alone.support_poms().is_empty());

    let linux: Vec<_> = (kept.into_iter())
        .filter(|kept| kept.platform() == &platform("linux-x86_64"))
        .collect();
    carry_forward(&mut fresh, &previous, &linux).unwrap();
    let names: Vec<String> = fresh
        .platforms
        .iter()
        .map(|entry| entry.platform.to_string())
        .collect();
    assert_eq!(names, ["linux-x86_64", "macos-aarch64"]);
    assert_eq!(fresh.support_poms(), previous.support_poms());
    assert!(
        fresh.platforms[1].support_poms.is_empty(),
        "macos read none"
    );
    // A kept platform's rows keep their markers.
    assert_eq!(
        fresh.repo_ids["https://shared.example/"],
        ["fresh".into(), "previous".into()].into()
    );
    assert_eq!(
        fresh.repo_ids["https://old.example/"],
        ["old".into()].into()
    );
    assert!(!fresh.repo_ids.contains_key("https://win.example/"));
    // Neither platform used every id, so each lists its own.
    assert_eq!(fresh.platforms[1].repo_ids, Some(alone.repo_ids.clone()));
    assert_eq!(
        fresh.platforms[0].repo_ids.as_ref().map(BTreeMap::len),
        Some(2)
    );
    assert_eq!(alone.platforms[0].repo_ids, None);
    let reads = fresh.target_reads();
    assert_eq!(
        reads[0].repo_ids["https://shared.example/"],
        ["previous".into()].into()
    );
    assert_eq!(reads[1].repo_ids, alone.repo_ids);
}

#[test]
fn carry_forward_orders_jdk_targets_as_written() {
    let target = |jdk: &str| {
        let mut entry = locked_platform("linux-x86_64", Vec::new(), '7');
        entry.platform = entry.platform.with_jdk(jdk);
        entry
    };
    let previous = lock(vec![target("17")]);
    let mut fresh = lock(vec![target("21")]);
    let kept = kept(&fresh, &previous);
    carry_forward(&mut fresh, &previous, &kept).unwrap();
    let names: Vec<String> = (fresh.platforms.iter())
        .map(|entry| entry.platform.to_string())
        .collect();
    assert_eq!(names, ["linux-x86_64 (JDK 17)", "linux-x86_64 (JDK 21)"]);
}

#[test]
fn a_support_pom_and_a_companion_pom_must_agree() {
    let mut agreeing = fresh();
    set_support_pom(&mut agreeing, "com.example:a:1", '7');
    assert_eq!(agreeing.support_companion_conflict(), None);
    set_support_pom(&mut agreeing, "com.example:a:1", '8');
    assert_eq!(
        agreeing.support_companion_conflict().as_deref(),
        Some("com.example:a:1")
    );
}

/// Within one resolution, a row read from a repository that lacks the POM
/// pins none and agrees with the support POM another repository served,
/// which is the one file the local repository holds. Across runs a kept
/// row agrees only where the previous lock pinned that support POM too, on
/// its own platform or another: a platform whose row read no POM is dropped
/// beside a new support POM, which a repository it reads may now serve. A
/// fresh row without a POM agrees with a kept support POM.
#[test]
fn a_row_without_a_pom_agrees_with_its_own_support_pom() {
    let unpinned = |platform: &str, support: bool| {
        let mut entry = locked_platform(platform, vec![package("a", "1", '1')], '7');
        entry.artifacts[0].pom_sha256 = None;
        let mut lock = lock(vec![entry]);
        if support {
            set_support_pom(&mut lock, "com.example:a:1", '8');
        }
        lock
    };
    assert_eq!(
        unpinned("linux-x86_64", true).support_companion_conflict(),
        None
    );
    let other_pom = "it pins a different POM for com.example:a:1 than this run resolved, and \
                     Maven has one local-repository path per coordinate";
    let mut fresh_support = lock(vec![locked_platform("linux-x86_64", Vec::new(), '7')]);
    set_support_pom(&mut fresh_support, "com.example:a:1", '8');
    for (fresh, previous, verdict) in [
        (
            unpinned("linux-x86_64", true),
            unpinned("macos-aarch64", true),
            None,
        ),
        (fresh_support.clone(), unpinned("macos-aarch64", true), None),
        (
            fresh_support.clone(),
            unpinned("macos-aarch64", false),
            Some(other_pom),
        ),
        (
            unpinned("linux-x86_64", false),
            unpinned("macos-aarch64", true),
            None,
        ),
    ] {
        assert_eq!(verdicts(&fresh, &previous)[0].1.as_deref(), verdict);
    }
    let mut beside = unpinned("macos-aarch64", false);
    let mut windows = locked_platform("windows-x86_64", Vec::new(), '7');
    windows.support_poms = fresh_support.platforms[0].support_poms.clone();
    beside.platforms.push(windows);
    assert_eq!(
        verdicts(&fresh_support, &beside),
        [
            ("macos-aarch64".to_string(), None),
            ("windows-x86_64".to_string(), None)
        ]
    );
}

/// Codex's counterexamples: a kept row without a POM agrees with a fresh
/// support POM only where the previous lock pinned it from the same
/// repository, and never with a fresh row that pins it, since its own
/// repository may serve the POM now.
#[test]
fn a_kept_row_without_a_pom_needs_the_same_support_pom_provenance() {
    let sha = |c: char| -> Sha256 { c.to_string().repeat(64).parse().unwrap() };
    let unpinned = |platform: &str| {
        let mut entry = locked_platform(platform, vec![package("a", "1", '1')], '7');
        entry.artifacts[0].pom_sha256 = None;
        entry
    };
    let support = |platform: &str, url: &str| {
        let mut entry = locked_platform(platform, Vec::new(), '7');
        (entry.support_poms).insert(
            "com.example:a:1".to_string(),
            SupportPom::new(url, sha('8')),
        );
        entry
    };
    let previous = lock(vec![
        unpinned("linux-x86_64"),
        support("windows-x86_64", "https://b.example/"),
    ]);
    let same = lock(vec![support("windows-x86_64", "https://b.example/")]);
    assert_eq!(
        verdicts(&same, &previous)[0],
        ("linux-x86_64".to_string(), None)
    );
    let moved = lock(vec![support("windows-x86_64", "https://a.example/")]);
    assert!(verdicts(&moved, &previous)[0].1.is_some());
    let mut own = unpinned("macos-aarch64");
    (own.support_poms).insert(
        "com.example:a:1".to_string(),
        SupportPom::new("https://b.example/", sha('8')),
    );
    let mut fresh = locked_platform("linux-x86_64", vec![package("a", "1", '1')], '7');
    fresh.artifacts[0].pom_sha256 = Some(sha('8'));
    assert!(
        verdicts(&lock(vec![fresh]), &lock(vec![own]))[0]
            .1
            .is_some()
    );
}
