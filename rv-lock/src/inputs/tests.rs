//! Literal digests pin the recipes over plain inputs. The CLI golden hashes
//! check the same recipes from projects on disk.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::ambient::AmbientInput;
use crate::lock::LockPlatform;
use rv_maven_types::Gav;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn full_resolution_inputs() -> ResolutionInputs {
    ResolutionInputs {
        profile_selections: Vec::new(),
        active_profiles: strings(&["ci", "release", "ci"]),
        inactive_profiles: strings(&["slow"]),
        repositories: vec![
            RepositoryInputs {
                id: Some("central".to_string()),
                url: "https://repo1.maven.org/maven2".to_string(),
                releases: Some(true),
                snapshots: None,
                snapshots_update_policy: "daily".to_string(),
                releases_update_policy: "daily".to_string(),
                releases_checksum_policy: "Fail".to_string(),
                snapshots_checksum_policy: "Warn".to_string(),
            },
            RepositoryInputs {
                id: None,
                url: " file:///srv/m2/ ".to_string(),
                releases: None,
                snapshots: Some(false),
                snapshots_update_policy: "always".to_string(),
                releases_update_policy: "never".to_string(),
                releases_checksum_policy: "Ignore".to_string(),
                snapshots_checksum_policy: "Fail".to_string(),
            },
        ],
        allow_transitive_repositories: true,
        allow_env_substitution: strings(&["HOME", "CI", "HOME"]),
        transitive_repository_allowlist: strings(&["https://b.example/", "https://a.example/"]),
        jdks: Vec::new(),
        settings_profiles: Vec::new(),
        ambient: BTreeMap::new(),
    }
}

#[test]
fn config_hash_is_stable() {
    assert_eq!(
        config_hash(&ResolutionInputs::default()),
        "448c55f91c8faa7254373cdbd47b6485f125d0ce1714d91dd876b3eaf43435e7"
    );
    assert_eq!(
        config_hash(&full_resolution_inputs()),
        "d6b353af13ee3bc358c3a54513aee2fa47eec54adcdf88702c3c0d1951e1b8fd"
    );
    assert_eq!(
        config_hash(&ambient_resolution_inputs()),
        "b065e24cc21e873f4193385639dd8084a8d89bcb98953309a5210ca72193a45d"
    );
}

/// Asserts that each change of `$base` changes `$hash`, one change per line.
macro_rules! each_change_differs {
    ($hash:expr, $base:expr => $ty:ty; $($what:literal: $change:expr;)*) => {{
        let baseline = $hash(&$base);
        $(
            let mut inputs = $base;
            let change: fn(&mut $ty) = $change;
            change(&mut inputs);
            assert_ne!($hash(&inputs), baseline, $what);
        )*
    }};
}

#[test]
fn config_hash_frames_every_input() {
    each_change_differs! { config_hash, full_resolution_inputs() => ResolutionInputs;
        "active profile": |i| i.active_profiles.push("x".into());
        "profile moved": |i| i.inactive_profiles.push(i.active_profiles.remove(0));
        "repository order": |i| i.repositories.reverse();
        "releases flag unset": |i| i.repositories[0].releases = None;
        "update policy": |i| i.repositories[1].releases_update_policy = "daily".into();
        "transitive repositories": |i| i.allow_transitive_repositories = false;
        "command line": |i| i.profile_selections.push("-Pci".into());
    }
    let with_profile_selections = || ResolutionInputs {
        profile_selections: strings(&["-Pci", "-P!slow"]),
        ..full_resolution_inputs()
    };
    each_change_differs! { config_hash, with_profile_selections() => ResolutionInputs;
        "argument order": |i| i.profile_selections.reverse();
        "argument value": |i| i.profile_selections[0].push('0');
        "no arguments": |i| i.profile_selections.clear();
    }
    each_change_differs! { config_hash, ambient_resolution_inputs() => ResolutionInputs;
        "profile order": |i| i.settings_profiles.reverse();
        "profile content": |i| i.settings_profiles[0].content.push(' ');
        "no profiles": |i| i.settings_profiles.clear();
        "value": |i| drop(i.ambient.insert(AmbientInput::JavaVersion, Some("21".into())));
        "unset versus empty": |i| {
            i.ambient.insert(AmbientInput::env("UNSET").unwrap(), Some(String::new()));
        };
        "fewer names": |i| drop(i.ambient.remove(&AmbientInput::JavaHome));
        "an unset host value": |i| drop(i.ambient.insert(AmbientInput::OsRelease, None));
        "no names": |i| i.ambient.clear();
    }
    let mut unset = ambient_resolution_inputs();
    unset
        .ambient
        .insert(AmbientInput::env("OTHER").unwrap(), None);
    assert_eq!(
        config_hash(&unset),
        config_hash(&ambient_resolution_inputs()),
        "another unset name"
    );

    let mut same = full_resolution_inputs();
    same.active_profiles = strings(&["release", "ci"]);
    same.repositories[0].url.push('/');
    let baseline = config_hash(&full_resolution_inputs());
    assert_eq!(
        config_hash(&same),
        baseline,
        "profile order and trailing slash"
    );
}

fn ambient_resolution_inputs() -> ResolutionInputs {
    ResolutionInputs {
        settings_profiles: vec![
            SettingsProfileInput {
                id: "jdk17".into(),
                content: "<activation><jdk>17</jdk></activation>".into(),
            },
            SettingsProfileInput {
                id: "ci".into(),
                content: "env.CI".into(),
            },
        ],
        ambient: BTreeMap::from([
            (AmbientInput::JavaVersion, Some("17.0.2".to_string())),
            (AmbientInput::env("CI").unwrap(), Some("true".to_string())),
            (AmbientInput::env("UNSET").unwrap(), None),
            (AmbientInput::JavaHome, Some("/opt/jdk".to_string())),
        ]),
        ..full_resolution_inputs()
    }
}

fn reactor_inputs() -> ReactorInputs {
    ReactorInputs {
        // Given out of path order: the recipe orders them.
        modules: vec![
            ModuleInput {
                path: "pom.xml".into(),
                group: "com.example".into(),
                artifact: "root".into(),
                version: "1.0".into(),
                pom: b"<project><artifactId>root</artifactId></project>".to_vec(),
                active_profiles: strings(&["ci"]),
                resolution_context: Vec::new(),
            },
            ModuleInput {
                path: "app/pom.xml".into(),
                group: "com.example".into(),
                artifact: "app".into(),
                version: "1.0".into(),
                pom: b"<project>\r\n<artifactId>app</artifactId>\r\n</project>\r\n".to_vec(),
                active_profiles: strings(&["linux", "ci"]),
                resolution_context: Vec::new(),
            },
        ],
        active_profiles: strings(&["linux", "ci", "linux"]),
        local_parents: vec![LocalParentInput {
            label: "../parent/pom.xml".into(),
            pom: b"<project>parent</project>\n".to_vec(),
        }],
    }
}

#[test]
fn model_hash_is_stable() {
    assert_eq!(
        model_hash(&ReactorInputs::default()).hash,
        "58a6f981f0a68fdd05d119576bb42413baf4298ee855842fc499df1b1fbacb04"
    );
    let hashed = model_hash(&reactor_inputs());
    assert_eq!(
        hashed.hash,
        "c0b014b76d9fb14638bed6a5018b4c1465b43c584dd8095b090183b0a74a9b30"
    );
    let poms: Vec<String> = hashed
        .pom_hashes
        .iter()
        .map(|(path, sha)| format!("{path} {sha}"))
        .collect();
    assert_eq!(
        poms,
        [
            "../parent/pom.xml 21de5e7c8d55076e11245e7f87904b87685c377dc9c0096ad00ffb5552564da1",
            "app/pom.xml c7e384eae63504a4920a3eb4ecb57ad2a20fc6ecf7d3fdd8de78426d5244cef9",
            "pom.xml b3ef2e1b38909d33b30b5d12d79247221f13967c0ff66f6f33692517386ad5f4",
        ]
    );
}

#[test]
fn model_hash_ignores_line_endings_and_profile_order_only() {
    assert_eq!(pom_sha256(b"<p>\r\n</p>\r\n"), pom_sha256(b"<p>\n</p>\n"));
    assert_ne!(pom_sha256(b"<p>\r</p>"), pom_sha256(b"<p>\n</p>"));
    let mut reordered = reactor_inputs();
    reordered.active_profiles = strings(&["ci", "linux"]);
    reordered.modules[1].active_profiles.reverse();
    let baseline = model_hash(&reactor_inputs()).hash;
    assert_eq!(model_hash(&reordered).hash, baseline);
    let hash = |inputs: &ReactorInputs| model_hash(inputs).hash;
    each_change_differs! { hash, reactor_inputs() => ReactorInputs;
        "root POM bytes": |i| i.modules[0].pom.push(b' ');
        "active profile ids": |i| i.active_profiles.push("staging".into());
        "a module's profile ids": |i| i.modules[0].active_profiles = strings(&["linux"]);
        "local parent": |i| i.local_parents.clear();
        "inherited resolution context": |i| i.modules[1].resolution_context = vec![Some("2".into())];
    }
}

#[test]
fn module_context_is_framed_and_does_not_change_other_records() {
    let baseline = model_hash(&reactor_inputs());
    let context = |values| {
        let mut inputs = reactor_inputs();
        inputs.modules[1].resolution_context = values;
        let hashed = model_hash(&inputs);
        assert_eq!(hashed.pom_hashes["pom.xml"], baseline.pom_hashes["pom.xml"]);
        hashed.pom_hashes["app/pom.xml"].clone()
    };
    assert_ne!(context(vec![None]), context(vec![Some(String::new())]));
    assert_ne!(
        context(vec![Some("a".into()), Some("bc".into())]),
        context(vec![Some("ab".into()), Some("c".into())])
    );
}

fn platform() -> Platform {
    Platform::new("linux", "x86_64").expect("platform")
}

/// A lock recording `reactor_inputs()` for one platform, as `raeva sync`
/// records it, and the matching current model.
fn locked_and_current() -> (Lockfile, CurrentModel) {
    let inputs = reactor_inputs();
    let hashed = model_hash(&inputs);
    let mut locked = LockPlatform {
        model_hash: hashed.hash.clone(),
        ..LockPlatform::single_module(
            platform(),
            Gav::new("com.example", "root", "1.0"),
            "pom",
            Vec::new(),
        )
    };
    let mut app = locked.modules[0].clone();
    app.path = "app/pom.xml".into();
    app.gav = Gav::new("com.example", "app", "1.0");
    locked.modules.push(app);
    let profiles = strings(&["ci", "linux"]);
    locked.set_model_inputs(&profiles, &hashed.pom_hashes);
    let mut lock = Lockfile::new();
    lock.platforms.push(locked);
    let current = CurrentModel {
        platform: platform(),
        model_hash: hashed.hash,
        active_profiles: profiles,
        modules: inputs
            .modules
            .iter()
            .map(|module| CurrentModule {
                path: module.path.clone(),
                group: module.group.clone(),
                artifact: module.artifact.clone(),
                version: module.version.clone(),
            })
            .collect(),
        pom_hashes: hashed.pom_hashes,
    };
    (lock, current)
}

#[test]
fn an_unchanged_model_has_no_drift() {
    let (lock, current) = locked_and_current();
    assert!(lock.models_match(std::slice::from_ref(&current)));
    assert_eq!(lock.model_drift(std::slice::from_ref(&current)), None);
    assert_eq!(lock.model_drift(&[]), None, "an undescribed platform");
}

#[test]
fn model_drift_names_the_first_difference() {
    let changed = "f".repeat(64);
    let drift = |edit: &dyn Fn(&mut CurrentModel)| {
        let (lock, mut current) = locked_and_current();
        current.model_hash = changed.clone();
        edit(&mut current);
        assert!(!lock.models_match(std::slice::from_ref(&current)));
        lock.model_drift(std::slice::from_ref(&current))
            .expect("drift")
            .to_string()
    };
    assert_eq!(
        drift(&|current| current.active_profiles = strings(&["ci"])),
        "active Maven profiles changed for platform linux-x86_64 \
         (locked: [ci, linux], current: [ci])"
    );
    assert_eq!(
        drift(&|current| {
            let mut extra = current.modules[0].clone();
            extra.path = "lib/pom.xml".into();
            current.modules.push(extra);
        }),
        "reactor module added: lib/pom.xml"
    );
    assert_eq!(
        drift(&|current| current.modules.retain(|module| module.path == "pom.xml")),
        "reactor module removed: app/pom.xml"
    );
    assert_eq!(
        drift(&|current| current.modules[1].version = "2.0".into()),
        "effective GAV changed for module app/pom.xml \
         (locked com.example:app:1.0, current com.example:app:2.0)"
    );
    assert_eq!(
        drift(&|current| {
            current
                .pom_hashes
                .insert("app/pom.xml".into(), "0".repeat(64).parse().unwrap());
        }),
        "module POM changed: app/pom.xml"
    );
    assert_eq!(
        drift(&|current| {
            current
                .pom_hashes
                .insert("../parent/pom.xml".into(), "0".repeat(64).parse().unwrap());
        }),
        "local parent POM changed: ../parent/pom.xml"
    );
    assert_eq!(
        drift(&|_| {}),
        "reactor model changed for platform linux-x86_64"
    );
}

#[test]
fn graphs_that_disagree_with_matching_records_are_drift() {
    let (mut lock, current) = locked_and_current();
    lock.platforms[0].modules.pop();
    assert!(!lock.models_match(std::slice::from_ref(&current)));
    assert_eq!(
        lock.model_drift(std::slice::from_ref(&current))
            .expect("drift")
            .to_string(),
        "reactor module added: app/pom.xml"
    );
    let (mut lock, current) = locked_and_current();
    lock.platforms[0].modules[1].gav = Gav::new("com.example", "app", "0.9");
    assert!(!lock.models_match(std::slice::from_ref(&current)));
}

#[test]
fn config_drift_requires_a_recorded_equal_hash() {
    let mut lock = Lockfile::new();
    assert_eq!(lock.config_drift("a"), Some(ConfigDrift::Unrecorded));
    lock.config_hash = Some("a".into());
    assert_eq!(lock.config_drift("a"), None);
    assert_eq!(lock.config_drift("b"), Some(ConfigDrift::Changed));
}

/// A module's reads bind only its own graph, the platform's bind every
/// graph, and a lock whose `ambient_inputs` misses a read, or that has no
/// graph digests, is not trusted.
#[test]
fn graph_digests_cover_the_names_each_graph_read() {
    let (lock, _) = locked_and_current();
    let digests = |edit: &dyn Fn(&mut crate::ModelInputs)| {
        let mut platform = lock.platforms[0].clone();
        edit(platform.model_inputs.as_mut().unwrap());
        graph_digests(
            &platform,
            platform.model_inputs.as_ref().unwrap(),
            Some("h"),
            &crate::TargetReads::default(),
        )
    };
    let v = || BTreeSet::from([AmbientInput::user_property("v").unwrap()]);
    let base = digests(&|_| {});
    let app = digests(&|inputs| {
        inputs
            .module_ambient_inputs
            .insert("app/pom.xml".into(), v());
    });
    assert_ne!(app["app/pom.xml"], base["app/pom.xml"]);
    assert_eq!(app["pom.xml"], base["pom.xml"]);
    let shared = digests(&|inputs| inputs.ambient_inputs = v());
    assert!(shared.iter().all(|(path, digest)| *digest != base[path]));
    assert_ne!(shared["app/pom.xml"], app["app/pom.xml"]);

    let mut platform = lock.platforms[0].clone();
    let inputs = platform.model_inputs.as_mut().unwrap();
    inputs
        .module_ambient_inputs
        .insert("app/pom.xml".into(), v());
    let graphs = graph_digests(
        &platform,
        platform.model_inputs.as_ref().unwrap(),
        Some("h"),
        &crate::TargetReads::default(),
    );
    platform.model_inputs.as_mut().unwrap().graphs = graphs;
    assert!(platform.graphs_match(Some("h"), &v(), &crate::RepoIds::new()));
    assert!(!platform.graphs_match(Some("h"), &BTreeSet::new(), &crate::RepoIds::new()));
    platform.model_inputs = None;
    assert!(
        !platform.graphs_match(Some("h"), &v(), &crate::RepoIds::new()),
        "no digests prove nothing"
    );
}

/// What a target read binds every graph of the target, whether it lists it
/// or reads all the lock lists, so a merge or an edit cannot pair one
/// branch's repository ids or conditions with another's graphs.
#[test]
fn graph_digests_cover_what_a_target_read() {
    let (lock, _) = locked_and_current();
    let central = || {
        crate::RepoIds::from([(
            "https://r.example/".to_string(),
            BTreeSet::from(["central".to_string()]),
        )])
    };
    let jdk = || BTreeSet::from([AmbientInput::JavaVersion]);
    let digests =
        |platform: &LockPlatform, ids: &crate::RepoIds, ambient: &BTreeSet<AmbientInput>| {
            let reads = platform.reads(ids, ambient);
            graph_digests(
                platform,
                platform.model_inputs.as_ref().unwrap(),
                Some("h"),
                &reads,
            )
        };
    let plain = lock.platforms[0].clone();
    let (no_ids, no_names) = (crate::RepoIds::new(), BTreeSet::new());
    let mut own_ids = plain.clone();
    own_ids.repo_ids = Some(central());
    let mut own_none = plain.clone();
    own_none.host_inputs = Some(BTreeSet::new());
    let mut own_jdk = plain.clone();
    own_jdk.host_inputs = Some(jdk());
    let all = [
        digests(&plain, &no_ids, &no_names),
        digests(&plain, &central(), &no_names),
        digests(&plain, &no_ids, &jdk()),
        digests(&own_ids, &central(), &jdk()),
    ];
    for (i, digests) in all.iter().enumerate() {
        for other in &all[i + 1..] {
            assert!(digests.iter().all(|(path, digest)| *digest != other[path]));
        }
    }
    // The same reads, listed or not, give the same digests.
    assert_eq!(digests(&own_jdk, &no_ids, &jdk()), all[2]);
    assert_eq!(digests(&own_none, &no_ids, &jdk()), all[0]);

    // A merge keeping one branch's graphs and the other's lists.
    let mut merged = plain.clone();
    merged.model_inputs.as_mut().unwrap().graphs = all[1].clone();
    assert!(merged.graphs_match(Some("h"), &no_names, &central()));
    assert!(!merged.graphs_match(Some("h"), &no_names, &no_ids));
    merged.model_inputs.as_mut().unwrap().graphs = all[2].clone();
    assert!(merged.graphs_match(Some("h"), &jdk(), &no_ids));
    assert!(!merged.graphs_match(Some("h"), &no_names, &no_ids));
    merged.host_inputs = Some(BTreeSet::new());
    assert!(!merged.graphs_match(Some("h"), &jdk(), &no_ids));
}
