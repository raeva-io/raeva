use rv_lock::Platform;
use rv_maven_types::Gav;

/// Hash the reactor model rooted at `project_root` for the current
/// platform, exactly as `raeva sync` does.
fn discover_model(project_root: &std::path::Path) -> super::ReactorModel {
    use rv_config::{Config, ResolvedPaths};

    let paths = ResolvedPaths::from_raeva_home(project_root.join("raeva-home"));
    let config = Config::for_testing_with_repos(project_root.to_path_buf(), paths, Vec::new());
    let platform = Platform::current().expect("platform");
    super::discover_reactor_model(&config, &platform).expect("discover model")
}

/// A CI-friendly local parent: parent and child both write
/// `${revision}`, which `.mvn/maven.config` sets. Resolution loads that
/// parent, so its bytes shape the resolved graph and both hashes have to
/// cover them: otherwise editing that parent leaves `model_hash`
/// unchanged, the fast path reuses the stale lock, and `--frozen` reports
/// no drift.
#[test]
fn model_hash_covers_a_ci_friendly_parent() {
    use rv_lock::{LockPlatform, Lockfile};
    use std::fs;

    let dir = tempfile::tempdir().expect("tempdir");
    let parent_dir = dir.path().join("parent");
    fs::create_dir_all(&parent_dir).expect("mkdir parent");
    let parent_pom = parent_dir.join("pom.xml");
    fs::write(
        &parent_pom,
        "<project><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>${revision}</version>\
             <packaging>pom</packaging>\
             <properties><foo>one</foo></properties></project>",
    )
    .expect("write parent pom");

    let project_root = dir.path().join("app");
    fs::create_dir_all(project_root.join(".mvn")).expect("mkdir .mvn");
    fs::write(
        project_root.join(".mvn").join("maven.config"),
        "-Drevision=1.2.3\n",
    )
    .expect("write maven.config");
    fs::write(
        project_root.join("pom.xml"),
        "<project>\
             <parent><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>${revision}</version>\
             <relativePath>../parent/pom.xml</relativePath></parent>\
             <artifactId>app</artifactId><version>1.0</version></project>",
    )
    .expect("write project pom");

    let model = discover_model(&project_root);
    assert_eq!(
        model.pom_hashes.keys().cloned().collect::<Vec<_>>(),
        ["../parent/pom.xml", "pom.xml"],
        "the parent resolution loads must be a hashed model input"
    );

    // A lock written from this model, as `raeva sync` records it.
    let mut platform = LockPlatform::single_module(
        Platform::current().expect("platform"),
        Gav::new("com.example", "app", "1.0"),
        "jar",
        Vec::new(),
    );
    platform.model_hash = model.model_hash.clone();
    platform.set_model_inputs(&model.active_profiles, &model.pom_hashes);
    let mut lock = Lockfile::new();
    lock.platforms.push(platform);
    let lock = Lockfile::from_toml(&lock.to_toml().unwrap()).unwrap();
    assert!(
        super::frozen_models_match(&lock, std::slice::from_ref(&model)),
        "an untouched reactor must stay on the fast path"
    );

    fs::write(
        &parent_pom,
        "<project><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>${revision}</version>\
             <packaging>pom</packaging>\
             <properties><foo>two</foo></properties></project>",
    )
    .expect("rewrite parent pom");

    let edited = discover_model(&project_root);
    assert_ne!(
        model.model_hash, edited.model_hash,
        "editing that parent must change model_hash"
    );
    let note = super::model_change_note(&lock, &lock, std::slice::from_ref(&edited))
        .expect("the edited parent needs a note if resolution matches");
    assert!(note.contains("../parent/pom.xml changed"), "{note}");
    assert!(!super::frozen_models_match(&lock, &[edited]));
}
