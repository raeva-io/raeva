//! Literal `config_hash` and `model_hash` values for a few representative
//! projects, computed through the functions `raeva sync` records in raeva.lock.
//!
//! A committed raeva.lock stays valid only while these digests stay the same, so
//! a dependency bump or refactor that moves one of them invalidates every
//! existing lock. These fixtures use config recipe v7, which hashes consulted
//! user-property values, and model recipe v3, which aggregates contextual
//! per-POM records. A change
//! to one is a lock compatibility break, not a test fix.
//!
//! Each case is `test-fixtures/lock-input-hashes/<name>` with the project in
//! `project/`. A `home/` directory, when present, is the user's Raeva and Maven
//! homes.

use rv_config::Config;
use rv_lock::Platform;
use rv_test_support::fixtures;

#[derive(Debug)]
struct Hashes {
    config_hash: String,
    models: Vec<Model>,
    /// What the fixture configures, so a test can show its inputs took effect.
    repositories: Vec<String>,
    mirrors: Vec<String>,
    timeout_and_retries: (u64, usize),
}

#[derive(Debug)]
struct Model {
    platform: String,
    hash: String,
    pom_paths: Vec<String>,
    active_profiles: Vec<String>,
    /// `path=groupId:artifactId:version` of each reactor module.
    modules: Vec<String>,
}

const PLATFORMS: [&str; 3] = ["linux-x86_64", "windows-x86_64", "macos-aarch64"];

/// Directories a `hashes` call below opens. A new directory must fail here
/// until a test names it.
fn lock_input_hash_cases() -> Vec<String> {
    let mut names =
        fixtures::quoted_after(include_str!("golden_hashes.rs"), concat!("hashes", "("));
    names.sort();
    names.dedup();
    names
}

fn hashes(case: &str) -> Hashes {
    let dir = tempfile::tempdir().expect("tempdir");
    fixtures::copy_tree_lf(
        &fixtures::path(&format!("lock-input-hashes/{case}")),
        dir.path(),
    );
    let (home, project) = (dir.path().join("home"), dir.path().join("project"));
    let raeva_home = home.join("raeva-home");
    let maven_home = home.join("maven-home");
    temp_env::with_vars(
        [
            ("RAEVA_HOME", Some(raeva_home.as_os_str())),
            (
                rv_config::MAVEN_USER_HOME_TEST_ENV,
                Some(maven_home.as_os_str()),
            ),
            ("HOME", Some(maven_home.as_os_str())),
            ("RAEVA_TIMEOUT", None),
            ("RAEVA_RETRIES", None),
            ("RAEVA_LOW_SPEED_LIMIT", None),
            ("RAEVA_LOW_SPEED_TIME", None),
            ("JAVA_HOME", None),
            ("JAVA_VERSION", None),
        ],
        || {
            let config = Config::load(&project).expect("load config");
            let config_hash =
                super::resolution_config_hash(&config, &Default::default()).expect("config hash");
            let models = PLATFORMS
                .iter()
                .map(|name| {
                    let platform: Platform = name.parse().expect("platform");
                    let model =
                        super::discover_reactor_model(&config, &platform).expect("model hash");
                    let mut modules: Vec<String> = model
                        .workspace
                        .modules()
                        .iter()
                        .map(|module| {
                            let gav = module.gav();
                            format!(
                                "{}={}:{}:{}",
                                module.pom_path, gav.group_id, gav.artifact_id, gav.version
                            )
                        })
                        .collect();
                    modules.sort();
                    Model {
                        platform: name.to_string(),
                        hash: model.model_hash,
                        pom_paths: model.pom_hashes.into_keys().collect(),
                        active_profiles: model.active_profiles,
                        modules,
                    }
                })
                .collect();
            Hashes {
                config_hash,
                models,
                repositories: config
                    .repositories()
                    .iter()
                    .map(|repo| format!("{}={}", repo.id.as_deref().unwrap_or(""), repo.url))
                    .collect(),
                mirrors: config
                    .mirrors()
                    .iter()
                    .map(|mirror| format!("{}={}", mirror.id.as_deref().unwrap_or(""), mirror.url))
                    .collect(),
                timeout_and_retries: (config.network.timeout, config.network.retries),
            }
        },
    )
}

/// Deleting or adding a case under `lock-input-hashes/` must fail here, not
/// only in a named hash test someone remembered to write. A stray file next
/// to `project/`, or a `project/` without `pom.xml`, must fail too.
#[test]
fn every_lock_input_hashes_case_has_a_test() {
    let names = lock_input_hash_cases();
    let cases: Vec<&str> = names.iter().map(String::as_str).collect();
    let root = fixtures::path("lock-input-hashes");
    fixtures::assert_children(&root, &cases, &[]);
    for name in &names {
        let dir = root.join(name);
        let mut dirs = vec!["project"];
        if dir.join("home").is_dir() {
            dirs.push("home");
        }
        dirs.sort();
        fixtures::assert_children(&dir, &dirs, &[]);
        assert!(
            dir.join("project").join("pom.xml").is_file(),
            "{name}: project/pom.xml is missing"
        );
        if dir.join("home").is_dir() {
            let home = dir.join("home");
            let mut home_dirs = Vec::new();
            if home.join("maven-home").is_dir() {
                home_dirs.push("maven-home");
            }
            if home.join("raeva-home").is_dir() {
                home_dirs.push("raeva-home");
            }
            fixtures::assert_children(&home, &home_dirs, &[]);
        }
    }
}

/// Every platform hashes these fixtures' models alike.
#[track_caller]
fn assert_hashes(actual: &Hashes, config_hash: &str, model_hash: &str) {
    assert_eq!(actual.config_hash, config_hash, "config_hash");
    assert_eq!(actual.models.len(), PLATFORMS.len());
    for model in &actual.models {
        assert_eq!(model.hash, model_hash, "model_hash for {}", model.platform);
    }
}

#[test]
fn single_module_hashes_are_stable() {
    let actual = hashes("single-module");
    assert_eq!(
        actual.repositories,
        ["central=https://repo1.maven.org/maven2/"]
    );
    assert_eq!(actual.timeout_and_retries, (30, 3));
    assert_hashes(
        &actual,
        "c0ec4de46cce1cc336386a86ba9b89d893e4aab61fd7cf166d3875ccd0ea97e1",
        "f7045bbaf768ff3464df654909507163702a6672ee234dd42d60084e76c4fa8f",
    );
}

#[test]
fn reactor_with_local_parent_and_bom_import_hashes_are_stable() {
    let actual = hashes("reactor");
    let linux = &actual.models[0];
    assert_eq!(
        linux.pom_paths,
        [
            "build-parent/pom.xml",
            "core/pom.xml",
            "pom.xml",
            "web/pom.xml"
        ]
    );
    assert_eq!(
        linux.modules,
        [
            "core/pom.xml=com.example:core:3.1.0",
            "pom.xml=com.example:app-root:3.1.0",
            "web/pom.xml=com.example:web:3.1.0",
        ]
    );
    assert_eq!(
        actual.repositories,
        [
            "corp=https://repo.example.com/maven2/",
            "central=https://repo1.maven.org/maven2/"
        ]
    );
    assert_hashes(
        &actual,
        "016d908c638b40d43e47e0eeca11d1b8eedaf90e2a4f3520ad26bd9ea068c902",
        "763a2e3ecde9d8bf585f7537cb0b97347f1e83daa5c48d0bb0cad77aadc521b3",
    );
}

#[test]
fn settings_with_mirror_and_local_repository_hashes_are_stable() {
    let actual = hashes("settings");
    assert_eq!(
        actual.repositories,
        [
            "corp-releases=https://repo.example.com/releases/",
            "corp-snapshots=https://repo.example.com/snapshots/",
            "central=https://repo1.maven.org/maven2/",
        ]
    );
    assert_eq!(
        actual.mirrors,
        ["corp-mirror=https://mirror.example.com/maven2"]
    );
    assert_eq!(actual.timeout_and_retries, (45, 5));
    assert_eq!(actual.models[0].active_profiles, ["corp"]);
    assert_hashes(
        &actual,
        "d06ee1d20a1acaf36c98986e069cf75f6af9ef6de59ac4ab441fe994210c8c7a",
        "6c88b4aa5a827c7142045984348187f212562a29ff04a78c3c8186ac1b453faf",
    );
}
