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

/// A build extension that maps a dependency's type resolves from the
/// settings.xml plugin repositories, so the configuration hash covers those
/// of an active profile and of a conditional one, and the condition that
/// decides a profile with plugin repositories alone.
#[test]
fn config_hash_covers_settings_plugin_repositories() {
    use std::fs;

    let dir = tempfile::tempdir().expect("tempdir");
    let (home, project) = (dir.path().join("home"), dir.path().join("project"));
    fs::create_dir_all(home.join(".m2")).expect("mkdir .m2");
    fs::create_dir_all(&project).expect("mkdir project");
    fs::write(
        project.join("pom.xml"),
        "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>",
    )
    .expect("write pom");
    let profile = |id: &str, activation: &str, url: &str| {
        format!(
            "<profile><id>{id}</id>{activation}<pluginRepositories><pluginRepository>\
             <id>{id}-plugins</id><url>{url}</url></pluginRepository></pluginRepositories>\
             </profile>"
        )
    };
    let load = |named: &str, conditional: &str| {
        let settings = format!(
            "<settings><profiles>{}{}</profiles><activeProfiles><activeProfile>named\
             </activeProfile></activeProfiles></settings>",
            profile("named", "", named),
            profile(
                "conditional",
                "<activation><file><exists>marker</exists></file></activation>",
                conditional
            ),
        );
        fs::write(home.join(".m2/settings.xml"), settings).expect("write settings");
        let home = home.to_string_lossy().into_owned();
        temp_env::with_vars(
            [
                ("RAEVA_HOME", Some(home.as_str())),
                ("HOME", Some(home.as_str())),
                (rv_config::MAVEN_USER_HOME_TEST_ENV, Some(home.as_str())),
            ],
            || rv_config::Config::load(&project).expect("load config"),
        )
    };
    let hash = |config: &rv_config::Config| {
        super::resolution_config_hash(config, &Default::default()).expect("config hash")
    };
    let (a, b) = ("https://a.example/", "https://b.example/");
    let config = load(a, a);
    assert_ne!(hash(&config), hash(&load(b, a)), "an active profile's");
    assert_ne!(hash(&config), hash(&load(a, b)), "a conditional profile's");
    let platform = Platform::current().expect("platform");
    let scoped = config.for_platforms([(platform.os(), platform.arch(), None)]);
    let (ambient, _) = super::consulted_ambient(&scoped, false).expect("ambient");
    assert!(
        ambient
            .iter()
            .any(|input| matches!(input, rv_lock::AmbientInput::Condition { .. })),
        "{ambient:?}"
    );
}

/// With a filter basedir that names `${os.arch}`, the configuration hash
/// covers the rule files of every platform, sorted, and not the host's
/// first, so a lock of several platforms hashes alike on each of them.
#[test]
fn config_hash_covers_the_filter_rules_of_every_platform_alike() {
    use std::fs;

    let dir = tempfile::tempdir().expect("tempdir");
    let (home, project) = (dir.path().join("home"), dir.path().join("project"));
    fs::create_dir_all(home.join(".m2")).expect("mkdir .m2");
    for (arch, group) in [("amd64", "a"), ("aarch64", "b")] {
        let rules = project.join(".mvn/rrf").join(arch);
        fs::create_dir_all(&rules).expect("mkdir rules");
        fs::write(rules.join("groupId-r1.txt"), format!("{group}\n")).expect("write rules");
    }
    fs::write(
        project.join(".mvn/maven.config"),
        "-Daether.remoteRepositoryFilter.groupId=true\n\
         -Daether.remoteRepositoryFilter.groupId.basedir=${session.rootDirectory}/.mvn/rrf/${os.arch}\n",
    )
    .expect("write maven.config");
    let home = home.to_string_lossy().into_owned();
    let config = temp_env::with_vars(
        [
            ("RAEVA_HOME", Some(home.as_str())),
            ("HOME", Some(home.as_str())),
            (rv_config::MAVEN_USER_HOME_TEST_ENV, Some(home.as_str())),
        ],
        || rv_config::Config::load(&project).expect("load config"),
    );
    let listed = |name: &str| rv_lock::AmbientInput::user_property(name).is_ok();
    // What any host of these platforms sees: each one's rules.
    let every: std::collections::BTreeSet<String> = ["linux", "macos", "windows"]
        .into_iter()
        .flat_map(|os| ["x86_64", "aarch64"].map(|arch| (os, arch)))
        .filter_map(|(os, arch)| {
            let scoped = config.for_platforms([(os, arch, None)]);
            scoped.repository_filters().rule_input(listed)
        })
        .collect();
    assert_eq!(every.len(), 2, "{every:?}");
    let expected = (every.iter())
        .map(|input| format!("platform\n{input}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(super::filter_rule_input(&config), Some(expected));
}
