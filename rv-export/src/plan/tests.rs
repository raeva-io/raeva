use super::{
    ExportPlan, authorize_classifier_candidates, classifier_candidates, declared_repositories,
    external_artifacts, lock_poms, lock_support_poms, marker_ids, query_ids,
};
use crate::error::ExportError;
use crate::warning::ExportWarning;
use rv_lock::{LockArtifact, LockPlatform, Lockfile, Platform};
use rv_maven_types::{ArtifactCoord, BlobId, Digest, Gav, Sha1};
use rv_repo::Repository;
use std::collections::HashMap;
use std::path::Path;

fn package(
    group: &str,
    artifact: &str,
    version: &str,
    packaging: &str,
    classifier: Option<&str>,
) -> LockArtifact {
    LockArtifact::new(
        ArtifactCoord::new(group, artifact, version, packaging, classifier),
        "https://repo.example/maven2/",
    )
}

fn test_platform(platform: Platform, packages: Vec<LockArtifact>) -> LockPlatform {
    LockPlatform::single_module(
        platform,
        Gav::new("com.example", "root", "1"),
        "pom",
        packages,
    )
}

fn config_with_repos(root: &Path, urls: &[&str]) -> rv_config::Config {
    let repositories = urls
        .iter()
        .map(|url| {
            let mut repo_config = rv_config::RepoConfig::new(Some("repo"), url);
            repo_config.releases = Some(true);
            repo_config.snapshots = Some(false);
            repo_config
        })
        .collect();
    rv_config::Config::for_testing_with_repos(
        root.to_path_buf(),
        rv_config::ResolvedPaths::from_raeva_home(root.join("raeva-home")),
        repositories,
    )
}

fn mirror(id: Option<&str>, url: &str, mirror_of: &str) -> rv_config::MirrorConfig {
    let mut mirror = rv_config::MirrorConfig::new(id, url);
    mirror.mirror_of = vec![mirror_of.to_string()];
    mirror
}

/// The ids `mvn -o` may read a version list under: the lock's, as recorded
/// and as the mirrors configured now relabel them, the configured
/// repositories' and mirrors', and the super POM's `central`.
#[test]
fn query_ids_cover_recorded_configured_and_mirror_ids() {
    let root = tempfile::tempdir().unwrap();
    let lock = Lockfile::from_toml(
        "schema_version = 9\n\n[metadata]\nrepo_ids = \"https://nexus.corp/repo/\\tcorp\"\n",
    )
    .expect("well-formed lines decode");
    let config =
        config_with_repos(root.path(), &["https://configured.example/"]).with_mirrors(vec![
            mirror(Some("corp-mirror"), "https://mirror.corp/", "corp"),
            mirror(None, "https://anonymous.example/", "*"),
        ]);
    let ids = query_ids(
        &config,
        &lock,
        &marker_ids(&config, &declared_repositories(&config, &lock)),
    );
    assert_eq!(
        ids.into_iter().collect::<Vec<_>>(),
        ["central", "corp", "corp-mirror", "repo"]
    );
}

/// A stored file stands in for a row when the row's repository served it,
/// directly or through a mirror of an id the project declares, or for a
/// SHA-256 pin, when another declared repository served it. An id only the
/// lock records picks no mirror: another project may declare it.
#[test]
fn stored_files_stand_in_for_the_repositories_the_project_trusts() {
    const R: &str = "https://repo.example/maven2/";
    const S: &str = "https://s.example/";
    const M: &str = "https://m.example/";
    let root = tempfile::tempdir().unwrap();
    let mut lock = Lockfile::from_toml(&format!(
        "schema_version = 9\n\n[metadata]\nrepo_ids = \"{R}\\tgood\\n{R}\\tevil\"\n"
    ))
    .unwrap();
    let mut row = package("org.example", "lib", "1.0", "jar", None);
    row.checksums = vec![Digest::Sha256(BlobId::from_bytes(b"x"))];
    let mut sha1_row = row.clone();
    sha1_row.checksums = vec![Digest::Sha1(Sha1::from_bytes(b"x"))];
    lock.platforms.push(test_platform(
        Platform::current().unwrap(),
        vec![row.clone()],
    ));
    let project = HashMap::from([(
        Platform::current().unwrap(),
        vec![Repository::new(Some("good".into()), R, true, true)],
    )]);
    let served = |repo: &str, endpoint: &str| [(repo.to_string(), endpoint.to_string())];

    let config = config_with_repos(root.path(), &[S]).with_mirrors(vec![mirror(None, M, "evil")]);
    let plan = ExportPlan::from_lock(&config, &lock, &project).unwrap();
    assert!(plan.admits(&row, &served(R, R)));
    assert!(
        !plan.admits(&row, &served(R, M)),
        "a mirror of an id only the lock records"
    );
    assert!(
        plan.admits(&row, &served(S, S)),
        "a declared fallback for a SHA-256 pin"
    );
    assert!(
        !plan.admits(&sha1_row, &served(S, S)),
        "no fallback for a SHA-1 pin"
    );
    assert!(!plan.admits(
        &row,
        &served("https://evil.example/", "https://evil.example/")
    ));

    let config = config_with_repos(root.path(), &[S]).with_mirrors(vec![mirror(None, M, "good")]);
    let plan = ExportPlan::from_lock(&config, &lock, &project).unwrap();
    assert!(
        plan.admits(&row, &served(R, M)),
        "a mirror of a declared id"
    );
    let config = config_with_repos(root.path(), &[S]).with_mirrors(vec![mirror(None, M, "*")]);
    let plan = ExportPlan::from_lock(&config, &lock, &HashMap::new()).unwrap();
    assert!(!plan.admits(&row, &served(R, M)), "R is not declared");
    let plan = ExportPlan::from_lock(&config, &lock, &project).unwrap();
    assert!(
        plan.admits(&row, &served(R, M)),
        "a mirror of every repository"
    );
}

/// Export-m2 must recover POM-declared repo ids from the lockfile
/// metadata that `raeva sync` writes, so markers aren't mislabelled `central`.
/// A mirror configured now adds its own id, as Maven records it, whatever
/// served the files when the lock was written, and the declared id stays
/// for a `mvn -o` that does not use the mirror.
#[test]
fn marker_ids_follow_the_mirror_configured_now() {
    let root = tempfile::tempdir().unwrap();
    let lock = Lockfile::from_toml(
        "schema_version = 9\n\n[metadata]\nrepo_ids = \"https://repo1.maven.org/maven2/\\tcentral\\nhttps://nexus.corp/repo/\\tcorp\"\n",
    )
    .expect("well-formed lines decode");
    let config = config_with_repos(root.path(), &["https://configured.example/"]);
    let ids = marker_ids(&config, &declared_repositories(&config, &lock));
    assert_eq!(
        ids.get("https://nexus.corp/repo/").map(|ids| ids.join(",")),
        Some("corp".to_string())
    );
    assert_eq!(
        ids.get("https://repo1.maven.org/maven2/")
            .map(|ids| ids.join(",")),
        Some("central".to_string())
    );
    assert_eq!(
        ids.get("https://configured.example/")
            .map(|ids| ids.join(",")),
        Some("repo".to_string())
    );

    let mirrored =
        config_with_repos(root.path(), &["https://configured.example/"]).with_mirrors(vec![
            mirror(Some("corp-mirror"), "https://mirror.corp/", "central"),
            mirror(None, "https://anonymous.example/", "corp"),
        ]);
    let ids = marker_ids(&mirrored, &declared_repositories(&mirrored, &lock));
    assert_eq!(
        ids.get("https://repo1.maven.org/maven2/")
            .map(|ids| ids.join(",")),
        Some("central,corp-mirror".to_string())
    );
    assert_eq!(
        ids.get("https://nexus.corp/repo/").map(|ids| ids.join(",")),
        Some("corp".to_string()),
        "a mirror without an id keeps the declared id"
    );
    assert_eq!(
        ids.get("https://configured.example/")
            .map(|ids| ids.join(",")),
        Some("repo".to_string())
    );
}

/// A configured repository without an id is labelled with the id of the
/// mirror that serves it, as Maven labels what the mirror supplied, and
/// with `central` (no entry) without one; it does not hide the id another
/// declaration of its origin gives, which stays next to the mirror's.
#[test]
fn an_id_less_configured_repository_takes_its_mirror_id() {
    let root = tempfile::tempdir().unwrap();
    let lock = Lockfile::from_toml(
        "schema_version = 9\n\n[metadata]\nrepo_ids = \"https://nexus.corp/repo/\\tcorp\"\n",
    )
    .expect("well-formed lines decode");
    let config = |mirrors| {
        rv_config::Config::for_testing_with_repos(
            root.path().to_path_buf(),
            rv_config::ResolvedPaths::from_raeva_home(root.path().join("raeva-home")),
            ["https://plain.example/", "https://nexus.corp/repo/"]
                .map(|url| rv_config::RepoConfig::new(None, url))
                .to_vec(),
        )
        .with_mirrors(mirrors)
    };
    let ids =
        |config: &rv_config::Config| marker_ids(config, &declared_repositories(config, &lock));
    let plain = config(Vec::new());
    assert_eq!(ids(&plain).get("https://plain.example/"), None);
    assert_eq!(
        ids(&plain)
            .get("https://nexus.corp/repo/")
            .map(|ids| ids.join(",")),
        Some("corp".to_string())
    );
    let mirrored = config(vec![mirror(Some("nexus"), "https://mirror.corp/", "*")]);
    for (origin, labels) in [
        ("https://plain.example/", "nexus"),
        ("https://nexus.corp/repo/", "corp,nexus"),
    ] {
        assert_eq!(
            ids(&mirrored).get(origin).map(|ids| ids.join(",")),
            Some(labels.to_string()),
            "{origin}"
        );
    }
}

/// A configured repository and a repository only a POM declares may share a
/// URL under different ids; files from it are labelled with both.
#[test]
fn a_configured_id_joins_the_ids_recorded_for_its_url() {
    let root = tempfile::tempdir().unwrap();
    let lock = Lockfile::from_toml(
        "schema_version = 9\n\n[metadata]\nrepo_ids = \"https://configured.example/\\trepo\\nhttps://configured.example/\\tsnapshots\"\n",
    )
    .expect("well-formed lines decode");
    let config = config_with_repos(root.path(), &["https://configured.example/"]);
    let declared = declared_repositories(&config, &lock);
    let repos = &declared["https://configured.example/"];
    let ids: Vec<_> = repos.iter().filter_map(|repo| repo.id.as_deref()).collect();
    assert_eq!(ids, ["repo", "snapshots"]);
    assert!(
        !repos[0].snapshots_enabled,
        "the configured declaration wins"
    );
}

/// Rows that share a companion POM, across classifiers and platforms, must
/// pin it to one digest; a row without one has no POM to export.
#[test]
fn lock_poms_need_one_pin_per_pom() {
    let platforms = [
        Platform::new("linux", "x86_64").expect("platform"),
        Platform::new("darwin", "aarch64").expect("platform"),
    ];
    let lock = |digests: [Option<&str>; 2]| {
        let mut lock = Lockfile::new();
        for (platform, digest) in platforms.iter().zip(digests) {
            let mut entry = test_platform(
                platform.clone(),
                vec![package("com.example", "app", "1.0", "jar", None)],
            );
            entry.artifacts[0].pom_sha256 = digest.map(|d| d.repeat(64).parse().unwrap());
            lock.platforms.push(entry);
        }
        lock
    };

    let (agreeing, origins) = lock_poms(&lock([Some("b"), Some("b")])).expect("agreeing pins");
    assert_eq!(agreeing.len(), 1);
    assert_eq!(origins.len(), 1);
    let err = lock_poms(&lock([Some("b"), Some("c")])).expect_err("conflicting pins");
    let ExportError::ConflictingPinnedPom { coordinate, .. } = &err else {
        panic!("{err}");
    };
    assert_eq!(coordinate, "com.example:app:1.0");
    let (unpinned, _) = lock_poms(&lock([None, None])).expect("no POM in any repository");
    assert!(unpinned.is_empty());
}

#[test]
fn classifier_candidates_dedupes_and_skips_non_portable_entries() {
    let mut lock = Lockfile::new();
    lock.platforms.push(test_platform(
        Platform::new("linux", "x86_64").unwrap(),
        vec![
            package("com.example", "demo", "1.0.0", "jar", None),
            package("com.example", "demo", "1.0.0", "jar", None),
            package("com.example", "demo", "1.0.0", "pom", None),
            package("com.example", "demo", "1.0.0", "jar", Some("tests")),
        ],
    ));
    let candidates = classifier_candidates(&lock);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].gav, Gav::new("com.example", "demo", "1.0.0"));
}

/// A classifier origin is authorized by the declarations of the platform
/// whose row recorded it, before candidates for one coordinate collapse:
/// one platform's refused origin neither hides another platform's
/// declared one nor borrows its declarations.
#[test]
fn classifier_origins_are_authorized_per_platform_before_dedup() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = config_with_repos(tmp.path(), &[]);
    let linux = Platform::new("linux", "x86_64").unwrap();
    let macos = Platform::new("macos", "aarch64").unwrap();
    let row = |platform: &Platform, url: &str| {
        let mut package = package("com.example", "demo", "1.0.0", "jar", None);
        package.repo_url = url.to_string();
        test_platform(platform.clone(), vec![package])
    };
    let mut lock = Lockfile::new();
    lock.platforms
        .push(row(&linux, "https://attacker.example/"));
    lock.platforms
        .push(row(&macos, "https://corp.example/maven/"));
    let declared = HashMap::from([(
        macos.clone(),
        vec![rv_repo::Repository::new(
            Some("corp".to_string()),
            "https://corp.example/maven/",
            true,
            false,
        )],
    )]);

    let (authorized, warnings) =
        authorize_classifier_candidates(&config, classifier_candidates(&lock), &declared);
    assert_eq!(authorized.len(), 1);
    assert_eq!(authorized[0].repository.url, "https://corp.example/maven/");
    assert!(
        warnings.is_empty(),
        "a declared origin for the coordinate hides the refused one: {warnings:?}"
    );

    // The Linux row's origin is not authorized by the macOS declaration.
    lock.platforms[0] = row(&linux, "https://corp.example/maven/");
    lock.platforms.truncate(1);
    let (authorized, warnings) =
        authorize_classifier_candidates(&config, classifier_candidates(&lock), &declared);
    assert!(authorized.is_empty());
    assert_eq!(
        warnings,
        [ExportWarning::UntrustedClassifierOrigin {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            origin: "https://corp.example/maven/".to_string(),
        }]
    );
}

/// A support POM platforms read with the same bytes from other
/// repositories carries the ids of each, so every platform's offline build
/// finds it under the id it reads.
#[test]
fn a_support_pom_takes_the_ids_of_every_platform() {
    let mut lock = Lockfile::new();
    for (platform, url) in [
        (
            Platform::new("linux", "x86_64").unwrap(),
            "https://linux.example/m2/",
        ),
        (
            Platform::new("darwin", "aarch64").unwrap(),
            "https://mac.example/m2/",
        ),
    ] {
        let mut entry = test_platform(platform, Vec::new());
        entry.support_poms.insert(
            "g:bom:1".to_string(),
            rv_lock::SupportPom::new(url, "b".repeat(64).parse().unwrap()),
        );
        lock.platforms.push(entry);
    }
    let repo_ids: HashMap<String, Vec<String>> = [
        ("https://linux.example/m2/", "linux-repo"),
        ("https://mac.example/m2/", "mac-repo"),
    ]
    .into_iter()
    .map(|(url, id)| (rv_lock::recorded_key(url), vec![id.to_string()]))
    .collect();
    let poms = lock_support_poms(&lock, &repo_ids);
    assert_eq!(poms["g:bom:1"].repo_ids, ["linux-repo", "mac-repo"]);
}

/// A companion POM two platforms read from other repositories than their
/// jar keeps the repositories of both, and only those.
#[test]
fn a_companion_pom_keeps_the_origins_of_every_platform() {
    let mut lock = Lockfile::new();
    for (platform, pom) in [
        (
            Platform::new("linux", "x86_64").unwrap(),
            "https://a.example/",
        ),
        (
            Platform::new("darwin", "aarch64").unwrap(),
            "https://b.example/",
        ),
    ] {
        let mut row = package("g", "a", "1", "jar", None);
        row.pom_sha256 = Some("c".repeat(64).parse().unwrap());
        row.pom_repo_urls = vec![pom.to_string()];
        lock.platforms.push(test_platform(platform, vec![row]));
    }
    let rows = external_artifacts(&lock);
    let poms: Vec<&str> = rows[0].pom_origins().collect();
    assert_eq!(poms, ["https://a.example/", "https://b.example/"]);
}

/// A plugin without a version that two JDKs took at other versions from
/// the same repositories is written at the highest, which Maven tries
/// first and the older JDK passes over. Other repositories, or two versions
/// for one JDK, are refused.
#[test]
fn a_plugin_release_of_each_jdk_takes_the_highest() {
    use rv_lock::{MetadataVersion, MetadataVersionKind, PluginFiles, PluginRole, PluginSet};
    let read = |jdk: &str, os: &str, version: &str, repo: &str, plugin: &str| {
        let platform = Platform::new(os, "x86_64")
            .unwrap()
            .with_jdk(jdk.to_string());
        let mut entry = test_platform(platform, Vec::new());
        let mut files = PluginFiles::new(rv_maven_types::Sha256::from_bytes(b"inputs"));
        let mut set = PluginSet::new(&format!("sha256:{}", "a".repeat(64)), PluginRole::Plugin);
        set.coordinates = vec![format!("{plugin}:{version}")];
        set.repo_urls = vec![repo.to_string()];
        files.tables.sets.push(set);
        files.tables.metadata_versions.push(MetadataVersion {
            group: "g".to_string(),
            artifact: "p".to_string(),
            kind: MetadataVersionKind::Release,
            version: version.to_string(),
        });
        entry.set_plugins(files, &rv_lock::RepoIds::new()).unwrap();
        entry
    };
    let entry =
        |jdk: &str, os: &str, version: &str, repo: &str| read(jdk, os, version, repo, "g:p");
    let release = |platforms: Vec<LockPlatform>| {
        let mut lock = Lockfile::new();
        lock.platforms = platforms;
        super::markers(&lock).map(|markers| markers[&("g".into(), "p".into())].release.clone())
    };
    let central = "https://repo.example/";
    let both = vec![
        entry("11", "linux", "1.9", central),
        entry("17", "linux", "2.0", central),
        entry("11", "macos", "1.9", central),
        entry("17", "macos", "2.0", central),
    ];
    assert_eq!(release(both).unwrap().as_deref(), Some("2.0"));
    let elsewhere = vec![
        entry("17", "linux", "2.0", central),
        entry("11", "linux", "1.9", "https://other.example/"),
    ];
    assert!(matches!(
        release(elsewhere),
        Err(ExportError::ConflictingMarkers { .. })
    ));
    let one_jdk = vec![
        entry("11", "linux", "1.9", central),
        entry("17", "linux", "2.0", central),
        entry("17", "macos", "2.1", central),
    ];
    assert!(matches!(
        release(one_jdk),
        Err(ExportError::ConflictingMarkers { .. })
    ));
    let mixed = vec![
        entry("11", "linux", "1.9", central),
        entry("17", "linux", "2.0", central),
        entry("11", "macos", "1.9", "https://other.example/"),
    ];
    assert!(matches!(
        release(mixed),
        Err(ExportError::ConflictingMarkers { .. })
    ));
    // A release no plugin set resolves, as a dependency's, is one value.
    let dependency = vec![
        read("11", "linux", "1.9", central, "g:q"),
        read("17", "linux", "2.0", central, "g:q"),
    ];
    assert!(matches!(
        release(dependency),
        Err(ExportError::ConflictingMarkers { .. })
    ));
}

/// A recorded repository is labelled with the ids of the mirror its own
/// declaration picks: an `external:*` one for a `symlink+file:` URL as
/// written, which the lock records as the directory it names, even when a
/// later declaration of that directory spells it as a plain `file:` URL,
/// as plugin tables give one back, and none for a plain project directory.
#[test]
fn a_recorded_directory_takes_the_mirror_its_spelled_declaration_picks() {
    let temp = tempfile::tempdir().unwrap();
    let base = dunce::canonicalize(temp.path()).unwrap();
    let project = base.join("project");
    std::fs::create_dir_all(project.join("repo")).unwrap();
    let plain = url::Url::from_directory_path(base.join("plugins"))
        .unwrap()
        .to_string();
    let mut repo = rv_config::RepoConfig::new(Some("p"), &plain);
    repo.declared_url = Some(format!("symlink+{plain}"));
    let config = rv_config::Config::for_testing_with_repos(
        project.clone(),
        rv_config::ResolvedPaths::from_raeva_home(base.join("raeva-home")),
        vec![repo],
    )
    .with_mirrors(vec![mirror(
        Some("ext"),
        "https://mirror.example/",
        "external:*,!central",
    )]);
    let lock = Lockfile::from_toml(
        "schema_version = 9\n\n[metadata]\nrepo_ids = \"../plugins/\\tp\\n./repo/\\tlocal-repo\"\n",
    )
    .unwrap();
    let in_project = url::Url::from_directory_path(project.join("repo"))
        .unwrap()
        .to_string();
    let declared = HashMap::from([(
        Platform::current().unwrap(),
        vec![
            Repository::new(Some("p".into()), plain.as_str(), true, false),
            Repository::new(Some("local-repo".into()), in_project.as_str(), true, false),
        ],
    )]);
    let plan = ExportPlan::from_lock(&config, &lock, &declared).unwrap();
    assert_eq!(plan.repo_ids["../plugins/"], ["ext", "p"]);
    assert_eq!(plan.repo_ids["./repo/"], ["local-repo"]);
}
