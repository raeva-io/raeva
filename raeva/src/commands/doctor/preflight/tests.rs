use std::fs;
use std::path::Path;

use super::{Preflight, check, plugins_row, runs_frozen_sync};
use crate::commands::doctor::Outcome;
use crate::commands::util::read_lockfile_at;
use crate::output::WarningCode;

const POM: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
                   <artifactId>app</artifactId><version>1</version></project>";

fn write(root: &Path, path: &str, text: &str) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, text).expect("write");
}

/// The project checks of `root`, with a Raeva home and `HOME` inside it.
fn preflight(root: &Path) -> Preflight {
    check(&load(root), true)
}

/// The configuration of `root`, with a Raeva home and `HOME` inside it.
fn load(root: &Path) -> rv_config::Config {
    let home = root.join(".home");
    fs::create_dir_all(&home).expect("home");
    temp_env::with_vars(
        [
            ("HOME", Some(home.as_path())),
            ("USERPROFILE", Some(home.as_path())),
            (rv_config::MAVEN_USER_HOME_TEST_ENV, Some(home.as_path())),
            ("RAEVA_HOME", Some(home.as_path())),
        ],
        || rv_config::Config::load(root).expect("config"),
    )
}

/// Each row as `check status code`, the code empty when there is none.
fn rows(found: &Preflight) -> Vec<String> {
    (found.rows.iter())
        .map(|row| {
            let code = row.code.map(WarningCode::as_str).unwrap_or_default();
            format!("{} {} {code}", row.check, row.outcome.status())
                .trim_end()
                .to_string()
        })
        .collect()
}

fn row<'a>(found: &'a Preflight, check: &str) -> &'a super::Row {
    (found.rows.iter())
        .find(|row| row.check == check)
        .unwrap_or_else(|| panic!("no {check} row in {:?}", rows(found)))
}

/// Outside a Maven project there is nothing to check.
#[test]
fn no_project_has_no_project_checks() {
    let root = tempfile::tempdir().expect("tempdir");
    assert!(preflight(root.path()).rows.is_empty());
}

/// A plain project in git: the Maven mode, the plugin statement, and the
/// CI check and `.gitattributes` line it lacks.
#[test]
fn a_plain_project_gets_the_mode_and_the_plugin_statement() {
    let root = tempfile::tempdir().expect("tempdir");
    fs::create_dir(root.path().join(".git")).expect(".git");
    write(root.path(), "pom.xml", POM);
    let found = preflight(root.path());
    assert_eq!(
        rows(&found),
        [
            "Maven mode info",
            "plugins info PLUGINS_NOT_LOCKED",
            "CI check warn CI_CHECK_MISSING",
            ".gitattributes info LOCK_NOT_MARKED_GENERATED"
        ]
    );
    assert_eq!(
        row(&found, "Maven mode").details,
        "Maven 3.9, neither [lock] maven nor a Maven wrapper names one"
    );
    assert!(
        row(&found, "plugins")
            .details
            .contains("pins no Maven plugins, and build extensions only for a module that"),
        "{}",
        row(&found, "plugins").details
    );
}

/// The wrapper's version selects the mode, and `[lock] maven` overrides it;
/// raeva.lock records either line, so neither warns.
#[test]
fn the_maven_mode_names_the_wrapper_and_the_configuration() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "pom.xml", POM);
    let url = "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven";
    write(
        root.path(),
        ".mvn/wrapper/maven-wrapper.properties",
        &format!("distributionUrl={url}/3.9.9/apache-maven-3.9.9-bin.zip\n"),
    );
    let found = preflight(root.path());
    let mode = row(&found, "Maven mode");
    assert_eq!(mode.outcome, Outcome::Info);
    assert!(
        mode.details.starts_with("Maven 3.9, from ")
            && mode
                .details
                .ends_with("maven-wrapper.properties (Maven \"3.9.9\")"),
        "{}",
        mode.details
    );

    write(root.path(), "raeva.toml", "[lock]\nmaven = \"3.10\"\n");
    let found = preflight(root.path());
    let mode = row(&found, "Maven mode");
    assert_eq!(mode.outcome, Outcome::Info);
    assert_eq!(mode.code, None);
    assert!(
        mode.details.starts_with("Maven 3.10, from "),
        "{}",
        mode.details
    );
}

/// In the Maven 3.10 mode, a row names the URL that replaces Maven
/// Central's and where it was set; the 3.9 mode has none.
#[test]
fn a_replaced_central_is_named() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "pom.xml", POM);
    let found = |mode: &str| {
        write(
            root.path(),
            "raeva.toml",
            &format!("[lock]\nmaven = \"{mode}\"\n"),
        );
        temp_env::with_var(
            "MAVEN_REPO_CENTRAL",
            Some("https://central.example/m2/"),
            || preflight(root.path()),
        )
    };
    let central = found("3.10");
    assert_eq!(
        row(&central, "Maven Central").details,
        "replaced by https://central.example/m2/ from environment variable MAVEN_REPO_CENTRAL, \
         as Maven 3.10 replaces it"
    );
    assert!(
        !rows(&found("3.9"))
            .iter()
            .any(|row| row.starts_with("Maven Central"))
    );
}

/// Core extensions, `<build><extensions>` and plugins with
/// `<extensions>true</extensions>`, in modules and local parents, with
/// os-maven-plugin and Polyglot's extensions left to their own handling.
#[test]
fn declared_build_extensions_are_listed_by_file() {
    let root = tempfile::tempdir().expect("tempdir");
    write(
        root.path(),
        ".mvn/extensions.xml",
        "<extensions><extension><groupId>io.takari.polyglot</groupId>\
         <artifactId>polyglot-yaml</artifactId><version>0.7</version></extension>\
         <extension><groupId>com.example</groupId><artifactId>core-ext</artifactId>\
         <version>1</version></extension><extension><groupId>kr.motd.maven</groupId>\
         <artifactId>os-maven-plugin</artifactId><version>1.7.1</version></extension>\
         </extensions>",
    );
    write(
        root.path(),
        "parent/pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
         <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
         <build><extensions><extension><groupId>org.example</groupId>\
         <artifactId>wagon-x</artifactId><version>1</version></extension></extensions>\
         </build></project>",
    );
    write(
        root.path(),
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>\
         <artifactId>parent</artifactId><version>1</version>\
         <relativePath>parent/pom.xml</relativePath></parent><artifactId>app</artifactId>\
         <packaging>pom</packaging><modules><module>lib</module></modules>\
         <build><extensions><extension><groupId>kr.motd.maven</groupId>\
         <artifactId>os-maven-plugin</artifactId><version>1.7.1</version></extension>\
         </extensions></build></project>",
    );
    write(
        root.path(),
        "lib/pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
         <artifactId>lib</artifactId><version>1</version><build><plugins><plugin>\
         <groupId>org.apache.felix</groupId><artifactId>maven-bundle-plugin</artifactId>\
         <extensions>true</extensions></plugin></plugins></build></project>",
    );
    let found = preflight(root.path());
    let extensions = row(&found, "build extensions");
    assert_eq!(extensions.outcome, Outcome::Warn);
    assert_eq!(extensions.code, Some(WarningCode::BuildExtensions));
    assert!(
        extensions.details.starts_with(
            ".mvn/extensions.xml: com.example:core-ext; \
             lib/pom.xml: org.apache.felix:maven-bundle-plugin; \
             parent/pom.xml: org.example:wagon-x; raeva does not run build extensions"
        ),
        "{}",
        extensions.details
    );
    let polyglot = row(&found, "polyglot Maven");
    assert_eq!(polyglot.code, Some(WarningCode::PolyglotMaven));
    assert!(
        polyglot
            .details
            .starts_with("io.takari.polyglot:polyglot-yaml in .mvn/extensions.xml"),
        "{}",
        polyglot.details
    );
}

/// A polyglot POM without `pom.xml` is a project raeva cannot read.
#[test]
fn a_polyglot_pom_without_pom_xml_warns() {
    for name in ["pom.yaml", "pom.gy", "Mavenfile", "Jarfile"] {
        let root = tempfile::tempdir().expect("tempdir");
        write(root.path(), name, "modelVersion: 4.0.0\n");
        let found = preflight(root.path());
        assert_eq!(
            rows(&found)[..3],
            [
                "Maven mode info",
                "polyglot Maven warn POLYGLOT_MAVEN",
                "plugins info PLUGINS_NOT_LOCKED"
            ],
            "{name}"
        );
        let details = &row(&found, "polyglot Maven").details;
        assert!(
            details.starts_with(&format!("{name} and no pom.xml")),
            "{details}"
        );
    }
}

/// The selection and settings options sync ignores in `.mvn/maven.config`
/// carry the code of its warning.
#[test]
fn ignored_maven_config_options_warn() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "pom.xml", POM);
    write(root.path(), ".mvn/maven.config", "-pl\napp\n-am\n");
    let found = preflight(root.path());
    let config = row(&found, ".mvn/maven.config");
    assert_eq!(config.code, Some(WarningCode::SettingIgnored));
    assert!(
        config
            .details
            .starts_with("raeva ignores -pl, -am, since raeva locks the whole reactor"),
        "{}",
        config.details
    );
}

/// A lock of this machine's platform only warns, whatever JDKs it lists;
/// one that also records another platform does not, and one that cannot be
/// read warns with what to do.
#[test]
fn a_lock_of_the_host_platform_only_warns() {
    let host = rv_lock::Platform::current().expect("platform").to_string();
    let lock = fs::read_to_string(rv_test_support::fixtures::path(
        "lock-golden/snapshot/raeva.lock",
    ))
    .expect("lock fixture")
    .replace("linux-x86_64", &host);
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "pom.xml", POM);
    write(root.path(), "raeva.lock", &lock);
    let found = preflight(root.path());
    let platforms = row(&found, "lock platforms");
    assert_eq!(platforms.code, Some(WarningCode::HostPlatformOnly));
    assert!(
        platforms
            .details
            .contains(&format!("raeva sync --platforms {host},")),
        "{}",
        platforms.details
    );

    let other = if host == "linux-x86_64" {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    };
    let inputs =
        &lock[lock.find("[[inputs]]").expect("inputs")..lock.find("[metadata]").expect("metadata")];
    let both = lock
        .replace(
            &format!("targets = [\"{host}\"]"),
            &format!("targets = [\"{host}\", \"{other}\"]"),
        )
        .replace(
            "[metadata]",
            &format!("{}[metadata]", inputs.replace(&host, other)),
        );
    write(root.path(), "raeva.lock", &both);
    let found = preflight(root.path());
    let platforms = row(&found, "lock platforms");
    assert_eq!(platforms.outcome, Outcome::Info, "{}", platforms.details);
    assert_eq!(platforms.code, None);

    // A merge that left conflict markers, as an unreadable lock, names the
    // next step a sync names, and the plugin row does not read the lock.
    let conflicted = both.replacen(
        "[[platforms]]\n",
        "<<<<<<< ours\n[[platforms]]\n=======\n[[platforms]]\n>>>>>>> theirs\n",
        1,
    );
    for (text, next) in [
        (
            "not a lock\n",
            "Run 'raeva sync --update' to regenerate it without its pins",
        ),
        (
            &*conflicted,
            "Run 'raeva sync' without --frozen to regenerate it",
        ),
        (
            "schema_version = 99\n",
            "Upgrade raeva to a release that reads schema 99",
        ),
    ] {
        write(root.path(), "raeva.lock", text);
        let found = preflight(root.path());
        let platforms = row(&found, "lock platforms");
        assert_eq!(platforms.code, Some(WarningCode::LockUnreadable));
        assert!(
            (platforms.details)
                .starts_with("raeva.lock cannot be read, so raeva sync --frozen fails"),
            "{}",
            platforms.details
        );
        assert!(platforms.details.contains(next), "{}", platforms.details);
        let plugins = row(&found, "plugins");
        assert_eq!(
            plugins.details,
            "not checked, since raeva.lock cannot be read"
        );
    }
}

/// A `[plugins] mvn` path that names no file fails, as every sync refuses
/// it.
#[test]
fn a_launcher_that_is_no_file_fails() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "pom.xml", POM);
    write(
        root.path(),
        "raeva.toml",
        "[plugins]\nlock = true\ntrace = [\"test\"]\nmvn = \"./mvnw\"\n",
    );
    let found = preflight(root.path());
    let plugins = row(&found, "plugins");
    assert_eq!(plugins.outcome, Outcome::Config, "{}", plugins.details);
    assert!(
        plugins.details.contains("plugins.mvn"),
        "{}",
        plugins.details
    );
}

/// A directory or a link loop at raeva.lock is unreadable, as `--frozen`
/// finds it, not absent; a link to nothing is absent, as sync takes it.
#[test]
fn a_lock_that_is_no_file_is_unreadable() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "pom.xml", POM);
    let lock = root.path().join("raeva.lock");
    fs::create_dir(&lock).expect("mkdir");
    let found = preflight(root.path());
    assert_eq!(
        row(&found, "lock platforms").code,
        Some(WarningCode::LockUnreadable)
    );
    #[cfg(unix)]
    {
        fs::remove_dir(&lock).expect("rmdir");
        std::os::unix::fs::symlink("raeva.lock", &lock).expect("symlink");
        let found = preflight(root.path());
        assert_eq!(
            row(&found, "lock platforms").code,
            Some(WarningCode::LockUnreadable)
        );
        fs::remove_file(&lock).expect("rm");
        std::os::unix::fs::symlink("missing.lock", &lock).expect("symlink");
        let found = preflight(root.path());
        assert!(
            !rows(&found)
                .iter()
                .any(|row| row.starts_with("lock platforms"))
        );
    }
}

/// A lock with no section for this machine's platform warns that
/// `--frozen` fails here, also when it records no platform at all, and
/// asks for the command that adds it.
#[test]
fn a_lock_without_the_host_platform_warns() {
    let host = rv_lock::Platform::current().expect("platform");
    let host = host.without_jdk().to_string();
    let other = if host == "linux-x86_64" {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    };
    let lock = fs::read_to_string(rv_test_support::fixtures::path(
        "lock-golden/snapshot/raeva.lock",
    ))
    .expect("lock fixture")
    .replace("linux-x86_64", other);
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "pom.xml", POM);
    for (text, records) in [
        (lock.as_str(), format!("only {other}")),
        ("schema_version = 9\n", "no platform".to_string()),
    ] {
        write(root.path(), "raeva.lock", text);
        let found = preflight(root.path());
        let platforms = row(&found, "lock platforms");
        assert_eq!(platforms.code, Some(WarningCode::HostPlatformNotLocked));
        assert_eq!(
            platforms.details,
            format!(
                "raeva.lock records {records}, not this machine's {host}, so raeva sync \
                 --frozen and raeva export-m2 fail here; add it with raeva sync --platforms \
                 {host}"
            )
        );
    }
}

/// In a git repository, a missing CI check and `.gitattributes` line come
/// with the text to add, from the git root even for a project below it.
#[test]
fn a_git_repository_gets_the_ci_and_gitattributes_snippets() {
    let root = tempfile::tempdir().expect("tempdir");
    fs::create_dir(root.path().join(".git")).expect(".git");
    write(root.path(), "app/pom.xml", POM);
    let project = root.path().join("app");
    let found = preflight(&project);
    assert_eq!(
        rows(&found)[2..],
        [
            "CI check warn CI_CHECK_MISSING",
            ".gitattributes info LOCK_NOT_MARKED_GENERATED"
        ]
    );
    let snippets: Vec<(&str, &str)> = (found.snippets.iter())
        .map(|snippet| (snippet.file, snippet.text.as_str()))
        .collect();
    assert_eq!(
        snippets[1],
        (".gitattributes", "raeva.lock linguist-generated=true\n")
    );
    assert_eq!(snippets[0].0, "CI");
    assert!(
        snippets[0].1.ends_with("\nraeva -C app sync --frozen\n"),
        "{}",
        snippets[0].1
    );
    write(root.path(), "my app/pom.xml", POM);
    let spaced = preflight(&root.path().join("my app"));
    assert!(
        spaced.snippets[0]
            .text
            .ends_with("\nraeva -C 'my app' sync --frozen\n"),
        "{}",
        spaced.snippets[0].text
    );

    write(
        root.path(),
        ".github/workflows/lock.yml",
        "jobs:\n  lock:\n    steps:\n      - run: raeva --json sync --frozen\n",
    );
    write(
        root.path(),
        ".gitattributes",
        "# lock\n/raeva.lock -merge\n/app/raeva.lock -merge\n",
    );
    let found = preflight(&project);
    assert_eq!(
        rows(&found)[2..],
        [
            "CI check info",
            ".gitattributes warn LOCK_MERGE_DISABLED",
            ".gitattributes info LOCK_NOT_MARKED_GENERATED"
        ]
    );
    assert_eq!(
        row(&found, "CI check").details,
        "raeva sync --frozen runs in .github/workflows/lock.yml"
    );

    write(
        &project,
        ".gitattributes",
        "raeva.lock linguist-generated\n",
    );
    write(root.path(), ".gitattributes", "");
    let found = preflight(&project);
    assert_eq!(rows(&found)[2..], ["CI check info"]);
    assert!(found.snippets.is_empty());
    // An anchored pattern names the files of its own directory only.
    write(&project, ".gitattributes", "");
    for (attributes, generated) in [
        ("/app/*.lock linguist-generated\n", true),
        ("/app/* linguist-generated\n", true),
        ("/**/*.lock linguist-generated\n", true),
        ("/*.lock linguist-generated\n", false),
        ("/app/sub/*.lock linguist-generated\n", false),
    ] {
        write(root.path(), ".gitattributes", attributes);
        let found = preflight(&project);
        let unmarked =
            (found.rows.iter()).any(|row| row.code == Some(WarningCode::LockNotMarkedGenerated));
        assert_eq!(unmarked, !generated, "{attributes}");
    }
    write(&project, ".gitattributes", "/*.lock linguist-generated\n");
    write(root.path(), ".gitattributes", "");
    assert_eq!(rows(&preflight(&project))[2..], ["CI check info"]);

    // A later line, and a file nearer the lock, override an earlier one.
    write(
        root.path(),
        ".gitattributes",
        "* binary linguist-generated\n",
    );
    write(
        &project,
        ".gitattributes",
        "*.lock merge\nraeva.lock -linguist-generated\n",
    );
    let found = preflight(&project);
    assert_eq!(
        rows(&found)[2..],
        [
            "CI check info",
            ".gitattributes info LOCK_NOT_MARKED_GENERATED"
        ]
    );
    write(
        &project,
        ".gitattributes",
        "raeva.lock merge=union -merge\n",
    );
    let found = preflight(&project);
    assert_eq!(
        row(&found, ".gitattributes").details,
        "'raeva.lock merge=union -merge' in app/.gitattributes keeps git from merging \
         raeva.lock; remove it, since raeva sync merges a conflicted lock \
         (https://github.com/raeva-io/raeva/blob/main/docs/ci.md)"
    );
}

/// A plugin a local parent manages with `<extensions>true</extensions>` is
/// an extension of the module that declares it, as for maven-bundle-plugin.
#[test]
fn a_parent_managed_extension_is_listed() {
    let root = tempfile::tempdir().expect("tempdir");
    let plugin = |extensions: &str| {
        format!(
            "<plugin><groupId>org.apache.felix</groupId>\
             <artifactId>maven-bundle-plugin</artifactId>{extensions}</plugin>"
        )
    };
    write(
        root.path(),
        "parent/pom.xml",
        &format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
             <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
             <build><pluginManagement><plugins>{}</plugins></pluginManagement></build>\
             </project>",
            plugin("<version>5.1.9</version><extensions>true</extensions>")
        ),
    );
    write(
        root.path(),
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>\
         <artifactId>parent</artifactId><version>1</version>\
         <relativePath>parent/pom.xml</relativePath></parent><artifactId>app</artifactId>\
         <packaging>pom</packaging><modules><module>lib</module><module>off</module>\
         </modules></project>",
    );
    for (module, extensions) in [("lib", ""), ("off", "<extensions>false</extensions>")] {
        write(
            root.path(),
            &format!("{module}/pom.xml"),
            &format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>\
                 <artifactId>app</artifactId><version>1</version></parent>\
                 <artifactId>{module}</artifactId><build><plugins>{}</plugins></build>\
                 </project>",
                plugin(extensions)
            ),
        );
    }
    let found = preflight(root.path());
    let extensions = row(&found, "build extensions");
    assert_eq!(extensions.code, Some(WarningCode::BuildExtensions));
    assert!(
        extensions.details.starts_with(
            "lib/pom.xml: org.apache.felix:maven-bundle-plugin; raeva does not run build \
             extensions"
        ),
        "{}",
        extensions.details
    );
}

/// A reactor that cannot be read fails the check under `--offline`, where
/// no probe reports it; an `.mvn/extensions.xml` or plugin section that
/// cannot be read leaves the check undone, which warns.
#[test]
fn an_unreadable_project_is_not_checked() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "pom.xml", "<project><modelVersion>");
    let found = preflight(root.path());
    let extensions = row(&found, "build extensions");
    assert_eq!(extensions.outcome, Outcome::Config);
    assert!(
        extensions
            .details
            .starts_with("not checked: pom.xml could not be read"),
        "{}",
        extensions.details
    );

    write(root.path(), "pom.xml", POM);
    write(
        root.path(),
        ".mvn/extensions.xml",
        "<extensions><extension>",
    );
    let found = preflight(root.path());
    let extensions = row(&found, "build extensions");
    assert_eq!(extensions.outcome, Outcome::Warn);
    assert_eq!(extensions.code, Some(WarningCode::BuildExtensions));
    assert!(
        extensions.details.starts_with(
            "not checked, so the project may load build extensions: .mvn/extensions.xml"
        ),
        "{}",
        extensions.details
    );
}

/// A CI file doctor cannot read leaves the CI check undone, not missing.
#[test]
fn an_unreadable_ci_file_is_not_checked() {
    let root = tempfile::tempdir().expect("tempdir");
    fs::create_dir(root.path().join(".git")).expect(".git");
    write(root.path(), "pom.xml", POM);
    fs::create_dir_all(root.path().join(".github/workflows")).expect("mkdir");
    let ci = root.path().join(".github/workflows/ci.yml");
    fs::write(&ci, b"\xff\n- run: raeva sync --frozen\n").expect("write");
    let found = preflight(root.path());
    let row = row(&found, "CI check");
    assert_eq!((row.outcome, row.code), (Outcome::Inconclusive, None));
    assert!(
        row.details.starts_with("not checked, since project input")
            && row.details.ends_with("ci.yml is not valid UTF-8"),
        "{}",
        row.details
    );
    assert!(found.snippets.iter().all(|snippet| snippet.file != "CI"));
}

#[test]
fn a_frozen_sync_is_found_in_its_spellings() {
    for (text, found) in [
        ("run: raeva sync --frozen", true),
        ("- run: ./bin/raeva --offline sync -f", true),
        ("raeva.exe -C app sync --frozen", true),
        ("- uses: raeva-io/setup-raeva@abc # v1", false),
        (
            "- uses: raeva-io/setup-raeva@v1\n  with:\n    check: false",
            false,
        ),
        (
            "- uses: raeva-io/setup-raeva@v1\n  with:\n    check: true",
            true,
        ),
        (
            "- with:\n    check: \"true\"\n  uses: raeva-io/setup-raeva@v1",
            true,
        ),
        (
            "- uses: raeva-io/setup-raeva@v1\n- with: {check: true}",
            false,
        ),
        (
            "- uses: raeva-io/setup-raeva@v1\n  with: {version: 0.6.0, check: true}",
            true,
        ),
        ("- run: echo setup-raeva\n  with:\n    check: true", false),
        (
            "- run: true  # uses: raeva-io/setup-raeva@v1\n  with:\n    check: true",
            false,
        ),
        ("- run: |\n    raeva sync \\\n      --frozen", true),
        ("- run: >\n    raeva sync\n    --frozen", true),
        ("- run: >-\n    raeva sync\n  env:\n    A: --frozen", false),
        ("- run: |\n    raeva sync\n    mvn --frozen", false),
        ("run: raeva sync # --frozen", false),
        ("run: raeva sync", false),
        ("run: raeva lock verify --frozen", false),
        ("echo raevasync --frozen", false),
        ("sh 'raeva sync --frozen'", true),
        ("- \"raeva sync -f\"", true),
        ("raeva sync --frozen; mvn verify", true),
        ("raeva sync && mvn -f app/pom.xml verify", false),
        ("# run: raeva sync --frozen", false),
        ("  # uses: raeva-io/setup-raeva@v1", false),
        ("// sh 'raeva sync --frozen'", false),
        ("/opt/bin/raeva sync --frozen", true),
    ] {
        assert_eq!(runs_frozen_sync(text), found, "{text}");
    }
}

/// The row says whether raeva.lock locks the plugins, and warns when the
/// tables do not match `[plugins] lock` in raeva.toml.
#[test]
fn the_plugin_row_follows_the_lock_and_raeva_toml() {
    use rv_lock::{LockArtifact, LockPlatform, Lockfile, Platform, PluginFiles, PluginSet};
    use rv_maven_types::{ArtifactCoord, Digest, Gav, Sha256};

    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("raeva.lock");
    let status = |wanted| {
        let lock = path.is_file().then(|| read_lockfile_at(&path));
        let row = plugins_row(wanted, lock.as_ref());
        let code = row.code.map(WarningCode::as_str).unwrap_or_default();
        format!("{} {code}", row.outcome.status())
            .trim_end()
            .to_string()
    };
    assert_eq!(status(false), "info PLUGINS_NOT_LOCKED");
    assert_eq!(status(true), "info");
    let mut lock = Lockfile::new();
    // A lock of no platform pins no plugin.
    fs::write(&path, "schema_version = 9\n").expect("write");
    assert_eq!(status(true), "warn PLUGIN_TABLES_STALE");
    lock.platforms.push(LockPlatform::single_module(
        Platform::new("linux", "x86_64").expect("platform"),
        Gav::new("g", "app", "1"),
        "jar",
        Vec::new(),
    ));
    lock.write_atomic(&path).expect("write");
    assert_eq!(status(false), "info PLUGINS_NOT_LOCKED");
    assert_eq!(status(true), "warn PLUGIN_TABLES_STALE");

    let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
    let mut set = PluginSet::new(
        &format!("sha256:{}", "a".repeat(64)),
        rv_lock::PluginRole::Plugin,
    );
    set.coordinates = vec!["g:p:1".to_string()];
    let coordinate = ArtifactCoord::new("g", "p", "1", "jar", None);
    set.artifacts = vec![coordinate.clone()];
    files.tables.sets.push(set);
    let mut artifact = LockArtifact::new(coordinate, "https://repo.example/".to_string());
    artifact.checksums = vec![Digest::Sha256(Sha256::from_bytes(b"jar"))];
    files.artifacts.push(artifact);
    lock.platforms[0]
        .set_plugins(files, &rv_lock::RepoIds::new())
        .expect("tables");
    lock.write_atomic(&path).expect("write");
    assert_eq!(status(true), "ok");
    assert_eq!(status(false), "warn PLUGIN_TABLES_STALE");

    lock.platforms.push(LockPlatform::single_module(
        Platform::new("macos", "aarch64").expect("platform"),
        Gav::new("g", "app", "1"),
        "jar",
        Vec::new(),
    ));
    lock.write_atomic(&path).expect("write");
    assert_eq!(status(true), "warn PLUGIN_TABLES_STALE");
    assert_eq!(status(false), "warn PLUGIN_TABLES_STALE");
    let lock = path.is_file().then(|| read_lockfile_at(&path));
    assert!(
        plugins_row(true, lock.as_ref())
            .details
            .contains("lacks plugin tables for macos-aarch64, so"),
    );
}

/// The row is ok only when `raeva sync --frozen` takes the plugin tables
/// as held: with `[plugins] trace`, this machine's OS and architecture hold
/// a trace of the build raeva.toml names, and a trace anywhere is of that
/// build; it also warns about another OS and architecture with no trace.
#[test]
fn the_plugin_row_checks_the_trace() {
    use rv_lock::{LockPlatform, Lockfile, Platform, PluginFiles, PluginRole, PluginSet};
    use rv_maven_types::{Gav, Sha256};

    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "pom.xml", POM);
    let toml = |trace: &str| {
        let text = format!("[plugins]\nlock = true\n{trace}");
        write(root.path(), "raeva.toml", &text);
    };
    toml("trace = [\"verify\"]\n");
    let host = Platform::current().expect("host");
    let host = Platform::new(host.os(), host.arch()).expect("host");
    let other = match host.os() {
        "linux" => Platform::new("windows", "x86_64"),
        _ => Platform::new("linux", "x86_64"),
    }
    .expect("platform");
    // Each platform's tables, with a trace of the build raeva.toml names,
    // of another build, or none.
    let lock_of = |platforms: &[(&Platform, Option<bool>)]| {
        let config = load(root.path());
        let mut lock = Lockfile::new();
        for (platform, trace) in platforms {
            let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
            let mut set = PluginSet::new(&format!("sha256:{}", "a".repeat(64)), PluginRole::Plugin);
            set.coordinates = vec!["g:p:1".to_string()];
            files.tables.sets.push(set);
            let key = match trace {
                Some(true) => crate::commands::sync::trace_key(&config, &files.tables),
                Some(false) => Some(format!("sha256:{}", "b".repeat(64))),
                None => None,
            };
            if let Some(key) = key {
                files
                    .tables
                    .sets
                    .push(PluginSet::new(&key, PluginRole::Trace));
            }
            let mut entry = LockPlatform::single_module(
                (*platform).clone(),
                Gav::new("g", "app", "1"),
                "jar",
                Vec::new(),
            );
            entry
                .set_plugins(files, &rv_lock::RepoIds::new())
                .expect("tables");
            lock.platforms.push(entry);
        }
        let goals: &[String] = config
            .plugins
            .as_ref()
            .map_or(&[], |plugins| &plugins.goals);
        for at in 0..lock.platforms.len() {
            let inputs = crate::commands::sync::inputs_digest(
                &config,
                goals,
                &lock,
                &lock.platforms[at],
                &Default::default(),
            )
            .expect("inputs");
            lock.platforms[at].plugins.as_mut().expect("tables").inputs = inputs;
        }
        lock
    };
    let lock_path = root.path().join("raeva.lock");
    let plugins = |lock: &Lockfile| {
        lock.write_atomic(&lock_path).expect("write");
        let found = preflight(root.path());
        let row = row(&found, "plugins");
        let code = row.code.map(WarningCode::as_str).unwrap_or_default();
        let status = format!("{} {code}", row.outcome.status());
        (status.trim_end().to_string(), row.details.clone())
    };
    let stale = |lock: &Lockfile, expected: &str| {
        let (status, details) = plugins(lock);
        assert_eq!(status, "warn PLUGIN_TABLES_STALE", "{details}");
        assert!(details.contains(expected), "{expected}: {details}");
    };

    let traced = lock_of(&[(&host, Some(true))]);
    assert_eq!(plugins(&traced).0, "ok", "{}", plugins(&traced).1);
    let (host_name, other_name) = (host.os_arch(), other.os_arch());
    stale(
        &lock_of(&[(&host, Some(true)), (&other, None)]),
        &format!("raeva.lock has no trace for {other_name} of the build"),
    );
    stale(
        &lock_of(&[(&host, Some(true)), (&other, Some(false))]),
        &format!("holds a trace for platform '{other_name}' of another build"),
    );
    stale(
        &lock_of(&[(&host, None)]),
        &format!("no matching trace in raeva.lock for {host_name}"),
    );
    toml("trace = [\"package\"]\n");
    stale(
        &traced,
        &format!("holds a trace for platform '{host_name}' of another build"),
    );
    toml("");
    stale(
        &traced,
        "which raeva.toml does not ask for with [plugins] trace",
    );
}
