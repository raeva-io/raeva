//! Golden lock bytes: a real offline `raeva sync` of each project under
//! `test-fixtures/lock-golden/` must write exactly the committed `raeva.lock`.
//!
//! Each case copies `<case>/project/` into a temporary directory, copies the
//! shared fixture repository `test-fixtures/lock-golden/repository/` to each
//! place the case's POMs declare it (`file://${project.basedir}/repository/`),
//! syncs offline for explicit platforms, and compares the lock with
//! `<case>/raeva.lock`. A lock change is a deliberate act: regenerate with
//! `RAEVA_TEST_BLESS=1 cargo test -p raeva --test cli -- lock_golden` and commit
//! the reviewed diff with the change that caused it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use rv_test_support::{fixtures, golden};
use tempfile::TempDir;

use crate::common::{assert_success, raeva_command, run_raeva};

struct Case {
    name: &'static str,
    /// Project-relative directories that receive a copy of the fixture
    /// repository: every module basedir whose effective POM declares it.
    repositories: &'static [&'static str],
    sync_args: &'static [&'static str],
}

fn case_dir(name: &str) -> PathBuf {
    fixtures::path("lock-golden").join(name)
}

/// Every lock-golden directory that holds a `project/` raeva syncs. Names stay
/// sorted so a new directory fails [`every_lock_golden_project_has_a_sync_case`]
/// until it is listed here and given a test.
const PROJECT_CASES: &[Case] = &[
    Case {
        name: "host-conditions",
        repositories: &["."],
        sync_args: &["--offline", "--platforms", "linux-x86_64"],
    },
    Case {
        name: "profiles",
        repositories: &["."],
        // raeva.lock names the -D and -P options, never their values.
        sync_args: &[
            "-Dgolden.note=not-recorded",
            "-P!never",
            "--offline",
            "--platforms",
            "linux-x86_64,windows-x86_64,macos-aarch64",
        ],
    },
    Case {
        name: "reactor",
        repositories: &[".", "api", "app"],
        sync_args: &["--offline", "--platforms", "linux-x86_64,windows-x86_64"],
    },
    Case {
        name: "single-module",
        repositories: &["."],
        sync_args: &["--offline", "--platforms", "linux-x86_64"],
    },
    Case {
        name: "snapshot",
        repositories: &["."],
        sync_args: &["--offline", "--platforms", "linux-x86_64"],
    },
];

/// `raeva` on a host whose Linux release os-maven-plugin would read, as on
/// the Linux machine that wrote the golden locks, so that their records of
/// what the plugin reads hold on every host.
fn run_golden(project: &Path, home: &Path, args: &[&str]) -> Output {
    raeva_command(project, home)
        .env(
            rv_maven_model::OS_RELEASE_TEST_ENV,
            "ID=ubuntu\nID_LIKE=debian\n",
        )
        .args(args)
        .output()
        .expect("run raeva")
}

fn project_case(name: &str) -> &'static Case {
    PROJECT_CASES
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("no lock-golden project case {name}"))
}

fn stage(case: &Case, base: &Path) -> PathBuf {
    let project = base.join(case.name);
    fixtures::copy_tree_lf(&case_dir(case.name).join("project"), &project);
    let repository = fixtures::path("lock-golden/repository");
    for dir in case.repositories {
        fixtures::copy_tree_lf(&repository, &project.join(dir).join("repository"));
    }
    project
}

fn check(name: &str) {
    let case = project_case(name);
    let base = TempDir::new().expect("temp base");
    let home = TempDir::new().expect("temp home");
    let project = stage(case, base.path());

    let mut args = vec!["sync"];
    args.extend_from_slice(case.sync_args);
    assert_success(
        &run_golden(&project, home.path(), &args),
        &format!("{} golden sync", case.name),
    );
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("read written raeva.lock");
    golden::assert_golden(&case_dir(case.name).join("raeva.lock"), &lock);

    // The lock just written must satisfy a frozen check of the same options
    // unchanged. The platforms stay explicit: the host may not be among them.
    let mut frozen = args.clone();
    frozen.insert(1, "--frozen");
    assert_success(
        &run_golden(&project, home.path(), &frozen),
        &format!("{} frozen sync of the golden lock", case.name),
    );
    assert_eq!(
        fs::read_to_string(project.join("raeva.lock")).expect("re-read raeva.lock"),
        lock,
        "a frozen sync rewrote the lock"
    );
}

/// Deleting or adding a `project/` under `lock-golden/` must fail here, not
/// only in a named sync test someone remembered to write. A case in
/// [`PROJECT_CASES`] without a named check test must fail too.
#[test]
fn every_lock_golden_project_has_a_sync_case() {
    let found = fixtures::sorted_child_names(&fixtures::path("lock-golden"), |path| {
        path.join("project").is_dir()
    });
    let names: Vec<&str> = PROJECT_CASES.iter().map(|case| case.name).collect();
    assert_eq!(found, names);
    let mut checked = fixtures::quoted_after(include_str!("lock_golden.rs"), concat!("check", "("));
    checked.sort();
    checked.dedup();
    assert_eq!(checked, names, "PROJECT_CASES and named check calls differ");
}

/// Directories without a `project/` are the shared repository and the two
/// locks `rv-lock/tests/lock_bytes.rs` owns. A new directory, or a stray
/// file next to a case's `raeva.lock`, must fail here.
#[test]
fn every_lock_golden_directory_is_accounted_for() {
    let root = fixtures::path("lock-golden");
    let project_names: Vec<&str> = PROJECT_CASES.iter().map(|case| case.name).collect();
    let mut expected: Vec<&str> = project_names.clone();
    expected.extend(["api-built", "repository", "round-trip"]);
    expected.sort();
    fixtures::assert_children(&root, &expected, &[".gitattributes"]);
    for name in project_names {
        fixtures::assert_children(&root.join(name), &["project"], &["raeva.lock"]);
        assert!(
            root.join(name).join("project").join("pom.xml").is_file(),
            "{name}: project/pom.xml is missing"
        );
    }
    for name in ["api-built", "round-trip"] {
        fixtures::assert_children(&root.join(name), &[], &["raeva.lock"]);
    }
    fixtures::assert_children(&root.join("repository"), &["org"], &[]);
    fixtures::assert_children(&root.join("repository/org"), &["golden"], &[]);
}

/// Deleting or adding a `*.lock` under `lock-diff/` must fail here, not only
/// in `frozen_diffs_name_every_kind_of_change`. Each file is an edited copy
/// that test compares, and `frozen.txt` names it.
#[test]
fn every_lock_diff_lock_is_in_the_frozen_golden() {
    let root = fixtures::path("lock-diff");
    let frozen = fs::read_to_string(root.join("frozen.txt")).expect("read frozen.txt");
    let found = fixtures::sorted_child_names(&root, |path| {
        path.extension().is_some_and(|ext| ext == "lock")
    });
    let mut mentioned: Vec<String> = frozen
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("lock-golden/")?;
            let (_, right) = rest.split_once(" -> ")?;
            let name = right.strip_prefix("lock-diff/")?;
            name.ends_with(".lock").then(|| name.to_string())
        })
        .collect();
    mentioned.sort();
    assert_eq!(
        found, mentioned,
        "lock-diff files and frozen.txt pairs differ"
    );
    let mut files = found;
    files.extend([".gitattributes".into(), "frozen.txt".into()]);
    files.sort();
    let files: Vec<&str> = files.iter().map(String::as_str).collect();
    fixtures::assert_children(&root, &[], &files);
}

/// One jar module: release, classifier, `test-jar`, every scope, an
/// optional and a test-scoped transitive that stay out, SHA-1-only
/// sidecars, and a `system` file inside the project.
#[test]
fn single_module() {
    check("single-module");
}

/// A reactor whose root inherits from a local non-module parent that
/// declares the repository, a property-managed version and an imported BOM;
/// one module depends on another and on a wildcard-excluded artifact. Each
/// module basedir gets its own in-project repository origin.
#[test]
fn reactor() {
    check("reactor");
}

/// Profiles activated by OS family and name, by property, by `-P` from
/// `.mvn/maven.config`, a suppressed `activeByDefault` profile, `-D`
/// overriding a POM property, and a property-driven classifier, across three
/// platforms.
#[test]
fn profiles() {
    check("profiles");
}

/// A timestamped SNAPSHOT from a snapshot-enabled repository with an older
/// build present, and a version conflict.
#[test]
fn snapshot() {
    check("snapshot");
}

/// `<jdk>` conditions in two dependencies, written in no order and some
/// twice, reach `[resolution] ambient_inputs` sorted as text, each once,
/// with its outcome on the default JDK 17 the test environment leaves. The
/// condition of a profile that sets only a build property is left out.
#[test]
fn host_conditions() {
    check("host-conditions");
}

/// raeva.lock records the repositories the POMs and configuration declare,
/// never the mirror that served them. A sync through a mirror of the
/// fixture repository, with that repository emptied so only the mirror can
/// serve, writes the golden bytes. A mirror of every repository (`*`)
/// answers for Central first, so its lock may name Central for a file the
/// fixture repository holds; either lock still passes `--frozen` with and
/// without the mirror, so a lock written behind a corporate mirror holds in
/// CI without it and the other way round.
#[test]
fn a_mirror_leaves_the_lock_unchanged() {
    for (name, repository_id) in [
        ("single-module", "fixture"),
        ("snapshot", "fixture-snapshots"),
    ] {
        let case = project_case(name);
        for mirror_of in [repository_id, "*"] {
            check_through_mirror(case, mirror_of, mirror_of == repository_id);
        }
    }
}

fn check_through_mirror(case: &Case, mirror_of: &str, only_the_fixture: bool) {
    let what = format!("{} through a mirror of {mirror_of}", case.name);
    let base = TempDir::new().expect("temp base");
    let project = stage(case, base.path());
    let declared = project.join("repository");
    let empty_declared = || {
        fs::remove_dir_all(&declared).expect("empty the declared repository");
        fs::create_dir_all(&declared).expect("recreate it empty");
    };
    let fill_declared = || {
        fs::remove_dir_all(&declared).expect("remove the declared repository");
        fixtures::copy_tree_lf(&fixtures::path("lock-golden/repository"), &declared);
    };
    let mirror = base.path().join("mirror");
    fixtures::copy_tree_lf(&fixtures::path("lock-golden/repository"), &mirror);
    let mirror_url = url::Url::from_directory_path(&mirror).expect("mirror url");
    let mirrored_home = TempDir::new().expect("mirrored home");
    fs::write(
        mirrored_home.path().join("config.toml"),
        format!(
            "[[mirrors]]\nid = \"corp\"\nurl = \"{mirror_url}\"\nmirror_of = [\"{mirror_of}\"]\n"
        ),
    )
    .expect("config.toml");
    let mut args = vec!["sync"];
    args.extend_from_slice(case.sync_args);
    // Every repository is a directory, so an online check stays local, and
    // it fills the empty home that an offline check would find lacking.
    let mut frozen = args.clone();
    frozen.retain(|arg| *arg != "--offline");
    frozen.insert(1, "--frozen");
    let golden = fs::read_to_string(case_dir(case.name).join("raeva.lock")).expect("golden");

    // The golden lock, written without a mirror, holds through it.
    fs::write(project.join("raeva.lock"), &golden).expect("golden lock");
    empty_declared();
    assert_success(
        &run_golden(&project, mirrored_home.path(), &frozen),
        &format!("{what}: frozen sync of the golden lock"),
    );

    // A lock written through the mirror holds without it.
    fs::remove_file(project.join("raeva.lock")).expect("remove lock");
    assert_success(
        &run_golden(&project, mirrored_home.path(), &args),
        &format!("{what}: sync"),
    );
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("read written raeva.lock");
    assert!(
        !lock.contains(mirror_url.as_str()) && !lock.contains("corp"),
        "{what}: the lock names the mirror"
    );
    if only_the_fixture {
        assert_eq!(lock, golden, "{what}: the mirror changed the lock");
    }
    fill_declared();
    let plain_home = TempDir::new().expect("plain home");
    assert_success(
        &run_golden(&project, plain_home.path(), &frozen),
        &format!("{what}: frozen sync without the mirror"),
    );
}

/// Behind a `*` mirror the lock names the first configured repository,
/// `corp`, for a remote parent and a jar that only `central` serves once the
/// mirror is gone. A cold home restores them from `central`, as Maven finds
/// a file in any repository of the build.
#[test]
fn a_lock_written_behind_a_mirror_of_everything_restores_cold_without_it() {
    let base = TempDir::new().expect("temp base");
    let pom = |g: &str, a: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>{g}</groupId>\
             <artifactId>{a}</artifactId><version>1</version>{body}</project>"
        )
    };
    let url = |name: &str| {
        let dir = base.path().join(name);
        fs::create_dir_all(&dir).expect("repository dir");
        url::Url::from_directory_path(&dir).expect("file url")
    };
    let (corp, central, mirror) = (url("corp"), url("central"), url("mirror"));
    for repository in ["central", "mirror"] {
        let root = base.path().join(repository).join("p");
        let files = [
            (
                "par/1/par-1.pom",
                pom("p", "par", "<packaging>pom</packaging>"),
            ),
            ("lib/1/lib-1.pom", pom("p", "lib", "")),
            ("lib/1/lib-1.jar", "lib bytes".to_owned()),
        ];
        for (path, bytes) in files {
            let path = root.join(path);
            fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
            fs::write(path, bytes).expect("write repository file");
        }
    }
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("project dir");
    fs::write(
        project.join("pom.xml"),
        pom(
            "t",
            "app",
            "<parent><groupId>p</groupId><artifactId>par</artifactId><version>1</version>\
             <relativePath/></parent><dependencies><dependency><groupId>p</groupId>\
             <artifactId>lib</artifactId><version>1</version></dependency></dependencies>",
        ),
    )
    .expect("pom.xml");
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"corp\"\nurl = \"{corp}\"\n\n\
             [[repositories]]\nid = \"central\"\nurl = \"{central}\"\n"
        ),
    )
    .expect("raeva.toml");
    let mirrored = TempDir::new().expect("mirrored home");
    fs::write(
        mirrored.path().join("config.toml"),
        format!("[[mirrors]]\nid = \"all\"\nurl = \"{mirror}\"\nmirror_of = [\"*\"]\n"),
    )
    .expect("config.toml");
    let platforms = ["--platforms", "linux-x86_64"];
    assert_success(
        &run_raeva(
            &project,
            mirrored.path(),
            &[&["sync"][..], &platforms].concat(),
        ),
        "sync through the mirror",
    );
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("raeva.lock");
    assert!(
        lock.contains(corp.as_str()),
        "the mirror no longer answers for corp first:\n{lock}"
    );

    let cold = TempDir::new().expect("cold home");
    assert_success(
        &run_raeva(
            &project,
            cold.path(),
            &[&["sync", "--frozen"][..], &platforms].concat(),
        ),
        "cold frozen sync without the mirror",
    );
    assert_eq!(
        fs::read_to_string(project.join("raeva.lock")).expect("re-read raeva.lock"),
        lock,
        "a frozen sync rewrote the lock"
    );
}
