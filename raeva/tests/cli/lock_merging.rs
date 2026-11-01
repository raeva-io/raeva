use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use crate::common::{assert_status, assert_success};
use crate::offline_project::Project;

fn git_output(root: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("GIT_AUTHOR_NAME")
        .env_remove("GIT_AUTHOR_EMAIL")
        .env_remove("GIT_COMMITTER_NAME")
        .env_remove("GIT_COMMITTER_EMAIL")
        .args([
            "-c",
            "user.name=torutofu",
            "-c",
            "user.email=285838596+torutofu@users.noreply.github.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("run git")
}

fn git(root: &Path, args: &[&str]) {
    let output = git_output(root, args);
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// [`Project::synced_with`] without the lock of the first sync, whose host
/// section a sync of other platforms keeps or drops as stale, so that a test
/// of named platforms locks the same on every host.
fn unlocked(files: &[(&str, &str)]) -> Project {
    let project = Project::synced_with(files);
    fs::remove_file(project.root().join("raeva.lock")).unwrap();
    project
}

fn reactor_bom_project() -> Project {
    Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId><artifactId>root</artifactId><version>1</version><packaging>pom</packaging><modules><module>a</module><module>b</module></modules></project>",
        ),
        (
            "a/pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId><artifactId>a</artifactId><version>1</version><packaging>pom</packaging><dependencyManagement><dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></dependencyManagement></project>",
        ),
        (
            "b/pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId><artifactId>b</artifactId><version>1</version><repositories><repository><id>local</id><url>file://${project.basedir}/../repository/</url></repository></repositories><dependencyManagement><dependencies><dependency><groupId>org.test</groupId><artifactId>a</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement><dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>",
        ),
    ])
}

fn reactor_bom_through_remote_project(parent: bool) -> Project {
    let project = reactor_bom_project();
    let root = project.root();
    let path = root.join("repository/org/test/base/1/base-1.pom");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let remote = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId><artifactId>base</artifactId><version>1</version><packaging>pom</packaging><dependencyManagement><dependencies><dependency><groupId>org.test</groupId><artifactId>a</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></project>";
    fs::write(&path, remote).unwrap();
    fs::write(
        path.with_extension("pom.sha256"),
        crate::common::sha256_hex(remote.as_bytes()),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"central\"\nurl = \"{}\"\n",
            url::Url::from_directory_path(root.join("repository")).unwrap()
        ),
    )
    .unwrap();
    let b = root.join("b/pom.xml");
    let mut text = fs::read_to_string(&b).unwrap();
    if parent {
        let start = text.find("<dependencyManagement>").unwrap();
        let end = text.find("</dependencyManagement>").unwrap() + "</dependencyManagement>".len();
        text.replace_range(start..end, "");
        text = text.replace("<modelVersion>4.0.0</modelVersion>", "<modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId><artifactId>base</artifactId><version>1</version><relativePath/></parent>");
    } else {
        text = text.replace(
            "<artifactId>a</artifactId>",
            "<artifactId>base</artifactId>",
        );
    }
    fs::write(b, text).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "lock remote intermediary importing a reactor BOM",
    );
    project
}

#[test]
fn reactor_bom_and_consumer_edits_cannot_merge_into_a_stale_graph() {
    assert_bom_merge_requires_relock(reactor_bom_project());
}

#[test]
fn remote_parent_importing_a_reactor_bom_cannot_merge_into_a_stale_graph() {
    assert_bom_merge_requires_relock(reactor_bom_through_remote_project(true));
}

#[test]
fn remote_bom_importing_a_reactor_bom_cannot_merge_into_a_stale_graph() {
    assert_bom_merge_requires_relock(reactor_bom_through_remote_project(false));
}

fn assert_bom_merge_requires_relock(project: Project) {
    let root = project.root();
    let path = root.join("raeva.lock");
    let base = rv_lock::Lockfile::read(&path).unwrap();
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    let bom = root.join("a/pom.xml");
    fs::write(
        &bom,
        fs::read_to_string(&bom)
            .unwrap()
            .replace("<version>1.0</version>", "<version>2.0</version>"),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync changed BOM management",
    );
    let left = rv_lock::Lockfile::read(&path).unwrap();
    assert_eq!(base.platforms[0].artifacts, left.platforms[0].artifacts);
    assert_eq!(base.platforms[0].modules, left.platforms[0].modules);
    assert_ne!(
        base.platforms[0].model_inputs.as_ref().unwrap().pom_hashes["b/pom.xml"],
        left.platforms[0].model_inputs.as_ref().unwrap().pom_hashes["b/pom.xml"]
    );
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: change BOM management"]);
    git(&root, &["switch", "-c", "right", "main"]);
    let child = root.join("b/pom.xml");
    fs::write(
        &child,
        fs::read_to_string(&child)
            .unwrap()
            .replace("<version>1.0</version>", ""),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync consumer using management",
    );
    let right = rv_lock::Lockfile::read(&path).unwrap();
    assert_eq!(base.platforms[0].artifacts, right.platforms[0].artifacts);
    assert_eq!(base.platforms[0].modules, right.platforms[0].modules);
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: use BOM management"]);
    let merged = git_output(&root, &["merge", "--no-edit", "left"]);
    assert_eq!(
        merged.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&merged.stdout)
    );
    let conflicts = git_output(&root, &["diff", "--name-only", "--diff-filter=U"]);
    assert_eq!(
        String::from_utf8_lossy(&conflicts.stdout).trim(),
        "raeva.lock"
    );
    let lock = fs::read(&path).unwrap();
    assert!(
        !project
            .raeva(&["sync", "--frozen", "--offline"])
            .status
            .success()
    );
    assert_eq!(fs::read(&path).unwrap(), lock);
    let dir = root.join("repository/org/test/lib/2.0");
    fs::create_dir_all(&dir).unwrap();
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId><artifactId>lib</artifactId><version>2.0</version></project>";
    for (name, bytes) in [
        ("lib-2.0.pom", pom.as_bytes()),
        ("lib-2.0.jar", b"lib 2 jar".as_slice()),
    ] {
        fs::write(dir.join(name), bytes).unwrap();
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .unwrap();
    }
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "regenerate merged BOM graph",
    );
    let lock = rv_lock::Lockfile::read(&path).unwrap();
    assert!(
        lock.platforms[0]
            .artifacts
            .iter()
            .any(|a| a.coord().gav.version() == "2.0")
    );
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen corrected BOM graph",
    );
}

#[test]
fn bom_and_consumer_description_edits_merge_without_changing_consumer_context() {
    assert_bom_description_merge(reactor_bom_project());
}

#[test]
fn hidden_bom_imports_keep_metadata_only_edits_mergeable() {
    for parent in [true, false] {
        assert_bom_description_merge(reactor_bom_through_remote_project(parent));
    }
}

fn assert_bom_description_merge(project: Project) {
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let base = rv_lock::Lockfile::read(&lock_path).unwrap();
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    for (branch, path) in [("left", "a/pom.xml"), ("right", "b/pom.xml")] {
        git(&root, &["switch", "-c", branch, "main"]);
        let pom = root.join(path);
        fs::write(
            &pom,
            fs::read_to_string(&pom)
                .unwrap()
                .replace("</project>", "<description>edited</description></project>"),
        )
        .unwrap();
        assert_success(
            &project.raeva(&["sync", "--offline"]),
            "sync description edit",
        );
        if branch == "left" {
            let edited = rv_lock::Lockfile::read(&lock_path).unwrap();
            assert_eq!(
                base.platforms[0].model_inputs.as_ref().unwrap().pom_hashes["b/pom.xml"],
                edited.platforms[0]
                    .model_inputs
                    .as_ref()
                    .unwrap()
                    .pom_hashes["b/pom.xml"]
            );
        }
        git(&root, &["add", path, "raeva.lock"]);
        git(&root, &["commit", "-m", "test: edit description"]);
    }
    git(&root, &["merge", "--no-edit", "left"]);
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen merged BOM descriptions",
    );
}

#[test]
fn an_unread_ancestor_keeps_lock_inputs_portable_between_checkouts() {
    let first = Project::synced();
    let second = Project::synced();
    let repository = tempfile::tempdir().unwrap();
    let parent = repository.path().join("org/test/parent/1/parent-1.pom");
    fs::create_dir_all(parent.parent().unwrap()).unwrap();
    let text = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId><artifactId>parent</artifactId><version>1</version><packaging>pom</packaging></project>";
    fs::write(&parent, text).unwrap();
    fs::write(
        parent.with_extension("pom.sha256"),
        crate::common::sha256_hex(text.as_bytes()),
    )
    .unwrap();
    for project in [&first, &second] {
        let root = project.root();
        fs::write(
            root.join("raeva.toml"),
            format!(
                "[[repositories]]\nid = \"central\"\nurl = \"{}\"\n",
                url::Url::from_directory_path(repository.path()).unwrap()
            ),
        )
        .unwrap();
        for (name, text) in [
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId><artifactId>root</artifactId><version>1</version><packaging>pom</packaging><modules><module>a</module><module>b</module></modules></project>",
            ),
            (
                "a/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId><artifactId>parent</artifactId><version>1</version></parent><groupId>org.test</groupId><artifactId>a</artifactId><version>1</version><packaging>pom</packaging></project>",
            ),
            (
                "b/pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId><artifactId>a</artifactId><version>1</version><relativePath>../a/pom.xml</relativePath></parent><artifactId>b</artifactId></project>",
            ),
        ] {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        assert_success(
            &project.raeva(&["sync", "--offline"]),
            "sync checkout with remote ancestor",
        );
    }
    let first_lock = fs::read(first.root().join("raeva.lock")).unwrap();
    assert_eq!(
        first_lock,
        fs::read(second.root().join("raeva.lock")).unwrap()
    );
    fs::write(second.root().join("raeva.lock"), &first_lock).unwrap();
    assert_success(
        &second.raeva(&["sync", "--frozen", "--offline"]),
        "reuse lock after relocation",
    );
    assert_eq!(
        first_lock,
        fs::read(second.root().join("raeva.lock")).unwrap()
    );
}

fn reactor_dependency_project() -> Project {
    let module = |name: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>{name}</artifactId><version>1</version></project>"
        )
    };
    let (a, b) = (module("a"), module("b"));
    // Another module already pins lib, so the branches touch separate rows.
    let c = module("c").replace(
        "</project>",
        "<repositories><repository><id>local</id>\
         <url>file://${project.basedir}/../repository/</url></repository></repositories>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
         <version>1.0</version></dependency></dependencies></project>",
    );
    Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
         <modules><module>a</module><module>b</module><module>c</module></modules></project>",
        ),
        ("a/pom.xml", &a),
        ("b/pom.xml", &b),
        ("c/pom.xml", &c),
    ])
}

/// One branch changes what a reactor module brings in, the other starts
/// depending on that module, directly or through the external `org.test:ext`.
/// Git merges both locks cleanly, and the consumer's graph must not be
/// trusted from either side.
fn assert_reactor_dependency_merge_requires_relock(left_edit: &str, dependency: &str) {
    let project = reactor_dependency_project();
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let dir = root.join("repository/org/test/ext/1.0");
    fs::create_dir_all(&dir).unwrap();
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>ext</artifactId><version>1.0</version><dependencies><dependency>\
        <groupId>org.test</groupId><artifactId>a</artifactId><version>1</version>\
        </dependency></dependencies></project>";
    for (name, bytes) in [
        ("ext-1.0.pom", pom.as_bytes()),
        ("ext-1.0.jar", b"ext jar".as_slice()),
    ] {
        fs::write(dir.join(name), bytes).unwrap();
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .unwrap();
    }
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    let a = root.join("a/pom.xml");
    fs::write(
        &a,
        fs::read_to_string(&a)
            .unwrap()
            .replace("</project>", &format!("{left_edit}</project>")),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync left edit");
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: change module a"]);
    git(&root, &["switch", "-c", "right", "main"]);
    let b = root.join("b/pom.xml");
    fs::write(
        &b,
        fs::read_to_string(&b).unwrap().replace(
            "</project>",
            &format!(
                "<repositories><repository><id>local</id>\
                 <url>file://${{project.basedir}}/../repository/</url></repository>\
                 </repositories><dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>{dependency}</artifactId></dependency></dependencies>\
                 <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>{dependency}</artifactId><version>{}</version></dependency>\
                 </dependencies></dependencyManagement></project>",
                if dependency == "a" { "1" } else { "1.0" }
            ),
        ),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync right edit");
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: depend on module a"]);
    let merged = git_output(&root, &["merge", "--no-edit", "left"]);
    if merged.status.success() {
        let lock = fs::read(&lock_path).unwrap();
        assert_status(
            &project.raeva(&["sync", "--frozen", "--offline"]),
            7,
            "merged reactor dependency drift",
        );
        assert_eq!(fs::read(&lock_path).unwrap(), lock);
    } else {
        // The records of both modules now cover a, or every record covers
        // the whole reactor once ext reads it: only the lock conflicts.
        let conflicts = git_output(&root, &["diff", "--name-only", "--diff-filter=U"]);
        assert_eq!(
            String::from_utf8_lossy(&conflicts.stdout).trim(),
            "raeva.lock"
        );
        git(&root, &["checkout", "--theirs", "raeva.lock"]);
    }
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "resolve merged reactor dependency",
    );
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    let consumer = lock.platforms[0]
        .modules
        .iter()
        .find(|module| module.path == "b/pom.xml")
        .unwrap();
    assert!(
        consumer
            .packages
            .iter()
            .any(|package| package.coordinate.to_string().contains("org.test:lib")),
        "{consumer:?}"
    );
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen corrected reactor graph",
    );
}

#[test]
fn a_reactor_dependency_and_its_new_dependencies_cannot_merge_into_a_stale_graph() {
    for dependency in ["a", "ext"] {
        assert_reactor_dependency_merge_requires_relock(
            "<repositories><repository><id>local</id>\
             <url>file://${project.basedir}/../repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>1.0</version></dependency></dependencies>",
            dependency,
        );
    }
}

/// One branch changes os-maven-plugin's classifier likes in `a`, the module
/// Maven sorts first, to the release's ID; the other makes `b`, which does not depend on `a`,
/// depend on a `${os.detected.classifier}` artifact. Every classifier of the
/// reactor takes the suffix from `a`, so the merged graph is not trusted.
/// The build machine's release is a Debian one, whose ID is the like.
#[test]
fn first_module_classifier_likes_cannot_merge_into_a_stale_graph() {
    let like = "debian";
    let project = reactor_dependency_project();
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    // Only Linux is locked, whatever the host.
    fs::remove_file(&lock_path).unwrap();
    let a = root.join("a/pom.xml");
    let raeva = |args: &[&str]| {
        let release = [(rv_maven_model::OS_RELEASE_TEST_ENV, "ID=debian\n")];
        project.raeva_with(&release, &[args, &["--platforms", "linux-x86_64"]].concat())
    };
    let likes = |likes: &str| {
        fs::write(
            &a,
            fs::read_to_string(&a).unwrap().replace(
                "<version>1</version>",
                &format!(
                    "<version>1</version><properties><os.detection.classifierWithLikes>\
                     {likes}</os.detection.classifierWithLikes></properties>"
                ),
            ),
        )
        .unwrap();
    };
    likes("other");
    assert_success(&raeva(&["sync", "--offline"]), "sync other likes");
    let native = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>native</artifactId><version>1</version></project>";
    let suffixed = format!("native-1-linux-x86_64-{like}.jar");
    publish(
        &root,
        "native",
        &[
            ("native-1.pom", native.as_bytes()),
            ("native-1-linux-x86_64.jar", b"plain"),
            (&suffixed, b"suffixed"),
        ],
    );
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    let base = fs::read_to_string(&a).unwrap();
    fs::write(&a, base.replace(">other<", &format!(">{like}<"))).unwrap();
    assert_success(&raeva(&["sync", "--offline"]), "sync likes");
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: set classifier likes"]);
    git(&root, &["switch", "-c", "right", "main"]);
    let b = root.join("b/pom.xml");
    fs::write(
        &b,
        fs::read_to_string(&b).unwrap().replace(
            "</project>",
            "<repositories><repository><id>local</id>\
             <url>file://${project.basedir}/../repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>native</artifactId><version>1</version>\
             <classifier>${os.detected.classifier}</classifier></dependency></dependencies>\
             </project>",
        ),
    )
    .unwrap();
    assert_success(&raeva(&["sync", "--offline"]), "sync classifier");
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: depend on native"]);
    let merged = git_output(&root, &["merge", "--no-edit", "left"]);
    if merged.status.success() {
        let lock = fs::read(&lock_path).unwrap();
        assert!(!raeva(&["sync", "--frozen", "--offline"]).status.success());
        assert_eq!(fs::read(&lock_path).unwrap(), lock);
    } else {
        git(&root, &["checkout", "--theirs", "raeva.lock"]);
    }
    assert_success(&raeva(&["sync", "--offline"]), "resolve merged likes");
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    let suffix = format!("linux-x86_64-{like}");
    assert!(
        (lock.platforms[0].artifacts.iter())
            .any(|artifact| artifact.coord().classifier() == Some(suffix.as_str())),
        "{:?}",
        lock.platforms[0].artifacts
    );
    assert_success(
        &raeva(&["sync", "--frozen", "--offline"]),
        "frozen merged likes",
    );
}

/// Whole-reactor records all change with any POM edit, so the note names no
/// module that was not edited.
#[test]
fn a_whole_reactor_record_change_names_no_untouched_module() {
    let project = reactor_dependency_project();
    let root = project.root();
    let ext = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>ext</artifactId><version>1</version><dependencies><dependency>\
        <groupId>org.test</groupId><artifactId>a</artifactId><version>[1,2)</version>\
        </dependency></dependencies></project>";
    publish(
        &root,
        "ext",
        &[("ext-1.pom", ext.as_bytes()), ("ext-1.jar", b"ext jar")],
    );
    let b = root.join("b/pom.xml");
    fs::write(
        &b,
        fs::read_to_string(&b).unwrap().replace(
            "</project>",
            "<repositories><repository><id>local</id>\
             <url>file://${project.basedir}/../repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>ext</artifactId>\
             <version>1</version></dependency></dependencies></project>",
        ),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync range");
    let c = root.join("c/pom.xml");
    fs::write(
        &c,
        fs::read_to_string(&c).unwrap().replace(
            "<version>1.0</version>",
            "<version>1.0</version><optional>false</optional>",
        ),
    )
    .unwrap();
    let frozen = project.raeva(&["sync", "--frozen", "--offline"]);
    assert_success(&frozen, "frozen edited module");
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(
        stderr.contains("without changing the dependencies"),
        "{stderr}"
    );
    assert!(!stderr.contains("a/pom.xml"), "{stderr}");
}

/// `b` reaches a reactor module `a:1` that loses to the external `a:2`,
/// which `x` brings first. One branch makes `a` depend on `x:[2]`, renaming
/// it from `first` to `a`; the other makes `b` reach `a:1`: through the
/// external `y`, or with `relocating` through reactor module `r`, whose
/// external `p` and `q` relocate to `a:2` and `a:1`. The loser's dependency
/// on `x` still constrains `x`, so the merged graph is not trusted.
fn assert_loser_merge_requires_relock(first: &str, relocating: bool) {
    let pom = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let dependency = |artifact: &str, version: &str, extra: &str| {
        format!(
            "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version>{extra}</dependency>"
        )
    };
    let dependencies = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
    let repository = "<repositories><repository><id>local</id>\
        <url>file://${project.basedir}/../repository/</url></repository></repositories>";
    let module = |artifact: &str, list: &[String]| {
        pom(
            artifact,
            "1",
            &format!("{repository}{}", dependencies(list)),
        )
    };
    let relocation = |artifact: &str, version: &str| {
        format!(
            "<distributionManagement><relocation><artifactId>{artifact}</artifactId>\
             <version>{version}</version></relocation></distributionManagement>"
        )
    };
    let r = match relocating {
        true => module("r", &[dependency("p", "1", ""), dependency("q", "1", "")]),
        false => module("r", &[]),
    };
    let project = Project::synced_with(&[
        (
            "pom.xml",
            &pom(
                "root",
                "1",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                 <module>c</module><module>r</module></modules>",
            ),
        ),
        ("a/pom.xml", &module(first, &[])),
        ("b/pom.xml", &module("b", &[])),
        ("c/pom.xml", &module("c", &[])),
        ("r/pom.xml", &module("r", &[])),
    ]);
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let artifacts = [
        (
            "x",
            "1",
            pom("x", "1", &dependencies(&[dependency("a", "2", "")])),
        ),
        ("x", "2", pom("x", "2", "")),
        (
            "y",
            "1",
            pom("y", "1", &dependencies(&[dependency("a", "1", "")])),
        ),
        ("p", "1", pom("p", "1", &relocation("a", "2"))),
        ("q", "1", pom("q", "1", &relocation("a", "1"))),
        ("a", "2", pom("a", "2", "")),
        ("a", "1", pom("a", "1", "")),
    ];
    for (artifact, version, text) in &artifacts {
        let dir = root.join(format!("repository/org/test/{artifact}/{version}"));
        fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in [
            (format!("{artifact}-{version}.pom"), text.as_bytes()),
            (format!("{artifact}-{version}.jar"), b"jar".as_slice()),
        ] {
            fs::write(dir.join(&name), bytes).unwrap();
            fs::write(
                dir.join(format!("{name}.sha256")),
                crate::common::sha256_hex(bytes),
            )
            .unwrap();
        }
    }
    let metadata = "<metadata><groupId>org.test</groupId><artifactId>x</artifactId>\
        <versioning><versions><version>1</version><version>2</version></versions>\
        </versioning></metadata>";
    let path = root.join("repository/org/test/x/maven-metadata.xml");
    fs::write(&path, metadata).unwrap();
    fs::write(
        path.with_extension("xml.sha256"),
        crate::common::sha256_hex(metadata.as_bytes()),
    )
    .unwrap();
    let write = |path: &str, text: String| fs::write(root.join(path), text).unwrap();
    write("b/pom.xml", module("b", &[dependency("x", "[1]", "")]));
    write("r/pom.xml", r);
    // `c` pins every external artifact, without reaching `a`, so the
    // branches change only their own module rows.
    let without_a = "<exclusions><exclusion><groupId>org.test</groupId>\
        <artifactId>a</artifactId></exclusion></exclusions>";
    write(
        "c/pom.xml",
        module(
            "c",
            &[
                dependency("x", "2", ""),
                dependency("y", "1", without_a),
                dependency("a", "2", ""),
            ],
        ),
    );
    assert_success(&project.raeva(&["sync", "--offline"]), "sync base");
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    write("a/pom.xml", module("a", &[dependency("x", "[2]", "")]));
    assert_success(&project.raeva(&["sync", "--offline"]), "sync left edit");
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: make a depend on x"]);
    git(&root, &["switch", "-c", "right", "main"]);
    let reach = match relocating {
        true => dependency("r", "1", ""),
        false => dependency("y", "1", ""),
    };
    write(
        "b/pom.xml",
        module("b", &[dependency("x", "[1]", ""), reach]),
    );
    assert_success(&project.raeva(&["sync", "--offline"]), "sync right edit");
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen right edit",
    );
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: reach a"]);
    let merged = git_output(&root, &["merge", "--no-edit", "left"]);
    if merged.status.success() {
        let lock = fs::read(&lock_path).unwrap();
        assert!(
            !project
                .raeva(&["sync", "--frozen", "--offline"])
                .status
                .success(),
            "{first} {relocating}"
        );
        assert_eq!(fs::read(&lock_path).unwrap(), lock);
    }
}

#[test]
fn a_reactor_module_losing_mediation_cannot_merge_into_a_stale_graph() {
    for (first, relocating) in [("a", false), ("a", true), ("z", false)] {
        assert_loser_merge_requires_relock(first, relocating);
    }
}

fn publish(root: &Path, artifact: &str, files: &[(&str, &[u8])]) {
    let dir = root.join(format!("repository/org/test/{artifact}/1"));
    fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in files {
        fs::write(dir.join(name), bytes).unwrap();
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .unwrap();
    }
}

/// One branch renames reactor module `a` to `org.test:new:1`; the other
/// starts depending on `org.test:ext`, which reaches `new` as a dependency
/// or as its parent, then still an external POM. After a clean merge `new`
/// is a reactor module, so the locked graph is not trusted. With `subset`
/// the lock also records macOS, and a sync of Linux alone must not keep its
/// graph.
fn assert_renamed_module_merge_requires_relock(ext: &str, subset: bool) {
    let project = reactor_dependency_project();
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let a = root.join("a/pom.xml");
    fs::write(
        &a,
        fs::read_to_string(&a)
            .unwrap()
            .replace("</version>", "</version><packaging>pom</packaging>"),
    )
    .unwrap();
    let platforms = |listed: &'static str| match subset {
        true => vec!["sync", "--offline", "--platforms", listed],
        false => vec!["sync", "--offline"],
    };
    let frozen = |listed| {
        let mut args = platforms(listed);
        args.insert(1, "--frozen");
        args
    };
    let sync = platforms("linux-x86_64,macos-aarch64");
    assert_success(&project.raeva(&sync), "sync pom module");
    let new = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>new</artifactId><version>1</version><packaging>pom</packaging></project>";
    publish(&root, "new", &[("new-1.pom", new.as_bytes())]);
    publish(
        &root,
        "ext",
        &[("ext-1.pom", ext.as_bytes()), ("ext-1.jar", b"ext jar")],
    );
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    fs::write(
        &a,
        fs::read_to_string(&a)
            .unwrap()
            .replace("<artifactId>a</artifactId>", "<artifactId>new</artifactId>"),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync renamed module",
    );
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: rename module a"]);
    git(&root, &["switch", "-c", "right", "main"]);
    let b = root.join("b/pom.xml");
    fs::write(
        &b,
        fs::read_to_string(&b).unwrap().replace(
            "</project>",
            "<repositories><repository><id>local</id>\
             <url>file://${project.basedir}/../repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>ext</artifactId>\
             <version>1</version></dependency></dependencies></project>",
        ),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync new dependency",
    );
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: depend on ext"]);
    // A rename changes every record, which covers the reactor's
    // coordinates, so the locks can conflict.
    if !git_output(&root, &["merge", "--no-edit", "left"])
        .status
        .success()
    {
        git(&root, &["checkout", "--theirs", "raeva.lock"]);
    }
    let lock = fs::read(&lock_path).unwrap();
    assert!(
        !project
            .raeva(&frozen("linux-x86_64,macos-aarch64"))
            .status
            .success()
    );
    assert_eq!(fs::read(&lock_path).unwrap(), lock);
    let sync = platforms("linux-x86_64");
    assert_success(&project.raeva(&sync), "resolve merged rename");
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    let consumer = (lock.platforms[0].modules.iter())
        .find(|module| module.path == "b/pom.xml")
        .unwrap();
    assert!(
        !(consumer.packages.iter())
            .any(|package| package.coordinate.gav.artifact.as_str() == "new"
                && package.workspace_module.is_none()),
        "{consumer:?}"
    );
    assert!(
        !lock.platforms[0]
            .support_poms
            .contains_key("org.test:new:1")
    );
    assert_success(
        &project.raeva(&frozen("linux-x86_64")),
        "frozen renamed module graph",
    );
}

#[test]
fn an_external_pom_that_becomes_a_reactor_module_cannot_merge_into_a_stale_graph() {
    let head = "<project><modelVersion>4.0.0</modelVersion>";
    let tail = "<artifactId>ext</artifactId><version>1</version>";
    let dependency = format!(
        "{head}<groupId>org.test</groupId>{tail}<dependencies><dependency>\
         <groupId>org.test</groupId><artifactId>new</artifactId><version>1</version>\
         <type>pom</type></dependency></dependencies></project>"
    );
    let parent = format!(
        "{head}<parent><groupId>org.test</groupId><artifactId>new</artifactId>\
         <version>1</version><relativePath/></parent>{tail}</project>"
    );
    for subset in [false, true] {
        assert_renamed_module_merge_requires_relock(&dependency, subset);
        assert_renamed_module_merge_requires_relock(&parent, subset);
    }
}

/// One branch changes what reactor BOM `a` manages; the other starts
/// depending on `org.test:ext`, whose POM reads `a` as an import or as its
/// parent. Git merges both locks, and the consumer's graph must not be
/// trusted from either side.
fn assert_dependency_model_merge_requires_relock(ext: &str) {
    let project = reactor_dependency_project();
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let a = root.join("a/pom.xml");
    fs::write(
        &a,
        fs::read_to_string(&a).unwrap().replace(
            "</version>",
            "</version><packaging>pom</packaging><dependencyManagement><dependencies>\
             <dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>1.0</version></dependency></dependencies></dependencyManagement>",
        ),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync reactor BOM");
    publish(
        &root,
        "ext",
        &[("ext-1.pom", ext.as_bytes()), ("ext-1.jar", b"ext jar")],
    );
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    fs::write(
        &a,
        fs::read_to_string(&a)
            .unwrap()
            .replace("<version>1.0</version>", "<version>2.0</version>"),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync BOM change");
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: change BOM management"]);
    git(&root, &["switch", "-c", "right", "main"]);
    let b = root.join("b/pom.xml");
    fs::write(
        &b,
        fs::read_to_string(&b).unwrap().replace(
            "</project>",
            "<repositories><repository><id>local</id>\
             <url>file://${project.basedir}/../repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>ext</artifactId>\
             <version>1</version></dependency></dependencies></project>",
        ),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync new dependency",
    );
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen dependency reading the reactor",
    );
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: depend on ext"]);
    let merged = git_output(&root, &["merge", "--no-edit", "left"]);
    if merged.status.success() {
        let lock = fs::read(&lock_path).unwrap();
        assert!(
            !project
                .raeva(&["sync", "--frozen", "--offline"])
                .status
                .success()
        );
        assert_eq!(fs::read(&lock_path).unwrap(), lock);
    } else {
        let conflicts = git_output(&root, &["diff", "--name-only", "--diff-filter=U"]);
        assert_eq!(
            String::from_utf8_lossy(&conflicts.stdout).trim(),
            "raeva.lock"
        );
        git(&root, &["checkout", "--theirs", "raeva.lock"]);
    }
    let lib = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>lib</artifactId><version>2.0</version></project>";
    let dir = root.join("repository/org/test/lib/2.0");
    fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in [
        ("lib-2.0.pom", lib.as_bytes()),
        ("lib-2.0.jar", b"lib 2 jar".as_slice()),
    ] {
        fs::write(dir.join(name), bytes).unwrap();
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .unwrap();
    }
    assert_success(&project.raeva(&["sync", "--offline"]), "resolve merged BOM");
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    let consumer = (lock.platforms[0].modules.iter())
        .find(|module| module.path == "b/pom.xml")
        .unwrap();
    assert!(
        (consumer.packages.iter())
            .any(|package| package.coordinate.to_string().contains("lib:2.0")),
        "{consumer:?}"
    );
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen corrected dependency graph",
    );
}

/// One branch changes a property of reactor module `a`, which none of `a`'s
/// own declarations reads; the other makes `b` import the external BOM `m`,
/// whose parent is `a` and whose management reads that property. The
/// merged graph is not trusted.
#[test]
fn a_root_import_inheriting_a_reactor_pom_cannot_merge_into_a_stale_graph() {
    let project = reactor_dependency_project();
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let a = root.join("a/pom.xml");
    let property = |version: &str| {
        format!(
            "</version><packaging>pom</packaging><properties><libv>{version}</libv></properties>"
        )
    };
    let base = fs::read_to_string(&a).unwrap();
    fs::write(&a, base.replacen("</version>", &property("1.0"), 1)).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync property");
    let m = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
        <artifactId>a</artifactId><version>1</version><relativePath/></parent>\
        <artifactId>m</artifactId><packaging>pom</packaging><dependencyManagement>\
        <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
        <version>${libv}</version></dependency></dependencies></dependencyManagement></project>";
    publish(&root, "m", &[("m-1.pom", m.as_bytes())]);
    let lib = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>lib</artifactId><version>2.0</version></project>";
    let dir = root.join("repository/org/test/lib/2.0");
    fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in [
        ("lib-2.0.pom", lib.as_bytes()),
        ("lib-2.0.jar", b"lib 2 jar".as_slice()),
    ] {
        fs::write(dir.join(name), bytes).unwrap();
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .unwrap();
    }
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    fs::write(&a, base.replacen("</version>", &property("2.0"), 1)).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync property change",
    );
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: change the property"]);
    git(&root, &["switch", "-c", "right", "main"]);
    let b = root.join("b/pom.xml");
    fs::write(
        &b,
        fs::read_to_string(&b).unwrap().replace(
            "</project>",
            "<repositories><repository><id>local</id>\
             <url>file://${project.basedir}/../repository/</url></repository></repositories>\
             <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>m</artifactId><version>1</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             </dependency></dependencies></project>",
        ),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync import");
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen import inheriting the reactor",
    );
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: import m"]);
    let merged = git_output(&root, &["merge", "--no-edit", "left"]);
    if merged.status.success() {
        let lock = fs::read(&lock_path).unwrap();
        assert!(
            !project
                .raeva(&["sync", "--frozen", "--offline"])
                .status
                .success()
        );
        assert_eq!(fs::read(&lock_path).unwrap(), lock);
    } else {
        git(&root, &["checkout", "--theirs", "raeva.lock"]);
    }
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "resolve merged import",
    );
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    let consumer = (lock.platforms[0].modules.iter())
        .find(|module| module.path == "b/pom.xml")
        .unwrap();
    assert!(
        (consumer.packages.iter())
            .any(|package| package.coordinate.to_string().contains("lib:2.0")),
        "{consumer:?}"
    );
}

#[test]
fn a_dependency_model_reading_a_reactor_pom_cannot_merge_into_a_stale_graph() {
    let head = "<project><modelVersion>4.0.0</modelVersion>";
    let tail = "<artifactId>ext</artifactId><version>1</version>";
    let lib = "<dependencies><dependency><groupId>org.test</groupId>\
        <artifactId>lib</artifactId></dependency></dependencies></project>";
    assert_dependency_model_merge_requires_relock(&format!(
        "{head}<groupId>org.test</groupId>{tail}<dependencyManagement><dependencies>\
         <dependency><groupId>org.test</groupId><artifactId>a</artifactId><version>1</version>\
         <type>pom</type><scope>import</scope></dependency></dependencies>\
         </dependencyManagement>{lib}"
    ));
    assert_dependency_model_merge_requires_relock(&format!(
        "{head}<parent><groupId>org.test</groupId><artifactId>a</artifactId>\
         <version>1</version><relativePath/></parent>{tail}{lib}"
    ));
}

/// One branch moves reactor module `a` from version 0 to 2; the other starts
/// depending on `org.test:ext`, whose POM names `a` by the range `[1,3)`, as
/// a dependency or as its parent, or that `b` manages to that range, and
/// selects the repository's `a:1`. After the merge the reactor's `a:2` wins
/// the range, so the locked graph is not trusted.
fn assert_range_merge_requires_relock(ext: &str, management: &str) {
    let module = |name: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{name}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let repository = "<repositories><repository><id>local</id>\
        <url>file://${project.basedir}/../repository/</url></repository></repositories>";
    let lib = format!(
        "{repository}<dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>"
    );
    let project = Project::synced_with(&[
        (
            "pom.xml",
            &module(
                "root",
                "1",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                 <module>c</module></modules>",
            ),
        ),
        ("a/pom.xml", &module("a", "0", "<packaging>pom</packaging>")),
        ("b/pom.xml", &module("b", "1", "")),
        ("c/pom.xml", &module("c", "1", &lib)),
    ]);
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let a = module("a", "1", "<packaging>pom</packaging>");
    publish(&root, "a", &[("a-1.pom", a.as_bytes())]);
    let metadata = "<metadata><groupId>org.test</groupId><artifactId>a</artifactId>\
        <versioning><versions><version>1</version></versions></versioning></metadata>";
    let path = root.join("repository/org/test/a/maven-metadata.xml");
    fs::write(&path, metadata).unwrap();
    fs::write(
        path.with_extension("xml.sha256"),
        crate::common::sha256_hex(metadata.as_bytes()),
    )
    .unwrap();
    publish(
        &root,
        "ext",
        &[("ext-1.pom", ext.as_bytes()), ("ext-1.jar", b"ext jar")],
    );
    fs::write(root.join("b/a.jar"), b"system jar").unwrap();
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    fs::write(
        root.join("a/pom.xml"),
        module("a", "2", "<packaging>pom</packaging>"),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync new version");
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: move module a to 2"]);
    git(&root, &["switch", "-c", "right", "main"]);
    let dependency = format!(
        "{repository}<dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>ext</artifactId><version>1</version></dependency></dependencies>\
         {management}"
    );
    fs::write(root.join("b/pom.xml"), module("b", "1", &dependency)).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync new dependency",
    );
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: depend on ext"]);
    let merged = git_output(&root, &["merge", "--no-edit", "left"]);
    if merged.status.success() {
        let lock = fs::read(&lock_path).unwrap();
        assert!(
            !project
                .raeva(&["sync", "--frozen", "--offline"])
                .status
                .success()
        );
        assert_eq!(fs::read(&lock_path).unwrap(), lock);
    } else {
        let conflicts = git_output(&root, &["diff", "--name-only", "--diff-filter=U"]);
        assert_eq!(
            String::from_utf8_lossy(&conflicts.stdout).trim(),
            "raeva.lock"
        );
        git(&root, &["checkout", "--theirs", "raeva.lock"]);
    }
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "resolve merged range",
    );
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert!(
        !(lock.platforms[0].artifacts.iter())
            .any(|artifact| artifact.coord().gav.to_string() == "org.test:a:1"),
        "{:?}",
        lock.platforms[0].artifacts
    );
    assert!(!lock.platforms[0].support_poms.contains_key("org.test:a:1"));
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen merged range",
    );
}

#[test]
fn a_range_a_reactor_module_can_win_cannot_merge_into_a_stale_graph() {
    let head = "<project><modelVersion>4.0.0</modelVersion>";
    let tail = "<artifactId>ext</artifactId><version>1</version>";
    assert_range_merge_requires_relock(
        &format!(
            "{head}<groupId>org.test</groupId>{tail}<dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>a</artifactId><version>[1,3)</version>\
             <type>pom</type></dependency></dependencies></project>"
        ),
        "",
    );
    assert_range_merge_requires_relock(
        &format!(
            "{head}<parent><groupId>org.test</groupId><artifactId>a</artifactId>\
             <version>[1,3)</version><relativePath/></parent>{tail}</project>"
        ),
        "",
    );
    assert_range_merge_requires_relock(
        &format!(
            "{head}<groupId>org.test</groupId>{tail}<dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>a</artifactId><version>1</version>\
             </dependency></dependencies></project>"
        ),
        "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>a</artifactId><version>[1,3)</version><scope>system</scope>\
         <systemPath>${project.basedir}/a.jar</systemPath></dependency></dependencies>\
         </dependencyManagement>",
    );
}

/// `b` reaches the range `t:[1,2)` through the external `ext`. No reactor
/// module is a candidate, and the graphs cover which ones could be, so an
/// edit to `c` changes only `c`'s record.
#[test]
fn a_transitive_range_keeps_records_per_module() {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>b</module><module>c</module></modules></project>",
        ),
        ("b/pom.xml", &update_module("b", "")),
        ("c/pom.xml", &update_module("c", "")),
    ]);
    let root = project.root();
    release(&root, "t", "1.0", "", &["1.0"]);
    release(&root, "ext", "1", &update_dependency("t", "[1,2)"), &["1"]);
    let dependency = format!(
        "<dependencies>{}</dependencies>",
        update_dependency("ext", "1")
    );
    fs::write(root.join("b/pom.xml"), update_module("b", &dependency)).unwrap();
    let records = |label| {
        assert_success(&project.raeva(&["sync", "--offline"]), label);
        let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
        let b = (lock.platforms[0].modules.iter())
            .find(|module| module.path == "b/pom.xml")
            .unwrap();
        assert!(has(b, "org.test:t:1.0"), "{b:?}");
        lock.platforms[0].model_inputs.clone().unwrap().pom_hashes
    };
    let before = records("sync range");
    fs::write(
        root.join("c/pom.xml"),
        update_module("c", "<description>edited</description>"),
    )
    .unwrap();
    let after = records("sync edit");
    let changed: Vec<_> = (before.iter())
        .filter(|(path, digest)| after.get(*path) != Some(*digest))
        .map(|(path, _)| path.as_str())
        .collect();
    assert_eq!(changed, ["c/pom.xml"]);
}

/// `b` depends on reactor module `m`, which depends on the external `old`,
/// relocated to the external `a:1`. `b` manages `a` to `[1,2]`, which reactor
/// module `a:2` wins, read through `old`'s relocation, so an edit to `a`
/// changes `b`'s record too.
#[test]
fn a_managed_range_after_a_relocation_covers_the_reactor_module_it_reaches() {
    let a = |body: &str| {
        update_module("a", body).replace(
            "<version>1</version><repositories>",
            "<version>2</version><repositories>",
        )
    };
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module><module>b</module><module>m</module></modules>\
             </project>",
        ),
        ("a/pom.xml", &a("")),
        ("b/pom.xml", &update_module("b", "")),
        ("m/pom.xml", &update_module("m", "")),
    ]);
    let root = project.root();
    release(&root, "a", "1", "", &["1"]);
    release(&root, "z", "1", "", &["1"]);
    let old = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>old</artifactId><version>1</version><distributionManagement><relocation>\
        <artifactId>a</artifactId></relocation></distributionManagement></project>";
    publish(&root, "old", &[("old-1.pom", old.as_bytes())]);
    let m = format!(
        "<dependencies>{}</dependencies>",
        update_dependency("old", "1")
    );
    fs::write(root.join("m/pom.xml"), update_module("m", &m)).unwrap();
    let b = format!(
        "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
         <dependencies>{}</dependencies>",
        update_dependency("a", "[1,2]"),
        update_dependency("m", "1")
    );
    fs::write(root.join("b/pom.xml"), update_module("b", &b)).unwrap();
    let record = |label| {
        assert_success(&project.raeva(&["sync", "--offline"]), label);
        let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
        let b = (lock.platforms[0].modules.iter())
            .find(|module| module.path == "b/pom.xml")
            .unwrap();
        assert!(
            (b.packages.iter())
                .any(|package| package.workspace_module.as_deref() == Some("a/pom.xml")),
            "{b:?}"
        );
        lock.platforms[0].model_inputs.clone().unwrap().pom_hashes["b/pom.xml"].clone()
    };
    let before = record("sync");
    let z = format!(
        "<dependencies>{}</dependencies>",
        update_dependency("z", "1")
    );
    fs::write(root.join("a/pom.xml"), a(&z)).unwrap();
    assert_ne!(record("sync edit"), before);
}

/// Writes `org.test:{artifact}:{version}` with `dependencies` and lists
/// `versions` in its metadata.
fn release(root: &Path, artifact: &str, version: &str, dependencies: &str, versions: &[&str]) {
    let dir = root.join(format!("repository/org/test/{artifact}"));
    fs::create_dir_all(dir.join(version)).unwrap();
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>{artifact}</artifactId><version>{version}</version>\
         <dependencies>{dependencies}</dependencies></project>"
    );
    for (name, bytes) in [
        (format!("{artifact}-{version}.pom"), pom.as_bytes()),
        (format!("{artifact}-{version}.jar"), artifact.as_bytes()),
    ] {
        fs::write(dir.join(version).join(&name), bytes).unwrap();
        fs::write(
            dir.join(version).join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .unwrap();
    }
    let listed: String = (versions.iter())
        .map(|version| format!("<version>{version}</version>"))
        .collect();
    fs::write(
        dir.join("maven-metadata.xml"),
        format!(
            "<metadata><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <versioning><versions>{listed}</versions></versioning></metadata>"
        ),
    )
    .unwrap();
}

fn update_module(name: &str, body: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>{name}</artifactId><version>1</version><repositories><repository>\
         <id>local</id><url>file://${{project.basedir}}/../repository/</url></repository>\
         </repositories>{body}</project>"
    )
}

fn update_dependency(artifact: &str, version: &str) -> String {
    format!(
        "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
         <version>{version}</version></dependency>"
    )
}

/// Writes the SNAPSHOT BOM `org.test:bom:1-SNAPSHOT`, which manages `t` at
/// `version`.
fn snapshot_bom(root: &Path, version: &str) {
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>bom</artifactId><version>1-SNAPSHOT</version><packaging>pom</packaging>\
         <dependencyManagement><dependencies>{}</dependencies></dependencyManagement></project>",
        update_dependency("t", version)
    );
    let dir = root.join("repository/org/test/bom/1-SNAPSHOT");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("bom-1-SNAPSHOT.pom"), &pom).unwrap();
    fs::write(
        dir.join("bom-1-SNAPSHOT.pom.sha256"),
        crate::common::sha256_hex(pom.as_bytes()),
    )
    .unwrap();
}

const BOM_IMPORT: &str = "<dependencyManagement><dependencies><dependency>\
    <groupId>org.test</groupId><artifactId>bom</artifactId><version>1-SNAPSHOT</version>\
    <type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>";

/// Module `b` starts as `base` over the repository `publish` adds to. One
/// branch edits it to `edited`; the other changes upstream data with
/// `upstream` and runs `sync --update`, which leaves `b`'s POM alone. The
/// merged lock is not trusted however its conflicts are resolved, and a sync
/// of it records what the merged POMs resolve to, which `check` asserts on
/// `b`.
fn assert_update_merge_requires_relock(
    publish: impl FnOnce(&Path),
    base: &str,
    edited: &str,
    upstream: impl FnOnce(&Path),
    check: impl FnOnce(&rv_lock::LockModule),
) {
    // Another module already pins w, so the branches touch separate rows.
    let c = update_module(
        "c",
        &format!(
            "<dependencies>{}</dependencies>",
            update_dependency("w", "1")
        ),
    );
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>b</module><module>c</module></modules></project>",
        ),
        ("b/pom.xml", &update_module("b", "")),
        ("c/pom.xml", &update_module("c", "")),
    ]);
    let root = project.root();
    release(&root, "w", "1", "", &["1"]);
    release(&root, "t", "1.0", "", &["1.0"]);
    publish(&root);
    fs::write(root.join("b/pom.xml"), base).unwrap();
    fs::write(root.join("c/pom.xml"), &c).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync base");
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    fs::write(root.join("b/pom.xml"), edited).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync module edit");
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: edit b"]);
    git(&root, &["switch", "-c", "right", "main"]);
    upstream(&root);
    let before = fs::read(root.join("raeva.lock")).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "--update"]),
        "sync update",
    );
    assert_ne!(fs::read(root.join("raeva.lock")).unwrap(), before);
    git(&root, &["add", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: update"]);
    // Taking one side of each conflicting hunk keeps the other side's rows
    // and pins, as a hand resolution may.
    git(&root, &["merge", "--no-edit", "-X", "theirs", "left"]);
    let lock = fs::read(root.join("raeva.lock")).unwrap();
    assert!(
        !project
            .raeva(&["sync", "--frozen", "--offline"])
            .status
            .success()
    );
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), lock);
    assert_success(&project.raeva(&["sync", "--offline"]), "sync merge");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    check(
        (lock.platforms[0].modules.iter())
            .find(|module| module.path == "b/pom.xml")
            .unwrap(),
    );
}

fn has(module: &rv_lock::LockModule, coordinate: &str) -> bool {
    (module.packages.iter()).any(|package| package.coordinate.gav.to_string() == coordinate)
}

/// One branch excludes `w` from `b`'s dependency on `t`, which brings in
/// nothing yet; the other takes a new `t` release that depends on `w`.
#[test]
fn a_module_edit_and_an_update_of_its_graph_cannot_merge_into_a_stale_graph() {
    let base = update_module(
        "b",
        &format!(
            "<dependencies>{}</dependencies>",
            update_dependency("t", "[1,2)")
        ),
    );
    let edited = base.replace(
        "</version></dependency>",
        "</version><exclusions><exclusion><groupId>org.test</groupId>\
         <artifactId>w</artifactId></exclusion></exclusions></dependency>",
    );
    assert_update_merge_requires_relock(
        |_| {},
        &base,
        &edited,
        |root| {
            release(
                root,
                "t",
                "1.1",
                &update_dependency("w", "1"),
                &["1.0", "1.1"],
            )
        },
        |module| {
            assert!(has(module, "org.test:t:1.1"), "{module:?}");
            assert!(!has(module, "org.test:w:1"), "{module:?}");
        },
    );
}

/// One branch makes `b` depend on `t` at the version the SNAPSHOT BOM it
/// imports manages; the other publishes a BOM build managing another
/// version, which changes no row of `b`.
#[test]
fn a_module_edit_and_an_update_of_its_bom_cannot_merge_into_a_stale_graph() {
    let edited = update_module(
        "b",
        &format!(
            "{BOM_IMPORT}<dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>t</artifactId></dependency></dependencies>"
        ),
    );
    assert_update_merge_requires_relock(
        |root| snapshot_bom(root, "1.0"),
        &update_module("b", BOM_IMPORT),
        &edited,
        |root| {
            release(root, "t", "1.1", "", &["1.0", "1.1"]);
            snapshot_bom(root, "1.1");
        },
        |module| assert!(has(module, "org.test:t:1.1"), "{module:?}"),
    );
}

/// As above, but `b` starts with `t` at an explicit version and reads no
/// BOM, while `w`, which `c` depends on, imports the BOM and so pins it. The
/// update then changes the BOM's pin and no row of `b`.
#[test]
fn a_module_edit_and_an_update_of_a_bom_it_starts_reading_cannot_merge_into_a_stale_graph() {
    let edited = update_module(
        "b",
        &format!(
            "{BOM_IMPORT}<dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>t</artifactId></dependency></dependencies>"
        ),
    );
    assert_update_merge_requires_relock(
        |root| {
            snapshot_bom(root, "1.0");
            release(root, "w", "1", "", &["1"]);
            let dir = root.join("repository/org/test/w/1");
            let pom = fs::read_to_string(dir.join("w-1.pom"))
                .unwrap()
                .replace("<dependencies>", &format!("{BOM_IMPORT}<dependencies>"));
            fs::write(dir.join("w-1.pom"), &pom).unwrap();
            fs::write(
                dir.join("w-1.pom.sha256"),
                crate::common::sha256_hex(pom.as_bytes()),
            )
            .unwrap();
        },
        &update_module(
            "b",
            &format!(
                "<dependencies>{}</dependencies>",
                update_dependency("t", "1.0")
            ),
        ),
        &edited,
        |root| {
            release(root, "t", "1.1", "", &["1.0", "1.1"]);
            snapshot_bom(root, "1.1");
        },
        |module| assert!(has(module, "org.test:t:1.1"), "{module:?}"),
    );
}

/// One branch narrows a range `.mvn/maven.config` gives `b`, which still
/// selects the same `t`; the other publishes a `t` the old range selects
/// and updates. Only the configuration hash and `b`'s row change.
#[test]
fn a_configuration_edit_and_an_update_cannot_merge_into_a_stale_graph() {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>b</module></modules></project>",
        ),
        ("b/pom.xml", &update_module("b", "")),
    ]);
    let root = project.root();
    release(&root, "t", "1.0", "", &["1.0"]);
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/maven.config"), "-Dt.range=[1,3)\n").unwrap();
    fs::write(
        root.join("b/pom.xml"),
        update_module(
            "b",
            &format!(
                "<dependencies>{}</dependencies>",
                update_dependency("t", "${t.range}")
            ),
        ),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync base");
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    fs::write(root.join(".mvn/maven.config"), "-Dt.range=[1,2)\n").unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync narrowed range",
    );
    git(&root, &["add", ".mvn/maven.config", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: narrow the range"]);
    git(&root, &["switch", "-c", "right", "main"]);
    release(&root, "t", "2.0", "", &["1.0", "2.0"]);
    assert_success(
        &project.raeva(&["sync", "--offline", "--update"]),
        "sync update",
    );
    git(&root, &["add", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: update"]);
    git(&root, &["merge", "--no-edit", "-X", "theirs", "left"]);
    let lock = fs::read(root.join("raeva.lock")).unwrap();
    assert!(
        !project
            .raeva(&["sync", "--frozen", "--offline"])
            .status
            .success()
    );
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), lock);
    assert_success(&project.raeva(&["sync", "--offline"]), "sync merge");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    let b = (lock.platforms[0].modules.iter())
        .find(|module| module.path == "b/pom.xml")
        .unwrap();
    assert!(has(b, "org.test:t:1.0"), "{b:?}");
}

/// One branch makes `b` depend on `u`, which adds an edge to `b`'s row; the
/// other on `w`, which imports the BOM `bom`. Taking the first branch's side
/// of each conflict drops `bom` from `b`'s row but keeps the other branch's
/// support POM row for it, which no graph of the merged lock read.
#[test]
fn a_support_pom_only_the_other_side_read_cannot_merge_into_the_lock() {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>b</module></modules></project>",
        ),
        ("b/pom.xml", &update_module("b", "")),
    ]);
    let root = project.root();
    release(&root, "t", "1.0", "", &["1.0"]);
    release(&root, "u", "1", &update_dependency("t", "1.0"), &["1"]);
    release(&root, "w", "1", "", &["1"]);
    publish(
        &root,
        "bom",
        &[(
            "bom-1.pom",
            b"<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
              <artifactId>bom</artifactId><version>1</version><packaging>pom</packaging>\
              </project>",
        )],
    );
    let dir = root.join("repository/org/test/w/1");
    let import = BOM_IMPORT.replace("1-SNAPSHOT", "1");
    let pom = fs::read_to_string(dir.join("w-1.pom"))
        .unwrap()
        .replace("<dependencies>", &format!("{import}<dependencies>"));
    fs::write(dir.join("w-1.pom"), &pom).unwrap();
    fs::write(
        dir.join("w-1.pom.sha256"),
        crate::common::sha256_hex(pom.as_bytes()),
    )
    .unwrap();
    let b = |dependencies: &str| {
        update_module(
            "b",
            &format!(
                "<dependencies>{}{dependencies}</dependencies>",
                update_dependency("t", "1.0")
            ),
        )
    };
    fs::write(root.join("b/pom.xml"), b("")).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync base");
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    for (branch, artifact) in [("left", "u"), ("right", "w")] {
        git(&root, &["switch", "-c", branch, "main"]);
        fs::write(root.join("b/pom.xml"), b(&update_dependency(artifact, "1"))).unwrap();
        assert_success(&project.raeva(&["sync", "--offline"]), artifact);
        git(&root, &["add", "b/pom.xml", "raeva.lock"]);
        git(&root, &["commit", "-m", "test: add a dependency"]);
    }
    git(&root, &["merge", "--no-edit", "-X", "theirs", "left"]);
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    assert!(
        lock.platforms[0]
            .support_poms
            .contains_key("org.test:bom:1")
    );
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        7,
        "frozen merge",
    );
    assert_success(&project.raeva(&["sync", "--offline"]), "sync merge");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    assert!(lock.platforms[0].support_poms.is_empty(), "{lock:?}");
}

/// `e` and `y` depend on `t:1.0`, or `t:2.0` when the property `v` is set.
/// One branch drops `a`'s dependency on `e`, the only reader of `v`, and sets
/// `-Dv`; the other makes `b` depend on `y`. `c` keeps `t:1.0` locked on both.
#[test]
fn a_dropped_property_name_and_a_new_reader_cannot_merge_into_a_stale_graph() {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module><module>b</module><module>c</module></modules>\
             </project>",
        ),
        ("a/pom.xml", &update_module("a", "")),
        ("b/pom.xml", &update_module("b", "")),
        ("c/pom.xml", &update_module("c", "")),
    ]);
    let root = project.root();
    release(&root, "t", "1.0", "", &["1.0", "2.0"]);
    release(&root, "t", "2.0", "", &["1.0", "2.0"]);
    for artifact in ["e", "y"] {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version><properties>\
             <tv>1.0</tv></properties><dependencies>{}</dependencies><profiles><profile>\
             <id>v</id><activation><property><name>v</name></property></activation>\
             <properties><tv>2.0</tv></properties></profile></profiles></project>",
            update_dependency("t", "${tv}")
        );
        let jar = format!("{artifact}-1.jar");
        publish(
            &root,
            artifact,
            &[
                (&format!("{artifact}-1.pom"), pom.as_bytes()),
                (&jar, b"jar"),
            ],
        );
    }
    let depend = |artifact, version| {
        format!(
            "<dependencies>{}</dependencies>",
            update_dependency(artifact, version)
        )
    };
    fs::write(
        root.join("a/pom.xml"),
        update_module("a", &depend("e", "1")),
    )
    .unwrap();
    fs::write(
        root.join("c/pom.xml"),
        update_module("c", &depend("t", "1.0")),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync base");
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    fs::write(root.join("a/pom.xml"), update_module("a", "")).unwrap();
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/maven.config"), "-Dv\n").unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync left");
    let left = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!left.contains("user-property:v"), "{left}");
    // The hash covers the maven.config name, so no later sync restores the
    // base hash.
    assert_success(
        &project.raeva(&["sync", "--offline", "--update"]),
        "sync left again",
    );
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: drop e and set v"]);
    git(&root, &["switch", "-c", "right", "main"]);
    fs::write(
        root.join("b/pom.xml"),
        update_module("b", &depend("y", "1")),
    )
    .unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync right");
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: depend on y"]);
    // The name changes every graph, so the locks can conflict.
    if !git_output(&root, &["merge", "--no-edit", "left"])
        .status
        .success()
    {
        git(&root, &["checkout", "--theirs", "raeva.lock"]);
    }
    let lock = fs::read(root.join("raeva.lock")).unwrap();
    assert!(
        !project
            .raeva(&["sync", "--frozen", "--offline"])
            .status
            .success()
    );
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), lock);
    assert_success(&project.raeva(&["sync", "--offline"]), "sync merge");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    let b = (lock.platforms[0].modules.iter())
        .find(|module| module.path == "b/pom.xml")
        .unwrap();
    assert!(has(b, "org.test:t:2.0"), "{b:?}");
}

/// `e` depends on `t:1.0`, or `t:2.0` when the property `v` is set, and `y`
/// the same on `w`. One branch makes `b` depend on `e`, the other `c` on
/// `y`, so both add a name nothing read before to the same `ambient_inputs`
/// hunk, while their rows are apart. Resolving it with `-X theirs`, or by
/// hand to one side, drops the other side's name, and setting that name on
/// the command line, or in the `.mvn/maven.config` of the side that dropped
/// it, must not pass `--frozen`. With `subset` the lock also records macOS,
/// and a sync of Linux alone with the name set must not keep its graph.
#[test]
fn a_property_name_one_side_of_a_conflict_drops_cannot_merge_into_a_stale_graph() {
    assert_ambient_hunk_merge_requires_relock(false, false, false);
    assert_ambient_hunk_merge_requires_relock(false, true, false);
    assert_ambient_hunk_merge_requires_relock(true, false, false);
    assert_ambient_hunk_merge_requires_relock(false, false, true);
}

fn assert_ambient_hunk_merge_requires_relock(by_hand: bool, maven_config: bool, subset: bool) {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module><module>b</module><module>c</module></modules>\
             </project>",
        ),
        ("a/pom.xml", &update_module("a", "")),
        ("b/pom.xml", &update_module("b", "")),
        ("c/pom.xml", &update_module("c", "")),
    ]);
    let root = project.root();
    release(&root, "t", "1.0", "", &["1.0", "2.0"]);
    release(&root, "t", "2.0", "", &["1.0", "2.0"]);
    release(&root, "m", "1", "", &["1"]);
    for (artifact, property) in [("e", "v"), ("y", "w")] {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version><properties>\
             <tv>1.0</tv></properties><dependencies>{}</dependencies><profiles><profile>\
             <id>{property}</id><activation><property><name>{property}</name></property>\
             </activation><properties><tv>2.0</tv></properties></profile></profiles></project>",
            update_dependency("t", "${tv}")
        );
        let jar = format!("{artifact}-1.jar");
        publish(
            &root,
            artifact,
            &[
                (&format!("{artifact}-1.pom"), pom.as_bytes()),
                (&jar, b"jar"),
            ],
        );
    }
    let depend = |artifact| {
        format!(
            "<dependencies>{}</dependencies>",
            update_dependency(artifact, "1")
        )
    };
    fs::write(
        root.join("a/pom.xml"),
        update_module(
            "a",
            &format!(
                "<dependencies>{}{}</dependencies>",
                update_dependency("t", "1.0"),
                update_dependency("m", "1")
            ),
        ),
    )
    .unwrap();
    let sync: &[&str] = match subset {
        true => &[
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64,macos-aarch64",
        ],
        false => &["sync", "--offline"],
    };
    assert_success(&project.raeva(sync), "sync base");
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    fs::write(root.join("c/pom.xml"), update_module("c", &depend("y"))).unwrap();
    if maven_config {
        fs::create_dir_all(root.join(".mvn")).unwrap();
        fs::write(root.join(".mvn/maven.config"), "-Dv\n").unwrap();
    }
    assert_success(&project.raeva(sync), "sync left");
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: depend on y"]);
    git(&root, &["switch", "-c", "right", "main"]);
    fs::write(root.join("b/pom.xml"), update_module("b", &depend("e"))).unwrap();
    assert_success(&project.raeva(sync), "sync right");
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: depend on e"]);
    let (dropped, module) = if by_hand {
        assert!(
            !git_output(&root, &["merge", "--no-edit", "left"])
                .status
                .success()
        );
        let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
        let mut kept = String::new();
        let mut side = None;
        for line in text.split_inclusive('\n') {
            if line.starts_with("<<<<<<<") {
                side = Some(true);
            } else if line.starts_with("=======") {
                side = Some(false);
            } else if line.starts_with(">>>>>>>") {
                side = None;
            } else if side != Some(false) {
                kept.push_str(line);
            }
        }
        fs::write(root.join("raeva.lock"), kept).unwrap();
        ("w", "c/pom.xml")
    } else {
        git(&root, &["merge", "--no-edit", "-X", "theirs", "left"]);
        ("v", "b/pom.xml")
    };
    let merged = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    let listed = &merged.resolution.ambient_inputs;
    assert!(
        !listed.contains(&rv_lock::AmbientInput::user_property(dropped).unwrap()),
        "{listed:?}"
    );
    let define = format!("-D{dropped}");
    let defines = if maven_config {
        &[][..]
    } else {
        &[define.as_str()]
    };
    let lock = fs::read(root.join("raeva.lock")).unwrap();
    let frozen = |platforms: &'static str| match subset {
        true => vec!["sync", "--frozen", "--offline", "--platforms", platforms],
        false => vec!["sync", "--frozen", "--offline"],
    };
    assert!(
        !project
            .raeva(&[&frozen("linux-x86_64,macos-aarch64"), defines].concat())
            .status
            .success()
    );
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), lock);
    let sync: &[&str] = match subset {
        true => &["sync", "--offline", "--platforms", "linux-x86_64"],
        false => &["sync", "--offline"],
    };
    assert_success(&project.raeva(&[sync, defines].concat()), "sync merge");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    for platform in &lock.platforms {
        let locked = (platform.modules.iter())
            .find(|locked| locked.path == module)
            .unwrap();
        assert!(has(locked, "org.test:t:2.0"), "{locked:?}");
    }
    assert_success(
        &project.raeva(&[&frozen("linux-x86_64"), defines].concat()),
        "frozen merge",
    );
}

/// Only macOS has module `m`, whose `e` takes `t:2.0` when `v` is 2 and
/// whose own profile on `v` being 3 is inactive either way. A sync of Linux
/// alone reads `v` only while it discovers the macOS model to keep its
/// graph. Under unchanged options that keeps it; with `v` set on the
/// command line and missing from the lock, which the macOS graph lists as
/// read, `--frozen` fails and a sync that resolves Linux again drops it.
#[test]
fn a_name_only_a_kept_platform_reads_decides_whether_it_is_kept() {
    let project = unlocked(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module></modules><profiles><profile><id>mac</id>\
             <activation><os><family>mac</family></os></activation>\
             <modules><module>m</module></modules></profile></profiles></project>",
        ),
        ("a/pom.xml", &update_module("a", "")),
        ("m/pom.xml", &update_module("m", "")),
    ]);
    let root = project.root();
    release(&root, "t", "1.0", "", &["1.0", "2.0"]);
    release(&root, "t", "2.0", "", &["1.0", "2.0"]);
    release(&root, "z", "1", "", &["1"]);
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>e</artifactId><version>1</version><properties><tv>1.0</tv>\
         </properties><dependencies>{}</dependencies><profiles><profile><id>v</id>\
         <activation><property><name>v</name><value>2</value></property></activation>\
         <properties><tv>2.0</tv></properties></profile></profiles></project>",
        update_dependency("t", "${tv}")
    );
    publish(
        &root,
        "e",
        &[("e-1.pom", pom.as_bytes()), ("e-1.jar", b"jar")],
    );
    fs::write(
        root.join("m/pom.xml"),
        update_module(
            "m",
            &format!(
                "<dependencies>{}</dependencies><profiles><profile><id>three</id>\
                 <activation><property><name>v</name><value>3</value></property>\
                 </activation><dependencies>{}</dependencies></profile></profiles>",
                update_dependency("e", "1"),
                update_dependency("z", "1")
            ),
        ),
    )
    .unwrap();
    let platforms = |lock: &rv_lock::Lockfile| {
        (lock.platforms.iter())
            .map(|platform| platform.platform.to_string())
            .collect::<Vec<_>>()
    };
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/maven.config"), "-Dv=2\n").unwrap();
    for platform in ["linux-x86_64", "macos-aarch64"] {
        assert_success(
            &project.raeva(&["sync", "--offline", "--platforms", platform]),
            platform,
        );
    }
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    assert_eq!(platforms(&lock).len(), 2, "{:?}", platforms(&lock));

    fs::remove_file(root.join(".mvn/maven.config")).unwrap();
    assert_success(
        &project.raeva(&[
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64,macos-aarch64",
        ]),
        "sync without v",
    );
    let lock_path = root.join("raeva.lock");
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    let m = (lock.platforms.iter())
        .flat_map(|platform| &platform.modules)
        .find(|module| module.path == "m/pom.xml")
        .unwrap();
    assert!(has(m, "org.test:t:1.0"), "{m:?}");
    let text = fs::read_to_string(&lock_path).unwrap();
    let name = "\"user-property:v\"";
    let at = text.find(name).expect("v is listed");
    let rest = text[at + name.len()..].trim_start_matches(',').trim_start();
    fs::write(&lock_path, format!("{}{rest}", &text[..at])).unwrap();
    let lock = fs::read(&lock_path).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", "linux-x86_64", "-Dv=2"]),
        "sync Linux with v",
    );
    assert_eq!(fs::read(&lock_path).unwrap(), lock);
    assert_status(
        &project.raeva(&[
            "sync",
            "--frozen",
            "--offline",
            "--platforms",
            "linux-x86_64,macos-aarch64",
            "-Dv=2",
        ]),
        7,
        "the macOS graph read v, which the lock misses",
    );
    let a = fs::read_to_string(root.join("a/pom.xml")).unwrap();
    fs::write(
        root.join("a/pom.xml"),
        a.replace("</project>", "<description>a</description></project>"),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", "linux-x86_64", "-Dv=2"]),
        "resolve Linux with v",
    );
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert_eq!(platforms(&lock), ["linux-x86_64"]);
    assert_success(
        &project.raeva(&[
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64,macos-aarch64",
            "-Dv=2",
        ]),
        "sync both with v",
    );
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    let m = (lock.platforms.iter())
        .flat_map(|platform| &platform.modules)
        .find(|module| module.path == "m/pom.xml")
        .unwrap();
    assert!(has(m, "org.test:t:2.0"), "{m:?}");
}

/// Only macOS has module `m`, whose repository URL reads `mrepo`. A sync
/// that resolves Linux again discovers the macOS model to drop it, and that
/// read does not bind the Linux graph.
#[test]
fn a_dropped_platforms_discovery_reads_do_not_bind_a_fresh_platform() {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module></modules><profiles><profile><id>mac</id>\
             <activation><os><family>mac</family></os></activation>\
             <modules><module>m</module></modules></profile></profiles></project>",
        ),
        ("a/pom.xml", &update_module("a", "")),
        (
            "m/pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>m</artifactId><version>1</version><properties>\
             <mrepo>https://repo.example.com/m2/</mrepo></properties><repositories>\
             <repository><id>m</id><url>${mrepo}</url></repository></repositories>\
             </project>",
        ),
    ]);
    let root = project.root();
    assert_success(
        &project.raeva(&[
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64,macos-aarch64",
        ]),
        "sync both",
    );
    for module in ["a", "m"] {
        let path = root.join(module).join("pom.xml");
        let pom = fs::read_to_string(&path).unwrap();
        let pom = pom.replace("</project>", "<description>edit</description></project>");
        fs::write(path, pom).unwrap();
    }
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", "linux-x86_64"]),
        "sync Linux, dropping macOS",
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!lock.contains("macos-aarch64"), "{lock}");
    assert!(!lock.contains("mrepo"), "{lock}");
    assert_success(
        &project.raeva(&[
            "sync",
            "--frozen",
            "--offline",
            "--platforms",
            "linux-x86_64",
            "-Dmrepo=https://other.example.com/m2/",
        ]),
        "no Linux graph reads mrepo",
    );
}

/// A sync of some platforms keeps the names of another only while that
/// platform's graphs list them, set or not.
#[test]
fn a_partial_sync_lists_what_each_platform_still_reads() {
    for define in [None, Some("-Dlo=1.0")] {
        let project = unlocked(&[
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                 <modules><module>a</module></modules><profiles><profile><id>linux</id>\
                 <activation><os><name>linux</name></os></activation>\
                 <modules><module>l</module></modules></profile></profiles></project>",
            ),
            ("a/pom.xml", &update_module("a", "")),
            ("l/pom.xml", &update_module("l", "")),
        ]);
        let root = project.root();
        release(&root, "t", "1.0", "", &["1.0"]);
        let l = |version: &str| {
            update_module(
                "l",
                &format!(
                    "<properties><lo>1.0</lo></properties><dependencies>{}</dependencies>",
                    update_dependency("t", version)
                ),
            )
        };
        let sync = |platforms: &str| {
            let mut args = vec!["sync", "--offline", "--platforms", platforms];
            args.extend(define);
            project.raeva(&args)
        };
        fs::write(root.join("l/pom.xml"), l("${lo}")).unwrap();
        assert_success(&sync("linux-x86_64,macos-aarch64"), "sync both");
        fs::write(root.join("l/pom.xml"), l("1.0")).unwrap();
        assert_success(&sync("linux-x86_64"), "sync Linux after l stops reading lo");
        let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
        assert_eq!(lock.platforms.len(), 2, "macOS is kept");
        assert_success(
            &project.raeva(&[
                "sync",
                "--frozen",
                "--offline",
                "--platforms",
                "linux-x86_64,macos-aarch64",
                "-Dlo=2",
            ]),
            &format!("no graph reads lo, synced with {define:?}"),
        );
    }
}

/// A reactor of `a` on every platform and `l` on Linux only.
fn linux_module_project(l: &str) -> Project {
    unlocked(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module></modules><profiles><profile><id>linux</id>\
             <activation><os><name>linux</name></os></activation>\
             <modules><module>l</module></modules></profile></profiles></project>",
        ),
        ("a/pom.xml", &update_module("a", "")),
        ("l/pom.xml", l),
    ])
}

fn edit_description(root: &Path, module: &str) {
    let path = root.join(module).join("pom.xml");
    let pom = fs::read_to_string(&path).unwrap();
    fs::write(
        path,
        pom.replace("</project>", "<description>edit</description></project>"),
    )
    .unwrap();
}

/// A sync of some platforms replaces the repository ids they used, so an
/// id only a re-resolved platform declared leaves the lock.
#[test]
fn a_partial_sync_drops_a_repository_id_only_its_platform_used() {
    let l = |id: &str| update_module("l", "").replace("<id>local</id>", &format!("<id>{id}</id>"));
    let project = linux_module_project(&l("old"));
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let both = [
        "sync",
        "--offline",
        "--platforms",
        "linux-x86_64,macos-aarch64",
    ];
    let frozen = [&both[..1], &["--frozen"], &both[1..]].concat();
    assert_success(&project.raeva(&both), "sync both");
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(lock.contains("\\told\n"), "{lock}");
    let full = lock;
    fs::write(root.join("l/pom.xml"), l("new")).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", "linux-x86_64"]),
        "sync Linux after l renames its repository",
    );
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(!lock.contains("\\told\n"), "{lock}");
    assert!(lock.contains("\\tnew\n"), "{lock}");
    edit_description(&root, "a");
    assert_success(
        &project.raeva(&frozen),
        "frozen resolves both after an edit and finds the same ids",
    );
    // Only Linux reads `old` and `new`, so the full lock lists them for it.
    fs::write(root.join("l/pom.xml"), l("old")).unwrap();
    fs::write(root.join("a/pom.xml"), update_module("a", "")).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", "linux-x86_64"]),
        "sync Linux back",
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), full);
}

/// A sync of some platforms replaces the conditions they tested, so one
/// only a re-resolved platform tested leaves the lock, and one a kept
/// platform tested stays.
#[test]
fn a_partial_sync_lists_the_conditions_each_platform_still_tests() {
    let profile = format!(
        "<profiles><profile><id>m</id><activation><file>\
         <exists>${{project.basedir}}/marker</exists></file></activation>\
         <dependencies>{}</dependencies></profile></profiles>",
        update_dependency("lib", "1.0")
    );
    let project = linux_module_project(&update_module("l", &profile));
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    fs::write(root.join("l/marker"), "").unwrap();
    let both = [
        "sync",
        "--offline",
        "--platforms",
        "linux-x86_64,macos-aarch64",
    ];
    let frozen = [&both[..1], &["--frozen"], &both[1..]].concat();
    assert_success(&project.raeva(&both), "sync both");
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(lock.contains("\"file:l/marker is true\""), "{lock}");
    fs::write(root.join("l/pom.xml"), update_module("l", "")).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "--platforms", "linux-x86_64"]),
        "sync Linux after l drops the profile",
    );
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(!lock.contains("marker"), "{lock}");
    fs::remove_file(root.join("l/marker")).unwrap();
    assert_success(&project.raeva(&frozen), "no platform tests the marker");

    // macOS keeps the condition its own module tests.
    fs::write(root.join("l/pom.xml"), update_module("l", &profile)).unwrap();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom.replace("<name>linux</name>", "<family>mac</family>"),
    )
    .unwrap();
    fs::write(root.join("l/marker"), "").unwrap();
    assert_success(&project.raeva(&both), "sync both with l on macOS");
    assert_success(
        &project.raeva(&["sync", "-u", "--offline", "--platforms", "linux-x86_64"]),
        "resolve Linux again",
    );
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(lock.contains("\"file:l/marker is true\""), "{lock}");
    fs::remove_file(root.join("l/marker")).unwrap();
    assert_status(
        &project.raeva(&frozen),
        7,
        "the macOS graph tested the marker",
    );
}

/// A condition two platforms test through one dependency stays while the
/// kept platform tests it, although the re-resolved one no longer does.
#[test]
fn a_partial_sync_keeps_a_shared_condition_a_kept_platform_tests() {
    let module = |name: &str, depends: bool| {
        let body = match depends {
            true => format!(
                "<dependencies>{}</dependencies>",
                update_dependency("e", "1")
            ),
            false => String::new(),
        };
        update_module(name, &body)
    };
    let project = unlocked(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module></modules><profiles><profile><id>linux</id>\
             <activation><os><name>linux</name></os></activation>\
             <modules><module>l</module></modules></profile><profile><id>mac</id>\
             <activation><os><family>mac</family></os></activation>\
             <modules><module>m</module></modules></profile></profiles></project>",
        ),
        ("a/pom.xml", &module("a", false)),
        ("l/pom.xml", &module("l", false)),
        ("m/pom.xml", &module("m", false)),
    ]);
    let root = project.root();
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>e</artifactId><version>1</version><profiles><profile><id>new</id>\
         <activation><jdk>[99,)</jdk></activation><dependencies>{}</dependencies>\
         </profile></profiles></project>",
        update_dependency("lib", "1.0")
    );
    publish(
        &root,
        "e",
        &[("e-1.pom", pom.as_bytes()), ("e-1.jar", b"jar")],
    );
    fs::write(root.join("l/pom.xml"), module("l", true)).unwrap();
    fs::write(root.join("m/pom.xml"), module("m", true)).unwrap();
    let no_jdk = root.join("no-jdk");
    let sync = |jdk: &str, args: &[&str]| {
        let env = [
            ("JAVA_HOME", no_jdk.to_str().unwrap()),
            ("JAVA_VERSION", jdk),
        ];
        project.raeva_with(&env, args)
    };
    let both = [
        "sync",
        "--offline",
        "--platforms",
        "linux-x86_64,macos-aarch64",
    ];
    let frozen = [&both[..1], &["--frozen"], &both[1..]].concat();
    assert_success(&sync("17", &both), "sync both");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("\"jdk:[99,) is false\""), "{lock}");
    assert!(
        !lock.contains("host_inputs"),
        "both platforms test it: {lock}"
    );
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "linux"]);
    fs::write(root.join("l/pom.xml"), module("l", false)).unwrap();
    assert_success(
        &sync("17", &["sync", "--offline", "--platforms", "linux-x86_64"]),
        "sync Linux after l drops e",
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("macos-aarch64"), "{lock}");
    // Linux no longer tests it, so Linux lists what it does test.
    assert!(lock.contains("host_inputs = []"), "{lock}");
    assert_status(&sync("99", &frozen), 7, "the macOS graph tests the JDK");

    // Each branch drops one platform's last reader; the merged lock lists
    // the condition although no target tests it, and is refused.
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: drop the Linux reader"]);
    git(&root, &["switch", "-c", "mac", "main"]);
    fs::write(root.join("m/pom.xml"), module("m", false)).unwrap();
    assert_success(
        &sync("17", &["sync", "--offline", "--platforms", "macos-aarch64"]),
        "sync macOS after m drops e",
    );
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: drop the macOS reader"]);
    git(&root, &["merge", "--no-edit", "linux"]);
    let output = sync("17", &frozen);
    assert_status(&output, 3, "the merged lock");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("which no target's inputs list"), "{stderr}");
    assert_success(&sync("17", &["sync", "--offline"]), "sync the merge");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!lock.contains("jdk:[99,)"), "{lock}");
}

/// A sync lists only the names its resolution read: one nothing reads any
/// more leaves the lock, set or not, and a sync that replaces a conflicted
/// lock keeps none of the names it lists either.
#[test]
fn a_property_name_nothing_reads_leaves_the_lock() {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module></modules></project>",
        ),
        ("a/pom.xml", &update_module("a", "")),
    ]);
    let root = project.root();
    release(&root, "t", "1.0", "", &["1.0", "2.0"]);
    release(&root, "t", "2.0", "", &["1.0", "2.0"]);
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>e</artifactId><version>1</version><properties><tv>1.0</tv>\
         </properties><dependencies>{}</dependencies><profiles><profile><id>v</id>\
         <activation><property><name>v</name></property></activation><properties>\
         <tv>2.0</tv></properties></profile></profiles></project>",
        update_dependency("t", "${tv}")
    );
    publish(
        &root,
        "e",
        &[("e-1.pom", pom.as_bytes()), ("e-1.jar", b"jar")],
    );
    let depend = format!(
        "<dependencies>{}</dependencies>",
        update_dependency("e", "1")
    );
    fs::write(root.join("a/pom.xml"), update_module("a", &depend)).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync with a reader");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("\"user-property:v\""), "{lock}");
    let hash = lock
        .lines()
        .find(|line| line.starts_with("config_hash"))
        .unwrap();
    let conflicted = lock.replacen(
        hash,
        &format!("<<<<<<< ours\n{hash}\n=======\nconfig_hash = \"0\"\n>>>>>>> theirs"),
        1,
    );
    fs::write(root.join("raeva.lock"), conflicted).unwrap();
    fs::write(root.join("a/pom.xml"), update_module("a", "")).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "regenerate");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!lock.contains("\"user-property:v\""), "{lock}");
    fs::write(root.join("a/pom.xml"), update_module("a", &depend)).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "-Dv"]),
        "sync a reader again",
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("\"user-property:v\""), "{lock}");
    fs::write(root.join("a/pom.xml"), update_module("a", "")).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "-Dv"]),
        "drop the reader",
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!lock.contains("user-property:v"), "{lock}");
    assert!(!lock.contains("-Dv"), "{lock}");
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen without the unread -Dv",
    );
}

/// Reactor BOM `a` manages `t` in a profile active by default, which the
/// profile `-Px` selects for the reactor turns off in `a`'s own build but not
/// in an import of `a`, which Maven builds without the selection.
#[test]
fn a_reactor_bom_profile_only_its_import_activates_cannot_merge_into_a_stale_graph() {
    assert_reactor_bom_merge_requires_relock(None, |version| {
        format!(
            "<packaging>pom</packaging><profiles><profile><id>x</id></profile><profile>\
             <id>dflt</id><activation><activeByDefault>true</activeByDefault></activation>\
             <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
             </profile></profiles>",
            update_dependency("t", version)
        )
    });
}

/// Reactor BOM `a` manages `t` itself, and the profile `-Px` selects
/// replaces that in `a`'s own build only.
#[test]
fn a_reactor_bom_management_its_own_profile_replaces_cannot_merge_into_a_stale_graph() {
    assert_reactor_bom_merge_requires_relock(None, |version| {
        format!(
            "<packaging>pom</packaging><dependencyManagement><dependencies>{}</dependencies>\
             </dependencyManagement><profiles><profile><id>x</id><dependencyManagement>\
             <dependencies>{}</dependencies></dependencyManagement></profile></profiles>",
            update_dependency("t", version),
            update_dependency("t", "9")
        )
    });
}

/// As the first case, but `a`'s local parent has a default profile of the
/// same id, which both builds activate, so only the POM that declares each
/// active `dflt` tells the builds apart.
#[test]
fn a_reactor_bom_profile_id_its_parent_shares_cannot_merge_into_a_stale_graph() {
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>ap</artifactId><version>1</version><packaging>pom</packaging><profiles>\
        <profile><id>dflt</id><activation><activeByDefault>true</activeByDefault></activation>\
        <properties><unrelated>1</unrelated></properties></profile></profiles></project>";
    assert_reactor_bom_merge_requires_relock(Some(parent), |version| {
        format!(
            "<parent><groupId>org.test</groupId><artifactId>ap</artifactId><version>1</version>\
             <relativePath>../ap/pom.xml</relativePath></parent>\
             <packaging>pom</packaging><profiles><profile><id>x</id></profile><profile>\
             <id>dflt</id><activation><activeByDefault>true</activeByDefault></activation>\
             <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
             </profile></profiles>",
            update_dependency("t", version)
        )
    });
}

/// Reactor BOM `a` adds the module `x` in a profile the JDK activates. An
/// import of `a` activates that profile too, though a module list does not
/// count there, so an edit to `c` changes only `c`'s record.
#[test]
fn a_reactor_bom_profile_its_import_activates_too_keeps_records_per_module() {
    let module = |name: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{name}</artifactId><version>1</version>{body}</project>"
        )
    };
    let import = "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
        <artifactId>a</artifactId><version>1</version><type>pom</type><scope>import</scope>\
        </dependency></dependencies></dependencyManagement>";
    let project = Project::synced_with(&[
        (
            "pom.xml",
            &module(
                "root",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                 <module>c</module></modules>",
            ),
        ),
        (
            "a/pom.xml",
            &module(
                "a",
                "<packaging>pom</packaging><profiles><profile><id>jdk17</id><activation>\
                 <jdk>[17,)</jdk></activation><modules><module>x</module></modules>\
                 </profile></profiles>",
            ),
        ),
        ("a/x/pom.xml", &module("x", "")),
        ("b/pom.xml", &module("b", import)),
        ("c/pom.xml", &module("c", "")),
    ]);
    let root = project.root();
    let no_java_home = root.join("no-java-home");
    let env = [
        ("JAVA_HOME", no_java_home.to_str().unwrap()),
        ("JAVA_VERSION", "21"),
    ];
    let records = |label| {
        assert_success(&project.raeva_with(&env, &["sync", "--offline"]), label);
        let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
        assert!(
            lock.platforms[0]
                .modules
                .iter()
                .any(|m| m.path == "a/x/pom.xml")
        );
        lock.platforms[0].model_inputs.clone().unwrap().pom_hashes
    };
    let before = records("sync under 21");
    fs::write(
        root.join("c/pom.xml"),
        module("c", "<description>edited</description>"),
    )
    .unwrap();
    let after = records("sync edit");
    let changed: Vec<_> = (before.iter())
        .filter(|(path, digest)| after.get(*path) != Some(*digest))
        .map(|(path, _)| path.as_str())
        .collect();
    assert_eq!(changed, ["c/pom.xml"]);
}

/// `.mvn/maven.config` selects the profile `x`. Reactor module `a`, with the
/// local parent `parent` when given, has the body `bom` gives for the
/// version of `t` it manages in an import. One branch changes that version;
/// the other makes `b` import `a` and use `t`.
fn assert_reactor_bom_merge_requires_relock(parent: Option<&str>, bom: impl Fn(&str) -> String) {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module><module>b</module><module>c</module></modules></project>",
        ),
        (
            "a/pom.xml",
            &update_module("a", "<packaging>pom</packaging>"),
        ),
        ("b/pom.xml", &update_module("b", "")),
        ("c/pom.xml", &update_module("c", "")),
    ]);
    let root = project.root();
    release(&root, "t", "1.0", "", &["1.0", "1.1"]);
    release(&root, "t", "1.1", "", &["1.0", "1.1"]);
    // Another module already pins both versions of t.
    fs::write(
        root.join("c/pom.xml"),
        update_module(
            "c",
            &format!(
                "<dependencies>{}</dependencies><profiles><profile><id>pin</id>\
                 <activation><activeByDefault>true</activeByDefault></activation>\
                 </profile></profiles>",
                update_dependency("t", "1.0")
            ),
        ),
    )
    .unwrap();
    if let Some(parent) = parent {
        fs::create_dir_all(root.join("ap")).unwrap();
        fs::write(root.join("ap/pom.xml"), parent).unwrap();
    }
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/maven.config"), "-Px\n").unwrap();
    fs::write(root.join("a/pom.xml"), update_module("a", &bom("1.0"))).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync base");
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    fs::write(root.join("a/pom.xml"), update_module("a", &bom("1.1"))).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync management");
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: change management"]);
    git(&root, &["switch", "-c", "right", "main"]);
    let import = "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
        <artifactId>a</artifactId><version>1</version><type>pom</type><scope>import</scope>\
        </dependency></dependencies></dependencyManagement><dependencies><dependency>\
        <groupId>org.test</groupId><artifactId>t</artifactId></dependency></dependencies>";
    fs::write(root.join("b/pom.xml"), update_module("b", import)).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync import");
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: import a"]);
    git(&root, &["merge", "--no-edit", "-X", "theirs", "left"]);
    let lock = fs::read(root.join("raeva.lock")).unwrap();
    assert!(
        !project
            .raeva(&["sync", "--frozen", "--offline"])
            .status
            .success()
    );
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), lock);
    assert_success(&project.raeva(&["sync", "--offline"]), "sync merge");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    let b = (lock.platforms[0].modules.iter())
        .find(|module| module.path == "b/pom.xml")
        .unwrap();
    assert!(has(b, "org.test:t:1.1"), "{b:?}");
}

#[test]
fn independent_adjacent_module_edits_merge_with_git_and_pass_frozen() {
    let root_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
        <repositories><repository><id>local</id><url>file://${project.basedir}/repository/</url>\
        </repository></repositories><modules><module>a</module><module>b</module></modules></project>";
    let module = |name| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent>\
        <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version></parent>\
        <artifactId>{name}</artifactId><repositories><repository><id>local</id>\
        <url>file://${{project.basedir}}/../repository/</url></repository></repositories><dependencies><dependency><groupId>org.test</groupId>\
        <artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>"
        )
    };
    let a = module("a");
    let b = module("b");
    let project = unlocked(&[("pom.xml", root_pom), ("a/pom.xml", &a), ("b/pom.xml", &b)]);
    let root = project.root();
    let sync = [
        "sync",
        "--offline",
        "--platforms",
        "linux-x86_64,windows-x86_64",
    ];
    let frozen = [
        "sync",
        "--frozen",
        "--offline",
        "--platforms",
        "linux-x86_64,windows-x86_64",
    ];
    assert_success(&project.raeva(&sync), "lock both platforms");
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    fs::write(
        root.join("a/pom.xml"),
        a.replace("</project>", "<description>left</description></project>"),
    )
    .unwrap();
    assert_success(&project.raeva(&sync), "sync left module edit");
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: edit module a"]);
    git(&root, &["switch", "-c", "right", "main"]);
    fs::write(
        root.join("b/pom.xml"),
        b.replace("</project>", "<description>right</description></project>"),
    )
    .unwrap();
    assert_success(&project.raeva(&sync), "sync right module edit");
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: edit module b"]);
    git(&root, &["merge", "--no-edit", "left"]);
    let bytes = fs::read(root.join("raeva.lock")).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(text.matches("[[platforms]]").count(), 1, "{text}");
    assert_eq!(text.matches("[[inputs]]").count(), 2, "{text}");
    assert!(!text.contains("model_hash"), "{text}");
    assert_success(&project.raeva(&frozen), "frozen merged tree");
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), bytes);
    let changed = fs::read_to_string(root.join("a/pom.xml"))
        .unwrap()
        .replace("</dependency>", "<scope>runtime</scope></dependency>");
    fs::write(root.join("a/pom.xml"), changed).unwrap();
    assert_status(&project.raeva(&frozen), 7, "dependency scope drift");
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), bytes);
}

fn parent_child_project() -> Project {
    Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
         <modules><module>a</module><module>b</module></modules></project>",
        ),
        (
            "a/pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><parent>\
         <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>\
         </parent><artifactId>a</artifactId><packaging>pom</packaging>\
         <properties><v>1.0</v></properties></project>",
        ),
        (
            "b/pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><parent>\
         <groupId>org.test</groupId><artifactId>a</artifactId><version>1</version>\
         <relativePath>../a/pom.xml</relativePath></parent><artifactId>b</artifactId>\
         <repositories><repository><id>local</id><url>file://${project.basedir}/../repository/</url>\
         </repository></repositories><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>",
        ),
    ])
}

#[test]
fn merged_parent_value_and_child_interpolation_refuse_stale_graph() {
    let project = parent_child_project();
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let base = rv_lock::Lockfile::read(&lock_path).unwrap();
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    git(&root, &["switch", "-c", "left"]);
    let parent = root.join("a/pom.xml");
    fs::write(
        &parent,
        fs::read_to_string(&parent)
            .unwrap()
            .replace("<v>1.0</v>", "<v>2.0</v>"),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync changed parent value",
    );
    let left = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert_eq!(base.platforms[0].artifacts, left.platforms[0].artifacts);
    assert_eq!(base.platforms[0].modules, left.platforms[0].modules);
    assert_eq!(
        base.platforms[0].model_inputs.as_ref().unwrap().pom_hashes["b/pom.xml"],
        left.platforms[0].model_inputs.as_ref().unwrap().pom_hashes["b/pom.xml"]
    );
    git(&root, &["add", "a/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: edit parent value"]);
    git(&root, &["switch", "-c", "right", "main"]);
    let child = root.join("b/pom.xml");
    fs::write(
        &child,
        fs::read_to_string(&child)
            .unwrap()
            .replace("<version>1.0</version>", "<version>${v}</version>"),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync child interpolation",
    );
    let right = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert_eq!(base.platforms[0].artifacts, right.platforms[0].artifacts);
    assert_eq!(base.platforms[0].modules, right.platforms[0].modules);
    git(&root, &["add", "b/pom.xml", "raeva.lock"]);
    git(&root, &["commit", "-m", "test: interpolate child version"]);
    git(&root, &["merge", "--no-edit", "left"]);
    let merged = fs::read(&lock_path).unwrap();
    let dir = root.join("repository/org/test/lib/2.0");
    fs::create_dir_all(&dir).unwrap();
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>lib</artifactId><version>2.0</version></project>";
    for (name, bytes) in [
        ("lib-2.0.pom", pom.as_bytes()),
        ("lib-2.0.jar", b"lib 2 jar".as_slice()),
    ] {
        fs::write(dir.join(name), bytes).unwrap();
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .unwrap();
    }
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        7,
        "merged inherited dependency drift",
    );
    assert_eq!(fs::read(&lock_path).unwrap(), merged);
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "resolve merged inheritance",
    );
    let updated = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert!(
        updated.platforms[0]
            .artifacts
            .iter()
            .any(|artifact| artifact.coord().gav.version() == "2.0")
    );
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen corrected graph",
    );
}

#[test]
fn parent_and_child_description_edits_merge_without_changing_other_records() {
    let project = parent_child_project();
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let base = rv_lock::Lockfile::read(&lock_path).unwrap();
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "test: record base"]);
    for (branch, path, unchanged) in [
        ("left", "a/pom.xml", "b/pom.xml"),
        ("right", "b/pom.xml", "a/pom.xml"),
    ] {
        git(&root, &["switch", "-c", branch, "main"]);
        let pom = root.join(path);
        fs::write(
            &pom,
            fs::read_to_string(&pom)
                .unwrap()
                .replace("</project>", "<description>edited</description></project>"),
        )
        .unwrap();
        assert_success(
            &project.raeva(&["sync", "--offline"]),
            "sync description edit",
        );
        let edited = rv_lock::Lockfile::read(&lock_path).unwrap();
        assert_eq!(
            base.platforms[0].model_inputs.as_ref().unwrap().pom_hashes[unchanged],
            edited.platforms[0]
                .model_inputs
                .as_ref()
                .unwrap()
                .pom_hashes[unchanged]
        );
        git(&root, &["add", path, "raeva.lock"]);
        git(&root, &["commit", "-m", "test: edit description"]);
    }
    git(&root, &["merge", "--no-edit", "left"]);
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "frozen merged descriptions",
    );
}

/// Twelve modules depend on `e`, whose profile on `v` picks `t`. More
/// modules than resolve at once, so the later ones reuse the model an
/// earlier one built. Every graph lists `v` as read, and `a` and twelve
/// more modules, which read nothing, list nothing, so `v` is no name most
/// modules read.
#[test]
fn every_module_that_reuses_a_model_lists_what_its_build_read() {
    let names: Vec<String> = (1..=12).map(|index| format!("m{index}")).collect();
    let others: Vec<String> = (1..=12).map(|index| format!("o{index}")).collect();
    let modules: String = (std::iter::once("a")
        .chain(names.iter().chain(&others).map(String::as_str)))
    .map(|name| format!("<module>{name}</module>"))
    .collect();
    let root_pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
         <modules>{modules}</modules></project>"
    );
    let mut files = vec![
        ("pom.xml".to_string(), root_pom),
        ("a/pom.xml".to_string(), update_module("a", "")),
    ];
    files.extend(
        (names.iter().chain(&others))
            .map(|name| (format!("{name}/pom.xml"), update_module(name, ""))),
    );
    let files: Vec<(&str, &str)> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let project = Project::synced_with(&files);
    let root = project.root();
    release(&root, "t", "1.0", "", &["1.0", "2.0"]);
    release(&root, "t", "2.0", "", &["1.0", "2.0"]);
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>e</artifactId><version>1</version><properties><tv>1.0</tv>\
         </properties><dependencies>{}</dependencies><profiles><profile><id>v</id>\
         <activation><property><name>v</name></property></activation>\
         <properties><tv>2.0</tv></properties></profile></profiles></project>",
        update_dependency("t", "${tv}")
    );
    publish(
        &root,
        "e",
        &[("e-1.pom", pom.as_bytes()), ("e-1.jar", b"jar")],
    );
    let depend = format!(
        "<dependencies>{}</dependencies>",
        update_dependency("e", "1")
    );
    for name in &names {
        fs::write(
            root.join(format!("{name}/pom.xml")),
            update_module(name, &depend),
        )
        .unwrap();
    }
    assert_success(&project.raeva(&["sync", "--offline"]), "sync");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    let inputs = lock.platforms[0].model_inputs.as_ref().unwrap();
    let v = rv_lock::AmbientInput::user_property("v").unwrap();
    for name in &names {
        let reads = inputs.module_ambient_inputs.get(&format!("{name}/pom.xml"));
        assert!(
            reads.is_some_and(|reads| reads.contains(&v)),
            "{name}: {inputs:?}"
        );
    }
    assert!(!inputs.ambient_inputs.contains(&v), "{inputs:?}");
    assert!(
        !inputs.module_ambient_inputs.contains_key("a/pom.xml"),
        "{inputs:?}"
    );
}

/// `b` reaches `e`, whose profile tests `env.FLAG` against a value too long
/// for raeva.lock, which then lists the variable instead, and `c` reads
/// the variable itself. `b`'s graph lists it too, so a merge that keeps
/// `c`'s read out cannot leave `b` trusted.
#[test]
fn a_condition_listed_as_its_variable_counts_for_the_graph_that_tested_it() {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>b</module><module>c</module></modules></project>",
        ),
        ("b/pom.xml", &update_module("b", "")),
        (
            "c/pom.xml",
            &update_module(
                "c",
                "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>unused</artifactId><version>${env.FLAG}</version></dependency>\
                 </dependencies></dependencyManagement>",
            ),
        ),
    ]);
    let root = project.root();
    fs::write(
        project.raeva_home().join("config.toml"),
        "[security]\nallow_env_substitution = ['FLAG']\n",
    )
    .unwrap();
    release(&root, "t", "1.0", "", &["1.0", "2.0"]);
    release(&root, "t", "2.0", "", &["1.0", "2.0"]);
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>e</artifactId><version>1</version><properties><tv>1.0</tv>\
         </properties><dependencies>{}</dependencies><profiles><profile><id>flag</id>\
         <activation><property><name>env.FLAG</name><value>{}</value></property>\
         </activation><properties><tv>2.0</tv></properties></profile></profiles></project>",
        update_dependency("t", "${tv}"),
        "x".repeat(300)
    );
    publish(
        &root,
        "e",
        &[("e-1.pom", pom.as_bytes()), ("e-1.jar", b"jar")],
    );
    let depend = format!(
        "<dependencies>{}</dependencies>",
        update_dependency("e", "1")
    );
    fs::write(root.join("b/pom.xml"), update_module("b", &depend)).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "sync");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    let flag = rv_lock::AmbientInput::env("FLAG").unwrap();
    assert!(
        lock.resolution.ambient_inputs.contains(&flag),
        "{:?}",
        lock.resolution
    );
    let inputs = lock.platforms[0].model_inputs.as_ref().unwrap();
    for module in ["b/pom.xml", "c/pom.xml"] {
        let reads = inputs.module_ambient_inputs.get(module);
        assert!(
            inputs.ambient_inputs.contains(&flag)
                || reads.is_some_and(|reads| reads.contains(&flag)),
            "{module}: {inputs:?}"
        );
    }
}

/// A `-D` name no graph reads, on the command line or in
/// `.mvn/maven.config`, leaves a sync and `--frozen` on the lock as written,
/// without resolving, and a sync that resolves writes the same bytes.
#[test]
fn an_unread_define_neither_resolves_nor_changes_the_lock() {
    let project = Project::synced();
    let root = project.root();
    let lock_path = root.join("raeva.lock");
    let lock = fs::read(&lock_path).unwrap();
    let checked = |args: &[&str], what: &str| {
        let out = project.raeva(args);
        assert_success(&out, what);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.starts_with("Checked"), "{what}: {stderr}");
        assert_eq!(fs::read(&lock_path).unwrap(), lock, "{what}");
    };
    checked(&["sync", "--offline", "-DskipTests"], "sync with -D");
    checked(
        &["sync", "--frozen", "--offline", "-DskipTests"],
        "frozen with -D",
    );
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/maven.config"), "-DskipTests\n").unwrap();
    checked(&["sync", "--offline"], "sync with maven.config");
    checked(
        &["sync", "--frozen", "--offline"],
        "frozen with maven.config",
    );
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom.replace("</project>", "<!-- edit --></project>"),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline", "-Dci.note"]),
        "resolve",
    );
    fs::remove_file(root.join(".mvn/maven.config")).unwrap();
    let with = fs::read(&lock_path).unwrap();
    fs::remove_file(&lock_path).unwrap();
    assert_success(&project.raeva(&["sync", "--offline"]), "resolve without");
    assert_eq!(fs::read(&lock_path).unwrap(), with);
}

#[test]
fn user_property_values_only_matter_when_a_model_looks_up_the_name() {
    let project = Project::synced();
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline", "-Dci.note=unused"]),
        "ignore unread command-line property",
    );
    let root = project.root();
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/maven.config"), "-Dci.note=unused\n").unwrap();
    assert_success(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        "ignore unread maven.config property",
    );
    let pom = fs::read_to_string(root.join("pom.xml"))
        .unwrap()
        .replace(
            "<version>1.0</version>",
            "<version>${lib.version}</version>",
        )
        .replace(
            "</project>",
            "<properties><lib.version>1.0</lib.version></properties></project>",
        );
    fs::write(root.join("pom.xml"), pom).unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "record an absent override",
    );
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(text.contains("user-property:lib.version"), "{text}");
    assert!(!text.contains("ci.note"), "{text}");
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline", "-Dlib.version=2.0"]),
        7,
        "adding a consulted override is drift",
    );
    assert_success(
        &project.raeva(&["sync", "--offline", "-Dlib.version=1.0"]),
        "record a read override",
    );
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        7,
        "removing a consulted override is drift",
    );
}

#[test]
fn conflicted_shared_graphs_recover_every_platform_and_jdk() {
    let project = Project::synced();
    let root = project.root();
    fs::write(root.join("raeva.toml"), "[lock]\njdks = [\"17\", \"21\"]\n").unwrap();
    assert_success(
        &project.raeva(&[
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64,windows-x86_64",
        ]),
        "lock four targets",
    );
    let path = root.join("raeva.lock");
    let original = fs::read_to_string(&path).unwrap();
    assert_eq!(original.matches("[[platforms]]").count(), 1);
    let graphs = original.split("[[inputs]]").next().unwrap();
    fs::write(
        &path,
        format!("<<<<<<< HEAD\n{graphs}=======\n{graphs}>>>>>>> branch\n"),
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "recover targets from conflicted graph lists",
    );
    let decoded = rv_lock::Lockfile::read(&path).unwrap();
    let names: Vec<_> = decoded
        .platforms
        .iter()
        .map(|entry| entry.platform.to_string())
        .collect();
    assert_eq!(
        names,
        [
            "linux-x86_64 (JDK 17)",
            "linux-x86_64 (JDK 21)",
            "windows-x86_64 (JDK 17)",
            "windows-x86_64 (JDK 21)"
        ]
    );
    assert_success(
        &project.raeva(&[
            "sync",
            "--frozen",
            "--offline",
            "--platforms",
            "linux-x86_64,windows-x86_64",
        ]),
        "frozen regenerated targets",
    );
}

#[test]
fn settings_activation_tracks_an_absent_user_property_lookup() {
    let project = Project::synced();
    fs::write(
        project.m2_settings(),
        "<settings><profiles><profile><id>extra</id>\
        <activation><property><name>settings.flag</name></property></activation>\
        <repositories><repository><id>extra</id><url>file://${settings.repo}/</url>\
        </repository></repositories></profile></profiles></settings>",
    )
    .unwrap();
    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "record absent settings activation override",
    );
    let text = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
    assert!(text.contains("user-property:settings.flag"), "{text}");
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline", "-Dsettings.flag=true"]),
        7,
        "settings override is drift",
    );
}

/// The remote parent `p` sets `v`, which picks `t`. An active settings.xml
/// profile that starts setting `v` makes the lock stale, though the lock
/// lists `v` only as a user property.
#[test]
fn a_settings_profile_that_sets_a_listed_name_makes_the_lock_stale() {
    let project = Project::synced();
    let root = project.root();
    release(&root, "t", "1.0", "", &["1.0", "2.0"]);
    release(&root, "t", "2.0", "", &["1.0", "2.0"]);
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>p</artifactId><version>1</version><packaging>pom</packaging>\
        <properties><v>1.0</v></properties></project>";
    publish(&root, "p", &[("p-1.pom", parent.as_bytes())]);
    fs::write(
        root.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>p</artifactId><version>1</version><relativePath/></parent>\
             <artifactId>root</artifactId><repositories><repository><id>local</id>\
             <url>file://${{project.basedir}}/repository/</url></repository></repositories>\
             <dependencies>{}</dependencies></project>",
            update_dependency("t", "${v}")
        ),
    )
    .unwrap();
    let settings = |properties: &str| {
        fs::write(
            project.m2_settings(),
            format!(
                "<settings><activeProfiles><activeProfile>dev</activeProfile></activeProfiles>\
                 <profiles><profile><id>dev</id>{properties}<repositories><repository>\
                 <id>local</id><url>file://{}/repository/</url></repository></repositories>\
                 </profile></profiles></settings>",
                root.display()
            ),
        )
        .unwrap();
    };
    settings("");
    assert_success(&project.raeva(&["sync", "--offline"]), "lock t 1.0");
    settings("<properties><v>2.0</v></properties>");
    assert_status(
        &project.raeva(&["sync", "--frozen", "--offline"]),
        7,
        "the settings value of v",
    );
}

#[test]
fn user_values_interpolated_into_activation_text_stay_out_of_the_lock() {
    let project = Project::synced();
    let path = project.root().join("pom.xml");
    let pom = fs::read_to_string(&path).unwrap().replace("</project>", "<profiles><profile><id>version</id>\
        <activation><jdk>${activation.version}</jdk></activation>\
        <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>\
        </profile><profile><id>named</id><activation><property><name>${activation.name}</name></property></activation>\
        <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>\
        </profile></profiles></project>");
    fs::write(&path, pom).unwrap();
    assert_success(
        &project.raeva(&[
            "sync",
            "--offline",
            "-Dactivation.version=private-jdk-value",
            "-Dactivation.name=private-property-value",
        ]),
        "sync with interpolated activation text",
    );
    let text = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
    assert!(text.contains("user-property:activation.version"), "{text}");
    assert!(text.contains("user-property-lookup:"), "{text}");
    assert!(text.contains("${activation.name}"), "{text}");
    assert!(!text.contains("private-jdk-value"), "{text}");
    assert!(!text.contains("private-property-value"), "{text}");
}

#[test]
fn dependency_pom_lookups_remain_inputs_during_a_frozen_check() {
    let project = Project::synced();
    let root = project.root();
    let pom = root.join("repository/org/test/lib/1.0/lib-1.0.pom");
    let text = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
        <artifactId>lib</artifactId><version>1.0</version><profiles><profile><id>flag</id>\
        <activation><property><name>dep.flag</name><value>on</value></property></activation>\
        <dependencies><dependency><groupId>org.test</groupId><artifactId>leaf</artifactId>\
        <version>1.0</version></dependency></dependencies></profile></profiles></project>";
    fs::write(&pom, text).unwrap();
    fs::write(
        pom.with_extension("pom.sha256"),
        crate::common::sha256_hex(text.as_bytes()),
    )
    .unwrap();
    fs::remove_file(root.join("raeva.lock")).unwrap();
    let home = tempfile::TempDir::new().unwrap();
    let env = [("RAEVA_HOME", home.path().to_str().unwrap())];
    let run = |args: &[&str]| project.raeva_with(&env, args);
    assert_success(
        &run(&["sync", "--offline"]),
        "lock a dependency's absent activation override",
    );
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(text.contains("user-property:dep.flag"), "{text}");
    let added = run(&[
        "sync",
        "--frozen",
        "--offline",
        "-Ddep.flag=private-off-value",
    ]);
    assert_status(&added, 7, "adding a dependency-only override is drift");
    assert!(String::from_utf8_lossy(&added.stderr).contains("-Ddep.flag is set here"));
    assert_success(
        &run(&["sync", "--offline", "-Ddep.flag=private-off-value"]),
        "record the dependency override",
    );
    assert_success(
        &run(&[
            "sync",
            "--frozen",
            "--offline",
            "-Ddep.flag=private-off-value",
            "-Dunread=ignored",
        ]),
        "same dependency-only override",
    );
    let changed = run(&[
        "sync",
        "--frozen",
        "--offline",
        "-Ddep.flag=another-private-value",
    ]);
    assert_status(&changed, 7, "changing a dependency-only override is drift");
    assert!(!String::from_utf8_lossy(&changed.stderr).contains("not set here"));
    let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!text.contains("private-off-value"), "{text}");
}

/// The graph digests cover the repository ids a lock lists, so a merge or
/// an edit that changes them without the graphs is not trusted.
#[test]
fn an_edited_repository_id_is_not_trusted() {
    let project = Project::synced_with(&[
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module></modules></project>",
        ),
        ("a/pom.xml", &update_module("a", "")),
    ]);
    let lock_path = project.root().join("raeva.lock");
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(lock.contains("\\tlocal\n"), "{lock}");
    fs::write(&lock_path, lock.replace("\\tlocal\n", "\\tother\n")).unwrap();
    let edited = fs::read(&lock_path).unwrap();
    for offline in [true, false] {
        let mut args = vec!["sync", "--frozen"];
        if offline {
            args.push("--offline");
        }
        assert_status(&project.raeva(&args), 7, &format!("{args:?}"));
        assert_eq!(fs::read(&lock_path).unwrap(), edited);
    }
}
