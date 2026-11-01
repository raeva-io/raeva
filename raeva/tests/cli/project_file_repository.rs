//! A `file:` repository that a project POM declares inside the project is
//! recorded in raeva.lock as a project-relative origin, so the lock stays valid
//! when the checkout moves, and the origin grants nothing that no current
//! declaration grants.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{assert_status, assert_success, run_raeva, with_sha256, write_repo_toml};

const LIB_POM: &[u8] = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>
</project>"#;
const LIB_JAR: &[u8] = b"lib artifact bytes";
const LIB_SOURCES: &[u8] = b"lib sources bytes";

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A repository that serves `org.test:lib:1.0` sources and records every
/// request, standing in for an origin the project never declared.
fn spawn_sources_server() -> (String, StubServer) {
    let server = StubServer::start(|request| {
        with_sha256(
            &request.path,
            [("/org/test/lib/1.0/lib-1.0-sources.jar", LIB_SOURCES)],
        )
    });
    (format!("http://{}/", server.addr()), server)
}

const NATIVE_POM: &[u8] = b"<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
<artifactId>native</artifactId><version>1.0</version></project>";
const NATIVE_DEPENDENCY: &str = "<dependency><groupId>org.test</groupId>\
<artifactId>native</artifactId><version>1.0</version></dependency>";

/// A loopback HTTP repository serving `org.test:native:1.0`, which raeva
/// reaches only when configuration or the project's own POM declares it.
fn spawn_native_repository() -> (String, StubServer) {
    let server = StubServer::start(|request| {
        with_sha256(
            &request.path,
            [
                ("/org/test/native/1.0/native-1.0.pom", NATIVE_POM),
                (
                    "/org/test/native/1.0/native-1.0.jar",
                    b"native jar".as_slice(),
                ),
            ],
        )
    });
    (format!("http://{}/", server.addr()), server)
}

fn publish_lib(repository: &Path) {
    let dir = repository.join("org/test/lib/1.0");
    fs::create_dir_all(&dir).expect("create repository");
    fs::write(dir.join("lib-1.0.pom"), LIB_POM).expect("write pom");
    fs::write(dir.join("lib-1.0.jar"), LIB_JAR).expect("write jar");
    fs::write(dir.join("lib-1.0-sources.jar"), LIB_SOURCES).expect("write sources");
}

fn pom(extra_repositories: &str, profiles: &str) -> String {
    format!(
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>root</artifactId><version>1</version>
  <repositories>
    <repository><id>project-local</id><url>file://${{project.basedir}}/repository/</url></repository>{extra_repositories}
  </repositories>
  <dependencies><dependency>
    <groupId>org.test</groupId><artifactId>lib</artifactId><version>1.0</version>
  </dependency></dependencies>{profiles}
</project>
"#
    )
}

/// A project whose only declared repositories are an empty HTTP repository in
/// raeva.toml (so resolution never reaches the network) and its own
/// `repository/` directory.
fn write_project(project: &Path, config_repo: &str, pom_text: &str) {
    fs::create_dir_all(project).expect("create project");
    publish_lib(&project.join("repository"));
    write_repo_toml(project, "stub", config_repo);
    fs::write(project.join("pom.xml"), pom_text).expect("write pom.xml");
}

fn empty_repository() -> (String, StubServer) {
    let server = StubServer::start(|_| Response::new(404, ""));
    (format!("http://{}/", server.addr()), server)
}

fn lib_dir(m2: &Path) -> PathBuf {
    m2.join("org/test/lib/1.0")
}

/// Fresh and `--frozen` reject a lock whose row points at an origin no
/// current declaration names. Once the POM declares that origin, export-m2
/// may fetch classifier jars from it.
#[test]
fn classifier_export_refuses_origins_no_declaration_names() {
    let base = TempDir::new().expect("base");
    let home = TempDir::new().expect("home");
    let (stub, _server) = empty_repository();
    let project = base.path().join("project");
    write_project(&project, &stub, &pom("", ""));
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "initial sync");
    let lock_path = project.join("raeva.lock");
    let original = fs::read_to_string(&lock_path).expect("read lock");

    let (elsewhere, server) = spawn_sources_server();
    let outside = base.path().join("outside");
    publish_lib(&outside);
    let outside_url = url::Url::from_directory_path(&outside).unwrap().to_string();
    let mut origins = vec![elsewhere.clone(), outside_url];
    if cfg!(unix) {
        #[cfg(unix)]
        std::os::unix::fs::symlink("repository", project.join("link")).expect("symlink");
        origins.push("./link/".to_string());
    }

    for origin in origins {
        let edited = original.replace(
            "repo_url = \"./repository/\"",
            &format!("repo_url = \"{origin}\""),
        );
        assert_ne!(edited, original);
        fs::write(&lock_path, &edited).expect("write edited lock");
        let m2 = TempDir::new().expect("m2");
        let frozen = run_raeva(&project, home.path(), &["sync", "--frozen"]);
        let export = run_raeva(
            &project,
            home.path(),
            &[
                "export-m2",
                "--with-sources",
                "--m2-path",
                m2.path().to_str().unwrap(),
            ],
        );
        for (label, output) in [("frozen", &frozen), ("export-m2", &export)] {
            assert_status(
                output,
                7,
                &format!("{origin}: {label} must reject an undeclared origin"),
            );
            assert!(
                stderr(output).contains("raeva.lock is out of date"),
                "{origin}: {label}: {}",
                stderr(output)
            );
        }
        assert!(
            !lib_dir(m2.path()).join("lib-1.0-sources.jar").exists(),
            "{origin}: sources exported from an undeclared origin"
        );
        assert!(
            server.requests().is_empty(),
            "{origin}: export-m2 contacted an undeclared origin"
        );
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), edited);
    }

    // Once the root POM declares the HTTP origin, the same row is authorized.
    // The lock is synced again for the new POM first, since export-m2 needs
    // a current lock.
    fs::write(&lock_path, &original).expect("restore the lock");
    fs::write(
        project.join("pom.xml"),
        pom(
            &format!("\n    <repository><id>pom-http</id><url>{elsewhere}</url></repository>"),
            "",
        ),
    )
    .expect("declare the HTTP origin");
    assert_success(
        &run_raeva(&project, home.path(), &["sync", "--offline"]),
        "sync with the declared origin",
    );
    let edited = fs::read_to_string(&lock_path).expect("read lock").replace(
        "repo_url = \"./repository/\"",
        &format!("repo_url = \"{elsewhere}\""),
    );
    fs::write(&lock_path, &edited).expect("write edited lock");
    let m2 = TempDir::new().expect("m2");
    let export = run_raeva(
        &project,
        home.path(),
        &[
            "export-m2",
            "--with-sources",
            "--m2-path",
            m2.path().to_str().unwrap(),
        ],
    );
    assert_success(&export, "export with a root-declared HTTP origin");
    assert_eq!(
        fs::read(lib_dir(m2.path()).join("lib-1.0-sources.jar")).expect("read sources"),
        LIB_SOURCES
    );
    assert!(
        server
            .requests()
            .iter()
            .any(|request| request.path.ends_with("lib-1.0-sources.jar"))
    );
}

/// A lock whose only other origins are ones the project's POM declares is
/// reused as written: a sync into an empty home restores the jars from
/// those origins without resolving, so the configured repository gets no
/// request, and a loopback one keeps the grant the declaration gives it.
#[test]
fn a_lock_with_a_pom_declared_origin_is_reused() {
    let base = TempDir::new().expect("base");
    let home = TempDir::new().expect("home");
    let (stub, server) = empty_repository();
    let (native, _native_server) = spawn_native_repository();
    let project = base.path().join("project");
    let pom_text = pom(
        &format!("\n    <repository><id>pom-http</id><url>{native}</url></repository>"),
        "",
    )
    .replace(
        "</dependency></dependencies>",
        &format!("</dependency>{NATIVE_DEPENDENCY}</dependencies>"),
    );
    write_project(&project, &stub, &pom_text);
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "initial sync");
    let lock = fs::read(project.join("raeva.lock")).expect("read lock");

    let cold = TempDir::new().expect("cold home");
    let requests = server.requests().len();
    let sync = run_raeva(&project, cold.path(), &["sync"]);
    assert_success(&sync, "sync from the lock");
    assert!(stderr(&sync).contains("Checked"), "{}", stderr(&sync));
    assert_eq!(server.requests().len(), requests, "the sync resolved again");
    assert_eq!(fs::read(project.join("raeva.lock")).unwrap(), lock);
}

/// A row that also names an origin nothing declares fails `--frozen`, so a
/// plain sync with the files in the store resolves again and drops it
/// rather than call the lock up to date.
#[test]
fn a_sync_drops_a_row_origin_nothing_declares() {
    let base = TempDir::new().expect("base");
    let home = TempDir::new().expect("home");
    let (stub, _server) = empty_repository();
    let project = base.path().join("project");
    write_project(&project, &stub, &pom("", ""));
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "initial sync");
    let lock_path = project.join("raeva.lock");
    let lock = fs::read_to_string(&lock_path).expect("read lock");
    let row = lock.find("[[platforms.artifacts]]").expect("a row");
    let line = row + lock[row..].find("\nrepo_url = ").expect("repo_url") + 1;
    let end = line + lock[line..].find('\n').expect("line end") + 1;
    let edited = format!(
        "{}other_repo_urls = [\"https://undeclared.example/\"]\n{}",
        &lock[..end],
        &lock[end..]
    );
    fs::write(&lock_path, &edited).expect("write lock");
    assert!(
        !run_raeva(&project, home.path(), &["sync", "--frozen"])
            .status
            .success()
    );
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), lock);
    assert_success(
        &run_raeva(&project, home.path(), &["sync", "--frozen"]),
        "frozen",
    );
}

/// Index bytes can match after a no-op upsert, so this reads `PRAGMA
/// data_version` on a connection held open across the sync. SQLite advances
/// that value when another connection commits.
#[test]
fn an_up_to_date_sync_leaves_the_store_index_alone() {
    let base = TempDir::new().expect("base");
    let home = TempDir::new().expect("home");
    let empty = base.path().join("empty");
    fs::create_dir(&empty).expect("empty repository");
    let stub = url::Url::from_directory_path(&empty).expect("repository URL");
    let project = base.path().join("project");
    write_project(&project, stub.as_str(), &pom("", ""));
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "initial sync");

    let index = store_index(home.path());
    let before = data_version(&index);
    let sync = run_raeva(&project, home.path(), &["sync"]);
    assert_success(&sync, "second sync");
    assert!(stderr(&sync).contains("Checked"), "{}", stderr(&sync));
    assert_eq!(
        data_version(&index),
        before,
        "an up-to-date sync wrote the store index"
    );
}

fn store_index(home: &Path) -> rusqlite::Connection {
    let path = home.join("store").join("index.sqlite");
    rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open store index")
}

fn data_version(index: &rusqlite::Connection) -> i64 {
    index
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .expect("read data_version")
}

/// A project repository that links to a directory elsewhere is recorded by
/// its place in the project, so the lock stays the same in a checkout whose
/// link points somewhere else. Windows needs a privilege to create links.
#[cfg(unix)]
#[test]
fn a_linked_project_repository_is_recorded_in_the_project() {
    let base = TempDir::new().expect("base");
    let project = base.path().join("project");
    let elsewhere = base.path().join("elsewhere");
    fs::create_dir_all(&project).expect("create project");
    fs::create_dir(&elsewhere).expect("create target");
    std::os::unix::fs::symlink(&elsewhere, project.join("repository")).expect("link");
    let (stub, _server) = empty_repository();
    write_project(&project, &stub, &pom("", ""));
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let lock = rv_lock::Lockfile::read(&project.join("raeva.lock")).expect("lock");
    assert_eq!(lock.platforms[0].artifacts[0].repo_url, "./repository/");
}

/// A repository only the POM declares, outside the project and spelled with
/// a `localhost` host, keeps its id: a frozen sync accepts the lock after a
/// harmless edit, and export labels its files with that id even when the
/// lock spells the origin as declared.
#[test]
fn a_pom_file_repository_keeps_its_id_however_it_is_spelled() {
    let base = TempDir::new().expect("base");
    let outside = base.path().join("corp");
    publish_lib(&outside);
    let corp = url::Url::from_directory_path(&outside)
        .unwrap()
        .to_string()
        .replacen("file:///", "file://localhost/", 1);
    let project = base.path().join("project");
    let (stub, _server) = empty_repository();
    let pom_text = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><repositories><repository>\
         <id>corp</id><url>{corp}</url></repository></repositories><dependencies>\
         <dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
         <version>1.0</version></dependency></dependencies></project>"
    );
    write_project(&project, &stub, &pom_text);
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");

    let lock_path = project.join("raeva.lock");
    let written = fs::read_to_string(&lock_path).expect("read lock");
    let mut lock = rv_lock::Lockfile::read(&lock_path).expect("lock");
    let id = lock.repo_ids.pop_first().expect("corp id").1;
    assert_eq!(id, ["corp".to_string()].into());
    lock.repo_ids.insert(corp.clone(), id);
    fs::write(&lock_path, lock.to_toml().unwrap()).expect("write lock");
    let m2 = base.path().join("m2");
    let export = run_raeva(
        &project,
        home.path(),
        &["export-m2", "--m2-path", m2.to_str().unwrap()],
    );
    assert_success(&export, "export");
    let markers =
        fs::read_to_string(lib_dir(&m2).join("_remote.repositories")).expect("read markers");
    assert!(markers.contains("lib-1.0.jar>corp="), "{markers}");

    fs::write(&lock_path, written).expect("restore lock");
    fs::write(
        project.join("pom.xml"),
        pom_text.replace("</project>", "<!-- edit --></project>"),
    )
    .expect("edit pom");
    let frozen = run_raeva(&project, home.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "frozen sync after a harmless edit");
}

/// An export covers every platform raeva.lock records, so on an empty home
/// `sync --frozen`, or `lock verify --download` after a sync of the current
/// platform only, fetches the files of the others too, POMs included.
#[test]
fn a_cold_home_gets_every_locked_platform_for_export() {
    let base = TempDir::new().expect("base");
    let project = base.path().join("project");
    // Configured, so verify needs no resolution to trust the origin, and
    // spelled as `${project.basedir}` spells the directory: canonical, as a
    // temporary directory on macOS is not.
    let canonical = dunce::canonicalize(base.path()).expect("canonical base");
    let repository = url::Url::from_directory_path(canonical.join("project/repository")).unwrap();
    let (family, other) = if cfg!(windows) {
        ("unix", "linux-x86_64")
    } else {
        ("windows", "windows-x86_64")
    };
    let profile = format!(
        "\n  <profiles><profile><id>native</id><activation><os><family>{family}</family></os>\
         </activation><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>native</artifactId><version>1.0</version></dependency></dependencies>\
         </profile></profiles>"
    );
    write_project(&project, repository.as_str(), &pom("", &profile));
    let native = project.join("repository/org/test/native/1.0");
    fs::create_dir_all(&native).expect("create native dir");
    fs::write(
        native.join("native-1.0.pom"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>native</artifactId><version>1.0</version></project>",
    )
    .expect("write native pom");
    fs::write(native.join("native-1.0.jar"), b"native jar").expect("write native jar");
    let current = rv_lock::Platform::current().expect("platform").to_string();
    let platforms = format!("{current},{other}");
    let home = TempDir::new().expect("home");
    let sync = run_raeva(&project, home.path(), &["sync", "--platforms", &platforms]);
    assert_success(&sync, "sync of two platforms");

    let export = |home: &Path, name: &str| {
        let m2 = base.path().join(name);
        let output = run_raeva(
            &project,
            home,
            &["export-m2", "--m2-path", m2.to_str().unwrap()],
        );
        (
            output,
            m2.join("org/test/native/1.0/native-1.0.pom").is_file(),
        )
    };
    let cold = TempDir::new().expect("cold home");
    let frozen = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "frozen sync");
    let (output, exported) = export(cold.path(), "m2-frozen");
    assert_success(&output, "export after a frozen sync");
    assert!(exported);

    let cold = TempDir::new().expect("cold home");
    let frozen = run_raeva(
        &project,
        cold.path(),
        &["sync", "--frozen", "--platforms", &current],
    );
    assert_success(&frozen, "frozen sync of the current platform");
    let (output, _) = export(cold.path(), "m2-partial");
    assert_status(&output, 7, "export of a partial frozen home");
    let verify = run_raeva(&project, cold.path(), &["lock", "verify", "--download"]);
    assert_success(&verify, "verify --download");
    let (output, exported) = export(cold.path(), "m2-verified");
    assert_success(&output, "export after verify --download");
    assert!(exported);
}

/// `sync --frozen` downloads a platform it does not check from the
/// repositories that platform's own model declares: here a loopback one
/// only an OS-activated profile names, which keeps its grant too.
#[test]
fn a_frozen_sync_trusts_what_each_downloaded_platform_declares() {
    let base = TempDir::new().expect("base");
    let (stub, _server) = empty_repository();
    let (native, _native_server) = spawn_native_repository();
    let (family, other) = if cfg!(windows) {
        ("unix", "linux-x86_64")
    } else {
        ("windows", "windows-x86_64")
    };
    let profile = format!(
        "\n  <profiles><profile><id>native</id><activation><os><family>{family}</family></os>\
         </activation><repositories><repository><id>native-http</id><url>{native}</url>\
         </repository></repositories><dependencies>{NATIVE_DEPENDENCY}</dependencies>\
         </profile></profiles>"
    );
    let project = base.path().join("project");
    write_project(&project, &stub, &pom("", &profile));
    let current = rv_lock::Platform::current().expect("platform").to_string();
    let home = TempDir::new().expect("home");
    let sync = run_raeva(
        &project,
        home.path(),
        &["sync", "--platforms", &format!("{current},{other}")],
    );
    assert_success(&sync, "sync of two platforms");

    let cold = TempDir::new().expect("cold home");
    let frozen = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "frozen sync");
}

/// A token that names an in-project directory through a symlink no current
/// declaration uses is undeclared: `--frozen --offline` resolves afresh and
/// reports the drift, and `lock verify --download` will not fetch from it.
#[cfg(unix)]
#[test]
fn an_undeclared_symlink_token_grants_nothing() {
    let base = TempDir::new().expect("base");
    let home = TempDir::new().expect("home");
    let (stub, _server) = empty_repository();
    let project = base.path().join("project");
    write_project(&project, &stub, &pom("", ""));
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "initial sync");
    std::os::unix::fs::symlink("repository", project.join("link")).expect("symlink");
    let lock_path = project.join("raeva.lock");
    let edited = fs::read_to_string(&lock_path)
        .expect("read lock")
        .replace("repo_url = \"./repository/\"", "repo_url = \"./link/\"");
    fs::write(&lock_path, &edited).expect("write edited lock");

    let frozen = run_raeva(&project, home.path(), &["sync", "--frozen", "--offline"]);
    assert_status(&frozen, 7, "frozen sync of undeclared symlink token");
    assert!(
        stderr(&frozen).contains("origin ./link/ -> ./repository/"),
        "{}",
        stderr(&frozen)
    );

    // Verify resolves the project to learn what its POMs declare, which
    // fetches the jar from `./repository/` as sync would, but downloads
    // nothing for the row that names `./link/`.
    let cold = TempDir::new().expect("cold home");
    let verify = run_raeva(&project, cold.path(), &["lock", "verify", "--download"]);
    assert_status(&verify, 7, "verify --download of undeclared symlink token");
    let verify_output = format!(
        "{}{}",
        String::from_utf8_lossy(&verify.stdout),
        stderr(&verify)
    );
    assert!(
        verify_output.contains("untrusted origin ./link/"),
        "{verify_output}"
    );
    let cold = TempDir::new().expect("cold home");
    let verify = run_raeva(
        &project,
        cold.path(),
        &["--json", "lock", "verify", "--download"],
    );
    let envelope: serde_json::Value = serde_json::from_slice(&verify.stdout).expect("verify JSON");
    assert_eq!(envelope["data"]["downloaded"], 0, "{envelope}");
    assert_eq!(envelope["data"]["untrusted_origin"], 2, "{envelope}");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), edited);
}

/// A malformed origin is reported without its text, both by a reader that
/// refuses the lock and by the plain sync that regenerates it, because the
/// text may be a URL with credentials.
#[test]
fn a_malformed_origin_is_not_repeated_in_errors() {
    let base = TempDir::new().expect("base");
    let home = TempDir::new().expect("home");
    let (stub, _server) = empty_repository();
    let project = base.path().join("project");
    write_project(&project, &stub, &pom("", ""));
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "initial sync");
    let lock_path = project.join("raeva.lock");
    let original = fs::read_to_string(&lock_path).expect("read lock");
    let secret = ".https://user:s3cret@repo.example/";

    for (label, edited) in [
        (
            "artifact row",
            original.replace(
                "repo_url = \"./repository/\"",
                &format!("repo_url = \"{secret}\""),
            ),
        ),
        (
            "repo_ids key",
            original.replace("./repository/\\t", &format!("{secret}\\t")),
        ),
    ] {
        assert_ne!(edited, original, "{label}");
        fs::write(&lock_path, &edited).expect("write edited lock");
        let tree = run_raeva(&project, home.path(), &["tree"]);
        assert_status(&tree, 3, &format!("{label}: tree of malformed origin"));
        assert!(
            !stderr(&tree).contains("s3cret"),
            "{label}: {}",
            stderr(&tree)
        );

        let sync = run_raeva(&project, home.path(), &["sync"]);
        assert_success(&sync, &format!("{label}: regenerating sync"));
        assert!(
            stderr(&sync).contains("regenerating raeva.lock") && !stderr(&sync).contains("s3cret"),
            "{label}: {}",
            stderr(&sync)
        );
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), original, "{label}");
    }
}
