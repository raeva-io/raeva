//! Repositories that a remote parent of the project declares are used, as
//! Maven uses them, but they do not get the trust of repositories the user
//! named: a host that resolves to a private address is refused unless the
//! configuration or the project's own POM names it, or the transitive
//! repository allowlist approves it.

use std::sync::{Arc, OnceLock};

use crate::common::{
    assert_status, assert_success, raeva_command, sha1_hex, with_sha1, write_repo_toml,
};
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

const LIB_POM: &str = "<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version></project>";
const LIB_JAR: &str = "lib jar";

fn spawn_declared_repository() -> StubServer {
    StubServer::start(|request| {
        with_sha1(
            &request.path,
            [
                ("/declared/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
                ("/declared/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
            ],
        )
    })
}

/// A repository serving the project's parent, which declares `urls` in
/// order, and `lib` under `/fallback/`. [`FALLBACK`] in `urls` stands for
/// that path on this server. `properties` go in the parent's `<properties>`.
fn spawn_parent_repository(urls: &[String], properties: &str) -> StubServer {
    let urls = urls.to_vec();
    let properties = properties.to_string();
    let own_addr = Arc::new(OnceLock::<String>::new());
    let addr = Arc::clone(&own_addr);
    let server = StubServer::start(move |request| {
        let repositories: String = urls
            .iter()
            .enumerate()
            .map(|(index, url)| {
                let url = match url.as_str() {
                    FALLBACK => format!("http://{}/fallback/", addr.get().expect("address")),
                    url => url.to_string(),
                };
                format!("<repository><id>declared{index}</id><url>{url}</url></repository>")
            })
            .collect();
        let parent = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>corp-parent</artifactId><version>1.0</version><packaging>pom</packaging>\
<properties>{properties}</properties><repositories>{repositories}</repositories></project>"
        );
        with_sha1(
            &request.path,
            [
                (
                    "/maven/com/example/corp-parent/1.0/corp-parent-1.0.pom",
                    parent.as_str(),
                ),
                ("/fallback/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
                ("/fallback/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
            ],
        )
    });
    own_addr
        .set(server.addr().to_string())
        .expect("address set once");
    server
}

const FALLBACK: &str = "fallback";

fn project(configured: &str, own_repository: Option<&str>) -> TempDir {
    let dir = tempfile::tempdir().expect("project dir");
    let repositories = own_repository
        .map(|url| {
            format!(
                "<repositories><repository><id>own</id><url>{url}</url></repository></repositories>"
            )
        })
        .unwrap_or_default();
    std::fs::write(
        dir.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>com.example</groupId><artifactId>corp-parent</artifactId><version>1.0</version>\
<relativePath/></parent>\
<artifactId>app</artifactId>{repositories}<dependencies><dependency>\
<groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>\
</dependency></dependencies></project>"
        ),
    )
    .expect("write pom.xml");
    write_repo_toml(dir.path(), "configured", configured);
    dir
}

/// `localhost` resolves to a loopback address and is not the configured
/// host (`127.0.0.1`), so the address screen applies to it.
fn declared_url(server: &StubServer) -> String {
    format!("http://localhost:{}/declared/", server.addr().port())
}

fn sync(project: &TempDir, home: &TempDir) -> std::process::Output {
    raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .arg("sync")
        .output()
        .expect("run raeva sync")
}

#[test]
fn a_remote_parents_repository_on_a_private_address_is_refused() {
    let declared = spawn_declared_repository();
    let configured = spawn_parent_repository(&[declared_url(&declared)], "");
    let project = project(&format!("http://{}/maven/", configured.addr()), None);
    let home = tempfile::tempdir().expect("home");

    let output = sync(&project, &home);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_status(&output, 5, "private address a remote POM names");
    assert_eq!(
        declared.answered(),
        0,
        "raeva must not connect to a private address a remote POM names: {stderr}"
    );
}

#[test]
fn the_projects_own_repository_on_a_private_address_is_used() {
    let declared = spawn_declared_repository();
    let configured = spawn_parent_repository(&[declared_url(&declared)], "");
    let project = project(
        &format!("http://{}/maven/", configured.addr()),
        Some(&declared_url(&declared)),
    );
    let home = tempfile::tempdir().expect("home");

    let output = sync(&project, &home);
    assert_success(&output, "project repository on a private address");
    assert!(
        declared.answered() > 0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn an_allowlisted_remote_parent_repository_on_a_private_address_is_used() {
    let declared = spawn_declared_repository();
    let configured = spawn_parent_repository(&[declared_url(&declared)], "");
    let project = project(&format!("http://{}/maven/", configured.addr()), None);
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "[security]\ntransitive_repository_allowlist = [\"{}\"]\n",
            declared_url(&declared)
        ),
    )
    .expect("write config.toml");

    let output = sync(&project, &home);
    assert_success(&output, "allowlisted remote parent repository");
    assert!(
        declared.answered() > 0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_remote_parents_file_repository_is_refused() {
    let local = tempfile::tempdir().expect("local repository");
    let lib = local.path().join("org/example/lib/1.0");
    std::fs::create_dir_all(&lib).expect("create lib dir");
    for (name, body) in [("lib-1.0.pom", LIB_POM), ("lib-1.0.jar", LIB_JAR)] {
        std::fs::write(lib.join(name), body).expect("write lib file");
        std::fs::write(lib.join(format!("{name}.sha1")), sha1_hex(body.as_bytes()))
            .expect("write lib checksum");
    }
    let local_url = url::Url::from_directory_path(local.path())
        .expect("file URL")
        .to_string();
    let configured = spawn_parent_repository(&[local_url], "");
    let project = project(&format!("http://{}/maven/", configured.addr()), None);
    let home = tempfile::tempdir().expect("home");

    let output = sync(&project, &home);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_status(&output, 5, "remote parent file repository");
    assert!(stderr.contains("FETCHED_POM_REPO_REFUSED"), "{stderr}");
    assert!(!project.path().join("raeva.lock").exists(), "{stderr}");
}

/// A repository in the project's own POM whose URL comes from a property
/// the remote parent defines gets that parent's trust, so its private
/// address is refused. The same URL given with `-D` in `.mvn/maven.config`
/// is the user's.
#[test]
fn a_project_repository_url_from_a_remote_parents_property_gets_the_parents_trust() {
    let declared = spawn_declared_repository();
    let configured = spawn_parent_repository(
        &[],
        &format!("<repo.url>{}</repo.url>", declared_url(&declared)),
    );
    let project = project(
        &format!("http://{}/maven/", configured.addr()),
        Some("${repo.url}"),
    );
    let home = tempfile::tempdir().expect("home");

    let output = sync(&project, &home);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_status(&output, 5, "project repository URL from a fetched parent");
    assert!(
        stderr.contains("PROJECT_REPO_URL_FROM_FETCHED_POM"),
        "{stderr}"
    );
    assert_eq!(declared.answered(), 0, "{stderr}");

    std::fs::create_dir(project.path().join(".mvn")).expect("create .mvn");
    std::fs::write(
        project.path().join(".mvn/maven.config"),
        format!("-Drepo.url={}\n", declared_url(&declared)),
    )
    .expect("write maven.config");
    let output = sync(&project, &home);
    assert_success(&output, "maven.config repository URL");
    assert!(
        declared.answered() > 0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_project_repository_url_through_a_local_model_field_gets_the_parents_trust() {
    let repository = tempfile::tempdir().expect("parent repository");
    let parent = repository.path().join("com/example/corp-parent/1.0");
    std::fs::create_dir_all(&parent).expect("create parent directory");
    std::fs::write(
        parent.join("corp-parent-1.0.pom"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
         <artifactId>corp-parent</artifactId><version>1.0</version><packaging>pom</packaging>\
         <properties><host>localhost</host></properties></project>",
    )
    .expect("write parent POM");
    let configured = url::Url::from_directory_path(repository.path())
        .expect("repository URL")
        .to_string();
    for field in ["artifactId", "packaging"] {
        let project = project(
            &configured,
            Some(&format!("http://${{project.{field}}}:9/declared/")),
        );
        let pom = project.path().join("pom.xml");
        let original = std::fs::read_to_string(&pom).expect("read pom.xml");
        let fields = if field == "artifactId" {
            "<artifactId>${host}</artifactId>"
        } else {
            "<artifactId>app</artifactId><packaging>${host}</packaging>"
        };
        std::fs::write(
            &pom,
            original.replace("<artifactId>app</artifactId>", fields),
        )
        .expect("write pom.xml");
        let home = tempfile::tempdir().expect("home");
        std::fs::create_dir(home.path().join(".m2")).expect("create .m2");
        std::fs::write(
            home.path().join(".m2/settings.xml"),
            "<settings><servers><server><id>own</id><username>ci</username>\
             <password>private-password</password></server></servers></settings>",
        )
        .expect("write settings.xml");

        let output = sync(&project, &home);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_status(&output, 5, &format!("repository URL through {field}"));
        for warning in [
            "PROJECT_REPO_URL_FROM_FETCHED_POM",
            "ID_CREDENTIAL_WITHHELD",
        ] {
            assert!(stderr.contains(warning), "{field}: {stderr}");
        }
        assert!(
            stderr.contains("target address is not globally routable"),
            "{field}: {stderr}"
        );
        assert!(
            !project.path().join("raeva.lock").exists(),
            "{field}: {stderr}"
        );
    }
}

/// A fresh clone's plain sync restores a lock whose artifact comes from a
/// repository only the remote parent declares, and does not resolve it
/// again: a newer version in range does not replace the locked one.
#[test]
fn a_fresh_clone_keeps_a_lock_from_a_remote_parents_repository() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let released = Arc::new(AtomicBool::new(false));
    let newer = Arc::clone(&released);
    let own_addr = Arc::new(OnceLock::<String>::new());
    let addr = Arc::clone(&own_addr);
    let server = StubServer::start(move |request| {
        let parent = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>corp-parent</artifactId><version>1.0</version><packaging>pom</packaging>\
<repositories><repository><id>declared</id><url>http://{}/fallback/</url></repository>\
</repositories></project>",
            addr.get().expect("address")
        );
        let versions = if newer.load(Ordering::SeqCst) {
            "<version>1.0</version><version>1.1</version>"
        } else {
            "<version>1.0</version>"
        };
        let metadata = format!(
            "<metadata><groupId>org.example</groupId><artifactId>lib</artifactId>\
<versioning><versions>{versions}</versions></versioning></metadata>"
        );
        let lib = |version: &str| {
            LIB_POM.replace(
                "<version>1.0</version>",
                &format!("<version>{version}</version>"),
            )
        };
        let lib_10 = lib("1.0");
        let lib_11 = lib("1.1");
        with_sha1(
            &request.path,
            [
                (
                    "/maven/com/example/corp-parent/1.0/corp-parent-1.0.pom",
                    parent.as_str(),
                ),
                (
                    "/fallback/org/example/lib/maven-metadata.xml",
                    metadata.as_str(),
                ),
                ("/fallback/org/example/lib/1.0/lib-1.0.pom", lib_10.as_str()),
                ("/fallback/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
                ("/fallback/org/example/lib/1.1/lib-1.1.pom", lib_11.as_str()),
                ("/fallback/org/example/lib/1.1/lib-1.1.jar", LIB_JAR),
            ],
        )
    });
    own_addr
        .set(server.addr().to_string())
        .expect("address set once");
    let project = project(&format!("http://{}/maven/", server.addr()), None);
    let pom = project.path().join("pom.xml");
    let ranged = std::fs::read_to_string(&pom)
        .expect("read pom.xml")
        .replace(
            "<version>1.0</version>\n</dependency>",
            "<version>[1.0,2.0)</version>\n</dependency>",
        )
        .replace(
            "<version>1.0</version></dependency>",
            "<version>[1.0,2.0)</version></dependency>",
        );
    std::fs::write(&pom, ranged).expect("write pom.xml");

    let output = sync(&project, &tempfile::tempdir().expect("home"));
    assert_success(&output, "ranged lock");
    let lock = std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
    assert!(lock.contains("/fallback/"), "{lock}");
    assert!(lock.contains("version = \"1.0\""), "{lock}");

    released.store(true, Ordering::SeqCst);
    let output = sync(&project, &tempfile::tempdir().expect("fresh home"));
    assert_success(&output, "fresh clone keeps ranged lock");
    assert_eq!(
        std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock"),
        lock,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A locked release that moves from its repository, configured or declared
/// in the project's POM, to one only the remote parent declares, with the
/// same bytes, still restores into a fresh home: Maven searches the
/// parent's repositories too. So does one whose first repository now
/// serves other bytes for the jar alone, through the resolution that finds
/// its POM in the parent's repository, but a restore of the lock alone stops
/// at those bytes.
#[test]
fn a_release_moved_to_a_remote_parents_repository_restores() {
    for (own, replaced) in [(false, false), (true, false), (false, true)] {
        check_release_moved_to_the_parents_repository(own, replaced);
    }
}

fn check_release_moved_to_the_parents_repository(own: bool, replaced: bool) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let moved = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&moved);
    let own_addr = Arc::new(OnceLock::<String>::new());
    let addr = Arc::clone(&own_addr);
    let first = if own { "/own" } else { "/maven" };
    let server = StubServer::start(move |request| {
        let parent = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>corp-parent</artifactId><version>1.0</version><packaging>pom</packaging>\
<repositories><repository><id>declared</id><url>http://{}/fallback/</url></repository>\
</repositories></project>",
            addr.get().expect("address")
        );
        let moved = flag.load(Ordering::SeqCst);
        let root = if moved { "/fallback" } else { first };
        let lib = format!("{root}/org/example/lib/1.0/lib-1.0");
        let stale = format!("{first}/org/example/lib/1.0/lib-1.0.jar");
        let mut files = vec![
            (
                "/maven/com/example/corp-parent/1.0/corp-parent-1.0.pom".to_string(),
                parent,
            ),
            (format!("{lib}.pom"), LIB_POM.to_string()),
            (format!("{lib}.jar"), LIB_JAR.to_string()),
        ];
        if moved && replaced {
            files.push((stale, "other jar".to_string()));
        }
        with_sha1(
            &request.path,
            files
                .iter()
                .map(|(path, body)| (path.as_str(), body.as_str())),
        )
    });
    own_addr
        .set(server.addr().to_string())
        .expect("address set once");
    let own_url = format!("http://{}/own/", server.addr());
    let project = project(
        &format!("http://{}/maven/", server.addr()),
        own.then_some(own_url.as_str()),
    );
    let output = sync(&project, &tempfile::tempdir().expect("home"));
    assert_success(&output, "lock before the release moves");
    let lock = std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
    assert!(lock.contains(&format!("{first}/\"")), "{lock}");

    moved.store(true, Ordering::SeqCst);
    for args in [
        &["sync"][..],
        &["sync", "--frozen"],
        &["lock", "verify", "--download"],
    ] {
        let output = raeva_command(project.path(), tempfile::tempdir().expect("home").path())
            .env("RAEVA_RETRIES", "0")
            .args(args)
            .output()
            .expect("run raeva");
        let context = format!("own={own} replaced={replaced} {args:?}");
        if replaced && args[0] == "lock" {
            assert_eq!(output.status.code(), Some(7), "{context}");
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("do not match the recorded checksum"),
                "{context}"
            );
            continue;
        }
        assert_success(&output, &context);
        assert_eq!(
            std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock"),
            lock,
            "own={own} replaced={replaced} {args:?}"
        );
    }
}

/// A home that a restore filled resolves offline after a POM edit, without
/// the repositories: the restore cached each POM it read for resolution.
/// Without checksum files the lock pins vouch for the restored files.
#[test]
fn a_restored_home_resolves_offline_after_an_edit() {
    for sidecars in [true, false] {
        check_restored_home_offline(sidecars);
    }
}

fn check_restored_home_offline(sidecars: bool) {
    let own_addr = Arc::new(OnceLock::<String>::new());
    let addr = Arc::clone(&own_addr);
    let server = StubServer::start(move |request| {
        let parent = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>corp-parent</artifactId><version>1.0</version><packaging>pom</packaging>\
<repositories><repository><id>declared</id><url>http://{}/fallback/</url></repository>\
</repositories></project>",
            addr.get().expect("address")
        );
        if !sidecars && request.path.ends_with(".sha1") {
            return Response::new(404, "");
        }
        with_sha1(
            &request.path,
            [
                (
                    "/maven/com/example/corp-parent/1.0/corp-parent-1.0.pom",
                    parent.as_str(),
                ),
                ("/fallback/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
                ("/fallback/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
            ],
        )
    });
    own_addr
        .set(server.addr().to_string())
        .expect("address set once");
    let project = project(&format!("http://{}/maven/", server.addr()), None);
    let first = raeva_command(project.path(), tempfile::tempdir().expect("home").path())
        .env("RAEVA_RETRIES", "0")
        .args(["sync", "--allow-missing-checksums"])
        .output()
        .expect("run raeva");
    assert_success(&first, "pin with missing checksums");
    let lock = std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock");

    let home = tempfile::tempdir().expect("fresh home");
    let run = |args: &[&str]| {
        raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(args)
            .output()
            .expect("run raeva")
    };
    let restored = run(&["sync", "--frozen"]);
    assert_success(&restored, &format!("restore sidecars={sidecars}"));
    let pom = project.path().join("pom.xml");
    let edited = std::fs::read_to_string(&pom).expect("pom.xml") + "<!-- edited -->\n";
    std::fs::write(&pom, edited).expect("edit pom.xml");
    drop(server);
    let offline = run(&["sync", "--frozen", "--offline"]);
    assert_success(&offline, &format!("offline after edit sidecars={sidecars}"));
    assert_eq!(
        std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock"),
        lock
    );
}

/// A restore that finds the pinned bytes already stored, from another
/// project's repository, indexes them under the repository this lock
/// records, so the home resolves this project offline after an edit. Also
/// when the other project stored only the POM and the restore downloads the
/// jar, or named the same repository URL with another id.
#[test]
fn a_restore_of_bytes_stored_from_another_repository_resolves_offline() {
    let server = StubServer::start(|request| {
        with_sha1(
            &request.path,
            [
                ("/a/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
                ("/a/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
                ("/b/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
                ("/b/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
            ],
        )
    });
    let project = |id: &str, repo: &str, kind: &str| {
        let dir = tempfile::tempdir().expect("project dir");
        std::fs::write(
            dir.path().join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>app</artifactId><version>1</version><dependencies><dependency>\
<groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>{kind}\
</dependency></dependencies></project>"
            ),
        )
        .expect("write pom.xml");
        write_repo_toml(dir.path(), id, &format!("http://{}/{repo}/", server.addr()));
        dir
    };
    let b = project("b", "b", "");
    assert_success(&sync(&b, &tempfile::tempdir().expect("home")), "lock b");
    let lock = std::fs::read_to_string(b.path().join("raeva.lock")).expect("lock");
    let pom = b.path().join("pom.xml");
    let original = std::fs::read_to_string(&pom).expect("pom.xml");

    let mut homes = Vec::new();
    for (id, repo, kind) in [
        ("a", "a", ""),
        ("a", "a", "<type>pom</type>"),
        ("a", "b", ""),
    ] {
        let home = tempfile::tempdir().expect("shared home");
        assert_success(
            &sync(&project(id, repo, kind), &home),
            "a stores lib from its repository",
        );
        let restore = raeva_command(b.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(["sync", "--frozen"])
            .output()
            .expect("run raeva");
        let case = format!("{id} at /{repo}/ {kind}");
        assert_success(&restore, &format!("b restores from the store ({case})"));
        homes.push((case, home));
    }
    std::fs::write(&pom, original + "<!-- edited -->\n").expect("edit pom.xml");
    drop(server);
    for (case, home) in &homes {
        let offline = raeva_command(b.path(), home.path())
            .args(["sync", "--frozen", "--offline"])
            .output()
            .expect("run raeva");
        assert_success(&offline, &format!("b offline after an edit ({case})"));
    }
    assert_eq!(
        std::fs::read_to_string(b.path().join("raeva.lock")).expect("lock"),
        lock
    );
}

/// A restore stopped after it downloaded the jar of `lib`, whose POM
/// another project stored from its own repository, completes the POM's
/// indexing when it runs again.
#[test]
fn a_stopped_restore_indexes_the_pom_when_it_runs_again() {
    const SLOW_POM: &str = "<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.example</groupId><artifactId>slow</artifactId><version>1.0</version></project>";
    let stall = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stalled = Arc::clone(&stall);
    let server = StubServer::start(move |request| {
        if request.path == "/b/org/example/slow/1.0/slow-1.0.jar" {
            while stalled.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        with_sha1(
            &request.path,
            [
                ("/a/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
                ("/b/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
                ("/b/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
                ("/b/org/example/slow/1.0/slow-1.0.pom", SLOW_POM),
                ("/b/org/example/slow/1.0/slow-1.0.jar", "slow jar"),
            ],
        )
    });
    let project = |repo: &str, dependencies: &str| {
        let dir = tempfile::tempdir().expect("project dir");
        std::fs::write(
            dir.path().join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>app</artifactId><version>1</version><dependencies>{dependencies}\
</dependencies></project>"
            ),
        )
        .expect("write pom.xml");
        std::fs::write(
            dir.path().join("raeva.toml"),
            format!(
                "[network]\nconcurrency = 1\n\n[[repositories]]\nid = \"{repo}\"\n\
                 url = \"http://{}/{repo}/\"\n",
                server.addr()
            ),
        )
        .expect("write raeva.toml");
        dir
    };
    let dependency = |artifact: &str, kind: &str| {
        format!(
            "<dependency><groupId>org.example</groupId><artifactId>{artifact}</artifactId>\
<version>1.0</version>{kind}</dependency>"
        )
    };
    let a = project("a", &dependency("lib", "<type>pom</type>"));
    let b = project("b", &(dependency("lib", "") + &dependency("slow", "")));
    assert_success(&sync(&b, &tempfile::tempdir().expect("home")), "lock b");
    let home = tempfile::tempdir().expect("shared home");
    assert_success(&sync(&a, &home), "a stores the POM of lib");

    stall.store(true, std::sync::atomic::Ordering::SeqCst);
    let before = server.requests().len();
    let mut stopped = raeva_command(b.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .args(["sync", "--frozen"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn raeva");
    while !server.requests()[before..]
        .iter()
        .any(|r| r.path.ends_with("slow-1.0.jar"))
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    stopped.kill().expect("stop the restore");
    stopped.wait().expect("reap raeva");
    stall.store(false, std::sync::atomic::Ordering::SeqCst);

    let run = |args: &[&str]| {
        raeva_command(b.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&run(&["sync", "--frozen"]), "b restores again");
    let pom = b.path().join("pom.xml");
    let edited = std::fs::read_to_string(&pom).expect("pom.xml") + "<!-- edited -->\n";
    std::fs::write(&pom, edited).expect("edit pom.xml");
    drop(server);
    assert_success(
        &run(&["sync", "--frozen", "--offline"]),
        "b offline after an edit",
    );
}

/// Two platforms lock the same `lib` through repositories their own
/// profiles declare; one restore, or one `lock verify --download`, fetches
/// it once and both platforms then resolve offline. One file at a time, the
/// jar is verified before its POM is stored, also when a verification that
/// missed the POM is completed by a sync.
#[test]
fn a_row_shared_by_two_platforms_resolves_offline_on_both() {
    let pom_gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let gone = Arc::clone(&pom_gone);
    let server = StubServer::start(move |request| {
        if gone.load(std::sync::atomic::Ordering::SeqCst) && request.path.ends_with(".pom") {
            return Response::new(404, "");
        }
        let files: Vec<(String, String)> = ["linux", "windows"]
            .iter()
            .flat_map(|dir| {
                [
                    (
                        format!("/{dir}/org/example/lib/1.0/lib-1.0.pom"),
                        LIB_POM.to_string(),
                    ),
                    (
                        format!("/{dir}/org/example/lib/1.0/lib-1.0.jar"),
                        LIB_JAR.to_string(),
                    ),
                ]
            })
            .collect();
        with_sha1(
            &request.path,
            files
                .iter()
                .map(|(path, body)| (path.as_str(), body.as_str())),
        )
    });
    let base = format!("http://{}", server.addr());
    let profile = |id: &str, family: &str| {
        format!(
            "<profile><id>{id}</id><activation><os><family>{family}</family></os></activation>\
<repositories><repository><id>{id}</id><url>{base}/{id}/</url></repository></repositories>\
</profile>"
        )
    };
    let project = tempfile::tempdir().expect("project dir");
    std::fs::write(
        project.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>app</artifactId><version>1</version><dependencies><dependency>\
<groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>\
</dependency></dependencies><profiles>{}{}</profiles></project>",
            profile("linux", "unix"),
            profile("windows", "windows"),
        ),
    )
    .expect("write pom.xml");
    std::fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[network]\nconcurrency = 1\n\n\
             [[repositories]]\nid = \"configured\"\nurl = \"{base}/empty/\"\n\n\
             [[repositories]]\nid = \"central\"\nurl = \"{base}/central/\"\n"
        ),
    )
    .expect("write raeva.toml");
    let run = |home: &TempDir, args: &[&str]| {
        raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(args)
            .output()
            .expect("run raeva")
    };
    let platforms = ["--platforms", "linux-x86_64,windows-x86_64"];
    let frozen = [&["sync", "--frozen"][..], &platforms].concat();
    let first = run(
        &tempfile::tempdir().expect("home"),
        &[&["sync"][..], &platforms].concat(),
    );
    assert_success(&first, "two-platform sync");
    let lock = std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
    assert!(lock.contains(&format!("{base}/linux/")), "{lock}");
    assert!(lock.contains(&format!("{base}/windows/")), "{lock}");

    let mut homes: Vec<_> = [&frozen[..], &["lock", "verify", "--download"]]
        .into_iter()
        .map(|args| {
            let home = tempfile::tempdir().expect("fresh home");
            let restored = run(&home, args);
            assert_success(&restored, &format!("{args:?}"));
            home
        })
        .collect();
    let resumed = tempfile::tempdir().expect("fresh home");
    pom_gone.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_status(
        &run(&resumed, &["lock", "verify", "--download"]),
        5,
        "verify download while the POM is gone",
    );
    pom_gone.store(false, std::sync::atomic::Ordering::SeqCst);
    let restored = run(&resumed, &frozen);
    assert_success(&restored, "frozen restore after the POM returns");
    homes.push(resumed);
    let pom = project.path().join("pom.xml");
    let edited = std::fs::read_to_string(&pom).expect("pom.xml") + "<!-- edited -->\n";
    std::fs::write(&pom, edited).expect("edit pom.xml");
    drop(server);
    for home in &homes {
        let offline = run(home, &[&frozen[..], &["--offline"]].concat());
        assert_success(&offline, "offline after edit");
    }
    assert_eq!(
        std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock"),
        lock
    );
}

/// A mirror of the id only the remote parent declares serves the jar, so
/// the store records it as served through that mirror. Offline, the frozen
/// check and export-m2 take it from the store: the parent's declaration
/// names the mirror, as it did for the resolution.
#[test]
fn files_a_mirror_of_a_remote_parents_repository_served_restore_offline() {
    let own_addr = Arc::new(OnceLock::<String>::new());
    let addr = Arc::clone(&own_addr);
    let server = StubServer::start(move |request| {
        let parent = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>corp-parent</artifactId><version>1.0</version><packaging>pom</packaging>\
<repositories><repository><id>parent-only</id><url>http://{}/nowhere/</url></repository>\
</repositories></project>",
            addr.get().expect("address")
        );
        with_sha1(
            &request.path,
            [
                (
                    "/maven/com/example/corp-parent/1.0/corp-parent-1.0.pom",
                    parent.as_str(),
                ),
                ("/mirror/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
                ("/mirror/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
            ],
        )
    });
    own_addr
        .set(server.addr().to_string())
        .expect("address set once");
    let project = project(&format!("http://{}/maven/", server.addr()), None);
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "[[mirrors]]\nid = \"m\"\nurl = \"http://{}/mirror/\"\nmirror_of = [\"parent-only\"]\n",
            server.addr()
        ),
    )
    .expect("write config.toml");
    let run = |args: &[&str]| {
        raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&run(&["sync"]), "sync through the mirror");
    let lock = std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
    assert!(lock.contains("/nowhere/"), "{lock}");
    drop(server);
    assert_success(&run(&["sync", "--frozen", "--offline"]), "offline frozen");
    let m2 = tempfile::tempdir().expect("m2");
    let m2_path = m2.path().to_str().expect("utf-8 path");
    assert_success(
        &run(&["export-m2", "--offline", "--m2-path", m2_path]),
        "offline export",
    );
    assert_eq!(
        std::fs::read(m2.path().join("org/example/lib/1.0/lib-1.0.jar")).expect("exported jar"),
        LIB_JAR.as_bytes()
    );
}

/// A restore that falls back to a remote parent's repository, through the
/// mirror of its id, keeps the configured origin the lock records. Offline,
/// the frozen check and export-m2 still find the file: they resolve to learn
/// the parent's repositories when a stored file needs one.
#[test]
fn files_a_fallback_restore_took_from_a_remote_parents_mirror_count_offline() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let moved = Arc::new(AtomicBool::new(false));
    let gone = Arc::clone(&moved);
    let own_addr = Arc::new(OnceLock::<String>::new());
    let addr = Arc::clone(&own_addr);
    let server = StubServer::start(move |request| {
        let parent = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>corp-parent</artifactId><version>1.0</version><packaging>pom</packaging>\
<repositories><repository><id>parent-only</id><url>http://{}/nowhere/</url></repository>\
</repositories></project>",
            addr.get().expect("address")
        );
        if gone.load(Ordering::SeqCst) && request.path.starts_with("/maven/org/") {
            return Response::new(404, "");
        }
        with_sha1(
            &request.path,
            [
                (
                    "/maven/com/example/corp-parent/1.0/corp-parent-1.0.pom",
                    parent.as_str(),
                ),
                ("/maven/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
                ("/maven/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
                ("/mirror/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
                ("/mirror/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
            ],
        )
    });
    own_addr
        .set(server.addr().to_string())
        .expect("address set once");
    let project = project(&format!("http://{}/maven/", server.addr()), None);
    let mirror = format!(
        "[[mirrors]]\nid = \"m\"\nurl = \"http://{}/mirror/\"\nmirror_of = [\"parent-only\"]\n",
        server.addr()
    );
    let run = |home: &TempDir, args: &[&str]| {
        std::fs::write(home.path().join("config.toml"), &mirror).expect("write config.toml");
        raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&run(&tempfile::tempdir().expect("home"), &["sync"]), "lock");
    let lock = std::fs::read_to_string(project.path().join("raeva.lock")).expect("lock");
    assert!(lock.contains("/maven/"), "{lock}");
    moved.store(true, Ordering::SeqCst);
    let home = tempfile::tempdir().expect("fresh home");
    assert_success(&run(&home, &["sync", "--frozen"]), "fallback restore");
    drop(server);
    assert_success(
        &run(&home, &["sync", "--frozen", "--offline"]),
        "offline frozen",
    );
    let m2 = tempfile::tempdir().expect("m2");
    let m2_path = m2.path().to_str().expect("utf-8 path");
    assert_success(
        &run(&home, &["export-m2", "--offline", "--m2-path", m2_path]),
        "offline export",
    );
    assert_eq!(
        std::fs::read(m2.path().join("org/example/lib/1.0/lib-1.0.jar")).expect("exported jar"),
        LIB_JAR.as_bytes()
    );
}
