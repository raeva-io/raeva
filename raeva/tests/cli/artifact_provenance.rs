use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rv_lock::Lockfile;
use rv_maven_types::BlobId;
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{
    assert_status, assert_success, local_central, raeva_command, run_raeva, serve_sha256, sha1_hex,
    with_sha1, write_repo_toml,
};

const POM: &[u8] = b"<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
<artifactId>lib</artifactId><version>1</version></project>";
const JAR_PATH: &str = "/test/lib/1/lib-1.jar";
const SNAPSHOT_POM: &[u8] = b"<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
<artifactId>lib</artifactId><version>1-SNAPSHOT</version></project>";

fn repository(jar: &'static [u8], checksum: bool) -> (String, StubServer) {
    let server = StubServer::start(move |request| serve(&request.path, jar, checksum));
    (format!("http://{}/", server.addr()), server)
}

fn serve(request: &str, jar: &'static [u8], checksum: bool) -> Response {
    let metadata =
        b"<metadata><versioning><versions><version>1</version></versions></versioning></metadata>";
    let snapshot = b"<metadata><groupId>test</groupId><artifactId>lib</artifactId>\
        <version>1-SNAPSHOT</version><versioning><snapshot><timestamp>20260101.010101</timestamp>\
        <buildNumber>1</buildNumber></snapshot><lastUpdated>20260101010101</lastUpdated>\
        </versioning></metadata>";
    let build = "/test/lib/1-SNAPSHOT/lib-1-20260101.010101-1";
    for (path, bytes) in [
        ("/test/lib/1/lib-1.pom", POM),
        (JAR_PATH, jar),
        ("/test/lib/maven-metadata.xml", metadata),
        ("/test/lib/1-SNAPSHOT/maven-metadata.xml", snapshot),
        (&format!("{build}.pom"), SNAPSHOT_POM),
        (&format!("{build}.jar"), jar),
    ] {
        if request == path {
            return Response::new(200, bytes);
        }
        if request == format!("{path}.sha256") && (checksum || bytes != jar) {
            return Response::new(200, BlobId::from_bytes(bytes).to_string());
        }
    }
    Response::new(404, "")
}

fn project(path: &Path, url: &str) {
    fs::create_dir_all(path).unwrap();
    write_repo_toml(path, "repo", url);
    fs::write(
        path.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>test</groupId><artifactId>lib</artifactId><version>1</version>\
         </dependency></dependencies></project>",
    )
    .unwrap();
}

fn assert_jar(project: &Path, jar: &[u8], url: &str) {
    let lock = Lockfile::read(&project.join("raeva.lock")).unwrap();
    let row = &lock.platforms[0].artifacts[0];
    assert_eq!(
        row.pin().unwrap().as_sha256(),
        Some(&BlobId::from_bytes(jar))
    );
    assert_eq!(row.repo_url, url);
}

#[test]
fn an_alternate_repository_cannot_replace_a_pinned_dependency_pom() {
    alternate_repository_pom_pin("", "lib");
}

#[test]
fn an_alternate_repository_cannot_replace_pinned_support_poms() {
    for (body, pinned) in [
        (
            "<parent><groupId>test</groupId><artifactId>parent</artifactId>\
             <version>1</version><relativePath/></parent>",
            "parent",
        ),
        (
            "<dependencyManagement><dependencies><dependency><groupId>test</groupId>\
             <artifactId>bom</artifactId><version>1</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>",
            "bom",
        ),
        (
            "<distributionManagement><relocation><artifactId>target</artifactId>\
             </relocation></distributionManagement>",
            "lib",
        ),
    ] {
        alternate_repository_pom_pin(body, pinned);
    }
}

fn alternate_repository_pom_pin(body: &str, pinned: &str) {
    let base = TempDir::new().unwrap();
    let first = base.path().join("first");
    let second = base.path().join("second");
    fs::create_dir_all(&first).unwrap();
    let publish = |repo: &Path, artifact: &str, bytes: &[u8]| {
        let dir = repo.join(format!("test/{artifact}/1"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{artifact}-1.pom")), bytes).unwrap();
        fs::write(
            dir.join(format!("{artifact}-1.pom.sha256")),
            BlobId::from_bytes(bytes).as_str(),
        )
        .unwrap();
        fs::write(dir.join(format!("{artifact}-1.jar")), b"lib jar").unwrap();
    };
    let files: Vec<_> = ["lib", "parent", "bom", "target"]
        .into_iter()
        .map(|artifact| {
            let body = if artifact == "lib" {
                body
            } else {
                "<packaging>pom</packaging>"
            };
            let pom = format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
                 <artifactId>{artifact}</artifactId><version>1</version>{body}</project>"
            );
            publish(&second, artifact, pom.as_bytes());
            (artifact, pom)
        })
        .collect();
    let first_url = url::Url::from_directory_path(&first).unwrap().to_string();
    let second_url = url::Url::from_directory_path(&second).unwrap().to_string();
    let app = base.path().join("app");
    project(&app, &second_url);
    fs::write(
        app.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"first\"\nurl = \"{first_url}\"\n\
             [[repositories]]\nid = \"central\"\nurl = \"{second_url}\"\n"
        ),
    )
    .unwrap();
    assert_success(
        &run_raeva(&app, TempDir::new().unwrap().path(), &["sync"]),
        "initial lock from the second repository",
    );
    let lock_path = app.join("raeva.lock");
    let lock = fs::read(&lock_path).unwrap();
    let original = &files
        .iter()
        .find(|(artifact, _)| *artifact == pinned)
        .unwrap()
        .1;
    let original_pin = BlobId::from_bytes(original.as_bytes());
    let locked = Lockfile::read(&lock_path).unwrap();
    if body.is_empty() {
        assert_eq!(
            locked.platforms[0].artifacts[0].pom_sha256,
            Some(original_pin.clone())
        );
    } else {
        assert!(
            locked.platforms[0]
                .support_poms
                .values()
                .any(|pom| pom.sha256 == original_pin)
        );
    }
    for (artifact, pom) in &files {
        publish(&first, artifact, pom.as_bytes());
    }
    let modified = format!("{original}<!-- republished -->");
    publish(&first, pinned, modified.as_bytes());
    let pom = fs::read_to_string(app.join("pom.xml")).unwrap();
    fs::write(
        app.join("pom.xml"),
        pom.replacen("</modelVersion>", "</modelVersion><name>edited</name>", 1),
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    let output = run_raeva(&app, home.path(), &["sync"]);
    let modified_pin = BlobId::from_bytes(modified.as_bytes());
    let hash = modified_pin.as_str();
    assert!(
        !home
            .path()
            .join("store/blobs")
            .join(&hash[..2])
            .join(&hash[2..4])
            .join(hash)
            .exists()
    );
    let conn = rusqlite::Connection::open(home.path().join("store/index.sqlite")).unwrap();
    for table in ["artifacts", "served_files"] {
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                [hash],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "{table} contains the refused POM");
    }
    assert_status(&output, 7, "sync refuses the alternate repository's POM");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("checksum mismatch") && stderr.contains(&first_url),
        "{stderr}"
    );
    assert_eq!(fs::read(&lock_path).unwrap(), lock);
    publish(&first, pinned, original.as_bytes());
    assert_success(
        &run_raeva(&app, home.path(), &["sync", "--update"]),
        "update after repairing the repository",
    );
    let updated = fs::read_to_string(&lock_path).unwrap();
    assert!(updated.contains(original_pin.as_str()));
    assert!(!updated.contains(hash));

    publish(&first, pinned, modified.as_bytes());
    assert_success(
        &run_raeva(&app, TempDir::new().unwrap().path(), &["sync", "--update"]),
        "update locks republished POM bytes",
    );
    assert!(fs::read_to_string(&lock_path).unwrap().contains(hash));
}

#[test]
fn mirror_evidence_is_reused_only_for_the_same_endpoint() {
    let base = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let (origin, origin_server) = repository(b"origin jar", true);
    let (mirror, mirror_server) = repository(b"mirror jar", true);
    let a = base.path().join("a");
    let b = base.path().join("b");
    project(&a, &origin);
    project(&b, &origin);
    // Only the runs in `a` see a settings.xml with the mirror; all share
    // one store.
    let maven_home = TempDir::new().unwrap();
    fs::create_dir_all(maven_home.path().join(".m2")).unwrap();
    fs::write(
        maven_home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>mirror</id><mirrorOf>*</mirrorOf>\
             <url>{mirror}</url></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    let mirrored = |args: &[&str]| {
        let mut command = raeva_command(&a, home.path());
        crate::common::isolate_maven_user_home(&mut command, maven_home.path(), "");
        command.args(args).output().unwrap()
    };
    assert_success(&mirrored(&["sync"]), "mirror sync");
    assert_jar(&a, b"mirror jar", &origin);
    assert_success(&run_raeva(&b, home.path(), &["sync"]), "direct sync");
    assert_jar(&b, b"origin jar", &origin);
    assert!(origin_server.requests().iter().any(|r| r.path == JAR_PATH));
    assert_success(&mirrored(&["sync", "--update"]), "mirror reuse");
    assert_jar(&a, b"mirror jar", &origin);
    assert_eq!(
        mirror_server
            .requests()
            .iter()
            .filter(|r| r.path == JAR_PATH)
            .count(),
        1
    );
}

#[test]
fn lock_only_acceptance_does_not_become_repository_checksum_evidence() {
    let base = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let (url, server) = repository(b"jar without sidecar", false);
    let a = base.path().join("a");
    let b = base.path().join("b");
    project(&a, &url);
    project(&b, &url);
    assert_success(
        &run_raeva(&a, home.path(), &["sync", "--allow-missing-checksums"]),
        "permissive sync",
    );
    assert_success(
        &run_raeva(&a, home.path(), &["sync", "--update"]),
        "pinned sync",
    );
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|r| r.path == JAR_PATH)
            .count(),
        2
    );
    let strict = run_raeva(&b, home.path(), &["sync"]);
    assert_status(&strict, 5, "fresh strict sync of lock-only evidence");
    let err = String::from_utf8_lossy(&strict.stderr);
    assert!(err.contains("checksum"), "{err}");
}

#[test]
fn shared_store_a_b_a_sync_and_export_follow_the_lock_pin() {
    let base = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let (repo_a, _a_server) = repository(b"jar a", true);
    let (repo_b, _b_server) = repository(b"jar b", true);
    let a = base.path().join("a");
    let b = base.path().join("b");
    project(&a, &repo_a);
    project(&b, &repo_b);
    assert_success(&run_raeva(&a, home.path(), &["sync"]), "sync a");
    let lock = fs::read(a.join("raeva.lock")).unwrap();
    assert_success(&run_raeva(&b, home.path(), &["sync"]), "sync b");
    let m2 = base.path().join("m2");
    let export = || {
        assert_success(
            &run_raeva(
                &a,
                home.path(),
                &["export-m2", "--m2-path", m2.to_str().unwrap()],
            ),
            "export a after b",
        );
        assert_eq!(fs::read(m2.join("test/lib/1/lib-1.jar")).unwrap(), b"jar a");
    };
    export();
    assert_success(
        &run_raeva(&a, home.path(), &["sync", "--update"]),
        "sync a again",
    );
    assert_eq!(fs::read(a.join("raeva.lock")).unwrap(), lock);
    assert_jar(&a, b"jar a", &repo_a);
    export();
}

/// A repository that answers 429 is not passed over for the next one, which
/// serves the same files: the lock would name whichever repository answered
/// that day. The sync fails with a network error and writes no lock, for a
/// version, a version range and a SNAPSHOT alike, and once the repository answers again
/// the lock names it. Meanwhile `--frozen` from an empty home restores the
/// pinned files from the next repository, and one that resolves again fails
/// with the network error, not as drift.
#[test]
fn a_rate_limited_repository_is_not_passed_over() {
    for version in ["1", "[1,2)", "1-SNAPSHOT"] {
        rate_limited_first_repository(version);
    }
}

fn rate_limited_first_repository(version: &str) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let jar: &'static [u8] = b"jar";
    let down = Arc::new(AtomicBool::new(true));
    let limited = {
        let down = Arc::clone(&down);
        StubServer::start(move |request| match down.load(Ordering::SeqCst) {
            true => Response::new(429, ""),
            false => serve(&request.path, jar, true),
        })
    };
    let first = format!("http://{}/", limited.addr());
    let second = repository(jar, true);
    let (_central, central) = local_central();
    let base = TempDir::new().unwrap();
    let dir = base.path().join("app");
    project(&dir, &first);
    let pom = fs::read_to_string(dir.join("pom.xml")).unwrap();
    let pom = pom.replace(
        "<version>1</version></dependency>",
        &format!("<version>{version}</version></dependency>"),
    );
    fs::write(dir.join("pom.xml"), pom).unwrap();
    fs::write(
        dir.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"first\"\nurl = \"{first}\"\nsnapshots = true\n\
             [[repositories]]\nid = \"second\"\nurl = \"{}\"\nsnapshots = true\n{central}",
            second.0
        ),
    )
    .unwrap();
    let sync = |home: &Path, args: &[&str]| {
        raeva_command(&dir, home)
            .env("RAEVA_RETRIES", "0")
            .args(args)
            .output()
            .unwrap()
    };
    let home = TempDir::new().unwrap();
    let failed = sync(home.path(), &["sync"]);
    assert_status(&failed, 4, "sync while the first repository is limited");
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        stderr.contains("429")
            && stderr.contains(&first)
            && stderr.contains("does not fall back to another repository"),
        "{stderr}"
    );
    assert!(!dir.join("raeva.lock").exists());
    assert!(
        second
            .1
            .requests()
            .iter()
            .all(|r| !r.path.ends_with(".jar"))
    );

    down.store(false, Ordering::SeqCst);
    assert_success(&sync(home.path(), &["sync"]), "sync once it answers");
    assert_jar(&dir, jar, &first);
    let written = fs::read(dir.join("raeva.lock")).unwrap();

    down.store(true, Ordering::SeqCst);
    let empty = TempDir::new().unwrap();
    assert_status(
        &sync(empty.path(), &["sync", "--frozen"]),
        4,
        "frozen restore stops after rate limiting",
    );
    // A POM edit makes --frozen resolve again, which from another empty
    // home meets the 429.
    let pom = fs::read_to_string(dir.join("pom.xml")).unwrap();
    let edited = pom.replace(
        "<dependencies>",
        "<properties><x>y</x></properties><dependencies>",
    );
    fs::write(dir.join("pom.xml"), edited).unwrap();
    let frozen = sync(TempDir::new().unwrap().path(), &["sync", "--frozen"]);
    assert_status(
        &frozen,
        4,
        "frozen resolution while the first repository is limited",
    );
    assert_eq!(fs::read(dir.join("raeva.lock")).unwrap(), written);
}

/// A repository that answers 429 for a few seconds is waited for, as
/// Maven waits, and the file comes from it rather than the next repository.
#[test]
fn a_short_burst_of_429s_is_waited_out() {
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};
    let jar: &'static [u8] = b"jar";
    let burst = OnceLock::new();
    let limited = StubServer::start(move |request| {
        if burst.get_or_init(Instant::now).elapsed() < Duration::from_secs(4) {
            return Response::new(429, "");
        }
        serve(&request.path, jar, true)
    });
    let first = format!("http://{}/", limited.addr());
    let second = repository(jar, true);
    let dir = TempDir::new().unwrap();
    project(dir.path(), &first);
    fs::write(
        dir.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"first\"\nurl = \"{first}\"\n\
             [[repositories]]\nid = \"second\"\nurl = \"{}\"\n",
            second.0
        ),
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    let start = Instant::now();
    assert_success(
        &raeva_command(dir.path(), home.path())
            .arg("sync")
            .output()
            .unwrap(),
        "sync through a burst of 429s",
    );
    assert!(start.elapsed() >= Duration::from_secs(5));
    assert_jar(dir.path(), jar, &first);
    assert!(second.1.requests().is_empty());
}

/// A SNAPSHOT parent is the newest build across the repositories, so a
/// repository that answers 429 for its metadata fails the sync rather than
/// leave the build to the one that answered.
#[test]
fn a_rate_limited_repository_fails_a_snapshot_parent() {
    const PARENT: &[u8] = b"<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
<artifactId>parent</artifactId><version>1-SNAPSHOT</version><packaging>pom</packaging></project>";
    const METADATA: &[u8] = b"<metadata><groupId>test</groupId><artifactId>parent</artifactId>\
<version>1-SNAPSHOT</version><versioning><snapshot><timestamp>20260101.010101</timestamp>\
<buildNumber>1</buildNumber></snapshot><lastUpdated>20260101010101</lastUpdated></versioning></metadata>";
    let healthy = StubServer::start(|request| {
        for (path, bytes) in [
            ("/test/parent/1-SNAPSHOT/maven-metadata.xml", METADATA),
            (
                "/test/parent/1-SNAPSHOT/parent-1-20260101.010101-1.pom",
                PARENT,
            ),
        ] {
            if request.path == path {
                return Response::new(200, bytes);
            }
            if request.path == format!("{path}.sha256") {
                return Response::new(200, BlobId::from_bytes(bytes).to_string());
            }
        }
        Response::new(404, "")
    });
    let limited = StubServer::start(|_| Response::new(429, ""));
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>test</groupId>\
         <artifactId>parent</artifactId><version>1-SNAPSHOT</version><relativePath/></parent>\
         <artifactId>app</artifactId></project>",
    )
    .unwrap();
    let repositories = [("first", healthy.addr()), ("second", limited.addr())]
        .map(|(id, addr)| {
            format!("[[repositories]]\nid = \"{id}\"\nurl = \"http://{addr}/\"\nsnapshots = true\n")
        })
        .concat();
    fs::write(dir.path().join("raeva.toml"), repositories).unwrap();
    let home = TempDir::new().unwrap();
    let output = raeva_command(dir.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .arg("sync")
        .output()
        .unwrap();
    assert_status(&output, 4, "sync while the second repository is limited");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("429"), "{stderr}");
}

/// A repository that serves other bytes for a release file raeva.lock pins,
/// with a checksum file that matches them, leaves them neither in the store
/// nor in the metadata cache: once it serves the pinned bytes again, neither
/// an update nor another project locks the other ones.
#[test]
fn other_bytes_for_a_pinned_release_file_are_not_kept() {
    const OTHER_POM: &[u8] = b"<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
<artifactId>lib</artifactId><version>1</version><!-- other --></project>";
    for (replaced, other) in [
        (JAR_PATH, b"other jar".as_slice()),
        ("/test/lib/1/lib-1.pom", OTHER_POM),
    ] {
        let tampered = Arc::new(AtomicBool::new(false));
        let serving = Arc::clone(&tampered);
        let server = StubServer::start(move |request| {
            if serving.load(Ordering::SeqCst) {
                let path = request.path.as_str();
                if path == replaced {
                    return Response::new(200, other);
                }
                if path.strip_suffix(".sha256") == Some(replaced) {
                    return Response::new(200, BlobId::from_bytes(other).to_string());
                }
            }
            serve(&request.path, b"lib jar", true)
        });
        let url = format!("http://{}/", server.addr());
        let base = TempDir::new().unwrap();
        let (a, b) = (base.path().join("a"), base.path().join("b"));
        project(&a, &url);
        project(&b, &url);
        assert_success(
            &run_raeva(&a, TempDir::new().unwrap().path(), &["sync"]),
            "sync",
        );

        let home = TempDir::new().unwrap();
        tampered.store(true, Ordering::SeqCst);
        let frozen = run_raeva(&a, home.path(), &["sync", "--frozen"]);
        assert_status(&frozen, 7, "frozen sync of other bytes");
        let pom = fs::read_to_string(a.join("pom.xml")).unwrap();
        let edited = pom.replacen("</modelVersion>", "</modelVersion><name>e</name>", 1);
        fs::write(a.join("pom.xml"), edited).unwrap();
        assert_status(
            &run_raeva(&a, home.path(), &["sync"]),
            7,
            "sync of other bytes",
        );

        tampered.store(false, Ordering::SeqCst);
        assert_success(&run_raeva(&b, home.path(), &["sync"]), "other project");
        assert_success(&run_raeva(&a, home.path(), &["sync", "--update"]), "update");
        for project in [&a, &b] {
            assert_jar(project, b"lib jar", &url);
            let lock = Lockfile::read(&project.join("raeva.lock")).unwrap();
            let row = &lock.platforms[0].artifacts[0];
            assert_eq!(row.pom_sha256, Some(BlobId::from_bytes(POM)), "{replaced}");
        }
    }
}

#[test]
fn other_bytes_for_a_pinned_snapshot_dependency_pom_are_not_kept() {
    snapshot_pom_pin_is_not_kept(false);
}

#[test]
fn other_bytes_for_a_pinned_snapshot_bom_are_not_kept() {
    snapshot_pom_pin_is_not_kept(true);
}

fn snapshot_pom_pin_is_not_kept(bom: bool) {
    const BOM: &[u8] = b"<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
<artifactId>bom</artifactId><version>1-SNAPSHOT</version><packaging>pom</packaging></project>";
    const BOM_METADATA: &[u8] = b"<metadata><groupId>test</groupId><artifactId>bom</artifactId>\
<version>1-SNAPSHOT</version><versioning><snapshot><timestamp>20260101.010101</timestamp>\
<buildNumber>1</buildNumber></snapshot></versioning></metadata>";
    let (artifact, genuine) = if bom {
        ("bom", BOM)
    } else {
        ("lib", SNAPSHOT_POM)
    };
    let replaced = format!("/test/{artifact}/1-SNAPSHOT/{artifact}-1-20260101.010101-1.pom");
    let target = replaced.clone();
    let other = [genuine, b"<!-- changed -->"].concat();
    let tampered = Arc::new(AtomicBool::new(false));
    let serving = Arc::clone(&tampered);
    let server = StubServer::start(move |request| {
        let bytes = if serving.load(Ordering::SeqCst) {
            other.as_slice()
        } else {
            genuine
        };
        if request.path == target {
            return Response::new(200, bytes);
        }
        if request.path.strip_suffix(".sha256") == Some(target.as_str()) {
            return Response::new(200, BlobId::from_bytes(bytes).to_string());
        }
        if request.path == "/test/bom/1-SNAPSHOT/maven-metadata.xml" {
            return Response::new(200, BOM_METADATA);
        }
        if request.path == "/test/bom/1-SNAPSHOT/maven-metadata.xml.sha256" {
            return Response::new(200, BlobId::from_bytes(BOM_METADATA).to_string());
        }
        serve(&request.path, b"lib jar", true)
    });
    let url = format!("http://{}/", server.addr());
    let base = TempDir::new().unwrap();
    let (a, b) = (base.path().join("a"), base.path().join("b"));
    for path in [&a, &b] {
        project(path, &url);
        fs::write(
            path.join("raeva.toml"),
            format!("[[repositories]]\nid = \"central\"\nurl = \"{url}\"\nsnapshots = true\n"),
        )
        .unwrap();
        let pom = fs::read_to_string(path.join("pom.xml")).unwrap();
        let pom = if bom {
            pom.replace(
                "<dependencies>",
                "<dependencyManagement><dependencies><dependency>\
                <groupId>test</groupId><artifactId>bom</artifactId><version>1-SNAPSHOT</version>\
                <type>pom</type><scope>import</scope></dependency></dependencies>\
                </dependencyManagement><dependencies>",
            )
        } else {
            pom.replace(
                "<artifactId>lib</artifactId><version>1</version>",
                "<artifactId>lib</artifactId><version>1-SNAPSHOT</version>",
            )
        };
        fs::write(path.join("pom.xml"), pom).unwrap();
    }
    assert_success(
        &run_raeva(&a, TempDir::new().unwrap().path(), &["sync"]),
        "initial sync",
    );
    let home = TempDir::new().unwrap();
    tampered.store(true, Ordering::SeqCst);
    let frozen = run_raeva(&a, home.path(), &["sync", "--frozen"]);
    assert_status(&frozen, 7, "frozen sync of other snapshot POM bytes");
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(
        stderr.contains("do not match their checksums in raeva.lock")
            && stderr.contains(&format!("test:{artifact}:")),
        "{stderr}"
    );
    tampered.store(false, Ordering::SeqCst);
    let before = server
        .requests()
        .iter()
        .filter(|r| r.path == replaced)
        .count();
    assert_success(&run_raeva(&b, home.path(), &["sync"]), "other project");
    assert!(
        server
            .requests()
            .iter()
            .filter(|r| r.path == replaced)
            .count()
            > before
    );
    let lock = Lockfile::read(&b.join("raeva.lock")).unwrap();
    let pinned = BlobId::from_bytes(genuine);
    if bom {
        assert!(
            lock.platforms[0]
                .support_poms
                .values()
                .any(|pom| pom.sha256 == pinned)
        );
    } else {
        assert_eq!(lock.platforms[0].artifacts[0].pom_sha256, Some(pinned));
    }
}

/// A copy the store holds from an earlier run, verified by its checksum file
/// but other than the bytes the lock pins, does not stand in for the pinned
/// file, under `--update` too: the resolution asks the repository again.
#[test]
fn a_stored_copy_other_than_the_pin_is_not_reused() {
    for (sha1, args) in [
        (false, &["sync"][..]),
        (true, &["sync"]),
        (false, &["sync", "--update"]),
    ] {
        let replaced = Arc::new(AtomicBool::new(false));
        let serving = Arc::clone(&replaced);
        let server = StubServer::start(move |request| {
            let jar: &'static [u8] = if serving.load(Ordering::SeqCst) {
                b"other jar"
            } else {
                b"lib jar"
            };
            serve(&request.path, jar, true)
        });
        let url = format!("http://{}/", server.addr());
        let base = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let a = base.path().join("a");
        project(&a, &url);
        let elsewhere = TempDir::new().unwrap();
        assert_success(&run_raeva(&a, elsewhere.path(), &["sync"]), "sync");
        let mut lock = fs::read_to_string(a.join("raeva.lock")).unwrap();
        replaced.store(true, Ordering::SeqCst);
        fs::remove_file(a.join("raeva.lock")).unwrap();
        assert_success(&run_raeva(&a, home.path(), &["sync"]), "other bytes");
        assert_jar(&a, b"other jar", &url);
        replaced.store(false, Ordering::SeqCst);
        if sha1 {
            let row = |algorithm: &str, digest: String| {
                format!("algorithm = \"{algorithm}\"\ndigest = \"{digest}\"")
            };
            let sha256_row = row("sha256", BlobId::from_bytes(b"lib jar").to_string());
            assert!(lock.contains(&sha256_row), "{lock}");
            lock = lock.replace(&sha256_row, &row("sha1", sha1_hex(b"lib jar")));
        }
        fs::write(a.join("raeva.lock"), lock).unwrap();
        let pom = fs::read_to_string(a.join("pom.xml")).unwrap();
        let edited = pom.replacen("</modelVersion>", "</modelVersion><name>e</name>", 1);
        fs::write(a.join("pom.xml"), edited).unwrap();
        assert_success(&run_raeva(&a, home.path(), args), "sync");
        assert_jar(&a, b"lib jar", &url);
    }
}

fn warning_codes(output: &std::process::Output) -> Vec<String> {
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    (envelope["data"]["warnings"]
        .as_array()
        .into_iter()
        .flatten())
    .map(|warning| warning["code"].as_str().unwrap_or_default().to_string())
    .collect()
}

/// A jar its repository publishes no checksum file for fails the sync, and
/// the JSON error carries the flag that accepts it as a hint, not only in
/// the message.
#[test]
fn a_missing_checksum_names_the_flag_in_the_json_hints() {
    let (url, _server) = repository(b"jar bytes", false);
    let base = TempDir::new().unwrap();
    let app = base.path().join("app");
    project(&app, &url);
    let home = TempDir::new().unwrap();
    let output = run_raeva(&app, home.path(), &["--json", "sync"]);
    assert_status(&output, 5, "missing checksum");
    let envelope = crate::common::envelope(&output);
    let error = envelope["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("missing checksum for test/lib/1/lib-1.jar"),
        "{envelope}"
    );
    let hints = envelope["hints"].as_array().expect("hints");
    assert!(
        (hints.iter()).any(|hint| hint
            .as_str()
            .is_some_and(|hint| hint.contains("sync --allow-missing-checksums"))),
        "{envelope}"
    );
    let text = run_raeva(&app, home.path(), &["sync"]);
    assert_status(&text, 5, "missing checksum, text");
    let stderr = String::from_utf8_lossy(&text.stderr);
    assert_eq!(
        stderr.matches("--allow-missing-checksums").count(),
        1,
        "{stderr}"
    );
}

/// A jar accepted without a checksum file is marked on its row. A sync that
/// admits it by its pin keeps the marker, `--frozen` warns about it unless
/// the flag is passed again, a checksum file published later that disagrees
/// with the pin fails a restore, and a download one verifies clears the
/// marker, on a platform the sync keeps too.
#[test]
fn a_file_accepted_without_a_checksum_file_stays_marked_until_one_verifies_it() {
    // No checksum file, then a wrong one, then the right one.
    let state = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let published = state.clone();
    let server = StubServer::start(move |request| {
        if request.path == format!("{JAR_PATH}.sha256") {
            return match published.load(Ordering::SeqCst) {
                0 => Response::new(404, ""),
                1 => Response::new(200, BlobId::from_bytes(b"other").to_string()),
                _ => Response::new(200, BlobId::from_bytes(b"jar bytes").to_string()),
            };
        }
        serve(&request.path, b"jar bytes", true)
    });
    let url = format!("http://{}/", server.addr());
    let base = TempDir::new().unwrap();
    let app = base.path().join("app");
    project(&app, &url);
    let lock_path = app.join("raeva.lock");
    let marked = || {
        let lock = Lockfile::read(&lock_path).unwrap();
        (lock.platforms.iter())
            .map(|platform| {
                let row = &platform.artifacts[0];
                (row.missing_checksum, row.pom_missing_checksum)
            })
            .collect::<Vec<_>>()
    };
    let host = rv_lock::Platform::current().unwrap().to_string();
    let other = if host == "linux-x86_64" {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    };
    let both = format!("{host},{other}");
    // One home, so later runs find the files in the store.
    let home = TempDir::new().unwrap();
    let sync = |args: &[&str]| run_raeva(&app, home.path(), args);
    assert_status(&sync(&["sync"]), 5, "missing checksum refused");
    let allowed = sync(&["sync", "--allow-missing-checksums", "--platforms", &both]);
    assert_success(&allowed, "allowed");
    assert_eq!(marked(), [(true, false); 2]);
    assert!(
        fs::read_to_string(&lock_path)
            .unwrap()
            .contains("\nmissing_checksum = true\n")
    );

    let frozen = sync(&["--json", "sync", "--frozen"]);
    assert_success(&frozen, "frozen");
    assert!(warning_codes(&frozen).contains(&"CHECKSUM_MISSING_LOCKED".to_string()));
    let frozen = sync(&["--json", "sync", "--frozen", "--allow-missing-checksums"]);
    assert_success(&frozen, "frozen with the flag");
    assert!(!warning_codes(&frozen).contains(&"CHECKSUM_MISSING_LOCKED".to_string()));

    // Resolving again under the pin needs no flag and keeps the marker.
    let pom = app.join("pom.xml");
    let text = fs::read_to_string(&pom).unwrap();
    fs::write(
        &pom,
        text.replacen(
            "</modelVersion>",
            "</modelVersion><description>x</description>",
            1,
        ),
    )
    .unwrap();
    assert_success(&sync(&["sync"]), "resolve under the pin");
    assert_eq!(marked(), [(true, false); 2]);

    // A restore into an empty store asks for the checksum file again.
    state.store(1, Ordering::SeqCst);
    let restore = run_raeva(&app, TempDir::new().unwrap().path(), &["sync", "--frozen"]);
    assert_status(&restore, 9, "a disagreeing checksum file");

    state.store(2, Ordering::SeqCst);
    assert_success(&sync(&["sync"]), "stored bytes");
    assert_eq!(marked(), [(true, false); 2]);
    // The flag lets a run take unverified stored bytes; `--update` asks
    // for the checksum file of a marked one again. The platform this sync
    // keeps pins the same file.
    let update = sync(&[
        "sync",
        "--update",
        "--allow-missing-checksums",
        "--platforms",
        &host,
    ]);
    assert_success(&update, "verified download");
    assert_eq!(marked(), [(false, false); 2]);
    assert!(
        !fs::read_to_string(&lock_path)
            .unwrap()
            .contains("missing_checksum")
    );
}

/// A plain sync that keeps the lock as written and downloads a marked file
/// again, into an empty store, drops the marker a checksum file published
/// since then verifies, and says so.
#[test]
fn a_plain_sync_that_downloads_a_marked_file_a_checksum_file_verifies_clears_it() {
    let published = Arc::new(AtomicBool::new(false));
    let sidecar = published.clone();
    let server = StubServer::start(move |request| {
        if request.path == format!("{JAR_PATH}.sha256") && !sidecar.load(Ordering::SeqCst) {
            return Response::new(404, "");
        }
        serve(&request.path, b"jar bytes", true)
    });
    let url = format!("http://{}/", server.addr());
    let base = TempDir::new().unwrap();
    let app = base.path().join("app");
    project(&app, &url);
    let lock_path = app.join("raeva.lock");
    let marked = || Lockfile::read(&lock_path).unwrap().platforms[0].artifacts[0].missing_checksum;
    let home = TempDir::new().unwrap();
    let allowed = run_raeva(&app, home.path(), &["sync", "--allow-missing-checksums"]);
    assert_success(&allowed, "allowed");
    assert!(marked());

    published.store(true, Ordering::SeqCst);
    let fresh = TempDir::new().unwrap();
    let downloaded = run_raeva(&app, fresh.path(), &["sync"]);
    assert_success(&downloaded, "downloaded again");
    let said = String::from_utf8_lossy(&downloaded.stderr);
    assert!(said.contains("now verified by a checksum file"), "{said}");
    assert!(!marked());
    assert_success(&run_raeva(&app, fresh.path(), &["sync"]), "stored");
    assert!(!marked());
}

/// A POM marker clears as the jar's does, and a checksum file published
/// later that disagrees with the pinned bytes is refused.
#[test]
fn a_pom_accepted_without_a_checksum_file_is_checked_by_one_published_later() {
    let state = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let published = state.clone();
    let server = StubServer::start(move |request| {
        if request.path == "/test/lib/1/lib-1.pom.sha256" {
            return match published.load(Ordering::SeqCst) {
                0 => Response::new(404, ""),
                1 => Response::new(200, BlobId::from_bytes(b"other").to_string()),
                _ => Response::new(200, BlobId::from_bytes(POM).to_string()),
            };
        }
        serve(&request.path, b"jar bytes", true)
    });
    let url = format!("http://{}/", server.addr());
    let base = TempDir::new().unwrap();
    let app = base.path().join("app");
    project(&app, &url);
    let lock_path = app.join("raeva.lock");
    let marked = || {
        let lock = Lockfile::read(&lock_path).unwrap();
        let row = &lock.platforms[0].artifacts[0];
        (row.missing_checksum, row.pom_missing_checksum)
    };
    let home = TempDir::new().unwrap();
    let sync = |args: &[&str]| run_raeva(&app, home.path(), args);
    assert_success(&sync(&["sync", "--allow-missing-checksums"]), "allowed");
    assert_eq!(marked(), (false, true));
    assert!(
        fs::read_to_string(&lock_path)
            .unwrap()
            .contains("\npom_missing_checksum = true\n")
    );

    state.store(1, Ordering::SeqCst);
    assert_status(
        &sync(&["sync", "--update"]),
        9,
        "a disagreeing checksum file",
    );
    assert_eq!(marked(), (false, true));

    state.store(2, Ordering::SeqCst);
    assert_success(&sync(&["sync", "--update"]), "verified download");
    assert_eq!(marked(), (false, false));

    // The cache keeps the POM as verified, so a lock written without the
    // pin from that copy does not mark it.
    fs::remove_file(&lock_path).unwrap();
    let again = sync(&["sync", "--allow-missing-checksums", "--offline"]);
    assert_success(&again, "from the cache");
    assert_eq!(marked(), (false, false));
}

/// A jar only the second repository serves, restored on a fresh home by
/// `sync --frozen` or `sync` with the lock, is found offline: the lock pin
/// admits it there as it does in the first repository.
#[test]
fn a_restored_jar_of_a_later_repository_resolves_offline() {
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>\
               <artifactId>a</artifactId><version>1</version></project>";
    let serve = |jar: bool| {
        StubServer::start(move |request| {
            serve_sha256(&request.path, |path| match path {
                "/org/example/a/1/a-1.pom" => Some(pom),
                "/org/example/a/1/a-1.jar" if jar => Some("a jar"),
                _ => None,
            })
        })
    };
    let first = serve(false);
    let second = serve(true);
    let (_central, central) = local_central();
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"first\"\nurl = \"http://{}/\"\n\
             [[repositories]]\nid = \"second\"\nurl = \"http://{}/\"\n{central}",
            first.addr(),
            second.addr()
        ),
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>org.example</groupId><artifactId>a</artifactId><version>1</version>\
         </dependency></dependencies></project>",
    )
    .unwrap();
    let sync = |home: &TempDir, args: &[&str]| run_raeva(project.path(), home.path(), args);
    assert_success(&sync(&TempDir::new().unwrap(), &["sync"]), "sync");
    for restore in [&["sync", "--frozen"][..], &["sync"]] {
        let home = TempDir::new().unwrap();
        assert_success(&sync(&home, restore), "restore");
        assert_success(
            &sync(&home, &["--offline", "sync", "--frozen"]),
            &format!("offline frozen after {restore:?}"),
        );
        fs::write(
            project.path().join("pom.xml"),
            fs::read_to_string(project.path().join("pom.xml"))
                .unwrap()
                .replace("<project>", "<project><!-- edit -->"),
        )
        .unwrap();
        assert_success(
            &sync(&home, &["--offline", "sync"]),
            &format!("offline sync after an edit, {restore:?}"),
        );
    }
}

/// A jar whose `.sha256` and `.sha1` both disagree with its bytes: the
/// sync fails on the `.sha256`, naming the jar's URL and the repository's
/// id, and says how to tell a wrong checksum file from wrong bytes and how
/// to get past it.
#[test]
fn a_wrong_sha256_file_is_named_with_what_to_do() {
    let jar: &[u8] = b"jar bytes";
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/test/lib/1/lib-1.pom" => Response::new(200, POM),
        "/test/lib/1/lib-1.pom.sha1" => Response::new(200, sha1_hex(POM)),
        "/test/lib/1/lib-1.jar" => Response::new(200, jar),
        "/test/lib/1/lib-1.jar.sha1" => Response::new(200, sha1_hex(b"other")),
        "/test/lib/1/lib-1.jar.sha256" => Response::new(200, "0".repeat(64)),
        _ => Response::new(404, ""),
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>test</groupId><artifactId>lib</artifactId><version>1</version>\
         </dependency></dependencies></project>",
    )
    .unwrap();
    write_repo_toml(project.path(), "central", &url);
    let output = run_raeva(project.path(), TempDir::new().unwrap().path(), &["sync"]);
    assert_status(&output, 9, "a wrong .sha256");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for text in [
        &format!("checksum mismatch for {url}test/lib/1/lib-1.jar: expected sha256:"),
        "(the repository's .sha256 file)",
        "The repository 'central' served bytes that do not match the .sha256 file",
        "when they match, the repository's .sha256 file is wrong",
        "mirror the repository id 'central' in settings.xml",
        "No .sha1 or .md5 file of the repository, which Maven checks by default, vouches",
    ] {
        assert!(stderr.contains(text), "{text}\n{stderr}");
    }
}

/// A jar whose `.sha1` has disagreed with its bytes for years and that has
/// no `.sha256`, as repo.osgeo.org serves opendap 2.1: the hint does not
/// send the user to run the command again later, but says what a second
/// run tells and what to do when the checksum file is wrong.
#[test]
fn a_stale_sha1_file_is_not_blamed_on_the_transfer() {
    let jar: &[u8] = b"jar bytes";
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/test/lib/1/lib-1.pom" => Response::new(200, POM),
        "/test/lib/1/lib-1.pom.sha1" => Response::new(200, sha1_hex(POM)),
        "/test/lib/1/lib-1.jar" => Response::new(200, jar),
        "/test/lib/1/lib-1.jar.sha1" => Response::new(200, sha1_hex(b"an older jar")),
        _ => Response::new(404, ""),
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>test</groupId><artifactId>lib</artifactId><version>1</version>\
         </dependency></dependencies></project>",
    )
    .unwrap();
    write_repo_toml(project.path(), "osgeo", &url);
    let output = run_raeva(project.path(), TempDir::new().unwrap().path(), &["sync"]);
    assert_status(&output, 9, "a stale .sha1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for text in [
        &format!("checksum mismatch for {url}test/lib/1/lib-1.jar: expected sha1:"),
        "(the repository's .sha1 file)",
        "The repository 'osgeo' served bytes that do not match the .sha1 file",
        "If a second run gets the same checksum, the transfer is not at fault",
        "when they match, the repository's .sha1 file is wrong",
        "mirror the repository id 'osgeo' in settings.xml",
    ] {
        assert!(stderr.contains(text), "{text}\n{stderr}");
    }
    assert!(!stderr.contains("again later"), "{stderr}");
}

/// A POM whose `.sha256` and `.sha1` are wrong, served by a settings.xml
/// mirror of Central: the error names the mirror and the id of the
/// repository it stands in for, the id a `<mirrorOf>` takes.
#[test]
fn a_wrong_sha256_file_of_a_mirror_names_the_mirrored_id() {
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/test/lib/1/lib-1.pom" => Response::new(200, POM),
        "/test/lib/1/lib-1.pom.sha1" => Response::new(200, sha1_hex(b"other")),
        "/test/lib/1/lib-1.pom.sha256" => Response::new(200, "0".repeat(64)),
        _ => Response::new(404, ""),
    });
    let mirror = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>test</groupId><artifactId>lib</artifactId><version>1</version>\
         </dependency></dependencies></project>",
    )
    .unwrap();
    let maven_home = TempDir::new().unwrap();
    fs::create_dir_all(maven_home.path().join(".m2")).unwrap();
    fs::write(
        maven_home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stand-in</id><mirrorOf>*</mirrorOf>\
             <url>{mirror}</url></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    let mut command = raeva_command(project.path(), home.path());
    crate::common::isolate_maven_user_home(&mut command, maven_home.path(), "");
    let output = command.arg("sync").output().unwrap();
    assert_status(&output, 9, "a wrong .sha256 of a mirror");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for text in [
        "(the repository's .sha256 file)",
        &format!(
            "The mirror {mirror} of the repository 'central' served bytes that do not match \
             the .sha256 file"
        ),
        "mirror the repository id 'central' in settings.xml",
    ] {
        assert!(stderr.contains(text), "{text}\n{stderr}");
    }
}

/// A POM and a jar whose `.sha256` disagrees with their bytes while their
/// `.sha1` agrees, as some mirrors serve them: Maven checks only the
/// `.sha1` and builds, and raeva locks the SHA-256 of the bytes with a
/// warning that names the repository, the file and both checksum files.
/// raeva.lock then decides, frozen and in `lock verify`, whatever the
/// checksum files say.
#[test]
fn a_wrong_sha256_file_with_a_matching_sha1_locks_with_a_warning() {
    let jar: &[u8] = b"jar bytes";
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/test/lib/1/lib-1.pom" => Response::new(200, POM),
        "/test/lib/1/lib-1.pom.sha1" => Response::new(200, sha1_hex(POM)),
        "/test/lib/1/lib-1.pom.sha256" => Response::new(200, "0".repeat(64)),
        "/test/lib/1/lib-1.jar" => Response::new(200, jar),
        "/test/lib/1/lib-1.jar.sha1" => Response::new(200, sha1_hex(jar)),
        "/test/lib/1/lib-1.jar.sha256" => Response::new(200, "1".repeat(64)),
        _ => Response::new(404, ""),
    });
    let url = format!("http://{}/", server.addr());
    let dir = TempDir::new().unwrap();
    project(dir.path(), &url);
    let home = TempDir::new().unwrap();
    let output = run_raeva(dir.path(), home.path(), &["--json", "sync"]);
    assert_success(&output, "a wrong .sha256 and a matching .sha1");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let warned: Vec<String> = (envelope["data"]["warnings"]
        .as_array()
        .into_iter()
        .flatten())
    .filter(|warning| warning["code"] == "SHA256_FILE_MISMATCH")
    .map(|warning| warning["message"].as_str().unwrap_or_default().to_string())
    .collect();
    assert_eq!(warned.len(), 2, "{envelope}");
    for file in ["lib-1.pom", "lib-1.jar"] {
        assert!(
            warned
                .iter()
                .any(|message| message.contains(&format!("test/lib/1/{file}"))
                    && message.contains(&format!("the repository 'repo' ({url})"))
                    && message.contains("does not match the .sha256 file")
                    && message.contains("matches its .sha1 file")),
            "{file}: {warned:?}"
        );
    }
    assert_jar(dir.path(), jar, &url);
    let lock = Lockfile::read(&dir.path().join("raeva.lock")).unwrap();
    assert_eq!(
        lock.platforms[0].artifacts[0].pom_sha256,
        Some(BlobId::from_bytes(POM))
    );
    for args in [
        &["sync", "--frozen"][..],
        &["--offline", "sync", "--frozen"],
        &["lock", "verify", "--download"],
    ] {
        assert_success(&run_raeva(dir.path(), home.path(), args), &args.join(" "));
    }
    // The pins decide a frozen sync into an empty store, which reads no
    // checksum file.
    let frozen = run_raeva(
        dir.path(),
        TempDir::new().unwrap().path(),
        &["sync", "--frozen"],
    );
    assert_success(&frozen, "frozen into an empty store");
    assert!(
        !String::from_utf8_lossy(&frozen.stderr).contains("SHA256_FILE_MISMATCH"),
        "{}",
        String::from_utf8_lossy(&frozen.stderr)
    );
    let other = TempDir::new().unwrap();
    project(other.path(), &url);
    let text = run_raeva(other.path(), TempDir::new().unwrap().path(), &["sync"]);
    assert_success(&text, "text output");
    let stderr = String::from_utf8_lossy(&text.stderr);
    assert!(
        stderr.contains("warning: SHA256_FILE_MISMATCH:") && stderr.contains("and 1 more"),
        "{stderr}"
    );
}

/// SNAPSHOT metadata whose `.sha256` is stale while its `.sha1` matches, as
/// on Central's snapshot repository for a publisher that deploys only
/// Maven's default checksums, from a repository whose snapshots
/// `<checksumPolicy>` is `fail`: Maven checks the `.sha1` and builds, and
/// raeva locks the build with a warning, then checks it again, online and
/// offline.
#[test]
fn snapshot_metadata_with_a_stale_sha256_and_a_matching_sha1_locks() {
    let snapshot = b"<metadata><groupId>test</groupId><artifactId>lib</artifactId>\
        <version>1-SNAPSHOT</version><versioning><snapshot><timestamp>20260101.010101</timestamp>\
        <buildNumber>1</buildNumber></snapshot><lastUpdated>20260101010101</lastUpdated>\
        </versioning></metadata>";
    let metadata = "/test/lib/1-SNAPSHOT/maven-metadata.xml";
    let server = StubServer::start(move |request| match request.path.strip_prefix(metadata) {
        Some(".sha256") => Response::new(200, "0".repeat(64)),
        Some(".sha1") => Response::new(200, sha1_hex(snapshot)),
        _ => serve(&request.path, b"jar bytes", true),
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
             <artifactId>app</artifactId><version>1</version><repositories><repository>\
             <id>snapshots</id><url>{url}</url><releases><enabled>false</enabled></releases>\
             <snapshots><checksumPolicy>fail</checksumPolicy></snapshots></repository>\
             </repositories><dependencies><dependency><groupId>test</groupId>\
             <artifactId>lib</artifactId><version>1-SNAPSHOT</version></dependency>\
             </dependencies></project>"
        ),
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    let output = run_raeva(project.path(), home.path(), &["--json", "sync"]);
    assert_success(&output, "a stale .sha256 of SNAPSHOT metadata");
    assert!(
        warning_codes(&output).contains(&"SHA256_FILE_MISMATCH".to_string()),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    assert!(lock.contains("timestamp = \"20260101.010101\""), "{lock}");
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--frozen"]),
        "frozen",
    );
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["--offline", "sync", "--frozen"],
        ),
        "offline frozen",
    );
}

/// JitPack's `main-SNAPSHOT` of a branch: its metadata's `<snapshot>` has
/// a commit hash for a timestamp, and its `<version>` already names the
/// build. Maven 3.9.16 appends `<timestamp>-<buildNumber>` to the version
/// asked for, whatever its shape, and fetches `main-0d99b1a098-1`, a
/// version it reads as a release, from its own directory. raeva locks that
/// version, and a frozen sync, online or offline, keeps it.
#[test]
fn a_jitpack_branch_snapshot_resolves_to_the_build_maven_takes() {
    const BUILD: &str = "main-0d99b1a098-1";
    let metadata = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <metadata modelVersion=\"1.0.0\"><groupId>com.github.test</groupId>\
         <artifactId>lib</artifactId><version>{BUILD}</version><versioning><snapshot>\
         <timestamp>0d99b1a098</timestamp><buildNumber>1</buildNumber></snapshot>\
         </versioning></metadata>"
    );
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.github.test</groupId>\
         <artifactId>lib</artifactId><version>{BUILD}</version></project>"
    );
    let files = [
        (
            "/com/github/test/lib/main-SNAPSHOT/maven-metadata.xml".to_string(),
            metadata.into_bytes(),
        ),
        (
            format!("/com/github/test/lib/{BUILD}/lib-{BUILD}.pom"),
            pom.into_bytes(),
        ),
        (
            format!("/com/github/test/lib/{BUILD}/lib-{BUILD}.jar"),
            b"jar bytes".to_vec(),
        ),
    ];
    let server = StubServer::start(move |request| with_sha1(&request.path, files.clone()));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>com.github.test</groupId><artifactId>lib</artifactId>\
         <version>main-SNAPSHOT</version></dependency></dependencies></project>",
    )
    .unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!("[[repositories]]\nid = \"jitpack.io\"\nurl = \"{url}\"\nsnapshots = true\n"),
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let lock = Lockfile::read(&project.path().join("raeva.lock")).unwrap();
    let packages: Vec<String> = (lock.platforms[0].modules[0].packages.iter())
        .map(|package| package.coordinate.to_string())
        .collect();
    assert_eq!(packages, [format!("com.github.test:lib:{BUILD}:jar")]);
    assert_jar(project.path(), b"jar bytes", &url);
    for args in [
        &["sync", "--frozen"][..],
        &["sync", "--offline", "--frozen"],
    ] {
        assert_success(
            &run_raeva(project.path(), home.path(), args),
            &args.join(" "),
        );
    }
}

/// com.anji-plus:captcha:1.4.0 on Central: its `.sha1` and `.md5` are
/// stale, while the `X-Checksum-SHA1` header Central sends with the jar,
/// or the `x-goog-meta-checksum-sha1` its Google mirror sends, matches the
/// bytes. maven-resolver checks the header and reads no checksum file, so
/// Maven builds, even with `-C`; so does raeva, and raeva.lock pins the
/// bytes. Other bytes with a header that matches them still fail the pin.
#[test]
fn a_matching_checksum_header_outvotes_stale_checksum_files() {
    for header in ["X-Checksum-SHA1", "x-goog-meta-checksum-sha1"] {
        let replaced = Arc::new(AtomicBool::new(false));
        let server = StubServer::start({
            let replaced = Arc::clone(&replaced);
            move |request| {
                let jar: &[u8] = match replaced.load(Ordering::SeqCst) {
                    false => b"jar bytes",
                    true => b"other jar bytes",
                };
                match request.path.as_str() {
                    "/test/lib/1/lib-1.pom" => Response::new(200, POM),
                    "/test/lib/1/lib-1.pom.sha1" => Response::new(200, sha1_hex(POM)),
                    "/test/lib/1/lib-1.jar" => {
                        Response::new(200, jar.to_vec()).header(header, sha1_hex(jar))
                    }
                    "/test/lib/1/lib-1.jar.sha1" => Response::new(200, sha1_hex(b"an older jar")),
                    "/test/lib/1/lib-1.jar.md5" => Response::new(200, "0".repeat(32)),
                    _ => Response::new(404, ""),
                }
            }
        });
        let jar: &[u8] = b"jar bytes";
        let url = format!("http://{}/", server.addr());
        let project = TempDir::new().unwrap();
        fs::write(
            project.path().join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
             <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
             <groupId>test</groupId><artifactId>lib</artifactId><version>1</version>\
             </dependency></dependencies></project>",
        )
        .unwrap();
        write_repo_toml(project.path(), "central", &url);
        let home = TempDir::new().unwrap();
        assert_success(&run_raeva(project.path(), home.path(), &["sync"]), header);
        assert_jar(project.path(), jar, &url);
        assert_success(
            &run_raeva(project.path(), home.path(), &["sync", "--frozen"]),
            header,
        );
        replaced.store(true, Ordering::SeqCst);
        let restore = run_raeva(
            project.path(),
            TempDir::new().unwrap().path(),
            &["sync", "--frozen"],
        );
        assert_status(&restore, 7, header);
    }
}

/// A checksum header that does not match the bytes fails them as a broken
/// transfer, as in maven-resolver, even when the checksum files match:
/// raeva is never looser than Maven on integrity.
#[test]
fn a_checksum_header_that_does_not_match_fails_the_file() {
    let jar: &'static [u8] = b"jar bytes";
    for header in ["X-Checksum-SHA1", "x-goog-meta-checksum-sha1"] {
        let server = StubServer::start(move |request| match request.path.as_str() {
            "/test/lib/1/lib-1.pom" => Response::new(200, POM),
            "/test/lib/1/lib-1.pom.sha1" => Response::new(200, sha1_hex(POM)),
            "/test/lib/1/lib-1.jar" => {
                Response::new(200, jar).header(header, sha1_hex(b"other bytes"))
            }
            "/test/lib/1/lib-1.jar.sha1" => Response::new(200, sha1_hex(jar)),
            _ => Response::new(404, ""),
        });
        let project = TempDir::new().unwrap();
        fs::write(
            project.path().join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
             <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
             <groupId>test</groupId><artifactId>lib</artifactId><version>1</version>\
             </dependency></dependencies></project>",
        )
        .unwrap();
        write_repo_toml(
            project.path(),
            "central",
            &format!("http://{}/", server.addr()),
        );
        let synced = run_raeva(project.path(), TempDir::new().unwrap().path(), &["sync"]);
        assert_status(&synced, 9, header);
        let stderr = String::from_utf8_lossy(&synced.stderr);
        assert!(stderr.contains("checksum header"), "{header}: {stderr}");
        assert!(
            stderr.contains("run the command again"),
            "{header}: {stderr}"
        );
        assert!(!project.path().join("raeva.lock").exists(), "{header}");
    }
}

/// repo.dotcms.com publishes no `.sha256` files and redirects every miss to
/// a busy server, so raeva's probes for them meet 429, where other hosts
/// answer 404. The `.sha256` is a checksum Maven never reads: whatever it
/// answers, raeva goes on to the `.sha1` and `.md5` as after a 404. With
/// neither, the file is as unchecked as with no `.sha256`, which
/// `--allow-missing-checksums` admits. A `.sha256` answered with a wait of
/// an hour holds back no `.sha1`.
#[test]
fn a_busy_answer_for_a_sha256_file_is_no_sha256_file() {
    let jar: &'static [u8] = b"jar bytes";
    for (sha1, args, retry_after) in [
        (true, &["sync"][..], None),
        (false, &["sync", "--allow-missing-checksums"], None),
        (true, &["sync"], Some("3600")),
    ] {
        let server = StubServer::start(move |request| {
            let path = request.path.as_str();
            if path.ends_with(".sha256") {
                return match retry_after {
                    Some(after) => Response::new(429, "").header("Retry-After", after),
                    None => Response::new(429, ""),
                };
            }
            match path {
                "/test/lib/1/lib-1.pom" => Response::new(200, POM),
                "/test/lib/1/lib-1.pom.sha1" if sha1 => Response::new(200, sha1_hex(POM)),
                "/test/lib/1/lib-1.jar" => Response::new(200, jar),
                "/test/lib/1/lib-1.jar.sha1" if sha1 => Response::new(200, sha1_hex(jar)),
                _ => Response::new(404, ""),
            }
        });
        let url = format!("http://{}/", server.addr());
        let project = TempDir::new().unwrap();
        fs::write(
            project.path().join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
             <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
             <groupId>test</groupId><artifactId>lib</artifactId><version>1</version>\
             </dependency></dependencies></project>",
        )
        .unwrap();
        write_repo_toml(project.path(), "central", &url);
        let mut command = raeva_command(project.path(), TempDir::new().unwrap().path());
        // An answer to come back after an hour refuses the server at once.
        if retry_after.is_none() {
            command.env("RAEVA_RETRIES", "0");
        }
        let output = command.args(args).output().unwrap();
        assert_success(&output, &args.join(" "));
        assert_jar(project.path(), jar, &url);
    }
}

/// The CHECKSUM_MISSING line names a command that lists every file taken
/// without a checksum file, and it does so on a later run too, when the
/// store already holds them and nothing is downloaded or warned again.
#[test]
fn the_missing_checksum_hint_names_a_command_that_still_lists_them() {
    let server = StubServer::start(|request| match request.path.as_str() {
        "/test/a/1/a-1.pom" => Response::new(200, pom_for("a")),
        "/test/b/1/b-1.pom" => Response::new(200, pom_for("b")),
        "/test/a/1/a-1.pom.sha1" => Response::new(200, sha1_hex(pom_for("a").as_bytes())),
        "/test/b/1/b-1.pom.sha1" => Response::new(200, sha1_hex(pom_for("b").as_bytes())),
        "/test/a/1/a-1.jar" | "/test/b/1/b-1.jar" => Response::new(200, "jar"),
        _ => Response::new(404, ""),
    });
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies>\
         <dependency><groupId>test</groupId><artifactId>a</artifactId><version>1</version></dependency>\
         <dependency><groupId>test</groupId><artifactId>b</artifactId><version>1</version></dependency>\
         </dependencies></project>",
    )
    .unwrap();
    write_repo_toml(
        project.path(),
        "central",
        &format!("http://{}/", server.addr()),
    );
    let home = TempDir::new().unwrap();
    let synced = run_raeva(
        project.path(),
        home.path(),
        &["sync", "--allow-missing-checksums"],
    );
    assert_success(&synced, "sync");
    let stderr = String::from_utf8_lossy(&synced.stderr);
    let line = (stderr.lines())
        .find(|line| line.starts_with("warning: CHECKSUM_MISSING:"))
        .unwrap_or_else(|| panic!("{stderr}"));
    let hint = line.split('\'').nth(1).unwrap_or_else(|| panic!("{line}"));
    let args: Vec<&str> = hint.split_whitespace().skip(1).collect();
    let listed = run_raeva(project.path(), home.path(), &args);
    assert_success(&listed, hint);
    let listed = format!(
        "{}{}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr)
    );
    for jar in ["test/a/1/a-1.jar", "test/b/1/b-1.jar"] {
        assert!(listed.contains(jar), "{hint}: {listed}");
    }
}

fn pom_for(artifact: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>{artifact}</artifactId><version>1</version></project>"
    )
}

/// A SNAPSHOT deployed Maven 2 style, `lib-1.0-SNAPSHOT.jar` with no
/// `maven-metadata.xml` in its version directory, as jpms.pkg.st serves
/// checker-qual 3.43.0-SNAPSHOT: Maven's request for the metadata gets a
/// 404, so it takes the version asked for and fetches the files under that
/// name. raeva locks them, and a frozen sync, online or offline, keeps
/// them. A later repository whose metadata names a build still wins over
/// the plain files of an earlier one, as in Maven 3.9.12 and 3.10.0.
/// Metadata that does not parse counts as none, with a warning, as both
/// read past it: the first repository in the declared order that serves
/// the plain files gives them, remote or local. Metadata with no checksum
/// file still fails the sync unless a local repository serves the plain
/// files.
#[test]
fn a_snapshot_without_version_metadata_resolves_to_its_plain_files() {
    const DIR: &str = "/org/test/lib/1.0-SNAPSHOT";
    const BUILD: &str = "1.0-20240101.010101-1";
    let pom = b"<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                <artifactId>lib</artifactId><version>1.0-SNAPSHOT</version></project>";
    let plain = [
        (format!("{DIR}/lib-1.0-SNAPSHOT.pom"), pom.to_vec()),
        (format!("{DIR}/lib-1.0-SNAPSHOT.jar"), b"plain jar".to_vec()),
    ];
    let listed = [
        (
            format!("{DIR}/maven-metadata.xml"),
            b"<metadata><groupId>org.test</groupId><artifactId>lib</artifactId>\
              <version>1.0-SNAPSHOT</version><versioning/></metadata>"
                .to_vec(),
        ),
        plain[0].clone(),
        plain[1].clone(),
    ];
    let plain = StubServer::start(move |request| with_sha1(&request.path, plain.clone()));
    let listed = StubServer::start(move |request| with_sha1(&request.path, listed.clone()));
    let stamped = [
        (
            format!("{DIR}/maven-metadata.xml"),
            b"<metadata><groupId>org.test</groupId><artifactId>lib</artifactId>\
              <version>1.0-SNAPSHOT</version><versioning><snapshot>\
              <timestamp>20240101.010101</timestamp><buildNumber>1</buildNumber></snapshot>\
              <lastUpdated>20240101010101</lastUpdated></versioning></metadata>"
                .to_vec(),
        ),
        (format!("{DIR}/lib-{BUILD}.pom"), pom.to_vec()),
        (format!("{DIR}/lib-{BUILD}.jar"), b"stamped jar".to_vec()),
    ];
    let stamped = StubServer::start(move |request| with_sha1(&request.path, stamped.clone()));
    let unreadable = [(
        format!("{DIR}/maven-metadata.xml"),
        b"<metadata><versioning>".to_vec(),
    )];
    let broken = StubServer::start(move |request| with_sha1(&request.path, unreadable.clone()));
    // Metadata with no checksum file fails raeva's checksum policy, where
    // Maven's default warns and reads it.
    let unchecked = StubServer::start(|request| match request.path.as_str() {
        "/org/test/lib/1.0-SNAPSHOT/maven-metadata.xml" => {
            Response::new(200, "<metadata><versioning>")
        }
        _ => Response::new(404, ""),
    });
    let plain = format!("http://{}/", plain.addr());
    let stamped = format!("http://{}/", stamped.addr());
    let broken = format!("http://{}/", broken.addr());
    let unchecked = format!("http://{}/", unchecked.addr());
    let listed = format!("http://{}/", listed.addr());
    let toml = |repositories: &[&String]| -> String {
        (repositories.iter().enumerate())
            .map(|(i, url)| {
                format!("[[repositories]]\nid = \"r{i}\"\nurl = \"{url}\"\nsnapshots = true\n")
            })
            .collect()
    };
    let dependent = "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>org.test</groupId><artifactId>lib</artifactId>\
         <version>1.0-SNAPSHOT</version></dependency></dependencies></project>";
    // Unreadable metadata before or after the plain files, and behind an
    // empty `file:` repository, as Maven 3.9.12 and 3.10.0 read them.
    let nothing = TempDir::new().unwrap();
    let nothing = url::Url::from_directory_path(nothing.path())
        .unwrap()
        .to_string();
    for repositories in [
        vec![&plain, &broken],
        vec![&broken, &plain],
        vec![&plain, &nothing, &broken],
    ] {
        let project = TempDir::new().unwrap();
        fs::write(project.path().join("pom.xml"), dependent).unwrap();
        fs::write(project.path().join("raeva.toml"), toml(&repositories)).unwrap();
        let home = TempDir::new().unwrap();
        let sync = run_raeva(project.path(), home.path(), &["sync"]);
        let case = format!("{repositories:?}");
        assert_success(&sync, &case);
        let stderr = String::from_utf8_lossy(&sync.stderr);
        assert!(stderr.contains("POM_PROBLEM"), "{case}: {stderr}");
        assert_jar(project.path(), b"plain jar", &plain);
        for args in [
            &["sync", "--frozen"][..],
            &["sync", "--offline", "--frozen"],
        ] {
            let replay = run_raeva(project.path(), home.path(), args);
            assert_success(&replay, &format!("{case} {}", args.join(" ")));
        }
    }
    // Plain files no metadata names may lose to a build the unchecked
    // metadata names, so the sync fails, as 0.6.0 failed it; metadata that
    // names no build keeps its plain files, as 0.6.0 kept them.
    for repositories in [vec![&plain, &unchecked], vec![&plain, &broken, &unchecked]] {
        let project = TempDir::new().unwrap();
        fs::write(project.path().join("pom.xml"), dependent).unwrap();
        fs::write(project.path().join("raeva.toml"), toml(&repositories)).unwrap();
        let home = TempDir::new().unwrap();
        let sync = run_raeva(project.path(), home.path(), &["sync"]);
        let stderr = String::from_utf8_lossy(&sync.stderr);
        assert!(!sync.status.success(), "{repositories:?}: {stderr}");
        assert!(stderr.contains(&unchecked), "{stderr}");
        assert!(!project.path().join("raeva.lock").exists());
    }
    {
        let project = TempDir::new().unwrap();
        fs::write(project.path().join("pom.xml"), dependent).unwrap();
        fs::write(
            project.path().join("raeva.toml"),
            toml(&[&listed, &unchecked]),
        )
        .unwrap();
        let home = TempDir::new().unwrap();
        assert_success(&run_raeva(project.path(), home.path(), &["sync"]), &listed);
        assert_jar(project.path(), b"plain jar", &listed);
    }
    // A local repository's plain files stand where it is declared, over
    // metadata that cannot be read or checked: first, after a remote that
    // has nothing, after the unreadable metadata, and as a remote one a
    // mirror serves from disk.
    let local_dir = TempDir::new().unwrap();
    let dir = local_dir.path().join(DIR.trim_start_matches('/'));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("lib-1.0-SNAPSHOT.pom"), pom).unwrap();
    fs::write(dir.join("lib-1.0-SNAPSHOT.jar"), b"local jar").unwrap();
    let local = url::Url::from_directory_path(local_dir.path())
        .unwrap()
        .to_string();
    let empty = StubServer::start(|_| Response::new(404, ""));
    let empty = format!("http://{}/", empty.addr());
    let mirrored = "https://mirrored.invalid/".to_string();
    let mirror = format!(
        "<settings><mirrors><mirror><id>disk</id><mirrorOf>r0</mirrorOf><url>{local}</url>\
         </mirror></mirrors></settings>"
    );
    let cases = [&broken, &unchecked].into_iter().flat_map(|failed| {
        [
            (vec![&local, failed], None),
            (vec![&empty, &local, failed], None),
            (vec![&mirrored, failed], Some(&mirror)),
        ]
    });
    let cases = cases.chain([(vec![&broken, &local], None)]);
    for (repositories, settings) in cases {
        let project = TempDir::new().unwrap();
        fs::write(project.path().join("pom.xml"), dependent).unwrap();
        fs::write(project.path().join("raeva.toml"), toml(&repositories)).unwrap();
        let home = TempDir::new().unwrap();
        if let Some(settings) = settings {
            fs::create_dir_all(home.path().join(".m2")).unwrap();
            fs::write(home.path().join(".m2/settings.xml"), settings).unwrap();
        }
        let case = format!("{repositories:?}");
        assert_success(&run_raeva(project.path(), home.path(), &["sync"]), &case);
        let lock = Lockfile::read(&project.path().join("raeva.lock")).unwrap();
        let pin = lock.platforms[0].artifacts[0].pin().unwrap();
        let local_jar = BlobId::from_bytes(b"local jar");
        assert_eq!(pin.as_sha256(), Some(&local_jar), "{case}");
    }
    for (repositories, jar, url) in [
        (vec![&plain], &b"plain jar"[..], &plain),
        (vec![&plain, &stamped], b"stamped jar", &stamped),
    ] {
        let project = TempDir::new().unwrap();
        fs::write(project.path().join("pom.xml"), dependent).unwrap();
        fs::write(project.path().join("raeva.toml"), toml(&repositories)).unwrap();
        let home = TempDir::new().unwrap();
        let sync = run_raeva(project.path(), home.path(), &["sync"]);
        assert_success(&sync, url);
        let stderr = String::from_utf8_lossy(&sync.stderr);
        assert!(!stderr.contains("POM_PROBLEM"), "{stderr}");
        let lock = Lockfile::read(&project.path().join("raeva.lock")).unwrap();
        let packages: Vec<String> = (lock.platforms[0].modules[0].packages.iter())
            .map(|package| package.coordinate.to_string())
            .collect();
        assert_eq!(packages, ["org.test:lib:1.0-SNAPSHOT:jar"]);
        assert_jar(project.path(), jar, url);
        for args in [
            &["sync", "--frozen"][..],
            &["sync", "--offline", "--frozen"],
        ] {
            assert_success(
                &run_raeva(project.path(), home.path(), args),
                &args.join(" "),
            );
        }
    }
}

/// An imported BOM at a SNAPSHOT version reads past version metadata that
/// cannot be read to the plain files another repository serves, before or
/// after it, as a dependency does and Maven 3.9.12 and 3.10.0 do; one with
/// no checksum file fails the sync.
#[test]
fn a_snapshot_bom_behind_unreadable_metadata_resolves_to_its_plain_files() {
    const DIR: &str = "/org/test/bom/1.0-SNAPSHOT";
    let bom = b"<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                <artifactId>bom</artifactId><version>1.0-SNAPSHOT</version>\
                <packaging>pom</packaging></project>";
    let plain = [(format!("{DIR}/bom-1.0-SNAPSHOT.pom"), bom.to_vec())];
    let plain = StubServer::start(move |request| with_sha1(&request.path, plain.clone()));
    let unreadable = [(
        format!("{DIR}/maven-metadata.xml"),
        b"<metadata><versioning>".to_vec(),
    )];
    let broken = StubServer::start(move |request| with_sha1(&request.path, unreadable.clone()));
    let unchecked = StubServer::start(|request| match request.path.as_str() {
        "/org/test/bom/1.0-SNAPSHOT/maven-metadata.xml" => {
            Response::new(200, "<metadata><versioning>")
        }
        _ => Response::new(404, ""),
    });
    let (plain, broken, unchecked) = (
        format!("http://{}/", plain.addr()),
        format!("http://{}/", broken.addr()),
        format!("http://{}/", unchecked.addr()),
    );
    for repositories in [[&plain, &broken], [&broken, &plain], [&plain, &unchecked]] {
        let project = TempDir::new().unwrap();
        fs::write(
            project.path().join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencyManagement>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>bom</artifactId>\
         <version>1.0-SNAPSHOT</version><type>pom</type><scope>import</scope></dependency>\
         </dependencies></dependencyManagement></project>",
        )
        .unwrap();
        let toml: String = (repositories.iter().enumerate())
            .map(|(i, url)| {
                format!("[[repositories]]\nid = \"r{i}\"\nurl = \"{url}\"\nsnapshots = true\n")
            })
            .collect();
        fs::write(project.path().join("raeva.toml"), toml).unwrap();
        let home = TempDir::new().unwrap();
        let case = format!("{repositories:?}");
        let sync = run_raeva(project.path(), home.path(), &["sync"]);
        // Metadata that fails the checksum policy fails the sync, as it
        // does a dependency's.
        if repositories[1] == &unchecked {
            let stderr = String::from_utf8_lossy(&sync.stderr);
            assert!(!sync.status.success(), "{stderr}");
            assert!(stderr.contains(&unchecked), "{stderr}");
            assert!(!project.path().join("raeva.lock").exists());
            continue;
        }
        assert_success(&sync, &case);
        let lock = Lockfile::read(&project.path().join("raeva.lock")).unwrap();
        let read = BlobId::from_bytes(bom);
        let row = &lock.platforms[0].support_poms["org.test:bom:1.0-SNAPSHOT"];
        assert_eq!((&row.sha256, &row.repo_url), (&read, &plain), "{case}");
        for args in [
            &["sync", "--frozen"][..],
            &["sync", "--offline", "--frozen"],
        ] {
            let replay = run_raeva(project.path(), home.path(), args);
            assert_success(&replay, &format!("{case} {}", args.join(" ")));
        }
    }
}
