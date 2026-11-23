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
    write_repo_toml,
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
