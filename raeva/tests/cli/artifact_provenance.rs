use std::fs;
use std::path::Path;

use rv_lock::Lockfile;
use rv_maven_types::BlobId;
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{
    assert_status, assert_success, local_central, raeva_command, run_raeva, write_repo_toml,
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
        raeva_command(&a, home.path())
            .env(rv_config::MAVEN_USER_HOME_TEST_ENV, maven_home.path())
            .args(args)
            .output()
            .unwrap()
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
