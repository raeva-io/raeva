//! A cold sync asks each repository for each file once: a repository listed
//! before the one that serves the files is not asked again for a parent its
//! dependencies share or a jar it lacks, platforms resolved together download
//! each jar once and read a version listing once, and a locked restore reads
//! no checksum files for the files the lock pins.

use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rv_maven_types::BlobId;
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{
    assert_success, envelope, local_central, pom, raeva_command, run_raeva, serve_sha256, sha1_hex,
    sha256_repository, write_repo_toml,
};

const PARENT: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>\
<artifactId>parent</artifactId><version>1</version><packaging>pom</packaging></project>";

fn library(artifact: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.example</groupId>\
         <artifactId>parent</artifactId><version>1</version></parent>\
         <artifactId>{artifact}</artifactId></project>"
    )
}

fn counts(server: &StubServer) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for request in server.requests() {
        *counts.entry(request.path).or_default() += 1;
    }
    counts
}

#[test]
fn a_cold_sync_asks_for_each_file_once() {
    let mut files = HashMap::from([(
        "/org/example/parent/1/parent-1.pom".to_string(),
        PARENT.to_string(),
    )]);
    for artifact in ["a", "b", "c"] {
        let dir = format!("/org/example/{artifact}/1/{artifact}-1");
        files.insert(format!("{dir}.pom"), library(artifact));
        files.insert(format!("{dir}.jar"), format!("{artifact} jar"));
    }
    let listing = "/org/example/a/maven-metadata.xml".to_string();
    files.insert(
        listing.clone(),
        "<metadata><groupId>org.example</groupId><artifactId>a</artifactId><versioning>\
         <versions><version>1</version></versions></versioning></metadata>"
            .to_string(),
    );
    // The repository listed first has the libraries' POMs but not their jars.
    let poms: Vec<(String, String)> = (files.iter())
        .filter(|(path, _)| path.ends_with(".pom") && !path.contains("parent"))
        .map(|(path, body)| (path.clone(), body.clone()))
        .collect();
    let empty = sha256_repository(poms);
    let served = sha256_repository(files);
    let (_central, central) = local_central();
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"empty\"\nurl = \"http://{}/\"\n\
             [[repositories]]\nid = \"served\"\nurl = \"http://{}/\"\n{central}",
            empty.addr(),
            served.addr()
        ),
    )
    .unwrap();
    let dependencies: String = ["a", "b", "c"]
        .iter()
        .map(|artifact| {
            let version = if *artifact == "a" { "[1,2)" } else { "1" };
            format!(
                "<dependency><groupId>org.example</groupId><artifactId>{artifact}</artifactId>\
                 <version>{version}</version></dependency>"
            )
        })
        .collect();
    fs::write(
        project.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
             <artifactId>app</artifactId><version>1</version>\
             <dependencies>{dependencies}</dependencies></project>"
        ),
    )
    .unwrap();
    let sync = ["sync", "--platforms", "linux-x86_64,macos-aarch64"];
    let home = TempDir::new().unwrap();
    assert_success(&run_raeva(project.path(), home.path(), &sync), "sync");

    let asked = counts(&empty);
    assert_eq!(asked["/org/example/parent/1/parent-1.pom"], 1, "{asked:?}");
    assert!(asked.values().all(|count| *count == 1), "{asked:?}");
    let downloaded = counts(&served);
    assert_eq!(downloaded[&listing], 1, "{downloaded:?}");
    for artifact in ["a", "b", "c"] {
        let jar = format!("/org/example/{artifact}/1/{artifact}-1.jar");
        assert_eq!(downloaded[&jar], 1, "{downloaded:?}");
    }

    let cold = TempDir::new().unwrap();
    let frozen = [&sync[..], &["--frozen"]].concat();
    assert_success(
        &run_raeva(project.path(), cold.path(), &frozen),
        "frozen sync",
    );
    // The check resolves again, reading the version listing and its
    // checksum once more, and the pinned files without theirs.
    let restored = counts(&served);
    let sidecars = |counts: &HashMap<String, usize>| -> usize {
        (counts.iter())
            .filter(|(path, _)| path.ends_with(".sha256") || path.ends_with(".sha1"))
            .filter(|(path, _)| !path.contains("maven-metadata.xml"))
            .map(|(_, count)| count)
            .sum()
    };
    assert_eq!(sidecars(&restored), sidecars(&downloaded), "{restored:?}");
    assert_eq!(restored[&listing], 2, "{restored:?}");
    for artifact in ["a", "b", "c"] {
        let jar = format!("/org/example/{artifact}/1/{artifact}-1.jar");
        assert_eq!(restored[&jar], 2, "{restored:?}");
    }
}

/// A jar's download slot is free again once the jar has arrived: the next
/// jar is asked for while the first one's checksum file, as slow as a
/// `.sha256` miss at Central's CDN, is still pending.
#[test]
fn a_cold_sync_asks_for_the_next_jar_while_a_checksum_file_is_pending() {
    const HELD: Duration = Duration::from_secs(2);
    let jars = ["a", "b", "c", "d"];
    let mut files = HashMap::new();
    for artifact in jars {
        let dir = format!("/t/{artifact}/1/{artifact}-1");
        files.insert(format!("{dir}.pom"), pom(artifact, ""));
        files.insert(format!("{dir}.jar"), format!("{artifact} jar"));
    }
    let asked: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();
    let server = StubServer::start({
        let asked = asked.clone();
        move |request| {
            let response = serve_sha256(&request.path, |path| files.get(path));
            if request.path.ends_with(".jar") {
                (asked.lock().unwrap()).insert(request.path.clone(), Instant::now());
            }
            if request.path.ends_with(".jar.sha256") {
                response.delayed(HELD)
            } else {
                response
            }
        }
    });
    let project = TempDir::new().unwrap();
    write_repo_toml(
        project.path(),
        "central",
        &format!("http://{}/", server.addr()),
    );
    let toml = fs::read_to_string(project.path().join("raeva.toml")).unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!("[network]\nconcurrency = 1\n{toml}"),
    )
    .unwrap();
    let dependencies: String = (jars.iter())
        .map(|artifact| {
            format!(
                "<dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
                 <version>1</version></dependency>"
            )
        })
        .collect();
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &format!("<dependencies>{dependencies}</dependencies>"),
        ),
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");

    let asked = asked.lock().unwrap();
    assert_eq!(asked.len(), jars.len(), "{asked:?}");
    let (first, last) = (asked.values().min().unwrap(), asked.values().max().unwrap());
    let spread = last.saturating_duration_since(*first);
    assert!(
        spread < HELD,
        "the last jar was asked for {spread:?} after the first, whose checksum file was \
         held for {HELD:?}"
    );
}

/// A repository that serves `chain`, each artifact depending on the next,
/// with a `.sha1` for each file and the `.sha256` of each POM answered by
/// `sha256` after `held`, and the times each POM was asked for.
fn chain_repository(
    chain: &'static [&'static str],
    held: Duration,
    sha256: fn(&str) -> Response,
) -> (StubServer, Arc<Mutex<HashMap<String, Instant>>>) {
    let mut files = HashMap::new();
    for (at, artifact) in chain.iter().enumerate() {
        let dependency = chain.get(at + 1).map_or(String::new(), |next| {
            format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>{next}</artifactId>\
                 <version>1</version></dependency></dependencies>"
            )
        });
        let dir = format!("/t/{artifact}/1/{artifact}-1");
        files.insert(format!("{dir}.pom"), pom(artifact, &dependency));
        files.insert(format!("{dir}.jar"), format!("{artifact} jar"));
    }
    let asked: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();
    let server = StubServer::start({
        let asked = asked.clone();
        move |request| {
            let path = request.path.as_str();
            if let Some(file) = path.strip_suffix(".sha1") {
                return match files.get(file) {
                    Some(body) => Response::new(200, sha1_hex(body.as_bytes())),
                    None => Response::new(404, ""),
                };
            }
            if let Some(file) = path.strip_suffix(".sha256") {
                return match files.get(file) {
                    Some(body) if file.ends_with(".pom") => sha256(body).delayed(held),
                    _ => Response::new(404, ""),
                };
            }
            if path.ends_with(".pom") {
                (asked.lock().unwrap()).insert(path.to_string(), Instant::now());
            }
            match files.get(path) {
                Some(body) => Response::new(200, body.as_str()),
                None => Response::new(404, ""),
            }
        }
    });
    (server, asked)
}

fn chain_project(server: &StubServer, first: &str) -> TempDir {
    let project = TempDir::new().unwrap();
    write_repo_toml(
        project.path(),
        "central",
        &format!("http://{}/", server.addr()),
    );
    let dependency = format!(
        "<dependencies><dependency><groupId>t</groupId><artifactId>{first}</artifactId>\
         <version>1</version></dependency></dependencies>"
    );
    fs::write(project.path().join("pom.xml"), pom("app", &dependency)).unwrap();
    project
}

/// A cold sync reads a chain of POMs, each naming the next, without waiting
/// for each one's `.sha256`, as slow to be missing as at Central's CDN, once
/// the repository has lacked one: it takes each POM whose `.sha1` matches,
/// and checks its `.sha256` before the lock is written. A missing one gives
/// the weak-hash warning, as it does when the sync waits for it.
#[test]
fn a_cold_sync_reads_a_chain_of_poms_without_waiting_for_each_sha256() {
    const HELD: Duration = Duration::from_millis(1500);
    const CHAIN: &[&str] = &["a", "b", "c", "d", "e", "f"];
    let (server, asked) = chain_repository(CHAIN, HELD, |_| Response::new(404, ""));
    let project = chain_project(&server, CHAIN[0]);
    let home = TempDir::new().unwrap();
    let synced = run_raeva(project.path(), home.path(), &["--json", "sync"]);
    assert_success(&synced, "sync");

    let asked = asked.lock().unwrap();
    let at = |artifact: &str| asked[&format!("/t/{artifact}/1/{artifact}-1.pom")];
    let spread = at(CHAIN[CHAIN.len() - 1]).saturating_duration_since(at(CHAIN[0]));
    assert!(
        spread < 2 * HELD,
        "the last POM of the chain was asked for {spread:?} after the first, each \
         `.sha256` held for {HELD:?}"
    );
    let envelope = envelope(&synced);
    let weak = (envelope["data"]["warnings"].as_array().unwrap().iter())
        .find(|warning| warning["code"] == "WEAK_HASH_FALLBACK");
    let weak = weak.unwrap_or_else(|| panic!("{envelope}"));
    assert_eq!(weak["context"]["count"], 2 * CHAIN.len(), "{envelope}");
}

/// A POM taken on its `.sha1` while its `.sha256` was still pending fails the
/// sync, before a lock is written, when a proxy refuses the `.sha256`, with
/// the error a read that waited for it gives.
#[test]
fn a_sync_fails_on_a_late_sha256_that_does_not_match() {
    const HELD: Duration = Duration::from_millis(500);
    const CHAIN: &[&str] = &["a", "b", "c"];
    let (server, _) = chain_repository(CHAIN, HELD, |body| {
        if !body.contains("<dependencies>") {
            Response::new(407, "")
        } else {
            Response::new(404, "")
        }
    });
    let project = chain_project(&server, CHAIN[0]);
    let home = TempDir::new().unwrap();
    let synced = run_raeva(project.path(), home.path(), &["sync"]);
    let stderr = String::from_utf8_lossy(&synced.stderr);
    assert_eq!(synced.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains("407 Proxy Authentication Required for http://")
            && stderr.contains("/t/c/1/c-1.pom.sha256")
            && stderr.contains("through t:a:1 -> t:b:1"),
        "{stderr}"
    );
    assert!(!project.path().join("raeva.lock").exists(), "{stderr}");
}

/// A pass that fails on a POM taken on its `.sha1` before it reaches the
/// check, here a module's parent read for its inherited groupId, still fails
/// with the refusal of that POM's `.sha256`, as a read that waited for it.
#[test]
fn a_parent_taken_on_its_sha1_fails_on_its_sha256() {
    const HELD: Duration = Duration::from_millis(500);
    let parent = pom("p1", "<packaging>pom</packaging>");
    let forged = "not a POM".to_string();
    let server = StubServer::start(move |request| {
        let path = request.path.as_str();
        let (file, sidecar) = path.rsplit_once(".pom").unwrap_or((path, ""));
        let body = match file {
            "/t/p1/1/p1-1" => &parent,
            "/t/p2/1/p2-1" => &forged,
            _ => return Response::new(404, ""),
        };
        match (file, sidecar) {
            (_, "") => Response::new(200, body.as_str()),
            (_, ".sha1") => Response::new(200, sha1_hex(body.as_bytes())),
            ("/t/p2/1/p2-1", ".sha256") => Response::new(407, "").delayed(HELD),
            (_, ".sha256") => Response::new(404, "").delayed(HELD),
            _ => Response::new(404, ""),
        }
    });
    let project = TempDir::new().unwrap();
    write_repo_toml(
        project.path(),
        "central",
        &format!("http://{}/", server.addr()),
    );
    let modules = "<packaging>pom</packaging><modules><module>one</module>\
                   <module>two</module></modules>";
    fs::write(project.path().join("pom.xml"), pom("root", modules)).unwrap();
    for (module, parent) in [("one", "p1"), ("two", "p2")] {
        fs::create_dir(project.path().join(module)).unwrap();
        let own = match module {
            "one" => "<groupId>t</groupId><version>1</version>",
            _ => "",
        };
        let body = format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
             <artifactId>{parent}</artifactId><version>1</version><relativePath/></parent>\
             {own}<artifactId>{module}</artifactId></project>"
        );
        fs::write(project.path().join(module).join("pom.xml"), body).unwrap();
    }
    let home = TempDir::new().unwrap();
    let synced = run_raeva(project.path(), home.path(), &["sync"]);
    let stderr = String::from_utf8_lossy(&synced.stderr);
    assert_eq!(synced.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains("407 Proxy Authentication Required for http://")
            && stderr.contains("/t/p2/1/p2-1.pom.sha256"),
        "{stderr}"
    );
    assert!(!project.path().join("raeva.lock").exists(), "{stderr}");
}

/// A cold `--frozen` asks for every POM the lock pins at once, also from the
/// repository searched before the one that serves it: the last POM of a
/// chain only the chain's POMs name is asked for while the first one's
/// answer is still held back, which a resolution reading them one after
/// another cannot do.
#[test]
fn a_cold_frozen_check_asks_for_the_pinned_poms_at_once() {
    const HELD: Duration = Duration::from_secs(3);
    let chain = ["a", "b", "c", "d"];
    let mut files = HashMap::new();
    for (index, artifact) in chain.iter().enumerate() {
        let dependency = chain.get(index + 1).map_or(String::new(), |next| {
            format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>{next}</artifactId>\
                 <version>1</version></dependency></dependencies>"
            )
        });
        let dir = format!("/t/{artifact}/1/{artifact}-1");
        files.insert(format!("{dir}.pom"), pom(artifact, &dependency));
        files.insert(format!("{dir}.jar"), format!("{artifact} jar"));
    }
    let holding = Arc::new(AtomicBool::new(false));
    let asked: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();
    let server = StubServer::start({
        let (holding, asked) = (holding.clone(), asked.clone());
        move |request| {
            let (path, sidecar) = match request.path.strip_suffix(".sha256") {
                Some(path) => (path, true),
                None => (request.path.as_str(), false),
            };
            let Some(body) = files.get(path) else {
                return Response::new(404, "");
            };
            if sidecar {
                return Response::new(200, BlobId::from_bytes(body.as_bytes()).to_string());
            }
            let response = Response::new(200, body.clone());
            if !holding.load(Ordering::SeqCst) {
                return response;
            }
            (asked.lock().unwrap())
                .entry(request.path.clone())
                .or_insert_with(Instant::now);
            if path == "/t/a/1/a-1.pom" {
                response.delayed(HELD)
            } else {
                response
            }
        }
    });
    let missed: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();
    let empty = StubServer::start({
        let (holding, missed) = (holding.clone(), missed.clone());
        move |request| {
            if holding.load(Ordering::SeqCst) {
                (missed.lock().unwrap())
                    .entry(request.path.clone())
                    .or_insert_with(Instant::now);
            }
            Response::new(404, "")
        }
    });
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"empty\"\nurl = \"http://{}/\"\n\
             [[repositories]]\nid = \"central\"\nurl = \"http://{}/\"\n",
            empty.addr(),
            server.addr()
        ),
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<dependencies><dependency><groupId>t</groupId><artifactId>a</artifactId>\
             <version>1</version></dependency></dependencies>",
        ),
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");

    holding.store(true, Ordering::SeqCst);
    let cold = TempDir::new().unwrap();
    assert_success(
        &run_raeva(project.path(), cold.path(), &["sync", "--frozen"]),
        "frozen sync",
    );
    let first = asked.lock().unwrap()["/t/a/1/a-1.pom"];
    for (repository, asked) in [("central", &asked), ("empty", &missed)] {
        let last = asked.lock().unwrap()["/t/d/1/d-1.pom"];
        let after = last.saturating_duration_since(first);
        assert!(
            after < HELD,
            "{repository} was asked for d-1.pom {after:?} after central for a-1.pom, \
             whose answer was held for {HELD:?}"
        );
    }
}

/// A repository only the project's remote parents declare is known once the
/// resolution has read the parent declaring it. The pinned POMs it serves
/// are then asked for at once, by a cold `--frozen` check and by a cold
/// plain sync of the lock, whose restore needs that resolution to trust the
/// repository, and only from the repositories searched before it.
#[test]
fn a_cold_sync_asks_at_once_for_what_a_remote_parents_repository_serves() {
    const HELD: Duration = Duration::from_secs(3);
    let chain = ["a", "b", "c", "d"];
    let mut files = HashMap::new();
    for (index, artifact) in chain.iter().enumerate() {
        let dependency = chain.get(index + 1).map_or(String::new(), |next| {
            format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>{next}</artifactId>\
                 <version>1</version></dependency></dependencies>"
            )
        });
        let dir = format!("/t/{artifact}/1/{artifact}-1");
        files.insert(format!("{dir}.pom"), pom(artifact, &dependency));
        files.insert(format!("{dir}.jar"), format!("{artifact} jar"));
    }
    let holding = Arc::new(AtomicBool::new(false));
    let asked: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();
    let declared = StubServer::start({
        let (holding, asked) = (holding.clone(), asked.clone());
        move |request| {
            let (path, sidecar) = match request.path.strip_suffix(".sha256") {
                Some(path) => (path, true),
                None => (request.path.as_str(), false),
            };
            let Some(body) = files.get(path) else {
                return Response::new(404, "");
            };
            if sidecar {
                return Response::new(200, BlobId::from_bytes(body.as_bytes()).to_string());
            }
            let response = Response::new(200, body.clone());
            if !holding.load(Ordering::SeqCst) {
                return response;
            }
            (asked.lock().unwrap())
                .entry(request.path.clone())
                .or_insert_with(Instant::now);
            if path == "/t/a/1/a-1.pom" {
                response.delayed(HELD)
            } else {
                response
            }
        }
    });
    // The parent's repository, searched before the grandparent's, and
    // Central, searched after it.
    let (first, central) = (
        StubServer::start(|_| Response::new(404, "")),
        StubServer::start(|_| Response::new(404, "")),
    );
    let parent = |artifact: &str, parent: &str, id: &str, url: String| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{parent}<groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version><packaging>pom</packaging>\
             <repositories><repository><id>{id}</id><url>http://{url}/</url></repository>\
             </repositories></project>"
        )
    };
    let parents = HashMap::from([
        (
            "/t/parent/1/parent-1.pom",
            parent(
                "parent",
                "<parent><groupId>t</groupId><artifactId>grand</artifactId><version>1</version>\
                 </parent>",
                "first",
                first.addr().to_string(),
            ),
        ),
        (
            "/t/grand/1/grand-1.pom",
            parent("grand", "", "declared", declared.addr().to_string()),
        ),
    ]);
    let parents = sha256_repository(parents);
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"parents\"\nurl = \"http://{}/\"\n",
            parents.addr()
        ),
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
         <artifactId>parent</artifactId><version>1</version><relativePath/></parent>\
         <artifactId>app</artifactId><dependencies><dependency><groupId>t</groupId>\
         <artifactId>a</artifactId><version>1</version></dependency></dependencies>\
         </project>",
    )
    .unwrap();
    // A remote parent's repository on a private address needs the user's
    // allowlist.
    let home = || {
        let home = TempDir::new().unwrap();
        fs::write(
            home.path().join("config.toml"),
            format!(
                "[security]\ntransitive_repository_allowlist = [\"http://{}/\", \"http://{}/\"]\n",
                first.addr(),
                declared.addr()
            ),
        )
        .unwrap();
        home
    };
    let sync = |home: &TempDir, args: &[&str]| {
        (raeva_command(project.path(), home.path()))
            .env(rv_repo::CENTRAL_TEST_ENV, central.addr().to_string())
            .args(args)
            .output()
            .unwrap()
    };
    let warm = home();
    assert_success(&sync(&warm, &["sync"]), "sync");
    let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();

    holding.store(true, Ordering::SeqCst);
    for args in [&["sync", "--frozen"][..], &["sync"]] {
        asked.lock().unwrap().clear();
        let (first_before, central_before) = (counts(&first), counts(&central));
        let cold = home();
        assert_success(&sync(&cold, args), &args.join(" "));
        assert_eq!(
            fs::read_to_string(project.path().join("raeva.lock")).unwrap(),
            lock,
            "{args:?}"
        );
        let asked = asked.lock().unwrap();
        let after = asked["/t/d/1/d-1.pom"].saturating_duration_since(asked["/t/a/1/a-1.pom"]);
        assert!(
            after < HELD,
            "{args:?}: d-1.pom was asked for {after:?} after a-1.pom, whose answer was held \
             for {HELD:?}"
        );
        let (first, central) = (counts(&first), counts(&central));
        for artifact in chain {
            let path = format!("/t/{artifact}/1/{artifact}-1.pom");
            let probes = |now: &HashMap<String, usize>, before: &HashMap<String, usize>, path| {
                now.get(path).unwrap_or(&0) - before.get(path).unwrap_or(&0)
            };
            let in_central = format!("/maven2{path}");
            assert_eq!(
                probes(&first, &first_before, &path),
                1,
                "{args:?}: {path} from first"
            );
            assert_eq!(
                probes(&central, &central_before, &in_central),
                0,
                "{args:?}: {path} from Central"
            );
        }
    }
}

/// A home a locked sync filled holds jars the lock pin admitted without
/// their checksum files. `--update` takes them as the pins verified them
/// when locked, as it takes the POMs, and downloads none again.
#[test]
fn an_update_takes_the_restored_jars_the_lock_pins() {
    let files = HashMap::from([
        (
            "/org/example/a/1/a-1.pom".to_string(),
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>\
             <artifactId>a</artifactId><version>1</version></project>"
                .to_string(),
        ),
        ("/org/example/a/1/a-1.jar".to_string(), "a jar".to_string()),
    ]);
    let served = sha256_repository(files);
    let (_central, central) = local_central();
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"served\"\nurl = \"http://{}/\"\n{central}",
            served.addr()
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
    let sync = |home: &TempDir, args: &[&str]| {
        assert_success(
            &run_raeva(project.path(), home.path(), args),
            &format!("{args:?}"),
        );
    };
    sync(&TempDir::new().unwrap(), &["sync"]);
    let home = TempDir::new().unwrap();
    sync(&home, &["sync"]);
    let jar = "/org/example/a/1/a-1.jar";
    let asked = |path: &str| counts(&served).get(path).copied().unwrap_or(0);
    let restored = (asked(jar), asked(&format!("{jar}.sha256")));
    for round in [1, 2] {
        let before = (asked(jar), asked(&format!("{jar}.sha256")));
        sync(&home, &["sync", "--update"]);
        let after = (asked(jar), asked(&format!("{jar}.sha256")));
        assert_eq!(
            (after.0 - before.0, after.1 - before.1),
            (0, 0),
            "update {round}, restored {restored:?}: {:?}",
            counts(&served)
        );
    }
}

/// A jar the root's management fixes the version of below its own
/// dependencies is downloaded once its POM is read, not once the walk places
/// it: x's while slow-1.pom, which the walk reads before it places x, is still
/// held back.
/// A managed POM that relocates has no jar of its own to download.
#[test]
fn a_cold_sync_downloads_a_managed_jar_once_its_pom_is_read() {
    const HELD: Duration = Duration::from_secs(3);
    let dependency = |artifact: &str, version: &str| {
        format!(
            "<dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version></dependency>"
        )
    };
    let files = HashMap::from([
        (
            "/t/a/1/a-1.pom".to_string(),
            pom(
                "a",
                &format!(
                    "<dependencies>{}{}</dependencies>",
                    dependency("x", "0.9"),
                    dependency("y", "0.9")
                ),
            ),
        ),
        ("/t/slow/1/slow-1.pom".to_string(), pom("slow", "")),
        ("/t/x/1/x-1.pom".to_string(), pom("x", "")),
        (
            "/t/y/1/y-1.pom".to_string(),
            pom(
                "y",
                "<distributionManagement><relocation><artifactId>z</artifactId>\
                 </relocation></distributionManagement>",
            ),
        ),
        ("/t/z/1/z-1.pom".to_string(), pom("z", "")),
    ]);
    let jars =
        ["a", "slow", "x", "y", "z"].map(|artifact| format!("/t/{artifact}/1/{artifact}-1.jar"));
    let asked: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();
    let server = StubServer::start({
        let asked = asked.clone();
        move |request| {
            (asked.lock().unwrap())
                .entry(request.path.clone())
                .or_insert_with(Instant::now);
            let (path, sidecar) = match request.path.strip_suffix(".sha256") {
                Some(path) => (path, true),
                None => (request.path.as_str(), false),
            };
            let body = match files.get(path) {
                Some(body) => body.clone(),
                None if jars.iter().any(|jar| jar == path) => format!("{path} bytes"),
                None => return Response::new(404, ""),
            };
            if sidecar {
                return Response::new(200, BlobId::from_bytes(body.as_bytes()).to_string());
            }
            let response = Response::new(200, body);
            if path == "/t/slow/1/slow-1.pom" {
                response.delayed(HELD)
            } else {
                response
            }
        }
    });
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"central\"\nurl = \"http://{}/\"\n",
            server.addr()
        ),
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &format!(
                "<dependencyManagement><dependencies>{}{}</dependencies></dependencyManagement>\
                 <dependencies>{}{}</dependencies>",
                dependency("x", "1"),
                dependency("y", "1"),
                dependency("a", "1"),
                dependency("slow", "1")
            ),
        ),
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");

    let asked = asked.lock().unwrap();
    let slow = asked["/t/slow/1/slow-1.pom"];
    let after = asked["/t/x/1/x-1.jar"].saturating_duration_since(slow);
    assert!(
        after < HELD,
        "x-1.jar was asked for {after:?} after slow-1.pom, whose answer was held for {HELD:?}"
    );
    assert!(asked.contains_key("/t/z/1/z-1.jar"), "{asked:?}");
    assert!(!asked.contains_key("/t/y/1/y-1.jar"), "{asked:?}");
}

/// A dependency of a type no core handler knows has the resolution read
/// the build extensions, as Maven does, from the plugin repositories: the
/// super POM's Central there is `repo.maven.apache.org`, not raeva's
/// `repo1.maven.org`, and a mirror of `central` serves both. That read is
/// not the project's resolution, so a cold `--frozen` check asks the mirror
/// for each POM the lock pins once, not again as the other Central.
#[test]
fn a_cold_frozen_check_asks_for_each_pom_once_beside_an_extension() {
    // An empty jar: the extension defines no artifact handlers.
    let jar = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec();
    let mirror = sha256_repository([
        ("/t/a/1/a-1.pom", pom("a", "").into_bytes()),
        ("/t/a/1/a-1.zip", b"a zip".to_vec()),
        ("/t/ext/1/ext-1.pom", pom("ext", "").into_bytes()),
        ("/t/ext/1/ext-1.jar", jar),
    ]);
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<dependencies><dependency><groupId>t</groupId><artifactId>a</artifactId>\
             <version>1</version><type>zip</type></dependency></dependencies><build>\
             <extensions><extension><groupId>t</groupId><artifactId>ext</artifactId>\
             <version>1</version></extension></extensions></build>",
        ),
    )
    .unwrap();
    let home = || {
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
                 <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
                mirror.addr()
            ),
        )
        .unwrap();
        home
    };
    assert_success(&run_raeva(project.path(), home().path(), &["sync"]), "sync");

    let before = counts(&mirror);
    assert_success(
        &run_raeva(project.path(), home().path(), &["sync", "--frozen"]),
        "frozen sync",
    );
    let twice: Vec<_> = (counts(&mirror).into_iter())
        .filter(|(path, count)| {
            path.ends_with(".pom") && count - before.get(path).unwrap_or(&0) > 1
        })
        .collect();
    assert!(twice.is_empty(), "{twice:?}");
}

/// A `pom`-typed dependency's file is the POM the resolution reads as its
/// model, so a cold `--frozen` check asks for it once.
#[test]
fn a_cold_frozen_check_asks_once_for_a_pom_typed_dependency() {
    let packaged = pom("p", "<packaging>pom</packaging>");
    let central = sha256_repository([("/t/p/1/p-1.pom", packaged)]);
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"central\"\nurl = \"http://{}/\"\n",
            central.addr()
        ),
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<dependencies><dependency><groupId>t</groupId><artifactId>p</artifactId>\
             <version>1</version><type>pom</type></dependency></dependencies>",
        ),
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");

    let before = counts(&central);
    let cold = TempDir::new().unwrap();
    assert_success(
        &run_raeva(project.path(), cold.path(), &["sync", "--frozen"]),
        "frozen sync",
    );
    let path = "/t/p/1/p-1.pom";
    let asked = counts(&central).get(path).unwrap_or(&0) - before.get(path).unwrap_or(&0);
    assert_eq!(asked, 1, "{:?}", central.requests());
}

/// A `.sha256` asked for late that the repository answers busy keeps the
/// stall watchdog from firing while the sync waits for it before the lock is
/// written: waiting out a busy answer, at least 5 s, is progress.
#[test]
fn a_late_sha256_retried_after_a_busy_answer_is_not_a_stall() {
    const BUSY: usize = 1;
    let a = pom(
        "a",
        "<dependencies><dependency><groupId>t</groupId><artifactId>b</artifactId>\
         <version>1</version></dependency></dependencies>",
    );
    let b = pom("b", "");
    let busy = Arc::new(Mutex::new(0usize));
    let server = StubServer::start({
        let busy = busy.clone();
        move |request| {
            let path = request.path.as_str();
            let (file, sidecar) = path.rsplit_once(".pom").unwrap_or((path, ""));
            let body = match file {
                "/t/a/1/a-1" => &a,
                "/t/b/1/b-1" => &b,
                _ if path.ends_with(".jar") => return Response::new(200, "jar"),
                _ if path.ends_with(".jar.sha1") => return Response::new(200, sha1_hex(b"jar")),
                _ => return Response::new(404, ""),
            };
            match (file, sidecar) {
                // a's `.sha256` is missing, and known to be before b is named.
                ("/t/a/1/a-1", "") => {
                    Response::new(200, body.as_str()).delayed(Duration::from_millis(200))
                }
                (_, "") => Response::new(200, body.as_str()),
                (_, ".sha1") => Response::new(200, sha1_hex(body.as_bytes())),
                ("/t/b/1/b-1", ".sha256") => {
                    let mut busy = busy.lock().unwrap();
                    *busy += 1;
                    match *busy {
                        // Once b is read on its `.sha1`.
                        ..=BUSY => (Response::new(503, "").header("Retry-After", "1"))
                            .delayed(Duration::from_millis(500)),
                        _ => Response::new(404, ""),
                    }
                }
                _ => Response::new(404, ""),
            }
        }
    });
    let project = chain_project(&server, "a");
    let home = TempDir::new().unwrap();
    let synced = raeva_command(project.path(), home.path())
        .args(["sync"])
        .env("RAEVA_WORKSPACE_STALL_TIMEOUT_SECS", "2")
        .output()
        .unwrap();
    assert_success(&synced, "sync");
    assert_eq!(*busy.lock().unwrap(), BUSY + 1);
}
