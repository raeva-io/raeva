//! A cold sync asks each repository for each file once: a repository listed
//! before the one that serves the files is not asked again for a parent its
//! dependencies share or a jar it lacks, platforms resolved together download
//! each jar once and read a version listing once, and a locked restore reads
//! no checksum files for the files the lock pins.

use std::collections::HashMap;
use std::fs;

use rv_maven_types::BlobId;
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{assert_success, local_central, run_raeva};

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
    let serve = |files: HashMap<String, String>| {
        StubServer::start(move |request| {
            let (path, sidecar) = match request.path.strip_suffix(".sha256") {
                Some(path) => (path, true),
                None => (request.path.as_str(), false),
            };
            match files.get(path) {
                Some(body) if sidecar => {
                    Response::new(200, BlobId::from_bytes(body.as_bytes()).to_string())
                }
                Some(body) => Response::new(200, body.clone()),
                None => Response::new(404, ""),
            }
        })
    };
    // The repository listed first has the libraries' POMs but not their jars.
    let poms = (files.iter())
        .filter(|(path, _)| path.ends_with(".pom") && !path.contains("parent"))
        .map(|(path, body)| (path.clone(), body.clone()))
        .collect();
    let empty = serve(poms);
    let served = serve(files);
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
    let restored = counts(&served);
    let sidecars = |counts: &HashMap<String, usize>| -> usize {
        (counts.iter())
            .filter(|(path, _)| path.ends_with(".sha256") || path.ends_with(".sha1"))
            .map(|(_, count)| count)
            .sum()
    };
    assert_eq!(sidecars(&restored), sidecars(&downloaded), "{restored:?}");
    for artifact in ["a", "b", "c"] {
        let jar = format!("/org/example/{artifact}/1/{artifact}-1.jar");
        assert_eq!(restored[&jar], 2, "{restored:?}");
    }
}
