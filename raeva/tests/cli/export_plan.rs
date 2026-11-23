//! `export-m2 --plan-json` describes the repository an export writes, so a
//! tool that cannot run raeva rebuilds it from the plan alone.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use rv_test_support::http::StubServer;
use tempfile::TempDir;

use crate::common::{
    assert_status, assert_success, raeva_command, run_raeva, serve_sha256, sha256_hex,
    write_with_sha256,
};

const TOKEN: &str = "tok3n-in-the-mirror-path";
const PASSWORD: &str = "s3cret-server-password";
const BUILD: &str = "1.0-20240101.010101-1";

fn pom(artifact: &str, version: &str, body: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
    )
}

/// The files of two repositories, `r/` for releases and `s/` for
/// snapshots, by path below the server root.
fn repositories() -> BTreeMap<String, Vec<u8>> {
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut put = |path: &str, bytes: String| {
        files.insert(path.to_string(), bytes.into_bytes());
    };
    put(
        "r/org/test/parent/1/parent-1.pom",
        pom("parent", "1", "<packaging>pom</packaging>"),
    );
    put(
        "r/org/test/bom/1/bom-1.pom",
        pom(
            "bom",
            "1",
            "<packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>dep</artifactId><version>2</version>\
             </dependency></dependencies></dependencyManagement>",
        ),
    );
    put(
        "r/org/test/lib/1.0/lib-1.0.pom",
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
         <artifactId>parent</artifactId><version>1</version></parent>\
         <artifactId>lib</artifactId><version>1.0</version>\
         <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>bom</artifactId><version>1</version><type>pom</type>\
         <scope>import</scope></dependency></dependencies></dependencyManagement>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>dep</artifactId>\
         </dependency></dependencies></project>"
            .to_string(),
    );
    put("r/org/test/lib/1.0/lib-1.0.jar", "lib jar".to_string());
    put(
        "r/org/test/lib/1.0/lib-1.0-sources.jar",
        "lib sources".to_string(),
    );
    put("r/org/test/dep/2/dep-2.pom", pom("dep", "2", ""));
    put("r/org/test/dep/2/dep-2.jar", "dep jar".to_string());
    put(
        "r/org/test/ranged/maven-metadata.xml",
        "<metadata><groupId>org.test</groupId><artifactId>ranged</artifactId><versioning>\
         <versions><version>1.0</version><version>1.5</version><version>2.0</version>\
         </versions></versioning></metadata>"
            .to_string(),
    );
    put(
        "r/org/test/ranged/1.5/ranged-1.5.pom",
        pom("ranged", "1.5", ""),
    );
    put(
        "r/org/test/ranged/1.5/ranged-1.5.jar",
        "ranged jar".to_string(),
    );
    let snap = "s/org/test/snap/1.0-SNAPSHOT";
    put(
        &format!("{snap}/maven-metadata.xml"),
        format!(
            "<metadata><groupId>org.test</groupId><artifactId>snap</artifactId>\
             <version>1.0-SNAPSHOT</version><versioning><snapshot>\
             <timestamp>20240101.010101</timestamp><buildNumber>1</buildNumber></snapshot>\
             <lastUpdated>20240101010101</lastUpdated><snapshotVersions>\
             <snapshotVersion><extension>jar</extension><value>{BUILD}</value>\
             <updated>20240101010101</updated></snapshotVersion>\
             <snapshotVersion><extension>pom</extension><value>{BUILD}</value>\
             <updated>20240101010101</updated></snapshotVersion>\
             </snapshotVersions></versioning></metadata>"
        ),
    );
    put(
        &format!("{snap}/snap-{BUILD}.pom"),
        pom("snap", "1.0-SNAPSHOT", ""),
    );
    put(&format!("{snap}/snap-{BUILD}.jar"), "snap jar".to_string());
    files
}

/// Serves `files` with `.sha256` sidecars, and the snapshot repository
/// also below a mirror path that holds [`TOKEN`].
fn serve(files: BTreeMap<String, Vec<u8>>) -> StubServer {
    StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let path = (path.strip_prefix(&format!("tok/{TOKEN}/")))
            .map_or_else(|| path.to_string(), |rest| rest.to_string());
        serve_sha256(&path, |path| files.get(path))
    })
}

/// A project on `server` whose snapshot repository the settings mirror
/// through a URL with [`TOKEN`] in its path, read from a secret-named
/// variable, and whose release repository has a `<server>` password.
struct Project {
    base: TempDir,
    home: TempDir,
}

impl Project {
    fn new(server: &StubServer) -> Self {
        let project = Self {
            base: TempDir::new().expect("base"),
            home: TempDir::new().expect("home"),
        };
        let root = project.root();
        fs::create_dir_all(&root).expect("project");
        let addr = server.addr();
        fs::write(
            root.join("raeva.toml"),
            format!(
                "[[repositories]]\nid = \"corp\"\nurl = \"http://{addr}/r/\"\n\
                 [[repositories]]\nid = \"snaps\"\nurl = \"http://{addr}/s/\"\nsnapshots = true\n"
            ),
        )
        .expect("raeva.toml");
        let dependency = |artifact: &str, version: &str| {
            format!(
                "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
                 <version>{version}</version></dependency>"
            )
        };
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                "1",
                &format!(
                    "<dependencies>{}{}{}</dependencies>",
                    dependency("lib", "1.0"),
                    dependency("ranged", "[1,2)"),
                    dependency("snap", "1.0-SNAPSHOT")
                ),
            ),
        )
        .expect("pom.xml");
        let m2 = project.home.path().join(".m2");
        fs::create_dir_all(&m2).expect(".m2");
        fs::write(
            m2.join("settings.xml"),
            format!(
                "<settings><servers><server><id>corp</id><username>deploy</username>\
                 <password>{PASSWORD}</password></server></servers><mirrors><mirror>\
                 <id>snap-mirror</id><mirrorOf>snaps</mirrorOf>\
                 <url>http://{addr}/tok/${{env.MIRROR_TOKEN}}/s/</url></mirror></mirrors>\
                 </settings>"
            ),
        )
        .expect("settings.xml");
        project
    }

    fn root(&self) -> std::path::PathBuf {
        self.base.path().join("project")
    }

    fn raeva(&self, args: &[&str]) -> std::process::Output {
        raeva_command(&self.root(), self.home.path())
            .env("MIRROR_TOKEN", TOKEN)
            .args(args)
            .output()
            .expect("run raeva")
    }

    fn plan(&self, args: &[&str]) -> serde_json::Value {
        let output = self.raeva(&[&["export-m2", "--plan-json"], args].concat());
        assert_success(&output, "export-m2 --plan-json");
        let text = String::from_utf8(output.stdout).expect("UTF-8 plan");
        for secret in [TOKEN, PASSWORD, "tok/", "deploy@"] {
            assert!(!text.contains(secret), "{secret} in the plan: {text}");
        }
        serde_json::from_str(&text).expect("JSON plan")
    }
}

/// Every file below `dir`, by its path there, but the export's own lock.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(at) = dirs.pop() {
        for entry in fs::read_dir(&at).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let relative = path.strip_prefix(dir).expect("below").to_string_lossy();
            let relative = relative.replace('\\', "/");
            if relative != ".raeva-export.lock" {
                files.insert(relative, fs::read(&path).expect("read"));
            }
        }
    }
    files
}

/// A repository rebuilt from `plan` alone, as a tool that cannot run raeva
/// would: each file fetched from its URL, here the stub's, and checked
/// against its SHA-256, and each generated file written as given.
fn rebuild(plan: &serde_json::Value, base: &str, served: &BTreeMap<String, Vec<u8>>) -> TempDir {
    let dir = TempDir::new().expect("rebuilt");
    let write = |path: &str, bytes: &[u8]| {
        assert!(!path.contains("..") && !path.starts_with('/'), "{path}");
        let dest = dir.path().join(path);
        fs::create_dir_all(dest.parent().expect("parent")).expect("dirs");
        fs::write(dest, bytes).expect("write");
    };
    for file in plan["files"].as_array().expect("files") {
        let url = file["url"].as_str().expect("url");
        let served = (url.strip_prefix(base))
            .and_then(|path| served.get(path))
            .unwrap_or_else(|| panic!("{url} is not a repository file"));
        assert_eq!(sha256_hex(served), file["sha256"], "{url}");
        write(file["path"].as_str().expect("path"), served);
    }
    for file in plan["generated"].as_array().expect("generated") {
        let content = file["content"].as_str().expect("content");
        write(file["path"].as_str().expect("path"), content.as_bytes());
    }
    dir
}

/// The plan names every file a clean export writes, with the URL of the
/// repository raeva.lock records, never the mirror's or a credential, and
/// a repository rebuilt from it is the export byte for byte: the parent
/// and imported BOM, the version list a range reads, the snapshot build,
/// its metadata and plain copy, the markers and the empty lists, and with
/// `--with-sources` the sources jar.
#[test]
fn a_repository_rebuilt_from_the_plan_is_the_export() {
    let served = repositories();
    let server = serve(served.clone());
    let project = Project::new(&server);
    assert_success(&project.raeva(&["sync"]), "sync");
    let base = format!("http://{}/", server.addr());
    let exported = TempDir::new().expect("export");
    let mut trees = Vec::new();
    for args in [&[][..], &["--with-sources"]] {
        let m2 = exported.path().join(format!("m2{}", trees.len()));
        let destination = ["--m2-path", m2.to_str().expect("path")];
        let output = project.raeva(&[&["export-m2"], args, &destination].concat());
        assert_success(&output, &format!("export-m2 {args:?}"));
        let plan = project.plan(args);
        assert_eq!(plan["version"], 1, "{plan}");
        let rebuilt = rebuild(&plan, &base, &served);
        let (expected, actual) = (tree(&m2), tree(rebuilt.path()));
        assert_eq!(
            expected.keys().collect::<Vec<_>>(),
            actual.keys().collect::<Vec<_>>()
        );
        for (path, bytes) in &expected {
            assert_eq!(
                String::from_utf8_lossy(bytes),
                String::from_utf8_lossy(&actual[path]),
                "{path}"
            );
        }
        trees.push(expected);
    }
    assert!(trees[1].contains_key("org/test/lib/1.0/lib-1.0-sources.jar"));
    assert!(!trees[0].contains_key("org/test/lib/1.0/lib-1.0-sources.jar"));
    let expected = &trees[0];
    for path in [
        "org/test/parent/1/parent-1.pom",
        "org/test/bom/1/bom-1.pom",
        "org/test/ranged/maven-metadata-corp.xml",
        "org/test/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar",
        "org/test/snap/1.0-SNAPSHOT/maven-metadata-snaps.xml",
        "org/test/snap/1.0-SNAPSHOT/_remote.repositories",
    ] {
        assert!(expected.contains_key(path), "{path} not exported");
    }
}

/// A plan with `--with-sources` writes nothing, so a sources jar the store
/// lacks is neither downloaded nor stored.
#[test]
fn a_plan_fetches_no_classifier_jar() {
    let server = serve(repositories());
    let project = Project::new(&server);
    assert_success(&project.raeva(&["sync"]), "sync");
    let plan = project.plan(&["--with-sources"]);
    let sources = |path: &str| path.ends_with("-sources.jar");
    let requests = server.requests();
    assert!(
        !requests.iter().any(|request| sources(&request.path)),
        "{:?}",
        requests
            .iter()
            .map(|request| &request.path)
            .collect::<Vec<_>>()
    );
    let files = plan["files"].as_array().expect("files");
    assert!(
        !files
            .iter()
            .any(|file| sources(file["path"].as_str().expect("path"))),
        "{plan}"
    );
}

/// The options that place or judge files in a destination make no sense
/// with a plan, which writes none.
#[test]
fn destination_options_are_refused_with_a_plan() {
    let served = repositories();
    let server = serve(served);
    let project = Project::new(&server);
    for args in [
        &["--dry-run"][..],
        &["--overwrite"],
        &["--link", "copy"],
        &["--m2-path", "elsewhere"],
    ] {
        let output = project.raeva(&[&["export-m2", "--plan-json"], args].concat());
        assert_status(&output, 2, &format!("--plan-json {args:?}"));
    }
}

/// A plan takes each file's digests from the store, so a store that lacks
/// a locked file fails it, and the error says why.
#[test]
fn a_plan_needs_every_file_in_the_store() {
    let served = repositories();
    let server = serve(served);
    let project = Project::new(&server);
    assert_success(&project.raeva(&["sync"]), "sync");
    let jar = sha256_hex(b"lib jar");
    let mut dirs = vec![project.home.path().to_path_buf()];
    let mut removed = false;
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).expect("read dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.file_name().is_some_and(|name| name == jar.as_str()) {
                fs::remove_file(&path).expect("remove blob");
                removed = true;
            }
        }
    }
    assert!(removed, "no stored blob {jar}");
    let output = project.raeva(&["--offline", "export-m2", "--plan-json"]);
    assert_status(&output, 7, "--plan-json without the jar");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("raeva's store"), "{stderr}");
    assert!(
        output.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// A repository inside the project is named by a path relative to the
/// directory of raeva.lock, which a checkout elsewhere shares, and a
/// repository rebuilt by reading the files there is the export.
#[test]
fn a_project_repository_gives_paths_relative_to_the_lock() {
    let (root, home) = (TempDir::new().expect("root"), TempDir::new().expect("home"));
    let dir = root.path().join("repository/org/test/lib/1.0");
    fs::create_dir_all(&dir).expect("repository");
    let lib = pom("lib", "1.0", "");
    for (name, bytes) in [("lib-1.0.pom", lib.as_bytes()), ("lib-1.0.jar", b"jar")] {
        write_with_sha256(&dir.join(name), bytes);
    }
    fs::write(
        root.path().join("pom.xml"),
        pom(
            "app",
            "1",
            "<repositories><repository><id>in-project</id>\
             <url>file://${project.basedir}/repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>1.0</version></dependency></dependencies>",
        ),
    )
    .expect("pom.xml");
    let raeva = |args: &[&str]| run_raeva(root.path(), home.path(), args);
    assert_success(&raeva(&["sync", "--offline"]), "sync");
    let m2 = home.path().join("m2");
    assert_success(
        &raeva(&["export-m2", "--m2-path", m2.to_str().expect("path")]),
        "export-m2",
    );
    let output = raeva(&["export-m2", "--plan-json"]);
    assert_success(&output, "--plan-json");
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON plan");
    let mut served = BTreeMap::new();
    for file in plan["files"].as_array().expect("files") {
        let url = file["url"].as_str().expect("url");
        assert!(url.starts_with("./repository/org/test/lib/1.0/"), "{url}");
        served.insert(
            url.to_string(),
            fs::read(root.path().join(url)).expect("read"),
        );
    }
    let rebuilt = rebuild(&plan, "", &served);
    assert_eq!(tree(&m2), tree(rebuilt.path()));
}
