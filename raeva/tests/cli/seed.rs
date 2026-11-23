//! `raeva seed save` and `restore`: a seed fills an empty store so that
//! `sync --frozen` passes offline and asks the repository for nothing, and a
//! seed with changed bytes or saved for another lock is refused.

use std::fs;
use std::path::Path;

use rv_test_support::http::StubServer;
use tempfile::TempDir;

use crate::common::{
    assert_status, assert_success, envelope, pom, raeva_command, run_raeva, with_sha256,
    write_repo_toml, write_with_sha256,
};

const PARENT: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>parent</artifactId><version>1</version><packaging>pom</packaging></project>";

const LISTING: &str = "<metadata><groupId>t</groupId><artifactId>lib</artifactId>\
<versioning><versions><version>1</version></versions></versioning></metadata>";

fn repository() -> StubServer {
    StubServer::start(|request| answer(&request.path))
}

/// What [`repository`] answers at `path`.
fn answer(path: &str) -> rv_test_support::http::Response {
    let lib = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
<artifactId>parent</artifactId><version>1</version></parent><artifactId>lib</artifactId>\
<version>1</version></project>";
    with_sha256(
        path,
        [
            ("/t/parent/1/parent-1.pom", PARENT.as_bytes()),
            ("/t/lib/1/lib-1.pom", lib.as_bytes()),
            ("/t/lib/1/lib-1.jar", b"lib jar bytes".as_slice()),
            ("/t/lib/maven-metadata.xml", LISTING.as_bytes()),
        ],
    )
}

/// A project locked against `server`, a seed saved from that sync's store,
/// and the seed directory.
fn saved_seed(server: &StubServer) -> (TempDir, TempDir, std::path::PathBuf) {
    saved_seed_of(server, "1")
}

/// [`saved_seed`] for a project that asks for `version` of the library.
fn saved_seed_of(server: &StubServer, version: &str) -> (TempDir, TempDir, std::path::PathBuf) {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    write_repo_toml(
        project.path(),
        "central",
        &format!("http://{}/", server.addr()),
    );
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            &format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
                 <version>{version}</version></dependency></dependencies>"
            ),
        ),
    )
    .unwrap();
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let seed = home.path().join("seed");
    let saved = run_raeva(
        project.path(),
        home.path(),
        &["--json", "seed", "save", seed.to_str().unwrap()],
    );
    assert_success(&saved, "seed save");
    assert_eq!(envelope(&saved)["data"]["files"], 3, "jar, POM and parent");
    (project, home, seed)
}

fn key(project: &Path, home: &Path) -> String {
    let output = run_raeva(project, home, &["seed", "key"]);
    assert_success(&output, "seed key");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[test]
fn a_restored_seed_passes_an_offline_frozen_sync_without_requests() {
    let server = repository();
    let (project, home, seed) = saved_seed(&server);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(seed.join("seed.json")).unwrap()).unwrap();
    assert_eq!(manifest["key"], key(project.path(), home.path()));

    let empty = TempDir::new().unwrap();
    let restored = run_raeva(
        project.path(),
        empty.path(),
        &["--json", "seed", "restore", seed.to_str().unwrap()],
    );
    assert_success(&restored, "seed restore");
    assert_eq!(envelope(&restored)["data"]["files"], 3);
    let offline = run_raeva(
        project.path(),
        empty.path(),
        &["--offline", "sync", "--frozen"],
    );
    assert_success(&offline, "offline frozen sync after restore");

    let before = server.requests().len();
    assert_success(
        &run_raeva(project.path(), empty.path(), &["sync", "--frozen"]),
        "frozen sync after restore",
    );
    let m2 = empty.path().join("m2");
    assert_success(
        &run_raeva(
            project.path(),
            empty.path(),
            &["export-m2", "--m2-path", m2.to_str().unwrap()],
        ),
        "export after restore",
    );
    let after: Vec<_> = (server.requests().into_iter().skip(before))
        .map(|request| request.path)
        .collect();
    assert!(after.is_empty(), "requests after restore: {after:?}");
    assert_eq!(
        fs::read(m2.join("t/lib/1/lib-1.jar")).unwrap(),
        b"lib jar bytes"
    );
}

/// A seed saved from a checkout whose POM declares a repository inside the
/// project restores in a checkout at another path.
#[test]
fn a_seed_of_an_in_project_repository_restores_in_another_checkout() {
    let checkouts = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let first = checkouts.path().join("a");
    let dir = first.join("repository/t/lib/1");
    fs::create_dir_all(&dir).unwrap();
    let lib = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
               <artifactId>lib</artifactId><version>1</version></project>";
    for (name, bytes) in [("lib-1.pom", lib.as_bytes()), ("lib-1.jar", b"jar")] {
        write_with_sha256(&dir.join(name), bytes);
    }
    fs::write(
        first.join("pom.xml"),
        pom(
            "app",
            "<repositories><repository><id>in-project</id>\
             <url>file://${project.basedir}/repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
             <version>1</version></dependency></dependencies>",
        ),
    )
    .unwrap();
    assert_success(
        &run_raeva(&first, home.path(), &["--offline", "sync"]),
        "sync",
    );
    let seed = home.path().join("seed");
    assert_success(
        &run_raeva(
            &first,
            home.path(),
            &["seed", "save", seed.to_str().unwrap()],
        ),
        "seed save",
    );
    let second = checkouts.path().join("b");
    fs::create_dir_all(second.join("repository/t/lib/1")).unwrap();
    for file in [
        "pom.xml",
        "raeva.lock",
        "repository/t/lib/1/lib-1.pom",
        "repository/t/lib/1/lib-1.pom.sha256",
        "repository/t/lib/1/lib-1.jar",
        "repository/t/lib/1/lib-1.jar.sha256",
    ] {
        fs::copy(first.join(file), second.join(file)).unwrap();
    }
    let empty = TempDir::new().unwrap();
    assert_success(
        &run_raeva(
            &second,
            empty.path(),
            &["seed", "restore", seed.to_str().unwrap()],
        ),
        "seed restore in another checkout",
    );
    assert_success(
        &run_raeva(&second, empty.path(), &["--offline", "sync", "--frozen"]),
        "offline frozen sync after restore",
    );
}

#[test]
fn a_pom_edit_that_keeps_the_pins_takes_the_restored_jar() {
    let server = repository();
    let (project, _home, seed) = saved_seed(&server);
    let empty = TempDir::new().unwrap();
    assert_success(
        &run_raeva(
            project.path(),
            empty.path(),
            &["seed", "restore", seed.to_str().unwrap()],
        ),
        "seed restore",
    );
    // Same seed key, so the frozen check resolves again with an empty
    // metadata cache: it reads the POMs, but the jar is the seed's.
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<properties><edit>1</edit></properties><dependencies><dependency><groupId>t\
             </groupId><artifactId>lib</artifactId><version>1</version></dependency>\
             </dependencies>",
        ),
    )
    .unwrap();
    let before = server.requests().len();
    assert_success(
        &run_raeva(project.path(), empty.path(), &["sync", "--frozen"]),
        "frozen sync of the edited POM",
    );
    let jars: Vec<_> = (server.requests().into_iter().skip(before))
        .map(|request| request.path)
        .filter(|path| path.contains(".jar"))
        .collect();
    assert!(jars.is_empty(), "jar requests after restore: {jars:?}");
}

#[test]
fn a_seed_with_changed_bytes_is_refused_and_not_used() {
    let server = repository();
    let (project, _home, seed) = saved_seed(&server);
    let jar = fs::read_dir(seed.join("blobs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| fs::read(path).unwrap() == b"lib jar bytes")
        .expect("the jar's blob");
    let mut permissions = fs::metadata(&jar).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(&jar, permissions).unwrap();
    fs::write(&jar, b"lib jar bytez").unwrap();

    let empty = TempDir::new().unwrap();
    let refused = run_raeva(
        project.path(),
        empty.path(),
        &["--json", "seed", "restore", seed.to_str().unwrap()],
    );
    assert_status(&refused, 7, "restore of a changed seed");
    let envelope = envelope(&refused);
    assert_eq!(envelope["code"], "LOCKFILE_MISMATCH");
    assert!(
        (envelope["error"].as_str().unwrap()).contains("t:lib:1:jar"),
        "{envelope}"
    );
    // The files that matched their pins are stored, as docs/ci.md says, but
    // without the evidence of who served them or the POMs a resolution
    // reads, so the offline check still fails.
    fn files(dir: &Path, found: &mut Vec<Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            match path.is_dir() {
                true => files(&path, found),
                false => found.push(fs::read(&path).unwrap()),
            }
        }
    }
    let mut stored = Vec::new();
    files(&empty.path().join("store").join("blobs"), &mut stored);
    assert!(
        stored.iter().any(|bytes| bytes.starts_with(b"<project")),
        "the POM that matched its pin is stored"
    );
    assert!(!stored.iter().any(|bytes| bytes == b"lib jar bytez"));
    let offline = run_raeva(
        project.path(),
        empty.path(),
        &["--offline", "sync", "--frozen"],
    );
    assert_status(&offline, 5, "offline frozen sync after a refused restore");
    assert!(
        String::from_utf8_lossy(&offline.stderr).contains("not available in local cache"),
        "{}",
        String::from_utf8_lossy(&offline.stderr)
    );
    let verify = run_raeva(
        project.path(),
        empty.path(),
        &["--json", "lock", "verify", "--download"],
    );
    assert_success(&verify, "lock verify --download after a refused restore");
    let offline = run_raeva(
        project.path(),
        empty.path(),
        &["--offline", "sync", "--frozen"],
    );
    assert_success(&offline, "offline frozen sync after lock verify --download");
}

#[test]
fn a_seed_for_another_lock_is_refused() {
    let server = repository();
    let (project, home, seed) = saved_seed(&server);
    let other = TempDir::new().unwrap();
    write_repo_toml(
        other.path(),
        "central",
        &format!("http://{}/", server.addr()),
    );
    fs::write(other.path().join("pom.xml"), pom("other", "")).unwrap();
    assert_success(&run_raeva(other.path(), home.path(), &["sync"]), "sync");
    assert_ne!(
        key(other.path(), home.path()),
        key(project.path(), home.path())
    );

    let empty = TempDir::new().unwrap();
    let refused = run_raeva(
        other.path(),
        empty.path(),
        &["--json", "seed", "restore", seed.to_str().unwrap()],
    );
    assert_status(&refused, 7, "restore of another lock's seed");
    assert!(
        (envelope(&refused)["error"].as_str().unwrap()).contains("for another lock"),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
    assert!(
        !empty.path().join("store").join("blobs").exists()
            || fs::read_dir(empty.path().join("store").join("blobs"))
                .unwrap()
                .next()
                .is_none(),
        "a refused seed adds no blob"
    );
}

/// The key follows the mirrors and the settings.xml plugin repositories,
/// which serve build extensions and plugins.
#[test]
fn the_key_follows_the_mirror_and_save_needs_a_new_directory() {
    let server = repository();
    let (project, home, seed) = saved_seed(&server);
    let before = key(project.path(), home.path());
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    let settings = |plugins: &str| {
        fs::write(
            home.path().join(".m2").join("settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>m</id><mirrorOf>central</mirrorOf>\
                 <url>http://{}/</url></mirror></mirrors><profiles><profile><id>p</id>\
                 <pluginRepositories>{plugins}</pluginRepositories></profile></profiles>\
                 <activeProfiles><activeProfile>p</activeProfile></activeProfiles></settings>",
                server.addr()
            ),
        )
        .unwrap();
        key(project.path(), home.path())
    };
    let mirrored = settings("");
    assert_ne!(mirrored, before);
    let plugin_repository = |id: &str| {
        format!(
            "<pluginRepository><id>{id}</id><url>http://plugins.invalid/</url>\
                            </pluginRepository>"
        )
    };
    let a = settings(&plugin_repository("plugins-a"));
    assert_ne!(a, mirrored);
    assert_ne!(settings(&plugin_repository("plugins-b")), a);

    let again = run_raeva(
        project.path(),
        home.path(),
        &["seed", "save", seed.to_str().unwrap()],
    );
    assert_status(&again, 2, "save into an existing seed");
}

/// The key takes each platform's own settings.xml profiles, so two
/// platforms' plugin repositories of one id both count.
#[test]
fn the_key_follows_each_platforms_plugin_repositories() {
    let server = repository();
    let (project, home, _seed) = saved_seed(&server);
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["sync", "--platforms", "windows-x86_64,macos-aarch64"],
        ),
        "sync for two platforms",
    );
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    let settings = |windows: &str| {
        let profile = |family: &str, url: &str| {
            format!(
                "<profile><id>{family}</id><activation><os><family>{family}</family></os>\
                 </activation><pluginRepositories><pluginRepository><id>plugins</id>\
                 <url>{url}</url></pluginRepository></pluginRepositories></profile>"
            )
        };
        fs::write(
            home.path().join(".m2").join("settings.xml"),
            format!(
                "<settings><profiles>{}{}</profiles></settings>",
                profile("windows", windows),
                profile("mac", "http://mac.invalid/")
            ),
        )
        .unwrap();
        key(project.path(), home.path())
    };
    assert_ne!(
        settings("http://windows-a.invalid/"),
        settings("http://windows-b.invalid/")
    );
}

fn edit_manifest(seed: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let path = seed.join("seed.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    edit(&mut manifest);
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

#[test]
fn a_seed_that_names_another_repository_is_refused() {
    let server = repository();
    let (project, _home, seed) = saved_seed(&server);
    edit_manifest(&seed, |manifest| {
        for file in manifest["files"].as_array_mut().unwrap() {
            file["served"] =
                serde_json::json!([["http://elsewhere.example/", "http://elsewhere.example/"]]);
        }
    });
    let empty = TempDir::new().unwrap();
    let refused = run_raeva(
        project.path(),
        empty.path(),
        &["--json", "seed", "restore", seed.to_str().unwrap()],
    );
    assert_status(&refused, 7, "restore of a seed naming another repository");
    assert!(
        (envelope(&refused)["error"].as_str().unwrap()).contains("the repository the lock records"),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
}

#[test]
fn a_seed_whose_blobs_directory_is_a_link_is_refused() {
    let server = repository();
    let (project, home, seed) = saved_seed(&server);
    let elsewhere = home.path().join("elsewhere");
    fs::rename(seed.join("blobs"), &elsewhere).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&elsewhere, seed.join("blobs")).unwrap();
    // A junction needs no privilege, unlike a symbolic link.
    #[cfg(windows)]
    rv_test_support::create_junction(&seed.join("blobs"), &elsewhere).unwrap();
    let empty = TempDir::new().unwrap();
    let refused = run_raeva(
        project.path(),
        empty.path(),
        &["--json", "seed", "restore", seed.to_str().unwrap()],
    );
    assert_status(&refused, 7, "restore through a linked blobs directory");
    assert!(
        (envelope(&refused)["error"].as_str().unwrap()).contains("has no blobs directory"),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
}

#[test]
fn a_seed_key_with_a_line_break_prints_on_one_line() {
    let server = repository();
    let (project, _home, seed) = saved_seed(&server);
    edit_manifest(&seed, |manifest| {
        manifest["key"] = "raeva-seed-x\n::error::injected".into();
    });
    let empty = TempDir::new().unwrap();
    let refused = run_raeva(
        project.path(),
        empty.path(),
        &["seed", "restore", seed.to_str().unwrap()],
    );
    assert_status(&refused, 7, "restore of a seed with another key");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("for another lock"), "{stderr}");
    assert!(!stderr.contains("\n::error::injected"), "{stderr}");
}

#[test]
fn a_file_in_place_of_the_seed_directory_is_refused() {
    let server = repository();
    let (project, home, _seed) = saved_seed(&server);
    let file = home.path().join("a-file");
    fs::write(&file, b"not a seed").unwrap();
    let path = file.to_str().unwrap();
    assert_status(
        &run_raeva(project.path(), home.path(), &["seed", "save", path]),
        2,
        "save into a file",
    );
    assert_status(
        &run_raeva(project.path(), home.path(), &["seed", "restore", path]),
        7,
        "restore from a file",
    );
}

#[test]
fn the_key_follows_the_lock_configuration() {
    let server = repository();
    let (project, home, _seed) = saved_seed(&server);
    let before = key(project.path(), home.path());
    let lock = project.path().join("raeva.lock");
    let text = fs::read_to_string(&lock).unwrap();
    let start = text.find("config_hash = \"").expect("a config_hash") + "config_hash = \"".len();
    let mut edited = text.clone();
    edited.replace_range(start..start + 64, &"0".repeat(64));
    assert_ne!(edited, text);
    fs::write(&lock, edited).unwrap();
    assert_ne!(key(project.path(), home.path()), before);
}

/// A lock written behind a `*` mirror records the files under the empty
/// repository the POM lists first, which the mirror served them for. A
/// machine without that mirror fetches them in `sync --frozen` from the next
/// repository Maven would ask, Central through its mirror or another POM
/// repository, and a seed saved there carries them and restores offline.
#[test]
fn a_seed_saved_after_a_frozen_check_carries_files_from_the_next_repository() {
    let server = repository();
    let empty = StubServer::start(|_| rv_test_support::http::Response::new(404, ""));
    let url = format!("http://{}/", server.addr());
    let settings = |home: &Path, mirror_of: Option<&str>| {
        let mirrors = mirror_of.map(|mirror_of| {
            format!(
                "<mirrors><mirror><id>stub</id><url>{url}</url><mirrorOf>{mirror_of}</mirrorOf>\
                 </mirror></mirrors>"
            )
        });
        fs::create_dir_all(home.join(".m2")).unwrap();
        let settings = format!("<settings>{}</settings>", mirrors.unwrap_or_default());
        fs::write(home.join(".m2/settings.xml"), settings).unwrap();
    };
    let repository =
        |id: &str, url: &str| format!("<repository><id>{id}</id><url>{url}</url></repository>");
    let first = repository("first", &format!("http://{}/", empty.addr()));
    // Behind Central's mirror, then behind another repository of the POM.
    for (mirror_of, second) in [
        (Some("central"), String::new()),
        (None, repository("second", &url)),
    ] {
        let project = TempDir::new().unwrap();
        fs::write(
            project.path().join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<repositories>{first}{second}</repositories><dependencies><dependency>\
                     <groupId>t</groupId><artifactId>lib</artifactId><version>1</version>\
                     </dependency></dependencies>"
                ),
            ),
        )
        .unwrap();
        let locked = TempDir::new().unwrap();
        settings(locked.path(), Some("*"));
        assert_success(&run_raeva(project.path(), locked.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
        let recorded = format!("repo_url = \"http://{}/\"", empty.addr());
        assert!(lock.contains(&recorded), "{lock}");

        let ci = TempDir::new().unwrap();
        settings(ci.path(), mirror_of);
        let frozen = run_raeva(project.path(), ci.path(), &["sync", "--frozen"]);
        assert_success(&frozen, "frozen sync without the * mirror");
        let seed = ci.path().join("seed");
        let save = ["seed", "save", seed.to_str().unwrap()];
        assert_success(&run_raeva(project.path(), ci.path(), &save), "seed save");

        let restored = TempDir::new().unwrap();
        settings(restored.path(), mirror_of);
        let restore = ["seed", "restore", seed.to_str().unwrap()];
        assert_success(
            &run_raeva(project.path(), restored.path(), &restore),
            "seed restore",
        );
        let before = server.requests().len();
        let offline = ["--offline", "sync", "--frozen"];
        assert_success(
            &run_raeva(project.path(), restored.path(), &offline),
            "offline frozen sync after restore",
        );
        assert_eq!(server.requests().len(), before, "{second}");
    }
}

/// As [`a_seed_saved_after_a_frozen_check_carries_files_from_the_next_repository`],
/// with the empty repository declared only by the project's remote parent:
/// in its repositories, in a profile active by default, or at a URL a
/// property fills.
#[test]
fn a_seed_carries_files_from_the_repository_after_a_remote_parents() {
    let repository = "<repository><id>first</id><url>{url}</url></repository>";
    seed_after_a_remote_parents(&format!("<repositories>{repository}</repositories>"));
    seed_after_a_remote_parents(&format!(
        "<profiles><profile><id>corp</id><activation><activeByDefault>true</activeByDefault>\
         </activation><repositories>{repository}</repositories></profile></profiles>"
    ));
    seed_after_a_remote_parents(&format!(
        "<properties><first.url>{{url}}</first.url></properties><repositories>{}</repositories>",
        repository.replace("{url}", "${first.url}")
    ));
}

/// A frozen check of a project whose remote parent holds `declaration`,
/// with `{url}` the repository the lock records, passes, and the seed saved
/// after it restores for an offline frozen check.
fn seed_after_a_remote_parents(declaration: &str) {
    let empty = StubServer::start(|_| rv_test_support::http::Response::new(404, ""));
    let parent = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>corp-parent</artifactId><version>1</version><packaging>pom</packaging>\
         {}</project>",
        declaration.replace("{url}", &format!("http://{}/", empty.addr()))
    );
    let server = StubServer::start(move |request| {
        match request
            .path
            .strip_prefix("/t/corp-parent/1/corp-parent-1.pom")
        {
            Some("") => rv_test_support::http::Response::new(200, parent.clone()),
            Some(".sha256") => rv_test_support::http::Response::new(
                200,
                crate::common::sha256_hex(parent.as_bytes()),
            ),
            _ => answer(&request.path),
        }
    });
    let url = format!("http://{}/", server.addr());
    let settings = |home: &Path, mirror_of: &str| {
        fs::create_dir_all(home.join(".m2")).unwrap();
        let settings = format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>{mirror_of}</mirrorOf></mirror></mirrors></settings>"
        );
        fs::write(home.join(".m2/settings.xml"), settings).unwrap();
    };
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
         <artifactId>corp-parent</artifactId><version>1</version><relativePath/></parent>\
         <artifactId>app</artifactId><dependencies><dependency><groupId>t</groupId>\
         <artifactId>lib</artifactId><version>1</version></dependency></dependencies>\
         </project>",
    )
    .unwrap();
    let locked = TempDir::new().unwrap();
    settings(locked.path(), "*");
    assert_success(&run_raeva(project.path(), locked.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    let recorded = format!("repo_url = \"http://{}/\"", empty.addr());
    assert!(lock.contains(&recorded), "{lock}");

    let ci = TempDir::new().unwrap();
    settings(ci.path(), "central");
    let frozen = run_raeva(project.path(), ci.path(), &["sync", "--frozen"]);
    assert_success(
        &frozen,
        &format!("frozen sync with only Central mirrored, {declaration}"),
    );
    let seed = ci.path().join("seed");
    let save = ["seed", "save", seed.to_str().unwrap()];
    assert_success(
        &run_raeva(project.path(), ci.path(), &save),
        &format!("seed save, {declaration}"),
    );

    let restored = TempDir::new().unwrap();
    settings(restored.path(), "central");
    let before = (server.requests().len(), empty.requests().len());
    let restore = ["seed", "restore", seed.to_str().unwrap()];
    assert_success(
        &run_raeva(project.path(), restored.path(), &restore),
        &format!("seed restore, {declaration}"),
    );
    let offline = ["--offline", "sync", "--frozen"];
    assert_success(
        &run_raeva(project.path(), restored.path(), &offline),
        "offline frozen sync after restore",
    );
    assert_eq!((server.requests().len(), empty.requests().len()), before);
}

/// As [`a_seed_carries_files_from_the_repository_after_a_remote_parents`],
/// in a reactor where only module `b` has the remote parent and needs its
/// repository, and each other module reads a file from Central: before `b`,
/// after it, and more of them than resolve at once.
#[test]
fn a_seed_carries_files_from_the_repository_after_one_modules_remote_parent() {
    let many: Vec<String> = (0..12).map(|module| format!("a{module}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).chain(["b"]).collect();
    for modules in [&["a", "b"][..], &["b", "a"], &many] {
        seed_of_a_reactor(modules);
    }
}

fn seed_of_a_reactor(modules: &[&str]) {
    let empty = StubServer::start(|_| rv_test_support::http::Response::new(404, ""));
    let parent = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>corp-parent</artifactId><version>1</version><packaging>pom</packaging>\
         <repositories><repository><id>first</id><url>http://{}/</url></repository>\
         </repositories></project>",
        empty.addr()
    );
    let dep = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
               <artifactId>dep</artifactId><version>1</version></project>";
    let server = StubServer::start(move |request| {
        let files = [
            ("/t/corp-parent/1/corp-parent-1.pom", parent.as_bytes()),
            ("/t/dep/1/dep-1.pom", dep.as_bytes()),
            ("/t/dep/1/dep-1.jar", b"dep jar bytes".as_slice()),
        ];
        match files.iter().any(|(path, _)| request.path.starts_with(path)) {
            true => with_sha256(&request.path, files),
            false => answer(&request.path),
        }
    });
    let url = format!("http://{}/", server.addr());
    let settings = |home: &Path, mirror_of: &str| {
        fs::create_dir_all(home.join(".m2")).unwrap();
        let settings = format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>{mirror_of}</mirrorOf></mirror></mirrors></settings>"
        );
        fs::write(home.join(".m2/settings.xml"), settings).unwrap();
    };
    let project = TempDir::new().unwrap();
    let listed: String = (modules.iter())
        .map(|module| format!("<module>{module}</module>"))
        .collect();
    let root = pom(
        "root",
        &format!("<packaging>pom</packaging><modules>{listed}</modules>"),
    );
    fs::write(project.path().join("pom.xml"), root).unwrap();
    let dependency = |artifact: &str| {
        format!(
            "<dependencies><dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version></dependency></dependencies>"
        )
    };
    for module in modules.iter().filter(|module| **module != "b") {
        fs::create_dir_all(project.path().join(module)).unwrap();
        let path = project.path().join(module).join("pom.xml");
        fs::write(path, pom(module, &dependency("lib"))).unwrap();
    }
    fs::create_dir_all(project.path().join("b")).unwrap();
    fs::write(
        project.path().join("b/pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
             <artifactId>corp-parent</artifactId><version>1</version><relativePath/></parent>\
             <artifactId>b</artifactId>{}</project>",
            dependency("dep")
        ),
    )
    .unwrap();
    let locked = TempDir::new().unwrap();
    settings(locked.path(), "*");
    assert_success(&run_raeva(project.path(), locked.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    let recorded = format!("repo_url = \"http://{}/\"", empty.addr());
    assert!(lock.contains(&recorded), "{lock}");

    let ci = TempDir::new().unwrap();
    settings(ci.path(), "central");
    let frozen = run_raeva(project.path(), ci.path(), &["sync", "--frozen"]);
    assert_success(&frozen, &format!("frozen sync, modules {modules:?}"));
    let seed = ci.path().join("seed");
    let save = ["seed", "save", seed.to_str().unwrap()];
    assert_success(
        &run_raeva(project.path(), ci.path(), &save),
        &format!("seed save, modules {modules:?}"),
    );
    let restored = TempDir::new().unwrap();
    settings(restored.path(), "central");
    let before = (server.requests().len(), empty.requests().len());
    let restore = ["seed", "restore", seed.to_str().unwrap()];
    assert_success(
        &run_raeva(project.path(), restored.path(), &restore),
        &format!("seed restore, modules {modules:?}"),
    );
    let offline = ["--offline", "sync", "--frozen"];
    assert_success(
        &run_raeva(project.path(), restored.path(), &offline),
        "offline frozen sync after restore",
    );
    assert_eq!((server.requests().len(), empty.requests().len()), before);
}

#[test]
fn save_needs_the_repository_the_lock_records() {
    let server = repository();
    let (project, home, _seed) = saved_seed(&server);
    // The store's evidence names the stub; the lock now names another
    // repository, so no recorded route vouches for the files.
    let lock = project.path().join("raeva.lock");
    let text = fs::read_to_string(&lock).unwrap();
    let edited = text.replace(
        &format!("http://{}/", server.addr()),
        "http://elsewhere.example/",
    );
    assert_ne!(edited, text);
    fs::write(&lock, edited).unwrap();
    let seed = home.path().join("other-seed");
    let refused = run_raeva(
        project.path(),
        home.path(),
        &["--json", "seed", "save", seed.to_str().unwrap()],
    );
    assert_status(&refused, 7, "save without a recorded route");
    assert!(!seed.join("seed.json").exists());
}

#[test]
fn a_restored_seed_of_a_range_passes_an_offline_frozen_sync() {
    let server = repository();
    let (project, _home, seed) = saved_seed_of(&server, "[1,2)");
    let empty = TempDir::new().unwrap();
    assert_success(
        &run_raeva(
            project.path(),
            empty.path(),
            &["seed", "restore", seed.to_str().unwrap()],
        ),
        "seed restore",
    );
    let before = server.requests().len();
    assert_success(
        &run_raeva(
            project.path(),
            empty.path(),
            &["--offline", "sync", "--frozen"],
        ),
        "offline frozen sync of a range after restore",
    );
    assert_success(
        &run_raeva(project.path(), empty.path(), &["sync", "--frozen"]),
        "frozen sync of a range after restore",
    );
    let after: Vec<_> = (server.requests().into_iter().skip(before))
        .map(|request| request.path)
        .collect();
    assert!(after.is_empty(), "requests after restore: {after:?}");
}

/// A row expires no later than the update policy its scope records allows,
/// whatever the clock of the job that saved the seed said.
#[test]
fn a_restored_row_lives_no_longer_than_its_update_policy() {
    let server = repository();
    let (project, _home, seed) = saved_seed_of(&server, "[1,2)");
    let mut listings = 0;
    edit_manifest(&seed, |manifest| {
        for row in manifest["metadata"].as_array_mut().unwrap() {
            if row["table"] == "version-list" {
                let scope = row["scope"].as_str().unwrap();
                assert!(scope.ends_with("\u{1f}update=daily"), "{scope}");
                row["expires_at"] = i64::MAX.into();
                listings += 1;
            }
        }
    });
    assert!(listings > 0, "the seed holds a version listing");
    let empty = TempDir::new().unwrap();
    assert_success(
        &run_raeva(
            project.path(),
            empty.path(),
            &["seed", "restore", seed.to_str().unwrap()],
        ),
        "seed restore",
    );
    let cache = rusqlite::Connection::open(empty.path().join("metadata.db")).unwrap();
    let longest: i64 = cache
        .query_row(
            "SELECT MAX(expires_at - fetched_at) FROM version_list_cache_v4",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(longest <= 24 * 60 * 60, "a listing kept for {longest}s");
}

/// The seed's file for the metadata row of `path`.
fn row_file(seed: &Path, path: &str) -> std::path::PathBuf {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(seed.join("seed.json")).unwrap()).unwrap();
    let row = (manifest["metadata"].as_array().unwrap().iter())
        .find(|row| row["path"] == path)
        .unwrap_or_else(|| panic!("a metadata row for {path}: {manifest}"));
    seed.join("metadata").join(row["sha256"].as_str().unwrap())
}

#[test]
fn a_seed_with_a_changed_pom_is_refused() {
    let server = repository();
    let (project, _home, seed) = saved_seed(&server);
    let pom = "t/lib/1/lib-1.pom";
    // Bytes that differ from what the manifest lists.
    let file = row_file(&seed, pom);
    fs::write(&file, b"<project/>").unwrap();
    let empty = TempDir::new().unwrap();
    let refused = run_raeva(
        project.path(),
        empty.path(),
        &["--json", "seed", "restore", seed.to_str().unwrap()],
    );
    assert_status(&refused, 7, "restore of a changed POM row");
    assert!(
        (envelope(&refused)["error"].as_str().unwrap()).contains("other metadata than it lists"),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
    // Bytes the manifest lists, but not the ones raeva.lock pins.
    edit_manifest(&seed, |manifest| {
        let changed = rv_maven_types::Sha256::from_bytes(b"<project/>").to_string();
        for row in manifest["metadata"].as_array_mut().unwrap() {
            if row["path"] == pom {
                row["sha256"] = changed.clone().into();
            }
        }
        fs::write(seed.join("metadata").join(&changed), b"<project/>").unwrap();
    });
    let refused = run_raeva(
        project.path(),
        empty.path(),
        &["--json", "seed", "restore", seed.to_str().unwrap()],
    );
    assert_status(&refused, 7, "restore of a POM row with other bytes");
    assert!(
        (envelope(&refused)["error"].as_str().unwrap())
            .contains("other bytes than raeva.lock pins"),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
    let offline = run_raeva(
        project.path(),
        empty.path(),
        &["--offline", "sync", "--frozen"],
    );
    assert_status(&offline, 5, "offline frozen sync after a refused restore");
}

#[test]
fn a_seed_from_a_shared_home_leaves_another_repositorys_pom_behind() {
    let lib = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
<artifactId>parent</artifactId><version>1</version></parent><artifactId>lib</artifactId>\
<version>1</version><!-- as another repository serves it --></project>";
    let other = StubServer::start(move |request| {
        with_sha256(
            &request.path,
            [
                ("/t/parent/1/parent-1.pom", PARENT.as_bytes()),
                ("/t/lib/1/lib-1.pom", lib.as_bytes()),
                ("/t/lib/1/lib-1.jar", b"lib jar bytes".as_slice()),
            ],
        )
    });
    let server = repository();
    let home = TempDir::new().unwrap();
    let mut projects = Vec::new();
    for repo in [&other, &server] {
        let project = TempDir::new().unwrap();
        write_repo_toml(
            project.path(),
            "central",
            &format!("http://{}/", repo.addr()),
        );
        fs::write(
            project.path().join("pom.xml"),
            pom(
                "app",
                "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
                 <version>1</version></dependency></dependencies>",
            ),
        )
        .unwrap();
        assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
        projects.push(project);
    }
    let project = projects.pop().unwrap();
    let seed = home.path().join("seed");
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["seed", "save", seed.to_str().unwrap()],
        ),
        "seed save from the shared home",
    );
    let empty = TempDir::new().unwrap();
    let restored = run_raeva(
        project.path(),
        empty.path(),
        &["--json", "seed", "restore", seed.to_str().unwrap()],
    );
    assert_success(&restored, "seed restore");
    assert_success(
        &run_raeva(
            project.path(),
            empty.path(),
            &["--offline", "sync", "--frozen"],
        ),
        "offline frozen sync after restore",
    );
}

/// Settings.xml mirrors whose URLs take a token from the environment in
/// their path: the seed names each by its id, so it holds no token, not
/// even one an earlier sync of the home used, and a restore under the same
/// settings puts each mirror's URL back, so the restored home answers
/// `sync --frozen` without a request. Masked, both URLs would read the same.
/// A later job's own token keeps the key and restores the seed.
/// Neither home's store index nor `metadata.db`, which CI caches, holds a
/// token either.
#[test]
fn a_seed_carries_no_mirror_token() {
    const OLD: &str = "tok-old-0b1d";
    const TOKEN: &str = "tok-5e3c7a91";
    const ROTATED: &str = "tok-9f20d4e6";
    const OTHER: &str = "tok-b";
    // A mirror whose whole URL comes from one secret-named variable.
    const WHOLE: &str = "tok-whole-77";
    let server = StubServer::start(|request| {
        let path = request.path.as_str();
        for (token, artifact) in [(OTHER, "other"), (WHOLE, "whole")] {
            if let Some(path) = path.strip_prefix(&format!("/{token}")) {
                let (pom, jar) = (pom(artifact, ""), format!("{artifact} jar bytes"));
                return with_sha256(
                    path,
                    [
                        (
                            format!("/t/{artifact}/1/{artifact}-1.pom"),
                            pom.into_bytes(),
                        ),
                        (
                            format!("/t/{artifact}/1/{artifact}-1.jar"),
                            jar.into_bytes(),
                        ),
                    ],
                );
            }
        }
        let token = [OLD, TOKEN, ROTATED]
            .into_iter()
            .find(|token| path.starts_with(&format!("/{token}/")));
        answer(token.map_or("/not-the-mirror", |token| &path[token.len() + 1..]))
    });
    let project = TempDir::new().unwrap();
    let settings = format!(
        "<settings><mirrors><mirror><id>m</id><mirrorOf>central</mirrorOf>\
         <url>http://{0}/${{env.REPO_TOKEN}}/</url></mirror><mirror><id>n</id>\
         <mirrorOf>other</mirrorOf><url>http://{0}/${{env.OTHER_TOKEN}}/</url></mirror>\
         <mirror><id>w</id><mirrorOf>whole</mirrorOf><url>${{env.WHOLE_TOKEN}}</url></mirror>\
         </mirrors></settings>",
        server.addr()
    );
    let home = || {
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(home.path().join(".m2/settings.xml"), &settings).unwrap();
        home
    };
    let raeva_with = |token: &str, home: &Path, args: &[&str]| {
        (raeva_command(project.path(), home))
            .env("REPO_TOKEN", token)
            .env("OTHER_TOKEN", OTHER)
            .env("WHOLE_TOKEN", format!("http://{}/{WHOLE}/", server.addr()))
            .args(args)
            .output()
            .expect("run raeva")
    };
    let raeva = |home: &Path, args: &[&str]| raeva_with(TOKEN, home, args);
    fs::write(
        project.path().join("raeva.toml"),
        "[[repositories]]\nid = \"central\"\nurl = \"http://central.invalid/\"\n\n\
         [[repositories]]\nid = \"other\"\nurl = \"http://other.invalid/\"\n\n\
         [[repositories]]\nid = \"whole\"\nurl = \"http://whole.invalid/\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
             <version>1</version></dependency><dependency><groupId>t</groupId>\
             <artifactId>other</artifactId><version>1</version></dependency><dependency>\
             <groupId>t</groupId><artifactId>whole</artifactId><version>1</version></dependency>\
             </dependencies>",
        ),
    )
    .unwrap();
    let saving = home();
    assert_success(
        &raeva_with(OLD, saving.path(), &["sync"]),
        "sync, old token",
    );
    assert_success(&raeva(saving.path(), &["sync", "--frozen"]), "frozen sync");
    let tokenless = |dir: &Path| {
        for entry in walk(dir) {
            let text = String::from_utf8_lossy(&fs::read(&entry).unwrap()).to_string();
            for token in [OLD, TOKEN, OTHER, WHOLE] {
                assert!(!text.contains(token), "{token} in {}", entry.display());
            }
        }
    };
    tokenless(saving.path());
    let seed = saving.path().join("seed");
    assert_success(
        &raeva(saving.path(), &["seed", "save", seed.to_str().unwrap()]),
        "seed save",
    );
    tokenless(&seed);

    let restoring = home();
    assert_success(
        &raeva(
            restoring.path(),
            &["seed", "restore", seed.to_str().unwrap()],
        ),
        "seed restore",
    );
    let before = server.requests().len();
    assert_success(
        &raeva(restoring.path(), &["--offline", "sync", "--frozen"]),
        "offline frozen sync after restore",
    );
    assert_success(
        &raeva(restoring.path(), &["sync", "--frozen"]),
        "frozen sync after restore",
    );
    let after: Vec<_> = (server.requests().into_iter().skip(before))
        .map(|request| request.path)
        .collect();
    assert!(after.is_empty(), "requests after restore: {after:?}");
    tokenless(restoring.path());

    let key = |token: &str| {
        let output = raeva_with(token, saving.path(), &["seed", "key"]);
        assert_success(&output, "seed key");
        String::from_utf8(output.stdout).unwrap()
    };
    assert_eq!(key(TOKEN), key(ROTATED));
    let rotated = home();
    let seed = seed.to_str().unwrap();
    let restore = raeva_with(ROTATED, rotated.path(), &["seed", "restore", seed]);
    assert_success(&restore, "seed restore with another token");
    let offline = raeva_with(ROTATED, rotated.path(), &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline frozen sync with another token");
}

/// Maven keeps the first of two settings.xml mirrors with one id, as of
/// two without one, which are both `default`, and reaches the repository
/// the later one names directly. A config.toml mirror comes before them.
/// With a token in each settings.xml mirror's URL, the later mirror gets no
/// request, the seed saves, restores and passes an offline frozen sync, and
/// nothing holds the token.
#[test]
fn a_mirror_with_an_earlier_mirrors_id_is_not_used() {
    const TOKEN: &str = "tok-d1a5c0e2";
    // The first mirror is in settings.xml, or in config.toml, which comes
    // first, with no token in its URL.
    for (id, user) in [("<id>d</id>", false), ("", false), ("<id>d</id>", true)] {
        let server = StubServer::start(|request| {
            let path = request.path.as_str();
            if let Some(path) = path.strip_prefix("/direct") {
                let (pom, jar) = (pom("other", ""), "other jar bytes");
                return with_sha256(
                    path,
                    [
                        ("/t/other/1/other-1.pom", pom.into_bytes()),
                        ("/t/other/1/other-1.jar", jar.as_bytes().to_vec()),
                    ],
                );
            }
            answer(
                (path.strip_prefix(&format!("/{TOKEN}")))
                    .or_else(|| path.strip_prefix("/plain"))
                    .unwrap_or("/not-the-mirror"),
            )
        });
        let project = TempDir::new().unwrap();
        let first = match user {
            false => format!(
                "<mirror>{id}<mirrorOf>central</mirrorOf>\
                 <url>http://{}/${{env.REPO_TOKEN}}/</url></mirror>",
                server.addr()
            ),
            true => String::new(),
        };
        let settings = format!(
            "<settings><mirrors>{first}<mirror>{id}<mirrorOf>other</mirrorOf>\
             <url>http://{}/${{env.REPO_TOKEN}}-2/</url></mirror></mirrors></settings>",
            server.addr()
        );
        let home = || {
            let home = TempDir::new().unwrap();
            fs::create_dir_all(home.path().join(".m2")).unwrap();
            fs::write(home.path().join(".m2/settings.xml"), &settings).unwrap();
            if user {
                let mirror = format!(
                    "[[mirrors]]\nid = \"d\"\nurl = \"http://{}/plain/\"\nmirror_of = [\"central\"]\n",
                    server.addr()
                );
                fs::write(home.path().join("config.toml"), mirror).unwrap();
            }
            home
        };
        let raeva = |home: &Path, args: &[&str]| {
            (raeva_command(project.path(), home))
                .env("REPO_TOKEN", TOKEN)
                .args(args)
                .output()
                .expect("run raeva")
        };
        fs::write(
            project.path().join("raeva.toml"),
            format!(
                "[[repositories]]\nid = \"central\"\nurl = \"http://central.invalid/\"\n\n\
                 [[repositories]]\nid = \"other\"\nurl = \"http://{}/direct/\"\n",
                server.addr()
            ),
        )
        .unwrap();
        fs::write(
            project.path().join("pom.xml"),
            pom(
                "app",
                "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
                 <version>1</version></dependency><dependency><groupId>t</groupId>\
                 <artifactId>other</artifactId><version>1</version></dependency>\
                 </dependencies>",
            ),
        )
        .unwrap();
        let tokenless = |dir: &Path| {
            for entry in walk(dir) {
                let text = String::from_utf8_lossy(&fs::read(&entry).unwrap()).to_string();
                assert!(!text.contains(TOKEN), "{id}: {}", entry.display());
            }
        };
        let saving = home();
        assert_success(&raeva(saving.path(), &["sync"]), "sync");
        let later: Vec<_> = (server.requests().into_iter())
            .map(|request| request.path)
            .filter(|path| path.starts_with(&format!("/{TOKEN}-2/")))
            .collect();
        assert!(later.is_empty(), "{id:?}: {later:?}");
        tokenless(saving.path());
        tokenless(project.path());
        let seed = saving.path().join("seed");
        assert_success(
            &raeva(saving.path(), &["seed", "save", seed.to_str().unwrap()]),
            &format!("seed save, {id:?}"),
        );
        tokenless(&seed);

        let restoring = home();
        let seed = seed.to_str().unwrap();
        assert_success(
            &raeva(restoring.path(), &["seed", "restore", seed]),
            "seed restore",
        );
        let before = server.requests().len();
        assert_success(
            &raeva(restoring.path(), &["--offline", "sync", "--frozen"]),
            "offline frozen sync after restore",
        );
        assert_eq!(server.requests().len(), before);
        let again = restoring.path().join("again");
        assert_success(
            &raeva(restoring.path(), &["seed", "save", again.to_str().unwrap()]),
            "seed save from the restored store",
        );
        tokenless(restoring.path());
    }
}

/// Every file below `dir`.
fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}

/// Offline, only the 404 an online sync kept proves a POM missing, not
/// raeva.lock's word. A lock that records `nopom`'s POM as missing passes
/// `--offline sync --frozen` in the home that synced it and in one a seed
/// restores, under the default update policy, under `always`, which keeps
/// nothing fresh online, and with a credential, whose answers a seed does
/// not carry. A lock edited to drop `a`'s POM pin, and
/// with it `a`'s dependency `b`, fails it with exit 7, from a seed without
/// `a`'s POM.
#[test]
fn only_a_kept_404_proves_a_pom_missing_offline() {
    let a_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>a</artifactId><version>1</version><dependencies><dependency><groupId>t</groupId>\
<artifactId>b</artifactId><version>1</version></dependency></dependencies></project>";
    let b = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>b</artifactId><version>1</version></project>";
    // Once `without` is set, no POM for `a` is served, as the edit below
    // claims.
    let without = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let served = std::sync::Arc::clone(&without);
    let server = StubServer::start(move |request| {
        let a = match served.load(std::sync::atomic::Ordering::SeqCst) {
            true => "/none",
            false => "/t/a/1/a-1.pom",
        };
        with_sha256(
            &request.path,
            [
                (a, a_pom.as_bytes()),
                ("/t/a/1/a-1.jar", b"a jar".as_slice()),
                ("/t/b/1/b-1.pom", b.as_bytes()),
                ("/t/b/1/b-1.jar", b"b jar".as_slice()),
                ("/t/nopom/1/nopom-1.jar", b"jar without a POM".as_slice()),
            ],
        )
    });
    let offline = ["--offline", "sync", "--frozen"];
    let auth = "[[auth]]\nid = \"central\"\ntoken = \"t0k3n\"\n";
    for (policy, config) in [
        ("", ""),
        ("releases-update-policy = \"always\"\n", ""),
        ("", auth),
    ] {
        without.store(false, std::sync::atomic::Ordering::SeqCst);
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let restored = TempDir::new().unwrap();
        for home in [&home, &restored] {
            fs::write(home.path().join("config.toml"), config).unwrap();
        }
        let root = project.path();
        let url = format!("http://{}/", server.addr());
        let toml = format!("[[repositories]]\nid = \"central\"\nurl = \"{url}\"\n{policy}");
        fs::write(root.join("raeva.toml"), toml).unwrap();
        let dependencies = "<dependencies><dependency><groupId>t</groupId><artifactId>a</artifactId>\
<version>1</version></dependency><dependency><groupId>t</groupId><artifactId>nopom</artifactId>\
<version>1</version></dependency></dependencies>";
        fs::write(root.join("pom.xml"), pom("app", dependencies)).unwrap();
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        let honest = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(!honest.contains("nopom-1.pom"), "{honest}");
        assert_success(
            &run_raeva(root, home.path(), &offline),
            "offline frozen sync",
        );
        let seed = home.path().join("seed");
        let save = ["seed", "save", seed.to_str().unwrap()];
        assert_success(&run_raeva(root, home.path(), &save), "seed save");
        let restore = ["seed", "restore", seed.to_str().unwrap()];
        assert_success(&run_raeva(root, restored.path(), &restore), "seed restore");
        let before = server.requests().len();
        assert_success(
            &run_raeva(root, restored.path(), &offline),
            "offline frozen sync after restore",
        );
        assert_eq!(server.requests().len(), before);
        if !policy.is_empty() || !config.is_empty() {
            continue;
        }

        // The edit keeps the project and configuration hashes, and takes the
        // graph hash a sync against a repository without `a`'s POM writes.
        without.store(true, std::sync::atomic::Ordering::SeqCst);
        let scratch = TempDir::new().unwrap();
        for file in ["raeva.toml", "pom.xml"] {
            fs::copy(root.join(file), scratch.path().join(file)).unwrap();
        }
        let scratch_home = TempDir::new().unwrap();
        assert_success(
            &run_raeva(scratch.path(), scratch_home.path(), &["sync"]),
            "sync",
        );
        let graph = |lock: &str| {
            let line = lock.lines().find(|line| line.starts_with("graph = "));
            line.unwrap().to_string()
        };
        let forged_graph = graph(&fs::read_to_string(scratch.path().join("raeva.lock")).unwrap());
        let pin = (honest.lines())
            .find(|line| line.starts_with("pom_sha256 = "))
            .unwrap();
        let edited = (honest.split_inclusive("[[platforms.artifacts]]\n"))
            .map(|block| match block.contains("artifact = \"b\"") {
                // The row before `b`'s ends with the header `b`'s opens.
                true => "[[platforms.artifacts]]\n",
                false => block,
            })
            .collect::<String>()
            .replacen(
                "[[platforms.artifacts]]\n[[platforms.artifacts]]\n",
                "[[platforms.artifacts]]\n",
                1,
            )
            .replacen(&format!("{pin}\n"), "", 1)
            .replace("t:b:1\\tjar\n", "")
            .replace("edges = \"0 1 compile\"", "edges = \"\"")
            .replace(&graph(&honest), &forged_graph);
        assert!(!edited.contains("artifact = \"b\""), "{edited}");
        fs::write(root.join("raeva.lock"), &edited).unwrap();
        let forged = home.path().join("forged");
        let save = ["seed", "save", forged.to_str().unwrap()];
        assert_success(
            &run_raeva(root, home.path(), &save),
            "seed save of the edited lock",
        );
        edit_manifest(&forged, |manifest| {
            (manifest["metadata"].as_array_mut().unwrap()).retain(|row| row["table"] != "pom");
        });
        let attacked = TempDir::new().unwrap();
        let restore = ["seed", "restore", forged.to_str().unwrap()];
        assert_success(
            &run_raeva(root, attacked.path(), &restore),
            "restore of the edited seed",
        );
        let output = run_raeva(root, attacked.path(), &offline);
        assert_status(&output, 7, "offline frozen sync of the edited lock");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("records the POM t/a/1/a-1.pom as missing"),
            "{stderr}"
        );
    }
}

/// A snapshot POM recorded as missing is looked for on the repository that
/// served the snapshot's jar, not on an earlier one: an honest lock passes
/// `--offline sync --frozen` with two snapshot repositories, and a lock
/// written against a repository that lacked the POM fails `sync --frozen`
/// once that repository serves it, though the earlier one has none.
#[test]
fn a_missing_snapshot_pom_is_looked_for_where_its_jar_came_from() {
    const METADATA: &str = "<metadata><groupId>t</groupId><artifactId>s</artifactId>\
<version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20240101.120000</timestamp>\
<buildNumber>1</buildNumber></snapshot><lastUpdated>20240101120000</lastUpdated></versioning></metadata>";
    let s_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>s</artifactId><version>1.0-SNAPSHOT</version><dependencies><dependency>\
<groupId>t</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies>\
</project>";
    let b = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>b</artifactId><version>1</version></project>";
    let with_pom = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let serves = std::sync::Arc::clone(&with_pom);
    let empty = StubServer::start(|_| rv_test_support::http::Response::new(404, ""));
    let server = StubServer::start(move |request| {
        let pom = match serves.load(std::sync::atomic::Ordering::SeqCst) {
            true => "/t/s/1.0-SNAPSHOT/s-1.0-20240101.120000-1.pom",
            false => "/none",
        };
        with_sha256(
            &request.path,
            [
                ("/t/s/1.0-SNAPSHOT/maven-metadata.xml", METADATA.as_bytes()),
                (
                    "/t/s/1.0-SNAPSHOT/s-1.0-20240101.120000-1.jar",
                    b"snapshot jar".as_slice(),
                ),
                (pom, s_pom.as_bytes()),
                ("/t/b/1/b-1.pom", b.as_bytes()),
                ("/t/b/1/b-1.jar", b"b jar".as_slice()),
            ],
        )
    });
    let project = TempDir::new().unwrap();
    let root = project.path();
    let repository = |id: &str, server: &StubServer| {
        format!(
            "[[repositories]]\nid = \"{id}\"\nurl = \"http://{}/\"\nsnapshots = true\n",
            server.addr()
        )
    };
    let toml = repository("first", &empty) + &repository("second", &server);
    fs::write(root.join("raeva.toml"), toml).unwrap();
    let dependency = "<dependencies><dependency><groupId>t</groupId><artifactId>s</artifactId>\
<version>1.0-SNAPSHOT</version></dependency></dependencies>";
    fs::write(root.join("pom.xml"), pom("app", dependency)).unwrap();
    let home = TempDir::new().unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let forged = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!forged.contains("pom_sha256"), "{forged}");
    for args in [
        &["sync", "--frozen"][..],
        &["--offline", "sync", "--frozen"],
    ] {
        assert_success(&run_raeva(root, home.path(), args), &format!("{args:?}"));
    }

    with_pom.store(true, std::sync::atomic::Ordering::SeqCst);
    let fresh = TempDir::new().unwrap();
    let output = run_raeva(root, fresh.path(), &["sync", "--frozen"]);
    assert_status(&output, 7, "frozen sync of a lock without the POM");
}

/// A settings.xml profile whose activation Maven cannot evaluate fails
/// `seed key` and `seed save` as it fails `sync --frozen`, instead of a key
/// worked out with every settings profile dropped.
#[test]
fn a_seed_refuses_settings_whose_activation_fails() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let dir = project.path().join("repository/t/lib/1");
    fs::create_dir_all(&dir).unwrap();
    let lib = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
               <artifactId>lib</artifactId><version>1</version></project>";
    for (name, bytes) in [("lib-1.pom", lib.as_bytes()), ("lib-1.jar", b"jar")] {
        write_with_sha256(&dir.join(name), bytes);
    }
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<repositories><repository><id>in-project</id>\
             <url>file://${project.basedir}/repository/</url></repository></repositories>\
             <dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
             <version>1</version></dependency></dependencies>",
        ),
    )
    .unwrap();
    let platforms = [
        "--offline",
        "sync",
        "--platforms",
        "linux-x86_64,windows-x86_64",
    ];
    assert_success(&run_raeva(project.path(), home.path(), &platforms), "sync");
    let good = key(project.path(), home.path());
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        "<settings><profiles><profile><id>w</id><activation><os><family>windows</family>\
         <version>regex:[</version></os></activation></profile></profiles></settings>",
    )
    .unwrap();
    let frozen = run_raeva(
        project.path(),
        home.path(),
        &["--offline", "sync", "--frozen"],
    );
    assert_status(&frozen, 3, "sync --frozen");
    let seed = home.path().join("seed");
    for args in [
        &["seed", "key"][..],
        &["seed", "save", seed.to_str().unwrap()],
    ] {
        let output = run_raeva(project.path(), home.path(), args);
        assert_status(&output, 3, &args.join(" "));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("activation for profile w"), "{stderr}");
    }
    assert!(!seed.exists());
    fs::remove_file(home.path().join(".m2/settings.xml")).unwrap();
    assert_eq!(key(project.path(), home.path()), good);
}

/// A `file:` mirror with a token in its path, written `file:/` or with an
/// uppercase scheme, saves a seed that names it by its id and holds no
/// token, and that restores.
#[test]
fn a_file_mirror_token_stays_out_of_the_seed() {
    const TOKEN: &str = "tok-file-41d2";
    let base = TempDir::new().unwrap();
    let mirror = base.path().join("mirror");
    crate::common::publish(&mirror.join(TOKEN), "t:lib:1", "");
    let dir = mirror.to_str().unwrap().trim_start_matches('/');
    for url in [
        format!("file:/{dir}/${{env.REPO_TOKEN}}/"),
        format!("FILE:///{dir}/${{env.REPO_TOKEN}}/"),
    ] {
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>m</id><mirrorOf>*</mirrorOf><url>{url}</url>\
                 </mirror></mirrors></settings>"
            ),
        )
        .unwrap();
        fs::write(
            project.path().join("pom.xml"),
            pom(
                "app",
                "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
                 <version>1</version></dependency></dependencies>",
            ),
        )
        .unwrap();
        let raeva = |args: &[&str]| {
            (raeva_command(project.path(), home.path()))
                .env("REPO_TOKEN", TOKEN)
                .args(args)
                .output()
                .expect("run raeva")
        };
        assert_success(&raeva(&["sync"]), &url);
        let seed = base.path().join(format!("seed-{}", url.len()));
        assert_success(&raeva(&["seed", "save", seed.to_str().unwrap()]), &url);
        let saved = fs::read_to_string(seed.join("seed.json")).unwrap();
        assert!(!saved.contains(TOKEN), "{url}: {saved}");
        assert!(saved.contains("mirror:m/"), "{url}: {saved}");
        fs::remove_dir_all(home.path().join("store")).unwrap();
        let seed = seed.to_str().unwrap();
        assert_success(&raeva(&["seed", "restore", seed]), &url);
        assert_success(&raeva(&["--offline", "sync", "--frozen"]), &url);
    }
}

/// `home` with settings.xml mirroring `mirror_of` to `url`, or none, and a
/// user config allowing `allowed` as a transitive repository.
fn ci_home(mirror: Option<(&str, &str)>, allowed: Option<&str>) -> TempDir {
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    let mirrors = mirror.map(|(mirror_of, url)| {
        format!(
            "<mirrors><mirror><id>nexus</id><url>{url}</url><mirrorOf>{mirror_of}</mirrorOf>\
             </mirror></mirrors>"
        )
    });
    let settings = format!("<settings>{}</settings>", mirrors.unwrap_or_default());
    fs::write(home.path().join(".m2/settings.xml"), settings).unwrap();
    if let Some(allowed) = allowed {
        let config = format!("[security]\ntransitive_repository_allowlist = [\"{allowed}\"]\n");
        fs::write(home.path().join("config.toml"), config).unwrap();
    }
    home
}

/// Whether any file under `dir` holds `bytes`.
fn holds_bytes(dir: &Path, bytes: &[u8]) -> bool {
    dir.exists()
        && walk(dir)
            .iter()
            .any(|file| fs::read(file).is_ok_and(|read| read == bytes))
}

/// A copy of `seed` holding `forged` in place of the blob of `bytes` is
/// refused by a restore into a home `home` makes, whose offline frozen
/// check then fails.
fn forged_seed_is_refused(
    project: &Path,
    seed: &Path,
    bytes: &[u8],
    forged: &[u8],
    home: impl Fn() -> TempDir,
) {
    let copy = copied(seed);
    let blob = copy
        .path()
        .join("blobs")
        .join(crate::common::sha256_hex(bytes));
    fs::write(&blob, forged).unwrap();
    let restored = home();
    let restore = ["seed", "restore", copy.path().to_str().unwrap()];
    let refused = run_raeva(project, restored.path(), &restore);
    assert_status(&refused, 7, "seed restore of other bytes");
    let offline = ["--offline", "sync", "--frozen"];
    let offline = run_raeva(project, restored.path(), &offline);
    assert!(
        !offline.status.success(),
        "offline frozen sync after a refused restore"
    );
}

/// A copy of `seed`.
fn copied(seed: &Path) -> TempDir {
    let copy = TempDir::new().unwrap();
    for file in walk(seed) {
        let target = copy.path().join(file.strip_prefix(seed).unwrap());
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(&file, &target).unwrap();
    }
    copy
}

/// A frozen check passes in `ci`; a seed saved there restores in `restored`
/// for an offline frozen check that asks `servers` for nothing.
fn seed_round_trip(
    project: &Path,
    ci: &Path,
    restored: &Path,
    servers: &[&StubServer],
    what: &str,
) {
    let frozen = run_raeva(project, ci, &["sync", "--frozen"]);
    assert_success(&frozen, &format!("frozen sync, {what}"));
    let seed = ci.join("seed");
    let save = ["seed", "save", seed.to_str().unwrap()];
    assert_success(
        &run_raeva(project, ci, &save),
        &format!("seed save, {what}"),
    );
    let restore = ["seed", "restore", seed.to_str().unwrap()];
    assert_success(
        &run_raeva(project, restored, &restore),
        &format!("seed restore, {what}"),
    );
    let before: Vec<_> = servers
        .iter()
        .map(|server| server.requests().len())
        .collect();
    let offline = ["--offline", "sync", "--frozen"];
    assert_success(
        &run_raeva(project, restored, &offline),
        &format!("offline frozen sync after restore, {what}"),
    );
    let after: Vec<_> = servers
        .iter()
        .map(|server| server.requests().len())
        .collect();
    assert_eq!(after, before, "{what}");
}

/// A repository only a dependency's POM declares, which the user's allowlist
/// admits, holds the file raeva.lock records from it. A frozen check behind a
/// mirror of every repository, or of Central only, takes the file from the
/// mirror, and the seed saved after it restores. A home whose policy refuses
/// that repository refuses the seed, and a mirror serving other bytes for
/// the file fails the frozen check and the save, which copies none of them.
#[test]
fn a_seed_carries_a_file_from_a_repository_a_dependency_declares() {
    use std::sync::{Arc, Mutex};
    const FORGED: &[u8] = b"forged lib jar";
    let lib = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>lib</artifactId><version>1</version></project>";
    let first = StubServer::start(move |request| {
        with_sha256(
            &request.path,
            [
                ("/t/lib/1/lib-1.pom", lib.as_bytes()),
                ("/t/lib/1/lib-1.jar", b"lib jar bytes".as_slice()),
            ],
        )
    });
    let first_url = format!("http://{}/", first.addr());
    let dep = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>d</groupId>\
         <artifactId>dep</artifactId><version>1</version><repositories><repository>\
         <id>first</id><url>{first_url}</url></repository></repositories><dependencies>\
         <dependency><groupId>t</groupId><artifactId>lib</artifactId><version>1</version>\
         </dependency></dependencies></project>"
    );
    let dep_files = move || {
        [
            ("/d/dep/1/dep-1.pom", dep.clone().into_bytes()),
            ("/d/dep/1/dep-1.jar", b"dep jar bytes".to_vec()),
        ]
    };
    let central = StubServer::start({
        let dep_files = dep_files.clone();
        move |request| with_sha256(&request.path, dep_files())
    });
    let jar: Arc<Mutex<&'static [u8]>> = Arc::new(Mutex::new(b"lib jar bytes"));
    let all = StubServer::start({
        let jar = Arc::clone(&jar);
        move |request| {
            let lib = [
                ("/t/lib/1/lib-1.pom", lib.as_bytes().to_vec()),
                ("/t/lib/1/lib-1.jar", jar.lock().unwrap().to_vec()),
            ];
            with_sha256(&request.path, dep_files().into_iter().chain(lib))
        }
    });
    let (central_url, all_url) = (
        format!("http://{}/", central.addr()),
        format!("http://{}/", all.addr()),
    );
    let allowed = Some(first_url.as_str());
    for mirror_of in ["*", "central"] {
        let project = TempDir::new().unwrap();
        let dependency = "<dependencies><dependency><groupId>d</groupId><artifactId>dep\
</artifactId><version>1</version></dependency></dependencies>";
        fs::write(project.path().join("pom.xml"), pom("app", dependency)).unwrap();
        let locked = ci_home(Some(("central", &central_url)), allowed);
        assert_success(&run_raeva(project.path(), locked.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
        assert!(
            lock.contains(&format!("repo_url = \"{first_url}\"")),
            "{lock}"
        );

        let ci = ci_home(Some((mirror_of, &all_url)), allowed);
        let restored = ci_home(Some((mirror_of, &all_url)), allowed);
        let servers = [&first, &all];
        seed_round_trip(
            project.path(),
            ci.path(),
            restored.path(),
            &servers,
            mirror_of,
        );
        if mirror_of != "*" {
            continue;
        }

        let seed = ci.path().join("seed");
        let restore = ["seed", "restore", seed.to_str().unwrap()];
        let refusing = ci_home(Some((mirror_of, &all_url)), None);
        let refused = run_raeva(project.path(), refusing.path(), &restore);
        assert_status(
            &refused,
            7,
            "seed restore where the policy refuses the repository",
        );
        let offline = ["--offline", "sync", "--frozen"];
        let offline = run_raeva(project.path(), refusing.path(), &offline);
        assert!(
            !offline.status.success(),
            "offline frozen sync after a refused restore"
        );

        forged_seed_is_refused(project.path(), &seed, b"lib jar bytes", FORGED, || {
            ci_home(Some((mirror_of, &all_url)), allowed)
        });
        *jar.lock().unwrap() = FORGED;
        let forged = ci_home(Some((mirror_of, &all_url)), allowed);
        let frozen = run_raeva(project.path(), forged.path(), &["sync", "--frozen"]);
        assert!(!frozen.status.success(), "frozen sync of other bytes");
        let seed = forged.path().join("seed");
        let save = run_raeva(
            project.path(),
            forged.path(),
            &["seed", "save", seed.to_str().unwrap()],
        );
        assert_status(&save, 7, "seed save of other bytes");
        assert!(
            !holds_bytes(&seed, FORGED),
            "the seed holds the other bytes"
        );
        *jar.lock().unwrap() = b"lib jar bytes";
    }
}

/// raeva.lock records a SNAPSHOT build from the first repository, which a
/// mirror of every repository served. Without the mirror that repository is
/// empty and the next one holds the build: a frozen check takes it from
/// there, as Maven does, and the seed saved after it restores. Other bytes
/// under the build's name fail the frozen check and the save.
#[test]
fn a_seed_carries_a_snapshot_build_from_the_next_repository() {
    use std::sync::{Arc, Mutex};
    const FORGED: &[u8] = b"forged snapshot jar";
    const METADATA: &str = "<metadata><groupId>t</groupId><artifactId>s</artifactId>\
<version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20260101.120000</timestamp>\
<buildNumber>3</buildNumber></snapshot><lastUpdated>20260101120000</lastUpdated>\
<snapshotVersions><snapshotVersion><extension>jar</extension>\
<value>1.0-20260101.120000-3</value><updated>20260101120000</updated></snapshotVersion>\
<snapshotVersion><extension>pom</extension><value>1.0-20260101.120000-3</value>\
<updated>20260101120000</updated></snapshotVersion></snapshotVersions></versioning></metadata>";
    let s_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>s</artifactId><version>1.0-SNAPSHOT</version></project>";
    let jar: Arc<Mutex<&'static [u8]>> = Arc::new(Mutex::new(b"snapshot jar"));
    let snaps = StubServer::start({
        let jar = Arc::clone(&jar);
        move |request| {
            let dir = "/t/s/1.0-SNAPSHOT";
            with_sha256(
                &request.path,
                [
                    (
                        format!("{dir}/maven-metadata.xml"),
                        METADATA.as_bytes().to_vec(),
                    ),
                    (
                        format!("{dir}/s-1.0-20260101.120000-3.pom"),
                        s_pom.as_bytes().to_vec(),
                    ),
                    (
                        format!("{dir}/s-1.0-20260101.120000-3.jar"),
                        jar.lock().unwrap().to_vec(),
                    ),
                ],
            )
        }
    });
    let empty = StubServer::start(|_| rv_test_support::http::Response::new(404, ""));
    let project = TempDir::new().unwrap();
    let repositories = format!(
        "<repositories><repository><id>first</id><url>http://{}/</url><snapshots>\
         <enabled>true</enabled></snapshots></repository><repository><id>snaps</id>\
         <url>http://{}/</url><releases><enabled>false</enabled></releases><snapshots>\
         <enabled>true</enabled></snapshots></repository></repositories>",
        empty.addr(),
        snaps.addr()
    );
    let dependency = "<dependencies><dependency><groupId>t</groupId><artifactId>s</artifactId>\
<version>1.0-SNAPSHOT</version></dependency></dependencies>";
    let body = format!("{repositories}{dependency}");
    fs::write(project.path().join("pom.xml"), pom("app", &body)).unwrap();
    let snaps_url = format!("http://{}/", snaps.addr());
    let locked = ci_home(Some(("*", &snaps_url)), None);
    assert_success(&run_raeva(project.path(), locked.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    let recorded = format!("repo_url = \"http://{}/\"", empty.addr());
    assert!(lock.contains(&recorded), "{lock}");

    let (ci, restored) = (ci_home(None, None), ci_home(None, None));
    let servers = [&snaps, &empty];
    seed_round_trip(
        project.path(),
        ci.path(),
        restored.path(),
        &servers,
        "snapshot",
    );

    let seed = ci.path().join("seed");
    forged_seed_is_refused(project.path(), &seed, b"snapshot jar", FORGED, || {
        ci_home(None, None)
    });
    *jar.lock().unwrap() = FORGED;
    let forged = ci_home(None, None);
    let frozen = run_raeva(project.path(), forged.path(), &["sync", "--frozen"]);
    assert!(!frozen.status.success(), "frozen sync of other bytes");
    let seed = forged.path().join("seed");
    let save = run_raeva(
        project.path(),
        forged.path(),
        &["seed", "save", seed.to_str().unwrap()],
    );
    assert_status(&save, 7, "seed save of other bytes");
    assert!(
        !holds_bytes(&seed, FORGED),
        "the seed holds the other bytes"
    );
}

/// A lock written with `-Pextra`: seed save and restore without it refuse
/// as `sync --frozen` does, naming the option, and the key is the same.
#[test]
fn a_seed_refuses_the_options_a_frozen_check_refuses() {
    let server = repository();
    let project = TempDir::new().unwrap();
    write_repo_toml(
        project.path(),
        "central",
        &format!("http://{}/", server.addr()),
    );
    let profile = "<profiles><profile><id>extra</id><dependencies><dependency>\
<groupId>t</groupId><artifactId>lib</artifactId><version>1</version></dependency>\
</dependencies></profile></profiles>";
    fs::write(project.path().join("pom.xml"), pom("app", profile)).unwrap();
    let home = TempDir::new().unwrap();
    let (project, home) = (project.path(), home.path());
    assert_success(&run_raeva(project, home, &["-Pextra", "sync"]), "sync");
    let frozen = ["-Pextra", "sync", "--frozen"];
    assert_success(&run_raeva(project, home, &frozen), "frozen sync");
    let seed = home.join("seed");
    let seed = seed.to_str().unwrap();
    for command in ["save", "restore"] {
        let refused = run_raeva(project, home, &["seed", command, seed]);
        assert_status(&refused, 7, &format!("seed {command} without -Pextra"));
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("-Pextra, which is not set here"),
            "{stderr}"
        );
        assert!(!stderr.contains("sync --frozen' first"), "{stderr}");
    }
    let key = |args: &[&str]| {
        let output = run_raeva(project, home, args);
        assert_success(&output, "seed key");
        output.stdout
    };
    assert_eq!(key(&["seed", "key"]), key(&["-Pextra", "seed", "key"]));
    assert_success(
        &run_raeva(project, home, &["-Pextra", "seed", "save", seed]),
        "seed save",
    );
    let restored = TempDir::new().unwrap();
    let restore = ["-Pextra", "seed", "restore", seed];
    assert_success(
        &run_raeva(project, restored.path(), &restore),
        "seed restore",
    );
    let offline = ["-Pextra", "--offline", "sync", "--frozen"];
    assert_success(
        &run_raeva(project, restored.path(), &offline),
        "offline frozen sync",
    );
}

/// A mirror whose URL holds a token and whose id has a character outside
/// letters, digits, `.`, `_` and `-` is named by its id with that character
/// written `%XX`. Its seed restores, with the version listing of a range,
/// and a mirror whose id is that spelling does not take it.
#[test]
fn a_seed_names_a_token_mirror_by_any_id() {
    const TOKEN: &str = "tok-odd-41";
    let server = StubServer::start(|request| {
        let path = request.path.strip_prefix(&format!("/{TOKEN}"));
        answer(path.unwrap_or("/not-the-mirror"))
    });
    let project = TempDir::new().unwrap();
    write_repo_toml(project.path(), "central", "http://central.invalid/");
    let dependency = "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
<version>[1,2)</version></dependency></dependencies>";
    fs::write(project.path().join("pom.xml"), pom("app", dependency)).unwrap();
    let home = |id: &str| {
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        let settings = format!(
            "<settings><mirrors><mirror><id>{id}</id><mirrorOf>*</mirrorOf>\
             <url>http://{}/${{env.REPO_TOKEN}}/</url></mirror></mirrors></settings>",
            server.addr()
        );
        fs::write(home.path().join(".m2/settings.xml"), settings).unwrap();
        home
    };
    let raeva = |home: &Path, args: &[&str]| {
        (raeva_command(project.path(), home))
            .env("REPO_TOKEN", TOKEN)
            .args(args)
            .output()
            .expect("run raeva")
    };
    for (id, name) in [
        ("corp:nexus", "corp%3Anexus"),
        ("corp+nexus", "corp%2Bnexus"),
        ("nexus~1", "nexus%7E1"),
        ("https://id.example/", "https%3A%2F%2Fid.example%2F"),
    ] {
        let ci = home(id);
        assert_success(&raeva(ci.path(), &["sync"]), "sync");
        assert_success(&raeva(ci.path(), &["sync", "--frozen"]), "frozen sync");
        let seed = ci.path().join("seed");
        let seed = seed.to_str().unwrap();
        assert_success(
            &raeva(ci.path(), &["seed", "save", seed]),
            &format!("seed save, {id}"),
        );
        let manifest = fs::read_to_string(Path::new(seed).join("seed.json")).unwrap();
        assert!(
            manifest.contains(&format!("\"mirror:{name}/\"")),
            "{manifest}"
        );
        assert!(walk(Path::new(seed)).iter().all(|file| {
            !fs::read(file)
                .unwrap()
                .windows(TOKEN.len())
                .any(|bytes| bytes == TOKEN.as_bytes())
        }));
        let restored = home(id);
        let restore = ["seed", "restore", seed];
        assert_success(
            &raeva(restored.path(), &restore),
            &format!("seed restore, {id}"),
        );
        let before = server.requests().len();
        let offline = ["--offline", "sync", "--frozen"];
        assert_success(
            &raeva(restored.path(), &offline),
            &format!("offline frozen, {id}"),
        );
        assert_eq!(server.requests().len(), before, "{id}");

        let spelled = home(name);
        assert_status(
            &raeva(spelled.path(), &restore),
            7,
            &format!("seed restore, {name}"),
        );
        let offline = raeva(spelled.path(), &["--offline", "sync", "--frozen"]);
        assert!(!offline.status.success(), "offline frozen sync, {name}");
    }
}

/// A seed whose unpinned rows steer the restore's resolution of a range to
/// another version, whose POM declares an allowlisted repository the lock
/// records nowhere, does not get a pinned file in through that repository.
#[test]
fn a_seed_cannot_steer_its_restore_to_a_repository_the_lock_does_not_record() {
    let server = repository();
    let other = StubServer::start(|_| rv_test_support::http::Response::new(404, ""));
    let other_url = format!("http://{}/", other.addr());
    let home = || ci_home(None, Some(&other_url));
    let project = TempDir::new().unwrap();
    write_repo_toml(
        project.path(),
        "central",
        &format!("http://{}/", server.addr()),
    );
    let dependency = "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
<version>[0,2)</version></dependency></dependencies>";
    fs::write(project.path().join("pom.xml"), pom("app", dependency)).unwrap();
    let ci = home();
    let (project, ci) = (project.path(), ci.path());
    assert_success(&run_raeva(project, ci, &["sync"]), "sync");
    assert_success(
        &run_raeva(project, ci, &["sync", "--frozen"]),
        "frozen sync",
    );
    let seed = ci.join("seed");
    let save = ["seed", "save", seed.to_str().unwrap()];
    assert_success(&run_raeva(project, ci, &save), "seed save");

    let steer = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>lib</artifactId><version>1.5</version><repositories><repository>\
         <id>other</id><url>{other_url}</url></repository></repositories><dependencies>\
         <dependency><groupId>t</groupId><artifactId>parent</artifactId><version>1</version>\
         <type>pom</type></dependency></dependencies></project>"
    );
    let listing = LISTING.replace(
        "<version>1</version>",
        "<version>1</version><version>1.5</version>",
    );
    let add = |content: &str| {
        let digest = crate::common::sha256_hex(content.as_bytes());
        fs::write(seed.join("metadata").join(&digest), content).unwrap();
        digest
    };
    let (steer, listing) = (add(&steer), add(&listing));
    edit_manifest(&seed, |manifest| {
        let rows = manifest["metadata"].as_array_mut().unwrap();
        let mut pom = (rows.iter())
            .find(|row| row["path"] == "t/lib/1/lib-1.pom")
            .unwrap()
            .clone();
        pom["path"] = "t/lib/1.5/lib-1.5.pom".into();
        pom["sha256"] = steer.into();
        for row in rows.iter_mut() {
            if row["path"] == "t/lib/maven-metadata.xml" {
                row["sha256"] = listing.clone().into();
            }
        }
        rows.push(pom);
        for file in manifest["files"].as_array_mut().unwrap() {
            if file["coordinate"] == "t:lib:1:jar" {
                file["served"] = serde_json::json!([[other_url, other_url]]);
            }
        }
    });
    let restored = home();
    let restore = ["seed", "restore", seed.to_str().unwrap()];
    let refused = run_raeva(project, restored.path(), &restore);
    assert_status(&refused, 7, "seed restore steered to another repository");
    let offline = ["--offline", "sync", "--frozen"];
    let offline = run_raeva(project, restored.path(), &offline);
    assert!(
        !offline.status.success(),
        "offline frozen sync after a refused restore"
    );
}

/// A dependency's POM declares two repositories that hold the file, and
/// raeva.lock records the first. Once the first lacks it, a frozen check
/// takes the file from the second, which the lock records nowhere, and so
/// does the seed.
#[test]
fn a_seed_carries_a_file_from_the_next_repository_a_dependency_declares() {
    let lib = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>lib</artifactId><version>1</version></project>";
    let lib_files = move || {
        [
            ("/t/lib/1/lib-1.pom", lib.as_bytes().to_vec()),
            ("/t/lib/1/lib-1.jar", b"lib jar bytes".to_vec()),
        ]
    };
    let serves = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let empty = StubServer::start({
        let serves = std::sync::Arc::clone(&serves);
        move |request| match serves.load(std::sync::atomic::Ordering::SeqCst) {
            true => with_sha256(&request.path, lib_files()),
            false => rv_test_support::http::Response::new(404, ""),
        }
    });
    let second = StubServer::start(move |request| with_sha256(&request.path, lib_files()));
    let (first_url, second_url) = (
        format!("http://{}/", empty.addr()),
        format!("http://{}/", second.addr()),
    );
    let dep = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>d</groupId>\
         <artifactId>dep</artifactId><version>1</version><repositories><repository>\
         <id>first</id><url>{first_url}</url></repository><repository><id>second</id>\
         <url>{second_url}</url></repository></repositories><dependencies><dependency>\
         <groupId>t</groupId><artifactId>lib</artifactId><version>1</version></dependency>\
         </dependencies></project>"
    );
    let dep_files = move || {
        [
            ("/d/dep/1/dep-1.pom", dep.clone().into_bytes()),
            ("/d/dep/1/dep-1.jar", b"dep jar bytes".to_vec()),
        ]
    };
    let central = StubServer::start({
        let dep_files = dep_files.clone();
        move |request| with_sha256(&request.path, dep_files())
    });
    let home = |mirror: Option<(&str, &str)>| {
        let home = ci_home(mirror, None);
        let config = format!(
            "[security]\ntransitive_repository_allowlist = [\"{first_url}\", \"{second_url}\"]\n"
        );
        fs::write(home.path().join("config.toml"), config).unwrap();
        home
    };
    let project = TempDir::new().unwrap();
    let dependency = "<dependencies><dependency><groupId>d</groupId><artifactId>dep\
</artifactId><version>1</version></dependency></dependencies>";
    fs::write(project.path().join("pom.xml"), pom("app", dependency)).unwrap();
    let central_url = format!("http://{}/", central.addr());
    let locked = home(Some(("central", &central_url)));
    assert_success(&run_raeva(project.path(), locked.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    assert!(
        lock.contains(&format!("repo_url = \"{first_url}\"")),
        "{lock}"
    );

    let central_url = format!("http://{}/", central.addr());
    let (ci, restored) = (
        home(Some(("central", &central_url))),
        home(Some(("central", &central_url))),
    );
    let servers = [&second, &central];
    seed_round_trip(project.path(), ci.path(), restored.path(), &servers, "next");
}

/// An imported BOM declares repositories `first`, which alone holds the BOM's
/// parent, and `second`, so raeva.lock records the parent from `first`. A
/// frozen check behind a mirror of every repository, or of Central only,
/// reads that parent where the BOM's build searches, and the seed saved after
/// it restores. `first` serves that parent alone: a seed or a store naming it
/// for another file is refused, and so are other bytes for the parent and a
/// seed naming `second` for it, which the lock records for nothing.
#[test]
fn a_seed_carries_a_bom_parent_from_the_repository_only_the_bom_declares() {
    use std::sync::{Arc, Mutex};
    const PARENT: &[u8] = b"<project><modelVersion>4.0.0</modelVersion><groupId>d</groupId>\
<artifactId>bom-parent</artifactId><version>1.0</version><packaging>pom</packaging></project>";
    const FORGED: &[u8] = b"<project><modelVersion>4.0.0</modelVersion><groupId>d</groupId>\
<artifactId>bom-parent</artifactId><version>1.0</version><packaging>pom</packaging>\
<description>other</description></project>";
    const COMMON: &[u8] = b"common jar bytes";
    let parent: Arc<Mutex<&'static [u8]>> = Arc::new(Mutex::new(PARENT));
    let parent_file = {
        let parent = Arc::clone(&parent);
        move || {
            (
                "/d/bom-parent/1.0/bom-parent-1.0.pom",
                parent.lock().unwrap().to_vec(),
            )
        }
    };
    let first = StubServer::start({
        let parent_file = parent_file.clone();
        move |request| with_sha256(&request.path, [parent_file()])
    });
    let first_url = format!("http://{}/", first.addr());
    let second = StubServer::start(|_| rv_test_support::http::Response::new(404, ""));
    let second_url = format!("http://{}/", second.addr());
    let bom = format!(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>d</groupId>\
         <artifactId>bom-parent</artifactId><version>1.0</version><relativePath/></parent>\
         <artifactId>bom</artifactId><packaging>pom</packaging><repositories><repository>\
         <id>first</id><url>{first_url}</url></repository><repository><id>second</id>\
         <url>{second_url}</url></repository></repositories>\
         <dependencyManagement><dependencies><dependency><groupId>c</groupId>\
         <artifactId>common</artifactId><version>1.0</version></dependency></dependencies>\
         </dependencyManagement></project>"
    );
    let central_files = move || {
        [
            ("/d/bom/1.0/bom-1.0.pom", bom.clone().into_bytes()),
            (
                "/c/common/1.0/common-1.0.pom",
                b"<project><modelVersion>4.0.0</modelVersion><groupId>c</groupId>\
<artifactId>common</artifactId><version>1.0</version></project>"
                    .to_vec(),
            ),
            ("/c/common/1.0/common-1.0.jar", COMMON.to_vec()),
        ]
    };
    let central = StubServer::start({
        let central_files = central_files.clone();
        move |request| with_sha256(&request.path, central_files())
    });
    let all = StubServer::start(move |request| {
        with_sha256(
            &request.path,
            central_files().into_iter().chain([parent_file()]),
        )
    });
    let (central_url, all_url) = (
        format!("http://{}/", central.addr()),
        format!("http://{}/", all.addr()),
    );
    let project = TempDir::new().unwrap();
    let body = "<dependencyManagement><dependencies><dependency><groupId>d</groupId>\
<artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope>\
</dependency></dependencies></dependencyManagement><dependencies><dependency>\
<groupId>c</groupId><artifactId>common</artifactId></dependency></dependencies>";
    fs::write(project.path().join("pom.xml"), pom("app", body)).unwrap();
    let project = project.path();
    let ci_home = |mirror| {
        let home = ci_home(mirror, None);
        let config = "[security]\nallow_transitive_repositories = true\n";
        fs::write(home.path().join("config.toml"), config).unwrap();
        home
    };
    let locked = ci_home(Some(("central", &central_url)));
    assert_success(&run_raeva(project, locked.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).unwrap();
    assert!(
        lock.contains(&format!(
            "coordinate = \"d:bom-parent:1.0\"\nrepo_url = \"{first_url}\""
        )),
        "{lock}"
    );

    for mirror_of in ["*", "central"] {
        let home = || ci_home(Some((mirror_of, &all_url)));
        let (ci, restored) = (home(), home());
        let servers = [&first, &all];
        seed_round_trip(project, ci.path(), restored.path(), &servers, mirror_of);
        let seed = ci.path().join("seed");
        let endpoint = |url: &String| {
            if mirror_of == "*" {
                all_url.clone()
            } else {
                url.clone()
            }
        };
        let first_endpoint = endpoint(&first_url);

        let routes = [
            ("c:common:1.0:jar", &first_url),
            ("c:common:1.0:pom", &first_url),
            ("d:bom:1.0:pom", &first_url),
            ("d:bom-parent:1.0:pom", &second_url),
        ];
        for (coordinate, repository) in routes {
            let forged = copied(&seed);
            edit_manifest(forged.path(), |manifest| {
                for file in manifest["files"].as_array_mut().unwrap() {
                    if file["coordinate"] == coordinate {
                        let route = [repository.clone(), endpoint(repository)];
                        file["served"] = serde_json::json!([route]);
                    }
                }
            });
            let restored = home();
            let restore = ["seed", "restore", forged.path().to_str().unwrap()];
            let refused = run_raeva(project, restored.path(), &restore);
            assert_status(
                &refused,
                7,
                &format!("restore of {coordinate} from {repository}"),
            );
            let offline = ["--offline", "sync", "--frozen"];
            let offline = run_raeva(project, restored.path(), &offline);
            assert!(
                !offline.status.success(),
                "offline frozen sync after a refused restore of {coordinate}"
            );
        }

        forged_seed_is_refused(project, &seed, PARENT, FORGED, home);
        *parent.lock().unwrap() = FORGED;
        let forged = home();
        let frozen = run_raeva(project, forged.path(), &["sync", "--frozen"]);
        assert!(!frozen.status.success(), "frozen sync of other bytes");
        let forged_seed = forged.path().join("seed");
        let save = ["seed", "save", forged_seed.to_str().unwrap()];
        assert_status(
            &run_raeva(project, forged.path(), &save),
            7,
            "save of other bytes",
        );
        assert!(
            !holds_bytes(&forged_seed, FORGED),
            "the seed holds the other bytes"
        );
        *parent.lock().unwrap() = PARENT;

        let store = rusqlite::Connection::open(ci.path().join("store/index.sqlite")).unwrap();
        let moved = store
            .execute(
                "UPDATE served_files SET repo_url = ?1, endpoint_url = ?2 \
                 WHERE artifact_id = 'common' AND packaging = 'jar'",
                [&first_url, &first_endpoint],
            )
            .unwrap();
        assert_eq!(moved, 1);
        drop(store);
        let other = ci.path().join("seed-common");
        let save = ["seed", "save", other.to_str().unwrap()];
        let refused = run_raeva(project, ci.path(), &save);
        assert_status(&refused, 7, "save of a jar the store holds from first");
        assert!(!holds_bytes(&other, COMMON), "the seed holds the jar");
    }
}
