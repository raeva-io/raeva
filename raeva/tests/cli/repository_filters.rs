//! Maven's remote repository filters: a repository is not asked for what
//! its `groupId` or `prefixes` rule file leaves out, and the settings and
//! rule files are inputs a frozen sync checks.

use std::fs;
use std::path::Path;

use rv_maven_types::BlobId;
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{assert_status, assert_success, run_raeva, sha1_hex};

fn publish(repository: &Path, group: &str, artifact: &str) {
    let dir = repository.join(format!("{}/{artifact}/1.0", group.replace('.', "/")));
    fs::create_dir_all(&dir).expect("create repository");
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>{group}</groupId>\
         <artifactId>{artifact}</artifactId><version>1.0</version></project>"
    );
    fs::write(dir.join(format!("{artifact}-1.0.pom")), pom).expect("write pom");
    fs::write(
        dir.join(format!("{artifact}-1.0.jar")),
        format!("{artifact} bytes"),
    )
    .expect("write jar");
}

/// Serves the files below `root`, each with a `.sha256` sidecar.
fn file_server(root: &Path) -> StubServer {
    let root = root.to_path_buf();
    StubServer::start(move |request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        match fs::read(root.join(path.trim_start_matches('/'))) {
            Ok(bytes) if sidecar => Response::new(200, BlobId::from_bytes(&bytes).to_string()),
            Ok(bytes) => Response::new(200, bytes),
            Err(_) => Response::new(404, ""),
        }
    })
}

fn asked(server: &StubServer, prefix: &str) -> usize {
    (server.requests().iter())
        .filter(|request| request.path.starts_with(prefix))
        .count()
}

/// The repository raeva.lock records for each artifact, by artifact id.
fn origins(project: &Path) -> Vec<(String, String)> {
    let lock = rv_lock::Lockfile::read(&project.join("raeva.lock")).expect("lock");
    let mut origins: Vec<_> = (lock.platforms.iter())
        .flat_map(|platform| platform.artifacts.iter())
        .map(|artifact| {
            let id = artifact.coordinate.gav.artifact.as_str().to_string();
            (id, artifact.repo_url.clone())
        })
        .collect();
    origins.sort();
    origins.dedup();
    origins
}

struct Fixture {
    base: TempDir,
    home: TempDir,
    project: std::path::PathBuf,
    r1: StubServer,
    r2: StubServer,
}

/// `r1` serves `org.ex.b:b1`, `org.ex.b.sub:c1` and `org.ex.a:a1`, `r2`
/// the last two, and the project, which configures `r1` then `r2`,
/// depends on all three.
fn fixture() -> Fixture {
    let base = TempDir::new().unwrap();
    let (one, two) = (base.path().join("one"), base.path().join("two"));
    publish(&one, "org.ex.b", "b1");
    publish(&one, "org.ex.b.sub", "c1");
    publish(&one, "org.ex.a", "a1");
    publish(&two, "org.ex.a", "a1");
    publish(&two, "org.ex.b.sub", "c1");
    let (r1, r2) = (file_server(&one), file_server(&two));
    let project = base.path().join("project");
    fs::create_dir_all(project.join(".mvn")).unwrap();
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"r1\"\nurl = \"http://{}/\"\n\n\
             [[repositories]]\nid = \"r2\"\nurl = \"http://{}/\"\n",
            r1.addr(),
            r2.addr()
        ),
    )
    .unwrap();
    let dependency = |group: &str, artifact: &str| {
        format!(
            "<dependency><groupId>{group}</groupId><artifactId>{artifact}</artifactId>\
             <version>1.0</version></dependency>"
        )
    };
    fs::write(
        project.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.ex</groupId>\
             <artifactId>fx</artifactId><version>1</version><dependencies>{}{}{}\
             </dependencies></project>",
            dependency("org.ex.a", "a1"),
            dependency("org.ex.b", "b1"),
            dependency("org.ex.b.sub", "c1"),
        ),
    )
    .unwrap();
    Fixture {
        base,
        home: TempDir::new().unwrap(),
        project,
        r1,
        r2,
    }
}

fn url(server: &StubServer) -> String {
    format!("http://{}/", server.addr())
}

fn maven_310(project: &Path) {
    let wrapper = project.join(".mvn/wrapper");
    fs::create_dir_all(&wrapper).unwrap();
    fs::write(
        wrapper.join("maven-wrapper.properties"),
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/\
         3.10.0/apache-maven-3.10.0-bin.zip\n",
    )
    .unwrap();
}

/// The groupId filter of `.mvn/maven.config`, whose basedir is
/// `${session.rootDirectory}/.mvn/rrf/`, keeps `r1` from the groups its
/// file does not list, exactly as Maven 3.9 matches them; the rule file is
/// an input a frozen sync checks; and `export-m2` exports what the filtered
/// resolution locked.
#[test]
fn a_group_id_filter_keeps_a_repository_to_its_listed_groups() {
    let Fixture {
        base,
        home,
        project,
        r1,
        r2,
    } = fixture();
    let rrf = project.join(".mvn/rrf");
    fs::create_dir_all(&rrf).unwrap();
    fs::write(
        project.join(".mvn/maven.config"),
        "-Daether.remoteRepositoryFilter.groupId=true\n\
         -Daether.remoteRepositoryFilter.groupId.basedir=${session.rootDirectory}/.mvn/rrf/\n",
    )
    .unwrap();
    fs::write(
        rrf.join("groupId-r1.txt"),
        "# r1 serves only these\norg.ex.b\n",
    )
    .unwrap();

    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    assert_eq!(asked(&r1, "/org/ex/a/"), 0, "{:?}", r1.requests());
    assert_eq!(asked(&r1, "/org/ex/b/sub/"), 0, "{:?}", r1.requests());
    assert!(asked(&r1, "/org/ex/b/b1/") > 0);
    let expected = |c1: &StubServer| {
        vec![
            ("a1".to_string(), url(&r2)),
            ("b1".to_string(), url(&r1)),
            ("c1".to_string(), url(c1)),
        ]
    };
    assert_eq!(origins(&project), expected(&r2));

    let m2 = base.path().join("m2");
    let export = run_raeva(
        &project,
        home.path(),
        &["export-m2", "--m2-path", m2.to_str().unwrap()],
    );
    assert_success(&export, "export-m2");
    assert!(m2.join("org/ex/b/sub/c1/1.0/c1-1.0.jar").is_file());

    assert_success(
        &run_raeva(&project, home.path(), &["sync", "--frozen"]),
        "frozen",
    );
    fs::write(rrf.join("groupId-r1.txt"), "org.ex.b\norg.ex.b.sub\n").unwrap();
    let frozen = run_raeva(&project, home.path(), &["sync", "--frozen"]);
    assert_status(&frozen, 7, "frozen sync after the rule file changed");
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(
        stderr.contains("remote repository filter files"),
        "{stderr}"
    );
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    assert_eq!(origins(&project), expected(&r1));
    assert!(asked(&r1, "/org/ex/b/sub/") > 0);
    assert_eq!(asked(&r1, "/org/ex/a/"), 0);
}

/// A filter basedir that names `${os.arch}` gives each platform the rules
/// of its own architecture's directory, as Maven run there reads them, in
/// either mode, whichever platforms a sync takes and in what order; a cold
/// frozen check restores each, and a change to the rules of a platform
/// other than the host's makes the lock stale.
#[test]
fn each_platform_reads_the_filter_rules_its_architecture_names() {
    for maven in ["3.9", "3.10"] {
        let Fixture {
            base: _base,
            home,
            project,
            r1,
            r2,
        } = fixture();
        if maven == "3.10" {
            maven_310(&project);
        }
        fs::write(
            project.join(".mvn/maven.config"),
            "-Daether.remoteRepositoryFilter.groupId=true\n\
             -Daether.remoteRepositoryFilter.groupId.basedir=\
             ${session.rootDirectory}/.mvn/rrf/${os.arch}\n",
        )
        .unwrap();
        for (arch, groups) in [("amd64", "org.ex.b\n"), ("aarch64", "org.ex.b\norg.ex.a\n")] {
            let dir = project.join(".mvn/rrf").join(arch);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("groupId-r1.txt"), groups).unwrap();
        }
        // a1 comes from r1 where its group is listed, else from r2.
        let a1 = |platform: &str| {
            let lock = rv_lock::Lockfile::read(&project.join("raeva.lock")).expect("lock");
            let entry = (lock.platforms.iter())
                .find(|entry| entry.platform.os_arch() == platform)
                .unwrap_or_else(|| panic!("{platform}"));
            (entry.artifacts.iter())
                .find(|artifact| artifact.coordinate.gav.artifact.as_str() == "a1")
                .map(|artifact| artifact.repo_url.clone())
                .expect("a1")
        };
        let (aarch64, x86_64) = (url(&r1), url(&r2));
        for platforms in [
            "linux-aarch64",
            "linux-x86_64",
            "linux-x86_64,linux-aarch64",
            "linux-aarch64,linux-x86_64",
        ] {
            let _ = fs::remove_file(project.join("raeva.lock"));
            let sync = run_raeva(&project, home.path(), &["sync", "--platforms", platforms]);
            assert_success(&sync, &format!("{maven} {platforms}"));
            if platforms.contains("aarch64") {
                assert_eq!(a1("linux-aarch64"), aarch64, "{maven} {platforms}");
            }
            if platforms.contains("x86_64") {
                assert_eq!(a1("linux-x86_64"), x86_64, "{maven} {platforms}");
            }
        }
        // `export-m2` and a plain frozen check need the host's platform.
        let host = rv_lock::Platform::current().unwrap().os_arch();
        if !host.starts_with("linux-") {
            let sync = run_raeva(&project, home.path(), &["sync", "--platforms", &host]);
            assert_success(&sync, &format!("{maven} {host}"));
            let own = match std::env::consts::ARCH {
                "aarch64" => &aarch64,
                _ => &x86_64,
            };
            assert_eq!(&a1(&host), own, "{maven} {host}");
            assert_eq!(a1("linux-aarch64"), aarch64, "{maven} {host}");
        }
        // Only r1 has a1's sources, which only the aarch64 rules let it serve.
        let sources = _base.path().join("one/org/ex/a/a1/1.0/a1-1.0-sources.jar");
        fs::write(&sources, "a1 sources").unwrap();
        let m2 = _base.path().join("m2");
        let export = run_raeva(
            &project,
            home.path(),
            &[
                "export-m2",
                "--with-sources",
                "--m2-path",
                m2.to_str().unwrap(),
            ],
        );
        assert_success(&export, &format!("{maven} export-m2"));
        assert!(
            m2.join("org/ex/a/a1/1.0/a1-1.0-sources.jar").is_file(),
            "{maven}: {}",
            String::from_utf8_lossy(&export.stderr)
        );

        let cold = TempDir::new().unwrap();
        let frozen = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
        assert_success(&frozen, &format!("{maven} cold frozen"));

        // The rules of the platform other than the host's.
        let other = match std::env::consts::ARCH {
            "aarch64" => "amd64",
            _ => "aarch64",
        };
        let rules = project.join(".mvn/rrf").join(other).join("groupId-r1.txt");
        fs::write(&rules, "org.ex.b\norg.ex.changed\n").unwrap();
        let frozen = run_raeva(&project, home.path(), &["sync", "--frozen"]);
        assert_status(
            &frozen,
            7,
            &format!("{maven} frozen after {other} rules changed"),
        );
    }
}

/// Maven 3.10 enables the filters by default and reads a rule file from
/// `.remoteRepositoryFilters` in the local repository; a prefixes file needs
/// its header there. Maven 3.9 reads neither without the property. A copy
/// cached from the repository the filter now leaves out is not used, and a
/// property that turns the filter off for a repository is an input.
#[test]
fn maven_310_reads_a_prefixes_file_from_the_local_repository_by_default() {
    let Fixture {
        base: _base,
        home,
        project,
        r1,
        r2,
    } = fixture();
    let rules = home.path().join(".m2/repository/.remoteRepositoryFilters");
    fs::create_dir_all(&rules).unwrap();
    fs::write(
        rules.join("prefixes-r1.txt"),
        "## repository-prefixes/2.0\n/org/ex/b\n",
    )
    .unwrap();
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "3.9 sync");
    assert!(asked(&r1, "/org/ex/a/") > 0);
    let before = asked(&r1, "/");

    maven_310(&project);
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "3.10 sync");
    let asked_since = |prefix: &str| {
        (r1.requests().iter().skip(before))
            .filter(|request| request.path.starts_with(prefix))
            .count()
    };
    assert_eq!(asked_since("/org/ex/a/"), 0, "{:?}", r1.requests());
    let origins = origins(&project);
    assert!(
        origins.contains(&("a1".to_string(), url(&r2))),
        "{origins:?}"
    );
    assert!(
        origins.contains(&("c1".to_string(), url(&r1))),
        "{origins:?}"
    );

    // Turning the filter off for r1 reads the same rule files, and only the
    // property tells the lock is out of date.
    let off = "-Daether.remoteRepositoryFilter.prefixes.r1=false";
    let frozen = run_raeva(&project, home.path(), &["sync", "--frozen", off]);
    assert_status(&frozen, 7, "frozen sync with the filter off for r1");
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(stderr.contains(off.split('=').next().unwrap()), "{stderr}");
}

/// A filter set on the command line after raeva.lock was written makes it
/// out of date, though no model reads the property, and raeva.lock then
/// lists the property as a user property it was resolved with.
#[test]
fn a_filter_set_after_the_lock_was_written_makes_it_stale() {
    let Fixture {
        base,
        home,
        project,
        r1,
        r2: _r2,
    } = fixture();
    let rrf = base.path().join("rrf");
    fs::create_dir_all(&rrf).unwrap();
    fs::write(rrf.join("groupId-r1.txt"), "org.ex.b\n").unwrap();
    let basedir = format!(
        "-Daether.remoteRepositoryFilter.groupId.basedir={}",
        rrf.display()
    );
    let on = "-Daether.remoteRepositoryFilter.groupId=true";
    let sync = |args: &[&str]| run_raeva(&project, home.path(), args);
    assert_success(&sync(&["sync"]), "sync");
    assert!(asked(&r1, "/org/ex/a/") > 0);

    let frozen = sync(&["sync", "--frozen", on, &basedir]);
    assert_status(&frozen, 7, "frozen sync with a filter set");
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(stderr.contains(on.split('=').next().unwrap()), "{stderr}");

    assert_success(&sync(&["sync", on, &basedir]), "filtered sync");
    let lock = rv_lock::Lockfile::read(&project.join("raeva.lock")).expect("lock");
    assert!(
        (lock.resolution.ambient_inputs).contains(&rv_lock::AmbientInput::UserProperty(
            "aether.remoteRepositoryFilter.groupId".into()
        )),
        "{:?}",
        lock.resolution.ambient_inputs
    );
    assert!(
        (lock.resolution.ambient_inputs.iter()).all(|input| !input.to_string().contains("basedir")),
        "{:?}",
        lock.resolution.ambient_inputs
    );
    assert_success(&sync(&["sync", "--frozen", on, &basedir]), "frozen");
    let unset = sync(&["sync", "--frozen"]);
    assert_status(&unset, 7, "frozen sync without the filter");
}

/// Maven 3.10 names a rule file for one repository URL by the SHA-1 of the
/// URL as declared, so `r1` declared without a trailing slash reads the
/// file named for that spelling.
#[test]
fn maven_310_keys_a_rule_file_by_the_url_as_declared() {
    let Fixture {
        base: _base,
        home,
        project,
        r1,
        r2,
    } = fixture();
    let declared = format!("http://{}", r1.addr());
    let config = fs::read_to_string(project.join("raeva.toml")).unwrap();
    let config = config.replacen(&url(&r1), &declared, 1);
    fs::write(project.join("raeva.toml"), config).unwrap();
    maven_310(&project);
    let rules = home.path().join(".m2/repository/.remoteRepositoryFilters");
    fs::create_dir_all(&rules).unwrap();
    let name = format!("groupId-r1-{}.txt", sha1_hex(declared.as_bytes()));
    fs::write(rules.join(name), "org.ex.b\n").unwrap();
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    assert_eq!(asked(&r1, "/org/ex/a/"), 0, "{:?}", r1.requests());
    let origins = origins(&project);
    assert!(
        origins.contains(&("a1".to_string(), url(&r2))),
        "{origins:?}"
    );
}

/// A dependency the groupId filter keeps from the one repository that
/// serves it is not found, as in Maven, which names the filter ("G:org.ex.b
/// NOT allowed from r1"); the error says the filter refused that
/// repository rather than that it answered 404.
#[test]
fn a_dependency_the_filter_keeps_from_its_repository_names_the_filter() {
    let Fixture {
        base: _base,
        home,
        project,
        r1,
        r2,
    } = fixture();
    let rrf = project.join(".mvn/rrf");
    fs::create_dir_all(&rrf).unwrap();
    fs::write(
        project.join(".mvn/maven.config"),
        "-Daether.remoteRepositoryFilter.groupId=true\n\
         -Daether.remoteRepositoryFilter.groupId.basedir=${session.rootDirectory}/.mvn/rrf/\n",
    )
    .unwrap();
    fs::write(rrf.join("groupId-r1.txt"), "org.ex.a\norg.ex.b.sub\n").unwrap();

    let sync = run_raeva(&project, home.path(), &["--json", "sync"]);
    assert_status(&sync, 5, "sync of a filtered dependency");
    assert_eq!(asked(&r1, "/org/ex/b/b1/"), 0, "{:?}", r1.requests());
    let envelope: serde_json::Value = serde_json::from_slice(&sync.stdout).expect("envelope");
    assert_eq!(envelope["code"], "ARTIFACT_NOT_FOUND", "{envelope}");
    let error = envelope["error"].as_str().unwrap();
    assert!(
        error.contains(&format!(
            "{} (not allowed by the remote repository filters)",
            url(&r1)
        )) && error.contains(&format!("{} (404)", url(&r2))),
        "{error}"
    );
    let hints = envelope["hints"].to_string();
    assert!(hints.contains("aether.remoteRepositoryFilter"), "{hints}");
}

/// Publishes `org.ex.b:parent:1.0` and `org.ex.b:bom:1.0` and `b1`'s version
/// list in `r1` only, keeps `r1` to `org.ex.a` with the groupId filter, syncs
/// a project with `pom` as its POM, and checks the error names the filter
/// for `r1` and a 404 for `r2`. `served` are POMs `r2` serves, by
/// `group/artifact`, at version 1.0. Returns the envelope.
fn filtered_out(pom: &str, modules: &[(&str, &str)], served: &[(&str, &str)]) -> serde_json::Value {
    let Fixture {
        base,
        home,
        project,
        r1,
        r2,
    } = fixture();
    let one = base.path().join("one");
    for artifact in ["b1", "parent"] {
        let dir = one.join(format!("org/ex/b/{artifact}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("maven-metadata.xml"),
            format!(
                "<metadata><groupId>org.ex.b</groupId><artifactId>{artifact}</artifactId>\
                 <versioning><versions><version>1.0</version></versions></versioning></metadata>"
            ),
        )
        .unwrap();
    }
    for artifact in ["parent", "bom"] {
        let dir = one.join(format!("org/ex/b/{artifact}/1.0"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!("{artifact}-1.0.pom")),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.ex.b</groupId>\
                 <artifactId>{artifact}</artifactId><version>1.0</version>\
                 <packaging>pom</packaging></project>"
            ),
        )
        .unwrap();
    }
    for (path, pom) in served {
        let dir = base.path().join("two").join(path).join("1.0");
        fs::create_dir_all(&dir).unwrap();
        let artifact = path.rsplit('/').next().unwrap();
        fs::write(dir.join(format!("{artifact}-1.0.pom")), pom).unwrap();
    }
    let rrf = project.join(".mvn/rrf");
    fs::create_dir_all(&rrf).unwrap();
    fs::write(
        project.join(".mvn/maven.config"),
        "-Daether.remoteRepositoryFilter.groupId=true\n\
         -Daether.remoteRepositoryFilter.groupId.basedir=${session.rootDirectory}/.mvn/rrf/\n",
    )
    .unwrap();
    fs::write(rrf.join("groupId-r1.txt"), "org.ex.a\n").unwrap();
    fs::write(project.join("pom.xml"), pom).unwrap();
    for (dir, pom) in modules {
        fs::create_dir_all(project.join(dir)).unwrap();
        fs::write(project.join(dir).join("pom.xml"), pom).unwrap();
    }
    let sync = run_raeva(&project, home.path(), &["--json", "sync"]);
    assert_status(&sync, 5, "sync");
    let envelope: serde_json::Value = serde_json::from_slice(&sync.stdout).expect("envelope");
    let error = envelope["error"].as_str().unwrap();
    assert!(
        error.contains(&format!(
            "{} (not allowed by the remote repository filters)",
            url(&r1)
        )) && !error.contains(&format!("{} (404)", url(&r1)))
            && error.contains(&format!("{} (404)", url(&r2))),
        "{envelope}"
    );
    assert!(
        envelope["hints"]
            .to_string()
            .contains("aether.remoteRepositoryFilter"),
        "{envelope}"
    );
    assert_eq!(asked(&r1, "/org/ex/b/"), 0, "{:?}", r1.requests());
    envelope
}

const FX: &str = "<modelVersion>4.0.0</modelVersion><groupId>org.ex</groupId>\
                  <artifactId>fx</artifactId><version>1</version>";

/// A version range only a repository the filter keeps out lists fails as
/// in Maven, and the error names the filter for that repository.
#[test]
fn a_range_the_filter_keeps_out_names_the_filter() {
    let envelope = filtered_out(
        &format!(
            "<project>{FX}<dependencies><dependency><groupId>org.ex.b</groupId>\
             <artifactId>b1</artifactId><version>[1.0,2.0)</version></dependency>\
             </dependencies></project>"
        ),
        &[],
        &[],
    );
    assert_eq!(envelope["code"], "ARTIFACT_NOT_FOUND", "{envelope}");
    assert_eq!(envelope["location"]["module"], "pom.xml", "{envelope}");
}

/// A BOM import only a repository the filter keeps out serves fails as in
/// Maven, and the error names the filter for that repository.
#[test]
fn an_import_the_filter_keeps_out_names_the_filter() {
    let envelope = filtered_out(
        &format!(
            "<project>{FX}<dependencyManagement><dependencies><dependency>\
             <groupId>org.ex.b</groupId><artifactId>bom</artifactId><version>1.0</version>\
             <type>pom</type><scope>import</scope></dependency></dependencies>\
             </dependencyManagement></project>"
        ),
        &[],
        &[],
    );
    assert_eq!(envelope["exit_code"], 5, "{envelope}");
}

/// A parent two modules share that only a repository the filter keeps out
/// serves fails as in Maven, and the error names the filter for that
/// repository, also for the module that finds the miss cached, and for a
/// parent declared by a range.
#[test]
fn a_parent_the_filter_keeps_out_names_the_filter() {
    for version in ["1.0", "[1.0]", "[1.0,2.0)"] {
        let child = |artifact: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent>\
                 <groupId>org.ex.b</groupId><artifactId>parent</artifactId>\
                 <version>{version}</version><relativePath/></parent>\
                 <artifactId>{artifact}</artifactId><version>1</version></project>"
            )
        };
        let envelope = filtered_out(
            &format!(
                "<project>{FX}<packaging>pom</packaging><modules><module>m1</module>\
                 <module>m2</module></modules></project>"
            ),
            &[("m1", &child("m1")), ("m2", &child("m2"))],
            &[],
        );
        assert_eq!(envelope["exit_code"], 5, "{version}: {envelope}");
        assert!(
            (envelope["error"].as_str().unwrap())
                .contains(&format!("Parent POM not found: org.ex.b:parent:{version}")),
            "{version}: {envelope}"
        );
    }
}

/// A parent or BOM that a POM served by an allowed repository names, which
/// only a repository the filter keeps out serves, fails as in Maven, and
/// the error names the filter for that repository.
#[test]
fn a_nested_parent_or_import_the_filter_keeps_out_names_the_filter() {
    let mid = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.ex.b</groupId>\
               <artifactId>parent</artifactId><version>1.0</version><relativePath/></parent>\
               <groupId>org.ex.c</groupId><artifactId>mid</artifactId><version>1.0</version>\
               <packaging>pom</packaging></project>";
    let outer = "<project><modelVersion>4.0.0</modelVersion><groupId>org.ex.c</groupId>\
                 <artifactId>outer</artifactId><version>1.0</version><packaging>pom</packaging>\
                 <dependencyManagement><dependencies><dependency><groupId>org.ex.b</groupId>\
                 <artifactId>bom</artifactId><version>1.0</version><type>pom</type>\
                 <scope>import</scope></dependency></dependencies></dependencyManagement>\
                 </project>";
    let parent = filtered_out(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.ex.c</groupId>\
         <artifactId>mid</artifactId><version>1.0</version><relativePath/></parent>\
         <artifactId>fx</artifactId></project>",
        &[],
        &[("org/ex/c/mid", mid)],
    );
    assert_eq!(parent["exit_code"], 5, "{parent}");
    let import = filtered_out(
        &format!(
            "<project>{FX}<dependencyManagement><dependencies><dependency>\
             <groupId>org.ex.c</groupId><artifactId>outer</artifactId><version>1.0</version>\
             <type>pom</type><scope>import</scope></dependency></dependencies>\
             </dependencyManagement></project>"
        ),
        &[],
        &[("org/ex/c/outer", outer)],
    );
    assert_eq!(import["exit_code"], 5, "{import}");
}

/// Modules `a` and `b` declare one server under the ids `full` and `poms`,
/// and the prefixes filter lets `poms` serve `x`'s POM, not its jar. `a`
/// resolves `x` first; `b` must not take `a`'s jar for the server's URL, as
/// its own filter keeps the jar from it and no other repository of `b`'s
/// has it: Maven fails `b` the same way.
#[test]
fn a_module_takes_no_file_its_filter_keeps_from_a_repository_of_that_url() {
    let base = TempDir::new().unwrap();
    let served = base.path().join("served");
    publish(&served, "org.ex", "x");
    let server = file_server(&served);
    let empty = file_server(&base.path().join("empty"));
    let project = base.path().join("project");
    let home = TempDir::new().unwrap();
    fs::create_dir_all(project.join(".mvn/rrf")).unwrap();
    fs::write(
        project.join(".mvn/maven.config"),
        "-Daether.remoteRepositoryFilter.prefixes=true\n\
         -Daether.remoteRepositoryFilter.prefixes.basedir=${session.rootDirectory}/.mvn/rrf/\n",
    )
    .unwrap();
    fs::write(
        project.join(".mvn/rrf/prefixes-poms.txt"),
        "## repository-prefixes/2.0\n/org/ex/x/1.0/x-1.0.pom\n",
    )
    .unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>none</id><mirrorOf>central</mirrorOf>\
             <url>{}</url></mirror></mirrors></settings>",
            url(&empty)
        ),
    )
    .unwrap();
    let module = |name: &str, id: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.ex</groupId>\
             <artifactId>root</artifactId><version>1</version></parent>\
             <artifactId>{name}</artifactId><repositories><repository><id>{id}</id>\
             <url>{}</url></repository></repositories><dependencies><dependency>\
             <groupId>org.ex</groupId><artifactId>x</artifactId><version>1.0</version>\
             </dependency></dependencies></project>",
            url(&server)
        )
    };
    for (path, text) in [
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.ex</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module><module>b</module></modules></project>"
                .to_string(),
        ),
        ("a/pom.xml", module("a", "full")),
        ("b/pom.xml", module("b", "poms")),
    ] {
        let path = project.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let output = run_raeva(&project, home.path(), &["sync"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("org.ex:x:1.0"), "{stderr}");
    assert!(stderr.contains("b/pom.xml"), "{stderr}");
}
