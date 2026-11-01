//! `raeva sync` on the projects in `test-fixtures/maven-parity`, compared with
//! the output Maven 3.9.11 recorded for them in each fixture's
//! `maven-3.9.11-*.txt` files.

use crate::common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use rv_test_support::fixtures;
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

const PLATFORMS: [&str; 3] = ["linux-x86_64", "macos-aarch64", "windows-x86_64"];

/// Groups a case below syncs, including nested groups such as
/// `pom-markup/project-pom`. A new top-level directory, or a sibling of a
/// nested group, must fail here until a test names it.
fn maven_parity_groups() -> Vec<String> {
    let source = include_str!("maven_parity.rs");
    let mut names: Vec<String> = [
        concat!("assert_cases_match_maven", "("),
        concat!("sync", "("),
        concat!("copy_case", "("),
    ]
    .into_iter()
    .flat_map(|prefix| fixtures::quoted_after(source, prefix))
    .filter(|name| !name.is_empty())
    .collect();
    names.sort();
    names.dedup();
    names
}

fn fixture(name: &str) -> PathBuf {
    fixtures::path("maven-parity").join(name)
}

/// Copy a case into `target` byte for byte, since some cases test line
/// endings, leaving Maven recordings and the HTTP `srv/` tree in the fixture.
fn copy_case(name: &str, target: &Path) {
    fixtures::copy_tree_skipping(&fixture(name), target, |entry| {
        let entry = entry.to_string_lossy();
        entry.starts_with("maven-3.9.11") || entry == SERVED || entry == ARGUMENTS
    });
}

/// The file listing, one per line, the options a case gave `mvn` and gives
/// `raeva`, which runs in the project directory as Maven did.
const ARGUMENTS: &str = "mvn-args.txt";

/// The file a case records its expected outcome in: Maven's output for a
/// platform, or [`RAEVA_DIFFERS`].
fn recording_path(fixture_name: &str, file: &str) -> PathBuf {
    if file == RAEVA_DIFFERS {
        fixture(fixture_name).join(format!("{RAEVA_DIFFERS}.txt"))
    } else {
        fixture(fixture_name).join(format!("maven-3.9.11-{file}.txt"))
    }
}

/// A case where raeva knowingly differs from Maven keeps Maven's recording and
/// states raeva's outcome, in the same keys, in `raeva-differs.txt`, whose
/// comments say why.
const RAEVA_DIFFERS: &str = "raeva-differs";

/// `key=value` lines of a recorded Maven output file, in file order.
fn recorded(fixture_name: &str, file: &str) -> Vec<(String, String)> {
    let path = recording_path(fixture_name, file);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let (key, value) = line.split_once('=').expect("key=value line");
            (key.to_string(), value.to_string())
        })
        .collect()
}

/// Whether a recorded Maven output lists the active profiles, so an empty
/// list means Maven activated none.
fn records_active_profiles(fixture_name: &str, file: &str) -> bool {
    let path = recording_path(fixture_name, file);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .lines()
        .any(|line| line.starts_with('#') && line.contains("help:active-profiles"))
}

fn recorded_values(fixture_name: &str, file: &str, key: &str) -> Vec<String> {
    recorded(fixture_name, file)
        .into_iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value)
        .collect()
}

struct Synced {
    project: TempDir,
    home: TempDir,
    output: Output,
    lock: Option<toml::Value>,
}

/// A fixture's directory of files served over HTTP, for repositories that
/// a fetched POM declares, which `raeva` uses only over HTTP or HTTPS. In the
/// served files and in the project's `pom.xml`, `raeva.toml` and
/// `settings.xml`, [`BASE`] stands for the server's address. Maven recorded
/// the case against a server that did the same.
const SERVED: &str = "srv";
const BASE: &str = "@BASE@";

fn serve(root: PathBuf) -> (StubServer, String) {
    let base = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
    let seen = std::sync::Arc::clone(&base);
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        if path.split('/').any(|part| part.is_empty() || part == "..") {
            return Response::new(404, "");
        }
        let (path, sidecar) = match path.strip_suffix(".sha1") {
            Some(file) if !root.join(path).is_file() => (file, true),
            _ => (path, false),
        };
        let Ok(bytes) = fs::read(root.join(path)) else {
            return Response::new(404, "");
        };
        // Replaced as bytes, since a served POM need not be UTF-8.
        let address = seen.get().expect("server address").as_bytes();
        let mut body = Vec::with_capacity(bytes.len());
        let mut rest = bytes.as_slice();
        while let Some(at) = rest
            .windows(BASE.len())
            .position(|window| window == BASE.as_bytes())
        {
            body.extend_from_slice(&rest[..at]);
            body.extend_from_slice(address);
            rest = &rest[at + BASE.len()..];
        }
        body.extend_from_slice(rest);
        if sidecar {
            Response::new(200, common::sha1_hex(&body))
        } else {
            Response::new(200, body)
        }
    });
    let address = format!("http://{}", server.addr());
    base.set(address.clone()).expect("address set once");
    (server, address)
}

/// `raeva sync --offline` on a copy of a fixture. A fixture with a `jdk`
/// directory runs with `JAVA_HOME` there, so its `release` file names the
/// JDK Maven recorded with, a fixture's `settings.xml` is the user's
/// `~/.m2/settings.xml`, which Maven read through `-s` or as that file, and
/// the options in [`ARGUMENTS`] come first.
///
/// A fixture with a [`SERVED`] directory syncs online against it instead,
/// with the transitive repositories its POMs declare allowed. [`BASE`] is
/// replaced in every XML file of the project directory too.
fn sync(fixture_name: &str, platforms: &[&str]) -> Synced {
    let (project, home) = common::temp_project();
    copy_case(fixture_name, project.path());
    let served = fixture(fixture_name).join(SERVED);
    let server = served.is_dir().then(|| serve(served));
    let mut command = common::raeva_command(project.path(), home.path());
    if let Ok(arguments) = fs::read_to_string(fixture(fixture_name).join(ARGUMENTS)) {
        command.current_dir(project.path()).args(arguments.lines());
    }
    if let Some((_, base)) = &server {
        let entries = fs::read_dir(project.path()).expect("read project directory");
        for entry in entries {
            let path = entry.expect("project entry").path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if !path.is_file() || !(name.ends_with(".xml") || name == "raeva.toml") {
                continue;
            }
            let text = fs::read_to_string(&path).expect("read served project file");
            fs::write(&path, text.replace(BASE, base)).expect("write served project file");
        }
        fs::write(
            home.path().join("config.toml"),
            "[security]\nallow_transitive_repositories = true\n",
        )
        .expect("write config.toml");
        command.env("RAEVA_RETRIES", "0").args(["sync"]);
    } else {
        command.args(["sync", "--offline"]);
    }
    command.args(["--platforms", &platforms.join(",")]);
    let settings = project.path().join("settings.xml");
    if settings.is_file() {
        let m2 = home.path().join(".m2");
        fs::create_dir_all(&m2).expect("create .m2");
        fs::copy(&settings, m2.join("settings.xml")).expect("copy settings.xml");
    }
    let jdk = project.path().join("jdk");
    if jdk.join("release").is_file() {
        command.env("JAVA_HOME", &jdk);
    }
    let output = command.output().expect("run raeva sync");
    let lock = fs::read_to_string(project.path().join("raeva.lock"))
        .ok()
        .map(|text| toml::from_str(&text).expect("raeva.lock parses"));
    Synced {
        project,
        home,
        output,
        lock,
    }
}

fn platform<'a>(lock: &'a toml::Value, name: &str) -> &'a toml::Value {
    lock["platforms"]
        .as_array()
        .expect("platforms")
        .iter()
        .find(|entry| {
            entry["targets"]
                .as_array()
                .is_some_and(|targets| targets.iter().any(|target| target.as_str() == Some(name)))
        })
        .unwrap_or_else(|| panic!("platform {name} in raeva.lock"))
}

fn model_profiles<'a>(lock: &'a toml::Value, name: &str) -> &'a toml::Value {
    &lock["inputs"]
        .as_array()
        .expect("inputs")
        .iter()
        .find(|entry| entry["target"].as_str() == Some(name))
        .expect("target inputs")["profiles"]
}

fn artifact_classifiers(lock: &toml::Value, name: &str) -> Vec<String> {
    platform(lock, name)["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .map(|artifact| {
            artifact["coordinate"]["classifier"]
                .as_str()
                .expect("classifier")
                .to_string()
        })
        .collect()
}

/// `group:artifact:version:repository` for each locked artifact, the
/// repository being the last segment of its `repo_url`.
fn artifact_sources(lock: &toml::Value, name: &str) -> Vec<String> {
    platform(lock, name)["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .map(|artifact| {
            let coordinate = &artifact["coordinate"];
            let repository = artifact["repo_url"]
                .as_str()
                .expect("repo_url")
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .expect("repository")
                .to_string();
            format!(
                "{}:{}:{}:{repository}",
                coordinate["group"].as_str().expect("group"),
                coordinate["artifact"].as_str().expect("artifact"),
                coordinate["version"].as_str().expect("version"),
            )
        })
        .collect()
}

fn system_dependencies(lock: &toml::Value, name: &str) -> Vec<String> {
    let mut found = std::collections::BTreeSet::new();
    for module in platform(lock, name)["modules"].as_array().expect("modules") {
        // Tab-separated columns; the sixth is the system path.
        let packages = module["packages"].as_str().expect("packages");
        for columns in packages
            .lines()
            .map(|line| line.split('\t').collect::<Vec<_>>())
        {
            if columns.get(5).is_some_and(|path| !path.is_empty()) {
                found.insert(columns[0].to_string());
            }
        }
    }
    found.into_iter().collect()
}

/// `group:artifact:version:scope` for each package `raeva --json tree`
/// shows, which is the scope the package resolves to.
fn package_scopes(synced: &Synced) -> Vec<String> {
    let output = common::raeva_command(synced.project.path(), synced.home.path())
        .args(["--json", "tree"])
        .output()
        .expect("run raeva tree");
    common::assert_success(&output, "raeva tree");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("tree JSON");
    let mut found = std::collections::BTreeSet::new();
    let mut nodes: Vec<&serde_json::Value> = Vec::new();
    for module in json["data"]["modules"].as_array().expect("modules") {
        nodes.extend(module["dependencies"].as_array().expect("dependencies"));
    }
    while let Some(node) = nodes.pop() {
        let coordinate = node["coordinate"].as_str().expect("coordinate");
        let gav: Vec<&str> = coordinate.splitn(4, ':').take(3).collect();
        let scope = node["scope"].as_str().expect("scope");
        found.insert(format!("{}:{scope}", gav.join(":")));
        nodes.extend(node["children"].as_array().expect("children"));
    }
    found.into_iter().collect()
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

/// Deleting or adding a group under `maven-parity/` must fail here, not
/// only in a named test someone remembered to write. A sibling of a nested
/// group such as `pom-markup/project-pom` must fail too.
#[test]
fn every_maven_parity_group_has_a_test() {
    let names = maven_parity_groups();
    let mut top = Vec::new();
    let mut nested: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in &names {
        match name.split_once('/') {
            Some((parent, child)) => {
                assert!(
                    !child.contains('/'),
                    "maven-parity group is at most two levels: {name}"
                );
                nested
                    .entry(parent.to_string())
                    .or_default()
                    .push(child.to_string());
                top.push(parent.to_string());
            }
            None => top.push(name.clone()),
        }
    }
    top.sort();
    top.dedup();
    let top_refs: Vec<&str> = top.iter().map(String::as_str).collect();
    fixtures::assert_children(&fixtures::path("maven-parity"), &top_refs, &[]);
    for (parent, mut children) in nested {
        children.sort();
        children.dedup();
        let children: Vec<&str> = children.iter().map(String::as_str).collect();
        let dir = fixture(&parent);
        let files: Vec<&str> = if dir.join(".gitattributes").is_file() {
            vec![".gitattributes"]
        } else {
            vec![]
        };
        fixtures::assert_children(&dir, &children, &files);
    }
}

/// Profile activation on `<os>` and on `os.*` `<property>` conditions, with
/// `-Dos.version=10.0` in `.mvn/maven.config`, matches Maven run on Linux,
/// macOS and Windows.
#[test]
fn os_activation_matches_maven_on_each_platform() {
    let synced = sync("os-activation", &PLATFORMS);
    common::assert_success(&synced.output, "os-activation sync");
    let lock = synced.lock.as_ref().expect("raeva.lock written");
    for name in PLATFORMS {
        assert_eq!(
            sorted(common::toml_strings(model_profiles(lock, name))),
            sorted(recorded_values("os-activation", name, "active")),
            "active profiles for {name}"
        );
    }
}

/// The `-D`, `-P` and `-s` options merge with `.mvn/maven.config` as Maven
/// 3.9.12 merges them: the command line's `-P` first and `-D` last, the
/// first `-s` read in place of `~/.m2/settings.xml`, and a deselection
/// winning in any order.
#[test]
fn command_line_options_match_maven() {
    assert_cases_match_maven("command-line");
}

/// Run `raeva sync` on every case under `group` and compare with the outcome
/// Maven recorded in the case's `maven-3.9.11-linux-x86_64.txt`:
/// `result=success` with the `module=` coordinates Maven built, and the
/// `active=` profiles, dependency `classifier=` values, `artifact=` sources
/// and package `scope=` values when recorded, and the `system=` dependencies,
/// or `result=failure` with the `error=` text raeva must print, Maven's
/// message where raeva words it the same, or the `parent=` or other
/// `missing=` POM Maven could not resolve, which raeva names by coordinates
/// or by repository path.
fn assert_cases_match_maven(group: &str) {
    let names = fixtures::sorted_child_names(&fixture(group), |_| true);
    assert!(!names.is_empty());
    for name in names {
        let case = format!("{group}/{name}");
        let recording = if recording_path(&case, RAEVA_DIFFERS).is_file() {
            RAEVA_DIFFERS
        } else {
            "linux-x86_64"
        };
        let values = |key| recorded_values(&case, recording, key);
        let synced = sync(&case, &["linux-x86_64"]);
        let stderr = String::from_utf8_lossy(&synced.output.stderr);
        match values("result").as_slice() {
            [outcome] if outcome == "failure" => {
                assert!(
                    !synced.output.status.success(),
                    "{name}: raeva sync succeeded"
                );
                for error in values("error") {
                    assert!(
                        stderr.contains(&error),
                        "{name}: expected {error}: {stderr}"
                    );
                }
                for parent in values("parent").into_iter().chain(values("missing")) {
                    let mut parts = parent.splitn(3, ':');
                    let (group, artifact, version) = (
                        parts.next().expect("group"),
                        parts.next().expect("artifact"),
                        parts.next().expect("version"),
                    );
                    let path = format!(
                        "{}/{artifact}/{version}/{artifact}-{version}.pom",
                        group.replace('.', "/")
                    );
                    assert!(
                        stderr.contains(&parent) || stderr.contains(&path),
                        "{name}: expected parent {parent}: {stderr}"
                    );
                }
            }
            [outcome] if outcome == "success" => {
                common::assert_success(&synced.output, &name);
                let lock = synced.lock.as_ref().expect("raeva.lock written");
                let modules: Vec<String> = platform(lock, "linux-x86_64")["modules"]
                    .as_array()
                    .expect("modules")
                    .iter()
                    .map(|module| module["gav"].as_str().expect("gav").to_string())
                    .collect();
                assert_eq!(
                    sorted(modules),
                    sorted(values("module")),
                    "{name}: module coordinates"
                );
                let packaging = values("packaging");
                if !packaging.is_empty() {
                    let modules: Vec<String> = platform(lock, "linux-x86_64")["modules"]
                        .as_array()
                        .expect("modules")
                        .iter()
                        .map(|module| {
                            format!(
                                "{}:{}",
                                module["gav"].as_str().expect("gav"),
                                module["packaging"].as_str().expect("packaging")
                            )
                        })
                        .collect();
                    assert_eq!(sorted(modules), sorted(packaging), "{name}: packaging");
                }
                let active = values("active");
                if !active.is_empty() || records_active_profiles(&case, recording) {
                    assert_eq!(
                        sorted(common::toml_strings(model_profiles(lock, "linux-x86_64"))),
                        sorted(active),
                        "{name}: active profiles"
                    );
                }
                let artifacts = values("artifact");
                if !artifacts.is_empty() {
                    assert_eq!(
                        sorted(artifact_sources(lock, "linux-x86_64")),
                        sorted(artifacts),
                        "{name}: artifacts"
                    );
                }
                assert_eq!(
                    system_dependencies(lock, "linux-x86_64"),
                    sorted(values("system")),
                    "{name}: system dependencies"
                );
                let scopes = values("scope");
                if !scopes.is_empty() {
                    assert_eq!(package_scopes(&synced), sorted(scopes), "{name}: scopes");
                }
                let classifiers = values("classifier");
                if !classifiers.is_empty() {
                    assert_eq!(
                        artifact_classifiers(lock, "linux-x86_64"),
                        classifiers,
                        "{name}: classifiers"
                    );
                }
            }
            other => panic!("{name}: unexpected recorded result {other:?}"),
        }
    }
}

/// The markup around a POM's root element, and the comments and processing
/// instructions in it, are refused or accepted as Maven's XML parser does,
/// for the project's own POM, which then fails the build, and for a
/// dependency's POM served over HTTP, which then loses its dependencies.
#[test]
fn project_pom_markup_is_read_as_maven_reads_it() {
    assert_cases_match_maven("pom-markup/project-pom");
}

#[test]
fn dependency_pom_markup_is_read_as_maven_reads_it() {
    assert_cases_match_maven("pom-markup/dependency-pom");
}

/// POM bytes are read as Maven's model reader reads them: the encoding a
/// byte order mark or the XML declaration names, UTF-8 with replacement
/// characters otherwise, the XHTML entities, and a DTD skipped without
/// defining its entities.
#[test]
fn poms_are_read_as_maven_reads_them() {
    assert_cases_match_maven("pom-reading");
}

/// `<jdk>` activation, a `java.version` property condition and
/// `${java.version}` in the model all read the JDK's `java.version`.
#[test]
fn java_version_has_one_source_as_in_maven() {
    assert_cases_match_maven("jdk");
}

/// A dependency's model is built without the project's active profile ids,
/// and with the user properties as system properties, below the
/// dependency's own properties. A transitive dependency with the project's
/// own group and artifact id is collected like any other.
#[test]
fn dependency_models_are_built_as_maven_builds_them() {
    assert_cases_match_maven("dependency-models");
}

/// An imported BOM's profiles activate by condition with the importer's
/// user and system properties, its `packaging` included, but not by the
/// importer's profile ids, and user properties win over the BOM's own.
#[test]
fn bom_imports_are_built_as_maven_builds_them() {
    assert_cases_match_maven("bom-imports");
}

/// Repositories without an id in a dependency's POM merge by their absent id
/// as Maven merges them, and an imported BOM's repositories serve only that
/// BOM's parents and nested imports.
#[test]
fn repositories_are_scoped_as_maven_scopes_them() {
    assert_cases_match_maven("repository-scoping");
}

/// The `<releases>` and `<snapshots>` policies of a repository a POM or
/// settings.xml declares: when `<enabled>` is read, before or after
/// interpolation, what it defaults to, and which `<checksumPolicy>` values
/// make Maven refuse the repository.
#[test]
fn repository_policies_are_read_as_maven_reads_them() {
    assert_cases_match_maven("repository-policies");
}

/// `<parent>` lookups: Maven 3.9 matches the coordinates as written against
/// the POM at `<relativePath>`, never expands them first, and does not take
/// a parent from another reactor module.
#[test]
fn parent_coordinates_resolve_as_maven_does() {
    assert_cases_match_maven("parent-coordinates");
}

/// A parent or imported BOM, of the project or of a dependency, that no
/// repository serves fails the build. One that a repository serves but that
/// does not parse fails a project, and costs a dependency only its
/// transitive dependencies, as does a dependency POM that does not parse.
/// A parent missing from the first repository comes from the next one.
#[test]
fn parent_and_bom_lookups_fail_as_maven_does() {
    assert_cases_match_maven("parent-and-bom-lookups");
}

/// Maven 3.9 rejects a project whose effective `groupId` or `artifactId`
/// uses characters outside its id pattern, or whose effective version still
/// holds `${`, and only warns about a `:` in the version.
#[test]
fn build_coordinates_are_validated_as_maven_does() {
    assert_cases_match_maven("build-coordinates");
}

/// Profile activation is interpolated per POM before inheritance, from that
/// POM's own properties, user properties and system properties, and sees the
/// input POM's packaging as the `packaging` user property, across the whole
/// parent chain.
#[test]
fn activation_interpolation_matches_maven() {
    let synced = sync("activation-interpolation", &["linux-x86_64"]);
    common::assert_success(&synced.output, "activation-interpolation sync");
    let lock = synced.lock.as_ref().expect("raeva.lock written");
    assert_eq!(
        sorted(common::toml_strings(model_profiles(lock, "linux-x86_64"))),
        sorted(recorded_values(
            "activation-interpolation",
            "linux-x86_64",
            "active"
        ))
    );
}

/// Unprefixed model fields such as `${version}` and `${parent.version}`
/// resolve after properties, so a `version` or `groupId` property wins.
#[test]
fn model_fields_interpolate_after_properties_as_in_maven() {
    assert_cases_match_maven("interpolation");
}

/// `${project.build.*}` reads the effective `<build>`, inherited, set by
/// an active profile or the super POM's, with a reactor module's
/// directories aligned to its directory, in a project and in a
/// dependency's POM.
#[test]
fn build_values_interpolate_as_in_maven() {
    assert_cases_match_maven("build-values");
}

/// `.mvn/maven.config` is read one argument per line, quotes joined and
/// stripped as Maven's `CleanArgument` does, `-D` values expanded against the
/// other `-D` values, and entries Maven rejects fail the sync.
#[test]
fn maven_config_is_read_as_maven_does() {
    assert_cases_match_maven("maven-config");
}

/// os-maven-plugin's `${os.detected.classifier}` in a dependency classifier
/// names each target platform, as the plugin does on that platform.
#[test]
fn os_detected_classifier_follows_each_platform() {
    let synced = sync("os-detected", &PLATFORMS);
    common::assert_success(&synced.output, "os-detected sync");
    let lock = synced.lock.as_ref().expect("raeva.lock written");
    for name in PLATFORMS {
        assert_eq!(
            artifact_classifiers(lock, name),
            recorded_values("os-detected", name, "classifier"),
            "classifier for {name}"
        );
    }
}

/// `-Dos.detected.classifier`, which os-maven-plugin leaves as it is, wins
/// over the classifier the plugin derives with
/// `os.detection.classifierWithLikes`, so the lock does not depend on the
/// Linux release.
#[test]
fn os_detected_classifier_override_wins_over_likes() {
    let (project, home) = common::temp_project();
    copy_case("os-detected", project.path());
    let pom = project.path().join("pom.xml");
    let text = fs::read_to_string(&pom).expect("read pom.xml");
    let text = text.replace(
        "<properties>",
        "<properties><os.detection.classifierWithLikes>fedora,arch\
         </os.detection.classifierWithLikes>",
    );
    fs::write(&pom, text).expect("write pom.xml");
    let jars = project.path().join("repository/org/test/native/1.0");
    fs::copy(
        jars.join("native-1.0-linux-x86_64.jar"),
        jars.join("native-1.0-linux-x86_64-fedora.jar"),
    )
    .expect("copy jar");
    fs::create_dir_all(project.path().join(".mvn")).expect("create .mvn");
    fs::write(
        project.path().join(".mvn/maven.config"),
        "-Dos.detected.classifier=linux-x86_64-fedora\n",
    )
    .expect("write maven.config");
    let output = common::raeva_command(project.path(), home.path())
        .args(["--json", "sync", "--offline", "--platforms", "linux-x86_64"])
        .output()
        .expect("run raeva sync");
    common::assert_success(&output, "os-detected classifier override");
    let text = fs::read_to_string(project.path().join("raeva.lock")).expect("raeva.lock");
    assert!(!text.contains("os-release"), "{text}");
    let lock: toml::Value = toml::from_str(&text).expect("raeva.lock parses");
    assert_eq!(
        artifact_classifiers(&lock, "linux-x86_64"),
        ["linux-x86_64-fedora"]
    );

    // A command-line `-D` comes after `.mvn/maven.config`, so it wins.
    fs::copy(
        jars.join("native-1.0-linux-x86_64.jar"),
        jars.join("native-1.0-linux-x86_64-cli.jar"),
    )
    .expect("copy jar");
    let output = common::raeva_command(project.path(), home.path())
        .args([
            "--json",
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64",
            "-Dos.detected.classifier=linux-x86_64-cli",
        ])
        .output()
        .expect("run raeva sync");
    common::assert_success(&output, "command-line classifier override");
    let lock: toml::Value =
        toml::from_str(&fs::read_to_string(project.path().join("raeva.lock")).expect("lock"))
            .expect("raeva.lock parses");
    assert_eq!(
        artifact_classifiers(&lock, "linux-x86_64"),
        ["linux-x86_64-cli"]
    );
}

/// os-maven-plugin reads `os.detection.classifierWithLikes` once, from the
/// project Maven sorts first, so a module's own list adds no classifier
/// suffix when another project is first. Maven recorded the bare classifier,
/// which is the same on any build machine.
#[test]
fn classifier_likes_come_from_the_first_sorted_project() {
    assert_cases_match_maven("classifier-likes");
}

/// Profile selection: the `activeByDefault` fallback, values trimmed when
/// the POM is read and not after interpolation, Java regular expressions in
/// `<os><version>`, file conditions interpolated only with the project
/// directory as `${basedir}`, and a POM's own properties before user
/// properties in its activation.
#[test]
fn profile_selection_matches_maven() {
    assert_cases_match_maven("profile-selection");
}

/// Profiles across a parent chain: each POM's active profiles are selected
/// on their own, with `activeByDefault` falling back per POM, and injected
/// into that POM before inheritance, so the child's own properties and
/// management override a parent profile's, a profile's imported BOM comes
/// after the POM's own management, and a profile's repositories are searched
/// first. A profile without `<id>` is `default`, and two in one project POM
/// are an error. A property an active profile sets reaches a reactor
/// module's packaging.
#[test]
fn profiles_are_injected_per_pom_as_maven_does() {
    assert_cases_match_maven("profile-lineage");
}

/// A package takes the scope of its direct declaration, else the widest of
/// its paths, a managed scope as it is, and its own dependencies derive
/// their scope from the one it took, as Maven's JavaScopeSelector and
/// JavaScopeDeriver do.
#[test]
fn package_scopes_are_selected_as_maven_selects_them() {
    assert_cases_match_maven("dependency-scopes");
}

/// A POM that declares one dependency twice keeps the last declaration in
/// the place of the first, with or without a parent, as Maven's model does.
#[test]
fn repeated_dependencies_keep_the_last_declaration_as_maven_does() {
    assert_cases_match_maven("repeated-dependencies");
}

/// Snapshot versions as maven-resolver decides them: a version ending in
/// `SNAPSHOT`, case-sensitively, or a timestamped version, whose base may be
/// empty, comes from a repository with snapshots enabled.
#[test]
fn snapshot_versions_follow_maven_resolver() {
    assert_cases_match_maven("snapshot-versions");
}
