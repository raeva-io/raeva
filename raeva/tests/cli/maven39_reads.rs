//! Plugin locking in the Maven 3.9 mode, one case per reader and read kind
//! of docs/design/plugin-locking.md: Maven 3.9 keeps one reading of each
//! file for the build, and one POM per version in the local repository, so
//! what raeva cannot show to be the same for every reader is refused
//! (exit 5), and the rest locks.

use std::fs;
use std::path::Path;

use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{assert_status, assert_success, envelope, pom, run_raeva, write_with_sha256};

/// An empty zip: a jar with no descriptor in it.
const JAR: &[u8] = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// A project with the repositories `dep` and `plug` in its directory and a
/// Central that serves every plugin but the group `t`.
struct Shape {
    project: TempDir,
    home: TempDir,
    _central: StubServer,
}

impl Shape {
    /// With `toml` as raeva.toml.
    fn new(toml: &str) -> Self {
        let central = StubServer::start(|request| {
            let path = request.path.trim_start_matches('/');
            let (path, sidecar) = match path.strip_suffix(".sha256") {
                Some(path) => (path, true),
                None => (path, false),
            };
            let parts: Vec<&str> = path.split('/').collect();
            let [group @ .., artifact, version, file] = parts.as_slice() else {
                return Response::new(404, "");
            };
            let body = if path.starts_with("t/") {
                return Response::new(404, "");
            } else if *file == format!("{artifact}-{version}.pom") {
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                     <artifactId>{artifact}</artifactId><version>{version}</version>\
                     <packaging>maven-plugin</packaging></project>",
                    group.join(".")
                )
                .into_bytes()
            } else if *file == format!("{artifact}-{version}.jar") {
                JAR.to_vec()
            } else {
                return Response::new(404, "");
            };
            match sidecar {
                true => Response::new(200, crate::common::sha256_hex(&body)),
                false => Response::new(200, body),
            }
        });
        let shape = Self {
            project: TempDir::new().unwrap(),
            home: TempDir::new().unwrap(),
            _central: central,
        };
        let plugin_repository = format!(
            "<profiles><profile><id>core</id><pluginRepositories><pluginRepository>\
             <id>plug</id><url>{}</url></pluginRepository></pluginRepositories></profile>\
             </profiles><activeProfiles><activeProfile>core</activeProfile></activeProfiles>",
            shape.url("plug")
        );
        shape.write(
            &shape.home.path().join(".m2/settings.xml"),
            &format!(
                "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
                 <mirrorOf>central</mirrorOf></mirror></mirrors>{plugin_repository}</settings>",
                shape._central.addr()
            ),
        );
        shape.write(&shape.root().join("raeva.toml"), toml);
        shape.publish(
            "plug",
            "one-maven-plugin",
            "1",
            Some("<packaging>maven-plugin</packaging>"),
        );
        shape
    }

    fn root(&self) -> &Path {
        self.project.path()
    }

    fn url(&self, repo: &str) -> String {
        format!("file://{}/{repo}/", self.root().display())
    }

    fn write(&self, path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// `t:<artifact>:<version>`'s jar in `repo`, with a POM of `body`
    /// where there is one.
    fn publish(&self, repo: &str, artifact: &str, version: &str, body: Option<&str>) {
        self.publish_file(repo, artifact, version, None, body);
    }

    /// As [`Self::publish`], the jar with `classifier`.
    fn publish_file(
        &self,
        repo: &str,
        artifact: &str,
        version: &str,
        classifier: Option<&str>,
        body: Option<&str>,
    ) {
        let dir = self.root().join(format!("{repo}/t/{artifact}/{version}"));
        let classifier = classifier.map_or(String::new(), |c| format!("-{c}"));
        write_with_sha256(
            &dir.join(format!("{artifact}-{version}{classifier}.jar")),
            JAR,
        );
        if let Some(body) = body {
            let pom = format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
            );
            write_with_sha256(
                &dir.join(format!("{artifact}-{version}.pom")),
                pom.as_bytes(),
            );
        }
    }

    /// Repository metadata in `repo` listing `versions` of `t:<artifact>`.
    fn list(&self, repo: &str, artifact: &str, versions: &[&str]) {
        let listed: String = (versions.iter())
            .map(|version| format!("<version>{version}</version>"))
            .collect();
        let metadata = format!(
            "<metadata><groupId>t</groupId><artifactId>{artifact}</artifactId><versioning>\
             <versions>{listed}</versions></versioning></metadata>"
        );
        let path = self
            .root()
            .join(format!("{repo}/t/{artifact}/maven-metadata.xml"));
        write_with_sha256(&path, metadata.as_bytes());
    }

    /// The `<repositories>` and `<pluginRepositories>` of a module.
    fn repositories(&self) -> String {
        format!(
            "<repositories><repository><id>dep</id><url>{}</url></repository></repositories>\
             <pluginRepositories><pluginRepository><id>plug</id><url>{}</url>\
             </pluginRepository></pluginRepositories>",
            self.url("dep"),
            self.url("plug")
        )
    }

    /// `path` as the POM of `t:<artifact>:1`, with the repositories.
    fn module(&self, path: &str, artifact: &str, body: &str) {
        let text = pom(artifact, &format!("{}{body}", self.repositories()));
        self.write(&self.root().join(path), &text);
    }

    /// A reactor of `modules`, each a directory with its POM.
    fn reactor(&self, modules: &[&str]) {
        let listed: String = (modules.iter())
            .map(|module| format!("<module>{module}</module>"))
            .collect();
        let text = pom(
            "root",
            &format!("<packaging>pom</packaging><modules>{listed}</modules>"),
        );
        self.write(&self.root().join("pom.xml"), &text);
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        run_raeva(self.root(), self.home.path(), args)
    }

    /// A sync that is refused with exit 5, its message holding each of
    /// `holds`, and no lock written.
    fn refused(&self, case: &str, holds: &[&str]) {
        let output = self.run(&["--json", "sync"]);
        assert_status(&output, 5, case);
        let text = envelope(&output).to_string();
        for held in holds {
            assert!(text.contains(held), "{case}: {held} not in {text}");
        }
        assert!(!self.root().join("raeva.lock").exists(), "{case}");
    }

    /// A sync that locks, and a `--frozen` sync of that lock on another
    /// home that holds.
    fn answered(&self, case: &str) {
        assert_success(&self.run(&["sync"]), case);
        let other = TempDir::new().unwrap();
        fs::create_dir_all(other.path().join(".m2")).unwrap();
        let settings = fs::read(self.home.path().join(".m2/settings.xml")).unwrap();
        fs::write(other.path().join(".m2/settings.xml"), settings).unwrap();
        let frozen = run_raeva(self.root(), other.path(), &["sync", "--frozen"]);
        assert_success(&frozen, case);
    }
}

const LOCK: &str = "[plugins]\nlock = true\n";
const LOCK_310: &str = "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n";

/// `<dependency>` elements on `t:<artifact>:<version>`, each given as
/// `artifact:version`, or as a whole element.
fn dependencies(each: &[&str]) -> String {
    let each: String = (each.iter())
        .map(|dependency| match dependency.split_once(':') {
            Some((artifact, version)) if !dependency.starts_with('<') => format!(
                "<dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
                 <version>{version}</version></dependency>"
            ),
            _ => dependency.to_string(),
        })
        .collect();
    format!("<dependencies>{each}</dependencies>")
}

/// `t:shared:1` with `extra` inside the dependency.
fn shared(extra: &str) -> String {
    format!(
        "<dependency><groupId>t</groupId><artifactId>shared</artifactId><version>1</version>\
         {extra}</dependency>"
    )
}

/// The build extension `t:ext:1`.
const EXTENSION: &str = "<build><extensions><extension><groupId>t</groupId><artifactId>ext\
                         </artifactId><version>1</version></extension></extensions></build>";

/// `t:one-maven-plugin:1`, bound at `validate`, declaring `declared`.
fn plugin(declared: &str) -> String {
    format!(
        "<build><plugins><plugin><groupId>t</groupId><artifactId>one-maven-plugin</artifactId>\
         <version>1</version>{declared}<executions><execution><phase>validate</phase><goals>\
         <goal>run</goal></goals></execution></executions></plugin></plugins></build>"
    )
}

/// `t:lib:2` and `t:lib:1` in `dep`, which `t:shared:1`'s POMs below name.
fn libraries(shape: &Shape) {
    shape.publish("dep", "lib", "2", Some(""));
    shape.publish("dep", "lib", "1", Some(""));
    shape.publish("plug", "lib", "2", Some(""));
}

/// A build extension, a plugin, or a module reads `t:shared:1` without a
/// POM as a losing version, a range's candidate or a relocation's target,
/// where another reader reads it with one: Maven 3.9 hands the empty
/// reading to whichever reads it later. Each is refused, naming both
/// readers.
#[test]
fn a_read_without_a_pom_of_any_kind_is_refused() {
    let lib2 = dependencies(&["lib:2"]);
    // (case, how the realm reads shared, the modules' dependencies, the
    // realm's build, the set named beside the module)
    let cases: [(&str, &str, String, String, &str); 5] = [
        (
            "an extension's losing version",
            "losing",
            dependencies(&["shared:1"]),
            EXTENSION.to_string(),
            "build-extension t:ext:1",
        ),
        (
            "a plugin's losing version",
            "losing",
            dependencies(&["shared:1"]),
            plugin(&dependencies(&["shared:2", "b:1"])),
            "plugin t:one-maven-plugin:1",
        ),
        (
            "an extension's range candidate",
            "range",
            dependencies(&["shared:1"]),
            EXTENSION.to_string(),
            "build-extension t:ext:1",
        ),
        (
            "a module's losing version",
            "module losing",
            dependencies(&["shared:2", "b:1"]),
            plugin(&dependencies(&["shared:1"])),
            "plugin t:one-maven-plugin:1",
        ),
        (
            "a module's range candidate",
            "module range",
            dependencies(&["shared:[1,2]"]),
            plugin(&dependencies(&["shared:1"])),
            "plugin t:one-maven-plugin:1",
        ),
    ];
    for (case, read, modules, build, set) in cases {
        let shape = Shape::new(LOCK);
        libraries(&shape);
        let (with, without) = match read.starts_with("module") {
            true => ("plug", "dep"),
            false => ("dep", "plug"),
        };
        shape.publish(with, "shared", "1", Some(&lib2));
        shape.publish(without, "shared", "1", None);
        shape.publish(with, "shared", "2", Some(""));
        shape.publish(without, "shared", "2", Some(""));
        shape.publish(without, "b", "1", Some(&dependencies(&["shared:1"])));
        shape.list(without, "shared", &["1", "2"]);
        let ext = match read {
            "losing" => dependencies(&["shared:2", "b:1"]),
            _ => dependencies(&["shared:[1,2]"]),
        };
        shape.publish("plug", "ext", "1", Some(&ext));
        shape.module("pom.xml", "app", &format!("{modules}{build}"));
        let holds = [
            "t:shared:1:jar has a different POM, or none, for module pom.xml",
            set,
        ];
        shape.refused(case, &holds);
    }
}

/// A module reading a file without a POM is refused in the Maven 3.9 mode
/// with plugins locked even where no plugin reads it: whether a plugin
/// does is the build's to decide, not the lock's.
#[test]
fn a_module_read_without_a_pom_is_refused_alone() {
    let shape = Shape::new(LOCK);
    shape.publish("dep", "alone", "1", None);
    shape.module(
        "pom.xml",
        "app",
        &format!("{}{}", dependencies(&["alone:1"]), plugin("")),
    );
    shape.refused("alone", &["module pom.xml reads t:alone:1:jar"]);
    // Without plugin locking, or as Maven 3.10, it locks.
    fs::write(shape.root().join("raeva.toml"), LOCK_310).unwrap();
    shape.answered("3.10");
}

/// A case of [`two_files_of_one_version_read_two_ways_are_refused`]: the
/// modules' `shared`, `dep`'s POM of it, the plugin's `shared`, `plug`'s.
type Reads<'a> = (&'a str, &'a str, Option<&'a str>, &'a str, Option<&'a str>);

/// Two files of one version read two ways, the jar and its tests jar or
/// the jar and the POM as a `type=pom` dependency: Maven 3.9 gives the
/// later reader the POM the first put in the local repository, so any
/// difference is refused, before the plugin's read without a POM is.
#[test]
fn two_files_of_one_version_read_two_ways_are_refused() {
    let lib2 = dependencies(&["lib:2"]);
    let tests = shared("<classifier>tests</classifier>");
    let pom_type = shared("<type>pom</type>");
    // (case, the modules' shared, dep's POM, the plugin's shared, plug's POM)
    let cases: [Reads<'_>; 4] = [
        (
            "tests jar, other bytes",
            "shared:1",
            Some(&lib2),
            &tests,
            Some(""),
        ),
        (
            "tests jar, module without",
            "shared:1",
            None,
            &tests,
            Some(&lib2),
        ),
        (
            "type pom, plugin without",
            &pom_type,
            Some(&lib2),
            "shared:1",
            None,
        ),
        (
            "type pom, other bytes",
            &pom_type,
            Some(&lib2),
            "shared:1",
            Some(""),
        ),
    ];
    for (case, modules, in_dep, plugins, in_plug) in cases {
        let shape = Shape::new(LOCK);
        libraries(&shape);
        shape.publish("dep", "shared", "1", in_dep);
        shape.publish_file("plug", "shared", "1", Some("tests"), in_plug);
        shape.publish("plug", "shared", "1", in_plug);
        let body = format!(
            "{}{}",
            dependencies(&[modules]),
            plugin(&dependencies(&[plugins]))
        );
        shape.module("pom.xml", "app", &body);
        shape.refused(
            case,
            &[
                "t:shared:1",
                "has a different POM, or none, for module pom.xml",
                "plugin t:one-maven-plugin:1",
            ],
        );
    }
    // The same bytes in both repositories lock.
    let shape = Shape::new(LOCK);
    libraries(&shape);
    let body = format!("<packaging>pom</packaging>{lib2}");
    shape.publish("dep", "shared", "1", Some(&body));
    shape.publish("plug", "shared", "1", Some(&body));
    let modules = dependencies(&[pom_type.as_str()]);
    shape.module(
        "pom.xml",
        "app",
        &format!("{modules}{}", plugin(&dependencies(&["shared:1"]))),
    );
    shape.answered("type pom, same bytes");
}

/// As Maven 3.10 reads them, a `type=pom` dependency beside a plugin's
/// jar of the version with another POM or none: Maven builds it, but one
/// local repository holds one POM per version, which raeva.lock cannot
/// record for both. Refused (exit 5) by both readers, not as a damaged
/// lockfile. So is a module's jar read without a POM beside a plugin's
/// tests jar of the version read with one.
#[test]
fn one_pom_per_version_is_refused_as_maven_3_10_reads() {
    for (case, in_plug) in [("without", None), ("other bytes", Some(""))] {
        let shape = Shape::new(LOCK_310);
        libraries(&shape);
        let body = format!("<packaging>pom</packaging>{}", dependencies(&["lib:2"]));
        shape.publish("dep", "shared", "1", Some(&body));
        shape.publish("plug", "shared", "1", in_plug);
        let modules = dependencies(&[shared("<type>pom</type>").as_str()]);
        shape.module(
            "pom.xml",
            "app",
            &format!("{modules}{}", plugin(&dependencies(&["shared:1"]))),
        );
        shape.refused(
            case,
            &[
                "RESOLUTION",
                "module pom.xml",
                "plugin t:one-maven-plugin:1",
                "one POM per version",
            ],
        );
    }
    let shape = Shape::new(LOCK_310);
    libraries(&shape);
    shape.publish("dep", "shared", "1", None);
    shape.publish_file("plug", "shared", "1", Some("tests"), Some(""));
    let tests = shared("<classifier>tests</classifier>");
    let body = format!(
        "{}{}",
        dependencies(&["shared:1"]),
        plugin(&dependencies(&[tests.as_str()]))
    );
    shape.module("pom.xml", "app", &body);
    let holds = [
        "t:shared:1:jar",
        "module pom.xml",
        "plugin t:one-maven-plugin:1",
    ];
    shape.refused(
        "module without",
        &[&holds[..], &["one POM per version"]].concat(),
    );
}

/// A core extension reads `t:shared:1` with a POM of its own before the
/// modules read it with another: the core's session is its own, but the
/// local repository holds the first POM, which the modules then take.
/// Refused. One read without a POM leaves nothing there, and locks.
#[test]
fn a_core_extension_pom_the_modules_read_otherwise_is_refused() {
    for (case, in_plug) in [("other bytes", Some("")), ("without", None)] {
        let shape = Shape::new(LOCK);
        libraries(&shape);
        shape.publish("dep", "shared", "1", Some(&dependencies(&["lib:2"])));
        shape.publish("plug", "shared", "1", in_plug);
        shape.publish("plug", "ext", "1", Some(&dependencies(&["shared:1"])));
        shape.write(
            &shape.root().join(".mvn/extensions.xml"),
            "<extensions><extension><groupId>t</groupId><artifactId>ext</artifactId>\
             <version>1</version></extension></extensions>",
        );
        shape.module(
            "pom.xml",
            "app",
            &format!("{}{}", dependencies(&["shared:1"]), plugin("")),
        );
        match in_plug {
            Some(_) => shape.refused(
                case,
                &["has a different POM, or none", "core-extension t:ext:1"],
            ),
            None => shape.answered(case),
        }
    }
}

/// A build extension reads a reactor module's coordinate from a
/// repository: it resolves before the reactor, and the modules after it
/// take its reading over the module's pom.xml. Refused, with a POM or
/// without. A plugin that declares the module as its dependency reads it
/// from the reactor, which Maven builds first, and locks; one in an
/// earlier module that reaches it through a repository artifact is
/// refused, as Maven builds the module after the plugin runs.
#[test]
fn a_realm_reading_a_reactor_module_is_refused_unless_maven_orders_it() {
    let lib2 = dependencies(&["lib:2"]);
    // (case, plug's shared POM, m2's build, refused with)
    let cases: [(&str, Option<&str>, String, Option<&str>); 4] = [
        (
            "extension with a POM",
            Some(""),
            EXTENSION.to_string(),
            Some("for the reactor module m1/pom.xml"),
        ),
        (
            "extension without",
            None,
            EXTENSION.to_string(),
            Some("t:shared:1"),
        ),
        (
            "declared plugin dependency",
            None,
            plugin(&dependencies(&["shared:1"])),
            None,
        ),
        (
            "through a repository artifact",
            None,
            plugin(&dependencies(&["b:1"])),
            Some("reaches the reactor module t:shared:1:jar"),
        ),
    ];
    for (case, in_plug, build, refused) in cases {
        let shape = Shape::new(LOCK);
        libraries(&shape);
        shape.publish("plug", "shared", "1", in_plug);
        shape.publish("plug", "ext", "1", Some(&dependencies(&["shared:1"])));
        shape.publish("plug", "b", "1", Some(&dependencies(&["shared:1"])));
        shape.reactor(&["m1", "m2"]);
        if case == "through a repository artifact" {
            // The plugin runs in m1, before the reactor builds m2.
            shape.module("m1/pom.xml", "m1", &build);
            shape.module("m2/pom.xml", "shared", &lib2);
        } else {
            shape.module("m1/pom.xml", "shared", &lib2);
            shape.module(
                "m2/pom.xml",
                "m2",
                &format!("{}{build}", dependencies(&["shared:1"])),
            );
        }
        match refused {
            Some(held) => shape.refused(case, &["RESOLUTION", held]),
            None => shape.answered(case),
        }
    }
}

/// A plugin reads a file the modules read, with the same POM from another
/// repository: one descriptor, and it locks.
#[test]
fn a_file_read_with_the_same_pom_twice_locks() {
    let shape = Shape::new(LOCK);
    libraries(&shape);
    let lib2 = dependencies(&["lib:2"]);
    shape.publish("dep", "shared", "1", Some(&lib2));
    shape.publish("plug", "shared", "1", Some(&lib2));
    let body = format!(
        "{}{}",
        dependencies(&["shared:1"]),
        plugin(&dependencies(&["shared:1"]))
    );
    shape.module("pom.xml", "app", &body);
    shape.answered("same POM");
}

/// A module's range candidate or losing version that a plugin reads with
/// other bytes, both with a POM: Maven 3.9 hands the later reader the
/// first one's, so it is refused naming both.
#[test]
fn a_losing_read_with_other_bytes_is_refused() {
    let lib2 = dependencies(&["lib:2"]);
    for (case, modules) in [
        ("range candidate", dependencies(&["shared:[1,2]"])),
        ("losing version", dependencies(&["shared:2", "b:1"])),
    ] {
        let shape = Shape::new(LOCK);
        libraries(&shape);
        shape.publish("dep", "shared", "1", Some(&lib2));
        shape.publish("dep", "shared", "2", Some(""));
        shape.publish("dep", "b", "1", Some(&dependencies(&["shared:1"])));
        shape.list("dep", "shared", &["1", "2"]);
        shape.publish("plug", "shared", "1", Some(""));
        let body = format!("{modules}{}", plugin(&dependencies(&["shared:1"])));
        shape.module("pom.xml", "app", &body);
        shape.refused(
            case,
            &["t:shared:1", "module pom.xml", "t:one-maven-plugin:1"],
        );
    }
}

/// A module that takes its own coordinates' jar from a repository and a
/// build extension at those coordinates that reads other POM bytes from
/// its own repository are refused in the Maven 3.10 mode as well, naming
/// both: a local repository holds one POM per version.
#[test]
fn a_module_own_row_with_other_extension_bytes_is_refused() {
    let shape = Shape::new(LOCK_310);
    shape.publish("dep", "lib", "1", Some(""));
    shape.list("dep", "lib", &["1"]);
    shape.publish("plug", "lib", "1", Some("<packaging>jar</packaging>"));
    shape.reactor(&["lib", "app"]);
    shape.module("lib/pom.xml", "lib", &dependencies(&["lib:[1,1]"]));
    let extension = "<build><extensions><extension><groupId>t</groupId><artifactId>lib\
                     </artifactId><version>1</version></extension></extensions></build>";
    shape.module("app/pom.xml", "app", extension);
    shape.refused(
        "own row",
        &[
            "t:lib:1",
            "module lib/pom.xml",
            "build-extension t:lib:1",
            "one POM per version",
        ],
    );
}
