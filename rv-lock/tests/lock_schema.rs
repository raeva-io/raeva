//! What raeva.lock may hold: the structural, digest, origin and text rules a
//! read and a write both enforce, and the messages that name what broke
//! them without echoing control characters or credentials.

use std::collections::BTreeMap;
use std::fs;

use rv_lock::{
    LockArtifact, LockModule, LockModulePackage, LockPlatform, Lockfile, Platform, Scope,
    SnapshotStamp, SupportPom,
};
use rv_maven_types::{ArtifactCoord, Digest, Gav};

const MODEL_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn every_field_lock() -> String {
    let digest = "a".repeat(64);
    format!(
        r#"
schema_version = 10
config_hash = "{MODEL_HASH}"

[resolution]
ambient_inputs = ["env.CI"]

[metadata]
repo_ids = "https://repo.example/maven2/	central"

[[inputs]]
target = "linux-x86_64"
profiles = ["ci"]
poms = [{{ path="pom.xml", sha256 = "{MODEL_HASH}" }}]

[[platforms]]
targets = ["linux-x86_64"]

[[platforms.artifacts]]
repo_url = "https://repo.example/maven2/"
pom_sha256 = "{digest}"
snapshot = {{ timestamp = "20240101.010101", build_number = 3 }}
[platforms.artifacts.coordinate]
group = "com.example"
artifact = "alpha"
version = "1.0-SNAPSHOT"
packaging = "jar"
classifier = "tests"
[[platforms.artifacts.checksums]]
algorithm = "sha256"
digest = "{digest}"

[[platforms.modules]]
path = "pom.xml"
gav = "com.example:root:1"
packaging = "pom"
packages = """
com.example:alpha:1.0-SNAPSHOT\tjar:tests\tcompile
com.sun:tools:1.8\tjar\tsystem\t\t\t\tlib/tools.jar\t{digest}"""
edges = "0 1 system"

[[platforms.support_poms]]
coordinate = "com.example:parent:1"
repo_url = "https://repo.example/parent/"
sha256 = "{digest}"
"#
    )
}

/// Edits of the base lock, one per line: `from => to, expected`.
macro_rules! edits {
    ($($from:expr => $to:expr, $expected:expr;)*) => {
        &[$(($from, $to, $expected)),*]
    };
}

fn read(raw: &str) -> Result<Lockfile, rv_lock::LockError> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raeva.lock");
    fs::write(&path, raw).expect("write lock");
    Lockfile::read(&path)
}

/// Each edit of the base lock is refused with a message naming the problem,
/// and no message carries a control character. A typo such as `classifer`
/// must not turn a row into the plain jar, and a key or value from a cloned
/// repository must not steer the terminal.
#[test]
fn every_rule_of_the_schema_is_enforced_on_read() {
    let base = every_field_lock();
    let lock = read(&base).expect("the base lock reads");
    assert_eq!(lock.platforms[0].modules[0].packages.len(), 2);
    // `{A}`, `{B}` and `{UPPER}` stand for digests, `{ESC}` for terminal
    // escapes. An empty expectation means the edit is valid.
    let cases: &[(&str, &str, &str)] = edits! {
        // Unknown and missing keys, in every table.
        "config_hash =" => "x = 1\nconfig_hash =", r#"field "x" in the top level"#;
        "ambient_inputs =" => "x = 1\nambient_inputs =", r#"field "x" in the [resolution] table"#;
        "repo_ids =" => "x = 1\nrepo_ids =", r#"field "x" in the [metadata] table"#;
        "profiles =" => "profile =", r#"field "profile" in target inputs"#;
        "targets =" => "x = 1\ntargets =", r#"field "x" in platform 'linux-x86_64'"#;
        "pom_sha256 =" => "x = 1\npom_sha256 =", r#"field "x" in artifact 'com.example:alpha"#;
        "classifier = " => "classifer = ", r#""classifer" in the coordinate table of artifact"#;
        "build_number = 3 }" => "build_number = 3, x = 1 }", r#""x" in the snapshot table"#;
        "algorithm =" => "x = 1\nalgorithm =", r#"field "x" in the checksum table"#;
        "path = " => "x = 1\npath = ", r#"field "x" in module 'pom.xml'"#;
        "path = \"pom.xml\"\n" => "path = \"pom.xml\"\n\"x{ESC}\" = 1\n", r"x\u{1b}[31m";
        "gav = \"com.example:root:1\"\n" => "", r#"missing field "gav" in module 'pom.xml'"#;
        "coordinate = \"com.example:parent:1\"" => "x = 1\ncoordinate = \"com.example:parent:1\"", r#"field "x" in support POM 'com.example:parent:1'"#;
        "parent/\"\n" => "parent/\"\nsnapshot = { timestamp = \"20240101.010101\" }\n", r#"missing field "build_number" in the snapshot table of support POM"#;
        // Schema versions.
        "schema_version = 10" => "schema_version = 5", "unsupported lockfile schema version 5";
        "schema_version = 10" => "schema_version = 99", "unsupported lockfile schema version 99";
        "schema_version = 10" => "schema_version = \"6\"", "must be a whole number";
        "schema_version = 10" => "", r#"missing field "schema_version""#;
        "schema_version = 10" => "schema_version = 9", "unsupported lockfile schema version 9";
        // The shared record of a target.
        "\n\n[resolution]" => "\nmaven = \"3.10\"\n\n[resolution]", "";
        "\n\n[resolution]" => "\nmaven = \"3.9\"\n\n[resolution]", r#"maven "3.9" must be "3.10" or left out"#;
        "\n\n[resolution]" => "\nmaven = \"4.0\"\n\n[resolution]", r#"must be "3.10" or left out"#;
        "profiles = [\"ci\"]\n" => "maven = \"3.10\"\nprofiles = [\"ci\"]\n", r#"unknown field "maven" in target inputs"#;
        // Digests and checksums.
        "digest = \"{A}\"" => "digest = \"aaaa\"", "expected 64 hex characters";
        "algorithm = \"sha256\"" => "algorithm = \"md5\"", "unsupported checksum algorithm 'md5'";
        "[[platforms.artifacts.checksums]]" => "{CHECKSUM}", "duplicate sha256";
        "pom_sha256 = \"{A}\"\nsnapshot = { timestamp = \"20240101.010101\", build_number = 3 }\n[platforms.artifacts.coordinate]\ngroup = \"com.example\"\nartifact = \"alpha\"\nversion = \"1.0-SNAPSHOT\"\npackaging = \"jar\"\nclassifier = \"tests\"\n[[platforms.artifacts.checksums]]\nalgorithm = \"sha256\"\ndigest = \"{A}\"\n" => "pom_sha256 = \"{A}\"\nchecksums = []\n[platforms.artifacts.coordinate]\ngroup = \"com.example\"\nartifact = \"alpha\"\nversion = \"1.0-SNAPSHOT\"\npackaging = \"jar\"\nclassifier = \"tests\"\n", "has no checksum";
        "pom_sha256 = \"{A}\"" => "pom_sha256 = \"nothex\"", "must be 64 hex characters";
        // A row without a companion POM is a dependency no repository has one for.
        "pom_sha256 = \"{A}\"\n" => "", "";
        "version = \"1.0-SNAPSHOT\"" => "version = \"1.0\"", "artifact 'com.example:alpha:1.0:jar:tests' on platform 'linux-x86_64' records a snapshot build, but its version is not a SNAPSHOT";
        // Other origins are sorted, distinct and leave out repo_url.
        "pom_sha256 = \"{A}\"\n" => "pom_sha256 = \"{A}\"\nother_repo_urls = [\"https://b.example/\", \"https://c.example/\"]\n", "";
        "pom_sha256 = \"{A}\"\n" => "pom_sha256 = \"{A}\"\nother_repo_urls = [\"https://c.example/\", \"https://b.example/\"]\n", "other_repo_urls for artifact";
        "pom_sha256 = \"{A}\"\n" => "pom_sha256 = \"{A}\"\nother_repo_urls = [\"https://b.example/\", \"https://b.example/\"]\n", "other_repo_urls for artifact";
        "pom_sha256 = \"{A}\"\n" => "pom_sha256 = \"{A}\"\nother_repo_urls = [\"https://repo.example/maven2/\"]\n", "other_repo_urls for artifact";

        "profiles = [\"ci\"]\n" => "", "target inputs need";
        "sha256 = \"{HASH}\"" => "sha256 = \"x\"", "POM input";
        // The names the graphs read, for every graph and for one module's.
        "profiles = [\"ci\"]\n" => "profiles = [\"ci\"]\nambient_inputs = [\"env.CI\"]\n", "";
        "profiles = [\"ci\"]\n" => "profiles = [\"ci\"]\nambient_inputs = [\"java.version\"]\n", "is not a property or variable name";
        "profiles = [\"ci\"]\n" => "profiles = [\"ci\"]\nambient_inputs = [\"env.CI\", \"env.CI\"]\n", "duplicate ambient input \"env.CI\" in the inputs of target 'linux-x86_64'";
        "\"{HASH}\" }]" => "\"{HASH}\", ambient_inputs = [\"user-property:v\"] }]", "";
        "profiles = [\"ci\"]\n" => "profiles = [\"ci\"]\nambient_inputs = []\n", "an empty ambient_inputs list in the inputs of target";
        "\"{HASH}\" }]" => "\"{HASH}\", ambient_inputs = [\"os-release\"] }]", "is not a property or variable name";
        "profiles = [\"ci\"]\npoms = [{ path=\"pom.xml\", sha256 = \"{HASH}\" }]" => "profiles = [\"ci\"]\nambient_inputs = [\"env.CI\"]\npoms = [{ path=\"pom.xml\", sha256 = \"{HASH}\", ambient_inputs = [\"env.CI\"] }]", "ambient input \"env.CI\" of the inputs of target 'linux-x86_64' is listed for the target and for a module";
        "\"{HASH}\" }]" => "\"{HASH}\" }, { path = \"parent/pom.xml\", sha256 = \"{HASH}\", ambient_inputs = [\"env.CI\"] }]", "POM input \"parent/pom.xml\" of the inputs of target 'linux-x86_64' lists ambient inputs but is no module";
        // A target lists only repository ids the lock lists.
        "profiles = [\"ci\"]\n" => "profiles = [\"ci\"]\nrepo_ids = \"https://repo.example/maven2/\tcentral\"\n", "";
        "profiles = [\"ci\"]\n" => "profiles = [\"ci\"]\nrepo_ids = \"https://repo.example/maven2/\tother\"\n", "the inputs of target 'linux-x86_64' list repository id \"other\"";
        // And only conditions and host values the lock lists; an empty
        // list is a target that consulted none.
        "[\"env.CI\"]\n\n[metadata]\nrepo_ids = \"https://repo.example/maven2/\tcentral\"\n\n[[inputs]]\ntarget = \"linux-x86_64\"\n" => "[\"env.CI\", \"java.version\"]\n\n[metadata]\nrepo_ids = \"https://repo.example/maven2/\tcentral\"\n\n[[inputs]]\ntarget = \"linux-x86_64\"\nhost_inputs = [\"java.version\"]\n", "";
        "profiles = [\"ci\"]\n" => "profiles = [\"ci\"]\nhost_inputs = [\"java.home\"]\n", "list host input \"java.home\"";
        "profiles = [\"ci\"]\n" => "profiles = [\"ci\"]\nhost_inputs = [\"env.CI\"]\n", "list host input \"env.CI\", which is a property";
        "profiles = [\"ci\"]\n" => "profiles = [\"ci\"]\nhost_inputs = []\n", "";
        // And every one the lock lists is one a target read.
        "profiles = [\"ci\"]\n" => "profiles = [\"ci\"]\nrepo_ids = \"\"\n", "metadata.repo_ids lists repository id \"central\"";
        "[\"env.CI\"]\n\n[metadata]\nrepo_ids = \"https://repo.example/maven2/\tcentral\"\n\n[[inputs]]\ntarget = \"linux-x86_64\"\n" => "[\"env.CI\", \"java.version\"]\n\n[metadata]\nrepo_ids = \"https://repo.example/maven2/\tcentral\"\n\n[[inputs]]\ntarget = \"linux-x86_64\"\nhost_inputs = []\n", "host input \"java.version\", which no target's inputs list";
        // Module and package rows.
        // A `<module>` entry may name its POM file under any name.
        "path = \"pom.xml\"" => "path = \"app/mypom.xml\"", "";
        // A sibling module, which `<module>../app</module>` declares.
        "path = \"pom.xml\"" => "path = \"../pom.xml\"", "";
        "path = \"pom.xml\"" => "path = \"../../app/pom.xml\"", "";
        "path = \"pom.xml\"" => "path = \"app/..\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"..\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"../\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"../..\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"./pom.xml\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"../app/../pom.xml\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"../app//pom.xml\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"/pom.xml\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"/../pom.xml\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"//server/share/pom.xml\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"..\\\\pom.xml\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"C:/pom.xml\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"../C:/pom.xml\"", "with any '..' parts first";
        "path = \"pom.xml\"" => "path = \"\"", "with any '..' parts first";
        "classifier = \"tests\"" => "classifier = \"\"", "must be omitted rather than empty";
        "gav = \"com.example:root:1\"" => "gav = \"com.example:root\"", "must be 'group:artifact:version'";
        "\"0 1 system\"" => "\"0 5 system\"", "edge (0 -> 5) is out of bounds for 2 packages";
        "\"0 1 system\"" => "\"0 1 a\\u00a0b\"", "which is not a scope";
        "\"0 1 system\"" => "\"0 1 a\\u200bb\"", "which is not a scope";
        // A scope Maven does not know is kept, `optional` among them.
        "\"0 1 system\"" => "\"0 1 merged\"", "";
        "\"0 1 system\"" => "\"0 1 foo:bar\"", "";
        "\"0 1 system\"" => "\"0 1 a/b optional\"", "";
        "\"0 1 system\"" => "\"0 1 optional\"", "";
        "\"0 1 system\"" => "\"0 1 optional optional\"", "";
        "\"0 1 system\"" => "\"0 1 system optional\"", "";
        "\"0 1 system\"" => "\"0 1 optional system\"", "is not 'from to scope [optional]'";
        "\"0 1 system\"" => "\"0 1\"", "is not 'from to scope [optional]'";
        "\"0 1 system\"" => "\"0 x\"", "is not 'from to scope [optional]'";
        "\"0 1 system\"\n" => "\"0 1 system\"\nsupport_poms = \"com.example:parent:1\"\n", "";
        "\"0 1 system\"\n" => "\"0 1 system\"\nsupport_poms = \"com.example:other:1\"\n", "support POM 'com.example:other:1' of module 'pom.xml' on platform 'linux-x86_64' has no support_poms row";
        "\"0 1 system\"\n" => "\"0 1 system\"\nsupport_poms = \"com.example:parent\"\n", "must be 'group:artifact:version'";
        "\"0 1 system\"\n" => "\"0 1 system\"\nsupport_poms = \"com.example:parent:1\"\nparents = \"com.example:parent:1\"\n", "";
        "\"0 1 system\"\n" => "\"0 1 system\"\nparents = \"com.example:parent:1\"\n", "parent 'com.example:parent:1' of module 'pom.xml' on platform 'linux-x86_64' is not one of its support POMs";
        // A list out of order is still the module's list.
        "\"0 1 system\"\n\n" => "\"0 1 system\"\nsupport_poms = \"com.example:parent:1\\ncom.example:c:1\\ncom.example:b:1\"\nparents = \"com.example:parent:1\"\n\n{MORE}", "";
        "\"0 1 system\"\n" => "\"0 1 system\"\nsupport_poms = \"com.example:parent:1\"\nparents = \"com.example:parent:1\\ncom.example:parent:1\"\n", "or is named twice";
        "jar:tests\\t" => "jar:\\t", "it must start with group:artifact:version";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT", "package line 1 of module 'pom.xml'";
        "{A}\"\"\"" => "{A}\\tx\"\"\"", "more than eight columns";
        // System rows stay inside the project and are pinned.
        "\\t\\tlib/" => "\\t\\t/opt/lib/", "the path is absolute";
        "\\t\\tlib/" => "\\t\\t../lib/", "'..' part";
        "\\t\\tlib/" => "\\t\\tC:/lib/", r"'\' or ':'";
        "tools.jar\\t{A}" => "tools.jar", "has a system_path but no system_sha256";
        "tools.jar\\t{A}" => "tools.jar\\t{UPPER}", "system SHA-256 must be 64 lowercase";
        "\\tsystem\\t\\t\\t\\tlib" => "\\tcompile\\t\\t\\t\\tlib", "but scope \"compile\"";
        // A system file a range picks over a compile declaration is system.
        "\\tsystem\\t\\t\\t\\tlib" => "\\tcompile\\tsystem\\t\\t\\tlib", "";
        "\\tsystem\\t\\t\\t\\tlib" => "\\tsystem\\tsystem\\t\\t\\tlib", "must be empty when it is the direct scope";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\t\\tcompile", "must be empty when it is the direct scope";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\t\\ttest", "";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\tcompile\\tmerged", "";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\tcompile\\ta b", "the scope in the package line 1";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\tfoo:bar\\tx/y", "";
        // `?` is the empty scope, only as the scope a package resolves to.
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\t\\t?", "";
        // The type column, set only when the type is not the extension.
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\tcompile\\t\\ttest-jar", "";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\tcompile\\t\\tjar", "its type column must be empty when the type is the extension";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\tcompile\\t\\ttest:jar", "";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\tcompile\\t\\tmy%20type", "";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\tcompile\\t\\tmy type", "its type must be written with each whitespace character";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\t?", "the direct scope in the package line 1";
        "\"0 1 system\"" => "\"0 1 ?\"", "which is not a scope";
        "\\t\\tlib/tools.jar\\t" => "\\t\\t\\t", "has a system_sha256 but no system_path";
        "\\tjar\\tsystem\\t\\t\\t\\tlib/tools.jar\\t{A}" => "\\tjar\\tsystem", "has no artifact-table row";
        // Resolution settings and snapshot builds.
        "ambient_inputs = [" => "strategy = \"nearest\"\nambient_inputs = [", r#"field "strategy" in the [resolution] table"#;
        "[\"env.CI\"]" => "[\"env.CI\", \"env.CI\"]", "duplicate ambient input \"env.CI\"";
        "[\"env.CI\"]" => "[\"jdk:1 is true\", \"jdk:1 is false\"]", "listed with both outcomes";
        "build_number = 3" => "build_number = 4294967296", "snapshot build_number 4294967296 for";
        "build_number = 3" => "build_number = -1", "must be between 0 and 4294967295";
        "timestamp = \"2024" => "timestamp = \"x2024", "must use YYYYMMDD.HHMMSS";
        // Metadata lines.
        "\tcentral\"" => "\"", "malformed repo_ids entry";
        "maven2/\tcentral\"" => "maven2/\tcentral\\n{REPO}\tcentral\"", "duplicate repo_ids";
        // Support POMs.
        "parent/\"\nsha256 = \"{A}\"" => "parent/\"\nsha256 = \"{UPPER}\"", "must be 64 lowercase hex characters";
        "\"com.example:parent:1\"" => "\"com.example:parent\"", "must be 'group:artifact:version'";
        "parent/\"\nsha256 = \"{A}\"\n" => "parent/\"\nsha256 = \"{A}\"\n{SUPPORT}", "duplicate support POM 'com.example:parent:1'";
        "\"https://repo.example/parent/\"" => "\"https://repo example/\"", "repo_url of support POM 'com.example:parent:1'";
        "parent/\"\n" => "parent/\"\n{BUILD}", "records a snapshot build, but its version is not a SNAPSHOT";
        // A support POM naming the row's POM file must pin the row's POM.
        "parent:1\"" => "alpha:1.0-20240101.010101-3\"", "";
        "parent:1\"" => "alpha:1.0-SNAPSHOT\"\n{BUILD}", "";
        "parent:1\"\nrepo_url = \"https://repo.example/parent/\"\nsha256 = \"{A}\"" => "alpha:1.0-SNAPSHOT\"\n{BUILD}repo_url = \"https://r/\"\nsha256 = \"{B}\"", "conflicting POM";
        "parent:1\"" => "alpha:1.0-SNAPSHOT\"", "";
        "parent:1\"\nrepo_url = \"https://repo.example/parent/\"\nsha256 = \"{A}\"" => "alpha:1.0-SNAPSHOT\"\nsnapshot = { timestamp = \"20240101.010101\", build_number = 4 }\nrepo_url = \"https://r/\"\nsha256 = \"{B}\"", "pin different bytes";
        "parent/\"\nsha256 = \"{A}\"\n" => "parent/\"\nsha256 = \"{A}\"\n{ALIAS}", "they name one file";
    };
    let fill = |text: &str| {
        let table = "[[platforms.artifacts.checksums]]";
        let checksum = format!("{table}\nalgorithm = \"sha-256\"\ndigest = \"{{A}}\"\n{table}");
        text.replace("{CHECKSUM}", &checksum)
            .replace(
                "{SUPPORT}",
                "[[platforms.support_poms]]\ncoordinate = \"com.example:parent:1\"\n\
                 repo_url = \"https://other.example/\"\nsha256 = \"{A}\"\n",
            )
            .replace(
                "{ALIAS}",
                "[[platforms.support_poms]]\ncoordinate = \"com.example:snap:1-SNAPSHOT\"\n\
                 repo_url = \"https://other.example/\"\nsha256 = \"{A}\"\n{BUILD}\
                 [[platforms.support_poms]]\ncoordinate = \"com.example:snap:1-20240101.010101-3\"\n\
                 repo_url = \"https://other.example/\"\nsha256 = \"{B}\"\n",
            )
            .replace(
                "{MORE}",
                "[[platforms.support_poms]]\ncoordinate = \"com.example:b:1\"\n\
                 repo_url = \"https://other.example/\"\nsha256 = \"{A}\"\n\n\
                 [[platforms.support_poms]]\ncoordinate = \"com.example:c:1\"\n\
                 repo_url = \"https://other.example/\"\nsha256 = \"{A}\"\n\n",
            )
            .replace(
                "{BUILD}",
                "snapshot = { timestamp = \"20240101.010101\", build_number = 3 }\n",
            )
            .replace("{REPO}", "https://repo.example/maven2/")
            .replace("{A}", &"a".repeat(64))
            .replace("{B}", &"b".repeat(64))
            .replace("{UPPER}", &"A".repeat(64))
            .replace("{HASH}", MODEL_HASH)
            .replace("{ESC}", r"\u001b[31mred\u001b]0;title\u0007")
    };
    for (from, to, expected) in cases {
        let (from, to) = (fill(from), fill(to));
        assert!(base.contains(&from), "the base lock has no {from:?}");
        let edited = base.replacen(&from, &to, 1);
        if expected.is_empty() {
            read(&edited).unwrap_or_else(|err| panic!("{to:?}: {err}"));
            continue;
        }
        let err = read(&edited).expect_err(&to);
        assert!(err.is_incompatible_lockfile(), "{to:?}: {err}");
        let message = err.to_string();
        assert!(
            message.contains(expected),
            "{to:?}: expected {expected:?} in {message}"
        );
        assert!(
            !message.chars().any(|c| c.is_control() && c != '\n'),
            "{message:?}"
        );
    }

    for raw in ["", " \n\t\n"] {
        let err = read(raw).expect_err("empty");
        assert!(err.to_string().contains("is empty"), "{err}");
    }

    // Digests are read in either case and any algorithm spelling, and kept
    // in canonical form.
    let spelled = base
        .replace(r#"algorithm = "sha256""#, r#"algorithm = " SHA-256 ""#)
        .replace(&fill("digest = \"{A}\""), &fill("digest = \"{UPPER}\""));
    let checksum = &read(&spelled).expect("spellings").platforms[0].artifacts[0].checksums[0];
    assert_eq!(checksum, &Digest::parse("sha256", &"a".repeat(64)).unwrap());
}

/// The published schema, which holds what [`Lockfile::read`] holds.
fn schema() -> jsonschema::Validator {
    let schema = include_str!("../../schemas/raeva-lock.json");
    jsonschema::validator_for(&serde_json::from_str(schema).expect("schema JSON"))
        .expect("compile schema")
}

/// Whether the schema takes the lock `raw`.
fn schema_takes(schema: &jsonschema::Validator, raw: &str) -> bool {
    let document: toml::Value = toml::from_str(raw).expect("TOML");
    schema.is_valid(&serde_json::to_value(document).expect("JSON"))
}

/// The schema takes a module path, a package's workspace module and a
/// system path exactly when [`Lockfile::read`] does: each case runs through
/// both, for the structure and for every character that may hide.
#[test]
fn the_schema_takes_the_paths_the_reader_takes() {
    let schema = schema();
    let base: toml::Value = toml::from_str(&every_field_lock()).expect("base lock");
    let digest = "a".repeat(64);
    // The reader takes a workspace module only where a module row has its
    // path, which the schema does not check; that row gets the path for the
    // reader, a valid one for the schema.
    let document = |module: &str, workspace: &str, system: &str, row: &str| {
        let mut document = base.clone();
        let modules = document["platforms"][0]["modules"].as_array_mut().unwrap();
        let mut module_row = modules[0].clone();
        module_row["path"] = row.into();
        module_row["gav"] = "org.example:module:1".into();
        module_row["packaging"] = "jar".into();
        module_row["packages"] = "".into();
        module_row["edges"] = "".into();
        modules.push(module_row);
        let row = &mut modules[0];
        row["path"] = module.into();
        row["packages"] = format!(
            "com.example:alpha:1.0-SNAPSHOT\tjar:tests\tcompile\n\
             com.sun:tools:1.8\tjar\tsystem\t\t\t\t{system}\t{digest}\n\
             org.example:module:1\tjar\tcompile\t\t\t{workspace}"
        )
        .into();
        toml::to_string(&document).expect("TOML")
    };
    let both = |module: &str, workspace: &str, system: &str| {
        let reader = read(&document(module, workspace, system, workspace));
        let valid = document(module, workspace, system, "app/pom.xml");
        (reader.is_ok(), schema_takes(&schema, &valid))
    };
    if let Err(err) = read(&document(
        "pom.xml",
        "app/pom.xml",
        "lib/tools.jar",
        "app/pom.xml",
    )) {
        panic!("{err}");
    }
    assert_eq!(
        both("pom.xml", "app/pom.xml", "lib/tools.jar"),
        (true, true)
    );
    let module_paths = [
        "pom.xml",
        "app/my pom.xml",
        "../pom.xml",
        "../../app/pom.xml",
        "..",
        "../",
        "",
        "/pom.xml",
        "app/../pom.xml",
        "../app/./pom.xml",
        "./pom.xml",
        "app//pom.xml",
        "app/",
        "C:/app/pom.xml",
        "app\\pom.xml",
        "app:x/pom.xml",
        "../app/..",
        ".../pom.xml",
    ];
    // The reader's limit is 4096 bytes, which the schema checks as
    // characters: the same for an ASCII path.
    let longest = format!("lib/{}", "x".repeat(4092));
    let too_long = format!("lib/{}", "x".repeat(4093));
    let system_paths = [
        "lib/x.jar",
        &longest,
        &too_long,
        "../lib/x.jar",
        "/x.jar",
        "lib//x.jar",
        "lib/./x.jar",
        "a:b",
        "a\\b",
        "lib/",
        ".",
    ];
    // Every character where the reader's or the schema's verdict on a POM
    // path changes, and the one before it; between two of them both stay
    // as they were.
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../../schemas/raeva-lock.json")).expect("schema");
    let pom_path = jsonschema::validator_for(&raw["$defs"]["pomPath"]).expect("pomPath");
    let verdicts = |c: char| {
        let path = format!("../app/{c}pom.xml");
        (
            rv_maven_types::is_terminal_safe(&path),
            pom_path.is_valid(&serde_json::Value::String(path)),
        )
    };
    let mut characters = vec!['a'];
    let mut last = verdicts('\0');
    for c in ('\0'..=char::MAX).skip(1) {
        let now = verdicts(c);
        if now != last {
            characters.extend(char::from_u32(c as u32 - 1));
            characters.push(c);
            last = now;
        }
    }
    let mut mismatches = Vec::new();
    let mut check = |what: String, module: &str, workspace: &str, system: &str| {
        let (reader, schema) = both(module, workspace, system);
        if reader != schema {
            mismatches.push(format!("{what}: reader {reader}, schema {schema}"));
        }
    };
    // The root module's path, which no other row may share, and an empty
    // workspace column, which names no module, are no cases of their own.
    let (root, module, system) = ("main/pom.xml", "app/pom.xml", "lib/tools.jar");
    for path in module_paths {
        check(format!("module {path:?}"), path, module, system);
        if !path.is_empty() {
            check(format!("workspace {path:?}"), root, path, system);
        }
    }
    for path in system_paths {
        check(format!("system {path:?}"), root, module, path);
    }
    for c in characters {
        let path = format!("../app/{c}pom.xml");
        check(format!("module {c:?}"), &path, module, system);
        check(format!("workspace {c:?}"), root, &path, system);
        check(
            format!("system {c:?}"),
            root,
            module,
            &format!("lib/{c}x.jar"),
        );
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn a_lock_left_with_merge_conflict_markers_names_the_first_marker() {
    let lock = every_field_lock();
    let (head, tail) = lock.split_at(lock.find("[metadata]").expect("metadata"));
    let line = head.lines().count() + 1;
    // Git writes longer markers under the `conflict-marker-size` attribute.
    for size in [7, 9] {
        let [open, split, close] = ['<', '=', '>'].map(|c| c.to_string().repeat(size));
        let conflicted = format!("{head}{open} HEAD\n{split}\n{close} topic\n{tail}");
        let message = read(&conflicted).expect_err("conflicted").to_string();
        assert!(
            message.ends_with(&format!(
                "it has a Git merge conflict marker at line {line}"
            )),
            "{size}: {message}"
        );
    }
}

#[test]
fn merge_conflicts_inside_package_and_edge_blocks_name_the_first_marker() {
    for (field, block) in [
        ("packages", "packages = \"\"\"\n"),
        ("edges", "edges = \"\"\"\n"),
    ] {
        let lock = every_field_lock()
            .replace("edges = \"0 1 system\"", "edges = \"\"\"\n0 1 system\"\"\"");
        for marker in ["<<<<<<< HEAD", "||||||| base", "=======", ">>>>>>> topic"] {
            let position = lock.find(block).expect(field) + block.len();
            let (head, tail) = lock.split_at(position);
            let conflicted = format!("{head}{marker}\n=======\n>>>>>>> topic\n{tail}");
            let line = head.lines().count() + 1;
            for ending in ["\n", "\r\n"] {
                let contents = conflicted.replace('\n', ending);
                assert!(toml::from_str::<toml::Table>(&contents).is_ok());
                let message = read(&contents).expect_err(field).to_string();
                assert!(
                    message.ends_with(&format!(
                        "it has a Git merge conflict marker at line {line}"
                    )),
                    "{field}, {marker:?}, {ending:?}: {message}"
                );
            }
        }
    }
}

/// A checkout with `core.autocrlf` turns every line ending into CRLF,
/// including those inside the multi-line `repo_ids` string. The lock reads
/// the same, and an unchanged lock is not rewritten.
#[test]
fn a_crlf_checkout_reads_the_same_lock() {
    let mut lock = lock_with_origin("https://repo.example/maven2/");
    lock.set_repo_ids(BTreeMap::from([
        (
            "https://repo.example/maven2/".into(),
            ["central".into()].into(),
        ),
        ("https://other.example/".into(), ["other".into()].into()),
    ]))
    .unwrap();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raeva.lock");
    lock.write_atomic(&path).expect("write");
    let lf = fs::read_to_string(&path).expect("read back");
    assert!(lf.contains("repo_ids = \"\"\"\n"), "{lf}");
    fs::write(&path, lf.replace('\n', "\r\n")).expect("crlf");
    assert_eq!(Lockfile::read(&path).expect("CRLF"), lock);
    lock.write_atomic(&path).expect("rewrite");
    let kept = fs::read_to_string(&path).unwrap();
    assert!(
        kept.contains("\r\n"),
        "an unchanged CRLF lock is left as it is"
    );
}

/// Every coordinate component, path, scope, origin, snapshot stamp, model
/// input and metadata value is checked on read, and the error never echoes
/// a control character. TOML basic strings may encode any control character,
/// so a cloned repository can put them in raeva.lock; refusing them here keeps
/// them out of `raeva tree`, `raeva why`, messages, `.mvn/checksums` lines and
/// local-repository paths.
#[test]
fn hostile_values_are_refused_without_echoing_control_characters() {
    let base = every_field_lock();
    let esc = r"\u001b[31mred\u001b]0;title\u0007";
    let cases: &[(&str, &str, &str)] = edits! {
        r#"group = "com.example""# => r#"group = "com.example{ESC}""#, "";
        r#"group = "com.example""# => r#"group = "com.example\u007f""#, "";
        r#"group = "com.example""# => r#"group = "com example""#, "";
        r#"artifact = "alpha""# => r#"artifact = "alpha{ESC}""#, "";
        r#"version = "1.0-SNAPSHOT""# => r#"version = "1.0-SNAPSHOT\naaaa  org/x/y-1.jar""#, "";
        r#"version = "1.0-SNAPSHOT""# => r#"version = "1.0\r-SNAPSHOT""#, "";
        r#"version = "1.0-SNAPSHOT""# => r#"version = "1.0:evil-SNAPSHOT""#, "";
        r#"version = "1.0-SNAPSHOT""# => r#"version = "../../x-SNAPSHOT""#, "";
        r#"version = "1.0-SNAPSHOT""# => r#"version = "1.0\u0085-SNAPSHOT""#, "";
        r#"packaging = "jar""# => r#"packaging = "jar/../x""#, "";
        r#"classifier = "tests""# => r#"classifier = "te\u0007sts""#, "";
        r#"classifier = "tests""# => r#"classifier = "te\u202Ests""#, "";
        r#"gav = "com.example:root:1""# => r#"gav = "com.example:root{ESC}:1""#, "";
        r#"path = "pom.xml""# => r#"path = "a{ESC}/pom.xml""#, "";
        r#"packaging = "pom""# => r#"packaging = "p\u001bom""#, "";
        r"\tcompile" => r"\tcompile{ESC}", "";
        r"lib/tools.jar" => r"lib/{ESC}tools.jar", "";
        r#"repo_url = "https://repo.example/maven2/""# => r#"repo_url = "https://r/{ESC}""#, "";
        r#"timestamp = "20240101.010101""# => r#"timestamp = "2024{ESC}""#, "";
        r#"profiles = ["ci"]"# => r#"profiles = ["ci{ESC}"]"#, "";
        r#"target = "linux-x86_64""# => r#"target = "linux{ESC}-x86_64""#, "";
        "\"com.example:parent:1\"" => "\"com.example:par{ESC}ent:1\"", "";
        "\"com.example:parent:1\"" => "\"com.example:parent:..\"", "";
        "\"https://repo.example/parent/\"" => "\"https://repo.example/par{ESC}ent/\"", "";
        "maven2/\tcentral\"" => "maven2/\tcen{ESC}tral\"", "";
        "config_hash = \"" => "config_hash = \"{ESC}", "";
        r#"["env.CI"]"# => r#"["env.A\u0007"]"#, "";
        r#"["env.CI"]"# => r#"["java.vm.vendor"]"#, "";
        r#"["env.CI"]"# => r#"["env.1"]"#, "";
        r#"["env.CI"]"# => r#"["jdk:[17,)"]"#, "";
        r#"["env.CI"]"# => r#"["property:os.name is true"]"#, "";
    };
    for (from, to, _) in cases {
        let to = to.replace("{ESC}", esc);
        assert!(base.contains(from), "the base lock has no {from:?}");
        let err = read(&base.replacen(from, &to, 1))
            .expect_err(&to)
            .to_string();
        assert!(
            !err.chars().any(|c| c.is_control() && c != '\n'),
            "{to}: {err:?}"
        );
    }
}

fn row(artifact: &str, digest: char) -> LockArtifact {
    let mut row = LockArtifact::new(
        ArtifactCoord::new("com.example", artifact, "1.0.0", "jar", None),
        "https://repo.example/maven2/",
    );
    row.checksums = vec![Digest::parse("sha256", &digest.to_string().repeat(64)).unwrap()];
    row.pom_sha256 = Some("c".repeat(64).parse().unwrap());
    row
}

fn lock_of(rows: Vec<LockArtifact>) -> Lockfile {
    let mut platform = LockPlatform::single_module(
        Platform::new("linux", "x86_64").unwrap(),
        Gav::new("com.example", "root", "1.0.0"),
        "pom",
        rows,
    );
    platform.model_hash = MODEL_HASH.to_string();
    let mut lock = Lockfile::new();
    lock.platforms.push(platform);
    lock
}

/// A symbolic link where other bytes are written is refused, whatever it
/// names, and left as it is with the file it names. The same bytes are
/// kept, as for a regular file.
#[cfg(unix)]
#[test]
fn a_symlinked_lock_is_not_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("shared.lock");
    let lock = lock_with_origin("https://repo.example/maven2/");
    lock.write_atomic(&target).expect("write the target");
    let before = fs::read(&target).unwrap();
    let link = dir.path().join("raeva.lock");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    lock.write_atomic(&link).expect("the same bytes");
    let dangling = dir.path().join("dangling.lock");
    std::os::unix::fs::symlink(dir.path().join("missing.lock"), &dangling).unwrap();
    for (link, written) in [
        (&link, lock_with_origin("https://other.example/")),
        (&dangling, lock.clone()),
    ] {
        let err = written.write_atomic(link).expect_err("a link").to_string();
        assert!(err.contains("it is a symbolic link"), "{err}");
    }
    for link in [&link, &dangling] {
        assert!(fs::symlink_metadata(link).unwrap().is_symlink());
    }
    assert_eq!(fs::read(&target).unwrap(), before);
    assert!(!dir.path().join("missing.lock").exists());
}

fn lock_with_origin(repo_url: &str) -> Lockfile {
    let mut external = row("alpha", 'a');
    external.repo_url = repo_url.to_string();
    lock_of(vec![external])
}

fn write(lock: &Lockfile) -> Result<(), rv_lock::LockError> {
    let dir = tempfile::tempdir().expect("tempdir");
    lock.write_atomic(&dir.path().join("raeva.lock"))
}

fn package(coordinate: &ArtifactCoord) -> LockModulePackage {
    LockModulePackage::new(coordinate.clone(), None)
}

/// Asserts that each edit of the base platform is refused on write with a
/// message holding the given text, one edit per line.
macro_rules! refused_on_write {
    ($($expected:literal: $edit:expr;)*) => {$(
        let mut lock = lock_with_origin("https://repo.example/maven2/");
        let edit: fn(&mut LockPlatform) = $edit;
        edit(&mut lock.platforms[0]);
        let err = write(&lock).expect_err($expected).to_string();
        assert!(err.contains($expected), "expected {:?} in {err}", $expected);
    )*};
}

/// A lockfile built in memory is checked by the same rules when it is
/// written, so `raeva sync` cannot write what a read would refuse.
#[test]
fn a_lock_that_breaks_a_rule_is_not_written() {
    refused_on_write! {
        "duplicate module path": |p| p.modules.push(p.modules[0].clone());
        "duplicate effective module GAV": |p| {
            let mut other = p.modules[0].clone();
            other.path = "app/pom.xml".into();
            other.packages.clear();
            p.modules.push(other);
        };
        "duplicate package": |p| {
            let packages = &mut p.modules[0].packages;
            packages.push(packages[0].clone());
        };
        "duplicate artifact": |p| p.artifacts.push(p.artifacts[0].clone());
        "orphan artifact row": |p| p.artifacts.push(row("beta", 'b'));
        "has no artifact-table row": |p| {
            p.modules[0].packages.push(package(&row("gamma", 'c').coordinate));
        };
        "does not resolve to a module row": |p| {
            let lib = ArtifactCoord::new("com.example", "lib", "1", "jar", None);
            let mut workspace = package(&lib);
            workspace.workspace_module = Some("lib/pom.xml".into());
            p.modules[0].packages.push(workspace);
        };
        "must not have an artifact-table row": |p| {
            let gav = Gav::new("com.example", "alpha", "1.0.0");
            let mut lib = LockModule::new("lib/pom.xml", gav, "jar");
            lib.packages.clear();
            p.modules.push(lib);
            p.modules[0].packages[0].workspace_module = Some("lib/pom.xml".into());
        };
        "cannot be both workspace and system scoped": |p| {
            let package = &mut p.modules[0].packages[0];
            package.workspace_module = Some("pom.xml".into());
            package.system_path = Some("lib/a.jar".into());
        };
        "out of bounds": |p| {
            let edge = rv_lock::LockEdge::new(0, 9, Scope::Compile, false);
            p.modules[0].edges.push(edge);
        };
        "has no modules": |p| p.modules.clear();
        "has no checksum": |p| p.artifacts[0].checksums.clear();
        "conflicting pom_sha256": |p| {
            let mut tests = row("alpha", 'a');
            tests.coordinate =
                ArtifactCoord::new("com.example", "alpha", "1.0.0", "jar", Some("tests"));
            tests.pom_sha256 = Some("d".repeat(64).parse().unwrap());
            p.modules[0].packages.push(package(&tests.coordinate));
            p.artifacts.push(tests);
        };
        "for packaging=pom those name the same file": |p| {
            let mut bom = row("bom", 'a');
            bom.coordinate = ArtifactCoord::new("com.example", "bom", "1", "pom", None);
            p.modules[0].packages.push(package(&bom.coordinate));
            p.artifacts.push(bom);
        };
        // The graph digests cover pom_sha256 only, so a pom-packaged row
        // pinned another way would let an edit choose its bytes.
        "pins payload sha1:": |p| {
            let mut bom = row("bom", 'c');
            bom.coordinate = ArtifactCoord::new("com.example", "bom", "1", "pom", None);
            bom.checksums = vec![Digest::parse("sha1", &"e".repeat(40)).unwrap()];
            p.modules[0].packages.push(package(&bom.coordinate));
            p.artifacts.push(bom);
        };
        "pom_sha256 none;": |p| {
            let mut bom = row("bom", 'c');
            bom.coordinate = ArtifactCoord::new("com.example", "bom", "1", "pom", None);
            bom.pom_sha256 = None;
            p.modules[0].packages.push(package(&bom.coordinate));
            p.artifacts.push(bom);
        };
        "pinned by one sha256": |p| {
            let mut bom = row("bom", 'c');
            bom.coordinate = ArtifactCoord::new("com.example", "bom", "1", "pom", None);
            bom.checksums.push(Digest::parse("sha1", &"e".repeat(40)).unwrap());
            p.modules[0].packages.push(package(&bom.coordinate));
            p.artifacts.push(bom);
        };
    }

    let mut lock = lock_with_origin("https://repo.example/maven2/");
    lock.platforms.push(lock.platforms[0].clone());
    assert!(
        write(&lock)
            .unwrap_err()
            .to_string()
            .contains("duplicate platform")
    );

    let mut lock = lock_with_origin("https://repo.example/maven2/");
    lock.platforms[0].support_poms.insert(
        "com.example:alpha:1.0.0".into(),
        SupportPom::new("https://repo.example/", "d".repeat(64).parse().unwrap()),
    );
    let err = write(&lock).unwrap_err().to_string();
    assert!(
        err.contains("conflicting POM digests for 'com.example:alpha:1.0.0'"),
        "{err}"
    );

    for (field, value) in [
        ("version", "1.0\n0000  org/x/y/1/y-1.jar"),
        ("classifier", "x/../y"),
        ("artifact", "a:b"),
    ] {
        let mut lock = lock_with_origin("https://repo.example/maven2/");
        let platform = &mut lock.platforms[0];
        for coordinate in [
            &mut platform.artifacts[0].coordinate,
            &mut platform.modules[0].packages[0].coordinate,
        ] {
            let version = if field == "version" { value } else { "1.0.0" };
            let artifact = if field == "artifact" { value } else { "alpha" };
            let classifier = (field == "classifier").then_some(value);
            *coordinate = ArtifactCoord::new("com.example", artifact, version, "jar", classifier);
        }
        write(&lock).expect_err(value);
    }

    let mut lock = lock_with_origin("https://repo.example/maven2/");
    lock.set_repo_ids(BTreeMap::from([(
        "https://x/".into(),
        ["a\tb".into()].into(),
    )]))
    .expect_err("a tab would split the line");
    lock.platforms[0].support_poms.insert(
        "com.example:parent".into(),
        SupportPom::new("https://repo.example/", "a".repeat(64).parse().unwrap()),
    );
    write(&lock).expect_err("not group:artifact:version");

    // Two platforms reading one parent read one file.
    let mut lock = lock_with_origin("https://repo.example/maven2/");
    let parent = SupportPom::new("https://repo.example/", "a".repeat(64).parse().unwrap());
    lock.platforms[0]
        .support_poms
        .insert("com.example:parent:1".into(), parent.clone());
    let mut darwin = lock.platforms[0].clone();
    darwin.platform = Platform::new("darwin", "aarch64").unwrap();
    darwin.support_poms.insert(
        "com.example:parent:1".into(),
        SupportPom::new("https://other.example/", "a".repeat(64).parse().unwrap()),
    );
    lock.platforms.push(darwin);
    write(&lock).expect("the same bytes from another repository");
    lock.platforms[1]
        .support_poms
        .get_mut("com.example:parent:1")
        .unwrap()
        .sha256 = "b".repeat(64).parse().unwrap();
    let err = write(&lock)
        .expect_err("two pins for one parent")
        .to_string();
    assert!(err.contains("conflicting pins for support POM"), "{err}");
}

/// Maven 3.9 only warns about a `:` in a project version, so a reactor
/// module may carry one, in its row and in a workspace package that names
/// it. Such a version still may not hold control characters.
#[test]
fn reactor_versions_follow_maven_and_stay_printable() {
    let lock_with_module_version = |version: &str| {
        let mut lock = lock_with_origin("https://repo.example/maven2/");
        let platform = &mut lock.platforms[0];
        platform.modules[0].gav = Gav::new("com.example", "app", version);
        let mut child = LockModule::new(
            "lib/pom.xml",
            Gav::new("com.example", "lib", version),
            "jar",
        );
        child.packages.clear();
        let mut package = LockModulePackage::new(
            ArtifactCoord::new("com.example", "lib", version, "jar", None),
            None,
        );
        package.workspace_module = Some("lib/pom.xml".to_string());
        platform.modules[0].packages.push(package);
        platform.modules.push(child);
        lock
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raeva.lock");
    lock_with_module_version("1.0:x")
        .write_atomic(&path)
        .expect("a ':' is written");
    Lockfile::read(&path).expect("and read");
    write(&lock_with_module_version("1.0\u{1b}[2J")).expect_err("a control character");
}

/// Maven keeps one file per local-repository path, so rows that name one
/// file, under one coordinate on two platforms or under two spellings,
/// must pin the same bytes and the same snapshot build.
#[test]
fn rows_naming_one_file_must_pin_the_same_bytes() {
    let spelled = |classifier: &str, packaging: &str, digest: char| {
        let mut row = row("alpha", digest);
        row.coordinate =
            ArtifactCoord::new("com.example", "alpha", "1.0.0", packaging, Some(classifier));
        row
    };
    let two_platforms = |linux: Vec<LockArtifact>, darwin: Vec<LockArtifact>| {
        let mut lock = lock_of(linux);
        if !darwin.is_empty() {
            let mut other = lock_of(darwin).platforms.remove(0);
            other.platform = Platform::new("darwin", "aarch64").unwrap();
            lock.platforms.push(other);
        }
        lock
    };
    let with_sha1 = |mut row: LockArtifact, digest: char| {
        let sha1 = Digest::parse("sha1", &digest.to_string().repeat(40)).unwrap();
        row.checksums.push(sha1);
        row
    };
    let refused = |linux, darwin| {
        let err = write(&two_platforms(linux, darwin)).expect_err("two pins for one file");
        assert!(err.to_string().contains("conflicting pins"), "{err}");
    };
    let snapshot = |version: &str, digest: char| {
        let mut row = row("alpha", digest);
        row.coordinate = ArtifactCoord::new("com.example", "alpha", version, "jar", Some("x"));
        row
    };
    let mut timestamped = snapshot("1.0-20240101.010101-7", 'a');
    let mut resolved = snapshot("1.0-SNAPSHOT", 'b');
    resolved.snapshot = SnapshotStamp::new("20240101.010101", 7);

    refused(vec![row("alpha", 'a')], vec![row("alpha", 'b')]);
    let tar_gz = || spelled("x", "tar.gz", 'b');
    refused(vec![spelled("x.tar", "gz", 'a'), tar_gz()], vec![]);
    refused(vec![spelled("x.tar", "gz", 'a')], vec![tar_gz()]);
    // Each agrees with the first, which has no SHA-1, but not with each other.
    let first = spelled("x", "a.b.c", 'a');
    let second = with_sha1(spelled("x.a", "b.c", 'a'), '1');
    refused(
        vec![first, second],
        vec![with_sha1(spelled("x.a.b", "c", 'a'), '2')],
    );
    refused(vec![timestamped.clone(), resolved.clone()], vec![]);

    timestamped.checksums = resolved.checksums.clone();
    let accepted = |linux, darwin| {
        write(&two_platforms(linux, darwin)).expect("one file, one pin");
    };
    let sha1_too = with_sha1(row("alpha", 'a'), '1');
    accepted(vec![row("alpha", 'a')], vec![sha1_too]);
    accepted(
        vec![spelled("x.tar", "gz", 'a'), spelled("x", "tar.gz", 'a')],
        vec![],
    );
    accepted(vec![timestamped], vec![resolved]);

    // A hand edit is refused on read too.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raeva.lock");
    two_platforms(vec![row("alpha", 'a')], vec![row("alpha", 'a')])
        .write_atomic(&path)
        .unwrap();
    let text = fs::read_to_string(&path).unwrap();
    let mut raw: toml::Value = toml::from_str(&text).unwrap();
    let graphs = raw["platforms"].as_array_mut().unwrap();
    let mut second = graphs[0].clone();
    graphs[0]["targets"] = toml::Value::Array(vec!["darwin-aarch64".into()]);
    second["targets"] = toml::Value::Array(vec!["linux-x86_64".into()]);
    second["artifacts"][0]["checksums"][0]["digest"] = "f".repeat(64).into();
    graphs.push(second);
    let tampered = toml::to_string(&raw).unwrap();
    let err = read(&tampered).expect_err("tampered pins");
    assert!(err.to_string().contains("conflicting pins"), "{err}");
}

fn file_url(path: &std::path::Path) -> String {
    url::Url::from_directory_path(path).unwrap().to_string()
}

/// A project-relative origin is read and written as its text names it, and
/// every spelling that could name another directory is refused. An origin
/// may be a URL with credentials, so no message repeats it, and a URL with
/// userinfo, a query or a fragment is never read or written.
#[test]
fn origins_are_validated_and_never_leak_a_credential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dunce::canonicalize(dir.path()).unwrap();
    let path = root.join("raeva.lock");
    lock_with_origin("./repository/")
        .write_atomic(&path)
        .expect("write token");
    let token_lock = fs::read_to_string(&path).unwrap();
    assert_eq!(
        Lockfile::read(&path).unwrap().platforms[0].artifacts[0].repo_url,
        "./repository/"
    );

    // validate_project_relative_origin's own tests cover every spelling.
    for bad in [
        "./../outside/",
        "./a\\b/",
        "../a/../outside/",
        ".https://user:s3cret@repo.example/",
    ] {
        let err = lock_with_origin(bad).write_atomic(&path).expect_err(bad);
        assert!(err.is_incompatible_lockfile(), "{bad}: {err}");
        let err = read(&token_lock.replace("./repository/", bad)).expect_err(bad);
        assert!(!err.to_string().contains("s3cret"), "{err}");
    }

    for secret in [
        "https://user:s3cret@repo.example/maven2/",
        "https://repo.example/maven2/?token=s3cret",
        "https://repo.example/maven2/#s3cret",
    ] {
        let err = write(&lock_with_origin(secret))
            .expect_err(secret)
            .to_string();
        assert!(
            err.contains("may hold a credential") && !err.contains("s3cret"),
            "{err}"
        );
        // A lock that reads is one raeva can write back.
        let err = read(&token_lock.replace("./repository/", secret))
            .expect_err(secret)
            .to_string();
        assert!(
            err.contains("may hold a credential") && !err.contains("s3cret"),
            "{err}"
        );
        let mut lock = lock_with_origin("https://repo.example/maven2/");
        lock.repo_ids.insert(secret.into(), ["corp".into()].into());
        let err = write(&lock).expect_err(secret).to_string();
        assert!(
            err.contains("an origin in repo_ids") && !err.contains("s3cret"),
            "{err}"
        );
    }
    let secret = ".https://user:s3cret@repo.example/";
    let err = lock_with_origin("./repository/")
        .set_repo_ids(BTreeMap::from([(secret.into(), ["leaky".into()].into())]))
        .expect_err("malformed repo_ids key");
    assert!(!err.to_string().contains("s3cret"), "{err}");

    // An absolute `file:` origin inside the project ties the lock to one
    // checkout path, so it is refused; relativizing records the token. One
    // outside the project is read as written, where it matches no
    // declaration, and relativizing records it from the directory both
    // share.
    let absolute = file_url(&root.join("repository"));
    let err = lock_with_origin(&absolute)
        .write_atomic(&path)
        .expect_err("absolute");
    assert!(err.to_string().contains("./repository/"), "{err}");
    fs::write(&path, token_lock.replace("./repository/", &absolute)).unwrap();
    assert!(Lockfile::read(&path).is_err());
    let mut lock = lock_with_origin(&absolute);
    lock.repo_ids
        .insert(absolute.clone(), ["local".into()].into());
    lock.relativize_origins(&rv_lock::LockOrigins::for_root(&root))
        .unwrap();
    assert_eq!(lock.platforms[0].artifacts[0].repo_url, "./repository/");
    assert_eq!(lock.repo_ids["./repository/"], ["local".into()].into());

    let outside = tempfile::tempdir().expect("outside");
    let outside_url = file_url(&dunce::canonicalize(outside.path()).unwrap());
    lock_with_origin(&outside_url)
        .write_atomic(&path)
        .expect("outside origin");
    assert_eq!(
        Lockfile::read(&path).unwrap().platforms[0].artifacts[0].repo_url,
        outside_url
    );
    let mut lock = lock_with_origin(&outside_url);
    lock.relativize_origins(&rv_lock::LockOrigins::for_root(&root))
        .unwrap();
    let name = outside.path().file_name().unwrap().to_str().unwrap();
    assert_eq!(
        lock.platforms[0].artifacts[0].repo_url,
        format!("../{name}/")
    );
}

/// Checkouts at different paths record the same `other_repo_urls`:
/// relativizing a project origin can move it in the sorted list or merge
/// two spellings of it, and the list is sorted and deduplicated again.
#[test]
fn other_origins_are_sorted_after_relativizing() {
    let base = tempfile::tempdir().expect("base");
    let base = dunce::canonicalize(base.path()).unwrap();
    let outside = file_url(&base.join("m/outside"));
    let mut recorded = Vec::new();
    for checkout in ["a/checkout", "z/checkout"] {
        let root = base.join(checkout);
        fs::create_dir_all(root.join("repo")).unwrap();
        let inside = file_url(&root.join("repo"));
        let mut lock = lock_with_origin("https://repo.example/maven2/");
        let mut others = vec![
            inside.clone(),
            outside.clone(),
            inside.replace("/repo/", "/./repo/"),
        ];
        others.sort();
        lock.platforms[0].artifacts[0].other_repo_urls = others;
        lock.relativize_origins(&rv_lock::LockOrigins::for_root(&root))
            .unwrap();
        let path = root.join("raeva.lock");
        lock.write_atomic(&path).unwrap();
        recorded.push(
            Lockfile::read(&path).unwrap().platforms[0].artifacts[0]
                .other_repo_urls
                .clone(),
        );
    }
    assert_eq!(recorded[0], recorded[1]);
    assert_eq!(recorded[0], ["../../m/outside/", "./repo/"]);
}

/// An unchanged lockfile is left as it is, its modification time too, so a
/// sync that changes nothing leaves no change for a build tool or git to see.
#[test]
fn an_unchanged_lockfile_is_left_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raeva.lock");
    let mut lock = lock_with_origin("https://repo.example/maven2/");
    lock.write_atomic(&path).unwrap();
    let marker = dir.path().join("raeva.lock.marker");
    fs::hard_link(&path, &marker).unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 86_400);
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(old)
        .unwrap();

    lock.write_atomic(&path).unwrap();
    assert_eq!(fs::read(&marker).unwrap(), fs::read(&path).unwrap());
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    assert!(modified < old + std::time::Duration::from_secs(60));
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let inode = |p: &std::path::Path| fs::metadata(p).unwrap().ino();
        assert_eq!(inode(&path), inode(&marker), "not rewritten");
        lock.config_hash = Some("changed".into());
        lock.write_atomic(&path).unwrap();
        assert_ne!(
            inode(&path),
            inode(&marker),
            "a changed lockfile is replaced"
        );
    }

    let mut darwin = lock.platforms[0].clone();
    darwin.platform = Platform::new("darwin", "aarch64").unwrap();
    lock.platforms.push(darwin.clone());
    lock.platforms[0].support_poms.insert(
        "com.example:parent:1".into(),
        SupportPom::new("https://repo.example/", "e".repeat(64).parse().unwrap()),
    );
    let selected = lock.select_platforms(&[darwin.platform.clone()]).unwrap();
    assert_eq!(selected.platforms, [darwin]);
    assert!(
        selected.support_poms().is_empty(),
        "linux's parent stays out"
    );
    let missing = Platform::new("windows", "x86_64").unwrap();
    assert_eq!(
        lock.select_platforms(std::slice::from_ref(&missing)),
        Err(missing)
    );
}

/// `--frozen` compares a system file with its recorded digest without
/// resolving, so a changed or deleted file is drift even offline.
#[test]
fn a_changed_or_missing_system_file_is_drift() {
    let project = tempfile::tempdir().expect("project");
    let lib = project.path().join("lib");
    fs::create_dir(&lib).unwrap();
    fs::write(lib.join("tools.jar"), b"tools").unwrap();
    let recorded = rv_lock::SystemFile::record(project.path(), &lib.join("tools.jar")).unwrap();
    assert_eq!(recorded.path, "lib/tools.jar");
    let lock = Lockfile::from_toml(&every_field_lock().replace(
        &format!("tools.jar\\t{}", "a".repeat(64)),
        &format!("tools.jar\\t{}", recorded.sha256),
    ))
    .unwrap();
    assert_eq!(lock.system_file_drift(project.path()), None);

    fs::write(lib.join("tools.jar"), b"other tools").unwrap();
    assert_eq!(
        lock.system_file_drift(project.path()).unwrap().to_string(),
        "the system-scoped file lib/tools.jar changed or cannot be read"
    );
    fs::remove_file(lib.join("tools.jar")).unwrap();
    assert!(
        lock.platforms[0]
            .system_file_drift(project.path())
            .is_some()
    );
}

#[test]
fn companion_snapshot_build_round_trips_and_is_strict() {
    let base = every_field_lock();
    let table = "pom_snapshot = { timestamp = \"20240101.010101\", build_number = 1 }\n";
    let raw = base.replace("snapshot =", &format!("{table}snapshot ="));
    let lock = read(&raw).unwrap();
    let row = &lock.platforms[0].artifacts[0];
    assert_eq!(row.file_version(), "1.0-20240101.010101-3");
    assert_eq!(row.pom_gav().version(), "1.0-20240101.010101-1");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raeva.lock");
    lock.write_atomic(&path).unwrap();
    assert_eq!(
        Lockfile::read(&path).unwrap().to_toml().unwrap(),
        lock.to_toml().unwrap()
    );
    for table in [
        "pom_snapshot = { timestamp = \"20240101.010101\", build_number = 3 }\n",
        "pom_snapshot = { timestamp = \"bad\", build_number = 1 }\n",
        "pom_snapshot = { timestamp = \"20240101.010101\", build_number = 1, extra = true }\n",
    ] {
        assert!(read(&base.replace("snapshot =", &format!("{table}snapshot ="))).is_err());
    }
    // The base `-SNAPSHOT.pom` of a timestamped file.
    let raw = base.replace("snapshot =", "pom_base = true\nsnapshot =");
    let based = read(&raw).unwrap();
    let row = &based.platforms[0].artifacts[0];
    assert_eq!(row.file_version(), "1.0-20240101.010101-3");
    assert_eq!(row.pom_gav().version(), "1.0-SNAPSHOT");
    assert_eq!(row.pom_build(), None);
    based.write_atomic(&path).unwrap();
    assert_eq!(
        fs::read_to_string(&path)
            .unwrap()
            .matches("pom_base = true")
            .count(),
        1
    );
    assert_eq!(
        Lockfile::read(&path).unwrap().to_toml().unwrap(),
        based.to_toml().unwrap()
    );
    for raw in [
        base.replace("snapshot =", "pom_base = false\nsnapshot ="),
        base.replace("snapshot =", &format!("pom_base = true\n{table}snapshot =")),
        base.replace(
            "snapshot = { timestamp = \"20240101.010101\", build_number = 3 }",
            "pom_base = true",
        ),
    ] {
        assert!(read(&raw).is_err(), "{raw}");
    }
    let mut different = lock.clone();
    let mut row = different.platforms[0].artifacts[0].clone();
    row.coordinate = row.coordinate.pom();
    row.snapshot = row.pom_snapshot.take();
    different.platforms[0].modules[0]
        .packages
        .push(LockModulePackage::new(row.coordinate.clone(), None));
    different.platforms[0].artifacts.push(row);
    different.write_atomic(&path).unwrap();
    different.platforms[0].artifacts[0].pom_snapshot = SnapshotStamp::new("20240101.010101", 2);
    assert!(
        different
            .write_atomic(&path)
            .unwrap_err()
            .to_string()
            .contains("companion POM builds")
    );
}

#[test]
fn missing_checksum_markers_round_trip_and_are_strict() {
    let base = every_field_lock();
    let marked = base
        .replace(
            "snapshot =",
            "missing_checksum = true\npom_missing_checksum = true\nsnapshot =",
        )
        .replace(
            "repo_url = \"https://repo.example/parent/\"",
            "repo_url = \"https://repo.example/parent/\"\nmissing_checksum = true",
        );
    let lock = read(&marked).unwrap();
    let row = &lock.platforms[0].artifacts[0];
    assert!(row.missing_checksum && row.pom_missing_checksum);
    assert!(
        lock.platforms[0]
            .support_poms
            .values()
            .all(|pin| pin.missing_checksum)
    );
    assert_eq!(lock.missing_checksum_files().len(), 3);
    let text = lock.to_toml().unwrap();
    assert_eq!(text.matches("\nmissing_checksum = true\n").count(), 2);
    assert_eq!(text.matches("\npom_missing_checksum = true\n").count(), 1);
    assert_eq!(read(&text).unwrap().to_toml().unwrap(), text);
    assert!(
        !read(&base)
            .unwrap()
            .to_toml()
            .unwrap()
            .contains("missing_checksum")
    );
    for (raw, expected) in [
        (
            base.replace("snapshot =", "missing_checksum = false\nsnapshot ="),
            "written only as true",
        ),
        (
            base.replace("snapshot =", "pom_missing_checksum = false\nsnapshot ="),
            "written only as true",
        ),
        (
            base.replace("snapshot =", "pom_missing_checksum = true\nsnapshot =")
                .replace(&format!("pom_sha256 = \"{}\"\n", "a".repeat(64)), ""),
            "needs pom_sha256",
        ),
        (
            base.replace(
                "repo_url = \"https://repo.example/parent/\"",
                "repo_url = \"https://repo.example/parent/\"\nmissing_checksum = false",
            ),
            "written only as true",
        ),
    ] {
        let err = read(&raw).unwrap_err().to_string();
        assert!(err.contains(expected), "{err}");
    }
}

#[test]
fn managed_sources_round_trip_and_are_strict() {
    let base = every_field_lock();
    let with = |managed: &str| {
        base.replace(
            "edges = \"0 1 system\"",
            &format!("edges = \"0 1 system\"\nmanaged = \"{managed}\""),
        )
    };
    let lock = read(&with(
        r"pom\tcom.example:root\t\t1\nimport\tcom.example:bom\tbom.version\t0",
    ))
    .unwrap();
    let packages = &lock.platforms[0].modules[0].packages;
    let source = packages[0].managed.as_deref().unwrap();
    assert_eq!(source.kind, rv_maven_types::ManagedKind::Import);
    assert_eq!(source.pom, "com.example:bom");
    assert_eq!(source.property.as_deref(), Some("bom.version"));
    assert_eq!(packages[1].managed.as_deref().unwrap().property, None);
    let text = lock.to_toml().unwrap();
    assert_eq!(
        read(&text).unwrap().platforms[0].modules,
        lock.platforms[0].modules
    );
    assert_eq!(read(&text).unwrap().to_toml().unwrap(), text);
    for (managed, expected) in [
        (
            r"bom\tcom.example:bom\t\t0",
            "kind must be pom, import or property",
        ),
        (r"import\tcom.example\t\t0", "must be 'group:artifact'"),
        (
            r"import\tcom.example:bom:1\t\t0",
            "must be 'group:artifact'",
        ),
        (r"import\tcom.example:bom\t$${x}\t0", "not a property name"),
        (
            r"property\tcom.example:parent\t\t0",
            "a property line names its property",
        ),
        (
            r"import\tcom.example:bom\t\t2",
            "ascending and name packages",
        ),
        (
            r"import\tcom.example:bom\t\t1 0",
            "ascending and name packages",
        ),
        (
            r"import\tcom.example:bom\t\t",
            "ascending and name packages",
        ),
        (
            r"import\tcom.example:bom\t\t0\nimport\tcom.example:bom\t\t1",
            "sorted",
        ),
        (
            r"import\tcom.example:bom\t\t0\npom\tcom.example:root\t\t1",
            "sorted",
        ),
        (
            r"import\tcom.example:a\t\t0\nimport\tcom.example:b\t\t0",
            "one source",
        ),
        (r"import\tcom.example:bom\t0", "expected kind"),
        (
            r"import\tcom.example:bom\t\t+0",
            "ascending and name packages",
        ),
        (
            r"import\tcom.example:bom\t\t01",
            "ascending and name packages",
        ),
    ] {
        let err = read(&with(managed)).unwrap_err().to_string();
        assert!(err.contains(expected), "{managed}: {err}");
    }
}

/// A module's optional packages read back as written, and a line that
/// does not name packages in ascending order is refused.
#[test]
fn optional_packages_round_trip_and_are_strict() {
    let base = every_field_lock();
    let with = |optional: &str| {
        base.replace(
            "edges = \"0 1 system\"",
            &format!("edges = \"0 1 system\"\noptional = \"{optional}\""),
        )
    };
    let lock = read(&with("1")).unwrap();
    let packages = &lock.platforms[0].modules[0].packages;
    assert_eq!(
        packages
            .iter()
            .map(|package| package.optional)
            .collect::<Vec<_>>(),
        [false, true]
    );
    let text = lock.to_toml().unwrap();
    assert!(text.contains("\noptional = \"1\"\n"), "{text}");
    assert_eq!(read(&text).unwrap().to_toml().unwrap(), text);
    assert!(!read(&base).unwrap().to_toml().unwrap().contains("optional"));
    for optional in ["", "2", "1 0", "0 0", "0  1", "+1", "01", " 0", "x"] {
        let err = read(&with(optional)).unwrap_err().to_string();
        assert!(err.contains("ascending"), "{optional:?}: {err}");
    }
}

/// A module's evicted ranges read back as written, sorted and checked in
/// the lock's Maven order, and a malformed line is refused.
#[test]
fn evicted_ranges_round_trip_and_are_strict() {
    let base = every_field_lock();
    let with = |evicted: &str| {
        base.replace(
            "edges = \"0 1 system\"",
            &format!("edges = \"0 1 system\"\nevicted_ranges = \"{evicted}\""),
        )
    };
    let lock = read(&with(
        r"com.example:a\t[1,3)\t./repo/\t1 1.0 2\ncom.example:a\t[1,3)\thttps://repo.example/m2/\t2\ncom.example:b\t[1.0,2),[3,)\thttps://repo.example/m2/\t3.1",
    ))
    .unwrap();
    let ranges = &lock.platforms[0].modules[0].evicted_ranges;
    assert_eq!(
        ranges,
        &[
            rv_lock::EvictedRange {
                group: "com.example".into(),
                artifact: "a".into(),
                range: "[1,3)".into(),
                origin: "./repo/".into(),
                versions: vec!["1".into(), "1.0".into(), "2".into()],
            },
            rv_lock::EvictedRange {
                group: "com.example".into(),
                artifact: "a".into(),
                range: "[1,3)".into(),
                origin: "https://repo.example/m2/".into(),
                versions: vec!["2".into()],
            },
            rv_lock::EvictedRange {
                group: "com.example".into(),
                artifact: "b".into(),
                range: "[1.0,2),[3,)".into(),
                origin: "https://repo.example/m2/".into(),
                versions: vec!["3.1".into()],
            },
        ]
    );
    let text = lock.to_toml().unwrap();
    assert_eq!(
        read(&text).unwrap().platforms[0].modules,
        lock.platforms[0].modules
    );
    assert_eq!(read(&text).unwrap().to_toml().unwrap(), text);
    // 3.9 orders `alpha` the same as `0`, so by their text; 3.10 below.
    let in_mode = |mode: &str| {
        let text = with(r"com.example:a\t(,1)\t./repo/\talpha 0")
            .replace("\n\n[resolution]", &format!("\n{mode}\n[resolution]"));
        read(&text).map(|_| ())
    };
    let err = in_mode("").unwrap_err().to_string();
    assert!(err.contains("sorted, each once"), "{err}");
    in_mode("maven = \"3.10\"").unwrap();
    // The empty origin names a mirrored repository the lock cannot record.
    let empty = read(&with(r"com.example:a\t[1,3)\t\t1")).unwrap();
    assert_eq!(empty.platforms[0].modules[0].evicted_ranges[0].origin, "");
    for (evicted, expected) in [
        (r"com.example:a\t[1,3)", "expected group:artifact"),
        (r"com.example:a\t[1,3)\t1", "expected group:artifact"),
        (
            r"com.example:a\t[1,3)\t./repo/ ./b/\t1",
            "contains whitespace",
        ),
        (
            r"com.example:a\t[1,3)\thttps://b.example/\t1\ncom.example:a\t[1,3)\thttps://a.example/\t1",
            "one per range and origin",
        ),
        (
            r"com.example:a\t[1,3)\t./repo/\t1\ncom.example:a\t[1,3)\t./repo/\t2",
            "one per range and origin",
        ),
        (
            r"com.example:a\t[1,3)\thttps://user:secret@b.example/\t1",
            "may hold a credential",
        ),
        (
            r"com.example:a\t[1,3)\t../a/../out/\t1",
            "project-relative origin",
        ),
        (r"com.example\t[1,3)\t./repo/\t1", "expected group:artifact"),
        (r"com.example:a:1\t[1,3)\t./repo/\t1", "not a coordinate"),
        (
            r"com.example:a\t1.0\t./repo/\t1.0",
            "not a range as raeva writes it",
        ),
        (
            r"com.example:a\t[1.0]\t./repo/\t1.0",
            "not a range as raeva writes it",
        ),
        (
            r"com.example:a\t[1, 3)\t./repo/\t1",
            "not a range as raeva writes it",
        ),
        (
            r"com.example:a\t[1,3)\t./repo/\t",
            "not one the range matches",
        ),
        (
            r"com.example:a\t[1,3)\t./repo/\t4",
            "not one the range matches",
        ),
        (
            r"com.example:a\t[1,3)\t./repo/\t1 x\u001b",
            "not one the range matches",
        ),
        (r"com.example:a\t[1,3)\t./repo/\t2 1", "sorted, each once"),
        (r"com.example:a\t[1,3)\t./repo/\t1 1", "sorted, each once"),
        (
            r"com.example:b\t[1,3)\t./repo/\t1\ncom.example:a\t[1,3)\t./repo/\t1",
            "one per range and origin",
        ),
    ] {
        let err = read(&with(evicted)).unwrap_err().to_string();
        assert!(err.contains(expected), "{evicted}: {err}");
        assert!(!err.contains('\u{1b}'), "{evicted}: {err}");
    }
}

#[test]
fn shared_graphs_require_one_input_record_per_target() {
    let base = every_field_lock();
    let extra = |target: &str| {
        format!("\n[[inputs]]\ntarget = \"{target}\"\nmodel_hash = \"{MODEL_HASH}\"\n")
    };
    for (text, message) in [
        (
            base.replace("targets = [\"linux-x86_64\"]", "targets = []"),
            "at least one target",
        ),
        (
            base.replace(
                "targets = [\"linux-x86_64\"]",
                "targets = [\"linux-x86_64\", \"linux-x86_64\"]",
            ),
            "missing or duplicate inputs",
        ),
        (
            base.replace("target = \"linux-x86_64\"", "target = \"windows-x86_64\""),
            "missing or duplicate inputs",
        ),
        (
            format!("{base}{}", extra("linux-x86_64")),
            "duplicate inputs",
        ),
        (
            format!("{base}{}", extra("windows-x86_64")),
            "no platform graph",
        ),
        (
            base.replace(
                "profiles =",
                &format!("model_hash = \"{MODEL_HASH}\"\nprofiles ="),
            ),
            "target inputs need",
        ),
        (
            base.replace(
                "poms = [",
                &format!("poms = [{{ path=\"pom.xml\", sha256 = \"{MODEL_HASH}\" }}, "),
            ),
            "duplicate POM input path",
        ),
    ] {
        let error = read(&text).expect_err(message).to_string();
        assert!(error.contains(message), "{error}");
    }
}

#[test]
fn parent_range_evidence_is_checked_and_controls_shared_graphs_and_drift() {
    let raw = every_field_lock().replace("edges = \"0 1 system\"", "edges = \"0 1 system\"\nparent_ranges = [{ model = \"com.example:root:1\", parent = \"com.example:parent:[1,3)\", selected = \"com.example:parent:1\" }]");
    let mut lock = read(&raw).unwrap();
    let selection = &lock.platforms[0].modules[0].parent_ranges[0];
    assert_eq!(selection.selected, "com.example:parent:1");
    for (from, to) in [
        ("parent:[1,3)", "parent:1"),
        (
            "selected = \"com.example:parent:1\"",
            "selected = \"com.example:parent:3\"",
        ),
        (
            "selected = \"com.example:parent:1\"",
            "selected = \"com.example:other:1\"",
        ),
        (
            "model = \"com.example:root:1\"",
            "model = \"com.example:root\"",
        ),
        ("selected =", "unexpected ="),
        ("parent:[1,3)", "parent:[1,\\n3)"),
    ] {
        assert!(read(&raw.replace(from, to)).is_err(), "accepted {to}");
    }
    // A remote parent is selected in the resolver's order: 3.10 orders `ga`
    // below `0`, 3.9 the same.
    let odd = raw.replace(
        "parent = \"com.example:parent:[1,3)\", selected = \"com.example:parent:1\"",
        "parent = \"com.example:parent:(,0)\", selected = \"com.example:parent:ga\"",
    );
    assert_ne!(odd, raw);
    assert!(read(&odd).is_err());
    read(&odd.replace("\n\n[resolution]", "\nmaven = \"3.10\"\n\n[resolution]")).unwrap();
    let mut duplicate = lock.clone();
    duplicate.platforms[0].modules[0]
        .parent_ranges
        .push(selection.clone());
    assert!(duplicate.to_toml().is_err());

    let mut other = lock.platforms[0].clone();
    other.platform = "darwin-aarch64".parse().unwrap();
    lock.platforms.push(other);
    let text = lock.to_toml().unwrap();
    let decoded: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(decoded["platforms"].as_array().unwrap().len(), 1);
    let mut changed = lock.clone();
    changed.platforms[1].modules[0].parent_ranges[0].selected = "com.example:parent:2".into();
    assert!(
        lock.resolution_drift(&changed, |_, _| true, |_, _, _| false)
            .is_some()
    );
    let text = changed.to_toml().unwrap();
    let decoded: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(decoded["platforms"].as_array().unwrap().len(), 2);
    assert_eq!(read(&text).unwrap().to_toml().unwrap(), text);
}

/// The schema takes a scope Maven does not know, in an edge and in either
/// scope column of a package, exactly when [`Lockfile::read`] does,
/// percent-encoded whitespace among them.
#[test]
fn the_schema_takes_the_scopes_the_reader_takes() {
    let schema = schema();
    let base: toml::Value = toml::from_str(&every_field_lock()).expect("base lock");
    let document = |edge: &str, direct: &str, resolved: &str| {
        let mut document = base.clone();
        let row = &mut document["platforms"][0]["modules"][0];
        row["edges"] = format!("0 1 {edge}").into();
        row["packages"] = format!(
            "com.example:alpha:1.0-SNAPSHOT\tjar:tests\t{direct}\t{resolved}\n\
             com.sun:tools:1.8\tjar\tsystem\t\t\t\tlib/tools.jar\t{}",
            "a".repeat(64)
        )
        .into();
        toml::to_string(&document).expect("TOML")
    };
    // The 255-character bound is on the scope as written, before encoding.
    let nbsp = format!("x%C2%A0{}", "y".repeat(253));
    let long = format!("{}%20", "x".repeat(254));
    let longer = format!("{}%20", "x".repeat(255));
    let percents = "%25".repeat(255);
    let more_percents = "%25".repeat(256);
    let scopes = [
        "foo:bar",
        "provided,%20test",
        "%20compile%20",
        "100%25",
        "a%C2%A0b",
        "a%E2%80%8Ab",
        "a%E3%80%80b",
        &nbsp,
        &long,
        &longer,
        &percents,
        &more_percents,
        "50%",
        "%2",
        "%63ompile",
        "a%2fb",
        "a%2Fb",
        "a%c2%a0b",
        "tab%09here",
        "a%C2%85b",
        "a%E2%80%8Bb",
        "a%E2%80%A8b",
        "%FF",
        "a b",
    ];
    for scope in scopes {
        for (edge, direct, resolved) in [
            (scope, "compile", "test"),
            ("system", scope, ""),
            ("system", "compile", scope),
        ] {
            let raw = document(edge, direct, resolved);
            assert_eq!(
                read(&raw).is_ok(),
                schema_takes(&schema, &raw),
                "{edge:?} {direct:?} {resolved:?}"
            );
        }
    }
    for scope in [
        "provided,%20test",
        "100%25",
        "a%C2%A0b",
        &nbsp,
        &long,
        &percents,
    ] {
        let raw = document(scope, "compile", "test");
        assert!(
            read(&raw).is_ok() && schema_takes(&schema, &raw),
            "{scope:?}"
        );
    }
}

/// The schema takes a package's type exactly when [`Lockfile::read`] does:
/// any text a scope Maven does not know may be, with each whitespace
/// character and `%` percent-encoded, as a build extension's handler may
/// name any type.
#[test]
fn the_schema_takes_the_types_the_reader_takes() {
    let schema = schema();
    let base: toml::Value = toml::from_str(&every_field_lock()).expect("base lock");
    let document = |type_: &str| {
        let mut document = base.clone();
        let row = &mut document["platforms"][0]["modules"][0];
        row["packages"] = format!(
            "com.example:alpha:1.0-SNAPSHOT\tjar:tests\tcompile\t\t{type_}\n\
             com.sun:tools:1.8\tjar\tsystem\t\t\t\tlib/tools.jar\t{}",
            "a".repeat(64)
        )
        .into();
        toml::to_string(&document).expect("TOML")
    };
    let long = "x".repeat(255);
    let longer = "x".repeat(256);
    let read_back = [
        ("my%20type", "my type"),
        ("a:b", "a:b"),
        ("é", "é"),
        ("50%25", "50%"),
        ("test-jar", "test-jar"),
        (&long, &long),
    ];
    for (written, type_) in read_back {
        let raw = document(written);
        let lock = read(&raw).expect(written);
        let package = &lock.platforms[0].modules[0].packages[0];
        assert_eq!(package.type_.as_deref(), Some(type_), "{written:?}");
        assert!(schema_takes(&schema, &raw), "{written:?}");
        let again: toml::Value = toml::from_str(&lock.to_toml().unwrap()).expect("TOML");
        let line = again["platforms"][0]["modules"][0]["packages"]
            .as_str()
            .map(str::lines);
        let first = line.and_then(|mut lines| lines.next()).unwrap_or_default();
        assert!(
            first.ends_with(&format!("\t{written}")),
            "{written:?}: {first:?}"
        );
    }
    for type_ in [
        "my type",
        "50%",
        "%6Dy",
        "tab%09here",
        "a%E2%80%8Bb",
        "?",
        &longer,
    ] {
        let raw = document(type_);
        assert!(read(&raw).is_err(), "{type_:?}");
        assert!(!schema_takes(&schema, &raw), "{type_:?}");
    }
    // The schema cannot compare columns: only the reader refuses a type
    // that is the extension.
    assert!(read(&document("jar")).is_err());
}

/// The schema takes the repository ids in `metadata.repo_ids` and a
/// target's `repo_ids` exactly when [`Lockfile::read`] does: no control or
/// invisible character, also above U+FFFF.
#[test]
fn the_schema_takes_the_repo_ids_the_reader_takes() {
    let schema = schema();
    let base: toml::Value = toml::from_str(&every_field_lock()).expect("base lock");
    for (id, taken) in [
        ("central", true),
        ("cen tral", true),
        ("central\u{e0100}", false),
        ("cen\u{200b}tral", false),
        ("cen\u{1b}tral", false),
    ] {
        let mut document = base.clone();
        document["metadata"]["repo_ids"] =
            format!("https://other.example/\t{id}\nhttps://repo.example/maven2/\tcentral").into();
        let raw = toml::to_string(&document).expect("TOML");
        assert_eq!(read(&raw).is_ok(), taken, "{id:?}");
        assert_eq!(schema_takes(&schema, &raw), taken, "{id:?}");
        if !taken {
            let mut document = base.clone();
            let lines =
                format!("https://repo.example/maven2/\tcentral\nhttps://other.example/\t{id}");
            let target = document["inputs"][0].as_table_mut().expect("target");
            target.insert("repo_ids".into(), lines.into());
            let raw = toml::to_string(&document).expect("TOML");
            assert!(read(&raw).is_err(), "{id:?}");
            assert!(!schema_takes(&schema, &raw), "target {id:?}");
        }
    }
}

/// The schema takes a plugin set's coordinate exactly when
/// [`Lockfile::read`] does: no control or invisible character, also above
/// U+FFFF.
#[test]
fn the_schema_takes_the_plugin_coordinates_the_reader_takes() {
    let schema = schema();
    let base: toml::Value = toml::from_str(&every_field_lock()).expect("base lock");
    for (coordinate, taken) in [
        ("g:p:1", true),
        ("g:p:1\u{e0100}", false),
        ("g:p\u{200b}:1", false),
        ("g:p\u{1b}:1", false),
    ] {
        let mut document = base.clone();
        let mut plugins: toml::Value = toml::from_str(&format!(
            "inputs = \"{MODEL_HASH}\"\n[[sets]]\nkey = \"sha256:{MODEL_HASH}\"\n\
             role = \"plugin\""
        ))
        .expect("plugins");
        let set = plugins["sets"][0].as_table_mut().expect("set");
        set.insert("coordinates".into(), vec![coordinate].into());
        let platform = document["platforms"][0].as_table_mut().expect("platform");
        platform.insert("plugins".into(), plugins);
        let raw = toml::to_string(&document).expect("TOML");
        assert_eq!(
            read(&raw).is_ok(),
            taken,
            "{coordinate:?}: {:?}",
            read(&raw).err()
        );
        assert_eq!(schema_takes(&schema, &raw), taken, "{coordinate:?}");
    }
}
