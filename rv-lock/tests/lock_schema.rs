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
schema_version = 8
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
com.sun:tools:1.8\tjar\tsystem\t\t\tlib/tools.jar\t{digest}"""
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
        "schema_version = 8" => "schema_version = 5", "unsupported lockfile schema version 5";
        "schema_version = 8" => "schema_version = 99", "unsupported lockfile schema version 99";
        "schema_version = 8" => "schema_version = \"6\"", "must be a whole number";
        "schema_version = 8" => "", r#"missing field "schema_version""#;
        // Digests and checksums.
        "digest = \"{A}\"" => "digest = \"aaaa\"", "expected 64 hex characters";
        "algorithm = \"sha256\"" => "algorithm = \"md5\"", "unsupported checksum algorithm 'md5'";
        "[[platforms.artifacts.checksums]]" => "{CHECKSUM}", "duplicate sha256";
        "pom_sha256 = \"{A}\"\nsnapshot = { timestamp = \"20240101.010101\", build_number = 3 }\n[platforms.artifacts.coordinate]\ngroup = \"com.example\"\nartifact = \"alpha\"\nversion = \"1.0-SNAPSHOT\"\npackaging = \"jar\"\nclassifier = \"tests\"\n[[platforms.artifacts.checksums]]\nalgorithm = \"sha256\"\ndigest = \"{A}\"\n" => "pom_sha256 = \"{A}\"\nchecksums = []\n[platforms.artifacts.coordinate]\ngroup = \"com.example\"\nartifact = \"alpha\"\nversion = \"1.0-SNAPSHOT\"\npackaging = \"jar\"\nclassifier = \"tests\"\n", "has no checksum";
        "pom_sha256 = \"{A}\"" => "pom_sha256 = \"nothex\"", "must be 64 hex characters";
        // A row without a companion POM is a dependency no repository has one for.
        "pom_sha256 = \"{A}\"\n" => "", "";
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
        "path = \"pom.xml\"" => "path = \"app/mypom.xml\"", "normalized root-relative pom.xml";
        "path = \"pom.xml\"" => "path = \"../pom.xml\"", "normalized root-relative pom.xml";
        "classifier = \"tests\"" => "classifier = \"\"", "must be omitted rather than empty";
        "gav = \"com.example:root:1\"" => "gav = \"com.example:root\"", "must be 'group:artifact:version'";
        "\"0 1 system\"" => "\"0 5 system\"", "edge (0 -> 5) is out of bounds for 2 packages";
        "\"0 1 system\"" => "\"0 1 merged\"", "expected one of compile, provided";
        "\"0 1 system\"" => "\"0 1 system optional\"", "";
        "\"0 1 system\"" => "\"0 1 optional system\"", "is not 'from to [scope] [optional]'";
        "\"0 1 system\"" => "\"0 x\"", "is not 'from to [scope] [optional]'";
        "\"0 1 system\"\n" => "\"0 1 system\"\nsupport_poms = \"com.example:parent:1\"\n", "";
        "\"0 1 system\"\n" => "\"0 1 system\"\nsupport_poms = \"com.example:other:1\"\n", "support POM 'com.example:other:1' of module 'pom.xml' on platform 'linux-x86_64' has no support_poms row";
        "\"0 1 system\"\n" => "\"0 1 system\"\nsupport_poms = \"com.example:parent\"\n", "must be 'group:artifact:version'";
        "jar:tests\\t" => "jar:\\t", "it must start with group:artifact:version";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT", "package line 1 of module 'pom.xml'";
        "{A}\"\"\"" => "{A}\\tx\"\"\"", "more than seven columns";
        // System rows stay inside the project and are pinned.
        "\\t\\tlib/" => "\\t\\t/opt/lib/", "the path is absolute";
        "\\t\\tlib/" => "\\t\\t../lib/", "'..' part";
        "\\t\\tlib/" => "\\t\\tC:/lib/", r"'\' or ':'";
        "tools.jar\\t{A}" => "tools.jar", "has a system_path but no system_sha256";
        "tools.jar\\t{A}" => "tools.jar\\t{UPPER}", "system SHA-256 must be 64 lowercase";
        "\\tsystem\\t\\t\\tlib" => "\\tcompile\\t\\t\\tlib", "but scope \"compile\"";
        // A system file a range picks over a compile declaration is system.
        "\\tsystem\\t\\t\\tlib" => "\\tcompile\\tsystem\\t\\tlib", "";
        "\\tsystem\\t\\t\\tlib" => "\\tsystem\\tsystem\\t\\tlib", "must be empty when it is the direct scope";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\t\\tcompile", "must be empty when it is the direct scope";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\t\\ttest", "";
        "SNAPSHOT\\tjar:tests\\tcompile" => "SNAPSHOT\\tjar:tests\\tcompile\\tmerged", "the scope in the package line 1";
        "\\t\\tlib/tools.jar\\t" => "\\t\\t\\t", "has a system_sha256 but no system_path";
        "\\tjar\\tsystem\\t\\t\\tlib/tools.jar\\t{A}" => "\\tjar\\tsystem", "has no artifact-table row";
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

#[test]
fn a_lock_left_with_merge_conflict_markers_names_the_first_marker() {
    let lock = every_field_lock();
    let (head, tail) = lock.split_at(lock.find("[metadata]").expect("metadata"));
    let conflicted = format!("{head}<<<<<<< HEAD\n=======\n>>>>>>> topic\n{tail}");
    let line = head.lines().count() + 1;
    let message = read(&conflicted).expect_err("conflicted").to_string();
    assert!(
        message.ends_with(&format!(
            "it has a Git merge conflict marker at line {line}"
        )),
        "{message}"
    );
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
        r#"["env.CI"]"# => r#"["java.vendor"]"#, "";
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
            let edge = rv_lock::LockEdge::new(0, 9, Some(Scope::Compile), false);
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
    let mut other_build = row("alpha", 'a');
    other_build.snapshot = SnapshotStamp::new("20240101.010101", 1);
    let snapshot = |version: &str, digest: char| {
        let mut row = row("alpha", digest);
        row.coordinate = ArtifactCoord::new("com.example", "alpha", version, "jar", Some("x"));
        row
    };
    let mut timestamped = snapshot("1.0-20240101.010101-7", 'a');
    let mut resolved = snapshot("1.0-SNAPSHOT", 'b');
    resolved.snapshot = SnapshotStamp::new("20240101.010101", 7);

    refused(vec![row("alpha", 'a')], vec![row("alpha", 'b')]);
    refused(vec![row("alpha", 'a')], vec![other_build]);
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
        "../outside/",
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
    // outside the project stays absolute.
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
    assert_eq!(recorded[0], ["./repo/".to_string(), outside]);
}

/// `raeva sync` reads the lockfile's modification time as when SNAPSHOTs were
/// last refreshed: an unchanged lockfile keeps its file but moves that time.
#[test]
fn an_unchanged_lockfile_is_kept_with_a_new_modification_time() {
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
    assert!(modified > old + std::time::Duration::from_secs(86_400));
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
    assert!(lock.resolution_drift(&changed, |_, _| true).is_some());
    let text = changed.to_toml().unwrap();
    let decoded: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(decoded["platforms"].as_array().unwrap().len(), 2);
    assert_eq!(read(&text).unwrap().to_toml().unwrap(), text);
}
