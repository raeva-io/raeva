use std::path::Path;
use std::process::{Command, Output};

use rv_test_support::fixtures;
use rv_test_support::http::{Response, StubServer};
use sha1::Sha1;
use sha2::Sha256;
use tempfile::TempDir;

/// Variables `raeva` reads that would make a test depend on the developer's
/// shell. [`raeva_command`] removes them; a test that needs one sets it on the
/// returned command.
pub(crate) const HOST_ENV: &[&str] = &[
    "RAEVA_TIMEOUT",
    "RAEVA_RETRIES",
    "RAEVA_LOW_SPEED_LIMIT",
    "RAEVA_LOW_SPEED_TIME",
    "RAEVA_MAX_ARTIFACT_SIZE",
    "RAEVA_WORKSPACE_STALL_TIMEOUT_SECS",
    "RAEVA_EXPORT_M2_MAX_SUPPORT_POMS",
    "RAEVA_OSV_BASE_URL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "JAVA_HOME",
    "JAVA_VERSION",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "NO_COLOR",
    "RUST_LOG",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
    // clap_complete prints a script and exits when this is set.
    "COMPLETE",
];

/// clap colours `--help` when these are set; raeva itself only reads
/// `NO_COLOR`. [`raeva_command`] strips them so a developer's shell cannot
/// paint ANSI into help text the tests parse.
const CLAP_COLOR_ENV: &[&str] = &["CLICOLOR", "CLICOLOR_FORCE", "FORCE_COLOR"];

pub(crate) fn temp_project() -> (TempDir, TempDir) {
    let project = TempDir::new().expect("temp project dir");
    let home = TempDir::new().expect("temp raeva home");
    (project, home)
}

/// `raeva` for the project at `project_root`, with `home` in place of every
/// user-level input: the Raeva home, the user `config.toml`, Maven settings
/// (also on Windows, where the home directory ignores `HOME` and
/// `USERPROFILE`), and none of [`HOST_ENV`], [`CLAP_COLOR_ENV`] or the
/// os-release a test sets.
pub(crate) fn raeva_command(project_root: &Path, home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_raeva"));
    cmd.env("RAEVA_HOME", home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env(rv_config::MAVEN_USER_HOME_TEST_ENV, home)
        .env_remove(rv_maven_model::OS_RELEASE_TEST_ENV)
        .arg("-C")
        .arg(project_root);
    for name in HOST_ENV.iter().chain(CLAP_COLOR_ENV) {
        cmd.env_remove(name);
    }
    cmd
}

pub(crate) fn run_raeva(project_root: &Path, home: &Path, args: &[&str]) -> Output {
    raeva_command(project_root, home)
        .args(args)
        .output()
        .expect("run raeva")
}

pub(crate) fn write_empty_pom(path: &Path) {
    std::fs::write(
        path,
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
         <artifactId>demo</artifactId><version>1.0.0</version></project>\n",
    )
    .expect("write pom.xml");
}

/// A raeva.toml whose one repository is `url`. Configured repositories add
/// to Maven Central, so an entry with Central's id points it at `url` too,
/// and no test reaches the real Central.
pub(crate) fn write_repo_toml(project: &Path, id: &str, url: &str) {
    let mut toml = format!("[[repositories]]\nid = \"{id}\"\nurl = \"{url}\"\n");
    if id != "central" {
        toml.push_str(&format!(
            "\n[[repositories]]\nid = \"central\"\nurl = \"{url}\"\n"
        ));
    }
    std::fs::write(project.join("raeva.toml"), toml).expect("write raeva.toml");
}

/// A Central stand-in that answers 404 to every request, and the
/// raeva.toml entry that points Central at it, for a test whose resolution
/// would otherwise go on to the real Central.
pub(crate) fn local_central() -> (StubServer, String) {
    let server = StubServer::start(|_| Response::new(404, ""));
    let entry = format!(
        "\n[[repositories]]\nid = \"central\"\nurl = \"http://{}/\"\n",
        server.addr()
    );
    (server, entry)
}

/// A `t:{artifact}:1` POM with `body` after its coordinates.
pub(crate) fn pom(artifact: &str, body: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>{artifact}</artifactId><version>1</version>{body}</project>"
    )
}

/// The one JSON document on stdout.
pub(crate) fn envelope(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("{err}: {}", String::from_utf8_lossy(&output.stdout)))
}

pub(crate) fn assert_success(output: &Output, action: &str) {
    assert_status(output, 0, action);
}

pub(crate) fn assert_status(output: &Output, code: i32, action: &str) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{action} exited {}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A jar dependency served by `https://repo.example/maven2/`, unpinned.
pub(crate) fn package(group: &str, artifact: &str, version: &str) -> rv_lock::LockArtifact {
    rv_lock::LockArtifact::new(
        rv_maven_types::ArtifactCoord::new(group, artifact, version, "jar", None),
        "https://repo.example/maven2/",
    )
}

/// The raeva.lock text for a single root module on `platform` that depends on
/// `packages`, in the shape `raeva sync` writes. Every artifact row pins a
/// placeholder SHA-256 and companion POM, which the lock schema requires.
pub(crate) fn lock_text(
    platform: &str,
    config_hash: Option<&str>,
    packages: Vec<rv_lock::LockArtifact>,
) -> String {
    let mut entry = rv_lock::LockPlatform::single_module(
        platform.parse().expect("platform"),
        rv_maven_types::Gav::new("test", "test", "1.0"),
        "jar",
        packages,
    );
    // `to_toml` refuses an origin that may hold a credential, and some tests
    // need one on disk: write a stand-in and put the origin back after.
    let mut secrets = Vec::new();
    for artifact in &mut entry.artifacts {
        if artifact.checksums.is_empty() {
            artifact.checksums =
                vec![rv_maven_types::Digest::parse("sha256", &"a".repeat(64)).unwrap()];
        }
        artifact.pom_sha256 = Some(("b".repeat(64)).parse().unwrap());
        if rv_config::secret_url_part(&artifact.repo_url).is_some() {
            let stand_in = format!("https://secret-{}.invalid/", secrets.len());
            secrets.push((
                stand_in.clone(),
                std::mem::replace(&mut artifact.repo_url, stand_in),
            ));
        }
    }
    let mut lock = rv_lock::Lockfile::new();
    lock.config_hash = config_hash.map(str::to_string);
    lock.platforms.push(entry);
    let mut text = lock.to_toml().expect("serialize lock");
    for (stand_in, origin) in secrets {
        let quoted = toml::Value::String(origin).to_string();
        text = text.replace(&format!("\"{stand_in}\""), &quoted);
    }
    text
}

/// Syncs `com.example:demo:1.0.0`, a project with no dependencies, offline,
/// then makes its root module depend directly on the `org.example` artifacts
/// `packages` lists at version 2.0.0, as (artifactId, packaging, classifier,
/// scope), with `edges` between them. Every row gets a placeholder artifact SHA-256 and
/// a pinned companion POM in the store. Origins are Maven Central so a Fresh lock check
/// (`sbom`, `vuln`) does not re-resolve the empty POM.
pub(crate) fn write_demo_lock(
    project_root: &Path,
    home: &Path,
    packages: &[(&str, &str, Option<&str>, rv_lock::Scope)],
    edges: Vec<rv_lock::LockEdge>,
) {
    write_empty_pom(&project_root.join("pom.xml"));
    assert_success(
        &run_raeva(project_root, home, &["--quiet", "sync", "--offline"]),
        "sync",
    );
    let lock_path = project_root.join("raeva.lock");
    let mut lock = rv_lock::Lockfile::read(&lock_path).expect("read generated lock");
    let platform = lock.platforms.first_mut().expect("generated platform");
    let store = rv_store::Store::open(&home.join("store")).expect("open fixture store");
    let runtime = tokio::runtime::Runtime::new().expect("fixture runtime");
    for &(artifact_id, packaging, classifier, scope) in packages {
        let coordinate = rv_maven_types::ArtifactCoord::new(
            "org.example",
            artifact_id,
            "2.0.0",
            packaging,
            classifier,
        );
        let mut artifact =
            rv_lock::LockArtifact::new(coordinate, rv_config::RepoConfig::maven_central().url);
        artifact.checksums =
            vec![rv_maven_types::Digest::parse("sha256", &"a".repeat(64)).unwrap()];
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>\
             <artifactId>{artifact_id}</artifactId><version>2.0.0</version></project>"
        );
        let blob = runtime
            .block_on(store.put_bytes(pom.as_bytes()))
            .expect("cache fixture POM");
        artifact.pom_sha256 = Some(blob.to_string().parse().unwrap());
        platform.modules[0]
            .packages
            .push(rv_lock::LockModulePackage::new(
                artifact.coordinate.clone(),
                Some(scope),
            ));
        platform.artifacts.push(artifact);
    }
    platform.modules[0].edges = edges;
    lock.write_atomic(&lock_path).expect("write fixture lock");
}

pub(crate) fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(<Sha1 as sha1::Digest>::digest(bytes))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(<Sha256 as sha2::Digest>::digest(bytes))
}

pub(crate) fn with_sha1<N, B>(path: &str, files: impl IntoIterator<Item = (N, B)>) -> Response
where
    N: AsRef<str>,
    B: AsRef<[u8]>,
{
    with_sidecar(path, ".sha1", sha1_hex, files)
}

pub(crate) fn with_sha256<N, B>(path: &str, files: impl IntoIterator<Item = (N, B)>) -> Response
where
    N: AsRef<str>,
    B: AsRef<[u8]>,
{
    with_sidecar(path, ".sha256", sha256_hex, files)
}

fn with_sidecar<N, B>(
    path: &str,
    sidecar: &str,
    digest: fn(&[u8]) -> String,
    files: impl IntoIterator<Item = (N, B)>,
) -> Response
where
    N: AsRef<str>,
    B: AsRef<[u8]>,
{
    for (name, body) in files {
        let name = name.as_ref();
        let body = body.as_ref();
        if path == name {
            return Response::new(200, body);
        }
        if path.strip_suffix(sidecar) == Some(name) {
            return Response::new(200, digest(body));
        }
    }
    Response::new(404, "")
}

/// String values of a TOML array, in file order.
pub(crate) fn toml_strings(value: &toml::Value) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item.as_str().expect("string").to_string())
        .collect()
}

pub(crate) fn spawn_osv(status: u16, body: &'static str) -> (String, StubServer) {
    let server = StubServer::start(move |_| {
        Response::new(status, body).header("Content-Type", "application/json")
    });
    (format!("http://{}/v1", server.addr()), server)
}

/// Command names from `raeva help`, skipping clap's `help` subcommand.
pub(crate) fn cli_commands(args: &[&str]) -> Vec<String> {
    let (project, home) = temp_project();
    let output = raeva_command(project.path(), home.path())
        .args(args)
        .output()
        .expect("run raeva help");
    assert_success(&output, &format!("{args:?}"));
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    let mut commands = Vec::new();
    let mut in_commands = false;
    for line in help.lines() {
        if line.starts_with("Commands:") {
            in_commands = true;
            continue;
        }
        if in_commands {
            if line.is_empty() {
                break;
            }
            let name = line.split_whitespace().next().expect("command name");
            if name != "help" {
                commands.push(name.to_string());
            }
        }
    }
    assert!(!commands.is_empty(), "no commands in {help}");
    commands
}

/// Long names of global options from `raeva --help`, with a short form when
/// clap shows one. `--help` and `--version` are omitted. Completeness tests
/// compare these to the README Commands section.
pub(crate) fn cli_global_flags() -> Vec<(String, Option<char>)> {
    let help = {
        let (project, home) = temp_project();
        let output = raeva_command(project.path(), home.path())
            .arg("--help")
            .output()
            .expect("run raeva --help");
        assert_success(&output, "help");
        String::from_utf8(output.stdout).expect("UTF-8 help")
    };
    let mut flags = Vec::new();
    let mut in_options = false;
    for line in help.lines() {
        if line.starts_with("Global Options:") {
            in_options = true;
            continue;
        }
        if in_options && !line.is_empty() && !line.starts_with([' ', '\t']) {
            break;
        }
        if !in_options {
            continue;
        }
        let trimmed = line.trim_start();
        if !trimmed.starts_with('-') {
            continue;
        }
        let short = match trimmed.strip_prefix('-') {
            Some(after) if !after.starts_with('-') => after.chars().next(),
            _ => None,
        };
        let Some((_, after)) = trimmed.split_once("--") else {
            continue;
        };
        let long = after
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .next()
            .unwrap_or("")
            .trim_end_matches('-')
            .to_string();
        if long.is_empty() || long == "help" || long == "version" {
            continue;
        }
        flags.push((long, short));
    }
    flags.sort_by(|left, right| left.0.cmp(&right.0));
    flags
}

/// Top-level commands and `lock` subcommands as `lock-<sub>`, matching
/// `json-payloads/` directory names and the README command list.
pub(crate) fn cli_command_dirs() -> Vec<String> {
    let mut names = Vec::new();
    for command in cli_commands(&["--help"]) {
        if command == "lock" {
            for sub in cli_commands(&["lock", "--help"]) {
                names.push(format!("lock-{sub}"));
            }
        } else {
            names.push(command);
        }
    }
    names.sort();
    names
}

/// [`HOST_ENV`] is exactly the documented variables [`raeva_command`] does
/// not overwrite. [`CLAP_COLOR_ENV`] is stripped separately.
#[test]
fn host_env_covers_the_documented_variables() {
    let text = fixtures::workspace_file("docs/configuration.md");
    let mut overwritten = fixtures::quoted_after(include_str!("mod.rs"), concat!(".env", "("));
    overwritten.sort();
    overwritten.dedup();
    assert!(
        overwritten.contains(&"RAEVA_HOME".to_string()),
        "raeva_command must set RAEVA_HOME"
    );
    let documented = fixtures::markdown_first_column_parts(&text, "## Environment variables");
    let mut expected: Vec<&str> = documented
        .iter()
        .map(String::as_str)
        .filter(|name| !overwritten.iter().any(|set| set == name))
        .collect();
    expected.sort();
    let mut stripped: Vec<&str> = HOST_ENV.to_vec();
    stripped.sort();
    assert_eq!(
        stripped, expected,
        "HOST_ENV must be the documented variables the tests do not overwrite"
    );
    for name in CLAP_COLOR_ENV {
        assert!(
            !HOST_ENV.contains(name),
            "{name} is a clap colour variable, not a documented raeva input"
        );
    }
}

/// The URL of a loopback server that closes every connection without an
/// answer, a failure raeva retries after a short backoff.
pub(crate) fn closing_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = rv_test_support::http::read_request_head_blocking(&mut stream);
        }
    });
    format!("http://{addr}")
}
