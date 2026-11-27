use std::path::Path;
use std::process::{Command, Output};
use std::sync::OnceLock;

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
    "MAVEN_SKIP_RC",
    "MAVEN_DEBUG_OPTS",
    "MAVEN_ARGS",
    "MAVEN_CONFIG",
    "CFFIXED_USER_HOME",
    "_JAVA_OPTIONS",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "OPENJ9_JAVA_OPTIONS",
    "IBM_JAVA_OPTIONS",
    "MAVEN_REPO_CENTRAL",
    "LC_ALL",
    "LC_CTYPE",
    "LANG",
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
/// os-release a test sets. No `java` is found without `JAVA_HOME`, as the
/// lookup hook names a directory without one, and the CPU reads as one
/// without AVX-512 VBMI. Requests for Maven Central go to
/// [`central_stand_in`].
pub(crate) fn raeva_command(project_root: &Path, home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_raeva"));
    cmd.env("RAEVA_HOME", home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env(rv_maven_model::JAVA_PATH_TEST_ENV, home.join("no-jdk"))
        .env(rv_maven_model::AVX512_VBMI_TEST_ENV, "0")
        .env(
            rv_repo::CENTRAL_TEST_ENV,
            central_stand_in().addr().to_string(),
        )
        .env_remove(rv_maven_model::OS_RELEASE_TEST_ENV)
        .arg("-C")
        .arg(project_root);
    for name in HOST_ENV.iter().chain(CLAP_COLOR_ENV) {
        cmd.env_remove(name);
    }
    isolate_maven_user_home(&mut cmd, home, "");
    cmd
}

/// Point Maven's user home, which the JVM takes from the passwd entry and
/// not `HOME`, at `home` through `MAVEN_OPTS`, after `opts`, as Maven's
/// own launcher would; a run that reads the real one fails. A test that
/// sets `MAVEN_OPTS` itself calls this instead.
pub(crate) fn isolate_maven_user_home(cmd: &mut Command, home: &Path, opts: &str) {
    let define = format!("-Duser.home={}", home.display());
    let opts = match opts {
        "" => define,
        opts => format!("{opts} {define}"),
    };
    cmd.env("MAVEN_OPTS", opts)
        .env(rv_config::REAL_HOME_GUARD_TEST_ENV, "1");
}

/// This test process's Maven Central: a stub that answers
/// 404, as the real Central does for the coordinates tests publish, so a
/// resolution that goes on to Central never leaves the machine.
pub(crate) fn central_stand_in() -> &'static StubServer {
    static CENTRAL: OnceLock<StubServer> = OnceLock::new();
    CENTRAL.get_or_init(|| StubServer::start(|_| Response::new(404, "")))
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

/// A project with one dependency, `org.example:lib:1.0`, from the repository
/// at `url`.
pub(crate) fn lib_project(url: &str) -> TempDir {
    let dir = tempfile::tempdir().expect("project dir");
    std::fs::write(
        dir.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>app</artifactId><version>1.0</version><dependencies><dependency>\
<groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>\
</dependency></dependencies></project>",
    )
    .expect("write pom.xml");
    write_repo_toml(dir.path(), "fixture", url);
    dir
}

/// A Central stand-in that answers 404 to every request, and the
/// raeva.toml entry that points Central at it, for a test that configures
/// Central itself rather than leave it to [`central_stand_in`].
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

/// The origin raeva.lock in `project` records for a repository at `url`:
/// a `file:` one beside the project is relative to it.
pub(crate) fn recorded_origin(project: &Path, url: &str) -> String {
    rv_lock::LockOrigins::for_root(project)
        .declared(url)
        .expect("a URL raeva.lock records")
}

/// The text `output` wrote to stderr.
pub(crate) fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
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
/// `packages` lists at version 2.0.0, as (artifactId, type, classifier,
/// scope), with `edges` between them. A type is locked at the extension
/// Maven's core handler gives it. Every row gets a placeholder artifact SHA-256 and
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
    let types = rv_maven_model::ArtifactTypes::core(rv_maven_types::MavenMode::Maven39);
    for &(artifact_id, type_, classifier, scope) in packages {
        let extension = types.extension(type_);
        let coordinate = rv_maven_types::ArtifactCoord::new(
            "org.example",
            artifact_id,
            "2.0.0",
            extension,
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
        let mut package = rv_lock::LockModulePackage::new(artifact.coordinate.clone(), Some(scope));
        package.type_ = (type_ != extension).then(|| type_.to_string());
        platform.modules[0].packages.push(package);
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

/// `path` from `lookup`, or its SHA-256 file, or 404.
pub(crate) fn serve_sha256<B: AsRef<[u8]>>(
    path: &str,
    lookup: impl FnOnce(&str) -> Option<B>,
) -> Response {
    let (path, sidecar) = match path.strip_suffix(".sha256") {
        Some(path) => (path, true),
        None => (path, false),
    };
    match lookup(path) {
        Some(body) if sidecar => Response::new(200, sha256_hex(body.as_ref())),
        Some(body) => Response::new(200, body.as_ref()),
        None => Response::new(404, ""),
    }
}

/// A repository that serves `files` by request path, each with its SHA-256
/// file.
pub(crate) fn sha256_repository<K, B>(files: impl IntoIterator<Item = (K, B)>) -> StubServer
where
    K: Into<String>,
    B: Into<Vec<u8>>,
{
    let files: std::collections::HashMap<String, Vec<u8>> = (files.into_iter())
        .map(|(path, body)| (path.into(), body.into()))
        .collect();
    StubServer::start(move |request| serve_sha256(&request.path, |path| files.get(path)))
}

/// Writes `bytes` at `path`, and its SHA-256 file beside it.
pub(crate) fn write_with_sha256(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create repository directory");
    std::fs::write(path, bytes).expect("write repository file");
    let mut sidecar = path.as_os_str().to_owned();
    sidecar.push(".sha256");
    std::fs::write(sidecar, sha256_hex(bytes)).expect("write sidecar");
}

/// Publishes `group:artifact:version` in the file repository `repository`:
/// a POM with `body` in its `<project>`, and a jar unless `body` sets the
/// packaging to `pom`, each with its SHA-256 file.
pub(crate) fn publish(repository: &Path, coordinate: &str, body: &str) {
    let [group, artifact, version] = coordinate.split(':').collect::<Vec<_>>()[..] else {
        panic!("{coordinate}");
    };
    let dir = (repository.join(group.replace('.', "/")))
        .join(artifact)
        .join(version);
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>{group}</groupId>\
         <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
    );
    write_with_sha256(
        &dir.join(format!("{artifact}-{version}.pom")),
        pom.as_bytes(),
    );
    if !body.contains("<packaging>pom</packaging>") {
        let jar = format!("{coordinate} jar");
        write_with_sha256(
            &dir.join(format!("{artifact}-{version}.jar")),
            jar.as_bytes(),
        );
    }
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

/// Top-level commands, and `lock` and `seed` subcommands as `lock-<sub>`
/// and `seed-<sub>`, matching `json-payloads/` directory names and the
/// README command list.
pub(crate) fn cli_command_dirs() -> Vec<String> {
    let mut names = Vec::new();
    for command in cli_commands(&["--help"]) {
        if command == "lock" || command == "seed" {
            for sub in cli_commands(&[&command, "--help"]) {
                names.push(format!("{command}-{sub}"));
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
        // Tests run git from PATH; their `java` lookup reads RAEVA_TEST_JAVA_PATH.
        .filter(|name| *name != "PATH")
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

/// Every file under `root` but `skip`, with the marker `zq...zq` it holds.
pub(crate) fn markers_under(root: &std::path::Path, skip: &[&std::path::Path]) -> Vec<String> {
    let mut found = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if !skip.contains(&path.as_path()) {
                let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
                found.extend(
                    markers_in(&text).map(|marker| format!("{}: {marker}", path.display())),
                );
            }
        }
    }
    found
}

/// The markers `zq...zq`, an upper-case word between `zq`s, `text` holds.
pub(crate) fn markers_in(text: &str) -> impl Iterator<Item = String> + '_ {
    text.match_indices("zq").filter_map(|(at, _)| {
        let rest = &text[at + 2..];
        let end = rest.find("zq")?;
        let inner = &rest[..end];
        (!inner.is_empty() && inner.bytes().all(|b| b.is_ascii_uppercase()))
            .then(|| format!("zq{inner}zq"))
    })
}
