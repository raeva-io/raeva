use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use jsonschema::{Retrieve, Uri, Validator};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const CYCLONEDX_SCHEMA: &str = include_str!("fixtures/schemas/cyclonedx/bom-1.5.schema.json");
const CYCLONEDX_JSF_SCHEMA: &str = include_str!("fixtures/schemas/cyclonedx/jsf-0.82.schema.json");
const CYCLONEDX_SPDX_SCHEMA: &str = include_str!("fixtures/schemas/cyclonedx/spdx.schema.json");
const SPDX_SCHEMA: &str = include_str!("fixtures/schemas/spdx/spdx-2.3.schema.json");

struct BundledSchemas {
    schemas: HashMap<String, Value>,
}

impl Retrieve for BundledSchemas {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.schemas
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("schema is not bundled: {uri}").into())
    }
}

fn parse_schema(source: &str) -> Value {
    serde_json::from_str(source).expect("parse vendored schema")
}

fn cyclonedx_validator() -> Validator {
    let schemas = HashMap::from([
        (
            "http://cyclonedx.org/schema/jsf-0.82.schema.json".to_string(),
            parse_schema(CYCLONEDX_JSF_SCHEMA),
        ),
        (
            "http://cyclonedx.org/schema/spdx.schema.json".to_string(),
            parse_schema(CYCLONEDX_SPDX_SCHEMA),
        ),
    ]);
    jsonschema::options()
        .with_retriever(BundledSchemas { schemas })
        .build(&parse_schema(CYCLONEDX_SCHEMA))
        .expect("compile CycloneDX schema")
}

fn assert_schema_valid(validator: &Validator, document: &Value) {
    let errors = validator
        .iter_errors(document)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors:\n{}", errors.join("\n"));
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-fixtures")
        .join("reactor-cli")
        .join(name)
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("create fixture target");
    for entry in fs::read_dir(source).expect("read fixture") {
        let entry = entry.expect("fixture entry");
        let destination = target.join(entry.file_name());
        if entry.file_type().expect("fixture type").is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy fixture file");
        }
    }
}

fn response(status: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn handle_connection(mut socket: TcpStream, routes: &HashMap<String, Vec<u8>>) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let Ok(read) = socket.read(&mut buffer) else {
            return;
        };
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let path = std::str::from_utf8(&request)
        .ok()
        .and_then(|request| request.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let payload = if let Some(base_path) = path.strip_suffix(".sha256") {
        routes.get(base_path).map_or_else(
            || response("404 Not Found", b""),
            |body| response("200 OK", hex::encode(Sha256::digest(body)).as_bytes()),
        )
    } else {
        routes.get(path).map_or_else(
            || response("404 Not Found", b""),
            |body| response("200 OK", body),
        )
    };
    let _ = socket.write_all(&payload);
    let _ = socket.flush();
}

/// Route table a test can rewrite while the fixture repository is serving it.
type MutableRoutes = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// Repository whose route bodies can be rewritten after it starts serving, so
/// a test can republish a POM at the same origin the lockfile recorded.
fn spawn_mutable_repository(routes: HashMap<String, Vec<u8>>) -> (String, MutableRoutes) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture repository");
    let address = listener.local_addr().expect("fixture repository address");
    let routes = Arc::new(Mutex::new(routes));
    let served = Arc::clone(&routes);
    thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(socket) = socket else {
                break;
            };
            let served = Arc::clone(&served);
            thread::spawn(move || {
                let snapshot = served.lock().expect("routes lock").clone();
                handle_connection(socket, &snapshot);
            });
        }
    });
    (format!("http://{address}/"), routes)
}

fn spawn_repository(routes: HashMap<String, Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture repository");
    let address = listener.local_addr().expect("fixture repository address");
    let routes = Arc::new(routes);
    thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(socket) = socket else {
                break;
            };
            let routes = Arc::clone(&routes);
            thread::spawn(move || handle_connection(socket, &routes));
        }
    });
    format!("http://{address}/")
}

fn snapshot_publication(advanced: bool) -> (&'static str, u32) {
    if advanced {
        ("20240202.020202", 9)
    } else {
        ("20240101.010101", 7)
    }
}

fn snapshot_route(path: &str, advanced: bool) -> Option<Vec<u8>> {
    let (timestamp, build_number) = snapshot_publication(advanced);
    let resolved = format!("1.0-{timestamp}-{build_number}");
    match path {
        "/org/test/zz-release/1.0/zz-release-1.0.pom" => Some(
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>zz-release</artifactId><version>1.0</version>
</project>"#
                .to_vec(),
        ),
        "/org/test/zz-release/1.0/zz-release-1.0.jar" => Some(b"release artifact bytes".to_vec()),
        "/org/test/snapshot/1.0-SNAPSHOT/maven-metadata.xml" => Some(
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>snapshot</artifactId>\
                 <version>1.0-SNAPSHOT</version><versioning><snapshot>\
                 <timestamp>{timestamp}</timestamp><buildNumber>{build_number}</buildNumber>\
                 </snapshot><snapshotVersions><snapshotVersion><extension>jar</extension>\
                 <value>{resolved}</value></snapshotVersion><snapshotVersion>\
                 <extension>pom</extension><value>{resolved}</value></snapshotVersion>\
                 </snapshotVersions></versioning></metadata>"
            )
            .into_bytes(),
        ),
        _ if path == format!("/org/test/snapshot/1.0-SNAPSHOT/snapshot-{resolved}.pom") => Some(
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>snapshot</artifactId>
  <version>1.0-SNAPSHOT</version>
</project>"#
                .to_vec(),
        ),
        _ if path == format!("/org/test/snapshot/1.0-SNAPSHOT/snapshot-{resolved}.jar") => {
            Some(format!("snapshot artifact bytes {resolved}").into_bytes())
        }
        _ => None,
    }
}

fn handle_snapshot_connection(mut socket: TcpStream, advanced: &AtomicBool) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let Ok(read) = socket.read(&mut buffer) else {
            return;
        };
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let path = std::str::from_utf8(&request)
        .ok()
        .and_then(|request| request.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let advanced = advanced.load(Ordering::SeqCst);
    let payload = if let Some(base_path) = path.strip_suffix(".sha256") {
        snapshot_route(base_path, advanced).map_or_else(
            || response("404 Not Found", b""),
            |body| response("200 OK", hex::encode(Sha256::digest(body)).as_bytes()),
        )
    } else {
        snapshot_route(path, advanced).map_or_else(
            || response("404 Not Found", b""),
            |body| response("200 OK", &body),
        )
    };
    let _ = socket.write_all(&payload);
    let _ = socket.flush();
}

fn spawn_snapshot_repository() -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind snapshot repository");
    let address = listener.local_addr().expect("snapshot repository address");
    let advanced = Arc::new(AtomicBool::new(false));
    let server_state = Arc::clone(&advanced);
    thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(socket) = socket else {
                break;
            };
            let advanced = Arc::clone(&server_state);
            thread::spawn(move || handle_snapshot_connection(socket, &advanced));
        }
    });
    (format!("http://{address}/"), advanced)
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut expected_length = None;
    loop {
        let read = stream.read(&mut buffer).expect("read mock request");
        assert_ne!(read, 0, "mock request ended before its body");
        request.extend_from_slice(&buffer[..read]);
        if expected_length.is_none()
            && let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
        {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let body_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("Content-Length"))
                    })
                })
                .unwrap_or(0);
            expected_length = Some(header_end + 4 + body_length);
        }
        if expected_length.is_some_and(|length| request.len() >= length) {
            break;
        }
    }
    String::from_utf8(request).expect("mock request UTF-8")
}

fn spawn_osv(
    routes: Vec<(&'static str, &'static str)>,
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind OSV mock");
    let address = listener.local_addr().expect("OSV mock address");
    let request_count = routes.len();
    let mut routes = routes.into_iter().fold(
        HashMap::<String, VecDeque<&'static str>>::new(),
        |mut routes, (path, body)| {
            routes.entry(path.to_string()).or_default().push_back(body);
            routes
        },
    );
    let server = thread::spawn(move || {
        let mut requests = Vec::with_capacity(request_count);
        for _ in 0..request_count {
            let (mut stream, _) = listener.accept().expect("accept OSV request");
            let request = read_http_request(&mut stream);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .expect("OSV request path");
            let body = routes
                .get_mut(path)
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| panic!("unexpected OSV request path {path}"));
            requests.push(request);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write OSV response");
        }
        requests
    });
    (format!("http://{address}/v1"), server)
}

fn basic_routes() -> HashMap<String, Vec<u8>> {
    HashMap::from([
        (
            "/org/test/shared/1/shared-1.pom".to_string(),
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>shared</artifactId><version>1</version>
</project>"#
                .to_vec(),
        ),
        (
            "/org/test/shared/1/shared-1.jar".to_string(),
            b"shared artifact bytes".to_vec(),
        ),
        (
            "/org/test/app-only/1/app-only-1.pom".to_string(),
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>app-only</artifactId><version>1</version>
</project>"#
                .to_vec(),
        ),
        (
            "/org/test/app-only/1/app-only-1.jar".to_string(),
            b"app-only artifact bytes".to_vec(),
        ),
        (
            "/org/test/external-parent/1/external-parent-1.pom".to_string(),
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>external-parent</artifactId>
  <version>1</version><packaging>pom</packaging>
</project>"#
                .to_vec(),
        ),
        (
            "/org/test/bom-parent/1/bom-parent-1.pom".to_string(),
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>bom-parent</artifactId>
  <version>1</version><packaging>pom</packaging>
</project>"#
                .to_vec(),
        ),
        (
            "/org/test/bom/1/bom-1.pom".to_string(),
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.test</groupId><artifactId>bom-parent</artifactId><version>1</version>
  </parent>
  <artifactId>bom</artifactId><packaging>pom</packaging>
  <dependencyManagement><dependencies><dependency>
    <groupId>org.test</groupId><artifactId>shared</artifactId><version>1</version>
  </dependency></dependencies></dependencyManagement>
</project>"#
                .to_vec(),
        ),
    ])
}

fn conflict_routes(bytes: &'static [u8]) -> HashMap<String, Vec<u8>> {
    HashMap::from([
        (
            "/org/test/conflict/1/conflict-1.pom".to_string(),
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>conflict</artifactId><version>1</version>
</project>"#
                .to_vec(),
        ),
        (
            "/org/test/conflict/1/conflict-1.jar".to_string(),
            bytes.to_vec(),
        ),
    ])
}

/// A graph where the two mediation strategies disagree: the root declares
/// `leaf:1` directly (depth 1) and reaches `leaf:2` transitively through
/// `mid:1` (depth 2). Nearest-wins keeps 1, highest-wins promotes 2.
fn mediation_routes() -> HashMap<String, Vec<u8>> {
    HashMap::from([
        (
            "/org/test/mid/1/mid-1.pom".to_string(),
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>mid</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.test</groupId><artifactId>leaf</artifactId><version>2</version>
    </dependency>
  </dependencies>
</project>"#
                .to_vec(),
        ),
        (
            "/org/test/mid/1/mid-1.jar".to_string(),
            b"mid artifact bytes".to_vec(),
        ),
        (
            "/org/test/leaf/1/leaf-1.pom".to_string(),
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>leaf</artifactId><version>1</version>
</project>"#
                .to_vec(),
        ),
        (
            "/org/test/leaf/1/leaf-1.jar".to_string(),
            b"leaf 1 artifact bytes".to_vec(),
        ),
        (
            "/org/test/leaf/2/leaf-2.pom".to_string(),
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>leaf</artifactId><version>2</version>
</project>"#
                .to_vec(),
        ),
        (
            "/org/test/leaf/2/leaf-2.jar".to_string(),
            b"leaf 2 artifact bytes".to_vec(),
        ),
    ])
}

fn write_mediation_project(project: &Path, repo_url: &str) {
    write_config(project, repo_url);
    fs::write(
        project.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>mediation-root</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.test</groupId><artifactId>mid</artifactId><version>1</version>
    </dependency>
    <dependency>
      <groupId>org.test</groupId><artifactId>leaf</artifactId><version>1</version>
    </dependency>
  </dependencies>
</project>
"#,
    )
    .expect("write mediation pom.xml");
}

fn locked_versions(lock_path: &Path, artifact_id: &str) -> Vec<String> {
    let lock = rv_config::Lockfile::read(lock_path).expect("read lock");
    let mut versions: Vec<String> = lock
        .platforms
        .iter()
        .flat_map(|platform| platform.modules.iter())
        .flat_map(|module| module.packages.iter())
        .filter(|package| package.coordinate.artifact == artifact_id)
        .map(|package| package.coordinate.version.clone())
        .collect();
    versions.sort();
    versions.dedup();
    versions
}

fn locked_platforms(lock_path: &Path) -> Vec<String> {
    let lock = rv_config::Lockfile::read(lock_path).expect("read lock");
    let mut platforms: Vec<String> = lock
        .platforms
        .iter()
        .map(|platform| platform.platform.to_string())
        .collect();
    platforms.sort();
    platforms
}

fn write_config(project: &Path, repo_url: &str) {
    fs::write(
        project.join("rv.toml"),
        format!(
            "[[repositories]]\nid = \"fixture\"\nurl = \"{repo_url}\"\n\
             releases = true\nsnapshots = false\n"
        ),
    )
    .expect("write rv.toml");
}

fn write_snapshot_project(project: &Path, repo_url: &str) {
    fs::write(
        project.join("rv.toml"),
        format!(
            "[[repositories]]\nid = \"snapshot-fixture\"\nurl = \"{repo_url}\"\n\
             releases = true\nsnapshots = true\nsnapshots-update-policy = \"always\"\n"
        ),
    )
    .expect("write snapshot rv.toml");
    fs::write(
        project.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>snapshot-root</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.test</groupId><artifactId>zz-release</artifactId><version>1.0</version>
    </dependency>
    <dependency>
      <groupId>org.test</groupId><artifactId>snapshot</artifactId>
      <version>1.0-SNAPSHOT</version>
    </dependency>
  </dependencies>
</project>
"#,
    )
    .expect("write snapshot pom.xml");
}

fn run_rv(project: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rv"))
        .arg("-C")
        .arg(project)
        .args(args)
        .env("RAEVA_HOME", home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("RUST_LOG")
        .output()
        .expect("run rv")
}

fn assert_success(output: &Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn m2_path(root: &Path, group: &str, artifact: &str, version: &str, extension: &str) -> PathBuf {
    root.join(group.replace('.', "/"))
        .join(artifact)
        .join(version)
        .join(format!("{artifact}-{version}.{extension}"))
}

/// `--strategy` never reaches `config_hash` or `model_hash`, so the lockfile
/// records it directly. Changing it must re-resolve rather than reuse the
/// lock, and `--frozen` must refuse a lock built under the other strategy.
#[test]
fn resolution_strategy_is_persisted_and_gates_lock_reuse() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let repo_url = spawn_repository(mediation_routes());
    write_mediation_project(project.path(), &repo_url);
    let lock_path = project.path().join("rv.lock");

    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "nearest sync",
    );
    assert_eq!(
        locked_versions(&lock_path, "leaf"),
        ["1"],
        "nearest-wins must keep the directly declared leaf:1"
    );
    assert_eq!(
        rv_config::Lockfile::read(&lock_path)
            .expect("read nearest lock")
            .resolution
            .map(|resolution| resolution.strategy),
        Some(rv_config::LockResolutionStrategy::Nearest)
    );

    let frozen = run_rv(
        project.path(),
        home.path(),
        &["sync", "--frozen", "--strategy", "highest"],
    );
    assert_eq!(
        frozen.status.code(),
        Some(7),
        "--frozen must reject a lock built under another strategy\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&frozen.stdout),
        String::from_utf8_lossy(&frozen.stderr)
    );
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(
        stderr.contains("--strategy nearest") && stderr.contains("--strategy highest"),
        "frozen strategy mismatch must name both strategies: {stderr}"
    );

    // The fast path keys on the same inputs, so it must not hand the
    // nearest-wins graph back for `--strategy highest`.
    assert_success(
        &run_rv(
            project.path(),
            home.path(),
            &["sync", "--strategy", "highest"],
        ),
        "highest sync",
    );
    assert_eq!(
        locked_versions(&lock_path, "leaf"),
        ["2"],
        "highest-wins must promote the transitive leaf:2"
    );
    assert_eq!(
        rv_config::Lockfile::read(&lock_path)
            .expect("read highest lock")
            .resolution
            .map(|resolution| resolution.strategy),
        Some(rv_config::LockResolutionStrategy::Highest)
    );
    assert_success(
        &run_rv(
            project.path(),
            home.path(),
            &["sync", "--frozen", "--strategy", "highest"],
        ),
        "frozen sync under the recorded strategy",
    );
}

/// Online `--frozen` resolves the graph again and compares it canonically, so
/// it catches drift no local hash can see. Offline `--frozen` keeps the
/// weaker contract: local inputs only.
#[test]
fn online_frozen_resolves_afresh_while_offline_frozen_checks_hashes_only() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let repo_url = spawn_repository(mediation_routes());
    write_mediation_project(project.path(), &repo_url);
    let lock_path = project.path().join("rv.lock");

    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "initial sync",
    );

    // Edit the locked graph without touching any hashed local input, so
    // config_hash and model_hash still verify but no fresh resolution could
    // produce this lockfile.
    let original = fs::read_to_string(&lock_path).expect("read lock");
    let edited = original.replacen(
        "direct_scope = \"compile\"",
        "direct_scope = \"provided\"",
        1,
    );
    assert_ne!(
        edited, original,
        "fixture must lock a compile-scoped direct dependency"
    );
    fs::write(&lock_path, &edited).expect("write edited lock");

    assert_success(
        &run_rv(
            project.path(),
            home.path(),
            &["sync", "--frozen", "--offline"],
        ),
        "offline frozen sync",
    );
    assert_eq!(
        fs::read_to_string(&lock_path).expect("read lock after offline frozen"),
        edited,
        "offline --frozen must neither reject nor rewrite on graph drift"
    );

    let frozen = run_rv(project.path(), home.path(), &["sync", "--frozen"]);
    assert_eq!(
        frozen.status.code(),
        Some(7),
        "online --frozen must reject graph drift\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&frozen.stdout),
        String::from_utf8_lossy(&frozen.stderr)
    );
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(
        stderr.contains("dependencies would change from current lockfile"),
        "online frozen drift must be reported as a lockfile mismatch: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(&lock_path).expect("read lock after online frozen"),
        edited,
        "--frozen must never rewrite the lockfile"
    );
}

/// A partial `--platforms` sync installs a new top-level `config_hash`. It may
/// only carry an unselected platform forward when that platform was resolved
/// under the same resolution inputs; otherwise its graph would be blessed by a
/// hash it was never checked against.
#[test]
fn partial_platform_sync_drops_platforms_locked_under_other_resolution_inputs() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let repo_url = spawn_repository(mediation_routes());
    write_mediation_project(project.path(), &repo_url);
    let lock_path = project.path().join("rv.lock");

    assert_success(
        &run_rv(
            project.path(),
            home.path(),
            &["sync", "--platforms", "linux-x86_64,darwin-aarch64"],
        ),
        "two-platform sync",
    );
    assert_eq!(
        locked_platforms(&lock_path),
        ["darwin-aarch64", "linux-x86_64"]
    );

    // Unchanged resolution inputs: the unselected platform survives.
    assert_success(
        &run_rv(
            project.path(),
            home.path(),
            &["sync", "--platforms", "linux-x86_64"],
        ),
        "partial sync with unchanged inputs",
    );
    assert_eq!(
        locked_platforms(&lock_path),
        ["darwin-aarch64", "linux-x86_64"],
        "an unselected platform must survive a partial sync that changes nothing"
    );

    // Changed configuration: the unselected platform was resolved against the
    // old configuration and must not be re-blessed under the new hash.
    let config = fs::read_to_string(project.path().join("rv.toml")).expect("read rv.toml");
    fs::write(
        project.path().join("rv.toml"),
        format!("{config}\n[[repositories]]\nid = \"spare\"\nurl = \"{repo_url}\"\nreleases = true\nsnapshots = false\n"),
    )
    .expect("add repository");
    let partial = run_rv(
        project.path(),
        home.path(),
        &["sync", "--platforms", "linux-x86_64"],
    );
    assert_success(&partial, "partial sync after a configuration change");
    assert_eq!(
        locked_platforms(&lock_path),
        ["linux-x86_64"],
        "a platform locked under the old configuration must be dropped"
    );
    let stderr = String::from_utf8_lossy(&partial.stderr);
    assert!(
        stderr.contains("Dropping stale platform darwin-aarch64")
            && stderr.contains("rv sync --platforms darwin-aarch64"),
        "dropping a platform must tell the operator how to re-sync it: {stderr}"
    );

    // The same applies to a strategy change, which no hash covers.
    assert_success(
        &run_rv(
            project.path(),
            home.path(),
            &["sync", "--platforms", "linux-x86_64,darwin-aarch64"],
        ),
        "restore both platforms",
    );
    let partial = run_rv(
        project.path(),
        home.path(),
        &[
            "sync",
            "--platforms",
            "linux-x86_64",
            "--strategy",
            "highest",
        ],
    );
    assert_success(&partial, "partial sync after a strategy change");
    assert_eq!(
        locked_platforms(&lock_path),
        ["linux-x86_64"],
        "a platform locked under the other strategy must be dropped"
    );
}

#[test]
fn frozen_accepts_unchanged_external_snapshot_metadata() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let (repo_url, _advanced) = spawn_snapshot_repository();
    write_snapshot_project(project.path(), &repo_url);

    let initial = run_rv(project.path(), home.path(), &["sync"]);
    assert_success(&initial, "initial snapshot sync");
    let lock_path = project.path().join("rv.lock");
    let before = fs::read(&lock_path).expect("read initial snapshot lock");

    let frozen = run_rv(project.path(), home.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "frozen snapshot refresh with unchanged metadata");
    assert_eq!(
        fs::read(lock_path).expect("read frozen snapshot lock"),
        before,
        "--frozen must not rewrite an unchanged snapshot lock"
    );
}

#[test]
fn frozen_rejects_advanced_external_snapshot_and_names_coordinate() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let (repo_url, advanced) = spawn_snapshot_repository();
    write_snapshot_project(project.path(), &repo_url);

    let initial = run_rv(project.path(), home.path(), &["sync"]);
    assert_success(&initial, "initial snapshot sync");
    let lock_path = project.path().join("rv.lock");
    let before = fs::read(&lock_path).expect("read initial snapshot lock");
    advanced.store(true, Ordering::SeqCst);

    let frozen = run_rv(project.path(), home.path(), &["sync", "--frozen"]);
    assert_eq!(
        frozen.status.code(),
        Some(7),
        "advanced snapshot must fail with lockfile mismatch\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&frozen.stdout),
        String::from_utf8_lossy(&frozen.stderr)
    );
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(
        stderr.contains("[pom.xml]")
            && stderr.contains("org.test:snapshot")
            && stderr.contains("1.0-20240101.010101-7")
            && stderr.contains("1.0-20240202.020202-9"),
        "frozen mismatch must name the module, coordinate, and snapshot transition: {stderr}"
    );
    assert_eq!(
        fs::read(lock_path).expect("read rejected snapshot lock"),
        before,
        "--frozen must not rewrite the rejected snapshot lock"
    );
}

fn write_release_project(project: &Path, repo_url: &str) {
    fs::write(
        project.join("rv.toml"),
        format!(
            "[[repositories]]\nid = \"release-fixture\"\nurl = \"{repo_url}\"\n\
             releases = true\nsnapshots = false\n"
        ),
    )
    .expect("write release rv.toml");
    fs::write(
        project.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>release-root</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.test</groupId><artifactId>zz-release</artifactId><version>1.0</version>
    </dependency>
  </dependencies>
</project>
"#,
    )
    .expect("write release pom.xml");
}

/// Rewrite a schema-4 lock in place as the flat schema 1-3 layout it replaced,
/// keeping `config_hash` so the legacy hash gate passes unchanged. Passing
/// `repo_url_override` records an origin the current `rv.toml` does not
/// declare. Returns the bytes written, so a caller can assert `--frozen` left
/// them alone.
fn downgrade_lock_to_v3(lock_path: &Path, repo_url_override: Option<&str>) -> Vec<u8> {
    let lock = rv_config::Lockfile::read(lock_path).expect("read schema-4 lock");
    let config_hash = lock.config_hash.as_deref().expect("config hash");
    let mut out = format!("schema_version = 3\nconfig_hash = \"{config_hash}\"\n");
    for platform in &lock.platforms {
        out.push_str(&format!(
            "\n[[platforms]]\nplatform = \"{}\"\n",
            platform.platform
        ));
        for package in platform.external_packages() {
            let repo_url = repo_url_override.unwrap_or(&package.repo_url);
            out.push_str(&format!(
                "\n[[platforms.packages]]\ngroup_id = \"{}\"\nartifact_id = \"{}\"\n\
                 version = \"{}\"\npackaging = \"{}\"\nrepo_url = \"{repo_url}\"\n",
                package.group_id, package.artifact_id, package.version, package.packaging,
            ));
            if let Some(timestamp) = &package.snapshot_timestamp {
                out.push_str(&format!("snapshot_timestamp = \"{timestamp}\"\n"));
            }
            if let Some(checksum) = &package.checksum {
                out.push_str(&format!(
                    "\n[platforms.packages.checksum]\nalgorithm = \"{}\"\ndigest = \"{}\"\n",
                    checksum.algorithm, checksum.digest
                ));
            }
        }
    }
    fs::write(lock_path, &out).expect("write schema-3 lock");
    out.into_bytes()
}

/// A schema 1-3 lock is exempt from fresh resolution under `--frozen`, and the
/// exemption holds even when the lock carries a SNAPSHOT whose update policy
/// has expired. Re-resolving would compare the adapter's sentinel module GAV
/// against the real one and report drift for a graph that never changed.
///
/// The documented cost: an advanced snapshot goes unnoticed on a legacy lock.
/// The next non-frozen sync rewrites it to schema 4, after which the full
/// online contract applies.
#[test]
fn frozen_legacy_lock_keeps_local_checks_despite_stale_snapshot() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let (repo_url, advanced) = spawn_snapshot_repository();
    // `snapshots-update-policy = "always"` expires the lock's SNAPSHOT pins
    // immediately, which is the condition that used to force a re-resolve.
    write_snapshot_project(project.path(), &repo_url);

    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "initial snapshot sync",
    );
    let lock_path = project.path().join("rv.lock");
    let v3 = downgrade_lock_to_v3(&lock_path, None);

    let frozen = run_rv(project.path(), home.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "online frozen sync of a legacy snapshot lock");
    assert_eq!(
        fs::read(&lock_path).expect("read legacy lock after frozen"),
        v3,
        "--frozen must not rewrite a valid schema-3 lock"
    );

    advanced.store(true, Ordering::SeqCst);
    let frozen = run_rv(project.path(), home.path(), &["sync", "--frozen"]);
    assert_success(
        &frozen,
        "online frozen sync of a legacy lock past an advanced snapshot",
    );
    assert_eq!(
        fs::read(&lock_path).expect("read legacy lock after advanced snapshot"),
        v3,
        "--frozen must not rewrite a schema-3 lock it validated from local inputs"
    );

    // The migration path out of the weaker check: one non-frozen sync.
    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "non-frozen sync migrating the legacy lock",
    );
    assert_eq!(
        rv_config::Lockfile::read(&lock_path)
            .expect("read migrated lock")
            .schema_version,
        4,
        "a non-frozen sync must migrate the legacy lock to schema 4"
    );
    let frozen = run_rv(project.path(), home.path(), &["sync", "--frozen"]);
    assert_success(
        &frozen,
        "frozen sync of the migrated lock at the advanced snapshot",
    );
}

/// The same exemption holds when the legacy lock records an origin the current
/// `rv.toml` no longer declares. That condition exists to rediscover
/// POM-declared repositories before a download; it must not drag a legacy lock
/// into a comparison the sentinel GAV can only fail.
#[test]
fn frozen_legacy_lock_keeps_local_checks_despite_unconfigured_origin() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let (repo_url, _advanced) = spawn_snapshot_repository();
    write_release_project(project.path(), &repo_url);

    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "initial release sync",
    );
    let lock_path = project.path().join("rv.lock");
    // Point the recorded origin at a repository `rv.toml` does not declare.
    // The artifacts are already in the content store, so the download pass
    // never has to resolve the origin against the trust roots.
    let v3 = downgrade_lock_to_v3(&lock_path, Some("http://127.0.0.1:9/removed/"));

    let frozen = run_rv(project.path(), home.path(), &["sync", "--frozen"]);
    assert_success(
        &frozen,
        "online frozen sync of a legacy lock with a removed origin",
    );
    assert_eq!(
        fs::read(&lock_path).expect("read legacy lock after frozen"),
        v3,
        "--frozen must not rewrite a valid schema-3 lock"
    );
}

#[test]
fn reactor_sync_frozen_diff_and_exports_are_module_aware() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    copy_tree(&fixture("basic"), project.path());
    let repo_url = spawn_repository(basic_routes());
    write_config(project.path(), &repo_url);

    let first = run_rv(project.path(), home.path(), &["sync"]);
    assert_success(&first, "initial reactor sync");
    let lock_path = project.path().join("rv.lock");
    let first_bytes = fs::read(&lock_path).expect("read first lock");
    let lock = rv_config::Lockfile::read(&lock_path).expect("parse reactor lock");
    assert_eq!(lock.schema_version, 4);
    let platform = lock.platforms.first().expect("platform");
    assert_eq!(
        platform
            .modules
            .iter()
            .map(|module| module.path.as_str())
            .collect::<Vec<_>>(),
        ["app/pom.xml", "lib/pom.xml", "pom.xml"]
    );
    assert_eq!(
        platform
            .artifacts
            .iter()
            .filter(|artifact| artifact.coordinate.artifact == "shared")
            .count(),
        1,
        "shared external must be deduplicated in the artifact union"
    );

    let app = platform
        .modules
        .iter()
        .find(|module| module.path == "app/pom.xml")
        .expect("app module");
    let sibling_index = app
        .packages
        .iter()
        .position(|package| package.workspace_module.as_deref() == Some("lib/pom.xml"))
        .expect("workspace sibling marker");
    let shared_index = app
        .packages
        .iter()
        .position(|package| package.coordinate.artifact == "shared")
        .expect("shared package");
    assert!(
        app.edges
            .iter()
            .any(|edge| edge.from == sibling_index && edge.to == shared_index),
        "workspace sibling must retain its edge to the shared external"
    );

    let aggregate_verify = run_rv(project.path(), home.path(), &["--json", "lock", "verify"]);
    assert_success(&aggregate_verify, "aggregate reactor lock verify");
    let aggregate_verify: Value =
        serde_json::from_slice(&aggregate_verify.stdout).expect("aggregate verify JSON");
    assert_eq!(aggregate_verify["data"]["verified"], 2);
    assert_eq!(aggregate_verify["data"]["workspace_skipped"], 1);
    assert_eq!(
        aggregate_verify["data"]["workspace_entries"][0]["workspace_module"],
        "lib/pom.xml"
    );

    let selected_verify = run_rv(
        project.path(),
        home.path(),
        &["--json", "lock", "verify", "--module", "lib/pom.xml"],
    );
    assert_success(&selected_verify, "selected reactor lock verify");
    let selected_verify: Value =
        serde_json::from_slice(&selected_verify.stdout).expect("selected verify JSON");
    assert_eq!(selected_verify["data"]["verified"], 1);
    assert_eq!(selected_verify["data"]["workspace_skipped"], 0);

    let shared_digest = platform
        .artifacts
        .iter()
        .find(|artifact| artifact.coordinate.artifact == "shared")
        .and_then(|artifact| {
            artifact
                .checksums
                .iter()
                .find(|checksum| checksum.algorithm == "sha256")
        })
        .expect("shared SHA-256")
        .digest
        .clone();
    let shared_blob = home
        .path()
        .join("store/blobs")
        .join(&shared_digest[0..2])
        .join(&shared_digest[2..4])
        .join(&shared_digest);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&shared_blob)
            .expect("shared blob metadata")
            .permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&shared_blob, permissions).expect("make shared blob writable");
    }
    fs::write(&shared_blob, b"corrupt shared artifact").expect("corrupt shared blob");
    let corrupt_verify = run_rv(project.path(), home.path(), &["--json", "lock", "verify"]);
    assert_eq!(corrupt_verify.status.code(), Some(7));
    let corrupt_verify: Value =
        serde_json::from_slice(&corrupt_verify.stdout).expect("corrupt verify JSON");
    assert_eq!(corrupt_verify["data"]["corrupt"], 1);
    assert_eq!(
        corrupt_verify["data"]["corrupt_artifacts"][0]["affected_modules"],
        serde_json::json!(["app/pom.xml", "lib/pom.xml"])
    );
    fs::write(&shared_blob, b"shared artifact bytes").expect("restore shared blob");

    let tree = run_rv(project.path(), home.path(), &["tree"]);
    assert_success(&tree, "aggregate reactor tree");
    let tree = String::from_utf8(tree.stdout).expect("tree output");
    for module in ["app/pom.xml", "lib/pom.xml", "pom.xml"] {
        assert!(
            tree.contains(&format!("Module: {module}")),
            "aggregate tree must contain a section for {module}: {tree}"
        );
    }
    assert!(
        tree.contains("com.example:lib:1:jar (workspace)"),
        "workspace sibling must render distinctly: {tree}"
    );

    let app_tree = run_rv(
        project.path(),
        home.path(),
        &["tree", "--module", "com.example:app"],
    );
    assert_success(&app_tree, "selected reactor tree");
    let app_tree = String::from_utf8(app_tree.stdout).expect("selected tree output");
    assert!(app_tree.contains("com.example:lib:1:jar (workspace)"));
    assert!(app_tree.contains("org.test:shared:1:jar"));
    assert!(
        !app_tree.contains("Module:"),
        "selected tree is a single graph, not an aggregate section: {app_tree}"
    );

    let why = run_rv(project.path(), home.path(), &["why", "org.test:shared"]);
    assert_success(&why, "aggregate reactor why");
    let why = String::from_utf8(why.stdout).expect("why output");
    assert!(why.contains("Module: app/pom.xml"));
    assert!(why.contains("Module: lib/pom.xml"));
    assert!(
        why.contains("com.example:lib:1:jar (workspace) -> org.test:shared:1:jar"),
        "why must trace through the workspace sibling: {why}"
    );

    let app_why = run_rv(
        project.path(),
        home.path(),
        &["why", "org.test:shared", "--module", "app/pom.xml"],
    );
    assert_success(&app_why, "selected reactor why");
    let app_why = String::from_utf8(app_why.stdout).expect("selected why output");
    assert!(app_why.contains("com.example:lib:1:jar (workspace)"));
    assert!(!app_why.contains("Module: lib/pom.xml"));

    let (osv_url, osv) = spawn_osv(vec![(
        "/v1/querybatch",
        r#"{"results":[{"vulns":[]},{"vulns":[]}]}"#,
    )]);
    let aggregate_vuln = Command::new(env!("CARGO_BIN_EXE_rv"))
        .arg("-C")
        .arg(project.path())
        .arg("vuln")
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("RAEVA_OSV_BASE_URL", osv_url)
        .output()
        .expect("run aggregate vuln");
    assert_success(&aggregate_vuln, "aggregate reactor vuln");
    let requests = osv.join().expect("OSV aggregate server");
    assert_eq!(requests.len(), 1, "aggregate scan uses one OSV query set");
    let request = &requests[0];
    assert!(request.contains("pkg:maven/org.test/app-only@1"));
    assert!(request.contains("pkg:maven/org.test/shared@1"));
    assert_eq!(
        request.matches("pkg:maven/org.test/shared@1").count(),
        1,
        "shared external must be queried once across modules: {request}"
    );
    assert!(
        !request.contains("pkg:maven/com.example/lib@1"),
        "workspace modules must never be queried: {request}"
    );

    let (osv_url, osv) = spawn_osv(vec![("/v1/query", "{}")]);
    let selected_vuln = Command::new(env!("CARGO_BIN_EXE_rv"))
        .arg("-C")
        .arg(project.path())
        .args(["vuln", "--module", "lib/pom.xml"])
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("RAEVA_OSV_BASE_URL", osv_url)
        .output()
        .expect("run selected vuln");
    assert_success(&selected_vuln, "selected reactor vuln");
    let requests = osv.join().expect("OSV selected server");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("pkg:maven/org.test/shared@1"));
    assert!(!requests[0].contains("app-only"));

    let (osv_url, osv) = spawn_osv(vec![
        (
            "/v1/querybatch",
            r#"{"results":[{"vulns":[]},{"vulns":[{"id":"OSV-SHARED"}]}]}"#,
        ),
        (
            "/v1/vulns/OSV-SHARED",
            r#"{"id":"OSV-SHARED","summary":"shared finding","severity":[{"type":"CVSS_V3","score":"7.5"}],"affected":[]}"#,
        ),
    ]);
    let findings = Command::new(env!("CARGO_BIN_EXE_rv"))
        .arg("-C")
        .arg(project.path())
        .args(["vuln", "--format", "json"])
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("RAEVA_OSV_BASE_URL", osv_url)
        .output()
        .expect("run aggregate vuln findings");
    assert_eq!(findings.status.code(), Some(1));
    let findings: serde_json::Value =
        serde_json::from_slice(&findings.stdout).expect("vuln findings JSON");
    assert_eq!(
        findings["data"]["results"][0]["affected_modules"],
        serde_json::json!(["app/pom.xml", "lib/pom.xml"])
    );
    assert_eq!(osv.join().expect("OSV findings server").len(), 2);

    let cyclonedx_first = run_rv(
        project.path(),
        home.path(),
        &["sbom", "--format", "cyclonedx"],
    );
    let cyclonedx_second = run_rv(
        project.path(),
        home.path(),
        &["sbom", "--format", "cyclonedx"],
    );
    assert_success(&cyclonedx_first, "aggregate CycloneDX");
    assert_success(&cyclonedx_second, "repeat aggregate CycloneDX");
    assert_eq!(
        cyclonedx_first.stdout, cyclonedx_second.stdout,
        "aggregate CycloneDX must be byte-identical"
    );
    let cyclonedx: Value =
        serde_json::from_slice(&cyclonedx_first.stdout).expect("aggregate CycloneDX JSON");
    assert_schema_valid(&cyclonedx_validator(), &cyclonedx);
    let components = cyclonedx["components"].as_array().expect("components");
    let first_party_components = components
        .iter()
        .filter(|component| component["group"] == "com.example")
        .count()
        + usize::from(cyclonedx["metadata"]["component"]["group"] == "com.example");
    assert_eq!(
        first_party_components, 3,
        "all reactor modules, including the metadata root, are first-party components"
    );
    for module in ["reactor", "app", "lib"] {
        let component = if module == "reactor" {
            &cyclonedx["metadata"]["component"]
        } else {
            components
                .iter()
                .find(|component| component["name"] == module)
                .unwrap_or_else(|| panic!("missing first-party component {module}"))
        };
        assert!(
            component.get("hashes").is_none(),
            "first-party module {module} must not have download hashes"
        );
    }
    let app_purl = "pkg:maven/com.example/app@1";
    let lib_purl = "pkg:maven/com.example/lib@1";
    let shared_purl = "pkg:maven/org.test/shared@1";
    let dependencies = cyclonedx["dependencies"]
        .as_array()
        .expect("CycloneDX dependencies");
    let app_dependencies = dependencies
        .iter()
        .find(|dependency| dependency["ref"] == app_purl)
        .expect("app relationships")["dependsOn"]
        .as_array()
        .expect("app dependsOn");
    assert!(app_dependencies.iter().any(|purl| purl == lib_purl));
    let lib_dependencies = dependencies
        .iter()
        .find(|dependency| dependency["ref"] == lib_purl)
        .expect("lib relationships")["dependsOn"]
        .as_array()
        .expect("lib dependsOn");
    assert!(lib_dependencies.iter().any(|purl| purl == shared_purl));

    let selected_sbom = run_rv(
        project.path(),
        home.path(),
        &["sbom", "--module", "app/pom.xml"],
    );
    assert_success(&selected_sbom, "selected CycloneDX");
    let selected_sbom: Value =
        serde_json::from_slice(&selected_sbom.stdout).expect("selected CycloneDX JSON");
    assert_schema_valid(&cyclonedx_validator(), &selected_sbom);
    assert_eq!(selected_sbom["metadata"]["component"]["name"], "app");
    assert!(
        selected_sbom["components"]
            .as_array()
            .expect("selected components")
            .iter()
            .any(|component| component["name"] == "lib"),
        "selected module view keeps its reachable sibling"
    );
    let selected_lib_dependencies = selected_sbom["dependencies"]
        .as_array()
        .expect("selected relationships")
        .iter()
        .find(|dependency| dependency["ref"] == lib_purl)
        .expect("selected lib relationships")["dependsOn"]
        .as_array()
        .expect("selected lib dependsOn");
    assert!(
        selected_lib_dependencies
            .iter()
            .any(|purl| purl == shared_purl),
        "reachable sibling keeps its external relationship"
    );

    let spdx_first = Command::new(env!("CARGO_BIN_EXE_rv"))
        .arg("-C")
        .arg(project.path())
        .args(["sbom", "--format", "spdx"])
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .expect("run aggregate SPDX");
    let spdx_second = Command::new(env!("CARGO_BIN_EXE_rv"))
        .arg("-C")
        .arg(project.path())
        .args(["sbom", "--format", "spdx"])
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .expect("repeat aggregate SPDX");
    assert_success(&spdx_first, "aggregate SPDX");
    assert_success(&spdx_second, "repeat aggregate SPDX");
    assert_eq!(
        spdx_first.stdout, spdx_second.stdout,
        "SOURCE_DATE_EPOCH makes reactor SPDX byte-identical"
    );
    let spdx: Value = serde_json::from_slice(&spdx_first.stdout).expect("aggregate SPDX JSON");
    let spdx_validator =
        jsonschema::validator_for(&parse_schema(SPDX_SCHEMA)).expect("compile SPDX schema");
    assert_schema_valid(&spdx_validator, &spdx);
    assert_eq!(spdx["creationInfo"]["created"], "2023-11-14T22:13:20Z");
    let first_party_packages = spdx["packages"]
        .as_array()
        .expect("SPDX packages")
        .iter()
        .filter(|package| {
            package["externalRefs"][0]["referenceLocator"]
                .as_str()
                .is_some_and(|purl| purl.contains("pkg:maven/com.example/"))
        })
        .count();
    assert_eq!(first_party_packages, 3);

    let selected_spdx = Command::new(env!("CARGO_BIN_EXE_rv"))
        .arg("-C")
        .arg(project.path())
        .args(["sbom", "--format", "spdx", "--module", "com.example:app"])
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .expect("run selected SPDX");
    assert_success(&selected_spdx, "selected SPDX");
    let selected_spdx: Value =
        serde_json::from_slice(&selected_spdx.stdout).expect("selected SPDX JSON");
    assert_schema_valid(&spdx_validator, &selected_spdx);
    let selected_packages = selected_spdx["packages"]
        .as_array()
        .expect("selected SPDX packages");
    assert!(
        selected_packages
            .iter()
            .any(|package| package["name"] == "app")
    );
    assert!(
        selected_packages
            .iter()
            .any(|package| package["name"] == "lib")
    );
    assert!(
        !selected_packages
            .iter()
            .any(|package| package["name"] == "reactor")
    );
    let id_for = |name: &str| {
        selected_packages
            .iter()
            .find(|package| package["name"] == name)
            .unwrap_or_else(|| panic!("missing selected SPDX package {name}"))["SPDXID"]
            .as_str()
            .expect("SPDX ID")
            .to_string()
    };
    let lib_id = id_for("lib");
    let shared_id = id_for("shared");
    assert!(
        selected_spdx["relationships"]
            .as_array()
            .expect("selected SPDX relationships")
            .iter()
            .any(|relationship| {
                relationship["spdxElementId"] == lib_id
                    && relationship["relationshipType"] == "DEPENDS_ON"
                    && relationship["relatedSpdxElement"] == shared_id
            }),
        "selected SPDX must keep the sibling-to-external relationship"
    );

    for command in [
        vec!["tree", "--module", "missing/pom.xml"],
        vec!["why", "org.test:shared", "--module", "missing/pom.xml"],
        vec!["vuln", "--module", "missing/pom.xml"],
        vec!["sbom", "--module", "missing/pom.xml"],
        vec!["lock", "verify", "--module", "missing/pom.xml"],
    ] {
        let output = run_rv(project.path(), home.path(), &command);
        let expected = if command[0] == "vuln" { 2 } else { 1 };
        assert_eq!(output.status.code(), Some(expected));
        let error = String::from_utf8(output.stderr).expect("selector error");
        assert!(error.contains("available modules"), "{error}");
        assert!(error.contains("app/pom.xml"), "{error}");
        assert!(error.contains("lib/pom.xml"), "{error}");
        assert!(error.contains("pom.xml"), "{error}");
    }

    let second = run_rv(project.path(), home.path(), &["sync"]);
    assert_success(&second, "idempotent reactor sync");
    assert_eq!(
        first_bytes,
        fs::read(&lock_path).expect("read second lock"),
        "unchanged re-sync must be byte-identical"
    );
    assert_success(
        &run_rv(project.path(), home.path(), &["sync", "--frozen"]),
        "frozen reactor sync",
    );

    let m2 = project.path().join("m2-export");
    let exported = run_rv(
        project.path(),
        home.path(),
        &["export-m2", "--m2-path", m2.to_str().expect("m2 path")],
    );
    assert_success(&exported, "reactor export-m2");
    assert!(m2_path(&m2, "org.test", "shared", "1", "jar").is_file());
    assert!(m2_path(&m2, "org.test", "app-only", "1", "jar").is_file());
    assert!(
        !m2_path(&m2, "com.example", "lib", "1", "jar").exists(),
        "workspace sibling must never be exported"
    );
    for support in ["external-parent", "bom", "bom-parent"] {
        assert!(
            m2_path(&m2, "org.test", support, "1", "pom").is_file(),
            "support POM {support} must be exported"
        );
    }

    let checksums = run_rv(project.path(), home.path(), &["export-checksums"]);
    assert_success(&checksums, "reactor export-checksums");
    let checksum_text = fs::read_to_string(project.path().join(".mvn/checksums/checksums.sha256"))
        .expect("read checksums");
    assert_eq!(checksum_text.matches("shared-1.jar").count(), 1);
    assert!(!checksum_text.contains("lib-1.jar"));

    let lib_pom = project.path().join("lib/pom.xml");
    let original = fs::read_to_string(&lib_pom).expect("read lib POM");
    fs::write(&lib_pom, format!("{original}\n<!-- changed -->\n")).expect("edit lib POM");
    let stale = run_rv(project.path(), home.path(), &["sync", "--frozen"]);
    assert!(!stale.status.success());
    let stale_error = String::from_utf8_lossy(&stale.stderr);
    assert!(
        stale_error.contains("module POM changed: lib/pom.xml"),
        "frozen module drift must name the module: {stale_error}"
    );

    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "refresh edited module",
    );
    fs::create_dir_all(project.path().join(".mvn")).expect("create .mvn");
    fs::write(project.path().join(".mvn/maven.config"), "-Pextra\n")
        .expect("activate extra profile");
    let profile_stale = run_rv(project.path(), home.path(), &["sync", "--frozen"]);
    assert!(!profile_stale.status.success());
    let profile_error = String::from_utf8_lossy(&profile_stale.stderr);
    assert!(
        profile_error.contains("active Maven profiles changed") && profile_error.contains("extra"),
        "frozen profile drift must be specific: {profile_error}"
    );
}

#[test]
fn reactor_sync_rejects_same_coordinate_with_different_bytes() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    copy_tree(&fixture("conflict"), project.path());
    let dummy_url = spawn_repository(HashMap::new());
    let repo_a = spawn_repository(conflict_routes(b"bytes from repository A"));
    let repo_b = spawn_repository(conflict_routes(b"bytes from repository B"));
    for module in ["a", "b"] {
        let pom = project.path().join(module).join("pom.xml");
        let contents = fs::read_to_string(&pom)
            .expect("read conflict POM")
            .replace("__REPO_A__", &repo_a)
            .replace("__REPO_B__", &repo_b);
        fs::write(pom, contents).expect("write conflict repo URL");
    }
    write_config(project.path(), &dummy_url);

    let output = run_rv(project.path(), home.path(), &["sync"]);
    assert!(!output.status.success(), "conflicting bytes must fail sync");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("org.test:conflict:1:jar")
            && stderr.contains("a/pom.xml")
            && stderr.contains("b/pom.xml")
            && stderr.contains("different bytes"),
        "conflict error must name the coordinate and both modules: {stderr}"
    );
}

/// `rv sync` must pin the bytes of every POM it exports later: the companion
/// POM of each locked artifact (on the artifact row) and each support POM
/// (parent / imported BOM, in the recorded provenance). The store's coordinate
/// index is last-writer-wins, so without these digests a later sync of another
/// project sharing the store can silently substitute the POM `rv export-m2`
/// ships for this lockfile.
#[test]
fn sync_pins_companion_and_support_pom_bytes() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    copy_tree(&fixture("basic"), project.path());
    let routes = basic_routes();
    let repo_url = spawn_repository(basic_routes());
    write_config(project.path(), &repo_url);

    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "initial sync",
    );

    let lock_path = project.path().join("rv.lock");
    let lock = rv_config::Lockfile::read(&lock_path).expect("read lock");
    let platform = lock.platforms.first().expect("platform");

    let served_digest = |path: &str| {
        hex::encode(Sha256::digest(
            routes.get(path).unwrap_or_else(|| panic!("route {path}")),
        ))
    };

    for artifact in &platform.artifacts {
        let coord = &artifact.coordinate;
        assert_eq!(
            artifact.pom_sha256.as_deref(),
            Some(
                served_digest(&format!(
                    "/org/test/{0}/{1}/{0}-{1}.pom",
                    coord.artifact, coord.version
                ))
                .as_str()
            ),
            "artifact {}:{} must pin the companion POM bytes the repository served",
            coord.artifact,
            coord.version
        );
    }

    let support = lock
        .metadata
        .get("support_repo_ids")
        .expect("support-POM provenance");
    let recorded: Vec<Vec<&str>> = support
        .lines()
        .map(|line| line.split('\t').collect())
        .collect();
    assert!(
        recorded.iter().all(|fields| fields.len() == 3),
        "every support-POM line must carry coordinate, repo id, and digest: {support}"
    );
    let bom = recorded
        .iter()
        .find(|fields| fields[0] == "org.test:bom:1")
        .expect("the imported BOM must be recorded");
    assert_eq!(
        bom[2],
        served_digest("/org/test/bom/1/bom-1.pom"),
        "the imported BOM must pin the bytes the repository served"
    );
    let parent = recorded
        .iter()
        .find(|fields| fields[0] == "org.test:external-parent:1")
        .expect("the external parent must be recorded");
    assert_eq!(
        parent[2],
        served_digest("/org/test/external-parent/1/external-parent-1.pom"),
        "the external parent must pin the bytes the repository served"
    );
}

/// Rewrite `rv.lock` into the pre-pin schema-4 shape: artifact rows without
/// `pom_sha256`, support-POM lines back to their two-field form. Both are
/// still accepted on read, which is exactly why a lock in that state would
/// otherwise be reused unchanged forever.
fn strip_pom_pins(lock_path: &Path) {
    use rv_config::{LOCK_SUPPORT_POMS_KEY, SupportPomLine, encode_support_pom_lines};

    let mut lock = rv_config::Lockfile::read(lock_path).expect("read lock");
    for platform in &mut lock.platforms {
        for artifact in &mut platform.artifacts {
            artifact.pom_sha256 = None;
        }
    }
    if let Some(encoded) = lock.metadata.get(LOCK_SUPPORT_POMS_KEY) {
        let stripped = rv_config::decode_support_pom_lines(encoded)
            .expect("decode support lines")
            .into_iter()
            .map(|(coord, line)| {
                (
                    coord,
                    SupportPomLine {
                        repo_id: line.repo_id,
                        sha256: None,
                    },
                )
            })
            .collect();
        lock.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            encode_support_pom_lines(&stripped).expect("encode legacy lines"),
        );
    }
    lock.write_atomic(lock_path).expect("write unpinned lock");
}

/// Schema 4 reads the pre-pin shape so an existing lockfile keeps working, but
/// nothing else about such a lock ever changes: hashes, model, strategy and
/// origins all still match, so the fast path would reuse it on every sync and
/// its POMs would stay on the store's last-writer-wins coordinate index
/// forever — the dependency schema 4's pins exist to remove. The next plain
/// sync must migrate it once, exactly as a schema-3 lock is rewritten.
///
/// `--frozen` must not: it writes no lockfile, and an offline frozen run
/// validates from local inputs alone, so the unpinned lock stays valid and
/// untouched there.
#[test]
fn a_pre_pin_schema_four_lock_migrates_on_the_next_sync() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    copy_tree(&fixture("basic"), project.path());
    let repo_url = spawn_repository(basic_routes());
    write_config(project.path(), &repo_url);
    let lock_path = project.path().join("rv.lock");

    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "initial sync",
    );
    let pinned = fs::read(&lock_path).expect("read pinned lock");

    strip_pom_pins(&lock_path);
    let unpinned = fs::read(&lock_path).expect("read unpinned lock");
    assert_ne!(pinned, unpinned, "the fixture must actually lose its pins");

    // Frozen must accept the older shape and leave it alone: forcing a
    // migration from a mode that cannot write a lockfile would just fail CI on
    // a lock that still describes the project correctly.
    assert_success(
        &run_rv(
            project.path(),
            home.path(),
            &["sync", "--frozen", "--offline"],
        ),
        "offline frozen sync on an unpinned lock",
    );
    assert_eq!(
        unpinned,
        fs::read(&lock_path).expect("read lock after frozen"),
        "--frozen must never rewrite the lockfile"
    );

    // The plain sync falls through the fast path and rewrites the pins.
    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "migrating sync",
    );
    let migrated = rv_config::Lockfile::read(&lock_path).expect("read migrated lock");
    for platform in &migrated.platforms {
        for artifact in &platform.artifacts {
            assert!(
                artifact.pom_sha256.is_some(),
                "artifact {} must be pinned after migration",
                artifact.coordinate.format_coord()
            );
        }
    }
    let support = migrated
        .metadata
        .get("support_repo_ids")
        .expect("support-POM provenance");
    assert!(
        support
            .lines()
            .all(|line| line.split('\t').count() == 3 && !line.is_empty()),
        "every support-POM line must be rewritten with its digest: {support}"
    );

    // One shot: the migrated lock is fast-path eligible again, so a second
    // sync must not rewrite a byte.
    let migrated_bytes = fs::read(&lock_path).expect("read migrated bytes");
    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "post-migration sync",
    );
    assert_eq!(
        migrated_bytes,
        fs::read(&lock_path).expect("read lock after second sync"),
        "the migration must happen once, not on every sync"
    );
}

/// A companion POM republished with different bytes and an unchanged
/// dependency graph is drift: a plain `rv sync` would rewrite `pom_sha256`, so
/// `--frozen` reporting "up to date" would contradict its own contract and let
/// CI build against a POM the lockfile does not describe. The republished
/// parent here only gains a comment, so not one edge, version, or checksum in
/// the graph moves.
///
/// The frozen run uses a fresh `RAEVA_HOME` so it re-fetches instead of
/// replaying the POM cache the first sync filled; that is what a CI runner
/// with a cold cache does.
#[test]
fn frozen_reports_a_republished_pom_with_an_unchanged_graph() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    copy_tree(&fixture("basic"), project.path());
    let (repo_url, routes) = spawn_mutable_repository(basic_routes());
    write_config(project.path(), &repo_url);

    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "initial sync",
    );

    // Cold cache, unchanged repository: frozen must still pass, or the check
    // below would prove nothing.
    let cold = TempDir::new().expect("cold home");
    assert_success(
        &run_rv(project.path(), cold.path(), &["sync", "--frozen"]),
        "frozen sync against an unchanged repository",
    );

    // Republish the external parent with different bytes and an identical
    // effective model.
    let parent_path = "/org/test/external-parent/1/external-parent-1.pom";
    let shared_path = "/org/test/shared/1/shared-1.pom";
    {
        let mut routes = routes.lock().expect("routes lock");
        for path in [parent_path, shared_path] {
            let body = routes.get_mut(path).expect("route");
            body.extend_from_slice(b"\n<!-- republished -->");
        }
    }

    let cold = TempDir::new().expect("cold home");
    let output = run_rv(project.path(), cold.path(), &["sync", "--frozen"]);
    assert!(
        !output.status.success(),
        "a republished POM must fail --frozen even with an unchanged graph"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("support POM changed for org.test:external-parent:1"),
        "the frozen diff must name the republished support POM: {stderr}"
    );
    assert!(
        stderr.contains("POM changed for org.test:shared:1"),
        "the frozen diff must name the republished companion POM: {stderr}"
    );

    // A plain `rv sync` still takes the lockfile fast path — nothing local
    // changed — so the pins are what catches the republication there too, and
    // the report names the POM coordinate whose pin failed rather than the jar
    // that happens to reference it.
    let cold = TempDir::new().expect("cold home");
    let fast_path = run_rv(project.path(), cold.path(), &["sync"]);
    assert!(
        !fast_path.status.success(),
        "the lockfile fast path must not accept POM bytes this lock was not resolved against"
    );
    assert!(
        String::from_utf8_lossy(&fast_path.stderr).contains("org.test:shared:1:pom"),
        "the mismatch must name the POM coordinate: {}",
        String::from_utf8_lossy(&fast_path.stderr)
    );

    // Re-resolving accepts the republished bytes and rewrites the pins.
    let cold = TempDir::new().expect("cold home");
    assert_success(
        &run_rv(project.path(), cold.path(), &["sync", "--update"]),
        "sync --update after republication",
    );
    let lock = rv_config::Lockfile::read(&project.path().join("rv.lock")).expect("read lock");
    let republished = {
        let routes = routes.lock().expect("routes lock");
        hex::encode(Sha256::digest(routes.get(shared_path).expect("route")))
    };
    let shared = lock.platforms[0]
        .artifacts
        .iter()
        .find(|artifact| artifact.coordinate.artifact == "shared")
        .expect("shared artifact row");
    assert_eq!(
        shared.pom_sha256.as_deref(),
        Some(republished.as_str()),
        "the rewritten lock must pin the republished bytes"
    );
}

/// An expired SNAPSHOT update policy must not drag `--frozen --offline` into a
/// re-resolve. The cached `maven-metadata.xml` such a resolve needs carries the
/// same TTL that declared the pins stale, so the resolve could only abort with
/// "not available in local cache" — the run would fail for every project with a
/// SNAPSHOT dependency and a lockfile older than its update policy, without
/// ever reporting drift.
#[test]
fn offline_frozen_accepts_a_stale_snapshot_lock() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    // `snapshots-update-policy = "always"` expires the lock's SNAPSHOT pins the
    // instant it is written.
    let (repo_url, _advanced) = spawn_snapshot_repository();
    write_snapshot_project(project.path(), &repo_url);

    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "initial snapshot sync",
    );
    let lock_path = project.path().join("rv.lock");
    let before = fs::read(&lock_path).expect("read snapshot lock");

    let frozen = run_rv(
        project.path(),
        home.path(),
        &["sync", "--frozen", "--offline"],
    );
    assert_success(&frozen, "offline frozen sync of a stale snapshot lock");
    assert_eq!(
        fs::read(&lock_path).expect("re-read snapshot lock"),
        before,
        "offline --frozen must not rewrite the lockfile"
    );
}

/// The exception that stays: a lockfile origin the current `rv.toml` does not
/// declare still forces an offline re-resolve. Repository trust comes from the
/// model, never from lockfile metadata, and that question is answerable from
/// the local model plus the POMs a previous sync cached — no network needed.
#[test]
fn offline_frozen_still_rediscovers_an_unconfigured_origin() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    copy_tree(&fixture("basic"), project.path());
    let repo_url = spawn_repository(basic_routes());
    write_config(project.path(), &repo_url);

    assert_success(
        &run_rv(project.path(), home.path(), &["sync"]),
        "initial sync",
    );

    let lock_path = project.path().join("rv.lock");
    let raw = fs::read_to_string(&lock_path).expect("read lock");
    let edited = raw.replace(
        &format!("repo_url = \"{repo_url}\""),
        "repo_url = \"http://127.0.0.1:9/removed/\"",
    );
    assert_ne!(raw, edited, "fixture must record the fixture repo url");
    fs::write(&lock_path, &edited).expect("write edited lock");

    let frozen = run_rv(
        project.path(),
        home.path(),
        &["sync", "--frozen", "--offline"],
    );
    assert_eq!(
        frozen.status.code(),
        Some(7),
        "an unconfigured recorded origin must be re-resolved offline and reported as drift\
         \nstdout={}\nstderr={}",
        String::from_utf8_lossy(&frozen.stdout),
        String::from_utf8_lossy(&frozen.stderr)
    );
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(
        stderr.contains("external origin changed"),
        "the offline resolve must produce a real diff, not a cache error: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(&lock_path).expect("re-read lock"),
        edited,
        "--frozen must not rewrite the lockfile it rejected"
    );
}
