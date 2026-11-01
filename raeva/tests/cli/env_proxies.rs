//! `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` against a local proxy.

use std::io::Read;
use std::net::TcpListener;
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rv_test_support::http::{Request, Response, StubServer};
use tempfile::TempDir;

use crate::common::{assert_success, envelope, raeva_command, with_sha256};

/// `io.raeva:lib:1.0`, served under `http://repo.test/maven/`.
const LIBRARY: [(&str, &[u8]); 2] = [
    (
        "http://repo.test/maven/io/raeva/lib/1.0/lib-1.0.pom",
        b"<project><modelVersion>4.0.0</modelVersion><groupId>io.raeva</groupId>\
          <artifactId>lib</artifactId><version>1.0</version></project>",
    ),
    (
        "http://repo.test/maven/io/raeva/lib/1.0/lib-1.0.jar",
        b"library bytes",
    ),
];

const BASIC: &str = "Basic cHJveHktdXNlcjpwcm94eS1zZWNyZXQ="; // proxy-user:proxy-secret

/// The name raeva gives the variable a test set as `name`. Windows ignores
/// the case of variable names, so there the lower-case name, which raeva
/// reads first, finds it.
fn named(name: &str) -> String {
    if cfg!(windows) {
        name.to_ascii_lowercase()
    } else {
        name.to_string()
    }
}

/// A project that depends on `io.raeva:lib:1.0` from `repo.test`, a name
/// only the proxy knows, and from `second.test` and `central.test`, in
/// place of the real Central, after it.
fn project() -> (TempDir, TempDir) {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    std::fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>io.raeva</groupId><artifactId>lib</artifactId><version>1.0</version>\
         </dependency></dependencies></project>",
    )
    .expect("write pom.xml");
    std::fs::write(
        project.path().join("raeva.toml"),
        "[[repositories]]\nid = \"corp\"\nurl = \"http://repo.test/maven/\"\n\n\
         [[repositories]]\nid = \"second\"\nurl = \"http://second.test/maven/\"\n\n\
         [[repositories]]\nid = \"central\"\nurl = \"http://central.test/maven/\"\n",
    )
    .expect("write raeva.toml");
    (project, home)
}

/// A forward proxy that serves [`LIBRARY`] to requests with the proxy
/// credentials, and answers 407 to the others.
fn library_proxy() -> StubServer {
    StubServer::start(|request: &Request| {
        if request.header("proxy-authorization") != Some(BASIC) {
            return Response::new(407, "").header("Proxy-Authenticate", "Basic realm=\"corp\"");
        }
        with_sha256(&request.path, LIBRARY)
    })
}

fn sync(project: &TempDir, home: &TempDir, env: &[(&str, String)]) -> Output {
    let mut command = raeva_command(project.path(), home.path());
    for (name, value) in env {
        command.env(name, value);
    }
    command
        .args(["--json", "sync"])
        .output()
        .expect("run raeva")
}

fn hints(output: &Output) -> String {
    envelope(output)["hints"].to_string()
}

/// `HTTP_PROXY` carries the sync, with the credentials of its URL, which
/// no output shows. A config.toml proxy takes precedence over it.
#[test]
fn sync_goes_through_the_http_proxy_variable() {
    let (project, home) = project();
    let proxy = library_proxy();
    let variable = format!(
        "http://proxy-user:proxy-secret@127.0.0.1:{}",
        proxy.addr().port()
    );
    let output = sync(&project, &home, &[("HTTP_PROXY", variable.clone())]);
    assert_success(&output, "sync through HTTP_PROXY");
    let requests = proxy.requests();
    assert!(
        (requests.iter()).any(|request| request.path.ends_with("lib-1.0.jar")),
        "{requests:?}"
    );
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!printed.contains("proxy-secret"), "{printed}");

    let configured = library_proxy();
    let other_home = TempDir::new().expect("home");
    std::fs::write(
        other_home.path().join("config.toml"),
        format!(
            "[[proxies]]\nhost = \"127.0.0.1\"\nport = {}\nusername = \"proxy-user\"\n\
             password = \"proxy-secret\"\n",
            configured.addr().port()
        ),
    )
    .expect("write config.toml");
    std::fs::remove_file(project.path().join("raeva.lock")).expect("remove lock");
    let before = proxy.requests().len();
    let output = sync(&project, &other_home, &[("HTTP_PROXY", variable)]);
    assert_success(&output, "sync through the config.toml proxy");
    assert_eq!(proxy.requests().len(), before);
    assert!(!configured.requests().is_empty());
}

/// A 407 is a proxy refusal whose hint names the variable, and a host
/// `NO_PROXY` names goes direct.
#[test]
fn a_refusing_proxy_and_no_proxy() {
    let (project, home) = project();
    let proxy = library_proxy();
    let port = proxy.addr().port();
    let output = sync(
        &project,
        &home,
        &[("http_proxy", format!("http://127.0.0.1:{port}"))],
    );
    assert_eq!(envelope(&output)["code"], "PROXY_AUTH", "{output:?}");
    let hints = hints(&output);
    assert!(
        hints.contains(&format!("127.0.0.1:{port} from http_proxy")),
        "{hints}"
    );

    let before = proxy.requests().len();
    let direct = sync(
        &project,
        &home,
        &[
            ("HTTP_PROXY", format!("http://127.0.0.1:{port}")),
            ("NO_PROXY", "example.org, .test".to_string()),
        ],
    );
    assert!(!direct.status.success());
    assert_eq!(proxy.requests().len(), before, "{:?}", proxy.requests());
}

/// A proxy that accepts the connection and never answers times out. The
/// retried failure fails the sync at the first repository rather than let
/// the next one stand in, and the hint names the proxy and its variable.
#[test]
fn a_silent_proxy_times_out_with_a_hint() {
    let (project, home) = project();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    {
        let accepted = Arc::clone(&accepted);
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for mut stream in listener.incoming().flatten() {
                accepted.fetch_add(1, Ordering::SeqCst);
                let _ = stream.read(&mut [0u8; 4096]);
                held.push(stream);
            }
        });
    }
    let output = sync(
        &project,
        &home,
        &[
            ("HTTP_PROXY", format!("127.0.0.1:{port}")),
            ("RAEVA_TIMEOUT", "1".to_string()),
            ("RAEVA_RETRIES", "1".to_string()),
        ],
    );
    let envelope = envelope(&output);
    assert_eq!(envelope["code"], "NETWORK", "{envelope}");
    let error = envelope["error"].as_str().expect("error");
    assert!(
        error.contains("http://repo.test/") && !error.contains("second.test"),
        "{error}"
    );
    let hints = envelope["hints"].to_string();
    assert!(
        hints.contains(&format!("127.0.0.1:{port} from {}", named("HTTP_PROXY")))
            && hints.contains("NO_PROXY"),
        "{hints}"
    );
    assert!(accepted.load(Ordering::SeqCst) >= 2);
    assert!(!project.path().join("raeva.lock").exists());
}

/// A value raeva cannot use stops the sync with the variable's name and
/// without its text.
#[test]
fn an_unsupported_proxy_variable_is_refused() {
    let (project, home) = project();
    for (name, value) in [
        ("HTTPS_PROXY", "socks5://user:s3cret@127.0.0.1:1080"),
        ("HTTP_PROXY", "https://user:s3cret@127.0.0.1:3128"),
    ] {
        let output = sync(&project, &home, &[(name, value.to_string())]);
        let envelope = envelope(&output);
        assert_eq!(envelope["exit_code"], 3, "{envelope}");
        let text = envelope.to_string();
        let name = named(name);
        assert!(text.contains(&name) && !text.contains("s3cret"), "{text}");
        // A proxy is not a repository.
        let error = envelope["error"].as_str().unwrap();
        assert!(
            error.starts_with(&format!("invalid configuration: {name}: ")),
            "{error}"
        );
    }
    let output = sync(
        &project,
        &home,
        &[
            ("HTTP_PROXY", "127.0.0.1:3128".to_string()),
            (
                "NO_PROXY",
                ".test, http://user:s3cret@proxy:3128".to_string(),
            ),
        ],
    );
    let text = envelope(&output).to_string();
    assert!(
        text.contains(&named("NO_PROXY")) && text.contains("entry 2 ") && !text.contains("s3cret"),
        "{text}"
    );
}

/// A proxy config.toml names gets hints that name it and its file, not
/// the proxy variables, which raeva does not read while a file names one.
#[test]
fn a_configured_proxy_is_named_in_the_hints() {
    let (project, home) = project();
    let write_proxy = |port: u16| {
        std::fs::write(
            home.path().join("config.toml"),
            format!("[[proxies]]\nhost = \"127.0.0.1\"\nport = {port}\n"),
        )
        .expect("write config.toml");
    };
    let proxy = library_proxy();
    let port = proxy.addr().port();
    write_proxy(port);
    let output = sync(&project, &home, &[]);
    assert_eq!(envelope(&output)["code"], "PROXY_AUTH", "{output:?}");
    let given = hints(&output);
    assert!(
        given.contains(&format!(
            "The proxy is 127.0.0.1:{port}, from config.toml or settings.xml; give its \
             credentials in that entry"
        )),
        "{given}"
    );

    let refusing = rv_test_support::net::RefusingPort::bind();
    let port = refusing.addr().port();
    write_proxy(port);
    let output = sync(&project, &home, &[]);
    assert_eq!(envelope(&output)["code"], "NETWORK", "{output:?}");
    let given = hints(&output);
    assert!(
        given.contains(&format!(
            "raeva connects through the proxy 127.0.0.1:{port}, from config.toml or settings.xml"
        )) && !given.contains("set HTTPS_PROXY"),
        "{given}"
    );
}
