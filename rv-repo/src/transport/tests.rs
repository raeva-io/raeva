use std::collections::HashSet;
use std::io::Write;
use std::net::{IpAddr, TcpListener as StdTcpListener};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use reqwest::dns::Resolve;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rv_test_support::http::{Response, StubServer};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use url::Url;

use super::guard::*;
use super::*;
use crate::error::{RedirectRejectionKind, RepoError, Result};
use crate::fetch::{FetchConfig, fetch_bytes};

// Self-signed localhost certificate used only by the in-process redirect
// stubs. The reqwest clients below opt into accepting it.
const TEST_CERT_DER: &str = "308201993082013fa00302010202142edbe5ec174441664b0b0f3b828a97fe31e81747300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f7374301e170d3236303732343233343131335a170d3336303732313233343131335a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d03010703420004325fb4c3e179b836c763009e555ff7709191f1fec299a00a5cfb7a34d99fe02e9c346670096f9bd5c4a8b3d2acf3b1894646cb99f04584a20f3492fd8e99cc4ba36f306d301d0603551d0e04160414730484bd1929ef7f056e4256368807a07197a43c301f0603551d23041830168014730484bd1929ef7f056e4256368807a07197a43c300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300a06082a8648ce3d040302034800304502210099131112ae00cf55f0d34b1283ced2c520d4d9c029dfe2ccafc327456953de66022029cbd4d385d2d1d11fd11550073ccfaf8a1c6d2e6febe89f9439c928b33c78fe";
const TEST_KEY_DER: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104200e9f9cb30589ef41f37a668cc1928b38f76ca3c443feb73aef12380ccac2f9a9a14403420004325fb4c3e179b836c763009e555ff7709191f1fec299a00a5cfb7a34d99fe02e9c346670096f9bd5c4a8b3d2acf3b1894646cb99f04584a20f3492fd8e99cc4b";

struct HttpsStub {
    addr: std::net::SocketAddr,
    request: Arc<Mutex<Option<String>>>,
}

impl HttpsStub {
    fn url(&self, path: &str) -> Url {
        url(&format!("https://127.0.0.1:{}{path}", self.addr.port()))
    }

    fn contacted(&self) -> bool {
        self.request.lock().unwrap().is_some()
    }
}

/// Answers one HTTPS request with `handler`'s bytes.
fn spawn_https_stub(handler: impl Fn(&str) -> Vec<u8> + Send + 'static) -> HttpsStub {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = CertificateDer::from(hex::decode(TEST_CERT_DER).unwrap());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(hex::decode(TEST_KEY_DER).unwrap()));
    let tls = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let request = Arc::new(Mutex::new(None));
    let captured = Arc::clone(&request);
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let connection = rustls::ServerConnection::new(tls).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, stream);
        let bytes = rv_test_support::http::read_request_head_blocking(&mut stream).unwrap();
        let raw_request = String::from_utf8_lossy(&bytes).into_owned();
        *captured.lock().unwrap() = Some(raw_request.clone());
        stream.write_all(&handler(&raw_request)).unwrap();
        stream.flush().unwrap();
    });
    HttpsStub { addr, request }
}

fn redirect_response(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// A stub that redirects its one request to `location`.
fn redirecting(location: impl ToString) -> HttpsStub {
    let location = location.to_string();
    spawn_https_stub(move |_| redirect_response(&location))
}

/// A guard for a configuration that named exactly these origins. Mirrors
/// `redirect_guard`: naming an origin also exempts its host from the
/// address screen.
fn origins_guard(origins: HashSet<String>) -> RedirectGuard {
    let exempt_hosts: Vec<String> = origins
        .iter()
        .filter_map(|origin| Url::parse(origin).ok())
        .filter_map(|origin| origin.host_str().map(str::to_string))
        .collect();
    RedirectGuard {
        origins,
        root_issuer: None,
        exempt_hosts: ConfiguredHosts::new(exempt_hosts),
        proxies: ProxySet::default(),
    }
}

fn redirect_test_client(trusted_origins: HashSet<String>) -> reqwest::Client {
    rv_http::client_builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .redirect(trusted_redirect_policy(origins_guard(trusted_origins)))
        .build()
        .unwrap()
}

fn url(raw: &str) -> Url {
    Url::parse(raw).unwrap()
}

fn origin_set<const N: usize>(raw: [&str; N]) -> HashSet<String> {
    raw.iter()
        .map(|value| url(value).origin().ascii_serialization())
        .collect()
}

fn frozen_hosts<const N: usize>(raw: [&str; N]) -> ConfiguredHosts {
    ConfiguredHosts::new(raw.iter().map(|host| host.to_string()))
}

fn repo(url: impl ToString) -> Repository {
    Repository::new(None, url.to_string(), true, false)
}

async fn fetch_redirect_test(client: &reqwest::Client, url: &Url) -> Result<Bytes> {
    let config = FetchConfig {
        retries: 0,
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    fetch_bytes(client, url, None, None, &config, None).await
}

async fn fetch_via(client: &ClientSet, url: &Url) -> Result<Bytes> {
    fetch_redirect_test(client.client_for(url).unwrap().as_ref(), url).await
}

#[track_caller]
fn assert_rejected(result: &Result<Bytes>, expected: RedirectRejectionKind) {
    let rejected =
        matches!(result, Err(RepoError::RedirectRejected { kind, .. }) if *kind == expected);
    assert!(rejected, "{result:?}");
}

/// A set wired the way [`ClientSet::build`] wires one: a redirect-capable
/// client screening against the frozen configured set, and a
/// same-origin-only client screening against the live runtime set that
/// `trust_repositories` grows.
fn screened_test_client(guard: RedirectGuard) -> ClientSet {
    let options = BuildOptions {
        accept_invalid_certs: true,
    };
    ClientSet::from_guard(guard, crate::proxy::ProxySet::default(), options)
}

/// `localhost` stands in for `nexus.corp.internal`: a name that resolves
/// onto an address the screen rejects. Only a name exercises the resolver;
/// an IP literal never reaches one.
fn loopback_name_url(port: u16, path: &str) -> Url {
    url(&format!("https://localhost:{port}{path}"))
}

/// A cross-origin redirect, through a configured pair or from a root-POM
/// grant, drops the credential and cookie the source received.
#[tokio::test]
async fn cross_origin_redirect_strips_sensitive_headers() {
    for root in [false, true] {
        let target = spawn_https_stub(|_| ok_response(b"artifact bytes"));
        let target_url = target.url("/artifact");
        let source = redirecting(&target_url);
        let source_url = source.url("/start");
        let client = if root {
            let client = screened_test_client(origins_guard(origin_set([target_url.as_str()])));
            client.trust_root_repositories(&[repo(&source_url)]);
            client.client_for(&source_url).unwrap().into_owned()
        } else {
            redirect_test_client(origin_set([source_url.as_str(), target_url.as_str()]))
        };
        let response = client
            .get(source_url)
            .bearer_auth("registry-secret")
            .header(reqwest::header::COOKIE, "session=private")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.bytes().await.unwrap(),
            Bytes::from_static(b"artifact bytes")
        );
        let at_source = source
            .request
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .to_ascii_lowercase();
        assert!(at_source.contains("authorization: bearer registry-secret"));
        let at_target = target
            .request
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .to_ascii_lowercase();
        assert!(!at_target.contains("authorization:") && !at_target.contains("cookie:"));
    }
}

/// The policy decisions that need no network. A root-POM issuer keeps the
/// HTTPS, hop and address limits. A configured host's DNS exemption is
/// host-level, so a redirect to it must still match the configured origin;
/// a proxy host's exemption makes it dialable, not a redirect target. With
/// a proxy active the proxy resolves names, so a hostname hop is followed
/// only to a configured origin, and IP literals are still screened.
#[test]
fn redirect_guard_decisions() {
    use RedirectRejectionKind::*;
    let root = url("https://root.example/repository/artifact");
    let storage = url("https://storage.example/artifact");
    let mut root_guard = origins_guard(HashSet::new());
    root_guard.root_issuer = Some(root.origin().ascii_serialization());
    let mut insecure_root = origins_guard(HashSet::new());
    insecure_root.root_issuer = Some("http://root.example".into());
    let exempt = RedirectGuard {
        root_issuer: None,
        origins: origin_set(["https://mirror.example", "https://nexus.corp"]),
        exempt_hosts: frozen_hosts(["mirror.example", "nexus.corp", "proxy.corp"]),
        proxies: ProxySet::default(),
    };
    let proxied = RedirectGuard {
        root_issuer: None,
        origins: origin_set(["https://mirror.example", "https://cdn.example"]),
        exempt_hosts: frozen_hosts(["mirror.example", "cdn.example", "proxy.corp"]),
        proxies: ProxySet::new(&[rv_config::ProxyConfig::new("proxy.corp", 3128)]).unwrap(),
    };
    // Guard, previous hops, target, and the rejection, if any. An unexempt
    // name is left to the resolver.
    let cases = "\
        root  R                      https://storage.example/artifact         -
        root  https://dependency.example/a S                                  OriginNotConfigured
        root  https://root.example:8443/a  S                                  OriginNotConfigured
        root  R                      http://storage.example/artifact          HttpsDowngrade
        root  R,S                    https://another.example/a                SecondCrossOriginHop
        root  R                      https://127.0.0.1/secret                 NonGlobalTarget
        http  http://root.example/artifact S                                  InsecureOrigin
        exempt M                     https://nexus.corp:8443/demo-1.0.jar     ExemptHostOriginMismatch
        exempt M                     https://proxy.corp/demo-1.0.jar          ExemptHostOriginMismatch
        exempt M                     https://nexus.corp/demo-1.0.jar          -
        exempt M                     https://cdn.example/demo-1.0.jar         -
        proxy M                      https://admin.internal/                  ProxiedTargetNotConfigured
        proxy M                      https://cdn.example:8443/demo-1.0.jar    ProxiedTargetNotConfigured
        proxy M                      https://elsewhere.example/demo-1.0.jar   ProxiedTargetNotConfigured
        proxy M                      https://proxy.corp/demo-1.0.jar          ProxiedTargetNotConfigured
        proxy M                      https://cdn.example/demo-1.0.jar         -
        proxy M                      https://93.184.216.34/demo-1.0.jar       -
        proxy M                      https://169.254.169.254/latest/meta-data NonGlobalTarget";
    let expand = |raw: &str| match raw {
        "R" => root.clone(),
        "S" => storage.clone(),
        "M" => url("https://mirror.example/demo-1.0.jar"),
        raw => url(raw),
    };
    for case in cases.lines() {
        let [guard, previous, target, expected] = case.split_whitespace().collect::<Vec<_>>()[..]
        else {
            panic!("{case}");
        };
        let guard = match guard {
            "root" => &root_guard,
            "http" => &insecure_root,
            "exempt" => &exempt,
            _ => &proxied,
        };
        let previous: Vec<Url> = previous.split(',').map(expand).collect();
        let target = expand(target);
        let decision = guard.evaluate(&previous, &target);
        let kind = decision.as_ref().err().map(|r| format!("{:?}", r.kind));
        assert_eq!(kind.as_deref().unwrap_or("-"), expected, "{case}");
        if let Err(rejection) = decision
            && matches!(rejection.kind, ExemptHostOriginMismatch | InsecureOrigin)
        {
            let details = rejection.details;
            assert!(details.contains(target.host_str().unwrap()), "{details}");
        }
    }
}

/// Redirect authority comes from configuration or a root-POM grant, never
/// from a transitive declaration, and a later root grant does not widen
/// the DNS screen of a client already built.
#[tokio::test]
async fn transitive_grant_does_not_authorize_redirects_but_root_grant_does() {
    for root in [false, true] {
        let target = spawn_https_stub(|_| ok_response(b"artifact bytes"));
        let target_url = loopback_name_url(target.addr.port(), "/artifact");
        let source = redirecting(&target_url);
        let source_url = source.url("/repo/");
        let client = screened_test_client(origins_guard(origin_set([target_url.as_str()])));
        // A transitive declaration encountered first must not prevent a
        // later root declaration from granting trust to the same endpoint.
        client.trust_repositories(&[repo(&source_url)]);
        if root {
            client.trust_root_repositories(&[repo(&source_url)]);
        }
        let result = fetch_via(&client, &source_url).await;
        if root {
            assert_eq!(result.unwrap(), Bytes::from_static(b"artifact bytes"));
        } else {
            assert_rejected(&result, RedirectRejectionKind::OriginNotConfigured);
            assert!(!target.contacted());
        }
    }

    let client = screened_test_client(origins_guard(HashSet::new()));
    let source = url("https://root.example/repository/");
    client.trust_root_repositories(&[repo(&source)]);
    let http = client.client_for(&source).unwrap();
    let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let target_url = loopback_name_url(target.addr.port(), "/secret");
    client.trust_root_repositories(&[repo(&target_url)]);
    let result = fetch_redirect_test(&http, &target_url).await;
    assert_rejected(&result, RedirectRejectionKind::NonGlobalTarget);
    assert!(!target.contacted());
}

/// A configured issuer cannot send raeva to a non-global literal or over plain
/// HTTP, or a second cross-origin hop away; an unconfigured one cannot
/// redirect at all. The refused target is never contacted.
#[tokio::test]
async fn redirect_rejections_end_to_end() {
    use RedirectRejectionKind::*;
    let loopback = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let plain = StubServer::start(|_| Response::new(200, b"no"));
    let mut cases = vec![(loopback.url("/artifact").to_string(), NonGlobalTarget, "")];
    for literal in [
        "https://169.254.169.254/latest/meta-data",
        "https://[::ffff:10.0.0.1]/a",
        "https://[fd00::1]/a",
    ] {
        cases.push((literal.to_string(), NonGlobalTarget, ""));
    }
    cases.push((
        format!("http://{}/artifact", plain.addr()),
        HttpsDowngrade,
        "target is not HTTPS",
    ));
    for (target, kind, message) in cases {
        let source = redirecting(&target);
        let source_url = source.url("/start");
        let client = redirect_test_client(origin_set([source_url.as_str()]));
        let result = fetch_redirect_test(&client, &source_url).await;
        assert_rejected(&result, kind);
        assert!(result.unwrap_err().to_string().contains(message));
    }
    assert!(!loopback.contacted());
    assert_eq!(plain.connections(), 0);

    let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let source = redirecting(target.url("/artifact"));
    let source_url = source.url("/start");
    let result = fetch_redirect_test(&redirect_test_client(HashSet::new()), &source_url).await;
    assert_rejected(&result, OriginNotConfigured);
    let origin = source_url.origin().ascii_serialization();
    assert!(result.unwrap_err().to_string().contains(&origin));
    assert!(!target.contacted());

    // The middle origin is configured so the first hop clears the address
    // guard and the second hop is what fails.
    let last = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let middle = redirecting(last.url("/artifact"));
    let first = redirecting(middle.url("/middle"));
    let first_url = first.url("/start");
    let client = redirect_test_client(origin_set([first_url.as_str(), middle.url("/").as_str()]));
    let result = fetch_redirect_test(&client, &first_url).await;
    assert_rejected(&result, SecondCrossOriginHop);
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("second cross-origin hop")
    );
    assert!(middle.contacted() && !last.contacted());
}

/// Minimal CONNECT-capable stub proxy. Records each request head it
/// accepts and tunnels CONNECT through to the real (loopback) address, so a
/// permitted hop can still complete. An absolute-form GET is answered
/// `proxied` with no upstream.
async fn spawn_recording_proxy() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&heads);
    tokio::spawn(async move {
        while let Ok((mut downstream, _)) = listener.accept().await {
            let recorder = Arc::clone(&recorder);
            tokio::spawn(async move {
                let Some(head) = rv_test_support::http::read_request_head(&mut downstream).await
                else {
                    return;
                };
                let request = String::from_utf8_lossy(&head).into_owned();
                recorder.lock().unwrap().push(request.clone());
                let authority = request
                    .strip_prefix("CONNECT ")
                    .and_then(|rest| rest.split_whitespace().next());
                let Some(authority) = authority else {
                    let _ = downstream.write_all(&ok_response(b"proxied")).await;
                    return;
                };
                let Ok(mut upstream) = tokio::net::TcpStream::connect(authority).await else {
                    let _ = downstream
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        .await;
                    return;
                };
                if downstream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_ok()
                {
                    let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                }
            });
        }
    });
    (addr, heads)
}

fn proxied_set(origins: HashSet<String>, proxies: crate::proxy::ProxySet) -> ClientSet {
    let guard = RedirectGuard {
        origins,
        root_issuer: None,
        exempt_hosts: frozen_hosts(["127.0.0.1"]),
        proxies: proxies.clone(),
    };
    let options = BuildOptions {
        accept_invalid_certs: true,
    };
    ClientSet::from_guard(guard, proxies, options)
}

/// Proxy credentials go to the proxy and nowhere else: for an HTTPS URL
/// they ride the CONNECT, never the request inside the tunnel; for a plain
/// URL the proxy gets the request itself; and a request that
/// `non_proxy_hosts` sends direct carries none.
#[tokio::test]
async fn proxy_credentials_reach_only_the_proxy() {
    for (https, bearer, bypass) in [
        (true, false, false),
        (true, true, false),
        (true, false, true),
        (false, false, false),
        (false, false, true),
    ] {
        let (proxy_addr, heads) = spawn_recording_proxy().await;
        let tls_origin = spawn_https_stub(|_| ok_response(b"direct"));
        let plain_origin = StubServer::start(|_| Response::new(200, b"direct".to_vec()));
        let origin_url = if https {
            tls_origin.url("/a.jar")
        } else {
            url(&format!("http://{}/a.jar", plain_origin.addr()))
        };
        let mut proxy = rv_config::ProxyConfig::new("127.0.0.1", proxy_addr.port());
        proxy.protocol = Some("all".to_string());
        let secret = || Some(secrecy::SecretString::from("proxy-secret".to_string()));
        if bearer {
            proxy.auth_type = Some(rv_config::ProxyAuthType::Bearer);
            proxy.token = secret();
        } else {
            proxy.username = Some("proxy-user".to_string());
            proxy.password = secret();
        }
        if bypass {
            proxy.non_proxy_hosts = vec!["127.0.0.1".to_string()];
        }
        let proxies = crate::proxy::ProxySet::new(&[proxy]).unwrap();
        let client = proxied_set(origin_set([origin_url.as_str()]), proxies);
        let bytes = fetch_via(&client, &origin_url).await.unwrap();
        let heads = heads.lock().unwrap().clone();
        let proxy_answered = !https && !bypass;
        assert_eq!(
            bytes.as_ref(),
            if proxy_answered {
                b"proxied".as_slice()
            } else {
                b"direct"
            }
        );
        if bypass {
            assert!(heads.is_empty(), "a bypassed request skips the proxy");
        } else {
            assert_eq!(heads.len(), 1, "{heads:?}");
            let line = if https {
                "CONNECT ".to_string()
            } else {
                format!("GET {origin_url} ")
            };
            assert!(heads[0].starts_with(&line), "{heads:?}");
            // `cHJveHktdXNlcjpwcm94eS1zZWNyZXQ=` is `proxy-user:proxy-secret`.
            let expected = if bearer {
                "proxy-authorization: Bearer proxy-secret"
            } else {
                "proxy-authorization: Basic cHJveHktdXNlcjpwcm94eS1zZWNyZXQ="
            };
            assert!(heads[0].contains(expected), "{heads:?}");
        }
        let at_origin = if https {
            tls_origin
                .request
                .lock()
                .unwrap()
                .clone()
                .into_iter()
                .collect()
        } else {
            plain_origin
                .requests()
                .into_iter()
                .map(|r| r.raw)
                .collect::<Vec<_>>()
        };
        assert_eq!(at_origin.len(), usize::from(!proxy_answered));
        for raw in at_origin.iter().map(|raw| raw.to_ascii_lowercase()) {
            assert!(
                !raw.contains("authorization") && !raw.contains("proxy-secret"),
                "{raw}"
            );
        }
    }
}

#[test]
fn redirect_guard_uses_the_targets_proxy_route() {
    let issuer = url("https://repo.example/a.jar");
    let target = url("https://storage.example/a.jar?signature=secret");
    for (protocol, bypass, carried) in [
        ("https", true, false),
        ("https", false, true),
        ("http", true, false),
        // Maven falls back to an HTTP proxy for HTTPS targets.
        ("http", false, true),
    ] {
        let mut proxy = rv_config::ProxyConfig::new("proxy.corp", 3128);
        proxy.protocol = Some(protocol.into());
        if bypass {
            proxy.non_proxy_hosts = vec!["*.STORAGE.EXAMPLE".into()];
        }
        let mut guard = origins_guard(origin_set([issuer.as_str()]));
        guard.proxies = ProxySet::new(&[proxy]).unwrap();
        assert_eq!(guard.proxies.carries(&target), carried);
        let decision = guard.evaluate(std::slice::from_ref(&issuer), &target);
        if carried {
            let error = decision.unwrap_err();
            assert_eq!(
                error.kind,
                RedirectRejectionKind::ProxiedTargetNotConfigured
            );
            assert!(!error.details.contains("signature") && !error.details.contains("secret"));
        } else {
            decision.unwrap();
            let private = url("https://127.0.0.1/a.jar");
            assert_eq!(
                guard
                    .evaluate(std::slice::from_ref(&issuer), &private)
                    .unwrap_err()
                    .kind,
                RedirectRejectionKind::NonGlobalTarget
            );
            // A direct hostname still reaches the DNS address screen.
            assert!(
                screen_resolved_addrs(
                    "storage.example",
                    false,
                    vec!["127.0.0.1:443".parse().unwrap()]
                )
                .is_err()
            );
        }
    }
}

fn environment_proxy_set(vars: &[(&str, &str)]) -> ProxySet {
    let vars: std::collections::HashMap<&str, &str> = vars.iter().copied().collect();
    let proxies = rv_config::environment_proxies(|name| vars.get(name).map(|v| v.to_string()))
        .expect("proxy variables");
    ProxySet::new(&proxies).expect("proxies")
}

/// The proxy variables take the guarded path of configured proxies: a
/// redirect target they carry must be a configured origin, one `NO_PROXY`
/// or the scheme sends direct meets the address screen, and `HTTP_PROXY`
/// does not carry `https:` URLs.
#[test]
fn environment_proxies_take_the_guarded_path() {
    let issuer = url("https://repo.example/a.jar");
    for (vars, target, carried) in [
        (
            &[("HTTPS_PROXY", "proxy.corp:3128")][..],
            "https://storage.example/a.jar",
            true,
        ),
        (
            &[
                ("HTTPS_PROXY", "proxy.corp:3128"),
                ("NO_PROXY", "storage.example"),
            ],
            "https://cdn.storage.example/a.jar",
            false,
        ),
        (
            &[("HTTP_PROXY", "proxy.corp:3128")],
            "https://storage.example/a.jar",
            false,
        ),
        (
            &[("HTTP_PROXY", "proxy.corp:3128")],
            "http://storage.example/a.jar",
            true,
        ),
    ] {
        let target = url(target);
        let mut guard = origins_guard(origin_set([issuer.as_str()]));
        guard.proxies = environment_proxy_set(vars);
        assert_eq!(guard.proxies.carries(&target), carried, "{vars:?} {target}");
        let decision = guard.evaluate(std::slice::from_ref(&issuer), &target);
        if target.scheme() == "http" {
            assert_eq!(
                decision.unwrap_err().kind,
                RedirectRejectionKind::HttpsDowngrade
            );
        } else if carried {
            assert_eq!(
                decision.unwrap_err().kind,
                RedirectRejectionKind::ProxiedTargetNotConfigured
            );
        } else {
            decision.unwrap();
            let private = url("https://127.0.0.1/a.jar");
            assert!(!guard.proxies.carries(&private));
            assert_eq!(
                guard
                    .evaluate(std::slice::from_ref(&issuer), &private)
                    .unwrap_err()
                    .kind,
                RedirectRejectionKind::NonGlobalTarget
            );
        }
    }
}

/// A request through `HTTP_PROXY` carries the URL's credentials to the
/// proxy only, and a 407 to the `CONNECT` of an `https:` URL is a proxy
/// refusal that is not retried.
#[tokio::test]
async fn environment_proxy_credentials_and_refusals() {
    let (proxy_addr, heads) = spawn_recording_proxy().await;
    let port = proxy_addr.port();
    let proxies = environment_proxy_set(&[(
        "http_proxy",
        &format!("http://proxy%2Duser:proxy%3Asecret@127.0.0.1:{port}"),
    )]);
    let client = proxied_set(origin_set(["http://repo.test"]), proxies);
    let target = url("http://repo.test/a.jar");
    let bytes = fetch_via(&client, &target).await.unwrap();
    assert_eq!(bytes.as_ref(), b"proxied");
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert!(
        heads[0].starts_with("GET http://repo.test/a.jar "),
        "{heads:?}"
    );
    // `cHJveHktdXNlcjpwcm94eTpzZWNyZXQ=` is `proxy-user:proxy:secret`.
    assert!(
        heads[0].contains("proxy-authorization: Basic cHJveHktdXNlcjpwcm94eTpzZWNyZXQ="),
        "{heads:?}"
    );

    // hyper-util tells a 407 apart only in an HTTP/1.1 answer.
    for (answer, message, moves_on) in [
        (
            &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
            "HTTPS_PROXY",
            true,
        ),
        (
            b"HTTP/1.0 407 Proxy Authentication Required\r\n\r\n",
            "refused the tunnel",
            false,
        ),
        (
            b"HTTP/1.1 403 Forbidden\r\n\r\n",
            "refused the tunnel",
            false,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connects = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&connects);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = rv_test_support::http::read_request_head(&mut stream).await;
                let _ = stream.write_all(answer).await;
            }
        });
        let proxies = environment_proxy_set(&[("HTTPS_PROXY", &format!("127.0.0.1:{port}"))]);
        let client = proxied_set(origin_set(["https://repo.test"]), proxies);
        let target = url("https://repo.test/a.jar");
        let config = FetchConfig {
            retries: 3,
            timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let error = fetch_bytes(
            client.client_for(&target).unwrap().as_ref(),
            &target,
            None,
            None,
            &config,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.class(), crate::ErrorClass::ProxyAuth, "{error}");
        assert!(
            !error.is_transient()
                && error.moves_to_next_repository() == moves_on
                && error.to_string().contains(message),
            "{error}"
        );
        assert_eq!(connects.load(Ordering::SeqCst), 1);
    }
}

/// Every IPv4 special-purpose block at both edges, then the routable
/// addresses just outside each. The neighbours are the point: an off-by-one
/// in a mask either opens a private range or blackholes a public one.
#[test]
fn ipv4_special_purpose_blocks_are_excluded() {
    let excluded = "0.0.0.0 0.255.255.255 10.0.0.0 10.255.255.255 100.64.0.0 100.127.255.255 \
         127.0.0.0 127.255.255.255 169.254.0.0 169.254.169.254 172.16.0.0 \
         172.31.255.255 192.0.0.0 192.0.0.255 192.0.2.0 192.0.2.255 192.88.99.0 \
         192.88.99.255 192.168.0.0 192.168.255.255 198.18.0.0 198.19.255.255 \
         198.51.100.0 198.51.100.255 203.0.113.0 203.0.113.255 224.0.0.0 \
         239.255.255.255 240.0.0.0 255.255.255.255";
    let global = "1.0.0.0 9.255.255.255 11.0.0.0 100.63.255.255 100.128.0.0 126.255.255.255 \
         128.0.0.1 169.253.255.255 169.255.0.0 172.15.255.255 172.32.0.0 \
         191.255.255.255 192.0.1.0 192.0.1.255 192.0.3.0 192.88.98.255 192.88.100.0 \
         192.167.255.255 192.169.0.0 198.17.255.255 198.20.0.0 198.51.99.255 \
         198.51.101.0 203.0.112.255 203.0.114.0 223.255.255.255 1.1.1.1 8.8.8.8 \
         93.184.216.34";
    assert_routability(excluded, global);
}

/// The IPv6 half, plus the embedded-IPv4 forms that would otherwise
/// launder an RFC1918 destination through a v6 literal. A DNS64 network
/// answers with `64:ff9b::/96` for every public destination, so that prefix
/// must stay usable for public addresses.
#[test]
fn ipv6_special_purpose_blocks_are_excluded() {
    let excluded = ":: ::1 100:: 100::ffff:ffff:ffff:ffff 100:0:0:1:: \
         100:0:0:1:ffff:ffff:ffff:ffff 64:ff9b:1:: 64:ff9b:1:ffff:ffff:ffff:ffff:ffff \
         2001:: 2001:1::1 2001:2::1 2001:20::1 2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff \
         2001:db8:: 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff 2002:: 2002:a00:1::1 \
         2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff 3fff:: \
         3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff 5f00:: \
         5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff fc00::1 fd00::1 \
         fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff fe80::1 \
         febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff fec0::1 \
         feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ff02::1 ff05::1:3 ::ffff:10.0.0.1 \
         ::ffff:127.0.0.1 ::ffff:169.254.169.254 ::ffff:0.0.0.1 ::10.0.0.1 \
         64:ff9b::10.0.0.1 64:ff9b::169.254.169.254";
    let global = "100:0:0:2::1 101::1 64:ff9b:2::1 2000::1 2001:200::1 2001:db7::1 2001:db9::1 \
         2003::1 3ffe::1 3fff:1000::1 5eff:ffff::1 5f01::1 fbff:ffff::1 \
         2606:4700:4700::1111 2a00:1450:4001:80e::200e 64:ff9b::8.8.8.8 ::ffff:8.8.8.8";
    assert_routability(excluded, global);
}

fn assert_routability(excluded: &str, global: &str) {
    for (addresses, routable) in [(excluded, false), (global, true)] {
        for address in addresses.split_whitespace() {
            let address: IpAddr = address.parse().unwrap();
            assert_eq!(is_globally_routable(address), routable, "{address}");
        }
    }
}

/// The resolver screen keeps a public answer, rejects a rebinding answer
/// that mixes in a private address wholesale (the connector would still
/// reach it), and passes a configured host's private answer.
#[tokio::test]
async fn dns_screen_rejects_any_non_global_answer_unless_exempt() {
    let public = vec![
        "8.8.8.8:443".parse().unwrap(),
        "[2606:4700:4700::1111]:443".parse().unwrap(),
    ];
    assert_eq!(
        screen_resolved_addrs("cdn.example.com", false, public.clone()).unwrap(),
        public
    );
    let mixed = vec![
        "8.8.8.8:443".parse().unwrap(),
        "169.254.169.254:443".parse().unwrap(),
    ];
    let error = screen_resolved_addrs("rebind.example.com", false, mixed).unwrap_err();
    assert_eq!(error.kind, RedirectRejectionKind::NonGlobalTarget);
    assert!(
        error.details.contains("169.254.169.254"),
        "{}",
        error.details
    );
    let private = vec!["10.1.2.3:8443".parse().unwrap()];
    assert_eq!(
        screen_resolved_addrs("nexus.corp.internal", true, private.clone()).unwrap(),
        private
    );

    let resolver = GlobalOnlyResolver {
        exempt_hosts: TrustedHosts::default(),
    };
    let error = resolver
        .resolve("localhost".parse().unwrap())
        .await
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("not globally routable"),
        "{error}"
    );
    let exempt = TrustedHosts::default();
    exempt.insert("localhost");
    let resolver = GlobalOnlyResolver {
        exempt_hosts: exempt,
    };
    assert!(
        resolver
            .resolve("localhost".parse().unwrap())
            .await
            .unwrap()
            .count()
            > 0
    );
}

/// Only an origin `raeva.toml` named is served by the redirect-capable client;
/// no trust grant moves an origin onto it, and a granted origin moves to
/// the runtime client. A request to a proxy host on a port no proxy carries
/// goes out direct, without the proxy host's exemption.
#[test]
fn client_routing_follows_configuration_and_grants() {
    let client = screened_test_client(origins_guard(origin_set(["https://mirror.example"])));
    let routed = |client: &ClientSet, raw: &str| {
        let chosen = client.client_for(&url(raw)).unwrap();
        let chosen: *const reqwest::Client = chosen.as_ref();
        let clients = client.clients.get().unwrap();
        [
            &clients.configured,
            &clients.screened,
            &clients.runtime,
            &clients.direct,
        ]
        .iter()
        .position(|candidate| std::ptr::eq(*candidate, chosen))
        .unwrap()
    };
    let (configured, screened, runtime, direct) = (0, 1, 2, 3);
    let nexus = "https://nexus.corp.internal/demo-1.0.jar";
    for (raw, expected) in [
        ("https://mirror.example/demo-1.0.jar", configured),
        ("https://mirror.example:8443/demo-1.0.jar", screened),
        (nexus, screened),
    ] {
        assert_eq!(routed(&client, raw), expected, "{raw}");
    }
    client.trust_repositories(&[repo("https://nexus.corp.internal/repo/")]);
    assert_eq!(routed(&client, nexus), runtime);
    assert!(client.trusts_origin(&url("https://nexus.corp.internal/")));
    assert_eq!(
        routed(&client, "http://nexus.corp.internal/x.jar"),
        screened
    );

    let mut proxy = rv_config::ProxyConfig::new("proxy.corp", 3128);
    proxy.protocol = Some("https".to_string());
    let proxies = crate::proxy::ProxySet::new(&[proxy]).unwrap();
    let guard = RedirectGuard {
        exempt_hosts: frozen_hosts(["proxy.corp"]),
        proxies: proxies.clone(),
        ..RedirectGuard::default()
    };
    let client = ClientSet::from_guard(guard, proxies, BuildOptions::default());
    assert_eq!(routed(&client, "http://proxy.corp:6379/a.pom"), direct);
    assert_eq!(routed(&client, "https://proxy.corp:8443/a.pom"), screened);
    assert_eq!(routed(&client, "http://repo.example/a.pom"), screened);
    // The proxy would resolve a loopback name on its side, out of the
    // resolver's reach.
    for raw in [
        "https://localhost:8080/a.pom",
        "https://nexus.LOCALHOST./a.pom",
    ] {
        let refused = client.client_for(&url(raw));
        assert!(
            matches!(refused, Err(RepoError::NonGlobalAddress { .. })),
            "{raw}"
        );
    }
    assert_eq!(routed(&client, "http://localhost:8080/a.pom"), screened);
}

/// A private hostname nothing trusts fails the address screen before any
/// connection. Configuring it, or a root POM declaring it part-way through
/// a resolve, lets the running client fetch from it without a rebuild, but
/// trust for one port does not reach another port on the same host.
#[tokio::test]
async fn trust_admits_one_private_origin_and_not_its_other_ports() {
    for configured in [false, true] {
        let trusted = spawn_https_stub(|_| ok_response(b"artifact bytes"));
        let other = spawn_https_stub(|_| ok_response(b"must not arrive"));
        let trusted_url = loopback_name_url(trusted.addr.port(), "/demo-1.0.jar");
        let other_url = loopback_name_url(other.addr.port(), "/demo-1.0.jar");
        let client = if configured {
            screened_test_client(origins_guard(origin_set([trusted_url.as_str()])))
        } else {
            let client = screened_test_client(origins_guard(HashSet::new()));
            let result = fetch_via(&client, &trusted_url).await;
            assert_rejected(&result, RedirectRejectionKind::NonGlobalTarget);
            assert!(!trusted.contacted());
            client.trust_repositories(&[repo(loopback_name_url(trusted.addr.port(), "/repo/"))]);
            let upper = url(&format!("https://LOCALHOST:{}/", trusted.addr.port()));
            assert!(client.trusts_origin(&upper), "the grant is case-blind");
            client
        };
        let bytes = fetch_via(&client, &trusted_url).await.unwrap();
        assert_eq!(bytes, Bytes::from_static(b"artifact bytes"));
        let result = fetch_via(&client, &other_url).await;
        assert_rejected(&result, RedirectRejectionKind::NonGlobalTarget);
        assert!(!other.contacted());
    }
}

/// A hostile configured mirror redirects to a host nothing trusts yet; the
/// policy permits the hop because the resolver will screen it; then a
/// concurrent task trusts a repository on that host. The grant must not
/// retroactively license the hop: the redirect-capable client's resolver
/// reads the frozen configured set, which runtime trust cannot reach.
#[tokio::test]
async fn trust_granted_after_policy_evaluation_leaves_the_target_screened() {
    let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let target_url = loopback_name_url(target.addr.port(), "/secret");
    let source = redirecting(&target_url);
    let source_url = source.url("/start");
    let guard = origins_guard(origin_set([source_url.as_str()]));
    let client = screened_test_client(guard.clone());
    guard
        .evaluate(std::slice::from_ref(&source_url), &target_url)
        .expect("an unexempt hostname target is left to the resolver");
    client.trust_repositories(&[repo(loopback_name_url(target.addr.port(), "/repo/"))]);
    assert!(client.trusts_origin(&target_url));
    assert!(!guard.exempt_hosts.contains("localhost"));
    let resolver = GlobalOnlyResolver {
        exempt_hosts: guard.exempt_hosts.clone(),
    };
    let error = resolver
        .resolve("localhost".parse().unwrap())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("non-global address"), "{error}");
    let result = fetch_via(&client, &source_url).await;
    assert_rejected(&result, RedirectRejectionKind::NonGlobalTarget);
    assert!(!target.contacted());
}

/// The client for an unconfigured origin follows a redirect only within
/// that origin, such as `/foo` to `/foo/`, and caps a chain that loops.
/// Otherwise a hostile mirror could bounce raeva to another server.
#[tokio::test]
async fn same_origin_policy_follows_only_its_own_origin() {
    let client = rv_http::client_builder()
        .no_proxy()
        .redirect(same_origin_redirect_policy())
        .build()
        .unwrap();
    let target = StubServer::start(|_| Response::new(200, "hello"));
    let elsewhere = format!("http://{}/jar", target.addr());
    let source = StubServer::start(move |_| Response::new(302, "").header("Location", &elsewhere));
    let result = client
        .get(format!("http://{}/jar", source.addr()))
        .send()
        .await;
    assert!(result.is_err(), "{result:?}");
    assert_eq!(target.connections(), 0);

    let counter = AtomicU32::new(0);
    let server = StubServer::start(move |request| {
        if request.path == "/loop" {
            Response::new(302, "").header("Location", "/loop")
        } else if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            Response::new(302, "").header("Location", "/target")
        } else {
            Response::new(200, "ok")
        }
    });
    let start = url(&format!("http://{}/start", server.addr()));
    assert_eq!(
        fetch_redirect_test(&client, &start).await.unwrap().as_ref(),
        b"ok"
    );
    let looping = url(&format!("http://{}/loop", server.addr()));
    let result = fetch_redirect_test(&client, &looping).await;
    assert_rejected(&result, RedirectRejectionKind::ChainLimit);
}

/// An HTTP/2 server whose first connection answers one request, then stops
/// reading, as a connection does when a middlebox drops it. The others
/// answer every request. Returns its address and how many connections it
/// accepted.
async fn h2_server_that_freezes() -> (std::net::SocketAddr, Arc<AtomicU32>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicU32::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let first = count.fetch_add(1, Ordering::SeqCst) == 0;
            tokio::spawn(async move {
                let Ok(mut conn) = h2::server::handshake(socket).await else {
                    return;
                };
                let mut served = 0;
                while let Some(Ok((_, mut respond))) = conn.accept().await {
                    if first && served == 1 {
                        // Holding the connection unpolled answers no ping.
                        std::future::pending::<()>().await;
                    }
                    let head = http::Response::new(());
                    let mut body = respond.send_response(head, false).unwrap();
                    body.send_data(Bytes::from_static(b"ok"), true).unwrap();
                    served += 1;
                }
            });
        }
    });
    (addr, accepted)
}

/// Requests on an HTTP/2 connection that stops answering are retried on a
/// new connection within seconds, for metadata and artifacts alike, rather
/// than each attempt waiting out the request timeout on the dead one.
#[tokio::test]
async fn a_dead_http2_connection_is_replaced_quickly() {
    let client = BuildOptions::default()
        .builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let config = FetchConfig::default();
    let metadata = async {
        let (addr, accepted) = h2_server_that_freezes().await;
        let path = url(&format!("http://{addr}/g/a/maven-metadata.xml"));
        for _ in 0..2 {
            let body = fetch_bytes(&client, &path, None, None, &config, None).await;
            assert_eq!(body.unwrap().as_ref(), b"ok");
        }
        accepted.load(Ordering::SeqCst)
    };
    let artifact = async {
        let (addr, accepted) = h2_server_that_freezes().await;
        let dir = tempfile::tempdir().unwrap();
        let store = rv_store::Store::open(dir.path()).unwrap();
        let path = url(&format!("http://{addr}/g/a/1/a-1.jar"));
        for _ in 0..2 {
            let fetched = crate::fetch::fetch_artifact_into_store(
                &client,
                &path,
                None,
                None,
                &config,
                None,
                &store,
                crate::fetch::ArtifactChecks::default(),
            )
            .await;
            assert_eq!(fetched.unwrap().size, 2);
        }
        accepted.load(Ordering::SeqCst)
    };
    // Well under the 30 second request timeout an attempt would otherwise
    // wait out.
    let connections = tokio::time::timeout(
        Duration::from_secs(20),
        futures::future::join(metadata, artifact),
    )
    .await
    .expect("a dead connection must not hold requests for the request timeout");
    assert_eq!(connections, (2, 2));
}
