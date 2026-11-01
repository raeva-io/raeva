//! Which HTTP failures a retry can fix.

use reqwest::StatusCode;

use crate::{tls_cause, tls_failure_is_permanent};

/// Responses worth retrying: 429 and 503, which maven-resolver retries by
/// default, and 502 and 504, which a proxy or load balancer sends when the
/// server behind it is briefly unreachable. Other 5xx answers come from the
/// server itself and are not retried.
pub fn status_is_transient(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

/// Transport failures of the network rather than of the server's answer: a
/// timeout, a failed connection, or a request or response body that broke
/// off, unless TLS refused the server. [`transport_is_retryable`] says which
/// of them a retry may fix.
pub fn transport_is_transient(err: &reqwest::Error) -> bool {
    (err.is_timeout() || err.is_connect() || err.is_request() || err.is_body() || err.is_decode())
        && !tls_cause(err).is_some_and(tls_failure_is_permanent)
}

/// The transient failures worth retrying: all but an unreachable host and
/// a proxy that refused the tunnel.
pub fn transport_is_retryable(err: &reqwest::Error) -> bool {
    transport_is_transient(err) && !transport_is_unreachable(err) && tunnel_refusal(err).is_none()
}

/// How a proxy answered the `CONNECT` for an `https:` URL with something
/// other than 200.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRefusal {
    /// 407: the proxy wants credentials, or refused the ones sent.
    AuthRequired,
    /// Any other answer, such as a 403 for a host the proxy blocks.
    Refused,
}

/// The proxy's refusal behind `err`, if it is one. hyper-util does not export
/// its tunnel error, so it is recognised by its message.
pub fn tunnel_refusal(err: &reqwest::Error) -> Option<TunnelRefusal> {
    causes(err).find_map(|cause| match cause.to_string().as_str() {
        "tunnel error: proxy authorization required" => Some(TunnelRefusal::AuthRequired),
        "tunnel error: unsuccessful" => Some(TunnelRefusal::Refused),
        _ => None,
    })
}

/// What stopped a request that got no complete answer, in a few words: a
/// timeout, a failed host name lookup, a refused, reset or closed
/// connection, or else the innermost cause's own text. reqwest's message
/// leaves the cause out. `None` for a TLS failure, which
/// [`crate::describe_tls_failure`] describes, and for an error with no cause.
pub fn transport_detail(err: &reqwest::Error) -> Option<String> {
    use std::io::ErrorKind;
    if tls_cause(err).is_some() {
        return None;
    }
    if err.is_timeout() {
        let what = if err.is_connect() {
            "connection timed out"
        } else {
            "timed out"
        };
        return Some(what.to_string());
    }
    let innermost = crate::one_line(&causes(err).skip(1).last()?.to_string());
    let innermost = without_goaway_data(innermost);
    if err.is_dns() {
        // getaddrinfo's text repeats what the prefix says.
        let reason = innermost
            .strip_prefix("failed to lookup address information: ")
            .unwrap_or(&innermost);
        return Some(format!("host name lookup failed: {reason}"));
    }
    let kind =
        causes(err).find_map(|cause| cause.downcast_ref::<std::io::Error>().map(|io| io.kind()));
    Some(match kind {
        Some(ErrorKind::ConnectionRefused) => "connection refused".to_string(),
        Some(ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted) => {
            "connection reset".to_string()
        }
        Some(ErrorKind::UnexpectedEof) => {
            "connection closed before the whole response arrived".to_string()
        }
        _ => innermost,
    })
}

/// `text` without the debug data h2 appends to a GOAWAY's reason, in
/// parentheses: the server chooses it, and it may echo a credential.
fn without_goaway_data(text: String) -> String {
    match text.split_once(" (") {
        Some((reason, _)) if reason.starts_with("connection error ") => reason.to_string(),
        _ => text,
    }
}

/// `err` and the errors behind it, outermost first.
fn causes<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> {
    std::iter::successors(Some(err), |cause| cause.source())
}

/// A connection that failed before reaching a server: the host name did not
/// resolve, or the connection was refused or had no route. A retry seconds
/// later meets the same network, so it is not retried, as Maven's resolver
/// does not retry an unknown host or a refused connection. A temporary DNS
/// failure counts as one too. A connection that timed out, or that found no
/// free local port, is not one of these.
pub fn transport_is_unreachable(err: &reqwest::Error) -> bool {
    use std::io::ErrorKind;
    fn has_io(err: &reqwest::Error, pred: impl Fn(&std::io::Error) -> bool) -> bool {
        causes(err)
            .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
            .any(pred)
    }
    // hyper-util reports a failed lookup as `DnsError`. The address screen
    // also fails the lookup, with an error of its own and no `io::Error`,
    // which is a refusal, not this.
    if err.is_dns() {
        return has_io(err, |_| true);
    }
    if !err.is_connect() {
        return false;
    }
    has_io(err, |io| {
        matches!(
            io.kind(),
            ErrorKind::ConnectionRefused
                | ErrorKind::NetworkUnreachable
                | ErrorKind::HostUnreachable
                | ErrorKind::NetworkDown
                // hyper-util synthesizes this when DNS returns no addresses.
                | ErrorKind::NotConnected
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn failure(url: &str) -> reqwest::Error {
        crate::client_builder()
            .build()
            .unwrap()
            .get(url)
            .send()
            .await
            .unwrap_err()
    }

    #[test]
    fn a_goaway_leaves_out_its_debug_data() {
        for (text, shown) in [
            (
                "connection error received: not a result of an error (b\"token=s3cret\")",
                "connection error received: not a result of an error",
            ),
            (
                "connection error detected: frame size",
                "connection error detected: frame size",
            ),
            ("invalid header (x)", "invalid header (x)"),
        ] {
            assert_eq!(without_goaway_data(text.to_string()), shown);
        }
    }

    #[tokio::test]
    async fn an_unreachable_host_is_not_retried() {
        let refused = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            format!("http://127.0.0.1:{port}/")
        };
        for url in [refused.as_str(), "http://repo.nonexistent.invalid/"] {
            let err = failure(url).await;
            assert!(transport_is_unreachable(&err), "{url}: {err:?}");
            assert!(transport_is_transient(&err), "{url}: {err:?}");
            assert!(!transport_is_retryable(&err), "{url}: {err:?}");
        }
    }

    /// Each transport failure names its cause, the same words on every OS.
    #[tokio::test]
    async fn transport_detail_names_the_cause() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let refused = failure(&format!("http://127.0.0.1:{port}/")).await;
        assert_eq!(
            transport_detail(&refused).as_deref(),
            Some("connection refused")
        );
        let unknown = failure("http://repo.nonexistent.invalid/").await;
        let detail = transport_detail(&unknown).unwrap();
        assert!(detail.starts_with("host name lookup failed: "), "{detail}");

        // A body cut short, and a server that never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut short, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 1024];
            let _ = short.read(&mut head).await;
            let _ = short
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc")
                .await;
            drop(short);
            let (_silent, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let client = crate::client_builder().build().unwrap();
        let url = format!("http://{addr}/");
        let response = client.get(&url).send().await.unwrap();
        let cut = response.bytes().await.unwrap_err();
        assert_eq!(
            transport_detail(&cut).as_deref(),
            Some("connection closed before the whole response arrived")
        );
        let request = client
            .get(&url)
            .timeout(std::time::Duration::from_millis(200));
        let silent = request.send().await.unwrap_err();
        assert_eq!(transport_detail(&silent).as_deref(), Some("timed out"));
    }

    /// A proxy that answers the `CONNECT` with 407 or 403 is not retried.
    #[tokio::test]
    async fn a_refused_tunnel_is_not_retried() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (answer, refusal) in [
            (
                &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
                TunnelRefusal::AuthRequired,
            ),
            (b"HTTP/1.1 403 Forbidden\r\n\r\n", TunnelRefusal::Refused),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let _ = stream.write_all(answer).await;
            });
            let proxy = reqwest::Proxy::https(format!("http://127.0.0.1:{port}")).unwrap();
            let err = crate::client_builder()
                .proxy(proxy)
                .build()
                .unwrap()
                .get("https://repo.example/")
                .send()
                .await
                .unwrap_err();
            assert_eq!(tunnel_refusal(&err), Some(refusal), "{err:?}");
            assert!(!transport_is_retryable(&err), "{err:?}");
        }
    }
}
