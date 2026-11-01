//! HTTP client construction and the failure rules Raeva's clients share.
//!
//! [`client_builder`] starts a reqwest client builder with the trust roots
//! that the repository client and the OSV client both use, and
//! [`client_defaults`] adds the settings both send every request with.
//! [`trust_roots`] reports where the roots come from, and [`read_env_roots`]
//! reads the ones the environment names ahead of a build. [`tls_cause`] finds a
//! TLS failure behind an error, [`tls_failure_is_permanent`] tells whether a
//! retry can help, and [`describe_tls_failure`] describes the failure on one
//! line. [`transient`] decides which other failures a retry can fix,
//! [`retry::run`] retries them under one rule, [`headers::retry_after`]
//! reads the server's requested delay, and [`body::read_limited`] reads a
//! body under a size limit.
//!
//! The crate reads `SSL_CERT_FILE` and `SSL_CERT_DIR` on purpose, once per
//! process: when either is set, the certificates it names are the only
//! trust roots (see [`client_builder`]). It reads no other environment
//! variable itself, and [`client_defaults`] turns off reqwest's own reading
//! of the proxy variables.
//!
//! It sends no requests of its own and knows nothing about Maven
//! repositories, OSV, credentials or proxies. Repository URLs,
//! authentication, address screening and the user's proxy settings belong
//! to the clients that build on [`client_defaults`].

pub mod body;
pub mod headers;
pub mod retry;
mod roots;
pub mod transient;

use std::time::Duration;

pub use roots::{TrustRoots, client_builder, read_env_roots, trust_roots};

/// The User-Agent every Raeva request sends. Some private repositories and
/// many CDN firewalls reject requests without one.
pub const USER_AGENT: &str = concat!("raeva/", env!("CARGO_PKG_VERSION"));

/// [`client_builder`] with the settings every Raeva client shares: the
/// [`USER_AGENT`], a 10 second connect timeout, HTTP/2 pings, and no
/// proxies. reqwest's own reading of the proxy variables is off because a
/// proxy resolves host names itself, past any address screen the client
/// installs; callers add the proxies of the configuration, which holds those
/// variables' proxies too, after this call.
pub fn client_defaults() -> reqwest::ClientBuilder {
    client_builder()
        .connect_timeout(Duration::from_secs(10))
        // One HTTP/2 connection carries every request to a host, retries
        // included. A ping on a request that hears nothing for 5 seconds,
        // unanswered for 5 more, closes a connection that stopped answering,
        // so the retries open a new one rather than each waiting out its
        // timeout on the dead one.
        .http2_keep_alive_interval(Duration::from_secs(5))
        .http2_keep_alive_timeout(Duration::from_secs(5))
        .no_proxy()
        .user_agent(USER_AGENT)
}

use rustls::CertificateError;

/// A TLS failure on one line. For a rejected certificate this names the
/// cause in plain words, then the verifier's own detail: the rustls variant,
/// or the operating system's message and status code on macOS and Windows,
/// where the platform verifier passes most failures on as text.
pub fn describe_tls_failure(err: &rustls::Error) -> String {
    match err {
        rustls::Error::InvalidCertificate(cert) => {
            format!("invalid peer certificate: {}", describe_certificate(cert))
        }
        other => one_line(&other.to_string()),
    }
}

fn describe_certificate(err: &CertificateError) -> String {
    use CertificateError as E;
    let plain = match err {
        E::Other(other) => return describe_platform_error(&other.0.to_string()),
        // rustls already words these, with the times or names involved.
        E::ExpiredContext { .. }
        | E::NotValidYetContext { .. }
        | E::ExpiredRevocationListContext { .. }
        | E::NotValidForNameContext { .. }
        | E::InvalidPurposeContext { .. } => return one_line(&err.to_string()),
        E::BadEncoding => "certificate is malformed",
        E::Expired => EXPIRED,
        E::NotValidYet => NOT_VALID_YET,
        E::Revoked => REVOKED,
        E::UnhandledCriticalExtension => CRITICAL_EXTENSION,
        E::UnknownIssuer => "certificate issuer is unknown or not trusted",
        E::UnknownRevocationStatus => REVOCATION_UNKNOWN,
        E::ExpiredRevocationList => "certificate revocation list has expired",
        E::BadSignature => BAD_SIGNATURE,
        E::UnsupportedSignatureAlgorithmContext { .. }
        | E::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
            "certificate signature algorithm is not supported"
        }
        E::NotValidForName => WRONG_NAME,
        E::InvalidPurpose => WRONG_PURPOSE,
        E::InvalidOcspResponse => "stapled OCSP response is not valid",
        E::ApplicationVerificationFailure => "certificate was rejected by the application",
        _ => return one_line(&err.to_string()),
    };
    format!("{plain} ({})", one_line(&format!("{err:?}")))
}

const EXPIRED: &str = "certificate has expired";
const NOT_VALID_YET: &str = "certificate is not valid yet";
const REVOKED: &str = "certificate has been revoked";
const REVOCATION_UNKNOWN: &str = "certificate revocation status could not be checked";
const CRITICAL_EXTENSION: &str = "certificate has an unsupported critical extension";
const BAD_SIGNATURE: &str = "certificate signature is not valid";
const WRONG_NAME: &str = "certificate is not valid for this host name";
const WRONG_PURPOSE: &str = "certificate is not valid for server authentication";
const NOT_TRUSTED: &str = "certificate is not trusted";

/// The text rustls-platform-verifier puts in `CertificateError::Other`:
/// `"<description>: <OSStatus>"` from the Security framework on macOS, and
/// `"<message> (os error <HRESULT>)"` from the CryptoAPI on Windows.
fn describe_platform_error(text: &str) -> String {
    let text = one_line(text);
    if let Some((description, status)) = text
        .rsplit_once(": ")
        .and_then(|(description, code)| Some((description, code.parse::<i32>().ok()?)))
        .filter(|(_, status)| *status < 0)
    {
        let detail = format!("{description}, OSStatus {status}");
        return with_cause(apple_cause(status), detail);
    }
    if let Some((message, code)) = text
        .strip_suffix(')')
        .and_then(|rest| rest.rsplit_once(" (os error "))
        .and_then(|(message, code)| Some((message, code.parse::<i32>().ok()?)))
    {
        let message = message.trim_end_matches('.');
        // HRESULTs are documented in hex.
        let hresult = code.cast_unsigned();
        let detail = format!("{message}, 0x{hresult:08X}");
        return with_cause(windows_cause(hresult), detail);
    }
    text
}

fn with_cause(cause: Option<&str>, detail: String) -> String {
    match cause {
        Some(cause) => format!("{cause} ({detail})"),
        None => detail,
    }
}

/// Trust evaluation results from `SecBase.h`.
fn apple_cause(status: i32) -> Option<&'static str> {
    Some(match status {
        -67818 => EXPIRED,
        -67819 => NOT_VALID_YET,
        -67843 => NOT_TRUSTED,
        -25318 => "certificate chain to a trusted root could not be built",
        -67654 => "certificate is denied by the trust settings",
        -67612 => "root certificate is not valid",
        -67602 => WRONG_NAME,
        -67900 => "certificate is not allowed to name this host",
        -67820 => REVOKED,
        -67821 => "certificate has been suspended",
        -67635 => REVOCATION_UNKNOWN,
        -67608 | -67609 => WRONG_PURPOSE,
        -67901 => "certificate validity period is longer than macOS allows",
        -67603 => CRITICAL_EXTENSION,
        -67880 => "certificate lacks a required extension",
        -67604 | -67605 => "issuer certificate lacks basic constraints",
        -67611 => "certificate chain is longer than an issuer allows",
        -67902 => "certificate is a CA certificate, not a server certificate",
        -67688 => BAD_SIGNATURE,
        -67815 => "certificate digest algorithm is not supported",
        -67735 => "certificate key size is not supported",
        _ => return None,
    })
}

/// Certificate trust HRESULTs from `winerror.h`.
fn windows_cause(hresult: u32) -> Option<&'static str> {
    Some(match hresult {
        // CERT_E_EXPIRED covers both ends of the validity period.
        0x800B_0101 => "certificate has expired or is not valid yet",
        0x800B_0102 => "certificate validity period does not nest in its issuer's",
        0x800B_0109 | 0x800B_010D => "certificate root is not trusted",
        0x800B_010A => "certificate chain to a trusted root could not be built",
        0x800B_0112 => "certificate issuer is not trusted",
        0x800B_0111 => "certificate is explicitly distrusted",
        0x800B_0107 => "certificate issuer chain is not valid",
        0x800B_010C | 0x8009_2010 => REVOKED,
        0x800B_010E | 0x8009_2012 | 0x8009_2013 => REVOCATION_UNKNOWN,
        0x800B_010F | 0x800B_0114 => WRONG_NAME,
        0x800B_0106 | 0x800B_0110 => WRONG_PURPOSE,
        0x800B_0105 => CRITICAL_EXTENSION,
        0x800B_0108 => "certificate is malformed",
        0x8009_6004 => BAD_SIGNATURE,
        0x8009_6019 => "certificate basic constraints are not valid",
        0x800B_0104 => "certificate chain is longer than an issuer allows",
        0x800B_0103 => "certificate is used in a role it may not have",
        0x800B_0113 => "certificate policy is not valid",
        _ => return None,
    })
}

/// Collapses line breaks and runs of whitespace, which some platform
/// messages contain, to single spaces.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The TLS failure behind an error, if any, such as a `reqwest::Error`.
/// reqwest classifies these as connect errors and its message omits the
/// cause, which only the source chain carries.
pub fn tls_cause<'a>(err: &'a (dyn std::error::Error + 'static)) -> Option<&'a rustls::Error> {
    std::iter::successors(Some(err), |current| {
        // `io::Error::source` skips the error it wraps, and the TLS stack
        // nests the rustls error in io errors.
        match current
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
            None => current.source(),
        }
    })
    .find_map(|error| error.downcast_ref::<rustls::Error>())
}

/// Whether a TLS failure comes from trust or protocol configuration, which
/// retrying cannot change, rather than from a server having a bad moment.
pub fn tls_failure_is_permanent(err: &rustls::Error) -> bool {
    use rustls::AlertDescription as Alert;
    match err {
        rustls::Error::InvalidCertificate(_)
        | rustls::Error::NoCertificatesPresented
        | rustls::Error::InvalidCertRevocationList(_)
        | rustls::Error::PeerIncompatible(_) => true,
        rustls::Error::AlertReceived(alert) => matches!(
            alert,
            Alert::BadCertificate
                | Alert::UnsupportedCertificate
                | Alert::CertificateRevoked
                | Alert::CertificateExpired
                | Alert::CertificateUnknown
                | Alert::UnknownCA
                | Alert::CertificateRequired
                | Alert::ProtocolVersion
                | Alert::InsufficientSecurity
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{describe_tls_failure, tls_failure_is_permanent};
    use rustls::{AlertDescription as Alert, CertificateError, OtherError};
    use std::sync::Arc;
    use std::time::Duration;

    fn platform(text: &str) -> rustls::Error {
        let error = Box::<dyn std::error::Error + Send + Sync>::from(text.to_string());
        rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::from(error))))
    }

    #[test]
    fn tls_failures_name_the_cause_and_keep_the_platform_detail() {
        let cert = rustls::Error::InvalidCertificate;
        let unix = |secs| rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        for (error, expected) in [
            (
                platform("\u{201c}*.badssl.com\u{201d} certificate is expired: -67818"),
                "certificate has expired (\u{201c}*.badssl.com\u{201d} certificate is expired, \
                 OSStatus -67818)",
            ),
            (
                platform("\u{201c}x\u{201d} certificate\n  has a problem: -99999"),
                "\u{201c}x\u{201d} certificate has a problem, OSStatus -99999",
            ),
            (
                platform(
                    "The revocation function was unable to check revocation because the \
                     revocation server was offline.\r\n (os error -2146885613)",
                ),
                "certificate revocation status could not be checked (The revocation function \
                 was unable to check revocation because the revocation server was offline, \
                 0x80092013)",
            ),
            (
                platform("Something else. (os error -2146762485)"),
                "Something else, 0x800B010B",
            ),
            (
                cert(CertificateError::UnknownIssuer),
                "certificate issuer is unknown or not trusted (UnknownIssuer)",
            ),
            (
                cert(CertificateError::ExpiredContext {
                    time: unix(200),
                    not_after: unix(100),
                }),
                "certificate expired: verification time 200 (UNIX), but certificate is not \
                 valid after 100 (100 seconds ago)",
            ),
        ] {
            assert_eq!(
                describe_tls_failure(&error),
                format!("invalid peer certificate: {expected}")
            );
        }
        assert_eq!(
            describe_tls_failure(&rustls::Error::General("line one\nline two".to_string())),
            "unexpected error: line one line two"
        );
    }

    #[test]
    fn only_trust_and_protocol_tls_failures_are_permanent() {
        for (error, permanent) in [
            (
                rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer),
                true,
            ),
            (
                rustls::Error::AlertReceived(Alert::CertificateRequired),
                true,
            ),
            (rustls::Error::AlertReceived(Alert::HandshakeFailure), false),
        ] {
            assert_eq!(tls_failure_is_permanent(&error), permanent, "{error:?}");
        }
    }
}
