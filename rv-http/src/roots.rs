use std::sync::LazyLock;

use tracing::warn;

/// Starts a reqwest client builder with the ring crypto provider installed
/// and the trust roots [`trust_roots`] reports.
///
/// reqwest is built without a provider of its own and panics when a client is
/// built before one is installed for the process.
///
/// The roots are read from the environment on purpose: when `SSL_CERT_FILE`
/// or `SSL_CERT_DIR` is set, even to an empty value, the certificates they
/// name replace the platform verifier on every platform, and nothing falls
/// back to the system store. Both variables are read once per process, on
/// the first call of this function, [`trust_roots`] or [`read_env_roots`];
/// `SSL_CERT_DIR` may list several directories, separated as `PATH` is.
/// Unreadable files and certificates rustls cannot use as anchors are
/// skipped with a warning.
#[allow(clippy::disallowed_methods)]
pub fn client_builder() -> reqwest::ClientBuilder {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let builder = reqwest::Client::builder();
    match env_roots() {
        // The platform verifier asks the OS on macOS and Windows and would
        // ignore these variables there.
        Some(roots) => builder.tls_certs_only(reqwest_certs(roots)),
        None => match system_roots() {
            // The platform verifier refuses to build without system roots,
            // which would break offline and file:// runs. With no roots every
            // HTTPS handshake still fails verification.
            SystemRoots::Empty => builder.tls_certs_only(Vec::new()),
            // Linux and other non-Apple Unix: feed the system CA bundle once
            // via rustls. The platform verifier re-parses that PEM on every
            // Client::build (four times per RepoClient), which dominated warm
            // sync --update profiles.
            SystemRoots::Cached(roots) => builder.tls_certs_only(reqwest_certs(roots)),
            // macOS, Windows, Android keep the OS verifier.
            SystemRoots::PlatformVerifier => builder,
        },
    }
}

fn reqwest_certs(
    roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Vec<reqwest::Certificate> {
    roots
        .iter()
        .filter_map(|cert| reqwest::Certificate::from_der(cert).ok())
        .collect()
}

/// Where clients from [`client_builder`] take their trust roots from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustRoots {
    /// The operating system's verifier, or on a Unix other than Apple's and
    /// Android the system roots.
    Platform,
    /// A Unix other than Apple's and Android with no system roots: every
    /// HTTPS handshake fails verification.
    Empty,
    /// `SSL_CERT_FILE` or `SSL_CERT_DIR` replace the platform's roots.
    Environment {
        /// How many certificates from the variables are usable as roots.
        /// Zero means every HTTPS handshake fails verification.
        certificates: usize,
    },
}

/// Where the roots of [`client_builder`] come from, for diagnostics. Reads
/// `SSL_CERT_FILE` and `SSL_CERT_DIR` as [`client_builder`] does, sharing
/// its once-per-process result, and on Unix systems other than Apple's and
/// Android checks whether the system store has any roots.
pub fn trust_roots() -> TrustRoots {
    match env_roots() {
        Some(roots) => TrustRoots::Environment {
            certificates: roots.len(),
        },
        None => match system_roots() {
            SystemRoots::Empty => TrustRoots::Empty,
            SystemRoots::Cached(_) | SystemRoots::PlatformVerifier => TrustRoots::Platform,
        },
    }
}

/// Read the roots `SSL_CERT_FILE` and `SSL_CERT_DIR` name now, if either is
/// set, so their warnings come before the first client is built.
pub fn read_env_roots() {
    env_roots();
}

/// The roots named by `SSL_CERT_FILE` or `SSL_CERT_DIR`, read once per
/// process. Either variable being set, even to an empty value, replaces the
/// platform's roots, as OpenSSL and raeva 0.4.1 did: a configuration that names
/// its roots never falls back to the system trust store.
fn env_roots() -> Option<&'static [rustls::pki_types::CertificateDer<'static>]> {
    static ROOTS: LazyLock<Option<Vec<rustls::pki_types::CertificateDer<'static>>>> =
        LazyLock::new(|| {
            let file = std::env::var_os("SSL_CERT_FILE");
            let dirs = std::env::var_os("SSL_CERT_DIR");
            if file.is_none() && dirs.is_none() {
                return None;
            }
            Some(usable_roots(load_env_roots(file, dirs)))
        });
    ROOTS.as_deref()
}

/// Load the roots the variables name. rustls-native-certs falls back to the
/// platform's roots when they name nothing usable, such as an empty
/// `SSL_CERT_DIR`, which would defeat replacing them, so each path is loaded
/// on its own and empty entries count as unreadable.
fn load_env_roots(
    file: Option<std::ffi::OsString>,
    dirs: Option<std::ffi::OsString>,
) -> rustls_native_certs::CertificateResult {
    let mut loaded = rustls_native_certs::CertificateResult::default();
    let dirs = dirs.iter().flat_map(std::env::split_paths);
    let paths = (file.map(std::path::PathBuf::from).map(|file| (file, false)))
        .into_iter()
        .chain(dirs.map(|dir| (dir, true)));
    for (path, is_dir) in paths {
        if path.as_os_str().is_empty() {
            let env = if is_dir {
                "SSL_CERT_DIR"
            } else {
                "SSL_CERT_FILE"
            };
            warn!(
                sec_code = "SETTING_IGNORED",
                env, "ignoring an empty TLS roots path"
            );
            continue;
        }
        let path = Some(path.as_path());
        let (file, dir) = if is_dir { (None, path) } else { (path, None) };
        let mut result = rustls_native_certs::load_certs_from_paths(file, dir);
        loaded.certs.append(&mut result.certs);
        loaded.errors.append(&mut result.errors);
    }
    loaded
}

/// Keep the certificates rustls accepts as trust anchors, warning about the
/// rest. One unparsable certificate would otherwise fail every client build.
fn usable_roots(
    loaded: rustls_native_certs::CertificateResult,
) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    for err in &loaded.errors {
        warn!(
            sec_code = "SETTING_IGNORED",
            env = "SSL_CERT_FILE/SSL_CERT_DIR",
            "cannot read TLS roots: {err}"
        );
    }
    let total = loaded.certs.len();
    let usable: Vec<_> = loaded
        .certs
        .into_iter()
        .filter(|cert| rustls::RootCertStore::empty().add(cert.clone()).is_ok())
        .collect();
    if usable.len() < total {
        warn!(
            sec_code = "SETTING_IGNORED",
            env = "SSL_CERT_FILE/SSL_CERT_DIR",
            "ignoring {} of {total} certificates that are not usable as TLS roots",
            total - usable.len()
        );
    }
    if usable.is_empty() {
        warn!(
            sec_code = "SETTING_IGNORED",
            env = "SSL_CERT_FILE/SSL_CERT_DIR",
            "no usable TLS roots, so HTTPS servers cannot be verified; unset the variables to \
             use the system trust store"
        );
    }
    usable
}

/// How [`client_builder`] takes system trust roots when `SSL_CERT_*` is unset.
enum SystemRoots {
    Empty,
    Cached(&'static [rustls::pki_types::CertificateDer<'static>]),
    PlatformVerifier,
}

/// System roots for the process. On Linux and other non-Apple Unix the CA
/// bundle is loaded once; Apple, Windows, and Android keep the OS verifier.
fn system_roots() -> SystemRoots {
    if cfg!(any(
        not(unix),
        target_vendor = "apple",
        target_os = "android",
        target_arch = "wasm32"
    )) {
        return SystemRoots::PlatformVerifier;
    }
    static ROOTS: LazyLock<Vec<rustls::pki_types::CertificateDer<'static>>> = LazyLock::new(|| {
        let loaded = rustls_native_certs::load_native_certs();
        let mut store = rustls::RootCertStore::empty();
        loaded
            .certs
            .into_iter()
            .filter(|cert| store.add(cert.clone()).is_ok())
            .collect()
    });
    if ROOTS.is_empty() {
        SystemRoots::Empty
    } else {
        SystemRoots::Cached(ROOTS.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::CertificateDer;

    use super::{load_env_roots, usable_roots};

    #[test]
    fn unusable_ssl_cert_file_entries_are_dropped_individually() {
        use rustls::pki_types::pem::PemObject;

        let pem = include_bytes!("../../test-fixtures/tls/ca.pem");
        let ca = CertificateDer::from_pem_slice(pem).expect("ca.pem");
        let mut loaded = rustls_native_certs::CertificateResult::default();
        loaded.certs.push(CertificateDer::from(vec![0x30, 0x00]));
        loaded.certs.push(ca.clone());
        assert_eq!(usable_roots(loaded), vec![ca]);
    }

    #[test]
    fn empty_ssl_cert_paths_load_no_roots() {
        use std::ffi::OsString;

        let loaded = load_env_roots(None, Some(OsString::new()));
        assert!(loaded.certs.is_empty());
        let loaded = load_env_roots(Some(OsString::new()), None);
        assert!(loaded.certs.is_empty());

        let dir = tempfile::tempdir().expect("dir");
        std::fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../test-fixtures/tls/ca.pem"),
            dir.path().join("ca.pem"),
        )
        .expect("copy ca.pem");
        let loaded = load_env_roots(None, Some(dir.path().as_os_str().to_owned()));
        assert_eq!(loaded.certs.len(), 1);
    }
}
