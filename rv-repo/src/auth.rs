use reqwest::RequestBuilder;
use secrecy::{ExposeSecret, Secret};
use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::error::{RepoError, Result};
use crate::repository::Repository;

/// Repository authentication methods.
///
/// - `Basic`: username and password via HTTP Basic authentication.
/// - `Bearer`: token via the Bearer scheme.
#[derive(Clone)]
pub(crate) enum Auth {
    Basic {
        username: String,
        password: Secret<String>,
    },
    Bearer {
        token: Secret<String>,
    },
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Auth::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"***")
                .finish(),
            Auth::Bearer { .. } => f.debug_struct("Bearer").field("token", &"***").finish(),
        }
    }
}

impl PartialEq for Auth {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Auth::Basic {
                    username: u1,
                    password: p1,
                },
                Auth::Basic {
                    username: u2,
                    password: p2,
                },
            ) => u1 == u2 && p1.expose_secret() == p2.expose_secret(),
            (Auth::Bearer { token: t1 }, Auth::Bearer { token: t2 }) => {
                t1.expose_secret() == t2.expose_secret()
            }
            _ => false,
        }
    }
}

impl Eq for Auth {}

impl Auth {
    pub(crate) fn apply(&self, request: RequestBuilder) -> RequestBuilder {
        match self {
            Auth::Basic { username, password } => {
                request.basic_auth(username, Some(password.expose_secret()))
            }
            Auth::Bearer { token } => request.bearer_auth(token.expose_secret()),
        }
    }
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host.starts_with("127.") || host == "::1" || host == "[::1]"
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AuthStore {
    entries: Vec<AuthEntry>,
    default: Option<Auth>,
    // Per-instance dedup so independent AuthStores (e.g. per-test fixtures)
    // do not interfere with each other's CLEARTEXT_AUTH warning state.
    // Arc<Mutex<>> so clones of an AuthStore share the dedup set, which
    // matches the previous process-wide semantics for a single logical store
    // while keeping the set scoped per-instance.
    cleartext_warned: Arc<Mutex<HashSet<(String, String)>>>,
}

#[derive(Debug, Clone)]
struct AuthEntry {
    id: String,
    auth: Auth,
}

impl AuthStore {
    pub(crate) fn from_config(config: &rv_config::Config) -> Result<Self> {
        Self::from_auth_configs(config.auth())
    }

    pub(crate) fn from_auth_configs(configs: &[rv_config::AuthConfig]) -> Result<Self> {
        let mut entries = Vec::new();
        let mut default = None;

        for config in configs {
            let Some(auth) = build_auth(config)? else {
                continue;
            };
            if let Some(id) = config.id.as_ref() {
                entries.push(AuthEntry {
                    id: id.clone(),
                    auth,
                });
            } else if default.is_none() {
                default = Some(auth);
            }
        }

        Ok(Self {
            entries,
            default,
            cleartext_warned: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Look up auth for `repo`, optionally suppressing the default-fallback
    /// when the repo URL is the result of a cross-host mirror substitution.
    ///
    /// `host_changed = true` is the signal from [`crate::mirror::MirrorSelector::resolve_with_host_change`]
    /// that a wildcard mirror redirected the original repo to a different
    /// host. In that case we must NOT forward the user's default (no-id)
    /// credentials, since a third-party CDN should not receive a Nexus
    /// bearer token. Id-matched entries are still honored: the user
    /// explicitly opted into that pairing.
    pub(crate) fn for_repository_with_policy(
        &self,
        repo: &Repository,
        host_changed: bool,
    ) -> Option<&Auth> {
        let resolved = self.lookup_auth(repo, host_changed)?;
        // Auth resolved. If we'd attach it over plaintext HTTP to a
        // non-loopback host, fire the CLEARTEXT_AUTH warn. Per-instance
        // dedup so a fan-out fetch only warns once per (host, scheme).
        if let Ok(url) = url::Url::parse(&repo.url)
            && url.scheme() == "http"
            && let Some(host) = url.host_str()
            && !is_loopback_host(host)
        {
            self.warn_cleartext_auth_once(host, url.scheme());
        }
        Some(resolved)
    }

    fn lookup_auth(&self, repo: &Repository, host_changed: bool) -> Option<&Auth> {
        if let Some(id) = repo.id.as_deref()
            && let Some(entry) = self.entries.iter().find(|entry| entry.id == id)
        {
            let method = match &entry.auth {
                Auth::Basic { .. } => "basic",
                Auth::Bearer { .. } => "bearer",
            };
            tracing::debug!(
                repo_id = id,
                auth_method = method,
                "using auth for repository"
            );
            return Some(&entry.auth);
        }
        if host_changed {
            // `sec_code` is the JSON-envelope contract field that the CLI's
            // `WarningCollectorLayer` picks up so this security event
            // survives `--json` mode (where the fmt subscriber runs at
            // `off`). The string code is the stable machine identifier
            // documented in `rv_cli::output::WarningCollector`.
            tracing::warn!(
                sec_code = "CROSS_HOST_MIRROR",
                repo_url = %repo.url,
                "suppressing default credentials for cross-host mirror substitution"
            );
            return None;
        }
        self.default.as_ref()
    }

    fn warn_cleartext_auth_once(&self, host: &str, scheme: &str) {
        let mut guard = match self.cleartext_warned.lock() {
            Ok(g) => g,
            // A poisoned lock means another thread panicked while updating
            // the dedup set; surfacing the warn is still safer than dropping.
            Err(p) => p.into_inner(),
        };
        if guard.insert((host.to_string(), scheme.to_string())) {
            tracing::warn!(
                sec_code = "CLEARTEXT_AUTH",
                host = %host,
                "attaching credentials to a plaintext HTTP request"
            );
        }
    }
}

fn build_auth(config: &rv_config::AuthConfig) -> Result<Option<Auth>> {
    if let Some(token) = config.token.as_ref() {
        return Ok(Some(Auth::Bearer {
            token: token.clone(),
        }));
    }

    match (&config.username, &config.password) {
        (Some(username), Some(password)) => Ok(Some(Auth::Basic {
            username: username.clone(),
            password: password.clone(),
        })),
        (None, None) => Ok(None),
        _ => Err(RepoError::AuthError(
            "basic auth requires username and password".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{Auth, AuthStore};
    use crate::repository::Repository;
    use secrecy::{ExposeSecret, Secret};

    #[test]
    fn resolves_auth_by_repo_id() {
        let configs = vec![rv_config::AuthConfig {
            id: Some("central".to_string()),
            username: Some("user".to_string()),
            password: Some(Secret::new("pass".to_string())),
            token: None,
        }];
        let store = AuthStore::from_auth_configs(&configs).unwrap();
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2/",
            true,
            false,
        );
        let auth = store.for_repository_with_policy(&repo, false).unwrap();

        match auth {
            Auth::Basic { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password.expose_secret(), "pass");
            }
            _ => panic!("expected basic auth"),
        }
    }

    #[test]
    fn host_changed_suppresses_default_auth() {
        // Default credentials must NOT be forwarded to a wildcard mirror
        // running on a different host.
        let configs = vec![rv_config::AuthConfig {
            id: None,
            username: None,
            password: None,
            token: Some(Secret::new("corp-bearer".to_string())),
        }];
        let store = AuthStore::from_auth_configs(&configs).unwrap();
        let resolved = Repository::new(
            Some("central".to_string()),
            "https://cdn.example/",
            true,
            false,
        );
        // Without the policy: default token leaks (host_changed=false path).
        assert!(store.for_repository_with_policy(&resolved, false).is_some());
        // With host_changed: default token is suppressed.
        assert!(
            store.for_repository_with_policy(&resolved, true).is_none(),
            "default credentials must not be forwarded to a cross-host mirror"
        );
    }

    #[test]
    fn host_changed_still_honors_id_matched_auth() {
        // An explicit id-matched AuthConfig wins regardless of host change,
        // because the user opted into that mapping.
        let configs = vec![rv_config::AuthConfig {
            id: Some("mirror-id".to_string()),
            username: None,
            password: None,
            token: Some(Secret::new("mirror-token".to_string())),
        }];
        let store = AuthStore::from_auth_configs(&configs).unwrap();
        let resolved = Repository::new(
            Some("mirror-id".to_string()),
            "https://cdn.example/",
            true,
            false,
        );
        assert!(store.for_repository_with_policy(&resolved, true).is_some());
    }

    #[test]
    fn cleartext_auth_warn_fires_for_http_non_loopback() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct VecWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for VecWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for VecWriter {
            type Writer = VecWriter;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let writer = VecWriter(buf.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();

        // Per-instance dedup: a freshly built AuthStore has its own warn
        // set, so test ordering can no longer leak warning state.
        let configs = vec![rv_config::AuthConfig {
            id: None,
            username: None,
            password: None,
            token: Some(Secret::new("token".to_string())),
        }];
        let store = AuthStore::from_auth_configs(&configs).unwrap();

        let plain_repo = Repository::new(None, "http://repo.example/", true, false);
        let same_repo = Repository::new(None, "http://repo.example/other", true, false);
        let loopback = Repository::new(None, "http://127.0.0.1:8080/", true, false);
        let loopback_named = Repository::new(None, "http://localhost/", true, false);

        tracing::subscriber::with_default(subscriber, || {
            let _ = store.for_repository_with_policy(&plain_repo, false);
            // Second call to same host should NOT emit a duplicate warn.
            let _ = store.for_repository_with_policy(&same_repo, false);
            // Loopback must NOT warn.
            let _ = store.for_repository_with_policy(&loopback, false);
            let _ = store.for_repository_with_policy(&loopback_named, false);
        });

        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("CLEARTEXT_AUTH"),
            "expected CLEARTEXT_AUTH warning, got: {output}"
        );
        assert!(
            output.contains("repo.example"),
            "expected host in warning, got: {output}"
        );
        assert!(
            !output.contains("127.0.0.1") && !output.contains("localhost"),
            "loopback must not warn: {output}"
        );
        let count = output.matches("CLEARTEXT_AUTH").count();
        assert_eq!(count, 1, "dedup must collapse repeat warns, got {count}");
    }

    #[test]
    fn resolves_default_auth() {
        let configs = vec![rv_config::AuthConfig {
            id: None,
            username: None,
            password: None,
            token: Some(Secret::new("token".to_string())),
        }];
        let store = AuthStore::from_auth_configs(&configs).unwrap();
        let repo = Repository::new(None, "https://repo.example/", true, false);
        let auth = store.for_repository_with_policy(&repo, false).unwrap();

        match auth {
            Auth::Bearer { token } => {
                assert_eq!(token.expose_secret(), "token");
            }
            _ => panic!("expected bearer auth"),
        }
    }
}
