use reqwest::RequestBuilder;
use rv_config::{
    AuthConfig, AuthConfigLayers, AuthType, CredentialError, CredentialRecord, CredentialStore,
    KeyringCredentialStore, NormalizedEndpoint,
};
use secrecy::{ExposeSecret, Secret};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::error::{RepoError, Result};
use crate::mirror::origins_differ;
use crate::repository::{Repository, normalize_repo_url};

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
struct ConfigAuthLayers {
    project: Vec<AuthConfig>,
    user: Vec<AuthConfig>,
    settings: Vec<AuthConfig>,
}

impl From<&AuthConfigLayers> for ConfigAuthLayers {
    fn from(layers: &AuthConfigLayers) -> Self {
        Self {
            project: layers.project().to_vec(),
            user: layers.user().to_vec(),
            settings: layers.settings().to_vec(),
        }
    }
}

#[derive(Debug, Default)]
struct KeyringWarningState {
    unavailable: bool,
    entry_missing: bool,
}

/// The configured mirror URLs that must not receive the user's default
/// (no-id) credentials.
///
/// Resolution records the *substituted* URL as a package's `repo_url`, so a
/// later `rv sync` hands the mirror's own URL to the fetch path. Mirror
/// selection then matches that URL against the very entry that produced it,
/// short-circuits as a self-reference (`MIRROR_SELF_REF`) and reports
/// `host_changed = false`, silently losing the cross-host suppression
/// resolution applied. Recognising a mirror URL on its own restores the
/// decision, so a sync reaches exactly the credentials resolution used:
/// keyring endpoint matches and the mirror's own id-scoped entry, never the
/// origin repository's entry (the sync path never carries the origin id) nor
/// the id-less default.
///
/// A mirror sharing an origin with a configured repository is exempt: the
/// default credential already reaches that origin through the repository
/// itself, so routing it through the mirror leaks nothing new.
#[derive(Debug, Clone, Default)]
struct MirrorAuthPolicy {
    foreign_mirror_urls: HashSet<String>,
}

impl MirrorAuthPolicy {
    fn from_config(config: &rv_config::Config) -> Self {
        let repositories = config.repositories();
        Self {
            foreign_mirror_urls: config
                .mirrors()
                .iter()
                .filter(|mirror| {
                    repositories
                        .iter()
                        .all(|repo| origins_differ(&repo.url, &mirror.url))
                })
                .map(|mirror| normalize_repo_url(&mirror.url))
                .collect(),
        }
    }

    fn suppresses_default_auth(&self, url: &str) -> bool {
        self.foreign_mirror_urls.contains(&normalize_repo_url(url))
    }
}

#[derive(Clone)]
pub(crate) struct AuthStore {
    layers: ConfigAuthLayers,
    credential_store: Arc<dyn CredentialStore>,
    credential_cache: Arc<Mutex<HashMap<NormalizedEndpoint, Option<CredentialRecord>>>>,
    keyring_warnings: Arc<Mutex<KeyringWarningState>>,
    mirror_policy: MirrorAuthPolicy,
    // Warn-once dedup for auth inputs rv could not use: repository URLs that
    // are not valid credential endpoints, and config entries carrying none of
    // the credential fields rv models. Keyed by a per-kind prefix so the two
    // subjects cannot collide.
    unusable_warned: Arc<Mutex<HashSet<String>>>,
    // Per-instance dedup so independent AuthStores (e.g. per-test fixtures)
    // do not interfere with each other's CLEARTEXT_AUTH warning state.
    // Arc<Mutex<>> so clones of an AuthStore share the dedup set, which
    // matches the previous process-wide semantics for a single logical store
    // while keeping the set scoped per-instance.
    cleartext_warned: Arc<Mutex<HashSet<(String, String)>>>,
}

impl fmt::Debug for AuthStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthStore")
            .field("layers", &self.layers)
            .finish_non_exhaustive()
    }
}

impl Default for AuthStore {
    fn default() -> Self {
        Self::new(
            ConfigAuthLayers::default(),
            Arc::new(KeyringCredentialStore),
        )
    }
}

impl AuthStore {
    pub(crate) fn from_config(config: &rv_config::Config) -> Result<Self> {
        Ok(Self {
            mirror_policy: MirrorAuthPolicy::from_config(config),
            ..Self::new(
                ConfigAuthLayers::from(config.auth_layers()),
                Arc::new(KeyringCredentialStore),
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn from_auth_configs(configs: &[rv_config::AuthConfig]) -> Result<Self> {
        Ok(Self::new(
            ConfigAuthLayers {
                project: configs.to_vec(),
                ..ConfigAuthLayers::default()
            },
            Arc::new(NoCredentialStore),
        ))
    }

    fn new(layers: ConfigAuthLayers, credential_store: Arc<dyn CredentialStore>) -> Self {
        Self {
            layers,
            credential_store,
            credential_cache: Arc::new(Mutex::new(HashMap::new())),
            keyring_warnings: Arc::new(Mutex::new(KeyringWarningState::default())),
            mirror_policy: MirrorAuthPolicy::default(),
            unusable_warned: Arc::new(Mutex::new(HashSet::new())),
            cleartext_warned: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    #[cfg(test)]
    fn with_foreign_mirrors(mut self, urls: &[&str]) -> Self {
        self.mirror_policy.foreign_mirror_urls =
            urls.iter().map(|url| normalize_repo_url(url)).collect();
        self
    }

    #[cfg(test)]
    fn with_sources_and_store(
        project: Vec<AuthConfig>,
        user: Vec<AuthConfig>,
        settings: Vec<AuthConfig>,
        credential_store: Arc<dyn CredentialStore>,
    ) -> Self {
        Self::new(
            ConfigAuthLayers {
                project,
                user,
                settings,
            },
            credential_store,
        )
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
    ) -> Result<Option<Auth>> {
        let Some(resolved) = self.lookup_auth(repo, host_changed)? else {
            return Ok(None);
        };
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
        Ok(Some(resolved))
    }

    fn lookup_auth(&self, repo: &Repository, host_changed: bool) -> Result<Option<Auth>> {
        // A lockfile row records the mirror-substituted URL, so the caller's
        // mirror pass cannot recompute the cross-host flag for it; see
        // [`MirrorAuthPolicy`].
        let host_changed = host_changed || self.mirror_policy.suppresses_default_auth(&repo.url);
        // A repository URL the credential-endpoint normalizer rejects (query,
        // userinfo, fragment, non-http(s) scheme) simply has no keyring
        // identity. It is still a perfectly fetchable repository, so treat the
        // rejection as "no endpoint match" and fall through to the configured
        // sources and anonymous fetch rather than aborting the whole resolve.
        // The strict normalizer still gates the endpoints `rv login` STORES.
        let endpoint = match NormalizedEndpoint::parse(&repo.url) {
            Ok(endpoint) => Some(endpoint),
            Err(err) => {
                self.warn_unusable_endpoint_once(&repo.url, &err.to_string());
                None
            }
        };
        let (record, entry_missing) = match endpoint.as_ref() {
            Some(endpoint) => self.lookup_os_record(endpoint)?,
            None => (None, false),
        };
        if let Some(record) = record {
            let auth = auth_from_record(&record)?;
            tracing::debug!(
                endpoint = ?endpoint,
                auth_method = %record.auth_type,
                "using auth from OS credential store"
            );
            return Ok(Some(auth));
        }
        if entry_missing
            && let Some(endpoint) = endpoint.as_ref()
            && self.has_config_candidate(repo, host_changed)
        {
            self.warn_keyring_entry_missing_once(endpoint);
        }

        if let Some(id) = repo.id.as_deref() {
            for (source, configs) in [
                ("project rv.toml", self.layers.project.as_slice()),
                ("user config", self.layers.user.as_slice()),
                ("settings.xml", self.layers.settings.as_slice()),
            ] {
                if let Some(config) = configs.iter().find(|entry| entry.id.as_deref() == Some(id)) {
                    // An entry carrying none of the fields rv models says
                    // nothing about HTTP credentials for this id — a
                    // settings.xml `<server>` may exist purely for
                    // `<privateKey>`/`<passphrase>` scp deploys. Skipping it
                    // keeps the id usable; a PARTIALLY filled entry (say a
                    // username with no password) is still a hard error.
                    if is_unmodeled_auth_entry(config) {
                        self.warn_unmodeled_auth_entry_once(id, source);
                        continue;
                    }
                    let auth = build_complete_auth(config, source)?;
                    tracing::debug!(
                        repo_id = id,
                        auth_method = auth.method(),
                        auth_source = source,
                        "using auth for repository"
                    );
                    return Ok(Some(auth));
                }
            }
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
            return Ok(None);
        }

        for (source, configs) in [
            ("project rv.toml default", self.layers.project.as_slice()),
            ("user config default", self.layers.user.as_slice()),
            ("settings.xml default", self.layers.settings.as_slice()),
        ] {
            if let Some(config) = configs.iter().find(|entry| entry.id.is_none()) {
                return build_complete_auth(config, source).map(Some);
            }
        }
        Ok(None)
    }

    fn lookup_os_record(
        &self,
        endpoint: &NormalizedEndpoint,
    ) -> Result<(Option<CredentialRecord>, bool)> {
        if self
            .keyring_warnings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .unavailable
        {
            return Ok((None, false));
        }
        let mut cache = self
            .credential_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(record) = cache.get(endpoint) {
            return Ok((record.clone(), record.is_none()));
        }

        match self.credential_store.get(endpoint) {
            Ok(record) => {
                cache.insert(endpoint.clone(), record.clone());
                let missing = record.is_none();
                Ok((record, missing))
            }
            Err(CredentialError::BackendUnavailable(details)) => {
                self.warn_keyring_unavailable_once(&details);
                Ok((None, false))
            }
            Err(err) => Err(RepoError::AuthError(err.to_string())),
        }
    }

    fn warn_keyring_unavailable_once(&self, details: &str) {
        let mut state = self
            .keyring_warnings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.unavailable {
            return;
        }
        tracing::warn!(
            sec_code = "KEYRING_UNAVAILABLE",
            error = %details,
            "OS credential store is unavailable; using configured credentials"
        );
        // Set the flag only after the subscriber has processed the event, so
        // a concurrent clone cannot return through the warn-once fast path
        // while the warning is still being written.
        state.unavailable = true;
    }

    fn warn_keyring_entry_missing_once(&self, endpoint: &NormalizedEndpoint) {
        let mut state = self
            .keyring_warnings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.entry_missing {
            return;
        }
        tracing::warn!(
            sec_code = "KEYRING_ENTRY_MISSING",
            endpoint = %endpoint,
            "OS credential entry is missing; using configured credentials"
        );
        state.entry_missing = true;
    }

    fn warn_unusable_endpoint_once(&self, repo_url: &str, details: &str) {
        let endpoint = redacted_repo_url(repo_url);
        self.warn_unusable_once(
            format!("endpoint:{endpoint}"),
            || tracing::warn!(
                sec_code = "KEYRING_ENTRY_MISSING",
                endpoint = %endpoint,
                error = %details,
                "repository URL cannot be an OS credential endpoint; skipping the credential store for it"
            ),
        );
    }

    fn warn_unmodeled_auth_entry_once(&self, id: &str, source: &str) {
        self.warn_unusable_once(format!("auth-entry:{source}:{id}"), || {
            tracing::warn!(
                repo_id = id,
                auth_source = source,
                "ignoring auth entry with no username, password or token; it carries only \
                 fields rv does not model (e.g. privateKey/passphrase)"
            )
        });
    }

    fn warn_unusable_once(&self, key: String, emit: impl FnOnce()) {
        let mut guard = self
            .unusable_warned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.insert(key) {
            emit();
        }
    }

    fn has_config_candidate(&self, repo: &Repository, host_changed: bool) -> bool {
        let layers = [
            self.layers.project.as_slice(),
            self.layers.user.as_slice(),
            self.layers.settings.as_slice(),
        ];
        if let Some(id) = repo.id.as_deref()
            && layers
                .iter()
                .any(|configs| configs.iter().any(|entry| entry.id.as_deref() == Some(id)))
        {
            return true;
        }
        !host_changed
            && layers
                .iter()
                .any(|configs| configs.iter().any(|entry| entry.id.is_none()))
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

#[cfg(test)]
struct NoCredentialStore;

#[cfg(test)]
impl CredentialStore for NoCredentialStore {
    fn get(
        &self,
        _endpoint: &NormalizedEndpoint,
    ) -> std::result::Result<Option<CredentialRecord>, CredentialError> {
        Ok(None)
    }

    fn set(
        &self,
        _endpoint: &NormalizedEndpoint,
        _record: &CredentialRecord,
    ) -> std::result::Result<(), CredentialError> {
        unreachable!("read-only test credential store")
    }

    fn delete(&self, _endpoint: &NormalizedEndpoint) -> std::result::Result<bool, CredentialError> {
        unreachable!("read-only test credential store")
    }
}

impl Auth {
    fn method(&self) -> &'static str {
        match self {
            Self::Basic { .. } => "basic",
            Self::Bearer { .. } => "bearer",
        }
    }
}

fn auth_from_record(record: &CredentialRecord) -> Result<Auth> {
    match record.auth_type {
        AuthType::Basic => Ok(Auth::Basic {
            username: record.username.clone().ok_or_else(|| {
                RepoError::AuthError(
                    "credential record is corrupt: basic auth has no username".to_string(),
                )
            })?,
            password: Secret::new(record.expose_secret().to_string()),
        }),
        AuthType::Bearer => Ok(Auth::Bearer {
            token: Secret::new(record.expose_secret().to_string()),
        }),
    }
}

/// True when an auth entry carries none of the credential fields rv models.
/// Such an entry cannot yield an `Auth`, and it must not be mistaken for a
/// misconfigured one: `settings.xml` servers holding only `<privateKey>`,
/// `<passphrase>` or `<filePermissions>` are standard for scp deploys.
fn is_unmodeled_auth_entry(config: &AuthConfig) -> bool {
    config.token.is_none() && config.username.is_none() && config.password.is_none()
}

/// A repository URL rendered for logging with everything secret-bearing
/// removed: userinfo (`https://alice:secret@…`) and the query string
/// (`?api_key=…`) both routinely carry credentials, and both are exactly what
/// makes a URL unusable as a credential endpoint.
fn redacted_repo_url(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url.trim()) else {
        return "<unparsable repository url>".to_string();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

fn build_complete_auth(config: &AuthConfig, source: &str) -> Result<Auth> {
    if let Some(token) = config.token.as_ref() {
        if token.expose_secret().is_empty() {
            return Err(incomplete_auth_error(
                config,
                source,
                "bearer auth requires a non-empty token",
            ));
        }
        return Ok(Auth::Bearer {
            token: token.clone(),
        });
    }

    match (&config.username, &config.password) {
        (Some(username), Some(password))
            if !username.is_empty() && !password.expose_secret().is_empty() =>
        {
            Ok(Auth::Basic {
                username: username.clone(),
                password: password.clone(),
            })
        }
        _ => Err(incomplete_auth_error(
            config,
            source,
            "basic auth requires a non-empty username and password, or bearer auth requires a non-empty token",
        )),
    }
}

fn incomplete_auth_error(config: &AuthConfig, source: &str, details: &str) -> RepoError {
    let target = config
        .id
        .as_deref()
        .map(|id| format!(" for repository id {id:?}"))
        .unwrap_or_default();
    RepoError::AuthError(format!("incomplete {source} auth entry{target}: {details}"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::{Auth, AuthStore};
    use crate::mirror::MirrorSelector;
    use crate::repository::Repository;
    use rv_config::{
        AuthConfig, CredentialError, CredentialRecord, CredentialStore, NormalizedEndpoint,
    };
    use secrecy::{ExposeSecret, Secret};

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    // Scoped tracing subscribers refresh process-global callsite interest.
    // Keep warning-buffer assertions from installing competing subscribers
    // while the test harness runs this module in parallel.
    static WARNING_CAPTURE_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy)]
    enum StoreFailure {
        Unavailable,
        Corrupt,
    }

    struct RecordingCredentialStore {
        records: HashMap<NormalizedEndpoint, CredentialRecord>,
        lookups: Mutex<Vec<NormalizedEndpoint>>,
        failure: Option<StoreFailure>,
    }

    impl RecordingCredentialStore {
        fn empty() -> Self {
            Self {
                records: HashMap::new(),
                lookups: Mutex::new(Vec::new()),
                failure: None,
            }
        }

        fn with_record(endpoint: &str, record: CredentialRecord) -> Self {
            Self {
                records: HashMap::from([(
                    NormalizedEndpoint::parse(endpoint).expect("endpoint"),
                    record,
                )]),
                ..Self::empty()
            }
        }

        fn failing(failure: StoreFailure) -> Self {
            Self {
                failure: Some(failure),
                ..Self::empty()
            }
        }
    }

    impl CredentialStore for RecordingCredentialStore {
        fn get(
            &self,
            endpoint: &NormalizedEndpoint,
        ) -> std::result::Result<Option<CredentialRecord>, CredentialError> {
            self.lookups.lock().expect("lock").push(endpoint.clone());
            match self.failure {
                Some(StoreFailure::Unavailable) => Err(CredentialError::BackendUnavailable(
                    "test backend unavailable".to_string(),
                )),
                Some(StoreFailure::Corrupt) => Err(CredentialError::CorruptRecord(
                    "test record has invalid JSON".to_string(),
                )),
                None => Ok(self.records.get(endpoint).cloned()),
            }
        }

        fn set(
            &self,
            _endpoint: &NormalizedEndpoint,
            _record: &CredentialRecord,
        ) -> std::result::Result<(), CredentialError> {
            unreachable!("read-only test credential store")
        }

        fn delete(
            &self,
            _endpoint: &NormalizedEndpoint,
        ) -> std::result::Result<bool, CredentialError> {
            unreachable!("read-only test credential store")
        }
    }

    /// Run `body` under a scoped WARN-level subscriber and return everything
    /// it logged.
    fn capture_warnings(body: impl FnOnce()) -> String {
        use std::io::Write;
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct VecWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for VecWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(buf);
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

        let _guard = WARNING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(VecWriter(output.clone()))
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, body);
        String::from_utf8(output.lock().expect("lock").clone()).expect("UTF-8")
    }

    fn empty_entry(id: &str) -> AuthConfig {
        AuthConfig {
            id: Some(id.to_string()),
            username: None,
            password: None,
            token: None,
        }
    }

    fn basic(id: Option<&str>, username: &str, password: &str) -> AuthConfig {
        AuthConfig {
            id: id.map(str::to_string),
            username: Some(username.to_string()),
            password: Some(Secret::new(password.to_string())),
            token: None,
        }
    }

    fn bearer(id: Option<&str>, token: &str) -> AuthConfig {
        AuthConfig {
            id: id.map(str::to_string),
            username: None,
            password: None,
            token: Some(Secret::new(token.to_string())),
        }
    }

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
        let auth = store
            .for_repository_with_policy(&repo, false)
            .unwrap()
            .unwrap();

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
        assert!(
            store
                .for_repository_with_policy(&resolved, false)
                .unwrap()
                .is_some()
        );
        // With host_changed: default token is suppressed.
        assert!(
            store
                .for_repository_with_policy(&resolved, true)
                .unwrap()
                .is_none(),
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
        assert!(
            store
                .for_repository_with_policy(&resolved, true)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn cleartext_auth_warn_fires_for_http_non_loopback() {
        let _warning_guard = WARNING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        let auth = store
            .for_repository_with_policy(&repo, false)
            .unwrap()
            .unwrap();

        match auth {
            Auth::Bearer { token } => {
                assert_eq!(token.expose_secret(), "token");
            }
            _ => panic!("expected bearer auth"),
        }
    }

    #[test]
    fn project_basic_replaces_lower_precedence_settings_bearer() {
        let store = AuthStore::with_sources_and_store(
            vec![basic(Some("corp"), "project-user", "project-password")],
            Vec::new(),
            vec![bearer(Some("corp"), "settings-bearer-must-not-survive")],
            Arc::new(RecordingCredentialStore::empty()),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/maven2/",
            true,
            false,
        );

        let auth = store
            .for_repository_with_policy(&repo, false)
            .expect("lookup")
            .expect("auth");
        match auth {
            Auth::Basic { username, password } => {
                assert_eq!(username, "project-user");
                assert_eq!(password.expose_secret(), "project-password");
            }
            Auth::Bearer { .. } => {
                panic!("lower-precedence bearer token survived under project basic auth")
            }
        }
    }

    #[test]
    fn loaded_project_basic_does_not_inherit_settings_bearer() {
        let _env_guard = ENV_LOCK.lock().expect("env lock");
        let home = tempfile::tempdir().expect("home");
        let project = home.path().join("project");
        std::fs::create_dir_all(&project).expect("project");
        std::fs::write(
            project.join("rv.toml"),
            r#"[[auth]]
id = "corp"
username = "project-user"
password = "project-password"
"#,
        )
        .expect("rv.toml");
        let m2 = home.path().join(".m2");
        std::fs::create_dir_all(&m2).expect("m2");
        std::fs::write(
            m2.join("settings.xml"),
            r#"<settings>
  <servers>
    <server>
      <id>corp</id>
      <configuration>
        <httpHeaders>
          <property>
            <name>Authorization</name>
            <value>Bearer lower-settings-token</value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
  </servers>
</settings>"#,
        )
        .expect("settings.xml");
        let home_string = home.path().to_string_lossy().into_owned();
        let raeva_home = home.path().join("raeva");
        let raeva_home_string = raeva_home.to_string_lossy().into_owned();

        temp_env::with_vars(
            [
                ("HOME", Some(home_string.as_str())),
                ("USERPROFILE", Some(home_string.as_str())),
                ("RAEVA_HOME", Some(raeva_home_string.as_str())),
            ],
            || {
                let config = rv_config::Config::load(&project).expect("config");
                let layers = config.auth_layers();
                let store = AuthStore::with_sources_and_store(
                    layers.project().to_vec(),
                    layers.user().to_vec(),
                    layers.settings().to_vec(),
                    Arc::new(RecordingCredentialStore::empty()),
                );
                let repo = Repository::new(
                    Some("corp".to_string()),
                    "https://repo.example/",
                    true,
                    false,
                );

                let auth = store
                    .for_repository_with_policy(&repo, false)
                    .expect("lookup")
                    .expect("auth");
                match auth {
                    Auth::Basic { username, password } => {
                        assert_eq!(username, "project-user");
                        assert_eq!(password.expose_secret(), "project-password");
                    }
                    Auth::Bearer { .. } => {
                        panic!("settings bearer survived under loaded project basic auth")
                    }
                }
            },
        );
    }

    #[test]
    fn user_auth_precedes_settings_auth() {
        let store = AuthStore::with_sources_and_store(
            Vec::new(),
            vec![basic(Some("corp"), "user-config", "user-password")],
            vec![bearer(Some("corp"), "settings-token")],
            Arc::new(RecordingCredentialStore::empty()),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/",
            true,
            false,
        );

        let auth = store
            .for_repository_with_policy(&repo, false)
            .expect("lookup")
            .expect("auth");
        match auth {
            Auth::Basic { username, .. } => assert_eq!(username, "user-config"),
            Auth::Bearer { .. } => panic!("settings auth must not override user config"),
        }
    }

    #[test]
    fn id_scoped_settings_auth_precedes_idless_default() {
        let store = AuthStore::with_sources_and_store(
            vec![bearer(None, "project-default")],
            Vec::new(),
            vec![basic(Some("corp"), "settings-user", "settings-password")],
            Arc::new(RecordingCredentialStore::empty()),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/",
            true,
            false,
        );

        let auth = store
            .for_repository_with_policy(&repo, false)
            .expect("lookup")
            .expect("auth");
        match auth {
            Auth::Basic { username, .. } => assert_eq!(username, "settings-user"),
            Auth::Bearer { .. } => panic!("id-less default must be the final fallback"),
        }
    }

    #[test]
    fn incomplete_higher_precedence_entry_is_a_config_error() {
        let incomplete = AuthConfig {
            id: Some("corp".to_string()),
            username: Some("project-user".to_string()),
            password: None,
            token: None,
        };
        let store = AuthStore::with_sources_and_store(
            vec![incomplete],
            vec![bearer(Some("corp"), "lower-token")],
            Vec::new(),
            Arc::new(RecordingCredentialStore::empty()),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/",
            true,
            false,
        );

        let err = store
            .for_repository_with_policy(&repo, false)
            .expect_err("incomplete project entry must block lower sources");
        let message = err.to_string();
        assert!(message.contains("incomplete project rv.toml auth entry"));
        assert!(message.contains("username and password"));
        assert!(!message.contains("lower-token"));
    }

    #[test]
    fn exact_keyring_endpoint_overrides_config_auth() {
        let keyring = Arc::new(RecordingCredentialStore::with_record(
            "https://repo.example/maven2/",
            CredentialRecord::bearer("keyring-token").expect("record"),
        ));
        let store = AuthStore::with_sources_and_store(
            vec![basic(Some("corp"), "config-user", "config-password")],
            Vec::new(),
            Vec::new(),
            keyring,
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example:443/maven2",
            true,
            false,
        );

        let auth = store
            .for_repository_with_policy(&repo, false)
            .expect("lookup")
            .expect("auth");
        match auth {
            Auth::Bearer { token } => assert_eq!(token.expose_secret(), "keyring-token"),
            Auth::Basic { .. } => panic!("config auth must not override exact keyring endpoint"),
        }
    }

    #[test]
    fn mirror_and_origin_use_separate_endpoint_lookups() {
        let mirror_endpoint = "https://mirror.example/repository/";
        let origin_endpoint = "https://origin.example/maven2/";
        let mut records = HashMap::new();
        records.insert(
            NormalizedEndpoint::parse(mirror_endpoint).expect("mirror endpoint"),
            CredentialRecord::bearer("mirror-token").expect("mirror record"),
        );
        records.insert(
            NormalizedEndpoint::parse(origin_endpoint).expect("origin endpoint"),
            CredentialRecord::basic("origin-user", "origin-password").expect("origin record"),
        );
        let keyring = Arc::new(RecordingCredentialStore {
            records,
            ..RecordingCredentialStore::empty()
        });
        let store =
            AuthStore::with_sources_and_store(Vec::new(), Vec::new(), Vec::new(), keyring.clone());
        let selector = MirrorSelector::from_mirrors(vec![rv_config::MirrorConfig {
            id: Some("mirror".to_string()),
            url: mirror_endpoint.to_string(),
            mirror_of: vec!["central".to_string()],
        }]);
        let origin = Repository::new(Some("central".to_string()), origin_endpoint, true, false);
        let (mirror, host_changed) = selector.resolve_with_host_change(&origin);

        let mirror_auth = store
            .for_repository_with_policy(&mirror, host_changed)
            .expect("mirror lookup")
            .expect("mirror auth");
        let origin_auth = store
            .for_repository_with_policy(&origin, false)
            .expect("origin lookup")
            .expect("origin auth");
        assert!(matches!(mirror_auth, Auth::Bearer { .. }));
        assert!(matches!(origin_auth, Auth::Basic { .. }));
        let lookups = keyring.lookups.lock().expect("lock");
        assert_eq!(
            lookups.as_slice(),
            [
                NormalizedEndpoint::parse(mirror_endpoint).expect("mirror"),
                NormalizedEndpoint::parse(origin_endpoint).expect("origin"),
            ]
        );
    }

    #[test]
    fn unavailable_keyring_warns_once_and_falls_through() {
        let _warning_guard = WARNING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        use std::io::Write;
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct VecWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for VecWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(buf);
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

        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(VecWriter(output.clone()))
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let store = AuthStore::with_sources_and_store(
            vec![basic(Some("corp"), "config-user", "config-password")],
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::failing(StoreFailure::Unavailable)),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/",
            true,
            false,
        );

        tracing::subscriber::with_default(subscriber, || {
            assert!(
                store
                    .for_repository_with_policy(&repo, false)
                    .expect("first lookup")
                    .is_some()
            );
            assert!(
                store
                    .for_repository_with_policy(&repo, false)
                    .expect("second lookup")
                    .is_some()
            );
        });

        let output = String::from_utf8(output.lock().expect("lock").clone()).expect("UTF-8");
        assert_eq!(output.matches("KEYRING_UNAVAILABLE").count(), 1);
    }

    #[test]
    fn concurrent_lookup_waits_for_keyring_warning_emission() {
        use std::io::Write;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Barrier, mpsc};
        use std::thread;
        use std::time::Duration;
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone)]
        struct BlockingWriter {
            entered: Arc<Barrier>,
            release: Arc<Barrier>,
            blocked_once: Arc<AtomicBool>,
        }

        impl Write for BlockingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if !self.blocked_once.swap(true, Ordering::SeqCst) {
                    self.entered.wait();
                    self.release.wait();
                }
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for BlockingWriter {
            type Writer = BlockingWriter;

            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let _warning_guard = WARNING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(BlockingWriter {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                blocked_once: Arc::new(AtomicBool::new(false)),
            })
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let store = AuthStore::with_sources_and_store(
            vec![basic(Some("corp"), "config-user", "config-password")],
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::failing(StoreFailure::Unavailable)),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/",
            true,
            false,
        );

        let first_store = store.clone();
        let first_repo = repo.clone();
        let first = thread::spawn(move || {
            tracing::subscriber::with_default(subscriber, || {
                first_store
                    .for_repository_with_policy(&first_repo, false)
                    .expect("first lookup")
            })
        });
        entered.wait();

        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let second = thread::spawn(move || {
            started_tx.send(()).expect("signal start");
            let result = store
                .for_repository_with_policy(&repo, false)
                .expect("second lookup");
            done_tx.send(result.is_some()).expect("signal completion");
        });
        started_rx.recv().expect("second lookup started");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "a concurrent lookup returned before the warn-once event finished emitting"
        );

        release.wait();
        assert!(first.join().expect("first thread").is_some());
        assert!(done_rx.recv().expect("second lookup completed"));
        second.join().expect("second thread");
    }

    #[test]
    fn missing_keyring_entry_warns_once_and_falls_through() {
        let _warning_guard = WARNING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        use std::io::Write;
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct VecWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for VecWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(buf);
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

        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(VecWriter(output.clone()))
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let store = AuthStore::with_sources_and_store(
            vec![basic(Some("corp"), "config-user", "config-password")],
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::empty()),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/",
            true,
            false,
        );

        tracing::subscriber::with_default(subscriber, || {
            assert!(
                store
                    .for_repository_with_policy(&repo, false)
                    .expect("first lookup")
                    .is_some()
            );
            assert!(
                store
                    .for_repository_with_policy(&repo, false)
                    .expect("second lookup")
                    .is_some()
            );
        });

        let output = String::from_utf8(output.lock().expect("lock").clone()).expect("UTF-8");
        assert_eq!(output.matches("KEYRING_ENTRY_MISSING").count(), 1);
    }

    #[test]
    fn corrupt_keyring_record_is_a_hard_error() {
        let store = AuthStore::with_sources_and_store(
            vec![basic(Some("corp"), "config-user", "config-password")],
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::failing(StoreFailure::Corrupt)),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/",
            true,
            false,
        );

        let err = store
            .for_repository_with_policy(&repo, false)
            .expect_err("corrupt keyring record must not fall through");
        assert!(err.to_string().contains("credential record is corrupt"));
        assert!(!err.to_string().contains("config-password"));
    }

    /// A lockfile records the mirror-SUBSTITUTED url, so a later sync hands
    /// the mirror's own url to the fetch path and mirror selection can no
    /// longer see the host change. The default (no-id) credential must still
    /// be withheld from that third-party origin.
    #[test]
    fn mirror_url_alone_suppresses_the_default_credential() {
        let store = AuthStore::with_sources_and_store(
            vec![bearer(None, "corp-token")],
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::empty()),
        )
        .with_foreign_mirrors(&["https://cdn.example/maven"]);
        // `repository_for_package` rebuilds the repo from the mirror entry, so
        // it carries the MIRROR's id and the caller's flag reads false.
        let recorded = Repository::new(
            Some("cdn".to_string()),
            "https://cdn.example/maven/",
            true,
            true,
        );

        assert!(
            store
                .for_repository_with_policy(&recorded, false)
                .expect("lookup")
                .is_none(),
            "the corp default token must not reach a cross-host mirror on re-sync"
        );
    }

    /// Control: a mirror sharing an origin with a configured repository is not
    /// foreign, so the default credential still flows to it.
    #[test]
    fn same_host_mirror_url_still_receives_the_default_credential() {
        let store = AuthStore::with_sources_and_store(
            vec![bearer(None, "corp-token")],
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::empty()),
        )
        .with_foreign_mirrors(&["https://cdn.example/maven"]);
        let recorded = Repository::new(
            Some("internal".to_string()),
            "https://nexus.corp/mirror/",
            true,
            true,
        );

        assert!(
            store
                .for_repository_with_policy(&recorded, false)
                .expect("lookup")
                .is_some()
        );
    }

    /// The mirror's OWN id-scoped credential is still honored on a re-sync:
    /// the user paired that id with that url deliberately.
    #[test]
    fn mirror_url_still_honors_the_mirror_id_credential() {
        let store = AuthStore::with_sources_and_store(
            vec![bearer(Some("cdn"), "cdn-token"), bearer(None, "corp-token")],
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::empty()),
        )
        .with_foreign_mirrors(&["https://cdn.example/maven"]);
        let recorded = Repository::new(
            Some("cdn".to_string()),
            "https://cdn.example/maven/",
            true,
            true,
        );

        match store
            .for_repository_with_policy(&recorded, false)
            .expect("lookup")
            .expect("auth")
        {
            Auth::Bearer { token } => assert_eq!(token.expose_secret(), "cdn-token"),
            Auth::Basic { .. } => panic!("expected the mirror's own bearer token"),
        }
    }

    /// Regression: a repo url the credential-endpoint normalizer rejects must
    /// not abort the resolve. It has no keyring identity, nothing more.
    #[test]
    fn query_string_repo_url_fetches_anonymously_with_a_warn() {
        let store = AuthStore::with_sources_and_store(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::empty()),
        );
        let repo = Repository::new(
            None,
            "https://repo.example/maven2?api_key=s3cr3t",
            true,
            false,
        );

        let output = capture_warnings(|| {
            assert!(
                store
                    .for_repository_with_policy(&repo, false)
                    .expect("an unnormalizable repo url must not fail the lookup")
                    .is_none(),
                "no credentials are configured, so the fetch is anonymous"
            );
        });
        assert!(
            output.contains("repo.example"),
            "expected a warn naming the repository, got: {output}"
        );
        assert!(
            !output.contains("s3cr3t"),
            "the query string may carry a secret and must be redacted: {output}"
        );
        // The strict normalizer still governs endpoints being STORED.
        assert!(NormalizedEndpoint::parse("https://repo.example/maven2?api_key=s3cr3t").is_err());
    }

    /// The same for embedded userinfo, and configured credentials still apply
    /// to the repository: only the keyring lookup is skipped.
    #[test]
    fn userinfo_repo_url_still_resolves_configured_auth() {
        let store = AuthStore::with_sources_and_store(
            vec![bearer(Some("corp"), "corp-token")],
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::empty()),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://alice:hunter2@nexus.corp/repo/",
            true,
            false,
        );

        let mut resolved = None;
        let output = capture_warnings(|| {
            resolved = store
                .for_repository_with_policy(&repo, false)
                .expect("lookup");
        });
        match resolved.expect("auth") {
            Auth::Bearer { token } => assert_eq!(token.expose_secret(), "corp-token"),
            Auth::Basic { .. } => panic!("expected the id-matched bearer token"),
        }
        assert!(
            !output.contains("hunter2"),
            "userinfo must be redacted out of the warn: {output}"
        );
        assert!(NormalizedEndpoint::parse("https://alice:hunter2@nexus.corp/repo/").is_err());
    }

    /// Regression: a settings.xml `<server>` carrying only fields rv does not
    /// model (privateKey/passphrase, standard for scp deploys) must not poison
    /// its repository id. It is skipped, and the sync continues.
    #[test]
    fn auth_entry_without_any_modeled_field_is_skipped() {
        let store = AuthStore::with_sources_and_store(
            Vec::new(),
            Vec::new(),
            vec![empty_entry("corp")],
            Arc::new(RecordingCredentialStore::empty()),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/",
            true,
            false,
        );

        let output = capture_warnings(|| {
            assert!(
                store
                    .for_repository_with_policy(&repo, false)
                    .expect("an entry with no modeled credential must not fail the lookup")
                    .is_none(),
                "nothing else is configured, so the fetch is anonymous"
            );
        });
        assert!(
            output.contains("corp"),
            "the warn must name the id it skipped, got: {output}"
        );
    }

    /// Skipping is a fall-through, not a stop: a lower-precedence source that
    /// does carry credentials for the id still applies.
    #[test]
    fn skipped_empty_entry_falls_through_to_a_lower_source() {
        let store = AuthStore::with_sources_and_store(
            vec![empty_entry("corp")],
            vec![bearer(Some("corp"), "user-token")],
            Vec::new(),
            Arc::new(RecordingCredentialStore::empty()),
        );
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/",
            true,
            false,
        );

        match store
            .for_repository_with_policy(&repo, false)
            .expect("lookup")
            .expect("auth")
        {
            Auth::Bearer { token } => assert_eq!(token.expose_secret(), "user-token"),
            Auth::Basic { .. } => panic!("expected the lower source's bearer token"),
        }
    }

    /// The documented contract stands: a PARTIALLY filled entry is still a
    /// hard error, and a token-only entry still works.
    #[test]
    fn partial_entry_still_errors_and_token_only_entry_still_works() {
        let partial = AuthConfig {
            id: Some("corp".to_string()),
            username: Some("user".to_string()),
            password: None,
            token: None,
        };
        let repo = Repository::new(
            Some("corp".to_string()),
            "https://repo.example/",
            true,
            false,
        );

        let store = AuthStore::with_sources_and_store(
            vec![partial],
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::empty()),
        );
        let err = store
            .for_repository_with_policy(&repo, false)
            .expect_err("username without password stays a hard error");
        assert!(
            err.to_string()
                .contains("incomplete project rv.toml auth entry")
        );

        let store = AuthStore::with_sources_and_store(
            vec![bearer(Some("corp"), "corp-token")],
            Vec::new(),
            Vec::new(),
            Arc::new(RecordingCredentialStore::empty()),
        );
        assert!(
            store
                .for_repository_with_policy(&repo, false)
                .expect("lookup")
                .is_some()
        );
    }

    #[test]
    fn settings_env_interpolation_reaches_effective_basic_auth_and_redacts() {
        let _env_guard = ENV_LOCK.lock().expect("env lock");
        let home = tempfile::tempdir().expect("home");
        let project = home.path().join("project");
        std::fs::create_dir_all(&project).expect("project");
        let m2 = home.path().join(".m2");
        std::fs::create_dir_all(&m2).expect("m2");
        std::fs::write(
            m2.join("settings.xml"),
            r#"<settings>
  <servers>
    <server>
      <id>corp</id>
      <username>${env.RAEVA_USER}</username>
      <password>${env.RAEVA_TOKEN}</password>
    </server>
  </servers>
</settings>"#,
        )
        .expect("settings.xml");
        let home_string = home.path().to_string_lossy().into_owned();
        let raeva_home = home.path().join("raeva");
        let raeva_home_string = raeva_home.to_string_lossy().into_owned();
        let ci_user = "ci-interpolated-user";
        let ci_secret = "ci-interpolated-secret";

        temp_env::with_vars(
            [
                ("HOME", Some(home_string.as_str())),
                ("USERPROFILE", Some(home_string.as_str())),
                ("RAEVA_HOME", Some(raeva_home_string.as_str())),
                ("RAEVA_USER", Some(ci_user)),
                ("RAEVA_TOKEN", Some(ci_secret)),
            ],
            || {
                let config = rv_config::Config::load(&project).expect("config");
                let layers = config.auth_layers();
                let store = AuthStore::with_sources_and_store(
                    layers.project().to_vec(),
                    layers.user().to_vec(),
                    layers.settings().to_vec(),
                    Arc::new(RecordingCredentialStore::empty()),
                );
                let repo = Repository::new(
                    Some("corp".to_string()),
                    "https://repo.example/",
                    true,
                    false,
                );
                let auth = store
                    .for_repository_with_policy(&repo, false)
                    .expect("lookup")
                    .expect("auth");

                match &auth {
                    Auth::Basic { username, password } => {
                        assert_eq!(username, ci_user);
                        assert_eq!(password.expose_secret(), ci_secret);
                    }
                    Auth::Bearer { .. } => panic!("settings password must construct basic auth"),
                }
                for rendered in [
                    format!("{auth:?}"),
                    format!("{store:?}"),
                    format!("{config:?}"),
                ] {
                    assert!(!rendered.contains(ci_secret), "secret leaked: {rendered}");
                    assert!(!rendered.contains("${env.RAEVA_TOKEN}"));
                }
            },
        );
    }
}
