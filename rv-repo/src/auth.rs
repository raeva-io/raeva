use reqwest::RequestBuilder;
use rv_config::{AuthConfig, AuthConfigLayers};
use rv_store::metadata_cache::KeyedDigest;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::error::{RepoError, Result};
use crate::repository::Repository;

#[derive(Clone)]
pub(crate) struct Auth {
    pub(crate) scheme: Scheme,
    pub(crate) sent: SentCredential,
}

/// Repository authentication methods.
///
/// - `Basic`: username and password via HTTP Basic authentication.
/// - `Bearer`: token via the Bearer scheme.
#[derive(Clone)]
pub(crate) enum Scheme {
    Basic {
        username: String,
        password: SecretString,
    },
    Bearer {
        token: SecretString,
    },
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.scheme {
            Scheme::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"***")
                .finish(),
            Scheme::Bearer { .. } => f.debug_struct("Bearer").field("token", &"***").finish(),
        }
    }
}

impl Auth {
    pub(crate) fn apply(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.scheme {
            Scheme::Basic { username, password } => {
                request.basic_auth(username, Some(password.expose_secret()))
            }
            Scheme::Bearer { token } => request.bearer_auth(token.expose_secret()),
        }
    }

    /// A keyed digest of this credential as sent to `endpoint`, which tells
    /// it from another credential, such as a replaced token, in the keys of
    /// answers kept across runs, without holding the secret.
    pub(crate) fn identity(&self, endpoint: &str, mut digest: KeyedDigest) -> String {
        let mut field = |bytes: &[u8]| {
            digest.update(&(bytes.len() as u64).to_le_bytes());
            digest.update(bytes);
        };
        field(endpoint.as_bytes());
        match &self.scheme {
            Scheme::Basic { username, password } => {
                field(b"basic");
                field(username.as_bytes());
                field(password.expose_secret().as_bytes());
            }
            Scheme::Bearer { token } => {
                field(b"bearer");
                field(token.expose_secret().as_bytes());
            }
        }
        digest.finalize_hex()
    }
}

/// The credential a refused request carried, by where it came from. It
/// holds no secret, so errors carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentCredential {
    /// The entry's id, `None` for the default entry.
    pub id: Option<String>,
    /// The file that holds the entry.
    pub file: CredentialFile,
    /// The variables of `${env.NAME}` references in a settings.xml entry
    /// that are not set, so the repository received the reference as
    /// written.
    pub unset_variables: Vec<String>,
}

/// A file credentials are read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFile {
    /// The project `raeva.toml`.
    Project,
    /// The user `config.toml`.
    User,
    /// Maven's `settings.xml`.
    Settings,
}

impl CredentialFile {
    fn label(self) -> &'static str {
        match self {
            Self::Project => "project raeva.toml",
            Self::User => "user config",
            Self::Settings => "settings.xml",
        }
    }
}

/// Loopback by parsed host: `localhost`, any 127.0.0.0/8 address, or `::1`.
/// A DNS name such as `127.example.com` is not loopback.
fn is_loopback_host(host: Option<url::Host<&str>>) -> bool {
    match host {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

#[derive(Debug, Clone, Default)]
struct ConfigAuthLayers {
    project: Vec<AuthConfig>,
    user: Vec<AuthConfig>,
    settings: Vec<AuthConfig>,
}

impl ConfigAuthLayers {
    fn by_file(&self) -> [(CredentialFile, &[AuthConfig]); 3] {
        [
            (CredentialFile::Project, &self.project),
            (CredentialFile::User, &self.user),
            (CredentialFile::Settings, &self.settings),
        ]
    }

    /// Whether a layer holds a default credential, one without an id.
    fn has_default(&self) -> bool {
        (self.by_file().iter()).any(|(_, configs)| configs.iter().any(|entry| entry.id.is_none()))
    }
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

#[derive(Clone)]
pub(crate) struct AuthStore {
    layers: ConfigAuthLayers,
    // Warn-once dedup for credential warnings, keyed by a per-kind prefix
    // (`id-withheld:`, `default-withheld`) so the kinds cannot collide.
    unusable_warned: Arc<Mutex<HashSet<String>>>,
    // Per-instance dedup so independent AuthStores (e.g. per-test fixtures)
    // do not interfere with each other's CLEARTEXT_AUTH warning state.
    // Arc<Mutex<>> so clones of an AuthStore share the dedup set, which
    // matches the previous process-wide semantics for a single logical store
    // while keeping the set scoped per-instance.
    cleartext_warned: Arc<Mutex<HashSet<(String, String)>>>,
    /// The origins of the configured repositories, mirrors and transitive
    /// repository allowlist, and of the repositories the project's own POMs
    /// declare, when the store was built from a configuration. An entry with
    /// an id goes to a repository a fetched POM declares only on one of
    /// these: such a POM must not choose where the secret goes, but a
    /// corporate parent may pair another id with a host the project uses.
    named_origins: Option<NamedOrigins>,
    /// The origins of the repositories and mirrors that the user's own
    /// files name (see [`rv_config::Config::user_endpoint_urls`]), when the
    /// store was built from a configuration. An entry without an id goes
    /// only to these: nothing else ties it to an origin, and the project's
    /// POMs and `raeva.toml` must not choose where it goes.
    user_origins: Option<Arc<HashSet<String>>>,
    /// Credential lookups made through this store and its clones.
    #[cfg(test)]
    lookups: Arc<std::sync::atomic::AtomicUsize>,
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
        Self::new(ConfigAuthLayers::default())
    }
}

impl AuthStore {
    pub(crate) fn from_config(config: &rv_config::Config) -> Result<Self> {
        let configured = (config.repositories().iter().map(|repo| repo.url.as_str()))
            .chain(config.mirrors().iter().map(|mirror| mirror.url.as_str()))
            .chain(config.user_endpoint_urls().iter().map(String::as_str));
        let named = NamedOrigins::default();
        (configured.chain(
            config
                .security
                .transitive_repository_allowlist
                .iter()
                .map(String::as_str),
        ))
        .for_each(|url| named.add(url));
        let user_origins = config
            .user_endpoint_urls()
            .iter()
            .filter_map(|url| http_origin(url))
            .collect();
        Ok(Self {
            named_origins: Some(named),
            user_origins: Some(Arc::new(user_origins)),
            ..Self::new(ConfigAuthLayers::from(config.auth_layers()))
        })
    }

    /// Treat `urls` as the configured repositories, which the user's own
    /// files name.
    #[cfg(test)]
    pub(crate) fn with_configured_urls(mut self, urls: &[&str]) -> Self {
        let named = NamedOrigins::default();
        urls.iter().for_each(|url| named.add(url));
        self.user_origins = Some(Arc::new(
            urls.iter().filter_map(|url| http_origin(url)).collect(),
        ));
        self.named_origins = Some(named);
        self
    }

    /// Where [`crate::RepositoryPolicy`] records the origins of the project's
    /// own POM repositories, when this store limits fetched POMs to named
    /// origins.
    pub(crate) fn named_origins(&self) -> Option<NamedOrigins> {
        self.named_origins.clone()
    }

    /// How many times the named origins have grown, so a miss recorded
    /// before a credential could follow is asked again.
    pub(crate) fn generation(&self) -> u64 {
        self.named_origins
            .as_ref()
            .map_or(0, |named| named.generation())
    }

    #[cfg(test)]
    pub(crate) fn from_auth_configs(configs: &[rv_config::AuthConfig]) -> Result<Self> {
        Ok(Self::new(ConfigAuthLayers {
            project: configs.to_vec(),
            ..ConfigAuthLayers::default()
        }))
    }

    fn new(layers: ConfigAuthLayers) -> Self {
        Self {
            layers,
            unusable_warned: Arc::new(Mutex::new(HashSet::new())),
            cleartext_warned: Arc::new(Mutex::new(HashSet::new())),
            named_origins: None,
            user_origins: None,
            #[cfg(test)]
            lookups: Arc::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn lookups(&self) -> usize {
        self.lookups.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    fn with_sources(
        project: Vec<AuthConfig>,
        user: Vec<AuthConfig>,
        settings: Vec<AuthConfig>,
    ) -> Self {
        Self::new(ConfigAuthLayers {
            project,
            user,
            settings,
        })
    }

    /// Look up auth for `repo`, the endpoint of a [`crate::routing::Route`].
    ///
    /// `host_changed` is the route's `cross_origin`: the endpoint is a mirror
    /// on another origin than the repository it replaced. The user's default
    /// (no-id) credential is then withheld, since a third-party CDN must not
    /// receive a Nexus bearer token. Id-matched entries still apply: the user
    /// paired that id with that endpoint.
    pub(crate) fn for_repository_with_policy(
        &self,
        repo: &Repository,
        host_changed: bool,
    ) -> Result<Option<Auth>> {
        #[cfg(test)]
        self.lookups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(resolved) = self.lookup_auth(repo, host_changed)? else {
            return Ok(None);
        };
        // Auth resolved. If we'd attach it over plaintext HTTP to a
        // non-loopback host, fire the CLEARTEXT_AUTH warn. Per-instance
        // dedup so a fan-out fetch only warns once per (host, scheme).
        if let Ok(url) = url::Url::parse(&repo.url)
            && url.scheme() == "http"
            && let Some(host) = url.host_str()
            && !is_loopback_host(url.host())
        {
            self.warn_cleartext_auth_once(host, url.scheme());
        }
        Ok(Some(resolved))
    }

    fn lookup_auth(&self, repo: &Repository, host_changed: bool) -> Result<Option<Auth>> {
        if let Some(id) = repo.id.as_deref() {
            for (file, configs) in self.layers.by_file() {
                let source = file.label();
                if let Some(config) = configs.iter().find(|entry| entry.id.as_deref() == Some(id)) {
                    // An entry carrying none of the fields raeva models says
                    // nothing about HTTP credentials for this id: a
                    // settings.xml `<server>` may exist purely for
                    // `<privateKey>`/`<passphrase>` scp deploys. Skipping it
                    // keeps the id usable; a PARTIALLY filled entry (say a
                    // username with no password) is still a hard error.
                    if config.token.is_none()
                        && config.username.is_none()
                        && config.password.is_none()
                    {
                        tracing::debug!(
                            repo_id = id,
                            auth_source = source,
                            "ignoring auth entry with no username, password or token"
                        );
                        continue;
                    }
                    if self.withholds_id_credential(id, repo, source) {
                        return Ok(None);
                    }
                    let auth = build_complete_auth(config, file, source)?;
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
            // Only a default credential that exists is withheld; without one
            // there is nothing to say.
            if self.layers.has_default() {
                tracing::warn!(
                    sec_code = "CROSS_HOST_MIRROR",
                    repo_url = %rv_config::redact_url(&repo.url),
                    "not sending the default credential to the mirror {}, which is on another host than the repository it mirrors",
                    rv_config::redact_url(&repo.url)
                );
            }
            return Ok(None);
        }

        if self.withholds_default_credential(repo) {
            return Ok(None);
        }

        for (file, configs) in self.layers.by_file() {
            if let Some(config) = configs.iter().find(|entry| entry.id.is_none()) {
                let source = format!("{} default", file.label());
                return build_complete_auth(config, file, &source).map(Some);
            }
        }
        Ok(None)
    }

    /// Whether the entry for `id` is kept from `repo`, which a fetched POM
    /// declares on an origin no configured repository or mirror and no
    /// repository of the project's own POMs names. The project's own POMs
    /// are trusted to pair their ids with `settings.xml` servers, as in
    /// Maven. Reported once per id and origin.
    fn withholds_id_credential(&self, id: &str, repo: &Repository, source: &str) -> bool {
        if repo.provenance() != crate::Provenance::FetchedPom {
            return false;
        }
        let Some(named) = self.named_origins.as_ref() else {
            return false;
        };
        let origin = http_origin(&repo.url);
        if origin
            .as_deref()
            .is_some_and(|origin| named.contains(origin))
        {
            return false;
        }
        let origin = origin.unwrap_or_else(|| rv_config::redact_url(&repo.url));
        let key = format!("id-withheld:{id}\u{1f}{origin}");
        let (id, source) = (id.to_string(), source.to_string());
        self.warn_unusable_once(key, move || {
            tracing::warn!(
                sec_code = "ID_CREDENTIAL_WITHHELD",
                repo_id = id,
                origin = %origin,
                auth_source = source,
                "not sending the credential for repository id '{id}' to {origin}: a POM \
                 fetched from a repository declared it, and neither your configuration nor \
                 the project's POMs name that origin; declare the repository in raeva.toml, \
                 config.toml or settings.xml if it should get the credential"
            )
        });
        true
    }

    /// Whether an entry without an id is kept from `repo`, whose origin no
    /// repository or mirror in the user's own files names. A project could
    /// otherwise collect it by declaring a repository on its own host in a
    /// POM or `raeva.toml`, and so could any POM fetched from a repository.
    fn withholds_default_credential(&self, repo: &Repository) -> bool {
        let Some(user_origins) = self.user_origins.as_deref() else {
            return false;
        };
        let origin = http_origin(&repo.url);
        if origin
            .as_ref()
            .is_some_and(|origin| user_origins.contains(origin))
        {
            return false;
        }
        if self.layers.has_default() {
            let origin = origin.unwrap_or_else(|| rv_config::redact_url(&repo.url));
            self.warn_unusable_once(format!("default-withheld\u{1f}{origin}"), move || {
                tracing::warn!(
                    sec_code = "DEFAULT_CREDENTIAL_WITHHELD",
                    origin = %origin,
                    "not sending the [[auth]] entry without an id to {origin}: no repository \
                     or mirror in config.toml or settings.xml names that origin; declare the \
                     repository there, or give it an id and an [[auth]] entry with that id"
                )
            });
        }
        true
    }

    fn warn_unusable_once(&self, key: String, emit: impl FnOnce() + Send + Sync + 'static) {
        let warned = Arc::clone(&self.unusable_warned);
        rv_maven_model::held::when_shown(move || {
            let first = (warned.lock())
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(key);
            if first {
                emit();
            }
        });
    }

    fn warn_cleartext_auth_once(&self, host: &str, scheme: &str) {
        let warned = Arc::clone(&self.cleartext_warned);
        let (host, scheme) = (host.to_string(), scheme.to_string());
        rv_maven_model::held::when_shown(move || {
            // A poisoned lock means another thread panicked while updating
            // the dedup set; surfacing the warn is still safer than dropping.
            let first = (warned.lock())
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert((host.clone(), scheme));
            if first {
                tracing::warn!(
                    sec_code = "CLEARTEXT_AUTH",
                    host = %host,
                    "attaching credentials to a plaintext HTTP request"
                );
            }
        });
    }
}

/// See [`AuthStore::named_origins`]. Grows while a resolution admits the
/// project's POM repositories.
#[derive(Clone, Default)]
pub(crate) struct NamedOrigins(Arc<RwLock<HashSet<String>>>, Arc<AtomicU64>);

impl NamedOrigins {
    pub(crate) fn add(&self, url: &str) {
        if let Some(origin) = http_origin(url)
            && self
                .0
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(origin)
        {
            self.1.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// How many origins have been added: an answer a request got before
    /// the count changed may have been to a credential since allowed.
    pub(crate) fn generation(&self) -> u64 {
        self.1.load(Ordering::Relaxed)
    }

    fn contains(&self, origin: &str) -> bool {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(origin)
    }
}

fn http_origin(url: &str) -> Option<String> {
    let url = url::Url::parse(url.trim()).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

impl Auth {
    fn method(&self) -> &'static str {
        match self.scheme {
            Scheme::Basic { .. } => "basic",
            Scheme::Bearer { .. } => "bearer",
        }
    }
}

fn build_complete_auth(config: &AuthConfig, file: CredentialFile, source: &str) -> Result<Auth> {
    let scheme = complete_scheme(config, source)?;
    let texts = match &scheme {
        Scheme::Basic { username, password } => vec![username.as_str(), password.expose_secret()],
        Scheme::Bearer { token } => vec![token.expose_secret()],
    };
    let mut unset_variables: Vec<String> = Vec::new();
    // Only settings.xml interpolates, so only there does reference text
    // stand for an unset variable.
    if file == CredentialFile::Settings {
        for name in texts.into_iter().flat_map(rv_config::unset_env_references) {
            if !unset_variables.contains(&name) {
                unset_variables.push(name);
            }
        }
    }
    let sent = SentCredential {
        id: config.id.clone(),
        file,
        unset_variables,
    };
    Ok(Auth { scheme, sent })
}

fn complete_scheme(config: &AuthConfig, source: &str) -> Result<Scheme> {
    if let Some(token) = config.token.as_ref() {
        if token.expose_secret().is_empty() {
            return Err(incomplete_auth_error(
                config,
                source,
                "bearer auth requires a non-empty token",
            ));
        }
        return Ok(Scheme::Bearer {
            token: token.clone(),
        });
    }

    match (&config.username, &config.password) {
        (Some(username), Some(password))
            if !username.is_empty() && !password.expose_secret().is_empty() =>
        {
            Ok(Scheme::Basic {
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
    RepoError::AuthSetup(format!("incomplete {source} auth entry{target}: {details}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::{Auth, AuthStore, Scheme, is_loopback_host};
    use crate::repository::Repository;
    use rv_config::AuthConfig;
    use rv_test_support::capture_warnings;
    use secrecy::{ExposeSecret, SecretString};

    #[test]
    fn loopback_is_decided_on_the_parsed_host() {
        #[rustfmt::skip]
        let cases = [
            ("http://localhost/", true), ("http://LOCALHOST:8080/", true), ("http://127.255.0.9/", true),
            ("http://[::1]/", true), ("http://127.example.com/", false), ("http://127.0.0.1.evil.test/", false),
            ("http://localhost.evil.test/", false), ("http://10.0.0.1/", false), ("http://[::2]/", false),
        ];
        for (url, loopback) in cases {
            assert_eq!(
                is_loopback_host(url::Url::parse(url).unwrap().host()),
                loopback,
                "{url}"
            );
        }
    }

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn empty_entry(id: &str) -> AuthConfig {
        let mut auth = AuthConfig::new(None);
        auth.id = Some(id.to_string());
        auth
    }

    fn basic(id: Option<&str>, username: &str, password: &str) -> AuthConfig {
        let mut auth = AuthConfig::new(id);
        auth.username = Some(username.to_string());
        auth.password = Some(SecretString::from(password.to_string()));
        auth
    }

    fn bearer(id: Option<&str>, token: &str) -> AuthConfig {
        let mut auth = AuthConfig::new(id);
        auth.token = Some(SecretString::from(token.to_string()));
        auth
    }

    fn repo(id: Option<&str>, url: &str) -> Repository {
        Repository::new(id.map(str::to_string), url, true, false)
    }

    fn sources(
        project: Vec<AuthConfig>,
        user: Vec<AuthConfig>,
        settings: Vec<AuthConfig>,
    ) -> AuthStore {
        AuthStore::with_sources(project, user, settings)
    }

    fn shown(auth: Option<&Auth>) -> Option<String> {
        auth.map(|auth| match &auth.scheme {
            Scheme::Basic { username, password } => {
                format!("basic {username} {}", password.expose_secret())
            }
            Scheme::Bearer { token } => format!("bearer {}", token.expose_secret()),
        })
    }

    /// Which entry answers for a repository id: the id-matched entry of the
    /// highest-precedence source that carries a credential, then the id-less
    /// default, which is withheld from a cross-host mirror. A `<server>` with
    /// only fields raeva does not model, such as an scp private key, is skipped.
    #[test]
    fn credentials_follow_id_precedence_and_host_change() {
        let (corp, cdn) = ("https://repo.example/", "https://cdn.example/");
        let (none, empty) = (Vec::new, || vec![empty_entry("corp")]);
        #[rustfmt::skip]
        let cases = [
            (sources(vec![basic(Some("corp"), "u", "p")], none(), none()), Some("corp"), corp, false, Some("basic u p")),
            (sources(vec![bearer(None, "token")], none(), none()), None, corp, false, Some("bearer token")),
            (sources(none(), none(), vec![bearer(None, "default")]), Some("central"), cdn, true, None),
            (sources(none(), none(), vec![bearer(Some("corp"), "id-token")]), Some("corp"), cdn, true, Some("bearer id-token")),
            (sources(vec![basic(Some("corp"), "project-user", "pw")], none(), vec![bearer(Some("corp"), "lower")]),
                Some("corp"), corp, false, Some("basic project-user pw")),
            (sources(none(), vec![basic(Some("corp"), "user-config", "pw")], vec![bearer(Some("corp"), "lower")]),
                Some("corp"), corp, false, Some("basic user-config pw")),
            (sources(vec![bearer(None, "project-default")], none(), vec![basic(Some("corp"), "settings-user", "pw")]),
                Some("corp"), corp, false, Some("basic settings-user pw")),
            (sources(none(), none(), empty()), Some("corp"), corp, false, None),
            (sources(empty(), vec![bearer(Some("corp"), "user-token")], none()), Some("corp"), corp, false, Some("bearer user-token")),
        ];
        for (index, (store, id, url, host_changed, expected)) in cases.into_iter().enumerate() {
            let auth = store
                .for_repository_with_policy(&repo(id, url), host_changed)
                .unwrap();
            assert_eq!(shown(auth.as_ref()).as_deref(), expected, "case {index}");
        }
    }

    #[test]
    fn incomplete_higher_precedence_entry_is_a_config_error() {
        let mut incomplete = AuthConfig::new(Some("corp"));
        incomplete.username = Some("project-user".to_string());
        let store = sources(
            vec![incomplete],
            vec![bearer(Some("corp"), "lower-token")],
            Vec::new(),
        );
        let err = store
            .for_repository_with_policy(&repo(Some("corp"), "https://repo.example/"), false)
            .expect_err("incomplete project entry must block lower sources");
        let message = err.to_string();
        assert!(message.contains("incomplete project raeva.toml auth entry"));
        assert!(message.contains("username and password"));
        assert!(!message.contains("lower-token"));
    }

    #[test]
    fn cleartext_auth_warns_once_per_host_and_not_for_loopback() {
        let store = sources(vec![bearer(None, "token")], vec![], vec![]);
        let output = capture_warnings(|| {
            for url in [
                "http://repo.example/",
                "http://repo.example/other",
                "http://127.0.0.1:8080/",
                "http://localhost/",
            ] {
                let _ = store.for_repository_with_policy(&repo(None, url), false);
            }
        });
        assert_eq!(output.matches("CLEARTEXT_AUTH").count(), 1, "{output}");
        assert!(output.contains("repo.example"), "{output}");
        assert!(
            !output.contains("127.0.0.1") && !output.contains("localhost"),
            "{output}"
        );
    }

    /// A lookup whose events are held and never shown leaves the warning to
    /// the next one.
    #[test]
    fn a_dropped_hold_leaves_the_cleartext_warning_to_the_next_lookup() {
        let store = sources(vec![bearer(None, "token")], vec![], vec![]);
        let output = capture_warnings(|| {
            let holds = rv_maven_model::held::Holds::default();
            let lookup = async {
                store.for_repository_with_policy(&repo(None, "http://repo.example/"), false)
            };
            drop(futures::executor::block_on(holds.hold(lookup)));
            let _ = store.for_repository_with_policy(&repo(None, "http://repo.example/"), false);
        });
        assert_eq!(output.matches("CLEARTEXT_AUTH").count(), 1, "{output}");
    }

    /// An id-scoped credential goes to any repository the configuration or
    /// the project's own POMs declare with the id, as in Maven, but to one a
    /// fetched POM declares only on an origin those name. Withholding it is
    /// reported once, without the secret.
    #[test]
    fn a_fetched_pom_cannot_send_an_id_credential_to_its_own_origin() {
        let store = AuthStore::from_auth_configs(&[bearer(Some("corp"), "corp-secret")])
            .unwrap()
            .with_configured_urls(&["https://nexus.corp/maven/"]);
        let policy = crate::RepositoryPolicy::new(
            &rv_config::Config::for_testing(
                ".".into(),
                rv_config::ResolvedPaths::for_testing().unwrap(),
            ),
            crate::transport::ClientSet::screened().grants(),
            store.named_origins(),
        );
        // The project's own POM pairs a repository with a settings.xml
        // server by id; that is the usual Maven setup.
        let project = policy
            .admit(
                [repo(Some("corp"), "https://nexus2.corp/maven/")],
                crate::Declaration::LocalPom,
            )
            .admitted;
        let fetched = |url: &str| {
            let mut repo = repo(Some("corp"), url);
            repo.set_provenance(crate::Provenance::FetchedPom);
            repo
        };
        let mut configured = repo(Some("corp"), "https://nexus.corp/other/");
        configured.set_provenance(crate::Provenance::Configured);
        let claimed = fetched("https://evil.example/maven/");

        let output = capture_warnings(|| {
            for (repo, sent) in [
                (&configured, true),
                (&project[0], true),
                (&fetched("https://nexus.corp/snapshots/"), true),
                (&fetched("https://nexus2.corp/snapshots/"), true),
                (&claimed, false),
                (&claimed, false),
            ] {
                let auth = store.for_repository_with_policy(repo, false).unwrap();
                assert_eq!(auth.is_some(), sent, "{}", repo.url);
            }
        });
        assert_eq!(
            output.matches("ID_CREDENTIAL_WITHHELD").count(),
            1,
            "{output}"
        );
        assert!(output.contains("https://evil.example"), "{output}");
        for absent in ["nexus.corp", "nexus2.corp", "corp-secret"] {
            assert!(!output.contains(absent), "{output}");
        }
    }

    /// An entry without an id goes only to an origin the user's files name.
    /// A POM or a project `raeva.toml` cannot collect it by declaring a
    /// repository on its own host.
    #[test]
    fn the_default_credential_goes_only_to_an_origin_the_user_names() {
        let store = AuthStore::from_auth_configs(&[bearer(None, "default-secret")])
            .unwrap()
            .with_configured_urls(&["https://nexus.corp/maven/"]);
        let output = capture_warnings(|| {
            for provenance in [
                crate::Provenance::Caller,
                crate::Provenance::Configured,
                crate::Provenance::LocalPom,
                crate::Provenance::FetchedPom,
            ] {
                for (url, allowed) in [
                    ("https://evil.example/maven/", false),
                    ("http://nexus.corp/maven/", false),
                    ("https://nexus.corp/other/", true),
                ] {
                    let mut repo = repo(None, url);
                    repo.set_provenance(provenance);
                    let auth = store.for_repository_with_policy(&repo, false).unwrap();
                    assert_eq!(auth.is_some(), allowed, "{url} {provenance:?}");
                }
            }
        });
        assert_eq!(
            output.matches("DEFAULT_CREDENTIAL_WITHHELD").count(),
            2,
            "{output}"
        );
        assert!(output.contains("https://evil.example"), "{output}");
        assert!(output.contains("http://nexus.corp"), "{output}");
        assert!(!output.contains("default-secret"), "{output}");
    }

    /// The user's origins come from `config.toml` and `settings.xml`, or the
    /// built-in repositories when no file names one, never from `raeva.toml`.
    #[test]
    fn a_project_rv_toml_repository_does_not_get_the_default_credential() {
        let _env_guard = ENV_LOCK.lock().expect("env lock");
        let home = tempfile::tempdir().expect("home");
        let project = home.path().join("project");
        std::fs::create_dir_all(&project).expect("project");
        let raeva_home = home.path().join("raeva");
        std::fs::create_dir_all(&raeva_home).expect("raeva home");
        let lookup = |raeva_toml: &str, config_toml: &str, url: &str| {
            std::fs::write(project.join("raeva.toml"), raeva_toml).expect("raeva.toml");
            std::fs::write(raeva_home.join("config.toml"), config_toml).expect("config.toml");
            temp_env::with_vars(
                [
                    ("HOME", Some(home.path().as_os_str())),
                    ("USERPROFILE", Some(home.path().as_os_str())),
                    (
                        rv_config::MAVEN_USER_HOME_TEST_ENV,
                        Some(home.path().as_os_str()),
                    ),
                    ("RAEVA_HOME", Some(raeva_home.as_os_str())),
                ],
                || {
                    let config = rv_config::Config::load(&project).expect("config");
                    let store = AuthStore::from_config(&config).expect("store");
                    let mut repo = repo(None, url);
                    repo.set_provenance(crate::Provenance::Configured);
                    store
                        .for_repository_with_policy(&repo, false)
                        .expect("lookup")
                        .is_some()
                },
            )
        };
        let default = "[[auth]]\ntoken = \"default-secret\"\n";
        let user_repo = format!("{default}[[repositories]]\nurl = \"https://nexus.corp/maven/\"\n");
        let project_repo = "[[repositories]]\nurl = \"https://evil.example/maven/\"\n";
        let (nexus, evil) = ("https://nexus.corp/maven/", "https://evil.example/maven/");
        let central = "https://repo1.maven.org/maven2/";
        // The built-in Central is the user's, whatever else is listed.
        #[rustfmt::skip]
        let cases = [
            (project_repo, user_repo.as_str(), nexus, true),
            (project_repo, &user_repo, evil, false),
            ("", default, central, true),
            (project_repo, default, central, true),
        ];
        for (raeva_toml, config_toml, url, allowed) in cases {
            assert_eq!(
                lookup(raeva_toml, config_toml, url),
                allowed,
                "{raeva_toml} {url}"
            );
        }
    }

    #[test]
    fn id_collisions_do_not_hide_active_user_credential_origins() {
        let _env_guard = ENV_LOCK.lock().expect("env lock");
        let home = tempfile::tempdir().unwrap();
        let project = home.path().join("project");
        let raeva_home = home.path().join("raeva");
        for dir in [&project, &raeva_home, &home.path().join(".m2")] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let profile = |id: &str, host: &str| {
            format!(
                "<profile><id>{id}</id><repositories><repository><id>shared</id>\
             <url>https://{host}/repo/</url></repository></repositories></profile>"
            )
        };
        std::fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><servers><server><id>corp</id><username>u</username>\
             <password>secret</password></server></servers><profiles>{}{}{}</profiles>\
             <activeProfiles><activeProfile>a</activeProfile><activeProfile>b</activeProfile>\
             </activeProfiles></settings>",
                profile("a", "a.example"),
                profile("b", "b.example"),
                profile("inactive", "inactive.example")
            ),
        )
        .unwrap();
        for project_config in [
            "",
            "[[repositories]]\nid = \"shared\"\nurl = \"https://project.example/repo/\"\n",
        ] {
            std::fs::write(project.join("raeva.toml"), project_config).unwrap();
            temp_env::with_vars(
                [
                    ("HOME", Some(home.path().as_os_str())),
                    ("USERPROFILE", Some(home.path().as_os_str())),
                    (
                        rv_config::MAVEN_USER_HOME_TEST_ENV,
                        Some(home.path().as_os_str()),
                    ),
                    ("RAEVA_HOME", Some(raeva_home.as_os_str())),
                ],
                || {
                    let config = rv_config::Config::load(&project).unwrap();
                    assert!(
                        !config
                            .repositories()
                            .iter()
                            .any(|repo| repo.url.contains("b.example"))
                    );
                    let store = AuthStore::from_config(&config).unwrap();
                    for (host, allowed) in [
                        ("a.example", true),
                        ("b.example", true),
                        ("inactive.example", false),
                    ] {
                        let mut repo = repo(Some("corp"), &format!("https://{host}/fetched/"));
                        repo.set_provenance(crate::Provenance::FetchedPom);
                        assert_eq!(
                            store
                                .for_repository_with_policy(&repo, false)
                                .unwrap()
                                .is_some(),
                            allowed,
                            "{project_config}: {host}"
                        );
                    }
                },
            );
        }
    }

    /// A repository URL with embedded userinfo still gets its configured
    /// credentials, and the userinfo stays out of the warnings.
    #[test]
    fn userinfo_repo_url_still_resolves_configured_auth() {
        let store = sources(
            vec![bearer(Some("corp"), "corp-token")],
            Vec::new(),
            Vec::new(),
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
        match resolved.expect("auth").scheme {
            Scheme::Bearer { token } => assert_eq!(token.expose_secret(), "corp-token"),
            Scheme::Basic { .. } => panic!("expected the id-matched bearer token"),
        }
        assert!(
            !output.contains("hunter2"),
            "userinfo must be redacted out of the warn: {output}"
        );
    }

    /// A cross-host mirror that withholds a default credential warns once,
    /// without userinfo or query tokens from either URL; without a default
    /// credential nothing is said.
    #[test]
    fn cross_host_mirror_warnings_redact_both_urls() {
        let selector = crate::mirror::MirrorSelector::from_mirrors(vec![{
            let mut mirror_config = rv_config::MirrorConfig::new(
                None,
                "https://mallory:mirror-secret@mirror.example/m2/?sig=mirror-token",
            );
            mirror_config.mirror_of = vec!["*".to_string()];
            mirror_config
        }]);
        let repo = repo(
            Some("corp"),
            "https://alice:hunter2@nexus.corp/repo/?token=origin-token",
        );
        for (settings, warnings) in [(vec![bearer(None, "default-token")], 1), (vec![], 0)] {
            let store = sources(vec![], vec![], settings);
            let output = capture_warnings(|| {
                let (resolved, _, host_changed) = selector.select(&repo);
                assert!(host_changed);
                assert!(
                    store
                        .for_repository_with_policy(&resolved, host_changed)
                        .expect("lookup")
                        .is_none(),
                    "no default credential crosses hosts"
                );
            });
            assert_eq!(
                output.matches("CROSS_HOST_MIRROR").count(),
                warnings,
                "{output}"
            );
            for secret in [
                "hunter2",
                "origin-token",
                "mirror-secret",
                "mirror-token",
                "alice",
                "mallory",
            ] {
                assert!(!output.contains(secret), "{secret} leaked: {output}");
            }
            if warnings > 0 {
                assert!(output.contains("mirror.example/m2/?***"), "{output}");
            }
        }
    }

    /// settings.xml `${env.X}` reaches the credential, a project `[[auth]]`
    /// entry replaces a lower-precedence settings bearer, and no rendering
    /// shows the secret.
    #[test]
    #[cfg_attr(
        windows,
        ignore = "settings.xml is read from the profile directory, which HOME does not redirect on Windows"
    )]
    fn loaded_credentials_interpolate_layer_and_redact() {
        let _env_guard = ENV_LOCK.lock().expect("env lock");
        let home = tempfile::tempdir().expect("home");
        let project = home.path().join("project");
        std::fs::create_dir_all(&project).expect("project");
        std::fs::write(
            project.join("raeva.toml"),
            "[[auth]]\nid = \"proj\"\nusername = \"project-user\"\npassword = \"project-password\"\n",
        )
        .expect("raeva.toml");
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
    <server>
      <id>proj</id>
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
        let raeva_home = home.path().join("raeva").to_string_lossy().into_owned();
        let (ci_user, ci_secret) = ("ci-interpolated-user", "ci-interpolated-secret");

        temp_env::with_vars(
            [
                ("HOME", Some(home_string.as_str())),
                ("USERPROFILE", Some(home_string.as_str())),
                ("RAEVA_HOME", Some(raeva_home.as_str())),
                ("RAEVA_USER", Some(ci_user)),
                ("RAEVA_TOKEN", Some(ci_secret)),
            ],
            || {
                let config = rv_config::Config::load(&project).expect("config");
                let layers = config.auth_layers();
                let store = sources(
                    layers.project().to_vec(),
                    layers.user().to_vec(),
                    layers.settings().to_vec(),
                );
                for (id, user, password) in [
                    ("corp", ci_user, ci_secret),
                    ("proj", "project-user", "project-password"),
                ] {
                    let auth = store
                        .for_repository_with_policy(&repo(Some(id), "https://repo.example/"), false)
                        .expect("lookup");
                    let expected = format!("basic {user} {password}");
                    assert_eq!(
                        shown(auth.as_ref()).as_deref(),
                        Some(expected.as_str()),
                        "{id}"
                    );
                    assert!(!format!("{auth:?}").contains(ci_secret));
                }
                for rendered in [format!("{store:?}"), format!("{config:?}")] {
                    assert!(!rendered.contains(ci_secret), "secret leaked: {rendered}");
                    assert!(!rendered.contains("${env.RAEVA_TOKEN}"));
                }
            },
        );
    }
}
