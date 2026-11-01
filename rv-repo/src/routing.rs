//! Where one request goes: the mirror that serves a repository and the
//! credentials sent to it, decided once per request.

use std::collections::HashSet;
use std::sync::OnceLock;

use rv_config::MirrorConfig;

use crate::auth::{Auth, AuthStore};
use crate::error::{RepoError, Result};
use crate::mirror::{MirrorSelector, origins_differ};
use crate::repository::{Repository, normalize_repo_url};

/// The destination of one request. Nothing downstream re-runs mirror
/// selection: running it again on an endpoint that is already a mirror URL
/// matches that mirror as a self-reference and loses `cross_origin`, which
/// would send the default credential to a foreign mirror.
pub(crate) struct Route<'a> {
    pub(crate) origin: String,
    pub(crate) endpoint: Repository,
    pub(crate) mirror: Option<MirrorConfig>,
    /// The default (id-less) credential must not reach `endpoint`: a mirror
    /// changed scheme, host or port, or `endpoint` is a configured mirror on
    /// an origin no configured repository shares.
    pub(crate) cross_origin: bool,
    /// `origin \x1f endpoint \x1f id=<endpoint id>`. Keys the metadata and
    /// POM cache, so a wildcard mirror cannot serve one origin's rows to
    /// another, a changed mirror does not reuse rows fetched through the old
    /// one, and one URL under two ids, each with its own credential, keeps
    /// its answers apart.
    pub(crate) scope: String,
    auth_store: &'a AuthStore,
    /// The credential, with the credential generation it was picked under.
    auth: OnceLock<(Option<Auth>, u64)>,
}

impl Route<'_> {
    /// The credential for `endpoint`, looked up on first use. A request that
    /// a cache answers never reads the credential sources. Every request
    /// reads it first, so a blocked mirror refuses them here.
    pub(crate) fn auth(&self) -> Result<Option<&Auth>> {
        if let Some(mirror) = self.mirror.as_ref().filter(|mirror| mirror.blocked) {
            let name = mirror.id.clone();
            return Err(RepoError::BlockedMirror(
                name.unwrap_or_else(|| rv_config::redact_url(&mirror.url).to_string()),
            ));
        }
        if let Some((auth, _)) = self.auth.get() {
            return Ok(auth.as_ref());
        }
        let generation = self.auth_store.generation();
        let auth = self
            .auth_store
            .for_repository_with_policy(&self.endpoint, self.cross_origin)?;
        Ok(self.auth.get_or_init(|| (auth, generation)).0.as_ref())
    }

    /// The credential generation [`Self::auth`] picked the credential under,
    /// once it has.
    pub(crate) fn auth_generation(&self) -> Option<u64> {
        self.auth.get().map(|(_, generation)| *generation)
    }

    pub(crate) fn info(&self) -> RouteInfo {
        RouteInfo {
            endpoint: self.endpoint.clone(),
            mirror: self.mirror.clone(),
            cross_origin: self.cross_origin,
        }
    }
}

/// Where requests for a repository go, for callers that report it, such as
/// `raeva doctor` and resolution error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInfo {
    /// The repository that receives the requests: the mirror, or the
    /// repository itself. A mirror without its own id takes the repository's
    /// id only when it stays on the same origin.
    pub endpoint: Repository,
    /// The configured mirror that replaced the repository, if one did.
    pub mirror: Option<MirrorConfig>,
    /// Whether the default (id-less) credential is withheld from the
    /// endpoint because it is on another origin than the repository, or is a
    /// configured mirror on an origin no configured repository shares.
    pub cross_origin: bool,
}

/// Mirror selection and credentials for every request of one client.
#[derive(Clone, Debug)]
pub(crate) struct Router {
    mirrors: MirrorSelector,
    foreign_mirrors: ForeignMirrors,
    auth: AuthStore,
}

impl Router {
    pub(crate) fn from_config(config: &rv_config::Config) -> Result<Self> {
        Ok(Self {
            mirrors: MirrorSelector::from_config(config),
            foreign_mirrors: ForeignMirrors::from_config(config),
            auth: AuthStore::from_config(config)?,
        })
    }

    #[cfg(test)]
    pub(crate) fn new(mirrors: MirrorSelector, auth: AuthStore) -> Self {
        Self {
            mirrors,
            foreign_mirrors: ForeignMirrors::default(),
            auth,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_foreign_mirrors(mut self, urls: &[&str]) -> Self {
        self.foreign_mirrors.urls = urls.iter().map(|url| normalize_repo_url(url)).collect();
        self
    }

    pub(crate) fn auth_store(&self) -> &AuthStore {
        &self.auth
    }

    /// Decide where requests for `repo` go. Mirror selection runs here and
    /// nowhere else.
    pub(crate) fn route(&self, repo: &Repository) -> Route<'_> {
        let (endpoint, mirror, host_changed) = self.mirrors.select(repo);
        let scope = cache_scope_key(&repo.url, &endpoint);
        Route {
            origin: repo.url.clone(),
            cross_origin: host_changed || self.foreign_mirrors.contains(&endpoint.url),
            endpoint,
            mirror,
            scope,
            auth_store: &self.auth,
            auth: OnceLock::new(),
        }
    }
}

/// The repository that serves `repo` under `config`'s mirrors: the mirror,
/// with the id a request through it uses, or `repo` itself. Runs the same
/// selection as a request, without logging it, for callers that only label
/// files, such as `raeva export-m2` writing the repository ids Maven checks.
pub fn mirrored_repository(config: &rv_config::Config, repo: &Repository) -> Repository {
    crate::mirror::resolve_mirror(config.mirrors(), repo).0
}

/// Build the metadata and POM cache scope for an `(origin, endpoint)` pair.
/// `\u{1f}` (unit separator) cannot appear in a URL, so the parts join
/// without an ambiguous boundary.
pub(crate) fn cache_scope_key(origin_url: &str, endpoint: &Repository) -> String {
    let id = endpoint.id.as_deref().unwrap_or_default();
    format!("{origin_url}\u{1f}{}\u{1f}id={id}", endpoint.url)
}

/// Configured mirror URLs that must not receive the default (id-less)
/// credential.
///
/// A repository whose own URL is a mirror's, such as one a POM declares
/// with that URL, matches the mirror as a self-reference, so mirror
/// selection reports no origin change. Knowing the mirror URLs keeps the
/// decision a routed request gets: the mirror's own id-scoped entry, never
/// the default.
///
/// A mirror on the origin of a configured repository is not foreign: the
/// default credential already reaches that origin through the repository.
#[derive(Debug, Clone, Default)]
struct ForeignMirrors {
    urls: HashSet<String>,
}

impl ForeignMirrors {
    fn from_config(config: &rv_config::Config) -> Self {
        let repositories = config.repositories();
        Self {
            urls: config
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

    fn contains(&self, url: &str) -> bool {
        self.urls.contains(&normalize_repo_url(url))
    }
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, SecretString};

    use super::Router;
    use crate::auth::{Auth, AuthStore, Scheme};
    use crate::mirror::MirrorSelector;
    use crate::repository::Repository;

    fn bearer(id: Option<&str>, token: &str) -> rv_config::AuthConfig {
        let mut auth = rv_config::AuthConfig::new(id);
        auth.token = Some(SecretString::from(token.to_string()));
        auth
    }

    fn router(auth: &[rv_config::AuthConfig]) -> Router {
        Router::new(
            MirrorSelector::default(),
            AuthStore::from_auth_configs(auth).expect("auth"),
        )
        .with_foreign_mirrors(&["https://cdn.example/maven"])
    }

    fn token(auth: Option<&Auth>) -> Option<String> {
        auth.map(|auth| match &auth.scheme {
            Scheme::Bearer { token } => token.expose_secret().to_string(),
            Scheme::Basic { .. } => panic!("expected a bearer token"),
        })
    }

    #[test]
    fn same_url_mirror_uses_the_mirrors_credential() {
        let mut mirror =
            rv_config::MirrorConfig::new(Some("mirror"), "https://repo.example/maven/");
        mirror.mirror_of = vec!["*".to_string()];
        let router = Router::new(
            MirrorSelector::from_mirrors(vec![mirror]),
            AuthStore::from_auth_configs(&[bearer(Some("mirror"), "mirror-token")]).unwrap(),
        );
        let repo = Repository::new(
            Some("original".to_string()),
            "https://repo.example/maven/",
            true,
            false,
        );
        let route = router.route(&repo);
        assert_eq!(
            token(route.auth().unwrap()).as_deref(),
            Some("mirror-token")
        );
        assert_eq!(route.endpoint.id.as_deref(), Some("mirror"));
        assert!(!route.cross_origin);
        assert!(!route.endpoint.snapshots_enabled);
        assert!(route.mirror.is_some());
    }

    /// A repository declared with a mirror's own URL matches the mirror as
    /// a self-reference, so mirror selection sees no origin change. The
    /// default credential must still stay off that origin, though the
    /// mirror's own id-scoped credential applies and a mirror on a
    /// configured origin is not foreign.
    #[test]
    fn a_foreign_mirror_url_gets_only_its_own_credential() {
        let default = bearer(None, "corp-token");
        let cdn = bearer(Some("cdn"), "cdn-token");
        for (auth, id, url, cross_origin, expected) in [
            (
                vec![default.clone()],
                "cdn",
                "https://cdn.example/maven/",
                true,
                None,
            ),
            (
                vec![cdn, default.clone()],
                "cdn",
                "https://cdn.example/maven/",
                true,
                Some("cdn-token"),
            ),
            (
                vec![default],
                "internal",
                "https://nexus.corp/mirror/",
                false,
                Some("corp-token"),
            ),
        ] {
            let router = router(&auth);
            let route = router.route(&Repository::new(Some(id.to_string()), url, true, true));
            assert_eq!(route.cross_origin, cross_origin, "{id} {url}");
            // A route looks up its credential once.
            for _ in 0..2 {
                let found = token(route.auth().expect("lookup"));
                assert_eq!(found.as_deref(), expected, "{id} {url}");
            }
            assert_eq!(router.auth_store().lookups(), 1);
        }
    }
}
