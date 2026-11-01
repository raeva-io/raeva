mod guard;
#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use reqwest::Client;
use rv_config::{Config, redact_url};
use url::Url;

use crate::error::{RepoError, Result};
use crate::proxy::ProxySet;
use crate::repository::Repository;

pub(crate) use guard::redirect_rejection_from_reqwest;
pub(crate) use guard::same_origin_redirect_policy;
use guard::{
    ConfiguredHosts, ExemptHosts, GlobalOnlyResolver, RedirectGuard, TrustedHosts, TrustedOrigins,
    ip_literal, is_globally_routable, origin_key, redirect_guard, trusted_redirect_policy,
};

/// The clients one `RepoClient` sends requests through, and the sets their
/// screens read.
///
/// Each client's resolver waves some hosts through the address screen, and
/// a resolver sees only a name, never a port or scheme. So the exemption is
/// made exact by routing instead: [`ClientSet::client_for`] gives a client
/// only requests whose whole origin that client's exemptions were granted
/// for.
#[derive(Clone)]
pub(crate) struct ClientSet {
    clients: Arc<LazyClients>,
    /// Per-root-origin clients freeze their DNS exemptions before any request.
    root_redirects: Arc<RootRedirectClients>,
    /// Origins named by `raeva.toml` (repositories and mirrors), frozen at
    /// construction. Selects the configured client.
    configured_origins: Arc<HashSet<String>>,
    /// Origins that may sit off the public internet: the configured ones
    /// plus whatever [`Grants::exempt`] adds.
    trusted_origins: TrustedOrigins,
    /// Hosts the runtime client's resolver waves through: the configured
    /// ones and the hosts of the origins [`Grants::exempt`] adds. See
    /// [`TrustedHosts`].
    trusted_hosts: TrustedHosts,
    proxy_hosts: ConfiguredHosts,
    proxies: Arc<ProxySet>,
    /// Refuse a direct request to an IP literal outside the public internet
    /// unless [`Self::trusted_origins`] holds its origin. Off only for tests
    /// that serve repositories from loopback.
    screen_literals: bool,
}

impl ClientSet {
    pub(crate) fn build(config: &Config) -> Result<Self> {
        // Proxy auth (Basic and Bearer alike) is wired into the Proxy object
        // inside build_proxy so it rides the CONNECT for HTTPS upstreams and
        // is never leaked into the TLS tunnel.
        let proxies = ProxySet::from_config(config)?;
        let guard = redirect_guard(config, &proxies)?;
        // The clients are built on the first request, which a run may never
        // make; the warnings about configured roots are due regardless.
        rv_http::read_env_roots();
        Ok(Self::from_guard(guard, proxies, BuildOptions::default()))
    }

    fn from_guard(guard: RedirectGuard, proxies: ProxySet, options: BuildOptions) -> Self {
        // Seeded with the configured hosts, then grown by `Grants::exempt`.
        // A separate set, not a second handle on the guard's: the guard's must
        // stay frozen.
        let trusted_hosts = guard.exempt_hosts.to_runtime_set();
        let proxy_hosts = ConfiguredHosts::new(proxies.hosts.iter().cloned());
        let configured_origins = Arc::new(guard.origins.clone());
        Self {
            clients: Arc::new(LazyClients {
                guard: guard.clone(),
                trusted_hosts: trusted_hosts.clone(),
                proxy_hosts: proxy_hosts.clone(),
                proxies: proxies.proxies.clone(),
                options,
                built: OnceLock::new(),
                building: Mutex::new(()),
            }),
            trusted_origins: TrustedOrigins::new(configured_origins.iter().cloned()),
            configured_origins,
            root_redirects: Arc::new(RootRedirectClients {
                guard,
                proxies: proxies.proxies.clone(),
                options,
                clients: RwLock::default(),
            }),
            trusted_hosts,
            proxy_hosts,
            proxies: Arc::new(proxies),
            screen_literals: true,
        }
    }

    /// A set whose clients have no address screen and no redirect authority,
    /// for tests that serve repositories from loopback.
    #[cfg(test)]
    pub(crate) fn unscreened(client: Client) -> Self {
        Self {
            clients: Arc::new(LazyClients {
                guard: RedirectGuard::default(),
                trusted_hosts: TrustedHosts::default(),
                proxy_hosts: ConfiguredHosts::default(),
                proxies: Vec::new(),
                options: BuildOptions::default(),
                built: OnceLock::from(Clients {
                    configured: client.clone(),
                    runtime: client.clone(),
                    screened: client.clone(),
                    direct: client,
                }),
                building: Mutex::new(()),
            }),
            root_redirects: Arc::default(),
            configured_origins: Arc::default(),
            trusted_origins: TrustedOrigins::default(),
            trusted_hosts: TrustedHosts::default(),
            proxy_hosts: ConfiguredHosts::default(),
            proxies: Arc::default(),
            screen_literals: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn screened() -> Self {
        Self::from_guard(
            RedirectGuard::default(),
            ProxySet::default(),
            BuildOptions::default(),
        )
    }

    /// Whether `url`'s origin may issue a cross-origin redirect.
    #[cfg(test)]
    pub(crate) fn authorizes_issuer(&self, url: &str) -> bool {
        Url::parse(url)
            .ok()
            .and_then(|url| origin_key(&url))
            .is_some_and(|origin| {
                self.root_redirects
                    .clients
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains_key(&origin)
            })
    }

    /// Exempt `repos` from the address screen, as a policy grant does.
    #[cfg(test)]
    pub(crate) fn trust_repositories<'a>(&self, repos: impl IntoIterator<Item = &'a Repository>) {
        let grants = self.grants();
        repos.into_iter().for_each(|repo| grants.exempt(repo));
    }

    /// Give `repos` redirect authority, as a policy grant does.
    #[cfg(test)]
    pub(crate) fn trust_root_repositories<'a>(
        &self,
        repos: impl IntoIterator<Item = &'a Repository>,
    ) {
        let grants = self.grants();
        repos
            .into_iter()
            .for_each(|repo| grants.authorize_issuer(repo));
    }

    pub(crate) fn grants(&self) -> Grants {
        Grants {
            trusted_origins: self.trusted_origins.clone(),
            trusted_hosts: self.trusted_hosts.clone(),
            root_redirects: Arc::clone(&self.root_redirects),
        }
    }

    /// Root issuers use a client with a frozen exemption for their own host.
    /// Runtime/transitive DNS grants never widen any redirect client's screen.
    ///
    /// Every other request picks its client by its origin: a configured
    /// origin uses the configured client, an origin granted at runtime the
    /// runtime client, and anything else a client whose resolver exempts
    /// nothing but the proxy hosts. Another port or scheme on a trusted host
    /// is another origin, so its host name is screened.
    ///
    /// An IP literal never reaches a resolver, so the address screen is
    /// applied here for direct requests: a literal outside the public
    /// internet is refused unless its origin is exempt. A root issuer's client
    /// exempts its own host, so its literal passes too.
    pub(crate) fn client_for(&self, url: &Url) -> Result<Cow<'_, Client>> {
        if let Some(client) = self.root_redirects.client_for(url)? {
            return Ok(Cow::Owned(client));
        }
        let origin = origin_key(url);
        let trusted = origin
            .as_deref()
            .is_some_and(|origin| self.trusted_origins.contains(origin));
        // Refuse an IP literal outside the public internet when the origin
        // is not exempt.
        if self.screen_literals && !trusted {
            // A proxy resolves a name itself, out of the resolver's reach, so
            // a `localhost` name (RFC 6761) it carries is screened here too.
            let loopback = self.proxies.carries(url)
                && url.host_str().is_some_and(|host| {
                    let host = host.trim_end_matches('.').to_ascii_lowercase();
                    host == "localhost" || host.ends_with(".localhost")
                });
            match ip_literal(url).or(loopback.then_some(IpAddr::V4(Ipv4Addr::LOCALHOST))) {
                Some(addr) if !is_globally_routable(addr) => {
                    return Err(RepoError::NonGlobalAddress {
                        url: redact_url(url),
                        addr,
                    });
                }
                _ => {}
            }
        }
        let clients = self.clients.get()?;
        Ok(Cow::Borrowed(match origin {
            Some(origin) if self.configured_origins.contains(&origin) => &clients.configured,
            Some(_) if trusted => &clients.runtime,
            _ if url
                .host_str()
                .is_some_and(|host| self.proxy_hosts.contains(host))
                && !self.proxies.carries(url) =>
            {
                &clients.direct
            }
            _ => &clients.screened,
        }))
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn trusts_origin(&self, url: &Url) -> bool {
        origin_key(url).is_some_and(|origin| self.trusted_origins.contains(&origin))
    }
}

/// The clients of a [`ClientSet`] other than the root issuers'.
struct Clients {
    /// Requests to a configured repository or mirror origin. Its redirect
    /// policy and resolver read the frozen [`ConfiguredHosts`] set.
    /// It never consults runtime DNS trust. See [`ClientSet::client_for`].
    configured: Client,
    /// Requests to an origin trusted at runtime by [`Grants::exempt`]. Its
    /// resolver reads the live [`TrustedHosts`] set so a grant taken
    /// mid-resolve is honoured without a rebuild, and its redirect policy is
    /// same-origin only, so that live set can never widen what a redirect
    /// may reach.
    runtime: Client,
    /// Requests to every other origin. Its resolver exempts only the proxy
    /// hosts, which it must reach to send a request through a proxy, and its
    /// redirect policy is same-origin only.
    screened: Client,
    /// Requests to an origin nothing exempts whose host is a proxy host and
    /// that no proxy carries. It has no proxies and no exemptions, so the
    /// proxy host's exemption cannot cover another port on that host.
    direct: Client,
}

/// [`Clients`] built on the first request: a client loads the system trust
/// roots, which a run that sends no request never reads.
struct LazyClients {
    guard: RedirectGuard,
    trusted_hosts: TrustedHosts,
    proxy_hosts: ConfiguredHosts,
    proxies: Vec<reqwest::Proxy>,
    options: BuildOptions,
    built: OnceLock<Clients>,
    building: Mutex<()>,
}

impl LazyClients {
    fn get(&self) -> Result<&Clients> {
        if let Some(clients) = self.built.get() {
            return Ok(clients);
        }
        let _building = self.building.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(clients) = self.built.get() {
            return Ok(clients);
        }
        let options = self.options;
        // A prefetch or held population may be first to ask: the warnings
        // of loading the trust roots are the run's, not that request's.
        let clients = rv_maven_model::held::unheld(|| self.build(options))?;
        Ok(self.built.get_or_init(|| clients))
    }

    fn build(&self, options: BuildOptions) -> Result<Clients> {
        // `client_defaults` sets `no_proxy`, so reqwest does not read
        // HTTP_PROXY/HTTPS_PROXY itself: an implicit environment proxy
        // resolves hostnames itself, so it silently bypasses
        // `GlobalOnlyResolver` while `RedirectGuard::proxies` does not carry
        // the target and the policy relaxes accordingly. Proxies come from the
        // configuration, the variables' included, which is the path both
        // guards are told about.
        let clients = Clients {
            configured: options.client(
                trusted_redirect_policy(self.guard.clone()),
                self.guard.exempt_hosts.clone(),
                &self.proxies,
            )?,
            // Same-origin only, so nothing this client dials can be
            // redirected anywhere its live exemption set has not already
            // been asked about.
            runtime: options.client(
                same_origin_redirect_policy(),
                self.trusted_hosts.clone(),
                &self.proxies,
            )?,
            screened: options.client(
                same_origin_redirect_policy(),
                self.proxy_hosts.clone(),
                &self.proxies,
            )?,
            direct: options.client(
                same_origin_redirect_policy(),
                ConfiguredHosts::default(),
                &[],
            )?,
        };
        Ok(clients)
    }
}

#[derive(Clone)]
pub(crate) struct Grants {
    trusted_origins: TrustedOrigins,
    trusted_hosts: TrustedHosts,
    root_redirects: Arc<RootRedirectClients>,
}

impl Grants {
    /// Exempt `repo`'s origin from the address screen on direct connections,
    /// so an on-prem registry the user named in a POM rather than in
    /// `raeva.toml` stays reachable on an RFC1918 address. Other ports and
    /// schemes on the same host stay screened.
    ///
    /// The exemption covers DIRECT connections only and carries no redirect
    /// authority: it is read by one resolver, and that resolver belongs to the
    /// same-origin-only client, so a grant cannot be parlayed into a probe of
    /// the private network, nor can a grant landing mid-request retroactively
    /// excuse a redirect the policy let through on the expectation that the
    /// resolver would screen it. See [`ClientSet::client_for`] and
    /// `RedirectGuard`.
    pub(crate) fn exempt(&self, repo: &Repository) {
        // An unparsable or non-HTTP endpoint never reaches the resolver, so
        // there is nothing to exempt; the fetch path reports it. Same filter
        // as `redirect_guard`.
        let Some((url, origin)) = parsed_origin(repo) else {
            return;
        };
        // The host first: a request that sees the origin trusted goes to the
        // runtime client, whose resolver must already know the host.
        if let Some(host) = url.host_str() {
            self.trusted_hosts.insert(host);
        }
        self.trusted_origins.insert(origin);
    }

    /// Let `repo`'s origin issue one cross-origin redirect, as a configured
    /// repository may. Origins shared with such a declaration share its
    /// authority, irrespective of which POM later asks to use that endpoint.
    pub(crate) fn authorize_issuer(&self, repo: &Repository) {
        if let Some((_, origin)) = parsed_origin(repo) {
            self.root_redirects
                .clients
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .entry(origin)
                .or_insert(None);
        }
    }
}

fn parsed_origin(repo: &Repository) -> Option<(Url, String)> {
    let url = Url::parse(&repo.url).ok()?;
    let origin = origin_key(&url)?;
    Some((url, origin))
}

/// How the clients of one set are built. Tests accept the self-signed
/// certificate of their HTTPS stubs; nothing else differs.
#[derive(Clone, Copy, Debug, Default)]
struct BuildOptions {
    #[cfg(test)]
    accept_invalid_certs: bool,
}

impl BuildOptions {
    fn builder(self) -> reqwest::ClientBuilder {
        // No cap on idle connections per host: the fetch concurrency bounds
        // how many there can be, and a cap below it closes connections that
        // the next requests then reopen.
        let builder = rv_http::client_defaults()
            .tcp_keepalive(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(75));
        #[cfg(test)]
        let builder = builder.danger_accept_invalid_certs(self.accept_invalid_certs);
        builder
    }

    fn client(
        self,
        redirect: reqwest::redirect::Policy,
        exempt_hosts: impl ExemptHosts,
        proxies: &[reqwest::Proxy],
    ) -> Result<Client> {
        let builder = self
            .builder()
            .redirect(redirect)
            .dns_resolver(Arc::new(GlobalOnlyResolver { exempt_hosts }));
        let builder = proxies
            .iter()
            .fold(builder, |builder, proxy| builder.proxy(proxy.clone()));
        Ok(builder.build()?)
    }
}

/// Root grants select cached clients without changing their DNS policies.
/// A concurrent grant must not disable address checks on an in-progress redirect.
#[derive(Default)]
struct RootRedirectClients {
    guard: RedirectGuard,
    proxies: Vec<reqwest::Proxy>,
    options: BuildOptions,
    clients: RwLock<HashMap<String, Option<Client>>>,
}

impl RootRedirectClients {
    fn client_for(&self, url: &Url) -> Result<Option<Client>> {
        let Some(origin) = origin_key(url) else {
            return Ok(None);
        };
        {
            let clients = self.clients.read().unwrap_or_else(|e| e.into_inner());
            match clients.get(&origin) {
                None => return Ok(None),
                Some(Some(client)) => return Ok(Some(client.clone())),
                Some(None) => {}
            }
        }
        let mut clients = self.clients.write().unwrap_or_else(|e| e.into_inner());
        let entry = clients
            .get_mut(&origin)
            .expect("root issuer grant persists");
        if let Some(client) = entry {
            return Ok(Some(client.clone()));
        }
        let mut guard = self.guard.clone();
        guard.root_issuer = Some(origin);
        guard.exempt_hosts = ConfiguredHosts::new(
            guard
                .exempt_hosts
                .0
                .iter()
                .cloned()
                .chain(url.host_str().map(str::to_owned)),
        );
        let client = rv_maven_model::held::unheld(|| {
            self.options.client(
                trusted_redirect_policy(guard.clone()),
                guard.exempt_hosts,
                &self.proxies,
            )
        })?;
        *entry = Some(client.clone());
        Ok(Some(client))
    }
}
