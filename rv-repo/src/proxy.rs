use std::sync::Arc;

use reqwest::header::HeaderValue;
use rv_config::{EnvironmentProxy, ProxyAuthType, ProxyConfig};
use secrecy::ExposeSecret;
use url::Url;

use crate::error::RepoError;

/// The proxies `config` names, with their credentials, in the form every
/// Raeva HTTP client attaches them.
///
/// A bearer proxy whose token is given by `token_env` reads that environment
/// variable here, each time this is called. It is the one environment
/// variable this crate reads; rv-config reads `HTTP_PROXY` and `HTTPS_PROXY`.
///
/// # Errors
///
/// [`RepoError::Config`] for an unknown protocol, a malformed host, a
/// settings.xml proxy port that is not a number or a proxy variable raeva
/// cannot use, and
/// [`RepoError::AuthSetup`] when a bearer token is missing, its variable is
/// unset, or it is not a valid header value.
pub fn configured_proxies(config: &rv_config::Config) -> Result<Vec<reqwest::Proxy>, RepoError> {
    Ok(ProxySet::from_config(config)?.proxies)
}

/// The configured proxies, and the rule that picks the one a URL goes
/// through, which each proxy's reqwest matcher applies.
#[derive(Clone, Default)]
pub(crate) struct ProxySet {
    pub(crate) proxies: Vec<reqwest::Proxy>,
    pub(crate) hosts: Vec<String>,
    routes: Arc<Routes>,
}

impl ProxySet {
    pub(crate) fn from_config(config: &rv_config::Config) -> Result<Self, RepoError> {
        if let Some(error) = config.proxy_error() {
            return Err(RepoError::Config(error.to_string()));
        }
        Self::new(config.proxies())
    }

    pub(crate) fn new(configs: &[ProxyConfig]) -> Result<Self, RepoError> {
        let routes = Arc::new(Routes(
            configs.iter().map(Route::new).collect::<Result<_, _>>()?,
        ));
        Ok(Self {
            proxies: configs
                .iter()
                .enumerate()
                .map(|(index, config)| build_proxy(config, Arc::clone(&routes), index))
                .collect::<Result<_, _>>()?,
            hosts: configs.iter().map(|proxy| proxy.host.clone()).collect(),
            routes,
        })
    }

    pub(crate) fn carries(&self, url: &Url) -> bool {
        self.routes.select(url).is_some()
    }
}

/// Leaves out the `reqwest::Proxy` values: their Debug shows credentials.
impl std::fmt::Debug for ProxySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxySet")
            .field("hosts", &self.hosts)
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

/// The URLs a proxy's `protocol` selects. It never names how raeva talks to
/// the proxy: that is always plain HTTP, with a `CONNECT` tunnel for an
/// `https:` URL, as in Maven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Http,
    Https,
    /// Not a Maven protocol: both schemes.
    All,
}

#[derive(Debug)]
struct Route {
    protocol: Protocol,
    non_proxy_hosts: Vec<String>,
    environment: Option<EnvironmentProxy>,
}

impl Route {
    fn new(config: &ProxyConfig) -> Result<Self, RepoError> {
        // Maven's default when `<protocol>` is absent is `http`.
        let protocol = config.protocol.as_deref().unwrap_or("http");
        let protocol = match protocol.to_ascii_lowercase().as_str() {
            "http" => Protocol::Http,
            "https" => Protocol::Https,
            "all" => Protocol::All,
            _ => {
                return Err(RepoError::Config(format!(
                    "a proxy has protocol {protocol:?}; use http, https or all"
                )));
            }
        };
        Ok(Self {
            protocol,
            non_proxy_hosts: config.non_proxy_hosts.clone(),
            environment: config.environment.clone(),
        })
    }

    fn carries(&self, scheme: &str, url: &Url) -> bool {
        let selected = match self.protocol {
            Protocol::Http => scheme == "http",
            Protocol::Https => scheme == "https",
            Protocol::All => true,
        };
        selected
            && !url
                .host_str()
                .is_some_and(|host| should_bypass_proxy(host, &self.non_proxy_hosts))
            && !(self.environment.as_ref()).is_some_and(|environment| environment.bypasses(url))
    }
}

#[derive(Debug, Default)]
struct Routes(Vec<Route>);

impl Routes {
    /// The proxy for `url`, as Maven's `DefaultProxySelector` picks it: the
    /// first proxy whose protocol is the URL's scheme and whose
    /// `non_proxy_hosts` leave its host alone; for an `https:` URL without
    /// one, the first such `http` proxy that is not `HTTP_PROXY`, which
    /// carries `http:` URLs only, as in curl.
    fn select(&self, url: &Url) -> Option<usize> {
        let first = |scheme: &str| self.0.iter().position(|route| route.carries(scheme, url));
        match url.scheme() {
            "http" => first("http"),
            "https" => first("https").or_else(|| {
                (self.0.iter())
                    .position(|route| route.environment.is_none() && route.carries("http", url))
            }),
            _ => None,
        }
    }
}

/// The reqwest proxy for `configs[index]`, which carries the URLs that
/// `routes` gives it.
fn build_proxy(
    config: &ProxyConfig,
    routes: Arc<Routes>,
    index: usize,
) -> Result<reqwest::Proxy, RepoError> {
    let proxy_url = build_proxy_url(&config.host, config.port)?;
    let mut proxy = reqwest::Proxy::custom(move |url| {
        (routes.select(url) == Some(index)).then(|| proxy_url.clone())
    });

    match config.auth_type.unwrap_or(ProxyAuthType::Basic) {
        ProxyAuthType::Basic => {
            if let Some(username) = config.username.as_deref() {
                let password = config.password.as_ref().map_or("", |s| s.expose_secret());
                // reqwest sends this as `Proxy-Authorization` on every
                // request it routes through this proxy: on the CONNECT for an
                // HTTPS URL, and on the request to the proxy for a plain HTTP
                // one, which the proxy consumes. raeva never sends it to the
                // repository itself.
                proxy = proxy.basic_auth(username, password);
            }
        }
        ProxyAuthType::Bearer => {
            // Set on the proxy, not on each request, so reqwest sends it on
            // the CONNECT for an HTTPS URL instead of inside the tunnel to
            // the repository.
            let token = proxy_auth_token(config)?;
            let mut header = HeaderValue::from_bytes(format!("Bearer {token}").as_bytes())
                .map_err(|err| RepoError::AuthSetup(err.to_string()))?;
            header.set_sensitive(true);
            proxy = proxy.custom_http_auth(header);
        }
    }

    Ok(proxy)
}

/// The bearer token for a proxy: `token` when set, else the value of the
/// environment variable `token_env` names. This is the one place rv-repo
/// reads the environment.
fn proxy_auth_token(config: &ProxyConfig) -> Result<String, RepoError> {
    if let Some(token) = config.token.as_ref() {
        return Ok(token.expose_secret().to_string());
    }
    let env = (config.token_env.as_deref())
        .ok_or_else(|| RepoError::AuthSetup("proxy auth token missing".to_string()))?;
    std::env::var(env)
        .map_err(|_| RepoError::AuthSetup(format!("proxy auth env var {env} not set")))
}

/// Assemble the `http:` URL of a proxy safely. Brackets bare IPv6 literals,
/// rejects `@` (would smuggle a `userinfo@authority` switch) and other URL
/// delimiters, then round-trips through `Url::parse` to surface any residual
/// weirdness.
pub(crate) fn build_proxy_url(host: &str, port: u16) -> Result<String, RepoError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(RepoError::Config(
            "proxy host must not be empty".to_string(),
        ));
    }
    // Reject userinfo characters outright: proxy creds live in
    // ProxyConfig::username/password, not embedded in the host.
    if trimmed.contains('@') {
        // Not echoed: what precedes the `@` is likely a password.
        return Err(RepoError::Config(
            "proxy host contains '@'; put credentials in the proxy config's \
             username/password fields, not in the host"
                .to_string(),
        ));
    }
    if trimmed.contains(['/', '?', '#']) {
        return Err(RepoError::Config(
            "proxy host contains '/', '?' or '#'; expected a bare host name or IP literal"
                .to_string(),
        ));
    }

    // Bracket bare IPv6 literals (more than one `:`, no surrounding brackets).
    // Hostnames and IPv4 literals contain at most one `:` if any (the port),
    // but `host` is already port-free here. So multiple `:` ⇒ IPv6.
    let bracketed = trimmed.starts_with('[') && trimmed.ends_with(']');
    let candidate = if !bracketed && trimmed.contains(':') {
        if trimmed.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(RepoError::Config(
                "proxy host contains ':' but is not a valid IPv6 literal".to_string(),
            ));
        }
        format!("http://[{trimmed}]:{port}")
    } else {
        format!("http://{trimmed}:{port}")
    };
    // Round-trip through url::Url so any residual malformed component is
    // surfaced as a real error rather than silently accepted by reqwest.
    Url::parse(&candidate)
        .map_err(|err| RepoError::Config(format!("invalid proxy host: {err}")))?;
    Ok(candidate)
}

/// Whether `non_proxy_hosts` sends `host` direct. As in Maven, an entry
/// matches the whole host name, ignoring case, and `*` in it matches any run
/// of characters, so `10.*` and `*.corp.*` work. Two forms also match more
/// than in Maven: `.example.com` matches any host under `example.com`, and
/// `*.example.com` matches `example.com` itself. Maven reads an entry as a
/// Java regular expression with `.` escaped; other regex syntax, such as `?`
/// or `[...]`, is matched literally here.
pub(crate) fn should_bypass_proxy(host: &str, non_proxy_hosts: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    non_proxy_hosts.iter().any(|entry| {
        let entry = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        if entry.is_empty() {
            return false;
        }
        let dotted = entry
            .strip_prefix('.')
            .is_some_and(|suffix| !suffix.is_empty() && (host == suffix || host.ends_with(&entry)));
        dotted
            || entry.strip_prefix("*.") == Some(host.as_str())
            || glob_matches(entry.as_bytes(), host.as_bytes())
    })
}

fn glob_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut resume: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            resume = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((star, matched)) = resume {
            p = star + 1;
            t = matched + 1;
            resume = Some((star, matched + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&b| b == b'*')
}

#[cfg(test)]
mod tests {
    use super::{ProxySet, build_proxy_url};
    use crate::error::RepoError;
    use rv_config::ProxyConfig;
    use secrecy::SecretString;

    fn proxy(protocol: Option<&str>, non_proxy_hosts: &[&str]) -> ProxyConfig {
        let mut proxy = ProxyConfig::new("proxy.example", 8080);
        proxy.protocol = protocol.map(str::to_string);
        proxy.non_proxy_hosts = non_proxy_hosts.iter().map(|s| s.to_string()).collect();
        proxy
    }

    const HTTP: &str = "http://repo.example/a";
    const HTTPS: &str = "https://repo.example/a";

    /// Selection as in Maven's `DefaultProxySelector`: an absent protocol
    /// is `http`, the first proxy whose `non_proxy_hosts` leave the host
    /// alone wins, and an `https:` URL with no usable `https` proxy goes
    /// through an `http` one.
    #[test]
    fn proxy_selection_follows_maven() {
        type Spec<'a> = &'a [(Option<&'a str>, &'a [&'a str])];
        #[rustfmt::skip]
        let cases: &[(Spec<'_>, &str, Option<usize>)] = &[
            (&[(None, &[])], HTTP, Some(0)),
            (&[(None, &[])], HTTPS, Some(0)),
            (&[(Some("HTTP"), &[])], HTTPS, Some(0)),
            (&[(Some("https"), &[])], HTTP, None),
            (&[(Some("https"), &[])], HTTPS, Some(0)),
            (&[(Some("all"), &[])], HTTP, Some(0)),
            (&[(Some("all"), &[])], HTTPS, Some(0)),
            (&[(Some("all"), &[])], "file:///srv/repo", None),
            (&[(Some("http"), &[]), (Some("https"), &[])], HTTP, Some(0)),
            (&[(Some("http"), &[]), (Some("https"), &[])], HTTPS, Some(1)),
            (&[(Some("https"), &[]), (Some("http"), &[])], HTTP, Some(1)),
            (&[(Some("https"), &[]), (Some("http"), &[])], HTTPS, Some(0)),
            (&[(Some("http"), &["repo.example"]), (Some("http"), &[])], HTTP, Some(1)),
            (&[(Some("http"), &["repo.example"]), (Some("http"), &[])], "http://other.example/", Some(0)),
            (&[(Some("https"), &["*.example"]), (Some("http"), &[])], HTTPS, Some(1)),
            (&[(Some("all"), &["*"])], HTTPS, None),
            (&[(Some("http"), &["10.*", "*.corp.*"])], "https://10.0.0.5/repo/", None),
            (&[(Some("http"), &["10.*", "*.corp.*"])], "http://nexus.corp.example/", None),
            (&[(Some("http"), &["10.*", "*.corp.*"])], HTTPS, Some(0)),
        ];
        for (spec, url, expected) in cases {
            let proxies: Vec<_> = spec.iter().map(|(p, hosts)| proxy(*p, hosts)).collect();
            let set = ProxySet::new(&proxies).expect("proxies");
            let got = set.routes.select(&url::Url::parse(url).unwrap());
            assert_eq!(got, *expected, "{spec:?} {url}");
        }
    }

    /// A proxy with another protocol would carry nothing, so its traffic
    /// would go direct without a word.
    #[test]
    fn an_unknown_protocol_is_refused() {
        let error = ProxySet::new(&[proxy(Some("socks5"), &[])]).unwrap_err();
        assert!(matches!(error, RepoError::Config(_)), "{error}");
        assert!(error.to_string().contains("socks5"), "{error}");
    }

    #[test]
    fn proxy_set_debug_leaves_out_credentials() {
        let mut basic = proxy(None, &[]);
        basic.username = Some("user".to_string());
        basic.password = Some(SecretString::from("proxy-pass".to_string()));
        let mut bearer = proxy(Some("https"), &[]);
        bearer.auth_type = Some(rv_config::ProxyAuthType::Bearer);
        bearer.token = Some(SecretString::from("super-secret-token".to_string()));
        let set = ProxySet::new(&[basic, bearer]).unwrap();
        let rendered = format!("{set:?} {:?}", set.proxies);
        assert!(rendered.contains("proxy.example"), "{rendered}");
        for secret in ["proxy-pass", "user", "super-secret-token"] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
    }

    /// A host with `@` would otherwise be read as `userinfo@authority` and
    /// steer the connection elsewhere; no rejection echoes the host, which
    /// may hold a token.
    #[test]
    fn build_proxy_url_brackets_ipv6_and_rejects_url_delimiters() {
        for (host, port, url) in [
            ("example.com", 8080, "http://example.com:8080"),
            ("10.0.0.1", 3128, "http://10.0.0.1:3128"),
            ("::1", 8080, "http://[::1]:8080"),
            ("[::1]", 8080, "http://[::1]:8080"),
            ("2001:db8::1", 8080, "http://[2001:db8::1]:8080"),
        ] {
            assert_eq!(build_proxy_url(host, port).unwrap(), url);
        }
        for (host, says) in [
            ("user:s3cret@evil.example", "'@'"),
            ("host:with:colons", "IPv6"),
            ("proxy.example/path", ""),
            ("proxy.example/?token=s3cret", ""),
            ("proxy.example#s3cret", ""),
            ("alice:s3cret", ""),
            ("[alice:s3cret]", ""),
            ("   ", ""),
        ] {
            let rendered = build_proxy_url(host, 8080).unwrap_err().to_string();
            assert!(rendered.contains(says), "{host}: {rendered}");
            assert!(!rendered.contains("s3cret"), "{rendered}");
        }
    }
}
