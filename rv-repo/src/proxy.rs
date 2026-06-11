use reqwest::header::HeaderValue;
use rv_config::{ProxyAuthType, ProxyConfig};
use secrecy::ExposeSecret;
use url::Url;

use crate::error::RepoError;

pub(crate) fn build_proxy(config: &ProxyConfig) -> Result<reqwest::Proxy, RepoError> {
    // Maven's default when <protocol> is absent is HTTP-only. Only route HTTPS
    // (or all) traffic through the proxy when explicitly configured.
    let protocol = config.protocol.as_deref().unwrap_or("http");
    let proxy_url = build_proxy_url(protocol, &config.host, config.port)?;
    let non_proxy_hosts = config.non_proxy_hosts.clone();

    let mut proxy = if non_proxy_hosts.is_empty() {
        match protocol.to_ascii_lowercase().as_str() {
            "https" => reqwest::Proxy::https(proxy_url)?,
            "all" => reqwest::Proxy::all(proxy_url)?,
            _ => reqwest::Proxy::http(proxy_url)?,
        }
    } else {
        // Custom per-URL routing: honour non_proxy_hosts regardless of protocol.
        let proxy_url_str = proxy_url.clone();
        let protocol_lower = protocol.to_ascii_lowercase();
        reqwest::Proxy::custom(move |url| {
            route_through_proxy(&protocol_lower, url, &proxy_url_str, &non_proxy_hosts)
        })
    };

    match config.auth_type.unwrap_or(ProxyAuthType::Basic) {
        ProxyAuthType::Basic => {
            if let Some(username) = config.username.as_deref() {
                let password = config
                    .password
                    .as_ref()
                    .map(|s| s.expose_secret().as_str())
                    .unwrap_or("");
                // reqwest's `Proxy::basic_auth` attaches the credentials to
                // *every* outbound proxy request reqwest decides to route
                // through this proxy, regardless of upstream origin. There is
                // no per-origin scoping, so a user-agent that talks to multiple
                // upstreams through one proxy can bleed Basic credentials to
                // upstreams the user did not intend. Use `non_proxy_hosts` to
                // constrain exposure when Basic must remain in play.
                tracing::warn!(
                    host = %config.host,
                    port = %config.port,
                    "proxy Basic credentials cannot be scoped per upstream origin in reqwest; \
                     consider non_proxy_hosts to limit credential exposure"
                );
                proxy = proxy.basic_auth(username, password);
            }
        }
        ProxyAuthType::Bearer => {
            // Wire the Bearer token into the Proxy object via
            // `custom_http_auth` so reqwest emits it as `Proxy-Authorization`
            // during the CONNECT handshake for HTTPS upstreams (and on the
            // request line for plain HTTP). The previous design attached it as
            // a manual per-request header, which for an HTTPS upstream either
            // missed the CONNECT entirely (proxy answers 407) or, worse, rode
            // INSIDE the TLS tunnel to the origin artifact server, disclosing
            // the proxy secret to a party that must never see it.
            let token = proxy_auth_token(config)?;
            let mut header_bytes = Vec::with_capacity(7 + token.len());
            header_bytes.extend_from_slice(b"Bearer ");
            header_bytes.extend_from_slice(token.as_bytes());
            let mut header = HeaderValue::from_bytes(&header_bytes)
                .map_err(|err| RepoError::AuthError(err.to_string()))?;
            header.set_sensitive(true);
            proxy = proxy.custom_http_auth(header);
        }
    }

    Ok(proxy)
}

fn proxy_auth_token(config: &ProxyConfig) -> Result<String, RepoError> {
    if let Some(token) = config.token.as_ref() {
        return Ok(token.expose_secret().to_string());
    }
    if let Some(env) = config.token_env.as_deref() {
        return std::env::var(env)
            .map_err(|_| RepoError::AuthError(format!("proxy auth env var {env} not set")));
    }
    Err(RepoError::AuthError("proxy auth token missing".to_string()))
}

/// Per-URL routing decision for a proxy with non_proxy_hosts configured.
/// Returns the proxy URL when the request should be proxied, None to go
/// direct. Mirrors the Proxy::https/all/http split used when no
/// non_proxy_hosts exist: the configured protocol selects WHICH request
/// schemes the proxy handles. The arms are keyed on the configured protocol
/// alone; a bare `_ if url.scheme() != "http"` fall-through arm would also
/// catch the https protocol (whose guarded arm falls through when the URL
/// scheme IS https) and turn an https proxy into a no-op.
fn route_through_proxy(
    protocol_lower: &str,
    url: &Url,
    proxy_url: &str,
    non_proxy_hosts: &[String],
) -> Option<String> {
    match protocol_lower {
        "https" => {
            if url.scheme() != "https" {
                return None;
            }
        }
        "all" => {}
        _ => {
            if url.scheme() != "http" {
                return None;
            }
        }
    }

    let Some(host) = url.host_str() else {
        // No host to test against non_proxy_hosts; keep proxying, matching
        // the behavior of the non-custom Proxy::http/https/all variants.
        return Some(proxy_url.to_string());
    };
    if should_bypass_proxy(host, non_proxy_hosts) {
        None
    } else {
        Some(proxy_url.to_string())
    }
}

/// Assemble a proxy URL safely. Brackets bare IPv6 literals, rejects `@`
/// (would smuggle a `userinfo@authority` switch) and other URL delimiters,
/// then round-trips through `Url::parse` to surface any residual weirdness.
pub(crate) fn build_proxy_url(protocol: &str, host: &str, port: u16) -> Result<String, RepoError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(RepoError::AuthError(
            "proxy host must not be empty".to_string(),
        ));
    }
    // Reject userinfo characters outright: proxy creds live in
    // ProxyConfig::username/password, not embedded in the host.
    if trimmed.contains('@') {
        return Err(RepoError::AuthError(format!(
            "proxy host {host:?} contains '@'; put credentials in the proxy \
             config's username/password fields, not in the host"
        )));
    }
    if trimmed.contains('/') || trimmed.contains('?') || trimmed.contains('#') {
        return Err(RepoError::AuthError(format!(
            "proxy host {host:?} contains a URL delimiter; expected bare host or IP literal"
        )));
    }

    // Bracket bare IPv6 literals (more than one `:`, no surrounding brackets).
    // Hostnames and IPv4 literals contain at most one `:` if any (the port),
    // but `host` is already port-free here. So multiple `:` ⇒ IPv6.
    let host_authority = if trimmed.starts_with('[') && trimmed.ends_with(']') {
        trimmed.to_string()
    } else if trimmed.contains(':') {
        // Validate it really parses as IPv6 before we wrap it.
        if trimmed.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(RepoError::AuthError(format!(
                "proxy host {host:?} contains ':' but is not a valid IPv6 literal"
            )));
        }
        format!("[{trimmed}]")
    } else {
        trimmed.to_string()
    };

    let candidate = format!("{protocol}://{host_authority}:{port}");
    // Round-trip through url::Url so any residual malformed component is
    // surfaced as a real error rather than silently accepted by reqwest.
    let _ = Url::parse(&candidate)
        .map_err(|err| RepoError::AuthError(format!("invalid proxy URL {candidate:?}: {err}")))?;
    Ok(candidate)
}

pub(crate) fn should_bypass_proxy(host: &str, non_proxy_hosts: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    // Maven's `<nonProxyHosts>` accepts a bare `*` as a match-everything
    // wildcard; short-circuit on it so `*.suffix`-only matchers don't
    // silently proxy every request.
    if non_proxy_hosts.iter().any(|entry| entry.trim() == "*") {
        return true;
    }

    non_proxy_hosts.iter().any(|entry| {
        let entry = entry.trim();
        if entry.is_empty() {
            return false;
        }

        if let Some(suffix) = entry.strip_prefix("*.").or_else(|| entry.strip_prefix('.')) {
            let suffix = suffix.trim_end_matches('.').to_ascii_lowercase();
            !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
        } else {
            host == entry.trim_end_matches('.').to_ascii_lowercase()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{build_proxy, route_through_proxy, should_bypass_proxy};
    use rv_config::ProxyConfig;
    use secrecy::Secret;

    /// The configured protocol selects which request schemes the proxy
    /// handles, exactly like the Proxy::https/all/http variants used when
    /// no non_proxy_hosts exist. An https proxy must route https requests;
    /// the old fall-through arm keyed on the URL scheme returned None for
    /// every https request, making the proxy a no-op.
    #[test]
    fn custom_routing_protocol_filter_matches_builtin_variants() {
        let proxy = "https://proxy.example:8080";
        let none: &[String] = &[];
        let https_url = url::Url::parse("https://repo.example/a").unwrap();
        let http_url = url::Url::parse("http://repo.example/a").unwrap();

        assert_eq!(
            route_through_proxy("https", &https_url, proxy, none).as_deref(),
            Some(proxy),
            "https proxy must route https requests"
        );
        assert_eq!(
            route_through_proxy("https", &http_url, proxy, none),
            None,
            "https proxy must not route http requests"
        );
        assert_eq!(
            route_through_proxy("http", &http_url, proxy, none).as_deref(),
            Some(proxy)
        );
        assert_eq!(route_through_proxy("http", &https_url, proxy, none), None);
        assert_eq!(
            route_through_proxy("all", &https_url, proxy, none).as_deref(),
            Some(proxy)
        );
        assert_eq!(
            route_through_proxy("all", &http_url, proxy, none).as_deref(),
            Some(proxy)
        );
    }

    #[test]
    fn custom_routing_honours_non_proxy_hosts_per_protocol() {
        let proxy = "https://proxy.example:8080";
        let bypass = vec!["repo.example".to_string()];
        let matching = url::Url::parse("https://repo.example/a").unwrap();
        let other = url::Url::parse("https://elsewhere.example/a").unwrap();

        assert_eq!(
            route_through_proxy("https", &matching, proxy, &bypass),
            None
        );
        assert_eq!(
            route_through_proxy("https", &other, proxy, &bypass).as_deref(),
            Some(proxy)
        );
    }

    fn proxy_config() -> ProxyConfig {
        ProxyConfig {
            id: None,
            protocol: None,
            host: "proxy.example".to_string(),
            port: 8080,
            auth_type: None,
            username: None,
            password: None,
            token_env: None,
            token: None,
            non_proxy_hosts: Vec::new(),
        }
    }

    #[test]
    fn build_proxy_defaults_protocol() {
        let config = proxy_config();
        let proxy = build_proxy(&config).unwrap();
        let rendered = format!("{proxy:?}");
        assert!(rendered.contains("scheme: \"http\""));
        assert!(rendered.contains("proxy.example"));
        assert!(rendered.contains("port: Some(8080)"));
    }

    #[test]
    fn build_proxy_applies_auth() {
        let mut config = proxy_config();
        config.protocol = Some("https".to_string());
        config.username = Some("user".to_string());
        config.password = Some(Secret::new("pass".to_string()));
        let proxy = build_proxy(&config).unwrap();
        let rendered = format!("{proxy:?}");
        assert!(rendered.contains("username: \"user\""));
    }

    /// Bearer proxy auth must be wired into the Proxy object (so reqwest sends
    /// it during the CONNECT for HTTPS upstreams) rather than attached as a
    /// manual per-request header that would leak into the TLS tunnel to the
    /// origin. The token must be marked sensitive so it never surfaces in
    /// Debug/log output.
    #[test]
    fn build_proxy_wires_bearer_via_custom_http_auth() {
        let mut config = proxy_config();
        config.protocol = Some("https".to_string());
        config.auth_type = Some(rv_config::ProxyAuthType::Bearer);
        config.token = Some(Secret::new("super-secret-token".to_string()));
        let proxy = build_proxy(&config).expect("bearer proxy builds");
        let rendered = format!("{proxy:?}");
        assert!(
            !rendered.contains("super-secret-token"),
            "bearer token must be sensitive and never appear in Debug: {rendered}"
        );
    }

    #[test]
    fn should_bypass_proxy_exact_match() {
        let non_proxy = vec!["repo.example.com".to_string()];
        assert!(should_bypass_proxy("repo.example.com", &non_proxy));
        assert!(!should_bypass_proxy("sub.repo.example.com", &non_proxy));
    }

    /// Regression: a bare `*` rule (Maven's "bypass proxy for every host"
    /// wildcard) must short-circuit the matcher for any host.
    #[test]
    fn should_bypass_proxy_star_matches_everything() {
        let non_proxy = vec!["*".to_string()];
        assert!(should_bypass_proxy("repo.example.com", &non_proxy));
        assert!(should_bypass_proxy("internal", &non_proxy));
        assert!(should_bypass_proxy("10.0.0.1", &non_proxy));
        assert!(should_bypass_proxy("::1", &non_proxy));

        // `*` mixed in with other rules still short-circuits.
        let non_proxy = vec!["*.foo".to_string(), "*".to_string()];
        assert!(should_bypass_proxy("anything.else", &non_proxy));

        // Surrounded by whitespace it should still match; Maven users
        // routinely paste `<nonProxyHosts>` with stray spaces.
        let non_proxy = vec!["  *  ".to_string()];
        assert!(should_bypass_proxy("anything.com", &non_proxy));
    }

    #[test]
    fn should_bypass_proxy_suffix_match() {
        let non_proxy = vec![".example.com".to_string(), "*.internal".to_string()];
        assert!(should_bypass_proxy("repo.example.com", &non_proxy));
        assert!(should_bypass_proxy("api.internal", &non_proxy));
    }

    /// Regression: hostnames and IPv4 literals must build a plain
    /// authority. IPv6 literals must be bracketed. Hosts containing `@` or
    /// other URL delimiters must be rejected outright.
    #[test]
    fn build_proxy_url_brackets_ipv6_and_rejects_at_sign() {
        use super::build_proxy_url;

        // hostname: plain authority.
        let url = build_proxy_url("http", "example.com", 8080).unwrap();
        assert_eq!(url, "http://example.com:8080");

        // IPv4: same.
        let url = build_proxy_url("http", "10.0.0.1", 3128).unwrap();
        assert_eq!(url, "http://10.0.0.1:3128");

        // Bare IPv6 literal: must get bracketed.
        let url = build_proxy_url("http", "::1", 8080).unwrap();
        assert_eq!(url, "http://[::1]:8080");

        // Pre-bracketed IPv6: pass through unchanged.
        let url = build_proxy_url("http", "[::1]", 8080).unwrap();
        assert_eq!(url, "http://[::1]:8080");

        // Longer IPv6 literal.
        let url = build_proxy_url("http", "2001:db8::1", 8080).unwrap();
        assert_eq!(url, "http://[2001:db8::1]:8080");

        // Host with `@` is rejected; previously this would have been
        // reinterpreted as `userinfo@authority`, steering the connection to
        // `evil.example` instead of `proxy.example`.
        let err = build_proxy_url("http", "user@evil.example", 8080).unwrap_err();
        let rendered = format!("{err}");
        assert!(
            rendered.contains("'@'") || rendered.contains("@"),
            "expected '@'-rejection error, got {rendered}"
        );

        // Junk hostname with `:` but not valid IPv6 is rejected, not silently
        // forwarded.
        let err = build_proxy_url("http", "host:with:colons", 8080).unwrap_err();
        assert!(format!("{err}").contains("IPv6"));
    }

    /// Regression: the full `build_proxy` path must wire these
    /// validations in. Verifies via the `Debug` formatting that the host
    /// landed correctly in the reqwest proxy.
    #[test]
    fn build_proxy_accepts_ipv6_host() {
        let mut config = proxy_config();
        config.host = "::1".to_string();
        let proxy = build_proxy(&config).unwrap();
        let rendered = format!("{proxy:?}");
        // reqwest stores the authority with the brackets stripped, but the
        // host string itself must be the v6 literal.
        assert!(
            rendered.contains("::1"),
            "expected proxy debug to mention IPv6 host: {rendered}"
        );
    }

    // --- proxy default protocol ---

    /// When `<protocol>` is absent, the proxy must handle HTTP traffic only,
    /// not HTTPS. Maven's default is HTTP-only.
    #[test]
    fn build_proxy_no_protocol_defaults_to_http_only() {
        let config = proxy_config(); // protocol: None
        let proxy = build_proxy(&config).unwrap();
        let rendered = format!("{proxy:?}");
        // The reqwest debug output for Proxy::http uses Intercept::Http.
        assert!(
            rendered.contains("Http("),
            "protocol=None must produce an HTTP-only proxy, got: {rendered}"
        );
        assert!(
            !rendered.contains("All("),
            "protocol=None must NOT produce Proxy::all, got: {rendered}"
        );
    }

    /// When `<protocol>` is `"https"`, the proxy must handle HTTPS traffic only.
    #[test]
    fn build_proxy_protocol_https_routes_https_only() {
        let mut config = proxy_config();
        config.protocol = Some("https".to_string());
        let proxy = build_proxy(&config).unwrap();
        let rendered = format!("{proxy:?}");
        assert!(
            rendered.contains("Https("),
            "protocol=https must produce an HTTPS-only proxy, got: {rendered}"
        );
    }

    /// When `<protocol>` is `"all"`, the proxy must handle all traffic.
    #[test]
    fn build_proxy_protocol_all_routes_all_traffic() {
        let mut config = proxy_config();
        config.protocol = Some("all".to_string());
        let proxy = build_proxy(&config).unwrap();
        let rendered = format!("{proxy:?}");
        assert!(
            rendered.contains("All("),
            "protocol=all must produce Proxy::all, got: {rendered}"
        );
    }

    /// When `<protocol>` is explicitly `"http"`, behaves the same as the default.
    #[test]
    fn build_proxy_explicit_http_protocol() {
        let mut config = proxy_config();
        config.protocol = Some("http".to_string());
        let proxy = build_proxy(&config).unwrap();
        let rendered = format!("{proxy:?}");
        assert!(
            rendered.contains("Http("),
            "protocol=http must produce an HTTP-only proxy, got: {rendered}"
        );
    }
}
