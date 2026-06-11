use std::collections::HashSet;
use std::sync::Mutex;

use url::Url;

use crate::repository::Repository;

/// Per-process dedup set for unrecognized `<mirrorOf>` pattern warnings.
/// Keyed by `(pattern, mirror_id)` so each unique pair warns at most once.
static UNKNOWN_PATTERN_WARNED: Mutex<Option<HashSet<(String, String)>>> = Mutex::new(None);

fn warn_unknown_pattern_once(pattern: &str, mirror_id: &str) {
    let mut guard = UNKNOWN_PATTERN_WARNED
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let set = guard.get_or_insert_with(HashSet::new);
    let key = (pattern.to_string(), mirror_id.to_string());
    if set.insert(key) {
        tracing::warn!(
            pattern = pattern,
            mirror_id = mirror_id,
            "unrecognized <mirrorOf> pseudo-pattern; Maven also does not recognize it; \
             falling back to exact-id comparison (will not match)"
        );
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MirrorSelector {
    mirrors: Vec<rv_config::MirrorConfig>,
}

impl MirrorSelector {
    pub(crate) fn from_config(config: &rv_config::Config) -> Self {
        Self {
            mirrors: config.mirrors().to_vec(),
        }
    }

    /// Crate-internal constructor for tests. Avoids requiring callers to
    /// build a full `rv_config::Config` just to plug a single `MirrorConfig`
    /// into the selector.
    #[cfg(test)]
    pub(crate) fn from_mirrors(mirrors: Vec<rv_config::MirrorConfig>) -> Self {
        Self { mirrors }
    }

    /// Convenience wrapper that discards the host-change flag from
    /// [`Self::resolve_with_host_change`]. Production code in `rv-repo::client`
    /// threads the flag into [`crate::auth::AuthStore::for_repository_with_policy`].
    #[cfg(test)]
    pub(crate) fn resolve(&self, repo: &Repository) -> Repository {
        self.resolve_with_host_change(repo).0
    }

    /// Resolve the mirror for `repo`, returning the rewritten `Repository`
    /// alongside a flag indicating whether the mirror substitution crossed
    /// to a different host.
    ///
    /// The host-change flag is used by the auth layer to decide whether the
    /// default (no-id) `AuthConfig` should be forwarded: when a wildcard
    /// mirror substitutes a repo URL with a third-party CDN, blindly
    /// attaching a Nexus bearer token to that CDN request would leak the
    /// credential. Callers in `rv-repo::client` should treat a host change
    /// combined with a default-fallback auth as "do not attach auth"; an
    /// id-matched `AuthConfig` is unaffected because the user opted into
    /// that pairing.
    pub(crate) fn resolve_with_host_change(&self, repo: &Repository) -> (Repository, bool) {
        if let Some(mirror) = self.matching_mirror(repo) {
            // Treat `mirror.url == repo.url` as "no mirror matched". Without
            // this, the fallback path in `RepoClient::resolve_repo_with_fallback`
            // would see a substitution and retry the origin against itself.
            if mirror.url == repo.url {
                tracing::warn!(
                    sec_code = "MIRROR_SELF_REF",
                    id = ?repo.id,
                    "mirror points at the repo it mirrors; ignoring"
                );
                return (repo.clone(), false);
            }
            let host_changed = origins_differ(&repo.url, &mirror.url);
            // Inherit the origin repo's id (so its configured credentials keep
            // applying) ONLY when the mirror has no id of its own and we are
            // not crossing hosts. Inheriting the origin id across a host
            // boundary would let `lookup_auth` id-match and forward the
            // origin's id-scoped credential to the foreign mirror host, which
            // is the exact leak the host_changed suppression exists to prevent. A
            // mirror with its OWN explicit id is left untouched: the user opted
            // into that pairing.
            let id = match mirror.id.clone() {
                Some(mirror_id) => Some(mirror_id),
                None if host_changed => None,
                None => repo.id.clone(),
            };
            tracing::debug!(
                original_url = %repo.url,
                mirror_url = %mirror.url,
                mirror_id = ?id,
                "redirecting to mirror"
            );
            if host_changed {
                tracing::warn!(
                    original_url = %repo.url,
                    mirror_url = %mirror.url,
                    "mirror substitution crossed hosts; default credentials will not be forwarded"
                );
            }
            let resolved = Repository::new(
                id,
                mirror.url.clone(),
                repo.releases_enabled,
                repo.snapshots_enabled,
            )
            .with_snapshot_policy(repo.snapshots_update_policy);
            return (resolved, host_changed);
        }

        (repo.clone(), false)
    }

    pub(crate) fn matching_mirror(&self, repo: &Repository) -> Option<&rv_config::MirrorConfig> {
        // Maven's `DefaultMirrorSelector` runs two passes: an exact single-ID
        // match wins over any wildcard or pattern match, regardless of list
        // order. Without this, `[{mirrorOf:"*"}, {mirrorOf:"central"}]` would
        // shadow the second entry for `central`.
        self.mirrors
            .iter()
            .find(|mirror| is_exact_id_mirror(mirror, repo))
            .or_else(|| {
                self.mirrors
                    .iter()
                    .find(|mirror| matches_mirror(mirror, repo))
            })
    }
}

fn is_exact_id_mirror(mirror: &rv_config::MirrorConfig, repo: &Repository) -> bool {
    let Some(repo_id) = repo.id.as_deref() else {
        return false;
    };
    let patterns = expand_patterns(&mirror.mirror_of);
    patterns.len() == 1 && patterns[0] == repo_id
}

fn matches_mirror(mirror: &rv_config::MirrorConfig, repo: &Repository) -> bool {
    let patterns = expand_patterns(&mirror.mirror_of);
    if patterns.is_empty() {
        return false;
    }

    let mirror_id = mirror.id.as_deref().unwrap_or("<unnamed>");
    let mut matched = false;
    for pattern in patterns {
        if let Some(rule) = pattern.strip_prefix('!') {
            if pattern_matches(rule, repo, mirror_id) {
                return false;
            }
        } else if pattern_matches(&pattern, repo, mirror_id) {
            matched = true;
        }
    }
    matched
}

fn expand_patterns(patterns: &[String]) -> Vec<String> {
    patterns
        .iter()
        .flat_map(|p| p.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn pattern_matches(pattern: &str, repo: &Repository, mirror_id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern == "central" {
        return repo.id.as_deref() == Some("central");
    }
    if pattern == "external:*" {
        return is_external_repo(&repo.url);
    }
    if pattern == "external:http:*" {
        // Maven 3.8.1+ pattern matching only non-HTTPS external repos.
        return is_external_repo(&repo.url) && repo_scheme(&repo.url).as_deref() == Some("http");
    }
    if pattern == "external:https:*" {
        return is_external_repo(&repo.url) && repo_scheme(&repo.url).as_deref() == Some("https");
    }
    if pattern == "internal:*" {
        return !is_external_repo(&repo.url);
    }
    // Unrecognized pseudo-patterns: warn once and fall through to exact-id comparison.
    if pattern.starts_with("external:") || pattern.starts_with("internal:") {
        warn_unknown_pattern_once(pattern, mirror_id);
    }
    match repo.id.as_deref() {
        Some(id) => id == pattern,
        None => false,
    }
}

fn repo_scheme(url: &str) -> Option<String> {
    Url::parse(url).ok().map(|u| u.scheme().to_string())
}

/// Compare two URLs by origin: scheme, host (case-insensitive) and effective
/// port (`port_or_known_default`, so `https://x:443` equals `https://x`).
/// Returns `true` when the URLs resolve to different origins. Comparing the
/// host alone is not enough: `http://nexus.corp:8081/` and
/// `https://nexus.corp/` are different endpoints, and treating them as the
/// same would forward origin credentials to a plaintext or otherwise
/// unrelated listener. If either URL fails to parse (or has no host or
/// derivable port), this returns `true` defensively so the caller treats it
/// as an origin change and declines to forward default credentials.
pub fn origins_differ(original: &str, resolved: &str) -> bool {
    fn origin(url: &str) -> Option<(String, String, u16)> {
        let parsed = Url::parse(url).ok()?;
        let host = parsed.host_str()?.to_ascii_lowercase();
        let port = parsed.port_or_known_default()?;
        Some((parsed.scheme().to_string(), host, port))
    }
    match (origin(original), origin(resolved)) {
        (Some(a), Some(b)) => a != b,
        _ => true,
    }
}

fn is_external_repo(url: &str) -> bool {
    let parsed = match Url::parse(url) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    match parsed.scheme() {
        "http" | "https" => match parsed.host() {
            Some(url::Host::Domain(h)) => h != "localhost",
            Some(url::Host::Ipv4(addr)) => !addr.is_loopback(),
            Some(url::Host::Ipv6(addr)) => {
                // `Ipv6Addr::is_loopback()` covers only `::1`. IPv4-mapped
                // addresses such as `::ffff:127.0.0.1` are also loopback;
                // check the mapped IPv4 address to cover those variants.
                !addr.is_loopback() && !addr.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
            }
            None => false,
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::MirrorSelector;
    use crate::repository::Repository;

    fn mirror_config(id: &str, url: &str, mirror_of: &[&str]) -> rv_config::MirrorConfig {
        rv_config::MirrorConfig {
            id: Some(id.to_string()),
            url: url.to_string(),
            mirror_of: mirror_of.iter().map(|value| value.to_string()).collect(),
        }
    }

    #[test]
    fn matches_by_id() {
        let mirror = mirror_config("corp", "https://mirror.example/", &["central"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2/",
            true,
            false,
        );
        let resolved = selector.resolve(&repo);
        assert_eq!(resolved.url, "https://mirror.example/");
    }

    #[test]
    fn exact_id_match_wins_over_earlier_wildcard() {
        // Maven-compat: even though the wildcard mirror is listed first, an
        // exact-ID mirror must take priority for repos matching its id.
        let wildcard = mirror_config("any", "https://wildcard.example/", &["*"]);
        let exact = mirror_config("corp", "https://corp.example/", &["central"]);
        let selector = MirrorSelector {
            mirrors: vec![wildcard, exact],
        };
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2/",
            true,
            false,
        );
        let resolved = selector.resolve(&repo);
        assert_eq!(resolved.url, "https://corp.example/");
    }

    #[test]
    fn first_entry_wins_within_same_match_class() {
        // Selection takes the first matching mirror within a class, so the
        // higher-precedence layer (placed first by Config's project > user >
        // settings merge order) wins when two mirrors target the same repo
        // with the same specificity.
        let project = mirror_config("project-m", "https://project.example/", &["central"]);
        let settings = mirror_config("settings-m", "https://settings.example/", &["central"]);
        let selector = MirrorSelector {
            mirrors: vec![project, settings],
        };
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2/",
            true,
            false,
        );
        let resolved = selector.resolve(&repo);
        assert_eq!(resolved.url, "https://project.example/");
    }

    #[test]
    fn resolve_with_host_change_flags_cross_host_redirect() {
        let mirror = mirror_config("cdn", "https://cdn.example/", &["*"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let repo = Repository::new(
            Some("internal".to_string()),
            "https://nexus.corp/repo/",
            true,
            false,
        );
        let (resolved, host_changed) = selector.resolve_with_host_change(&repo);
        assert_eq!(resolved.url, "https://cdn.example/");
        assert!(host_changed, "host changed from nexus.corp to cdn.example");
    }

    /// A wildcard mirror with NO id of its own that crosses hosts must NOT
    /// inherit the origin repo's id. Otherwise `lookup_auth` would id-match
    /// the origin's id-scoped credential and forward it to the foreign mirror
    /// host, defeating the cross-host credential suppression.
    #[test]
    fn cross_host_unnamed_mirror_does_not_inherit_origin_id() {
        let mirror = rv_config::MirrorConfig {
            id: None,
            url: "https://cdn.example/".to_string(),
            mirror_of: vec!["*".to_string()],
        };
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let repo = Repository::new(
            Some("central".to_string()),
            "https://nexus.corp/repo/",
            true,
            false,
        );
        let (resolved, host_changed) = selector.resolve_with_host_change(&repo);
        assert!(host_changed);
        assert_eq!(
            resolved.id, None,
            "cross-host unnamed mirror must drop the inherited origin id"
        );
    }

    /// A SAME-host unnamed mirror still inherits the origin id so configured
    /// credentials keep applying; there is no cross-host leak risk.
    #[test]
    fn same_host_unnamed_mirror_inherits_origin_id() {
        let mirror = rv_config::MirrorConfig {
            id: None,
            url: "https://nexus.corp/mirror/".to_string(),
            mirror_of: vec!["*".to_string()],
        };
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let repo = Repository::new(
            Some("central".to_string()),
            "https://nexus.corp/repo/",
            true,
            false,
        );
        let (resolved, host_changed) = selector.resolve_with_host_change(&repo);
        assert!(!host_changed);
        assert_eq!(resolved.id.as_deref(), Some("central"));
    }

    /// Same host but a different SCHEME is a different origin. An unnamed
    /// mirror at `http://nexus.corp/` for origin `https://nexus.corp/` must
    /// NOT inherit the origin id, otherwise id-matched credentials would be
    /// forwarded to the plaintext endpoint.
    #[test]
    fn scheme_change_same_host_unnamed_mirror_does_not_inherit_origin_id() {
        let mirror = rv_config::MirrorConfig {
            id: None,
            url: "http://nexus.corp:8081/mirror/".to_string(),
            mirror_of: vec!["*".to_string()],
        };
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let repo = Repository::new(
            Some("central".to_string()),
            "https://nexus.corp/repo/",
            true,
            false,
        );
        let (resolved, host_changed) = selector.resolve_with_host_change(&repo);
        assert!(
            host_changed,
            "http://nexus.corp:8081 is a different origin than https://nexus.corp"
        );
        assert_eq!(
            resolved.id, None,
            "scheme/port change must drop the inherited origin id"
        );
    }

    /// Effective-port comparison: an explicit default port is the same origin
    /// as the implicit one, while a non-default port is a different origin.
    #[test]
    fn origins_differ_uses_effective_port() {
        use super::origins_differ;
        assert!(
            !origins_differ("https://nexus.corp/", "https://nexus.corp:443/"),
            "explicit default port equals implicit default port"
        );
        assert!(
            !origins_differ("http://nexus.corp/", "http://nexus.corp:80/"),
            "explicit default port equals implicit default port"
        );
        assert!(
            origins_differ("https://nexus.corp/", "https://nexus.corp:8443/"),
            "non-default port is a different origin"
        );
        assert!(
            origins_differ("https://nexus.corp/", "http://nexus.corp/"),
            "scheme change is a different origin even on the same host"
        );
        assert!(
            !origins_differ("https://NEXUS.corp/", "https://nexus.CORP/"),
            "host comparison stays case-insensitive"
        );
    }

    #[test]
    fn resolve_with_host_change_same_host_returns_false() {
        // Same host, just a different path is NOT a host change.
        let mirror = mirror_config("alt", "https://nexus.corp/alt/", &["*"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let repo = Repository::new(
            Some("internal".to_string()),
            "https://nexus.corp/repo/",
            true,
            false,
        );
        let (_resolved, host_changed) = selector.resolve_with_host_change(&repo);
        assert!(!host_changed);
    }

    #[test]
    fn external_http_pattern_matches_only_http() {
        let mirror = mirror_config("safe", "https://mirror.example/", &["external:http:*"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let http_repo = Repository::new(
            Some("http-repo".to_string()),
            "http://insecure.example/",
            true,
            false,
        );
        let https_repo = Repository::new(
            Some("https-repo".to_string()),
            "https://secure.example/",
            true,
            false,
        );
        assert_eq!(
            selector.resolve(&http_repo).url,
            "https://mirror.example/",
            "external:http:* must redirect http repos"
        );
        assert_eq!(
            selector.resolve(&https_repo).url,
            "https://secure.example/",
            "external:http:* must NOT redirect https repos"
        );
    }

    #[test]
    fn external_https_pattern_matches_only_https() {
        let mirror = mirror_config("safe", "https://mirror.example/", &["external:https:*"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let http_repo = Repository::new(
            Some("http-repo".to_string()),
            "http://insecure.example/",
            true,
            false,
        );
        let https_repo = Repository::new(
            Some("https-repo".to_string()),
            "https://secure.example/",
            true,
            false,
        );
        assert_eq!(selector.resolve(&http_repo).url, "http://insecure.example/");
        assert_eq!(selector.resolve(&https_repo).url, "https://mirror.example/");
    }

    /// `mirrorOf="central,snapshots"` is a comma-joined include list, not a
    /// single repo id. It must NOT trigger the exact-ID pass (`is_exact_id_mirror`
    /// requires a single-element pattern list), but must still match either
    /// `central` or `snapshots` repos via the pattern-pass fallback.
    #[test]
    fn multi_id_mirror_of_falls_through_to_pattern_pass() {
        let mirror = mirror_config("multi", "https://multi.example/", &["central,snapshots"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };

        let central = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2/",
            true,
            false,
        );
        assert_eq!(selector.resolve(&central).url, "https://multi.example/");

        let snapshots = Repository::new(
            Some("snapshots".to_string()),
            "https://snapshots.example/",
            true,
            true,
        );
        assert_eq!(selector.resolve(&snapshots).url, "https://multi.example/");

        // A repo not in the list is left alone.
        let other = Repository::new(
            Some("releases".to_string()),
            "https://releases.example/",
            true,
            false,
        );
        assert_eq!(selector.resolve(&other).url, "https://releases.example/");
    }

    #[test]
    fn self_referential_mirror_is_treated_as_no_match() {
        // A mirror entry whose URL is identical to the repo it mirrors must
        // not produce a substitution; otherwise the fallback retries the
        // origin against itself.
        let url = "https://repo1.maven.org/maven2/";
        let mirror = mirror_config("central", url, &["central"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let repo = Repository::new(Some("central".to_string()), url, true, false);
        let (resolved, host_changed) = selector.resolve_with_host_change(&repo);
        assert_eq!(resolved.url, repo.url);
        assert!(!host_changed);
    }

    #[test]
    fn respects_exclusions() {
        let mirror = mirror_config("corp", "https://mirror.example/", &["*", "!central"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2/",
            true,
            false,
        );
        let resolved = selector.resolve(&repo);
        assert_eq!(resolved.url, repo.url);
    }

    /// When a mirror with a distinct id substitutes for the origin, the
    /// resolved Repository must carry the *mirror's* id, not the origin's.
    /// AuthStore::for_repository_with_policy looks up auth by id; if the
    /// origin's id leaked through, mirror-scoped credentials would never
    /// match.
    #[test]
    fn mirror_id_is_preserved_on_resolved_repo() {
        let mirror = mirror_config("corp-mirror", "https://mirror.corp/", &["*"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        let origin = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2/",
            true,
            false,
        );
        let resolved = selector.resolve(&origin);
        assert_eq!(resolved.url, "https://mirror.corp/");
        assert_eq!(
            resolved.id.as_deref(),
            Some("corp-mirror"),
            "resolved repo must carry the mirror's id (was {:?}), not the origin's",
            resolved.id
        );
    }

    // --- unrecognized pseudo-pattern warn (dedup) ---

    /// An unrecognized `external:grpc:*` pattern must NOT match anything. It
    /// falls through to exact-id comparison and must not panic.
    #[test]
    fn unrecognized_external_pseudo_pattern_does_not_match() {
        let mirror = mirror_config("grpc-mirror", "https://grpc.example/", &["external:grpc:*"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        // A real external repo should NOT match the bogus pattern.
        let repo = Repository::new(
            Some("some-repo".to_string()),
            "https://external.example/repo/",
            true,
            false,
        );
        let resolved = selector.resolve(&repo);
        assert_eq!(
            resolved.url, repo.url,
            "unrecognized pattern must not produce a mirror substitution"
        );
    }

    /// Confirm the exact-id fallback path: `external:grpc:*` used as the sole
    /// pattern falls through to an id comparison, so a repo whose id literally
    /// equals `external:grpc:*` would match. (Pathological but correct per Maven.)
    #[test]
    fn unrecognized_external_pseudo_pattern_falls_through_to_id_match() {
        let mirror = mirror_config("grpc-mirror", "https://grpc.example/", &["external:grpc:*"]);
        let selector = MirrorSelector {
            mirrors: vec![mirror],
        };
        // A repo whose ID is literally the bogus pattern string.
        let repo = Repository::new(
            Some("external:grpc:*".to_string()),
            "https://external.example/repo/",
            true,
            false,
        );
        // is_exact_id_mirror fires first here (single-element pattern list == repo id).
        let resolved = selector.resolve(&repo);
        assert_eq!(
            resolved.url, "https://grpc.example/",
            "exact-id fallback must still match when repo id equals the pattern string"
        );
    }

    // --- IPv6 loopback variants for is_external_repo ---

    /// IPv4-mapped IPv6 loopback (`::ffff:127.0.0.1`) must NOT be treated as
    /// an external repository.
    #[test]
    fn ipv4_mapped_ipv6_loopback_is_not_external() {
        use super::is_external_repo;
        // ::ffff:127.0.0.1, IPv4-mapped IPv6 loopback
        assert!(
            !is_external_repo("http://[::ffff:7f00:1]/repo"),
            "::ffff:127.0.0.1 must not be external"
        );
    }

    /// Plain `::1` (compact IPv6 loopback) must NOT be external.
    #[test]
    fn ipv6_loopback_is_not_external() {
        use super::is_external_repo;
        assert!(
            !is_external_repo("http://[::1]/repo"),
            "[::1] must not be external"
        );
        assert!(
            !is_external_repo("https://[::1]:8080/repo"),
            "[::1] on HTTPS port must not be external"
        );
    }

    /// A regular external HTTPS URL must still be considered external.
    #[test]
    fn regular_https_url_is_external() {
        use super::is_external_repo;
        assert!(is_external_repo("https://repo.example.com/maven2/"));
    }

    /// `localhost` and `127.0.0.1` remain non-external.
    #[test]
    fn localhost_and_ipv4_loopback_are_not_external() {
        use super::is_external_repo;
        assert!(!is_external_repo("http://localhost/repo"));
        assert!(!is_external_repo("http://127.0.0.1/repo"));
        assert!(!is_external_repo("https://127.0.0.1:8080/repo"));
    }
}
