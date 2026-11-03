use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

use url::Url;

use crate::repository::{Repository, normalize_repo_url};

/// Per-process dedup set for unrecognized `<mirrorOf>` pattern warnings.
/// Keyed by `(pattern, mirror_id)` so each unique pair warns at most once.
static UNKNOWN_PATTERN_WARNED: LazyLock<Mutex<HashSet<(String, String)>>> =
    LazyLock::new(Mutex::default);

fn warn_unknown_pattern_once(pattern: &str, mirror_id: &str) {
    let key = (pattern.to_string(), mirror_id.to_string());
    rv_maven_model::held::when_shown(move || {
        let first = UNKNOWN_PATTERN_WARNED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.clone());
        if first {
            let (pattern, mirror_id) = key;
            tracing::warn!(
                sec_code = "SETTING_IGNORED",
                pattern = pattern,
                mirror_id = mirror_id,
                "unrecognized <mirrorOf> pseudo-pattern; Maven also does not recognize it, \
                 so it matches only a repository of that id"
            );
        }
    });
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

    /// The repository that serves `repo`, the mirror that replaced it, and
    /// whether the replacement changed scheme, host or effective port. Logs
    /// the substitution, so [`crate::routing::Router::route`] is its only
    /// production caller.
    pub(crate) fn select(
        &self,
        repo: &Repository,
    ) -> (Repository, Option<rv_config::MirrorConfig>, bool) {
        let (resolved, mirror, host_changed) = resolve_mirror_impl(&self.mirrors, repo, true);
        (resolved, mirror.cloned(), host_changed)
    }
}

/// Resolve silently to the effective repository, applied mirror, and whether
/// the origin (scheme, host, or effective port) changed, preserving repository policies.
pub(crate) fn resolve_mirror<'a>(
    mirrors: &'a [rv_config::MirrorConfig],
    repo: &Repository,
) -> (Repository, Option<&'a rv_config::MirrorConfig>, bool) {
    resolve_mirror_impl(mirrors, repo, false)
}

fn resolve_mirror_impl<'a>(
    mirrors: &'a [rv_config::MirrorConfig],
    repo: &Repository,
    diagnostics: bool,
) -> (Repository, Option<&'a rv_config::MirrorConfig>, bool) {
    let Some(mirror) = matching_mirror(mirrors, repo, diagnostics) else {
        return (repo.clone(), None, false);
    };
    let host_changed = origins_differ(&repo.url, &mirror.url);
    // Inherit the origin repo's id (so its configured credentials keep
    // applying) ONLY when the mirror has no id of its own and we are not
    // crossing hosts. Inheriting the origin id across a host boundary would
    // let `lookup_auth` id-match and forward the origin's id-scoped
    // credential to the foreign mirror host. A mirror with its OWN explicit
    // id is left untouched: the user opted into that pairing.
    let id = match mirror.id.clone() {
        None if !host_changed => repo.id.clone(),
        id => id,
    };
    if diagnostics {
        tracing::debug!(
            original_url = %rv_config::redact_url(&repo.url),
            mirror_url = %rv_config::redact_url(&mirror.url),
            mirror_id = ?id,
            host_changed,
            "redirecting to mirror"
        );
    }
    // A mirror changes the endpoint, not the origin's policies.
    let mut resolved = repo.clone();
    resolved.id = id;
    resolved.url = normalize_repo_url(&mirror.url);
    (resolved, Some(mirror), host_changed)
}

/// Maven Resolver 1.9's `DefaultMirrorSelector.findMirror`: a mirror whose
/// whole `<mirrorOf>` is the repository's id wins over any pattern match,
/// regardless of list order; then the first mirror whose pattern matches.
/// Either way the mirror's layouts must include the repository's.
fn matching_mirror<'a>(
    mirrors: &'a [rv_config::MirrorConfig],
    repo: &Repository,
    diagnostics: bool,
) -> Option<&'a rv_config::MirrorConfig> {
    let pattern = |mirror: &rv_config::MirrorConfig| mirror.mirror_of.join(",");
    mirrors
        .iter()
        .find(|mirror| {
            repo.id.as_deref() == Some(pattern(mirror).as_str()) && serves_layout(mirror)
        })
        .or_else(|| {
            mirrors.iter().find(|mirror| {
                let mirror_id = mirror.id.as_deref().unwrap_or("<unnamed>");
                match_pattern(repo, &pattern(mirror), mirror_id, diagnostics)
                    && serves_layout(mirror)
            })
        })
}

/// Resolver's `matchPattern`: `*`, the id itself, or a comma-separated list
/// read in order, where the first `!id` or `id` that names the repository
/// decides and `*`, `external:*` and `external:http:*` match unless a later
/// entry excludes the repository. Entries are not trimmed.
fn match_pattern(repo: &Repository, pattern: &str, mirror_id: &str, diagnostics: bool) -> bool {
    let id = repo.id.as_deref();
    if pattern == "*" || Some(pattern) == id {
        return true;
    }
    let mut matched = false;
    // Java's `split` drops trailing empty entries.
    for entry in pattern.trim_end_matches(',').split(',') {
        if let Some(excluded) = entry.strip_prefix('!').filter(|rest| !rest.is_empty()) {
            if Some(excluded) == id {
                return false;
            }
        } else if Some(entry) == id {
            return true;
        } else if (entry == "external:*" && is_external_repo(&repo.url))
            || (entry == "external:http:*" && is_external_http_repo(&repo.url))
            || entry == "*"
        {
            matched = true;
        } else if diagnostics && (entry.starts_with("external:") || entry.starts_with("internal:"))
        {
            warn_unknown_pattern_once(entry, mirror_id);
        }
    }
    matched
}

/// Resolver's `matchesType` for a repository of the `default` layout, the
/// one raeva reads every repository in.
fn serves_layout(mirror: &rv_config::MirrorConfig) -> bool {
    const LAYOUT: &str = "default";
    let layouts = mirror
        .mirror_of_layouts
        .as_deref()
        .unwrap_or("default,legacy");
    if layouts.is_empty() || layouts == "*" || layouts == LAYOUT {
        return true;
    }
    let mut matched = false;
    for entry in layouts.trim_end_matches(',').split(',') {
        if let Some(excluded) = entry.strip_prefix('!').filter(|rest| !rest.is_empty()) {
            if excluded == LAYOUT {
                return false;
            }
        } else if entry == LAYOUT {
            return true;
        } else if entry == "*" {
            matched = true;
        }
    }
    matched
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
pub(crate) fn origins_differ(original: &str, resolved: &str) -> bool {
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

fn is_local_host(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
}

/// For `external:*`, a `file:` URL and the parsed hosts `localhost` and
/// `127.0.0.1` are local. Unparseable URLs are external.
pub(crate) fn is_external_repo(url: &str) -> bool {
    Url::parse(url).map_or(true, |url| !(is_local_host(&url) || url.scheme() == "file"))
}

/// For `external:http:*` and the HTTP blocker, use the request parser's
/// scheme and host. Unparseable URLs are treated as external HTTP.
pub(crate) fn is_external_http_repo(url: &str) -> bool {
    Url::parse(url).map_or(true, |url| url.scheme() == "http" && !is_local_host(&url))
}

#[cfg(test)]
mod tests {
    use super::MirrorSelector;
    use crate::repository::Repository;

    fn mirror_config(id: Option<&str>, url: &str, mirror_of: &[&str]) -> rv_config::MirrorConfig {
        let mut mirror = rv_config::MirrorConfig::new(id, url);
        mirror.mirror_of = mirror_of.iter().map(|value| value.to_string()).collect();
        mirror
    }

    #[test]
    fn external_mirrors_match_the_parsed_host_and_fail_closed() {
        for pattern in ["external:*", "external:http:*"] {
            for url in [
                r"http://repo.example\@localhost/maven2/",
                "http://repo.example?@localhost/",
                "http://repo.example#@localhost/",
                "http://[invalid]/",
                "http://localhost:invalid/",
                "not a URL",
            ] {
                let repo = Repository::new(Some("corp".into()), url, true, true);
                let selector = MirrorSelector::from_mirrors(vec![mirror_config(
                    Some("mirror"),
                    "https://mirror.example/",
                    &[pattern],
                )]);
                let (resolved, mirror, _) = selector.select(&repo);
                assert!(mirror.is_some(), "{pattern}: {url}");
                assert_eq!(resolved.url, "https://mirror.example/", "{pattern}: {url}");
            }
        }
    }

    /// Maven Resolver 1.9's mirror selection: an exact id beats an earlier
    /// wildcard, the first entry wins within a match class, the first `id`
    /// or `!id` in a list that names the repository decides, entries are not
    /// trimmed, `external:http:*` matches as Maven matches it, and an
    /// unrecognized pseudo-pattern such as `external:https:*` matches only a
    /// repository of that id.
    /// The resolved repository carries the mirror's id even at the same URL;
    /// an unnamed mirror
    /// inherits the origin's only on the same origin, so id-scoped
    /// credentials never cross hosts.
    #[test]
    fn mirror_selection_follows_maven() {
        type Repo = (Option<&'static str>, &'static str);
        type Mirror = (Option<&'static str>, &'static str, &'static [&'static str]);
        type Expected = (&'static str, Option<&'static str>, bool);
        const CENTRAL: Repo = (Some("central"), "https://repo1.maven.org/maven2/");
        const NEXUS: Repo = (Some("central"), "https://nexus.corp/repo/");
        // (mirrors, repository, (resolved url, resolved id, host changed))
        #[rustfmt::skip]
        let cases: &[(&[Mirror], Repo, Expected)] = &[
            (&[(Some("corp"), "https://mirror.example/", &["central"])], CENTRAL, ("https://mirror.example/", Some("corp"), true)),
            (&[(Some("any"), "https://wildcard.example/", &["*"]), (Some("corp"), "https://corp.example/", &["central"])],
                CENTRAL, ("https://corp.example/", Some("corp"), true)),
            (&[(Some("first"), "https://first.example/", &["central"]), (Some("second"), "https://second.example/", &["central"])],
                CENTRAL, ("https://first.example/", Some("first"), true)),
            (&[(Some("corp"), "https://mirror.example/", &["*", "!central"])], CENTRAL, (CENTRAL.1, Some("central"), false)),
            (&[(Some("multi"), "https://multi.example/", &["central,snapshots"])], CENTRAL, ("https://multi.example/", Some("multi"), true)),
            (&[(Some("multi"), "https://multi.example/", &["central,snapshots"])], (Some("snapshots"), "https://snapshots.example/"),
                ("https://multi.example/", Some("multi"), true)),
            (&[(Some("multi"), "https://multi.example/", &["central,snapshots"])], (Some("releases"), "https://releases.example/"),
                ("https://releases.example/", Some("releases"), false)),
            (&[(Some("safe"), "https://mirror.example/", &["external:http:*"])], (Some("r"), "http://insecure.example/"),
                ("https://mirror.example/", Some("safe"), true)),
            (&[(Some("safe"), "https://mirror.example/", &["external:http:*"])], (Some("r"), "https://secure.example/"),
                ("https://secure.example/", Some("r"), false)),
            (&[(Some("safe"), "https://mirror.example/", &["external:https:*"])], (Some("r"), "https://secure.example/"),
                ("https://secure.example/", Some("r"), false)),
            (&[(Some("in"), "https://mirror.example/", &["internal:*"])], (Some("r"), "http://localhost/repo/"),
                ("http://localhost/repo/", Some("r"), false)),
            (&[(Some("first"), "https://first.example/", &["central,!central"])], CENTRAL, ("https://first.example/", Some("first"), true)),
            (&[(Some("first"), "https://first.example/", &["!central,*"])], CENTRAL, (CENTRAL.1, Some("central"), false)),
            (&[(Some("multi"), "https://multi.example/", &["central, snapshots"])], (Some("snapshots"), "https://snapshots.example/"),
                ("https://snapshots.example/", Some("snapshots"), false)),
            (&[(Some("multi"), "https://multi.example/", &["central,snapshots"])], (Some("central,snapshots"), "https://odd.example/"),
                ("https://multi.example/", Some("multi"), true)),
            (&[(Some("g"), "https://grpc.example/", &["external:grpc:*"])], (Some("some-repo"), "https://external.example/repo/"),
                ("https://external.example/repo/", Some("some-repo"), false)),
            (&[(Some("g"), "https://grpc.example/", &["external:grpc:*"])], (Some("external:grpc:*"), "https://external.example/repo/"),
                ("https://grpc.example/", Some("g"), true)),
            (&[(Some("corp"), CENTRAL.1, &["central"])], CENTRAL, (CENTRAL.1, Some("corp"), false)),
            (&[(Some("central"), "https://repo1.maven.org/maven2", &["central"])], CENTRAL, (CENTRAL.1, Some("central"), false)),
            (&[(Some("central"), " https://repo1.maven.org/maven2/ ", &["central"])], CENTRAL, (CENTRAL.1, Some("central"), false)),
            (&[(Some("cdn"), "https://cdn.example/", &["*"])], NEXUS, ("https://cdn.example/", Some("cdn"), true)),
            (&[(Some("alt"), "https://nexus.corp/alt/", &["*"])], NEXUS, ("https://nexus.corp/alt/", Some("alt"), false)),
            (&[(None, "https://cdn.example/", &["*"])], NEXUS, ("https://cdn.example/", None, true)),
            (&[(None, "https://nexus.corp/mirror/", &["*"])], NEXUS, ("https://nexus.corp/mirror/", Some("central"), false)),
            (&[(None, "http://nexus.corp:8081/mirror/", &["*"])], NEXUS, ("http://nexus.corp:8081/mirror/", None, true)),
        ];
        for (index, (mirrors, (id, url), (expected_url, expected_id, changed))) in
            cases.iter().enumerate()
        {
            let mirrors: Vec<_> = mirrors
                .iter()
                .map(|(id, url, of)| mirror_config(*id, url, of))
                .collect();
            let repo = Repository::new(id.map(str::to_string), *url, true, true);
            let selector = MirrorSelector::from_mirrors(mirrors);
            let (resolved, _, host_changed) = selector.select(&repo);
            assert_eq!(resolved.url, *expected_url, "case {index}");
            assert_eq!(resolved.id.as_deref(), *expected_id, "case {index}");
            assert_eq!(host_changed, *changed, "case {index}");
        }
    }

    /// Origins compare scheme, case-insensitive host and effective port.
    /// `external:*` reads the parsed host too.
    #[test]
    fn origins_and_loopback_are_decided_on_the_parsed_url() {
        for (a, b, differ) in [
            ("https://nexus.corp/", "https://nexus.corp:443/", false),
            ("http://nexus.corp/", "http://nexus.corp:80/", false),
            ("https://NEXUS.corp/", "https://nexus.CORP/", false),
            ("https://nexus.corp/", "https://nexus.corp:8443/", true),
            ("https://nexus.corp/", "http://nexus.corp/", true),
        ] {
            assert_eq!(super::origins_differ(a, b), differ, "{a} {b}");
        }
        for (url, external) in [
            ("http://[::ffff:7f00:1]/repo", true),
            ("https://[::1]:8080/repo", true),
            ("http://127.0.0.2/repo", true),
            ("http://localhost/repo", false),
            ("http://LOCALHOST/repo", false),
            ("http://user@localhost:8080/repo", false),
            (r"http://localhost\@repo.example/repo", false),
            ("http://127.1/repo", false),
            ("http://2130706433/repo", false),
            ("file:///srv/repo/", false),
            ("FILE:///srv/repo/", false),
            ("https://127.0.0.1:8080/repo", false),
            ("https://repo.example.com/maven2/", true),
        ] {
            assert_eq!(super::is_external_repo(url), external, "{url}");
        }
    }

    /// A mirror serves the layouts `<mirrorOfLayouts>` names, `default` and
    /// `legacy` when unset, read as Resolver reads `<mirrorOf>`.
    #[test]
    fn mirror_layouts_follow_maven() {
        for (layouts, serves) in [
            (None, true),
            (Some(""), true),
            (Some("*"), true),
            (Some("legacy"), false),
            (Some("legacy,default"), true),
            (Some("*,!default"), false),
            (Some("default,!default"), true),
            (Some("legacy, default"), false),
        ] {
            let mut mirror = mirror_config(Some("m"), "https://mirror.example/", &["*"]);
            mirror.mirror_of_layouts = layouts.map(str::to_string);
            let repo = Repository::new(Some("central".into()), "https://repo.example/", true, true);
            let (resolved, _, _) = MirrorSelector::from_mirrors(vec![mirror]).select(&repo);
            assert_eq!(
                resolved.url == "https://mirror.example/",
                serves,
                "{layouts:?}"
            );
        }
    }
}
