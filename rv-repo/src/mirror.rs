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
    /// Default repositories on plain HTTP to a host that is not loopback,
    /// such as a Maven 3.10 Central from `maven.repo.central`, which
    /// [`http_blocker`] serves when no mirror does.
    blocked: HashSet<String>,
}

/// The id of the mirror in Maven's `conf/settings.xml` that blocks
/// external plain HTTP. A user mirror with this id replaces it.
pub const HTTP_BLOCKER_ID: &str = "maven-default-http-blocker";

/// Whether Maven's default HTTP blocker applies under `mirrors`: unless
/// one of them takes its id, as a user `settings.xml` may to turn it off.
pub(crate) fn http_blocker_applies(mirrors: &[rv_config::MirrorConfig]) -> bool {
    !(mirrors.iter()).any(|mirror| mirror.id.as_deref() == Some(HTTP_BLOCKER_ID))
}

/// The normalized URLs of the repositories `raeva.toml` and `config.toml`
/// name, which Maven's default HTTP blocker does not see.
pub(crate) fn own_urls(config: &rv_config::Config) -> HashSet<String> {
    (config.own_repositories())
        .map(|repo| normalize_repo_url(&repo.url))
        .collect()
}

/// The mirror Maven lists `repo` under, its default HTTP blocker among
/// them: the mirror's id, `default` for one without, and whether it
/// blocks. `None` when no mirror takes it.
pub fn listing_mirror(config: &rv_config::Config, repo: &Repository) -> Option<(String, bool)> {
    if let Some(mirror) = resolve_mirror(config.mirrors(), repo).1 {
        let id = mirror.id.clone().unwrap_or_else(|| "default".to_string());
        return Some((id, mirror.blocked));
    }
    (http_blocker_applies(config.mirrors())
        && is_external_http_repo(&repo.url)
        && !own_urls(config).contains(&normalize_repo_url(&repo.url)))
    .then(|| (HTTP_BLOCKER_ID.to_string(), true))
}

/// Maven's default HTTP blocker, a blocked mirror of `external:http:*`.
fn http_blocker() -> rv_config::MirrorConfig {
    let mut blocker = rv_config::MirrorConfig::new(Some(HTTP_BLOCKER_ID), "http://0.0.0.0/");
    blocker.mirror_of = vec!["external:http:*".to_string()];
    blocker.blocked = true;
    blocker
}

impl MirrorSelector {
    /// The configured mirrors and, unless one replaces it, Maven's default
    /// HTTP blocker for the default and settings.xml repositories. Those of
    /// `raeva.toml` and `config.toml` are trusted on plain HTTP, and a
    /// POM's are refused before a request
    /// (`crate::policy::http_repository_blocked`).
    pub(crate) fn from_config(config: &rv_config::Config) -> Self {
        let own = own_urls(config);
        let repositories: Vec<Repository> = (config.all_repositories())
            .map(Repository::from)
            .filter(|repo| !own.contains(&normalize_repo_url(&repo.url)))
            .collect();
        let selector = Self::new(config.mirrors().to_vec(), repositories.iter().cloned());
        let central = |repo: &Repository| {
            repo.id.as_deref() == Some("central")
                && (config.default_repositories().iter()).any(|default| repo.url == default.url)
        };
        for repo in &repositories {
            if selector.blocked.contains(&normalize_repo_url(&repo.url))
                && matching_mirror(&selector.mirrors, repo, false).is_none()
            {
                match central(repo) {
                    true => warn_blocked_central(config),
                    false => warn_blocked_settings_repository(repo),
                }
            }
        }
        selector
    }

    /// The URLs of `defaults` on external plain HTTP go to the blocker
    /// whatever repository names them, unless a mirror of the user's serves
    /// that repository.
    fn new(
        mirrors: Vec<rv_config::MirrorConfig>,
        defaults: impl Iterator<Item = Repository>,
    ) -> Self {
        let blocked = (defaults.filter(|_| http_blocker_applies(&mirrors)))
            .filter(|repo| is_external_http_repo(&repo.url))
            .map(|repo| normalize_repo_url(&repo.url))
            .collect();
        Self { mirrors, blocked }
    }

    /// Crate-internal constructor for tests. Avoids requiring callers to
    /// build a full `rv_config::Config` just to plug a single `MirrorConfig`
    /// into the selector.
    #[cfg(test)]
    pub(crate) fn from_mirrors(mirrors: Vec<rv_config::MirrorConfig>) -> Self {
        Self::new(mirrors, std::iter::empty())
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
        if mirror.is_none() && self.blocked.contains(&normalize_repo_url(&repo.url)) {
            return (resolved, Some(http_blocker()), false);
        }
        (resolved, mirror.cloned(), host_changed)
    }
}

static CENTRAL_BLOCKED_WARNED: std::sync::Once = std::sync::Once::new();

/// Say once that Central is not searched, naming where its URL was set,
/// never the URL.
fn warn_blocked_central(config: &rv_config::Config) {
    let origin = config
        .replaced_central()
        .map(|(_, origin)| origin.to_string());
    CENTRAL_BLOCKED_WARNED.call_once(|| {
        tracing::warn!(
            sec_code = "HTTP_REPO_BLOCKED",
            origin = origin.as_deref().unwrap_or("the configuration"),
            project = true,
            "Maven Central from {} is plain HTTP to a host that is not loopback, which Maven's \
             default HTTP blocker refuses, so no request goes to it; mirror it or give an \
             https URL",
            origin.as_deref().unwrap_or("the configuration"),
        );
    });
}

static SETTINGS_BLOCKED_WARNED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);

/// Say once per URL that a settings.xml repository is not searched, by its
/// id: a shown URL is normalized, so `http://127.1/` would read as
/// loopback.
fn warn_blocked_settings_repository(repo: &Repository) {
    let first = (SETTINGS_BLOCKED_WARNED.lock())
        .unwrap_or_else(|poison| poison.into_inner())
        .insert(repo.url.clone());
    if first {
        let id = rv_maven_types::bounded(repo.id.as_deref().unwrap_or("<no id>"));
        tracing::warn!(
            sec_code = "HTTP_REPO_BLOCKED",
            repository = %id,
            project = true,
            "ignoring repository '{id}' that settings.xml declares: plain HTTP to a host that \
             is not loopback as Maven reads the URL, which Maven's default HTTP blocker \
             refuses, so no request goes to it; mirror it or give an https URL"
        );
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
            original_url = %rv_config::redact_repository_url(&repo.url),
            mirror_url = %rv_config::redact_url(&mirror.url),
            mirror_id = ?id,
            host_changed,
            "redirecting to mirror"
        );
    }
    // A mirror changes the endpoint, not the origin's policies.
    let mut resolved = repo.clone();
    resolved.id = id;
    resolved.set_mirror_url(mirror);
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
    // Resolver's builder reads an absent id as an empty one.
    let id = repo.id.as_deref().unwrap_or_default();
    mirrors
        .iter()
        .find(|mirror| id == pattern(mirror) && serves_layout(mirror, repo.layout()))
        .or_else(|| {
            mirrors.iter().find(|mirror| {
                let mirror_id = mirror.id.as_deref().unwrap_or("<unnamed>");
                match_pattern(repo, &pattern(mirror), mirror_id, diagnostics)
                    && serves_layout(mirror, repo.layout())
            })
        })
}

/// Resolver's `matchPattern`: `*`, the id itself, or a comma-separated list
/// read in order, where the first `!id` or `id` that names the repository
/// decides and `*`, `external:*` and `external:http:*` match unless a later
/// entry excludes the repository. Entries are not trimmed.
fn match_pattern(repo: &Repository, pattern: &str, mirror_id: &str, diagnostics: bool) -> bool {
    let id = repo.id.as_deref().unwrap_or_default();
    if pattern == "*" || pattern == id {
        return true;
    }
    let mut matched = false;
    // Java's `split` drops trailing empty entries, and leaves none of a
    // list of commas alone.
    let list = pattern.trim_end_matches(',');
    if list.is_empty() {
        return false;
    }
    for entry in list.split(',') {
        if let Some(excluded) = entry.strip_prefix('!').filter(|rest| !rest.is_empty()) {
            if excluded == id {
                return false;
            }
        } else if entry == id {
            return true;
        } else if (entry == "external:*" && is_external_repo(repo.declared_url()))
            || (entry == "external:http:*" && is_external_http_repo(repo.declared_url()))
            || entry == "*"
        {
            matched = true;
        } else if diagnostics
            && !matches!(entry, "external:*" | "external:http:*")
            && (entry.starts_with("external:") || entry.starts_with("internal:"))
        {
            warn_unknown_pattern_once(entry, mirror_id);
        }
    }
    matched
}

/// Resolver's `matchesType` for a repository of `layout`.
fn serves_layout(mirror: &rv_config::MirrorConfig, layout: &str) -> bool {
    let layouts = mirror
        .mirror_of_layouts
        .as_deref()
        .unwrap_or("default,legacy");
    if layouts.is_empty() || layouts == "*" || layouts == layout {
        return true;
    }
    let mut matched = false;
    for entry in layouts.trim_end_matches(',').split(',') {
        if let Some(excluded) = entry.strip_prefix('!').filter(|rest| !rest.is_empty()) {
            if excluded == layout {
                return false;
            }
        } else if entry == layout {
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

/// The protocol and host Resolver's `RemoteRepository` reads in `url`,
/// with the pattern `([^:/]+(:[^:/]{2,}+(?=://))?):(//([^@/]*@)?([^/:]+))?.*`
/// that must match the whole URL; both are empty when it does not. So
/// `./repo`, `repo/` and `${undefined}/repo` have no protocol, and
/// `http://[::1` reads as `http` on the host `[`.
fn resolver_parts(url: &str) -> (&str, &str) {
    // Java's `.` matches no line terminator.
    let plain = |text: &str| !text.contains(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}']);
    let run = |text: &str, stop: &[char]| text.find(stop).unwrap_or(text.len());
    let first = run(url, &[':', '/']);
    if first == 0 || !url[first..].starts_with(':') {
        return ("", "");
    }
    // The optional `:[^:/]{2,}+` before `://`, as in `dav:http://`, is
    // tried first, then the protocol without it.
    let second = run(&url[first + 1..], &[':', '/']);
    // `{2,}` counts characters, not bytes.
    let long = (url[first + 1..first + 1 + second].chars().nth(1).is_some()
        && url[first + 1 + second..].starts_with("://"))
    .then_some(first + 1 + second);
    for end in long.into_iter().chain([first]) {
        let rest = &url[end + 1..];
        if let Some(authority) = rest.strip_prefix("//") {
            let user = run(authority, &['@', '/']);
            let with_user = authority[user..].starts_with('@').then_some(user + 1);
            for skip in with_user.into_iter().chain([0]) {
                let tail = &authority[skip..];
                let host = run(tail, &['/', ':']);
                if host > 0 && plain(&tail[host..]) {
                    return (&url[..end], &tail[..host]);
                }
            }
        }
        if plain(rest) {
            return (&url[..end], "");
        }
    }
    ("", "")
}

/// Resolver's `isLocal` of the host it reads in `url` (`localhost` or
/// `127.0.0.1`, as spelled), when the request parser, if it reads the URL,
/// reads that host too: text it reads as another host is never local.
fn is_local(url: &str) -> bool {
    let local = |host: Option<&str>| matches!(host, Some("localhost" | "127.0.0.1"));
    local(Some(resolver_parts(url).1))
        && Url::parse(url).map_or(true, |parsed| local(parsed.host_str()))
}

/// Resolver's `isExternalRepo` for `external:*`: neither a local host nor
/// the `file` protocol.
pub(crate) fn is_external_repo(url: &str) -> bool {
    !(is_local(url) || resolver_parts(url).0.eq_ignore_ascii_case("file"))
}

/// Resolver's `isExternalHttpRepo` for `external:http:*` and the HTTP
/// blocker: the `http`, `dav`, `dav:http` or `dav+http` protocol on a host
/// that is not local. A URL the request parser reads as plain HTTP to such
/// a host is external HTTP too, whatever Resolver reads in it, as raeva
/// would fetch it so.
pub(crate) fn is_external_http_repo(url: &str) -> bool {
    let protocol = resolver_parts(url).0;
    let http = ["http", "dav", "dav:http", "dav+http"]
        .iter()
        .any(|name| protocol.eq_ignore_ascii_case(name))
        || Url::parse(url).is_ok_and(|parsed| parsed.scheme() == "http");
    http && !is_local(url)
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

    /// Maven's default HTTP blocker serves a default repository on plain
    /// HTTP to another host, such as a Maven 3.10 Central from
    /// `maven.repo.central`, unless a mirror of it does or a user mirror
    /// takes the blocker's id.
    #[test]
    fn the_http_blocker_serves_an_http_default_no_mirror_serves() {
        let central = Repository::new(
            Some("central".into()),
            "http://central.example/m2",
            true,
            false,
        );
        let served = |mirrors: &[(&str, &str)], default: &Repository, repo: &Repository| {
            let mirrors = (mirrors.iter())
                .map(|(id, of)| mirror_config(Some(id), "https://mirror.example/", &[of]))
                .collect();
            let selector = MirrorSelector::new(mirrors, std::iter::once(default.clone()));
            let (_, mirror, _) = selector.select(repo);
            mirror.map(|mirror| (mirror.id.unwrap(), mirror.blocked))
        };
        let served_by =
            |mirrors: &[(&str, &str)], default: &Repository| served(mirrors, default, &central);
        let blocker = Some(("maven-default-http-blocker".to_string(), true));
        assert_eq!(served_by(&[], &central), blocker);
        assert_eq!(served_by(&[("corp", "other")], &central), blocker);
        for of in ["central", "*", "external:*", "external:http:*"] {
            assert_eq!(
                served_by(&[("corp", of)], &central),
                Some(("corp".into(), false)),
                "{of}"
            );
        }
        assert_eq!(
            served_by(&[("maven-default-http-blocker", "other")], &central),
            None
        );
        // Another repository on that URL that the mirror of Central does
        // not serve is blocked, as Maven blocks it.
        let other = Repository::new(Some("other".into()), &central.url, true, false);
        assert_eq!(served(&[("corp", "central")], &central, &other), blocker);
        // Only a default repository on plain HTTP to another host is blocked.
        for url in ["https://central.example/m2", "http://localhost:8081/m2"] {
            let default = Repository::new(Some("central".into()), url, true, false);
            assert_eq!(served_by(&[], &default), None, "{url}");
        }
    }

    /// `external:*` and `external:http:*` read the protocol and host as
    /// Resolver's `RemoteRepository` does, and a host the request parser
    /// reads otherwise is not local.
    #[test]
    fn external_mirrors_read_the_url_as_resolver_does() {
        // (url, external:*, external:http:*)
        for (url, external, http) in [
            (r"http://repo.example\@localhost/maven2/", true, true),
            ("dav:\u{e9}://repo.example/", true, true),
            ("http://repo.example?@localhost/", true, true),
            ("http://repo.example#@localhost/", true, true),
            ("http://[invalid]/", true, true),
            ("http://[::1", true, true),
            // Resolver reads `localhost`, the request parser nothing.
            ("http://localhost:invalid/", false, false),
            ("not a URL", true, false),
            ("./x", true, false),
            ("x/", true, false),
            ("${undefined.prop}/x", true, false),
            ("ftp://h.example/x/", true, false),
            ("dav:http://h.example/x/", true, true),
            ("DAV+HTTP://h.example/x/", true, true),
            ("dav://localhost/x/", false, false),
            ("symlink+file:///srv/repo/", true, false),
            ("C:/srv/repo", true, false),
            ("file:repo", false, false),
            ("http:/localhost/x/", true, true),
            // The request parser drops the line break and reads HTTP.
            ("ht\ntp://h.example/x/", true, true),
        ] {
            assert_eq!(super::is_external_repo(url), external, "{url:?}");
            assert_eq!(super::is_external_http_repo(url), http, "{url:?}");
            for (pattern, matched) in [("external:*", external), ("external:http:*", http)] {
                let repo = Repository::new(Some("corp".into()), url, true, true);
                let selector = MirrorSelector::from_mirrors(vec![mirror_config(
                    Some("mirror"),
                    "https://mirror.example/",
                    &[pattern],
                )]);
                let (_, mirror, _) = selector.select(&repo);
                assert_eq!(mirror.is_some(), matched, "{pattern}: {url:?}");
            }
        }
    }

    /// The protocol and host groups of Resolver's URL pattern.
    #[test]
    fn resolver_parts_follow_the_url_pattern() {
        for (url, protocol, host) in [
            ("https://repo.example:8443/m2/", "https", "repo.example"),
            ("http://user:pw@localhost:8080/", "http", "localhost"),
            ("http://[::1", "http", "["),
            ("http://[::1]:8080/", "http", "["),
            ("dav:http://h.example/", "dav:http", "h.example"),
            ("a:bc://h/", "a:bc", "h"),
            ("a:b://h/", "a", ""),
            ("dav:\u{e9}://repo.example/", "dav", ""),
            (
                "dav:\u{e9}\u{e9}://repo.example/",
                "dav:\u{e9}\u{e9}",
                "repo.example",
            ),
            ("file:///srv/repo", "file", ""),
            ("file:repo", "file", ""),
            ("C:/srv/repo", "C", ""),
            ("./x", "", ""),
            ("x/", "", ""),
            ("${undefined.prop}/x", "", ""),
            ("", "", ""),
            ("http://h/x\n", "", ""),
            ("http://a\nb@h/x", "http", "h"),
            ("http://h\n/x", "http", "h\n"),
        ] {
            assert_eq!(super::resolver_parts(url), (protocol, host), "{url:?}");
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
            // Java's split leaves no entry of a list of commas alone.
            (&[(Some("commas"), "https://commas.example/", &[",,"])], CENTRAL, (CENTRAL.1, Some("central"), false)),
            // Resolver's builder reads an absent id as an empty one, which
            // `*` matches.
            (&[(Some("all"), "https://all.example/", &["*"])], (None, "https://no-id.example/"),
                ("https://all.example/", Some("all"), true)),
            // An empty entry names it, even on this machine.
            (&[(Some("empty"), "https://empty.example/", &["external:*", "", "!central"])],
                (None, "http://127.0.0.1:1/"), ("https://empty.example/", Some("empty"), true)),
            (&[(Some("empty"), "https://empty.example/", &["", "never"])],
                (None, "http://127.0.0.1:1/"), ("https://empty.example/", Some("empty"), true)),
            (&[(Some("empty"), "https://empty.example/", &["", "never"])], CENTRAL,
                (CENTRAL.1, Some("central"), false)),
            (&[(Some("commas"), "https://commas.example/", &["", ""])],
                (None, "http://127.0.0.1:1/"), ("http://127.0.0.1:1/", None, false)),
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
    /// `external:*` takes a host as local only when both the request parser
    /// and Resolver, which reads the host as spelled, do.
    #[test]
    fn origins_are_parsed_and_loopback_is_spelled() {
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
            ("http://LOCALHOST/repo", true),
            ("http://user@localhost:8080/repo", false),
            (r"http://localhost\@repo.example/repo", true),
            ("http://127.1/repo", true),
            ("http://2130706433/repo", true),
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
