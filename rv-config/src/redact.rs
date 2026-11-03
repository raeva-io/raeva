use std::sync::{PoisonError, RwLock};
use url::Url;

const REDACTED: &str = "***";

/// Mirror URLs that settings.xml expanded with a secret-named variable, as
/// parsed, each with the masked form shown in their place.
static MASKED_URLS: RwLock<Vec<(String, String)>> = RwLock::new(Vec::new());

/// Show `masked` in place of `expanded` wherever [`redact_url`] or
/// [`redacted_url`] shows that URL or one under it: the same text up to a
/// `/`, `?` or `#`, with or without a trailing slash. `expanded` is a
/// mirror URL as settings.xml expanded it, and `masked` the same URL with
/// `***` for each secret-named variable: a mirror URL may take a token, as
/// services such as Cloudsmith expect.
pub fn register_masked_url(expanded: &str, masked: &str) {
    let shown = |url: &Url| {
        let shown = redact_parsed(url, false).to_string();
        shown.trim_end_matches('/').to_string()
    };
    let Ok(expanded) = Url::parse(expanded).map(|url| shown(&url)) else {
        return;
    };
    // A masked host may not parse; such a URL is not shown at all.
    let masked = Url::parse(masked).map_or_else(
        |_| UNPARSABLE_URL_PLACEHOLDER.trim_end_matches('/').to_string(),
        |url| shown(&url),
    );
    let mut urls = MASKED_URLS.write().unwrap_or_else(PoisonError::into_inner);
    if expanded != masked && !urls.iter().any(|(known, _)| *known == expanded) {
        urls.push((expanded, masked));
        // The longest first, so a mirror under another's path matches whole.
        urls.sort_by_key(|(expanded, _)| std::cmp::Reverse(expanded.len()));
    }
}

fn mask(url: Url) -> Url {
    let urls = MASKED_URLS.read().unwrap_or_else(PoisonError::into_inner);
    let shown = url.as_str();
    let Some((expanded, masked)) = urls.iter().find(|(expanded, _)| {
        shown
            .strip_prefix(expanded.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '#']))
    }) else {
        return url;
    };
    let masked = format!("{masked}{}", &shown[expanded.len()..]);
    Url::parse(&masked)
        .unwrap_or_else(|_| Url::parse(UNPARSABLE_URL_PLACEHOLDER).expect("placeholder URL parses"))
}

/// What stands in for text that does not parse as a URL.
pub const UNPARSABLE_URL: &str = "<unparsable URL>";

/// What [`redacted_url`] returns for a URL without an authority, whose
/// scheme and path may be a misread `user:password`.
const UNPARSABLE_URL_PLACEHOLDER: &str = "https://redacted.invalid/";

/// A URL with everything that may carry a secret removed, for messages and
/// logs: the userinfo (`user:pass@`) is dropped, a query string becomes
/// `?***` because its names can be tokens too, and the fragment is dropped.
/// A URL without userinfo whose authority has a port, and an `@` after it,
/// may still hold userinfo that the parser read as host and port, as in
/// `https://user:1234/x@host/`, where the password starts with `1234/`.
/// Such a URL loses everything before its last `@`, or everything after the
/// scheme when that `@` comes after a `?` or `#`, where it may sit in a
/// query. Without a port, a later `@` is kept, as in a signed download URL
/// that names an account in its query.
///
/// Text that does not parse as a URL with an authority, such as
/// `user:pass@host/path` or `user:/pass@host/path`, which parse with `user`
/// as their scheme, is not shown at all: it may be a token pasted in place of a URL, or a URL whose
/// credentials made it fail to parse. It becomes [`UNPARSABLE_URL`].
pub fn redact_url(url: impl AsRef<str>) -> String {
    let raw = url.as_ref();
    match Url::parse(raw) {
        Ok(parsed) if parsed.has_authority() => {
            // The parser drops an empty or default port, as in
            // `https://user:443/x@host/`, so look for it in the text.
            mask(redact_parsed(&parsed, raw_authority_has_port(raw))).to_string()
        }
        _ => UNPARSABLE_URL.to_string(),
    }
}

/// [`redact_url`] for a parsed URL, as a `Url` so it can be attached to an
/// error in place of the original. A URL without an authority becomes
/// `https://redacted.invalid/`. It cannot see a port that parsing
/// dropped, so `https://user:443/x@host/` keeps `user` as the host and `/x@`
/// in the path; the text form passed to [`redact_url`] does not.
pub fn redacted_url(url: &Url) -> Url {
    mask(redact_parsed(url, false))
}

/// The part of `url` that [`redact_url`] would remove because it may carry
/// a secret: `"userinfo"`, `"a query"` or `"a fragment"`, or `None` when
/// the redacted form is the URL itself. A repository URL with such a part
/// cannot be recorded in raeva.lock or shown without leaking it. Text that does
/// not parse as a URL with an authority counts as userinfo when it holds an
/// `@`, since that is what made it fail, and as clean otherwise.
pub fn secret_url_part(url: &str) -> Option<&'static str> {
    let parsed = match Url::parse(url) {
        Ok(parsed) if parsed.has_authority() => parsed,
        _ => return url.contains('@').then_some("userinfo"),
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Some("userinfo");
    }
    if parsed.query().is_some() {
        return Some("a query");
    }
    if parsed.fragment().is_some() {
        return Some("a fragment");
    }
    // A port read from a password, as in `https://user:1234/x@host/`.
    let redacted = redact_parsed(&parsed, raw_authority_has_port(url)).to_string();
    (redacted != parsed.as_str()).then_some("userinfo")
}

/// Whether a property or environment variable name looks like it holds a
/// secret: it has `TOKEN`, `SECRET`, `PASS`, `KEY`, `AUTH`, `CREDENTIAL` or
/// `ENTITLEMENT` in it, in any case.
pub fn secret_named(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASS",
        "KEY",
        "AUTH",
        "CREDENTIAL",
        "ENTITLEMENT",
    ]
    .iter()
    .any(|word| upper.contains(word))
}

/// The path of a repository URL as written, where services such as
/// Cloudsmith take a token: what follows the authority, or the whole text
/// when it has no `://`, as the scheme or host may still be unexpanded.
/// `None` for a `file:` URL, whose path names a local directory.
pub(crate) fn repository_url_path(url: &str) -> Option<&str> {
    if Url::parse(url).is_ok_and(|url| url.scheme() == "file") {
        return None;
    }
    Some(match url.split_once("://") {
        // A backslash ends an http(s) authority too.
        Some((_, rest)) => rest.find(['/', '\\']).map_or("", |slash| &rest[slash..]),
        None => url,
    })
}

/// Whether `value` makes up one or more whole segments of the path of the
/// repository URL `url`, as a token a service takes there does: what
/// follows the authority, or the whole text without a `://`. A `${...}`
/// left in `value`, which only a model can expand, stands for any text, so
/// such a value counts by the text around it. A value with no text but
/// separators never counts, nor does a `file:` URL.
pub fn url_path_holds(url: &str, value: &str) -> bool {
    repository_url_path(url).is_some_and(|path| holds_value(path, value, true))
}

/// Whether `text` holds `value`, as whole segments when `segments`, with
/// each `${...}` in `value` standing for any text.
fn holds_value(text: &str, value: &str, segments: bool) -> bool {
    let separator = |c: char| matches!(c, '/' | '\\');
    let parts = literal_parts(value);
    if !(parts.iter()).any(|part| part.contains(|c| !separator(c))) {
        return false;
    }
    let edge = |c: Option<char>| !segments || c.is_none_or(separator);
    let starts_segment =
        |at: usize, part: &str| edge(text[..at].chars().next_back()) || edge(part.chars().next());
    let ends_segment = |at: usize, part: &str| {
        let end = at + part.len();
        edge(text[end..].chars().next()) || edge(part.chars().next_back())
    };
    let found = |from, part| occurrences(text, from, part);
    let (first, rest) = parts.split_first().expect("a value has a first part");
    let Some((last, middle)) = rest.split_last() else {
        return found(0, first).any(|at| starts_segment(at, first) && ends_segment(at, first));
    };
    // The earliest start leaves the most room for the rest.
    let Some(start) = found(0, first).find(|&at| starts_segment(at, first)) else {
        return false;
    };
    let mut at = start + first.len();
    for part in middle {
        match text[at..].find(part) {
            Some(found) => at += found + part.len(),
            None => return false,
        }
    }
    found(at, last).any(|at| ends_segment(at, last))
}

/// Each place `part` starts in `text` at or after `from`, overlapping ones
/// too.
fn occurrences<'a>(text: &'a str, from: usize, part: &'a str) -> impl Iterator<Item = usize> + 'a {
    let mut at = from;
    std::iter::from_fn(move || {
        let found = at + text.get(at..)?.find(part)?;
        at = found + text[found..].chars().next().map_or(1, char::len_utf8);
        Some(found)
    })
}

/// The text of `value` around each `${...}` in it, one more than there are
/// of those. Expressions nest, as in `${${name}}`.
fn literal_parts(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find("${")
        && let Some(end) = closing_brace(&rest[start + 2..])
    {
        parts.push(&rest[..start]);
        rest = &rest[start + 2 + end + 1..];
    }
    parts.push(rest);
    parts
}

fn closing_brace(text: &str) -> Option<usize> {
    let mut depth = 1;
    text.char_indices().find_map(|(at, c)| {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        (depth == 0).then_some(at)
    })
}

/// How a message names the first of `secrets`, each a name and a value as
/// [`crate::Config::secret_named_inputs`] gives them, whose value makes up
/// whole segments of the path of `url` ([`url_path_holds`]).
pub fn secret_input_in_path<'a>(url: &str, secrets: &'a [(String, String)]) -> Option<&'a str> {
    (secrets.iter())
        .find(|(_, value)| url_path_holds(url, value))
        .map(|(input, _)| input.as_str())
}

/// `text`, such as a repository id, for a message, or `***` when it holds
/// the value of one of `secrets`, read as [`url_path_holds`] reads it but
/// anywhere in `text`.
pub fn without_secret_values<'a>(text: &'a str, secrets: &[(String, String)]) -> &'a str {
    if (secrets.iter()).any(|(_, value)| holds_value(text, value, false)) {
        REDACTED
    } else {
        text
    }
}

fn redact_parsed(url: &Url, had_port: bool) -> Url {
    if !url.has_authority() {
        return Url::parse(UNPARSABLE_URL_PLACEHOLDER).expect("placeholder URL parses");
    }
    let mut redacted = url.clone();
    if url.username().is_empty()
        && url.password().is_none()
        && (had_port || url.port().is_some())
        && url.as_str().contains('@')
    {
        // Parses with `***` as the userinfo, which is dropped below.
        redacted = Url::parse(&strip_misread_userinfo(url.as_str())).unwrap_or_else(|_| {
            let mut placeholder = url.clone();
            let _ = placeholder.set_host(Some("redacted.invalid"));
            let _ = placeholder.set_port(None);
            placeholder.set_path("");
            placeholder
        });
    }
    // Fails only for URLs that cannot have userinfo, such as `mailto:`.
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    if redacted.query().is_some() {
        redacted.set_query(Some(REDACTED));
    }
    redacted.set_fragment(None);
    redacted
}

fn raw_authority_has_port(raw: &str) -> bool {
    // The parser trims C0 controls and spaces around the input and drops
    // tabs and newlines anywhere in it.
    let cleaned: String = raw
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let Some((scheme, rest)) = cleaned.split_once(':') else {
        return false;
    };
    if !is_scheme(scheme) {
        return false;
    }
    let (rest, delimiters): (&str, &[char]) = match scheme.to_ascii_lowercase().as_str() {
        // These take any run of `/` or `\` after the scheme, including
        // none, as in `https:host:443/`.
        "http" | "https" | "ws" | "wss" | "ftp" => {
            (rest.trim_start_matches(['/', '\\']), &['/', '?', '#', '\\'])
        }
        // A file URL has no port; `C:` in `file:///C:/` is a drive.
        "file" => return false,
        _ => match rest.strip_prefix("//") {
            Some(rest) => (rest, &['/', '?', '#']),
            None => return false,
        },
    };
    let authority = &rest[..rest.find(delimiters).unwrap_or(rest.len())];
    let host_end = authority.rfind(']').map_or(0, |index| index + 1);
    authority[host_end..].contains(':')
}

fn is_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Removes everything up to the last `@` of a URL's text, and its query and
/// fragment, so the rest parses without the userinfo the parser misread.
fn strip_misread_userinfo(raw: &str) -> String {
    // A scheme only when it is one by RFC 3986, so a `user:pass://` prefix
    // is not kept as one.
    let scheme_len = raw
        .find("://")
        .filter(|&end| is_scheme(&raw[..end]))
        .map_or(0, |end| end + 3);
    let (scheme, rest) = raw.split_at(scheme_len);
    let mut out = String::with_capacity(raw.len());
    out.push_str(scheme);
    let query = rest.find(['?', '#']);
    // The last `@`, wherever it is: a password may contain `/` or `@`.
    let rest = match rest.rfind('@') {
        // After a `?` or `#` it may end a password holding one, or sit in
        // a query, so nothing after the scheme can be shown as a host.
        Some(at) if query.is_some_and(|query| query < at) => {
            out.push_str(REDACTED);
            return out;
        }
        Some(at) => {
            out.push_str(REDACTED);
            &rest[at..]
        }
        None => rest,
    };
    match rest.find(['?', '#']) {
        Some(index) => {
            out.push_str(&rest[..index]);
            out.push('?');
            out.push_str(REDACTED);
        }
        None => out.push_str(rest),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::redact_url;

    #[test]
    fn a_registered_mirror_url_is_shown_masked() {
        use super::{redact_url, register_masked_url};
        register_masked_url(
            "https://m.example/tok3n-zq/m2/",
            "https://m.example/***/m2/",
        );
        register_masked_url("https://q9.example/m2/", "https://***.example/m2/");
        for (raw, shown) in [
            (
                "https://m.example/tok3n-zq/m2/a/1/a-1.jar",
                "https://m.example/***/m2/a/1/a-1.jar",
            ),
            (
                "https://M.example:443/tok3n-zq/m2/",
                "https://m.example/***/m2/",
            ),
            (
                "https://m.example/other/tok3n-zq/m2/",
                "https://m.example/other/tok3n-zq/m2/",
            ),
            (
                "https://q9.example/m2/a.pom",
                "https://***.example/m2/a.pom",
            ),
            (
                "https://repo1.maven.org/maven2/m2/",
                "https://repo1.maven.org/maven2/m2/",
            ),
            ("https://m.example/tok3n-zq/m2", "https://m.example/***/m2"),
            (
                "https://m.example/tok3n-zq/m2-public/a.pom",
                "https://m.example/tok3n-zq/m2-public/a.pom",
            ),
            (
                "https://m.example/tok3n-zq/m2?x=1",
                "https://m.example/***/m2?***",
            ),
        ] {
            assert_eq!(redact_url(raw), shown, "{raw}");
        }
    }

    #[test]
    fn secret_url_parts_are_named() {
        use super::secret_url_part;
        for (raw, part) in [
            ("https://repo1.maven.org/maven2/", None),
            ("https://Repo.Example:8443/m2", None),
            ("file:///C:/Users/alice@corp/.m2/repository/", None),
            ("https://repo.example/npm/@types/node/", None),
            ("https://user:pass@repo.example/m2/", Some("userinfo")),
            ("https://token@repo.example/m2/", Some("userinfo")),
            ("https://alice:1234/x@repo.example/m2/", Some("userinfo")),
            ("https://user:pa/ss@repo.example/m2/", Some("userinfo")),
            ("user:pass@repo.example/m2/", Some("userinfo")),
            ("https://repo.example/m2/?token=abc", Some("a query")),
            ("https://repo.example/m2/#abc", Some("a fragment")),
            ("not a url", None),
        ] {
            assert_eq!(secret_url_part(raw), part, "{raw}");
        }
    }

    #[test]
    fn secret_names_are_recognised_in_any_case() {
        use super::secret_named;
        for name in [
            "cs.token",
            "CLOUDSMITH_API_KEY",
            "nexus.Password",
            "repo.secret",
            "auth.header",
            "aws.credentials",
            "entitlement",
        ] {
            assert!(secret_named(name), "{name}");
        }
        for name in ["nexus.url", "CI_PROJECT_ID", "repo.path", "revision"] {
            assert!(!secret_named(name), "{name}");
        }
    }

    #[test]
    fn repository_path_locality_uses_the_parsed_scheme() {
        assert!(super::repository_url_path("f\tile:///srv/repo/").is_none());
        assert!(super::repository_url_path("file://[invalid]/repo/").is_some());
    }

    /// A value counts when it makes up whole segments of the path, never
    /// when it is in the host, part of a segment or in a `file:` URL. An
    /// expression left in it stands for any text.
    #[test]
    fn url_path_values_are_whole_segments() {
        use super::url_path_holds;
        for (url, value) in [
            ("https://dl.example/abc123/org/maven/", "abc123"),
            ("https://dl.example/maven/abc123", "abc123"),
            ("https://dl.example\\abc123\\maven/", "abc123"),
            ("https://dl.example/org/abc/123/maven/", "abc/123"),
            ("https://dl.example/org/abc/123/maven/", "/abc/123/"),
            ("https://dl.example/xa/a/a/", "a/a"),
            ("dl.example/abc123/maven/", "abc123"),
            ("abc123/maven/", "abc123"),
            (
                "https://dl.example/amd64/abc123/maven/",
                "${os.arch}/abc123",
            ),
            (
                "https://dl.example/app-abc123/maven/",
                "${project.artifactId}-abc123",
            ),
            ("https://dl.example/x/abc/y/123/", "abc/${a}/123"),
            ("https://dl.example/abc123/x/", "abc${a}"),
            ("https://dl.example/prod/abc123/x/", "${${selector}}/abc123"),
            ("https://dl.example/ab/abc/", "${a}/abc"),
        ] {
            assert!(url_path_holds(url, value), "{url} {value}");
        }
        for (url, value) in [
            ("https://abc123.example/maven/", "abc123"),
            ("https://dl.example/abc1234/maven/", "abc123"),
            ("https://dl.example/v1/maven/", "1"),
            ("https://dl.example/maven/", ""),
            ("file:///srv/abc123/m2/", "abc123"),
            ("FILE:/C:/abc123/", "abc123"),
            ("https://dl.example/xabc123/maven/", "abc123${a}"),
            ("https://dl.example/abc/maven/", "${a}abc123"),
            ("https://dl.example/a/b/", "${a}/${b}"),
            ("https://dl.example/abc/abc12/", "${a}/abc123"),
        ] {
            assert!(!url_path_holds(url, value), "{url} {value}");
        }
    }

    #[test]
    fn texts_that_hold_a_secret_value_are_hidden() {
        use super::without_secret_values;
        let secrets = [("-Dcs.token".to_string(), "${stage}/abc123".to_string())];
        assert_eq!(without_secret_values("id-prod/abc123", &secrets), "***");
        assert_eq!(without_secret_values("id-x/abc123y", &secrets), "***");
        assert_eq!(without_secret_values("idabc123", &secrets), "idabc123");
        assert_eq!(without_secret_values("releases", &secrets), "releases");
    }

    #[test]
    fn parsed_urls_lose_userinfo_query_and_fragment() {
        for (raw, expected) in [
            (
                "https://user:pass@repo.example/maven/?token=secret&sig=abc#frag",
                "https://repo.example/maven/?***",
            ),
            (
                "https://user@repo.example/maven/",
                "https://repo.example/maven/",
            ),
            (
                "https://repo.example/maven/?ghp_bare",
                "https://repo.example/maven/?***",
            ),
            (
                "https://repo1.maven.org/maven2/",
                "https://repo1.maven.org/maven2/",
            ),
            ("file:///srv/m2/", "file:///srv/m2/"),
            ("https:user:pass@repo.example/m2", "https://repo.example/m2"),
            // These parse, with the password's digits as the port.
            (
                "https://alice:1234/x@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            ("https://alice:1234?x@repo.example/", "https://***/"),
            ("https://alice:1234#x@repo.example/", "https://***/"),
            // With a port, an `@` in the query may end a password.
            (
                "https://repo.example:8443/m2/?token=user@secret",
                "https://***/",
            ),
            ("https://repo.example:8443/m2/#user@secret", "https://***/"),
            ("https://alice:443/x@repo.example/", "https://repo.example/"),
            ("https://alice:/x@repo.example/", "https://repo.example/"),
            // The parser takes any run of `/` or `\` after the scheme.
            (
                "https:alice:443/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            (
                "https:///alice:443/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            (
                "https:\\\\alice:/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            // The parser trims spaces and drops tabs and newlines.
            (
                " https://alice:443/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            (
                "ht\ttps:/\t/alice:443/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            (
                "https://alice:4\n43/s3cret@repo.example/m2/",
                "https://repo.example/m2/",
            ),
            // A drive letter is not a port.
            (
                "file:///C:/Users/alice@corp/.m2/repository/",
                "file:///C:/Users/alice@corp/.m2/repository/",
            ),
            // With userinfo, a later `@` is part of the path.
            ("https://u:p@repo.example/a@b/", "https://repo.example/a@b/"),
            // Without a port, a later `@` is part of the path or query.
            (
                "https://repo.example/npm/@types/node",
                "https://repo.example/npm/@types/node",
            ),
            (
                "https://storage.example/b/o?cred=svc@project.example",
                "https://storage.example/b/o?***",
            ),
            ("https://[::1]/a@b/", "https://[::1]/a@b/"),
        ] {
            assert_eq!(redact_url(raw), expected, "{raw}");
        }
        let url = url::Url::parse("https://u:p@repo.example/a?b=c").unwrap();
        assert_eq!(redact_url(&url), "https://repo.example/a?***");
        let url = url::Url::parse("https://alice:1234/x@[bad/").unwrap();
        let redacted = super::redacted_url(&url).to_string();
        assert!(
            !redacted.contains("1234") && !redacted.contains("alice"),
            "{redacted}"
        );
    }

    /// Text that does not parse is not shown, however much of it is a URL.
    #[test]
    fn unparsable_text_is_not_shown() {
        for raw in [
            // The port does not parse: `pa/ss` is part of the password.
            "https://user:pa/ss@repo.example/m2/",
            "https://user:secret@[::1/m2/",
            "https://user:p@ss@repo example/",
            // Parses, with `user` as the scheme and no authority.
            "user:secret@repo.example/m2",
            "https://repo example/m2?token=secret",
            "https://alice:secret?tail@repo.example/",
            "alice:secret://x@repo.example",
            // Parse with `alice` as the scheme, a path and no authority.
            "alice:/s3cret@repo.example/m2",
            "alice:s3cret@repo.example",
            "ghp_secret",
            "",
        ] {
            assert_eq!(redact_url(raw), super::UNPARSABLE_URL, "{raw:?}");
        }
    }

    #[test]
    fn typed_redaction_needs_an_authority() {
        use super::redacted_url;
        for raw in ["alice:s3cret@repo.example", "alice:/s3cret@repo.example/m2"] {
            let url = url::Url::parse(raw).unwrap();
            assert_eq!(
                redacted_url(&url).as_str(),
                "https://redacted.invalid/",
                "{raw}"
            );
        }
        let url = url::Url::parse("file:///srv/m2/").unwrap();
        assert_eq!(redacted_url(&url).as_str(), "file:///srv/m2/");
        assert_eq!(super::redact_url("file:///srv/m2/"), "file:///srv/m2/");
        assert_eq!(super::redact_url("file:/srv/m2/"), "file:///srv/m2/");
    }
}
