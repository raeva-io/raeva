use url::Url;

const REDACTED: &str = "***";

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
            redact_parsed(&parsed, raw_authority_has_port(raw)).to_string()
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
    redact_parsed(url, false)
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
    (redact_url(url) != parsed.as_str()).then_some("userinfo")
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
