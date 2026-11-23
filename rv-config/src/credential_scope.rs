//! Maven 3.10's binding of a settings.xml server's username and password to
//! origins: `maven.repository.credentialScope`, a server's
//! `<repositoryOrigins>`, and
//! `aether.remoteRepositoryManager.authToDescriptorRepositories`.

use std::collections::{HashMap, HashSet};

/// Where Maven 3.10 sends the username and password of a settings.xml
/// server. Its `OriginBoundAuthenticationSelector` binds a server's id to
/// the origins (scheme, host and port) of the mirrors and the request's
/// repositories with that id and of the server's `<repositoryOrigins>`.
/// An `Authorization` header from `<httpHeaders>` is not bound: Maven
/// sends it to every repository with the id.
#[derive(Debug, Clone, Default)]
pub struct CredentialScope {
    scope: Scope,
    declared: HashMap<String, HashSet<String>>,
    to_descriptors: bool,
}

/// `maven.repository.credentialScope`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Scope {
    #[default]
    Origin,
    Strict,
    Id,
}

impl CredentialScope {
    /// The binding for `scope`, the value of `maven.repository.credentialScope`,
    /// `None` when Maven fails on it.
    pub(crate) fn new(scope: Option<&str>) -> Option<Self> {
        let scope = match scope.unwrap_or("origin") {
            "origin" => Scope::Origin,
            "strict" => Scope::Strict,
            "id" => Scope::Id,
            _ => return None,
        };
        Some(Self {
            scope,
            declared: HashMap::new(),
            to_descriptors: false,
        })
    }

    /// `aether.remoteRepositoryManager.authToDescriptorRepositories`.
    pub(crate) fn with_descriptors(self, to_descriptors: bool) -> Self {
        Self {
            to_descriptors,
            ..self
        }
    }

    /// Whether Maven sends a username and password to a repository that a
    /// dependency's POM declares and no mirror replaces. It does not,
    /// unless `aether.remoteRepositoryManager.authToDescriptorRepositories`
    /// is true, when it collects dependencies, but it does when it builds
    /// such a POM's model, for its parent or an imported BOM.
    pub fn to_descriptors(&self) -> bool {
        self.to_descriptors
    }

    /// Bind `id` to the origin of `url`, a mirror, a repository of Maven's
    /// request or a `<repositoryOrigin>`. A URL without one binds nothing,
    /// as in Maven, and with the scope `id` none does; `Err` when raeva
    /// cannot tell what Maven reads in it.
    pub(crate) fn declare(&mut self, id: &str, url: &str) -> Result<(), ()> {
        if self.scope == Scope::Id {
            return Ok(());
        }
        match java_origin(url) {
            Origin::Exact(Some(origin)) => {
                self.declared
                    .entry(id.to_string())
                    .or_default()
                    .insert(origin);
                Ok(())
            }
            Origin::Exact(None) => Ok(()),
            Origin::Unknown => Err(()),
        }
    }

    /// Whether Maven sends the username and password of the server `id` to
    /// the repository or mirror with that id at `url`: by id alone with
    /// the scope `id`, else only to an origin bound to the id, or, when
    /// none is, to any unless the scope is `strict`.
    pub fn sends(&self, id: &str, url: &str) -> bool {
        match self.declared.get(id) {
            _ if self.scope == Scope::Id => true,
            Some(origins) => {
                matches!(java_origin(url), Origin::Exact(Some(origin)) if origins.contains(&origin))
            }
            None => self.scope == Scope::Origin,
        }
    }

    /// Whether `url` is a `<repositoryOrigin>` Maven 3.10 takes: one that
    /// `java.net.URI` reads with a scheme and a host and no user
    /// information, or one with `${` in it, which Maven leaves unchecked.
    /// `Err` when raeva cannot tell.
    pub(crate) fn valid_repository_origin(url: &str) -> Result<bool, ()> {
        if url.contains("${") {
            return Ok(true);
        }
        match java_origin(url) {
            Origin::Unknown => Err(()),
            Origin::Exact(None) => Ok(false),
            Origin::Exact(Some(_)) => Ok(!url.split_once("//").is_some_and(|(_, rest)| {
                rest.split(['/', '?', '#'])
                    .next()
                    .is_some_and(|a| a.contains('@'))
            })),
        }
    }
}

/// The origin Maven's `originOf` gives a URL, through `java.net.URI` with
/// its server authority parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Origin {
    /// `scheme://host[:port]`, lowercase, the port left out when it is
    /// the scheme's own, or `None` when the URL has no host.
    Exact(Option<String>),
    /// A URL raeva cannot be sure `java.net.URI` reads as it does.
    Unknown,
}

/// [`Origin`] of `url`, as `java.net.URI` reads an ASCII URL: any part it
/// refuses, such as a space, a bad escape or a host that is no host name,
/// IPv4 address or IPv6 literal, gives it no origin. A URL with an ASCII
/// character no part takes has none either. Another non-ASCII URL, and an
/// IPv6 literal with a zone or an IPv4 tail, are [`Origin::Unknown`].
fn java_origin(url: &str) -> Origin {
    let none = Origin::Exact(None);
    if !url.is_ascii() {
        let mut ascii = url.chars().filter(char::is_ascii);
        let refused = ascii.any(|c| !uric(c.encode_utf8(&mut [0; 4]), "", "#[]%"));
        return if refused { none } else { Origin::Unknown };
    }
    let (url, fragment) = url.split_once('#').unwrap_or((url, ""));
    let Some((scheme, rest)) = url.split_once(':') else {
        return none;
    };
    let scheme_ok = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
    let Some(rest) = rest.strip_prefix("//").filter(|_| scheme_ok) else {
        return none;
    };
    let (authority, tail) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    if !uric(path, "", "") || !uric(query, "", "[]") || !uric(fragment, "", "[]") {
        return none;
    }
    let host_port = match authority.split_once('@') {
        Some((user, host_port)) if uric(user, "@/?", "") => host_port,
        Some(_) => return none,
        None => authority,
    };
    let (host, port) = if host_port.starts_with('[') {
        let Some((literal, port)) = host_port.split_once(']') else {
            return none;
        };
        if literal.contains(['%', '.']) {
            return Origin::Unknown;
        }
        let Some(port) = port.strip_prefix(':').or(port.is_empty().then_some("")) else {
            return none;
        };
        if !is_ipv6(&literal[1..]) {
            return Origin::Unknown;
        }
        (&host_port[..literal.len() + 1], port)
    } else {
        let (host, port) = host_port.split_once(':').unwrap_or((host_port, ""));
        if !(is_ipv4(host) || is_hostname(host)) {
            return none;
        }
        (host, port)
    };
    // `java.net.URI` reads the port as an `int`.
    let port = match port {
        "" => None,
        port if port.bytes().all(|b| b.is_ascii_digit()) => match port.parse::<i32>() {
            Ok(port) => Some(port),
            Err(_) => return none,
        },
        _ => return none,
    };
    let (scheme, host) = (scheme.to_ascii_lowercase(), host.to_ascii_lowercase());
    let port =
        port.filter(|&port| !matches!((port, scheme.as_str()), (80, "http") | (443, "https")));
    Origin::Exact(Some(match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    }))
}

/// Whether `part` holds only what RFC 2396 allows in a URI outside its
/// host, less the characters of `except` and with those of `extra`, with
/// every `%` an escape unless `extra` takes a bare one. `java.net.URI`
/// also takes `[` and `]` in a query and a fragment.
fn uric(part: &str, except: &str, extra: &str) -> bool {
    let bytes = part.as_bytes();
    bytes.iter().enumerate().all(|(at, &byte)| {
        let c = char::from(byte);
        match c {
            '%' if !extra.contains('%') => {
                (bytes.get(at + 1..at + 3)).is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            }
            _ => {
                (c.is_ascii_alphanumeric()
                    || "-_.!~*'();/?:@&=+$,".contains(c)
                    || extra.contains(c))
                    && !except.contains(c)
            }
        }
    })
}

/// Four decimal octets of up to 255, with any number of leading zeros, as
/// `java.net.URI` takes an IPv4 address.
fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            let digits = part.trim_start_matches('0');
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && digits.len() <= 3
                && (digits.is_empty() || digits.parse::<u16>().is_ok_and(|octet| octet <= 255))
        })
}

/// An RFC 2396 host name: labels of letters, digits and inner hyphens, and
/// an optional trailing dot. The last of several labels starts with a
/// letter.
fn is_hostname(host: &str) -> bool {
    let labels: Vec<&str> = host.strip_suffix('.').unwrap_or(host).split('.').collect();
    labels.iter().all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    }) && (labels.len() == 1
        || labels
            .last()
            .is_some_and(|label| label.starts_with(|c: char| c.is_ascii_alphabetic())))
}

/// Eight groups of one to four hex digits, or fewer around one `::`.
fn is_ipv6(literal: &str) -> bool {
    let groups = |part: &str| -> Option<usize> {
        if part.is_empty() {
            return Some(0);
        }
        (part.split(':'))
            .all(|group| {
                (1..=4).contains(&group.len()) && group.bytes().all(|b| b.is_ascii_hexdigit())
            })
            .then(|| part.split(':').count())
    };
    match literal.split_once("::") {
        Some((head, tail)) => {
            !tail.contains("::")
                && matches!((groups(head), groups(tail)), (Some(head), Some(tail)) if head + tail <= 7)
        }
        None => groups(literal) == Some(8),
    }
}

#[cfg(test)]
mod tests {
    use super::{CredentialScope, Origin, java_origin};

    /// Each URL with what `java.net.URI` gives Maven's `originOf` for it,
    /// from a run of that code on JDK 27.
    #[test]
    fn origins_are_spelled_as_java_spells_them() {
        let exact = |origin: &str| Origin::Exact(Some(origin.to_string()));
        let none = Origin::Exact(None);
        for (url, origin) in [
            (
                "https://Repo.Example.COM/maven2/",
                exact("https://repo.example.com"),
            ),
            ("HTTP://repo.example:80/m2", exact("http://repo.example")),
            ("https://repo.example:443", exact("https://repo.example")),
            ("http://repo.example:443/", exact("http://repo.example:443")),
            (
                "https://repo.example:080/",
                exact("https://repo.example:80"),
            ),
            ("https://repo.example:00443/", exact("https://repo.example")),
            ("http://127.0.0.1:18202/m2", exact("http://127.0.0.1:18202")),
            ("https://01.2.3.4/", exact("https://01.2.3.4")),
            ("https://repo.example:/m2", exact("https://repo.example")),
            (
                "https://repo.example:99999/",
                exact("https://repo.example:99999"),
            ),
            (
                "https://repo.example:2147483647/",
                exact("https://repo.example:2147483647"),
            ),
            ("https://REPO.example:0/", exact("https://repo.example:0")),
            ("https://repo.example./", exact("https://repo.example.")),
            ("https://1repo.example/", exact("https://1repo.example")),
            ("https://x--y.example/", exact("https://x--y.example")),
            ("https://a/", exact("https://a")),
            ("h+t.p://repo.example/", exact("h+t.p://repo.example")),
            (
                "https://user:pw@repo.example:8443/x",
                exact("https://repo.example:8443"),
            ),
            ("https://u%41@repo.example/", exact("https://repo.example")),
            (
                "https://u;:&=+$,@repo.example/",
                exact("https://repo.example"),
            ),
            ("https://@repo.example/", exact("https://repo.example")),
            ("https://repo.example?a#b?c", exact("https://repo.example")),
            (
                "https://repo.example/!$&'()*+,;=:@~",
                exact("https://repo.example"),
            ),
            ("https://repo.example/%4a", exact("https://repo.example")),
            ("https://[FE80::1]/", exact("https://[fe80::1]")),
            ("https://[0:0::1]:8443/", exact("https://[0:0::1]:8443")),
            (
                "https://[1:2:3:4:5:6:7:8]/",
                exact("https://[1:2:3:4:5:6:7:8]"),
            ),
            ("https://[::]/", exact("https://[::]")),
            (
                "https://[1:2:3:4:5:6:7::]/",
                exact("https://[1:2:3:4:5:6:7::]"),
            ),
            ("https://1repo/", exact("https://1repo")),
            ("https://123/", exact("https://123")),
            ("https://12./", exact("https://12.")),
            ("https://0001.2.3.4/", exact("https://0001.2.3.4")),
            (
                "https://0000000000000000000255.2.3.4/",
                exact("https://0000000000000000000255.2.3.4"),
            ),
            ("https://h/?a[b]", exact("https://h")),
            ("https://h/#[x]", exact("https://h")),
            ("https://h/?a#[b]", exact("https://h")),
            ("file:///srv/m2", none.clone()),
            ("file:/srv/m2", none.clone()),
            ("repo.example", none.clone()),
            ("https:repo.example", none.clone()),
            ("mailto:a@b", none.clone()),
            ("a/b:c", none.clone()),
            ("1http://repo.example/", none.clone()),
            ("https://", none.clone()),
            ("https:///path", none.clone()),
            ("https://:8080/", none.clone()),
            ("https://repo_1.example/", none.clone()),
            ("https://127.1/", none.clone()),
            ("https://256.1.1.1/", none.clone()),
            ("https://1.2.3.4.5/", none.clone()),
            ("https://1.2.3.4./", none.clone()),
            ("https://repo.123/", none.clone()),
            ("https://repo.1example/", none.clone()),
            ("https://repo..example/", none.clone()),
            ("https://-repo.example/", none.clone()),
            ("https://x.y-/", none.clone()),
            ("https://re%41po.example/", none.clone()),
            ("https://u@@repo.example/", none.clone()),
            ("https://u%zz@repo.example/", none.clone()),
            ("https://u@/", none.clone()),
            ("https://repo.example:2147483648/", none.clone()),
            ("https://repo.example:-1/", none.clone()),
            ("https://repo.example:8x/", none.clone()),
            ("https://repo.example:443:1/", none.clone()),
            ("https://repo.example/a b", none.clone()),
            ("https://repo.example/%zz", none.clone()),
            ("https://repo.example/%4", none.clone()),
            ("https://repo.example/[x]", none.clone()),
            ("https://repo.example/\\x", none.clone()),
            ("https://repo.example#a#b", none.clone()),
            ("https://[::1", none.clone()),
            ("https://[::1]x/", none.clone()),
            ("https://12.34/", none.clone()),
            ("https://1repo.2b/", none.clone()),
            ("https://1-/", none.clone()),
            ("https://1.2.3.0000256/", none.clone()),
            ("https://99999.1.1.1/", none.clone()),
            ("https://h/p[x]", none.clone()),
            ("https://h/?{x}", none.clone()),
            ("https://h/#a^b", none.clone()),
            ("https://h\u{e9}.example/${x}", none.clone()),
            ("https://h/?\u{e9}", Origin::Unknown),
            ("https://rép.example/", Origin::Unknown),
            ("https://repo.example/é", Origin::Unknown),
            ("https://[fe80::1%25eth0]/", Origin::Unknown),
            ("https://[::ffff:1.2.3.4]/", Origin::Unknown),
            ("https://[1::2::3]/", Origin::Unknown),
        ] {
            assert_eq!(java_origin(url), origin, "{url}");
        }
    }

    #[test]
    fn a_credential_goes_where_the_scope_and_the_declared_origins_send_it() {
        let mut origin = CredentialScope::new(None).unwrap();
        origin.declare("corp", "https://nexus.corp/maven/").unwrap();
        origin.declare("files", "file:///srv/m2").unwrap();
        assert!(origin.declare("odd", "https://rép.example/").is_err());
        let mut strict = CredentialScope::new(Some("strict")).unwrap();
        strict.declare("corp", "https://nexus.corp/maven/").unwrap();
        let mut id = CredentialScope::new(Some("id")).unwrap();
        id.declare("odd", "https://r\u{e9}p.example/").unwrap();
        assert!(CredentialScope::new(Some("ID")).is_none());
        for (scope, id, url, sends) in [
            (&origin, "corp", "https://NEXUS.corp:443/other/", true),
            (&origin, "corp", "https://evil.example/", false),
            (&origin, "corp", "https://user@nexus.corp/", true),
            (&origin, "corp", "file:///srv/m2", false),
            (&origin, "files", "https://evil.example/", true),
            (&origin, "other", "https://evil.example/", true),
            (&strict, "corp", "https://nexus.corp/", true),
            (&strict, "other", "https://nexus.corp/", false),
            (&id, "corp", "https://evil.example/", true),
        ] {
            assert_eq!(scope.sends(id, url), sends, "{id} {url}");
        }
    }

    #[test]
    fn repository_origins_are_checked_as_maven_checks_them() {
        for (url, valid) in [
            ("https://nexus.corp", Ok(true)),
            ("https://nexus.corp/path", Ok(true)),
            ("${env.NEXUS}", Ok(true)),
            ("nexus.corp", Ok(false)),
            ("https://user@nexus.corp", Ok(false)),
            ("http://127.0.0.1:18202:1/", Ok(false)),
            ("https://nexus_1.corp", Ok(false)),
            ("https://nëxus.corp", Err(())),
        ] {
            assert_eq!(
                CredentialScope::valid_repository_origin(url),
                valid,
                "{url}"
            );
        }
    }
}
