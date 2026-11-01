//! Proxies from `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, read as curl
//! reads them, for a user whose `config.toml` and `settings.xml` name none.
//!
//! Each variable is read in lower case first, then in upper case. A value is
//! `[http://][user[:password]@]host[:port][/]`, the port 80 when left out.
//! `HTTPS_PROXY` carries `https:` URLs and `HTTP_PROXY` `http:` ones; unlike
//! a Maven `http` proxy, `HTTP_PROXY` does not also carry `https:` URLs.
//! `ALL_PROXY` and other schemes are not read.

use std::net::IpAddr;

use rv_maven_types::quoted;
use secrecy::SecretString;
use url::{Host, Url};

use crate::settings::ProxyConfig;

/// The variables in the order raeva reads them, each with the scheme its
/// proxy carries.
const PROXY_VARIABLES: [(&str, [&str; 2]); 2] = [
    ("https", ["https_proxy", "HTTPS_PROXY"]),
    ("http", ["http_proxy", "HTTP_PROXY"]),
];
const NO_PROXY_VARIABLES: [&str; 2] = ["no_proxy", "NO_PROXY"];

/// A proxy from the environment: the variable that named it and the hosts
/// `NO_PROXY` sends direct.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvironmentProxy {
    /// The variable as it was set, such as `https_proxy`.
    pub variable: &'static str,
    /// The `NO_PROXY` entries.
    pub no_proxy: Vec<NoProxy>,
}

impl EnvironmentProxy {
    /// Whether `url` goes direct: `NO_PROXY` names it, or it is a loopback
    /// host, which a proxy cannot reach on this machine's behalf.
    pub fn bypasses(&self, url: &Url) -> bool {
        let loopback = match url.host() {
            Some(Host::Domain(name)) => {
                let name = name.trim_end_matches('.').to_ascii_lowercase();
                name == "localhost" || name.ends_with(".localhost")
            }
            Some(Host::Ipv4(addr)) => addr.is_loopback(),
            Some(Host::Ipv6(addr)) => addr.is_loopback(),
            None => false,
        };
        loopback || self.no_proxy.iter().any(|entry| entry.matches(url))
    }
}

/// One `NO_PROXY` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoProxy {
    /// `*`: every host.
    All,
    /// A host name and every host under it, written `example.com`,
    /// `.example.com` or `*.example.com`, on any port or on `port`.
    Domain {
        /// The name, lower case, without the leading `.` or `*.`.
        name: String,
        /// The one port the entry covers, when it names one.
        port: Option<u16>,
    },
    /// An IP address, on any port or on `port`.
    Address {
        /// The address.
        addr: IpAddr,
        /// The one port the entry covers, when it names one.
        port: Option<u16>,
    },
    /// A CIDR range such as `10.0.0.0/8`, on any port.
    Network {
        /// The first address of the range.
        addr: IpAddr,
        /// The prefix length.
        prefix: u8,
    },
}

impl NoProxy {
    /// Whether the entry covers `url`'s host and port.
    pub fn matches(&self, url: &Url) -> bool {
        let port_matches =
            |port: &Option<u16>| port.is_none() || *port == url.port_or_known_default();
        let ip = match url.host() {
            Some(Host::Ipv4(addr)) => Some(IpAddr::V4(addr)),
            Some(Host::Ipv6(addr)) => Some(IpAddr::V6(addr)),
            _ => None,
        };
        match self {
            Self::All => true,
            Self::Domain { name, port } => {
                let Some(Host::Domain(host)) = url.host() else {
                    return false;
                };
                let host = host.trim_end_matches('.').to_ascii_lowercase();
                let under = host
                    .strip_suffix(name.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'));
                under && port_matches(port)
            }
            Self::Address { addr, port } => ip == Some(*addr) && port_matches(port),
            Self::Network { addr, prefix } => {
                ip.is_some_and(|ip| network_start(ip, *prefix) == Some(*addr))
            }
        }
    }
}

/// The first address of the `/prefix` range `addr` is in, `None` when the
/// families differ from the prefix's bounds.
fn network_start(addr: IpAddr, prefix: u8) -> Option<IpAddr> {
    match addr {
        IpAddr::V4(addr) if prefix <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            Some(IpAddr::V4((u32::from(addr) & mask).into()))
        }
        IpAddr::V6(addr) if prefix <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            Some(IpAddr::V6((u128::from(addr) & mask).into()))
        }
        _ => None,
    }
}

/// The proxies `read` gives, `HTTPS_PROXY`'s first. `read` returns a
/// variable's value; an empty one counts as unset.
/// [`Config::proxies`](crate::Config::proxies) holds them when no file names
/// a proxy.
///
/// # Errors
///
/// The variable and what is wrong with it. A proxy value is never echoed,
/// since it may hold a password.
pub fn environment_proxies(
    read: impl Fn(&str) -> Option<String>,
) -> Result<Vec<ProxyConfig>, (&'static str, String)> {
    let first = |names: [&'static str; 2]| {
        names.into_iter().find_map(|name| {
            read(name)
                .filter(|value| !value.trim().is_empty())
                .map(|value| (name, value))
        })
    };
    let mut proxies = Vec::new();
    for (scheme, names) in PROXY_VARIABLES {
        if let Some((variable, value)) = first(names) {
            let mut proxy = parse_proxy(&value).map_err(|message| (variable, message))?;
            proxy.id = Some(variable.to_string());
            proxy.protocol = Some(scheme.to_string());
            proxy.environment = Some(EnvironmentProxy {
                variable,
                no_proxy: Vec::new(),
            });
            proxies.push(proxy);
        }
    }
    if proxies.is_empty() {
        return Ok(proxies);
    }
    if let Some((variable, value)) = first(NO_PROXY_VARIABLES) {
        let no_proxy = (value.split(','))
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .enumerate()
            .map(|(index, entry)| parse_no_proxy(index + 1, entry))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|message| (variable, message))?;
        for proxy in &mut proxies {
            if let Some(environment) = proxy.environment.as_mut() {
                environment.no_proxy.clone_from(&no_proxy);
            }
        }
    }
    Ok(proxies)
}

fn parse_proxy(value: &str) -> Result<ProxyConfig, String> {
    const FORM: &str = "use http://[user:password@]host:port";
    let value = value.trim();
    let url = if value.contains("://") {
        Url::parse(value)
    } else {
        Url::parse(&format!("http://{value}"))
    }
    .map_err(|_| format!("it is not a proxy URL; {FORM}"))?;
    if url.scheme() != "http" {
        return Err(format!(
            "raeva reaches a proxy over plain HTTP only, not {}; {FORM}",
            quoted(url.scheme())
        ));
    }
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Err(format!(
            "a proxy URL has no path, query or fragment; {FORM}"
        ));
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| format!("it names no host; {FORM}"))?;
    let mut proxy = ProxyConfig::new(host, url.port_or_known_default().unwrap_or(80));
    let username = percent_decode(url.username())
        .ok_or_else(|| "its user name is not valid percent-encoded UTF-8".to_string())?;
    let password = (url.password())
        .map(|password| {
            percent_decode(password)
                .ok_or_else(|| "its password is not valid percent-encoded UTF-8".to_string())
        })
        .transpose()?;
    match (username.is_empty(), password) {
        (true, Some(_)) => return Err(format!("it has a password but no user name; {FORM}")),
        (true, None) => {}
        (false, password) => {
            proxy.username = Some(username);
            proxy.password = password.map(SecretString::from);
        }
    }
    Ok(proxy)
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = text.get(index + 1..index + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `position` names the entry in an error, which does not show the entry:
/// it may be a proxy URL with credentials set in the wrong variable.
fn parse_no_proxy(position: usize, entry: &str) -> Result<NoProxy, String> {
    let unsupported = || {
        format!(
            "entry {position} is not supported; use *, a host name (which covers the hosts \
             under it), .domain, an IP address or a CIDR range such as 10.0.0.0/8, the names \
             and addresses optionally with :port"
        )
    };
    if entry == "*" {
        return Ok(NoProxy::All);
    }
    let address = |text: &str| {
        let text = text
            .strip_prefix('[')
            .and_then(|t| t.strip_suffix(']'))
            .unwrap_or(text);
        text.parse::<IpAddr>().ok()
    };
    if let Some((addr, prefix)) = entry.split_once('/') {
        let addr = address(addr).ok_or_else(unsupported)?;
        let prefix: u8 = prefix.parse().map_err(|_| unsupported())?;
        let start = network_start(addr, prefix).ok_or_else(unsupported)?;
        return Ok(NoProxy::Network {
            addr: start,
            prefix,
        });
    }
    if let Some(addr) = address(entry) {
        return Ok(NoProxy::Address { addr, port: None });
    }
    let (host, port) = match entry.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse::<u16>().map_err(|_| unsupported())?)),
        None => (entry, None),
    };
    if let Some(addr) = address(host) {
        return Ok(NoProxy::Address { addr, port });
    }
    let name = host
        .strip_prefix("*.")
        .or_else(|| host.strip_prefix('.'))
        .unwrap_or(host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let valid = !name.is_empty()
        && !name.starts_with('.')
        && (name.bytes()).all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if !valid {
        return Err(unsupported());
    }
    Ok(NoProxy::Domain { name, port })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::collections::HashMap;

    fn proxies(vars: &[(&str, &str)]) -> Result<Vec<ProxyConfig>, (&'static str, String)> {
        let vars: HashMap<String, String> = (vars.iter())
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        environment_proxies(|name| vars.get(name).cloned())
    }

    #[test]
    fn variables_map_to_one_proxy_per_scheme() {
        let found = proxies(&[
            ("HTTPS_PROXY", "http://upper.example:1"),
            ("https_proxy", "lower.example:3128"),
            ("HTTP_PROXY", "http://al%40ice:p%3Ass@[::1]:8080/"),
            ("http_proxy", " "),
        ])
        .unwrap();
        let summary: Vec<_> = (found.iter())
            .map(|proxy| {
                (
                    proxy.environment.as_ref().unwrap().variable,
                    proxy.protocol.as_deref().unwrap(),
                    proxy.host.as_str(),
                    proxy.port,
                    proxy.username.as_deref(),
                    proxy
                        .password
                        .as_ref()
                        .map(|p| p.expose_secret().to_string()),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("https_proxy", "https", "lower.example", 3128, None, None),
                (
                    "HTTP_PROXY",
                    "http",
                    "[::1]",
                    8080,
                    Some("al@ice"),
                    Some("p:ss".to_string())
                ),
            ]
        );
        assert!(proxies(&[("NO_PROXY", "*")]).unwrap().is_empty());
        let default_port = proxies(&[("HTTP_PROXY", "proxy.example")]).unwrap();
        assert_eq!(default_port[0].port, 80);
    }

    #[test]
    fn unsupported_values_name_the_variable_and_hide_the_value() {
        for value in [
            "https://alice:s3cret@proxy.example:3128",
            "socks5://alice:s3cret@proxy.example:1080",
            "http://alice:s3cret@proxy.example:3128/path",
            "http://alice:s3cret@proxy.example:3128/?q",
            "http://:s3cret@proxy.example:3128",
            "http://alice:s3cret@:3128",
            "http://alice:s3cret@proxy.example:99999",
        ] {
            let (variable, message) = proxies(&[("HTTPS_PROXY", value)]).unwrap_err();
            assert_eq!(variable, "HTTPS_PROXY");
            assert!(!message.contains("s3cret"), "{value}: {message}");
            assert!(message.contains("http://"), "{value}: {message}");
        }
    }

    #[test]
    fn no_proxy_entries_match_as_curl_matches_them() {
        let found = proxies(&[
            ("HTTPS_PROXY", "proxy.example:3128"),
            (
                "no_proxy",
                "corp.example, .internal.example,*.lan,10.0.0.0/8,192.168.1.7,[fd00::1]:8443,\
                 nexus.example:8081",
            ),
            ("NO_PROXY", "ignored.example"),
        ])
        .unwrap();
        let environment = found[0].environment.as_ref().unwrap();
        let direct = |url: &str| environment.bypasses(&Url::parse(url).unwrap());
        for url in [
            "https://corp.example/",
            "https://repo.corp.example/",
            "https://internal.example/",
            "https://a.b.internal.example/",
            "https://x.lan/",
            "https://10.20.30.40/",
            "https://192.168.1.7:9999/",
            "https://[fd00::1]:8443/",
            "http://nexus.example:8081/",
            "https://localhost:8443/",
            "https://127.0.0.2/",
            "https://[::1]/",
        ] {
            assert!(direct(url), "{url}");
        }
        for url in [
            "https://notcorp.example/",
            "https://ignored.example/",
            "https://11.0.0.1/",
            "https://[fd00::1]/",
            "https://nexus.example/",
        ] {
            assert!(!direct(url), "{url}");
        }
        let all = proxies(&[("HTTP_PROXY", "p:1"), ("NO_PROXY", "a.example, *")]).unwrap();
        assert!(
            all[0]
                .environment
                .as_ref()
                .unwrap()
                .bypasses(&Url::parse("http://x/").unwrap())
        );
    }

    #[test]
    fn unsupported_no_proxy_entries_are_refused() {
        for entry in [
            "*.corp.*",
            "10.*",
            "10.0.0.0/33",
            "host:port",
            "a b",
            "[::1",
        ] {
            let (variable, message) =
                proxies(&[("HTTP_PROXY", "p:1"), ("NO_PROXY", entry)]).unwrap_err();
            assert_eq!(variable, "NO_PROXY");
            assert!(
                message.contains("entry 1 ") && message.contains("CIDR"),
                "{entry}: {message}"
            );
        }
    }
}
