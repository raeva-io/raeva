use serde::Serialize;

/// An SPDX identifier or the license name supplied by a POM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum License {
    /// An unambiguous SPDX license identifier.
    Id(String),
    /// An unrecognized or ambiguous license name, as given.
    Name(String),
}

impl License {
    /// Map an exact SPDX name, identifier, or known license URL to its identifier.
    /// Conflicting name and URL mappings preserve the name. A URL without a
    /// name is retained as a name when its license is unknown.
    pub fn from_maven(name: Option<&str>, url: Option<&str>) -> Option<Self> {
        let name = name.filter(|value| !value.trim().is_empty());
        let url = url.filter(|value| !value.trim().is_empty());
        let by_name = name.and_then(name_id);
        let by_url = url.and_then(url_id);
        let id = match (by_name, by_url) {
            (Some(a), Some(b)) if a != b => None,
            (Some(id), _) | (_, Some(id)) => Some(id),
            _ => None,
        };
        // CycloneDX 1.5 fixes its SPDX vocabulary at license-list 3.21.
        id.filter(|id| {
            include_str!("spdx-1.5.txt")
                .lines()
                .any(|known| known == *id)
        })
        .map(|id| Self::Id(id.to_string()))
        .or_else(|| name.or(url).map(|name| Self::Name(name.to_string())))
    }
}

fn name_id(name: &str) -> Option<&'static str> {
    let name = name.trim();
    let mut matches = spdx::identifiers::LICENSES
        .iter()
        .filter(|license| {
            license.name.eq_ignore_ascii_case(name) || license.full_name.eq_ignore_ascii_case(name)
        })
        .map(|license| {
            spdx::gnu_license_id(
                license.name.trim_end_matches('+'),
                license.name.ends_with('+'),
            )
            .map_or(license.name, |id| id.name)
        });
    if let Some(first) = matches.next() {
        return matches.all(|id| id == first).then_some(first);
    }
    match name.to_ascii_lowercase().as_str() {
        "apache license, version 2.0"
        | "the apache license, version 2.0"
        | "the apache software license, version 2.0"
        | "apache license version 2.0"
        | "apache 2.0" => Some("Apache-2.0"),
        "the mit license" => Some("MIT"),
        _ => None,
    }
}

fn url_id(url: &str) -> Option<&'static str> {
    let url = url::Url::parse(url.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url
        .host_str()?
        .strip_prefix("www.")
        .unwrap_or(url.host_str()?);
    let path = url.path().trim_end_matches('/');
    match (host, path) {
        ("spdx.org", path) => name_id(
            path.strip_prefix("/licenses/")?
                .strip_suffix(".html")
                .unwrap_or(path.strip_prefix("/licenses/")?),
        ),
        (
            "apache.org",
            "/licenses/LICENSE-2.0" | "/licenses/LICENSE-2.0.txt" | "/licenses/LICENSE-2.0.html",
        ) => Some("Apache-2.0"),
        ("opensource.org", "/licenses/MIT" | "/licenses/mit" | "/license/mit") => Some("MIT"),
        ("opensource.org", "/licenses/BSD-2-Clause" | "/license/bsd-2-clause") => {
            Some("BSD-2-Clause")
        }
        ("opensource.org", "/licenses/BSD-3-Clause" | "/license/bsd-3-clause") => {
            Some("BSD-3-Clause")
        }
        ("mozilla.org", "/MPL/2.0" | "/MPL/2.0/index.txt") => Some("MPL-2.0"),
        ("eclipse.org", "/legal/epl-2.0" | "/legal/epl-2.0.html") => Some("EPL-2.0"),
        ("eclipse.org", "/legal/epl-v10.html") => Some("EPL-1.0"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::License;

    #[test]
    fn maps_only_unambiguous_names_and_urls() {
        for (name, url, id) in [
            (Some("GPL-2.0"), None, "GPL-2.0-only"),
            (Some("GPL-2.0+"), None, "GPL-2.0-or-later"),
            (
                Some("GNU General Public License v2.0 only"),
                None,
                "GPL-2.0-only",
            ),
            (Some("apache-2.0"), None, "Apache-2.0"),
            (Some("Apache License 2.0"), None, "Apache-2.0"),
            (
                Some("The Apache Software License, Version 2.0"),
                None,
                "Apache-2.0",
            ),
            (
                Some("BSD"),
                Some("https://opensource.org/licenses/BSD-3-Clause"),
                "BSD-3-Clause",
            ),
            (
                None,
                Some("http://www.apache.org/licenses/LICENSE-2.0.txt"),
                "Apache-2.0",
            ),
        ] {
            assert_eq!(License::from_maven(name, url), Some(License::Id(id.into())));
        }
        for name in [
            "BSD",
            "GPL",
            "A private license",
            "MIT OR Apache-2.0",
            "Unicode-3.0",
        ] {
            assert_eq!(
                License::from_maven(Some(name), None),
                Some(License::Name(name.into()))
            );
        }
        assert_eq!(License::from_maven(None, None), None);
        assert_eq!(
            License::from_maven(Some("MIT"), Some("https://apache.org/licenses/LICENSE-2.0")),
            Some(License::Name("MIT".into()))
        );
        assert_eq!(
            License::from_maven(Some("Custom"), Some("https://example.org/licenses/MIT")),
            Some(License::Name("Custom".into()))
        );
    }
}
