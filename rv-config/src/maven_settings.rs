use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use rv_maven_model::Activation;
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;

use crate::encryption::{SecuritySettings, is_encrypted, sanitize_password};
use crate::error::{ConfigError, io_error_with_context};
use crate::settings::{
    AuthConfig, MirrorConfig, ProxyConfig, RepoConfig, SettingsProfile, UpdatePolicy,
};

/// Upper bound on parseable settings.xml size. Real settings.xml files are far
/// smaller; 5 MiB matches `Pom::MAX_SIZE` and stops a hostile or malformed
/// input from exhausting memory. Also reused by `SecuritySettings` for
/// settings-security.xml, which is even smaller in practice.
pub(crate) const MAX_SETTINGS_SIZE: usize = 5 * 1024 * 1024;

/// Shared XML hardening for `settings.xml` and `settings-security.xml`:
/// size cap, BOM strip, DOCTYPE rejection. Fails closed.
pub(crate) fn harden_xml(xml: &str) -> Result<&str, ConfigError> {
    if xml.len() > MAX_SETTINGS_SIZE {
        return Err(ConfigError::InvalidSettings(format!(
            "XML input exceeds {}-byte limit",
            MAX_SETTINGS_SIZE
        )));
    }
    let xml = strip_utf8_bom(xml);
    reject_doctype(xml)?;
    Ok(xml)
}

/// A `<profile>` block from `settings.xml` bundled with its parsed
/// `<activation>` rule. The activation cannot live on `SettingsProfile`
/// because that type doubles as a TOML-serialisable user-config struct;
/// keeping the `<activation>` data here also lets `MavenSettings` consumers
/// evaluate it without pulling rv-maven-model into the TOML serde graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MavenProfile {
    pub profile: SettingsProfile,
    pub activation: Option<Activation>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MavenSettings {
    pub local_repository: Option<PathBuf>,
    pub mirrors: Option<Vec<MirrorConfig>>,
    pub servers: Option<Vec<AuthConfig>>,
    pub proxies: Option<Vec<ProxyConfig>>,
    pub profiles: Option<Vec<MavenProfile>>,
    pub active_profiles: Option<Vec<String>>,
}

impl MavenSettings {
    pub fn load_optional(path: &Path) -> Result<Self, ConfigError> {
        // `Read::take` enforces the cap at the read site so a file that grows
        // (or is symlink-swapped) after open still fails closed; `metadata`
        // + `read_to_string` would leak a TOCTOU bypass.
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(err) => {
                return Err(Err(err)
                    .with_context(|| format!("failed to open settings.xml {}", path.display()))
                    .map_err(|err| ConfigError::Io(io_error_with_context(err)))?);
            }
        };

        // Read up to MAX_SETTINGS_SIZE + 1 so we can distinguish "exactly at
        // the limit" (which is allowed) from "over the limit" (rejected).
        let mut bytes = Vec::with_capacity(MAX_SETTINGS_SIZE.min(64 * 1024));
        let limit = MAX_SETTINGS_SIZE as u64 + 1;
        if let Err(err) = file.take(limit).read_to_end(&mut bytes) {
            return Err(Err(err)
                .with_context(|| format!("failed to read settings.xml {}", path.display()))
                .map_err(|err| ConfigError::Io(io_error_with_context(err)))?);
        }
        if bytes.len() > MAX_SETTINGS_SIZE {
            return Err(ConfigError::InvalidSettings(format!(
                "settings.xml at {} exceeds {}-byte limit",
                path.display(),
                MAX_SETTINGS_SIZE
            )));
        }

        let contents = String::from_utf8(bytes).map_err(|err| {
            ConfigError::InvalidSettings(format!(
                "settings.xml at {} is not valid UTF-8: {err}",
                path.display()
            ))
        })?;

        Self::parse(&contents)
    }

    pub fn load_default() -> Result<Self, ConfigError> {
        match default_settings_path() {
            Some(path) => Self::load_optional(&path),
            None => Ok(Self::default()),
        }
    }

    pub fn parse(xml: &str) -> Result<Self, ConfigError> {
        Self::parse_with_security(xml, SecuritySettings::load_default()?.as_ref())
    }

    pub fn parse_with_security(
        xml: &str,
        security: Option<&SecuritySettings>,
    ) -> Result<Self, ConfigError> {
        let xml = harden_xml(xml)?;
        let xml_struct: SettingsXml = quick_xml::de::from_str(xml)
            .map_err(|e| ConfigError::InvalidSettings(e.to_string()))?;
        let mut settings = xml_struct.into_settings(security);
        interpolate_env(&mut settings);
        Ok(settings)
    }
}

// Closed-by-default prologue scanner: rejects DOCTYPE outright and any
// non-prologue byte before the root element so a hostile prefix can't shunt
// `<!DOCTYPE` past the check.
fn reject_doctype(xml: &str) -> Result<(), ConfigError> {
    let bytes = xml.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i] != b'<' {
            return Err(ConfigError::InvalidSettings(
                "settings.xml prologue contains non-whitespace bytes before the root element"
                    .to_string(),
            ));
        }
        let Some(&next) = bytes.get(i + 1) else {
            return Err(ConfigError::InvalidSettings(
                "settings.xml ends unexpectedly inside the prologue".to_string(),
            ));
        };
        match next {
            b'?' => {
                // Processing instruction (e.g., the XML declaration). Skip
                // until the matching `?>`.
                if let Some(end) = find_subsequence(&bytes[i + 2..], b"?>") {
                    i += 2 + end + 2;
                    continue;
                }
                return Err(ConfigError::InvalidSettings(
                    "settings.xml has an unterminated processing instruction".to_string(),
                ));
            }
            b'!' => {
                if bytes[i + 2..].starts_with(b"--") {
                    if let Some(end) = find_subsequence(&bytes[i + 4..], b"-->") {
                        i += 4 + end + 3;
                        continue;
                    }
                    return Err(ConfigError::InvalidSettings(
                        "settings.xml has an unterminated comment".to_string(),
                    ));
                }
                if bytes
                    .get(i + 2..i + 9)
                    .is_some_and(|s| s.eq_ignore_ascii_case(b"DOCTYPE"))
                {
                    return Err(ConfigError::InvalidSettings(
                        "settings.xml contains a DTD, which is not allowed for security reasons"
                            .to_string(),
                    ));
                }
                // Any other `<!...>` markup in the prologue (e.g. CDATA at
                // top level, which is illegal anyway) is rejected.
                return Err(ConfigError::InvalidSettings(
                    "settings.xml contains an unexpected `<!` markup block in the prologue"
                        .to_string(),
                ));
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                // Start of the root element. We've reached the document body
                // without encountering DOCTYPE; the rest of the parse is
                // quick-xml's responsibility.
                return Ok(());
            }
            _ => {
                return Err(ConfigError::InvalidSettings(
                    "settings.xml prologue contains an unexpected token after `<`".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// Maven's settings.xml interpolation: `${env.X}` expands to the host env
// across the file, not just in server/proxy auth fields. Mirror URLs and
// patterns, settings-profile repository ids/urls, and `<localRepository>`
// go through the same `expand_env` pass as credentials: settings.xml is
// user-owned config, so expansion is unconditional, and unknown vars
// survive verbatim for a recognisable diagnostic.
fn interpolate_env(settings: &mut MavenSettings) {
    if let Some(local_repository) = settings.local_repository.take() {
        // Round-trip through a string only when the path is valid UTF-8;
        // a non-UTF-8 path cannot contain `${env.X}` text anyway.
        settings.local_repository = Some(match local_repository.to_str() {
            Some(s) => PathBuf::from(expand_env(s)),
            None => local_repository,
        });
    }
    if let Some(mirrors) = settings.mirrors.as_mut() {
        for mirror in mirrors {
            if let Some(id) = mirror.id.as_mut() {
                *id = expand_env(id);
            }
            mirror.url = expand_env(&mirror.url);
            for pattern in &mut mirror.mirror_of {
                *pattern = expand_env(pattern);
            }
        }
    }
    if let Some(profiles) = settings.profiles.as_mut() {
        for profile in profiles {
            for repo in &mut profile.profile.repositories {
                if let Some(id) = repo.id.as_mut() {
                    *id = expand_env(id);
                }
                repo.url = expand_env(&repo.url);
            }
        }
    }
    if let Some(servers) = settings.servers.as_mut() {
        for server in servers {
            if let Some(username) = server.username.as_mut() {
                *username = expand_env(username);
            }
            if let Some(password) = server.password.take() {
                let expanded = expand_env(password.expose_secret());
                server.password = Some(Secret::new(expanded));
            }
            if let Some(token) = server.token.take() {
                let expanded = expand_env(token.expose_secret());
                server.token = Some(Secret::new(expanded));
            }
        }
    }
    if let Some(proxies) = settings.proxies.as_mut() {
        for proxy in proxies {
            if let Some(username) = proxy.username.as_mut() {
                *username = expand_env(username);
            }
            if let Some(password) = proxy.password.take() {
                let expanded = expand_env(password.expose_secret());
                proxy.password = Some(Secret::new(expanded));
            }
        }
    }
}

/// Remove every `${env.NAME}` occurrence from `input` verbatim, leaving the
/// surrounding text intact. Applied to *decrypted* secret values so a stored
/// credential whose plaintext contains `${env.HOME}` cannot exfiltrate env
/// vars through the subsequent `expand_env` pass. Decrypted secrets are
/// trusted as literal payloads only; if a user really wants env expansion
/// they should write `${env.NAME}` in plaintext, not hide it inside
/// `{base64}`.
fn strip_env_refs(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${env.") {
        output.push_str(&rest[..start]);
        let after = &rest[start + "${env.".len()..];
        if let Some(end) = after.find('}') {
            rest = &after[end + 1..];
        } else {
            return output;
        }
    }
    output.push_str(rest);
    output
}

/// Expand every `${env.NAME}` occurrence in `input` using the process
/// environment. Unknown variables are left intact.
fn expand_env(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${env.") {
        output.push_str(&rest[..start]);
        let after = &rest[start + "${env.".len()..];
        if let Some(end) = after.find('}') {
            let name = &after[..end];
            match std::env::var(name) {
                Ok(value) => output.push_str(&value),
                Err(_) => {
                    output.push_str("${env.");
                    output.push_str(name);
                    output.push('}');
                }
            }
            rest = &after[end + 1..];
        } else {
            output.push_str(rest);
            return output;
        }
    }
    output.push_str(rest);
    output
}

/// Returns `s` with a leading UTF-8 BOM (`\u{FEFF}`) removed, if present.
fn strip_utf8_bom(s: &str) -> &str {
    s.strip_prefix('\u{FEFF}').unwrap_or(s)
}

fn default_settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".m2").join("settings.xml"))
}

fn warn_failed_password_decryption(entry_kind: &str, entry_id: Option<&str>) {
    // `sec_code` is the JSON-envelope contract field that the CLI's
    // `WarningCollectorLayer` picks up so the dropped credential survives
    // `--json` mode instead of surfacing only as a bare 401 later.
    tracing::warn!(
        sec_code = "CREDENTIAL_DROPPED",
        entry_kind = %entry_kind,
        entry_id = entry_id.unwrap_or("<unnamed>"),
        "Maven-encrypted password in settings.xml could not be decrypted; this version uses a custom key derivation that may not be compatible with all Maven installations. Use plaintext passwords or token-based auth if authentication fails."
    );
}

// Shadow structs for XML parsing
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsXml {
    local_repository: Option<String>,
    mirrors: Option<MirrorsXml>,
    servers: Option<ServersXml>,
    proxies: Option<ProxiesXml>,
    profiles: Option<ProfilesXml>,
    active_profiles: Option<ActiveProfilesXml>,
}

// Container elements default to an empty list: Maven accepts `<mirrors/>` or
// `<mirrors></mirrors>` (the routine leftover after commenting out an entry),
// so a missing inner element must not fail the whole parse. The same applies
// to every container struct below.
#[derive(Deserialize)]
struct MirrorsXml {
    #[serde(default)]
    mirror: Vec<MirrorXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MirrorXml {
    id: Option<String>,
    url: String,
    mirror_of: String,
}

#[derive(Deserialize)]
struct ServersXml {
    #[serde(default)]
    server: Vec<ServerXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerXml {
    id: String,
    username: Option<String>,
    password: Option<String>,
    configuration: Option<ServerConfigXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerConfigXml {
    http_headers: Option<HttpHeadersXml>,
}

#[derive(Deserialize)]
struct HttpHeadersXml {
    #[serde(default)]
    property: Vec<PropertyXml>,
}

#[derive(Deserialize)]
struct PropertyXml {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct ProxiesXml {
    #[serde(default)]
    proxy: Vec<ProxyXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyXml {
    id: Option<String>,
    #[serde(default = "default_true_bool")]
    active: bool,
    protocol: Option<String>,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    non_proxy_hosts: Option<String>,
}

#[derive(Deserialize)]
struct ProfilesXml {
    #[serde(default)]
    profile: Vec<ProfileXml>,
}

#[derive(Deserialize)]
struct ProfileXml {
    id: Option<String>,
    repositories: Option<RepositoriesXml>,
    /// `<activation>` block. Reuses `rv_maven_model::Activation`, which already
    /// implements the full Maven activation schema (activeByDefault, jdk, os,
    /// file, property). Capturing it here is what makes profiles whose only
    /// activator is `<activeByDefault>true</activeByDefault>`, `<jdk>`, `<os>`,
    /// `<file>`, or `<property>` contribute their repositories. Without this
    /// field the activation is silently dropped and only `<activeProfiles>`
    /// takes effect.
    #[serde(default)]
    activation: Option<Activation>,
}

#[derive(Deserialize)]
struct RepositoriesXml {
    #[serde(default)]
    repository: Vec<RepositoryXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryXml {
    id: Option<String>,
    url: String,
    releases: Option<PolicyXml>,
    snapshots: Option<PolicyXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyXml {
    #[serde(default, deserialize_with = "deserialize_bool_lenient")]
    enabled: Option<bool>,
    update_policy: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActiveProfilesXml {
    #[serde(default)]
    active_profile: Vec<String>,
}

fn default_true_bool() -> bool {
    true
}

fn deserialize_bool_lenient<'de, D>(deserializer: D) -> std::result::Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => {
            if s.eq_ignore_ascii_case("true") {
                Ok(Some(true))
            } else if s.eq_ignore_ascii_case("false") {
                Ok(Some(false))
            } else {
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

impl SettingsXml {
    fn into_settings(self, security: Option<&SecuritySettings>) -> MavenSettings {
        let mirrors = self.mirrors.map(|m| {
            m.mirror
                .into_iter()
                .map(|m| MirrorConfig {
                    id: m.id,
                    url: m.url,
                    mirror_of: m
                        .mirror_of
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                })
                .collect()
        });

        let servers = self.servers.map(|s| {
            s.server
                .into_iter()
                .filter_map(|s| {
                    let mut token = None;
                    if let Some(config) = s.configuration
                        && let Some(headers) = config.http_headers
                    {
                        for prop in headers.property {
                            if prop.name.eq_ignore_ascii_case("Authorization") {
                                token = parse_bearer_token(&prop.value);
                            }
                        }
                    }

                    // A `<server>` carrying none of the credential fields rv
                    // models says nothing about HTTP auth for its id — holding
                    // only `<privateKey>`/`<passphrase>`/`<filePermissions>` is
                    // standard for scp deploys. Converting it anyway would turn
                    // an empty `AuthConfig` into an "incomplete auth entry"
                    // error and poison every repository using that id.
                    if s.username.is_none() && s.password.is_none() && token.is_none() {
                        tracing::warn!(
                            entry_id = %s.id,
                            "ignoring settings.xml <server> with no username, password or \
                             Authorization header; it carries only fields rv does not model"
                        );
                        return None;
                    }

                    let password = s
                        .password
                        .and_then(|p| {
                            let was_encrypted = is_encrypted(&p);
                            let password = sanitize_password(p.clone(), security);
                            if password.is_none() && was_encrypted {
                                warn_failed_password_decryption("server", Some(&s.id));
                            }
                            // Strip `${env.X}` references from the decrypted
                            // plaintext so a stored secret cannot exfiltrate
                            // host env vars through the later `interpolate_env`
                            // pass. Plaintext values keep their `${env.X}`
                            // tokens intact and go through normal expansion.
                            password.map(|plain| {
                                if was_encrypted {
                                    strip_env_refs(&plain)
                                } else {
                                    plain
                                }
                            })
                        })
                        .map(Secret::new);
                    // Bearer tokens are NOT Maven-encrypted passwords: they must
                    // not be piped through `sanitize_password` (which would try
                    // to decrypt a JWT-shaped `{eyJ...}` token as plexus-cipher
                    // and silently drop it on decryption failure).  Pass them
                    // through verbatim; trimming already happened in
                    // `parse_bearer_token`.
                    let token = token.map(Secret::new);

                    Some(AuthConfig {
                        id: Some(s.id),
                        username: s.username,
                        password,
                        token,
                    })
                })
                .collect()
        });

        let proxies = self.proxies.map(|p| {
            p.proxy
                .into_iter()
                .filter_map(|p| {
                    if !p.active {
                        return None;
                    }
                    let password = p
                        .password
                        .and_then(|pass| {
                            let was_encrypted = is_encrypted(&pass);
                            let password = sanitize_password(pass.clone(), security);
                            if password.is_none() && was_encrypted {
                                warn_failed_password_decryption("proxy", p.id.as_deref());
                            }
                            password.map(|plain| {
                                if was_encrypted {
                                    strip_env_refs(&plain)
                                } else {
                                    plain
                                }
                            })
                        })
                        .map(Secret::new);
                    let non_proxy_hosts = p
                        .non_proxy_hosts
                        .map(|h| {
                            h.split('|')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        })
                        .unwrap_or_default();

                    // Default proxy port to 8080 (Maven's default) when not specified.
                    let port = p.port.unwrap_or(8080);
                    Some(ProxyConfig {
                        id: p.id,
                        protocol: p.protocol,
                        host: p.host,
                        port,
                        auth_type: None,
                        username: p.username,
                        password,
                        token_env: None,
                        token: None,
                        non_proxy_hosts,
                    })
                })
                .collect()
        });

        let profiles = self.profiles.map(|p| {
            p.profile
                .into_iter()
                .map(|p| MavenProfile {
                    profile: SettingsProfile {
                        id: p.id,
                        repositories: p
                            .repositories
                            .map(|r| {
                                r.repository
                                    .into_iter()
                                    .map(|r| {
                                        let releases =
                                            r.releases.and_then(|p| p.enabled).or(Some(true));
                                        let snapshots = r
                                            .snapshots
                                            .as_ref()
                                            .and_then(|p| p.enabled)
                                            .or(Some(false));
                                        let snapshots_update_policy = r
                                            .snapshots
                                            .as_ref()
                                            .and_then(|p| p.update_policy.as_deref())
                                            .and_then(UpdatePolicy::parse);
                                        RepoConfig {
                                            id: r.id,
                                            url: r.url,
                                            releases,
                                            snapshots,
                                            snapshots_update_policy,
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    },
                    activation: p.activation,
                })
                .collect()
        });

        let active_profiles = self.active_profiles.map(|a| a.active_profile);

        MavenSettings {
            local_repository: self.local_repository.map(PathBuf::from),
            mirrors,
            servers,
            proxies,
            profiles,
            active_profiles,
        }
    }
}

fn parse_bearer_token(value: &str) -> Option<String> {
    let trimmed = value.trim();
    // Case-insensitive check for the "Bearer " prefix without ever indexing
    // by raw byte offset. `is_char_boundary(7)` guards the suffix slice
    // against a multi-byte char straddling the prefix length (which would
    // otherwise panic). `eq_ignore_ascii_case` on the 7-byte head matches
    // Maven's case-insensitive scheme keyword.
    const PREFIX_LEN: usize = "bearer ".len();
    if !trimmed.is_char_boundary(PREFIX_LEN) {
        return None;
    }
    let (head, rest) = trimmed.split_at(PREFIX_LEN);
    if !head.eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let token = rest.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::MavenSettings;
    use crate::settings::UpdatePolicy;
    use secrecy::ExposeSecret;

    #[test]
    fn parses_minimal_settings() {
        let xml = "<settings></settings>";
        let settings = MavenSettings::parse(xml).unwrap();
        assert!(settings.local_repository.is_none());
        assert!(settings.mirrors.is_none());
        assert!(settings.servers.is_none());
        assert!(settings.proxies.is_none());
        assert!(settings.profiles.is_none());
        assert!(settings.active_profiles.is_none());
    }

    #[test]
    fn parses_empty_container_elements() {
        // Maven accepts empty containers (the routine leftover after
        // commenting out the last entry); each must parse to an empty list
        // rather than failing the whole load with a missing-field error.
        let xml = r"
        <settings>
          <mirrors></mirrors>
          <servers/>
          <proxies/>
          <profiles></profiles>
          <activeProfiles/>
        </settings>
        ";
        let settings = MavenSettings::parse(xml).unwrap();
        assert_eq!(settings.mirrors.as_deref(), Some(&[][..]));
        assert_eq!(settings.servers.as_deref(), Some(&[][..]));
        assert_eq!(settings.proxies.as_deref(), Some(&[][..]));
        assert_eq!(settings.profiles.as_deref(), Some(&[][..]));
        assert_eq!(settings.active_profiles.as_deref(), Some(&[][..]));
    }

    #[test]
    fn parses_empty_nested_container_elements() {
        // Same gap one level down: an empty <repositories> in a profile and
        // an empty <httpHeaders> in a server configuration must parse.
        let xml = r"
        <settings>
          <servers>
            <server>
              <id>corp</id>
              <username>corp-user</username>
              <password>corp-password</password>
              <configuration>
                <httpHeaders/>
              </configuration>
            </server>
          </servers>
          <profiles>
            <profile>
              <id>dev</id>
              <repositories></repositories>
            </profile>
          </profiles>
        </settings>
        ";
        let settings = MavenSettings::parse(xml).unwrap();
        let servers = settings.servers.as_ref().unwrap();
        assert_eq!(servers.len(), 1);
        assert!(servers[0].token.is_none());
        let profiles = settings.profiles.as_ref().unwrap();
        assert_eq!(profiles.len(), 1);
        assert!(profiles[0].profile.repositories.is_empty());
    }

    #[test]
    fn parses_settings_with_utf8_bom() {
        // Windows-saved settings.xml files routinely carry a UTF-8 BOM that
        // quick-xml refuses; `parse_with_security` must strip it transparently.
        let xml = "\u{FEFF}<settings>\
          <localRepository>/tmp/m2</localRepository>\
        </settings>";
        let settings = MavenSettings::parse(xml).expect("BOM-prefixed settings should parse");
        assert_eq!(
            settings.local_repository.as_deref(),
            Some(std::path::Path::new("/tmp/m2"))
        );
    }

    #[test]
    fn parses_full_settings() {
        let xml = r"
        <settings>
          <localRepository>/path/to/local/repo</localRepository>
          <mirrors>
            <mirror>
              <id>corp</id>
              <mirrorOf>central</mirrorOf>
              <url>https://corp.example/maven2/</url>
            </mirror>
          </mirrors>
          <servers>
            <server>
              <id>corp</id>
              <username>user</username>
              <password>pass</password>
            </server>
          </servers>
          <proxies>
            <proxy>
              <id>myproxy</id>
              <active>true</active>
              <protocol>http</protocol>
              <host>proxy.example</host>
              <port>8080</port>
              <username>user</username>
              <password>pass</password>
              <nonProxyHosts>localhost|*.example.com</nonProxyHosts>
            </proxy>
          </proxies>
          <profiles>
            <profile>
              <id>dev</id>
              <repositories>
                <repository>
                  <id>snapshots</id>
                  <url>https://snapshots.example/</url>
                  <snapshots>
                    <enabled>true</enabled>
                    <updatePolicy>interval:15</updatePolicy>
                  </snapshots>
                </repository>
              </repositories>
            </profile>
          </profiles>
          <activeProfiles>
            <activeProfile>dev</activeProfile>
          </activeProfiles>
        </settings>
        ";

        let settings = MavenSettings::parse(xml).unwrap();
        assert_eq!(
            settings
                .local_repository
                .as_ref()
                .and_then(|path| path.to_str()),
            Some("/path/to/local/repo")
        );
        let mirrors = settings.mirrors.as_ref().unwrap();
        assert_eq!(mirrors.len(), 1);
        assert_eq!(mirrors[0].id.as_deref(), Some("corp"));
        assert_eq!(mirrors[0].url, "https://corp.example/maven2/");
        assert_eq!(mirrors[0].mirror_of, vec!["central"]);

        let servers = settings.servers.as_ref().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id.as_deref(), Some("corp"));
        assert_eq!(servers[0].username.as_deref(), Some("user"));
        assert_eq!(
            servers[0]
                .password
                .as_ref()
                .map(|s| s.expose_secret().as_str()),
            Some("pass")
        );

        let proxies = settings.proxies.as_ref().unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].id.as_deref(), Some("myproxy"));
        assert_eq!(proxies[0].protocol.as_deref(), Some("http"));
        assert_eq!(proxies[0].host, "proxy.example");
        assert_eq!(proxies[0].port, 8080);
        assert_eq!(proxies[0].username.as_deref(), Some("user"));
        assert_eq!(
            proxies[0]
                .password
                .as_ref()
                .map(|s| s.expose_secret().as_str()),
            Some("pass")
        );
        assert_eq!(
            proxies[0].non_proxy_hosts,
            vec!["localhost".to_string(), "*.example.com".to_string()]
        );

        let profiles = settings.profiles.as_ref().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].profile.id.as_deref(), Some("dev"));
        assert_eq!(profiles[0].profile.repositories.len(), 1);
        assert_eq!(
            profiles[0].profile.repositories[0].id.as_deref(),
            Some("snapshots")
        );
        assert_eq!(
            profiles[0].profile.repositories[0].url,
            "https://snapshots.example/"
        );
        assert!(profiles[0].profile.repositories[0].snapshots.unwrap());
        assert_eq!(
            profiles[0].profile.repositories[0].snapshots_update_policy,
            Some(UpdatePolicy::Interval(15))
        );

        let active_profiles = settings.active_profiles.as_ref().unwrap();
        assert_eq!(active_profiles, &vec!["dev".to_string()]);
    }

    #[test]
    fn parses_non_proxy_hosts() {
        let xml = r"
        <settings>
          <proxies>
            <proxy>
              <host>proxy.example</host>
              <port>8080</port>
              <nonProxyHosts>localhost|*.example.com|</nonProxyHosts>
            </proxy>
          </proxies>
        </settings>
        ";
        let settings = MavenSettings::parse(xml).unwrap();
        let proxies = settings.proxies.unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(
            proxies[0].non_proxy_hosts,
            vec!["localhost".to_string(), "*.example.com".to_string()]
        );
    }

    /// A `<server>` holding only fields rv does not model (the scp deploy
    /// trio) must be dropped, not converted into an empty `AuthConfig`. An
    /// empty entry would id-match its repository and abort resolution with
    /// "incomplete settings.xml auth entry" even though the user never
    /// configured HTTP credentials for it.
    #[test]
    fn drops_servers_carrying_no_modeled_credential() {
        let xml = r"
        <settings>
          <servers>
            <server>
              <id>scp-deploy</id>
              <privateKey>/home/user/.ssh/id_rsa</privateKey>
              <passphrase>secret</passphrase>
              <filePermissions>664</filePermissions>
            </server>
            <server>
              <id>corp</id>
              <username>user</username>
              <password>pass</password>
            </server>
          </servers>
        </settings>
        ";
        let settings = MavenSettings::parse(xml).unwrap();
        let servers = settings.servers.as_ref().unwrap();
        assert_eq!(servers.len(), 1, "the scp-only server must be dropped");
        assert_eq!(servers[0].id.as_deref(), Some("corp"));
    }

    #[test]
    fn skips_encrypted_passwords_without_security_settings() {
        let xml = r"
        <settings>
          <servers>
            <server>
              <id>corp</id>
              <username>user</username>
              <password>{EbvSxq8u/P5Y6MJqsF8=}</password>
            </server>
          </servers>
          <proxies>
            <proxy>
              <id>myproxy</id>
              <host>proxy.example</host>
              <port>8080</port>
              <password>{abc123DEF456=}</password>
            </proxy>
          </proxies>
        </settings>
        ";
        let settings = MavenSettings::parse_with_security(xml, None).unwrap();

        let servers = settings.servers.as_ref().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id.as_deref(), Some("corp"));
        assert_eq!(servers[0].username.as_deref(), Some("user"));
        assert!(
            servers[0].password.is_none(),
            "encrypted password should be skipped"
        );

        let proxies = settings.proxies.as_ref().unwrap();
        assert_eq!(proxies.len(), 1);
        assert!(
            proxies[0].password.is_none(),
            "encrypted proxy password should be skipped"
        );
    }

    #[test]
    fn keeps_plaintext_passwords() {
        let xml = r"
        <settings>
          <servers>
            <server>
              <id>corp</id>
              <username>user</username>
              <password>plaintext-pass</password>
            </server>
          </servers>
        </settings>
        ";
        let settings = MavenSettings::parse_with_security(xml, None).unwrap();
        let servers = settings.servers.as_ref().unwrap();
        assert_eq!(
            servers[0]
                .password
                .as_ref()
                .map(|s| s.expose_secret().as_str()),
            Some("plaintext-pass")
        );
    }

    #[test]
    fn parses_profile_activation_block() {
        // `<activation>` was previously silently dropped from settings.xml
        // profile parsing, so every profile mode except `<activeProfiles>`
        // failed to contribute repositories. Round-trip the full schema to
        // verify each activator deserialises into rv_maven_model::Activation.
        let xml = r"
        <settings>
          <profiles>
            <profile>
              <id>by-default</id>
              <activation>
                <activeByDefault>true</activeByDefault>
              </activation>
            </profile>
            <profile>
              <id>by-jdk</id>
              <activation>
                <jdk>[17,)</jdk>
              </activation>
            </profile>
            <profile>
              <id>by-os</id>
              <activation>
                <os>
                  <family>unix</family>
                  <arch>x86_64</arch>
                </os>
              </activation>
            </profile>
            <profile>
              <id>by-property</id>
              <activation>
                <property>
                  <name>raeva.feature</name>
                  <value>on</value>
                </property>
              </activation>
            </profile>
            <profile>
              <id>by-file</id>
              <activation>
                <file>
                  <exists>${user.home}/.raeva-flag</exists>
                </file>
              </activation>
            </profile>
          </profiles>
        </settings>
        ";
        let settings = MavenSettings::parse(xml).unwrap();
        let profiles = settings.profiles.as_ref().unwrap();
        assert_eq!(profiles.len(), 5);

        let by_default = &profiles[0];
        assert_eq!(by_default.profile.id.as_deref(), Some("by-default"));
        assert!(by_default.activation.as_ref().unwrap().active_by_default);

        let by_jdk = &profiles[1];
        assert_eq!(
            by_jdk.activation.as_ref().unwrap().jdk.as_deref(),
            Some("[17,)")
        );

        let by_os = &profiles[2];
        let os = by_os.activation.as_ref().unwrap().os.as_ref().unwrap();
        assert_eq!(os.family.as_deref(), Some("unix"));
        assert_eq!(os.arch.as_deref(), Some("x86_64"));

        let by_property = &profiles[3];
        let prop = by_property
            .activation
            .as_ref()
            .unwrap()
            .property
            .as_ref()
            .unwrap();
        assert_eq!(prop.name.as_deref(), Some("raeva.feature"));
        assert_eq!(prop.value.as_deref(), Some("on"));

        let by_file = &profiles[4];
        let file = by_file.activation.as_ref().unwrap().file.as_ref().unwrap();
        assert_eq!(file.exists.as_deref(), Some("${user.home}/.raeva-flag"));
    }

    #[test]
    fn interpolates_env_var_in_server_password() {
        // Use a deliberately uncommon name so we don't collide with the shell.
        temp_env::with_var("RAEVA_TEST_SETTINGS_PW", Some("from-env"), || {
            let xml = r"
            <settings>
              <servers>
                <server>
                  <id>corp</id>
                  <username>${env.RAEVA_TEST_SETTINGS_PW}-user</username>
                  <password>pre-${env.RAEVA_TEST_SETTINGS_PW}-post</password>
                </server>
              </servers>
            </settings>
            ";
            let settings = MavenSettings::parse_with_security(xml, None).unwrap();
            let servers = settings.servers.as_ref().unwrap();
            assert_eq!(servers[0].username.as_deref(), Some("from-env-user"));
            assert_eq!(
                servers[0]
                    .password
                    .as_ref()
                    .map(|s| s.expose_secret().as_str()),
                Some("pre-from-env-post")
            );
        });
    }

    #[test]
    fn decrypted_password_does_not_interpolate_env_refs() {
        // Regression: a stored credential whose *decrypted* plaintext contains
        // `${env.HOME}` must not have HOME interpolated into it. Otherwise an
        // operator who controls only the encrypted blob (e.g. by submitting a
        // settings-security.xml or a poisoned settings.xml fragment) can use
        // it to exfiltrate arbitrary host env vars through the resolved
        // password value.
        //
        // plexus-cipher payload for `pre-${env.HOME}-post` under master
        // `my-master` with a fixed salt; regenerated each run so the test
        // exercises the real decrypt path rather than a stale hex blob.
        let encrypted = crate::encryption::encrypt_for_tests(
            b"pre-${env.HOME}-post",
            "my-master",
            *b"01234567",
        );
        // Parse the security XML first (master = "my-master" plaintext).
        let security = crate::encryption::SecuritySettings::parse(
            "<settingsSecurity><master>my-master</master></settingsSecurity>",
        )
        .unwrap()
        .unwrap();
        let settings_xml = format!(
            r#"<settings>
              <servers>
                <server>
                  <id>corp</id>
                  <username>user</username>
                  <password>{encrypted}</password>
                </server>
              </servers>
            </settings>"#,
        );
        // Set HOME to a recognisable sentinel so the assertion below catches
        // any accidental interpolation.
        temp_env::with_var("HOME", Some("/SENTINEL-LEAKED-HOME"), || {
            let settings =
                MavenSettings::parse_with_security(&settings_xml, Some(&security)).unwrap();
            let servers = settings.servers.as_ref().unwrap();
            let pw = servers[0]
                .password
                .as_ref()
                .map(|s| s.expose_secret().to_string())
                .unwrap();
            assert!(
                !pw.contains("/SENTINEL-LEAKED-HOME"),
                "HOME leaked into decrypted password: {pw}"
            );
            // We strip `${env.X}` references entirely, so the surrounding
            // literal text remains.
            assert_eq!(pw, "pre--post", "unexpected decrypted password: {pw}");
        });
    }

    #[test]
    fn interpolates_env_in_mirror_repo_and_local_repository_fields() {
        // Maven interpolates `${env.X}` across settings.xml, not just in
        // credentials: mirror urls/patterns, settings-profile repository
        // urls, and <localRepository> must all expand.
        temp_env::with_var("RAEVA_TEST_SETTINGS_HOST", Some("corp.example"), || {
            let xml = r"
            <settings>
              <localRepository>/srv/${env.RAEVA_TEST_SETTINGS_HOST}/m2</localRepository>
              <mirrors>
                <mirror>
                  <id>mirror-${env.RAEVA_TEST_SETTINGS_HOST}</id>
                  <mirrorOf>central</mirrorOf>
                  <url>https://${env.RAEVA_TEST_SETTINGS_HOST}/maven2/</url>
                </mirror>
              </mirrors>
              <profiles>
                <profile>
                  <id>dev</id>
                  <repositories>
                    <repository>
                      <id>corp</id>
                      <url>https://${env.RAEVA_TEST_SETTINGS_HOST}/releases/</url>
                    </repository>
                  </repositories>
                </profile>
              </profiles>
            </settings>
            ";
            let settings = MavenSettings::parse_with_security(xml, None).unwrap();
            assert_eq!(
                settings.local_repository.as_deref(),
                Some(std::path::Path::new("/srv/corp.example/m2"))
            );
            let mirrors = settings.mirrors.as_ref().unwrap();
            assert_eq!(mirrors[0].id.as_deref(), Some("mirror-corp.example"));
            assert_eq!(mirrors[0].url, "https://corp.example/maven2/");
            let repo = &settings.profiles.as_ref().unwrap()[0].profile.repositories[0];
            assert_eq!(repo.url, "https://corp.example/releases/");
        });
    }

    #[test]
    fn leaves_unknown_env_var_verbatim_in_mirror_url() {
        let xml = r"
        <settings>
          <mirrors>
            <mirror>
              <id>corp</id>
              <mirrorOf>central</mirrorOf>
              <url>https://${env.RAEVA_TEST_DEFINITELY_NOT_SET}/maven2/</url>
            </mirror>
          </mirrors>
        </settings>
        ";
        let settings = MavenSettings::parse_with_security(xml, None).unwrap();
        let mirrors = settings.mirrors.as_ref().unwrap();
        assert_eq!(
            mirrors[0].url,
            "https://${env.RAEVA_TEST_DEFINITELY_NOT_SET}/maven2/"
        );
    }

    #[test]
    fn comment_wrapped_encrypted_password_decrypts_like_bare_form() {
        // Maven's sec-dispatcher allows decorations around the braces, e.g.
        // "Oleg reset this on 2009-03-11 {COQLCE6DU6GtcS5P=}". The decorated
        // form must route through the same decrypt path as a bare {...}
        // value, not be sent as a literal password.
        let encrypted = crate::encryption::encrypt_for_tests(b"s3cr3t", "my-master", *b"01234567");
        let security = crate::encryption::SecuritySettings::parse(
            "<settingsSecurity><master>my-master</master></settingsSecurity>",
        )
        .unwrap()
        .unwrap();
        let settings_xml = format!(
            r#"<settings>
              <servers>
                <server>
                  <id>corp</id>
                  <username>user</username>
                  <password>Oleg reset this on 2009-03-11 {encrypted}</password>
                </server>
              </servers>
            </settings>"#,
        );
        let settings = MavenSettings::parse_with_security(&settings_xml, Some(&security)).unwrap();
        let servers = settings.servers.as_ref().unwrap();
        assert_eq!(
            servers[0]
                .password
                .as_ref()
                .map(|s| s.expose_secret().as_str()),
            Some("s3cr3t")
        );
    }

    #[test]
    fn failed_decryption_warning_carries_credential_dropped_code() {
        use std::sync::{Arc, Mutex};
        use tracing::field::{Field, Visit};

        // Minimal hand-rolled subscriber: rv-config has no tracing-subscriber
        // dev-dependency, and all we need is the `sec_code` field of WARN
        // events on this thread.
        #[derive(Default)]
        struct CodeVisitor {
            sec_code: Option<String>,
        }
        impl Visit for CodeVisitor {
            fn record_str(&mut self, field: &Field, value: &str) {
                if field.name() == "sec_code" {
                    self.sec_code = Some(value.to_string());
                }
            }
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "sec_code" {
                    self.sec_code = Some(format!("{value:?}").trim_matches('"').to_string());
                }
            }
        }

        struct Collector {
            codes: Arc<Mutex<Vec<String>>>,
        }
        impl tracing::Subscriber for Collector {
            fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
                *metadata.level() == tracing::Level::WARN
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                let mut visitor = CodeVisitor::default();
                event.record(&mut visitor);
                if let Some(code) = visitor.sec_code {
                    self.codes.lock().unwrap().push(code);
                }
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        let codes = Arc::new(Mutex::new(Vec::new()));
        let collector = Collector {
            codes: Arc::clone(&codes),
        };
        // Encrypted password with no settings-security.xml: decryption fails
        // and the credential is dropped, which must emit the catalogued code.
        let xml = r"
        <settings>
          <servers>
            <server>
              <id>corp</id>
              <username>user</username>
              <password>{EbvSxq8u/P5Y6MJqsF8=}</password>
            </server>
          </servers>
        </settings>
        ";
        tracing::subscriber::with_default(collector, || {
            let settings = MavenSettings::parse_with_security(xml, None).unwrap();
            assert!(settings.servers.as_ref().unwrap()[0].password.is_none());
        });
        let codes = codes.lock().unwrap();
        assert!(
            codes.iter().any(|code| code == "CREDENTIAL_DROPPED"),
            "dropped credential must emit sec_code = CREDENTIAL_DROPPED, got {codes:?}"
        );
    }

    #[test]
    fn preserves_unknown_env_var_verbatim() {
        // Pick a name that is virtually certain to be unset.
        let xml = r"
        <settings>
          <servers>
            <server>
              <id>corp</id>
              <username>${env.RAEVA_TEST_DEFINITELY_NOT_SET}</username>
              <password>literal</password>
            </server>
          </servers>
        </settings>
        ";
        let settings = MavenSettings::parse_with_security(xml, None).unwrap();
        let servers = settings.servers.as_ref().unwrap();
        assert_eq!(
            servers[0].username.as_deref(),
            Some("${env.RAEVA_TEST_DEFINITELY_NOT_SET}")
        );
    }

    #[test]
    fn rejects_doctype_in_settings_xml() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE settings [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<settings>
  <localRepository>/tmp/m2</localRepository>
</settings>"#;
        let err = MavenSettings::parse(xml).expect_err("DOCTYPE should be rejected");
        match err {
            crate::error::ConfigError::InvalidSettings(msg) => {
                assert!(msg.to_lowercase().contains("dtd"), "got: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn releases_defaults_to_true_when_only_snapshots_block_present() {
        let xml = r"
        <settings>
          <profiles>
            <profile>
              <id>dev</id>
              <repositories>
                <repository>
                  <id>snapshots</id>
                  <url>https://snapshots.example/</url>
                  <snapshots>
                    <enabled>true</enabled>
                  </snapshots>
                </repository>
              </repositories>
            </profile>
          </profiles>
        </settings>
        ";
        let settings = MavenSettings::parse(xml).unwrap();
        let repo = &settings.profiles.as_ref().unwrap()[0].profile.repositories[0];
        assert_eq!(repo.releases, Some(true));
        assert_eq!(repo.snapshots, Some(true));
    }

    #[test]
    fn parses_server_bearer_token_from_http_headers() {
        let xml = r"
        <settings>
          <servers>
            <server>
              <id>github</id>
              <configuration>
                <httpHeaders>
                  <property>
                    <name>Authorization</name>
                    <value>Bearer token-123</value>
                  </property>
                </httpHeaders>
              </configuration>
            </server>
          </servers>
        </settings>
        ";
        let settings = MavenSettings::parse_with_security(xml, None).unwrap();
        let servers = settings.servers.as_ref().unwrap();
        assert_eq!(
            servers[0]
                .token
                .as_ref()
                .map(|s| s.expose_secret().as_str()),
            Some("token-123")
        );
    }

    /// A Bearer token whose value matches the Maven `{base64...}` encrypted
    /// password shape (e.g. a JWT wrapped in curly braces) must be passed through
    /// verbatim and NOT piped through the Maven password decryptor. Routing it
    /// through `sanitize_password` would detect `is_encrypted` = true on the
    /// brace-wrapped token, fail decryption, and silently drop the credential.
    #[test]
    fn bearer_token_with_jwt_shape_survives_unchanged() {
        // A minimal {base64} string that `is_encrypted` accepts (only base64 chars
        // inside braces). Real JWTs look like `{eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOi4}`;
        // we use a shorter fixture that has the same outer `{...}` shape.
        let jwt_shaped = "{eyJhbGciOiJSUzI1NiJ9base64payload=}";
        let xml = format!(
            r#"<settings>
              <servers>
                <server>
                  <id>private-registry</id>
                  <configuration>
                    <httpHeaders>
                      <property>
                        <name>Authorization</name>
                        <value>Bearer {jwt_shaped}</value>
                      </property>
                    </httpHeaders>
                  </configuration>
                </server>
              </servers>
            </settings>"#,
        );
        // Parse without security settings: a real `{base64}` maven password would
        // be dropped here (no master key), but the bearer token must survive.
        let settings = MavenSettings::parse_with_security(&xml, None).unwrap();
        let servers = settings.servers.as_ref().unwrap();
        assert_eq!(
            servers[0]
                .token
                .as_ref()
                .map(|s| s.expose_secret().as_str()),
            Some(jwt_shaped),
            "JWT-shaped bearer token must not be Maven-decrypted and must survive unchanged"
        );
    }
}
