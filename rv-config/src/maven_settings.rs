use std::path::{Path, PathBuf};

use rv_maven_model::{Activation, PropertyMap};
use secrecy::SecretString;
use serde::Deserialize;

use crate::encryption::{SecuritySettings, decrypt_password, is_encrypted};
use crate::error::ConfigError;
use crate::limited_read::{CappedReadError, read_capped};
use crate::settings::{
    AuthConfig, ChecksumPolicy, MirrorConfig, ProxyConfig, RepoConfig, UpdatePolicy,
};

/// Upper bound on parseable settings.xml size. Real settings.xml files are far
/// smaller; 5 MiB matches `Pom::MAX_SIZE` and stops a hostile or malformed
/// input from exhausting memory. Also reused by `SecuritySettings` for
/// settings-security.xml, which is even smaller in practice.
pub(crate) const MAX_SETTINGS_SIZE: usize = 5 * 1024 * 1024;

/// Shared XML hardening for `settings.xml` and `settings-security.xml`:
/// size cap, BOM strip, DOCTYPE rejection. Fails closed. Returns the text
/// and the root element's name, `None` for a document without one.
pub(crate) fn harden_xml(xml: &str) -> Result<(&str, Option<&str>), ConfigError> {
    if xml.len() > MAX_SETTINGS_SIZE {
        return Err(ConfigError::InvalidSettings(format!(
            "exceeds the {}-byte limit",
            MAX_SETTINGS_SIZE
        )));
    }
    let xml = xml.strip_prefix('\u{FEFF}').unwrap_or(xml);
    let root = reject_doctype(xml)?;
    Ok((xml, root))
}

#[derive(Debug, Clone)]
pub(crate) struct MavenProfile {
    pub id: Option<String>,
    pub repositories: Vec<RepoConfig>,
    pub properties: PropertyMap,
    pub activation: Option<Activation>,
    /// The activation before `${env.*}` expansion, which condition text is
    /// taken from so raeva.lock keys and messages never hold a host value.
    pub written_activation: Option<Activation>,
}

/// The text of the settings file at `path`, or `None` when there is none;
/// the error says what is wrong with the file. `read_capped` enforces the
/// cap at the read site so a file that grows (or is symlink-swapped) after
/// open still fails closed; `metadata` + `read_to_string` would leak a
/// TOCTOU bypass.
pub(crate) fn read_settings_text(path: &Path) -> Result<Option<String>, String> {
    let bytes = match read_capped(path, MAX_SETTINGS_SIZE) {
        Ok(bytes) => bytes,
        Err(CappedReadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(CappedReadError::Io(err)) => return Err(format!("cannot read it: {err}")),
        Err(CappedReadError::TooLarge) => {
            return Err(format!("exceeds the {MAX_SETTINGS_SIZE}-byte limit"));
        }
    };
    // Maven reads it through the same `XmlStreamReader` as a POM.
    match rv_maven_model::decode_pom(&bytes) {
        Ok(text) => Ok(Some(text.into_owned())),
        Err(err) => Err(err.to_string().replacen("the POM", "the file", 1)),
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MavenSettings {
    pub local_repository: Option<PathBuf>,
    pub mirrors: Option<Vec<MirrorConfig>>,
    pub servers: Option<Vec<AuthConfig>>,
    pub proxies: Option<Vec<ProxyConfig>>,
    pub profiles: Option<Vec<MavenProfile>>,
    pub active_profiles: Option<Vec<String>>,
    /// Why the first proxy raeva would use cannot be, raised only when a
    /// client is built, so a command that fetches nothing still runs.
    pub proxy_error: Option<String>,
}

impl MavenSettings {
    pub(crate) fn load_optional(path: &Path) -> Result<Self, ConfigError> {
        match read_settings_text(path).map_err(ConfigError::InvalidSettings)? {
            Some(contents) => Self::parse(&contents),
            None => Ok(Self::default()),
        }
    }

    pub(crate) fn parse(xml: &str) -> Result<Self, ConfigError> {
        Self::parse_with_security(xml, SecuritySettings::load_default()?.as_ref())
    }

    pub(crate) fn parse_with_security(
        xml: &str,
        security: Option<&SecuritySettings>,
    ) -> Result<Self, ConfigError> {
        let (xml, root) = harden_xml(xml)?;
        // Any other document, such as a pom.xml passed to `-s`, would parse
        // as settings with no mirrors, servers or proxies.
        if let Some(root) = root.filter(|root| root.rsplit(':').next() != Some("settings")) {
            return Err(ConfigError::InvalidSettings(format!(
                "its root element is <{}>, not <settings>, so it is not a Maven settings file",
                rv_maven_types::bounded(root)
            )));
        }
        let mut xml_struct: SettingsXml =
            from_xml(xml).map_err(|e| ConfigError::InvalidSettings(e.to_string()))?;
        interpolate_xml(&mut xml_struct)?;
        Ok(xml_struct.into_settings(security))
    }
}

/// Deserializes settings XML with the entities Maven's reader knows.
pub(crate) fn from_xml<'de, T: Deserialize<'de>>(xml: &'de str) -> Result<T, quick_xml::DeError> {
    let mut deserializer =
        quick_xml::de::Deserializer::from_str_with_resolver(xml, rv_maven_model::MavenEntities);
    T::deserialize(&mut deserializer)
}

// Closed-by-default prologue scanner: rejects DOCTYPE outright and any
// non-prologue byte before the root element so a hostile prefix can't shunt
// `<!DOCTYPE` past the check. Returns the root element's name.
fn reject_doctype(xml: &str) -> Result<Option<&str>, ConfigError> {
    let invalid = |message: &str| Err(ConfigError::InvalidSettings(message.to_string()));
    let mut rest = xml;
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if rest.is_empty() {
            return Ok(None);
        }
        let Some(markup) = rest.strip_prefix('<') else {
            return invalid("the prologue contains non-whitespace bytes before the root element");
        };
        if let Some(instruction) = markup.strip_prefix('?') {
            let Some(end) = instruction.find("?>") else {
                return invalid("the prologue has an unterminated processing instruction");
            };
            rest = &instruction[end + 2..];
        } else if let Some(comment) = markup.strip_prefix("!--") {
            let Some(end) = comment.find("-->") else {
                return invalid("the prologue has an unterminated comment");
            };
            rest = &comment[end + 3..];
        } else if let Some(declaration) = markup.strip_prefix('!') {
            if declaration
                .get(..7)
                .is_some_and(|name| name.eq_ignore_ascii_case("DOCTYPE"))
            {
                return invalid("contains a DTD, which is not allowed for security reasons");
            }
            return invalid("the prologue contains an unexpected `<!` markup block");
        } else if markup.is_empty() {
            return invalid("the file ends inside the prologue");
        } else if markup.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            let end = markup
                .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
                .unwrap_or(markup.len());
            return Ok(Some(&markup[..end]));
        } else {
            return invalid("the prologue contains an unexpected token after `<`");
        }
    }
}

// Maven's settings.xml interpolation: `${env.X}` expands to the host env
// across the file, not just in server/proxy auth fields. Settings.xml is
// user-owned config, so expansion is unconditional, and unknown vars
// survive verbatim for a recognisable diagnostic. Encrypted `{...}`
// passwords are left as they are, and their decrypted text is not expanded.
fn interpolate_xml(settings: &mut SettingsXml) -> Result<(), ConfigError> {
    fn expand(value: &mut String) {
        *value = expand_env(value);
    }
    fn expand_opt(value: &mut Option<String>) {
        if let Some(value) = value {
            expand(value);
        }
    }
    fn expand_plain(value: &mut Option<String>) {
        if let Some(value) = value
            && !is_encrypted(value)
        {
            expand(value);
        }
    }
    expand_opt(&mut settings.local_repository);
    if let Some(mirrors) = &mut settings.mirrors {
        for mirror in &mut mirrors.mirror {
            expand_opt(&mut mirror.id);
            expand(&mut mirror.url);
            expand(&mut mirror.mirror_of);
            expand_opt(&mut mirror.mirror_of_layouts);
        }
    }
    if let Some(servers) = &mut settings.servers {
        for server in &mut servers.server {
            expand(&mut server.id);
            expand_opt(&mut server.username);
            expand_plain(&mut server.password);
            if let Some(headers) = server
                .configuration
                .as_mut()
                .and_then(|config| config.http_headers.as_mut())
            {
                for property in &mut headers.property {
                    expand(&mut property.name);
                    expand(&mut property.value);
                }
            }
        }
    }
    if let Some(proxies) = &mut settings.proxies {
        for proxy in &mut proxies.proxy {
            expand_opt(&mut proxy.id);
            expand_opt(&mut proxy.protocol);
            expand(&mut proxy.host);
            expand_opt(&mut proxy.username);
            expand_plain(&mut proxy.password);
            expand_opt(&mut proxy.non_proxy_hosts);
        }
    }
    if let Some(profiles) = &mut settings.profiles {
        for profile in &mut profiles.profile {
            expand_opt(&mut profile.id);
            for value in profile.properties.values_mut() {
                *value = trim(std::mem::take(value));
                expand(value);
            }
            profile.written_activation = profile.activation.clone();
            if let Some(activation) = &mut profile.activation {
                let trim_and_expand = |field: &mut Option<String>| {
                    if let Some(value) = field {
                        *value = trim(std::mem::take(value));
                        expand(value);
                    }
                };
                trim_and_expand(&mut activation.jdk);
                if let Some(os) = &mut activation.os {
                    trim_and_expand(&mut os.name);
                    trim_and_expand(&mut os.family);
                    trim_and_expand(&mut os.arch);
                    trim_and_expand(&mut os.version);
                }
                if let Some(property) = &mut activation.property {
                    trim_and_expand(&mut property.name);
                    trim_and_expand(&mut property.value);
                }
                if let Some(file) = &mut activation.file {
                    trim_and_expand(&mut file.exists);
                    trim_and_expand(&mut file.missing);
                }
            }
            if let Some(repositories) = &mut profile.repositories {
                for repo in &mut repositories.repository {
                    expand_opt(&mut repo.id);
                    refuse_env_in_url_path(repo.id.as_deref(), &repo.url)?;
                    expand(&mut repo.url);
                    for policy in [&mut repo.releases, &mut repo.snapshots]
                        .into_iter()
                        .flatten()
                    {
                        expand_opt(&mut policy.update_policy);
                        expand_opt(&mut policy.checksum_policy);
                    }
                }
            }
        }
    }
    if let Some(active) = &mut settings.active_profiles {
        for id in &mut active.active_profile {
            expand(id);
        }
    }
    Ok(())
}

/// Refuse a remote repository URL that takes a variable named like a
/// secret into its path, where services such as Cloudsmith take a token,
/// or into its query or fragment: raeva.lock records the expanded URL. Other variables, as in
/// `projects/${env.CI_PROJECT_ID}/`, a host, a `file:` URL and a mirror's
/// URL, which the lock does not record, stay allowed.
fn refuse_env_in_url_path(id: Option<&str>, url: &str) -> Result<(), ConfigError> {
    const SECRET: char = '\u{1}';
    // Other references are expanded first, as a scheme or host may come
    // from the environment too. Each secret-named one becomes a marker
    // that names it.
    let mut secrets = Vec::new();
    let marked = replace_env_refs(url, |name| {
        if !crate::redact::secret_named(name) {
            return std::env::var(name).ok();
        }
        secrets.push(name.to_string());
        Some(format!("{SECRET}{}{SECRET}", secrets.len() - 1))
    });
    if secrets.is_empty() {
        return Ok(());
    }
    let Some(rest) = crate::redact::repository_url_path(&marked) else {
        return Ok(());
    };
    let (path, query) = rest.split_at(rest.find(['?', '#']).unwrap_or(rest.len()));
    let taken = |part: &str| {
        (secrets.iter().enumerate())
            .find(|(index, _)| part.contains(&format!("{SECRET}{index}{SECRET}")))
            .map(|(_, name)| name.clone())
    };
    let entry = id.map_or_else(
        || "a repository without an id".to_string(),
        |id| format!("repository '{id}'"),
    );
    // A query or fragment is refused whatever it holds, a mirror's too.
    if let Some(name) = taken(query) {
        return Err(ConfigError::RefusedSettings(format!(
            "the URL of {entry} takes ${{env.{name}}} into its query or fragment, which \
             raeva.lock would record expanded; put the credential in a <server> with the \
             repository's id, not in the URL"
        )));
    }
    let Some(name) = taken(path) else {
        return Ok(());
    };
    Err(ConfigError::RefusedSettings(format!(
        "the URL path of {entry} takes ${{env.{name}}}, which raeva.lock would record \
         expanded, and that name looks like a secret's; if the value is a token, give that \
         URL to a <mirror> of the repository, whose URL raeva.lock does not record, or put \
         the credential in a <server> with the repository's id; if it is not a secret, \
         rename {name}"
    )))
}

/// `input` with each `${env.NAME}` replaced by `value(NAME)`, or kept when
/// that is `None`. An unterminated reference is kept as written.
fn replace_env_refs(input: &str, mut value: impl FnMut(&str) -> Option<String>) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${env.") {
        let after = &rest[start + "${env.".len()..];
        let Some(end) = after.find('}') else {
            break;
        };
        output.push_str(&rest[..start]);
        match value(&after[..end]) {
            Some(value) => output.push_str(&value),
            None => output.push_str(&rest[start..=start + "${env.".len() + end]),
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    output
}

/// Expand every `${env.NAME}` from the process environment, leaving unknown
/// variables intact.
fn expand_env(input: &str) -> String {
    replace_env_refs(input, |name| std::env::var(name).ok())
}

/// The variables of the `${env.NAME}` references in `input` that are not
/// set, which settings.xml interpolation leaves as written.
pub fn unset_env_references(input: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    replace_env_refs(input, |name| {
        if std::env::var(name).is_err() && !names.iter().any(|known| known == name) {
            names.push(name.to_string());
        }
        None
    });
    names
}

/// Expand the `<localRepository>` expressions Maven resolves without project
/// context: `${user.home}` and `${env.NAME}`. Other expressions, and those
/// whose value is unknown, are left intact.
///
/// `Config::local_repository` keeps the configured text, because the lock's
/// configuration hash covers it; expand only where the path is used.
pub fn expand_local_repository(value: &str, user_home: Option<&Path>) -> String {
    let value = match user_home.and_then(Path::to_str) {
        Some(home) => value.replace("${user.home}", home),
        None => value.to_string(),
    };
    expand_env(&value)
}

pub(crate) fn default_settings_path() -> Option<PathBuf> {
    crate::paths::maven_user_home().map(|home| home.join(".m2").join("settings.xml"))
}

/// The password of a settings.xml `<server>` or `<proxy>`, decrypted when
/// it is Maven-encrypted. A password that cannot be decrypted is dropped with
/// a warning.
fn entry_password(
    value: &str,
    security: Option<&SecuritySettings>,
    entry_kind: &str,
    entry_id: Option<&str>,
) -> Option<String> {
    match decrypt_password(value, security) {
        // A decrypted secret is literal: `interpolate_xml` skipped it.
        Ok(plain) => Some(plain),
        Err(reason) => {
            tracing::warn!(
                sec_code = "CREDENTIAL_DROPPED",
                entry_kind = %entry_kind,
                entry_id = entry_id.unwrap_or("<unnamed>"),
                reason = %reason,
                "Maven-encrypted password in settings.xml could not be decrypted, so raeva dropped it"
            );
            None
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsXml {
    #[serde(default, deserialize_with = "trimmed_opt")]
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
    #[serde(default, deserialize_with = "trimmed_opt")]
    id: Option<String>,
    #[serde(deserialize_with = "trimmed")]
    url: String,
    #[serde(deserialize_with = "trimmed")]
    mirror_of: String,
    #[serde(default, deserialize_with = "trimmed_opt")]
    mirror_of_layouts: Option<String>,
    #[serde(default, deserialize_with = "trimmed_opt")]
    blocked: Option<String>,
}

#[derive(Deserialize)]
struct ServersXml {
    #[serde(default)]
    server: Vec<ServerXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerXml {
    // Maven's settings model names a server without an `<id>` `default`.
    #[serde(default = "default_server_id", deserialize_with = "trimmed")]
    id: String,
    #[serde(default, deserialize_with = "trimmed_opt")]
    username: Option<String>,
    #[serde(default, deserialize_with = "trimmed_opt")]
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
    #[serde(default, deserialize_with = "trimmed")]
    name: String,
    #[serde(default, deserialize_with = "trimmed")]
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
    #[serde(default, deserialize_with = "trimmed_opt")]
    id: Option<String>,
    #[serde(default, deserialize_with = "trimmed_opt")]
    active: Option<String>,
    #[serde(default, deserialize_with = "trimmed_opt")]
    protocol: Option<String>,
    #[serde(deserialize_with = "trimmed")]
    host: String,
    #[serde(default, deserialize_with = "trimmed_opt")]
    port: Option<String>,
    #[serde(default, deserialize_with = "trimmed_opt")]
    username: Option<String>,
    #[serde(default, deserialize_with = "trimmed_opt")]
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
    #[serde(default, deserialize_with = "trimmed_opt")]
    id: Option<String>,
    repositories: Option<RepositoriesXml>,
    #[serde(default)]
    properties: PropertyMap,
    #[serde(default)]
    activation: Option<Activation>,
    #[serde(skip)]
    written_activation: Option<Activation>,
}

#[derive(Deserialize)]
struct RepositoriesXml {
    #[serde(default)]
    repository: Vec<RepositoryXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryXml {
    #[serde(default, deserialize_with = "trimmed_opt")]
    id: Option<String>,
    #[serde(deserialize_with = "trimmed")]
    url: String,
    releases: Option<PolicyXml>,
    snapshots: Option<PolicyXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyXml {
    enabled: Option<String>,
    update_policy: Option<String>,
    checksum_policy: Option<String>,
}

/// Whether a `<releases>` or `<snapshots>` block enables its versions, as
/// Maven's settings reader decides: an absent block or `<enabled>`, or an
/// empty one, means yes; otherwise the trimmed text must be `true` in any
/// case. Maven reads the value before it interpolates the file, so a
/// `${env.X}` there is never `true`.
fn policy_enabled(policy: Option<&PolicyXml>) -> bool {
    match policy
        .and_then(|policy| policy.enabled.as_deref())
        .map(str::trim)
    {
        None | Some("") => true,
        Some(value) => value.eq_ignore_ascii_case("true"),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActiveProfilesXml {
    #[serde(default, deserialize_with = "trimmed_list")]
    active_profile: Vec<String>,
}

/// Element text as Maven's settings reader keeps it, trimmed of the
/// characters through U+0020 as Java's `String.trim()` trims them.
fn trim(text: String) -> String {
    let trimmed = text.trim_matches(|c| c <= ' ');
    if trimmed.len() == text.len() {
        text
    } else {
        trimmed.to_string()
    }
}

fn trimmed<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    String::deserialize(deserializer).map(trim)
}

fn trimmed_opt<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.map(trim))
}

fn trimmed_list<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    Ok(Vec::<String>::deserialize(deserializer)?
        .into_iter()
        .map(trim)
        .collect())
}

fn default_server_id() -> String {
    "default".to_string()
}

fn split_list(list: &str, sep: char) -> Vec<String> {
    let entries = list.split(sep).map(str::trim);
    entries
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

impl SettingsXml {
    fn into_settings(self, security: Option<&SecuritySettings>) -> MavenSettings {
        let mirrors = self.mirrors.map(|m| {
            let mirrors = m.mirror.into_iter();
            mirrors
                .map(|m| MirrorConfig {
                    id: m.id,
                    url: m.url,
                    mirror_of: vec![m.mirror_of],
                    mirror_of_layouts: m.mirror_of_layouts,
                    blocked: m
                        .blocked
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case("true")),
                })
                .collect()
        });
        let servers = self.servers.map(|s| {
            let servers = s.server.into_iter();
            servers.filter_map(|s| s.into_auth(security)).collect()
        });
        let mut proxy_error = None;
        let proxies = self.proxies.map(|p| {
            let proxies = p.proxy.into_iter();
            proxies
                .filter_map(|p| {
                    p.into_proxy(security).unwrap_or_else(|error| {
                        proxy_error.get_or_insert(error);
                        None
                    })
                })
                .collect()
        });
        let profiles = self.profiles.map(|p| {
            let profiles = p.profile.into_iter();
            profiles
                .map(|p| MavenProfile {
                    id: p.id,
                    repositories: p.repositories.map_or_else(Vec::new, |r| {
                        r.repository
                            .into_iter()
                            .map(RepositoryXml::into_repo)
                            .collect()
                    }),
                    properties: p.properties,
                    activation: p.activation,
                    written_activation: p.written_activation,
                })
                .collect()
        });
        MavenSettings {
            local_repository: self.local_repository.map(PathBuf::from),
            mirrors,
            servers,
            proxies,
            profiles,
            active_profiles: self.active_profiles.map(|a| a.active_profile),
            proxy_error,
        }
    }
}

impl ServerXml {
    fn into_auth(self, security: Option<&SecuritySettings>) -> Option<AuthConfig> {
        let headers = self.configuration.and_then(|config| config.http_headers);
        let token = (headers.map(|headers| headers.property).unwrap_or_default())
            .into_iter()
            .rfind(|prop| prop.name.eq_ignore_ascii_case("Authorization"))
            .and_then(|prop| parse_bearer_token(&prop.value));
        // A `<server>` with only fields raeva does not model, such as the
        // `<privateKey>` of an scp deploy, says nothing about HTTP auth for
        // its id, and an empty `AuthConfig` would fail every repository
        // using that id as incomplete.
        if self.username.is_none() && self.password.is_none() && token.is_none() {
            tracing::debug!(
                entry_id = %self.id,
                "ignoring settings.xml <server> with no username, password or \
                 Authorization header; it carries only fields raeva does not model"
            );
            return None;
        }
        let password =
            (self.password).and_then(|p| entry_password(&p, security, "server", Some(&self.id)));
        Some(AuthConfig {
            id: Some(self.id),
            username: self.username,
            password: password.map(SecretString::from),
            // A bearer token is never Maven-encrypted, even when it is
            // brace-wrapped like a JWT.
            token: token.map(SecretString::from),
        })
    }
}

impl ProxyXml {
    fn into_proxy(
        self,
        security: Option<&SecuritySettings>,
    ) -> Result<Option<ProxyConfig>, String> {
        // Maven reads `<active>` with `Boolean.valueOf`, and an empty one as true.
        if (self.active)
            .is_some_and(|active| !active.is_empty() && !active.eq_ignore_ascii_case("true"))
        {
            return Ok(None);
        }
        // Maven picks a proxy only for a repository whose URL scheme matches
        // its protocol, so one for socks or any other protocol never carries
        // a fetch there either.
        if !crate::config::is_supported_proxy_protocol(self.protocol.as_deref()) {
            tracing::warn!(
                sec_code = "SETTING_IGNORED",
                proxy_id = self.id.as_deref().unwrap_or_default(),
                "ignoring settings.xml <proxy> for {:?} with protocol {:?}; \
                 raeva supports http, https and all",
                self.host.rsplit('@').next().unwrap_or_default(),
                self.protocol.as_deref().unwrap_or_default()
            );
            return Ok(None);
        }
        // Maven reads a port that is not a number as 0, after a warning, so
        // the proxy it then uses cannot connect.
        let port = match self.port.as_deref() {
            None => 8080,
            Some(port) => port.parse().map_err(|_| {
                format!(
                    "<proxy> for '{}' has <port> '{port}', which is not a port number",
                    self.host.rsplit('@').next().unwrap_or_default()
                )
            })?,
        };
        let password = (self.password)
            .and_then(|pass| entry_password(&pass, security, "proxy", self.id.as_deref()));
        Ok(Some(ProxyConfig {
            id: self.id,
            protocol: self.protocol,
            username: self.username,
            password: password.map(SecretString::from),
            non_proxy_hosts: (self.non_proxy_hosts.as_deref())
                .map_or_else(Vec::new, |hosts| split_list(hosts, '|')),
            ..ProxyConfig::new(&self.host, port)
        }))
    }
}

impl RepositoryXml {
    fn into_repo(self) -> RepoConfig {
        // The policies are strings Maven interpolates, unlike `<enabled>`.
        // `${env.X}` is already expanded by `interpolate_xml`.
        let update = |policy: Option<&PolicyXml>| {
            let value = policy.and_then(|p| p.update_policy.as_deref())?;
            UpdatePolicy::parse(value)
        };
        let checksum = |policy: Option<&PolicyXml>| {
            let value = policy.and_then(|p| p.checksum_policy.as_deref())?;
            Some(ChecksumPolicy::from_maven(value))
        };
        let (releases, snapshots) = (self.releases.as_ref(), self.snapshots.as_ref());
        RepoConfig {
            id: self.id,
            url: self.url,
            releases: Some(policy_enabled(releases)),
            snapshots: Some(policy_enabled(snapshots)),
            snapshots_update_policy: update(snapshots),
            releases_update_policy: update(releases),
            releases_checksum_policy: checksum(releases),
            snapshots_checksum_policy: checksum(snapshots),
        }
    }
}

/// The token of an `Authorization: Bearer <token>` header value, whose
/// scheme is case-insensitive.
fn parse_bearer_token(value: &str) -> Option<String> {
    let (scheme, token) = value.trim().split_at_checked("bearer ".len())?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer ") && !token.is_empty()).then(|| token.to_string())
}

#[cfg(test)]
mod tests {
    use super::{MavenSettings, expand_local_repository};
    use crate::encryption::{SecuritySettings, encrypt_for_tests};
    use crate::settings::{ChecksumPolicy, UpdatePolicy};
    use secrecy::ExposeSecret;

    fn parse(xml: &str) -> MavenSettings {
        MavenSettings::parse_with_security(xml, None).unwrap()
    }

    fn secret(value: &Option<secrecy::SecretString>) -> Option<&str> {
        value.as_ref().map(|s| s.expose_secret())
    }

    #[test]
    fn parses_settings_xml() {
        let xml = "\u{FEFF}<settings>
          <localRepository>/srv/${env.RAEVA_TEST_SETTINGS_HOST}/m2</localRepository>
          <mirrors>
            <mirror>
              <id>mirror-${env.RAEVA_TEST_SETTINGS_HOST}</id>
              <mirrorOf>central, ${env.RAEVA_TEST_DEFINITELY_NOT_SET},</mirrorOf>
              <url>https://${env.RAEVA_TEST_SETTINGS_HOST}/maven2/</url>
            </mirror>
          </mirrors>
          <servers>
            <server>
              <id>scp-deploy</id>
              <privateKey>/home/user/.ssh/id_rsa</privateKey>
            </server>
            <server>
              <id>corp</id>
              <username>${env.RAEVA_TEST_SETTINGS_HOST}-user</username>
              <password>pre-${env.RAEVA_TEST_SETTINGS_HOST}-post</password>
              <configuration><httpHeaders/></configuration>
            </server>
            <server>
              <id>github</id>
              <configuration><httpHeaders><property>
                <name>authorization</name><value> bearer {eyJhbGciOiJSUzI1NiJ9base64=} </value>
              </property></httpHeaders></configuration>
            </server>
          </servers>
          <proxies>
            <proxy><id>off</id><active>false</active><host>off.example</host></proxy>
            <proxy><id>socks</id><protocol>socks5</protocol><host>socks.example</host></proxy>
            <proxy>
              <id>web</id>
              <protocol>HTTPS</protocol>
              <host>proxy.example</host>
              <username>user</username>
              <password>pass</password>
              <nonProxyHosts>localhost|*.example.com|</nonProxyHosts>
            </proxy>
          </proxies>
          <profiles>
            <profile><id>empty</id><repositories></repositories></profile>
            <profile>
              <id>dev</id>
              <activation><jdk>[17,)</jdk></activation>
              <repositories>
                <repository>
                  <id>corp</id>
                  <url>https://${env.RAEVA_TEST_SETTINGS_HOST}/releases/</url>
                  <snapshots><updatePolicy>interval:15</updatePolicy></snapshots>
                </repository>
              </repositories>
            </profile>
          </profiles>
          <activeProfiles><activeProfile>dev</activeProfile></activeProfiles>
        </settings>";
        let (settings, warnings) =
            temp_env::with_var("RAEVA_TEST_SETTINGS_HOST", Some("corp.example"), || {
                crate::test_warnings::capture_warnings(|| parse(xml))
            });
        assert_eq!(
            settings.local_repository.as_deref(),
            Some(std::path::Path::new("/srv/corp.example/m2"))
        );
        let mirror = &settings.mirrors.as_ref().unwrap()[0];
        assert_eq!(mirror.id.as_deref(), Some("mirror-corp.example"));
        assert_eq!(mirror.url, "https://corp.example/maven2/");
        assert_eq!(
            mirror.mirror_of,
            ["central, ${env.RAEVA_TEST_DEFINITELY_NOT_SET},"]
        );
        assert_eq!(mirror.mirror_of_layouts, None);

        let servers = settings.servers.as_ref().unwrap();
        assert_eq!(servers.len(), 2, "the scp-only server is dropped");
        assert_eq!(servers[0].username.as_deref(), Some("corp.example-user"));
        assert_eq!(secret(&servers[0].password), Some("pre-corp.example-post"));
        assert_eq!(secret(&servers[0].token), None);
        assert_eq!(
            secret(&servers[1].token),
            Some("{eyJhbGciOiJSUzI1NiJ9base64=}")
        );

        let proxies = settings.proxies.as_ref().unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(
            (proxies[0].host.as_str(), proxies[0].port),
            ("proxy.example", 8080)
        );
        assert_eq!(proxies[0].username.as_deref(), Some("user"));
        assert_eq!(secret(&proxies[0].password), Some("pass"));
        assert_eq!(proxies[0].non_proxy_hosts, ["localhost", "*.example.com"]);
        assert!(
            warnings
                .iter()
                .any(|w| w.message.contains("socks.example") && w.message.contains("socks5")),
            "{warnings:?}"
        );

        let profiles = settings.profiles.as_ref().unwrap();
        assert!(profiles[0].repositories.is_empty());
        let activation = profiles[1].activation.as_ref().unwrap();
        assert_eq!(activation.jdk.as_deref(), Some("[17,)"));
        let repo = &profiles[1].repositories[0];
        assert_eq!(repo.url, "https://corp.example/releases/");
        assert_eq!((repo.releases, repo.snapshots), (Some(true), Some(true)));
        assert_eq!(
            repo.snapshots_update_policy,
            Some(UpdatePolicy::Interval(15))
        );
        assert_eq!(settings.active_profiles, Some(vec!["dev".to_string()]));

        let empty = parse(
            "<settings><mirrors></mirrors><servers/><proxies/><profiles/><activeProfiles/>\
             </settings>",
        );
        assert_eq!(empty.mirrors.map(|m| m.len()), Some(0));
        assert_eq!(empty.servers.map(|s| s.len()), Some(0));
        assert_eq!(empty.active_profiles, Some(Vec::new()));
        assert!(parse("<settings/>").mirrors.is_none());
    }

    /// Maven interpolates `${env.X}` in `<mirrorOf>` and `<mirrorOfLayouts>`
    /// and before it splits `<nonProxyHosts>`, and it expands proxy
    /// host/protocol/id, server ids, and a Bearer header that is itself an
    /// env reference.
    #[test]
    fn interpolates_env_before_split_and_across_fields() {
        let xml = "<settings>
          <mirrors>
            <mirror>
              <id>${env.RAEVA_TEST_MIRROR_ID}</id>
              <mirrorOf>${env.RAEVA_TEST_MIRROR_OF}</mirrorOf>
              <mirrorOfLayouts>${env.RAEVA_TEST_MIRROR_OF}</mirrorOfLayouts>
              <url>https://mirror.example/</url>
            </mirror>
          </mirrors>
          <servers>
            <server>
              <id>${env.RAEVA_TEST_SERVER_ID}</id>
              <configuration><httpHeaders><property>
                <name>Authorization</name>
                <value>${env.RAEVA_TEST_AUTH_HEADER}</value>
              </property></httpHeaders></configuration>
            </server>
          </servers>
          <proxies>
            <proxy>
              <id>${env.RAEVA_TEST_PROXY_ID}</id>
              <protocol>${env.RAEVA_TEST_PROXY_PROTOCOL}</protocol>
              <host>${env.RAEVA_TEST_PROXY_HOST}</host>
              <nonProxyHosts>${env.RAEVA_TEST_NON_PROXY}</nonProxyHosts>
            </proxy>
          </proxies>
          <profiles>
            <profile>
              <id>${env.RAEVA_TEST_PROFILE_ID}</id>
              <repositories>
                <repository>
                  <id>${env.RAEVA_TEST_SERVER_ID}</id>
                  <url>https://repo.example/</url>
                </repository>
              </repositories>
            </profile>
          </profiles>
          <activeProfiles>
            <activeProfile>${env.RAEVA_TEST_PROFILE_ID}</activeProfile>
          </activeProfiles>
        </settings>";
        let settings = temp_env::with_vars(
            [
                ("RAEVA_TEST_MIRROR_ID", Some("corp-mirror")),
                ("RAEVA_TEST_MIRROR_OF", Some("central,google")),
                ("RAEVA_TEST_SERVER_ID", Some("corp")),
                ("RAEVA_TEST_AUTH_HEADER", Some("Bearer tok-from-env")),
                ("RAEVA_TEST_PROXY_ID", Some("web")),
                ("RAEVA_TEST_PROXY_PROTOCOL", Some("https")),
                ("RAEVA_TEST_PROXY_HOST", Some("proxy.example")),
                ("RAEVA_TEST_NON_PROXY", Some("localhost|*.example.com")),
                ("RAEVA_TEST_PROFILE_ID", Some("dev")),
            ],
            || parse(xml),
        );
        let mirror = &settings.mirrors.as_ref().unwrap()[0];
        assert_eq!(mirror.id.as_deref(), Some("corp-mirror"));
        assert_eq!(mirror.mirror_of, ["central,google"]);
        assert_eq!(mirror.mirror_of_layouts.as_deref(), Some("central,google"));
        let server = &settings.servers.as_ref().unwrap()[0];
        assert_eq!(server.id.as_deref(), Some("corp"));
        assert_eq!(secret(&server.token), Some("tok-from-env"));
        let proxy = &settings.proxies.as_ref().unwrap()[0];
        assert_eq!(proxy.id.as_deref(), Some("web"));
        assert_eq!(proxy.protocol.as_deref(), Some("https"));
        assert_eq!(proxy.host, "proxy.example");
        assert_eq!(proxy.non_proxy_hosts, ["localhost", "*.example.com"]);
        let profile = &settings.profiles.as_ref().unwrap()[0];
        assert_eq!(profile.id.as_deref(), Some("dev"));
        assert_eq!(profile.repositories[0].id.as_deref(), Some("corp"));
        assert_eq!(settings.active_profiles, Some(vec!["dev".to_string()]));
    }

    /// Maven's settings reader trims element text, so a value split over
    /// lines names the same profile, repository or server.
    /// raeva.lock records a repository's expanded URL, so a variable named
    /// like a secret in its path, where some services take a token, is
    /// refused, in every profile. Another variable, one in the host, in a
    /// `file:` path or in a mirror is not.
    #[test]
    fn an_env_reference_in_a_repository_url_path_is_refused() {
        let settings = |repository: &str, mirror: &str| {
            format!(
                "<settings><mirrors><mirror><id>m</id><mirrorOf>x</mirrorOf><url>{mirror}</url>\
                 </mirror></mirrors><profiles><profile><id>p</id><repositories><repository>\
                 <id>corp</id><url>{repository}</url></repository></repositories></profile>\
                 </profiles></settings>"
            )
        };
        for (repository, remedy) in [
            (
                "https://dl.example/${env.REPO_TOKEN}/acme/maven/",
                "<mirror>",
            ),
            ("https://dl.example\\${env.REPO_TOKEN}", "<mirror>"),
            (
                "${env.RAEVA_TEST_UNSET_BASE}/${env.REPO_TOKEN}/maven/",
                "<mirror>",
            ),
            (
                "https://dl.example/maven/?token=${env.REPO_TOKEN}",
                "query or fragment",
            ),
            (
                "https://dl.example/maven/#${env.REPO_TOKEN}",
                "query or fragment",
            ),
            // With several, the remedy and the name are the query's.
            (
                "https://dl.example/${env.OTHER_TOKEN}/maven/?token=${env.REPO_TOKEN}",
                "query or fragment",
            ),
            (
                "https://${env.OTHER_TOKEN_HOST}/maven/?token=${env.REPO_TOKEN}",
                "query or fragment",
            ),
            (
                "https://${env.OTHER_TOKEN_HOST}/${env.REPO_TOKEN}/maven/",
                "<mirror>",
            ),
        ] {
            let err = MavenSettings::parse(&settings(repository, "https://m.example/"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("repository 'corp'")
                    && err.contains("${env.REPO_TOKEN}")
                    && !err.contains("OTHER")
                    && err.contains(remedy),
                "{repository}: {err}"
            );
            assert_eq!(
                err.contains("<mirror>"),
                remedy == "<mirror>",
                "{repository}: {err}"
            );
        }
        for (repository, mirror) in [
            ("https://${env.REPO_HOST}/maven/", "https://m.example/"),
            (
                "https://${env.REPO_TOKEN_HOST}/maven/",
                "https://m.example/",
            ),
            (
                "https://git.example/projects/${env.CI_PROJECT_ID}/maven/",
                "https://m.example/",
            ),
            ("file:///${env.REPO_DIR}/maven/", "https://m.example/"),
            (
                "file:///srv/m2/${env.CI_PROJECT_KEY}/",
                "https://m.example/",
            ),
            ("file:/srv/m2/${env.CI_PROJECT_KEY}/", "https://m.example/"),
            ("FILE:/C:/m2/${env.CI_PROJECT_KEY}/", "https://m.example/"),
            (
                "https://dl.example/maven/",
                "https://m.example/${env.REPO_TOKEN}/",
            ),
        ] {
            MavenSettings::parse(&settings(repository, mirror)).expect(repository);
        }
    }

    #[test]
    fn element_text_is_trimmed() {
        let settings = parse(
            "<settings><activeProfiles><activeProfile>\n  corp\n</activeProfile>\
             </activeProfiles><profiles><profile><id>\n corp\n</id><repositories>\
             <repository><id>\n r\n</id><url>\n https://corp.example/\n</url></repository>\
             </repositories></profile></profiles><mirrors><mirror><id> m </id>\
             <url>\n https://mirror.example/\n</url><mirrorOf>*</mirrorOf>\
             <blocked>\n true\n</blocked></mirror></mirrors></settings>",
        );
        assert_eq!(settings.active_profiles, Some(vec!["corp".to_string()]));
        let profile = &settings.profiles.as_ref().unwrap()[0];
        assert_eq!(profile.id.as_deref(), Some("corp"));
        let repo = &profile.repositories[0];
        assert_eq!(
            (repo.id.as_deref(), repo.url.as_str()),
            (Some("r"), "https://corp.example/")
        );
        let mirror = &settings.mirrors.as_ref().unwrap()[0];
        assert_eq!(
            (mirror.id.as_deref(), mirror.url.as_str()),
            (Some("m"), "https://mirror.example/")
        );
        assert!(mirror.blocked);
    }

    /// Maven reads `<blocked>` with `Boolean.valueOf`, so any case of
    /// `true` blocks the mirror.
    #[test]
    fn blocked_is_read_in_any_case() {
        for (text, blocked) in [("TRUE", true), ("True", true), ("yes", false), ("", false)] {
            let settings = parse(&format!(
                "<settings><mirrors><mirror><id>m</id><url>https://mirror.example/</url>\
                 <mirrorOf>*</mirrorOf><blocked>{text}</blocked></mirror></mirrors></settings>"
            ));
            assert_eq!(settings.mirrors.unwrap()[0].blocked, blocked, "{text}");
        }
    }

    /// The `<enabled>` of a settings.xml repository as Maven's settings
    /// reader reads it, before interpolation, and its policies after.
    #[test]
    fn repository_policies_are_read_as_maven_reads_settings() {
        let repo = |inner: &str| {
            let xml = format!(
                "<settings><profiles><profile><id>p</id><repositories><repository>\
                 <url>https://example.com/</url>{inner}</repository></repositories>\
                 </profile></profiles></settings>"
            );
            parse(&xml).profiles.unwrap()[0].repositories[0].clone()
        };
        for (inner, releases, snapshots) in [
            ("", true, true),
            ("<snapshots><enabled></enabled></snapshots>", true, true),
            ("<snapshots><enabled>yes</enabled></snapshots>", true, false),
            ("<releases><enabled>false</enabled></releases>", false, true),
            (
                "<releases><enabled>${env.HOME}</enabled></releases>",
                false,
                true,
            ),
        ] {
            let repo = repo(inner);
            assert_eq!(repo.releases, Some(releases), "{inner}");
            assert_eq!(repo.snapshots, Some(snapshots), "{inner}");
        }
        for (value, policy) in [
            (" fail ", ChecksumPolicy::Fail),
            ("FAIL", ChecksumPolicy::Unsupported),
            ("", ChecksumPolicy::Unsupported),
        ] {
            let repo = repo(&format!(
                "<releases><checksumPolicy>{value}</checksumPolicy>\
                 <updatePolicy>always</updatePolicy></releases>"
            ));
            assert_eq!(repo.releases_checksum_policy, Some(policy), "{value:?}");
            assert_eq!(repo.releases_update_policy, Some(UpdatePolicy::Always));
            assert_eq!(repo.snapshots_checksum_policy, None, "{value:?}");
        }
        temp_env::with_var("RAEVA_TEST_SETTINGS_POLICY", Some("ignore"), || {
            let repo = repo(
                "<snapshots><checksumPolicy>${env.RAEVA_TEST_SETTINGS_POLICY}</checksumPolicy>\
                 <updatePolicy>${env.RAEVA_TEST_SETTINGS_POLICY}</updatePolicy></snapshots>",
            );
            assert_eq!(repo.snapshots_checksum_policy, Some(ChecksumPolicy::Ignore));
            // `ignore` is no update policy: Maven ignores it, so raeva does too.
            assert_eq!(repo.snapshots_update_policy, None);
        });
    }

    #[test]
    fn encrypted_passwords_decrypt_or_are_dropped() {
        let xml = |server: &str, proxy: &str| {
            format!(
                "<settings><servers><server><id>corp</id><username>user</username>\
                 <password>{server}</password></server></servers><proxies><proxy>\
                 <host>proxy.example</host><password>{proxy}</password></proxy></proxies>\
                 </settings>"
            )
        };
        let ((), warnings) = crate::test_warnings::capture_warnings(|| {
            let settings = parse(&xml("{EbvSxq8u/P5Y6MJqsF8=}", "{abc123DEF456=}"));
            assert!(settings.servers.unwrap()[0].password.is_none());
            assert!(settings.proxies.unwrap()[0].password.is_none());
        });
        let dropped = warnings
            .iter()
            .filter(|w| w.sec_code.as_deref() == Some("CREDENTIAL_DROPPED"))
            .count();
        assert_eq!(dropped, 2, "{warnings:?}");

        // A decrypted secret is a literal, as in Maven: its `${env.X}` text is
        // kept and never expanded.
        let security = SecuritySettings {
            master: Some("my-master".to_string()),
        };
        let decorated = format!(
            "Oleg reset this on 2009-03-11 {}",
            encrypt_for_tests(b"s3cr3t", "my-master", *b"01234567")
        );
        let with_env = encrypt_for_tests(b"pre-${env.HOME}-post", "my-master", *b"01234567");
        temp_env::with_var("HOME", Some("/SENTINEL-LEAKED-HOME"), || {
            let settings =
                MavenSettings::parse_with_security(&xml(&decorated, &with_env), Some(&security))
                    .unwrap();
            assert_eq!(
                secret(&settings.servers.unwrap()[0].password),
                Some("s3cr3t")
            );
            assert_eq!(
                secret(&settings.proxies.unwrap()[0].password),
                Some("pre-${env.HOME}-post")
            );
        });
    }

    #[test]
    fn rejects_doctype_and_other_prologue_markup() {
        for (xml, error) in [
            (
                "<?xml version=\"1.0\"?>\n<!-- c --><!DOCTYPE settings [<!ENTITY x SYSTEM \
                 \"file:///etc/passwd\">]><settings/>",
                "contains a DTD",
            ),
            ("x<settings/>", "non-whitespace bytes"),
            ("<?xml", "unterminated processing instruction"),
            ("<!-- open", "unterminated comment"),
            ("<![CDATA[x]]><settings/>", "unexpected `<!` markup"),
            ("  <", "ends inside the prologue"),
            ("<1settings/>", "unexpected token"),
            (
                "<project><modelVersion>4.0.0</modelVersion></project>",
                "root element is <project>, not <settings>",
            ),
        ] {
            let err = MavenSettings::parse(xml).unwrap_err().to_string();
            assert!(err.contains(error), "{xml:?}: {err}");
        }
    }

    #[test]
    fn local_repository_expands_only_where_it_is_used() {
        let settings = parse(
            "<settings><localRepository>${user.home}/.m2/custom</localRepository></settings>",
        );
        assert_eq!(
            settings.local_repository.as_deref(),
            Some(std::path::Path::new("${user.home}/.m2/custom"))
        );
        let home = std::path::Path::new("/home/user");
        temp_env::with_vars(
            [
                ("RAEVA_TEST_LOCAL_REPO", Some("cache")),
                ("RAEVA_TEST_LOCAL_REPO_UNSET", None),
            ],
            || {
                for (value, home, expanded) in [
                    (
                        "${user.home}/.m2/custom",
                        Some(home),
                        "/home/user/.m2/custom",
                    ),
                    (
                        "${user.home}/${env.RAEVA_TEST_LOCAL_REPO}/${user.home}",
                        Some(home),
                        "/home/user/cache//home/user",
                    ),
                    ("${user.home}/m2", None, "${user.home}/m2"),
                    (
                        "/srv/${env.RAEVA_TEST_LOCAL_REPO_UNSET}",
                        Some(home),
                        "/srv/${env.RAEVA_TEST_LOCAL_REPO_UNSET}",
                    ),
                    ("${user.dir}/m2/${env.", Some(home), "${user.dir}/m2/${env."),
                ] {
                    assert_eq!(expand_local_repository(value, home), expanded);
                }
            },
        );
    }

    #[test]
    fn test_home_hook_redirects_default_settings() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".m2")).unwrap();
        let path = home.path().join(".m2/settings.xml");
        temp_env::with_var(crate::MAVEN_USER_HOME_TEST_ENV, Some(home.path()), || {
            assert_eq!(super::default_settings_path(), Some(path.clone()));
            assert!(
                MavenSettings::load_optional(&path)
                    .unwrap()
                    .mirrors
                    .is_none()
            );
            std::fs::write(
                &path,
                "<settings><activeProfiles><activeProfile>hooked</activeProfile>\
                 </activeProfiles></settings>",
            )
            .unwrap();
            let settings = MavenSettings::load_optional(&path).unwrap();
            assert_eq!(settings.active_profiles, Some(vec!["hooked".to_string()]));
        });
    }

    /// Maven reads settings.xml through plexus-utils' `XmlStreamReader`, so
    /// in the encoding its declaration names, as it reads a POM.
    #[test]
    fn settings_are_read_in_their_declared_encoding() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("settings.xml");
        let mut latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n\
            <!-- Konfiguration f\xFCr Entwickler -->\n\
            <settings><servers><server><id>s</id><password>caf\xE9</password>\
            </server></servers></settings>"
            .to_vec();
        std::fs::write(&path, &latin1).unwrap();
        let settings = MavenSettings::load_optional(&path).unwrap();
        let server = &settings.servers.unwrap()[0];
        assert_eq!(secret(&server.password), Some("café"));

        latin1.splice(30..40, *b"Big5");
        std::fs::write(&path, &latin1).unwrap();
        let err = MavenSettings::load_optional(&path).unwrap_err().to_string();
        assert!(err.contains("the file declares encoding Big5"), "{err}");
    }

    /// Maven's settings reader knows the XHTML entities, as its POM reader
    /// does.
    #[test]
    fn settings_resolve_xhtml_entities() {
        let settings = parse(
            "<settings><servers><server><id>s</id>\
             <password>caf&eacute;&nbsp;&amp;</password></server></servers></settings>",
        );
        let server = &settings.servers.unwrap()[0];
        assert_eq!(secret(&server.password), Some("caf\u{E9}\u{A0}&"));
        assert!(
            MavenSettings::parse_with_security("<settings>&unknown;</settings>", None).is_err()
        );
    }

    #[test]
    fn profile_properties_and_activation_fields_expand_env() {
        temp_env::with_vars(
            [
                ("RAEVA_SETTINGS_VER", Some("2.0")),
                ("RAEVA_SETTINGS_JDK", Some("[17,)")),
                ("RAEVA_SETTINGS_OS", Some("linux")),
                ("RAEVA_SETTINGS_PROP", Some("ci.mode")),
                ("RAEVA_SETTINGS_VAL", Some("true")),
                ("RAEVA_SETTINGS_FILE", Some("marker.txt")),
            ],
            || {
                let settings = parse(
                    "<settings><profiles><profile><id>ext</id>\
                     <activation>\
                       <jdk> ${env.RAEVA_SETTINGS_JDK} </jdk>\
                       <os>\
                         <name> ${env.RAEVA_SETTINGS_OS} </name>\
                         <family>${env.RAEVA_SETTINGS_OS}</family>\
                         <arch>${env.RAEVA_SETTINGS_OS}</arch>\
                         <version>${env.RAEVA_SETTINGS_VER}</version>\
                       </os>\
                       <property>\
                         <name> ${env.RAEVA_SETTINGS_PROP} </name>\
                         <value> ${env.RAEVA_SETTINGS_VAL} </value>\
                       </property>\
                       <file>\
                         <exists> ${env.RAEVA_SETTINGS_FILE} </exists>\
                         <missing>${env.RAEVA_SETTINGS_FILE}.bak</missing>\
                       </file>\
                     </activation>\
                     <properties>\
                       <lib.version> 1.0 </lib.version>\
                       <other>${env.RAEVA_SETTINGS_VER}</other>\
                       <lib.version> ${env.RAEVA_SETTINGS_VER} </lib.version>\
                     </properties>\
                     </profile></profiles></settings>",
                );
                let profile = &settings.profiles.unwrap()[0];
                let pairs: Vec<(&str, &str)> = profile
                    .properties
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                assert_eq!(pairs, [("lib.version", "2.0"), ("other", "2.0")]);
                let activation = profile.activation.as_ref().unwrap();
                assert_eq!(activation.jdk.as_deref(), Some("[17,)"));
                let os = activation.os.as_ref().unwrap();
                assert_eq!(os.name.as_deref(), Some("linux"));
                assert_eq!(os.family.as_deref(), Some("linux"));
                assert_eq!(os.arch.as_deref(), Some("linux"));
                assert_eq!(os.version.as_deref(), Some("2.0"));
                let property = activation.property.as_ref().unwrap();
                assert_eq!(property.name.as_deref(), Some("ci.mode"));
                assert_eq!(property.value.as_deref(), Some("true"));
                let file = activation.file.as_ref().unwrap();
                assert_eq!(file.exists.as_deref(), Some("marker.txt"));
                assert_eq!(file.missing.as_deref(), Some("marker.txt.bak"));
            },
        );
    }

    /// Maven reads a proxy's `<active>` with `Boolean.valueOf` on the
    /// trimmed text, and an empty one as true.
    #[test]
    fn proxy_active_reads_like_maven() {
        for (text, active) in [
            ("true", true),
            ("TRUE", true),
            (" True ", true),
            ("", true),
            ("false", false),
            ("False", false),
            ("1", false),
            ("yes", false),
        ] {
            let settings = MavenSettings::parse_with_security(
                &format!(
                    "<settings><proxies><proxy><active>{text}</active><host>h</host>\
                     </proxy></proxies></settings>"
                ),
                None,
            )
            .unwrap_or_else(|err| panic!("{text:?}: {err}"));
            assert_eq!(
                settings.proxies.unwrap().len(),
                usize::from(active),
                "{text:?}"
            );
        }
    }

    /// Maven reads `<port>` as Java-trimmed text, and on one that is not a
    /// number it warns and reads the file again leniently, so a broken
    /// port only matters on a proxy that would be used, and only once it
    /// connects.
    #[test]
    fn proxy_port_reads_like_maven() {
        let proxy = |active: &str, protocol: &str, port: &str| {
            MavenSettings::parse_with_security(
                &format!(
                    "<settings><proxies><proxy><active>{active}</active>\
                     <protocol>{protocol}</protocol><host>h</host><port>{port}</port>\
                     </proxy></proxies></settings>"
                ),
                None,
            )
            .unwrap()
        };
        let read_port = |settings: MavenSettings| {
            assert_eq!(settings.proxy_error, None);
            settings.proxies.unwrap().first().map(|proxy| proxy.port)
        };
        for (port, read) in [
            ("3128", 3128),
            (" 3128 ", 3128),
            ("\n  3128\n", 3128),
            ("+3128", 3128),
        ] {
            assert_eq!(
                read_port(proxy("true", "http", port)),
                Some(read),
                "{port:?}"
            );
        }
        for port in [
            "",
            "x",
            "-1",
            "70000",
            "${env.RAEVA_TEST_DEFINITELY_NOT_SET}",
        ] {
            assert_eq!(read_port(proxy("false", "http", port)), None, "{port:?}");
            assert_eq!(read_port(proxy("true", "socks5", port)), None, "{port:?}");
            let settings = proxy("true", "http", port);
            assert!(
                settings.proxies.as_ref().is_some_and(Vec::is_empty),
                "{port:?}"
            );
            let err = settings.proxy_error.unwrap();
            assert!(
                err.contains("<port>") && err.contains("'h'"),
                "{port:?}: {err}"
            );
        }
    }

    /// Maven's settings model gives a `<server>` without an `<id>` the id
    /// `default`.
    #[test]
    fn a_server_without_an_id_is_named_default() {
        let settings = parse(
            "<settings><servers><server><username>u</username><password>p</password>\
             </server></servers></settings>",
        );
        let server = &settings.servers.unwrap()[0];
        assert_eq!(server.id.as_deref(), Some("default"));
        assert_eq!(server.username.as_deref(), Some("u"));
    }

    /// Maven trims the text of a server `<configuration>`, so a header name
    /// on its own line still names the header, and it skips a property
    /// without a name or value.
    #[test]
    fn an_http_header_name_is_trimmed() {
        let settings = parse(
            "<settings><servers><server><id>repo</id><configuration><httpHeaders>\
             <property><name>X-Only-Name</name></property><property/>\
             <property><name>\n  Authorization\n</name><value>Bearer t0ken</value></property>\
             </httpHeaders></configuration></server></servers></settings>",
        );
        let server = &settings.servers.unwrap()[0];
        assert_eq!(secret(&server.token), Some("t0ken"));
    }
}
