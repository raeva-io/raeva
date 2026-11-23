use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use rv_maven_model::{Activation, HostProperty, ModelEnvironment, PropertyMap};
use rv_maven_types::MavenMode;
use secrecy::SecretString;
use serde::Deserialize;

use crate::credential_scope::CredentialScope;
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
    pub id: String,
    pub repositories: Vec<RepoConfig>,
    pub plugin_repositories: Vec<RepoConfig>,
    pub properties: PropertyMap,
    pub activation: Option<Activation>,
    /// The activation before `${env.*}` expansion, which condition text is
    /// taken from so raeva.lock keys and messages never hold a host value.
    pub written_activation: Option<Activation>,
    /// The `${...}` each property took a value from when the file was read,
    /// by property name.
    pub property_inputs: HashMap<String, Vec<String>>,
    /// Why a repository of the profile cannot be used, one entry each: an
    /// `<id>` or `<layout>` that still holds a `${...}` once the file is
    /// interpolated, which Maven fills in with each project's properties
    /// when it injects the profile, or a literal layout other than
    /// `default`.
    pub refused_repositories: Vec<String>,
    /// The same of its plugin repositories, whose `<url>` counts too.
    /// They serve only the plugins.
    pub refused_plugin_repositories: Vec<String>,
    /// Those of [`Self::refused_repositories`] for a `<layout>` that still
    /// holds a `${...}`, which Maven's request keeps as written even when
    /// `-P` turns the profile off.
    pub expression_layouts: Vec<String>,
    /// The `<repositories>` whose URL still holds a `${...}` once the file
    /// is interpolated, as the project's model reads them: Maven
    /// injects the profile into each project's model, whose properties
    /// fill them in, and looks the project's parent up with them as
    /// written. [`Self::repositories`] holds them too, as Maven's request
    /// does, and a profile that is active gives the model's in its place.
    pub model_repositories: Vec<rv_maven_model::Repository>,
}

impl MavenProfile {
    /// Whether `repo` is one of [`Self::model_repositories`].
    pub(crate) fn fills_in(&self, repo: &RepoConfig) -> bool {
        let url = repo.declared_url.as_deref().unwrap_or(&repo.url);
        (self.model_repositories.iter()).any(|model| model.id == repo.id && model.url == url)
    }
}

/// How the error of [`read_settings_text`] starts when the file is there but
/// cannot be read.
pub(crate) const UNREADABLE: &str = "cannot read it";

/// The text of the settings file at `path`, or `None` when there is none;
/// the error says what is wrong with the file. `read_capped` enforces the
/// cap at the read site so a file that grows (or is symlink-swapped) after
/// open still fails closed; `metadata` + `read_to_string` would leak a
/// TOCTOU bypass. A file whose directory denies the lookup is none, as
/// `File.exists` reads it for Maven.
pub(crate) fn read_settings_text(path: &Path) -> Result<Option<String>, String> {
    let bytes = match read_capped(path, MAX_SETTINGS_SIZE) {
        Ok(bytes) => bytes,
        Err(CappedReadError::Io(err))
            if err.kind() == std::io::ErrorKind::NotFound || std::fs::metadata(path).is_err() =>
        {
            crate::jvm_options::record_option_file("a settings file", path, None);
            return Ok(None);
        }
        Err(CappedReadError::Io(err)) => return Err(format!("{UNREADABLE}: {err}")),
        Err(CappedReadError::TooLarge) => {
            return Err(format!("exceeds the {MAX_SETTINGS_SIZE}-byte limit"));
        }
        Err(CappedReadError::NotRegular) => {
            return Err(format!("{UNREADABLE}: not a regular file"));
        }
    };
    crate::jvm_options::record_option_file("a settings file", path, Some(&bytes));
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
    /// The `<repositoryOrigins>` of each server of `servers` in the Maven
    /// 3.10 mode.
    pub repository_origins: BTreeMap<String, Vec<String>>,
    /// The id of each `<server>` Maven's request keeps, credentials or not.
    pub server_ids: BTreeSet<String>,
    /// Those of `server_ids` that carry at most a username and password.
    pub basic_only_server_ids: BTreeSet<String>,
    pub proxies: Option<Vec<ProxyConfig>>,
    pub profiles: Option<Vec<MavenProfile>>,
    pub active_profiles: Option<Vec<String>>,
    /// The `<pluginGroups>`, which Maven searches for a plugin prefix
    /// before its default groups.
    pub plugin_groups: Vec<String>,
    /// `<offline>true</offline>`.
    pub offline: bool,
}

/// What reading settings.xml takes besides the file: the Maven line, and
/// the properties Maven's settings builder interpolates the file with, the
/// `-D` user properties before the system properties: `user.home`, and
/// those [`rv_maven_model::host_property`] answers on the host.
#[derive(Debug, Clone)]
pub(crate) struct SettingsInputs {
    pub mode: MavenMode,
    pub user_properties: HashMap<String, String>,
    pub user_home: Option<String>,
    /// The host, whose system properties the parts of settings.xml that
    /// configure this machine's requests take. A profile's properties and
    /// activation take each locked platform's later, so they keep them as
    /// written here.
    pub host: ModelEnvironment,
    /// `maven.multiModuleProjectDirectory`, the launcher's directory, which
    /// `mvn` passes as a system property.
    pub launcher_root: Option<String>,
    /// The ids of the user's config.toml mirrors, which come before these
    /// and take them.
    pub mirror_ids: Vec<String>,
    /// The secret-named inputs each user property took a value from, as
    /// [`crate::maven_config::MavenConfigOptions::secret_inputs`] gives them.
    pub secret_properties: HashMap<String, Vec<String>>,
    /// The `settings.security` the command line sets: the project's
    /// `.mvn/` does not choose where the master password is read from.
    pub settings_security: Option<String>,
    /// The JVM-owned names `.mvn/jvm.config` sets, which some JDKs keep
    /// their own value of, so settings.xml text that takes one refuses.
    pub project_defines: BTreeSet<String>,
    /// The first of [`Self::project_defines`] an expansion kept as written.
    kept_project_define: RefCell<Option<String>>,
}

/// The host of inputs a test reads settings.xml with: this process's
/// environment, with no mavenrc file. Elsewhere the caller sets it.
fn test_host() -> ModelEnvironment {
    #[cfg(test)]
    return rv_maven_model::HostSnapshot::for_testing(&[]).host_environment();
    #[cfg(not(test))]
    ModelEnvironment::default()
}

#[cfg(test)]
impl Default for SettingsInputs {
    fn default() -> Self {
        Self::new(MavenMode::default(), HashMap::new())
    }
}

impl SettingsInputs {
    pub(crate) fn new(mode: MavenMode, user_properties: HashMap<String, String>) -> Self {
        Self {
            settings_security: user_properties.get("settings.security").cloned(),
            mode,
            user_properties,
            user_home: crate::paths::jvm_user_home(crate::paths::LauncherJdk::default())
                .ok()
                .flatten()
                .and_then(|home| home.to_str().map(str::to_string)),
            host: test_host(),
            launcher_root: None,
            mirror_ids: Vec::new(),
            secret_properties: HashMap::new(),
            project_defines: BTreeSet::new(),
            kept_project_define: RefCell::new(None),
        }
    }

    /// The variable `name` as Maven's JVM has it, after the mavenrc files
    /// `mvn` sources.
    fn env(&self, name: &str) -> Option<String> {
        self.host.jvm_env(name).map(str::to_string)
    }

    /// Note `expression` when it is a project define an expansion keeps.
    fn keep(&self, expression: &str, value: Option<String>) -> Option<String> {
        if value.is_none() && self.project_defines.contains(expression) {
            self.kept_project_define
                .borrow_mut()
                .get_or_insert_with(|| expression.to_string());
        }
        value
    }

    /// How a message names the secret-named input `${expression}` takes a
    /// value from, itself or through a user property, with that input's
    /// name; `None` when it takes none.
    fn secret_source(&self, expression: &str) -> Option<(String, String)> {
        if crate::redact::secret_named(expression) {
            let name = expression.strip_prefix("env.").unwrap_or(expression);
            return Some((format!("${{{expression}}}"), name.to_string()));
        }
        let read = self.secret_properties.get(expression)?.first()?;
        let name = read.strip_prefix("env.").unwrap_or(read);
        Some((
            format!("${{{read}}} (through -D{expression})"),
            name.to_string(),
        ))
    }

    /// The value of `${expression}` that does not depend on the locked
    /// platform: a user property, `user.home`,
    /// `maven.multiModuleProjectDirectory`, or the environment variable
    /// `NAME` for `env.NAME` or for a `NAME` no system property has. The
    /// value of a secret-named input, or of one taking a value from it, is
    /// hidden from every output from here on.
    fn value(&self, expression: &str) -> Option<String> {
        let value = self.read(expression);
        if let Some(value) = &value
            && self.secret_source(expression).is_some()
        {
            crate::redact::register_named_secret(value);
        }
        value
    }

    fn read(&self, expression: &str) -> Option<String> {
        if let Some(value) = self.user_properties.get(expression) {
            return Some(value.clone());
        }
        // A `.mvn/jvm.config` system property of a name no JVM sets.
        if !rv_maven_model::jvm_owned(expression)
            && let Some(value) = self.host.system_properties().get(expression)
        {
            return Some(value.clone());
        }
        let host = rv_maven_model::host_property(&self.host, expression);
        match expression {
            "user.home" => self.user_home.clone(),
            "maven.multiModuleProjectDirectory" => self.launcher_root.clone(),
            // Maven's `EnvarBasedValueSource` answers a name without the
            // `env.` prefix too, after the system properties.
            _ => match expression.strip_prefix("env.") {
                Some(name) => self.env(name),
                None if host.is_none() => self.env(expression),
                None => None,
            },
        }
    }

    /// [`Self::value`], else the host's system property, for the parts of
    /// settings.xml that configure this machine's requests.
    fn host_value(&self, expression: &str) -> Option<String> {
        if let Some(value) = self.value(expression) {
            return Some(value);
        }
        // The launcher's directory in settings.xml is read apart.
        if expression == "maven.multiModuleProjectDirectory" {
            return None;
        }
        match rv_maven_model::host_property(&self.host, expression)? {
            HostProperty::Answered(value) => Some(value),
            HostProperty::Unread => None,
        }
    }

    /// `input` with each `${...}` whose value is known on the host replaced
    /// by it, and then those a user property took.
    fn expand(&self, input: &str) -> String {
        let expand = |expression: &str| self.keep(expression, self.host_value(expression));
        replace_refs(&replace_refs(input, expand), expand)
    }

    /// `input` with each `${...}` [`Self::value`] knows replaced by it, and
    /// the expressions it replaced. A system property stays as written, for
    /// each locked platform to expand.
    fn expand_taking(&self, input: &str) -> (String, Vec<String>) {
        let mut taken = Vec::new();
        let expanded = replace_refs(input, |expression| {
            let value = self.keep(expression, self.value(expression))?;
            taken.push(expression.to_string());
            Some(value)
        });
        (expanded, taken)
    }

    /// Refuse `text` of `element` when it takes a system property raeva
    /// does not read from the host, which Maven expands.
    fn refuse_unread_reference(&self, element: &str, text: &str) -> Result<(), ConfigError> {
        let expanded = replace_refs(text, |expression| self.value(expression));
        match rv_maven_model::unread_host_reference(&expanded, &self.host) {
            Some(name) => Err(ConfigError::RefusedSettings(format!(
                "{element} takes ${{{name}}}, which raeva does not read from the host; write \
                 the value out, or set it with -D{name}=<value>"
            ))),
            None => Ok(()),
        }
    }

    /// Refuse `text` of `element` when it takes a name a JVM option may set
    /// in a way raeva does not read: Maven expands settings.xml before a
    /// POM's properties could fill it.
    fn refuse_unread_option(&self, element: &str, text: &str) -> Result<(), ConfigError> {
        let mut found = None;
        let expanded = replace_refs(text, |expression| self.value(expression));
        replace_refs(&expanded, |expression| {
            if found.is_none() && self.host.unread_system_property(expression) {
                found = Some(expression.to_string());
            }
            None
        });
        match found.and_then(|name| Some((crate::unread_jvm_option(&name)?, name))) {
            Some((why, name)) => Err(ConfigError::RefusedSettings(format!(
                "{element} takes ${{{name}}}, which mvn's JVM may take from its options, where \
                 {why}, which raeva cannot read exactly; write that option plainly, or define \
                 {name} on the command line of both raeva and mvn"
            ))),
            None => Ok(()),
        }
    }

    /// Refuse `text` of `element`, which raeva.lock holds or which names a
    /// profile, when it still takes a system property that differs by
    /// platform or JDK, or that raeva does not read from the host: Maven
    /// expands it, and one value would not fit every locked platform.
    fn refuse_host_reference(&self, element: &str, text: &str) -> Result<(), ConfigError> {
        let mut found = None;
        // A user property's value can take one too.
        let expanded = replace_refs(text, |expression| self.value(expression));
        replace_refs(&expanded, |expression| {
            let refused = match rv_maven_model::host_property(&self.host, expression) {
                Some(HostProperty::Unread) => true,
                Some(HostProperty::Answered(_)) => {
                    rv_maven_model::PLATFORM_PROPERTIES.contains(&expression)
                }
                None => false,
            };
            // The launcher's directory is the same on every platform.
            let refused = refused && expression != "maven.multiModuleProjectDirectory";
            if found.is_none() && refused && self.value(expression).is_none() {
                found = Some(expression.to_string());
            }
            None
        });
        match found {
            Some(name) => Err(ConfigError::RefusedSettings(format!(
                "{element} takes ${{{name}}}, a system property that differs by platform or JDK \
                 or that raeva does not read from the host, and raeva cannot record which \
                 value Maven takes; write the value out, or set it with -D{name}=<value>"
            ))),
            None => Ok(()),
        }
    }

    /// Where Maven's sec-dispatcher reads the master password: the file the
    /// `settings.security` property names, else
    /// `~/.m2/settings-security.xml`, a leading `~` being `user.home`.
    fn security_path(&self) -> Option<PathBuf> {
        let location = (self.settings_security.as_deref()).unwrap_or("~/.m2/settings-security.xml");
        match location.strip_prefix('~') {
            Some(rest) => Some(PathBuf::from(self.value("user.home")? + rest)),
            None => Some(PathBuf::from(location)),
        }
    }

    fn security(&self) -> Result<Option<SecuritySettings>, ConfigError> {
        match self.security_path() {
            Some(path) => SecuritySettings::load(&path),
            None => Ok(None),
        }
    }
}

impl MavenSettings {
    pub(crate) fn load_optional(path: &Path, inputs: &SettingsInputs) -> Result<Self, ConfigError> {
        match read_settings_text(path).map_err(ConfigError::InvalidSettings)? {
            Some(contents) => Self::read(&contents, inputs, inputs.security()?.as_ref()),
            None => Ok(Self::default()),
        }
    }

    /// The settings in `xml`, with no security file: the one in the user's
    /// home is not the test's.
    #[cfg(test)]
    pub(crate) fn parse(xml: &str) -> Result<Self, ConfigError> {
        Self::read(xml, &SettingsInputs::default(), None)
    }

    #[cfg(test)]
    pub(crate) fn parse_with_security(
        xml: &str,
        security: Option<&SecuritySettings>,
    ) -> Result<Self, ConfigError> {
        Self::read(xml, &SettingsInputs::default(), security)
    }

    fn read(
        xml: &str,
        inputs: &SettingsInputs,
        security: Option<&SecuritySettings>,
    ) -> Result<Self, ConfigError> {
        // A parse error, or a validation before the credentials expand, may
        // quote the text.
        let masters: Vec<String> = (security.and_then(|security| security.master.clone()))
            .into_iter()
            .flat_map(|master| {
                let plain = crate::encryption::decrypt_maven_password(&master, "settings.security");
                std::iter::once(master).chain(plain)
            })
            .collect();
        let lookup = |name: &str| {
            let variable = name.strip_prefix("env.").unwrap_or(name);
            (inputs.user_properties.get(name).cloned())
                .or_else(|| inputs.host.jvm_env(variable).map(str::to_string))
                .or_else(|| std::env::var(variable).ok())
        };
        crate::prime::register_credential_text(xml, &masters, &lookup);
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
        // Before anything can fail with a message.
        register_credentials(&xml_struct, security);
        refuse_entries_without_id(&xml_struct, inputs.mode)?;
        interpolate_xml(&mut xml_struct, inputs)?;
        register_credentials(&xml_struct, security);
        if inputs.mode == MavenMode::Maven310 {
            // Maven 3.10 expands the text before it reads `<activeByDefault>`.
            let raw: ByDefaultXml =
                from_xml(xml).map_err(|e| ConfigError::InvalidSettings(e.to_string()))?;
            let raw = (raw.profiles.into_iter()).flat_map(|profiles| profiles.profile);
            let profiles = (xml_struct.profiles.iter_mut()).flat_map(|p| &mut p.profile);
            for (profile, raw) in profiles.zip(raw) {
                let text = raw.activation.and_then(|a| a.active_by_default);
                if let (Some(activation), Some(text)) = (&mut profile.activation, text) {
                    let text = trim(inputs.expand(&text));
                    activation.active_by_default = text.eq_ignore_ascii_case("true");
                }
            }
        }
        for group in xml_struct
            .plugin_groups
            .iter()
            .flat_map(|g| &g.plugin_group)
        {
            rv_maven_types::validate_coordinate_component(
                rv_maven_types::CoordinateField::Group,
                group,
            )
            .map_err(|error| ConfigError::InvalidSettings(format!("<pluginGroup>: {error}")))?;
        }
        Ok(xml_struct.into_settings(security, inputs.mode))
    }
}

/// Hide from every output the passwords, passphrases, private keys and
/// `Authorization` header values `settings` holds, as written or expanded,
/// and a Maven-encrypted one also decrypted with `security`, of every
/// entry, the ones Maven's request drops for their id included.
fn register_credentials(settings: &SettingsXml, security: Option<&SecuritySettings>) {
    let servers = (settings.servers.iter()).flat_map(|servers| &servers.server);
    let headers = (servers.clone())
        .filter_map(|server| server.configuration.as_ref()?.http_headers.as_ref())
        .flat_map(|headers| &headers.property)
        .filter(|property| property.name.eq_ignore_ascii_case("Authorization"))
        .flat_map(|property| {
            let token = parse_bearer_token(&property.value);
            std::iter::once(property.value.clone()).chain(token)
        });
    let proxies = (settings.proxies.iter()).flat_map(|proxies| &proxies.proxy);
    let server_secrets =
        servers.flat_map(|server| [&server.password, &server.passphrase, &server.private_key]);
    let passwords = server_secrets
        .chain(proxies.map(|proxy| &proxy.password))
        .flatten()
        .flat_map(|secret| {
            let plain = (is_encrypted(secret))
                .then(|| crate::encryption::decrypt_password(secret, security).ok())
                .flatten();
            std::iter::once(secret.clone()).chain(plain)
        });
    for secret in passwords.chain(headers) {
        crate::redact::register_secret(&secret);
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

// Maven's settings.xml interpolation: each `${...}` across the file takes a
// `-D` user property, a system property such as `user.home`, or `env.X` the
// host env. Settings.xml is user-owned config, so expansion is
// unconditional, and unknown expressions survive verbatim for a
// recognisable diagnostic. Encrypted `{...}` passwords are left as they
// are, and their decrypted text is not expanded. Maven 3.9 reads the
// booleans and the proxy port before it interpolates; 3.10 expands the text
// first.
fn interpolate_xml(settings: &mut SettingsXml, inputs: &SettingsInputs) -> Result<(), ConfigError> {
    let expand = |value: &mut String| *value = inputs.expand(value);
    let expand_opt = |value: &mut Option<String>| {
        if let Some(value) = value {
            expand(value);
        }
    };
    let expand_plain = |value: &mut Option<String>| {
        if let Some(value) = value
            && !is_encrypted(value)
        {
            expand(value);
        }
    };
    let expand_typed = |value: &mut Option<String>| {
        if let Some(value) = value
            && inputs.mode == MavenMode::Maven310
        {
            *value = trim(inputs.expand(value));
        }
    };
    let expand_id = |kind: &str, id: &mut Option<String>| {
        if let Some(id) = id {
            refuse_secret_in(&format!("the <id> of a <{kind}>"), id, inputs)?;
            expand(id);
        }
        Ok::<_, ConfigError>(())
    };
    expand_opt(&mut settings.local_repository);
    expand_typed(&mut settings.offline);
    for group in settings
        .plugin_groups
        .iter_mut()
        .flat_map(|g| &mut g.plugin_group)
    {
        expand(group);
    }
    if let Some(mirrors) = &mut settings.mirrors {
        // Maven's request takes a mirror only when no earlier one has its id.
        let taken = || inputs.mirror_ids.iter().cloned().collect::<HashSet<_>>();
        let mut ids = taken();
        for mirror in &mut mirrors.mirror {
            refuse_secret_in("the <id> of a <mirror>", &mirror.id, inputs)?;
            for (element, text) in [
                ("the <id> of a <mirror>", &mirror.id),
                ("the <url> of a <mirror>", &mirror.url),
                ("the <mirrorOf> of a <mirror>", &mirror.mirror_of),
            ] {
                inputs.refuse_unread_reference(element, text)?;
            }
            expand(&mut mirror.id);
            let kept = ids.insert(mirror.id.clone());
            // A mirror URL may take a token, which [`SettingsInputs::value`]
            // hides from every output; the store names such a mirror by id.
            let mut secret = false;
            let mut find = |expression: &str| {
                let value = inputs.value(expression);
                secret |= inputs.secret_source(expression).is_some()
                    && value.as_ref().is_some_and(|value| !value.trim().is_empty());
                value
            };
            // Twice, as `expand`: a value may hold a reference.
            replace_refs(&replace_refs(&mirror.url, &mut find), &mut find);
            expand(&mut mirror.url);
            if secret && kept {
                crate::redact::register_stored_name(&mirror.url, &mirror.id);
            }
            expand(&mut mirror.mirror_of);
            expand_opt(&mut mirror.mirror_of_layouts);
            expand_opt(&mut mirror.layout);
            if let Some(layout) = mirror
                .layout
                .as_deref()
                .filter(|layout| *layout != "default")
            {
                return Err(ConfigError::RefusedSettings(format!(
                    "the <layout> of mirror '{}' is '{}'; raeva reads every repository in the \
                     default layout, and Maven reaches none of another",
                    rv_maven_types::bounded(&mirror.id),
                    rv_maven_types::bounded(layout)
                )));
            }
            expand_typed(&mut mirror.blocked);
        }
        let mut ids = taken();
        mirrors
            .mirror
            .retain(|mirror| ids.insert(mirror.id.clone()));
    }
    if let Some(servers) = &mut settings.servers {
        for (index, server) in servers.server.iter_mut().enumerate() {
            for id in std::iter::once(&mut server.id)
                .chain(server.aliases.iter_mut().flat_map(|a| &mut a.alias))
            {
                refuse_secret_in("the <id> of a <server>", id, inputs)?;
                expand(id);
            }
            if inputs.mode == MavenMode::Maven310 {
                let origins = server.repository_origins.iter_mut();
                for (at, origin) in origins.flat_map(|o| &mut o.repository_origin).enumerate() {
                    expand(origin);
                    // The value is not shown: it may hold a secret's variable.
                    let entry = format!(
                        "<repositoryOrigin> servers.server[{index}].repositoryOrigins[{at}] of \
                         the <server> {}",
                        rv_maven_types::bounded(&server.id),
                    );
                    match CredentialScope::valid_repository_origin(origin) {
                        Ok(true) => {}
                        Ok(false) => {
                            return Err(ConfigError::InvalidSettings(format!(
                                "the {entry} is not of the form scheme://host[:port], which \
                                 Maven 3.10 requires"
                            )));
                        }
                        Err(()) => {
                            return Err(ConfigError::RefusedSettings(format!(
                                "raeva cannot tell which origin Maven 3.10 reads in the {entry}; \
                                 write the host in ASCII, as a name or an address"
                            )));
                        }
                    }
                }
            }
            expand_opt(&mut server.username);
            expand_plain(&mut server.password);
            expand_plain(&mut server.passphrase);
            expand_opt(&mut server.private_key);
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
            expand_id("proxy", &mut proxy.id)?;
            expand_typed(&mut proxy.active);
            expand_typed(&mut proxy.port);
            let protocol = proxy.protocol.as_deref().unwrap_or_default();
            refuse_secret_in("the <protocol> of a <proxy>", protocol, inputs)?;
            refuse_secret_in("the <host> of a <proxy>", &proxy.host, inputs)?;
            expand_opt(&mut proxy.protocol);
            expand(&mut proxy.host);
            expand_opt(&mut proxy.username);
            expand_plain(&mut proxy.password);
            expand_opt(&mut proxy.non_proxy_hosts);
        }
    }
    // A profile's properties and conditions take each locked platform's
    // system properties later; what names a profile or a repository takes
    // one value for every platform.
    let platform_free = |value: &mut String| {
        let (expanded, _) = inputs.expand_taking(value);
        *value = expanded;
    };
    if let Some(profiles) = &mut settings.profiles {
        for profile in &mut profiles.profile {
            refuse_secret_in("the <id> of a <profile>", &profile.id, inputs)?;
            inputs.refuse_host_reference("the <id> of a <profile>", &profile.id)?;
            expand(&mut profile.id);
            let names: Vec<String> = (profile.properties.iter())
                .map(|(name, _)| name.clone())
                .collect();
            for (name, value) in names.into_iter().zip(profile.properties.values_mut()) {
                *value = trim(std::mem::take(value));
                inputs.refuse_unread_option("a property of a <profile>", value)?;
                let (expanded, taken) = inputs.expand_taking(value);
                *value = expanded;
                if !taken.is_empty() {
                    profile.property_inputs.insert(name, taken);
                }
            }
            for value in activation_fields(&mut profile.activation) {
                *value = trim(std::mem::take(value));
            }
            profile.written_activation = profile.activation.clone();
            activation_fields(&mut profile.activation).for_each(platform_free);
            let plugin_repositories = (profile.plugin_repositories.iter_mut())
                .flat_map(|repositories| &mut repositories.plugin_repository)
                .map(|repo| ("plugin repository", repo));
            for (kind, repo) in (profile.repositories.iter_mut())
                .flat_map(|repositories| &mut repositories.repository)
                .map(|repo| ("repository", repo))
                .chain(plugin_repositories)
            {
                if let Some(id) = &repo.id {
                    inputs.refuse_host_reference("the <id> of a <repository>", id)?;
                }
                inputs.refuse_host_reference("the <url> of a <repository>", &repo.url)?;
                expand_id("repository", &mut repo.id)?;
                refuse_secret_in_url_path(repo.id.as_deref(), &repo.url, inputs)?;
                expand(&mut repo.url);
                expand_opt(&mut repo.layout);
                let entry = match repo.id.as_deref() {
                    Some(id) => format!("{kind} '{}'", rv_maven_types::bounded(id)),
                    None => format!("a {kind} without an id"),
                };
                let unresolved = |element: &str| {
                    format!(
                        "the <{element}> of {entry} still holds a ${{...}} once settings.xml \
                         is interpolated, which Maven fills in with each project's properties; \
                         write it out, or take the value from -D, the environment or a \
                         settings.xml value"
                    )
                };
                // A repository whose URL alone still holds one is the
                // project's to fill in (`MavenProfile::model_repositories`).
                let refusal = if repo.id.as_deref().is_some_and(|id| id.contains("${")) {
                    Some(unresolved("id"))
                } else if repo.expression_layout() {
                    let refusal = unresolved("layout");
                    if kind == "repository" {
                        profile.expression_layouts.push(refusal.clone());
                    }
                    Some(refusal)
                } else if kind == "repository" && repo.fills_in() {
                    None
                } else if repo.url.contains("${") {
                    Some(unresolved("url"))
                } else {
                    (repo.layout.as_deref())
                        .filter(|layout| *layout != "default")
                        .map(|layout| {
                            format!(
                                "the <layout> of {entry} is '{}'; raeva reads every repository in \
                                 the default layout, while Maven reaches one of another only \
                                 through a mirror",
                                rv_maven_types::bounded(layout)
                            )
                        })
                };
                match kind {
                    "repository" => profile.refused_repositories.extend(refusal),
                    _ => profile.refused_plugin_repositories.extend(refusal),
                }
                for policy in [&mut repo.releases, &mut repo.snapshots]
                    .into_iter()
                    .flatten()
                {
                    expand_typed(&mut policy.enabled);
                    expand_opt(&mut policy.update_policy);
                    expand_opt(&mut policy.checksum_policy);
                }
            }
        }
    }
    if let Some(active) = &mut settings.active_profiles {
        for id in &mut active.active_profile {
            refuse_secret_in("an <activeProfile>", id, inputs)?;
            inputs.refuse_host_reference("an <activeProfile>", id)?;
            expand(id);
        }
    }
    match inputs.kept_project_define.take() {
        Some(name) => Err(ConfigError::RefusedSettings(format!(
            "settings.xml takes ${{{name}}}, which .mvn/jvm.config sets, and which some JDKs \
             keep their own value of; write the value out, or set it with -D{name}=<value>"
        ))),
        None => Ok(()),
    }
}

/// The text of each condition `activation` holds.
fn activation_fields(activation: &mut Option<Activation>) -> impl Iterator<Item = &mut String> {
    activation.iter_mut().flat_map(|activation| {
        let os = (activation.os.iter_mut())
            .flat_map(|os| [&mut os.name, &mut os.family, &mut os.arch, &mut os.version]);
        let property = (activation.property.iter_mut()).flat_map(|p| [&mut p.name, &mut p.value]);
        let file = (activation.file.iter_mut()).flat_map(|f| [&mut f.exists, &mut f.missing]);
        (std::iter::once(&mut activation.jdk)
            .chain(os)
            .chain(property)
            .chain(file))
        .flatten()
    })
}

/// Refuse a profile's repository or plugin repository without an `<id>`,
/// and a mirror or server with an empty one, as Maven's settings validation
/// fails the build for one in any profile, active or not, before it
/// interpolates the file. A mirror or server without an `<id>` is `default`.
/// Maven 3.10 refuses an empty server `<alias>` too; 3.9 reads none.
fn refuse_entries_without_id(settings: &SettingsXml, mode: MavenMode) -> Result<(), ConfigError> {
    let mirrors = (settings.mirrors.iter())
        .flat_map(|mirrors| &mirrors.mirror)
        .map(|mirror| ("mirror", &mirror.id));
    let servers = (settings.servers.iter())
        .flat_map(|servers| &servers.server)
        .map(|server| ("server", &server.id));
    if let Some((entry, _)) = mirrors.chain(servers).find(|(_, id)| id.is_empty()) {
        return Err(ConfigError::InvalidSettings(format!(
            "a <{entry}> has an empty <id>, which Maven refuses"
        )));
    }
    let servers = (settings.servers.iter()).flat_map(|servers| &servers.server);
    for (index, server) in servers.enumerate().filter(|_| mode == MavenMode::Maven310) {
        let aliases = (server.aliases.iter()).flat_map(|aliases| &aliases.alias);
        if let Some(alias) = aliases.into_iter().position(String::is_empty) {
            return Err(ConfigError::InvalidSettings(format!(
                "'servers.server[{index}].aliases[{alias}]' for {} is missing: the server has \
                 an empty <alias>, which Maven 3.10 refuses",
                rv_maven_types::bounded(&server.id)
            )));
        }
    }
    for profile in settings
        .profiles
        .iter()
        .flat_map(|profiles| &profiles.profile)
    {
        let repositories = (profile.repositories.iter())
            .flat_map(|list| &list.repository)
            .map(|repo| ("repository", repo));
        let plugin_repositories = (profile.plugin_repositories.iter())
            .flat_map(|list| &list.plugin_repository)
            .map(|repo| ("pluginRepository", repo));
        if let Some((kind, _)) = repositories
            .chain(plugin_repositories)
            .find(|(_, repo)| repo.id.as_deref().is_none_or(str::is_empty))
        {
            return Err(ConfigError::InvalidSettings(format!(
                "profile '{}' has a <{kind}> without an <id>, which Maven refuses",
                rv_maven_types::bounded(&profile.id)
            )));
        }
    }
    Ok(())
}

/// Refuse a repository URL that takes a variable or property named like a
/// secret, or one that takes a value from one, anywhere: in its path, where
/// services such as Cloudsmith take a token, its query or fragment, or its
/// host, port or userinfo. raeva.lock records the expanded URL, and raeva
/// takes no secret from a URL it does not record either
/// ([`crate::secret_part_refusal`]). Other variables, as in
/// `projects/${env.CI_PROJECT_ID}/`, and a mirror's URL, which the lock does
/// not record, stay allowed.
fn refuse_secret_in_url_path(
    id: Option<&str>,
    url: &str,
    inputs: &SettingsInputs,
) -> Result<(), ConfigError> {
    const SECRET: char = '\u{1}';
    // Other references are expanded first, as a scheme or host may come
    // from the environment too. Each secret-named one becomes a marker
    // that names it.
    let mut secrets = Vec::new();
    let mut mark = |expression: &str| {
        let Some(source) = inputs.secret_source(expression) else {
            return inputs.value(expression);
        };
        secrets.push(source);
        Some(format!("{SECRET}{}{SECRET}", secrets.len() - 1))
    };
    // Twice, as [`SettingsInputs::expand`]: a value may hold a reference.
    let marked = replace_refs(&replace_refs(url, &mut mark), &mut mark);
    if secrets.is_empty() {
        return Ok(());
    }
    let rest = crate::redact::repository_url_path(&marked);
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
    let refused = crate::redact::secret_part_refusal(&inputs.expand(url), true);
    // A query or fragment is refused whatever it holds, a mirror's too.
    if let Some((source, _)) = taken(query) {
        return Err(ConfigError::RefusedSettings(format!(
            "the URL of {entry} takes {source} into its query or fragment, which {refused}; \
             put the credential in a <server> with the repository's id, not in the URL"
        )));
    }
    let Some((source, name)) = taken(path) else {
        // The scheme, userinfo, host and port, which raeva.lock records too.
        return match taken(&marked) {
            Some((source, _)) => Err(ConfigError::RefusedSettings(format!(
                "the URL of {entry} takes {source} before its path, which {refused}, and \
                 that name looks like a secret's; give that URL to a \
                 <mirror> of the repository, whose URL raeva.lock does not record, or put the \
                 credential in a <server> with the repository's id"
            ))),
            None => Ok(()),
        };
    };
    Err(ConfigError::RefusedSettings(format!(
        "the URL path of {entry} takes {source}, which {refused}, and that name looks like a \
         secret's; if the value is a token, give that \
         URL to a <mirror> of the repository, whose URL raeva.lock does not record, or put \
         the credential in a <server> with the repository's id; if it is not a secret, \
         rename {name}"
    )))
}

/// Refuse an id, or other text messages show, that takes a variable or
/// property named like a secret: messages, warnings and the seed name an
/// entry by its id.
fn refuse_secret_in(element: &str, text: &str, inputs: &SettingsInputs) -> Result<(), ConfigError> {
    let mut secret = None;
    let mut find = |expression: &str| {
        if secret.is_none() {
            secret = inputs.secret_source(expression);
        }
        inputs.value(expression)
    };
    // Twice, as [`SettingsInputs::expand`]: a value may hold a reference.
    replace_refs(&replace_refs(text, &mut find), &mut find);
    match secret {
        Some((source, _)) => Err(ConfigError::RefusedSettings(format!(
            "{element} takes {source}, a name that looks like a secret's, and raeva shows it \
             in messages; write it out"
        ))),
        None => Ok(()),
    }
}

/// `input` with each `${expression}` replaced by `value(expression)`, or
/// kept when that is `None`. An unterminated reference is kept as written.
/// `value` gets the expression without one leading dot, as Maven reads it.
fn replace_refs(input: &str, mut value: impl FnMut(&str) -> Option<String>) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            break;
        };
        output.push_str(&rest[..start]);
        let key = rv_maven_types::expression_key(&after[..end]);
        match (!key.is_empty()).then(|| value(key)).flatten() {
            Some(value) => output.push_str(&value),
            None => output.push_str(&rest[start..=start + 2 + end]),
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    output
}

/// The variables of the `${env.NAME}` references in `input`, settings.xml
/// text once interpolated, which expands each set one as Maven's JVM has
/// it and leaves an unset one as written.
pub fn unset_env_references(input: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    replace_refs(input, |expression| {
        let name = expression.strip_prefix("env.")?;
        if !names.iter().any(|known| known == name) {
            names.push(name.to_string());
        }
        None
    });
    names
}

/// Expand the `<localRepository>` expressions Maven resolves without project
/// context: `${user.home}` and `${env.NAME}`, as `host`, Maven's JVM after
/// the mavenrc files, has it. Other expressions, and those whose value is
/// unknown, are left intact.
pub fn expand_local_repository(
    value: &str,
    user_home: Option<&Path>,
    host: &rv_maven_model::HostSnapshot,
) -> String {
    replace_refs(value, |expression| match expression {
        "user.home" => user_home.and_then(Path::to_str).map(str::to_string),
        _ => {
            let name = expression.strip_prefix("env.")?;
            let value = host.jvm_env(name)?.to_string();
            if crate::secret_named(name) {
                crate::redact::register_named_secret(&value);
            }
            Some(value)
        }
    })
}

#[cfg(test)]
pub(crate) fn default_settings_path() -> Option<PathBuf> {
    crate::paths::maven_user_home(None, crate::paths::LauncherJdk::default())
        .ok()
        .flatten()
        .map(|home| home.join(".m2").join("settings.xml"))
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
        Ok(plain) => {
            crate::redact::register_secret(&plain);
            Some(plain)
        }
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
    #[serde(default, deserialize_with = "trimmed_opt")]
    offline: Option<String>,
    mirrors: Option<MirrorsXml>,
    servers: Option<ServersXml>,
    proxies: Option<ProxiesXml>,
    profiles: Option<ProfilesXml>,
    active_profiles: Option<ActiveProfilesXml>,
    plugin_groups: Option<PluginGroupsXml>,
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
    #[serde(default = "default_id", deserialize_with = "trimmed")]
    id: String,
    #[serde(deserialize_with = "trimmed")]
    url: String,
    #[serde(deserialize_with = "trimmed")]
    mirror_of: String,
    #[serde(default, deserialize_with = "trimmed_opt")]
    mirror_of_layouts: Option<String>,
    #[serde(default, deserialize_with = "trimmed_opt")]
    layout: Option<String>,
    #[serde(default, deserialize_with = "trimmed_opt")]
    blocked: Option<String>,
}

#[derive(Deserialize)]
struct ServersXml {
    #[serde(default)]
    server: Vec<ServerXml>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerXml {
    #[serde(default = "default_id", deserialize_with = "trimmed")]
    id: String,
    /// Maven 3.10's other ids for the server.
    aliases: Option<AliasesXml>,
    /// Maven 3.10's origins for the server's username and password.
    repository_origins: Option<RepositoryOriginsXml>,
    #[serde(default, deserialize_with = "trimmed_opt")]
    username: Option<String>,
    #[serde(default, deserialize_with = "trimmed_opt")]
    password: Option<String>,
    /// Read only to hide it, as an scp or sftp deploy's.
    #[serde(default, deserialize_with = "trimmed_opt")]
    passphrase: Option<String>,
    /// Read only to hide it.
    #[serde(default, deserialize_with = "trimmed_opt")]
    private_key: Option<String>,
    configuration: Option<ServerConfigXml>,
}

#[derive(Clone, Deserialize)]
struct AliasesXml {
    #[serde(default, deserialize_with = "trimmed_list")]
    alias: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryOriginsXml {
    #[serde(default, deserialize_with = "trimmed_list")]
    repository_origin: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerConfigXml {
    http_headers: Option<HttpHeadersXml>,
}

#[derive(Clone, Deserialize)]
struct HttpHeadersXml {
    #[serde(default)]
    property: Vec<PropertyXml>,
}

#[derive(Clone, Deserialize)]
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
    #[serde(default, deserialize_with = "trimmed_opt")]
    non_proxy_hosts: Option<String>,
}

#[derive(Deserialize)]
struct ProfilesXml {
    #[serde(default)]
    profile: Vec<ProfileXml>,
}

#[derive(Deserialize)]
struct ProfileXml {
    #[serde(default = "default_id", deserialize_with = "trimmed")]
    id: String,
    repositories: Option<RepositoriesXml>,
    #[serde(rename = "pluginRepositories")]
    plugin_repositories: Option<PluginRepositoriesXml>,
    #[serde(default)]
    properties: PropertyMap,
    #[serde(default)]
    activation: Option<Activation>,
    #[serde(skip)]
    written_activation: Option<Activation>,
    #[serde(skip)]
    property_inputs: HashMap<String, Vec<String>>,
    #[serde(skip)]
    refused_repositories: Vec<String>,
    #[serde(skip)]
    refused_plugin_repositories: Vec<String>,
    #[serde(skip)]
    expression_layouts: Vec<String>,
}

#[derive(Deserialize)]
struct ByDefaultXml {
    profiles: Option<ByDefaultProfilesXml>,
}

#[derive(Deserialize)]
struct ByDefaultProfilesXml {
    #[serde(default)]
    profile: Vec<ByDefaultProfileXml>,
}

#[derive(Deserialize)]
struct ByDefaultProfileXml {
    activation: Option<ByDefaultActivationXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ByDefaultActivationXml {
    active_by_default: Option<String>,
}

#[derive(Deserialize)]
struct RepositoriesXml {
    #[serde(default)]
    repository: Vec<RepositoryXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginRepositoriesXml {
    #[serde(default)]
    plugin_repository: Vec<RepositoryXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryXml {
    #[serde(default, deserialize_with = "trimmed_opt")]
    id: Option<String>,
    #[serde(deserialize_with = "trimmed")]
    url: String,
    #[serde(default, deserialize_with = "trimmed_opt")]
    layout: Option<String>,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginGroupsXml {
    #[serde(default, deserialize_with = "trimmed_list")]
    plugin_group: Vec<String>,
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

/// The id Maven's settings model gives a mirror, server or profile without
/// an `<id>`.
fn default_id() -> String {
    "default".to_string()
}

impl SettingsXml {
    fn into_settings(self, security: Option<&SecuritySettings>, mode: MavenMode) -> MavenSettings {
        let mirrors = self.mirrors.map(|m| {
            let mirrors = m.mirror.into_iter();
            mirrors
                .map(|m| MirrorConfig {
                    id: Some(m.id),
                    url: m.url,
                    mirror_of: vec![m.mirror_of],
                    mirror_of_layouts: m.mirror_of_layouts,
                    blocked: m
                        .blocked
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case("true")),
                    declared_url: None,
                })
                .collect()
        });
        let mut repository_origins = BTreeMap::new();
        let mut server_ids = BTreeSet::new();
        let mut basic_only_server_ids = BTreeSet::new();
        let servers = self.servers.map(|s| {
            // Maven 3.10 copies a server onto each of its aliases in place.
            // Of the servers with one id, Maven's request keeps the first,
            // which may carry no credential.
            let servers = s.server.into_iter().flat_map(|server| {
                let aliases = (server.aliases.iter())
                    .filter(|_| mode == MavenMode::Maven310)
                    .flat_map(|aliases| aliases.alias.clone());
                let copies: Vec<ServerXml> = (aliases.map(|id| ServerXml {
                    id,
                    ..server.clone()
                }))
                .collect();
                std::iter::once(server).chain(copies)
            });
            first_of_each_id(servers, |server| server.id.clone())
                .filter_map(|mut server| {
                    server_ids.insert(server.id.clone());
                    if server.configuration.is_none()
                        && server.private_key.is_none()
                        && server.passphrase.is_none()
                        && server.repository_origins.is_none()
                    {
                        basic_only_server_ids.insert(server.id.clone());
                    }
                    let origins = (server.repository_origins.take())
                        .filter(|_| mode == MavenMode::Maven310)
                        .map(|origins| origins.repository_origin)
                        .unwrap_or_default();
                    let auth = server.into_auth(security)?;
                    repository_origins.insert(auth.id.clone().unwrap_or_default(), origins);
                    Some(auth)
                })
                .collect()
        });
        // Maven's request takes the active proxies, the first of each id,
        // one without an `<id>` having `default`.
        let proxies = (self.proxies).map(|p| {
            let active = p.proxy.into_iter().filter(ProxyXml::is_active);
            first_of_each_id(active, |proxy| proxy.id.clone().unwrap_or_else(default_id))
                .filter_map(|p| p.into_proxy(security))
                .collect()
        });
        let profiles = self.profiles.map(|p| {
            let profiles = p.profile.into_iter();
            profiles
                .map(|p| MavenProfile {
                    id: p.id,
                    model_repositories: (p.repositories.iter())
                        .flat_map(|r| &r.repository)
                        .filter(|repo| repo.fills_in())
                        .map(RepositoryXml::to_model)
                        .collect(),
                    repositories: (p.repositories.into_iter())
                        .flat_map(|r| r.repository)
                        .map(RepositoryXml::into_repo)
                        .collect(),
                    plugin_repositories: (p.plugin_repositories.into_iter())
                        .flat_map(|r| r.plugin_repository)
                        .map(RepositoryXml::into_repo)
                        .collect(),
                    properties: p.properties,
                    activation: p.activation,
                    written_activation: p.written_activation,
                    property_inputs: p.property_inputs,
                    refused_repositories: p.refused_repositories,
                    refused_plugin_repositories: p.refused_plugin_repositories,
                    expression_layouts: p.expression_layouts,
                })
                .collect()
        });
        MavenSettings {
            // Maven takes an empty one as unset.
            local_repository: (self.local_repository.filter(|path| !path.is_empty()))
                .map(PathBuf::from),
            mirrors,
            servers,
            repository_origins,
            server_ids,
            basic_only_server_ids,
            proxies,
            profiles,
            active_profiles: self.active_profiles.map(|a| a.active_profile),
            plugin_groups: self
                .plugin_groups
                .map(|g| g.plugin_group)
                .unwrap_or_default(),
            // Read with `Boolean.valueOf`, as `<active>` is.
            offline: (self.offline.as_deref())
                .is_some_and(|value| value.eq_ignore_ascii_case("true")),
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
        let password = (self.password.as_deref())
            .map(|p| entry_password(p, security, "server", Some(&self.id)));
        // Without its dropped password, the user name alone would be an
        // incomplete entry; Maven goes on without the credential. A server
        // with no user name is left empty, so it is skipped.
        let password_dropped =
            matches!(password, Some(None)) && token.is_none() && self.username.is_some();
        Some(AuthConfig {
            id: Some(self.id),
            username: self.username.filter(|_| !password_dropped),
            password: password.flatten().map(SecretString::from),
            // A bearer token is never Maven-encrypted, even when it is
            // brace-wrapped like a JWT.
            token: token.map(SecretString::from),
            password_dropped,
        })
    }
}

/// The first of `entries` with each id, in order, as Maven's request keeps
/// a server or proxy only when none before it has its id.
fn first_of_each_id<T>(
    entries: impl Iterator<Item = T>,
    id: impl Fn(&T) -> String,
) -> impl Iterator<Item = T> {
    let mut ids = std::collections::HashSet::new();
    entries.filter(move |entry| ids.insert(id(entry)))
}

impl ProxyXml {
    /// Maven reads `<active>` with `Boolean.valueOf`, and an empty one as true.
    fn is_active(&self) -> bool {
        (self.active.as_deref())
            .is_none_or(|active| active.is_empty() || active.eq_ignore_ascii_case("true"))
    }

    fn into_proxy(self, security: Option<&SecuritySettings>) -> Option<ProxyConfig> {
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
            return None;
        }
        // Maven reads a port that is not a number as 0, after a warning, so
        // the proxy it then uses cannot connect.
        let port = match self.port.as_deref() {
            None => 8080,
            Some(port) => port.parse().unwrap_or_else(|_| {
                tracing::warn!(
                    sec_code = "SETTING_IGNORED",
                    proxy_id = self.id.as_deref().unwrap_or_default(),
                    "settings.xml <proxy> for {:?} has a <port> that is not a port number; \
                     raeva reads it as 0, as Maven does, so a fetch through it fails",
                    self.host.rsplit('@').next().unwrap_or_default()
                );
                0
            }),
        };
        let password = (self.password.as_deref())
            .map(|pass| entry_password(pass, security, "proxy", self.id.as_deref()));
        // Without its dropped password, the user name alone would go out as
        // Basic with an empty password.
        let username = self.username.filter(|_| !matches!(password, Some(None)));
        Some(ProxyConfig {
            id: self.id,
            protocol: self.protocol,
            username,
            password: password.flatten().map(SecretString::from),
            // Split as Maven's `StringTokenizer` splits it: entries keep
            // their spaces, and empty ones are dropped.
            non_proxy_hosts: (self.non_proxy_hosts.iter())
                .flat_map(|hosts| hosts.split('|'))
                .filter(|host| !host.is_empty())
                .map(str::to_string)
                .collect(),
            ..ProxyConfig::new(&self.host, port)
        })
    }
}

impl RepositoryXml {
    /// Whether the URL still holds a `${...}` once settings.xml is
    /// interpolated, which the project's model fills in, and the layout
    /// does not.
    fn fills_in(&self) -> bool {
        self.url.contains("${") && !self.expression_layout()
    }

    /// Whether the layout still holds a `${...}` once settings.xml is
    /// interpolated.
    fn expression_layout(&self) -> bool {
        (self.layout.as_deref()).is_some_and(|layout| layout.contains("${"))
    }

    /// The repository as a project's model declares it once the profile is
    /// injected, its `<enabled>` read as settings.xml reads it.
    fn to_model(&self) -> rv_maven_model::Repository {
        let mut repo = rv_maven_model::Repository::new(self.id.as_deref(), &self.url);
        repo.root_declared = true;
        repo.layout = self.layout.clone();
        repo.written_layout = self.layout.clone();
        let (releases, snapshots) = (self.releases.as_ref(), self.snapshots.as_ref());
        repo.releases_enabled = policy_enabled(releases);
        repo.snapshots_enabled = policy_enabled(snapshots);
        repo.releases_update_policy = releases.and_then(|p| p.update_policy.clone());
        repo.snapshots_update_policy = snapshots.and_then(|p| p.update_policy.clone());
        repo.releases_checksum_policy = releases.and_then(|p| p.checksum_policy.clone());
        repo.snapshots_checksum_policy = snapshots.and_then(|p| p.checksum_policy.clone());
        repo
    }

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
            declared_url: None,
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
    use super::{MavenSettings, SettingsInputs, expand_local_repository};
    use crate::encryption::{SecuritySettings, encrypt_for_tests};
    use crate::error::ConfigError;
    use crate::settings::{ChecksumPolicy, UpdatePolicy};
    use rv_maven_types::MavenMode;
    use secrecy::ExposeSecret;

    fn parse(xml: &str) -> MavenSettings {
        MavenSettings::parse_with_security(xml, None).unwrap()
    }

    fn inputs(mode: MavenMode, user: &[(&str, &str)]) -> SettingsInputs {
        SettingsInputs {
            mode,
            user_properties: (user.iter())
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            user_home: Some("/home/u".to_string()),
            ..SettingsInputs::new(mode, std::collections::HashMap::new())
        }
    }

    /// Maven interpolates the whole file with the `-D` user properties,
    /// then the system properties, `user.home` among them, then `env.NAME`.
    #[test]
    fn settings_expand_user_and_system_properties() {
        let inputs = inputs(
            MavenMode::Maven39,
            &[
                ("repo.url", "https://repo.example/maven/"),
                ("both", "user"),
            ],
        );
        let xml = "<settings><localRepository>${user.home}/m2</localRepository>
            <mirrors><mirror><id>local</id><url>file://${user.home}/mirror/</url>
            <mirrorOf>*</mirrorOf></mirror></mirrors>
            <profiles><profile><id>corp</id>
            <properties><both>${both}</both><home>${user.home}</home><other>${unknown}</other></properties>
            <repositories><repository><id>corp</id><url>${repo.url}</url></repository></repositories>
            </profile></profiles></settings>";
        let settings = MavenSettings::read(xml, &inputs, None).unwrap();
        assert_eq!(
            settings.local_repository.as_deref(),
            Some(std::path::Path::new("/home/u/m2"))
        );
        assert_eq!(settings.mirrors.unwrap()[0].url, "file:///home/u/mirror/");
        let profile = &settings.profiles.unwrap()[0];
        assert_eq!(profile.repositories[0].url, "https://repo.example/maven/");
        let property = |name: &str| profile.properties.get(name).map(String::as_str);
        assert_eq!(property("both"), Some("user"));
        assert_eq!(property("home"), Some("/home/u"));
        assert_eq!(property("other"), Some("${unknown}"));

        let token = "https://repo.example/${repo.token}/maven/";
        let error = MavenSettings::read(
            &xml.replace("${repo.url}", token),
            &self::inputs(MavenMode::Maven39, &[("repo.token", "s3cr3t")]),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("${repo.token}") && !error.contains("s3cr3t"),
            "{error}"
        );
    }

    /// Maven's settings builder expands the system properties too. The
    /// parts that configure this machine's requests take the host's; a
    /// profile's properties and activation keep them for each locked
    /// platform; and what names a profile or a repository refuses one that
    /// differs by platform or that raeva does not read. Maven 3.9.12 and
    /// 3.10.0 expand `${HOME}` without the `env.` prefix as well.
    #[test]
    fn settings_take_the_jvm_properties_as_maven_does() {
        let mut inputs = inputs(MavenMode::Maven39, &[("user.name", "ci")]);
        let host = rv_maven_model::HostSnapshot::for_testing(&[]).environment("linux", "x86_64");
        inputs.host = host;
        let xml =
            "<settings><mirrors><mirror><id>m-${os.name}</id><url>file:///m/${maven.version}/</url>
            <mirrorOf>*</mirrorOf></mirror></mirrors>
            <profiles><profile><id>corp</id><activation><property><name>x</name>
            <value>${os.name}</value></property></activation>
            <properties><os>${os.name}</os><user>${user.name}</user><path>${PATH}</path>
            <vendor>${java.vendor}</vendor></properties></profile></profiles></settings>";
        let settings = MavenSettings::read(xml, &inputs, None).unwrap();
        let mirror = &settings.mirrors.unwrap()[0];
        assert_eq!(mirror.id.as_deref(), Some("m-Linux"));
        assert_eq!(mirror.url, "file:///m/3.9.12/");
        let profile = &settings.profiles.unwrap()[0];
        let property = |name: &str| profile.properties.get(name).map(String::as_str);
        assert_eq!(property("os"), Some("${os.name}"));
        assert_eq!(property("user"), Some("ci"));
        assert_eq!(property("vendor"), Some("${java.vendor}"));
        assert_eq!(
            property("path").map(str::to_string),
            Some(std::env::var("PATH").unwrap_or_else(|_| "${PATH}".to_string()))
        );
        let activation = profile.activation.as_ref().unwrap();
        assert_eq!(
            activation.property.as_ref().unwrap().value.as_deref(),
            Some("${os.name}")
        );
        for refused in [
            "<settings><activeProfiles><activeProfile>p-${os.name}</activeProfile>\
             </activeProfiles></settings>",
            "<settings><profiles><profile><id>p-${java.version}</id></profile></profiles>\
             </settings>",
            "<settings><profiles><profile><id>p</id><repositories><repository><id>r</id>\
             <url>https://r/${java.vendor}/</url></repository></repositories></profile>\
             </profiles></settings>",
            "<settings><mirrors><mirror><id>m</id><url>https://m/${java.vendor}/</url>\
             <mirrorOf>*</mirrorOf></mirror></mirrors></settings>",
        ] {
            let error = MavenSettings::read(refused, &inputs, None).unwrap_err();
            assert!(
                matches!(error, ConfigError::RefusedSettings(_)),
                "{refused}"
            );
        }
        let named = "<settings><activeProfiles><activeProfile>p-${user.name}-${maven.version}\
                     </activeProfile></activeProfiles></settings>";
        let settings = MavenSettings::read(named, &inputs, None).unwrap();
        assert_eq!(settings.active_profiles.unwrap(), ["p-ci-3.9.12"]);
    }

    /// Of servers with one id Maven keeps the first, even one without
    /// credentials, and Maven 3.10 copies a server onto each `<alias>` in
    /// place, so an alias shadows a later server with its id.
    #[test]
    fn the_first_server_of_an_id_wins_and_maven_310_copies_it_onto_aliases() {
        let server = |id: &str, body: &str| format!("<server><id>{id}</id>{body}</server>");
        let xml = format!(
            "<settings><servers>{}{}{}{}{}{}</servers></settings>",
            server(
                "corp",
                "<username>ci</username><password>current</password>\
                 <aliases><alias> corp-alias </alias></aliases>"
            ),
            server("corp", "<username>old</username><password>stale</password>"),
            server(
                "corp-alias",
                "<username>old</username><password>stale</password>"
            ),
            server("deploy", "<privateKey>/k</privateKey>"),
            server("deploy", "<username>u</username><password>p</password>"),
            server(
                "other",
                "<username>ci</username><password>current</password>"
            ),
        );
        for (mode, ids) in [
            (MavenMode::Maven39, &["corp", "corp-alias", "other"][..]),
            (MavenMode::Maven310, &["corp", "corp-alias", "other"]),
        ] {
            let settings = MavenSettings::read(&xml, &inputs(mode, &[]), None).unwrap();
            let servers = settings.servers.unwrap();
            let found: Vec<_> = servers
                .iter()
                .map(|server| server.id.as_deref().unwrap())
                .collect();
            assert_eq!(found, ids, "{mode:?}");
            for server in &servers {
                let alias =
                    mode == MavenMode::Maven310 || server.id.as_deref() != Some("corp-alias");
                let (username, password) = if alias {
                    ("ci", "current")
                } else {
                    ("old", "stale")
                };
                assert_eq!(server.username.as_deref(), Some(username), "{mode:?}");
                assert_eq!(secret(&server.password), Some(password), "{mode:?}");
            }
        }
    }

    /// Maven 3.10.0 fails on an empty `<alias>`, blank or not, with
    /// "'servers.server[1].aliases[1]' for corp is missing"; Maven 3.9.12
    /// reads no aliases.
    #[test]
    fn maven_310_refuses_an_empty_server_alias() {
        for alias in ["<alias/>", "<alias> </alias>"] {
            let xml = format!(
                "<settings><servers><server><id>other</id></server><server><id>corp</id>\
                 <aliases><alias>a</alias>{alias}</aliases></server></servers></settings>"
            );
            MavenSettings::read(&xml, &inputs(MavenMode::Maven39, &[]), None).unwrap();
            let error = MavenSettings::read(&xml, &inputs(MavenMode::Maven310, &[]), None)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("'servers.server[1].aliases[1]' for corp is missing"),
                "{error}"
            );
        }
    }

    /// Maven keeps the first active proxy and the first mirror of each id,
    /// a proxy without an `<id>` having `default`, so a second proxy
    /// without one is never used.
    #[test]
    fn the_first_proxy_and_mirror_of_an_id_win() {
        let xml = "<settings><proxies>\
            <proxy><active>false</active><protocol>http</protocol><host>off.example</host></proxy>\
            <proxy><protocol>https</protocol><host>first.example</host></proxy>\
            <proxy><protocol>http</protocol><host>second.example</host></proxy>\
            <proxy><id>named</id><protocol>http</protocol><host>named.example</host></proxy>\
            </proxies><mirrors>\
            <mirror><id>m</id><url>https://m1.example/</url><mirrorOf>central</mirrorOf></mirror>\
            <mirror><id>m</id><url>https://m2.example/</url><mirrorOf>corp</mirrorOf></mirror>\
            </mirrors></settings>";
        let settings = MavenSettings::read(xml, &inputs(MavenMode::Maven39, &[]), None).unwrap();
        let hosts: Vec<_> = (settings.proxies.unwrap().iter())
            .map(|proxy| proxy.host.clone())
            .collect();
        assert_eq!(hosts, ["first.example", "named.example"]);
        let mirrors: Vec<_> = (settings.mirrors.unwrap().iter())
            .map(|mirror| mirror.url.clone())
            .collect();
        assert_eq!(mirrors, ["https://m1.example/"]);
    }

    /// Messages, warnings and the seed name an entry by its id, so an id
    /// may not take a value named like a secret.
    #[test]
    fn an_id_taking_a_secret_is_refused() {
        temp_env::with_var("RAEVA_TEST_ID_TOKEN", Some("s3cr3t"), || {
            for xml in [
                "<mirrors><mirror><id>${env.RAEVA_TEST_ID_TOKEN}</id>\
                 <url>https://m.example/</url><mirrorOf>*</mirrorOf></mirror></mirrors>",
                "<servers><server><id>m-${env.RAEVA_TEST_ID_TOKEN}</id>\
                 <username>u</username><password>p</password></server></servers>",
                "<proxies><proxy><id>${env.RAEVA_TEST_ID_TOKEN}</id>\
                 <host>proxy.example</host></proxy></proxies>",
                "<proxies><proxy><host>${env.RAEVA_TEST_ID_TOKEN}</host></proxy></proxies>",
                "<proxies><proxy><host>proxy.example</host>\
                 <protocol>${env.RAEVA_TEST_ID_TOKEN}</protocol></proxy></proxies>",
                "<activeProfiles><activeProfile>${env.RAEVA_TEST_ID_TOKEN}</activeProfile>\
                 </activeProfiles>",
                "<profiles><profile><id>p</id><repositories><repository>\
                 <id>${env.RAEVA_TEST_ID_TOKEN}</id><url>https://r.example/</url>\
                 </repository></repositories></profile></profiles>",
            ] {
                let error = MavenSettings::parse_with_security(
                    &format!("<settings>{xml}</settings>"),
                    None,
                )
                .unwrap_err()
                .to_string();
                assert!(
                    error.contains("${env.RAEVA_TEST_ID_TOKEN}") && !error.contains("s3cr3t"),
                    "{error}"
                );
            }
        });
    }

    /// Maven 3.9 reads `<enabled>` before it interpolates the file, and 3.10
    /// after.
    #[test]
    fn maven_310_expands_a_flag_before_it_reads_it() {
        let xml = "<settings><offline>${on}</offline><profiles><profile><id>p</id>
            <activation><activeByDefault>${on}</activeByDefault></activation>
            <repositories><repository><id>r</id><url>https://r.example/</url>
            <snapshots><enabled>${snap}</enabled></snapshots>
            </repository></repositories></profile></profiles></settings>";
        for (mode, enabled) in [(MavenMode::Maven39, false), (MavenMode::Maven310, true)] {
            let inputs = inputs(mode, &[("snap", "true"), ("on", " true ")]);
            let settings = MavenSettings::read(xml, &inputs, None).unwrap();
            assert_eq!(settings.offline, enabled, "{mode:?}");
            let profile = &settings.profiles.unwrap()[0];
            let activation = profile.activation.as_ref().unwrap();
            assert_eq!(activation.active_by_default, enabled, "{mode:?}");
            assert_eq!(profile.repositories[0].snapshots, Some(enabled), "{mode:?}");
        }
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
              <nonProxyHosts> localhost | *.example.com|</nonProxyHosts>
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
        // Maven trims the element, not the entries it splits it into.
        assert_eq!(proxies[0].non_proxy_hosts, ["localhost ", " *.example.com"]);
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

    /// `<pluginGroups>` are read trimmed, and one that is no groupId, which
    /// would name another path as its group metadata, is refused.
    #[test]
    fn plugin_groups_are_group_ids() {
        let settings = parse(
            "<settings><pluginGroups><pluginGroup> com.example </pluginGroup>\
             </pluginGroups></settings>",
        );
        assert_eq!(settings.plugin_groups, vec!["com.example".to_string()]);
        let refused = MavenSettings::parse_with_security(
            "<settings><pluginGroups><pluginGroup>../x</pluginGroup></pluginGroups></settings>",
            None,
        );
        assert!(matches!(
            refused,
            Err(crate::ConfigError::InvalidSettings(_))
        ));
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
        assert_eq!(profile.id, "dev");
        assert_eq!(profile.repositories[0].id.as_deref(), Some("corp"));
        assert_eq!(settings.active_profiles, Some(vec!["dev".to_string()]));
    }

    /// Maven's settings interpolation drops one leading dot of an
    /// expression, as its model interpolation does.
    #[test]
    fn a_leading_dot_names_the_same_variable() {
        let xml = "<settings>
          <profiles>
            <profile><id>${.env.RAEVA_TEST_DOT_ID}</id></profile>
            <profile><id>${.}</id></profile>
          </profiles>
        </settings>";
        let settings = temp_env::with_vars([("RAEVA_TEST_DOT_ID", Some("dotted"))], || parse(xml));
        let profiles = settings.profiles.as_ref().unwrap();
        assert_eq!(profiles[0].id, "dotted");
        assert_eq!(profiles[1].id, "${.}");
    }

    /// Maven's settings reader trims element text, so a value split over
    /// lines names the same profile, repository or server.
    /// raeva.lock records a repository's expanded URL, so a variable named
    /// like a secret in its path, where some services take a token, is
    /// refused, in every profile, a `file:` directory's too. Another
    /// variable, or one in the host or in a mirror, is not.
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
            // raeva.lock records a `file:` directory too.
            ("file:///srv/m2/${env.REPO_TOKEN}/", "<mirror>"),
            ("file:/srv/m2/${env.REPO_TOKEN}/", "<mirror>"),
            ("FILE:/C:/m2/${env.REPO_TOKEN}/", "<mirror>"),
            // The host, port and userinfo, which raeva.lock records too.
            ("https://${env.REPO_TOKEN}/maven/", "before its path"),
            (
                "https://dl.example:${env.REPO_TOKEN}/maven/",
                "before its path",
            ),
            (
                "https://${env.REPO_TOKEN}@dl.example/maven/",
                "before its path",
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
                remedy != "query or fragment",
                "{repository}: {err}"
            );
        }
        for (repository, mirror) in [
            ("https://${env.REPO_HOST}/maven/", "https://m.example/"),
            (
                "https://git.example/projects/${env.CI_PROJECT_ID}/maven/",
                "https://m.example/",
            ),
            ("file:///${env.REPO_DIR}/maven/", "https://m.example/"),
            (
                "https://dl.example/maven/",
                "https://m.example/${env.REPO_TOKEN}/",
            ),
        ] {
            MavenSettings::parse(&settings(repository, mirror)).expect(repository);
        }
    }

    /// A profile's `<pluginRepositories>` read as its `<repositories>`,
    /// with the same policies and the same refusal of a secret-named
    /// `${env.*}` in the path.
    #[test]
    fn profile_plugin_repositories_read_as_repositories() {
        let settings = parse(
            "<settings><profiles><profile><id>p</id><pluginRepositories>\
             <pluginRepository><id> corp </id><url>https://corp.example/plugins/</url>\
             <releases><updatePolicy>never</updatePolicy></releases>\
             <snapshots><enabled>false</enabled></snapshots></pluginRepository>\
             </pluginRepositories></profile></profiles></settings>",
        );
        let profile = &settings.profiles.unwrap()[0];
        assert!(profile.repositories.is_empty());
        let repo = &profile.plugin_repositories[0];
        assert_eq!(repo.id.as_deref(), Some("corp"));
        assert_eq!(repo.url, "https://corp.example/plugins/");
        assert_eq!((repo.releases, repo.snapshots), (Some(true), Some(false)));
        assert_eq!(repo.releases_update_policy, Some(UpdatePolicy::Never));
        temp_env::with_var("RAEVA_TEST_PLUGIN_TOKEN", Some("t0ken"), || {
            let refused = MavenSettings::parse(
                "<settings><profiles><profile><id>p</id><pluginRepositories>\
                 <pluginRepository><id>corp</id>\
                 <url>https://corp.example/${env.RAEVA_TEST_PLUGIN_TOKEN}/</url>\
                 </pluginRepository></pluginRepositories></profile></profiles></settings>",
            );
            assert!(refused.is_err());
        });
    }

    /// Maven's request takes a settings.xml mirror only when no earlier one
    /// has its id, as interpolated, so of two without an `<id>` it keeps the
    /// first `default` too. The repository the later one names is reached
    /// directly. A token in the dropped mirror's URL stays masked, and the
    /// store names only the mirror that is kept.
    /// A password is hidden before settings.xml can fail with a message
    /// that quotes other text, which may hold it too.
    #[test]
    fn a_password_is_hidden_before_settings_validation_fails() {
        let xml = "<settings><servers><server><id>corp</id><username>u</username>\
                   <password>zqEARLYzq!</password></server></servers><pluginGroups>\
                   <pluginGroup>zqEARLYzq!</pluginGroup></pluginGroups></settings>";
        let inputs = inputs(MavenMode::Maven39, &[]);
        let error = MavenSettings::read(xml, &inputs, None).expect_err("bad pluginGroup");
        let shown = crate::redact::redact_secrets(&error.to_string()).into_owned();
        assert!(
            !shown.contains("zqEARLYzq") && shown.contains("***"),
            "{shown}"
        );
    }

    #[test]
    fn a_mirror_with_an_earlier_mirrors_id_is_dropped() {
        let inputs = inputs(
            MavenMode::Maven39,
            &[("env.DUP_TOKEN", "tok-dup7"), ("dup.id", "d")],
        );
        for (n, id, later) in [
            (1, "<id>d</id>", "<id>d</id>"),
            (2, "<id>d</id>", "<id>${dup.id}</id>"),
            (3, "", ""),
        ] {
            let url = |host: &str| format!("https://{host}{n}.example/${{env.DUP_TOKEN}}/");
            let xml = format!(
                "<settings><mirrors><mirror>{id}<mirrorOf>central</mirrorOf><url>{}</url>\
                 </mirror><mirror>{later}<mirrorOf>other</mirrorOf><url>{}</url></mirror>\
                 <mirror><id>e</id><mirrorOf>third</mirrorOf><url>{}</url></mirror>\
                 </mirrors></settings>",
                url("dupa"),
                url("dupb"),
                url("dupc"),
            );
            let settings = MavenSettings::read(&xml, &inputs, None).unwrap();
            let urls: Vec<_> = (settings.mirrors.unwrap().into_iter())
                .map(|mirror| mirror.url)
                .collect();
            let expanded = |host: &str| format!("https://{host}{n}.example/tok-dup7/");
            assert_eq!(urls, [expanded("dupa"), expanded("dupc")], "{xml}");
            let dropped = expanded("dupb");
            assert_eq!(crate::redact::stored_urls(&dropped), dropped);
            assert!(!crate::redact::redact_secrets(&dropped).contains("tok-dup7"));
            let kept = if id.is_empty() {
                "mirror:default/"
            } else {
                "mirror:d/"
            };
            assert_eq!(crate::redact::stored_urls(&expanded("dupa")), kept);
        }
    }

    /// Maven's settings model names a mirror without an `<id>` `default`, as
    /// it names a server, so the server with that id gives it credentials.
    /// An empty `<id>` on a mirror or a server fails Maven's validation.
    #[test]
    fn a_mirror_without_an_id_is_named_default() {
        let settings = parse(
            "<settings><mirrors><mirror><url>https://mirror.example/</url>\
             <mirrorOf>*</mirrorOf></mirror></mirrors></settings>",
        );
        assert_eq!(settings.mirrors.unwrap()[0].id.as_deref(), Some("default"));
        for (entry, xml) in [
            (
                "mirror",
                "<mirrors><mirror><id> </id><url>https://secret.example/</url>\
                 <mirrorOf>*</mirrorOf></mirror></mirrors>",
            ),
            (
                "mirror",
                "<mirrors><mirror><id></id><url>https://secret.example/</url>\
                 <mirrorOf>*</mirrorOf></mirror></mirrors>",
            ),
            (
                "server",
                "<servers><server><id> </id><username>u</username>\
                 <password>secret-password</password></server></servers>",
            ),
        ] {
            let error = MavenSettings::parse(&format!("<settings>{xml}</settings>"))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!("a <{entry}> has an empty <id>")),
                "{error}"
            );
            assert!(!error.contains("secret"), "{error}");
        }
    }

    /// Maven fails on a profile repository or plugin repository without an
    /// id, or with an empty one, in any profile.
    #[test]
    fn a_profile_repository_without_an_id_is_refused() {
        for (list, entry, id) in [
            ("repositories", "repository", ""),
            ("pluginRepositories", "pluginRepository", ""),
            ("pluginRepositories", "pluginRepository", "<id> </id>"),
        ] {
            let error = MavenSettings::parse(&format!(
                "<settings><profiles><profile><id>idle</id><{list}><{entry}>{id}\
                 <url>https://secret.example/</url></{entry}></{list}></profile></profiles>\
                 </settings>"
            ))
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(&format!("profile 'idle' has a <{entry}> without an <id>")),
                "{error}"
            );
            assert!(!error.contains("secret.example"), "{error}");
        }
        let kept = parse(
            "<settings><profiles><profile><id>p</id><repositories><repository>\
             <id>${env.RAEVA_TEST_DEFINITELY_NOT_SET}</id><url>https://example.com/</url>\
             </repository></repositories></profile></profiles></settings>",
        );
        assert_eq!(kept.profiles.unwrap()[0].repositories.len(), 1);
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
        assert_eq!(profile.id, "corp");
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
                 <id>r</id><url>https://example.com/</url>{inner}</repository></repositories>\
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
                 <host>proxy.example</host><username>proxy-user</username>\
                 <password>{proxy}</password></proxy></proxies>\
                 </settings>"
            )
        };
        let ((), warnings) = crate::test_warnings::capture_warnings(|| {
            let settings = parse(&xml("{EbvSxq8u/P5Y6MJqsF8=}", "{abc123DEF456=}"));
            assert!(settings.servers.unwrap()[0].password.is_none());
            // Not sent as Basic with an empty password.
            let proxy = &settings.proxies.unwrap()[0];
            assert!(proxy.password.is_none() && proxy.username.is_none());
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
            let proxy = &settings.proxies.unwrap()[0];
            assert_eq!(proxy.username.as_deref(), Some("proxy-user"));
            assert_eq!(secret(&proxy.password), Some("pre-${env.HOME}-post"));
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
    fn local_repository_expands_user_home_and_env() {
        let home = std::path::Path::new("/home/user");
        temp_env::with_vars(
            [
                ("RAEVA_TEST_LOCAL_REPO", Some("cache")),
                ("RAEVA_TEST_LOCAL_REPO_UNSET", None),
            ],
            || {
                let host = rv_maven_model::HostSnapshot::for_testing(&[]);
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
                    assert_eq!(expand_local_repository(value, home, &host), expanded);
                }
            },
        );
    }

    /// Maven takes an empty `<localRepository>` as unset.
    #[test]
    fn an_empty_local_repository_is_unset() {
        let settings = parse("<settings><localRepository> </localRepository></settings>");
        assert!(settings.local_repository.is_none());
    }

    #[test]
    fn test_home_hook_redirects_default_settings() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".m2")).unwrap();
        let path = home.path().join(".m2/settings.xml");
        temp_env::with_var(crate::MAVEN_USER_HOME_TEST_ENV, Some(home.path()), || {
            assert_eq!(super::default_settings_path(), Some(path.clone()));
            assert!(
                MavenSettings::load_optional(&path, &SettingsInputs::default())
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
            let settings = MavenSettings::load_optional(&path, &SettingsInputs::default()).unwrap();
            assert_eq!(settings.active_profiles, Some(vec!["hooked".to_string()]));
        });
    }

    /// A `<server>` whose encrypted password does not decrypt answers for
    /// its id with no credential when it has a user name, and is left empty,
    /// so skipped, when it has none; a bearer token keeps it as it is.
    #[test]
    fn a_server_whose_password_drops_keeps_no_credential() {
        let settings = MavenSettings::parse(
            "<settings><servers>\
             <server><id>user</id><username>u</username><password>{COQLCE6DU6GtcS5P=}</password></server>\
             <server><id>only</id><password>{COQLCE6DU6GtcS5P=}</password></server>\
             <server><id>token</id><username>u</username><password>{COQLCE6DU6GtcS5P=}</password>\
             <configuration><httpHeaders><property><name>Authorization</name>\
             <value>Bearer t</value></property></httpHeaders></configuration></server>\
             </servers></settings>",
        )
        .unwrap();
        let servers = settings.servers.unwrap();
        let shape = |entry: &crate::settings::AuthConfig| {
            (
                entry.id.clone().unwrap(),
                entry.username.is_some(),
                entry.password.is_some(),
                entry.token.is_some(),
                entry.password_dropped,
            )
        };
        assert_eq!(
            servers.iter().map(shape).collect::<Vec<_>>(),
            [
                ("user".to_string(), false, false, false, true),
                ("only".to_string(), false, false, false, false),
                ("token".to_string(), true, false, true, false),
            ]
        );
    }

    /// A settings file in a directory that denies the lookup is none, as
    /// `File.exists` reads it for Maven; one Maven finds but cannot read
    /// fails, as Maven fails on it.
    #[cfg(unix)]
    #[test]
    fn a_settings_file_behind_a_closed_directory_is_none() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let m2 = dir.path().join(".m2");
        std::fs::create_dir(&m2).unwrap();
        let path = m2.join("settings.xml");
        std::fs::write(&path, "<settings/>").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        // A process that may override file modes, such as root in a user
        // namespace, reads both anyway.
        if std::fs::read(&path).is_err() {
            let err = super::read_settings_text(&path).unwrap_err();
            assert!(err.starts_with(super::UNREADABLE), "{err}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&m2, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::metadata(&path).is_err() {
            assert_eq!(super::read_settings_text(&path), Ok(None));
        }
        std::fs::set_permissions(&m2, std::fs::Permissions::from_mode(0o755)).unwrap();
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
        let load = |path: &std::path::Path| {
            temp_env::with_var(crate::MAVEN_USER_HOME_TEST_ENV, Some(home.path()), || {
                MavenSettings::load_optional(path, &SettingsInputs::default())
            })
        };
        let settings = load(&path).unwrap();
        let server = &settings.servers.unwrap()[0];
        assert_eq!(secret(&server.password), Some("café"));

        latin1.splice(30..40, *b"Big5");
        std::fs::write(&path, &latin1).unwrap();
        let err = load(&path).unwrap_err().to_string();
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
        let read_port =
            |settings: MavenSettings| settings.proxies.unwrap().first().map(|proxy| proxy.port);
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
            // Maven warns and reads it as 0, so only a fetch through that
            // proxy fails.
            let (settings, warnings) =
                crate::test_warnings::capture_warnings(|| proxy("true", "http", port));
            assert_eq!(read_port(settings), Some(0), "{port:?}");
            assert!(
                warnings.iter().any(|warning| {
                    warning.sec_code.as_deref() == Some("SETTING_IGNORED")
                        && warning.message.contains("<port>")
                }),
                "{port:?}"
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
