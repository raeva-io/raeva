use serde::Deserialize;

use crate::PomError;
use crate::dependency::{Dependency, DependencyManagement, deserialize_dependencies};
use crate::profile::Profile;
use crate::properties::PropertyMap;
use crate::repository::{Repository, deserialize_repositories};

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plugin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    pub artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Extension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    pub artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// The `<pluginManagement>` section of a POM build, providing default versions for plugins.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManagement {
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_plugins"
    )]
    pub plugins: Vec<Plugin>,
}

/// A single `<resource>` (or `<testResource>`) entry from the POM `<build>` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    /// The directory containing the resources (e.g., `src/main/resources`).
    #[serde(default)]
    pub directory: String,
    /// Whether Maven EL property substitution should be applied to this resource directory.
    #[serde(default, deserialize_with = "deserialize_bool_str")]
    pub filtering: bool,
    /// Optional include patterns (e.g., `**/*.properties`).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_include_list"
    )]
    pub includes: Vec<String>,
    /// Optional exclude patterns.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_exclude_list"
    )]
    pub excludes: Vec<String>,
    /// Optional target path within the output directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
}

/// The `<build>` section of a POM, containing plugin declarations.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Build {
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_plugins"
    )]
    pub plugins: Vec<Plugin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_management: Option<PluginManagement>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_extensions"
    )]
    pub extensions: Vec<Extension>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_resources"
    )]
    pub resources: Vec<Resource>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_resources"
    )]
    pub test_resources: Vec<Resource>,
}

fn deserialize_plugins<'de, D>(deserializer: D) -> Result<Vec<Plugin>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(rename = "plugin", default)]
        items: Vec<Plugin>,
    }
    Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.items).unwrap_or_default())
}

fn deserialize_extensions<'de, D>(deserializer: D) -> Result<Vec<Extension>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(rename = "extension", default)]
        items: Vec<Extension>,
    }
    Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.items).unwrap_or_default())
}

fn deserialize_resources<'de, D>(deserializer: D) -> Result<Vec<Resource>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(rename = "resource", default)]
        items: Vec<Resource>,
    }
    Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.items).unwrap_or_default())
}

/// Deserialize a `<filtering>true</filtering>` XML text element as a bool.
fn deserialize_bool_str<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
    Ok(s.trim().eq_ignore_ascii_case("true"))
}

/// Deserialize `<includes><include>…</include></includes>`. Distinct from the
/// exclude variant so a shared wrapper does not merge two disjoint Maven lists.
fn deserialize_include_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(rename = "include", default)]
        items: Vec<String>,
    }
    Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.items).unwrap_or_default())
}

/// Deserialize `<excludes><exclude>…</exclude></excludes>`. See
/// [`deserialize_include_list`] for why they are separate.
fn deserialize_exclude_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(rename = "exclude", default)]
        items: Vec<String>,
    }
    Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.items).unwrap_or_default())
}

/// A POM parent reference (groupId, artifactId, version, optional relativePath).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parent {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_path: Option<String>,
}

/// Artifact relocation metadata from `<distributionManagement><relocation>`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Relocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Distribution management metadata from a POM.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DistributionManagement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relocation: Option<Relocation>,
}

/// A raw parsed POM (pom.xml) before inheritance or property resolution.
///
/// Use `Project::from_pom()` to compute the effective model with parent inheritance,
/// property interpolation, profile activation, and BOM imports applied.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packaging: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Parent>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_dependencies"
    )]
    pub dependencies: Vec<Dependency>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_management: Option<DependencyManagement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) distribution_management: Option<DistributionManagement>,
    #[serde(default, skip_serializing_if = "PropertyMap::is_empty")]
    pub properties: PropertyMap,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_profiles"
    )]
    pub profiles: Vec<Profile>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_repositories"
    )]
    pub repositories: Vec<Repository>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_modules"
    )]
    pub modules: Vec<String>,
    /// The `<build>` section. NOTE (#22): this is parsed and inheritance-merged
    /// (see `merge_build` in [`crate::inheritance`]) so that plugin-version
    /// inheritance and resource declarations are modelled correctly, but the
    /// `<build>` section is deliberately NOT carried into the effective
    /// [`crate::Project`] model. Raeva resolves dependencies and lockfiles,
    /// not build execution, so plugins/resources have no consumer in v1. The
    /// parse and merge stay in place because the field is `pub(crate)` state
    /// an effective-model consumer may surface later, and dropping it would
    /// delete the only coverage of plugin-management inheritance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) build: Option<Build>,
}

fn deserialize_profiles<'de, D>(deserializer: D) -> Result<Vec<Profile>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(rename = "profile", default)]
        items: Vec<Profile>,
    }
    Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.items).unwrap_or_default())
}

fn deserialize_modules<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(rename = "module", default)]
        items: Vec<String>,
    }
    Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.items).unwrap_or_default())
}

impl Pom {
    /// Upper bound on parseable POM size. Real-world POMs sit well under
    /// 200 KiB; 5 MiB is generous headroom that still keeps a hostile or
    /// malformed input from exhausting memory.
    const MAX_SIZE: usize = 5 * 1024 * 1024;

    /// Upper bound on the number of `<properties>` entries accepted from a
    /// single POM. A 5 MiB POM stuffed with `<p>val</p>` entries can produce
    /// hundreds of thousands of map entries; property interpolation then walks
    /// that map for every dependency, turning a single hostile POM into a
    /// CPU-exhaustion vector. Real-world POMs rarely exceed 200 entries; 10 000
    /// gives comfortable headroom for generated POMs while capping the attack
    /// surface.
    const MAX_PROPERTIES: usize = 10_000;

    pub fn parse(xml: &str) -> Result<Self, PomError> {
        if xml.len() > Self::MAX_SIZE {
            return Err(PomError::Deserialize(quick_xml::de::DeError::Custom(
                "POM file exceeds 5MB limit".to_string(),
            )));
        }

        // Files saved on Windows (Notepad, certain Maven tools) frequently
        // begin with a UTF-8 BOM (`\u{FEFF}`). quick-xml does not strip it
        // and fails with a leading-whitespace error, so we peel it off here
        // before any other parsing logic runs.
        let xml = strip_utf8_bom(xml);
        Self::reject_doctype(xml)?;
        let pom: Pom = quick_xml::de::from_str(xml)?;
        // A coordinate field carrying a NUL byte (or any other ASCII
        // control character) sails through XML deserialization but then
        // fails downstream when the value gets re-serialized into TOML for
        // the lockfile with a low-level `invalid character` message. Reject
        // up front with a precise pointer at the offending field so callers
        // get an actionable error rather than a confusing TOML-serialize
        // failure.
        pom.validate_coord_fields()?;
        pom.validate_properties_count()?;
        Ok(pom)
    }

    /// Reject POMs with an unreasonably large `<properties>` section.
    ///
    /// Counts entries in the POM's own properties map and in every profile's
    /// properties map. A profile that contributes 10 001 properties is just as
    /// dangerous as a top-level section of the same size.
    fn validate_properties_count(&self) -> Result<(), PomError> {
        let pom_count = self.properties.iter().count();
        if pom_count > Self::MAX_PROPERTIES {
            return Err(PomError::InvalidModel(format!(
                "POM <properties> block contains {pom_count} entries, \
                 which exceeds the limit of {} (potential DoS); \
                 split the project or reduce the property count",
                Self::MAX_PROPERTIES
            )));
        }
        for profile in &self.profiles {
            let profile_count = profile.properties.iter().count();
            if profile_count > Self::MAX_PROPERTIES {
                return Err(PomError::InvalidModel(format!(
                    "POM profile '{}' <properties> block contains {profile_count} entries, \
                     which exceeds the limit of {} (potential DoS)",
                    profile.id,
                    Self::MAX_PROPERTIES
                )));
            }
        }
        Ok(())
    }

    /// Reject coordinate-bearing fields whose value contains an ASCII
    /// control character (bytes `< 0x20`, e.g. NUL). Real coordinates are
    /// drawn from a printable subset, so any control byte is either a
    /// truncation/garbage marker or a deliberate attempt to smuggle a value
    /// past downstream layers that assume well-formed text. The TOML
    /// serializer used by the lockfile rejects most of these bytes anyway,
    /// but with a low-level "invalid character" message that points nowhere
    /// useful; failing here gives the caller a precise field name.
    fn validate_coord_fields(&self) -> Result<(), PomError> {
        let coord_fields: [(&str, Option<&str>); 4] = [
            ("groupId", self.group_id.as_deref()),
            ("artifactId", self.artifact_id.as_deref()),
            ("version", self.version.as_deref()),
            ("packaging", self.packaging.as_deref()),
        ];
        for (field, value) in coord_fields {
            let Some(value) = value else {
                continue;
            };
            if let Some(byte) = value.as_bytes().iter().find(|b| **b < 0x20).copied() {
                return Err(PomError::InvalidModel(format!(
                    "POM <{field}> contains a control character (byte 0x{byte:02x}); \
                     coordinates must be printable text"
                )));
            }
        }
        Ok(())
    }

    /// Reject any document containing a DOCTYPE declaration. quick-xml does not
    /// resolve entities, so the practical XXE risk on the deserializer is low,
    /// but rejecting DOCTYPE outright keeps an attacker from getting the parser
    /// to do *any* DTD-related work and is a defence-in-depth measure.
    ///
    /// We hand-roll a byte-level prologue scan instead of spinning up a
    /// quick-xml Reader. Driving the full event machinery just to look at the
    /// first non-comment, non-PI markup would double the work that
    /// `quick_xml::de::from_str` already does. Here we step through the
    /// prologue (comments, processing instructions, the XML declaration,
    /// whitespace) until we either hit `<!DOCTYPE` (reject) or the first
    /// element start tag (accept).
    fn reject_doctype(xml: &str) -> Result<(), PomError> {
        let bytes = xml.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            // Skip whitespace between tags.
            if bytes[i].is_ascii_whitespace() {
                i += 1;
                continue;
            }
            // Anything other than `<` here means we're already inside text
            // content or hit malformed input; let quick-xml handle the
            // diagnostics.
            if bytes[i] != b'<' {
                return Ok(());
            }
            // Look at the byte after `<` to discriminate prologue items.
            let Some(&next) = bytes.get(i + 1) else {
                return Ok(());
            };
            match next {
                b'?' => {
                    // XML/PI declaration `<?...?>`: skip to the closing `?>`.
                    if let Some(end) = find_subsequence(&bytes[i + 2..], b"?>") {
                        i += 2 + end + 2;
                        continue;
                    }
                    return Ok(());
                }
                b'!' => {
                    // Could be a comment, CDATA, or DOCTYPE.
                    if bytes.get(i + 2..i + 4).is_some_and(|s| s == b"--") {
                        // Comment `<!--...-->`.
                        if let Some(end) = find_subsequence(&bytes[i + 4..], b"-->") {
                            i += 4 + end + 3;
                            continue;
                        }
                        return Ok(());
                    }
                    // DOCTYPE detection is case-insensitive: XML reserves
                    // `DOCTYPE` as upper-case but real-world inputs (and
                    // hostile fuzzers) sometimes lowercase or title-case it.
                    if bytes
                        .get(i + 2..i + 9)
                        .is_some_and(|s| s.eq_ignore_ascii_case(b"DOCTYPE"))
                    {
                        return Err(PomError::Deserialize(quick_xml::de::DeError::Custom(
                            "POM contains a DTD, which is not allowed for security reasons"
                                .to_string(),
                        )));
                    }
                    // Any other `<!...>` markup: bail and let quick-xml deal.
                    return Ok(());
                }
                _ => {
                    // First real element tag: prologue is done, no DOCTYPE.
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// Find the first occurrence of `needle` inside `haystack`, returning its
/// byte offset. Uses the standard library window scan; needles are tiny
/// (two or three bytes), so this is faster than pulling in a search
/// algorithm crate.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Strip a leading UTF-8 BOM. quick-xml otherwise rejects the document as
/// unexpected text before the root element, and Windows-written POMs (Notepad,
/// some Maven plugins) routinely include it.
fn strip_utf8_bom(s: &str) -> &str {
    s.strip_prefix('\u{FEFF}').unwrap_or(s)
}

pub(crate) fn parse_bool(value: &str) -> Result<bool, PomError> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(PomError::InvalidBoolean(value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_pom() {
        let xml = r"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <packaging>jar</packaging>
          <properties>
            <revision>1.0.0</revision>
            <custom>value</custom>
          </properties>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>org.sample</groupId>
                <artifactId>managed</artifactId>
                <version>${revision}</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>managed</artifactId>
            </dependency>
          </dependencies>
          <repositories>
            <repository>
              <id>central</id>
              <url>https://repo1.maven.org/maven2</url>
            </repository>
          </repositories>
          <profiles>
            <profile>
              <id>dev</id>
              <activation>
                <activeByDefault>true</activeByDefault>
              </activation>
              <dependencies>
                <dependency>
                  <groupId>org.sample</groupId>
                  <artifactId>dev-only</artifactId>
                  <version>1.2.3</version>
                </dependency>
              </dependencies>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>org.sample</groupId>
                    <artifactId>managed-dev</artifactId>
                    <version>9.9.9</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>
            </profile>
          </profiles>
          <modules>
            <module>module-a</module>
            <module>module-b</module>
          </modules>
        </project>
        ";

        let pom = Pom::parse(xml).unwrap();
        assert_eq!(pom.group_id.as_deref(), Some("com.example"));
        assert_eq!(pom.artifact_id.as_deref(), Some("demo"));
        assert_eq!(pom.version.as_deref(), Some("1.0.0"));
        assert_eq!(pom.packaging.as_deref(), Some("jar"));
        assert_eq!(pom.dependencies.len(), 1);
        assert_eq!(
            pom.dependency_management
                .as_ref()
                .unwrap()
                .dependencies
                .len(),
            1
        );
        assert_eq!(
            pom.properties.get("custom").map(String::as_str),
            Some("value")
        );
        assert_eq!(pom.repositories.len(), 1);
        assert_eq!(pom.profiles.len(), 1);
        assert_eq!(
            pom.profiles[0]
                .dependency_management
                .as_ref()
                .map(|management| management.dependencies.len()),
            Some(1)
        );
        assert_eq!(pom.modules, vec!["module-a", "module-b"]);
    }

    #[test]
    fn parses_parent() {
        let xml = r"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <parent>
            <groupId>org.base</groupId>
            <artifactId>parent</artifactId>
            <version>1.0.0</version>
            <relativePath>../pom.xml</relativePath>
          </parent>
          <artifactId>child</artifactId>
        </project>
        ";
        let pom = Pom::parse(xml).unwrap();
        let parent = pom.parent.unwrap();
        assert_eq!(parent.group_id, "org.base");
        assert_eq!(parent.relative_path.as_deref(), Some("../pom.xml"));
    }

    #[test]
    fn parses_distribution_management_relocation() {
        let xml = r"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <distributionManagement>
            <relocation>
              <groupId>com.example.new</groupId>
              <artifactId>demo-new</artifactId>
              <version>2.0.0</version>
              <message>use demo-new</message>
            </relocation>
          </distributionManagement>
        </project>
        ";

        let pom = Pom::parse(xml).unwrap();
        let relocation = pom
            .distribution_management
            .as_ref()
            .and_then(|dm| dm.relocation.as_ref())
            .expect("relocation");
        assert_eq!(relocation.group_id.as_deref(), Some("com.example.new"));
        assert_eq!(relocation.artifact_id.as_deref(), Some("demo-new"));
        assert_eq!(relocation.version.as_deref(), Some("2.0.0"));
        assert_eq!(relocation.message.as_deref(), Some("use demo-new"));
    }

    #[test]
    fn parses_namespaced_pom() {
        let xml = r"
        <p:project xmlns:p='http://maven.apache.org/POM/4.0.0'>
          <p:modelVersion>4.0.0</p:modelVersion>
          <p:groupId>com.example</p:groupId>
          <p:artifactId>namespaced</p:artifactId>
          <p:version>1.0.0</p:version>
        </p:project>
        ";
        let pom = Pom::parse(xml).unwrap();
        assert_eq!(pom.group_id.as_deref(), Some("com.example"));
        assert_eq!(pom.artifact_id.as_deref(), Some("namespaced"));
    }

    #[test]
    fn rejects_doctype_variants() {
        // DTDs must be rejected to block XXE; cover lower/upper/mixed-case forms.
        let cases = [
            r#"<!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <project><groupId>&xxe;</groupId></project>"#,
            r#"<!doctype project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <project><groupId>&xxe;</groupId></project>"#,
            r#"<!DocType project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <project><groupId>&xxe;</groupId></project>"#,
        ];
        for xml in cases {
            let err = Pom::parse(xml).expect_err("DOCTYPE must be rejected");
            assert!(
                err.to_string().contains("DTD, which is not allowed"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn parses_build_resources() {
        let xml = r#"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <build>
            <resources>
              <resource>
                <directory>src/main/resources</directory>
                <filtering>true</filtering>
              </resource>
              <resource>
                <directory>src/main/config</directory>
                <filtering>false</filtering>
              </resource>
            </resources>
          </build>
        </project>
        "#;
        let pom = Pom::parse(xml).unwrap();
        let build = pom.build.as_ref().expect("build section");
        assert_eq!(build.resources.len(), 2);
        let r0 = &build.resources[0];
        assert_eq!(r0.directory, "src/main/resources");
        assert!(r0.filtering, "first resource should have filtering=true");
        let r1 = &build.resources[1];
        assert_eq!(r1.directory, "src/main/config");
        assert!(!r1.filtering, "second resource should have filtering=false");
    }

    #[test]
    fn parses_build_test_resources() {
        let xml = r#"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <build>
            <testResources>
              <resource>
                <directory>src/test/resources</directory>
                <filtering>true</filtering>
              </resource>
            </testResources>
          </build>
        </project>
        "#;
        let pom = Pom::parse(xml).unwrap();
        let build = pom.build.as_ref().expect("build section");
        assert_eq!(build.test_resources.len(), 1);
        assert_eq!(build.test_resources[0].directory, "src/test/resources");
        assert!(build.test_resources[0].filtering);
    }

    #[test]
    fn parses_pom_with_utf8_bom() {
        // Files saved on Windows (Notepad, certain Maven plugins) prepend
        // a UTF-8 BOM. quick-xml rejects the BOM outright, so `Pom::parse`
        // must strip it before deserializing.
        let xml = "\u{FEFF}<project>\
          <modelVersion>4.0.0</modelVersion>\
          <groupId>com.example</groupId>\
          <artifactId>demo</artifactId>\
          <version>1.0.0</version>\
        </project>";
        let pom = Pom::parse(xml).expect("BOM-prefixed POM should parse");
        assert_eq!(pom.group_id.as_deref(), Some("com.example"));
        assert_eq!(pom.artifact_id.as_deref(), Some("demo"));
    }

    /// A NUL byte (or any control character) inside a coordinate must be
    /// rejected up front with a specific field-named error, not surface
    /// later as an opaque TOML-serialize failure.
    #[test]
    fn rejects_nul_byte_in_group_id() {
        let xml = "<project>\
                   <modelVersion>4.0.0</modelVersion>\
                   <groupId>com.example\u{0}bad</groupId>\
                   <artifactId>demo</artifactId>\
                   <version>1.0.0</version>\
                   </project>";
        let err = Pom::parse(xml).expect_err("NUL in groupId must be rejected");
        match err {
            PomError::InvalidModel(msg) => {
                assert!(msg.contains("groupId"), "error must name the field: {msg}");
                assert!(
                    msg.contains("control character"),
                    "error must describe the cause: {msg}"
                );
            }
            other => panic!("expected InvalidModel, got {other:?}"),
        }
    }

    /// A tab in `<version>` is a non-printable control byte and must be
    /// rejected on parse rather than leaking into downstream consumers.
    #[test]
    fn rejects_tab_in_version() {
        let xml = "<project>\
                   <modelVersion>4.0.0</modelVersion>\
                   <groupId>com.example</groupId>\
                   <artifactId>demo</artifactId>\
                   <version>1.0\t.0</version>\
                   </project>";
        let err = Pom::parse(xml).expect_err("tab in version must be rejected");
        match err {
            PomError::InvalidModel(msg) => {
                assert!(msg.contains("version"), "error must name the field: {msg}");
            }
            other => panic!("expected InvalidModel, got {other:?}"),
        }
    }

    #[test]
    fn resource_filtering_defaults_to_false() {
        let xml = r#"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <build>
            <resources>
              <resource>
                <directory>src/main/resources</directory>
              </resource>
            </resources>
          </build>
        </project>
        "#;
        let pom = Pom::parse(xml).unwrap();
        let build = pom.build.as_ref().expect("build section");
        assert_eq!(build.resources.len(), 1);
        assert!(
            !build.resources[0].filtering,
            "filtering should default to false"
        );
    }

    /// a POM with more than `MAX_PROPERTIES` entries in its
    /// `<properties>` block must be rejected at parse time with a clear
    /// `InvalidModel` error, not silently allowed to produce a
    /// potentially-huge `PropertyMap`.
    #[test]
    fn parse_rejects_excessive_properties() {
        // Build a POM XML with MAX_PROPERTIES + 1 entries.
        let mut props = String::new();
        for i in 0..=Pom::MAX_PROPERTIES {
            props.push_str(&format!("<prop{i}>val{i}</prop{i}>"));
        }
        let xml = format!(
            r#"<project>
              <groupId>com.example</groupId>
              <artifactId>demo</artifactId>
              <version>1.0</version>
              <properties>{props}</properties>
            </project>"#
        );

        let err = Pom::parse(&xml).expect_err("POM with >MAX_PROPERTIES entries must be rejected");
        match err {
            crate::PomError::InvalidModel(msg) => {
                assert!(
                    msg.contains("exceeds the limit"),
                    "error message must mention the limit, got: {msg}"
                );
            }
            other => panic!("expected InvalidModel, got: {other:?}"),
        }
    }
}
