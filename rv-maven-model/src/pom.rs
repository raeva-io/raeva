use rv_maven_types::bounded;
use serde::Deserialize;

use crate::dependency::{Dependency, DependencyManagement, deserialize_dependencies};
use crate::profile::Profile;
use crate::properties::PropertyMap;
use crate::repository::{Repository, deserialize_repositories};
use crate::{PomError, Provenance};

/// A license declared in a Maven POM.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct License {
    /// The license name, trimmed by the POM reader.
    pub name: Option<String>,
    /// The license URL, trimmed by the POM reader.
    pub url: Option<String>,
}

/// A POM parent reference (groupId, artifactId, version, optional relativePath).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parent {
    /// The parent's `groupId`, trimmed.
    pub group_id: String,
    /// The parent's `artifactId`, trimmed.
    pub artifact_id: String,
    /// The parent's version, trimmed. Maven does not interpolate it before
    /// the lookup.
    pub version: String,
    /// `<relativePath>` as written: `None` when absent, and an empty string
    /// for `<relativePath/>`, which turns the local lookup off.
    #[serde(default)]
    pub relative_path: Option<String>,
}

/// Artifact relocation metadata from `<distributionManagement><relocation>`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Relocation {
    /// The new `groupId`, or `None` to keep the current one.
    pub group_id: Option<String>,
    /// The new `artifactId`, or `None` to keep the current one.
    pub artifact_id: Option<String>,
    /// The new version, or `None` to keep the current one.
    pub version: Option<String>,
    /// The `<message>` explaining the move.
    pub message: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub(crate) struct DistributionManagement {
    pub relocation: Option<Relocation>,
}

/// The `<build>` values `${project.build.*}` reads, trimmed and not
/// interpolated. Its lists and plugins are not read. A profile's `<build>`
/// sets only `directory`, `finalName` and `defaultGoal`.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct Build {
    pub directory: Option<String>,
    pub final_name: Option<String>,
    pub default_goal: Option<String>,
    pub output_directory: Option<String>,
    pub test_output_directory: Option<String>,
    pub source_directory: Option<String>,
    pub test_source_directory: Option<String>,
    pub script_source_directory: Option<String>,
}

impl Build {
    /// The field names, as `${project.build.NAME}` spells them, in the
    /// order of [`Self::fields`].
    pub(crate) const NAMES: [&'static str; 8] = [
        "directory",
        "finalName",
        "defaultGoal",
        "outputDirectory",
        "testOutputDirectory",
        "sourceDirectory",
        "testSourceDirectory",
        "scriptSourceDirectory",
    ];

    /// The fields a profile's `<build>` sets.
    pub(crate) const PROFILE_NAMES: [&'static str; 3] = ["directory", "finalName", "defaultGoal"];

    pub(crate) fn fields(&self) -> [&Option<String>; 8] {
        [
            &self.directory,
            &self.final_name,
            &self.default_goal,
            &self.output_directory,
            &self.test_output_directory,
            &self.source_directory,
            &self.test_source_directory,
            &self.script_source_directory,
        ]
    }

    fn fields_mut(&mut self) -> [&mut Option<String>; 8] {
        [
            &mut self.directory,
            &mut self.final_name,
            &mut self.default_goal,
            &mut self.output_directory,
            &mut self.test_output_directory,
            &mut self.source_directory,
            &mut self.test_source_directory,
            &mut self.script_source_directory,
        ]
    }

    /// The value of the field `name`, or `None` for a name not in
    /// [`Self::NAMES`].
    pub(crate) fn field(&self, name: &str) -> Option<&Option<String>> {
        let index = Self::NAMES.iter().position(|known| *known == name)?;
        Some(self.fields()[index])
    }

    /// Fill each field `self` does not set from `parent`, as Maven's
    /// inheritance does.
    pub(crate) fn inherit(&mut self, parent: &Build) {
        for (own, inherited) in self.fields_mut().into_iter().zip(parent.fields()) {
            if own.is_none() {
                own.clone_from(inherited);
            }
        }
    }

    /// Put an active profile's `directory`, `finalName` and `defaultGoal`
    /// over this build's.
    pub(crate) fn inject_profile(&mut self, profile: &Build) {
        for (own, injected) in [
            (&mut self.directory, &profile.directory),
            (&mut self.final_name, &profile.final_name),
            (&mut self.default_goal, &profile.default_goal),
        ] {
            if injected.is_some() {
                own.clone_from(injected);
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub(crate) struct Prerequisites {
    pub maven: Option<String>,
}

/// A raw parsed POM (pom.xml) before inheritance or property resolution.
///
/// Use [`crate::Project::build`] to compute the effective model with parent inheritance,
/// property interpolation, profile activation, and BOM imports applied.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Pom {
    pub(crate) model_version: Option<String>,
    /// The `<groupId>`, trimmed and not interpolated. `None` when the POM
    /// inherits it from its parent.
    pub group_id: Option<String>,
    /// The `<artifactId>`, trimmed and not interpolated.
    pub artifact_id: Option<String>,
    /// The `<version>`, trimmed and not interpolated. `None` when the POM
    /// inherits it from its parent.
    pub version: Option<String>,
    /// The `<packaging>`, trimmed. `None` means `jar`.
    pub packaging: Option<String>,
    /// The `<parent>` reference.
    pub parent: Option<Parent>,
    /// The declared licenses. An empty list inherits the parent's licenses.
    #[serde(deserialize_with = "deserialize_licenses")]
    pub licenses: Vec<License>,
    pub(crate) prerequisites: Option<Prerequisites>,
    /// The `<dependencies>`, in declaration order and not interpolated.
    #[serde(deserialize_with = "deserialize_dependencies")]
    pub dependencies: Vec<Dependency>,
    /// The `<dependencyManagement>` section, BOM imports included.
    pub dependency_management: Option<DependencyManagement>,
    pub(crate) distribution_management: Option<DistributionManagement>,
    pub(crate) build: Box<Build>,
    /// The `<properties>`, with any user properties
    /// [`Self::overlay_user_properties`] put over them.
    pub properties: PropertyMap,
    /// The `<profiles>`, in declaration order.
    #[serde(deserialize_with = "deserialize_profiles")]
    pub profiles: Vec<Profile>,
    /// The `<repositories>`, in declaration order.
    #[serde(deserialize_with = "deserialize_repositories")]
    pub repositories: Vec<Repository>,
    /// The `<module>` entries, not interpolated.
    #[serde(deserialize_with = "deserialize_modules")]
    pub modules: Vec<String>,
    /// `<properties>` as written, kept once user properties are overlaid.
    #[serde(skip)]
    pub(crate) own_properties: Option<PropertyMap>,
    #[serde(skip)]
    pub(crate) user_properties: PropertyMap,
    /// The values the model gives the user properties overlaid on it, which
    /// they hide: the POM's own, else its active profiles', else its
    /// parents'.
    #[serde(skip)]
    pub(crate) shadowed_properties: PropertyMap,
    /// The ids of the profiles injected into this model, the POM's own first
    /// and then each parent's, as Maven's `help:active-profiles` lists them,
    /// except a profile that a host value activated and that cannot change
    /// the resolution.
    #[serde(skip)]
    pub(crate) active_profiles: Vec<String>,
    /// The ids of every profile active in each POM of the lineage, the
    /// POM's own first, including those `active_profiles` leaves out.
    #[serde(skip)]
    pub(crate) selected_profiles: Vec<Vec<String>>,
    /// Where the loader read this POM from; see [`Provenance`].
    #[serde(skip)]
    pub(crate) provenance: Option<Provenance>,
    /// `Some` when the build of this effective model went on without a
    /// parent, `Some(true)` when it took its groupId or version from that
    /// `<parent>` element.
    #[serde(skip)]
    pub(crate) unread_parent: Option<bool>,
}

element_list!(fn deserialize_profiles, "profile", Profile);
element_list!(fn deserialize_licenses, "license", License);
element_list!(pub(crate) fn deserialize_modules, "module", String);

impl Pom {
    /// Overlay Maven user properties on this POM's `<properties>`, where
    /// they win over the POM's own values in model interpolation. Profile
    /// activation still reads the properties as written, which Maven
    /// consults before user properties.
    pub fn overlay_user_properties<K, V>(&mut self, properties: impl IntoIterator<Item = (K, V)>)
    where
        K: Into<String>,
        V: Into<String>,
    {
        if self.own_properties.is_none() {
            self.own_properties = Some(self.properties.clone());
        }
        for (key, value) in properties {
            let (key, value) = (key.into(), value.into());
            if let Some(own) = self.declared_properties().get(&key) {
                self.shadowed_properties.insert(key.clone(), own.clone());
            }
            self.user_properties.insert(key.clone(), value.clone());
            self.properties.insert_external(key, value);
        }
    }

    /// Where this POM was read from, when its loader recorded it.
    pub fn provenance(&self) -> Option<&Provenance> {
        self.provenance.as_ref()
    }

    /// Record where this POM was read from. Only the code that read its
    /// bytes calls this; parsing never does.
    pub fn set_provenance(&mut self, provenance: Provenance) {
        self.provenance = Some(provenance);
    }

    /// `<properties>` as written, before any user property overlay.
    pub(crate) fn declared_properties(&self) -> &PropertyMap {
        self.own_properties.as_ref().unwrap_or(&self.properties)
    }

    /// Mark declarations loaded from a user-owned POM. Call only at the local
    /// model boundary, never when decoding repository or lockfile payloads.
    pub fn mark_root_repositories(&mut self) {
        for repo in self.repositories.iter_mut().chain(
            self.profiles
                .iter_mut()
                .flat_map(|profile| profile.repositories.iter_mut()),
        ) {
            repo.root_declared = true;
        }
    }

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

    /// Parse a POM from text already decoded (see [`crate::decode_pom`]).
    ///
    /// A leading byte order mark is dropped, the coordinates are trimmed as
    /// Maven's reader trims them, and the entities Maven knows are expanded.
    /// The POM is refused when it is over 5 MiB, has text before its root
    /// element, has a byte below 0x20 in its own `groupId`, `artifactId`,
    /// `version` or `packaging`, or has more than 10 000 entries in its
    /// `<properties>` or in one profile's. Nothing is inherited or
    /// interpolated.
    pub fn parse(xml: &str) -> Result<Self, PomError> {
        if xml.len() > Self::MAX_SIZE {
            return Err(PomError::Deserialize(quick_xml::de::DeError::Custom(
                "POM file exceeds 5MB limit".to_string(),
            )));
        }

        let root = crate::document::root_element(xml)?;
        let mut deserializer =
            quick_xml::de::Deserializer::from_str_with_resolver(root, crate::xml::MavenEntities);
        let mut pom = Pom::deserialize(&mut deserializer)?;
        pom.trim_text();
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

    /// Trim surrounding whitespace from the element text the model reads, as
    /// Maven's model reader does. This accepts element text split across
    /// lines. Validation checks interior characters.
    fn trim_text(&mut self) {
        trim_opt(&mut self.model_version);
        trim_opt(&mut self.group_id);
        trim_opt(&mut self.artifact_id);
        trim_opt(&mut self.version);
        trim_opt(&mut self.packaging);
        for license in &mut self.licenses {
            trim_opt(&mut license.name);
            trim_opt(&mut license.url);
        }
        if let Some(parent) = &mut self.parent {
            trim_str(&mut parent.group_id);
            trim_str(&mut parent.artifact_id);
            trim_str(&mut parent.version);
            if let Some(relative_path) = &mut parent.relative_path {
                trim_str(relative_path);
            }
        }
        if let Some(relocation) = self
            .distribution_management
            .as_mut()
            .and_then(|dm| dm.relocation.as_mut())
        {
            trim_opt(&mut relocation.group_id);
            trim_opt(&mut relocation.artifact_id);
            trim_opt(&mut relocation.version);
            trim_opt(&mut relocation.message);
        }
        if let Some(prerequisites) = &mut self.prerequisites {
            trim_opt(&mut prerequisites.maven);
        }
        self.build.fields_mut().into_iter().for_each(trim_opt);
        self.properties.values_mut().for_each(trim_str);
        trim_repositories(&mut self.repositories);
        trim_dependencies(&mut self.dependencies);
        if let Some(dm) = &mut self.dependency_management {
            trim_dependencies(&mut dm.dependencies);
        }
        for profile in &mut self.profiles {
            trim_str(&mut profile.id);
            profile.build.fields_mut().into_iter().for_each(trim_opt);
            profile.properties.values_mut().for_each(trim_str);
            trim_repositories(&mut profile.repositories);
            if let Some(activation) = &mut profile.activation {
                trim_activation(activation);
            }
            trim_dependencies(&mut profile.dependencies);
            if let Some(dm) = &mut profile.dependency_management {
                trim_dependencies(&mut dm.dependencies);
            }
        }
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
                    bounded(&profile.id),
                    Self::MAX_PROPERTIES
                )));
            }
        }
        Ok(())
    }

    /// Reject coordinate-bearing fields whose value contains a control
    /// character: C0 (such as NUL), DEL or C1 (such as U+009B, a terminal's
    /// control sequence introducer). Real coordinates are drawn from a
    /// printable subset, so any control character is either a
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
            if let Some(ch) = value.chars().find(|ch| ch.is_control()) {
                return Err(PomError::InvalidModel(format!(
                    "POM </project/{field}> contains a control character (U+{:04X}); \
                     coordinates must be printable text",
                    u32::from(ch)
                )));
            }
        }
        Ok(())
    }
}

/// Trim characters through U+0020, as Java's `String.trim()` does for Maven element text.
fn trim_str(value: &mut String) {
    let trimmed = value.trim_matches(|c| c <= ' ');
    if trimmed.len() != value.len() {
        *value = trimmed.to_owned();
    }
}

fn trim_activation(activation: &mut crate::Activation) {
    if let Some(property) = &mut activation.property {
        trim_opt(&mut property.name);
        trim_opt(&mut property.value);
    }
    if let Some(os) = &mut activation.os {
        trim_opt(&mut os.name);
        trim_opt(&mut os.family);
        trim_opt(&mut os.arch);
        trim_opt(&mut os.version);
    }
    trim_opt(&mut activation.jdk);
    if let Some(file) = &mut activation.file {
        trim_opt(&mut file.exists);
        trim_opt(&mut file.missing);
    }
}

fn trim_opt(value: &mut Option<String>) {
    if let Some(v) = value {
        trim_str(v);
    }
}

fn trim_repositories(repositories: &mut [Repository]) {
    for repo in repositories {
        trim_opt(&mut repo.id);
        trim_str(&mut repo.url);
        trim_opt(&mut repo.releases_enabled_text);
        trim_opt(&mut repo.snapshots_enabled_text);
        trim_opt(&mut repo.releases_checksum_policy);
        trim_opt(&mut repo.snapshots_checksum_policy);
    }
}

fn trim_dependencies(deps: &mut [Dependency]) {
    for dep in deps {
        trim_str(&mut dep.group_id);
        trim_str(&mut dep.artifact_id);
        trim_opt(&mut dep.version);
        trim_opt(&mut dep.type_);
        trim_opt(&mut dep.classifier);
        trim_opt(&mut dep.scope);
        trim_opt(&mut dep.optional);
        trim_opt(&mut dep.system_path);
        for exclusion in &mut dep.exclusions {
            trim_str(&mut exclusion.group_id);
            trim_str(&mut exclusion.artifact_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid_model(xml: &str) -> String {
        match Pom::parse(xml) {
            Err(PomError::InvalidModel(message)) => message,
            other => panic!("expected an invalid model, got {other:?}"),
        }
    }

    /// Maven trims the coordinates, skips a UTF-8 BOM before the root, and
    /// reads a namespace prefix past; plugin configuration is not checked.
    #[test]
    fn parses_a_pom_like_maven() {
        let xml = "\u{FEFF}<p:project xmlns:p='http://maven.apache.org/POM/4.0.0'>\
             <p:groupId>\n    org.osgi\n  </p:groupId><p:artifactId> compendium </p:artifactId>\
             <p:version>\n\t5.0.0\n</p:version><p:packaging>\n jar\n</p:packaging>\
             <p:parent><p:groupId>\n p.g\n</p:groupId><p:artifactId> pa </p:artifactId>\
             <p:version>\n1\n</p:version><p:relativePath>../pom.xml</p:relativePath></p:parent>\
             <p:properties><custom>value</custom></p:properties>\
             <p:dependencies><p:dependency><p:groupId>\n  d.g\n</p:groupId>\
             <p:artifactId>\n d \n</p:artifactId><p:version>\n 2 \n</p:version>\
             <p:type>\n pom\n</p:type><p:classifier>\n c\n</p:classifier>\
             <p:scope>\n test\n</p:scope><p:exclusions><p:exclusion><p:groupId>\n e.g\n\
             </p:groupId><p:artifactId>\n e\n</p:artifactId></p:exclusion></p:exclusions>\
             </p:dependency></p:dependencies>\
             <p:profiles><p:profile><p:id>dev</p:id><p:dependencyManagement><p:dependencies>\
             <p:dependency><p:groupId>m</p:groupId><p:artifactId>m</p:artifactId>\
             </p:dependency></p:dependencies></p:dependencyManagement></p:profile></p:profiles>\
             <p:modules><p:module>module-a</p:module><p:module>module-b</p:module></p:modules>\
             <p:distributionManagement><p:relocation><p:groupId>com.example.new</p:groupId>\
             <p:message>use demo-new</p:message></p:relocation></p:distributionManagement>\
             <p:build><p:pluginManagement><p:plugins><p:plugin><p:configuration>\
             <p:groupId>\n   org.apache.maven.plugins\u{1}\n </p:groupId></p:configuration>\
             </p:plugin></p:plugins></p:pluginManagement></p:build></p:project>";
        let pom = Pom::parse(xml).unwrap();
        let coordinates = [
            &pom.group_id,
            &pom.artifact_id,
            &pom.version,
            &pom.packaging,
        ];
        assert_eq!(
            coordinates.map(|c| c.as_deref()),
            [
                Some("org.osgi"),
                Some("compendium"),
                Some("5.0.0"),
                Some("jar")
            ]
        );
        let parent = pom.parent.unwrap();
        assert_eq!(
            [&parent.group_id, &parent.artifact_id, &parent.version],
            ["p.g", "pa", "1"]
        );
        assert_eq!(parent.relative_path.as_deref(), Some("../pom.xml"));
        assert_eq!(
            pom.properties.get("custom").map(String::as_str),
            Some("value")
        );
        let dep = &pom.dependencies[0];
        assert_eq!(
            [
                &dep.group_id,
                &dep.artifact_id,
                &dep.exclusions[0].group_id,
                &dep.exclusions[0].artifact_id
            ],
            ["d.g", "d", "e.g", "e"]
        );
        let fields = [&dep.version, &dep.type_, &dep.classifier, &dep.scope];
        assert_eq!(
            fields.map(|f| f.as_deref()),
            [Some("2"), Some("pom"), Some("c"), Some("test")]
        );
        let profile_management = pom.profiles[0].dependency_management.as_ref().unwrap();
        assert_eq!(profile_management.dependencies.len(), 1);
        assert_eq!(pom.modules, ["module-a", "module-b"]);
        let relocation = pom.distribution_management.unwrap().relocation.unwrap();
        assert_eq!(relocation.group_id.as_deref(), Some("com.example.new"));
        assert_eq!(relocation.message.as_deref(), Some("use demo-new"));
    }

    /// Maven's reader trims all element text it reads, not only the
    /// coordinates.
    #[test]
    fn element_text_is_trimmed() {
        let pom = Pom::parse(
            "<project><artifactId>a</artifactId><properties><p>\n  v \n</p></properties>\
             <dependencies><dependency><groupId>g</groupId><artifactId>d</artifactId>\
             <optional>\n true\n</optional><scope>system</scope>\
             <systemPath>\n /opt/d.jar\n</systemPath></dependency></dependencies>\
             <repositories><repository><id>\n r\n</id><url>\n https://r.example/\n</url>\
             </repository></repositories><profiles><profile><id>\n ci\n</id>\
             <properties><q> w </q></properties></profile></profiles></project>",
        )
        .unwrap();
        assert_eq!(pom.properties.get("p").map(String::as_str), Some("v"));
        let dep = &pom.dependencies[0];
        assert!(dep.effective_optional());
        assert_eq!(dep.system_path.as_deref(), Some("/opt/d.jar"));
        let repo = &pom.repositories[0];
        assert_eq!(
            (repo.id.as_deref(), repo.url.as_str()),
            (Some("r"), "https://r.example/")
        );
        let profile = &pom.profiles[0];
        assert_eq!(profile.id, "ci");
        assert_eq!(profile.properties.get("q").map(String::as_str), Some("w"));
    }

    /// Maven reads `<activeByDefault>` with `Boolean.valueOf` on the trimmed
    /// text: `true` in any case is true, anything else is false.
    #[test]
    fn active_by_default_reads_like_maven() {
        for (text, active) in [
            ("true", true),
            ("TRUE", true),
            (" True ", true),
            ("false", false),
            ("FALSE", false),
            ("", false),
            ("1", false),
            ("yes", false),
        ] {
            let pom = Pom::parse(&format!(
                "<project><artifactId>a</artifactId><profiles><profile><id>p</id><activation>\
                 <activeByDefault>{text}</activeByDefault></activation></profile></profiles></project>"
            ))
            .unwrap_or_else(|err| panic!("{text:?}: {err}"));
            let activation = pom.profiles[0].activation.as_ref().unwrap();
            assert_eq!(activation.active_by_default, active, "{text:?}");
        }
    }

    #[test]
    fn a_dtd_is_read_past_and_its_entities_are_never_expanded() {
        // Maven's parser skips the DTD without processing it, so an entity
        // it declares, external or internal, is unknown where it is used.
        let cases = [
            r#"<!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <project><groupId>&xxe;</groupId></project>"#,
            r#"<!DOCTYPE project [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>
            <project><groupId>&b;</groupId></project>"#,
            r#"<!DOCTYPE project [<!ENTITY v "1.0">]>
            <project><version>&v;</version></project>"#,
        ];
        for xml in cases {
            let err = Pom::parse(xml).expect_err("a declared entity is unknown");
            assert!(
                err.to_string().contains("unrecognized entity"),
                "got: {err}"
            );
            assert!(err.is_malformed_xml(), "{err:?}");
        }
        let pom = Pom::parse(
            r#"<?xml version="1.0"?>
            <!DOCTYPE project PUBLIC "-//EXAMPLE//DTD//EN" "http://example.invalid/project.dtd" [
              <!ENTITY unused "x">
            ]>
            <project><groupId>g</groupId><artifactId>a&amp;b&#x41;</artifactId></project>"#,
        )
        .expect("a DTD is skipped");
        assert_eq!(pom.artifact_id.as_deref(), Some("a&bA"));
    }

    /// A control character in a coordinate, C0, DEL or C1, is refused up
    /// front with an error naming the field and the code point rather than
    /// carrying it; one inside a value names the element path.
    #[test]
    fn rejects_control_characters_in_coordinates() {
        for (field, bad) in [
            ("groupId", "com.example\u{0}bad"),
            ("groupId", "com.example\u{7f}"),
            ("artifactId", "demo\u{9b}31m"),
            ("version", "1.0\t.0"),
            ("version", "1.0\u{85}"),
            ("packaging", "jar\u{9f}"),
        ] {
            let value = |name: &str, good: &'static str| if name == field { bad } else { good };
            let xml = format!(
                "<project><groupId>{}</groupId><artifactId>{}</artifactId>\
                 <version>{}</version><packaging>{}</packaging></project>",
                value("groupId", "com.example"),
                value("artifactId", "demo"),
                value("version", "1.0.0"),
                value("packaging", "jar"),
            );
            let message = invalid_model(&xml);
            assert!(message.contains(field), "{message}");
            assert!(message.contains("control character (U+00"), "{message}");
            assert!(!message.chars().any(char::is_control), "{message:?}");
        }
        let message = invalid_model(
            "<project><groupId>a\nb</groupId><artifactId>x</artifactId>\
             <version>1</version></project>",
        );
        assert!(message.contains("/project/groupId"), "{message}");
    }

    #[test]
    fn parse_rejects_excessive_properties() {
        let props: String = (0..=Pom::MAX_PROPERTIES)
            .map(|i| format!("<prop{i}>val{i}</prop{i}>"))
            .collect();
        let message = invalid_model(&format!(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <properties>{props}</properties></project>"
        ));
        assert!(message.contains("exceeds the limit"), "{message}");
    }

    /// Maven trims `<relativePath>` like every other element. Surrounding
    /// whitespace must not change the path, and a blank value is the empty
    /// string that turns local parent lookup off.
    #[test]
    fn parent_relative_path_is_trimmed() {
        let pom = Pom::parse(
            "<project><modelVersion>4.0.0</modelVersion>\
             <groupId>g</groupId><artifactId>child</artifactId><version>1</version>\
             <parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
             <relativePath>\n              ../pom.xml\n            </relativePath></parent></project>",
        )
        .unwrap();
        assert_eq!(
            pom.parent.as_ref().unwrap().relative_path.as_deref(),
            Some("../pom.xml")
        );

        let blank = Pom::parse(
            "<project><modelVersion>4.0.0</modelVersion>\
             <groupId>g</groupId><artifactId>child</artifactId><version>1</version>\
             <parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
             <relativePath>  </relativePath></parent></project>",
        )
        .unwrap();
        assert_eq!(
            blank.parent.as_ref().unwrap().relative_path.as_deref(),
            Some("")
        );
    }
}
