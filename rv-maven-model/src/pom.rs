use rv_maven_types::bounded;
use serde::Deserialize;

use crate::dependency::{Dependency, DependencyManagement, deserialize_dependencies};
use crate::plugin::{BuildPlugins, PluginSource};
use crate::profile::Profile;
use crate::properties::PropertyMap;
use crate::repository::{Repository, deserialize_repositories};
use crate::{PomError, Provenance};

/// A POM's own `<pluginRepositories>`, and each of its profiles', in order.
pub(crate) type PluginRepositoryLists = (Vec<Repository>, Vec<Vec<Repository>>);

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
#[serde(default, rename_all = "camelCase")]
pub(crate) struct DistributionManagement {
    pub relocation: Option<Relocation>,
    pub repository: Option<DeploymentRepository>,
    pub snapshot_repository: Option<DeploymentRepository>,
}

/// A `<repository>` or `<snapshotRepository>` of `<distributionManagement>`,
/// read only for the id Maven validates.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub(crate) struct DeploymentRepository {
    pub id: Option<String>,
}

impl DistributionManagement {
    /// The repository ids of `management` over those of `recessive`, as
    /// Maven merges a parent's or a profile's: an id one lacks comes from
    /// the other. The relocation stays `management`'s.
    pub(crate) fn merge_ids(management: Option<Self>, recessive: Option<&Self>) -> Option<Self> {
        let Some(recessive) = recessive else {
            return management;
        };
        let mut merged = management.unwrap_or_default();
        for (slot, other) in [
            (&mut merged.repository, &recessive.repository),
            (
                &mut merged.snapshot_repository,
                &recessive.snapshot_repository,
            ),
        ] {
            let Some(id) = other.as_ref().and_then(|repository| repository.id.as_ref()) else {
                continue;
            };
            let repository = slot.get_or_insert_default();
            if repository.id.is_none() {
                repository.id = Some(id.clone());
            }
        }
        Some(merged)
    }

    /// Each deployment repository id with its field, as Maven names it.
    pub(crate) fn repository_ids(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("distributionManagement.repository.id", &self.repository),
            (
                "distributionManagement.snapshotRepository.id",
                &self.snapshot_repository,
            ),
        ]
        .into_iter()
        .filter_map(|(field, repository)| Some((field, repository.as_ref()?.id.as_deref()?)))
    }
}

/// The model fields Maven's interpolation reads by name, `${project.NAME}`,
/// `${pom.NAME}` or `${NAME}`: the `<build>` values and
/// `<reporting><outputDirectory>`, trimmed and not interpolated.
/// [`BuildPlugins`] holds the plugin sections, read only for a project
/// build. A profile's `<build>` sets only `directory`, `finalName` and
/// `defaultGoal`.
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
    /// Not a `<build>` element: [`Pom::parse`] moves it here from
    /// `<reporting>`.
    #[serde(
        rename = "reporting.outputDirectory",
        skip_serializing_if = "Option::is_none"
    )]
    pub reporting_output_directory: Option<String>,
    /// Nor these: [`Pom::parse`] moves the project's plain text fields
    /// here, which no profile sets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inception_year: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    #[serde(rename = "organization.name", skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
    #[serde(rename = "organization.url", skip_serializing_if = "Option::is_none")]
    pub organization_url: Option<String>,
    /// Whether the POM declares `<organization>`, empty or not: Maven then
    /// inherits none of its parent's.
    #[serde(skip)]
    pub organization: bool,
}

/// Whether `name`, after `project.` or `pom.`, reaches a field of Maven's
/// model that raeva does not read, such as `url` or `build.plugins`: a list,
/// an object, or `url`, which a module inherits with its own path added.
/// Maven's interpolation reads the model ahead of the properties, so a
/// property of that name does not give Maven's value. A name no getter of
/// the model reads, such as `build.sourceEncoding`, is left to the
/// properties, as Maven leaves it.
pub(crate) fn is_unread_model_field(name: &str) -> bool {
    // A getter of a field's value, such as `name.empty`, which Maven reads
    // from the `String`.
    if (Build::FIELDS.iter())
        .any(|field| (name.strip_prefix(field.name)).is_some_and(|rest| rest.starts_with('.')))
    {
        return true;
    }
    let (first, second) = match name.split_once('.') {
        Some((first, rest)) => (first, rest.split('.').next()),
        None => (name, None),
    };
    // Getters of `Parent`, `Prerequisites`, `Organization`, `Build` and
    // `Reporting` that neither `resolve_builtin` nor [`Build::FIELDS`] reads.
    let unread: &[&str] = match first {
        "parent" => &["relativePath", "id"],
        "prerequisites" | "organization" => &[],
        "build" => &[
            "resources",
            "testResources",
            "filters",
            "extensions",
            "plugins",
            "pluginManagement",
            "pluginsAsMap",
        ],
        "reporting" => &["excludeDefaults", "plugins", "reportPluginsAsMap"],
        _ => {
            return [
                "url",
                "licenses",
                "developers",
                "contributors",
                "mailingLists",
                "modules",
                "scm",
                "issueManagement",
                "ciManagement",
                "distributionManagement",
                "dependencyManagement",
                "dependencies",
                "repositories",
                "pluginRepositories",
                "reports",
                "profiles",
                "id",
                "pomFile",
                "projectDirectory",
                "modelEncoding",
                "childProjectUrlInheritAppendPath",
            ]
            .contains(&first);
        }
    };
    second.is_none_or(|second| unread.contains(&second))
}

/// A model field [`Build`] holds, as Maven's interpolation reads it.
pub(crate) struct ModelField {
    /// The name after `project.`, as `${project.build.directory}` spells it.
    pub name: &'static str,
    /// The super POM's value, which every lineage inherits where none of
    /// its POMs sets one.
    pub super_pom: Option<&'static str>,
    /// Whether Maven's path translator aligns the value to the project
    /// directory: `AbstractStringBasedModelInterpolator`'s
    /// `TRANSLATED_PATH_EXPRESSIONS`, all of them.
    pub translated: bool,
    /// How a module takes its parent's value.
    pub inherited: Inheritance,
    /// Whether a profile's `<build>` or `<reporting>` sets it.
    pub profile: bool,
    /// Keeps a field out of reach of a literal outside this module, so
    /// every one is in [`Build::FIELDS`].
    _sealed: (),
}

/// How Maven's inheritance fills a [`ModelField`] a module does not set.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inheritance {
    /// From the parent.
    Inherited,
    /// Not at all: `<name>` and `<modelVersion>`.
    NotInherited,
    /// With the parent's whole `<organization>`, where the module declares
    /// none.
    WithOrganization,
}

impl Build {
    /// The fields, in the order of [`Self::fields`].
    pub(crate) const FIELDS: [ModelField; 15] = [
        ModelField::path("build.directory", Some("${project.basedir}/target")).in_profiles(),
        ModelField::text(
            "build.finalName",
            Some("${project.artifactId}-${project.version}"),
        )
        .in_profiles(),
        ModelField::text("build.defaultGoal", None).in_profiles(),
        ModelField::path(
            "build.outputDirectory",
            Some("${project.build.directory}/classes"),
        ),
        ModelField::path(
            "build.testOutputDirectory",
            Some("${project.build.directory}/test-classes"),
        ),
        ModelField::path(
            "build.sourceDirectory",
            Some("${project.basedir}/src/main/java"),
        ),
        ModelField::path(
            "build.testSourceDirectory",
            Some("${project.basedir}/src/test/java"),
        ),
        ModelField::path(
            "build.scriptSourceDirectory",
            Some("${project.basedir}/src/main/scripts"),
        ),
        ModelField::path(
            "reporting.outputDirectory",
            Some("${project.build.directory}/site"),
        )
        .in_profiles(),
        ModelField::plain("name", Inheritance::NotInherited),
        ModelField::plain("description", Inheritance::Inherited),
        ModelField::plain("inceptionYear", Inheritance::Inherited),
        ModelField::plain("modelVersion", Inheritance::NotInherited),
        ModelField::plain("organization.name", Inheritance::WithOrganization),
        ModelField::plain("organization.url", Inheritance::WithOrganization),
    ];

    /// The field `name` names, as [`ModelField::name`] spells it.
    pub(crate) fn model_field(name: &str) -> Option<&'static ModelField> {
        Self::FIELDS.iter().find(|field| field.name == name)
    }

    pub(crate) fn fields(&self) -> [&Option<String>; 15] {
        [
            &self.directory,
            &self.final_name,
            &self.default_goal,
            &self.output_directory,
            &self.test_output_directory,
            &self.source_directory,
            &self.test_source_directory,
            &self.script_source_directory,
            &self.reporting_output_directory,
            &self.name,
            &self.description,
            &self.inception_year,
            &self.model_version,
            &self.organization_name,
            &self.organization_url,
        ]
    }

    fn fields_mut(&mut self) -> [&mut Option<String>; 15] {
        [
            &mut self.directory,
            &mut self.final_name,
            &mut self.default_goal,
            &mut self.output_directory,
            &mut self.test_output_directory,
            &mut self.source_directory,
            &mut self.test_source_directory,
            &mut self.script_source_directory,
            &mut self.reporting_output_directory,
            &mut self.name,
            &mut self.description,
            &mut self.inception_year,
            &mut self.model_version,
            &mut self.organization_name,
            &mut self.organization_url,
        ]
    }

    /// The value of `field`, one of [`Self::FIELDS`], the only ones there
    /// are: a name finds its field through [`Self::model_field`].
    pub(crate) fn value(&self, field: &ModelField) -> &Option<String> {
        let index = (Self::FIELDS.iter())
            .position(|known| known.name == field.name)
            .expect("a field of Build::FIELDS");
        self.fields()[index]
    }

    /// Fill each field `self` does not set from `parent`, as Maven's
    /// inheritance does.
    pub(crate) fn inherit(&mut self, parent: &Build) {
        let organization = !self.organization && parent.organization;
        let fields = self.fields_mut().into_iter().zip(parent.fields());
        for ((own, inherited), field) in fields.zip(&Self::FIELDS) {
            let take = match field.inherited {
                Inheritance::Inherited => own.is_none(),
                Inheritance::NotInherited => false,
                Inheritance::WithOrganization => organization,
            };
            if take {
                own.clone_from(inherited);
            }
        }
        self.organization |= parent.organization;
    }

    /// This build without the plain text fields, which a replayed lookup
    /// does without.
    pub(crate) fn without_project_text(&self) -> Build {
        let mut build = self.clone();
        build.take_project_text(None);
        build
    }

    /// Take the plain text fields from `pom`, which reads them outside
    /// `<build>`; a profile, `None`, sets none of them.
    fn take_project_text(&mut self, pom: Option<&mut Pom>) {
        let Some(pom) = pom else {
            *self = Self {
                name: None,
                description: None,
                inception_year: None,
                model_version: None,
                organization_name: None,
                organization_url: None,
                organization: false,
                ..std::mem::take(self)
            };
            return;
        };
        self.name = pom.name.take();
        self.description = pom.description.take();
        self.inception_year = pom.inception_year.take();
        self.model_version.clone_from(&pom.model_version);
        let organization = pom.organization.take();
        self.organization = organization.is_some();
        (self.organization_name, self.organization_url) = organization
            .map_or((None, None), |organization| {
                (organization.name, organization.url)
            });
    }

    /// Put the fields an active profile sets over this build's.
    pub(crate) fn inject_profile(&mut self, profile: &Build) {
        let fields = self.fields_mut().into_iter().zip(profile.fields());
        for ((own, injected), field) in fields.zip(&Self::FIELDS) {
            if field.profile && injected.is_some() {
                own.clone_from(injected);
            }
        }
    }
}

impl ModelField {
    const fn path(name: &'static str, super_pom: Option<&'static str>) -> Self {
        Self {
            name,
            super_pom,
            translated: true,
            inherited: Inheritance::Inherited,
            profile: false,
            _sealed: (),
        }
    }

    const fn text(name: &'static str, super_pom: Option<&'static str>) -> Self {
        Self {
            name,
            super_pom,
            translated: false,
            inherited: Inheritance::Inherited,
            profile: false,
            _sealed: (),
        }
    }

    const fn in_profiles(self) -> Self {
        Self {
            profile: true,
            ..self
        }
    }

    const fn plain(name: &'static str, inherited: Inheritance) -> Self {
        Self {
            name,
            super_pom: None,
            translated: false,
            inherited,
            profile: false,
            _sealed: (),
        }
    }
}

/// `<organization>`, read only for the [`Build`] fields it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub(crate) struct Organization {
    #[serde(deserialize_with = "deserialize_text")]
    pub name: Option<String>,
    #[serde(deserialize_with = "deserialize_text")]
    pub url: Option<String>,
}

/// The text of a plain text field, `None` where it holds markup: Maven's
/// reader refuses that, and raeva, which reads the field only for
/// `${project.x}`, keeps the POM as it did before it read the field.
fn deserialize_text<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    struct Text;
    impl<'de> serde::de::Visitor<'de> for Text {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("text")
        }

        fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
            Ok(Some(text.to_owned()))
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Some(String::new()))
        }

        // An element's text comes as its `$text` entry and its attributes
        // as `@` ones; any other entry is markup.
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut text = Some(String::new());
            while let Some(key) = map.next_key::<String>()? {
                if key.starts_with('@') {
                    map.next_value::<serde::de::IgnoredAny>()?;
                } else if key == "$text" {
                    let part = map.next_value::<String>()?;
                    if let Some(text) = &mut text {
                        text.push_str(&part);
                    }
                } else {
                    map.next_value::<serde::de::IgnoredAny>()?;
                    text = None;
                }
            }
            Ok(text)
        }
    }
    deserializer.deserialize_any(Text)
}

/// `<reporting>`, read only for the [`Build`] field it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct Reporting {
    pub output_directory: Option<String>,
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
    pub(crate) reporting: Reporting,
    /// Moved to [`Build`] when parsed, with `inceptionYear` and
    /// `organization`.
    #[serde(deserialize_with = "deserialize_text")]
    pub(crate) name: Option<String>,
    #[serde(deserialize_with = "deserialize_text")]
    pub(crate) description: Option<String>,
    #[serde(deserialize_with = "deserialize_text")]
    pub(crate) inception_year: Option<String>,
    pub(crate) organization: Option<Organization>,
    /// The plugins, managed plugins and extensions of `<build>`, empty
    /// until [`Self::load_plugins`] reads them; for a project build, merged
    /// with its parents' and active profiles'.
    #[serde(skip)]
    pub(crate) plugins: Option<Box<BuildPlugins>>,
    /// The text [`Self::load_plugins`] reads the plugin sections from.
    #[serde(skip)]
    pub(crate) plugin_source: PluginSource,
    /// The `<pluginRepositories>`, in declaration order, read with
    /// [`Self::plugins`]; for a project build, merged as it is.
    #[serde(skip)]
    pub(crate) plugin_repositories: Vec<Repository>,
    /// Set by [`Self::mark_root_repositories`], for the plugin
    /// repositories read later.
    #[serde(skip)]
    pub(crate) root_declared: bool,
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
    /// The `<relativePath>` as written, `Some` once
    /// [`Self::anchor_relative_path`] replaced it with a resolved path.
    #[serde(skip)]
    pub(crate) written_relative_path: Option<Option<String>>,
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

    /// Read the plugin sections of this POM and of its profiles into
    /// [`Self::plugins`] and each [`Profile`]'s, once. A POM that
    /// [`Self::parse_with_plugins`] did not make has none to read.
    pub(crate) fn load_plugins(&mut self) -> Result<(), PomError> {
        let source = match std::mem::replace(&mut self.plugin_source, PluginSource::Read) {
            PluginSource::Kept(source) => source,
            PluginSource::Read => return Ok(()),
            PluginSource::Dropped => {
                self.plugin_source = PluginSource::Dropped;
                return Err(PomError::InvalidModel(
                    "the POM was read without its plugin sections".to_string(),
                ));
            }
        };
        let (own, profiles) = crate::plugin::read_sections(&source)?;
        self.plugins = Some(Box::new(own.0));
        self.plugin_repositories = own.1;
        for (profile, (plugins, repositories)) in self.profiles.iter_mut().zip(profiles) {
            profile.plugins = Some(Box::new(plugins));
            profile.plugin_repositories = repositories;
        }
        if self.root_declared {
            self.mark_root_repositories();
        }
        Ok(())
    }

    /// Read only the `<pluginRepositories>` of this POM and of its profiles,
    /// for a model built without its plugin sections. Sections that do not
    /// parse give none.
    pub(crate) fn load_plugin_repositories(&mut self) {
        let Ok(Some((own, profiles))) = self.plugin_repository_lists() else {
            return;
        };
        self.plugin_repositories = own;
        for (profile, repositories) in self.profiles.iter_mut().zip(profiles) {
            profile.plugin_repositories = repositories;
        }
        if self.root_declared {
            self.mark_root_repositories();
        }
    }

    /// Whether this POM keeps its plugin sections, read or not.
    pub fn keeps_plugin_sections(&self) -> bool {
        !matches!(self.plugin_source, PluginSource::Dropped)
    }

    /// The `<pluginRepositories>` of this POM and of each of its profiles,
    /// read from the kept text without loading the plugin sections; `None`
    /// for a POM read without them. Fails where the sections do not parse.
    pub fn plugin_repository_lists(&self) -> Result<Option<PluginRepositoryLists>, PomError> {
        match &self.plugin_source {
            PluginSource::Dropped => Ok(None),
            PluginSource::Read => Ok(Some((
                self.plugin_repositories.clone(),
                (self.profiles.iter())
                    .map(|profile| profile.plugin_repositories.clone())
                    .collect(),
            ))),
            PluginSource::Kept(source) => {
                let (own, profiles) = crate::plugin::read_sections(source)?;
                let profiles = profiles.into_iter().map(|(_, repositories)| repositories);
                Ok(Some((own.1, profiles.collect())))
            }
        }
    }

    /// The `(groupId, artifactId)`, as written, of each build plugin and
    /// build extension this POM or one of its profiles declares without a
    /// version; `None` for a POM read without its plugin sections.
    pub fn unversioned_plugins(&self) -> Result<Option<Vec<(String, String)>>, PomError> {
        let read;
        let sections: Vec<&BuildPlugins> = match &self.plugin_source {
            PluginSource::Dropped => return Ok(None),
            PluginSource::Read => (self.plugins.iter().map(Box::as_ref))
                .chain(
                    self.profiles
                        .iter()
                        .flat_map(|profile| profile.plugins.as_deref()),
                )
                .collect(),
            PluginSource::Kept(source) => {
                read = crate::plugin::read_sections(source)?;
                std::iter::once(&read.0.0)
                    .chain(read.1.iter().map(|(plugins, _)| plugins))
                    .collect()
            }
        };
        let mut unversioned = Vec::new();
        for section in sections {
            let plugins = (section.plugins.iter())
                .filter(|plugin| plugin.version.is_none())
                .map(|plugin| (plugin.group_id.clone(), plugin.artifact_id.clone()));
            let extensions = (section.extensions.iter())
                .filter(|extension| extension.version.is_none())
                .map(|extension| (extension.group_id.clone(), extension.artifact_id.clone()));
            unversioned.extend(plugins.chain(extensions));
        }
        Ok(Some(unversioned))
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

    /// Replace the `<relativePath>` with `path`, resolved by the code that
    /// read this POM, and keep the text as written for the checks Maven
    /// makes on it.
    pub fn anchor_relative_path(&mut self, path: String) {
        if let Some(parent) = &mut self.parent {
            let written = parent.relative_path.replace(path);
            self.written_relative_path.get_or_insert(written);
        }
    }

    /// The `<relativePath>` as written, before any anchoring.
    pub(crate) fn written_relative_path(&self) -> Option<&str> {
        match &self.written_relative_path {
            Some(written) => written.as_deref(),
            None => self.parent.as_ref()?.relative_path.as_deref(),
        }
    }

    /// `<properties>` as written, before any user property overlay.
    pub(crate) fn declared_properties(&self) -> &PropertyMap {
        self.own_properties.as_ref().unwrap_or(&self.properties)
    }

    /// Mark declarations loaded from a user-owned POM. Call only at the local
    /// model boundary, never when decoding repository or lockfile payloads.
    pub fn mark_root_repositories(&mut self) {
        self.root_declared = true;
        let profiles = self.profiles.iter_mut();
        let repositories = profiles.flat_map(|profile| {
            (profile.repositories.iter_mut()).chain(profile.plugin_repositories.iter_mut())
        });
        for repo in (self.repositories.iter_mut())
            .chain(self.plugin_repositories.iter_mut())
            .chain(repositories)
        {
            repo.root_declared = true;
        }
    }

    /// Upper bound on parseable POM size. Real-world POMs sit well under
    /// 200 KiB; 5 MiB is generous headroom that still keeps a hostile or
    /// malformed input from exhausting memory.
    pub(crate) const MAX_SIZE: usize = 5 * 1024 * 1024;

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
    /// interpolated, and the plugin sections are not kept.
    pub fn parse(xml: &str) -> Result<Self, PomError> {
        Self::read(xml, false)
    }

    /// [`Self::parse`], keeping the text of the plugin sections for a
    /// build with [`crate::ModelPolicy::PROJECT_PLUGINS`].
    pub fn parse_with_plugins(xml: &str) -> Result<Self, PomError> {
        Self::read(xml, true)
    }

    fn read(xml: &str, plugins: bool) -> Result<Self, PomError> {
        if xml.len() > Self::MAX_SIZE {
            return Err(PomError::Deserialize(quick_xml::de::DeError::Custom(
                "POM file exceeds 5MB limit".to_string(),
            )));
        }

        let root = crate::document::root_element(xml)?;
        let mut deserializer =
            quick_xml::de::Deserializer::from_str_with_resolver(root, crate::xml::MavenEntities);
        let mut pom = Pom::deserialize(&mut deserializer)?;
        if plugins {
            pom.plugin_source = PluginSource::Kept(root.into());
        }
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
        if let Some(management) = &mut self.distribution_management {
            for repository in [
                &mut management.repository,
                &mut management.snapshot_repository,
            ]
            .into_iter()
            .flatten()
            {
                trim_opt(&mut repository.id);
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
        self.build.reporting_output_directory = self.reporting.output_directory.take();
        let mut build = std::mem::take(&mut self.build);
        build.take_project_text(Some(self));
        self.build = build;
        self.build.fields_mut().into_iter().for_each(trim_opt);
        self.properties.values_mut().for_each(trim_str);
        trim_repositories(&mut self.repositories);
        trim_dependencies(&mut self.dependencies);
        if let Some(dm) = &mut self.dependency_management {
            trim_dependencies(&mut dm.dependencies);
        }
        for profile in &mut self.profiles {
            trim_str(&mut profile.id);
            profile.build.reporting_output_directory = profile.reporting.output_directory.take();
            profile.build.take_project_text(None);
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
pub(crate) fn trim_str(value: &mut String) {
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

pub(crate) fn trim_opt(value: &mut Option<String>) {
    if let Some(v) = value {
        trim_str(v);
    }
}

pub(crate) fn trim_repositories(repositories: &mut [Repository]) {
    for repo in repositories {
        trim_opt(&mut repo.id);
        trim_str(&mut repo.url);
        trim_opt(&mut repo.releases_enabled_text);
        trim_opt(&mut repo.snapshots_enabled_text);
        trim_opt(&mut repo.releases_checksum_policy);
        trim_opt(&mut repo.snapshots_checksum_policy);
    }
}

pub(crate) fn trim_dependencies(deps: &mut [Dependency]) {
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

    /// `<reporting><outputDirectory>` is read as a model field beside the
    /// `<build>` ones, in a profile too; a `<build>` element of its name is
    /// not Maven's and is not read.
    #[test]
    fn the_reporting_directory_is_a_model_field() {
        let pom = Pom::parse(
            "<project><artifactId>a</artifactId><build><reporting.outputDirectory>b\
             </reporting.outputDirectory></build><reporting><outputDirectory>\n r \n\
             </outputDirectory></reporting><profiles><profile><reporting>\
             <outputDirectory>p</outputDirectory></reporting></profile></profiles></project>",
        )
        .unwrap();
        assert_eq!(pom.build.reporting_output_directory, Some("r".into()));
        let profile = &pom.profiles[0].build;
        assert_eq!(profile.reporting_output_directory.as_deref(), Some("p"));
        let pom = Pom::parse(
            "<project><artifactId>a</artifactId><build><reporting.outputDirectory>b\
             </reporting.outputDirectory></build></project>",
        )
        .unwrap();
        assert_eq!(pom.build.reporting_output_directory, None);
    }

    /// The plain text fields are read from the project, trimmed, never from
    /// `<build>` or a profile, and a description with markup in it does not
    /// cost the POM.
    #[test]
    fn the_plain_text_fields_are_read_from_the_project() {
        let pom = Pom::parse(
            "<project><modelVersion>4.0.0</modelVersion><artifactId>a</artifactId>\
             <name> n </name><description>d<!-- c -->e</description>\
             <inceptionYear>2001</inceptionYear><organization/><build><name>b</name>\
             <description>b</description></build><profiles><profile><build><name>p</name>\
             </build></profile></profiles></project>",
        )
        .unwrap();
        let build = &pom.build;
        assert_eq!(build.name.as_deref(), Some("n"));
        assert_eq!(build.description.as_deref(), Some("de"));
        assert_eq!(build.inception_year.as_deref(), Some("2001"));
        assert_eq!(build.model_version.as_deref(), Some("4.0.0"));
        assert!(build.organization);
        assert_eq!(build.organization_name, None);
        assert_eq!(pom.profiles[0].build.name, None);
        let pom = Pom::parse(
            "<project><artifactId>a</artifactId><build><name>b</name></build>\
             <description>a <b>bold</b> one</description></project>",
        );
        let pom = pom.unwrap();
        assert_eq!(pom.build.name, None);
        assert!(!pom.build.organization);
        let pom = Pom::parse(
            "<project><modelVersion>4.0.0</modelVersion><artifactId>a</artifactId>\
             <name xml:lang=\"en\">n</name><description>d</description></project>",
        )
        .unwrap();
        assert_eq!(pom.build.name.as_deref(), Some("n"));
        // A replayed lookup, which the lock keeps, holds none of them.
        let plain = Pom::parse("<project><artifactId>a</artifactId></project>").unwrap();
        assert_eq!(
            crate::ModelLookup::new(&pom, None),
            crate::ModelLookup::new(&plain, None)
        );
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
