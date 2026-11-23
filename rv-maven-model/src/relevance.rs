//! Which profiles can change what a resolution sees.
//!
//! A profile that a host value activates (a `<jdk>` condition, or a
//! `<property>` condition on `java.version`, `java.home` or `env.NAME`) is a
//! resolution input only when the profile brings something resolution
//! reads: dependencies, managed dependencies, repositories, modules of a
//! project build, or a property or `<build>` value that one of those reads.
//! In a project build, the classifier likes os-maven-plugin reads count too.
//! A profile that only configures the build or its plugins otherwise gives
//! the same resolution on every JDK, so its condition is neither recorded
//! nor part of the model inputs.
//!
//! In a dependency's model, a test, provided or optional dependency never
//! reaches resolution: Maven leaves it out of the graph before it applies
//! dependency management. Such a declaration counts only when it can change
//! one that does reach resolution, by having its group and artifact id. A
//! management entry there counts only when it imports a BOM or manages a
//! declaration that reaches resolution, since only the project's own
//! management applies to the rest of the graph. An imported BOM's
//! management becomes the importer's, so all of it counts. A declaration
//! that may fail Maven's validation always counts, since that failure costs
//! the whole POM its dependencies; a `system` one at a path under
//! `${java.home}` never fails it, whether or not the file exists, unless a
//! `-D` or POM property sets `java.home` or another entry shares its key.

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};

use crate::dependency::{Dependency, DependencyManagement, Exclusion};
use crate::plugin::{BuildPlugins, ConfigNode, Plugin};
use crate::pom::Build;
use crate::properties::{PropertyMap, expression_names};
use crate::repository::Repository;
use crate::{ActivationContext, PluginModel, Pom, Profile, Relocation, Scope};

const LIKES: &str = "os.detection.classifierWithLikes";

/// What a lineage is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LineageRole {
    Project,
    Dependency,
    Import,
}

#[derive(Debug)]
pub(crate) struct ResolutionKeys {
    names: HashSet<String>,
    role: LineageRole,
    /// For a project build that keeps its plugin model, the `g:a` of each
    /// plugin the lineage declares outside its profiles or binds by its
    /// packaging; `None` otherwise.
    plugins: Option<HashSet<String>>,
    /// When only a profile that changes the build extensions counts, the
    /// `g:a` of each plugin the lineage gives an `<extensions>` value
    /// anywhere.
    extensions: Option<HashSet<String>>,
    /// The artifact ids, by group id, of the dependency declarations in the
    /// lineage that reach resolution. A declaration with the same ids that
    /// does not reach it can still change one that does, since merging
    /// declarations of one key takes the scope and optional flag of either.
    reaching: HashMap<String, HashSet<String>>,
    all_reach: bool,
    /// The `(groupId, artifactId)` of each declaration that cannot fail
    /// Maven's validation although it is in `system` scope; see
    /// [`system_under_java_home`].
    valid_system: HashSet<(String, String)>,
    /// The names that a declaration's version or type reads which no
    /// definition can make empty, see [`filled`].
    filled: Filled,
    /// The `(groupId, artifactId, type, classifier)`, as written, of each
    /// key whose version the lineage's management fills whichever profiles
    /// activate, see [`ResolutionKeys::managed_versions`].
    managed_versions: HashSet<(String, String, String, String)>,
}

/// Whether `keys` holds the plugin `key`, a `groupId:artifactId` that may
/// be written with `${...}`, as [`same_key`] compares them.
fn holds_key(keys: &HashSet<String>, key: &str) -> bool {
    keys.contains(key) || keys.iter().any(|known| same_key(known, key))
}

/// Whether two plugin keys may name one plugin once the model interpolates
/// them: a part written with `${...}` on either side may be any value.
fn same_key(a: &str, b: &str) -> bool {
    let part = |a: &str, b: &str| a == b || a.contains("${") || b.contains("${");
    match (a.split_once(':'), b.split_once(':')) {
        (Some((a_group, a_artifact)), Some((b_group, b_artifact))) => {
            part(a_group, b_group) && part(a_artifact, b_artifact)
        }
        _ => a == b,
    }
}

impl ResolutionKeys {
    fn new(role: LineageRole) -> Self {
        Self {
            names: HashSet::new(),
            role,
            plugins: None,
            extensions: None,
            reaching: HashMap::new(),
            all_reach: true,
            valid_system: HashSet::new(),
            filled: Filled::default(),
            managed_versions: HashSet::new(),
        }
    }

    /// The keys of `chain`, the POMs of one lineage built for `role`,
    /// before their profiles are injected.
    ///
    /// Only a profile with a condition or a project build with settings.xml
    /// profile properties needs keys; any other lineage gets none.
    ///
    /// In a project build that keeps its plugin model, a profile that
    /// changes the plugins the build resolves counts too, or with
    /// [`PluginModel::Extensions`] one that changes its build extensions.
    pub(crate) fn of_lineage(
        chain: &[Pom],
        ctx: &ActivationContext,
        role: LineageRole,
        plugins: PluginModel,
    ) -> Self {
        let mut keys = Self::new(role);
        let conditional = chain.iter().flat_map(|pom| &pom.profiles).any(|profile| {
            profile.activation.as_ref().is_some_and(|activation| {
                activation.jdk.is_some()
                    || activation.property.is_some()
                    || activation.os.is_some()
                    || activation.file.is_some()
            })
        });
        let has_settings_properties =
            role == LineageRole::Project && !ctx.settings_property_names.is_empty();
        if !conditional && !has_settings_properties {
            return keys;
        }
        // Every definition a lineage can give a name: the POMs' own and
        // their profiles' properties, and the settings, user and system
        // properties.
        let mut definitions: HashMap<&str, Vec<&str>> = HashMap::new();
        let maps = chain.iter().flat_map(|pom| {
            std::iter::once(&pom.properties).chain(pom.profiles.iter().map(|p| &p.properties))
        });
        let model = maps
            .chain(std::iter::once(&ctx.settings_properties))
            .flat_map(PropertyMap::iter);
        for (key, value) in model.chain(ctx.properties.iter().chain(&ctx.system_properties)) {
            definitions.entry(key).or_default().push(value);
        }
        // The plugin reads the project's own likes, even under a user
        // property of that name.
        if role == LineageRole::Project {
            for pom in chain {
                if let Some(likes) = pom.declared_properties().get(LIKES) {
                    definitions.entry(LIKES).or_default().push(likes);
                }
            }
        }
        // And every value a model field can take, the super POM's too.
        let mut build: HashMap<&str, Vec<&str>> = HashMap::new();
        let builds = chain.iter().flat_map(|pom| {
            std::iter::once(&pom.build).chain(pom.profiles.iter().map(|p| &p.build))
        });
        for fields in builds.map(|build| build.fields()) {
            for (field, value) in Build::FIELDS.iter().zip(fields) {
                if let Some(value) = value {
                    build.entry(field.name).or_default().push(value);
                }
            }
        }
        for field in &Build::FIELDS {
            if let Some(value) = field.super_pom {
                build.entry(field.name).or_default().push(value);
            }
        }
        if role != LineageRole::Project {
            keys.all_reach = false;
            keys.filled = filled(chain, &definitions, &build);
            keys.managed_versions = keys.managed_versions(chain);
            keys.valid_system = valid_system(chain, ctx);
            // A `-D` that later sets `java.home` can make such a path
            // relative, so the lock records that none does where a profile
            // that may activate holds one.
            let skips_files = ctx.repository_model();
            let may_activate = |profile: &&Profile| {
                ctx.active_profiles.contains(&profile.id)
                    || profile.activation.as_ref().is_some_and(|activation| {
                        activation.active_by_default
                            || activation.jdk.is_some()
                            || activation.property.is_some()
                            || activation.os.is_some()
                            || (activation.file.is_some() && !skips_files)
                    })
            };
            let held = (chain.iter().flat_map(|pom| &pom.profiles))
                .filter(may_activate)
                .flat_map(|profile| &profile.dependencies)
                .any(|dependency| keys.is_valid_system(dependency));
            if held {
                ctx.environment.record_user_property("java.home");
            }
            let declarations = chain.iter().flat_map(|pom| {
                (pom.profiles.iter())
                    .flat_map(|profile| {
                        (profile.dependencies.iter())
                            .map(|dependency| (Some(&*profile.id), dependency))
                    })
                    .chain(pom.dependencies.iter().map(|dependency| (None, dependency)))
            });
            for (profile, dependency) in declarations {
                if keys.left_out(dependency, profile) {
                    continue;
                }
                if dependency.group_id.contains("${") || dependency.artifact_id.contains("${") {
                    keys.all_reach = true;
                    break;
                }
                keys.reaching
                    .entry(dependency.group_id.clone())
                    .or_default()
                    .insert(dependency.artifact_id.clone());
            }
        }
        let mut pending = Vec::new();
        for pom in chain {
            keys.read_pom_fields(pom, &mut pending);
            for profile in &pom.profiles {
                keys.read_content(
                    Some(&profile.id),
                    &profile.dependencies,
                    profile.dependency_management.as_ref(),
                    &profile.repositories,
                    &profile.modules,
                    &mut pending,
                );
            }
        }
        if plugins.reads_plugins() && role == LineageRole::Project {
            keys.read_plugin_sections(chain, ctx, plugins == PluginModel::Extensions, &mut pending);
        }
        // Only the input POM's: Maven does not inherit `<prerequisites>`.
        let prerequisites =
            (chain.first()).and_then(|pom| pom.prerequisites.as_ref()?.maven.as_deref());
        let drain = |keys: &mut Self, pending: &mut Vec<String>| {
            while let Some(name) = pending.pop() {
                for value in definitions.get(name.as_str()).into_iter().flatten() {
                    keys.read(value, pending);
                }
                if matches!(
                    name.as_str(),
                    "project.prerequisites.maven" | "pom.prerequisites.maven"
                ) && let Some(value) = prerequisites
                {
                    keys.read(value, pending);
                }
                for value in build_field(&name)
                    .and_then(|field| build.get(field))
                    .into_iter()
                    .flatten()
                {
                    keys.read(value, pending);
                }
            }
        };
        drain(&mut keys, &mut pending);
        let pom_reads_likes = keys.names.contains(LIKES);
        if role == LineageRole::Project {
            // os-maven-plugin reads this from the first sorted project, and
            // every model's `os.detected.classifier` takes its suffix.
            keys.read(&format!("${{{LIKES}}}"), &mut pending);
            drain(&mut keys, &mut pending);
        }
        if has_settings_properties {
            for name in &ctx.settings_property_names {
                // A `-D` value hides a settings value. The plugin's read of
                // the likes counts only once a build reads the classifier,
                // and the search for them records it then.
                if keys.names.contains(name)
                    && !ctx.properties.contains_key(name)
                    && (name != LIKES || pom_reads_likes)
                {
                    ctx.environment
                        .record(crate::HostInput::SettingsProperty(name.clone()));
                }
            }
        }
        keys
    }

    pub(crate) fn is_relevant(&self, profile: &Profile) -> bool {
        let Profile {
            id: _,
            activation: _,
            dependencies,
            dependency_management,
            repositories,
            modules,
            properties,
            build,
            // Parsing moved its one field into `build`.
            reporting: _,
            // Only validation reads it.
            distribution_management: _,
            // Dependency resolution reads no plugin section.
            plugins: _,
            plugin_repositories: _,
        } = profile;
        dependencies
            .iter()
            .any(|dependency| self.reaches(dependency, Some(&profile.id)))
            || dependency_management.as_ref().is_some_and(|management| {
                management
                    .dependencies
                    .iter()
                    .any(|managed| self.manages(managed))
            })
            || !repositories.is_empty()
            || (self.role == LineageRole::Project && !modules.is_empty())
            || properties.iter().any(|(key, _)| self.names.contains(key))
            || (Build::FIELDS.iter()).any(|field| {
                field.profile
                    && build.value(field).is_some()
                    && ["project.", "pom.", ""]
                        .into_iter()
                        .any(|prefix| self.names.contains(&format!("{prefix}{}", field.name)))
            })
            || self.changes_plugins(profile)
    }

    /// Whether `profile` changes what a build that locks its plugins
    /// resolves: it declares plugin repositories, a default goal, a plugin
    /// the build would not run otherwise, or for a plugin the build runs,
    /// or manages one for, a version, dependencies, an `<extensions>` value
    /// or a parameter plugin resolution reads. One that only configures a
    /// plugin the build runs anyway does not.
    fn changes_plugins(&self, profile: &Profile) -> bool {
        let Some(known) = &self.plugins else {
            return false;
        };
        if let Some(marked) = &self.extensions {
            let changes = |plugin: &Plugin| {
                holds_key(marked, &plugin.key())
                    && (plugin.version.is_some() || plugin.extensions.is_some())
            };
            return !profile.plugin_repositories.is_empty()
                || profile.plugins.as_deref().is_some_and(|sections| {
                    (sections.plugins.iter()).any(|plugin| {
                        changes(plugin)
                            || (holds_key(marked, &plugin.key()) && !known.contains(&plugin.key()))
                    }) || sections.plugin_management.iter().any(changes)
                });
        }
        let changes = |plugin: &Plugin| {
            plugin.version.is_some()
                || !plugin.dependencies.is_empty()
                || plugin.extensions.is_some()
                || plugin.resolved_parameters().next().is_some()
        };
        let runs = |sections: &BuildPlugins, plugin: &Plugin| {
            let key = plugin.key();
            holds_key(known, &key)
                || (sections.plugins.iter()).any(|own| same_key(&own.key(), &key))
        };
        !profile.plugin_repositories.is_empty()
            || profile.build.default_goal.is_some()
            || profile.plugins.as_deref().is_some_and(|sections| {
                (sections.plugins.iter())
                    .any(|plugin| changes(plugin) || !known.contains(&plugin.key()))
                    || (sections.plugin_management.iter())
                        .any(|plugin| changes(plugin) && runs(sections, plugin))
            })
    }

    /// Note the names the plugin sections of `chain` read where they can
    /// change what the build resolves, and the plugins it runs outside its
    /// profiles.
    fn read_plugin_sections(
        &mut self,
        chain: &[Pom],
        ctx: &ActivationContext,
        extensions: bool,
        pending: &mut Vec<String>,
    ) {
        let mut known: HashSet<String> = HashSet::new();
        fn sections(pom: &Pom) -> impl Iterator<Item = &BuildPlugins> {
            let profiles = (pom.profiles.iter()).filter_map(|profile| profile.plugins.as_deref());
            pom.plugins.as_deref().into_iter().chain(profiles)
        }
        if extensions {
            let marked = (chain.iter().flat_map(sections))
                .flat_map(|sections| sections.plugins.iter().chain(&sections.plugin_management))
                .filter(|plugin| plugin.extensions.is_some());
            self.extensions = Some(marked.map(Plugin::key).collect());
        }
        let packaging = (chain.first()).and_then(|pom| pom.packaging.as_deref());
        let mode = ctx.environment.maven_mode();
        let bound = crate::plugin::lifecycle::lifecycle_plugins(packaging.unwrap_or("jar"), mode);
        let release = crate::plugin::lifecycle::super_pom_release_plugins(ctx);
        let release = release.map(|(plugins, _)| plugins).unwrap_or_default();
        known.extend((bound.into_iter().flatten().chain(release)).map(|plugin| plugin.key()));
        for pom in chain {
            let own = pom.plugins.as_deref();
            known.extend((own.into_iter()).flat_map(|own| own.plugins.iter().map(Plugin::key)));
            for sections in sections(pom) {
                let plugins = sections.plugins.iter().chain(&sections.plugin_management);
                for plugin in plugins {
                    if (self.extensions.as_ref())
                        .is_some_and(|marked| !holds_key(marked, &plugin.key()))
                    {
                        continue;
                    }
                    self.read(&plugin.group_id, pending);
                    self.read(&plugin.artifact_id, pending);
                    for value in [&plugin.version, &plugin.extensions].into_iter().flatten() {
                        self.read(value, pending);
                    }
                    if self.extensions.is_some() {
                        continue;
                    }
                    self.read_declarations(&plugin.dependencies, |_, _| true, pending);
                    for parameter in plugin.resolved_parameters() {
                        self.read_parameter(parameter, pending);
                    }
                }
                for extension in &sections.extensions {
                    self.read(&extension.group_id, pending);
                    self.read(&extension.artifact_id, pending);
                    if let Some(version) = &extension.version {
                        self.read(version, pending);
                    }
                }
            }
            let repositories =
                (pom.profiles.iter()).flat_map(|profile| &profile.plugin_repositories);
            let repositories: Vec<Repository> = pom
                .plugin_repositories
                .iter()
                .chain(repositories)
                .cloned()
                .collect();
            self.read_repositories(&repositories, pending);
            if let Some(goal) = pom.build.default_goal.as_ref()
                && self.extensions.is_none()
            {
                self.read(goal, pending);
            }
        }
        self.plugins = Some(known);
    }

    fn read_parameter(&mut self, node: &ConfigNode, pending: &mut Vec<String>) {
        for (_, value) in &node.attributes {
            self.read(value, pending);
        }
        if let Some(value) = &node.value {
            self.read(value, pending);
        }
        for child in &node.children {
            self.read_parameter(child, pending);
        }
    }

    fn read_pom_fields(&mut self, pom: &Pom, pending: &mut Vec<String>) {
        for value in [
            &pom.group_id,
            &pom.artifact_id,
            &pom.version,
            &pom.packaging,
        ]
        .into_iter()
        .flatten()
        {
            self.read(value, pending);
        }
        if let Some(parent) = &pom.parent {
            for value in [&parent.group_id, &parent.artifact_id, &parent.version] {
                self.read(value, pending);
            }
        }
        self.read_content(
            None,
            &pom.dependencies,
            pom.dependency_management.as_ref(),
            &pom.repositories,
            &pom.modules,
            pending,
        );
        if let Some(Relocation {
            group_id,
            artifact_id,
            version,
            message: _,
        }) = pom
            .distribution_management
            .as_ref()
            .and_then(|management| management.relocation.as_ref())
        {
            for value in [group_id, artifact_id, version].into_iter().flatten() {
                self.read(value, pending);
            }
        }
    }

    /// Note the names that the declarations which may reach resolution, the
    /// repositories and, in a project build, the modules read, of the POM
    /// or of its `profile`.
    fn read_content(
        &mut self,
        profile: Option<&str>,
        dependencies: &[Dependency],
        management: Option<&DependencyManagement>,
        repositories: &[Repository],
        modules: &[String],
        pending: &mut Vec<String>,
    ) {
        self.read_declarations(
            dependencies,
            |keys, dependency| keys.reaches(dependency, profile),
            pending,
        );
        let managed = management.map_or(&[][..], |management| &management.dependencies);
        self.read_declarations(managed, Self::manages, pending);
        self.read_repositories(repositories, pending);
        if self.role == LineageRole::Project {
            for module in modules {
                self.read(module, pending);
            }
        }
    }

    /// Whether `dependency`, declared outside the POM's profiles or in
    /// `profile`, may reach resolution or change a declaration that does.
    fn reaches(&self, dependency: &Dependency, profile: Option<&str>) -> bool {
        self.all_reach
            || !self.left_out(dependency, profile)
            || dependency.group_id.contains("${")
            || dependency.artifact_id.contains("${")
            || self.is_reaching(&dependency.group_id, &dependency.artifact_id)
    }

    fn is_valid_system(&self, dependency: &Dependency) -> bool {
        let key = (dependency.group_id.clone(), dependency.artifact_id.clone());
        system_under_java_home(dependency) && self.valid_system.contains(&key)
    }

    fn is_reaching(&self, group_id: &str, artifact_id: &str) -> bool {
        self.reaching
            .get(group_id)
            .is_some_and(|artifacts| artifacts.contains(artifact_id))
    }

    /// Whether the management entry `managed`, declared in this lineage,
    /// may change resolution. Resolution applies only the project's
    /// management to the graph, so in a dependency's model an entry counts
    /// when it imports a BOM or manages a declaration of the lineage that
    /// reaches resolution.
    fn manages(&self, managed: &Dependency) -> bool {
        let import = managed.scope.as_deref().is_some_and(|scope| {
            let scope = scope.trim();
            scope.eq_ignore_ascii_case("import") || scope.contains("${")
        });
        // Maven validates the management too, and an invalid entry costs
        // the whole POM its dependencies.
        self.role != LineageRole::Dependency
            || self.all_reach
            || import
            || may_be_invalid(managed, false)
            || managed.group_id.contains("${")
            || managed.artifact_id.contains("${")
            || self.is_reaching(&managed.group_id, &managed.artifact_id)
    }

    fn read_declarations(
        &mut self,
        dependencies: &[Dependency],
        counts: impl Fn(&Self, &Dependency) -> bool,
        pending: &mut Vec<String>,
    ) {
        for dependency in dependencies {
            if !counts(self, dependency) {
                continue;
            }
            let Dependency {
                group_id,
                artifact_id,
                version,
                type_,
                classifier,
                scope,
                optional,
                exclusions,
                system_path,
                system_path_from_project: _,
                origin: _,
            } = dependency;
            self.read(group_id, pending);
            self.read(artifact_id, pending);
            for value in [version, type_, classifier, scope, optional, system_path]
                .into_iter()
                .flatten()
            {
                self.read(value, pending);
            }
            for Exclusion {
                group_id,
                artifact_id,
            } in exclusions
            {
                self.read(group_id, pending);
                self.read(artifact_id, pending);
            }
        }
    }

    fn read_repositories(&mut self, repositories: &[Repository], pending: &mut Vec<String>) {
        for repository in repositories {
            let Repository {
                root_declared: _,
                id,
                url,
                releases_enabled: _,
                snapshots_enabled: _,
                releases_enabled_text,
                snapshots_enabled_text,
                releases_update_policy,
                snapshots_update_policy,
                releases_checksum_policy,
                snapshots_checksum_policy,
                declared_url: _,
                url_reads: _,
                id_reads: _,
                layout: _,
                written_layout,
            } = repository;
            self.read(url, pending);
            for value in [
                id,
                written_layout,
                releases_enabled_text,
                snapshots_enabled_text,
                releases_update_policy,
                snapshots_update_policy,
                releases_checksum_policy,
                snapshots_checksum_policy,
            ]
            .into_iter()
            .flatten()
            {
                self.read(value, pending);
            }
        }
    }

    fn read(&mut self, text: &str, pending: &mut Vec<String>) {
        for name in expression_names(text) {
            let mut add = |name: &str| {
                if self.names.insert(name.to_string()) {
                    pending.push(name.to_string());
                }
            };
            add(name);
            // `${project.properties.x}` and `${pom.properties.x}` read `x`.
            if let Some(key) = name
                .strip_prefix("project.properties.")
                .or_else(|| name.strip_prefix("pom.properties."))
            {
                add(key);
            }
        }
    }
}

/// The `<build>` field a `${project.build.x}`, `${pom.build.x}` or
/// `${build.x}` reference names.
fn build_field(name: &str) -> Option<&str> {
    let name = (name.strip_prefix("project."))
        .or_else(|| name.strip_prefix("pom."))
        .unwrap_or(name);
    Build::model_field(name).map(|field| field.name)
}

impl ResolutionKeys {
    /// Whether resolution leaves `dependency` out of a dependency's graph
    /// whatever its management says: its scope is `test` or `provided`, or
    /// it is optional, as written. Maven still validates such a declaration
    /// as interpolated, and one that fails validation costs the whole POM
    /// its dependencies, so one that may fail is not left out: one without
    /// its own version that the management may not fill, with a version or
    /// type that may interpolate to nothing, in `system` scope or with a
    /// `systemPath`, or with an id Maven rejects.
    fn left_out(&self, dependency: &Dependency, profile: Option<&str>) -> bool {
        let empty = |text: &str| text.trim().is_empty() || self.may_be_empty(text, profile);
        if may_be_invalid(dependency, self.is_valid_system(dependency))
            || dependency.version.as_deref().map_or(
                !self.managed_versions.contains(&management_key(dependency)),
                empty,
            )
            || dependency.type_.as_deref().is_some_and(empty)
        {
            return false;
        }
        let scope = dependency
            .scope
            .as_deref()
            .and_then(|scope| scope.trim().parse::<Scope>().ok());
        matches!(scope, Some(Scope::Test | Scope::Provided)) || dependency.effective_optional()
    }

    /// Whether `text`, written outside the POM's profiles or in `profile`,
    /// may fail to interpolate, or interpolate to the empty text, which
    /// Maven's validation rejects for a version or type: it reads a name
    /// [`filled`] found failing, or holds nothing outside its expressions
    /// and each names something it did not find filled.
    fn may_be_empty(&self, text: &str, profile: Option<&str>) -> bool {
        let (literal, names) = segments(text);
        let read: Vec<Verdict> = (names.iter())
            .map(|name| self.filled.verdict(profile, name))
            .collect();
        read.contains(&Verdict::Fails) || (!literal && !read.contains(&Verdict::Filled))
    }

    /// The keys, by [`management_key`], whose version the management of
    /// `chain` fills on every activation: an entry outside the profiles
    /// with written ids gives the key a version that cannot be empty, and
    /// every entry whose ids may read as the key's, in a profile or a
    /// nearer POM, which replaces it whole, gives one too. Maven fills a
    /// declaration's missing version from the management before it
    /// validates the model.
    fn managed_versions(&self, chain: &[Pom]) -> HashSet<(String, String, String, String)> {
        // Maven takes the `import` entries out of the management before it
        // fills versions, so a BOM's own entry fills none.
        let entries = || {
            let imported = |entry: &Dependency| entry.scope.as_deref() == Some("import");
            (chain.iter().flat_map(|pom| {
                let profiles = pom.profiles.iter().flat_map(|profile| {
                    let entries = managed(profile.dependency_management.as_ref()).iter();
                    entries.map(|entry| (Some(profile.id.as_str()), entry))
                });
                (managed(pom.dependency_management.as_ref()).iter())
                    .map(|entry| (None, entry))
                    .chain(profiles)
            }))
            .filter(move |(_, entry)| !imported(entry))
        };
        let certain = |entry: &Dependency, profile: Option<&str>| {
            (entry.version.as_deref()).is_some_and(|version| {
                !version.trim().is_empty() && !self.may_be_empty(version, profile)
            })
        };
        let mut keys: HashSet<_> = (entries())
            .filter(|(profile, entry)| {
                profile.is_none()
                    && certain(entry, None)
                    && !entry.group_id.contains("${")
                    && !entry.artifact_id.contains("${")
            })
            .map(|(_, entry)| management_key(entry))
            .collect();
        for (profile, entry) in entries() {
            if !certain(entry, profile) {
                keys.retain(|(group, artifact, _, _)| {
                    !(may_read_as(&entry.group_id, group)
                        && may_read_as(&entry.artifact_id, artifact))
                });
            }
        }
        keys
    }
}

fn managed(management: Option<&DependencyManagement>) -> &[Dependency] {
    management.map_or(&[][..], |management| &management.dependencies)
}

/// The key Maven matches a declaration to its management by, as written,
/// with the default type.
fn management_key(dependency: &Dependency) -> (String, String, String, String) {
    (
        dependency.group_id.clone(),
        dependency.artifact_id.clone(),
        dependency.type_.clone().unwrap_or_else(|| "jar".into()),
        dependency.classifier.clone().unwrap_or_default(),
    )
}

/// Whether Maven's validation of `dependency`, a declaration or a managed
/// entry, may fail: it is or may interpolate to `system` scope or has a
/// `systemPath`, or an id
/// written without `${` uses characters Maven does not allow. With
/// `valid_system`, its `system` scope and path cannot fail it.
fn may_be_invalid(dependency: &Dependency, valid_system: bool) -> bool {
    let invalid_id =
        |id: &str| !id.contains("${") && (id.is_empty() || !rv_maven_types::is_maven_id_text(id));
    // A scope written with `${...}` may interpolate to `system`.
    let system = dependency.system_path.is_some()
        || (dependency.scope.as_deref()).is_some_and(|scope| {
            let scope = scope.trim();
            scope.eq_ignore_ascii_case("system")
                || (scope.contains("${") && may_read_as(scope, "system"))
        });
    (system && !valid_system)
        || invalid_id(&dependency.group_id)
        || invalid_id(&dependency.artifact_id)
}

/// Whether `dependency` is in `system` scope at a path under `${java.home}`,
/// with the rest of the path, ids, version and type written out. Maven 3.9.12 and 3.10.0 reject
/// an empty or relative `systemPath`, but only warn of an absolute one that
/// names no file, so where `java.home` is the JDK's such a dependency is
/// valid whatever the JDK holds.
fn system_under_java_home(dependency: &Dependency) -> bool {
    let written = [&dependency.group_id, &dependency.artifact_id]
        .into_iter()
        .chain(&dependency.version)
        .chain(&dependency.type_)
        .all(|text| !text.contains("${"));
    // The reader trimmed what Maven's does, and Maven trims no further.
    written
        && dependency.scope.as_deref() == Some("system")
        && (dependency.system_path.as_deref()).is_some_and(|path| {
            let rest =
                (path.strip_prefix("${java.home}")).or_else(|| path.strip_prefix("${.java.home}"));
            rest.is_some_and(|rest| {
                (rest.is_empty() || rest.starts_with(['/', '\\'])) && !rest.contains("${")
            })
        })
}

/// The keys of the declarations in `chain`, a dependency's lineage, that
/// are [`system_under_java_home`] where `java.home` is the JDK's home, so
/// absolute on every JVM: no `-D`, settings.xml or POM property sets it.
/// A key that a management entry or a declaration of another kind shares
/// is left out, since merging them can bring a scope or path of the other's.
fn valid_system(chain: &[Pom], ctx: &ActivationContext) -> HashSet<(String, String)> {
    let set = |properties: &PropertyMap| properties.get("java.home").is_some();
    let overridden = ctx.properties.contains_key("java.home")
        || ctx.settings_properties.get("java.home").is_some()
        || ctx.system_properties.contains_key("java.home")
        || chain.iter().any(|pom| {
            set(&pom.properties) || pom.profiles.iter().any(|profile| set(&profile.properties))
        });
    if overridden {
        return HashSet::new();
    }
    let key =
        |dependency: &Dependency| (dependency.group_id.clone(), dependency.artifact_id.clone());
    let mut valid = HashMap::new();
    for pom in chain {
        let profiles = &pom.profiles;
        let declared = (pom.dependencies.iter())
            .chain(profiles.iter().flat_map(|profile| &profile.dependencies));
        for dependency in declared {
            let all = valid.entry(key(dependency)).or_insert(true);
            *all &= system_under_java_home(dependency);
        }
        let managed = (managed(pom.dependency_management.as_ref()).iter()).chain(
            profiles
                .iter()
                .flat_map(|profile| managed(profile.dependency_management.as_ref())),
        );
        for dependency in managed {
            valid.insert(key(dependency), false);
        }
    }
    // An id with an expression can read as any key its written text allows.
    let expressions: Vec<_> = (valid.keys())
        .filter(|(group, artifact)| group.contains("${") || artifact.contains("${"))
        .cloned()
        .collect();
    valid
        .into_iter()
        .filter(|((group, artifact), valid)| {
            *valid
                && !expressions.iter().any(|(other_group, other_artifact)| {
                    may_read_as(other_group, group) && may_read_as(other_artifact, artifact)
                })
        })
        .map(|(key, _)| key)
        .collect()
}

/// Whether `text` holds anything outside its `${...}` expressions, and the
/// names those expressions read, as Maven's interpolation reads them.
fn segments(text: &str) -> (bool, Vec<&str>) {
    let mut literal = false;
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) if end > 0 => {
                literal |= start > 0;
                names.push(&after[..end]);
                rest = &after[end + 1..];
            }
            _ => return (true, names),
        }
    }
    (literal || !rest.is_empty(), names)
}

/// What interpolation may make of each name that the versions and types
/// the declarations of `chain` write read, by `definitions`, every value a
/// property can take, and `build`, every value a `<build>` field can. A
/// name is filled when a POM of the lineage defines it outside its
/// profiles, which hides a `-D` from a dependency's model, or it is a
/// coordinate the model has or a `<build>` field the super POM or a POM
/// sets outside its profiles, and each of its values holds text outside its
/// expressions or reads a filled name. A name whose values reach a cycle,
/// or nest deeper than Maven interpolates, fails. Any other name may be
/// empty: a profile, a `-D` or an environment variable can give it the
/// empty value.
fn filled(
    chain: &[Pom],
    definitions: &HashMap<&str, Vec<&str>>,
    build: &HashMap<&str, Vec<&str>>,
) -> Filled {
    const COORDINATES: [&str; 3] = ["groupId", "artifactId", "version"];
    const PARENT: [&str; 3] = ["parent.groupId", "parent.artifactId", "parent.version"];
    // As Maven's interpolation depth.
    const DEPTH: usize = 100;
    let has_parent = chain.first().is_some_and(|pom| pom.parent.is_some());
    struct Walk<'a> {
        definitions: &'a HashMap<&'a str, Vec<&'a str>>,
        build: &'a HashMap<&'a str, Vec<&'a str>>,
        base: HashSet<&'a str>,
        base_build: HashSet<&'a str>,
        has_parent: bool,
        known: HashMap<String, Verdict>,
        open: HashSet<String>,
    }
    impl Walk<'_> {
        fn verdict(&mut self, name: &str) -> Verdict {
            let key = name
                .strip_prefix("project.properties.")
                .or_else(|| name.strip_prefix("pom.properties."))
                .unwrap_or(name);
            if let Some(known) = self.known.get(key) {
                return *known;
            }
            if self.open.contains(key) || self.open.len() >= DEPTH {
                return Verdict::Fails;
            }
            self.open.insert(key.to_string());
            let field = build_field(key);
            let model = key
                .strip_prefix("project.")
                .or_else(|| key.strip_prefix("pom."))
                .is_some_and(|field| {
                    COORDINATES.contains(&field) || (self.has_parent && PARENT.contains(&field))
                });
            let defined = model
                || self.base.contains(key)
                || field.is_some_and(|field| self.base_build.contains(field));
            let (definitions, build) = (self.definitions, self.build);
            let values = (definitions.get(key).into_iter().flatten()).chain(
                (field.and_then(|field| build.get(field)))
                    .into_iter()
                    .flatten(),
            );
            let mut verdict = match defined {
                true => Verdict::Filled,
                false => Verdict::MayBeEmpty,
            };
            for value in values {
                let (literal, names) = segments(value);
                let read: Vec<Verdict> = names.into_iter().map(|name| self.verdict(name)).collect();
                verdict = verdict.max(match read.iter().max() {
                    Some(Verdict::Fails) => Verdict::Fails,
                    _ if literal || read.contains(&Verdict::Filled) => Verdict::Filled,
                    _ => Verdict::MayBeEmpty,
                });
            }
            self.open.remove(key);
            self.known.insert(key.to_string(), verdict);
            verdict
        }
    }
    let base: HashSet<&str> = (chain.iter())
        .flat_map(|pom| pom.properties.iter().map(|(key, _)| key.as_str()))
        .collect();
    let base_build: HashSet<&str> = (Build::FIELDS.iter())
        .filter(|field| {
            field.super_pom.is_some() || (chain.iter()).any(|pom| pom.build.value(field).is_some())
        })
        .map(|field| field.name)
        .collect();
    // The declarations of a profile exist only with its properties, which
    // hide a `-D` as the POM's own do.
    let names = |defined: HashSet<&str>, declarations: &[Dependency]| {
        let mut walk = Walk {
            definitions,
            build,
            base: defined,
            base_build: base_build.clone(),
            has_parent,
            known: HashMap::new(),
            open: HashSet::new(),
        };
        let texts = (declarations.iter())
            .flat_map(|dependency| [&dependency.version, &dependency.type_])
            .flatten();
        let names: Vec<&str> = texts.flat_map(|text| segments(text).1).collect();
        (names.into_iter())
            .map(|name| (name.to_string(), walk.verdict(name)))
            .collect::<HashMap<_, _>>()
    };
    let mut filled = Filled::default();
    // Two POMs of the lineage can give one id different profiles, so a name
    // both read takes the worse verdict.
    let merge = |names: &mut HashMap<String, Verdict>, more: HashMap<String, Verdict>| {
        for (name, more) in more {
            let verdict = names.entry(name).or_insert(more);
            *verdict = (*verdict).max(more);
        }
    };
    for pom in chain {
        merge(&mut filled.base, names(base.clone(), &pom.dependencies));
        let management = managed(pom.dependency_management.as_ref());
        merge(&mut filled.base, names(base.clone(), management));
        for profile in &pom.profiles {
            let mut defined = base.clone();
            defined.extend(profile.properties.iter().map(|(key, _)| key.as_str()));
            let profiles = filled.profiles.entry(profile.id.clone()).or_default();
            merge(profiles, names(defined.clone(), &profile.dependencies));
            let management = managed(profile.dependency_management.as_ref());
            merge(profiles, names(defined, management));
        }
    }
    filled
}

/// What interpolation may make of a name, the worst last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Filled,
    MayBeEmpty,
    Fails,
}

/// The [`Verdict`] of each name the lineage's declarations read, outside
/// their profiles, and in each profile, by id.
#[derive(Debug, Default)]
struct Filled {
    base: HashMap<String, Verdict>,
    profiles: HashMap<String, HashMap<String, Verdict>>,
}

impl Filled {
    fn verdict(&self, profile: Option<&str>, name: &str) -> Verdict {
        let names = match profile {
            None => Some(&self.base),
            Some(id) => self.profiles.get(id),
        };
        (names.and_then(|names| names.get(name)).copied()).unwrap_or(Verdict::MayBeEmpty)
    }
}

/// Whether `text`, which may hold `${...}` expressions, can interpolate to
/// `literal`: its text before the first expression and after the last one
/// must begin and end it.
fn may_read_as(text: &str, literal: &str) -> bool {
    let Some(start) = text.find("${") else {
        return text == literal;
    };
    let end = text
        .rfind('}')
        .filter(|end| *end > start)
        .map_or(text.len(), |end| end + 1);
    let (prefix, suffix) = (&text[..start], &text[end..]);
    literal.len() >= prefix.len() + suffix.len()
        && literal.starts_with(prefix)
        && literal.ends_with(suffix)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{
        ActivationContext, HostInput, HostSnapshot, MemorySource, ModelPolicy, PluginModel, Pom,
        Project,
    };

    fn jdk(spec: &str) -> HostInput {
        HostInput::Jdk(spec.to_string())
    }

    /// The host conditions a dependency's model build records, with the
    /// active profile ids of its lineage, for a parent whose profiles are
    /// `profiles` and a child that reads `${lib.version}`.
    fn build(profiles: &str, child_profiles: &str) -> (BTreeSet<HostInput>, Project) {
        build_with(ModelPolicy::DEPENDENCY, profiles, child_profiles)
    }

    fn build_with(
        policy: ModelPolicy,
        profiles: &str,
        child_profiles: &str,
    ) -> (BTreeSet<HostInput>, Project) {
        let parent = Pom::parse(&format!(
            "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
             <packaging>pom</packaging><properties><lib.version>1</lib.version></properties>\
             <profiles>{profiles}</profiles></project>"
        ))
        .unwrap();
        let child = Pom::parse(&format!(
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><artifactId>child</artifactId><dependencies>\
             <dependency><groupId>g</groupId><artifactId>lib</artifactId>\
             <version>${{lib.version}}</version></dependency></dependencies>\
             <profiles>{child_profiles}</profiles></project>"
        ))
        .unwrap();
        let source = MemorySource::new().with_parent("g", "parent", "1", parent);
        let host = HostSnapshot::for_testing(&[]).with_java_version("21");
        let ctx = ActivationContext::new(host.environment("linux", "x86_64"));
        let project = crate::ready(Project::build(child, &source, policy, &ctx)).unwrap();
        (host.consulted(), project)
    }

    /// As guava-parent's srczip profiles: an optional `system` dependency under
    /// `${java.home}` is valid whatever the JDK holds, unless a `-D` or a
    /// POM property sets `java.home`, which can make the path relative, or
    /// another field or entry of its key can make it invalid.
    #[test]
    fn a_system_dependency_under_the_jdk_home_is_not_an_input() {
        let tool = |extra: &str| {
            format!(
                "<dependency><groupId>jdk</groupId><artifactId>tool</artifactId>\
                 <version>999</version>{extra}</dependency>"
            )
        };
        let system = "<scope>system</scope><systemPath>${java.home}/lib/tool.jar</systemPath>";
        let srczip = tool(&format!("{system}<optional>true</optional>"));
        let build = |head: &str, profile: &str, define: bool| {
            let parent = Pom::parse(&format!(
                "<project><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version><packaging>pom</packaging>{head}<profiles><profile>\
                 <id>p</id><activation><jdk>[25,)</jdk></activation>{profile}</profile>\
                 </profiles></project>"
            ))
            .unwrap();
            let child = Pom::parse(
                "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version></parent><artifactId>child</artifactId></project>",
            )
            .unwrap();
            let source = MemorySource::new().with_parent("g", "parent", "1", parent);
            let host = HostSnapshot::for_testing(&[]).with_java_version("21");
            let mut ctx = ActivationContext::new(host.environment("linux", "x86_64"));
            if define {
                ctx.properties.insert("java.home".into(), "rel".into());
            }
            let policy = ModelPolicy::DEPENDENCY;
            crate::ready(Project::build(child, &source, policy, &ctx)).unwrap();
            (host.consulted(), host.consulted_user_properties())
        };
        let declares = |dependency: &str| format!("<dependencies>{dependency}</dependencies>");
        let manages = |dependency: &str| {
            format!(
                "<dependencyManagement>{}</dependencyManagement>",
                declares(dependency)
            )
        };
        // A profile without a condition activates only by `-P`.
        let unconditioned = format!("</profile><profile><id>q</id>{}", declares(&srczip));
        let (_, user) = build("", &unconditioned, false);
        assert!(!user.contains("java.home"), "{user:?}");
        // guava-parent declares its srczip in two profiles, at two paths.
        let other = srczip.replace("lib/tool.jar", "../tool.jar");
        // Maven reads `${.java.home}` as `${java.home}`.
        let dotted = srczip.replace("${java.home}", "${.java.home}");
        for (head, profile) in [
            ("", declares(&srczip)),
            (&declares(&other), declares(&srczip)),
            ("", declares(&dotted)),
        ] {
            let (read, user) = build(head, &profile, false);
            assert!(read.is_empty(), "{head} {profile}: {read:?}");
            assert!(user.contains("java.home"), "{user:?}");
        }
        let typed = tool(&format!(
            "<type>${{t}}</type>{system}<optional>true</optional>"
        ));
        let test = tool("<scope>test</scope>");
        // Maven trims neither a no-break space nor other Unicode space.
        let spaced = srczip.replace(">system<", ">\u{a0}system\u{a0}<");
        let indented = srczip.replace(">${java.home}", ">\u{a0}${java.home}");
        let nested = srczip.replace("lib/tool.jar", "${p}");
        // A management entry whose ids interpolate to the key can merge in.
        let interpolated = format!(
            "<properties><g>jdk</g></properties>{}",
            manages(&tool(system).replace(">jdk<", ">${g}<"))
        );
        for (head, profile, define) in [
            (
                "<properties><java.home>rel</java.home></properties>",
                declares(&srczip),
                false,
            ),
            ("", declares(&srczip), true),
            // A type that may interpolate to nothing makes the POM invalid.
            ("", declares(&typed), false),
            ("", declares(&spaced), false),
            ("", declares(&indented), false),
            ("", declares(&nested), false),
            (&interpolated, declares(&srczip), false),
            // Merged into a test declaration of its key, the path makes the
            // POM invalid, whichever of the two the profile holds.
            (&declares(&test), manages(&tool(system)), false),
            (&declares(&srczip), declares(&test), false),
        ] {
            let (read, _) = build(head, &profile, define);
            let case = format!("{head} {profile} {define}");
            assert_eq!(read, BTreeSet::from([jdk("[25,)")]), "{case}");
        }
    }

    #[test]
    fn a_profile_that_only_configures_the_build_is_not_an_input() {
        let (read, _) = build(
            "<profile><id>release</id><activation><jdk>[21,)</jdk></activation>\
             <properties><maven.compiler.release>21</maven.compiler.release></properties>\
             <build><plugins><plugin><artifactId>p</artifactId></plugin></plugins></build>\
             </profile>",
            "",
        );
        assert!(read.is_empty(), "{read:?}");
    }

    /// A profile's `<build>` value is an input when resolution reads it,
    /// here through the super POM's `outputDirectory`, which reads the
    /// directory.
    #[test]
    fn a_build_value_that_resolution_reads_makes_the_profile_an_input() {
        let reads = "<profile><id>reads</id><activation><activeByDefault>true</activeByDefault>\
             </activation><properties><lib.version>${build.outputDirectory}</lib.version>\
             </properties></profile>";
        let (read, project) = build(
            "<profile><id>dir</id><activation><jdk>[21,)</jdk></activation>\
             <build><directory>jdk21</directory></build></profile>\
             <profile><id>name</id><activation><jdk>[17,)</jdk></activation>\
             <build><finalName>unread</finalName></build></profile>",
            reads,
        );
        assert_eq!(read, BTreeSet::from([jdk("[21,)")]));
        assert_eq!(
            project.dependencies[0].version.as_deref(),
            Some("jdk21/classes")
        );
    }

    #[test]
    fn a_property_that_resolution_reads_makes_the_profile_an_input() {
        let (read, project) = build(
            "<profile><id>old</id><activation><jdk>(,11)</jdk></activation>\
             <properties><lib.version>${legacy}</lib.version></properties></profile>\
             <profile><id>new</id><activation><jdk>[21,)</jdk></activation>\
             <properties><legacy>0.9</legacy></properties></profile>",
            "",
        );
        assert_eq!(read, BTreeSet::from([jdk("(,11)"), jdk("[21,)")]));
        assert_eq!(project.dependencies[0].version.as_deref(), Some("1"));
    }

    #[test]
    fn dependencies_management_and_repositories_make_a_profile_an_input() {
        for content in [
            "<dependencies><dependency><groupId>g</groupId><artifactId>x</artifactId>\
             <version>1</version></dependency></dependencies>",
            "<dependencyManagement><dependencies><dependency><groupId>g</groupId>\
             <artifactId>lib</artifactId><version>1</version></dependency></dependencies>\
             </dependencyManagement>",
            "<repositories><repository><id>r</id><url>https://repo.example/</url>\
             </repository></repositories>",
        ] {
            let (read, _) = build(
                &format!(
                    "<profile><id>p</id><activation><jdk>[25,)</jdk></activation>{content}\
                     </profile>"
                ),
                "",
            );
            assert_eq!(read, BTreeSet::from([jdk("[25,)")]), "{content}");
        }
    }

    /// A dependency's model leaves its test, provided and optional
    /// dependencies out of resolution, so a profile that adds only those
    /// counts only in a project build, or when it changes a declaration
    /// that reaches resolution.
    #[test]
    fn dependencies_left_out_of_a_dependency_graph_do_not_make_an_input() {
        let dependency = |artifact: &str, extra: &str| {
            format!(
                "<dependency><groupId>g</groupId><artifactId>{artifact}</artifactId>\
                 <version>${{mock.version}}</version>{extra}</dependency>"
            )
        };
        let profile = |dependencies: &str| {
            format!(
                "<profile><id>p</id><activation><jdk>[25,)</jdk></activation>\
                 <properties><mock.version>5</mock.version></properties>\
                 <dependencies>{dependencies}</dependencies></profile>"
            )
        };
        for extra in [
            "<scope>test</scope>",
            "<scope> provided </scope>",
            "<optional>true</optional>",
        ] {
            let profiles = profile(&dependency("mock", extra));
            let (read, _) = build(&profiles, "");
            assert!(read.is_empty(), "{extra}: {read:?}");
            let (read, _) = build_with(ModelPolicy::PROJECT, &profiles, "");
            assert_eq!(read, BTreeSet::from([jdk("[25,)")]), "{extra}");
            // The child's `g:lib` takes the profile's scope or flag.
            let (read, _) = build(&profile(&dependency("lib", extra)), "");
            assert_eq!(read, BTreeSet::from([jdk("[25,)")]), "{extra}");
        }
        for extra in [
            "<scope>runtime</scope>",
            "<scope>${s}</scope>",
            "<optional>${o}</optional>",
            "<scope>system</scope><optional>true</optional>",
            "<optional>true</optional><systemPath>/opt/x.jar</systemPath>",
            "<scope>test</scope><type></type>",
            // A relative or empty path makes the POM invalid.
            "<scope>system</scope><optional>true</optional><systemPath>lib/x.jar</systemPath>",
            "<scope>system</scope><optional>true</optional><systemPath></systemPath>",
            "<scope>system</scope><optional>true</optional>\
             <systemPath>${java.homex}/x.jar</systemPath>",
            // Maven's `system` is lowercase: another case may not hold a path.
            "<scope>System</scope><optional>true</optional>\
             <systemPath>${java.home}/x.jar</systemPath>",
            // Under `${java.home}`, but a version or type that may
            // interpolate to nothing makes the POM invalid.
            "<scope>system</scope><optional>true</optional>\
             <systemPath>${java.home}/lib/src.zip</systemPath>",
        ] {
            let (read, _) = build(&profile(&dependency("mock", extra)), "");
            assert_eq!(read, BTreeSet::from([jdk("[25,)")]), "{extra}");
        }
        // Without a version of its own, or with an id Maven rejects, a
        // declaration may fail validation.
        for declaration in [
            "<dependency><groupId>g</groupId><artifactId>mock</artifactId>\
             <scope>test</scope></dependency>"
                .to_string(),
            dependency("mock bar", "<scope>test</scope>"),
        ] {
            let (read, _) = build(&profile(&declaration), "");
            assert_eq!(read, BTreeSet::from([jdk("[25,)")]), "{declaration}");
        }
        // In a dependency's model, management counts when it imports a BOM
        // or manages a dependency that resolution follows.
        let managing = |entry: &str| {
            format!(
                "<profile><id>p</id><activation><jdk>[25,)</jdk></activation>\
                 <properties><mock.version>5</mock.version></properties>\
                 <dependencyManagement><dependencies>{entry}</dependencies>\
                 </dependencyManagement></profile>"
            )
        };
        let (read, _) = build(&managing(&dependency("mock", "")), "");
        assert!(read.is_empty(), "{read:?}");
        let (read, _) = build_with(ModelPolicy::PROJECT, &managing(&dependency("mock", "")), "");
        assert_eq!(read, BTreeSet::from([jdk("[25,)")]));
        for entry in [
            dependency("lib", ""),
            dependency("bom", "<type>pom</type><scope>import</scope>"),
            dependency("tools", "<scope>system</scope>"),
            dependency("mock bar", ""),
            "<dependency><groupId>${g}</groupId><artifactId>x</artifactId>\
             <version>1</version></dependency>"
                .to_string(),
        ] {
            let (read, _) = build(&managing(&entry), "");
            assert_eq!(read, BTreeSet::from([jdk("[25,)")]), "{entry}");
        }
        // A property that a reaching dependency reads still counts.
        let (read, _) = build(
            "<profile><id>p</id><activation><jdk>[25,)</jdk></activation>\
             <properties><lib.version>2</lib.version></properties></profile>",
            "",
        );
        assert_eq!(read, BTreeSet::from([jdk("[25,)")]));
    }

    /// Maven validates a left-out declaration as interpolated: a version or
    /// type that may expand to nothing, or a scope that may expand to
    /// `system`, can cost the POM its dependencies.
    #[test]
    fn a_left_out_declaration_counts_where_its_interpolated_value_may_fail_validation() {
        let optional = |version: &str, extra: &str| {
            format!(
                "<dependency><groupId>g</groupId><artifactId>mock</artifactId>\
                 <version>{version}</version><optional>true</optional>{extra}</dependency>"
            )
        };
        let profile = |properties: &str, dependencies: &str| {
            format!(
                "<profile><id>p</id><activation><jdk>[25,)</jdk></activation>\
                 <properties>{properties}</properties>\
                 <dependencies>{dependencies}</dependencies></profile>"
            )
        };
        let child = |properties: &str, dependencies: &str, profiles: &str| {
            let child = Pom::parse(&format!(
                "<project><groupId>g</groupId><artifactId>child</artifactId><version>1</version>\
                 <properties>{properties}</properties>\
                 <dependencies>{dependencies}</dependencies>\
                 <profiles>{profiles}</profiles></project>"
            ))
            .unwrap();
            let host = HostSnapshot::for_testing(&[]).with_java_version("21");
            let ctx = ActivationContext::new(host.environment("linux", "x86_64"));
            let policy = ModelPolicy::DEPENDENCY;
            let _ = crate::ready(Project::build(child, &MemorySource::new(), policy, &ctx));
            host.consulted()
        };
        let input = BTreeSet::from([jdk("[25,)")]);
        // In the profile, reading a property the POM defines.
        for (properties, version, extra, counts) in [
            ("<empty/>", "${empty}", "", true),
            ("<empty/>", "${empty}${project.properties.empty}", "", true),
            ("<v>1</v>", "${v}", "", false),
            ("<v>1</v>", "${project.version}", "", false),
            ("<v>1</v>", "x${empty}", "", false),
            ("<v>${empty}</v><empty/>", "${v}", "", true),
            ("<v>${v}</v>", "${v}", "", true),
            ("<v>1${v}</v>", "${v}", "", true),
            ("<v>1${w}</v><w>${v}</w>", "x${v}", "", true),
            ("", "${project.parent.version}", "", true),
            ("", "${project.version}", "", false),
            // Nothing in the POM defines it, so a `-D` can make it empty.
            ("", "${unset}", "", true),
            ("", "${env.V}", "", true),
            ("<v>1</v>", "${v}", "<type>${empty}</type>", true),
            ("<v>1</v><t>jar</t>", "${v}", "<type>${t}</type>", false),
            ("<v>1</v>", "${v}", "<scope>${s}</scope>", true),
            ("<v>1</v>", "${v}", "<scope>${s}x</scope>", false),
        ] {
            let read = child(properties, "", &profile("", &optional(version, extra)));
            let expected = if counts {
                input.clone()
            } else {
                BTreeSet::new()
            };
            assert_eq!(read, expected, "{properties} {version} {extra}");
        }
        // A chain deeper than Maven interpolates fails, a shorter one fills.
        for (depth, counts) in [(50, false), (150, true)] {
            let chain: String = (0..depth)
                .map(|at| format!("<p{at}>${{p{}}}</p{at}>", at + 1))
                .chain([format!("<p{depth}>1</p{depth}>")])
                .collect();
            let read = child(&chain, "", &profile("", &optional("${p0}", "")));
            assert_eq!(read.is_empty(), !counts, "{depth}");
        }
        // The profile's own property hides a `-D` while the declaration is
        // there.
        let read = child("", "", &profile("<v>1</v>", &optional("${v}", "")));
        assert!(read.is_empty(), "{read:?}");
        let read = child("", "", &profile("<v/>", &optional("${v}", "")));
        assert_eq!(read, input);
        // Outside the profile, the profile can empty or fill the property.
        for (base, own, counts) in [("<v>1</v>", "<v/>", true), ("<v/>", "<v>1</v>", true)] {
            let read = child(base, &optional("${v}", ""), &profile(own, ""));
            let expected = if counts {
                input.clone()
            } else {
                BTreeSet::new()
            };
            assert_eq!(read, expected, "{base} {own}");
        }
        let read = child("<v>1</v>", &optional("${v}", ""), &profile("<w/>", ""));
        assert!(read.is_empty(), "{read:?}");
        // A parent's profile of the same id that declares nothing leaves the
        // child's verdict, and one that empties the property counts.
        for (own, counts) in [("", false), ("<v/>", true)] {
            let parent = Pom::parse(&format!(
                "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
                 <packaging>pom</packaging><properties><v>1</v></properties>\
                 <profiles>{}</profiles></project>",
                profile(own, "")
            ))
            .unwrap();
            let child = Pom::parse(&format!(
                "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version></parent><artifactId>child</artifactId>\
                 <profiles>{}</profiles></project>",
                profile(
                    "",
                    &(optional("${v}", "") + &optional("${project.parent.version}", ""))
                )
            ))
            .unwrap();
            let source = MemorySource::new().with_parent("g", "parent", "1", parent);
            let host = HostSnapshot::for_testing(&[]).with_java_version("21");
            let ctx = ActivationContext::new(host.environment("linux", "x86_64"));
            let _ = crate::ready(Project::build(
                child,
                &source,
                ModelPolicy::DEPENDENCY,
                &ctx,
            ));
            let expected = if counts {
                input.clone()
            } else {
                BTreeSet::new()
            };
            assert_eq!(host.consulted(), expected, "{own}");
        }
    }

    /// As log4j's java8-tests profile under log4j-to-slf4j: a profile that
    /// redeclares in test scope a provided dependency of the child, whose
    /// version the parent's management fills, changes nothing resolution
    /// sees, and so does one that adds a test dependency whose version the
    /// management fills. It counts where the management may not fill that
    /// version, or where the child's declaration reaches resolution.
    #[test]
    fn a_profile_that_redeclares_a_managed_left_out_dependency_is_not_an_input() {
        let mock = |extra: &str| {
            format!(
                "<dependency><groupId>g</groupId><artifactId>mock</artifactId>{extra}</dependency>"
            )
        };
        let versioned = mock("<version>${mock.version}</version><scope>test</scope>");
        let build = |management: &str, profile: &str, declaration: &str| {
            let parent = Pom::parse(&format!(
                "<project><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version><packaging>pom</packaging>\
                 <properties><mock.version>5</mock.version></properties>{management}\
                 <profiles><profile><id>ci</id><activation><jdk>[25,)</jdk></activation>\
                 <build><plugins><plugin><artifactId>maven-surefire-plugin</artifactId>\
                 </plugin></plugins></build>{profile}</profile></profiles></project>"
            ))
            .unwrap();
            let child = Pom::parse(&format!(
                "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version></parent><artifactId>child</artifactId>\
                 <dependencies>{declaration}</dependencies></project>"
            ))
            .unwrap();
            let source = MemorySource::new().with_parent("g", "parent", "1", parent);
            let host = HostSnapshot::for_testing(&[]).with_java_version("21");
            let ctx = ActivationContext::new(host.environment("linux", "x86_64"));
            let policy = ModelPolicy::DEPENDENCY;
            let _ = crate::ready(Project::build(child, &source, policy, &ctx));
            host.consulted()
        };
        let declares = |dependency: &str| format!("<dependencies>{dependency}</dependencies>");
        let manages = |dependency: &str| {
            format!(
                "<dependencyManagement>{}</dependencyManagement>",
                declares(dependency)
            )
        };
        let managed = manages(&mock("<version>${mock.version}</version>"));
        let provided = mock("<scope>provided</scope>");
        // As jetty-quic-quiche-client's: the profile's own test declaration
        // takes its version from the management too.
        let versionless = mock("<scope>test</scope>");
        for profile in [declares(&versioned), declares(&versionless)] {
            let read = build(&managed, &profile, &provided);
            assert!(read.is_empty(), "{profile}: {read:?}");
        }
        let input = BTreeSet::from([jdk("[25,)")]);
        for (management, profile, declaration) in [
            // Without the management, only the profile fills the version.
            (String::new(), declares(&versioned), provided.clone()),
            (String::new(), declares(&versionless), String::new()),
            (
                String::new(),
                declares(&versioned) + &managed,
                provided.clone(),
            ),
            (
                manages(&mock("<version>${unset}</version>")),
                declares(&versioned),
                provided.clone(),
            ),
            (
                manages(&mock("<version>5</version><classifier>x</classifier>")),
                declares(&versioned),
                provided.clone(),
            ),
            // The profile's management can empty or drop the version it
            // fills.
            (
                managed.clone(),
                declares(&versioned) + &manages(&mock("<version>${unset}</version>")),
                provided.clone(),
            ),
            (
                managed.clone(),
                declares(&versioned) + &manages(&mock("<scope>test</scope>")),
                provided.clone(),
            ),
            // Maven takes an `import` entry out of the management before it
            // fills versions, so it fills none, the BOM's own included.
            (
                manages(&mock(
                    "<version>5</version><type>pom</type><scope>import</scope>",
                )),
                declares(&mock(
                    "<version>5</version><type>pom</type><scope>test</scope>",
                )),
                mock("<type>pom</type><scope>provided</scope>"),
            ),
            // The child's compile declaration takes the profile's scope.
            (managed.clone(), declares(&versioned), mock("")),
            // A compile dependency of the profile's own reaches resolution.
            (
                managed.clone(),
                declares(
                    "<dependency><groupId>g</groupId><artifactId>x</artifactId>\
                     <version>1</version></dependency>",
                ),
                provided.clone(),
            ),
        ] {
            let read = build(&management, &profile, &declaration);
            assert_eq!(read, input, "{management} {profile} {declaration}");
        }
    }

    /// An imported BOM's management becomes the importer's, so a profile
    /// of the BOM that changes it counts in a project build and in a
    /// dependency's model alike, whether it manages an entry itself or sets
    /// a property that one reads.
    #[test]
    fn an_imported_bom_profile_that_changes_management_is_an_input() {
        for profile in [
            "<dependencyManagement><dependencies><dependency><groupId>g</groupId>\
             <artifactId>lib</artifactId><version>2</version></dependency></dependencies>\
             </dependencyManagement>",
            "<properties><lib.version>2</lib.version></properties>",
        ] {
            let bom = Pom::parse(&format!(
                "<project><groupId>g</groupId><artifactId>bom</artifactId><version>1</version>\
                 <packaging>pom</packaging><properties><lib.version>1</lib.version></properties>\
                 <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
                 <artifactId>lib</artifactId><version>${{lib.version}}</version></dependency>\
                 </dependencies></dependencyManagement><profiles><profile><id>p</id>\
                 <activation><jdk>[17,)</jdk></activation>{profile}</profile></profiles>\
                 </project>"
            ))
            .unwrap();
            for policy in [ModelPolicy::PROJECT, ModelPolicy::DEPENDENCY] {
                let app = Pom::parse(
                    "<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>\
                     <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
                     <artifactId>bom</artifactId><version>1</version><type>pom</type>\
                     <scope>import</scope></dependency></dependencies></dependencyManagement>\
                     <dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId>\
                     </dependency></dependencies></project>",
                )
                .unwrap();
                let source = MemorySource::new().with_import("g", "bom", "1", bom.clone());
                let host = HostSnapshot::for_testing(&[]).with_java_version("21");
                let ctx = ActivationContext::new(host.environment("linux", "x86_64"));
                let project = crate::ready(Project::build(app, &source, policy, &ctx)).unwrap();
                assert_eq!(
                    project.dependencies[0].version.as_deref(),
                    Some("2"),
                    "{profile}"
                );
                assert_eq!(
                    host.consulted(),
                    BTreeSet::from([jdk("[17,)")]),
                    "{policy:?}: {profile}"
                );
            }
        }
    }

    /// Every condition of a POM decides whether its `activeByDefault`
    /// profiles apply, so they all count when such a profile is an input.
    /// A build-only profile whose activation depends on the host that way
    /// is left out of the active profile ids.
    #[test]
    fn a_relevant_default_profile_makes_every_condition_of_its_pom_an_input() {
        let default_with = |content: &str| {
            format!(
                "<profile><id>build</id><activation><jdk>[21,)</jdk></activation>\
                 <properties><maven.compiler.release>21</maven.compiler.release>\
                 </properties></profile>\
                 <profile><id>fallback</id><activation><activeByDefault>true\
                 </activeByDefault></activation>{content}</profile>"
            )
        };
        let (read, _) = build(
            &default_with("<properties><lib.version>2</lib.version></properties>"),
            "",
        );
        assert_eq!(read, BTreeSet::from([jdk("[21,)")]));
        let (read, _) = build(
            "",
            &default_with("<properties><unused>2</unused></properties>"),
        );
        assert!(read.is_empty(), "{read:?}");
    }

    /// A project profile that sets the classifier likes, or a property
    /// they read, is an input; in a dependency's model it is not.
    #[test]
    fn a_profile_setting_the_classifier_likes_is_a_project_input() {
        let mut pom = Pom::parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <properties><os.detection.classifierWithLikes>${likes}\
             </os.detection.classifierWithLikes></properties><profiles>\
             <profile><id>own</id><activation><jdk>[21,)</jdk></activation><properties>\
             <os.detection.classifierWithLikes>debian</os.detection.classifierWithLikes>\
             </properties></profile>\
             <profile><id>read</id><activation><jdk>[21,)</jdk></activation>\
             <properties><likes>fedora</likes></properties></profile></profiles></project>",
        )
        .unwrap();
        let relevant = |pom: &Pom, role| {
            let keys = super::ResolutionKeys::of_lineage(
                std::slice::from_ref(pom),
                &ActivationContext::default(),
                role,
                PluginModel::Off,
            );
            (pom.profiles.iter())
                .map(|profile| keys.is_relevant(profile))
                .collect::<Vec<_>>()
        };
        assert_eq!(relevant(&pom, super::LineageRole::Project), [true, true]);
        assert_eq!(
            relevant(&pom, super::LineageRole::Dependency),
            [false, false]
        );
        // A `-D` value does not hide what the project's own value reads.
        pom.overlay_user_properties([(super::LIKES, "user")]);
        assert_eq!(relevant(&pom, super::LineageRole::Project), [true, true]);
    }

    /// In a build that locks its plugins, a project profile that changes
    /// what the plugin resolution reads is an input; one that configures a
    /// plugin the build runs anyway, or manages one it does not run, is not.
    /// Read for the build extensions, only a profile that adds one, sets
    /// the version of one or a property it reads, is. A coordinate written
    /// with `${...}` may name any plugin.
    #[test]
    fn a_profile_changing_the_plugins_is_a_plugin_build_input() {
        let profile = |id: &str, build: &str| {
            format!(
                "<profile><id>{id}</id><activation><jdk>[21,)</jdk></activation>\
                 <build>{build}</build></profile>"
            )
        };
        let profiles = [
            profile(
                "configure",
                "<plugins><plugin><artifactId>maven-compiler-plugin</artifactId>\
                 <configuration><release>21</release></configuration></plugin></plugins>",
            ),
            profile(
                "unused",
                "<pluginManagement><plugins><plugin><groupId>t</groupId>\
                 <artifactId>other</artifactId><version>2</version></plugin></plugins>\
                 </pluginManagement>",
            ),
            profile(
                "manage",
                "<pluginManagement><plugins><plugin><groupId>t</groupId>\
                 <artifactId>own</artifactId><version>2</version></plugin></plugins>\
                 </pluginManagement>",
            ),
            profile(
                "add",
                "<plugins><plugin><groupId>t</groupId><artifactId>new</artifactId></plugin></plugins>",
            ),
            profile(
                "processor",
                "<plugins><plugin><artifactId>maven-compiler-plugin</artifactId>\
                 <configuration><annotationProcessorPaths><path><groupId>t</groupId>\
                 <artifactId>p</artifactId><version>1</version></path>\
                 </annotationProcessorPaths></configuration></plugin></plugins>",
            ),
            profile(
                "extension",
                "<plugins><plugin><groupId>t</groupId><artifactId>ext</artifactId>\
                 <version>1</version><extensions>true</extensions></plugin></plugins>",
            ),
            profile(
                "version",
                "<pluginManagement><plugins><plugin><groupId>t</groupId>\
                 <artifactId>marked</artifactId><version>2</version></plugin></plugins>\
                 </pluginManagement>",
            ),
            "<profile><id>property</id><activation><jdk>[21,)</jdk></activation>\
             <properties><marked.version>3</marked.version></properties></profile>"
                .to_string(),
            profile(
                "groups",
                "<plugins><plugin><artifactId>maven-surefire-plugin</artifactId>\
                 <configuration><groups>it</groups></configuration></plugin></plugins>",
            ),
            profile(
                "templated",
                "<pluginManagement><plugins><plugin><groupId>g</groupId>\
                 <artifactId>tmpl</artifactId><version>2</version></plugin></plugins>\
                 </pluginManagement>",
            ),
            "<profile><id>templated-extension</id><activation><jdk>[21,)</jdk></activation>\
             <properties><tx.version>3</tx.version></properties></profile>"
                .to_string(),
        ];
        let mut pom = Pom::parse_with_plugins(&format!(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <build><plugins><plugin><groupId>t</groupId><artifactId>own</artifactId>\
             <version>1</version></plugin><plugin><groupId>t</groupId>\
             <artifactId>marked</artifactId><version>${{marked.version}}</version>\
             <extensions>true</extensions></plugin><plugin><groupId>${{project.groupId}}</groupId>\
             <artifactId>tmpl</artifactId></plugin><plugin><groupId>${{project.groupId}}</groupId>\
             <artifactId>tx</artifactId><version>${{tx.version}}</version></plugin></plugins>\
             <pluginManagement><plugins><plugin><groupId>g</groupId><artifactId>tx</artifactId>\
             <extensions>true</extensions></plugin></plugins></pluginManagement></build>\
             <profiles>{}</profiles></project>",
            profiles.concat()
        ))
        .unwrap();
        pom.load_plugins().unwrap();
        let relevant = |plugins| {
            let keys = super::ResolutionKeys::of_lineage(
                std::slice::from_ref(&pom),
                &ActivationContext::default(),
                super::LineageRole::Project,
                plugins,
            );
            (pom.profiles.iter())
                .map(|profile| keys.is_relevant(profile))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            relevant(PluginModel::All),
            [
                false, false, true, true, true, true, true, true, true, true, true
            ]
        );
        assert_eq!(
            relevant(PluginModel::Extensions),
            [
                false, false, false, false, false, true, true, true, false, false, true
            ]
        );
        assert_eq!(relevant(PluginModel::Off), [false; 11]);
    }

    /// In a build that locks its plugins, the default goal picks the
    /// lifecycle the plugins come from: a profile that sets one is an input,
    /// and so is one that sets a property the project's default goal reads.
    /// Read for the build extensions only, neither is.
    #[test]
    fn a_default_goal_is_a_plugin_build_input() {
        let mut pom = Pom::parse_with_plugins(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <build><defaultGoal>${goal.name}</defaultGoal></build><profiles>\
             <profile><id>goal</id><activation><jdk>[21,)</jdk></activation>\
             <build><defaultGoal>verify</defaultGoal></build></profile>\
             <profile><id>property</id><activation><jdk>[21,)</jdk></activation>\
             <properties><goal.name>verify</goal.name></properties></profile>\
             <profile><id>other</id><activation><jdk>[21,)</jdk></activation>\
             <properties><other.name>verify</other.name></properties></profile>\
             </profiles></project>",
        )
        .unwrap();
        pom.load_plugins().unwrap();
        let relevant = |plugins| {
            let keys = super::ResolutionKeys::of_lineage(
                std::slice::from_ref(&pom),
                &ActivationContext::default(),
                super::LineageRole::Project,
                plugins,
            );
            (pom.profiles.iter())
                .map(|profile| keys.is_relevant(profile))
                .collect::<Vec<_>>()
        };
        assert_eq!(relevant(PluginModel::All), [true, true, false]);
        assert_eq!(relevant(PluginModel::Extensions), [false; 3]);
        assert_eq!(relevant(PluginModel::Off), [false; 3]);
    }

    /// `${lib.${flavor}}` is the one name `lib.${flavor`, so a profile that
    /// sets `flavor` changes nothing.
    #[test]
    fn a_nested_name_reads_no_inner_property() {
        let parent = Pom::parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <properties><flavor>x</flavor><lib.x>1</lib.x></properties>\
             <dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId>\
             <version>${lib.${flavor}}</version></dependency></dependencies><profiles>\
             <profile><id>p</id><activation><jdk>[21,)</jdk></activation>\
             <properties><flavor>y</flavor></properties></profile></profiles></project>",
        )
        .unwrap();
        let host = HostSnapshot::for_testing(&[]).with_java_version("21");
        let ctx = ActivationContext::new(host.environment("linux", "x86_64"));
        crate::ready(Project::build(
            parent,
            &MemorySource::new(),
            ModelPolicy::DEPENDENCY,
            &ctx,
        ))
        .unwrap();
        assert_eq!(host.consulted(), BTreeSet::new());
    }

    #[test]
    fn settings_properties_reach_project_lineage_only_and_record_when_read() {
        let bom = Pom::parse(
            "<project><groupId>g</groupId><artifactId>bom</artifactId><version>2</version>\
             <packaging>pom</packaging><properties><lib.version>1</lib.version></properties>\
             <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
             <artifactId>from-bom</artifactId><version>${lib.version}</version></dependency>\
             </dependencies></dependencyManagement><profiles><profile><id>bom-p</id>\
             <activation><property><name>flag</name></property></activation>\
             <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
             <artifactId>from-bom</artifactId><version>99</version></dependency>\
             </dependencies></dependencyManagement></profile></profiles></project>",
        )
        .unwrap();
        let parent = Pom::parse(
            "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
             <packaging>pom</packaging><properties><lib.version>1</lib.version></properties>\
             <profiles><profile><id>parent-flag</id>\
             <activation><property><name>flag</name></property></activation>\
             <properties><extra.version>${inactive.prop}</extra.version></properties>\
             </profile></profiles></project>",
        )
        .unwrap();
        let child = Pom::parse(
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><artifactId>app</artifactId>\
             <properties><inactive.prop>fallback</inactive.prop></properties>\
             <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
             <artifactId>bom</artifactId><version>${bom.version}</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>\
             <dependencies>\
               <dependency><groupId>g</groupId><artifactId>lib</artifactId>\
                 <version>${lib.version}</version></dependency>\
               <dependency><groupId>g</groupId><artifactId>from-bom</artifactId></dependency>\
               <dependency><groupId>g</groupId><artifactId>extra</artifactId>\
                 <version>${extra.version}</version></dependency>\
             </dependencies></project>",
        )
        .unwrap();
        let source = MemorySource::new()
            .with_parent("g", "parent", "1", parent)
            .with_import("g", "bom", "2", bom);
        let host = HostSnapshot::for_testing(&[]);
        let mut ctx = ActivationContext::new(host.environment("linux", "x86_64"));
        ctx.settings_properties.insert("lib.version", "2");
        ctx.settings_properties.insert("bom.version", "2");
        ctx.settings_properties.insert("flag", "true");
        ctx.settings_properties.insert("gpg.keyname", "ABC");
        ctx.settings_property_names = BTreeSet::from([
            "lib.version".to_string(),
            "bom.version".to_string(),
            "flag".to_string(),
            "inactive.prop".to_string(),
            "gpg.keyname".to_string(),
        ]);
        let project = crate::ready(Project::build(
            child.clone(),
            &source,
            ModelPolicy::PROJECT,
            &ctx,
        ))
        .unwrap();
        let versions: Vec<(&str, Option<&str>)> = project
            .dependencies
            .iter()
            .map(|d| (d.artifact_id.as_str(), d.version.as_deref()))
            .collect();
        // `lib` takes settings `lib.version=2`; `from-bom` takes the BOM's own
        // `lib.version=1` and does not activate `bom-p` on `flag`; `extra`
        // takes `fallback` via `parent-flag`.
        assert_eq!(
            versions,
            [
                ("lib", Some("2")),
                ("from-bom", Some("1")),
                ("extra", Some("fallback")),
            ]
        );
        // `gpg.keyname` is never read by resolution, so it is not recorded;
        // `inactive.prop` is read even though its settings profile is inactive.
        assert_eq!(
            host.consulted(),
            BTreeSet::from([
                HostInput::SettingsProperty("bom.version".to_string()),
                HostInput::SettingsProperty("flag".to_string()),
                HostInput::SettingsProperty("inactive.prop".to_string()),
                HostInput::SettingsProperty("lib.version".to_string()),
            ])
        );
        // `-D` user properties override settings properties.
        ctx.properties
            .insert("lib.version".to_string(), "3".to_string());
        let project =
            crate::ready(Project::build(child, &source, ModelPolicy::PROJECT, &ctx)).unwrap();
        assert_eq!(project.dependencies[0].version.as_deref(), Some("3"));
    }

    /// A settings property that `prerequisites.maven` reads, and a
    /// dependency reads through it, is read by resolution.
    #[test]
    fn a_settings_property_read_through_the_maven_prerequisite_is_recorded() {
        let pom = Pom::parse(
            "<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>\
             <prerequisites><maven>${v}</maven></prerequisites><dependencies><dependency>\
             <groupId>g</groupId><artifactId>t</artifactId>\
             <version>${project.prerequisites.maven}</version></dependency></dependencies>\
             </project>",
        )
        .unwrap();
        let host = HostSnapshot::for_testing(&[]);
        let mut ctx = ActivationContext::new(host.environment("linux", "x86_64"));
        ctx.settings_properties.insert("v", "2");
        ctx.settings_property_names = BTreeSet::from(["v".to_string()]);
        let project = crate::ready(Project::build(
            pom,
            &MemorySource::new(),
            ModelPolicy::PROJECT,
            &ctx,
        ))
        .unwrap();
        assert_eq!(project.dependencies[0].version.as_deref(), Some("2"));
        assert!(
            host.consulted()
                .contains(&HostInput::SettingsProperty("v".to_string()))
        );
    }

    /// Maven 3.9.12 and 3.10.0 read an unprefixed `${prerequisites.maven}`
    /// from the model after the properties, where `project.` reads it first.
    #[test]
    fn an_unprefixed_maven_prerequisite_reads_the_model_after_the_properties() {
        for (properties, expected) in [
            ("", ["3.9.0", "3.9.0"]),
            (
                "<prerequisites.maven>1</prerequisites.maven>",
                ["1", "3.9.0"],
            ),
        ] {
            let pom = Pom::parse(&format!(
                "<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>\
                 <prerequisites><maven>${{v}}</maven></prerequisites><properties><v>3.9.0</v>\
                 {properties}</properties><dependencies><dependency><groupId>g</groupId>\
                 <artifactId>a</artifactId><version>${{prerequisites.maven}}</version>\
                 </dependency><dependency><groupId>g</groupId><artifactId>b</artifactId>\
                 <version>${{project.prerequisites.maven}}</version></dependency>\
                 </dependencies></project>"
            ))
            .unwrap();
            let ctx = ActivationContext::new(
                HostSnapshot::for_testing(&[]).environment("linux", "x86_64"),
            );
            let project = crate::ready(Project::build(
                pom,
                &MemorySource::new(),
                ModelPolicy::PROJECT,
                &ctx,
            ))
            .unwrap();
            let versions = project
                .dependencies
                .iter()
                .map(|dependency| dependency.version.as_deref());
            assert!(versions.eq(expected.map(Some)), "{properties}");
        }
    }

    /// A parent's `prerequisites.maven` is not inherited, so the settings
    /// property it names is not read through the child's.
    #[test]
    fn a_parents_maven_prerequisite_reads_nothing_for_the_child() {
        let parent = Pom::parse(
            "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
             <packaging>pom</packaging><prerequisites><maven>${v}</maven></prerequisites>\
             </project>",
        )
        .unwrap();
        let child = Pom::parse(
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><artifactId>app</artifactId>\
             <prerequisites><maven>3</maven></prerequisites><dependencies><dependency>\
             <groupId>g</groupId><artifactId>t</artifactId>\
             <version>${project.prerequisites.maven}</version></dependency></dependencies>\
             </project>",
        )
        .unwrap();
        let source = MemorySource::new().with_parent("g", "parent", "1", parent);
        let host = HostSnapshot::for_testing(&[]);
        let mut ctx = ActivationContext::new(host.environment("linux", "x86_64"));
        ctx.settings_properties.insert("v", "2");
        ctx.settings_property_names = BTreeSet::from(["v".to_string()]);
        let project =
            crate::ready(Project::build(child, &source, ModelPolicy::PROJECT, &ctx)).unwrap();
        assert_eq!(project.dependencies[0].version.as_deref(), Some("3"));
        assert!(
            !host
                .consulted()
                .contains(&HostInput::SettingsProperty("v".to_string()))
        );
    }

    /// The classifier likes of a settings.xml profile are the model's under
    /// a `-D` value too. A project build records no read of them: the
    /// search for the first sorted project's likes does, once a build reads
    /// the classifier.
    #[test]
    fn settings_classifier_likes_win_over_a_user_property() {
        let pom = Pom::parse(
            "<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>\
             </project>",
        )
        .unwrap();
        let host = HostSnapshot::for_testing(&[]);
        let mut ctx = ActivationContext::new(host.environment("linux", "x86_64"));
        ctx.settings_properties.insert(super::LIKES, "fedora");
        ctx.settings_property_names = BTreeSet::from([super::LIKES.to_string()]);
        ctx.properties
            .insert(super::LIKES.to_string(), "user".to_string());
        let project = crate::ready(Project::build(
            pom,
            &MemorySource::new(),
            ModelPolicy::PROJECT,
            &ctx,
        ))
        .unwrap();
        assert_eq!(project.classifier_with_likes.as_deref(), Some("fedora"));
        assert_eq!(host.consulted(), BTreeSet::new());
    }
}
