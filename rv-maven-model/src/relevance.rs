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
//! management becomes the importer's, so all of it counts.

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};

use crate::dependency::{Dependency, DependencyManagement, Exclusion};
use crate::pom::Build;
use crate::properties::{PropertyMap, expression_names, super_pom_build};
use crate::repository::Repository;
use crate::{ActivationContext, Pom, Profile, Relocation, Scope};

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
    dynamic: bool,
    role: LineageRole,
    /// The artifact ids, by group id, of the dependency declarations in the
    /// lineage that reach resolution. A declaration with the same ids that
    /// does not reach it can still change one that does, since merging
    /// declarations of one key takes the scope and optional flag of either.
    reaching: HashMap<String, HashSet<String>>,
    all_reach: bool,
}

impl ResolutionKeys {
    fn new(role: LineageRole) -> Self {
        Self {
            names: HashSet::new(),
            dynamic: false,
            role,
            reaching: HashMap::new(),
            all_reach: true,
        }
    }

    /// The keys of `chain`, the POMs of one lineage built for `role`,
    /// before their profiles are injected.
    ///
    /// Only a profile with a condition or a project build with settings.xml
    /// profile properties needs keys; any other lineage gets none.
    pub(crate) fn of_lineage(chain: &[Pom], ctx: &ActivationContext, role: LineageRole) -> Self {
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
        if role != LineageRole::Project {
            keys.all_reach = false;
            let declarations = chain.iter().flat_map(|pom| {
                pom.profiles
                    .iter()
                    .flat_map(|profile| &profile.dependencies)
                    .chain(&pom.dependencies)
            });
            for dependency in declarations {
                if left_out(dependency) {
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
        if role == LineageRole::Project {
            // os-maven-plugin reads this from the first sorted project, and
            // every model's `os.detected.classifier` takes its suffix.
            keys.read(&format!("${{{LIKES}}}"), &mut pending);
        }
        for pom in chain {
            keys.read_pom_fields(pom, &mut pending);
            for profile in &pom.profiles {
                keys.read_content(
                    &profile.dependencies,
                    profile.dependency_management.as_ref(),
                    &profile.repositories,
                    &profile.modules,
                    &mut pending,
                );
            }
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
        // And every value a `<build>` field can take, the super POM's too.
        let mut build: HashMap<&str, Vec<&str>> = HashMap::new();
        let builds = chain.iter().flat_map(|pom| {
            std::iter::once(&pom.build).chain(pom.profiles.iter().map(|p| &p.build))
        });
        for fields in builds.map(|build| build.fields()) {
            for (name, value) in Build::NAMES.into_iter().zip(fields) {
                if let Some(value) = value {
                    build.entry(name).or_default().push(value);
                }
            }
        }
        for name in Build::NAMES {
            if let Some(value) = super_pom_build(name) {
                build.entry(name).or_default().push(value);
            }
        }
        // Only the input POM's: Maven does not inherit `<prerequisites>`.
        let prerequisites =
            (chain.first()).and_then(|pom| pom.prerequisites.as_ref()?.maven.as_deref());
        while let Some(name) = pending.pop() {
            for value in definitions.get(name.as_str()).into_iter().flatten() {
                keys.read(value, &mut pending);
            }
            if matches!(
                name.as_str(),
                "project.prerequisites.maven" | "pom.prerequisites.maven"
            ) && let Some(value) = prerequisites
            {
                keys.read(value, &mut pending);
            }
            for value in build_field(&name)
                .and_then(|field| build.get(field))
                .into_iter()
                .flatten()
            {
                keys.read(value, &mut pending);
            }
        }
        if has_settings_properties {
            for name in &ctx.settings_property_names {
                // A `-D` value hides a settings value, except the likes.
                if (keys.dynamic || keys.names.contains(name))
                    && (!ctx.properties.contains_key(name) || name == LIKES)
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
        } = profile;
        dependencies
            .iter()
            .any(|dependency| self.reaches(dependency))
            || dependency_management.as_ref().is_some_and(|management| {
                management
                    .dependencies
                    .iter()
                    .any(|managed| self.manages(managed))
            })
            || !repositories.is_empty()
            || (self.role == LineageRole::Project && !modules.is_empty())
            || (!properties.is_empty() && self.dynamic)
            || properties.iter().any(|(key, _)| self.names.contains(key))
            || Build::PROFILE_NAMES.into_iter().any(|name| {
                build.field(name).is_some_and(Option::is_some)
                    && (self.dynamic
                        || ["project.build.", "pom.build.", "build."]
                            .into_iter()
                            .any(|prefix| self.names.contains(&format!("{prefix}{name}"))))
            })
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
    /// repositories and, in a project build, the modules read.
    fn read_content(
        &mut self,
        dependencies: &[Dependency],
        management: Option<&DependencyManagement>,
        repositories: &[Repository],
        modules: &[String],
        pending: &mut Vec<String>,
    ) {
        self.read_declarations(dependencies, Self::reaches, pending);
        let managed = management.map_or(&[][..], |management| &management.dependencies);
        self.read_declarations(managed, Self::manages, pending);
        self.read_repositories(repositories, pending);
        if self.role == LineageRole::Project {
            for module in modules {
                self.read(module, pending);
            }
        }
    }

    fn reaches(&self, dependency: &Dependency) -> bool {
        self.all_reach
            || !left_out(dependency)
            || dependency.group_id.contains("${")
            || dependency.artifact_id.contains("${")
            || self.is_reaching(&dependency.group_id, &dependency.artifact_id)
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
            || may_be_invalid(managed)
            || managed.group_id.contains("${")
            || managed.artifact_id.contains("${")
            || self.is_reaching(&managed.group_id, &managed.artifact_id)
    }

    fn read_declarations(
        &mut self,
        dependencies: &[Dependency],
        counts: fn(&Self, &Dependency) -> bool,
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
            } = repository;
            self.read(url, pending);
            for value in [
                id,
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
            // Any property may be read, which covers whatever the inner
            // names would add, so they need no walk.
            if name.contains("${") {
                self.dynamic = true;
                continue;
            }
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
    name.strip_prefix("project.build.")
        .or_else(|| name.strip_prefix("pom.build."))
        .or_else(|| name.strip_prefix("build."))
}

/// Whether resolution leaves `dependency` out of a dependency's graph
/// whatever its management says: its scope is `test` or `provided`, or it
/// is optional, as written. Maven still validates such a declaration, and
/// one that fails validation costs the whole POM its dependencies, so one
/// that may fail is not left out: one without its own version, with an
/// empty type, in `system` scope or with a `systemPath`, or with an id
/// Maven rejects.
fn left_out(dependency: &Dependency) -> bool {
    if may_be_invalid(dependency)
        || dependency
            .version
            .as_deref()
            .is_none_or(|version| version.trim().is_empty())
        || dependency
            .type_
            .as_deref()
            .is_some_and(|type_| type_.trim().is_empty())
    {
        return false;
    }
    let scope = dependency
        .scope
        .as_deref()
        .and_then(|scope| scope.trim().parse::<Scope>().ok());
    matches!(scope, Some(Scope::Test | Scope::Provided)) || dependency.effective_optional()
}

/// Whether Maven's validation of `dependency`, a declaration or a managed
/// entry, may fail: it is in `system` scope or has a `systemPath`, or an id
/// written without `${` uses characters Maven does not allow.
fn may_be_invalid(dependency: &Dependency) -> bool {
    let invalid_id =
        |id: &str| !id.contains("${") && (id.is_empty() || !rv_maven_types::is_maven_id_text(id));
    dependency.system_path.is_some()
        || dependency
            .scope
            .as_deref()
            .is_some_and(|scope| scope.trim().eq_ignore_ascii_case("system"))
        || invalid_id(&dependency.group_id)
        || invalid_id(&dependency.artifact_id)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{
        ActivationContext, HostInput, HostSnapshot, MemorySource, ModelPolicy, Pom, Project,
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

    /// A name nested many levels deep is read in one pass, without a walk
    /// per level.
    #[test]
    fn a_deeply_nested_name_is_read_without_recursion() {
        let depth = 100_000;
        let version = format!("{}x{}", "${".repeat(depth), "}".repeat(depth));
        let pom = Pom::parse(&format!(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <dependencies><dependency><groupId>g</groupId><artifactId>b</artifactId>\
             <version>{version}</version></dependency></dependencies><profiles><profile>\
             <id>p</id><activation><jdk>[21,)</jdk></activation><properties><q>1</q>\
             </properties></profile></profiles></project>"
        ))
        .unwrap();
        let keys = super::ResolutionKeys::of_lineage(
            std::slice::from_ref(&pom),
            &ActivationContext::default(),
            super::LineageRole::Dependency,
        );
        assert!(keys.is_relevant(&pom.profiles[0]));
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

    #[test]
    fn a_computed_property_name_makes_every_property_an_input() {
        let parent = Pom::parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <properties><flavor>x</flavor><lib.x>1</lib.x></properties>\
             <dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId>\
             <version>${lib.${flavor}}</version></dependency></dependencies><profiles>\
             <profile><id>p</id><activation><jdk>[21,)</jdk></activation>\
             <properties><anything>1</anything></properties></profile></profiles></project>",
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
        assert_eq!(host.consulted(), BTreeSet::from([jdk("[21,)")]));
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

    /// The classifier likes of a settings.xml profile are the model's, so
    /// they are recorded as read under a `-D` value too.
    #[test]
    fn settings_classifier_likes_are_recorded_under_a_user_property() {
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
        assert_eq!(
            host.consulted(),
            BTreeSet::from([HostInput::SettingsProperty(super::LIKES.to_string())])
        );
    }
}
