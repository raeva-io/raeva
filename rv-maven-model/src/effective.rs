//! Lightweight effective identity and aggregation metadata.
//!
//! This module deliberately stops short of dependency management and BOM
//! resolution. Reactor discovery needs only the POM's interpolated identity,
//! its active aggregation declarations and its repositories, with the
//! parent chain applied for the properties it contributes.

use std::fmt;

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use crate::model::{Activated, Lineage};
use crate::properties::{ProjectInfo, PropertyMap};
use crate::source::{ImportCoord, ModelPolicy, ModelSource, ParentLookup};
use crate::{ActivationContext, ModelEnvironment, Pom, PomError};

/// An effective Maven group/artifact/version coordinate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Gav {
    /// The interpolated `groupId`, the parent's when the POM has none.
    pub group_id: String,
    /// The interpolated `artifactId`.
    pub artifact_id: String,
    /// The interpolated version, the parent's when the POM has none.
    pub version: String,
}

impl Gav {
    /// Whether a coordinate keeps a `${...}` that discovery could not expand,
    /// as one a remote parent's property completes.
    pub(crate) fn has_expression(&self) -> bool {
        [&self.group_id, &self.artifact_id, &self.version]
            .iter()
            .any(|part| part.contains("${"))
    }
}

impl fmt::Display for Gav {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.group_id, self.artifact_id, self.version
        )
    }
}

/// The subset of an effective Maven model needed for reactor discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EffectiveDescriptor {
    /// The effective coordinates.
    pub gav: Gav,
    /// The ids of the active profiles of this POM, then of its parents,
    /// without a profile that a host value activated and that brings nothing
    /// resolution reads: no dependencies, managed dependencies, repositories
    /// or modules, and no property that those read.
    pub active_profiles: Vec<String>,
    selected_profiles: Vec<Vec<String>>,
    /// The interpolated, trimmed `<module>` entries of this POM and its
    /// active profiles. Modules are never inherited.
    pub modules: Vec<String>,
    /// Interpolated repositories from this model and its active parent/profile lineage.
    pub repositories: Vec<crate::Repository>,
    /// Resolution-bearing declarations after local inheritance and profile
    /// injection, with the public POM values their interpolation can read.
    /// External values belong only to the aggregate configuration hash.
    pub resolution_context: Vec<Option<String>>,
    /// Coordinates expanded from public POM values only. Remaining expressions
    /// match conservatively when discovery associates local BOM inputs.
    pub context_gav: Gav,
    /// Potential BOM imports, expanded like [`Self::context_gav`].
    pub bom_imports: Vec<Gav>,
    /// Group and artifact ids of the declared dependencies, expanded like
    /// [`Self::context_gav`].
    pub dependencies: Vec<(String, String)>,
    /// A parent not read by discovery may introduce further BOM imports.
    pub has_unread_parent: bool,
    /// Whether a parent the build went on without may decide [`Self::gav`].
    unread_parent_decides: bool,
}

impl EffectiveDescriptor {
    /// The ids of every profile active in each POM of the lineage, this
    /// POM's first, including those [`Self::active_profiles`] leaves out.
    pub fn selected_profiles(&self) -> &[Vec<String>] {
        &self.selected_profiles
    }

    /// Whether [`Self::gav`] may change once the parents this build went on
    /// without are read: it keeps an expression; or it took its groupId or
    /// version from a `<parent>` element, where Maven inherits that parent's
    /// own, which may name its version through a property the child
    /// overrides; or it reads a system property or the environment, which a
    /// property of that parent overrides.
    pub fn gav_is_provisional(&self) -> bool {
        self.unread_parent_decides || self.gav.has_expression()
    }

    /// Compute a descriptor after resolving and applying the POM's parent
    /// chain from `source`.
    ///
    /// Reactor discovery normally avoids remote model construction, but local
    /// aggregator parents can contribute properties used by a child's
    /// effective GAV (for example `${revision}`). The source lets discovery
    /// load trusted local parents without coupling this crate to a
    /// filesystem or repository implementation.
    pub async fn build<S: ModelSource>(
        pom: Pom,
        source: &S,
        policy: ModelPolicy,
        ctx: &ActivationContext,
    ) -> Result<Self, S::Error> {
        let source = DescriptorSource {
            inner: source,
            unread_parent: Mutex::new(None),
        };
        let lineage = Lineage::build(pom, &source, policy, ctx).await?;
        let mut descriptor = lineage.activate()?.descriptor()?;
        // A remote ancestor can supply management not visible to discovery.
        // Keep its reference even when it is reached through local parents.
        let parent = source
            .unread_parent
            .into_inner()
            .expect("parent lookup mutex");
        descriptor.resolution_context.extend([
            parent.as_ref().map(|parent| parent.group_id.clone()),
            parent.as_ref().map(|parent| parent.artifact_id.clone()),
            parent.as_ref().map(|parent| parent.version.clone()),
        ]);
        Ok(descriptor)
    }
}

struct DescriptorSource<'a, S> {
    inner: &'a S,
    unread_parent: Mutex<Option<crate::Parent>>,
}

impl<S: ModelSource> ModelSource for DescriptorSource<'_, S> {
    type Error = S::Error;

    async fn parent(
        &self,
        parent: &mut crate::Parent,
        lookup: ParentLookup,
    ) -> Result<Option<Pom>, S::Error> {
        let declared = parent.clone();
        let pom = self.inner.parent(parent, lookup).await?;
        if pom.is_none() {
            *self.unread_parent.lock().expect("parent lookup mutex") = Some(declared);
        }
        Ok(pom)
    }

    async fn import(&self, bom: ImportCoord<'_>) -> Result<Option<Pom>, S::Error> {
        self.inner.import(bom).await
    }

    fn observe_repositories(&self, repositories: &[crate::Repository]) {
        self.inner.observe_repositories(repositories);
    }
}

impl Activated {
    /// The descriptor reactor discovery reads: the coordinates, the active
    /// profiles, the modules and the repositories.
    pub(crate) fn descriptor(self) -> Result<EffectiveDescriptor, PomError> {
        let Self {
            pom,
            properties,
            project,
            ctx,
            ..
        } = self;
        // Aggregation is never inherited: `pom.modules` holds the current
        // POM's own modules and those of its active profiles.
        let modules = pom
            .modules
            .iter()
            .map(|module| {
                properties
                    .interpolate_str(module, &project)
                    .map(|module| module.trim().to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;

        let unread_parent_decides = match pom.unread_parent {
            None => false,
            Some(inherited) => inherited || reads_host_values(&pom, &properties, &project),
        };
        let resolution_context = resolution_context(&pom, &ctx);
        let (context_gav, bom_imports, dependencies) = context_coordinates(&pom, &ctx);
        let has_unread_parent = pom.unread_parent.is_some();
        let repositories = crate::project::repositories::resolve_repositories(
            pom.repositories,
            &properties,
            &project,
        )?;

        Ok(EffectiveDescriptor {
            unread_parent_decides,
            repositories,
            gav: Gav {
                group_id: project.group_id,
                artifact_id: project.artifact_id,
                version: project.version,
            },
            active_profiles: pom.active_profiles,
            selected_profiles: pom.selected_profiles,
            modules,
            resolution_context,
            context_gav,
            bom_imports,
            dependencies,
            has_unread_parent,
        })
    }
}

/// Keep the interpolation graph as well as the declarations: two expressions
/// that currently expand alike may differ under an external override. Walk
/// only public POM values, so no per-module digest exposes a host or -D value.
fn resolution_context(pom: &Pom, ctx: &ActivationContext) -> Vec<Option<String>> {
    let mut context = Vec::new();
    let mut field = |value: Option<&str>| context.push(value.map(str::to_owned));
    for value in [
        pom.group_id.as_deref(),
        pom.artifact_id.as_deref(),
        pom.version.as_deref(),
        pom.packaging.as_deref(),
    ] {
        field(value);
    }
    let managed = pom.dependency_management.as_ref();
    for dependencies in [
        pom.dependencies.as_slice(),
        managed.map_or(&[], |management| management.dependencies.as_slice()),
    ] {
        field(Some(&dependencies.len().to_string()));
        for dep in dependencies {
            for value in [
                Some(dep.group_id.as_str()),
                Some(dep.artifact_id.as_str()),
                dep.version.as_deref(),
                dep.type_.as_deref(),
                dep.classifier.as_deref(),
                dep.scope.as_deref(),
                dep.optional.as_deref(),
                dep.system_path.as_deref(),
            ] {
                field(value);
            }
            field(Some(&dep.exclusions.len().to_string()));
            for exclusion in &dep.exclusions {
                field(Some(&exclusion.group_id));
                field(Some(&exclusion.artifact_id));
            }
        }
    }
    field(Some(&pom.repositories.len().to_string()));
    for repo in &pom.repositories {
        for value in [
            repo.id.as_deref(),
            Some(repo.url.as_str()),
            repo.releases_enabled_text.as_deref(),
            repo.snapshots_enabled_text.as_deref(),
            repo.releases_update_policy.as_deref(),
            repo.snapshots_update_policy.as_deref(),
            repo.releases_checksum_policy.as_deref(),
            repo.snapshots_checksum_policy.as_deref(),
        ] {
            field(value);
        }
    }
    let properties: BTreeMap<&str, &str> = pom
        .properties
        .iter()
        .filter(|(name, _)| pom.user_properties.get(name).is_none())
        .chain(pom.shadowed_properties.iter())
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    // os-maven-plugin's classifier suffix can be read by dependency models
    // even when no reactor dependency names it directly.
    context.push(
        properties
            .get("os.detection.classifierWithLikes")
            .map(|value| (*value).to_owned()),
    );
    let mut pending: Vec<String> = context.iter().flatten().cloned().collect();
    let mut reads = BTreeMap::new();
    let mut model_reads = BTreeMap::new();
    // An unread parent may introduce declarations that read any local value.
    let mut conservative = pom.unread_parent.is_some();
    while let Some(input) = pending.pop() {
        for name in crate::properties::expression_names(&input) {
            // A computed name or external expression can reach any public
            // property. Never expand external values into a module digest.
            if name.contains("${") {
                conservative = true;
                continue;
            }
            let name = name
                .strip_prefix("project.properties.")
                .or_else(|| name.strip_prefix("pom.properties."))
                .unwrap_or(name);
            if reads.contains_key(name) {
                continue;
            }
            let value = properties.get(name).copied();
            let model = model_value(pom, name);
            conservative |= value.is_none() && model.is_none();
            conservative |= pom.user_properties.get(name).is_some()
                || ctx.properties.contains_key(name)
                || ctx.settings_properties.get(name).is_some();
            if let Some(model) = model {
                let model = model.map(str::to_owned);
                if let Some(value) = &model {
                    pending.push(value.clone());
                }
                model_reads.insert(name.to_owned(), model);
            }
            let value = value.map(str::to_owned);
            if let Some(value) = &value {
                pending.push(value.clone());
            }
            reads.insert(name.to_owned(), value);
        }
    }
    if conservative {
        reads.extend(
            properties
                .iter()
                .map(|(name, value)| ((*name).to_owned(), Some((*value).to_owned()))),
        );
        // The coordinates lead the context already.
        let fields = [
            "parent.groupId",
            "parent.artifactId",
            "parent.version",
            "prerequisites.maven",
        ];
        let build = crate::pom::Build::NAMES
            .iter()
            .map(|name| format!("build.{name}"));
        for name in fields.into_iter().map(str::to_owned).chain(build) {
            let key = format!("project.{name}");
            model_reads.insert(
                key.clone(),
                model_value(pom, &key).flatten().map(str::to_owned),
            );
        }
    }
    for entries in [reads, model_reads] {
        context.push(Some(entries.len().to_string()));
        for (name, value) in entries {
            context.push(Some(name));
            context.push(value);
        }
    }
    context
}

fn context_coordinates(
    pom: &Pom,
    ctx: &ActivationContext,
) -> (Gav, Vec<Gav>, Vec<(String, String)>) {
    let mut properties = None;
    let mut interpolate = |raw: &str| {
        if !raw.contains("${") {
            return raw.trim().to_owned();
        }
        properties
            .get_or_insert_with(|| {
                let mut properties = PropertyMap::new();
                for (name, value) in pom.properties.iter().chain(pom.shadowed_properties.iter()) {
                    if pom.user_properties.get(name).is_none()
                        && !ctx.properties.contains_key(name)
                        && ctx.settings_properties.get(name).is_none()
                        // Model fields precede ordinary properties. Keep them
                        // uncertain, including through another property.
                        && !name.starts_with("project.")
                        && !name.starts_with("pom.")
                        && name != "basedir"
                    {
                        properties.insert(name, value);
                    }
                }
                properties
            })
            .interpolate_str_no_project(raw)
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|_| "${unresolved}".to_owned())
    };
    let context_gav = Gav {
        group_id: interpolate(
            pom.group_id
                .as_deref()
                .or_else(|| pom.parent.as_ref().map(|p| p.group_id.as_str()))
                .unwrap_or(""),
        ),
        artifact_id: interpolate(pom.artifact_id.as_deref().unwrap_or("")),
        version: interpolate(
            pom.version
                .as_deref()
                .or_else(|| pom.parent.as_ref().map(|p| p.version.as_str()))
                .unwrap_or(""),
        ),
    };
    let mut imports = Vec::new();
    for dep in pom
        .dependency_management
        .iter()
        .flat_map(|managed| &managed.dependencies)
    {
        let scope = interpolate(dep.scope.as_deref().unwrap_or(""));
        let type_ = interpolate(dep.type_.as_deref().unwrap_or("jar"));
        if (scope == "import" || scope.contains("${")) && (type_ == "pom" || type_.contains("${")) {
            imports.push(Gav {
                group_id: interpolate(&dep.group_id),
                artifact_id: interpolate(&dep.artifact_id),
                version: interpolate(dep.version.as_deref().unwrap_or("")),
            });
        }
    }
    let dependencies = pom
        .dependencies
        .iter()
        .map(|dep| (interpolate(&dep.group_id), interpolate(&dep.artifact_id)))
        .collect();
    (context_gav, imports, dependencies)
}

/// Raw public model fields that interpolation can reach. Absolute checkout
/// paths are deliberately absent; the module record already has its path.
fn model_value<'a>(pom: &'a Pom, name: &str) -> Option<Option<&'a str>> {
    let name = name
        .strip_prefix("project.")
        .or_else(|| name.strip_prefix("pom."))
        .unwrap_or(name);
    Some(match name {
        "groupId" => pom.group_id.as_deref(),
        "artifactId" => pom.artifact_id.as_deref(),
        "version" => pom.version.as_deref(),
        "packaging" => pom.packaging.as_deref(),
        "parent.groupId" => pom.parent.as_ref().map(|parent| parent.group_id.as_str()),
        "parent.artifactId" => pom
            .parent
            .as_ref()
            .map(|parent| parent.artifact_id.as_str()),
        "parent.version" => pom.parent.as_ref().map(|parent| parent.version.as_str()),
        "basedir" | "baseUri" => None,
        "prerequisites.maven" => pom.prerequisites.as_ref().and_then(|p| p.maven.as_deref()),
        _ => {
            let field = name.strip_prefix("build.")?;
            pom.build
                .field(field)?
                .as_deref()
                .or_else(|| crate::properties::super_pom_build(field))
        }
    })
}

/// Whether `project`'s coordinates take a value from a system property or
/// the environment rather than from `pom`'s properties: without them they
/// read a host value or come out otherwise.
fn reads_host_values(pom: &Pom, properties: &PropertyMap, project: &ProjectInfo) -> bool {
    // A JDK version keeps the stand-in's warning out of this probe.
    let (environment, read) = ModelEnvironment::builder()
        .jdk_version("17")
        .build()
        .probed();
    !crate::model::project_info_in(
        pom,
        properties,
        project.basedir.clone(),
        HashMap::new(),
        &environment,
    )
    .is_ok_and(|own| {
        [&own.group_id, &own.artifact_id, &own.version]
            == [&project.group_id, &project.artifact_id, &project.version]
    }) || read.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MissingParent;

    fn describe(pom: &Pom, ctx: &ActivationContext) -> EffectiveDescriptor {
        let policy = ModelPolicy {
            root: false,
            missing_parent: MissingParent::InheritDeclaredCoordinates,
        };
        let source = crate::MemorySource::new();
        crate::ready(EffectiveDescriptor::build(
            pom.clone(),
            &source,
            policy,
            ctx,
        ))
        .unwrap()
    }

    fn inherited_context(
        parent: &str,
        child: &str,
        ctx: &ActivationContext,
    ) -> Vec<Option<String>> {
        let mut parent = Pom::parse(&format!(
            "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
             {parent}</project>"
        ))
        .unwrap();
        for (name, value) in [("v", "1"), ("unused", "original")] {
            if parent.properties.get(name).is_none() {
                parent.properties.insert(name, value);
            }
        }
        let mut child = Pom::parse(&format!(
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
             </parent><artifactId>child</artifactId>{child}</project>"
        )).unwrap();
        child.overlay_user_properties(&ctx.properties);
        let source = crate::MemorySource::new().with_parent("g", "parent", "1", parent);
        crate::ready(EffectiveDescriptor::build(
            child,
            &source,
            ModelPolicy::PROJECT,
            ctx,
        ))
        .unwrap()
        .resolution_context
    }

    #[test]
    fn resolution_context_tracks_only_reached_parent_properties() {
        let ctx = ActivationContext::default();
        let dependency = |version| {
            format!(
                "<dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId>\
             <version>{version}</version></dependency></dependencies>"
            )
        };
        let changed = "<properties><v>2</v></properties>";
        let literal = dependency("1");
        assert_eq!(
            inherited_context("", &literal, &ctx),
            inherited_context(changed, &literal, &ctx)
        );
        let interpolation = dependency("${v}");
        let base = inherited_context("", &interpolation, &ctx);
        assert_ne!(base, inherited_context(changed, &interpolation, &ctx));
        assert_eq!(
            base,
            inherited_context("<description>edited</description>", &interpolation, &ctx)
        );
        assert_eq!(
            base,
            inherited_context(
                "<properties><unused>edited</unused></properties>",
                &interpolation,
                &ctx
            )
        );
    }

    #[test]
    fn public_import_coordinates_keep_model_fields_uncertain_through_properties() {
        for expression in [
            "${project.version}",
            "${alias}",
            "${chain}",
            "${pom.version}",
            "${basedir}",
            "${directory}",
            "${project.build.finalName}",
        ] {
            let pom = Pom::parse(&format!("<project><groupId>g</groupId><artifactId>b</artifactId><version>1</version><properties><project.version>2</project.version><pom.version>2</pom.version><basedir>2</basedir><project.build.finalName>2</project.build.finalName><alias>${{project.version}}</alias><chain>${{alias}}</chain><directory>${{basedir}}</directory></properties><dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>{expression}</version><scope>import</scope><type>pom</type></dependency></dependencies></dependencyManagement></project>")).unwrap();
            let descriptor = describe(&pom, &ActivationContext::default());
            assert_eq!(descriptor.gav.version, "1");
            assert!(
                descriptor.bom_imports[0].version.contains("${"),
                "{expression}: {:?}",
                descriptor.bom_imports
            );
        }
    }

    #[test]
    fn resolution_context_covers_inherited_management_imports_repositories_and_profiles() {
        let mut ctx = ActivationContext::default();
        ctx.active_profiles.push("p".into());
        for content in [
            "<dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>${v}</version></dependency></dependencies>",
            "<dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>bom</artifactId><version>${v}</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>",
            "<dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>${v}</version></dependency></dependencies></dependencyManagement>",
            "<repositories><repository><id>r</id><url>https://example.test/${v}</url></repository></repositories>",
            "<repositories><repository><id>${v}</id><url>https://example.test/</url><snapshots><enabled>${v}</enabled><updatePolicy>${v}</updatePolicy><checksumPolicy>${v}</checksumPolicy></snapshots></repository></repositories>",
            "<profiles><profile><id>p</id><dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>${v}</version></dependency></dependencies></profile></profiles>",
            "<build><finalName>${v}</finalName></build><dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>${project.build.finalName}</version></dependency></dependencies>",
        ] {
            assert_ne!(
                inherited_context(content, "", &ctx),
                inherited_context(
                    &format!("{content}<properties><v>2</v></properties>"),
                    "",
                    &ctx
                ),
                "{content}"
            );
        }
        // A raw import is recorded without asking the source for its BOM.
        assert!(!inherited_context("", "<dependencyManagement><dependencies><dependency><groupId>remote</groupId><artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>", &ctx).is_empty());
    }

    #[test]
    fn resolution_context_excludes_external_values_and_handles_indirect_names() {
        let child = "<dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId>\
                     <version>${v}</version></dependency></dependencies>";
        let mut ctx = ActivationContext::default();
        ctx.properties.insert("v".into(), "private-one".into());
        let first = inherited_context("", child, &ctx);
        ctx.properties.insert("v".into(), "private-two".into());
        assert_eq!(first, inherited_context("", child, &ctx));
        assert!(
            !first
                .iter()
                .flatten()
                .any(|value| value.contains("private"))
        );
        // Preserve the public expression graph even when its present expansion
        // is the same; an override may distinguish those expressions.
        assert_ne!(
            first,
            inherited_context(
                "<properties><v>${unused}</v><unused>1</unused></properties>",
                child,
                &ctx
            )
        );
        let indirect = child.replace("${v}", "${${selector}}");
        ctx.properties.insert("v".into(), "${unused}".into());
        assert_ne!(
            inherited_context("", child, &ctx),
            inherited_context("<properties><unused>2</unused></properties>", child, &ctx)
        );
        ctx.properties.insert("selector".into(), "v".into());
        assert_ne!(
            inherited_context("", &indirect, &ctx),
            inherited_context("<properties><v>2</v></properties>", &indirect, &ctx)
        );
        // An override can make a cyclic public property usable. Discovery
        // records that public context without rejecting the effective model.
        assert!(!inherited_context("<properties><v>${v}</v></properties>", child, &ctx).is_empty());
    }

    #[test]
    fn an_indirect_name_can_reach_every_model_value() {
        let mut ctx = ActivationContext::default();
        ctx.properties
            .insert("selector".into(), "project.prerequisites.maven".into());
        let child = |maven| {
            format!(
                "<prerequisites><maven>{maven}</maven></prerequisites><dependencies><dependency>\
                 <groupId>g</groupId><artifactId>lib</artifactId><version>${{${{selector}}}}</version>\
                 </dependency></dependencies>"
            )
        };
        assert_ne!(
            inherited_context("", &child("3"), &ctx),
            inherited_context("", &child("4"), &ctx)
        );
    }

    #[test]
    fn resolution_context_keeps_an_unread_remote_ancestor_reference() {
        let context = |version, property| {
            let parent = Pom::parse(&format!(
                "<project><parent><groupId>remote</groupId><artifactId>base</artifactId>\
                 <version>{version}</version><relativePath/></parent><groupId>g</groupId>\
                 <artifactId>parent</artifactId><version>1</version>\
                 <properties><read.only.by.remote>{property}</read.only.by.remote></properties></project>"
            ))
            .unwrap();
            let child = Pom::parse("<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId></project>").unwrap();
            let source = crate::MemorySource::new().with_parent("g", "parent", "1", parent);
            crate::ready(EffectiveDescriptor::build(
                child,
                &source,
                ModelPolicy {
                    root: true,
                    missing_parent: MissingParent::InheritDeclaredCoordinates,
                },
                &ActivationContext::default(),
            ))
            .unwrap()
            .resolution_context
        };
        assert_ne!(context("1", "one"), context("2", "one"));
        assert_ne!(context("1", "one"), context("1", "two"));
    }

    /// A parent the build went on without may still decide the coordinates
    /// when the POM takes its version from that `<parent>` element, or names
    /// a platform or environment value that a property of that parent would
    /// override.
    #[test]
    fn coordinates_an_unread_parent_may_decide_are_provisional() {
        let ctx = ActivationContext::new(
            crate::ModelEnvironment::builder()
                .platform("linux", "x86_64")
                .jdk_version("17")
                .env("REVISION", Some("1"))
                .build(),
        );
        for (parent, version, provisional) in [
            (true, "", true),
            (
                true,
                "<groupId>g</groupId><version>${java.version}</version>",
                true,
            ),
            (true, "<groupId>g</groupId><version>1</version>", false),
            (
                true,
                "<groupId>g</groupId><version>${env.REVISION}</version>",
                true,
            ),
            (
                true,
                "<groupId>g</groupId><version>${os.arch}</version>",
                true,
            ),
            (
                true,
                "<groupId>g</groupId><version>${revision}</version>\
                 <properties><revision>1</revision></properties>",
                false,
            ),
            (
                false,
                "<groupId>g</groupId><version>${env.REVISION}</version>",
                false,
            ),
        ] {
            let parent = match parent {
                true => {
                    "<parent><groupId>g</groupId><artifactId>p</artifactId>\
                         <version>1</version></parent>"
                }
                false => "",
            };
            let pom = Pom::parse(&format!(
                "<project>{parent}<artifactId>a</artifactId>{version}</project>"
            ))
            .unwrap();
            assert_eq!(
                describe(&pom, &ctx).gav_is_provisional(),
                provisional,
                "{parent}{version}"
            );
        }
    }

    /// The reactor descriptor takes its coordinates from `-D` values ahead
    /// of profile properties, or from the parent's declaration, and lists
    /// the modules of active profiles only.
    #[test]
    fn computes_ci_friendly_coordinates_and_active_profile_modules() {
        let reactor = Pom::parse(
            "<project><groupId>com.example</groupId><artifactId>reactor</artifactId>\
             <version>${revision}${sha1}${changelist}</version>\
             <modules><module>base</module></modules><profiles><profile><id>extras</id>\
             <modules><module>${module.dir}</module></modules><properties>\
             <module.dir>extra</module.dir><revision>profile</revision></properties>\
             </profile></profiles></project>",
        )
        .unwrap();
        let mut ctx = ActivationContext::default();
        for (name, value) in [
            ("revision", "2.0.0"),
            ("sha1", "-abc"),
            ("changelist", "-SNAPSHOT"),
        ] {
            ctx.properties.insert(name.to_string(), value.to_string());
        }
        let inactive = describe(&reactor, &ctx);
        assert!(inactive.active_profiles.is_empty());
        assert_eq!(inactive.modules, ["base"]);
        ctx.active_profiles.push("extras".to_string());
        let descriptor = describe(&reactor, &ctx);
        assert_eq!(
            descriptor.gav.to_string(),
            "com.example:reactor:2.0.0-abc-SNAPSHOT"
        );
        assert_eq!(descriptor.active_profiles, ["extras"]);
        assert_eq!(descriptor.modules, ["base", "extra"]);

        let child = Pom::parse(
            "<project><parent><groupId>com.example</groupId><artifactId>parent</artifactId>\
             <version>3.1.4</version></parent><artifactId>child</artifactId></project>",
        )
        .unwrap();
        let descriptor = describe(&child, &ctx);
        assert_eq!(descriptor.gav.to_string(), "com.example:child:3.1.4");
    }

    /// Discovery and a replayed lookup read `prerequisites.maven` as the
    /// model build does.
    #[test]
    fn the_maven_prerequisite_is_a_model_value() {
        let pom = Pom::parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <prerequisites><maven>2.0</maven></prerequisites>\
             <modules><module>m-${project.prerequisites.maven}</module></modules></project>",
        )
        .unwrap();
        let ctx = ActivationContext::default();
        assert_eq!(describe(&pom, &ctx).modules, ["m-2.0"]);
        let mut properties = PropertyMap::new();
        properties.insert("selector", "project.prerequisites.maven");
        let lookup = crate::properties::ModelLookup::new(&pom, None);
        let (value, _) = lookup.interpolate("${${selector}}", &properties, &ctx);
        assert_eq!(value.unwrap(), "2.0");
    }

    /// A replayed lookup reads a coordinate that named itself as the build
    /// expanded it, without the property behind it.
    #[test]
    fn a_replayed_lookup_keeps_a_coordinate_that_named_itself() {
        let pom = Pom::parse(
            "<project><groupId>${project.groupId}</groupId><artifactId>a</artifactId>\
             <version>1</version></project>",
        )
        .unwrap();
        let ctx = ActivationContext::default();
        let mut properties = PropertyMap::new();
        properties.insert("project.groupId", "com.example");
        let project = crate::model::project_info(&pom, &properties, &ctx).unwrap();
        let lookup = project.model_lookup.expect("a model lookup");
        let mut replayed = PropertyMap::new();
        replayed.insert("selector", "project.groupId");
        let (value, _) = lookup.interpolate("${${selector}}", &replayed, &ctx);
        assert_eq!(value.unwrap(), "com.example");
    }

    /// A `<file>` condition tests the project, so it counts as a host
    /// condition does: a profile it activates that brings resolution nothing
    /// is left out of the ids and records nothing, and one that does records
    /// the path it tested. `<os>` is tested first, and a condition after one
    /// that does not match records nothing.
    #[test]
    fn file_conditions_count_as_host_conditions() {
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("marker"), b"").unwrap();
        let dependency = "<dependencies><dependency><groupId>g</groupId>\
                          <artifactId>x</artifactId><version>1</version></dependency>\
                          </dependencies>";
        let build_only = "<properties><maven.compiler.release>21</maven.compiler.release>\
                          </properties>";
        use crate::HostInput;
        let file = |path: &str| HostInput::File(base.path().join(path).display().to_string());
        for (activation, content, active, read) in [
            (
                "<file><exists>marker</exists></file>",
                build_only,
                false,
                vec![],
            ),
            (
                "<file><exists>marker</exists></file>",
                dependency,
                true,
                vec![file("marker")],
            ),
            (
                "<os><family>mac</family></os><jdk>[17,)</jdk><file><missing>x</missing></file>",
                dependency,
                false,
                vec![],
            ),
            (
                "<jdk>[17,)</jdk><file><exists>absent</exists></file>",
                dependency,
                false,
                vec![file("absent")],
            ),
            (
                "<jdk>[17,)</jdk><file><exists>marker</exists></file>",
                dependency,
                true,
                vec![file("marker"), HostInput::Jdk("[17,)".to_string())],
            ),
        ] {
            let pom = Pom::parse(&format!(
                "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
                 <profiles><profile><id>p</id><activation>{activation}</activation>{content}\
                 </profile></profiles></project>"
            ))
            .unwrap();
            let host = crate::HostSnapshot::for_testing(&[]).with_java_version("21");
            let mut ctx = ActivationContext::new(host.environment("linux", "x86_64"));
            ctx.base_dir = Some(base.path().to_path_buf());
            let descriptor = describe(&pom, &ctx);
            assert_eq!(
                descriptor.active_profiles.is_empty(),
                !active,
                "{activation}{content}"
            );
            assert_eq!(
                host.consulted(),
                read.into_iter().collect(),
                "{activation}{content}"
            );
        }
        // A path that holds a host value, directly or through a `-D` value
        // expanded from one, is not recorded, only that value. Interpolation reads count only
        // for the path Maven tests, and only while the conditions before it
        // hold.
        let env = || HostInput::Env("CARGO_MANIFEST_DIR".to_string());
        for (activation, active, read) in [
            (
                "<file><exists>${env.CARGO_MANIFEST_DIR}/Cargo.toml</exists></file>",
                true,
                vec![env()],
            ),
            (
                "<file><exists>${project.basedir}/${probe}</exists></file>",
                true,
                vec![],
            ),
            (
                "<file><exists>${project.basedir}/${expanded}</exists></file>",
                true,
                vec![],
            ),
            (
                "<file><exists>marker</exists>\
                 <missing>${env.CARGO_MANIFEST_DIR}/x</missing></file>",
                true,
                vec![file("marker")],
            ),
            (
                "<os><family>mac</family></os>\
                 <file><exists>${env.CARGO_MANIFEST_DIR}/Cargo.toml</exists></file>",
                false,
                vec![],
            ),
            (
                "<file><exists>${project.basedir}/${packaging}</exists></file>",
                false,
                vec![file("jar")],
            ),
            (
                "<file><exists>marker/</exists></file>",
                true,
                vec![file("marker")],
            ),
            (
                "<jdk>99</jdk><property><name>env.CI</name><value>${probe}</value></property>",
                false,
                vec![HostInput::Jdk("99".to_string())],
            ),
        ] {
            let pom = Pom::parse(&format!(
                "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
                 <profiles><profile><id>p</id><activation>{activation}</activation>\
                 {dependency}</profile></profiles></project>"
            ))
            .unwrap();
            let host = crate::HostSnapshot::for_testing(&["CARGO_MANIFEST_DIR".to_string()]);
            let mut ctx = ActivationContext::new(host.environment("linux", "x86_64"));
            ctx.base_dir = Some(base.path().to_path_buf());
            for name in ["probe", "expanded"] {
                ctx.properties
                    .insert(name.to_string(), "marker".to_string());
            }
            ctx.expanded_properties.insert("expanded".to_string());
            let descriptor = describe(&pom, &ctx);
            assert_eq!(
                descriptor.active_profiles.is_empty(),
                !active,
                "{activation}"
            );
            assert_eq!(host.consulted(), read.into_iter().collect(), "{activation}");
        }
    }
}
