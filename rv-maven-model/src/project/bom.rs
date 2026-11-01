//! BOM (`import` scope) resolution in one pass against the importer's properties.

use crate::dependency::{Dependency, DependencyManagement};
use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::inheritance::{
    apply_inheritance_in_context, declares_expression, in_fetched_pom, is_fetched,
    is_reactor_module, observe_lineage_repositories, verify_pom_coord,
};
use crate::properties::{ProjectInfo, PropertyMap};
use crate::source::{ImportCoord, ModelPolicy, ModelSource, ParentLookup};
use crate::{ActivationContext, HostInput, ModelEnvironment, PomError};
use indexmap::IndexSet;
use rv_maven_types::bounded;

use super::dep_management::{
    interpolate_dependency, resolve_dependency, resolve_dependency_management,
    validate_dependencies,
};
use super::repositories::resolve_repositories;

#[derive(Debug)]
pub(super) struct BomImportResult {
    pub(super) management: DependencyManagement,
    /// Every import the build of these imports went through.
    imports: Vec<BomImportKey>,
    reached: usize,
    /// The first model error of these imports. Maven tries every import
    /// and fails on one it cannot resolve before it reports a model error.
    invalid: Option<PomError>,
}

type BomImportKey = (String, String, String, String, Option<String>);

/// What an imported BOM contributes to the build that imports it, which a
/// [`ModelSource`] may keep for later builds; see
/// [`ModelSource::reuse_import`].
pub struct ImportedBom {
    user_properties: HashMap<String, String>,
    system_properties: HashMap<String, String>,
    environment: ModelEnvironment,
    project_system_properties: HashMap<String, String>,
    project_environment: ModelEnvironment,
    management_dependencies: Arc<[Dependency]>,
    /// The BOM and every import its build went through. A build with one
    /// of them open would fail on the cycle, so it builds the BOM again.
    imports: Vec<BomImportKey>,
    /// How many levels below the importing one its build reached. A build
    /// that would pass [`MAX_BOM_DEPTH`] with it builds it again too.
    height: usize,
    activation_reads: Arc<BTreeSet<HostInput>>,
    project_reads: Arc<BTreeSet<HostInput>>,
}

impl std::fmt::Debug for ImportedBom {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportedBom")
            .field("imports", &self.imports)
            .finish_non_exhaustive()
    }
}

impl ImportedBom {
    /// Whether a build in `ctx` and `project` at nesting level `depth`,
    /// with `stack` open, would build this contribution again.
    fn rebuilds_alike(
        &self,
        ctx: &ActivationContext,
        project: &ProjectInfo,
        stack: &IndexSet<BomImportKey>,
        depth: usize,
    ) -> bool {
        self.user_properties == ctx.properties
            && self.system_properties == ctx.system_properties
            && self.environment == ctx.environment
            && self.project_system_properties == project.system_properties
            && self.project_environment == project.environment
            && depth + self.height < MAX_BOM_DEPTH
            && !self.imports.iter().any(|import| stack.contains(import))
    }
}

/// Collects the host reads made through `detached`, a copy of `to`, and
/// passes them on to `to`, also when the build fails before [`Self::take`].
struct ForwardReads<'e> {
    detached: ModelEnvironment,
    to: &'e ModelEnvironment,
}

impl<'e> ForwardReads<'e> {
    fn new(to: &'e ModelEnvironment) -> Self {
        Self {
            detached: to.detached(),
            to,
        }
    }

    fn take(self) -> Arc<BTreeSet<HostInput>> {
        let reads = Arc::new(self.detached.take_reads());
        self.to.record_reads(&reads);
        reads
    }
}

impl Drop for ForwardReads<'_> {
    fn drop(&mut self) {
        for input in self.detached.take_reads() {
            self.to.record(input);
        }
    }
}

/// Cap on BOM import nesting depth. Cycle detection catches repeated
/// coordinates but not a DAG of N distinct BOMs; without a depth cap an
/// adversarial chain of unique BOMs would recurse until OS stack exhaustion.
pub(crate) const MAX_BOM_DEPTH: usize = 50;

/// Ends the BOM build its source entered when dropped, so a failed build
/// leaves the scope too.
struct ImportScope<'s, S: ModelSource>(&'s S);

impl<S: ModelSource> Drop for ImportScope<'_, S> {
    fn drop(&mut self) {
        self.0.leave_import();
    }
}

fn import_key(dep: &Dependency, version: &str) -> BomImportKey {
    (
        dep.group_id.clone(),
        dep.artifact_id.clone(),
        version.to_string(),
        dep.type_.as_deref().unwrap_or("pom").to_string(),
        dep.classifier
            .clone()
            .filter(|classifier| !classifier.is_empty()),
    )
}

/// Maven's importer keys the management once a BOM is imported: a later
/// local replaces an earlier one with the same key in its place, and an
/// imported entry joins only under a key no local or earlier BOM holds.
fn merge_imports(locals: Vec<Dependency>, imports: &[Arc<[Dependency]>]) -> Vec<Dependency> {
    enum Slot {
        Local(usize),
        Imported(usize, usize),
    }
    let capacity = locals.len() + imports.iter().map(|import| import.len()).sum::<usize>();
    let mut positions = foldhash::HashMap::with_capacity_and_hasher(capacity, Default::default());
    let mut slots = Vec::with_capacity(capacity);
    for (at, dep) in locals.iter().enumerate() {
        match positions.entry(dep.management_key()) {
            Entry::Occupied(slot) => slots[*slot.get()] = Slot::Local(at),
            Entry::Vacant(slot) => {
                slot.insert(slots.len());
                slots.push(Slot::Local(at));
            }
        }
    }
    for (from, import) in imports.iter().enumerate() {
        for (at, dep) in import.iter().enumerate() {
            if let Entry::Vacant(slot) = positions.entry(dep.management_key()) {
                slot.insert(slots.len());
                slots.push(Slot::Imported(from, at));
            }
        }
    }
    drop(positions);
    let mut locals: Vec<Option<Dependency>> = locals.into_iter().map(Some).collect();
    slots
        .into_iter()
        .filter_map(|slot| match slot {
            Slot::Local(at) => locals[at].take(),
            Slot::Imported(from, at) => Some(imports[from][at].clone()),
        })
        .collect()
}

/// Apply the BOM imports of `management`. `blame` attributes an error in the
/// importing model's own entries; see [`crate::inheritance::in_pom`].
///
/// `ctx` is the importer's activation context. Maven builds an imported BOM
/// with the importer's system and user properties, the importer's
/// `packaging` user property among them, and without its profile ids or
/// project directory.
pub(super) async fn resolve_bom_imports_blamed<S: ModelSource>(
    management: DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
    source: &S,
    policy: ModelPolicy,
    ctx: &ActivationContext,
    blame: &(dyn Fn(PomError) -> PomError + Send + Sync),
) -> Result<BomImportResult, S::Error> {
    if !management.dependencies.iter().any(maybe_bom_import) {
        return Ok(BomImportResult {
            management: resolve_dependency_management(management, properties, project, true)
                .map_err(blame)?,
            imports: Vec::new(),
            reached: 0,
            invalid: None,
        });
    }

    let import_ctx = ActivationContext {
        property_source: match ctx.property_source {
            crate::PropertySource::System => crate::PropertySource::System,
            _ => crate::PropertySource::Import,
        },
        default_packaging: ctx.default_packaging.clone(),
        packaging_injected: ctx.packaging_injected,
        properties: ctx.properties.clone(),
        environment: ctx.environment.clone(),
        system_properties: ctx.system_properties.clone(),
        ..ActivationContext::default()
    };
    // An imported BOM is built at Maven's minimal validation level, not as
    // the project.
    let import_policy = ModelPolicy {
        root: false,
        ..policy
    };
    let mut stack: IndexSet<BomImportKey> = IndexSet::new();
    let imports = resolve_bom_imports_inner(
        management,
        properties,
        project,
        source,
        import_policy,
        &import_ctx,
        &mut stack,
        0,
        blame,
    );
    // Held so that what each BOM's build logs tells whether another
    // importer may reuse it; see `ModelSource::import_holds`.
    let mut result = match source.import_holds() {
        Some(holds) => {
            let (result, logged) = holds.hold(imports).await;
            logged.show();
            result
        }
        None => imports.await,
    }?;
    match result.invalid.take() {
        Some(error) => Err(error.into()),
        None => Ok(result),
    }
}

/// An import's dependency interpolated against the importer's own
/// properties, and its version; an error when Maven refuses the import.
/// `None` for an entry Maven does not import because its interpolated
/// scope is not `import` or its type is not `pom`, such as one without a
/// `<type>`: it stays a managed dependency.
///
/// Maven removes an import from the model before it validates the
/// managed dependencies, so only the coordinates it looks up are checked.
fn prepare_import(
    dependency: &Dependency,
    properties: &PropertyMap,
    project: &ProjectInfo,
    blame: &(dyn Fn(PomError) -> PomError + Send + Sync),
) -> Result<Option<(Dependency, String)>, PomError> {
    let dep =
        interpolate_dependency(dependency.clone(), properties, project, None).map_err(blame)?;
    // Scope may still hold `${...}` until this pass; a literal non-import
    // never reaches here because [`maybe_bom_import`] filtered it out.
    if !dep.is_import_scope() || dep.type_.as_deref() != Some("pom") {
        return Ok(None);
    }
    for (field, value) in [("groupId", &dep.group_id), ("artifactId", &dep.artifact_id)] {
        if value.is_empty() {
            return Err(blame(dep.missing(true, field)));
        }
    }
    let version = dep
        .version
        .clone()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            PomError::InvalidModel(format!(
                "import scope requires a version for {}:{}",
                bounded(&dep.group_id),
                bounded(&dep.artifact_id)
            ))
        })?;
    Ok(Some((dep, version)))
}

/// Whether an import's interpolated coordinates keep a `${...}`.
fn has_expression(dep: &Dependency, version: &str) -> bool {
    [&dep.group_id, &dep.artifact_id, version]
        .iter()
        .any(|value| value.contains("${"))
}

/// Cheap filter for a management entry that might become a BOM import after
/// interpolation: a literal `import` scope, or a scope that still holds
/// `${...}`.
fn maybe_bom_import(dep: &Dependency) -> bool {
    dep.is_import_scope()
        || dep
            .scope
            .as_deref()
            .is_some_and(|scope| scope.contains("${"))
}

type BomImportFuture<'a, E> = Pin<Box<dyn Future<Output = Result<BomImportResult, E>> + Send + 'a>>;

#[allow(clippy::too_many_arguments)]
fn resolve_bom_imports_inner<'a, S: ModelSource>(
    management: DependencyManagement,
    properties: &'a PropertyMap,
    project: &'a ProjectInfo,
    source: &'a S,
    policy: ModelPolicy,
    ctx: &'a ActivationContext,
    stack: &'a mut IndexSet<BomImportKey>,
    depth: usize,
    blame: &'a (dyn Fn(PomError) -> PomError + Send + Sync),
) -> BomImportFuture<'a, S::Error> {
    Box::pin(async move {
        if depth >= MAX_BOM_DEPTH {
            return Err(PomError::InvalidModel(format!(
                "BOM nesting too deep (limit {MAX_BOM_DEPTH})"
            ))
            .into());
        }
        // Keep literal `import` scopes and scopes that still hold `${...}`
        // so property-interpolated import scopes become imports after
        // [`prepare_import`], as Maven does.
        let mut pending_imports = Vec::new();
        let mut locals = Vec::new();
        for dep in management.dependencies {
            if maybe_bom_import(&dep) {
                pending_imports.push(dep);
            } else {
                locals.push(dep);
            }
        }

        // The management of each import, in declaration order.
        let mut resolved_imports: Vec<Arc<[Dependency]>> = Vec::new();
        let mut imports_seen: Vec<BomImportKey> = Vec::new();
        let mut reached = depth;

        // Maven resolves each import coordinate with the importer's own
        // properties only, so one pass suffices.
        let mut prepared = Vec::new();
        for pending in pending_imports {
            match prepare_import(&pending, properties, project, blame) {
                Ok(None) => locals.push(pending),
                Ok(Some(import)) => prepared.push((pending, Ok(import))),
                Err(error) => prepared.push((pending, Err(error))),
            }
        }
        // The source may start fetching every import this loop will ask for,
        // in order.
        let upcoming: Vec<ImportCoord<'_>> = prepared
            .iter()
            .filter_map(|(_, dep)| dep.as_ref().ok())
            .filter(|(dep, version)| !has_expression(dep, version))
            .filter_map(|(dep, version)| {
                (!stack.contains(&import_key(dep, version))).then_some(ImportCoord {
                    group_id: &dep.group_id,
                    artifact_id: &dep.artifact_id,
                    version,
                    type_: dep.type_.as_deref(),
                    classifier: dep.classifier.as_deref(),
                })
            })
            .collect();
        if !upcoming.is_empty() {
            source.prefetch_imports(&upcoming);
        }
        drop(upcoming);

        let mut invalid = None;
        for (pending, dep) in prepared {
            let (dep, version) = match dep {
                Ok(import) => import,
                Err(error) => {
                    invalid.get_or_insert(error);
                    continue;
                }
            };
            let version = &version;

            if has_expression(&dep, version) {
                return Err(PomError::UnresolvedImport(
                    format!("{}:{}:{version}", dep.group_id, dep.artifact_id),
                    format!(
                        "{}:{}:{}",
                        pending.group_id,
                        pending.artifact_id,
                        pending.version.as_deref().unwrap_or_default()
                    ),
                )
                .into());
            }

            let key = import_key(&dep, version);
            if stack.contains(&key) {
                invalid.get_or_insert(PomError::InvalidModel(format!(
                    "BOM import cycle detected for {}:{}:{}:{}{}",
                    bounded(&dep.group_id),
                    bounded(&dep.artifact_id),
                    bounded(version),
                    bounded(&key.3),
                    key.4
                        .as_deref()
                        .map(|value| format!(":{}", bounded(value)))
                        .unwrap_or_default()
                )));
                continue;
            }

            let coord = ImportCoord {
                group_id: &dep.group_id,
                artifact_id: &dep.artifact_id,
                version,
                type_: dep.type_.as_deref(),
                classifier: dep.classifier.as_deref(),
            };
            let usable = |kept: &ImportedBom| kept.rebuilds_alike(ctx, project, stack, depth);
            if let Some(kept) = source.reuse_import(coord, policy, &usable) {
                source.reused_import()?;
                ctx.environment.record_reads(&kept.activation_reads);
                project.environment.record_reads(&kept.project_reads);
                reached = reached.max(depth + kept.height);
                imports_seen.extend(kept.imports.iter().cloned());
                resolved_imports.push(Arc::clone(&kept.management_dependencies));
                continue;
            }

            stack.insert(key.clone());
            let built: Result<(), PomError> = 'build: {
                let Some(bom_pom) = source.import(coord).await? else {
                    return Err(PomError::ImportNotFound(
                        dep.group_id.clone(),
                        dep.artifact_id.clone(),
                        version.clone(),
                    )
                    .into());
                };
                // Verify the served BOM POM advertises the coordinates we requested.
                // Without this check, a hostile remote could swap in a payload with
                // unrelated dependencyManagement entries that would silently land in
                // the importing project's resolved version table.
                // A BOM that names itself through a property of its own parent is
                // checked once its lineage is merged.
                let reactor = is_reactor_module(&bom_pom);
                let verified = match reactor {
                    true => Ok(()),
                    false => verify_pom_coord(&dep.group_id, &dep.artifact_id, version, &bom_pom),
                };
                let unverified = match verified {
                    Ok(()) => None,
                    Err(error) if declares_expression(&bom_pom) => Some(error),
                    Err(error) => return Err(error.into()),
                };
                let bom_label = is_fetched(&bom_pom).then(|| {
                    format!(
                        "{}:{}:{}",
                        bounded(&dep.group_id),
                        bounded(&dep.artifact_id),
                        bounded(version)
                    )
                });
                let bom_own = |error: PomError| match &bom_label {
                    Some(label) => in_fetched_pom(|| label.clone(), error),
                    None => error,
                };
                tracing::debug!(
                    group_id = %bounded(&dep.group_id),
                    artifact_id = %bounded(&dep.artifact_id),
                    version = %bounded(version),
                    "resolved BOM import"
                );
                // Maven builds the BOM with a copy of the importer's
                // model resolver: what the BOM's lineage declares serves
                // the BOM's own parents and imports, and is gone after.
                source.enter_import();
                let import_scope = ImportScope(source);
                // What the build reads from the host is kept with it.
                let activation_reads = ForwardReads::new(&ctx.environment);
                let project_reads = ForwardReads::new(&project.environment);
                let bom_ctx = ActivationContext {
                    environment: activation_reads.detached.clone(),
                    ..ctx.clone()
                };
                let importer = ctx;
                let ctx = &bom_ctx;
                observe_lineage_repositories(source, &bom_pom, Some(ctx))?;
                let mut bom_effective = apply_inheritance_in_context(
                    bom_pom,
                    source,
                    policy,
                    ParentLookup::Import,
                    Some(ctx),
                )
                .await?;
                if reactor {
                    source.imported_reactor_profiles(coord, &bom_effective.selected_profiles);
                }
                // User properties win over the BOM's own, as in any model.
                for (key, value) in &ctx.properties {
                    bom_effective
                        .properties
                        .insert_external(key.as_str(), value.as_str());
                }
                // Maven builds an imported BOM with the importing build's
                // system properties.
                let bom_info = crate::model::project_info_in(
                    &bom_effective,
                    &bom_effective.properties,
                    None,
                    project.system_properties.clone(),
                    &project_reads.detached,
                )
                .map_err(bom_own);
                let bom_info = match bom_info {
                    Ok(bom_info) => bom_info,
                    Err(error) => break 'build Err(error),
                };
                if let Some(error) = unverified
                    && (bom_info.group_id != dep.group_id
                        || bom_info.artifact_id != dep.artifact_id
                        || bom_info.version != *version)
                {
                    return Err(error.into());
                }
                // A URL that fails to interpolate leaves the BOM's
                // effective repositories unobserved instead of failing
                // the import.
                if let Ok(repositories) = resolve_repositories(
                    bom_effective.repositories.clone(),
                    &bom_effective.properties,
                    &bom_info,
                ) && !repositories.is_empty()
                {
                    source.observe_effective_repositories(&repositories);
                }
                let bom_result = resolve_bom_imports_inner(
                    bom_effective.dependency_management.unwrap_or_default(),
                    &bom_effective.properties,
                    &bom_info,
                    source,
                    policy,
                    ctx,
                    &mut *stack,
                    depth + 1,
                    &bom_own,
                )
                .await?;
                drop(import_scope);
                if let Some(error) = bom_result.invalid {
                    break 'build Err(error);
                }

                // Each BOM interpolated its own entries with its own
                // properties; properties never pass from one BOM to another.
                let management = bom_result.management;
                // Maven builds the whole BOM model, its own dependencies included.
                if let Err(error) = validate_dependencies(
                    &bom_effective.dependencies,
                    &management,
                    &bom_effective.properties,
                    &bom_info,
                ) {
                    break 'build Err(bom_own(error));
                }
                let managed_deps: Arc<[Dependency]> = management.dependencies.into();

                let mut subtree = bom_result.imports;
                subtree.push(key.clone());
                reached = reached.max(bom_result.reached);
                source.keep_import(
                    coord,
                    policy,
                    Arc::new(ImportedBom {
                        user_properties: importer.properties.clone(),
                        system_properties: importer.system_properties.clone(),
                        environment: importer.environment.clone(),
                        project_system_properties: project.system_properties.clone(),
                        project_environment: project.environment.clone(),
                        management_dependencies: Arc::clone(&managed_deps),
                        imports: subtree.clone(),
                        height: bom_result.reached - depth,
                        activation_reads: activation_reads.take(),
                        project_reads: project_reads.take(),
                    }),
                );
                imports_seen.extend(subtree);
                resolved_imports.push(managed_deps);
                Ok(())
            };
            // Remove this iteration's guard precisely by key. `IndexSet::pop`
            // removes the most recently inserted entry, which is wrong when
            // recursive BOM resolution above also pushed and popped entries:
            // the topmost entry at this point may not be ours. `shift_remove`
            // targets the exact key we inserted, so the guard works under
            // nested recursion.
            stack.shift_remove(&key);
            if let Err(error) = built {
                invalid.get_or_insert(error);
            }
        }

        // Locals are this level's own managed dependencies, so they
        // interpolate against this level's own effective properties. Without
        // an import every entry stays.
        let mut dependencies = Vec::new();
        for dep in locals {
            match resolve_dependency(dep, properties, project) {
                Ok(dep) => dependencies.push(dep),
                Err(error) => {
                    invalid.get_or_insert(blame(error));
                }
            }
        }
        if !resolved_imports.is_empty() {
            dependencies = merge_imports(dependencies, &resolved_imports);
        }

        imports_seen.sort_unstable();
        imports_seen.dedup();
        Ok(BomImportResult {
            management: DependencyManagement { dependencies },
            imports: imports_seen,
            reached,
            invalid,
        })
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::pom::{Parent, Pom};
    use crate::source::ready;
    use crate::{MemorySource, MemorySourceError, Project};

    fn import(artifact_id: &str, version: &str, type_: &str) -> String {
        format!(
            "<dependency><groupId>com.example</groupId><artifactId>{artifact_id}</artifactId>\
             <version>{version}</version>{type_}<scope>import</scope></dependency>"
        )
    }

    fn bom(artifact_id: &str, entries: &str) -> Pom {
        Pom::parse(&format!(
            "<project><groupId>com.example</groupId><artifactId>{artifact_id}</artifactId>\
             <version>1</version><properties><second.version>1</second.version></properties>\
             <dependencyManagement><dependencies>{entries}</dependencies>\
             </dependencyManagement></project>"
        ))
        .unwrap()
    }

    fn build<S: ModelSource>(
        root: Pom,
        source: &S,
        ctx: &ActivationContext,
    ) -> Result<Project, S::Error> {
        ready(Project::build(root, source, ModelPolicy::DEPENDENCY, ctx))
    }

    fn managed(project: &Project) -> Vec<&str> {
        let entries = &project.dependency_management.dependencies;
        entries.iter().map(|dep| dep.artifact_id.as_str()).collect()
    }

    /// Refused imports still let later ones be asked for, as Maven does.
    #[test]
    fn imports_are_announced_before_they_are_fetched() {
        let imports = [
            import("first", "1", "<type>pom</type>"),
            import("managed", "1", ""),
            import("second", "${second.version}", "<type>pom</type>"),
            "<dependency><groupId>com.example</groupId><artifactId>refused</artifactId>\
             <type>pom</type><scope>import</scope></dependency>"
                .to_string(),
            import("never", "1", "<type>pom</type>"),
        ];
        let source = MemorySource::new()
            .with_import("com.example", "first", "1", bom("first", ""))
            .with_import("com.example", "second", "1", bom("second", ""));
        let error = build(
            bom("app", &imports.concat()),
            &source,
            &ActivationContext::default(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("BOM not found: com.example:never:1"),
            "{error}"
        );
        let events: Vec<String> = source
            .events()
            .into_iter()
            .filter(|event| !matches!(event.as_str(), "enter" | "leave"))
            .collect();
        assert_eq!(
            events,
            [
                "prefetch com.example:first:1 com.example:second:1 com.example:never:1",
                "import com.example:first:1",
                "import com.example:second:1",
                "import com.example:never:1",
            ]
        );
    }

    /// The BOM analog of the parent-coord-mismatch attack: a repository
    /// answering with a BOM that declares other coordinates is refused
    /// rather than folded into the model.
    #[test]
    fn mismatched_bom_coord_is_rejected() {
        let foreign = Pom::parse(
            "<project><groupId>evil.attacker</groupId><artifactId>backdoor</artifactId>\
             <version>0.0.1</version></project>",
        )
        .unwrap();
        let source = MemorySource::new().with_import("com.example", "platform", "1.0.0", foreign);
        let root = bom("app", &import("platform", "1.0.0", "<type>pom</type>"));
        let error = build(root, &source, &ActivationContext::default()).unwrap_err();
        let MemorySourceError::Model(PomError::ParentCoordMismatch(mismatch)) = error else {
            panic!("expected a coordinate mismatch, got {error:?}");
        };
        assert_eq!(
            [
                &mismatch.expected_group,
                &mismatch.expected_artifact,
                &mismatch.expected_version
            ],
            ["com.example", "platform", "1.0.0"]
        );
        assert_eq!(
            [
                &mismatch.actual_group,
                &mismatch.actual_artifact,
                &mismatch.actual_version
            ],
            ["evil.attacker", "backdoor", "0.0.1"]
        );
    }

    /// A BOM deployed with `${revision}` from its own parent is the BOM it
    /// was imported as when its lineage expands it to that version and it
    /// declares the imported artifactId.
    #[test]
    fn a_bom_may_name_itself_through_its_parent() {
        let parent = |revision: &str| {
            Pom::parse(&format!(
                "<project><groupId>com.example</groupId><artifactId>bp</artifactId>\
                 <version>1</version><properties><revision>{revision}</revision>\
                 </properties></project>"
            ))
            .unwrap()
        };
        let platform = |artifact: &str| {
            Pom::parse(&format!(
                "<project><parent><groupId>com.example</groupId><artifactId>bp</artifactId>\
                 <version>1</version></parent><artifactId>{artifact}</artifactId>\
                 <version>${{revision}}</version><properties><id>platform</id></properties>\
                 </project>"
            ))
            .unwrap()
        };
        let root = bom("app", &import("platform", "2", "<type>pom</type>"));
        for (artifact, revision, accepted) in [
            ("platform", "2", true),
            ("${id}", "2", true),
            ("platform", "3", false),
            ("other", "2", false),
        ] {
            let source = MemorySource::new()
                .with_import("com.example", "platform", "2", platform(artifact))
                .with_parent("com.example", "bp", "1", parent(revision));
            let result = build(root.clone(), &source, &ActivationContext::default());
            match result {
                Ok(_) => assert!(accepted, "{revision}"),
                Err(MemorySourceError::Model(PomError::ParentCoordMismatch(_))) => {
                    assert!(!accepted, "{revision}")
                }
                Err(error) => panic!("{revision}: {error}"),
            }
        }
    }

    /// A BOM without a version of its own takes its parent's as written,
    /// expanded with the BOM's properties.
    #[test]
    fn a_bom_inherits_its_version_as_written() {
        let parent = Pom::parse(
            "<project><groupId>com.example</groupId><artifactId>bp</artifactId>\
             <version>${revision}</version><properties><revision>1</revision></properties>\
             </project>",
        )
        .unwrap();
        let root = bom("app", &import("platform", "2", "<type>pom</type>"));
        for (revision, accepted) in [("2", true), ("3", false)] {
            let platform = Pom::parse(&format!(
                "<project><parent><groupId>com.example</groupId><artifactId>bp</artifactId>\
                 <version>1</version></parent><artifactId>platform</artifactId>\
                 <properties><revision>{revision}</revision></properties></project>"
            ))
            .unwrap();
            let source = MemorySource::new()
                .with_import("com.example", "platform", "2", platform)
                .with_parent("com.example", "bp", "1", parent.clone());
            match build(root.clone(), &source, &ActivationContext::default()) {
                Ok(_) => assert!(accepted, "{revision}"),
                Err(MemorySourceError::Model(PomError::ParentCoordMismatch(_))) => {
                    assert!(!accepted, "{revision}")
                }
                Err(error) => panic!("{revision}: {error}"),
            }
        }
    }

    /// Maven builds an imported BOM with the importing build's system
    /// properties, so `${os.arch}` and `${os.detected.classifier}` in a BOM
    /// name the platform being locked, not the host.
    #[test]
    fn bom_interpolates_with_the_importing_platform() {
        let native = "<dependency><groupId>com.example</groupId><artifactId>native</artifactId>\
            <version>1.0-${os.arch}</version><classifier>${os.detected.classifier}</classifier>\
            </dependency>";
        let source = MemorySource::new().with_import("com.example", "bom", "1", bom("bom", native));
        let mut ctx = ActivationContext::default();
        ctx.set_platform("macos", "aarch64");
        let root = bom("app", &import("bom", "1", "<type>pom</type>"));
        let project = build(root, &source, &ctx).unwrap();
        let native = &project.dependency_management.dependencies[0];
        assert_eq!(native.version.as_deref(), Some("1.0-aarch64"));
        assert_eq!(native.classifier.as_deref(), Some("osx-aarch_64"));
    }

    /// A source over BOMs that each import the BOMs listed for them and
    /// manage one artifact named after themselves, and that keeps what
    /// builds hand it.
    #[derive(Default)]
    struct Keeper {
        imports: Mutex<HashMap<String, Vec<String>>>,
        kept: Mutex<HashMap<String, Arc<ImportedBom>>>,
        lookups: Mutex<Vec<String>>,
        /// BOMs served as written instead of generated.
        written: Mutex<HashMap<String, Pom>>,
    }

    impl Keeper {
        fn with(self, bom: &str, imports: &[&str]) -> Self {
            let imports = imports.iter().map(|name| name.to_string()).collect();
            self.imports
                .lock()
                .unwrap()
                .insert(bom.to_string(), imports);
            self
        }

        fn build_in(&self, bom_id: &str, ctx: &ActivationContext) -> Result<Vec<String>, PomError> {
            let root = bom("app", &import(bom_id, "1", "<type>pom</type>"));
            let project = build(root, self, ctx)?;
            Ok(managed(&project).into_iter().map(str::to_string).collect())
        }

        fn build(&self, bom: &str) -> Result<Vec<String>, PomError> {
            self.build_in(bom, &ActivationContext::default())
        }

        fn lookups(&self) -> Vec<String> {
            self.lookups.lock().unwrap().clone()
        }
    }

    impl ModelSource for Keeper {
        type Error = PomError;

        async fn parent(&self, _: &mut Parent, _: ParentLookup) -> Result<Option<Pom>, PomError> {
            Ok(None)
        }

        async fn import(&self, coord: ImportCoord<'_>) -> Result<Option<Pom>, PomError> {
            let name = coord.artifact_id;
            self.lookups.lock().unwrap().push(name.to_string());
            if let Some(pom) = self.written.lock().unwrap().get(name) {
                return Ok(Some(pom.clone()));
            }
            let imports = self.imports.lock().unwrap();
            let nested = imports.get(name).into_iter().flatten();
            let entries: String = nested.map(|n| import(n, "1", "<type>pom</type>")).collect();
            let own = format!(
                "<dependency><groupId>com.example</groupId><artifactId>{name}-lib</artifactId>\
                 <version>1</version></dependency>"
            );
            Ok(Some(bom(name, &(entries + &own))))
        }

        fn reuse_import(
            &self,
            bom: ImportCoord<'_>,
            _: ModelPolicy,
            usable: &dyn Fn(&ImportedBom) -> bool,
        ) -> Option<Arc<ImportedBom>> {
            let kept = self.kept.lock().unwrap().get(bom.artifact_id).cloned();
            kept.filter(|kept| usable(kept))
        }

        fn keep_import(&self, bom: ImportCoord<'_>, _: ModelPolicy, imported: Arc<ImportedBom>) {
            let name = bom.artifact_id.to_string();
            self.kept.lock().unwrap().insert(name, imported);
        }
    }

    #[test]
    fn a_kept_import_is_reused_and_contributes_the_same() {
        let source = Keeper::default()
            .with("outer", &["inner"])
            .with("inner", &[]);
        let first = source.build("outer").unwrap();
        assert_eq!(source.lookups(), ["outer", "inner"]);
        let again = source.build("outer").unwrap();
        assert_eq!(source.lookups(), ["outer", "inner"]);
        assert_eq!(first, ["outer-lib", "inner-lib"]);
        assert_eq!(again, first);
    }

    /// A reuse records the host reads the build it stands for made, so a
    /// lock lists the same inputs whichever build ran first.
    #[test]
    fn a_kept_import_records_the_host_reads_of_its_build() {
        let source = Keeper::default();
        let jdk_bom = Pom::parse(
            "<project><groupId>com.example</groupId><artifactId>jdk-bom</artifactId>\
             <version>1</version><packaging>pom</packaging><profiles><profile><id>p</id>\
             <activation><jdk>[21,)</jdk></activation><dependencyManagement><dependencies>\
             <dependency><groupId>g</groupId><artifactId>lib</artifactId><version>1</version>\
             </dependency></dependencies></dependencyManagement></profile></profiles></project>",
        )
        .unwrap();
        source
            .written
            .lock()
            .unwrap()
            .insert("jdk-bom".to_string(), jdk_bom);
        let reads = || {
            let host = crate::HostSnapshot::for_testing(&[]).with_java_version("21");
            let ctx = ActivationContext::new(host.environment("linux", "x86_64"));
            assert_eq!(source.build_in("jdk-bom", &ctx).unwrap(), ["lib"]);
            host.consulted()
        };
        let built = reads();
        assert_eq!(built, BTreeSet::from([HostInput::Jdk("[21,)".to_string())]));
        let reused = reads();
        assert_eq!(source.lookups(), ["jdk-bom"]);
        assert_eq!(reused, built);
    }

    /// A kept import is built again where reusing it would hide a cycle or
    /// nest past [`MAX_BOM_DEPTH`].
    #[test]
    fn a_kept_import_is_built_again_where_it_would_close_a_cycle_or_nest_too_deep() {
        let source = Keeper::default()
            .with("outer", &["inner"])
            .with("inner", &[]);
        source.build("outer").unwrap();
        // `inner` now imports `outer`, and the source still offers what
        // `outer` contributed when it did not.
        let source = source.with("inner", &["outer"]);
        source.kept.lock().unwrap().remove("inner");
        let error = source.build("inner").unwrap_err();
        assert!(error.to_string().contains("cycle"), "{error}");

        let names: Vec<String> = (0..MAX_BOM_DEPTH).map(|n| format!("bom{n}")).collect();
        let mut source = Keeper::default();
        for pair in names.windows(2) {
            source = source.with(&pair[0], &[pair[1].as_str()]);
        }
        // From the top, `bom1`'s chain stays within the limit; one level
        // deeper, as it is under `bom0`, it does not.
        source.build("bom1").unwrap();
        let error = source.build("bom0").unwrap_err();
        assert!(error.to_string().contains("too deep"), "{error}");
    }
}
