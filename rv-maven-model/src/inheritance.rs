use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use indexmap::IndexMap;
use rv_maven_types::{MavenMode, bounded};

use crate::activation::select_profiles;
use crate::dependency::{Dependency, DependencyManagement};
use crate::error::ParentCoordMismatch;
use crate::pom::{Build, Parent};
use crate::provenance::Provenance;
use crate::relevance::{LineageRole, ResolutionKeys};
use crate::repository::Repository;
use crate::source::{MissingParent, ModelPolicy, ModelSource, ParentLookup};
use crate::{ActivationContext, Pom, PomError, Profile, PropertyMap};

/// Maximum number of `<parent>` hops any parent chain may traverse.
///
/// Every traversal of a parent chain shares this one limit so that the parents
/// inheritance resolves, the parents reactor discovery tolerates, and the
/// parents `raeva sync`'s model hash covers are the same set. A chain within the
/// limit is walked in full by all of them; a chain that needs one more hop is
/// rejected here before any resolution result can depend on the extra parent.
/// Real-world POMs rarely chain past four levels; the cap exists to keep a
/// pathological chain from spinning forever.
pub const MAX_PARENT_CHAIN_DEPTH: usize = 100;

/// Whether a `<parent>` declaration holds a `${...}` expression.
///
/// Maven 3.9 looks a parent up by its coordinates as written: the POM at
/// `<relativePath>` matches only when it declares the same text, such as the
/// same `${revision}`, and a repository lookup uses the unexpanded text, which
/// names no artifact. Every traversal of a parent chain therefore uses the raw
/// declaration, and a parent with an expression is never fetched remotely.
pub fn parent_has_expression(parent: &Parent) -> bool {
    [&parent.group_id, &parent.artifact_id, &parent.version]
        .iter()
        .any(|value| value.contains("${"))
}

/// The version range a `<parent>` names, such as `[1.0,2.0)`, which Maven
/// resolves to the highest version in it, read in `mode`'s version order.
/// Maven checks a local parent against the range with maven-artifact's
/// order in every mode; the resolver's order counts for a remote one.
pub fn parent_version_range(
    parent: &Parent,
    mode: MavenMode,
) -> Option<rv_maven_types::VersionReq> {
    let version = parent.version.trim_start();
    if !version.starts_with(['[', '(']) {
        return None;
    }
    rv_maven_types::VersionReq::parse_in(version, mode).ok()
}

/// `error`, found in `pom`'s own content. A project build reports a
/// property cycle or a `<parent>` that keeps a `${...}` as a fault of the
/// project's own POMs, so when `pom` was fetched from a repository they
/// become [`PomError::InvalidModel`] and
/// [`PomError::FetchedParentExpression`] naming `pom`.
pub(crate) fn in_pom(pom: &Pom, error: PomError) -> PomError {
    if !is_fetched(pom) {
        return error;
    }
    in_fetched_pom(|| pom_label(pom), error)
}

/// `pom`'s coordinates for a message, a missing group or version taken from
/// its `<parent>`.
fn pom_label(pom: &Pom) -> String {
    let parent = pom.parent.as_ref();
    format!(
        "{}:{}:{}",
        bounded(
            pom.group_id
                .as_deref()
                .or(parent.map(|parent| parent.group_id.as_str()))
                .unwrap_or_default()
        ),
        bounded(pom.artifact_id.as_deref().unwrap_or_default()),
        bounded(
            pom.version
                .as_deref()
                .or(parent.map(|parent| parent.version.as_str()))
                .unwrap_or_default()
        ),
    )
}

#[derive(Debug, Default)]
pub(crate) struct FetchedProperties {
    keys: HashMap<String, String>,
    pub(crate) parent_ranges: std::collections::BTreeMap<String, String>,
    /// The lineage's parents from a repository, `group:artifact:version`,
    /// nearest first.
    pub(crate) parents: Vec<String>,
}

impl FetchedProperties {
    /// Forget `name`, which a user property now defines.
    pub(crate) fn remove(&mut self, name: &str) {
        self.keys.remove(name);
    }

    /// `error`, found interpolating the effective model. A property cycle
    /// whose every property a fetched POM defines is that POM's, and becomes
    /// [`PomError::InvalidModel`] naming it; see [`in_pom`].
    pub(crate) fn blame(&self, error: PomError) -> PomError {
        let owner = match &error {
            PomError::PropertyCycle(names) => {
                // The path starts with the properties that led into the
                // cycle; the cycle is the part from the repeated name on.
                let start = names
                    .iter()
                    .position(|name| Some(name) == names.last())
                    .unwrap_or(0);
                let cycle = &names[start..];
                if cycle.iter().all(|name| self.keys.contains_key(name)) {
                    cycle.first().and_then(|name| self.keys.get(name))
                } else {
                    None
                }
            }
            _ => None,
        };
        match owner {
            Some(owner) => in_fetched_pom(|| owner.clone(), error),
            None => error,
        }
    }
}

/// Reactor modules keep coordinates as written for inheritors, as Maven's
/// workspace reader does.
pub(crate) fn is_reactor_module(pom: &Pom) -> bool {
    matches!(
        pom.provenance,
        Some(Provenance::RootProject { .. } | Provenance::ReactorModule { .. })
    )
}

pub(crate) fn is_fetched(pom: &Pom) -> bool {
    pom.provenance
        .as_ref()
        .is_some_and(|provenance| !provenance.is_local())
}

/// `error`, found in the content of the fetched POM `label` names; see
/// [`in_pom`].
pub(crate) fn in_fetched_pom(label: impl FnOnce() -> String, error: PomError) -> PomError {
    match error {
        PomError::PropertyCycle(_) => PomError::InvalidModel(format!("{}: {error}", label())),
        PomError::ParentExpression(parent) => PomError::FetchedParentExpression {
            pom: label(),
            parent,
        },
        other => other,
    }
}

/// [`apply_inheritance_tracked`] without the fetched properties.
pub(crate) async fn apply_inheritance_in_context<S: ModelSource>(
    pom: Pom,
    source: &S,
    policy: ModelPolicy,
    lookup: ParentLookup,
    ctx: Option<&ActivationContext>,
) -> Result<Pom, S::Error> {
    Ok(apply_inheritance_tracked(pom, source, policy, lookup, ctx)
        .await?
        .0)
}

#[cfg(test)]
pub(crate) fn apply_inheritance<S: ModelSource>(pom: Pom, source: &S) -> Result<Pom, S::Error> {
    crate::ready(apply_inheritance_in_context(
        pom,
        source,
        ModelPolicy::DEPENDENCY,
        ParentLookup::Project,
        None,
    ))
}

/// Apply inheritance and expose each ancestor's active-profile repositories.
/// The source uses them to find that ancestor's parent. `lookup` tells the
/// source whose parents these are.
///
/// With an activation context, each POM of the chain has its active profiles
/// injected before it is merged into its child, as Maven 3.9's
/// `DefaultModelBuilder` does: profiles are selected per POM, and a parent's
/// profile contributes to the parent's model, which the child's own values
/// then override. Profiles themselves are not inherited.
///
/// Also returns the properties a fetched POM defines in the result.
pub(crate) async fn apply_inheritance_tracked<S: ModelSource>(
    pom: Pom,
    source: &S,
    policy: ModelPolicy,
    lookup: ParentLookup,
    ctx: Option<&ActivationContext>,
) -> Result<(Pom, FetchedProperties), S::Error> {
    let project_validation = ctx.is_some() && policy.root;
    let mode = ctx.map_or(MavenMode::Maven39, |ctx| ctx.environment.maven_mode());
    let strict_310 = project_validation && mode == MavenMode::Maven310;
    if project_validation {
        reject_unsupported_model_version(&pom)?;
        reject_duplicate_profile_ids(&pom)?;
        reject_classified_imports(&pom)?;
        reject_incomplete_repositories(&pom, None)?;
        let model = [&pom.group_id, &pom.artifact_id, &pom.version].map(Option::as_deref);
        reject_self_reference("dependencies.dependency", model, &pom.dependencies)?;
    }
    if strict_310 {
        reject_310_raw_model(&pom)?;
    }
    let mut parent_ranges = std::collections::BTreeMap::new();
    let mut parents = Vec::new();
    let mut chain = Vec::new();
    let mut current_pom = pom;
    let mut visited = HashSet::new();
    let mut depth = 0usize;
    // Fetched parents whose coordinates hold an expression that only their
    // own ancestors define, by their index in `chain`.
    let mut unverified = Vec::new();
    let mut unread_parent = None;

    loop {
        let Some(parent) = current_pom.parent.clone() else {
            chain.push(current_pom);
            break;
        };

        // Counted per hop actually taken, so the chain a full walk accepts is
        // exactly the chain `accepted_local_parents` reports.
        if depth == MAX_PARENT_CHAIN_DEPTH {
            return Err(PomError::InvalidModel(format!(
                "parent chain exceeds the limit of {MAX_PARENT_CHAIN_DEPTH} parents"
            ))
            .into());
        }
        depth += 1;
        let parent_key = (
            parent.group_id.clone(),
            parent.artifact_id.clone(),
            parent.version.clone(),
        );
        if !visited.insert(parent_key) {
            return Err(PomError::InvalidModel("parent cycle detected".to_string()).into());
        }
        let mut requested = parent.clone();
        if let Some(parent_pom) = source.parent(&mut requested, lookup).await? {
            let range_mode = match is_fetched(&parent_pom) {
                true => mode,
                false => MavenMode::Maven39,
            };
            // The model keeps the declared range, as Maven's does.
            if parent_version_range(&parent, range_mode).is_some() {
                require_constant_version(&current_pom, &parent)?;
                if requested.version == parent.version {
                    requested.version = version_in_range(&parent, &parent_pom)?;
                }
            }
            // A dependency's range can also select a reactor module.
            if parent_version_range(&parent, range_mode).is_some()
                && (is_fetched(&parent_pom) || (!policy.root && is_reactor_module(&parent_pom)))
            {
                parent_ranges.insert(
                    format!(
                        "{}:{}:{}",
                        parent.group_id, parent.artifact_id, parent.version
                    ),
                    format!(
                        "{}:{}:{}",
                        requested.group_id, requested.artifact_id, requested.version
                    ),
                );
            }
            let parent = requested;
            if !is_reactor_module(&parent_pom)
                && let Err(error) = verify_pom_coord(
                    &parent.group_id,
                    &parent.artifact_id,
                    &parent.version,
                    &parent_pom,
                )
            {
                if !declares_expression(&parent_pom) {
                    return Err(error.into());
                }
                unverified.push((chain.len() + 1, parent.clone(), error));
            }
            if project_validation {
                reject_unsupported_model_version(&parent_pom)?;
                let model = [
                    &parent_pom.group_id,
                    &parent_pom.artifact_id,
                    &parent_pom.version,
                ];
                let model = model.map(Option::as_deref);
                reject_self_reference("dependencies.dependency", model, &parent_pom.dependencies)?;
                if (parent_pom.provenance.as_ref()).is_some_and(Provenance::is_local) {
                    reject_duplicate_profile_ids(&parent_pom)?;
                    reject_classified_imports(&parent_pom)?;
                    if strict_310 {
                        reject_310_raw_model(&parent_pom)?;
                    }
                }
                reject_incomplete_repositories(&parent_pom, Some(&parent))?;
            }
            // Maven uses each ancestor's repositories, as written, to find the
            // next parent; the source observes the full set after model
            // interpolation.
            observe_lineage_repositories(source, &parent_pom, ctx, policy.root, &[])?;
            if is_fetched(&parent_pom) {
                parents.push(format!(
                    "{}:{}:{}",
                    parent.group_id, parent.artifact_id, parent.version
                ));
            }
            chain.push(std::mem::replace(&mut current_pom, parent_pom));
            continue;
        }
        if parent_has_expression(&parent) {
            let error = PomError::ParentExpression(format!(
                "{}:{}:{}",
                parent.group_id, parent.artifact_id, parent.version
            ));
            return Err(in_pom(&current_pom, error).into());
        }
        let inherit = policy.missing_parent == MissingParent::InheritDeclaredCoordinates;
        let can_continue = (current_pom.group_id.is_some() || !parent.group_id.is_empty())
            && (current_pom.version.is_some() || !parent.version.is_empty());
        if !inherit || !can_continue {
            return Err(PomError::ParentNotFound(
                parent.group_id,
                parent.artifact_id,
                parent.version,
            )
            .into());
        }
        tracing::debug!(
            parent_group_id = %bounded(&parent.group_id),
            parent_artifact_id = %bounded(&parent.artifact_id),
            parent_version = %bounded(&parent.version),
            "parent POM not found; continuing without inheritance"
        );
        unread_parent = Some(current_pom.group_id.is_none() || current_pom.version.is_none());
        current_pom.group_id.get_or_insert(parent.group_id);
        current_pom.version.get_or_insert(parent.version);
        chain.push(current_pom);
        break;
    }

    // Maven keeps the last of a POM's repeated dependency declarations, in
    // the place of the first, whether or not the POM has a parent.
    for pom in &mut chain {
        pom.dependencies = merge_dependency_levels([&pom.dependencies]);
    }
    // Only a project build that asks for its plugin model, or that Maven
    // 3.10 validates, reads the plugin sections. Sections that do not parse
    // fail a validated build, as Maven refuses them; a POM raeva read
    // without its sections fails only the plugin model.
    let plugins = policy.root && (policy.plugins.reads_plugins() || strict_310);
    let repositories = policy.root && policy.plugins == crate::PluginModel::Repositories;
    // Maven 3.9 validates the plugin repositories of every project build
    // too, and warns of their ids; only that check reads them.
    let validated = project_validation && !plugins && !repositories;
    let mut plugin_error = None;
    if plugins {
        for (index, pom) in chain.iter_mut().enumerate() {
            let kept = pom.keeps_plugin_sections();
            if let Err(error) = pom.load_plugins() {
                if project_validation && kept {
                    return Err(in_pom(pom, error).into());
                }
                plugin_error.get_or_insert_with(|| in_pom(pom, error).to_string());
            }
            let validated =
                index == 0 || (pom.provenance.as_ref()).is_some_and(Provenance::is_local);
            if strict_310 && validated {
                reject_duplicate_plugins(pom)?;
            }
            if let Some(plugins) = &mut pom.plugins {
                crate::plugin::merge::merge_duplicates(&mut plugins.plugins);
            }
        }
    } else if repositories || validated {
        chain.iter_mut().for_each(Pom::load_plugin_repositories);
    }
    if project_validation {
        for (index, pom) in chain.iter().enumerate() {
            let parent = index
                .checked_sub(1)
                .and_then(|child| chain[child].parent.as_ref());
            reject_invalid_plugin_sections(pom, parent).map_err(|error| in_pom(pom, error))?;
        }
    }

    if let Some(ctx) = ctx {
        let role = match (policy.root, lookup) {
            (true, _) => LineageRole::Project,
            (false, ParentLookup::Import) => LineageRole::Import,
            (false, ParentLookup::Project) => LineageRole::Dependency,
        };
        let keys = ResolutionKeys::of_lineage(&chain, ctx, role, policy.plugins);
        for (index, pom) in chain.iter_mut().enumerate() {
            crate::project::profiles::interpolate_lineage_activations(pom, ctx)
                .map_err(|error| in_pom(pom, error))?;
            inject_active_profiles(pom, ctx, &keys, plugins).map_err(|error| in_pom(pom, error))?;
            // Maven injects the active settings.xml profiles into the
            // project's own model only, after its POM profiles.
            if policy.root && index == 0 {
                let settings: Vec<&[Repository]> = (ctx.settings_repositories.iter())
                    .map(Vec::as_slice)
                    .collect();
                pom.repositories =
                    inject_repository_lists(std::mem::take(&mut pom.repositories), &settings);
            }
        }
    }

    // Maven 3.10's super POM sets these below every lineage's own, its
    // active profiles' included, and a parent's coordinates read them.
    if mode == MavenMode::Maven310
        && let Some(top) = chain.last_mut()
    {
        for (name, value) in SUPER_POM_310_PROPERTIES {
            if top.properties.get(name).is_none() {
                top.properties.insert(name, value);
            }
        }
    }
    // After profile injection: an ancestor's active profile may define the
    // property.
    for (index, requested, error) in unverified {
        if !declares_through_ancestors(&chain[index..], &requested, ctx) {
            return Err(error.into());
        }
    }
    // A project build records which POM of its lineage declares each
    // managed entry, its active profiles' included.
    if policy.root {
        chain.iter_mut().for_each(note_management_origins);
        note_property_origins(&mut chain, ctx);
    }

    let mut effective_pom = chain.pop().ok_or_else(|| {
        PomError::InvalidModel("empty inheritance chain: no root POM".to_string())
    })?;
    effective_pom.repositories =
        merge_repositories(std::mem::take(&mut effective_pom.repositories), &[]);
    let mut fetched = FetchedValues::default();
    fetched.record(&effective_pom, chain.is_empty());
    // A check that runs without resolution takes the plugin rows from
    // Maven's own `central` as it takes those from the configuration's.
    let mut central = crate::plugin::lifecycle::super_pom_plugin_repository(mode);
    central.root_declared = repositories;
    if plugins {
        // Every lineage ends in the super POM, which Maven merges into the
        // topmost ancestor first.
        let mut super_pom = crate::plugin::BuildPlugins {
            plugin_management: crate::plugin::lifecycle::super_pom_plugin_management(mode),
            ..Default::default()
        };
        if let Some(ctx) = ctx
            && policy.plugins == crate::PluginModel::All
        {
            let (plugins, reads) = crate::plugin::lifecycle::super_pom_release_plugins(ctx)?;
            super_pom.plugins = plugins;
            reads
                .into_iter()
                .for_each(|input| ctx.environment.record(input));
        }
        crate::plugin::merge::inherit(
            effective_pom.plugins.get_or_insert_default(),
            &mut effective_pom.plugin_repositories,
            &super_pom,
            &[central],
        );
    } else if repositories || validated {
        effective_pom.plugin_repositories = crate::plugin::merge::merge_repositories(
            std::mem::take(&mut effective_pom.plugin_repositories),
            &[central],
        );
    }

    while let Some(mut child_pom) = chain.pop() {
        fetched.record(&child_pom, chain.is_empty());
        // Move the parent's property map out instead of cloning it: the
        // parent (`effective_pom`) is overwritten by `child_pom` at the end of
        // this iteration, and none of the merges below read `parent.properties`,
        // so taking it here avoids a full-map clone at every inheritance level.
        let parent_properties = std::mem::take(&mut effective_pom.properties);
        let parent = &effective_pom;

        if child_pom.group_id.is_none() {
            child_pom.group_id = parent.group_id.clone();
        }
        if child_pom.version.is_none() {
            child_pom.version = parent.version.clone();
        }

        let hidden: Vec<String> = child_pom
            .user_properties
            .iter()
            .filter(|(key, _)| child_pom.shadowed_properties.get(key).is_none())
            .map(|(key, _)| key.clone())
            .collect();
        for key in hidden {
            let inherited = if parent.user_properties.get(&key).is_some() {
                parent.shadowed_properties.get(&key)
            } else {
                parent_properties.get(&key)
            };
            if let Some(value) = inherited.cloned() {
                child_pom.shadowed_properties.insert(key, value);
            }
        }
        // A property the child declares, even as empty, overrides the parent's.
        // Maven's assembler leaves the parent's `project.directory` out.
        let mut properties = parent_properties;
        properties.remove("project.directory");
        properties.extend(&child_pom.properties);
        child_pom.properties = properties;
        child_pom
            .active_profiles
            .extend(parent.active_profiles.iter().cloned());
        (child_pom.selected_profiles).extend(parent.selected_profiles.iter().cloned());

        // Maven keeps child dependencies first, then appends unmatched parent entries.
        // An override keeps the child's position.
        child_pom.dependencies =
            merge_dependency_levels([&child_pom.dependencies, &parent.dependencies]);

        child_pom.dependency_management = merge_dependency_management(
            parent.dependency_management.clone(),
            child_pom.dependency_management,
        );

        child_pom.repositories = merge_repositories(child_pom.repositories, &parent.repositories);
        if plugins {
            crate::plugin::merge::inherit(
                child_pom.plugins.get_or_insert_default(),
                &mut child_pom.plugin_repositories,
                parent
                    .plugins
                    .as_deref()
                    .unwrap_or(&crate::plugin::NO_PLUGINS),
                &parent.plugin_repositories,
            );
        } else if repositories || validated {
            child_pom.plugin_repositories = crate::plugin::merge::merge_repositories(
                std::mem::take(&mut child_pom.plugin_repositories),
                &parent.plugin_repositories,
            );
        }
        child_pom.build.inherit(&parent.build);
        // A relocation is never inherited; the deployment repositories are.
        child_pom.distribution_management = crate::pom::DistributionManagement::merge_ids(
            child_pom.distribution_management,
            parent.distribution_management.as_ref(),
        );
        if child_pom.licenses.is_empty() {
            child_pom.licenses.clone_from(&parent.licenses);
        }

        effective_pom = child_pom;
    }

    if let Some(ctx) = ctx
        && policy.root
        && let Some(central) = super_pom_central(&effective_pom, ctx)
    {
        effective_pom.repositories.push(central);
    }
    let used = (effective_pom.plugin_repositories.iter_mut()).filter(|_| !validated);
    for repo in (effective_pom.repositories.iter_mut())
        .chain(used)
        .filter(|repo| repo.root_declared)
    {
        if fetched.chose(&repo.url, &effective_pom.properties, ctx) {
            // The repository is used, but with the trust of the fetched POM
            // that chose where it points.
            repo.root_declared = false;
            tracing::warn!(
                sec_code = "PROJECT_REPO_URL_FROM_FETCHED_POM",
                repository = %bounded(repo.id.as_deref().unwrap_or("")),
                "the URL of a repository the project declares takes a value from a parent POM \
                 fetched from a repository, so raeva uses it with that parent's trust"
            );
        }
    }

    if plugins {
        effective_pom.plugins.get_or_insert_default().error = plugin_error;
    }
    effective_pom.unread_parent = unread_parent;
    if let Some(ctx) = ctx {
        effective_pom.properties.set_input_context(ctx);
    }
    Ok((
        effective_pom,
        FetchedProperties {
            keys: fetched.keys,
            parent_ranges,
            parents,
        },
    ))
}

/// Model fields the input POM's directory decides, without interpolation.
const LOCAL_FIELDS: &[&str] = &["basedir", "baseUri"];

/// The `<properties>` of Maven 3.10.0's super POM, `pom-4.0.0.xml` in
/// maven-model-builder. Maven 3.9.12's has none.
const SUPER_POM_310_PROPERTIES: [(&str, &str); 3] = [
    ("project.build.sourceEncoding", "UTF-8"),
    ("project.reporting.outputEncoding", "UTF-8"),
    ("project.build.outputTimestamp", "1980-02-01T00:00:00Z"),
];

/// Maven 3.10's super POM `central`, whose URL is `${maven.repo.central}`,
/// for a project whose properties or settings.xml profile properties set
/// that and that, like the configuration, declares no `central`. It is trusted as the project's own
/// declarations are, unless a fetched parent chose the value. A `-D`,
/// `MAVEN_REPO_CENTRAL` or `.mvn/jvm.config` value alone is in the
/// configuration's Central already.
fn super_pom_central(pom: &Pom, ctx: &ActivationContext) -> Option<Repository> {
    const CENTRAL: &str = "maven.repo.central";
    let set =
        ctx.settings_properties.get(CENTRAL).is_some() || pom.properties.get(CENTRAL).is_some();
    let declared = (pom.repositories.iter()).any(|repo| repo.id.as_deref() == Some("central"));
    if ctx.environment.maven_mode() != MavenMode::Maven310
        || ctx.property_source != crate::PropertySource::User
        || ctx.properties.contains_key(CENTRAL)
        || !set
        || declared
        || ctx.configured_central
    {
        return None;
    }
    let mut central = Repository::new(Some("central"), &format!("${{{CENTRAL}}}"));
    central.snapshots_enabled = false;
    central.snapshots_enabled_text = Some("false".to_string());
    central.root_declared = true;
    Some(central)
}

/// Which values of an effective model a POM fetched from a repository chose:
/// properties it defined that no POM of the project redefined, and the
/// inherited group, version and `<build>` fields.
#[derive(Default)]
struct FetchedValues {
    any: bool,
    keys: HashMap<String, String>,
    group_id: Option<(bool, String)>,
    version: Option<(bool, String)>,
    local: HashMap<&'static str, String>,
    build: HashMap<&'static str, (bool, String)>,
}

impl FetchedValues {
    /// Record `pom`, applied over the ancestors recorded before it. A parent
    /// whose loader did not say where it came from counts as fetched.
    fn record(&mut self, pom: &Pom, input: bool) {
        let fetched = match pom.provenance() {
            Some(provenance) => !provenance.is_local(),
            None => !input,
        };
        self.any |= fetched;
        let label = fetched.then(|| pom_label(pom));
        for (key, _) in pom.properties.iter() {
            if let Some(label) = &label {
                self.keys.insert(key.clone(), label.clone());
            } else {
                self.keys.remove(key);
            }
        }
        if let Some(group_id) = &pom.group_id {
            self.group_id = Some((fetched, group_id.clone()));
        }
        if let Some(version) = &pom.version {
            self.version = Some((fetched, version.clone()));
        }
        // These fields are not inherited, but their expressions can read
        // inherited properties.
        self.local.clear();
        if let Some(artifact_id) = &pom.artifact_id {
            self.local.insert("artifactId", artifact_id.clone());
        }
        self.local.insert(
            "packaging",
            pom.packaging.clone().unwrap_or_else(|| "jar".into()),
        );
        if let Some(parent) = &pom.parent {
            for (name, value) in [
                ("parent.groupId", &parent.group_id),
                ("parent.artifactId", &parent.artifact_id),
                ("parent.version", &parent.version),
            ] {
                self.local.insert(name, value.clone());
            }
        }
        for (field, value) in Build::FIELDS.iter().zip(pom.build.fields()) {
            if let Some(value) = value {
                self.build.insert(field.name, (fetched, value.clone()));
            }
        }
    }

    /// Whether a fetched POM set the model field `field`, and its raw
    /// value, the super POM's when no POM of the lineage sets it.
    fn build_field(&self, field: &str) -> Option<(bool, &str)> {
        match self.build.get(field) {
            Some((fetched, value)) => Some((*fetched, value)),
            None => Build::model_field(field)?
                .super_pom
                .map(|value| (false, value)),
        }
    }

    /// Whether interpolating `text` takes a value a fetched POM chose. An
    /// untracked model field counts as chosen once any fetched POM is in
    /// the lineage, as does a reference too deep or too wide to follow.
    fn chose(&self, text: &str, properties: &PropertyMap, ctx: Option<&ActivationContext>) -> bool {
        let mut budget = 10_000usize;
        self.any && self.chose_within(text, properties, ctx, 0, &mut budget)
    }

    fn chose_within(
        &self,
        text: &str,
        properties: &PropertyMap,
        ctx: Option<&ActivationContext>,
        depth: usize,
        budget: &mut usize,
    ) -> bool {
        if depth > 16 {
            return true;
        }
        for name in crate::properties::expression_names(text) {
            let Some(left) = budget.checked_sub(1) else {
                return true;
            };
            *budget = left;
            fn coordinate(value: &Option<(bool, String)>) -> Option<(bool, &str)> {
                value
                    .as_ref()
                    .map(|(fetched, raw)| (*fetched, raw.as_str()))
            }
            fn build(field: &str) -> Option<&str> {
                Build::model_field(field).map(|field| field.name)
            }
            // Maven 3.10's root directory is the project's own, ahead of
            // the properties.
            if matches!(
                name,
                "project.rootDirectory" | "pom.rootDirectory" | "rootDirectory"
            ) && ctx.is_some_and(|ctx| ctx.root_directory().is_some())
            {
                continue;
            }
            // The same order as the interpolator: property aliases read
            // user or settings properties, then properties, then model
            // fields. Other `project.` and `pom.` names read the model first.
            let alias = name
                .strip_prefix("project.properties.")
                .or_else(|| name.strip_prefix("pom.properties."));
            let field = name
                .strip_prefix("project.")
                .or_else(|| name.strip_prefix("pom."))
                .filter(|_| alias.is_none());
            let model = match field {
                Some("groupId") => coordinate(&self.group_id),
                Some("version") => coordinate(&self.version),
                Some(field) if self.local.contains_key(field) => {
                    self.local.get(field).map(|raw| (false, raw.as_str()))
                }
                Some(field) if LOCAL_FIELDS.contains(&field) => continue,
                Some(field) => match build(field) {
                    Some(field) => self.build_field(field),
                    None => return true,
                },
                None => None,
            };
            let name = alias.unwrap_or(name);
            // A model field without a value falls through to the
            // properties, under its full name.
            let inherited = if model.is_some() {
                model
            } else if let Some(value) = ctx.and_then(|ctx| {
                ctx.properties
                    .get(name)
                    .or_else(|| ctx.settings_properties.get(name))
            }) {
                Some((false, value.as_str()))
            } else if self.keys.contains_key(name) {
                return true;
            } else if let Some(value) = properties.get(name) {
                if self.chose_within(value, properties, ctx, depth + 1, budget) {
                    return true;
                }
                continue;
            } else if field.is_some() {
                continue;
            } else {
                match name {
                    "groupId" => coordinate(&self.group_id),
                    "version" => coordinate(&self.version),
                    name if self.local.contains_key(name) => {
                        self.local.get(name).map(|raw| (false, raw.as_str()))
                    }
                    name => match build(name).filter(|_| alias.is_none()) {
                        Some(field) => self.build_field(field),
                        None => continue,
                    },
                }
            };
            let value = match inherited {
                Some((true, _)) => return true,
                Some((false, raw)) => raw,
                None => continue,
            };
            if self.chose_within(value, properties, ctx, depth + 1, budget) {
                return true;
            }
        }
        false
    }
}

/// With `refuse_hosts`, for the project's own lineage, a repository or
/// plugin repository URL here as written that names a host fails, before
/// the next parent is looked up; the id as written holds no input.
pub(crate) fn observe_lineage_repositories(
    source: &impl ModelSource,
    pom: &Pom,
    ctx: Option<&ActivationContext>,
    refuse_hosts: bool,
    settings: &[Vec<Repository>],
) -> Result<(), PomError> {
    // Maven interpolates activation before selecting a raw model's profiles
    // and exposing their repositories for the next parent lookup.
    let mut interpolated = Pom::default();
    let mut active = Vec::new();
    if let Some(ctx) = ctx {
        interpolated.profiles = pom.profiles.clone();
        interpolated.properties = pom.declared_properties().clone();
        crate::project::profiles::interpolate_lineage_activations(&mut interpolated, ctx)
            .map_err(|error| in_pom(pom, error))?;
        // The host reads of this selection are not recorded: injection selects
        // the same profiles again, in the same context, and records them there.
        let selection = select_profiles(&interpolated.profiles, pom.declared_properties(), ctx)
            .map_err(|error| in_pom(pom, error))?;
        active.extend(
            selection
                .active
                .into_iter()
                .map(|index| &interpolated.profiles[index]),
        );
    }
    // Maven looks the next parent up in these repositories before it
    // interpolates the model. A URL holding an expression has no scheme
    // there, so only a mirror that matches the repository serves it.
    let usable = inject_repositories(pom.repositories.clone(), &active);
    let settings: Vec<&[Repository]> = settings.iter().map(Vec::as_slice).collect();
    let usable: Vec<Repository> = inject_repository_lists(usable, &settings)
        .into_iter()
        .filter(|repo| !repo.url.is_empty())
        .map(|mut repo| {
            repo.read_policies_as_written();
            let environment = ctx.map(|ctx| &ctx.environment);
            if let Some(environment) = environment
                && let Some(base) = environment.reactor_root()
                && let Some(url) =
                    crate::file_transport::directory_url(&repo.url, environment.maven_mode(), base)
            {
                repo.declared_url = Some(std::mem::replace(&mut repo.url, url));
            }
            repo
        })
        .collect();
    if refuse_hosts {
        let written = |repos: &[Repository]| {
            (repos.iter())
                .filter(|repo| {
                    !repo
                        .declared_url
                        .as_deref()
                        .unwrap_or(&repo.url)
                        .contains("${")
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        crate::file_transport::reject_hosts("repository", &written(&usable), true)
            .and_then(|()| {
                let plugins =
                    (active.iter()).flat_map(|profile| written(&profile.plugin_repositories));
                let plugins: Vec<_> = written(&pom.plugin_repositories)
                    .into_iter()
                    .chain(plugins)
                    .collect();
                crate::file_transport::reject_hosts("plugin repository", &plugins, true)
            })
            .map_err(|error| in_pom(pom, error))?;
    }
    if !usable.is_empty() {
        source.observe_repositories(&usable);
    }
    Ok(())
}

/// Maven 3.9's `DefaultModelValidator` check of a project lineage POM's
/// `<modelVersion>`: anything but `4.0.0` fails the build, such as a Maven 4
/// `4.1.0`. The messages are Maven's. Maven also requires the element;
/// `raeva` reads a POM without it as `4.0.0`.
fn reject_unsupported_model_version(pom: &Pom) -> Result<(), PomError> {
    const SUPPORTED: &str = "4.0.0";
    let Some(version) = pom.model_version.as_deref() else {
        return Ok(());
    };
    if version.is_empty() || version == SUPPORTED {
        return Ok(());
    }
    let segments = |text: &str| -> Option<Vec<u64>> {
        text.split('.')
            .filter(|segment| !segment.is_empty())
            .map(|segment| segment.parse().ok())
            .collect()
    };
    let order = segments(version)
        .zip(segments(SUPPORTED))
        .map(|(ours, supported)| {
            let len = ours.len().max(supported.len());
            let at = |list: &[u64], i: usize| list.get(i).copied().unwrap_or(0);
            (0..len)
                .map(|i| at(&ours, i).cmp(&at(&supported, i)))
                .find(|order| order.is_ne())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    let version = bounded(version);
    let message = match order {
        Some(std::cmp::Ordering::Greater) => format!(
            "'modelVersion' of '{version}' is newer than the versions supported by this \
             version of Maven: [{SUPPORTED}]. Building this project requires a newer version \
             of Maven."
        ),
        Some(std::cmp::Ordering::Less) => format!(
            "'modelVersion' of '{version}' is older than the versions supported by this \
             version of Maven: [{SUPPORTED}]. Building this project requires an older version \
             of Maven."
        ),
        _ => format!("'modelVersion' must be one of [{SUPPORTED}] but is '{version}'."),
    };
    Err(PomError::InvalidModel(message))
}

/// Maven's `DefaultModelValidator` check that the profile ids of a POM it
/// builds as a project, or reads as its parent through `<relativePath>`,
/// are unique. A profile without `<id>` counts as `default`. Maven skips
/// the check for the POMs of dependencies and of imported BOMs, and
/// downgrades it to a warning for a parent read from a repository.
/// Maven's check, on the POM of a project it builds as written and again
/// on its effective model, that no dependency has the project's own
/// groupId, artifactId and version, and no classifier. A field the model
/// leaves out is `null` to Maven. The message is Maven's.
pub(crate) fn reject_self_reference(
    prefix: &str,
    model: [Option<&str>; 3],
    dependencies: &[Dependency],
) -> Result<(), PomError> {
    let own = model.map(|field| field.unwrap_or("null")).join(":");
    for dependency in dependencies {
        let version = dependency.version.as_deref().unwrap_or("null");
        let key = format!(
            "{}:{}:{version}",
            dependency.group_id, dependency.artifact_id
        );
        if dependency.classifier.is_none() && key == own {
            return Err(PomError::InvalidModel(format!(
                "'{prefix}[{0}]' for {0} is referencing itself.",
                bounded(&key)
            )));
        }
    }
    Ok(())
}

fn reject_duplicate_profile_ids(pom: &Pom) -> Result<(), PomError> {
    let mut seen = HashSet::new();
    for profile in &pom.profiles {
        if !seen.insert(profile.id.as_str()) {
            return Err(PomError::InvalidModel(format!(
                "'profiles.profile.id' must be unique but found duplicate profile with id {}",
                bounded(&profile.id)
            )));
        }
    }
    Ok(())
}

/// Maven's raw-model check, in a POM it builds as a project or reads as
/// its parent through `<relativePath>`, its profiles included, that no
/// import is written with a classifier. A parent from a repository is not
/// checked, and Maven imports its BOM without the classifier.
fn reject_classified_imports(pom: &Pom) -> Result<(), PomError> {
    let sections = std::iter::once(("", pom.dependency_management.as_ref())).chain(
        (pom.profiles.iter())
            .map(|profile| (profile.id.as_str(), profile.dependency_management.as_ref())),
    );
    for (profile, management) in sections {
        for dependency in management
            .into_iter()
            .flat_map(|management| &management.dependencies)
        {
            if let Some(classifier) =
                (dependency.classifier.as_deref()).filter(|value| !value.is_empty())
                && dependency.scope.as_deref() == Some("import")
                && dependency.type_.as_deref() == Some("pom")
            {
                let prefix = match profile {
                    "" => String::new(),
                    id => format!("profiles.profile[{}].", bounded(id)),
                };
                return Err(PomError::InvalidModel(format!(
                    "'{prefix}dependencyManagement.dependencies.dependency.classifier' for \
                     {}:{}:pom:{} must be empty, imported POM cannot have a classifier.",
                    bounded(&dependency.group_id),
                    bounded(&dependency.artifact_id),
                    bounded(classifier)
                )));
            }
        }
    }
    Ok(())
}

/// The checks Maven 3.10 makes errors of, and Maven 3.9 only warns about,
/// in a POM it builds as a project or reads as its parent through
/// `<relativePath>`: a `<relativePath>` with a character Windows reserves,
/// and a dependency or managed dependency declared twice, in a profile too.
/// The messages are Maven's.
fn reject_310_raw_model(pom: &Pom) -> Result<(), PomError> {
    if let Some(path) = pom.written_relative_path() {
        crate::project::reject_banned_characters("parent.relativePath", path, ":\"<>|?*")?;
    }
    let unique = |prefix: &str, dependencies: &[Dependency]| {
        let mut seen: HashMap<String, &Dependency> = HashMap::default();
        for dependency in dependencies {
            let (group_id, artifact_id, type_, classifier) = dependency.maven_key();
            let classifier = classifier.map(|c| format!(":{c}")).unwrap_or_default();
            let key = format!("{group_id}:{artifact_id}:{type_}{classifier}");
            let Some(existing) = seen.get(&key) else {
                seen.insert(key, dependency);
                continue;
            };
            let version = |dependency: &Dependency| {
                bounded(dependency.version.as_deref().unwrap_or("(?)")).to_string()
            };
            let message = if existing.version == dependency.version {
                format!("duplicate declaration of version {}", version(dependency))
            } else {
                format!("version {} vs {}", version(existing), version(dependency))
            };
            return Err(PomError::InvalidModel(format!(
                "'{prefix}(groupId:artifactId:type:classifier)' must be unique: {} -> {message}",
                bounded(&key)
            )));
        }
        Ok(())
    };
    fn management(management: &Option<DependencyManagement>) -> &[Dependency] {
        (management.as_ref()).map_or(&[], |management| &management.dependencies)
    }
    unique("dependencies.dependency.", &pom.dependencies)?;
    unique(
        "dependencyManagement.dependencies.dependency.",
        management(&pom.dependency_management),
    )?;
    for profile in &pom.profiles {
        let prefix = format!("profiles.profile[{}].", bounded(&profile.id));
        unique(
            &format!("{prefix}dependencies.dependency."),
            &profile.dependencies,
        )?;
        unique(
            &format!("{prefix}dependencyManagement.dependencies.dependency."),
            management(&profile.dependency_management),
        )?;
    }
    Ok(())
}

/// Maven 3.10's check, a warning in 3.9, that no plugin key appears twice
/// in the `<build>` plugins or plugin management of a POM it builds as a
/// project or reads as its parent through `<relativePath>`, nor in those of
/// any of its profiles, active or not. The messages are Maven's.
fn reject_duplicate_plugins(pom: &Pom) -> Result<(), PomError> {
    let unique = |prefix: &str, plugins: &[crate::Plugin]| {
        let mut seen = HashSet::new();
        for plugin in plugins {
            let key = plugin.key();
            if !seen.insert(key.clone()) {
                return Err(PomError::InvalidModel(format!(
                    "'{prefix}(groupId:artifactId)' must be unique but found duplicate \
                     declaration of plugin {}",
                    bounded(&key)
                )));
            }
        }
        Ok(())
    };
    let sections = |prefix: &str, plugins: Option<&crate::plugin::BuildPlugins>| {
        let Some(plugins) = plugins else {
            return Ok(());
        };
        unique(&format!("{prefix}plugins.plugin."), &plugins.plugins)?;
        unique(
            &format!("{prefix}pluginManagement.plugins.plugin."),
            &plugins.plugin_management,
        )
    };
    sections("build.", pom.plugins.as_deref())?;
    for profile in &pom.profiles {
        sections(
            &format!("profiles.profile[{}].", bounded(&profile.id)),
            profile.plugins.as_deref(),
        )?;
    }
    Ok(())
}

/// Maven's `DefaultModelValidator` check that every repository a POM of a
/// project's lineage declares, in any profile too, has an id and a URL, and
/// that no list names an id twice. Maven skips it for the POMs of
/// dependencies and imported BOMs. `parent` names the POM when it is a
/// parent.
fn reject_incomplete_repositories(pom: &Pom, parent: Option<&Parent>) -> Result<(), PomError> {
    let problem = repository_problem("repositories.repository.", &pom.repositories).or_else(|| {
        pom.profiles.iter().find_map(|profile| {
            repository_problem(
                &format!(
                    "profiles.profile[{}].repositories.repository.",
                    bounded(&profile.id)
                ),
                &profile.repositories,
            )
        })
    });
    reject_repository_problem(problem, parent)
}

/// The same check of the `<pluginRepositories>` of a POM whose plugin
/// sections are kept, which also fails where those sections do not parse,
/// as Maven fails on a POM it cannot parse.
fn reject_invalid_plugin_sections(pom: &Pom, parent: Option<&Parent>) -> Result<(), PomError> {
    let Some((own, profiles)) = pom.plugin_repository_lists()? else {
        return Ok(());
    };
    let problem = repository_problem("pluginRepositories.pluginRepository.", &own).or_else(|| {
        pom.profiles
            .iter()
            .zip(&profiles)
            .find_map(|(profile, repositories)| {
                repository_problem(
                    &format!(
                        "profiles.profile[{}].pluginRepositories.pluginRepository.",
                        bounded(&profile.id)
                    ),
                    repositories,
                )
            })
    });
    reject_repository_problem(problem, parent)
}

/// The first repository of `repositories` without an id or a URL, or whose
/// id an earlier one has, as Maven words it under the field `prefix`.
fn repository_problem(prefix: &str, repositories: &[Repository]) -> Option<String> {
    let mut seen: HashMap<&str, &str> = HashMap::new();
    repositories.iter().find_map(|repository| {
        let Some(id) = repository.id.as_deref().filter(|id| !id.trim().is_empty()) else {
            return Some(format!("'{prefix}id' is missing"));
        };
        if repository.url.is_empty() {
            return Some(format!("'{prefix}[{}].url' is missing", bounded(id)));
        }
        let first = seen.insert(id, &repository.url)?;
        Some(format!(
            "'{prefix}id' must be unique: {} -> {} vs {}",
            bounded(id),
            bounded(first),
            bounded(&repository.url)
        ))
    })
}

fn reject_repository_problem(
    problem: Option<String>,
    parent: Option<&Parent>,
) -> Result<(), PomError> {
    let Some(problem) = problem else {
        return Ok(());
    };
    let location = parent
        .map(|parent| {
            format!(
                " in {}:{}:{}",
                bounded(&parent.group_id),
                bounded(&parent.artifact_id),
                bounded(&parent.version)
            )
        })
        .unwrap_or_default();
    Err(PomError::InvalidModel(format!("{problem}{location}")))
}

/// Select the active profiles of one POM of a parent chain and inject them
/// into it, in order, as Maven 3.9's `DefaultProfileInjector` does with
/// `sourceDominant` set: a profile's properties replace the POM's, except
/// the user properties overlaid on it, and so do the `<build>` values it
/// sets; a profile's dependency or managed
/// dependency replaces the POM's entry with the same key in place, and new
/// ones are appended; its repositories come before the POM's, which keep
/// only the ids the profile does not declare; and its modules are appended
/// unless the POM lists them already. Activations must already be
/// interpolated.
///
/// The host values a profile's activation read count as read, in `ctx`'s
/// environment, only when `keys` finds the profile relevant to resolution,
/// or finds an `activeByDefault` profile of the POM relevant, whose
/// fallback every condition of the POM decides. A profile whose activation
/// host values decide and that is not relevant is left out of the POM's
/// active profile ids, so they are the same on every host.
pub(crate) fn inject_active_profiles(
    pom: &mut Pom,
    ctx: &ActivationContext,
    keys: &ResolutionKeys,
    plugins: bool,
) -> Result<(), PomError> {
    let selection = select_profiles(&pom.profiles, pom.declared_properties(), ctx)?;
    let relevant: Vec<bool> = pom
        .profiles
        .iter()
        .map(|profile| keys.is_relevant(profile))
        .collect();
    let default_relevant = pom
        .profiles
        .iter()
        .zip(&relevant)
        .any(|(profile, relevant)| *relevant && crate::activation::is_active_by_default(profile));
    if let Some((index, name)) = selection.undecided(&pom.profiles, &relevant) {
        return Err(in_pom(
            pom,
            PomError::Unlockable(format!(
                "the activation of profile {} depends on {name}, which raeva does not read \
                 from the host or which differs across the hosts the lock covers; {}",
                bounded(&pom.profiles[index].id),
                crate::activation::unread_property_fix(name, &ctx.environment),
            )),
        ));
    }
    for ((reads, reads_java), relevant) in selection
        .reads
        .iter()
        .zip(&selection.reads_java)
        .zip(&relevant)
    {
        if *relevant || default_relevant {
            if *reads_java {
                ctx.environment.warn_java_read_by(&pom_label(pom));
            }
            for input in reads {
                ctx.environment.record(input.clone());
            }
        }
    }
    pom.active_profiles = selection
        .active
        .iter()
        .filter(|&&index| relevant[index] || !selection.host_decides(&pom.profiles, index))
        .map(|&index| pom.profiles[index].id.clone())
        .collect();
    pom.selected_profiles = vec![
        (selection.active.iter())
            .map(|&index| pom.profiles[index].id.clone())
            .collect(),
    ];
    let active: Vec<&Profile> = selection
        .active
        .iter()
        .map(|&index| &pom.profiles[index])
        .collect();
    // One pass over each list gives what injecting the profiles one by one
    // gives, without rebuilding the POM's lists once per profile.
    for profile in &active {
        for (key, value) in profile.properties.iter() {
            if pom.user_properties.get(key).is_none() {
                pom.properties.insert(key, value);
            } else {
                pom.shadowed_properties.insert(key, value);
            }
        }
        pom.build.inject_profile(&profile.build);
    }
    pom.dependencies = merge_keyed(
        std::mem::take(&mut pom.dependencies),
        active.iter().map(|profile| profile.dependencies.as_slice()),
        Dependency::raw_key,
    );
    let managed: Vec<&[Dependency]> = active
        .iter()
        .filter_map(|profile| profile.dependency_management.as_ref())
        .map(|management| management.dependencies.as_slice())
        .collect();
    if !managed.is_empty() {
        let own = pom.dependency_management.take().unwrap_or_default();
        pom.dependency_management = Some(DependencyManagement {
            dependencies: merge_keyed(own.dependencies, managed, Dependency::raw_key),
        });
    }
    pom.repositories = inject_repositories(std::mem::take(&mut pom.repositories), &active);
    for profile in &active {
        if let Some(management) = &profile.distribution_management {
            // The profile's ids win, and its relocation is not read.
            let own = pom.distribution_management.take();
            let mut merged = crate::pom::DistributionManagement::merge_ids(
                Some(crate::pom::DistributionManagement {
                    relocation: None,
                    ..management.clone()
                }),
                own.as_ref(),
            )
            .unwrap_or_default();
            merged.relocation = own.and_then(|own| own.relocation);
            pom.distribution_management = Some(merged);
        }
    }
    if plugins {
        for profile in &active {
            crate::plugin::merge::inject_profile(
                pom.plugins.get_or_insert_default(),
                &mut pom.plugin_repositories,
                profile
                    .plugins
                    .as_deref()
                    .unwrap_or(&crate::plugin::NO_PLUGINS),
                &profile.plugin_repositories,
            );
        }
    } else {
        // Only a POM read for its plugin repositories alone has these.
        for profile in active
            .iter()
            .filter(|profile| !profile.plugin_repositories.is_empty())
        {
            pom.plugin_repositories = crate::plugin::merge::merge_repositories(
                profile.plugin_repositories.clone(),
                &pom.plugin_repositories,
            );
        }
    }
    let mut listed: HashSet<String> = pom.modules.iter().cloned().collect();
    for profile in &active {
        // Maven checks a profile's modules against the list as it stood
        // before that profile, so one profile may add a module twice.
        let added: Vec<String> = profile
            .modules
            .iter()
            .filter(|module| !listed.contains(*module))
            .cloned()
            .collect();
        listed.extend(added.iter().cloned());
        pom.modules.extend(added);
    }
    Ok(())
}

/// `target` with the entries of each list in `sources`, in order, replacing
/// the entry with their key in place or appended when there is none. The
/// target is returned as it is when no source has an entry.
fn merge_keyed<'a, T: Clone + 'a, K: std::hash::Hash + Eq>(
    target: Vec<T>,
    sources: impl IntoIterator<Item = &'a [T]>,
    key: impl Fn(&T) -> K,
) -> Vec<T> {
    let mut sources = sources
        .into_iter()
        .filter(|source| !source.is_empty())
        .peekable();
    if sources.peek().is_none() {
        return target;
    }
    let mut merged: IndexMap<K, T> = IndexMap::with_capacity(target.len());
    for item in target {
        merged.insert(key(&item), item);
    }
    for source in sources {
        for item in source {
            merged.insert(key(item), item.clone());
        }
    }
    merged.into_values().collect()
}

/// The repositories that injecting `active` into a POM with `own` leaves:
/// each profile's repositories ahead of what was there before it, so the
/// last profile's come first, and the POM's last. Within one profile a
/// repeated id replaces the earlier entry in place; an id a later profile
/// declares, or one already listed, drops the entry. As in Maven's
/// `ModelMerger`, the id is the key whether or not it is present, so the
/// repositories without an id share one key, and an empty `<id/>` is a key
/// of its own.
fn inject_repositories(own: Vec<Repository>, active: &[&Profile]) -> Vec<Repository> {
    let lists: Vec<&[Repository]> = (active.iter())
        .map(|profile| profile.repositories.as_slice())
        .collect();
    inject_repository_lists(own, &lists)
}

/// [`inject_repositories`] for the repository lists of profiles injected in
/// turn, such as the active `settings.xml` profiles of
/// [`ActivationContext::settings_repositories`].
fn inject_repository_lists(own: Vec<Repository>, active: &[&[Repository]]) -> Vec<Repository> {
    if active.iter().all(|repositories| repositories.is_empty()) {
        return own;
    }
    let mut merged: Vec<Repository> = Vec::new();
    let mut claimed: HashSet<Option<String>> = HashSet::new();
    for repositories in active.iter().rev() {
        let own_list: IndexMap<Option<&str>, &Repository> = repositories
            .iter()
            .map(|repo| (repo.id.as_deref(), repo))
            .collect();
        let fresh: Vec<&Repository> = own_list
            .into_values()
            .filter(|repo| !claimed.contains(&repo.id))
            .collect();
        claimed.extend(fresh.iter().map(|repo| repo.id.clone()));
        merged.extend(fresh.into_iter().cloned());
    }
    for repo in own {
        if claimed.insert(repo.id.clone()) {
            merged.push(repo);
        }
    }
    merged
}

/// A child's repositories merged over its parent's, as Maven's
/// `ModelMerger` merges them: keyed by id, with the repositories without an
/// id sharing one key. A later entry of `dominant` with a key already listed
/// replaces the earlier one in place, and an entry of `recessive` is
/// appended only when its key is new. Maven merges every POM with at least
/// the super POM, so a POM without a parent gets its own list keyed this way
/// too.
fn merge_repositories(dominant: Vec<Repository>, recessive: &[Repository]) -> Vec<Repository> {
    let mut merged: IndexMap<Option<String>, Repository> =
        IndexMap::with_capacity(dominant.len() + recessive.len());
    for repo in dominant {
        merged.insert(repo.id.clone(), repo);
    }
    for repo in recessive {
        merged
            .entry(repo.id.clone())
            .or_insert_with(|| repo.clone());
    }
    merged.into_values().collect()
}

/// Verifies that a fetched POM advertises the requested `(group, artifact, version)`
/// coordinates. Used both for parent POMs and for BOM `<scope>import</scope>` POMs
/// so a hostile or misrouted payload cannot impersonate a different artifact.
///
/// Maven permits a POM to omit `<groupId>` and `<version>` when those fields are
/// inherited from its own `<parent>` declaration; the helper falls back to that
/// inner declaration when those fields are missing from the served POM.
pub(crate) fn verify_pom_coord(
    requested_group: &str,
    requested_artifact: &str,
    requested_version: &str,
    fetched: &Pom,
) -> Result<(), PomError> {
    verify_pom_coord_with(
        requested_group,
        requested_artifact,
        requested_version,
        fetched,
        &fetched.properties,
        None,
        false,
    )
}

/// Whether `version`, a local parent's as written, is in `range`, as Maven
/// checks it: in maven-artifact's order, not the resolver's that every other
/// range uses, reading an expression in it as text. A range maven-artifact
/// rejects, such as one with overlapping parts, leaves the parent to the
/// repositories, as Maven 3.9.12 and 3.10.0 leave it.
pub fn local_parent_in_range(version: &str, range: &str) -> bool {
    crate::artifact_version::contains(version, range).unwrap_or(false)
}

/// The version of `parent_pom`, a local parent `parent` names by the
/// version range: the one it declares, expanded, which must be in the
/// range as written.
fn version_in_range(parent: &Parent, parent_pom: &Pom) -> Result<String, PomError> {
    let written = parent_pom
        .version
        .as_ref()
        .or(parent_pom.parent.as_ref().map(|p| &p.version))
        .map_or("", String::as_str);
    if !local_parent_in_range(written, &parent.version) {
        return Err(PomError::ParentCoordMismatch(Box::new(
            ParentCoordMismatch {
                expected_group: parent.group_id.clone(),
                expected_artifact: parent.artifact_id.clone(),
                expected_version: parent.version.clone(),
                actual_group: parent.group_id.clone(),
                actual_artifact: parent.artifact_id.clone(),
                actual_version: written.to_string(),
            },
        )));
    }
    Ok(parent_pom
        .properties
        .interpolate_str_no_project(written)
        .unwrap_or_else(|_| written.to_string()))
}

/// Maven's check that `child`, whose parent version is a range, declares a
/// version of its own that is not one of the exact expressions naming its
/// own or its parent's version.
fn require_constant_version(child: &Pom, parent: &Parent) -> Result<(), PomError> {
    const REFERENCES: [&str; 4] = [
        "${pom.version}",
        "${project.version}",
        "${pom.parent.version}",
        "${project.parent.version}",
    ];
    match child.version.as_deref() {
        Some(own) if !REFERENCES.contains(&own) => Ok(()),
        _ => Err(in_pom(
            child,
            PomError::InvalidModel(format!(
                "the version must be a constant when the parent version is the range {}",
                bounded(&parent.version)
            )),
        )),
    }
}

/// Whether `pom`'s own or inherited coordinates hold a `${...}`, or it
/// inherits its groupId or version, which its parent may name with one.
pub(crate) fn declares_expression(pom: &Pom) -> bool {
    if pom.group_id.is_none() || pom.version.is_none() {
        return true;
    }
    let parent = pom.parent.as_ref();
    let group = pom.group_id.as_ref().or(parent.map(|p| &p.group_id));
    let version = pom.version.as_ref().or(parent.map(|p| &p.version));
    [group, pom.artifact_id.as_ref(), version]
        .into_iter()
        .flatten()
        .any(|value| value.contains("${"))
}

/// Whether `lineage[0]`, a fetched parent, declares `requested` once its
/// expressions are expanded with its lineage's properties and its own
/// `<parent>` coordinates, as a CI-friendly parent deployed without
/// flattening names itself with `${revision}` from its own parent. As in
/// Maven's model interpolation, user properties win over the lineage's, and
/// system properties and the environment lose to them.
fn declares_through_ancestors(
    lineage: &[Pom],
    requested: &Parent,
    ctx: Option<&ActivationContext>,
) -> bool {
    let mut properties = PropertyMap::new();
    for pom in lineage.iter().rev() {
        properties.extend(&pom.properties);
    }
    for (key, value) in ctx
        .into_iter()
        .flat_map(ActivationContext::model_user_properties)
    {
        properties.insert_external(key, value);
    }
    if let Some(ctx) = ctx {
        properties.set_input_context(ctx);
    }
    // Maven reads `project.*` and `pom.*` from the model ahead of every
    // property, and the unprefixed model fields after all of them.
    let system = ctx.map(ActivationContext::interpolation_system_properties);
    if let Some(parent) = &lineage[0].parent {
        for (field, value) in [
            ("groupId", &parent.group_id),
            ("artifactId", &parent.artifact_id),
            ("version", &parent.version),
        ] {
            for prefix in ["project.parent", "pom.parent", "parent"] {
                let key = format!("{prefix}.{field}");
                let shadowed = prefix == "parent"
                    && (properties.get(&key).is_some()
                        || system
                            .as_ref()
                            .is_some_and(|system| system.contains_key(&key)));
                if prefix == "parent" && !shadowed {
                    properties.insert_below_system(key, value);
                } else if !shadowed {
                    properties.insert(key, value);
                }
            }
        }
    }
    // An inherited groupId or version is the first ancestor's as written.
    let mut fetched = lineage[0].clone();
    for ancestor in &lineage[1..] {
        if fetched.group_id.is_none() {
            fetched.group_id.clone_from(&ancestor.group_id);
        }
        if fetched.version.is_none() {
            fetched.version.clone_from(&ancestor.version);
        }
    }
    // Its own model fields expand as in its model, so `${project.artifactId}`
    // as its version names the artifactId.
    let environment = ctx.map(ActivationContext::model_environment);
    let own = crate::model::project_info_in(
        &fetched,
        &properties,
        (None, None),
        system.clone().unwrap_or_default(),
        &environment.unwrap_or_default(),
    );
    if let Ok(own) = own {
        let other = |actual: &str, requested: &str| actual != requested && !actual.contains("${");
        return !(other(&own.group_id, &requested.group_id)
            || other(&own.artifact_id, &requested.artifact_id)
            || other(&own.version, &requested.version));
    }
    verify_pom_coord_with(
        &requested.group_id,
        &requested.artifact_id,
        &requested.version,
        &fetched,
        &properties,
        ctx,
        true,
    )
    .is_ok()
}

fn verify_pom_coord_with(
    requested_group: &str,
    requested_artifact: &str,
    requested_version: &str,
    fetched: &Pom,
    properties: &PropertyMap,
    ctx: Option<&ActivationContext>,
    lineage: bool,
) -> Result<(), PomError> {
    let system = ctx.map(ActivationContext::interpolation_system_properties);
    let interpolate = |text: &str| match (ctx, &system) {
        (Some(ctx), Some(system)) => properties.interpolate_str_with_system_properties(
            text,
            system,
            &ctx.model_environment(),
        ),
        _ => properties.interpolate_str_no_project(text),
    };
    // A POM published with an un-flattened `<version>${revision}</version>`
    // names itself through its properties; the requested coordinate is
    // always interpolated, so compare against the expanded identity.
    // Maven 3.9.12 and 3.10.0 check none of these: once the whole lineage
    // reads an expression and still leaves it unresolved, raeva does not
    // either, and refuses only a coordinate it knows is another.
    let expanded = |actual: Option<&String>, inherited: Option<&String>, requested: &str| {
        let actual = actual.or(inherited).cloned().unwrap_or_default();
        if actual != requested && actual.contains("${") {
            match interpolate(&actual) {
                Ok(expanded) if expanded == requested => return expanded,
                Ok(expanded) if lineage && expanded.contains("${") => return requested.to_string(),
                Err(_) if lineage => return requested.to_string(),
                _ => {}
            }
        }
        actual
    };
    let parent = fetched.parent.as_ref();
    let actual_group = expanded(
        fetched.group_id.as_ref(),
        parent.map(|p| &p.group_id),
        requested_group,
    );
    let actual_artifact = expanded(fetched.artifact_id.as_ref(), None, requested_artifact);
    let actual_version = expanded(
        fetched.version.as_ref(),
        parent.map(|p| &p.version),
        requested_version,
    );

    if actual_group != requested_group
        || actual_artifact != requested_artifact
        || actual_version != requested_version
    {
        return Err(PomError::ParentCoordMismatch(Box::new(
            ParentCoordMismatch {
                expected_group: requested_group.to_string(),
                expected_artifact: requested_artifact.to_string(),
                expected_version: requested_version.to_string(),
                actual_group,
                actual_artifact,
                actual_version,
            },
        )));
    }

    Ok(())
}

/// Merge dependency lists from child to ancestor, preserving declaration order.
/// Later lists contribute only unseen keys; duplicates within a list replace in place.
pub(crate) fn merge_dependency_levels<'a>(
    levels: impl IntoIterator<Item = &'a Vec<Dependency>>,
) -> Vec<Dependency> {
    let mut merged = IndexMap::new();
    for level in levels {
        let own: IndexMap<_, _> = level.iter().map(|dep| (dep.raw_key(), dep)).collect();
        for (key, dep) in own {
            merged.entry(key).or_insert_with(|| dep.clone());
        }
    }
    merged.into_values().collect()
}

/// Tag each managed entry `pom` declares with the POM, by its coordinates
/// as written, and the property its version is written as; none where those
/// coordinates hold an expression. An import's entries name the BOM instead,
/// once interpolation shows it is one.
fn note_management_origins(pom: &mut Pom) {
    let Some(management) = &mut pom.dependency_management else {
        return;
    };
    let group = (pom.group_id.as_deref())
        .or_else(|| pom.parent.as_ref().map(|parent| parent.group_id.as_str()))
        .unwrap_or_default();
    let artifact = pom.artifact_id.as_deref().unwrap_or_default();
    let own =
        rv_maven_types::ManagedSource::new(rv_maven_types::ManagedKind::Pom, group, artifact, None);
    // One source per property, shared by the entries that name it.
    let mut shared: HashMap<Option<String>, std::sync::Arc<rv_maven_types::ManagedSource>> =
        HashMap::default();
    for entry in &mut management.dependencies {
        let property = (entry.version.as_deref()).and_then(rv_maven_types::single_property);
        let origin =
            own.as_ref().map(|own| {
                std::sync::Arc::clone(shared.entry(property.map(str::to_string)).or_insert_with(
                    || {
                        std::sync::Arc::new(rv_maven_types::ManagedSource {
                            property: property.map(str::to_string),
                            ..own.clone()
                        })
                    },
                ))
            });
        entry.origin = crate::ManagedOrigin(origin);
    }
}

/// Record where the one property a version is written as takes its value:
/// the nearest POM of the lineage, the project first, whose properties, its
/// active profiles' included, hold it. A dependency `chain` declares, or a
/// managed entry of its local POMs, names that POM when it is a parent from
/// a repository and the value reads no other property. A managed entry of
/// a parent from a repository keeps its own origin when that parent holds
/// a value that reads no other property, since the version moves with it,
/// and otherwise takes the holder's: none for a value the user,
/// `settings.xml`, the project, another property or the model sets.
fn note_property_origins(chain: &mut [Pom], ctx: Option<&ActivationContext>) {
    type Source = Option<std::sync::Arc<rv_maven_types::ManagedSource>>;
    // `usize::MAX` stands for a value from outside the lineage's properties.
    let holder = |name: &str| -> (usize, Source) {
        let model = name.starts_with("project.") || name.starts_with("pom.");
        let external = ctx
            .is_some_and(|ctx| ctx.model_user_properties().any(|(key, _)| key == name))
            || (chain.iter()).any(|pom| pom.user_properties.get(name).is_some());
        let held = (chain.iter()).position(|pom| pom.properties.get(name).is_some());
        let Some(at) = held.filter(|_| !model && !external) else {
            return (usize::MAX, None);
        };
        let pom = &chain[at];
        let direct = (pom.properties.get(name)).is_some_and(|value| !value.contains("${"));
        let remote = (pom.provenance.as_ref()).is_some_and(|provenance| !provenance.is_local());
        let group = (pom.group_id.as_deref())
            .or_else(|| pom.parent.as_ref().map(|parent| parent.group_id.as_str()));
        let source = (group.zip(pom.artifact_id.as_deref()))
            .filter(|_| direct && remote)
            .and_then(|(group, artifact)| {
                rv_maven_types::ManagedSource::new(
                    rv_maven_types::ManagedKind::Property,
                    group,
                    artifact,
                    Some(&format!("${{{name}}}")),
                )
            });
        (at, source.map(std::sync::Arc::new))
    };
    let mut holders: HashMap<String, (usize, Source)> = HashMap::default();
    let mut tags: Vec<(usize, bool, usize, Source)> = Vec::new();
    for (at, pom) in chain.iter().enumerate() {
        let local = (pom.provenance.as_ref()).is_none_or(Provenance::is_local);
        let managed = (pom.dependency_management.iter())
            .flat_map(|management| management.dependencies.iter().enumerate())
            .map(|(index, entry)| (true, index, entry));
        let declared =
            (pom.dependencies.iter().enumerate()).map(|(index, dep)| (false, index, dep));
        for (managed, index, dependency) in managed.chain(declared) {
            let Some(name) =
                (dependency.version.as_deref()).and_then(rv_maven_types::single_property)
            else {
                continue;
            };
            let found = holders
                .entry(name.to_string())
                .or_insert_with(|| holder(name));
            let (held_at, source) = found.clone();
            let tag = match managed && !local {
                true => held_at != at || source.is_none(),
                false => source.is_some(),
            };
            if tag {
                tags.push((at, managed, index, source));
            }
        }
    }
    for (at, managed, index, source) in tags {
        let pom = &mut chain[at];
        let dependency = match managed {
            true => (pom.dependency_management.as_mut())
                .map(|management| &mut management.dependencies[index]),
            false => Some(&mut pom.dependencies[index]),
        };
        if let Some(dependency) = dependency {
            dependency.origin = crate::ManagedOrigin(source);
        }
    }
}

/// Maven's model merger is source-dominant: the child's managed entries come
/// first, a repeated one replacing the earlier in place, then the parent's
/// the child does not override, in the parent's order. Order matters because
/// imported BOM payloads expand later against a first-wins index.
fn merge_dependency_management(
    parent: Option<DependencyManagement>,
    child: Option<DependencyManagement>,
) -> Option<DependencyManagement> {
    match (child, parent) {
        (None, parent) => parent,
        (child, None) => child,
        (Some(child), Some(parent)) => Some(DependencyManagement {
            dependencies: merge_dependency_levels([&child.dependencies, &parent.dependencies]),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySource, MemorySourceError};

    #[test]
    fn an_invalid_artifact_range_takes_no_local_parent() {
        for (range, version) in [("[1,1)", "1"), ("[1,3],[2,4]", "2"), ("[1,2", "1")] {
            assert!(crate::artifact_version::contains(version, range).is_none());
            assert!(!local_parent_in_range(version, range));
        }
        let deep = format!("{}1", "1-".repeat(100_000));
        assert!(!local_parent_in_range(&deep, "[1,2)"));
    }

    fn pom(xml: &str) -> Pom {
        Pom::parse(xml).unwrap()
    }

    fn pom_of(artifact: &str, parent: &str, body: &str) -> Pom {
        let parent = if parent.is_empty() {
            String::new()
        } else {
            format!(
                "<parent><groupId>g</groupId><artifactId>{parent}</artifactId>\
                 <version>1</version><relativePath/></parent>"
            )
        };
        pom(&format!(
            "<project><groupId>g</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version>{parent}{body}</project>"
        ))
    }

    fn repositories(repositories: &[(&str, &str)]) -> String {
        let entries: String = repositories
            .iter()
            .map(|(id, url)| match *id {
                "-" => format!("<repository><url>{url}</url></repository>"),
                id => format!("<repository><id>{id}</id><url>{url}</url></repository>"),
            })
            .collect();
        format!("<repositories>{entries}</repositories>")
    }

    fn model_error<T: std::fmt::Debug>(result: Result<T, MemorySourceError>) -> PomError {
        match result.unwrap_err() {
            MemorySourceError::Model(error) => error,
            other => panic!("{other}"),
        }
    }

    /// A version written as one property a parent from a repository sets
    /// names that parent, unless the user, `settings.xml`, the project or
    /// another property supplies the value; a parent's managed entry names
    /// the POM that holds the value.
    #[test]
    fn a_property_a_remote_parent_sets_names_that_parent() {
        let origins = |ctx: &ActivationContext, own: &str, version: &str, parent: &str| {
            let remote = |artifact, parent_of, body: &str| {
                let mut pom = pom_of(artifact, parent_of, body);
                pom.provenance = Some(Provenance::RemoteParentOfRoot);
                pom
            };
            let grand = remote(
                "grand",
                "",
                "<properties><a>1</a><b>${a}</b></properties><dependencyManagement>\
                 <dependencies><dependency><groupId>g</groupId><artifactId>m</artifactId>\
                 <version>${a}</version></dependency></dependencies></dependencyManagement>",
            );
            let mut app = pom_of(
                "app",
                "parent",
                &format!(
                    "<properties>{own}</properties><dependencies><dependency>\
                     <groupId>g</groupId><artifactId>lib</artifactId>\
                     <version>{version}</version></dependency></dependencies>"
                ),
            );
            app.provenance = Some(Provenance::RootProject {
                path: "pom.xml".into(),
            });
            let mut chain = [app, remote("parent", "grand", parent), grand];
            chain.iter_mut().for_each(note_management_origins);
            note_property_origins(&mut chain, Some(ctx));
            let name = |origin: &crate::ManagedOrigin| origin.0.as_ref().map(|s| s.to_string());
            let managed = &chain[2]
                .dependency_management
                .as_ref()
                .unwrap()
                .dependencies[0];
            (
                name(&chain[0].dependencies[0].origin),
                name(&managed.origin),
            )
        };
        let some = |text: &str| Some(text.to_string());
        let ctx = ActivationContext::default();
        assert_eq!(
            origins(&ctx, "", "${a}", ""),
            (some("property g:grand (${a})"), some("pom g:grand (${a})"))
        );
        let overridden = "<properties><a>2</a></properties>";
        assert_eq!(
            origins(&ctx, "", "${a}", overridden),
            (
                some("property g:parent (${a})"),
                some("property g:parent (${a})")
            )
        );
        assert_eq!(origins(&ctx, "<a>2</a>", "${a}", ""), (None, None));
        assert_eq!(origins(&ctx, "", "${b}", "").0, None);
        assert_eq!(origins(&ctx, "", "1", "").0, None);
        let mut chain = [pom_of("app", "grand", ""), {
            let mut grand = pom_of(
                "grand",
                "",
                "<properties><a>1</a><b>${a}</b></properties><dependencyManagement>\
                 <dependencies><dependency><groupId>g</groupId><artifactId>n</artifactId>\
                 <version>${b}</version></dependency><dependency><groupId>g</groupId>\
                 <artifactId>o</artifactId><version>${project.version}</version>\
                 </dependency></dependencies></dependencyManagement>",
            );
            grand.provenance = Some(Provenance::RemoteParentOfRoot);
            grand
        }];
        chain.iter_mut().for_each(note_management_origins);
        note_property_origins(&mut chain, Some(&ctx));
        let managed = &chain[1]
            .dependency_management
            .as_ref()
            .unwrap()
            .dependencies;
        assert!(managed.iter().all(|entry| entry.origin.0.is_none()));
        let mut settings = ActivationContext::default();
        settings.settings_properties.insert("a", "2");
        assert_eq!(origins(&settings, "", "${a}", ""), (None, None));
        let mut user = ActivationContext::default();
        user.properties.insert("a".into(), "2".into());
        assert_eq!(origins(&user, "", "${a}", ""), (None, None));
    }

    /// A cycle is a fetched POM's only when that POM defines every property
    /// in it; a user property takes a name back.
    #[test]
    fn a_cycle_is_blamed_on_a_fetched_pom_only_when_it_defines_every_name() {
        let cycle = || PomError::PropertyCycle(vec!["a".into(), "b".into(), "a".into()]);
        let mut fetched = FetchedProperties {
            keys: [
                ("a".to_string(), "com.example:parent:1".to_string()),
                ("b".to_string(), "com.example:parent:1".to_string()),
            ]
            .into_iter()
            .collect(),
            ..FetchedProperties::default()
        };
        assert!(matches!(
            fetched.blame(cycle()),
            PomError::InvalidModel(message) if message.starts_with("com.example:parent:1: ")
        ));
        // A project property that leads into the parent's cycle is not part
        // of it.
        let led_in = PomError::PropertyCycle(vec!["x".into(), "a".into(), "b".into(), "a".into()]);
        assert!(matches!(fetched.blame(led_in), PomError::InvalidModel(_)));
        fetched.remove("b");
        assert!(matches!(fetched.blame(cycle()), PomError::PropertyCycle(_)));
        let other = PomError::InvalidSystemPath("x".into());
        assert!(matches!(
            FetchedProperties::default().blame(other),
            PomError::InvalidSystemPath(_)
        ));
    }

    /// The child inherits the parent's coordinates, properties, dependencies
    /// and management, where entries differing only in type or classifier
    /// stay apart. Maven keys repositories by id with the absent id as one
    /// key: a later one replaces the earlier in place, the child's replaces
    /// the parent's, and an empty `<id></id>` is a key of its own.
    #[test]
    fn inherits_the_parents_fields_and_merges_repositories_by_id() {
        let managed = "<dependencyManagement><dependencies>\
            <dependency><groupId>m</groupId><artifactId>lib</artifactId><version>1</version></dependency>\
            <dependency><groupId>m</groupId><artifactId>lib</artifactId><version>1</version>\
            <type>test-jar</type><classifier>tests</classifier></dependency>\
            </dependencies></dependencyManagement>";
        let parent = pom_of(
            "parent",
            "",
            &format!(
                "<properties><k>v</k><project.directory>p</project.directory></properties>\
                 {managed}<dependencies><dependency>\
                 <groupId>m</groupId><artifactId>a</artifactId><version>1</version></dependency>\
                 </dependencies>{}",
                repositories(&[
                    ("central", "https://parent.example/central"),
                    ("-", "https://parent.example/"),
                    ("", "https://empty.example/"),
                    ("-", "https://parent-again.example/"),
                    ("snapshots", "https://snapshots.example/"),
                ])
            ),
        );
        let child = pom(&format!(
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><artifactId>child</artifactId>\
             <properties><child>yes</child></properties>{}</project>",
            repositories(&[
                ("-", "https://first.example/"),
                ("central", "https://child.example/central"),
                ("-", "https://second.example/"),
            ])
        ));
        let source = MemorySource::new().with_parent("g", "parent", "1", parent);
        let effective = apply_inheritance(child, &source).unwrap();
        assert_eq!(effective.group_id.as_deref(), Some("g"));
        assert_eq!(effective.version.as_deref(), Some("1"));
        assert_eq!(effective.properties.get("k").map(String::as_str), Some("v"));
        assert_eq!(effective.properties.get("project.directory"), None);
        assert_eq!(
            effective.properties.get("child").map(String::as_str),
            Some("yes")
        );
        assert_eq!(effective.dependencies.len(), 1);
        let management = effective.dependency_management.unwrap().dependencies;
        assert_eq!(management.len(), 2);
        let urls: Vec<&str> = effective
            .repositories
            .iter()
            .map(|r| r.url.as_str())
            .collect();
        assert_eq!(
            urls,
            [
                "https://second.example/",
                "https://child.example/central",
                "https://empty.example/",
                "https://snapshots.example/",
            ]
        );
    }

    /// Each ancestor's repositories, and those of its active profiles, serve
    /// the next parent lookup as written; an inactive profile's do not, and
    /// nothing of it is observed. Maven interpolates profile activation for
    /// that lookup but not repository URLs.
    #[test]
    fn ancestor_repositories_serve_the_next_parent_lookup() {
        let host = "https://host.example/";
        let profile = |activation: &str| {
            format!(
                "<properties><jdk.range>[17,)</jdk.range><os.family>unix</os.family>\
                 <property.name>host.enabled</property.name></properties><profiles>\
                 <profile><id>host</id>{activation}{}</profile></profiles>",
                repositories(&[("host", host)])
            )
        };
        let conditions = "<activation><jdk>${jdk.range}</jdk><os><family>${os.family}</family>\
            </os><property><name>${property.name}</name><value>yes</value></property>\
            </activation>";
        let direct = repositories(&[("host", host)]);
        let expression = format!(
            "<properties><host>{host}</host></properties>{}",
            repositories(&[("host", "${host}")])
        );
        let chain = |mid_body: &str| {
            MemorySource::new()
                .with_parent("g", "mid", "1", pom_of("mid", "top", mid_body))
                .with_parent("g", "top", "1", pom_of("top", "", ""))
                .with_gate("top", host)
        };
        // (the mid POM, -P, -P!, JDK, -Dhost.enabled, resolves)
        for (mid, active, inactive, jdk, enabled, resolves) in [
            (direct.as_str(), "", "", "21", "yes", true),
            (&expression, "", "", "21", "yes", false),
            (&profile(""), "host", "", "21", "yes", true),
            (&profile(""), "", "", "21", "yes", false),
            (&profile(conditions), "", "", "21", "yes", true),
            (&profile(conditions), "", "", "11", "yes", false),
            (&profile(conditions), "", "", "21", "no", false),
            (&profile(conditions), "", "host", "21", "yes", false),
        ] {
            let ctx = ActivationContext {
                environment: crate::ModelEnvironment::builder()
                    .platform("linux", "x86_64")
                    .jdk_version(jdk)
                    .build(),
                properties: std::collections::HashMap::from([(
                    "host.enabled".into(),
                    enabled.into(),
                )]),
                active_profiles: [active]
                    .into_iter()
                    .filter(|p| !p.is_empty())
                    .map(Into::into)
                    .collect(),
                inactive_profiles: [inactive]
                    .into_iter()
                    .filter(|p| !p.is_empty())
                    .map(Into::into)
                    .collect(),
                ..ActivationContext::default()
            };
            let source = chain(mid);
            let result = crate::ready(crate::Project::build(
                pom_of("app", "mid", ""),
                &source,
                ModelPolicy::DEPENDENCY,
                &ctx,
            ));
            let case = format!("{mid} -P{active} -P!{inactive} jdk={jdk} enabled={enabled}");
            assert_eq!(result.is_ok(), resolves, "{case}: {result:?}");
            if !resolves {
                assert!(
                    matches!(model_error(result), PomError::ParentNotFound(..)),
                    "{case}"
                );
                let observed = source.observed();
                assert!(
                    observed.iter().flatten().all(|repo| repo.url != host),
                    "{case}"
                );
            }
        }
    }

    /// A repository the project's own POM declares keeps the project's trust
    /// only when its URL takes no value a fetched parent chose: a property
    /// only that parent defines, directly or through another property, or
    /// the version it lends the project, or a `<build>` value it sets that
    /// the project does not. A parent of unknown origin counts as fetched.
    #[test]
    fn a_project_repository_url_from_a_fetched_parent_loses_the_projects_trust() {
        let urls = [
            ("chosen", "${repo.url}"),
            ("wrapped", "${wrapped}"),
            ("version", "https://repo.example/${project.version}/"),
            ("group-property", "${groupId}"),
            ("group", "https://repo.example/${project.groupId}/"),
            ("own", "${mine}"),
            ("overridden", "${overridden}"),
            ("environment", "https://repo.example/${env.HOME}/"),
            ("build", "file://${project.build.directory}/staging/"),
            ("final", "file://${build.finalName}/"),
            ("final-model", "file://${project.build.finalName}/"),
            ("output", "file://${project.build.outputDirectory}/"),
            ("source", "file://${pom.build.sourceDirectory}/"),
            ("goal", "file://${project.build.defaultGoal}/"),
        ];
        let build = |ctx: Option<&ActivationContext>, parent: Option<crate::Provenance>| {
            let mut fetched = pom(
                r#"<project><groupId>corp</groupId><artifactId>parent</artifactId>
                <version>7</version><packaging>pom</packaging><properties>
                <repo.url>https://attacker.example/</repo.url>
                <overridden>https://attacker.example/</overridden>
                <groupId>https://attacker.example/</groupId>
                <project.build.defaultGoal>/etc</project.build.defaultGoal>
                </properties><build><directory>/etc</directory><finalName>evil</finalName>
                </build></project>"#,
            );
            if let Some(provenance) = parent {
                fetched.set_provenance(provenance);
            }
            let mut project = pom(&format!(
                r#"<project><parent><groupId>corp</groupId><artifactId>parent</artifactId>
                <version>7</version></parent><groupId>mine</groupId><artifactId>app</artifactId>
                <properties>
                <mine>https://mine.example/</mine><wrapped>${{repo.url}}</wrapped>
                <overridden>https://mine.example/</overridden></properties>
                <build><directory>out</directory></build>{}</project>"#,
                repositories(&urls)
            ));
            project.mark_root_repositories();
            project.set_provenance(crate::Provenance::RootProject {
                path: "pom.xml".into(),
            });
            let source = MemorySource::new().with_parent("corp", "parent", "7", fetched);
            let effective = crate::ready(apply_inheritance_tracked(
                project,
                &source,
                ModelPolicy::DEPENDENCY,
                ParentLookup::Project,
                ctx,
            ))
            .unwrap()
            .0;
            effective
                .repositories
                .into_iter()
                .filter(|repo| repo.root_declared)
                .filter_map(|repo| repo.id)
                .collect::<Vec<_>>()
        };
        let remote = || Some(crate::Provenance::RemoteParentOfRoot);
        let kept = [
            "group",
            "own",
            "overridden",
            "environment",
            "build",
            "output",
            "source",
        ];
        assert_eq!(build(None, remote()), kept);
        assert_eq!(build(None, None), kept);

        // A `-D` value is the user's, but a `project.` name reads the model
        // before it.
        let mut ctx = ActivationContext::default();
        for name in [
            "repo.url",
            "build.finalName",
            "project.build.finalName",
            "project.build.defaultGoal",
            "project.version",
        ] {
            ctx.properties
                .insert(name.into(), "https://user.example/".into());
        }
        let user = [
            "chosen",
            "wrapped",
            "group",
            "own",
            "overridden",
            "environment",
            "build",
            "final",
            "output",
            "source",
            "goal",
        ];
        assert_eq!(build(Some(&ctx), remote()), user);
    }

    #[test]
    fn local_model_fields_trace_fetched_properties_in_repository_urls() {
        for field in ["artifactId", "packaging"] {
            for prefix in ["project.", "pom.", ""] {
                for (raw, own, user, trusted) in [
                    ("${wrapped}", "", false, false),
                    ("literal", "", false, true),
                    ("${wrapped}", "<chosen>local</chosen>", false, true),
                    ("${wrapped}", "", true, true),
                    ("${project.properties.chosen}", "", false, false),
                    (
                        "${project.properties.chosen}",
                        "<chosen>local</chosen>",
                        false,
                        true,
                    ),
                    ("${project.properties.chosen}", "", true, true),
                    ("${pom.properties.chosen}", "", false, false),
                    (
                        "${pom.properties.chosen}",
                        "<chosen>local</chosen>",
                        false,
                        true,
                    ),
                    ("${pom.properties.chosen}", "", true, true),
                ] {
                    let mut parent = pom(
                        "<project><groupId>g</groupId><artifactId>parent</artifactId>\
                         <version>1</version><packaging>pom</packaging>\
                         <properties><chosen>remote</chosen></properties></project>",
                    );
                    parent.set_provenance(crate::Provenance::RemoteParentOfRoot);
                    let source = MemorySource::new().with_parent("g", "parent", "1", parent);
                    let fields = if field == "artifactId" {
                        format!("<artifactId>{raw}</artifactId>")
                    } else {
                        format!("<artifactId>app</artifactId><packaging>{raw}</packaging>")
                    };
                    let mut project = pom(&format!(
                        "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
                         <version>1</version></parent><groupId>g</groupId><version>1</version>\
                         {fields}<properties>\
                         <wrapped>${{chosen}}</wrapped>{own}</properties>{}</project>",
                        repositories(&[
                            (
                                "direct",
                                &format!("https://repo.example/${{{prefix}{field}}}/")
                            ),
                            ("build", "https://repo.example/${project.build.finalName}/"),
                            ("default", "https://repo.example/${project.packaging}/"),
                        ])
                    ));
                    project.mark_root_repositories();
                    let mut ctx = ActivationContext::default();
                    if user {
                        ctx.properties.insert("chosen".into(), "user".into());
                    }
                    let effective = crate::ready(apply_inheritance_tracked(
                        project,
                        &source,
                        ModelPolicy::DEPENDENCY,
                        ParentLookup::Project,
                        Some(&ctx),
                    ))
                    .unwrap()
                    .0;
                    for repo in effective.repositories {
                        let expected = match repo.id.as_deref().unwrap() {
                            "direct" => trusted,
                            "build" => field != "artifactId" || trusted,
                            "default" => field != "packaging" || trusted,
                            _ => unreachable!(),
                        };
                        assert_eq!(
                            repo.root_declared, expected,
                            "{field} {prefix} {raw} own={own} user={user}: {:?}",
                            repo.id
                        );
                    }
                }
            }
        }
    }

    /// Maven 3.10's `${project.rootDirectory}` is the project's own, so a
    /// repository URL that reads it keeps the project's trust under a
    /// fetched parent, whatever properties that parent defines.
    #[test]
    fn a_maven_310_root_directory_is_no_fetched_value() {
        let dir = tempfile::tempdir().unwrap();
        for (mode, expression, trusted) in [
            (MavenMode::Maven310, "${project.rootDirectory}", true),
            (MavenMode::Maven310, "${pom.rootDirectory}", true),
            (MavenMode::Maven310, "${rootDirectory}", true),
            (MavenMode::Maven39, "${rootDirectory}", false),
        ] {
            let mut parent = pom(
                "<project><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version><packaging>pom</packaging>\
                 <properties><rootDirectory>/remote</rootDirectory></properties></project>",
            );
            parent.set_provenance(crate::Provenance::RemoteParentOfRoot);
            let source = MemorySource::new().with_parent("g", "parent", "1", parent);
            let mut project = pom(&format!(
                "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version></parent><groupId>g</groupId><artifactId>app</artifactId>\
                 {}</project>",
                repositories(&[("own", &format!("file://{expression}/r/"))])
            ));
            project.mark_root_repositories();
            let host = crate::HostSnapshot::for_testing(&[]).with_reactor_root(dir.path());
            let mut ctx =
                ActivationContext::new(host.environment("linux", "x86_64").with_maven_mode(mode));
            ctx.base_dir = Some(dir.path().to_path_buf());
            ctx.property_source = crate::PropertySource::User;
            let effective = crate::ready(crate::Project::build(
                project,
                &source,
                ModelPolicy::PROJECT,
                &ctx,
            ))
            .unwrap();
            let repo = &effective.repositories[0];
            assert_eq!(repo.root_declared, trusted, "{mode:?} {expression}");
        }
    }

    /// Maven 3.10's super POM `central` that `maven.repo.central` points is
    /// trusted as the project's repositories are, unless a fetched parent
    /// chose the URL.
    #[test]
    fn a_maven_310_central_from_a_fetched_parent_loses_the_projects_trust() {
        let central = "<maven.repo.central>https://central.example/m2</maven.repo.central>";
        for (parent_property, own, settings, trusted) in [
            (true, false, false, false),
            (true, true, false, true),
            (true, false, true, true),
            (false, true, false, true),
        ] {
            let mut parent = pom(&format!(
                "<project><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version><packaging>pom</packaging><properties>{}</properties>\
                 </project>",
                if parent_property { central } else { "" }
            ));
            parent.set_provenance(crate::Provenance::RemoteParentOfRoot);
            let source = MemorySource::new().with_parent("g", "parent", "1", parent);
            let mut project = pom(&format!(
                "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version></parent><groupId>g</groupId><artifactId>app</artifactId>\
                 <properties>{}</properties></project>",
                if own { central } else { "" }
            ));
            project.mark_root_repositories();
            let mut ctx = ActivationContext::new(
                crate::ModelEnvironment::default().with_maven_mode(MavenMode::Maven310),
            );
            ctx.property_source = crate::PropertySource::User;
            if settings {
                (ctx.settings_properties)
                    .insert("maven.repo.central", "https://central.example/m2");
            }
            let effective = crate::ready(crate::Project::build(
                project,
                &source,
                ModelPolicy::PROJECT,
                &ctx,
            ))
            .unwrap();
            let case = format!("parent={parent_property} own={own} settings={settings}");
            let [repo] = &effective.repositories[..] else {
                panic!("{case}: {:?}", effective.repositories);
            };
            assert_eq!(repo.url, "https://central.example/m2", "{case}");
            assert_eq!(repo.root_declared, trusted, "{case}");
        }
    }

    #[test]
    fn property_aliases_follow_interpolation_precedence_in_repository_urls() {
        for prefix in ["project.properties.", "pom.properties."] {
            for (key, own, user, settings, value, trusted) in [
                ("chosen", "", "", "", "remote", false),
                ("chosen", "<chosen>local</chosen>", "", "", "local", true),
                ("chosen", "", "user", "", "user", true),
                (
                    "chosen",
                    "<chosen>local</chosen>",
                    "${fetched}",
                    "",
                    "remote",
                    false,
                ),
                ("chosen", "", "", "settings", "settings", true),
                ("chosen", "", "user", "${fetched}", "user", true),
                ("groupId", "", "", "", "g", true),
                ("version", "", "", "", "1", false),
                (
                    "project.properties.chosen",
                    "<project.properties.chosen>local</project.properties.chosen>",
                    "",
                    "",
                    "local",
                    true,
                ),
                (
                    "build.finalName",
                    "",
                    "",
                    "",
                    "${project.properties.build.finalName}",
                    true,
                ),
            ] {
                let mut parent = pom(
                    "<project><groupId>g</groupId><artifactId>parent</artifactId>\
                     <version>1</version><packaging>pom</packaging>\
                     <properties><chosen>remote</chosen><fetched>remote</fetched></properties>\
                     <build><finalName>remote</finalName></build></project>",
                );
                parent.set_provenance(crate::Provenance::RemoteParentOfRoot);
                let source = MemorySource::new().with_parent("g", "parent", "1", parent);
                let mut project = pom(&format!(
                    "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
                     <version>1</version></parent><groupId>g</groupId><artifactId>app</artifactId>\
                     <properties>{own}</properties>{}</project>",
                    repositories(&[("own", &format!("https://repo.example/${{{prefix}{key}}}/"))])
                ));
                project.mark_root_repositories();
                let mut ctx = ActivationContext::default();
                ctx.properties
                    .insert(format!("{prefix}{key}"), "shadow".into());
                if !user.is_empty() {
                    ctx.properties.insert(key.into(), user.into());
                }
                if !settings.is_empty() {
                    ctx.settings_properties.insert(key, settings);
                }
                let effective = crate::ready(crate::Project::build(
                    project,
                    &source,
                    ModelPolicy::PROJECT,
                    &ctx,
                ))
                .unwrap();
                let repo = &effective.repositories[0];
                let value = value.replace("project.properties.", prefix);
                let case = format!("{prefix}{key} own={own} user={user} settings={settings}");
                assert_eq!(repo.url, format!("https://repo.example/{value}/"), "{case}");
                assert_eq!(repo.root_declared, trusted, "{case}");
            }
        }
    }

    #[test]
    fn local_parent_fields_trace_fetched_properties_in_repository_urls() {
        for field in ["groupId", "artifactId", "version"] {
            let coordinates = format!(
                "<groupId>{}</groupId><artifactId>{}</artifactId><version>{}</version>",
                if field == "groupId" { "${chosen}" } else { "g" },
                if field == "artifactId" {
                    "${chosen}"
                } else {
                    "parent"
                },
                if field == "version" { "${chosen}" } else { "1" },
            );
            let mut parent = pom(&format!(
                "<project><parent><groupId>g</groupId><artifactId>top</artifactId>\
                 <version>1</version></parent>{coordinates}</project>"
            ));
            parent.set_provenance(crate::Provenance::LocalParent {
                path: "../pom.xml".into(),
            });
            let mut top = pom(
                "<project><groupId>g</groupId><artifactId>top</artifactId><version>1</version>\
                 <properties><chosen>remote</chosen></properties></project>",
            );
            top.set_provenance(crate::Provenance::RemoteParentOfRoot);
            let source = MemorySource::new()
                .with_parent(
                    parent.group_id.as_deref().unwrap(),
                    parent.artifact_id.as_deref().unwrap(),
                    parent.version.as_deref().unwrap(),
                    parent.clone(),
                )
                .with_parent("g", "top", "1", top);
            let mut project = pom(&format!(
                "<project><parent>{coordinates}</parent><groupId>g</groupId>\
                 <artifactId>app</artifactId><version>1</version>{}</project>",
                repositories(&[(
                    "own",
                    &format!("https://repo.example/${{project.parent.{field}}}/")
                )])
            ));
            project.mark_root_repositories();
            let effective = crate::ready(apply_inheritance_tracked(
                project,
                &source,
                ModelPolicy::DEPENDENCY,
                ParentLookup::Project,
                None,
            ))
            .unwrap()
            .0;
            assert!(!effective.repositories[0].root_declared, "{field}");
        }
    }

    /// A strict build fails on a missing parent; a lenient one stands its
    /// declaration in for it, unless the child then lacks a groupId.
    #[test]
    fn a_missing_parent_follows_the_policy() {
        let lenient = ModelPolicy {
            root: false,
            plugins: crate::PluginModel::Off,
            missing_parent: MissingParent::InheritDeclaredCoordinates,
        };
        let child = |group: &str, own: &str| {
            pom(&format!(
                "<project><parent><groupId>{group}</groupId><artifactId>oss-parent</artifactId>\
                 <version>9</version><relativePath/></parent><artifactId>child</artifactId>\
                 {own}</project>"
            ))
        };
        let apply = |pom: Pom, policy: ModelPolicy| {
            crate::ready(apply_inheritance_tracked(
                pom,
                &MemorySource::new(),
                policy,
                ParentLookup::Project,
                None,
            ))
            .map(|(pom, _)| pom)
        };
        let own = "<groupId>io.netty</groupId><version>4.1.0</version>";
        let error = model_error(apply(child("org.oss", own), ModelPolicy::DEPENDENCY));
        assert!(
            matches!(&error, PomError::ParentNotFound(g, a, v)
                if (g.as_str(), a.as_str(), v.as_str()) == ("org.oss", "oss-parent", "9")),
            "{error:?}"
        );
        for (group, own, expected) in [
            ("org.oss", own, "io.netty:4.1.0"),
            ("org.oss", "", "org.oss:9"),
            ("", "<groupId>io.netty</groupId>", "io.netty:9"),
        ] {
            let effective = apply(child(group, own), lenient).unwrap();
            let gv = format!(
                "{}:{}",
                effective.group_id.unwrap_or_default(),
                effective.version.unwrap_or_default()
            );
            assert_eq!(gv, expected);
        }
        let error = model_error(apply(child("", ""), lenient));
        assert!(
            matches!(&error, PomError::ParentNotFound(g, ..) if g.is_empty()),
            "{error:?}"
        );
    }

    /// A fetched parent must declare the coordinates the child asked for,
    /// through its own properties or its own parent's declaration; a
    /// repository answering with another POM is refused.
    #[test]
    fn a_fetched_parent_must_declare_the_requested_coordinates() {
        let child = |version: &str| {
            pom(&format!(
                "<project><parent><groupId>com.base</groupId><artifactId>parent</artifactId>\
                 <version>{version}</version></parent><artifactId>child</artifactId></project>"
            ))
        };
        let unflattened = pom(
            "<project><groupId>com.base</groupId><artifactId>parent</artifactId>\
             <version>${revision}</version><properties><revision>0.0.20</revision>\
             </properties></project>",
        );
        let source =
            MemorySource::new().with_parent("com.base", "parent", "0.0.20", unflattened.clone());
        apply_inheritance(child("0.0.20"), &source).unwrap();
        let source = MemorySource::new().with_parent("com.base", "parent", "0.0.21", unflattened);
        let error = model_error(apply_inheritance(child("0.0.21"), &source));
        assert!(
            matches!(error, PomError::ParentCoordMismatch(_)),
            "{error:?}"
        );

        let inheriting = pom("<project><parent><groupId>com.base</groupId>\
             <artifactId>grandparent</artifactId><version>1</version><relativePath/></parent>\
             <artifactId>parent</artifactId></project>");
        let source = MemorySource::new()
            .with_parent("com.base", "parent", "1", inheriting)
            .with_parent(
                "com.base",
                "grandparent",
                "1",
                pom("<project><groupId>com.base\
                </groupId><artifactId>grandparent</artifactId><version>1</version></project>"),
            );
        apply_inheritance(child("1"), &source).unwrap();

        let foreign = pom("<project><groupId>evil.attacker</groupId>\
             <artifactId>backdoor</artifactId><version>0.0.1</version></project>");
        let source = MemorySource::new().with_parent("com.base", "parent", "1", foreign);
        let PomError::ParentCoordMismatch(mismatch) =
            model_error(apply_inheritance(child("1"), &source))
        else {
            panic!("expected a coordinate mismatch");
        };
        assert_eq!(
            [
                &mismatch.expected_group,
                &mismatch.expected_artifact,
                &mismatch.expected_version
            ],
            ["com.base", "parent", "1"]
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

    /// A CI-friendly parent deployed without flattening names itself with
    /// a property its own parent defines, or with its `<parent>`'s
    /// coordinates; Maven reads it as the parent it was fetched as.
    #[test]
    fn a_fetched_parent_may_name_itself_through_its_ancestors() {
        let child = pom(
            "<project><parent><groupId>corp</groupId><artifactId>mid</artifactId>\
             <version>1.0</version></parent><artifactId>child</artifactId></project>",
        );
        let mid = |coordinates: &str| {
            let artifact = match coordinates.contains("<artifactId>") {
                true => "",
                false => "<artifactId>mid</artifactId>",
            };
            pom(&format!(
                "<project><parent><groupId>corp</groupId><artifactId>gp</artifactId>\
                 <version>1.0</version><relativePath/></parent>{coordinates}{artifact}\
                 <properties><id>mid</id></properties></project>"
            ))
        };
        let gp = |revision: &str| {
            pom(&format!(
                "<project><groupId>corp</groupId><artifactId>gp</artifactId>\
                 <version>1.0</version><properties><revision>{revision}</revision>\
                 </properties></project>"
            ))
        };
        let source = |mid: Pom, revision: &str| {
            MemorySource::new()
                .with_parent("corp", "mid", "1.0", mid)
                .with_parent("corp", "gp", "1.0", gp(revision))
        };
        for coordinates in [
            "<version>${revision}</version>",
            "<version>${project.parent.version}</version>",
            "<groupId>${project.parent.groupId}</groupId><version>${parent.version}</version>",
            "<artifactId>${id}</artifactId>",
        ] {
            apply_inheritance(child.clone(), &source(mid(coordinates), "1.0"))
                .unwrap_or_else(|error| panic!("{coordinates}: {error}"));
        }
        // A property named `parent.version` wins over the model field.
        let override_mid = mid("<version>${parent.version}</version>");
        for (user, system, lineage) in [("2.0", "", ""), ("", "2.0", ""), ("", "", "2.0")] {
            let mut ctx = ActivationContext::default();
            for (map, value) in [
                (&mut ctx.properties, user),
                (&mut ctx.system_properties, system),
            ] {
                if !value.is_empty() {
                    map.insert("parent.version".into(), value.into());
                }
            }
            let gp = match lineage.is_empty() {
                true => gp("1.0"),
                false => pom(
                    "<project><groupId>corp</groupId><artifactId>gp</artifactId>\
                     <version>1.0</version><properties><parent.version>2.0</parent.version>\
                     </properties></project>",
                ),
            };
            let source = MemorySource::new()
                .with_parent("corp", "mid", "2.0", override_mid.clone())
                .with_parent("corp", "gp", "1.0", gp);
            let child = pom(
                "<project><parent><groupId>corp</groupId><artifactId>mid</artifactId>\
                 <version>2.0</version></parent><artifactId>child</artifactId></project>",
            );
            crate::ready(apply_inheritance_in_context(
                child,
                &source,
                ModelPolicy::DEPENDENCY,
                ParentLookup::Project,
                Some(&ctx),
            ))
            .unwrap_or_else(|error| panic!("{user}{system}{lineage}: {error}"));
        }
        let error = model_error(apply_inheritance(
            child,
            &source(mid("<version>${revision}</version>"), "2.0"),
        ));
        assert!(
            matches!(error, PomError::ParentCoordMismatch(_)),
            "{error:?}"
        );
    }

    /// A fetched parent without a version of its own takes its parent's as
    /// written, which its own properties expand: a grandparent's
    /// `${revision}` names the parent's revision.
    #[test]
    fn a_fetched_parent_inherits_its_version_as_written() {
        let child = pom(
            "<project><parent><groupId>corp</groupId><artifactId>mid</artifactId>\
             <version>2.0</version></parent><artifactId>child</artifactId></project>",
        );
        let gp = pom(
            "<project><groupId>corp</groupId><artifactId>gp</artifactId>\
             <version>${revision}</version><properties><revision>1.0</revision>\
             </properties></project>",
        );
        for (revision, accepted) in [("2.0", true), ("3.0", false)] {
            let mid = pom(&format!(
                "<project><parent><groupId>corp</groupId><artifactId>gp</artifactId>\
                 <version>1.0</version><relativePath/></parent><artifactId>mid</artifactId>\
                 <properties><revision>{revision}</revision></properties></project>"
            ));
            let source = MemorySource::new()
                .with_parent("corp", "mid", "2.0", mid)
                .with_parent("corp", "gp", "1.0", gp.clone());
            match apply_inheritance(child.clone(), &source) {
                Ok(_) => assert!(accepted, "{revision}"),
                Err(MemorySourceError::Model(PomError::ParentCoordMismatch(_))) => {
                    assert!(!accepted, "{revision}")
                }
                Err(error) => panic!("{revision}: {error}"),
            }
        }
    }

    /// The ancestors' properties expand as in the model: under the user
    /// properties, over the system properties and the environment.
    #[test]
    fn a_fetched_parent_names_itself_through_the_build_inputs() {
        let ctx = ActivationContext {
            environment: crate::ModelEnvironment::builder()
                .platform("linux", "x86_64")
                .jdk_version("21")
                .env("RELEASE_VERSION", Some("1.1"))
                .build(),
            properties: std::collections::HashMap::from([("user.revision".into(), "1.2".into())]),
            system_properties: std::collections::HashMap::from([(
                "system.revision".into(),
                "1.3".into(),
            )]),
            ..ActivationContext::default()
        };
        for (properties, version) in [
            ("<revision>${env.RELEASE_VERSION}</revision>", "1.1"),
            (
                "<user.revision>0</user.revision><revision>${user.revision}</revision>",
                "1.2",
            ),
            ("<revision>${system.revision}</revision>", "1.3"),
            ("<revision>${java.version}</revision>", "21"),
            ("<revision>1-${os.arch}</revision>", "1-amd64"),
        ] {
            let child = pom(&format!(
                "<project><parent><groupId>corp</groupId><artifactId>mid</artifactId>\
                 <version>{version}</version></parent><artifactId>child</artifactId></project>"
            ));
            let mid = pom(
                "<project><parent><groupId>corp</groupId><artifactId>gp</artifactId>\
                 <version>1.0</version><relativePath/></parent><version>${revision}</version>\
                 <artifactId>mid</artifactId></project>",
            );
            let gp = pom(&format!(
                "<project><groupId>corp</groupId><artifactId>gp</artifactId>\
                 <version>1.0</version><properties>{properties}</properties></project>"
            ));
            let source = MemorySource::new()
                .with_parent("corp", "mid", version, mid)
                .with_parent("corp", "gp", "1.0", gp);
            crate::ready(apply_inheritance_in_context(
                child,
                &source,
                ModelPolicy::DEPENDENCY,
                ParentLookup::Project,
                Some(&ctx),
            ))
            .unwrap_or_else(|error| panic!("{properties}: {error}"));
        }
    }

    /// [`MAX_PARENT_CHAIN_DEPTH`] is the boundary every parent-chain traversal
    /// shares (notably `rv_resolver::accepted_local_parents`, which feeds the
    /// lockfile model hash). Inheritance must therefore accept a chain of
    /// exactly that many parents and reject one hop more, rather than
    /// resolving past the depth the other walks stop at.
    #[test]
    fn parent_chain_limit_is_the_shared_boundary() {
        let chain = |length: usize| {
            (1..=length).fold(MemorySource::new(), |source, index| {
                let parent = if index < length {
                    format!("p{}", index + 1)
                } else {
                    String::new()
                };
                let pom = pom_of(&format!("p{index}"), &parent, "");
                source.with_parent("g", &format!("p{index}"), "1", pom)
            })
        };
        apply_inheritance(pom_of("child", "p1", ""), &chain(MAX_PARENT_CHAIN_DEPTH))
            .expect("a chain at the limit resolves");
        let error = apply_inheritance(
            pom_of("child", "p1", ""),
            &chain(MAX_PARENT_CHAIN_DEPTH + 1),
        )
        .expect_err("a chain past the limit must be rejected");
        assert!(
            error.to_string().contains("parent chain exceeds the limit"),
            "unexpected error: {error}"
        );
    }
}
