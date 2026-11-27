use crate::dependency::{Dependency, DependencyManagement, Exclusion};
use crate::properties::{ProjectInfo, PropertyMap};
use crate::{HostInput, PomError};
use rv_maven_types::bounded;
use std::collections::hash_map;

/// `management` interpolated, and validated when `validate`: an inactive
/// profile's copy is not, as Maven validates the effective model only.
pub(super) fn resolve_dependency_management(
    management: DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
    validate: bool,
) -> Result<DependencyManagement, PomError> {
    let dependencies = management
        .dependencies
        .into_iter()
        .map(|dep| match validate {
            true => resolve_dependency(dep, properties, project),
            false => interpolate_dependency(dep, properties, project, None),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DependencyManagement { dependencies })
}

/// The dependencies of a model, managed and interpolated. A host value
/// that only the version or the exclusions of a dependency read counts as
/// read only when resolution can follow that dependency: always for a
/// project's own, and for a dependency's POM, when
/// [`Dependency::is_followed_transitively`] says so. The others never reach
/// the resolution, except an environment variable in a version, which can
/// make the POM invalid. With `transitive`, the versions and exclusions are
/// read through a detached environment, and what they read passes to
/// `project` only for a dependency resolution follows.
pub(super) fn resolve_dependencies(
    deps: Vec<Dependency>,
    management: &DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
    transitive: bool,
) -> Result<Vec<Dependency>, PomError> {
    if deps.is_empty() {
        return Ok(Vec::new());
    }
    let index = build_managed_dep_index(management);
    let deferred = transitive.then(|| ProjectInfo {
        environment: project.environment.detached(),
        ..project.clone()
    });
    let mut resolved = Vec::with_capacity(deps.len());
    for dep in deps {
        let mut dep = interpolate_declared(dep, properties, project, deferred.as_ref())?;
        if let Some(version) = &mut dep.version {
            // Maven requests the version as written, which then matches no
            // artifact, but its range parser trims after a closing bracket.
            // A dependency's POM keeps the trimmed version: refusing it would
            // drop its other dependencies, test ones included.
            let java_space = |c: char| c <= ' ';
            let trimmed = version.trim_matches(java_space);
            if !transitive
                && !trimmed.is_empty()
                && (version.starts_with(java_space)
                    || (version.ends_with(java_space) && !trimmed.starts_with(['[', '('])))
            {
                return Err(PomError::InvalidProject(dep.problem(
                    "dependencies.dependency.version",
                    "has whitespace around it, which Maven keeps in the version it requests, so \
                     no artifact matches it",
                )));
            }
            crate::pom::trim_str(version);
        }
        if let Some(managed) = find_managed_dependency_indexed(&dep, &index) {
            apply_managed_dependency(&mut dep, managed);
        }
        if let Some(deferred) = &deferred {
            let reads = deferred.environment.take_reads();
            if dep.is_followed_transitively() {
                for input in reads {
                    project.environment.record(input);
                }
            }
        }
        dep.validate_coordinates(false)?;
        dep.validate_system_scope(&project.environment)?;
        // Maven keeps a scope it does not know as written; the resolver
        // refuses one of a dependency's POM that the lock cannot record.
        if !transitive && !dep.effective_scope().recordable() {
            return Err(PomError::InvalidProject(dep.problem(
                "dependencies.dependency.scope",
                "is a scope Maven does not know, which raeva.lock can record only as 1 to 255 \
                 characters without control or invisible characters; write a scope Maven knows",
            )));
        }
        if !transitive {
            warn_unknown_scope(&dep, project.environment.maven_mode(), false);
        }
        resolved.push(dep);
    }
    // Maven validates the version after this model's own management, for a
    // dependency's POM too: no outer management supplies one there.
    if let Some(dep) = resolved
        .iter()
        .find(|dep| dep.version.as_deref().is_none_or(str::is_empty))
    {
        return Err(match transitive {
            true => dep.missing(false, "version"),
            false => {
                PomError::InvalidProject(dep.missing_message("dependencies.dependency.version"))
            }
        });
    }
    // Maven's project validation only warns of an incomplete exclusion,
    // which excludes nothing.
    if !transitive {
        for dep in &resolved {
            for exclusion in &dep.exclusions {
                let field = if exclusion.group_id.is_empty() {
                    "groupId"
                } else if exclusion.artifact_id.is_empty() {
                    "artifactId"
                } else {
                    continue;
                };
                let (group_id, artifact_id, type_, _) = dep.management_key();
                tracing::warn!(
                    sec_code = "POM_PROBLEM",
                    "'dependencies.dependency.exclusions.exclusion.{field}' for {}:{}:{} is missing",
                    bounded(group_id),
                    bounded(artifact_id),
                    bounded(type_)
                );
            }
        }
    }
    Ok(resolved)
}

/// Warn, in Maven's words, of the scope of a project dependency, or of a
/// `management` entry, that Maven's validator does not know, which Maven
/// builds with.
pub(super) fn warn_unknown_scope(
    dep: &Dependency,
    mode: rv_maven_types::MavenMode,
    management: bool,
) {
    let Some(scope) = dep.scope.as_deref().filter(|scope| !scope.is_empty()) else {
        return;
    };
    let mut known = vec!["provided", "compile"];
    if mode == rv_maven_types::MavenMode::Maven310 {
        known.push("compile-only");
    }
    known.extend(["runtime", "test", "system"]);
    let field = if management {
        known.push("import");
        "dependencyManagement.dependencies.dependency.scope"
    } else {
        "dependencies.dependency.scope"
    };
    if known.contains(&scope) {
        return;
    }
    tracing::warn!(
        sec_code = "POM_PROBLEM",
        "{}",
        dep.problem(
            field,
            &format!(
                "must be one of [{}] but is '{}'",
                known.join(", "),
                bounded(scope)
            ),
        )
    );
}

/// Maven's validation of `deps`, the dependencies of a model whose
/// management alone is used, as an imported BOM's: managed by
/// `management`, they need their coordinates and a version.
pub(super) fn validate_dependencies(
    deps: &[Dependency],
    management: &DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<(), PomError> {
    resolve_dependencies(deps.to_vec(), management, properties, project, true).map(drop)
}

pub(super) fn resolve_dependency(
    dep: Dependency,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Dependency, PomError> {
    let resolved = interpolate_dependency(dep, properties, project, None)?;
    resolved.validate_coordinates(true)?;
    // Validate `<systemPath>` after interpolation so exporters cannot emit invalid entries.
    resolved.validate_system_scope(&project.environment)?;
    Ok(resolved)
}

/// `dep` interpolated, its version and exclusions through `deferred` when
/// given.
pub(crate) fn interpolate_dependency(
    dep: Dependency,
    properties: &PropertyMap,
    project: &ProjectInfo,
    deferred: Option<&ProjectInfo>,
) -> Result<Dependency, PomError> {
    let mut dep = interpolate_declared(dep, properties, project, deferred)?;
    if let Some(version) = &mut dep.version {
        crate::pom::trim_str(version);
    }
    Ok(dep)
}

/// [`interpolate_dependency`] with the version as interpolated: the POM's
/// text is trimmed when it is read, so whitespace around it came from a
/// host value or another property.
fn interpolate_declared(
    dep: Dependency,
    properties: &PropertyMap,
    project: &ProjectInfo,
    deferred: Option<&ProjectInfo>,
) -> Result<Dependency, PomError> {
    let version =
        properties.interpolate_opt(dep.version.as_deref(), deferred.unwrap_or(project))?;
    // An environment variable may be empty, which leaves the version missing
    // and a dependency's POM invalid, so it counts whether or not
    // resolution follows the dependency. No other host value is empty.
    if let Some(deferred) = deferred {
        for input in deferred.environment.take_reads() {
            match input {
                HostInput::Env(_) => project.environment.record(input),
                _ => deferred.environment.record(input),
            }
        }
    }
    let deferred = deferred.unwrap_or(project);
    refuse_secret_coordinate(&dep, properties, project, deferred)?;
    // Trim whitespace from the ids to match Maven's lenient parsing. Some
    // POMs have stray whitespace in <groupId> or <artifactId> (e.g. Quarkus
    // `<groupId> jakarta.servlet</groupId>`).
    let trim_string = |s: String| {
        let trimmed = s.trim();
        if trimmed.len() == s.len() {
            s
        } else {
            trimmed.to_string()
        }
    };
    let group_id = trim_string(properties.interpolate_str(&dep.group_id, project)?);
    let artifact_id = trim_string(properties.interpolate_str(&dep.artifact_id, project)?);
    let type_ = properties.interpolate_opt(dep.type_.as_deref(), project)?;
    let classifier = properties.interpolate_opt(dep.classifier.as_deref(), project)?;
    let scope = properties.interpolate_opt(dep.scope.as_deref(), project)?;
    let optional = properties.interpolate_opt(dep.optional.as_deref(), project)?;
    let exclusions = (dep.exclusions.into_iter())
        .map(|e| resolve_exclusion(e, properties, deferred))
        .collect::<Result<Vec<_>, _>>()?;
    let (system_path, from_project) = match dep.system_path.as_deref() {
        Some(path) => {
            let (path, from_project) = properties.interpolate_from_project(path, project)?;
            (Some(path), from_project)
        }
        None => (None, false),
    };
    Ok(Dependency {
        group_id,
        artifact_id,
        version,
        type_,
        classifier,
        scope,
        optional,
        exclusions,
        system_path,
        system_path_from_project: crate::ProjectDirectory(from_project),
        origin: dep.origin,
    })
}

/// Refuse `dep` when one of its coordinates reads a host input named like a
/// secret ([`crate::HostSnapshot::with_secret_names`]), whose value raeva.lock
/// and a repository request would take, its version and exclusions as
/// `deferred` reads them.
fn refuse_secret_coordinate(
    dep: &Dependency,
    properties: &PropertyMap,
    project: &ProjectInfo,
    deferred: &ProjectInfo,
) -> Result<(), PomError> {
    let exclusions = (dep.exclusions.iter())
        .flat_map(|e| [("exclusion", &e.group_id), ("exclusion", &e.artifact_id)])
        .map(|(field, text)| (field, Some(text.as_str()), deferred));
    let fields = [
        ("groupId", Some(dep.group_id.as_str()), project),
        ("artifactId", Some(dep.artifact_id.as_str()), project),
        ("version", dep.version.as_deref(), deferred),
        ("type", dep.type_.as_deref(), project),
        ("classifier", dep.classifier.as_deref(), project),
        ("scope", dep.scope.as_deref(), project),
    ];
    let of = || {
        let version = dep.version.as_deref().unwrap_or_default();
        format!("dependency {}:{}:{version}", dep.group_id, dep.artifact_id)
    };
    refuse_secret_coordinates(properties, fields.into_iter().chain(exclusions), of)
}

/// Refuse the coordinates `fields`, each a field name, its text as written
/// and the project that reads it, when one reads a host input named like a
/// secret ([`crate::HostSnapshot::with_secret_names`]), whose value
/// raeva.lock and a repository request would take. `of` names whose they
/// are.
pub(crate) fn refuse_secret_coordinates<'a>(
    properties: &PropertyMap,
    fields: impl IntoIterator<Item = (&'static str, Option<&'a str>, &'a ProjectInfo)>,
    of: impl FnOnce() -> String,
) -> Result<(), PomError> {
    for (field, text, project) in fields {
        if !project.environment.reads_secrets() {
            continue;
        }
        let Some(text) = text.filter(|text| text.contains("${")) else {
            continue;
        };
        let Ok((_, names)) = properties.interpolate_str_reading(text, project) else {
            continue;
        };
        if let Some(input) = project.environment.secret_input(&names) {
            let of = of();
            return Err(PomError::SecretCoordinate { field, of, input });
        }
    }
    Ok(())
}

fn resolve_exclusion(
    exclusion: Exclusion,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Exclusion, PomError> {
    Ok(Exclusion {
        group_id: properties.interpolate_str(&exclusion.group_id, project)?,
        artifact_id: properties.interpolate_str(&exclusion.artifact_id, project)?,
    })
}

/// Key for managed dependency lookup: (groupId, artifactId, effective_type, normalized_classifier)
type ManagedDepKey<'a> = (&'a str, &'a str, &'a str, Option<&'a str>);

/// Dependency management indexed by (groupId, artifactId, type, classifier).
/// Entries whose keys collide only after interpolation (a parent's
/// `${lib.name}` and a child's `foo`) merge as Maven's
/// DefaultDependencyManagementInjector applies them in turn: each field
/// comes from the first entry that sets it, and the exclusions from the
/// first entry that has any.
pub(super) struct ManagedIndex<'a> {
    index: foldhash::HashMap<ManagedDepKey<'a>, Slot<'a>>,
    merged: Vec<Dependency>,
}

#[derive(Clone, Copy)]
enum Slot<'a> {
    Entry(&'a Dependency),
    Merged(usize),
}

pub(super) fn build_managed_dep_index(management: &DependencyManagement) -> ManagedIndex<'_> {
    let mut index = foldhash::HashMap::with_capacity_and_hasher(
        management.dependencies.len(),
        Default::default(),
    );
    let mut merged = Vec::new();
    for dep in &management.dependencies {
        match index.entry(dep.maven_key()) {
            hash_map::Entry::Vacant(slot) => {
                slot.insert(Slot::Entry(dep));
            }
            hash_map::Entry::Occupied(mut slot) => {
                let at = match *slot.get() {
                    Slot::Merged(at) => at,
                    Slot::Entry(first) => {
                        merged.push(first.clone());
                        slot.insert(Slot::Merged(merged.len() - 1));
                        merged.len() - 1
                    }
                };
                apply_managed_dependency(&mut merged[at], dep);
            }
        }
    }
    ManagedIndex { index, merged }
}

pub(super) fn find_managed_dependency_indexed<'i>(
    dep: &Dependency,
    index: &'i ManagedIndex<'_>,
) -> Option<&'i Dependency> {
    match *index.index.get(&dep.maven_key())? {
        Slot::Entry(managed) => Some(managed),
        Slot::Merged(at) => Some(&index.merged[at]),
    }
}

pub(super) fn apply_managed_dependency(dep: &mut Dependency, managed: &Dependency) {
    // The origin follows the version it names.
    if dep.version.is_none() && managed.version.is_some() {
        dep.version.clone_from(&managed.version);
        dep.origin.clone_from(&managed.origin);
    }
    // Maven semantics: dependency-management `scope` is a fill-in only. A
    // declared scope on the concrete dependency wins; the managed entry's
    // scope applies ONLY when the concrete dependency has no scope of its
    // own. Mirrors managed `version` behaviour (fills in a missing concrete
    // version, never overrides a declared one).
    if dep.scope.is_none() && managed.scope.is_some() {
        dep.scope.clone_from(&managed.scope);
    }
    // Maven manages version, scope, type, classifier, and exclusions, but not `<optional>`.
    if dep.type_.is_none() {
        dep.type_.clone_from(&managed.type_);
    }
    if dep.classifier.is_none() {
        dep.classifier.clone_from(&managed.classifier);
    }
    // Maven's model merger fills a missing `<systemPath>` from dependencyManagement.
    if dep.system_path.is_none() {
        dep.system_path.clone_from(&managed.system_path);
        dep.system_path_from_project = managed.system_path_from_project;
    }
    // Maven 3.9's DefaultDependencyManagementInjector copies the managed
    // exclusions only onto a dependency that declares none. The resolver
    // adds the root project's managed exclusions to every dependency.
    if dep.exclusions.is_empty() {
        dep.exclusions.clone_from(&managed.exclusions);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Management only fills in: a declared version, scope or exclusion list
    /// wins.
    #[test]
    fn managed_fields_only_fill_in_a_declaration() {
        let dep = |version: Option<&str>, scope: Option<&str>, excluded: &[&str]| Dependency {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: version.map(str::to_string),
            type_: None,
            classifier: None,
            scope: scope.map(str::to_string),
            optional: None,
            exclusions: excluded
                .iter()
                .map(|group| Exclusion {
                    group_id: group.to_string(),
                    artifact_id: "lib".to_string(),
                })
                .collect(),
            system_path: None,
            system_path_from_project: Default::default(),
            origin: Default::default(),
        };
        for (declared, managed, expected) in [
            (
                dep(Some("1"), Some("compile"), &[]),
                dep(Some("2"), Some("runtime"), &[]),
                dep(Some("1"), Some("compile"), &[]),
            ),
            (
                dep(None, None, &[]),
                dep(Some("2"), Some("runtime"), &["x"]),
                dep(Some("2"), Some("runtime"), &["x"]),
            ),
            (
                dep(Some("1"), Some("test"), &["own"]),
                dep(None, None, &["managed", "own"]),
                dep(Some("1"), Some("test"), &["own"]),
            ),
        ] {
            let mut concrete = declared;
            apply_managed_dependency(&mut concrete, &managed);
            assert_eq!(concrete, expected);
        }
    }
}
