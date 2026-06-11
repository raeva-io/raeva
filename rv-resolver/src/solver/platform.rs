use std::borrow::Cow;
use std::collections::HashMap;

use rv_maven_model::{Dependency, Exclusion};

use crate::error::{ResolveError, Result};

pub(crate) struct AppliedConstraint {
    pub version: String,
    pub strict: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ConstraintVersion {
    pub requires: Option<String>,
    pub strictly: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PlatformConstraint {
    pub group: String,
    pub module: String,
    /// Maven dependency-management key includes the effective type; defaults to
    /// "jar" so a managed `test-jar` (effective type still `jar`, classifier
    /// `tests`) does not collide with a plain `jar` dep at the same coordinate.
    pub type_: String,
    /// Effective classifier (normalized to `None` when empty). Combined with
    /// `type_` to disambiguate managed entries for the same `(group, module)`.
    pub classifier: Option<String>,
    pub version: ConstraintVersion,
    pub enforced: bool,
    /// Managed `<scope>`: overrides a transitive dependency's declared scope
    /// (Maven's ClassicDependencyManager, applied from depth >= 2).
    pub scope: Option<String>,
    /// Managed `<optional>`: overrides a transitive dependency's declared flag.
    pub optional: Option<String>,
    /// Managed `<exclusions>`: unioned with a transitive dependency's own
    /// exclusions, pruning the subtree below it. This is the canonical
    /// "globally exclude commons-logging via dependencyManagement" pattern.
    pub exclusions: Vec<Exclusion>,
}

/// Key used to look up a constraint in O(1). Maven dep-mgmt is keyed by
/// `(group, module, type, classifier)`.
type ConstraintKey = (String, String, String, Option<String>);

#[derive(Debug, Clone, Default)]
pub(crate) struct PlatformConstraints {
    constraints: Vec<PlatformConstraint>,
    /// Secondary index keyed by `(group, module, type, classifier)` mapped to
    /// the position in `constraints`. The Vec keeps insertion order (and the
    /// `all()` iteration contract); the map makes apply_constraint O(1) per
    /// dep instead of O(N).
    index: HashMap<ConstraintKey, usize>,
}

impl PlatformConstraints {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add_constraint(&mut self, constraint: PlatformConstraint) {
        let key = (
            constraint.group.clone(),
            constraint.module.clone(),
            constraint.type_.clone(),
            constraint.classifier.clone(),
        );
        // Mirror the linear-scan behaviour of `find`: the first inserted
        // constraint wins. If a duplicate is added we keep the index pointing
        // at the original and still push the new one to preserve `all()`'s
        // iteration order for callers that walk every constraint.
        let idx = self.constraints.len();
        self.constraints.push(constraint);
        self.index.entry(key).or_insert(idx);
    }

    pub(crate) fn all(&self) -> impl Iterator<Item = &PlatformConstraint> {
        self.constraints.iter()
    }

    pub(crate) fn apply_constraint(
        &self,
        group_id: &str,
        artifact_id: &str,
        type_: &str,
        classifier: Option<&str>,
        version_hint: Option<&str>,
    ) -> Option<AppliedConstraint> {
        // The HashMap key owns its strings; build temporaries here. The hot
        // path is per-dependency, so the allocation cost is dwarfed by the
        // O(1) lookup it enables over a linear scan of all dep-mgmt entries.
        let key: ConstraintKey = (
            group_id.to_string(),
            artifact_id.to_string(),
            type_.to_string(),
            classifier.map(str::to_string),
        );
        let idx = *self.index.get(&key)?;
        let constraint = &self.constraints[idx];

        let version = constraint
            .version
            .strictly
            .as_ref()
            .or(constraint.version.requires.as_ref())?;

        if constraint.enforced {
            return Some(AppliedConstraint {
                version: version.clone(),
                strict: true,
            });
        }

        if version_hint.is_none() {
            return Some(AppliedConstraint {
                version: version.clone(),
                strict: false,
            });
        }

        None
    }

    /// Look up the managed entry for a coordinate to read its non-version
    /// metadata (scope/optional/exclusions). Unlike `apply_constraint`, this
    /// also matches entries that manage no version at all (a depMgmt entry
    /// with only `<exclusions>` is valid and common).
    pub(crate) fn managed(
        &self,
        group_id: &str,
        artifact_id: &str,
        type_: &str,
        classifier: Option<&str>,
    ) -> Option<&PlatformConstraint> {
        let key: ConstraintKey = (
            group_id.to_string(),
            artifact_id.to_string(),
            type_.to_string(),
            classifier.map(str::to_string),
        );
        self.index.get(&key).map(|idx| &self.constraints[*idx])
    }
}

pub(crate) fn resolve_version_str<'a>(
    constraints: &PlatformConstraints,
    dependency: &'a Dependency,
    depth: usize,
) -> Result<Cow<'a, str>> {
    // Maven semantics: for the project's own dependencies (depth <= 1),
    // <dependencyManagement> only fills in a MISSING version. A declared
    // version always wins, whether it is a soft pin (`<version>1.0</version>`),
    // a range, or a bracketed hard pin — declaring a direct dependency with a
    // version is exactly how Maven users override an imported BOM. Only an
    // `enforced` platform (Gradle enforcedPlatform semantics, never produced
    // from a pom.xml) may replace a declared version. Transitive dependencies
    // (depth > 1) are managed: the root's dep-mgmt overrides their declared
    // versions, matching Maven's ClassicDependencyManager which applies
    // management from depth >= 2.
    let version_hint = if depth > 1 {
        None
    } else {
        dependency.version.as_deref()
    };

    if let Some(applied) = constraints.apply_constraint(
        &dependency.group_id,
        &dependency.artifact_id,
        dependency.effective_type(),
        dependency.effective_classifier(),
        version_hint,
    ) {
        tracing::debug!(
            group_id = %dependency.group_id,
            artifact_id = %dependency.artifact_id,
            constraint_version = %applied.version,
            enforced = applied.strict,
            depth,
            "Applied platform constraint"
        );
        return Ok(Cow::Owned(applied.version));
    }

    let version = dependency
        .version
        .as_deref()
        .ok_or_else(|| ResolveError::MissingVersion {
            group_id: dependency.group_id.clone(),
            artifact_id: dependency.artifact_id.clone(),
        })?;
    Ok(Cow::Borrowed(version))
}

pub(crate) fn merge_platform_constraints(
    target: &mut PlatformConstraints,
    extra: Option<&PlatformConstraints>,
) {
    if let Some(extra_constraints) = extra {
        for constraint in extra_constraints.all() {
            target.add_constraint(constraint.clone());
        }
    }
}
