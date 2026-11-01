use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use indexmap::IndexMap;

use crate::pom::Build;
use crate::{ActivationContext, HostInput, ModelEnvironment, PomError, PropertySource};

/// Where a name missing from the property map is looked up.
#[derive(Clone, Copy)]
struct Lookup<'a> {
    project: Option<&'a ProjectInfo>,
    system_properties: Option<&'a HashMap<String, String>>,
    environment: Option<&'a ModelEnvironment>,
    /// Model interpolation, which also reads `${NAME}` as `${env.NAME}`, and
    /// `${java.version}` by the model rule.
    model: bool,
}

impl<'a> Lookup<'a> {
    fn new(
        project: Option<&'a ProjectInfo>,
        system_properties: Option<&'a HashMap<String, String>>,
        environment: Option<&'a ModelEnvironment>,
        model: bool,
    ) -> Self {
        Self {
            project,
            system_properties,
            environment,
            model,
        }
    }

    fn environment(&self) -> Option<&ModelEnvironment> {
        self.environment
            .or(self.project.map(|project| &project.environment))
    }
}

/// Maven properties by name, in insertion order, and the `${...}`
/// interpolation over them. A later insert of a name replaces its value and
/// keeps its position.
///
/// All interpolations over one map share a budget for what they expand,
/// sized for one model; build a map, or clone one, per model.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(transparent)]
pub struct PropertyMap {
    props: IndexMap<String, String>,
    #[serde(skip)]
    inputs: Option<Box<PropertyInputs>>,
    #[serde(skip)]
    expanded: Expanded,
}

/// The bytes a map's interpolations expanded, against
/// [`PropertyMap::MAX_EXPANDED_LENGTH`]. A copy starts again from zero.
#[derive(Debug, Default)]
struct Expanded(AtomicUsize);

impl Clone for Expanded {
    fn clone(&self) -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default)]
struct PropertyInputs {
    external: BTreeSet<String>,
    below_system: BTreeSet<String>,
    source: PropertySource,
    default_packaging: Option<String>,
}

impl PartialEq for PropertyMap {
    fn eq(&self, other: &Self) -> bool {
        self.props == other.props
    }
}
impl Eq for PropertyMap {}

/// The state of one interpolation: the properties being expanded,
/// outermost first, and the value of each property expanded so far. The
/// values are reused, so a POM that references one property many times over
/// many levels costs one expansion per property, not one per reference.
#[derive(Default)]
struct Walk {
    path: Vec<String>,
    resolved: HashMap<String, (String, bool)>,
    /// The value of each `<build>` field expanded so far, by name.
    build: HashMap<String, String>,
    /// The bytes `resolved` and `build` hold, against
    /// [`PropertyMap::MAX_RESOLVED_LENGTH`].
    resolved_len: usize,
    /// The property names looked up, when the caller asks for them.
    names: Option<std::collections::BTreeSet<String>>,
    public_names: Option<BTreeSet<String>>,
    external_depth: usize,
    external_values: usize,
    private_key: bool,
    private_names: bool,
    private_host: bool,
    /// The parent fields looked up that a system property would replace.
    below_system: BTreeSet<String>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub(crate) struct ParentInfo {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}

/// Public model fields needed to replay an interpolation without storing external values.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct ModelLookup {
    group_id: String,
    artifact_id: String,
    version: String,
    packaging: String,
    parent: Option<ParentInfo>,
    build: Box<Build>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prerequisites_maven: Option<String>,
    /// The local POM directory, normalized relative to the project root on disk.
    pub base_dir: Option<PathBuf>,
}

impl ModelLookup {
    pub(crate) fn new(pom: &crate::Pom, base_dir: Option<PathBuf>) -> Self {
        Self {
            group_id: pom
                .group_id
                .clone()
                .or_else(|| pom.parent.as_ref().map(|p| p.group_id.clone()))
                .unwrap_or_default(),
            artifact_id: pom.artifact_id.clone().unwrap_or_default(),
            version: pom
                .version
                .clone()
                .or_else(|| pom.parent.as_ref().map(|p| p.version.clone()))
                .unwrap_or_default(),
            packaging: pom.packaging.clone().unwrap_or_else(|| "jar".into()),
            parent: pom.parent.as_ref().map(|p| ParentInfo {
                group_id: p.group_id.clone(),
                artifact_id: p.artifact_id.clone(),
                version: p.version.clone(),
            }),
            build: pom.build.clone(),
            prerequisites_maven: (pom.prerequisites.as_ref())
                .and_then(|prerequisites| prerequisites.maven.clone()),
            base_dir,
        }
    }

    /// Keep the expanded value of a coordinate whose text names itself: the
    /// property behind it is not among those a lookup record keeps.
    pub(crate) fn keep_coordinate(&mut self, field: &str, value: &str) {
        match field {
            "groupId" => self.group_id = value.to_string(),
            "artifactId" => self.artifact_id = value.to_string(),
            "version" => self.version = value.to_string(),
            _ => {}
        }
    }

    /// Replay model interpolation with the current external input context.
    pub fn interpolate(
        &self,
        input: &str,
        properties: &PropertyMap,
        ctx: &ActivationContext,
    ) -> (Result<String, PomError>, BTreeSet<String>) {
        let pom = crate::Pom {
            group_id: Some(self.group_id.clone()),
            artifact_id: Some(self.artifact_id.clone()),
            version: Some(self.version.clone()),
            packaging: Some(self.packaging.clone()),
            parent: self.parent.as_ref().map(|p| crate::Parent {
                group_id: p.group_id.clone(),
                artifact_id: p.artifact_id.clone(),
                version: p.version.clone(),
                relative_path: None,
            }),
            build: self.build.clone(),
            prerequisites: (self.prerequisites_maven.clone())
                .map(|maven| crate::pom::Prerequisites { maven: Some(maven) }),
            ..crate::Pom::default()
        };
        let project = match crate::model::project_info(&pom, properties, ctx) {
            Ok(project) => project,
            Err(error) => return (Err(error), BTreeSet::new()),
        };
        properties.interpolate_names(input, Lookup::new(Some(&project), None, None, true), false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectInfo {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub packaging: String,
    pub parent: Option<ParentInfo>,
    pub basedir: Option<PathBuf>,
    /// The effective `<build>` values, not interpolated.
    pub build: Build,
    /// The `os.*` system properties of the platform being resolved for. They
    /// rank below the model's own properties, as in Maven.
    pub system_properties: HashMap<String, String>,
    pub environment: ModelEnvironment,
    pub model_lookup: Option<Box<ModelLookup>>,
}

impl PropertyMap {
    /// An empty map.
    pub fn new() -> Self {
        Self {
            props: IndexMap::new(),
            ..Self::default()
        }
    }

    /// Set `key` to `value`.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        if let Some(inputs) = &mut self.inputs {
            inputs.external.remove(&key);
            inputs.below_system.remove(&key);
        }
        self.props.insert(key, value.into());
    }

    /// Insert a value supplied outside the POM, retaining its interpolation provenance.
    pub fn insert_external(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        self.inputs
            .get_or_insert_default()
            .external
            .insert(key.clone());
        self.props.insert(key, value.into());
    }

    /// Set `key` to a value a system property of the same name would
    /// replace.
    pub(crate) fn insert_below_system(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        self.inputs
            .get_or_insert_default()
            .below_system
            .insert(key.clone());
        self.props.insert(key, value.into());
    }

    pub(crate) fn set_input_context(&mut self, ctx: &ActivationContext) {
        let inputs = self.inputs.get_or_insert_default();
        inputs.source = ctx.property_source;
        inputs.default_packaging = ctx.default_packaging.clone();
    }

    /// The value of `key`, not interpolated.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.props.get(key)
    }

    /// Whether an entry came from external configuration rather than the POM.
    pub fn is_external(&self, key: &str) -> bool {
        self.inputs
            .as_ref()
            .is_some_and(|inputs| inputs.external.contains(key))
    }

    fn is_below_system(&self, key: &str) -> bool {
        (self.inputs.as_ref()).is_some_and(|inputs| inputs.below_system.contains(key))
    }

    /// Whether the map has no entries.
    pub fn is_empty(&self) -> bool {
        self.props.is_empty()
    }

    /// Mutable references to the values, in insertion order.
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut String> {
        self.props.values_mut()
    }

    /// The entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.props.iter()
    }

    /// Insert every entry of `other`, whose values win.
    pub fn extend(&mut self, other: &PropertyMap) {
        if let Some(inputs) = &mut self.inputs {
            inputs
                .external
                .retain(|name| !other.props.contains_key(name));
            (inputs.below_system).retain(|name| !other.props.contains_key(name));
        }
        if let Some(inputs) = &other.inputs
            && !inputs.external.is_empty()
        {
            self.inputs
                .get_or_insert_default()
                .external
                .extend(inputs.external.iter().cloned());
        }
        for (key, value) in &other.props {
            self.props.insert(key.clone(), value.clone());
        }
    }

    pub(crate) fn interpolate_str(
        &self,
        input: &str,
        project: &ProjectInfo,
    ) -> Result<String, PomError> {
        self.interpolate_str_with(input, Lookup::new(Some(project), None, None, true))
    }

    /// Interpolate `${...}` references in `input` using only the entries in this
    /// map. No `${project.*}`, system property or environment variable is
    /// substituted.
    pub fn interpolate_str_no_project(&self, input: &str) -> Result<String, PomError> {
        self.interpolate_str_with(input, Lookup::new(None, None, None, false))
    }

    /// Like [`Self::interpolate_str_no_project`], with `system_properties`,
    /// the platform being resolved for, and `environment` below this map's
    /// entries, as a model interpolates them.
    pub(crate) fn interpolate_str_with_system_properties(
        &self,
        input: &str,
        system_properties: &HashMap<String, String>,
        environment: &ModelEnvironment,
    ) -> Result<String, PomError> {
        let lookup = Lookup::new(None, Some(system_properties), Some(environment), true);
        self.interpolate_str_with(input, lookup)
    }

    /// Interpolate `${...}` references with this map's entries, then the
    /// `java.version` system property and allowlisted `${env.NAME}` of
    /// `environment`, as Maven interpolates profile activations and
    /// command-line values: a name is looked up exactly, with no `${NAME}`
    /// read as `${env.NAME}`. Callers put the platform's `os.*` system
    /// properties into the map themselves, below their own entries.
    pub fn interpolate_str_exact(
        &self,
        input: &str,
        environment: &ModelEnvironment,
    ) -> Result<String, PomError> {
        self.interpolate_str_with(input, Lookup::new(None, None, Some(environment), false))
    }

    /// [`Self::interpolate_str_exact`], with authored property names, including absent reads.
    /// Names introduced by external expressions stay inside an aggregate-hash recipe.
    pub fn interpolate_str_exact_names(
        &self,
        input: &str,
        environment: &ModelEnvironment,
    ) -> (Result<String, PomError>, std::collections::BTreeSet<String>) {
        self.interpolate_names(
            input,
            Lookup::new(None, None, Some(environment), false),
            true,
        )
    }

    /// Interpolate for aggregate-hash replay, retaining private read names only in memory.
    pub fn replay_exact_names(
        &self,
        input: &str,
        environment: &ModelEnvironment,
    ) -> (Result<String, PomError>, BTreeSet<String>) {
        self.interpolate_names(
            input,
            Lookup::new(None, None, Some(environment), false),
            false,
        )
    }

    /// Replay model interpolation that does not have model fields in scope.
    pub fn replay_model_names(
        &self,
        input: &str,
        ctx: &ActivationContext,
    ) -> (Result<String, PomError>, BTreeSet<String>) {
        let system = ctx.interpolation_system_properties();
        let environment = ctx.model_environment();
        self.interpolate_names(
            input,
            Lookup::new(None, Some(&system), Some(&environment), true),
            false,
        )
    }

    fn interpolate_names(
        &self,
        input: &str,
        lookup: Lookup<'_>,
        public_only: bool,
    ) -> (Result<String, PomError>, BTreeSet<String>) {
        let mut walk = Walk {
            names: Some(BTreeSet::new()),
            public_names: Some(BTreeSet::new()),
            ..Walk::default()
        };
        let result = self.expand(input, lookup, &mut walk);
        self.record_private_reads(input, lookup, &walk);
        (
            result,
            if public_only {
                walk.public_names.unwrap_or_default()
            } else {
                walk.names.unwrap_or_default()
            },
        )
    }

    pub(crate) fn interpolate_opt(
        &self,
        input: Option<&str>,
        project: &ProjectInfo,
    ) -> Result<Option<String>, PomError> {
        input.map(|s| self.interpolate_str(s, project)).transpose()
    }

    fn interpolate_str_with(&self, input: &str, lookup: Lookup<'_>) -> Result<String, PomError> {
        if input.len() <= Self::MAX_INTERPOLATION_LENGTH && !input.contains("${") {
            return Ok(input.to_owned());
        }
        let mut walk = Walk::default();
        let result = self.expand(input, lookup, &mut walk);
        self.record_private_reads(input, lookup, &walk);
        result
    }

    fn record_private_reads(&self, input: &str, lookup: Lookup<'_>, walk: &Walk) {
        // A parent field has a public name however its key was formed, and a
        // lookup record replays its value ahead of the system properties.
        if lookup.model
            && let Some(environment) = lookup.environment()
        {
            for name in &walk.below_system {
                environment.record_user_property(name);
            }
        }
        if walk.private_names
            && let Some(environment) = lookup.environment()
        {
            let properties = walk
                .resolved
                .keys()
                .filter(|name| !self.is_external(name))
                .filter_map(|name| self.get(name).map(|value| (name.clone(), value.clone())))
                .collect();
            environment.record(HostInput::InterpolationLookup {
                expression: input.to_string(),
                properties,
                source: self
                    .inputs
                    .as_ref()
                    .map_or(PropertySource::User, |inputs| inputs.source),
                default_packaging: self
                    .inputs
                    .as_ref()
                    .and_then(|inputs| inputs.default_packaging.clone()),
                model: lookup
                    .project
                    .and_then(|project| project.model_lookup.clone()),
                model_interpolation: lookup.model,
                from_host: walk.private_host,
            });
        }
    }

    /// One interpolation, charged to this map: many fields that each
    /// expand a large property would otherwise fill memory together.
    fn expand(&self, input: &str, lookup: Lookup<'_>, walk: &mut Walk) -> Result<String, PomError> {
        let output = self.interpolate_str_inner(input, lookup, walk, 0)?;
        let spent = walk.resolved_len + output.len();
        if self.expanded.0.fetch_add(spent, Ordering::Relaxed) + spent > Self::MAX_EXPANDED_LENGTH {
            return Err(PomError::InvalidModel(
                "property interpolation too large for one model".to_string(),
            ));
        }
        Ok(output)
    }

    /// Cap on the size of an interpolated string. Stops a self-referential
    /// or exponentially-expanding property chain from ballooning memory.
    const MAX_INTERPOLATION_LENGTH: usize = 1024 * 1024;
    /// Cap on nested ${...} expansion depth. Maven's own limit is similar;
    /// real POMs almost never exceed two or three levels of indirection.
    const MAX_INTERPOLATION_DEPTH: usize = 100;
    /// Cap on the values one interpolation keeps for reuse, so many large
    /// values that the output drops cannot pile up.
    const MAX_RESOLVED_LENGTH: usize = 4 * Self::MAX_INTERPOLATION_LENGTH;
    /// Cap on what all interpolations over one map expand, far above the
    /// largest real models.
    const MAX_EXPANDED_LENGTH: usize = 32 * Self::MAX_INTERPOLATION_LENGTH;

    fn interpolate_str_inner(
        &self,
        input: &str,
        lookup: Lookup<'_>,
        walk: &mut Walk,
        depth: usize,
    ) -> Result<String, PomError> {
        // Counted per call, not by `path`: nested keys such as `${${${a}}}`
        // recurse without entering a property.
        if depth >= Self::MAX_INTERPOLATION_DEPTH {
            return Err(PomError::InvalidModel(format!(
                "property interpolation depth limit exceeded (max: {})",
                Self::MAX_INTERPOLATION_DEPTH
            )));
        }
        let too_large = |output: &String| {
            if output.len() > Self::MAX_INTERPOLATION_LENGTH {
                Err(PomError::InvalidModel(
                    "property interpolation too large".to_string(),
                ))
            } else {
                Ok(())
            }
        };
        let mut output = String::with_capacity(input.len() * 2);
        let mut rest = input;
        while let Some(start) = rest.find("${") {
            let after = &rest[start + 2..];
            let Some(end) = find_matching_brace(after) else {
                break;
            };
            output.push_str(&rest[..start]);
            let before = walk.external_values;
            let written_key = &after[..end];
            let expanded_key;
            // A borrowed key still counts toward the interpolation limits.
            let key = if depth + 1 < Self::MAX_INTERPOLATION_DEPTH
                && written_key.len() <= Self::MAX_INTERPOLATION_LENGTH
                && !written_key.contains("${")
            {
                written_key
            } else {
                expanded_key = self.interpolate_str_inner(written_key, lookup, walk, depth + 1)?;
                &expanded_key
            };
            let previous_private = walk.private_key;
            walk.private_key = walk.external_depth > 0 || walk.external_values != before;
            walk.private_names |= walk.private_key;
            let detached = walk
                .private_key
                .then(|| lookup.environment().map(ModelEnvironment::detached))
                .flatten();
            let private_lookup = Lookup {
                environment: detached.as_ref().or(lookup.environment),
                ..lookup
            };
            let value = self.resolve_value_inner(key, private_lookup, walk, depth + 1);
            if let Some(detached) = detached {
                walk.private_host |= detached.take_reads().iter().any(HostInput::is_host_read);
            }
            walk.private_key = previous_private;
            match value? {
                Some(value) => output.push_str(&value),
                None => {
                    output.push_str("${");
                    output.push_str(key);
                    output.push('}');
                }
            }
            // Checked after every substitution, so a long run of large ones
            // cannot grow the buffer before the end.
            too_large(&output)?;
            rest = &after[end + 1..];
        }
        output.push_str(rest);
        too_large(&output)?;
        Ok(output)
    }

    fn resolve_value_inner(
        &self,
        key: &str,
        lookup: Lookup<'_>,
        walk: &mut Walk,
        depth: usize,
    ) -> Result<Option<String>, PomError> {
        if let Some(field) = key
            .strip_prefix("project.build.")
            .or_else(|| key.strip_prefix("pom.build."))
            && let Some(value) = self.resolve_build(field, lookup, walk, depth)?
        {
            walk.external_values += 1;
            return Ok(Some(value));
        }
        if let Some(value) = resolve_builtin(key, lookup.project) {
            walk.external_values += 1;
            return Ok(Some(value));
        }
        if let Some(value) = self.resolve_prerequisite(key, lookup, walk, depth)? {
            walk.external_values += 1;
            return Ok(Some(value));
        }
        let unprefixed_build = key.strip_prefix("build.");
        // Maven's bean path `project.properties.X` (and `pom.`) reads the
        // `<X>` property, once, through the same cycle detector as a direct
        // lookup.
        let key = key
            .strip_prefix("project.properties.")
            .or_else(|| key.strip_prefix("pom.properties."))
            .unwrap_or(key);
        // A dependency model gets `-D` values as system properties, which
        // its own properties hide.
        let below_system = self.is_below_system(key);
        if below_system {
            walk.below_system.insert(key.to_string());
        }
        let hidden = self.props.contains_key(key)
            && (self.inputs.as_ref()).is_some_and(|inputs| inputs.source == PropertySource::System)
            && !below_system;
        if lookup.model
            && !walk.private_key
            && !hidden
            && let Some(environment) = lookup.environment()
        {
            environment.record_user_property(key);
            if key.starts_with("os.detected.") && self.props.get(key).is_none() {
                environment.record_user_property("os.name");
                environment.record_user_property("os.arch");
            }
        }
        if let Some(names) = walk.names.as_mut()
            && !names.contains(key)
        {
            names.insert(key.to_string());
        }
        if !walk.private_key
            && let Some(names) = walk.public_names.as_mut()
        {
            names.insert(key.to_string());
        }
        let Some(raw_value) = self.props.get(key) else {
            if let Some(value) = Self::os_detected_on_linux(key, lookup) {
                walk.external_values += 1;
                return Ok(Some(value));
            }
            if let Some(value) = resolve_system_property(key, lookup) {
                walk.external_values += 1;
                return Ok(Some(value));
            }
            if let Some(field) = unprefixed_build
                && let Some(value) = self.resolve_build(field, lookup, walk, depth)?
            {
                walk.external_values += 1;
                return Ok(Some(value));
            }
            let value = resolve_unprefixed_model_field(key, lookup.project);
            walk.external_values += usize::from(value.is_some());
            return Ok(value);
        };
        if let Some((value, external)) = walk.resolved.get(key) {
            walk.external_values += usize::from(*external);
            return Ok(Some(value.clone()));
        }
        let cycle = walk.path.iter().any(|name| name == key);
        walk.path.push(key.to_string());
        if cycle {
            return Err(PomError::PropertyCycle(walk.path.clone()));
        }
        let external = self.is_external(key);
        let before = walk.external_values;
        walk.external_values += usize::from(external);
        walk.external_depth += usize::from(external);
        let resolved = self.interpolate_str_inner(raw_value, lookup, walk, depth);
        walk.external_depth -= usize::from(external);
        let resolved = resolved?;
        walk.path.pop();
        walk.resolved_len += key.len() + resolved.len();
        if walk.resolved_len > Self::MAX_RESOLVED_LENGTH {
            return Err(PomError::InvalidModel(
                "property interpolation too large".to_string(),
            ));
        }
        walk.resolved.insert(
            key.to_string(),
            (resolved.clone(), walk.external_values != before),
        );
        Ok(Some(resolved))
    }

    /// The `<build>` field `field` of the project, or the super POM's
    /// default for it, interpolated. A directory of a project with a base
    /// directory is aligned to it, as Maven's interpolation post-processor
    /// aligns `${project.build.directory}` and the other build
    /// directories. `None` when the field is unknown or neither the
    /// lineage nor the super POM sets it, so the lookup goes on.
    /// Maven's expression evaluator reads `prerequisites.maven` from the
    /// model, ahead of any property of that name.
    fn resolve_prerequisite(
        &self,
        key: &str,
        lookup: Lookup<'_>,
        walk: &mut Walk,
        depth: usize,
    ) -> Result<Option<String>, PomError> {
        let name = "project.prerequisites.maven";
        if key != name && key != "pom.prerequisites.maven" {
            return Ok(None);
        }
        let Some(raw) = (lookup.project)
            .and_then(|project| project.model_lookup.as_ref())
            .and_then(|model| model.prerequisites_maven.as_deref())
        else {
            return Ok(None);
        };
        let cycle = walk.path.iter().any(|entry| entry == name);
        walk.path.push(name.to_string());
        if cycle {
            return Err(PomError::PropertyCycle(walk.path.clone()));
        }
        let resolved = self.interpolate_str_inner(raw, lookup, walk, depth)?;
        walk.path.pop();
        Ok(Some(resolved))
    }

    fn resolve_build(
        &self,
        field: &str,
        lookup: Lookup<'_>,
        walk: &mut Walk,
        depth: usize,
    ) -> Result<Option<String>, PomError> {
        let Some(project) = lookup.project else {
            return Ok(None);
        };
        let Some(raw) = project.build.field(field) else {
            return Ok(None);
        };
        let Some(raw) = raw.as_deref().or_else(|| super_pom_build(field)) else {
            return Ok(None);
        };
        if let Some(value) = walk.build.get(field) {
            return Ok(Some(value.clone()));
        }
        // `${build.x}` and `${project.build.x}` are one field to Maven's
        // recursion check.
        let name = format!("project.build.{field}");
        let cycle = walk.path.contains(&name);
        walk.path.push(name);
        if cycle {
            return Err(PomError::PropertyCycle(walk.path.clone()));
        }
        let mut resolved = self.interpolate_str_inner(raw, lookup, walk, depth)?;
        walk.path.pop();
        if let Some(basedir) = &project.basedir
            && field != "finalName"
            && field != "defaultGoal"
        {
            resolved = align_to_base_directory(&resolved, basedir);
        }
        walk.resolved_len += field.len() + resolved.len();
        if walk.resolved_len > Self::MAX_RESOLVED_LENGTH {
            return Err(PomError::InvalidModel(
                "property interpolation too large".to_string(),
            ));
        }
        walk.build.insert(field.to_string(), resolved.clone());
        Ok(Some(resolved))
    }

    /// What os-maven-plugin adds on Linux from the build machine's release:
    /// `os.detected.release`, `os.detected.release.version` and
    /// `os.detected.release.like.<id>`, and `os.detected.classifier` with
    /// the first entry of the build's classifier likes (see
    /// [`ModelEnvironment::with_classifier_likes`]) the release is like
    /// appended. A value the system properties already hold, a dependency's
    /// `-D` value, is left to them.
    fn os_detected_on_linux(key: &str, lookup: Lookup<'_>) -> Option<String> {
        let platform = lookup
            .system_properties
            .or(lookup.project.map(|project| &project.system_properties))?;
        let environment = lookup.environment()?;
        if !key.starts_with("os.detected.")
            || platform.get("os.detected.name").map(String::as_str) != Some("linux")
            || (key != "os.detected.classifier" && platform.contains_key(key))
        {
            return None;
        }
        let release = || environment.linux_release();
        match key {
            "os.detected.classifier" => {
                let classifier = platform.get(key)?;
                let mut likes = environment.classifier_likes().peekable();
                likes.peek()?;
                let release = release()?;
                likes
                    .find(|like| release.like.iter().any(|known| known == like))
                    .map(|like| format!("{classifier}-{like}"))
            }
            "os.detected.release" => release().map(|release| release.id.clone()),
            "os.detected.release.version" => release().and_then(|release| release.version.clone()),
            _ => key
                .strip_prefix("os.detected.release.like.")
                .and_then(|like| {
                    let release = release()?;
                    release
                        .like
                        .iter()
                        .any(|known| known == like)
                        .then(|| "true".to_string())
                }),
        }
    }
}

pub(crate) fn expression_names(input: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = find_matching_brace(after) else {
            break;
        };
        names.push(&after[..end]);
        rest = &after[end + 1..];
    }
    names
}

/// Find the position of the closing `}` that matches the opening `{` implied at position -1.
/// Handles nested `${}` expressions by counting brace depth. Returns the index
/// of the matching `}` in the input string, or None if not found.
fn find_matching_brace(s: &str) -> Option<usize> {
    let mut depth = 1;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn resolve_builtin(key: &str, project: Option<&ProjectInfo>) -> Option<String> {
    if let Some(rest) = key.strip_prefix("pom.")
        && let Some(value) = resolve_builtin(&format!("project.{rest}"), project)
    {
        return Some(value);
    }
    let project = project?;
    let basedir = project.basedir.as_deref();
    match key {
        "project.basedir" | "basedir" => basedir.map(path_to_string),
        "project.baseUri" => basedir.map(directory_uri),
        _ => resolve_unprefixed_model_field(key.strip_prefix("project.")?, Some(project)),
    }
}

/// Maven consults its system properties, and `env.*` through them, only
/// after the model's own properties, so a POM's `<os.name>` or
/// `<java.version>` wins over the JVM's.
fn resolve_system_property(key: &str, lookup: Lookup<'_>) -> Option<String> {
    // Deterministic Java-equivalent system properties (`java.version`,
    // `os.name`, `os.arch`) resolve to the platform's values instead of
    // falling through to the literal `${...}`. Host-path / host-identity
    // sysprops (`user.home`, `user.dir`, `java.home`) are never interpolated:
    // a transitive POM could otherwise copy the host's layout into raeva.lock,
    // and the value differs between machines.
    let platform = lookup
        .system_properties
        .or(lookup.project.map(|project| &project.system_properties));
    if let Some(value) = platform.and_then(|properties| properties.get(key)) {
        return Some(value.clone());
    }
    let environment = lookup.environment()?;
    if key == "java.version" {
        return Some(environment.java_version().to_string());
    }

    // Maven's model interpolation looks an unprefixed name up as
    // `env.<name>` too, so `${HOME}` means `${env.HOME}` there.
    let prefixed = key.strip_prefix("env.");
    if prefixed.is_none() && !lookup.model {
        return None;
    }
    let name = prefixed.unwrap_or(key);
    if name.is_empty() {
        return None;
    }
    // Supply-chain hardening: refuse to resolve ${env.NAME} unless the
    // operator has explicitly added NAME to the allowlist. Without this
    // gate, any transitive POM author can exfiltrate host env vars (like
    // AWS_SECRET_ACCESS_KEY or GITHUB_TOKEN) by interpolating them into
    // a value that lands in the lockfile, error messages, or cache keys.
    if !environment.allows_env(name) {
        environment.warn_hidden_env(name);
        return None;
    }
    environment.env_var(name).map(str::to_string)
}

/// Maven's last value source reads the model itself without a prefix, after
/// properties and system properties, so a `<version>` property wins over
/// `${version}` meaning the project version.
fn resolve_unprefixed_model_field(key: &str, project: Option<&ProjectInfo>) -> Option<String> {
    let project = project?;
    let parent = project.parent.as_ref();
    match key {
        // A coordinate is empty only while it is expanded, where a reference
        // to it falls through to the properties.
        "groupId" => Some(project.group_id.clone()).filter(|value| !value.is_empty()),
        "artifactId" => Some(project.artifact_id.clone()).filter(|value| !value.is_empty()),
        "version" => Some(project.version.clone()).filter(|value| !value.is_empty()),
        "packaging" => Some(project.packaging.clone()),
        "parent.groupId" => parent.map(|parent| parent.group_id.clone()),
        "parent.artifactId" => parent.map(|parent| parent.artifact_id.clone()),
        "parent.version" => parent.map(|parent| parent.version.clone()),
        _ => None,
    }
}

/// The super POM's `<build>` value for `field`, which every lineage
/// inherits where none of its POMs sets one. It has no `defaultGoal`.
pub(crate) fn super_pom_build(field: &str) -> Option<&'static str> {
    Some(match field {
        "directory" => "${project.basedir}/target",
        "finalName" => "${project.artifactId}-${project.version}",
        "outputDirectory" => "${project.build.directory}/classes",
        "testOutputDirectory" => "${project.build.directory}/test-classes",
        "sourceDirectory" => "${project.basedir}/src/main/java",
        "testSourceDirectory" => "${project.basedir}/src/test/java",
        "scriptSourceDirectory" => "${project.basedir}/src/main/scripts",
        _ => return None,
    })
}

/// Maven's `DefaultPathTranslator.alignToBaseDirectory`: `path`, with
/// either slash as the separator, as it is when absolute, under the drive
/// of `basedir` when it starts at a root without one (Windows), and
/// otherwise joined to `basedir` with `.` and `..` segments resolved.
/// Like Java's `File`, the result has no repeated or trailing separator.
fn align_to_base_directory(path: &str, basedir: &std::path::Path) -> String {
    use std::path::{Component, MAIN_SEPARATOR, Path};
    let path: String = path
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' {
                MAIN_SEPARATOR
            } else {
                c
            }
        })
        .collect();
    let path = Path::new(&path);
    if path.is_absolute() || path.has_root() {
        return java_file_path(&path_to_string(&basedir.join(path)));
    }
    let mut aligned = PathBuf::new();
    for component in basedir.join(path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir
                if matches!(aligned.components().next_back(), Some(Component::Normal(_))) =>
            {
                aligned.pop();
            }
            component => aligned.push(component),
        }
    }
    path_to_string(&aligned)
}

/// `path` as Java's `File` keeps it: runs of separators collapsed, except
/// the two that start a Windows UNC path, and no trailing separator after
/// anything but a root.
fn java_file_path(path: &str) -> String {
    use std::path::{MAIN_SEPARATOR, Path};
    let mut out = String::with_capacity(path.len());
    let unc = cfg!(windows) && path.starts_with(r"\\");
    for c in path.chars() {
        if c == MAIN_SEPARATOR && out.ends_with(MAIN_SEPARATOR) && !(unc && out.len() == 1) {
            continue;
        }
        out.push(c);
    }
    while out.ends_with(MAIN_SEPARATOR) && Path::new(&out).parent().is_some() {
        out.pop();
    }
    out
}

/// `${project.baseUri}`: Java's `Path.toUri().toASCIIString()` for the
/// project directory, such as `file:///home/me/app/` or
/// `file:///C:/work/app/`. Bytes outside the characters Java leaves in a
/// URI path are percent-encoded, and a directory ends with `/`.
fn directory_uri(path: &std::path::Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let mut uri = String::from("file://");
    if !text.starts_with('/') {
        uri.push('/');
    }
    for byte in text.bytes() {
        let keep = byte.is_ascii_alphanumeric() || b"-_.!~*'():@&=+$,;/".contains(&byte);
        if keep {
            uri.push(char::from(byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    if !uri.ends_with('/') {
        uri.push('/');
    }
    uri
}

fn path_to_string(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The `os.detected.*` value os-maven-plugin's `Detector` derives from the
/// JVM's `os.name` and `os.arch`: the target platform's, or a `-D` override.
/// Maven fails the build on a name or architecture the plugin does not know;
/// raeva leaves the property unresolved. The plugin sets them after the project
/// models are built, so they act as system properties: a POM property of the
/// same name wins, and profile activation does not see them.
pub(crate) fn os_detected(
    key: &str,
    os_name: Option<&str>,
    os_arch: Option<&str>,
) -> Option<String> {
    let name = || os_name.and_then(detected_os_name);
    let arch = || os_arch.and_then(detected_os_arch);
    match key {
        "os.detected.name" => name().map(str::to_string),
        "os.detected.arch" => arch().map(str::to_string),
        "os.detected.classifier" => Some(format!("{}-{}", name()?, arch()?)),
        _ => None,
    }
}

pub(crate) const OS_DETECTED_PROPERTIES: [&str; 3] = [
    "os.detected.name",
    "os.detected.arch",
    "os.detected.classifier",
];

fn detector_normalize(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect()
}

fn detected_os_name(os_name: &str) -> Option<&'static str> {
    let value = detector_normalize(os_name);
    let os400 = value.starts_with("os400")
        && !value
            .as_bytes()
            .get(5)
            .is_some_and(|byte| byte.is_ascii_digit());
    [
        ("aix", "aix"),
        ("hpux", "hpux"),
        ("linux", "linux"),
        ("mac", "osx"),
        ("osx", "osx"),
        ("freebsd", "freebsd"),
        ("openbsd", "openbsd"),
        ("netbsd", "netbsd"),
        ("solaris", "sunos"),
        ("sunos", "sunos"),
        ("windows", "windows"),
        ("zos", "zos"),
    ]
    .into_iter()
    .find(|(prefix, _)| value.starts_with(prefix))
    .map(|(_, name)| name)
    .or(os400.then_some("os400"))
}

fn detected_os_arch(os_arch: &str) -> Option<&'static str> {
    Some(match detector_normalize(os_arch).as_str() {
        "x8664" | "amd64" | "ia32e" | "em64t" | "x64" => "x86_64",
        "x8632" | "x86" | "i386" | "i486" | "i586" | "i686" | "ia32" | "x32" => "x86_32",
        "ia64" | "ia64w" | "itanium64" => "itanium_64",
        "ia64n" => "itanium_32",
        "sparc" | "sparc32" => "sparc_32",
        "sparcv9" | "sparc64" => "sparc_64",
        "arm" | "arm32" => "arm_32",
        "aarch64" => "aarch_64",
        "mips" | "mips32" => "mips_32",
        "mipsel" | "mips32el" => "mipsel_32",
        "mips64" => "mips_64",
        "mips64el" => "mipsel_64",
        "ppc" | "ppc32" => "ppc_32",
        "ppcle" | "ppc32le" => "ppcle_32",
        "ppc64" => "ppc_64",
        "ppc64le" => "ppcle_64",
        "s390" => "s390_32",
        "s390x" => "s390_64",
        "riscv" | "riscv32" => "riscv",
        "riscv64" => "riscv64",
        "e2k" => "e2k",
        "loongarch64" => "loongarch_64",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_expressions_keep_private_names_in_replay_only() {
        let mut properties = PropertyMap::new();
        properties.insert("public", "${alias}");
        properties.insert_external("alias", "${private-key}");
        properties.insert_external("private-key", "2");
        let environment = ModelEnvironment::default();
        let (value, names) = properties.interpolate_str_exact_names("${public}", &environment);
        assert_eq!(value.unwrap(), "2");
        assert_eq!(names, ["public".to_string(), "alias".to_string()].into());
        let (_, replay) = properties.replay_exact_names("${public}", &environment);
        assert!(replay.contains("private-key"));
        let reads = environment.take_reads();
        assert!(!reads.contains(&HostInput::UserProperty("private-key".into())));
        assert!(reads.iter().any(|input| matches!(input, HostInput::InterpolationLookup { expression, properties, .. }
            if expression == "${public}" && properties.get("public").map(String::as_str) == Some("${alias}")
                && !properties.contains_key("alias") && !properties.contains_key("private-key"))));
    }

    /// Maven's bean path reads the properties map once; a repeated prefix
    /// names a property of that name, not a chain of lookups.
    #[test]
    fn repeated_property_prefixes_are_one_lookup() {
        let mut props = PropertyMap::new();
        props.insert("x", "1");
        let started = std::time::Instant::now();
        let deep = format!("${{{}x}}", "pom.properties.".repeat(50_000));
        assert_eq!(props.interpolate_str_no_project(&deep).unwrap(), deep);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(
            props
                .interpolate_str_no_project("${project.properties.x}")
                .unwrap(),
            "1"
        );
    }

    fn project_in(environment: ModelEnvironment) -> ProjectInfo {
        ProjectInfo {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: "v".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            build: Build::default(),
            system_properties: Default::default(),
            environment,
            model_lookup: None,
        }
    }

    fn on_platform(rust_os: &str, rust_arch: &str, user: &[(&str, &str)]) -> ProjectInfo {
        let mut ctx = crate::ActivationContext::default();
        ctx.set_platform(rust_os, rust_arch);
        for (name, value) in user {
            ctx.properties.insert(name.to_string(), value.to_string());
        }
        ProjectInfo {
            system_properties: ctx.interpolation_system_properties(),
            ..project_in(ctx.environment.clone())
        }
    }

    fn map(properties: &[(&str, &str)]) -> PropertyMap {
        let mut map = PropertyMap::new();
        for (name, value) in properties {
            map.insert(*name, *value);
        }
        map
    }

    /// Maven reads properties, then the project's fields, then unprefixed
    /// model fields such as `${groupId}` or `${parent.version}` last;
    /// expressions nest, and one that resolves to nothing, `${settings.*}`
    /// included, stays as written.
    #[test]
    fn interpolates_like_maven() {
        let project = ProjectInfo {
            group_id: "io.netty".to_string(),
            artifact_id: "netty-codec-dns".to_string(),
            version: "4.1.0.Final".to_string(),
            parent: Some(ParentInfo {
                group_id: "com.base".to_string(),
                artifact_id: "parent".to_string(),
                version: "2.0.0".to_string(),
            }),
            ..project_in(ModelEnvironment::default())
        };
        for (properties, input, expected) in [
            (
                &[("name", "raeva"), ("path", "/opt/${name}")][..],
                "${path}/bin",
                "/opt/raeva/bin",
            ),
            (
                &[],
                "${project.groupId}:${project.artifactId}",
                "io.netty:netty-codec-dns",
            ),
            (
                &[],
                "${pom.groupId}:${pom.artifactId}:${pom.version}",
                "io.netty:netty-codec-dns:4.1.0.Final",
            ),
            (
                &[],
                "${groupId}:${artifactId}:${version}",
                "io.netty:netty-codec-dns:4.1.0.Final",
            ),
            (
                &[("groupId", "com.override")],
                "${groupId} ${project.groupId} ${pom.groupId}",
                "com.override io.netty io.netty",
            ),
            (
                &[("foo", "1.2")],
                "${project.properties.foo}-${pom.properties.foo}",
                "1.2-1.2",
            ),
            (
                &[],
                "${project.parent.groupId}:${project.parent.artifactId}:${project.parent.version}",
                "com.base:parent:2.0.0",
            ),
            (
                &[],
                "${parent.groupId}:${parent.artifactId}:${parent.version}",
                "com.base:parent:2.0.0",
            ),
            (
                &[("parent.version", "own")],
                "${parent.version} ${project.parent.version}",
                "own 2.0.0",
            ),
            (
                &[],
                "${missing}/bin ${settings.localRepository}",
                "${missing}/bin ${settings.localRepository}",
            ),
            (
                &[("env", "prod"), ("config.prod.url", "https://prod/")],
                "${config.${env}.url}",
                "https://prod/",
            ),
            (
                &[("level", "one"), ("one", "two"), ("value.two", "success")],
                "${value.${${level}}}",
                "success",
            ),
            (&[("a", "x")], "ab${c", "ab${c"),
            (&[("a", "x")], "${a}-${a", "x-${a"),
        ] {
            let value = map(properties).interpolate_str(input, &project).unwrap();
            assert_eq!(value, expected, "{input} with {properties:?}");
        }
        let mut props = map(&[("version", "1.0.0")]);
        assert_eq!(
            props.interpolate_str_no_project("${version}").unwrap(),
            "1.0.0"
        );
        props.insert("a", "${b}");
        props.insert("b", "${a}");
        let error = props.interpolate_str_no_project("${a}").unwrap_err();
        assert!(matches!(&error, PomError::PropertyCycle(path) if path == &["a", "b", "a"]));
    }

    /// The super POM's build directories sit under the base directory, and
    /// `${project.baseUri}` is Java's `Path.toUri().toASCIIString()` for it,
    /// as Maven 3.9.11 printed it; `${baseUri}` has no unprefixed form.
    #[test]
    fn interpolates_the_base_directory_and_its_uri() {
        let props = PropertyMap::new();
        let in_dir = |basedir: &str| ProjectInfo {
            basedir: Some(PathBuf::from(basedir)),
            ..project_in(ModelEnvironment::default())
        };
        let workspace = std::env::temp_dir().join("workspace");
        let project = in_dir(&workspace.to_string_lossy());
        for (expression, path) in [
            ("${project.basedir}", &[][..]),
            ("${project.build.directory}", &["target"]),
            ("${project.build.outputDirectory}", &["target", "classes"]),
            (
                "${project.build.testOutputDirectory}",
                &["target", "test-classes"],
            ),
            ("${project.build.sourceDirectory}", &["src", "main", "java"]),
            ("${pom.build.sourceDirectory}", &["src", "main", "java"]),
            ("${build.sourceDirectory}", &["src", "main", "java"]),
            (
                "${project.build.testSourceDirectory}",
                &["src", "test", "java"],
            ),
            (
                "${project.build.scriptSourceDirectory}",
                &["src", "main", "scripts"],
            ),
        ] {
            let expected: PathBuf = path
                .iter()
                .fold(workspace.clone(), |dir, part| dir.join(part));
            let value = props.interpolate_str(expression, &project).unwrap();
            assert_eq!(value, expected.to_string_lossy(), "{expression}");
        }
        for (basedir, expression, expected) in [
            ("/home/me/app", "${project.baseUri}", "file:///home/me/app/"),
            ("/home/me/app", "${pom.baseUri}", "file:///home/me/app/"),
            ("/home/me/app", "${baseUri}", "${baseUri}"),
            (
                "/tmp/a b/x#y%z/caf\u{e9}",
                "${project.baseUri}",
                "file:///tmp/a%20b/x%23y%25z/caf%C3%A9/",
            ),
            (
                "/tmp/k(1)~;@$,=+&!*'",
                "${project.baseUri}",
                "file:///tmp/k(1)~;@$,=+&!*'/",
            ),
            (
                "C:\\work\\app",
                "${project.baseUri}",
                "file:///C:/work/app/",
            ),
        ] {
            let value = props.interpolate_str(expression, &in_dir(basedir)).unwrap();
            assert_eq!(value, expected, "{basedir}");
        }
    }

    /// A `<build>` value is interpolated with the model, and a directory is
    /// aligned to the base directory once interpolated, as Maven 3.9.12
    /// printed them; a POM without a base directory keeps the super POM's
    /// `${project.basedir}`. A property of the same name wins over
    /// `${build.x}` only, and `defaultGoal` has no default.
    #[cfg(unix)]
    #[test]
    fn interpolates_build_values_like_maven() {
        let build = Build {
            directory: Some("../out//${name}/./x/".to_string()),
            final_name: Some("${project.artifactId}-fn".to_string()),
            output_directory: Some("/abs//classes/".to_string()),
            test_output_directory: Some(String::new()),
            ..Build::default()
        };
        let reactor = ProjectInfo {
            basedir: Some(PathBuf::from("/w/m")),
            build: build.clone(),
            ..project_in(ModelEnvironment::default())
        };
        let props = map(&[("name", "n"), ("build.finalName", "prop")]);
        for (expression, expected) in [
            ("${project.build.directory}", "/w/out/n/x"),
            ("${project.build.finalName}", "a-fn"),
            ("${pom.build.finalName}", "a-fn"),
            ("${build.finalName}", "prop"),
            ("${project.build.outputDirectory}", "/abs/classes"),
            ("${project.build.testOutputDirectory}", "/w/m"),
            (
                "${project.build.defaultGoal}",
                "${project.build.defaultGoal}",
            ),
            ("${build.resources}", "${build.resources}"),
        ] {
            let value = props.interpolate_str(expression, &reactor).unwrap();
            assert_eq!(value, expected, "{expression}");
        }
        let dependency = ProjectInfo {
            build: Build {
                directory: Some("pdir".to_string()),
                ..Build::default()
            },
            ..project_in(ModelEnvironment::default())
        };
        for (expression, expected) in [
            ("${project.build.directory}", "pdir"),
            ("${project.build.outputDirectory}", "pdir/classes"),
            ("${project.build.finalName}", "a-v"),
            (
                "${project.build.sourceDirectory}",
                "${project.basedir}/src/main/java",
            ),
        ] {
            let value = props.interpolate_str(expression, &dependency).unwrap();
            assert_eq!(value, expected, "{expression}");
        }
        let cyclic = ProjectInfo {
            build: Build {
                final_name: Some("x-${build.finalName}".to_string()),
                ..Build::default()
            },
            ..project_in(ModelEnvironment::default())
        };
        let error = PropertyMap::new()
            .interpolate_str("${project.build.finalName}", &cyclic)
            .unwrap_err();
        assert!(matches!(error, PomError::PropertyCycle(_)), "{error}");
    }

    /// Supply-chain hardening of `${env.X}` POM substitution: a variable
    /// outside the allowlist is never resolved, and the reference stays as
    /// written. The environment holds no value for it, so none can leak.
    /// Two environments with different allowlists stay independent.
    #[test]
    fn env_substitution_follows_the_allowlist() {
        let props = PropertyMap::new();
        let allowed = project_in(
            ModelEnvironment::builder()
                .env("RAEVA_TEST_ENV", Some("ok"))
                .env("RAEVA_UNSET", None)
                .build(),
        );
        for (input, expected) in [
            ("${env.RAEVA_TEST_ENV}", "ok"),
            // Maven also tries an unprefixed name as `env.<name>`.
            ("${RAEVA_TEST_ENV}", "ok"),
            (
                "${env.RAEVA_TEST_DISALLOWED_SECRET}",
                "${env.RAEVA_TEST_DISALLOWED_SECRET}",
            ),
            (
                "${RAEVA_TEST_DISALLOWED_SECRET}",
                "${RAEVA_TEST_DISALLOWED_SECRET}",
            ),
            ("${env.RAEVA_UNSET}", "${env.RAEVA_UNSET}"),
        ] {
            assert_eq!(props.interpolate_str(input, &allowed).unwrap(), expected);
        }
        let first = project_in(
            ModelEnvironment::builder()
                .env("RAEVA_A", Some("a"))
                .build(),
        );
        let second = project_in(
            ModelEnvironment::builder()
                .env("RAEVA_B", Some("b"))
                .build(),
        );
        let input = "${env.RAEVA_A}|${env.RAEVA_B}";
        assert_eq!(
            props.interpolate_str(input, &first).unwrap(),
            "a|${env.RAEVA_B}"
        );
        assert_eq!(
            props.interpolate_str(input, &second).unwrap(),
            "${env.RAEVA_A}|b"
        );

        let environment = ModelEnvironment::builder()
            .env("RAEVA_TEST_ALLOWED", Some("hello"))
            .jdk_version("21.0.4")
            .build();
        let props = map(&[("os.name", "Target")]);
        assert_eq!(
            props
                .interpolate_str_exact(
                    "${RAEVA_TEST_ALLOWED}|${env.RAEVA_TEST_ALLOWED}|${os.arch}|${os.name}|${java.version}",
                    &environment
                )
                .unwrap(),
            "${RAEVA_TEST_ALLOWED}|hello|${os.arch}|Target|21.0.4"
        );
        // Without an environment, only the map's entries resolve.
        assert_eq!(
            props
                .interpolate_str_no_project("${RAEVA_TEST_ALLOWED}|${os.name}")
                .unwrap(),
            "${RAEVA_TEST_ALLOWED}|Target"
        );
    }

    /// The host-path / host-identity sysprops `user.home`,
    /// `user.dir`, and `java.home` must NOT appear in the interpolation map, so
    /// a (possibly transitive) POM that references them cannot read the host's
    /// filesystem layout via a value that lands in the lockfile, an error
    /// message, or a cache key.
    #[test]
    fn sensitive_sysprops_are_not_interpolated() {
        let props = PropertyMap::new();
        let project = project_in(
            ModelEnvironment::builder()
                .platform("linux", "x86_64")
                .java_home("/opt/secret-jdk")
                .build(),
        );
        for key in ["user.home", "user.dir", "java.home"] {
            let value = props
                .interpolate_str(&format!("${{{key}}}"), &project)
                .unwrap();
            assert_eq!(value, format!("${{{key}}}"));
        }
    }

    /// Recorded with `help:effective-pom` from Maven 3.9.11: `${os.name}`
    /// and `${os.arch}` are the JVM's values on the build platform, and a
    /// model property of the same name wins over them. `${java.version}` is
    /// the known JDK, or a stand-in, and raeva does not know `os.version`.
    #[test]
    fn os_and_java_sysprops_follow_the_target_below_model_properties() {
        for (rust_os, rust_arch, name, arch) in [
            ("linux", "x86_64", "Linux", "amd64"),
            ("macos", "aarch64", "Mac OS X", "aarch64"),
            ("windows", "x86_64", "Windows 11", "amd64"),
        ] {
            let project = on_platform(rust_os, rust_arch, &[]);
            let mut props = PropertyMap::new();
            let input = "${os.name}/${os.arch} ${os.version} ${java.version}";
            assert_eq!(
                props.interpolate_str(input, &project).unwrap(),
                format!("{name}/{arch} ${{os.version}} 17")
            );
            props.insert("os.name", "custom-os");
            props.insert("java.version", "custom-java");
            assert_eq!(
                props
                    .interpolate_str("${os.name} ${java.version}", &project)
                    .unwrap(),
                "custom-os custom-java"
            );
        }
        let props = PropertyMap::new();
        let project = project_in(ModelEnvironment::builder().jdk_version("21.0.4").build());
        assert_eq!(
            props.interpolate_str("${java.version}", &project).unwrap(),
            "21.0.4"
        );
        let project = project_in(ModelEnvironment::default());
        assert_eq!(
            props.interpolate_str("${os.name}", &project).unwrap(),
            "${os.name}"
        );
    }

    /// os-maven-plugin's `os.detected.*` follow the target platform's
    /// `os.name` and `os.arch`, or their `-D` values, never the host's, and
    /// normalize them as the plugin does.
    #[test]
    fn os_detected_properties_follow_the_target_platform() {
        let expression = "${os.detected.name} ${os.detected.arch} ${os.detected.classifier}";
        for (rust_os, rust_arch, user, expected) in [
            ("linux", "x86_64", &[][..], "linux x86_64 linux-x86_64"),
            ("linux", "aarch64", &[], "linux aarch_64 linux-aarch_64"),
            ("linux", "x86", &[], "linux x86_32 linux-x86_32"),
            ("macos", "aarch64", &[], "osx aarch_64 osx-aarch_64"),
            ("macos", "x86_64", &[], "osx x86_64 osx-x86_64"),
            ("windows", "x86_64", &[], "windows x86_64 windows-x86_64"),
            (
                "windows",
                "aarch64",
                &[],
                "windows aarch_64 windows-aarch_64",
            ),
            ("freebsd", "x86_64", &[], "freebsd x86_64 freebsd-x86_64"),
            (
                "linux",
                "x86_64",
                &[("os.arch", "ppc64le")],
                "linux ppcle_64 linux-ppcle_64",
            ),
            (
                "linux",
                "riscv32gc",
                &[],
                "linux ${os.detected.arch} ${os.detected.classifier}",
            ),
        ] {
            let project = on_platform(rust_os, rust_arch, user);
            let value = PropertyMap::new()
                .interpolate_str(expression, &project)
                .unwrap();
            assert_eq!(value, expected, "{rust_os}-{rust_arch} {user:?}");
        }
        for (os_name, expected) in [
            ("Linux", Some("linux")),
            ("Mac OS X", Some("osx")),
            ("Windows 10", Some("windows")),
            ("SunOS", Some("sunos")),
            ("OS/400", Some("os400")),
            ("OS/4000", None),
            ("z/OS", Some("zos")),
            ("HP-UX", Some("hpux")),
            ("Plan 9", None),
        ] {
            let name = os_detected("os.detected.name", Some(os_name), None);
            assert_eq!(name.as_deref(), expected, "{os_name}");
        }
        for (os_arch, expected) in [
            ("amd64", Some("x86_64")),
            ("i686", Some("x86_32")),
            ("i786", None),
            ("arm", Some("arm_32")),
            ("s390x", Some("s390_64")),
            ("ia64w", Some("itanium_64")),
            ("loongarch64", Some("loongarch_64")),
            ("riscv64", Some("riscv64")),
        ] {
            let arch = os_detected("os.detected.arch", None, Some(os_arch));
            assert_eq!(arch.as_deref(), expected, "{os_arch}");
        }
    }

    /// On a Linux platform os-maven-plugin adds the build machine's release,
    /// and the first entry of the build's classifier likes the release is
    /// like to the classifier, in every model alike, unless a dependency's
    /// model has the classifier from a `-D` value. A model's own
    /// `os.detection.classifierWithLikes` property does not change it. Only
    /// a read that depends on the release records it.
    #[test]
    fn os_detected_release_follows_the_linux_release() {
        let release = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=\"debian\"\nVERSION_ID=\"24.04\"\n";
        let classifier = "${os.detected.classifier}";
        let release_values = "${os.detected.release} ${os.detected.release.version} \
             ${os.detected.release.like.debian} ${os.detected.release.like.fedora}";
        let reactor = Some(PathBuf::from("/work/app"));
        let user = |key: &str, value: &str| HashMap::from([(key.to_string(), value.to_string())]);
        let none = HashMap::new;
        for (rust_os, basedir, likes, system, expression, expected, recorded) in [
            (
                "linux",
                &reactor,
                "fedora, debian,ubuntu",
                none(),
                classifier,
                "linux-x86_64-debian",
                true,
            ),
            (
                "linux",
                &None,
                "debian",
                none(),
                classifier,
                "linux-x86_64-debian",
                true,
            ),
            (
                "linux",
                &reactor,
                "fedora",
                none(),
                classifier,
                "linux-x86_64",
                true,
            ),
            (
                "linux",
                &reactor,
                " ",
                none(),
                classifier,
                "linux-x86_64",
                false,
            ),
            (
                "linux",
                &None,
                "debian",
                user("os.detected.classifier", "x"),
                classifier,
                "x",
                false,
            ),
            (
                "linux",
                &None,
                "",
                none(),
                release_values,
                "ubuntu 24.04 true ${os.detected.release.like.fedora}",
                true,
            ),
            (
                "linux",
                &None,
                "",
                user("os.detected.release", "y"),
                "${os.detected.release}",
                "y",
                false,
            ),
            (
                "macos",
                &reactor,
                "debian",
                none(),
                classifier,
                "osx-x86_64",
                false,
            ),
        ] {
            let host = crate::HostSnapshot::for_testing(&[]).with_os_release(release);
            let mut ctx = crate::ActivationContext::new(
                host.environment(rust_os, "x86_64")
                    .with_classifier_likes(Some(likes)),
            );
            ctx.system_properties = system;
            let project = ProjectInfo {
                basedir: basedir.clone(),
                system_properties: ctx.interpolation_system_properties(),
                ..project_in(ctx.model_environment())
            };
            let value = map(&[("os.detection.classifierWithLikes", "fedora,ubuntu")])
                .interpolate_str(expression, &project)
                .unwrap();
            assert_eq!(value, expected, "{rust_os} {likes:?}");
            assert_eq!(
                host.consulted().contains(&crate::HostInput::OsRelease),
                recorded,
                "{rust_os} {likes:?}"
            );
        }
    }

    /// Each level references the one below four times: 4^40 expansions
    /// without reuse.
    #[test]
    fn repeated_references_expand_once() {
        let mut props = PropertyMap::new();
        props.insert("p0", "");
        for i in 1..=40 {
            let below = format!("${{p{}}}", i - 1);
            props.insert(format!("p{i}"), below.repeat(4));
        }
        props.insert("x", "${y}${y}");
        props.insert("y", "${x}");
        let start = std::time::Instant::now();
        assert_eq!(props.interpolate_str_no_project("[${p40}]").unwrap(), "[]");
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert!(matches!(
            props.interpolate_str_no_project("${x}"),
            Err(PomError::PropertyCycle(_))
        ));

        // Large values the output drops still count against the limit.
        let name = "n".repeat(256 * 1024);
        props.insert(name.as_str(), "");
        props.insert("base", name.as_str());
        let mut input = String::new();
        for i in 0..32 {
            props.insert(format!("a{i}"), "${base}");
            input.push_str(&format!("${{${{a{i}}}}}"));
        }
        let error = props.interpolate_str_no_project(&input).unwrap_err();
        assert!(
            matches!(&error, PomError::InvalidModel(message) if message.contains("too large")),
            "{error:?}"
        );
    }

    /// Each field of a hostile POM may expand a property up to the size
    /// limit; together they stop at the map's budget instead of filling
    /// memory, and a copy has its own budget.
    #[test]
    fn many_large_expansions_over_one_map_stop() {
        let mut props = PropertyMap::new();
        props.insert("p0", "a".repeat(1024));
        for i in 1..=10 {
            props.insert(format!("p{i}"), format!("${{p{0}}}${{p{0}}}", i - 1));
        }
        let error = (0..100)
            .map(|_| props.interpolate_str_no_project("${p10}"))
            .find_map(Result::err)
            .expect("stops");
        assert!(
            matches!(&error, PomError::InvalidModel(message) if message.contains("too large")),
            "{error:?}"
        );
        assert_eq!(
            props
                .clone()
                .interpolate_str_no_project("${p10}")
                .unwrap()
                .len(),
            1024 * 1024
        );
    }

    #[test]
    fn rejects_excessive_interpolation_depth() {
        let mut props = PropertyMap::new();
        for i in 0..101 {
            props.insert(format!("prop{i}"), format!("${{prop{}}}", i + 1));
        }
        props.insert("prop101", "final");
        let error = props.interpolate_str_no_project("${prop0}").unwrap_err();
        assert!(
            matches!(&error, PomError::InvalidModel(message) if message.contains("depth limit exceeded")),
            "{error:?}"
        );
    }
}
