//! Maven reactor discovery and effective-GAV indexing.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use rv_maven_model::{ActivationContext, EffectiveDescriptor, Gav, Pom, PomError};
use rv_version::Coord;
use thiserror::Error;

use crate::parent_resolver::{ParentResolverBase, RemotePomFetcher, local_parent_boundary};

/// One POM participating in a discovered Maven reactor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceModule {
    /// Canonical workspace-root-relative POM path using forward slashes.
    pub pom_path: String,
    pub descriptor: EffectiveDescriptor,
    pom: Pom,
}

impl WorkspaceModule {
    pub fn gav(&self) -> &Gav {
        &self.descriptor.gav
    }

    /// Raw user-authored POM retained for workspace-aware model resolution.
    pub fn pom(&self) -> &Pom {
        &self.pom
    }
}

/// A recursively discovered Maven reactor and its effective-GAV index.
#[derive(Debug, Clone)]
pub struct Workspace {
    root: PathBuf,
    modules: Vec<WorkspaceModule>,
    gav_index: HashMap<Gav, usize>,
    ga_index: HashMap<(String, String), Vec<usize>>,
    maven_config: MavenConfig,
}

impl Workspace {
    /// Discover a reactor from a root directory or its root `pom.xml`.
    pub fn discover(root: impl AsRef<Path>) -> Result<Self, WorkspaceError> {
        Self::discover_with_context(root, ActivationContext::from_system())
    }

    /// Discover a reactor with an activation context supplied by the caller.
    ///
    /// Discovery still reads the reactor root's `.mvn/maven.config` exactly
    /// once and overlays it on this context. Its `-D` properties and
    /// `-P`/`-!P` profile selections then apply to every discovered POM.
    pub fn discover_with_context(
        root: impl AsRef<Path>,
        mut activation: ActivationContext,
    ) -> Result<Self, WorkspaceError> {
        let (canonical_root, root_pom) = canonical_reactor_root(root.as_ref())?;
        let config = MavenConfig::read(&canonical_root)?;
        config.apply(&mut activation);

        let strict = Self::scan(
            &canonical_root,
            &root_pom,
            activation.clone(),
            &canonical_root,
            &config,
        );

        // The reactor root's own `<relativePath>` parent always sits outside
        // the root directory, so the strict boundary can never accept it. When
        // the reactor turns out to be a single selected module, resolution
        // *does* accept that immediate external parent
        // (`local_parent_boundary`), and discovery must agree or it indexes a
        // GAV resolution will never produce — or fails outright on a version
        // interpolated from a property the parent defines. Rescan under the
        // relaxed boundary and keep the result only while it stays one module.
        let relaxed_root = local_parent_boundary(&canonical_root, 1);
        let retry_relaxed = relaxed_root != canonical_root
            && match &strict {
                Ok(workspace) => workspace.len() == 1 && workspace.modules[0].pom.parent.is_some(),
                Err(_) => true,
            };
        if retry_relaxed
            && let Ok(relaxed) = Self::scan(
                &canonical_root,
                &root_pom,
                activation,
                &relaxed_root,
                &config,
            )
            && relaxed.len() == 1
        {
            return Ok(relaxed);
        }

        strict
    }

    fn scan(
        canonical_root: &Path,
        root_pom: &Path,
        activation: ActivationContext,
        parent_boundary: &Path,
        config: &MavenConfig,
    ) -> Result<Self, WorkspaceError> {
        let mut scanner = Scanner {
            root: canonical_root.to_path_buf(),
            parent_boundary: parent_boundary.to_path_buf(),
            activation,
            maven_config: config.clone(),
            modules: Vec::new(),
            gav_index: HashMap::new(),
            ga_index: HashMap::new(),
            states: HashMap::new(),
            stack: Vec::new(),
        };
        scanner.visit(root_pom.to_path_buf())?;

        Ok(Self {
            root: canonical_root.to_path_buf(),
            modules: scanner.modules,
            gav_index: scanner.gav_index,
            ga_index: scanner.ga_index,
            maven_config: config.clone(),
        })
    }

    /// Canonical reactor root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory that this reactor's local `<relativePath>` parents must stay
    /// inside. See [`local_parent_boundary`].
    pub fn local_parent_boundary(&self) -> PathBuf {
        local_parent_boundary(&self.root, self.modules.len())
    }

    /// Modules in deterministic depth-first discovery order, starting at the
    /// aggregator itself.
    pub fn modules(&self) -> &[WorkspaceModule] {
        &self.modules
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Look up a reactor member by its effective interpolated GAV.
    pub fn get(&self, gav: &Gav) -> Option<&WorkspaceModule> {
        self.gav_index
            .get(gav)
            .and_then(|index| self.modules.get(*index))
    }

    /// Reactor members with the requested group/artifact identity.
    ///
    /// Multiple versions of one GA may participate in a reactor. Range and
    /// dynamic resolution treat each effective version as an ordinary
    /// candidate alongside versions advertised by repositories.
    pub fn candidates<'a>(
        &'a self,
        group_id: &str,
        artifact_id: &str,
    ) -> impl Iterator<Item = &'a WorkspaceModule> + 'a {
        self.ga_index
            .get(&(group_id.to_string(), artifact_id.to_string()))
            .into_iter()
            .flatten()
            .filter_map(|index| self.modules.get(*index))
    }

    pub(crate) fn apply_root_maven_config(&self, activation: &mut ActivationContext) {
        self.maven_config.apply(activation);
    }

    pub(crate) fn inject_root_properties(&self, pom: &mut Pom) {
        self.maven_config.inject_properties(pom);
    }

    /// The reactor root's `.mvn/maven.config` `-D` entries, which resolution
    /// overlays on every module POM before inheritance runs.
    ///
    /// `rv sync`'s model hash walks each module's local parent chain with
    /// these, so the parents it covers stay the parents resolution accepts
    /// (see [`accepted_local_parents`](crate::accepted_local_parents)).
    pub fn user_properties(&self) -> &HashMap<String, String> {
        &self.maven_config.properties
    }
}

/// Reactor discovery failures.
#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("reactor root is neither a directory nor pom.xml: {path}")]
    InvalidRoot { path: String },
    #[error("failed to access workspace path {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid POM at {path}: {source}")]
    InvalidPom {
        path: String,
        #[source]
        source: PomError,
    },
    #[error(
        "module `{module}` declared by {declaring_pom} escapes canonical workspace root {workspace_root}"
    )]
    ModuleEscapes {
        module: String,
        declaring_pom: String,
        workspace_root: String,
    },
    #[error("module `{module}` declared by {declaring_pom} does not resolve to a pom.xml")]
    InvalidModule {
        module: String,
        declaring_pom: String,
    },
    #[error("aggregation cycle detected: {}", .cycle.join(" -> "))]
    AggregationCycle { cycle: Vec<String> },
    #[error("duplicate effective GAV {gav}: declared by both {first_pom} and {second_pom}")]
    DuplicateGav {
        gav: Gav,
        first_pom: String,
        second_pom: String,
    },
    #[error("{path} exceeds the {limit}-byte project input limit")]
    ProjectInputTooLarge { path: String, limit: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitState {
    Visiting,
    Done,
}

struct Scanner {
    root: PathBuf,
    /// Containment boundary for `<relativePath>` parents; see
    /// [`local_parent_boundary`]. Usually `root`, widened by one directory
    /// while probing a single selected module.
    parent_boundary: PathBuf,
    activation: ActivationContext,
    /// Reactor root `.mvn/maven.config`, overlaid on every module POM before
    /// inheritance exactly as resolution overlays it.
    maven_config: MavenConfig,
    modules: Vec<WorkspaceModule>,
    gav_index: HashMap<Gav, usize>,
    ga_index: HashMap<(String, String), Vec<usize>>,
    states: HashMap<PathBuf, VisitState>,
    stack: Vec<PathBuf>,
}

#[derive(Clone)]
struct DiscoveryPomFetcher;

impl RemotePomFetcher for DiscoveryPomFetcher {
    fn fetch_pom_by_coord(&self, _coord: &Coord) -> Result<Option<Pom>, PomError> {
        Ok(None)
    }
}

struct DiscoveryParentResolver {
    base: ParentResolverBase<DiscoveryPomFetcher>,
}

impl rv_maven_model::ParentResolver for DiscoveryParentResolver {
    fn resolve_parent(&self, parent: &rv_maven_model::Parent) -> Result<Option<Pom>, PomError> {
        self.base.resolve_parent(parent)
    }

    fn strict_parent_resolution(&self) -> bool {
        false
    }
}

impl Scanner {
    fn visit(&mut self, canonical_pom: PathBuf) -> Result<(), WorkspaceError> {
        match self.states.get(&canonical_pom) {
            Some(VisitState::Done) => return Ok(()),
            Some(VisitState::Visiting) => {
                let cycle_start = self
                    .stack
                    .iter()
                    .position(|path| path == &canonical_pom)
                    .unwrap_or(0);
                let cycle = self.stack[cycle_start..]
                    .iter()
                    .chain(std::iter::once(&canonical_pom))
                    .map(|path| normalized_relative_pom(&self.root, path))
                    .collect();
                return Err(WorkspaceError::AggregationCycle { cycle });
            }
            None => {}
        }

        self.states
            .insert(canonical_pom.clone(), VisitState::Visiting);
        self.stack.push(canonical_pom.clone());

        let pom_path = normalized_relative_pom(&self.root, &canonical_pom);
        let xml = read_project_input(&canonical_pom)?;
        let pom = Pom::parse(&xml).map_err(|source| WorkspaceError::InvalidPom {
            path: pom_path.clone(),
            source,
        })?;
        let mut module_activation = self.activation.clone();
        module_activation.base_dir = canonical_pom.parent().map(Path::to_path_buf);
        let mut parent_base = ParentResolverBase::new(
            canonical_pom.parent().map(Path::to_path_buf),
            DiscoveryPomFetcher,
            false,
        );
        parent_base.project_root = Some(self.parent_boundary.clone());
        // Resolution overlays the reactor root's `-D` user properties on a
        // module POM before building its model, so a `<parent>` version that
        // interpolates one of them names a real parent there. Discovery has to
        // overlay them too, or it walks a shorter chain — or fails outright on
        // the unexpanded version — for a module resolution handles fine.
        let mut inherited_pom = pom.clone();
        self.maven_config.inject_properties(&mut inherited_pom);
        let descriptor = inherited_pom
            .effective_descriptor_with_inheritance(
                DiscoveryParentResolver { base: parent_base },
                &module_activation,
            )
            .map_err(|source| WorkspaceError::InvalidPom {
                path: pom_path.clone(),
                source,
            })?;

        if let Some(existing_index) = self.gav_index.get(&descriptor.gav) {
            let first_pom = self.modules[*existing_index].pom_path.clone();
            return Err(WorkspaceError::DuplicateGav {
                gav: descriptor.gav,
                first_pom,
                second_pom: pom_path,
            });
        }

        let module_entries = descriptor.modules.clone();
        let index = self.modules.len();
        self.gav_index.insert(descriptor.gav.clone(), index);
        self.ga_index
            .entry((
                descriptor.gav.group_id.clone(),
                descriptor.gav.artifact_id.clone(),
            ))
            .or_default()
            .push(index);
        self.modules.push(WorkspaceModule {
            pom_path,
            descriptor,
            pom,
        });

        for module_entry in module_entries {
            let module_pom = self.resolve_module(&canonical_pom, &module_entry)?;
            self.visit(module_pom)?;
        }

        self.stack.pop();
        self.states.insert(canonical_pom, VisitState::Done);
        Ok(())
    }

    fn resolve_module(
        &self,
        declaring_pom: &Path,
        module_entry: &str,
    ) -> Result<PathBuf, WorkspaceError> {
        let declaring_pom_relative = normalized_relative_pom(&self.root, declaring_pom);
        let module_entry = module_entry.trim();
        if module_entry.is_empty() {
            return Err(WorkspaceError::InvalidModule {
                module: module_entry.to_string(),
                declaring_pom: declaring_pom_relative,
            });
        }

        // Accept either platform separator on every host, then canonicalize
        // so aliases and symlinks share one identity.
        let portable_entry = module_entry.replace('\\', "/");
        let declaring_dir = declaring_pom.parent().unwrap_or(&self.root);
        let candidate = declaring_dir.join(&portable_entry);
        let candidate = match fs::metadata(&candidate) {
            Ok(metadata) if metadata.is_dir() => candidate.join("pom.xml"),
            Ok(_) => candidate,
            Err(source) => {
                let pom_candidate = if candidate.extension().is_some() {
                    candidate
                } else {
                    candidate.join("pom.xml")
                };
                return Err(WorkspaceError::Io {
                    path: pom_candidate.display().to_string(),
                    source,
                });
            }
        };
        let canonical = fs::canonicalize(&candidate).map_err(|source| WorkspaceError::Io {
            path: candidate.display().to_string(),
            source,
        })?;

        if !canonical.starts_with(&self.root) {
            return Err(WorkspaceError::ModuleEscapes {
                module: module_entry.to_string(),
                declaring_pom: declaring_pom_relative,
                workspace_root: self.root.display().to_string(),
            });
        }
        if canonical.file_name().and_then(|name| name.to_str()) != Some("pom.xml")
            || !canonical.is_file()
        {
            return Err(WorkspaceError::InvalidModule {
                module: module_entry.to_string(),
                declaring_pom: declaring_pom_relative,
            });
        }

        Ok(canonical)
    }
}

fn canonical_reactor_root(root: &Path) -> Result<(PathBuf, PathBuf), WorkspaceError> {
    let metadata = fs::metadata(root).map_err(|source| WorkspaceError::Io {
        path: root.display().to_string(),
        source,
    })?;
    let (root_dir, root_pom) = if metadata.is_dir() {
        (root.to_path_buf(), root.join("pom.xml"))
    } else if metadata.is_file()
        && root.file_name().and_then(|name| name.to_str()) == Some("pom.xml")
    {
        let Some(parent) = root.parent() else {
            return Err(WorkspaceError::InvalidRoot {
                path: root.display().to_string(),
            });
        };
        (parent.to_path_buf(), root.to_path_buf())
    } else {
        return Err(WorkspaceError::InvalidRoot {
            path: root.display().to_string(),
        });
    };

    let canonical_root = fs::canonicalize(&root_dir).map_err(|source| WorkspaceError::Io {
        path: root_dir.display().to_string(),
        source,
    })?;
    let canonical_pom = fs::canonicalize(&root_pom).map_err(|source| WorkspaceError::Io {
        path: root_pom.display().to_string(),
        source,
    })?;
    if !canonical_pom.starts_with(&canonical_root)
        || canonical_pom.file_name().and_then(|name| name.to_str()) != Some("pom.xml")
        || !canonical_pom.is_file()
    {
        return Err(WorkspaceError::InvalidRoot {
            path: root.display().to_string(),
        });
    }
    Ok((canonical_root, canonical_pom))
}

/// Read a project input (a module POM, `.mvn/maven.config`) under
/// [`rv_config::MAX_PROJECT_INPUT_SIZE`] so a huge file cannot drive an
/// unbounded allocation during discovery.
fn read_project_input(path: &Path) -> Result<String, WorkspaceError> {
    rv_config::read_project_input_string(path).map_err(|error| workspace_input_error(path, error))
}

fn workspace_input_error(path: &Path, error: rv_config::ConfigError) -> WorkspaceError {
    let path = path.display().to_string();
    match error {
        rv_config::ConfigError::ProjectInputIo { source, .. } => {
            WorkspaceError::Io { path, source }
        }
        rv_config::ConfigError::ProjectInputTooLarge { limit, .. } => {
            WorkspaceError::ProjectInputTooLarge { path, limit }
        }
        // Matches what an unbounded `read_to_string` reported for non-UTF-8
        // input, so callers see no new failure shape.
        other => WorkspaceError::Io {
            path,
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
        },
    }
}

fn normalized_relative_pom(root: &Path, pom: &Path) -> String {
    pom.strip_prefix(root)
        .unwrap_or(pom)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[derive(Debug, Clone, Default)]
struct MavenConfig {
    properties: HashMap<String, String>,
    active_profiles: Vec<String>,
    inactive_profiles: Vec<String>,
}

impl MavenConfig {
    fn read(root: &Path) -> Result<Self, WorkspaceError> {
        let path = root.join(".mvn").join("maven.config");
        match rv_config::read_optional_project_input_string(&path) {
            Ok(Some(content)) => Ok(Self::parse(&content)),
            Ok(None) => Ok(Self::default()),
            Err(error) => Err(workspace_input_error(&path, error)),
        }
    }

    fn parse(content: &str) -> Self {
        let tokens: Vec<&str> = content.split_whitespace().collect();
        let mut config = Self::default();
        let mut index = 0;
        while index < tokens.len() {
            let token = tokens[index];
            if token == "-D" {
                if let Some(property) = tokens.get(index + 1) {
                    config.add_property(property);
                    index += 1;
                }
            } else if let Some(property) = token.strip_prefix("-D") {
                config.add_property(property);
            } else if token == "-P" || token == "-!P" {
                if let Some(profiles) = tokens.get(index + 1) {
                    config.add_profiles(profiles, token == "-!P");
                    index += 1;
                }
            } else if let Some(profiles) = token.strip_prefix("-!P") {
                config.add_profiles(profiles.trim_start_matches('='), true);
            } else if let Some(profiles) = token.strip_prefix("-P") {
                config.add_profiles(profiles.trim_start_matches('='), false);
            }
            index += 1;
        }
        config
    }

    fn add_property(&mut self, property: &str) {
        let (key, value) = property.split_once('=').unwrap_or((property, "true"));
        if !key.is_empty() {
            self.properties.insert(key.to_string(), value.to_string());
        }
    }

    fn add_profiles(&mut self, profiles: &str, force_inactive: bool) {
        for profile in profiles.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (inactive, profile) = if force_inactive {
                (true, profile.trim_start_matches(['!', '-', '+']))
            } else if let Some(profile) = profile.strip_prefix(['!', '-']) {
                (true, profile)
            } else {
                (false, profile.trim_start_matches('+'))
            };
            if profile.is_empty() {
                continue;
            }
            let destination = if inactive {
                &mut self.inactive_profiles
            } else {
                &mut self.active_profiles
            };
            if !destination.iter().any(|existing| existing == profile) {
                destination.push(profile.to_string());
            }
        }
    }

    /// Overlay the `-D` entries on a POM's own `<properties>`.
    ///
    /// Maven user properties sit above POM properties, so a same-named entry
    /// overwrites. Resolution does this to every POM it builds a model from;
    /// discovery does it to every module POM before inheritance so both name
    /// the same `<parent>` when the declaration interpolates a property only
    /// `.mvn/maven.config` supplies.
    fn inject_properties(&self, pom: &mut Pom) {
        for (key, value) in &self.properties {
            pom.properties.insert(key, value);
        }
    }

    fn apply(&self, activation: &mut ActivationContext) {
        activation.properties.extend(self.properties.clone());
        append_unique(
            &mut activation.active_profiles,
            self.active_profiles.clone(),
        );
        append_unique(
            &mut activation.inactive_profiles,
            self.inactive_profiles.clone(),
        );
    }
}

fn append_unique(destination: &mut Vec<String>, values: Vec<String>) {
    let mut seen: HashSet<String> = destination.iter().cloned().collect();
    for value in values {
        if seen.insert(value.clone()) {
            destination.push(value);
        }
    }
}

/// Pinned refs for the manually cloned acceptance corpus.
///
/// The acceptance tests assert exact reactor shapes, which are properties of a
/// specific upstream ref and not of a moving default branch. Both projects add
/// and remove modules on trunk (pdfbox trunk swapped `preflight*` for
/// `pdfbox-layout-*` and grew a module past what these tests expect), so the
/// corpus must be cloned at the tags below or the counts here are meaningless.
#[cfg(test)]
pub(crate) mod corpus {
    /// Release tag the `pdfbox` checkout must be cloned at.
    pub(crate) const PDFBOX_REF: &str = "3.0.5";
    /// Release tag the `dropwizard` checkout must be cloned at.
    pub(crate) const DROPWIZARD_REF: &str = "v5.0.2";

    /// Reactor size of `apache/pdfbox` at [`PDFBOX_REF`]: the root POM plus its
    /// 12 declared modules.
    pub(crate) const PDFBOX_MODULE_COUNT: usize = 13;

    /// Reactor size of `dropwizard/dropwizard` at [`DROPWIZARD_REF`]: the root
    /// POM plus every module reachable once the `all-modules` profile turns on
    /// `docs`, `dropwizard-e2e` and `dropwizard-benchmarks`.
    pub(crate) const DROPWIZARD_MODULE_COUNT: usize = 42;

    /// Assertion hint that points at corpus drift rather than at discovery.
    ///
    /// A mismatch here is nearly always an unpinned or stale checkout, so say
    /// so instead of leaving the developer to suspect the reactor walk.
    pub(crate) fn corpus_drift_hint(project: &str, expected_ref: &str) -> String {
        format!(
            "acceptance corpus for `{project}` looks like the wrong ref: these counts are pinned \
             to `{expected_ref}`. Re-clone with `git clone --depth 1 --branch {expected_ref}` \
             before suspecting reactor discovery."
        )
    }

    /// Clone command for a pinned corpus checkout, for skip/diagnostic output.
    pub(crate) fn clone_hint() -> String {
        format!(
            "clone the corpus pinned: `git clone --depth 1 --branch {PDFBOX_REF} \
             https://github.com/apache/pdfbox.git pdfbox` and `git clone --depth 1 --branch \
             {DROPWIZARD_REF} https://github.com/dropwizard/dropwizard.git dropwizard`"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::corpus::{DROPWIZARD_MODULE_COUNT, PDFBOX_MODULE_COUNT, corpus_drift_hint};
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("test-fixtures")
            .join("reactor-discovery")
            .join(name)
    }

    fn gav(group_id: &str, artifact_id: &str, version: &str) -> Gav {
        Gav {
            group_id: group_id.to_string(),
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
        }
    }

    #[test]
    fn discovers_profile_modules_and_propagates_root_config() {
        let workspace = Workspace::discover(fixture("profile-config")).expect("discover workspace");
        let paths: Vec<&str> = workspace
            .modules()
            .iter()
            .map(|module| module.pom_path.as_str())
            .collect();

        assert_eq!(paths, ["pom.xml", "module-a/pom.xml", "extra/pom.xml"]);
        assert_eq!(
            workspace.modules()[0].descriptor.active_profiles,
            ["extras"]
        );
        assert!(
            paths.iter().all(|path| !path.contains("disabled")),
            "explicitly inactive profile module must not be discovered"
        );
        assert!(
            workspace
                .get(&gav("com.example", "module-a", "2.5.0"))
                .is_some(),
            "root -Drevision must override module-local maven.config"
        );
        assert!(
            workspace
                .get(&gav("com.example", "extra", "2.5.0"))
                .is_some()
        );
    }

    #[test]
    fn discovers_nested_aggregators_and_dedupes_canonical_poms() {
        let workspace = Workspace::discover(fixture("nested-dedup")).expect("discover workspace");
        let paths: Vec<&str> = workspace
            .modules()
            .iter()
            .map(|module| module.pom_path.as_str())
            .collect();

        assert_eq!(paths, ["pom.xml", "aggregator/pom.xml", "leaf/pom.xml"]);
        assert_eq!(workspace.len(), 3);
    }

    #[test]
    fn indexes_child_gav_with_inherited_parent_property() {
        let workspace =
            Workspace::discover(fixture("inherited-properties")).expect("discover workspace");

        assert!(
            workspace
                .get(&gav("com.example", "revision-child", "2.5.0"))
                .is_some(),
            "the child GAV must interpolate properties inherited from its local parent"
        );
        assert!(
            workspace
                .get(&gav("com.example", "reactor", "2.5.0"))
                .is_some(),
            "an aggregator whose parent is one of its modules must inherit before indexing"
        );
    }

    /// A single selected module's immediate `../pom.xml` is the one parent
    /// outside the reactor root that resolution accepts, so discovery must
    /// accept it too: without it the child's `${revision}` version never
    /// interpolates and discovery fails before resolution's allowance applies.
    #[test]
    fn discovers_single_module_with_immediate_external_parent() {
        let workspace = Workspace::discover(fixture("external-parent").join("child"))
            .expect("discover selected module");

        assert_eq!(workspace.len(), 1);
        assert!(
            workspace
                .get(&gav("com.example", "selected-child", "2.5.0"))
                .is_some(),
            "the external parent's property must interpolate the child's version"
        );
    }

    /// The same external parent is rejected when it does not carry the
    /// coordinates the child declared, exactly as resolution rejects it.
    #[test]
    fn rejects_external_parent_with_mismatched_coordinates() {
        let workspace = Workspace::discover(fixture("external-parent-mismatch").join("child"))
            .expect("discover selected module");

        assert_eq!(
            workspace.modules()[0].gav().version,
            "${revision}",
            "a parent whose coordinates do not match the declaration must not \
             contribute properties; the version stays uninterpolated"
        );
    }

    #[test]
    fn reports_aggregation_cycles() {
        let error = Workspace::discover(fixture("cycle")).expect_err("cycle must fail");

        match error {
            WorkspaceError::AggregationCycle { cycle } => {
                assert_eq!(cycle, ["pom.xml", "a/pom.xml", "pom.xml"]);
            }
            other => panic!("expected aggregation cycle, got {other}"),
        }
    }

    #[test]
    fn reports_duplicate_effective_gav() {
        let error =
            Workspace::discover(fixture("duplicate-gav")).expect_err("duplicate GAV must fail");

        match error {
            WorkspaceError::DuplicateGav {
                gav,
                first_pom,
                second_pom,
            } => {
                assert_eq!(gav.to_string(), "com.example:duplicate:1");
                assert_eq!(first_pom, "a/pom.xml");
                assert_eq!(second_pom, "b/pom.xml");
            }
            other => panic!("expected duplicate GAV, got {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_real_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let workspace_root = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&workspace_root).expect("create workspace");
        fs::create_dir_all(&outside).expect("create outside");
        fs::copy(
            fixture("symlink-escape").join("pom.xml"),
            workspace_root.join("pom.xml"),
        )
        .expect("copy fixture");
        fs::write(
            outside.join("pom.xml"),
            r#"
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>outside</artifactId>
              <version>1</version>
            </project>
            "#,
        )
        .expect("write outside POM");
        symlink(&outside, workspace_root.join("escape")).expect("create real symlink");

        let error = Workspace::discover(&workspace_root).expect_err("escape must fail");

        assert!(matches!(error, WorkspaceError::ModuleEscapes { .. }));
    }

    /// A module whose `<parent>` version interpolates a property only the
    /// reactor root's `.mvn/maven.config` supplies. Resolution overlays those
    /// `-D` entries on the module POM before inheritance and loads the parent,
    /// so discovery must overlay them too — otherwise it indexes a module
    /// resolution never produces, or (as here, where the unexpanded version is
    /// not a coordinate) fails on a reactor Maven builds fine.
    #[test]
    fn discovers_a_module_whose_parent_version_comes_from_maven_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        fs::create_dir_all(root.join(".mvn")).expect("create .mvn");
        fs::write(
            root.join(".mvn").join("maven.config"),
            "-DparentVersion=1.2.3\n",
        )
        .expect("write maven.config");
        fs::write(
            root.join("pom.xml"),
            r#"
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>root</artifactId>
              <version>1.2.3</version>
              <packaging>pom</packaging>
              <properties><localrev>7.7.7</localrev></properties>
              <modules><module>child</module></modules>
            </project>
            "#,
        )
        .expect("write root POM");
        let module_dir = root.join("child");
        fs::create_dir_all(&module_dir).expect("create module");
        fs::write(
            module_dir.join("pom.xml"),
            r#"
            <project>
              <modelVersion>4.0.0</modelVersion>
              <parent>
                <groupId>com.example</groupId>
                <artifactId>root</artifactId>
                <version>${parentVersion}</version>
                <relativePath>../pom.xml</relativePath>
              </parent>
              <artifactId>child</artifactId>
              <version>${localrev}</version>
            </project>
            "#,
        )
        .expect("write module POM");

        let workspace = Workspace::discover(root).expect("discover workspace");

        // `localrev` is declared only by the parent, so the effective version
        // proves inheritance walked to it.
        assert!(
            workspace
                .get(&gav("com.example", "child", "7.7.7"))
                .is_some(),
            "module GAVs: {:?}",
            workspace
                .modules()
                .iter()
                .map(|module| module.gav().to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            workspace.user_properties().get("parentVersion").cloned(),
            Some("1.2.3".to_string()),
            "the hash walker needs these same entries to name that parent"
        );
    }

    /// Discovery reads module POMs under the project input limit, so a huge
    /// module POM fails with a typed error instead of being read whole.
    #[test]
    fn rejects_oversized_module_pom() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        fs::write(
            root.join("pom.xml"),
            r#"
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>root</artifactId>
              <version>1</version>
              <packaging>pom</packaging>
              <modules><module>big</module></modules>
            </project>
            "#,
        )
        .expect("write root POM");
        let module_dir = root.join("big");
        fs::create_dir_all(&module_dir).expect("create module");
        fs::write(
            module_dir.join("pom.xml"),
            vec![b'x'; rv_config::MAX_PROJECT_INPUT_SIZE + 1],
        )
        .expect("write oversized module POM");

        let error = Workspace::discover(root).expect_err("oversized module POM must fail");

        assert!(
            matches!(error, WorkspaceError::ProjectInputTooLarge { .. }),
            "expected a project input limit error, got {error}"
        );
    }

    /// The reactor root's `.mvn/maven.config` is bounded the same way.
    #[test]
    fn rejects_oversized_maven_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        fs::write(
            root.join("pom.xml"),
            r#"
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>root</artifactId>
              <version>1</version>
            </project>
            "#,
        )
        .expect("write root POM");
        let mvn_dir = root.join(".mvn");
        fs::create_dir_all(&mvn_dir).expect("create .mvn");
        fs::write(
            mvn_dir.join("maven.config"),
            vec![b'x'; rv_config::MAX_PROJECT_INPUT_SIZE + 1],
        )
        .expect("write oversized maven.config");

        let error = Workspace::discover(root).expect_err("oversized maven.config must fail");

        assert!(
            matches!(error, WorkspaceError::ProjectInputTooLarge { .. }),
            "expected a project input limit error, got {error}"
        );
    }

    #[test]
    fn parses_comma_profiles_and_explicit_inactive_switch() {
        let config = MavenConfig::parse("-Palpha,beta,!off -!Plegacy,unused");

        assert_eq!(config.active_profiles, ["alpha", "beta"]);
        assert_eq!(config.inactive_profiles, ["off", "legacy", "unused"]);
    }

    #[test]
    fn parses_properties_after_standalone_d_switch() {
        let config = MavenConfig::parse("-D\nrevision=2.5.0\n-D\napache.snapshots");

        assert_eq!(
            config.properties.get("revision").map(String::as_str),
            Some("2.5.0")
        );
        assert_eq!(
            config
                .properties
                .get("apache.snapshots")
                .map(String::as_str),
            Some("true")
        );
    }

    /// Discovers the reactors in the manually cloned acceptance corpus.
    ///
    /// The corpus is PINNED: the module counts below are properties of these
    /// exact refs, not of the projects' default branches (upstream trunk adds
    /// and removes modules, so an unpinned checkout drifts and fails here for
    /// reasons that have nothing to do with discovery). Clone with:
    ///
    /// ```sh
    /// git clone --depth 1 --branch 3.0.5 https://github.com/apache/pdfbox.git pdfbox
    /// git clone --depth 1 --branch v5.0.2 https://github.com/dropwizard/dropwizard.git dropwizard
    /// ```
    ///
    /// Set `RV_ACCEPTANCE_CORPUS` to the directory that holds those two
    /// checkouts. The test skips when the variable is unset.
    #[test]
    #[ignore = "requires the manually cloned acceptance corpus"]
    fn discovers_real_pdfbox_and_dropwizard_reactors() {
        let Ok(corpus_root) = std::env::var("RV_ACCEPTANCE_CORPUS") else {
            println!(
                "skipping: set RV_ACCEPTANCE_CORPUS to the acceptance corpus directory to run \
                 this test ({})",
                super::corpus::clone_hint()
            );
            return;
        };
        let corpus_root = Path::new(&corpus_root);

        let pdfbox =
            Workspace::discover(corpus_root.join("pdfbox")).expect("discover real pdfbox reactor");
        println!("pdfbox: {} modules", pdfbox.len());
        assert_eq!(
            pdfbox.len(),
            PDFBOX_MODULE_COUNT,
            "{}",
            corpus_drift_hint("pdfbox", "3.0.5")
        );
        assert!(
            pdfbox
                .modules()
                .iter()
                .any(|module| module.pom_path == "parent/pom.xml"),
            "{}",
            corpus_drift_hint("pdfbox", "3.0.5")
        );

        let dropwizard = Workspace::discover(corpus_root.join("dropwizard"))
            .expect("discover real dropwizard reactor");
        println!("dropwizard: {} modules", dropwizard.len());
        assert_eq!(
            dropwizard.len(),
            DROPWIZARD_MODULE_COUNT,
            "{}",
            corpus_drift_hint("dropwizard", "v5.0.2")
        );
        assert!(
            dropwizard.modules()[0]
                .descriptor
                .active_profiles
                .iter()
                .any(|profile| profile == "all-modules")
        );
        for profile_module in [
            "docs/pom.xml",
            "dropwizard-e2e/pom.xml",
            "dropwizard-benchmarks/pom.xml",
        ] {
            assert!(
                dropwizard
                    .modules()
                    .iter()
                    .any(|module| module.pom_path == profile_module),
                "missing profile-declared module {profile_module}; {}",
                corpus_drift_hint("dropwizard", "v5.0.2")
            );
        }
    }
}
