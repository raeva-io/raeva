use std::collections::{BTreeMap, HashMap, btree_map::Entry};
use std::io::Read;
use std::sync::Mutex;

use rv_config::Config;
use rv_lock::{LockModule, LockPlatform};
use rv_maven_model::{ImportCoord, ModelSource, Parent, ParentLookup, Pom, PomError};
use rv_maven_types::{BlobId, Sha256, Version};
use rv_sbom::License;
use rv_store::Store;

use crate::error::{CliError, Result};

pub(crate) fn populate(
    config: &Config,
    platform: &LockPlatform,
    workspace: &rv_resolver::Workspace,
    modules: &[&LockModule],
    licenses: &mut BTreeMap<String, Vec<License>>,
) -> Result<()> {
    let config = &config.for_platforms([(
        platform.platform.os(),
        platform.platform.arch(),
        platform.platform.jdk(),
    )]);
    // Resolution indexed the reactor by effective GAVs, which discovery
    // cannot know where a remote parent decides one.
    let gavs: Vec<_> = (workspace.modules().iter().enumerate())
        .filter(|(_, module)| module.descriptor.gav_is_provisional())
        .filter_map(|(index, module)| {
            let locked = (platform.modules.iter()).find(|locked| locked.path == module.pom_path)?;
            Some((
                index,
                rv_maven_model::Gav {
                    group_id: locked.gav.group.to_string(),
                    artifact_id: locked.gav.artifact.to_string(),
                    version: locked.gav.version().to_owned(),
                },
            ))
        })
        .collect();
    let effective;
    let workspace = if gavs.is_empty() {
        workspace
    } else {
        effective = (workspace.with_effective_gavs(gavs))
            .map_err(|error| CliError::lockfile_mismatch(error.to_string()))?;
        &effective
    };
    let evidence = PinnedPoms::new(config, platform)?;
    let mut module_by_gav = HashMap::new();
    for module in &platform.modules {
        module_by_gav
            .entry(module.gav.to_string())
            .or_insert(module);
    }
    // Each module's components, with the effective model to build for each
    // one that has a Maven descriptor. A component's effective licenses depend
    // only on its coordinates and the parent range selections recorded for
    // them, so modules that share a component build it once.
    let mut inventories = Vec::with_capacity(modules.len());
    let mut keys = Vec::new();
    let mut first_use = HashMap::new();
    for module in modules {
        let inventory =
            match crate::commands::lock_adapter::adapt_sbom_modules(platform, &[*module]) {
                Ok(inventory) => inventory,
                Err(err) => {
                    // Reported in turn, after what the modules before it give.
                    inventories.push(Err(CliError::LockfileDefect {
                        details: err.to_string(),
                    }));
                    break;
                }
            };
        let mut components = Vec::new();
        for component in std::iter::once(inventory.root).chain(inventory.components) {
            let gav = format!(
                "{}:{}:{}",
                component.group.as_deref().unwrap_or_default(),
                component.name,
                component.version
            );
            let reactor = module_by_gav.get(&gav).copied();
            // A locked dependency may legitimately have no Maven descriptor.
            let build = (evidence.pins.contains_key(&gav) || reactor.is_some()).then(|| {
                // A reactor module's model is its own, whichever module
                // depends on it.
                let selections: BTreeMap<&str, &str> = reactor
                    .unwrap_or(module)
                    .parent_ranges
                    .iter()
                    .filter(|selection| selection.model == gav)
                    .map(|selection| (selection.parent.as_str(), selection.selected.as_str()))
                    .collect();
                *first_use
                    .entry((gav.clone(), selections))
                    .or_insert_with_key(|key| {
                        keys.push(key.clone());
                        keys.len() - 1
                    })
            });
            components.push((gav, component.purl, build));
        }
        inventories.push(Ok(components));
    }
    let mut built: Vec<_> = rv_maven_model::held::par_map_held(&keys, |key| {
        effective_licenses(
            config,
            platform,
            workspace,
            &evidence,
            module_by_gav.get(&key.0).copied(),
            key,
        )
    })
    .into_iter()
    .map(|(mapped, held)| Some((mapped, held)))
    .collect();
    let mut shown = vec![None; keys.len()];
    for components in inventories {
        let mut model_licenses = BTreeMap::new();
        for (gav, purl, build) in components? {
            if let Entry::Vacant(entry) = model_licenses.entry(gav.clone()) {
                entry.insert(match build {
                    None => Vec::new(),
                    Some(index) => {
                        if let Some((mapped, held)) = built[index].take() {
                            held.show();
                            shown[index] = Some(mapped?);
                        }
                        shown[index].clone().expect("a shown build succeeded")
                    }
                });
            }
            let mapped = model_licenses[&gav].clone();
            if let Some(previous) = licenses.insert(purl.clone(), mapped.clone())
                && (previous.len() != mapped.len()
                    || previous.iter().any(|license| !mapped.contains(license)))
            {
                return Err(CliError::Usage(format!(
                    "cannot combine the selected SBOM modules or targets: {purl} has different effective licenses; pass --module, --platform and --jdk to select one context"
                )));
            }
        }
    }
    Ok(())
}

/// The licenses of `gav`'s effective model: a reactor module's from its local
/// POM, a dependency's from its pinned POM.
fn effective_licenses(
    config: &Config,
    platform: &LockPlatform,
    workspace: &rv_resolver::Workspace,
    evidence: &PinnedPoms,
    reactor_module: Option<&LockModule>,
    (gav, selections): &(String, BTreeMap<&str, &str>),
) -> Result<Vec<License>> {
    let source = PinnedModel {
        evidence,
        selections: selections.clone(),
        dependency: reactor_module.is_none(),
    };
    let licenses = if let Some(module) = reactor_module {
        let module = (workspace.modules().iter())
            .find(|candidate| candidate.pom_path == module.path)
            .ok_or_else(|| {
                CliError::lockfile_mismatch(format!(
                    "raeva.lock records module {}, which the reactor no longer has",
                    module.path
                ))
            })?;
        rv_maven_model::ready(workspace.module_metadata(
            module,
            config,
            &platform.platform,
            &source,
        ))
        .map_err(|error| failure(gav, Some(&module.pom_path), error))?
        .licenses
    } else {
        match evidence.read(gav) {
            Ok(pom) => {
                rv_maven_model::ready(workspace.dependency_metadata(
                    pom,
                    config,
                    &platform.platform,
                    &source,
                ))
                .map_err(|error| failure(gav, None, error))?
                .licenses
            }
            // Resolution keeps such a dependency without its model.
            Err(EvidenceError::Model(error))
                if error.is_malformed_xml() || error.is_deserialize() =>
            {
                Vec::new()
            }
            Err(error) => return Err(failure(gav, None, error)),
        }
    };
    let mut mapped = Vec::new();
    for license in licenses {
        if let Some(license) = License::from_maven(license.name.as_deref(), license.url.as_deref())
            && !mapped.contains(&license)
        {
            mapped.push(license);
        }
    }
    Ok(mapped)
}

/// The error for `gav`'s license evidence, built from the module POM at
/// `module` when it is a reactor module.
fn failure(gav: &str, module: Option<&str>, error: EvidenceError) -> CliError {
    let details = |reason: String| format!("cannot read SBOM license evidence for {gav}: {reason}");
    match error {
        EvidenceError::Model(source) => match module {
            Some(path) => CliError::Resolve(rv_resolver::ResolveError::LocalPom {
                path: path.to_string(),
                source,
            }),
            None => CliError::Resolve(rv_resolver::ResolveError::Pom(source)),
        },
        EvidenceError::Unstored(reason) => CliError::lockfile_mismatch_with(
            details(reason),
            "Run 'raeva sync --frozen' to restore locked POMs",
        ),
        EvidenceError::Defect(reason) => CliError::LockfileDefect {
            details: details(reason),
        },
    }
}

#[derive(Debug, thiserror::Error)]
enum EvidenceError {
    #[error(transparent)]
    Model(#[from] PomError),
    /// The content store lacks the pinned bytes.
    #[error("{0}")]
    Unstored(String),
    /// raeva.lock lacks the pin or selection the model needs.
    #[error("{0}")]
    Defect(String),
}

struct PinnedPoms {
    store: Store,
    pins: BTreeMap<String, Sha256>,
    /// Each POM read so far, by coordinates: parents are shared by many
    /// components.
    read: Mutex<HashMap<String, Pom>>,
    /// The coordinates of the platform's reactor modules.
    modules: std::collections::BTreeSet<String>,
}

impl PinnedPoms {
    fn new(config: &Config, platform: &LockPlatform) -> Result<Self> {
        let mut pins = BTreeMap::new();
        let mut insert = |gav: String, pin: Sha256| -> Result<()> {
            if let Some(previous) = pins.insert(gav.clone(), pin.clone())
                && previous != pin
            {
                return Err(failure(
                    &gav,
                    None,
                    EvidenceError::Defect(
                        "the lock pins different POM bytes for the same coordinates".into(),
                    ),
                ));
            }
            Ok(())
        };
        for artifact in &platform.artifacts {
            let pin = artifact.pom_sha256.as_ref().or_else(|| {
                artifact
                    .is_own_pom()
                    .then(|| {
                        artifact
                            .checksums
                            .iter()
                            .find_map(rv_maven_types::Digest::as_sha256)
                    })
                    .flatten()
            });
            if let Some(pin) = pin {
                insert(artifact.coordinate.gav.to_string(), pin.clone())?;
                insert(artifact.pom_gav().to_string(), pin.clone())?;
            }
        }
        for (gav, pom) in &platform.support_poms {
            insert(gav.clone(), pom.sha256.clone())?;
            if let Some(file) = pom.file_gav(gav) {
                insert(file.to_string(), pom.sha256.clone())?;
            }
        }
        Ok(Self {
            store: Store::open(&config.paths.store_dir)?,
            pins,
            read: Mutex::default(),
            modules: (platform.modules.iter())
                .map(|module| module.gav.to_string())
                .collect(),
        })
    }

    fn read(&self, gav: &str) -> std::result::Result<Pom, EvidenceError> {
        if let Some(pom) = self.read.lock().expect("POM cache lock").get(gav) {
            return Ok(pom.clone());
        }
        let unstored = |reason: &str| EvidenceError::Unstored(format!("POM {gav} {reason}"));
        let pin = (self.pins.get(gav)).ok_or_else(|| {
            EvidenceError::Defect(format!("POM {gav} has no SHA-256 pin in raeva.lock"))
        })?;
        let id: BlobId = pin.to_string().parse().expect("a SHA-256 is a blob id");
        let file = std::fs::File::open(self.store.get_path(&id))
            .map_err(|_| unstored("is unavailable in the content store"))?;
        let mut bytes = Vec::new();
        file.take(5 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| unstored("cannot be read from the content store"))?;
        if BlobId::from_bytes(&bytes) != id {
            return Err(unstored("does not match its locked SHA-256"));
        }
        let mut pom = Pom::parse(&rv_maven_model::decode_pom(&bytes)?)?;
        pom.set_provenance(rv_maven_model::Provenance::Dependency);
        if let Some(parent) = &mut pom.parent {
            parent.relative_path = Some(String::new());
        }
        self.read
            .lock()
            .expect("POM cache lock")
            .insert(gav.to_string(), pom.clone());
        Ok(pom)
    }
}

struct PinnedModel<'a> {
    evidence: &'a PinnedPoms,
    selections: BTreeMap<&'a str, &'a str>,
    /// Whether the model is a dependency's, whose parents resolution reads
    /// from the reactor first.
    dependency: bool,
}

impl ModelSource for PinnedModel<'_> {
    type Error = EvidenceError;

    async fn parent(
        &self,
        parent: &mut Parent,
        _lookup: ParentLookup,
    ) -> std::result::Result<Option<Pom>, Self::Error> {
        if let Some(range) = rv_maven_model::parent_version_range(parent) {
            let requested = format!(
                "{}:{}:{}",
                parent.group_id, parent.artifact_id, parent.version
            );
            let selected = self.selections.get(requested.as_str()).ok_or_else(|| {
                EvidenceError::Defect(format!("parent {requested} has no locked range selection"))
            })?;
            let (group, artifact, version) = rv_lock::split_support_pom_coord(selected)
                .ok_or_else(|| {
                    EvidenceError::Defect(format!("invalid parent selection {selected}"))
                })?;
            if group != parent.group_id
                || artifact != parent.artifact_id
                || !Version::parse(version).is_ok_and(|version| range.matches(&version))
            {
                return Err(EvidenceError::Defect(format!(
                    "parent selection {selected} does not match {requested}"
                )));
            }
            parent.version = version.to_string();
        }
        let gav = format!(
            "{}:{}:{}",
            parent.group_id, parent.artifact_id, parent.version
        );
        // The workspace has this one; see `Workspace::dependency_metadata`.
        if self.dependency && self.evidence.modules.contains(&gav) {
            return Ok(None);
        }
        self.evidence.read(&gav).map(Some)
    }

    async fn import(&self, _bom: ImportCoord<'_>) -> std::result::Result<Option<Pom>, Self::Error> {
        unreachable!("metadata builds do not import BOMs")
    }
}
