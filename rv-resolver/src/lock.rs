//! Assembling the resolutions of every requested platform into one lockfile.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use foldhash::{HashMap, HashMapExt};
use rv_config::Config;
use rv_lock::{
    AmbientInput, LockArtifact, LockError, LockModule, LockModulePackage, LockOrigins,
    LockPlatform, Lockfile, Platform, SupportPom, is_recordable_repo_id,
};
use rv_maven_model::HostInput;
use rv_maven_types::{ArtifactCoord, BlobId, Digest, Gav, Sha256};
use rv_repo::{Repository, normalize_repo_url};

use crate::error::{ConflictingPom, ResolveError};
use crate::output::{ResolvedArtifact, ResolvedPackage};
use crate::resolver::{SupportPomProvenance, WorkspaceResolution, pom_digest_text};

/// What one platform's entry in raeva.lock records about the model that
/// resolution started from.
#[derive(Debug, Clone, Copy)]
pub struct PlatformModel<'a> {
    /// The active profile ids used to compute the model hash.
    pub active_profiles: &'a [String],
    /// The digest of each module and local parent POM,
    /// keyed by path.
    pub pom_hashes: &'a BTreeMap<String, Sha256>,
    /// The same digests with each module's covering the whole reactor,
    /// recorded when [`WorkspaceResolution::reactor_through_dependencies`].
    pub whole_reactor_pom_hashes: &'a BTreeMap<String, Sha256>,
}

/// A lockfile assembled from fresh resolutions. Its repository origins are
/// still absolute: check them for aliases, then call
/// [`Lockfile::relativize_origins`].
#[derive(Debug)]
#[non_exhaustive]
pub struct AssembledLock {
    /// The assembled lockfile, not yet written anywhere.
    pub lock: Lockfile,
    /// The repositories resolution approved, one per id and normalized URL.
    pub trusted_repositories: Vec<Repository>,
    /// When more than one platform resolved, what each one's builds read:
    /// the reads of its reactor and of each module, unmerged.
    pub platform_reads: Vec<(Platform, Vec<BTreeSet<HostInput>>)>,
}

/// Why resolutions cannot become one lockfile.
#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    /// Modules or platforms disagree about bytes raeva.lock pins once (the
    /// `Conflicting*Bytes` variants), or a recorded digest does not parse.
    #[error(transparent)]
    Resolve(#[from] Box<ResolveError>),
    /// [`Lockfile`] refused a repository id or support POM pin it cannot
    /// record.
    #[error(transparent)]
    Lock(#[from] LockError),
    /// A `system` dependency whose file raeva.lock cannot record, named by the
    /// POM that declares it.
    #[error("invalid {}: {reason}", path.display())]
    SystemFile {
        /// The declaring module's POM, joined to the project root.
        path: PathBuf,
        /// The dependency and why its file cannot be recorded.
        reason: String,
    },
}

impl From<ResolveError> for AssembleError {
    fn from(error: ResolveError) -> Self {
        Self::Resolve(Box::new(error))
    }
}

/// The property and variable names among `reads`, as raeva.lock lists them.
/// A name it cannot hold fails the sync where the run's reads are listed.
fn read_names(reads: &BTreeSet<HostInput>) -> BTreeSet<AmbientInput> {
    (reads.iter())
        .filter_map(|input| match input {
            HostInput::UserProperty(name) => AmbientInput::user_property(name).ok(),
            HostInput::SettingsProperty(name) => AmbientInput::settings_property(name).ok(),
            HostInput::Env(name) => AmbientInput::env(name).ok(),
            // A condition the lock cannot list, or one past its limit, is
            // listed as the variable it tests.
            HostInput::Property { name, .. } => {
                let name = name.strip_prefix('!').unwrap_or(name);
                AmbientInput::env(name.strip_prefix("env.")?).ok()
            }
            _ => None,
        })
        .collect()
}

/// Turn the resolution of each platform into raeva.lock's rows.
///
/// Artifacts are shared by the modules of a platform, so two modules that
/// resolved different bytes for one coordinate fail, as do two modules or
/// platforms with different bytes for one companion or support POM: raeva.lock
/// pins one of each. When modules reach one artifact through different
/// repositories, the row names the one configured first and lists the others.
pub fn assemble(
    config: &Config,
    resolutions: Vec<(PlatformModel<'_>, WorkspaceResolution)>,
) -> Result<AssembledLock, AssembleError> {
    let mut lock = Lockfile::new();
    let mut trusted_repositories: BTreeMap<(String, Option<String>), Repository> = BTreeMap::new();
    let mut support_poms: BTreeMap<String, AggregateSupportPom> = BTreeMap::new();
    let mut companion_poms: BTreeMap<Gav, AggregateCompanionPom> = BTreeMap::new();
    let mut order = RepoOrder::new(config);
    // What aggregation leaves over is freed with the graphs, off this thread.
    let mut graphs = Vec::new();
    let mut leftovers = Vec::new();
    let split_reads = resolutions.len() > 1;
    let mut platform_reads = Vec::new();
    for (model, result) in resolutions {
        let mut repo_ids = rv_lock::RepoIds::new();
        let mut reads = Vec::new();
        let mut modules = Vec::with_capacity(result.modules.len());
        let mut module_reads = BTreeMap::new();
        let mut artifacts: BTreeMap<ArtifactCoord, AggregateArtifact> = BTreeMap::new();
        let mut platform_support: BTreeMap<String, AggregateSupportPom> = BTreeMap::new();
        let platform = result.platform;
        let pom_hashes = if result.reactor_through_dependencies {
            model.whole_reactor_pom_hashes
        } else {
            model.pom_hashes
        };

        for module in result.modules {
            let resolution = module.resolution;
            for repo in &resolution.trusted_repositories {
                trusted_repositories
                    .entry((normalize_repo_url(&repo.url), repo.id.clone()))
                    .or_insert_with(|| repo.clone());
            }
            for (url, id) in &resolution.repositories {
                // The URL is checked too: an unparsable POM URL is kept
                // verbatim and may hold a line break.
                if !is_recordable_repo_id(id) || !is_recordable_repo_id(url) {
                    continue;
                }
                repo_ids.entry(url.clone()).or_default().insert(id.clone());
            }
            for (coord, provenance) in &resolution.support_pom_provenance {
                merge_support_pom(&mut support_poms, coord, provenance, &module.pom_path)?;
                merge_support_pom(&mut platform_support, coord, provenance, &module.pom_path)?;
            }
            let mut duplicates = Vec::new();

            let mut packages = Vec::with_capacity(resolution.packages.len());
            for package in resolution.packages {
                packages.push(module_package(
                    &config.project_root,
                    &module.pom_path,
                    &package,
                )?);
                let Some(resolved) = package.artifact else {
                    continue;
                };
                merge_companion_pom(
                    &mut companion_poms,
                    &package.coordinate,
                    &resolved,
                    &platform,
                    &module.pom_path,
                )?;
                let rank = order.rank(&resolved.repo_url);
                // The POM may come from another repository than the jar.
                let pom_origin = (resolved.pom_repo_url.as_ref()).unwrap_or(&resolved.repo_url);
                if let Some(existing) = artifacts.get_mut(&package.coordinate) {
                    if existing.blob != resolved.blob {
                        return Err(ResolveError::ConflictingArtifactBytes {
                            coord: package.coordinate.to_string(),
                            first_module: existing.module_path.clone(),
                            second_module: module.pom_path.clone(),
                            first_blob: existing.blob.to_string(),
                            second_blob: resolved.blob.to_string(),
                        }
                        .into());
                    }
                    insert_new(&mut existing.origins, &resolved.repo_url);
                    insert_new(&mut existing.pom_origins, pom_origin);
                    if order.precedes(
                        (rank, &resolved.repo_url),
                        (existing.repo_rank, &existing.artifact.repo_url),
                    ) {
                        existing.artifact = lock_artifact(package.coordinate, resolved);
                        existing.repo_rank = rank;
                    } else {
                        duplicates.push((package.coordinate, resolved));
                    }
                    continue;
                }
                let (mut origins, mut pom_origins) = (BTreeSet::new(), BTreeSet::new());
                insert_new(&mut origins, &resolved.repo_url);
                insert_new(&mut pom_origins, pom_origin);
                let blob = resolved.blob.clone();
                artifacts.insert(
                    package.coordinate.clone(),
                    AggregateArtifact {
                        artifact: lock_artifact(package.coordinate, resolved),
                        blob,
                        module_path: module.pom_path.clone(),
                        repo_rank: rank,
                        origins,
                        pom_origins,
                    },
                );
            }

            module_reads.insert(module.pom_path.clone(), read_names(&resolution.host_reads));
            let mut host_reads = resolution.host_reads;
            if split_reads {
                reads.push(std::mem::take(&mut host_reads));
            }
            modules.push({
                let mut module = LockModule::new(
                    module.pom_path,
                    resolution.module_gav,
                    resolution.module_packaging,
                );
                module.packages = packages;
                module.edges = resolution.edges;
                module.parent_ranges = resolution.parent_ranges;
                module.support_poms = (resolution.support_pom_provenance.iter())
                    .map(|(coord, _)| coord.clone())
                    .collect();
                module.support_poms.sort();
                module
            });
            graphs.push(resolution.graph);
            leftovers.push((
                duplicates,
                resolution.support_pom_provenance,
                resolution.trusted_repositories,
                host_reads,
            ));
        }

        let mut entry = LockPlatform::new(platform, String::new());
        entry.artifacts = artifacts
            .into_values()
            .map(|mut aggregate| {
                let row = &mut aggregate.artifact;
                // A list that names the file's own origins is left out.
                if row.pom_sha256.is_some() && aggregate.pom_origins != aggregate.origins {
                    row.pom_repo_urls = aggregate.pom_origins.into_iter().collect();
                }
                aggregate.origins.remove(&row.repo_url);
                row.other_repo_urls = aggregate.origins.into_iter().collect();
                aggregate.artifact
            })
            .collect();
        entry.modules = modules;
        for (coord, aggregate) in platform_support {
            let provenance = aggregate.provenance;
            let sha256 = provenance.sha256.parse().map_err(|err| {
                ResolveError::InternalError(format!("support POM digest for {coord}: {err}"))
            })?;
            if !provenance.repo_id.is_empty()
                && is_recordable_repo_id(&provenance.repo_id)
                && is_recordable_repo_id(&provenance.repo_url)
            {
                repo_ids
                    .entry(provenance.repo_url.clone())
                    .or_default()
                    .insert(provenance.repo_id);
            }
            let mut pin = SupportPom::new(provenance.repo_url, sha256);
            pin.snapshot = provenance.snapshot;
            entry.support_poms.insert(coord, pin);
        }
        entry.repo_ids = Some(repo_ids);
        entry.set_model_inputs(model.active_profiles, pom_hashes);
        let inputs = entry.model_inputs.as_mut().expect("model inputs");
        inputs.ambient_inputs = read_names(&result.host_reads);
        if split_reads {
            reads.push(result.host_reads);
            platform_reads.push((entry.platform.clone(), reads));
        }
        inputs.module_ambient_inputs = module_reads;
        lock.platforms.push(entry);
    }

    crate::util::drop_in_background((graphs, leftovers));
    lock.platforms
        .sort_by(|a, b| a.platform.os_arch().cmp(&b.platform.os_arch()));

    // Each platform holds every id it used until the lock splits them.
    let reads: Vec<_> = (lock.platforms.iter())
        .map(|entry| {
            let mut reads = rv_lock::TargetReads::default();
            reads.repo_ids = entry.repo_ids.clone().unwrap_or_default();
            reads
        })
        .collect();
    lock.set_target_reads(&reads)?;

    Ok(AssembledLock {
        lock,
        trusted_repositories: trusted_repositories.into_values().collect(),
        platform_reads,
    })
}

fn module_package(
    project_root: &Path,
    pom_path: &str,
    package: &ResolvedPackage,
) -> Result<LockModulePackage, AssembleError> {
    let system_file = package
        .system_path
        .as_deref()
        .map(|path| {
            rv_lock::SystemFile::record(project_root, Path::new(path)).map_err(|err| {
                AssembleError::SystemFile {
                    path: project_root.join(pom_path),
                    reason: format!(
                        "system-scoped dependency {}: {err}{}",
                        rv_maven_types::bounded(&package.coordinate.to_string()),
                        if path.contains("${") {
                            " (it names a property that has no value)"
                        } else {
                            ""
                        }
                    ),
                }
            })
        })
        .transpose()?;
    Ok({
        let mut lock_package =
            LockModulePackage::new(package.coordinate.clone(), package.direct_scope);
        lock_package.scope = package.scope;
        lock_package.workspace_module = package.workspace_module.clone();
        lock_package.system_path = system_file.as_ref().map(|file| file.path.clone());
        lock_package.system_sha256 = system_file.map(|file| file.sha256);
        lock_package
    })
}

/// Inserts `url` unless it is empty or already there.
fn insert_new(set: &mut BTreeSet<String>, url: &str) {
    if !url.is_empty() && !set.contains(url) {
        set.insert(url.to_string());
    }
}

/// Which of two repositories an artifact row names: the earlier configured
/// one, then the lower origin key. Both are worked out once per URL.
struct RepoOrder {
    origins: LockOrigins,
    precedence: HashMap<String, usize>,
    known: HashMap<String, (usize, String)>,
}

impl RepoOrder {
    fn new(config: &Config) -> Self {
        let precedence = config
            .repositories()
            .iter()
            .enumerate()
            .map(|(index, repo)| (normalize_repo_url(&repo.url), index))
            .collect();
        Self {
            origins: LockOrigins::for_root(&config.project_root),
            precedence,
            known: HashMap::new(),
        }
    }

    fn known(&mut self, url: &str) -> &(usize, String) {
        if !self.known.contains_key(url) {
            let rank =
                (self.precedence.get(&normalize_repo_url(url)).copied()).unwrap_or(usize::MAX);
            let key = (self.origins.declared(url)).unwrap_or_else(|| normalize_repo_url(url));
            self.known.insert(url.to_string(), (rank, key));
        }
        &self.known[url]
    }

    fn rank(&mut self, url: &str) -> usize {
        self.known(url).0
    }

    /// Whether `a`, a rank and URL, comes before `b`.
    fn precedes(&mut self, a: (usize, &str), b: (usize, &str)) -> bool {
        if a.0 != b.0 {
            return a.0 < b.0;
        }
        self.known(a.1);
        self.known(b.1);
        self.known[a.1].1 < self.known[b.1].1
    }
}

struct AggregateArtifact {
    artifact: LockArtifact,
    blob: BlobId,
    module_path: String,
    repo_rank: usize,
    /// Every repository that served it to a module.
    origins: BTreeSet<String>,
    /// Every repository that served its companion POM to a module.
    pom_origins: BTreeSet<String>,
}

/// One support POM's aggregated provenance, plus the module that contributed
/// it so a byte-level conflict can name where each side came from.
struct AggregateSupportPom {
    provenance: SupportPomProvenance,
    module_path: String,
}

/// One GAV's companion-POM pin, plus where it was first seen.
struct AggregateCompanionPom {
    blob: Option<BlobId>,
    origin: String,
}

/// Fold one resolved artifact's companion-POM pin into the reactor-wide map.
///
/// A GAV has exactly one companion `.pom`, and `raeva export-m2` writes it to
/// exactly one path in `~/.m2`. Two modules, or two platforms, that resolved
/// different bytes for it therefore cannot both be honoured: the lockfile would
/// pin one and the other's build would compile against a POM it never resolved
/// against. Caught here, before the lockfile is written, so the run fails with
/// both origins named rather than producing a lockfile export has to reject.
fn merge_companion_pom(
    aggregate: &mut BTreeMap<Gav, AggregateCompanionPom>,
    coordinate: &ArtifactCoord,
    artifact: &ResolvedArtifact,
    platform: &Platform,
    module_path: &str,
) -> Result<(), ResolveError> {
    let gav = &coordinate.gav;
    let repo = artifact.pom_repo_url.as_ref().unwrap_or(&artifact.repo_url);
    let origin = || format!("{platform}/{module_path} from {repo}");
    match aggregate.get(gav) {
        Some(existing) if existing.blob != artifact.companion_pom => Err(
            ResolveError::ConflictingCompanionPomBytes(Box::new(ConflictingPom {
                coord: gav.to_string(),
                first_origin: existing.origin.clone(),
                second_origin: origin(),
                first_sha256: pom_digest_text(existing.blob.as_ref()),
                second_sha256: pom_digest_text(artifact.companion_pom.as_ref()),
            })),
        ),
        Some(_) => Ok(()),
        None => {
            aggregate.insert(
                gav.clone(),
                AggregateCompanionPom {
                    blob: artifact.companion_pom.clone(),
                    origin: origin(),
                },
            );
            Ok(())
        }
    }
}

/// Fold one module's record for a support POM into a platform's or the
/// reactor-wide map, by the rules a single resolution applies
/// (`SupportPomProvenance::absorb`): a later module's repository replaces one
/// without an id, and different bytes are an error naming both modules. This
/// is the cross-module backstop, where the two sides are separate
/// resolutions. An id the lock cannot record is recorded as empty, as
/// `_remote.repositories` then names no repository.
fn merge_support_pom(
    aggregate: &mut BTreeMap<String, AggregateSupportPom>,
    coord: &str,
    provenance: &SupportPomProvenance,
    module_path: &str,
) -> Result<(), ResolveError> {
    let recordable = is_recordable_repo_id(&provenance.repo_id);
    let recorded = || {
        let mut provenance = provenance.clone();
        if !recordable {
            provenance.repo_id.clear();
        }
        provenance
    };
    match aggregate.get_mut(coord) {
        Some(existing) if existing.provenance.sha256 != provenance.sha256 => Err(
            ResolveError::ConflictingSupportPomBytes(Box::new(ConflictingPom {
                coord: coord.to_string(),
                first_origin: existing.module_path.clone(),
                second_origin: module_path.to_string(),
                first_sha256: existing.provenance.sha256.clone(),
                second_sha256: provenance.sha256.clone(),
            })),
        ),
        Some(existing) => {
            if existing.provenance.repo_id.is_empty()
                && recordable
                && !provenance.repo_id.is_empty()
            {
                existing.provenance = recorded();
                existing.module_path = module_path.to_string();
            }
            Ok(())
        }
        None => {
            aggregate.insert(
                coord.to_string(),
                AggregateSupportPom {
                    provenance: recorded(),
                    module_path: module_path.to_string(),
                },
            );
            Ok(())
        }
    }
}

fn lock_artifact(coordinate: ArtifactCoord, artifact: ResolvedArtifact) -> LockArtifact {
    let mut row = LockArtifact::new(coordinate, artifact.repo_url);
    row.checksums = vec![Digest::Sha256(artifact.blob)];
    row.snapshot = artifact.snapshot;
    row.pom_snapshot = artifact.pom_snapshot;
    row.pom_base = artifact.pom_base;
    // Pinned from the resolution that produced this row, never from the
    // store's coordinate index: the index is last-writer-wins across every
    // project sharing the store, so by the time the lock is written it can
    // name a POM this graph was never built from.
    row.pom_sha256 = artifact.companion_pom;
    row
}

#[cfg(test)]
mod tests;
