use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;

use rv_lock::{LockArtifact, LockPlatform, Lockfile, Platform};
use rv_maven_types::{ArtifactCoord, BlobId, Digest, Gav, SnapshotStamp};
use rv_repo::Repository;

use crate::error::{ExportError, Result};
use crate::export::SupportPomPin;
use crate::warning::ExportWarning;

/// The project an export is for, as its own files describe it.
///
/// Maven reads the reactor's POMs from disk and builds its modules, so none
/// of them is a support POM to copy into the local repository; only the
/// parents and imported BOMs around them are.
#[derive(Debug, Clone, Default)]
pub struct Reactor {
    /// The POM files whose parents and imported BOMs are exported.
    pub poms: Vec<ProjectPom>,
    /// The effective coordinates of the reactor modules, interpolated as
    /// `raeva sync` discovers them, `${revision}` included. A parent or imported
    /// BOM with one of these coordinates comes from the reactor.
    pub modules: BTreeSet<Gav>,
}

/// One POM of the project, read from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPom {
    /// Where the POM file is.
    pub path: PathBuf,
    /// Its `<parent>` is a POM on disk that `raeva sync` accepts as a local
    /// parent, compared as Maven compares it, which matches a `${revision}`
    /// parent version as written.
    pub local_parent: bool,
}

/// What an export writes and the provenance the lock records for it.
///
/// Built once from a `raeva.lock` by [`ExportPlan::from_lock`], which refuses a
/// lock whose pins disagree before anything is written. The plan holds the
/// artifacts, the POM pins and the repository ids that label them; the
/// [`Exporter`](crate::Exporter) holds the destination and the store.
#[derive(Debug, Clone)]
pub struct ExportPlan {
    pub(crate) items: Vec<LockArtifact>,
    pub(crate) system_scoped: Vec<String>,
    pub(crate) repo_ids: HashMap<String, Vec<String>>,
    /// Every repository id `mvn -o` may read version lists under: see
    /// [`query_ids`].
    pub(crate) query_ids: BTreeSet<String>,
    pub(crate) support_poms: HashMap<String, SupportPomPin>,
    pub(crate) pom_digests: HashMap<(String, String, String), BlobId>,
    /// By companion POM, the lock keys of the repositories rows record for it.
    pom_origins: HashMap<(String, String, String), HashSet<String>>,
    classifier_candidates: Vec<ClassifierCandidate>,
    origins: rv_lock::LockOrigins,
    /// The lock keys of the repositories the configuration or the project's
    /// POMs declare.
    declared: HashSet<String>,
    /// By lock key, the endpoints that serve a repository the configuration
    /// or the project's POMs declare there, after mirrors.
    endpoints: HashMap<String, HashSet<String>>,
}

impl ExportPlan {
    /// The plan for every external artifact of `lock`, across all platforms
    /// and modules, deduplicated by coordinate.
    ///
    /// The lock records the repositories the configuration and POMs
    /// declare. Each file is labelled in `_remote.repositories` with the id
    /// of each repository that served it, as that repository is served under
    /// `config` now: the mirror's id when one of `config`'s mirrors applies,
    /// as Maven records it, otherwise the declared id. The ids of the
    /// configured repositories at an origin win over the ids the lock
    /// records for it. Workspace modules and system-scoped dependencies have no
    /// artifact row and are not exported. `project` holds the repositories
    /// the project declares on each platform, and any a resolution of it
    /// trusted, a remote parent's included.
    pub fn from_lock(
        config: &rv_config::Config,
        lock: &Lockfile,
        project: &HashMap<Platform, Vec<Repository>>,
    ) -> Result<Self> {
        let declared = declared_repositories(config, lock);
        let repo_ids = marker_ids(config, &declared);
        let origins = rv_lock::LockOrigins::for_root(&config.project_root);
        // The lock's ids pick no mirror: a mirror of an id that only another
        // project declares may serve other bytes for the coordinate.
        let trusted: Vec<Repository> = (config.repositories().iter().map(Repository::from))
            .chain(project.values().flatten().cloned())
            .collect();
        let mut endpoints: HashMap<String, HashSet<String>> = HashMap::new();
        for repo in &trusted {
            let endpoint = rv_repo::mirrored_repository(config, repo).url;
            if let Some(key) = origins.declared(&repo.url) {
                (endpoints.entry(key).or_default()).insert(rv_lock::normalize_repo_url(&endpoint));
            }
        }
        let trusted_keys = (trusted.iter())
            .filter_map(|repo| origins.declared(&repo.url))
            .collect();
        Ok(Self {
            items: external_artifacts(lock),
            system_scoped: system_scoped_coordinates(lock),
            support_poms: lock_support_poms(lock, &repo_ids),
            query_ids: query_ids(config, lock, &repo_ids),
            repo_ids,
            pom_digests: lock_pom_digests(lock)?,
            pom_origins: lock_pom_origins(lock),
            classifier_candidates: classifier_candidates(lock),
            origins,
            declared: trusted_keys,
            endpoints,
        })
    }

    /// Whether a stored file that the repositories `served_by` names served,
    /// each through an endpoint, may stand in for `artifact`: a repository
    /// the row records served it, or for a SHA-256 pin, as restore falls
    /// back, one the project declares, directly or through a mirror
    /// `endpoints` holds for it. Projects share the store, and another
    /// project's repository or mirror may serve other bytes for the
    /// coordinate.
    pub(crate) fn admits(&self, artifact: &LockArtifact, served_by: &[(String, String)]) -> bool {
        let recorded: HashSet<_> = artifact.file_origins().map(rv_lock::recorded_key).collect();
        let fallback = matches!(artifact.pin(), Some(Digest::Sha256(_)));
        self.served_for(&recorded, fallback, served_by)
    }

    /// [`Self::admits`] for the companion POM `gav`, under the repositories
    /// the rows record for it.
    pub(crate) fn admits_pom(
        &self,
        gav: &(String, String, String),
        served_by: &[(String, String)],
    ) -> bool {
        let recorded = self.pom_origins.get(gav).cloned().unwrap_or_default();
        self.served_for(&recorded, true, served_by)
    }

    /// [`Self::admits`] for a support POM, under the repositories its pins
    /// record.
    pub(crate) fn admits_support_pom(
        &self,
        pin: &SupportPomPin,
        served_by: &[(String, String)],
    ) -> bool {
        self.served_for(&pin.origins, true, served_by)
    }

    fn served_for(
        &self,
        recorded: &HashSet<String>,
        fallback: bool,
        served_by: &[(String, String)],
    ) -> bool {
        served_by.iter().any(|(repo, endpoint)| {
            let endpoint = rv_lock::normalize_repo_url(endpoint);
            self.origins.declared(repo).is_some_and(|key| {
                (recorded.contains(&key) || (fallback && self.declared.contains(&key)))
                    && (rv_lock::normalize_repo_url(repo) == endpoint
                        || (self.endpoints.get(&key))
                            .is_some_and(|known| known.contains(&endpoint)))
            })
        })
    }

    /// Keep the classifier candidates whose recorded origin a current
    /// declaration names, one per coordinate.
    ///
    /// Classifier jars carry no lockfile pin, so the origin is the only thing
    /// standing between a tampered raeva.lock and an arbitrary download: a
    /// candidate is fetched only from a configured repository, a mirror, or a
    /// repository the project's own POMs declare for the platform that
    /// recorded it. Anything else is skipped and reported in the returned
    /// warnings.
    pub fn authorize_classifiers(
        &self,
        config: &rv_config::Config,
        declared: &HashMap<Platform, Vec<Repository>>,
    ) -> (Vec<AuthorizedClassifier>, Vec<ExportWarning>) {
        authorize_classifier_candidates(config, self.classifier_candidates.clone(), declared)
    }
}

/// A platform row's coordinate that could have a `-sources` or `-javadoc`
/// jar, with the origin the lock recorded for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ClassifierCandidate {
    /// The platform whose row recorded this origin. Only that platform's
    /// declarations may authorize it.
    pub platform: Platform,
    /// The row's GAV, with the `-SNAPSHOT` version of a snapshot build.
    pub gav: Gav,
    /// The origin the row records, not redacted.
    pub repo_url: String,
    /// The deployed build the row records for a snapshot.
    pub snapshot: Option<SnapshotStamp>,
    /// The companion POM build when it differs from the artifact build.
    pub pom_snapshot: Option<SnapshotStamp>,
    /// Whether the companion POM is the base `-SNAPSHOT.pom`.
    pub pom_base: bool,
}

impl ClassifierCandidate {
    /// The `classifier` jar of the row's coordinate, recorded with the row's
    /// origin and snapshot build and no checksum.
    pub fn artifact(&self, classifier: &str) -> LockArtifact {
        let mut artifact = LockArtifact::new(
            ArtifactCoord::of(self.gav.clone(), "jar", Some(classifier)),
            self.repo_url.clone(),
        );
        artifact.snapshot = self.snapshot.clone();
        artifact.pom_snapshot = self.pom_snapshot.clone();
        artifact.pom_base = self.pom_base;
        artifact
    }

    /// The version in the file names: the timestamped build of a snapshot,
    /// otherwise the GAV's version.
    pub fn file_version(&self) -> String {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.resolved_version(self.gav.version()))
            .unwrap_or_else(|| self.gav.version().to_string())
    }
}

/// A classifier candidate and the declared repository it may be fetched from.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuthorizedClassifier {
    /// The candidate whose origin was found among the declarations.
    pub candidate: ClassifierCandidate,
    /// The declared repository the candidate's origin matches, with the
    /// declaration's own URL: fetch the classifier jars from this one.
    pub repository: Repository,
}

/// Every artifact row of every platform, deduplicated by coordinate, with
/// the origins of every platform's row.
/// Workspace and system nodes have no row, so they are never exported.
fn external_artifacts(lock: &Lockfile) -> Vec<LockArtifact> {
    let mut artifacts = BTreeMap::new();
    for artifact in lock
        .platforms
        .iter()
        .flat_map(|platform| &platform.artifacts)
    {
        match artifacts.entry(artifact.coord()) {
            Entry::Vacant(entry) => {
                entry.insert(artifact.clone());
            }
            // Platforms resolve independently, so one file may come from a
            // different repository on each; its markers name every one.
            Entry::Occupied(mut entry) => {
                let kept = entry.get_mut();
                let origins: BTreeSet<String> = (kept.other_repo_urls.iter().map(String::as_str))
                    .chain(artifact.origins())
                    .filter(|url| *url != kept.repo_url)
                    .map(str::to_string)
                    .collect();
                kept.other_repo_urls = origins.into_iter().collect();
            }
        }
    }
    artifacts.into_values().collect()
}

/// Collect the `"g:a:v"` of every system-scoped dependency the lock records,
/// deduplicated and ordered so one lock always warns about the same list.
///
/// A `systemPath` dependency resolves from an absolute path on the building
/// machine, so `raeva sync` puts no bytes in the content store for it and writes
/// it no `artifacts[]` row (`Lockfile::read` rejects a lock that gives one
/// both). The per-module package graphs are therefore the only place the lock
/// records these coordinates at all, and the only place export can see them:
/// the aggregate view it otherwise works from is built from artifact rows,
/// which have no system path.
fn system_scoped_coordinates(lock: &Lockfile) -> Vec<String> {
    let mut coords = BTreeSet::new();
    for platform in &lock.platforms {
        for module in &platform.modules {
            for package in &module.packages {
                if package.system_path.is_some() {
                    coords.insert(format!(
                        "{}:{}:{}",
                        package.coordinate.group_id(),
                        package.coordinate.artifact_id(),
                        package.coordinate.version()
                    ));
                }
            }
        }
    }
    coords.into_iter().collect()
}

fn classifier_candidates(lock: &Lockfile) -> Vec<ClassifierCandidate> {
    let mut platforms: Vec<&LockPlatform> = lock.platforms.iter().collect();
    platforms.sort_by_key(|platform| platform.platform.to_string());
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    for platform in platforms {
        for artifact in &platform.artifacts {
            if artifact.coordinate.extension() == "pom"
                || artifact.coordinate.classifier().is_some()
                || artifact.repo_url.trim().is_empty()
            {
                continue;
            }

            let candidate = ClassifierCandidate {
                platform: platform.platform.clone(),
                gav: artifact.coordinate.gav.clone(),
                repo_url: artifact.repo_url.clone(),
                snapshot: artifact.snapshot.clone(),
                pom_snapshot: artifact.pom_snapshot.clone(),
                pom_base: artifact.pom_base,
            };

            if seen.insert(candidate.clone()) {
                candidates.push(candidate);
            }
        }
    }

    candidates
}

fn authorize_classifier_candidates(
    config: &rv_config::Config,
    candidates: Vec<ClassifierCandidate>,
    declared: &HashMap<Platform, Vec<Repository>>,
) -> (Vec<AuthorizedClassifier>, Vec<ExportWarning>) {
    type Coordinate = (String, String, String, Option<String>);
    let mut authorized: BTreeMap<Coordinate, AuthorizedClassifier> = BTreeMap::new();
    let mut refused: BTreeMap<Coordinate, String> = BTreeMap::new();
    let origins = rv_lock::LockOrigins::for_root(&config.project_root);
    let mut selectors = HashMap::new();
    for candidate in candidates {
        let coordinate = (
            candidate.gav.group.to_string(),
            candidate.gav.artifact.to_string(),
            candidate.file_version(),
            candidate.snapshot.as_ref().map(ToString::to_string),
        );
        if authorized.contains_key(&coordinate) {
            continue;
        }
        let selector = selectors
            .entry(candidate.platform.clone())
            .or_insert_with(|| {
                let platform_declared = declared
                    .get(&candidate.platform)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                rv_repo::LockRepositorySelector::new(config, &origins, platform_declared)
            });
        match selector
            .select(&candidate.repo_url, Some(&candidate.file_version()))
            .declared()
        {
            Some(repository) => {
                refused.remove(&coordinate);
                authorized.insert(
                    coordinate,
                    AuthorizedClassifier {
                        candidate,
                        repository,
                    },
                );
            }
            None => {
                refused
                    .entry(coordinate)
                    .or_insert_with(|| candidate.repo_url.clone());
            }
        }
    }
    let warnings = refused
        .into_iter()
        .map(|((group_id, artifact_id, version, _), origin)| {
            ExportWarning::UntrustedClassifierOrigin {
                group_id,
                artifact_id,
                version,
                origin: rv_lock::redact_origin(&origin).to_string(),
            }
        })
        .collect();
    (authorized.into_values().collect(), warnings)
}

/// The repositories the lock's origins name, by recorded origin: the ones
/// raeva.lock records ids for, with configured ones first and in place of a
/// recorded one with the same id. Keyed as
/// [`rv_lock::recorded_key`] spells an origin, as the exporter looks it up.
fn declared_repositories(
    config: &rv_config::Config,
    lock: &Lockfile,
) -> BTreeMap<String, Vec<Repository>> {
    let origins = &rv_lock::LockOrigins::for_root(&config.project_root);
    let mut declared: BTreeMap<String, Vec<Repository>> = lock
        .repo_ids
        .iter()
        .map(|(origin, ids)| {
            let repos = ids
                .iter()
                .map(|id| Repository::new(Some(id.clone()), origin.clone(), true, true));
            (rv_lock::recorded_key(origin), repos.collect())
        })
        .collect();
    let mut configured: BTreeMap<String, Vec<Repository>> = BTreeMap::new();
    for repo in config.repositories() {
        if let Some(origin) = origins.declared(&repo.url) {
            configured
                .entry(origin)
                .or_default()
                .push(Repository::from(repo));
        }
    }
    // A configured declaration replaces the recorded one with its id; ids
    // only a POM declares at the same URL stay. A configured repository
    // without an id is still the one a mirror serves, which names the files
    // it supplied; it only stands in when no declaration of its origin gives
    // an id.
    for (origin, mut repos) in configured {
        let recorded = declared.remove(&origin).unwrap_or_default();
        if repos.iter().any(|repo| repo.id.is_some()) || !recorded.is_empty() {
            repos.retain(|repo| repo.id.is_some());
        }
        let ids: HashSet<Option<String>> = repos.iter().map(|repo| repo.id.clone()).collect();
        repos.extend(recorded.into_iter().filter(|repo| !ids.contains(&repo.id)));
        if !repos.is_empty() {
            declared.insert(origin, repos);
        }
    }
    declared
}

/// The `_remote.repositories` ids for each recorded origin: the id of each
/// repository there as it is served under the mirrors configured now. A
/// mirror without an id of its own labels nothing, and the declared id
/// stays. Origins without a known id are left out; the exporter labels them
/// `central`.
fn marker_ids(
    config: &rv_config::Config,
    declared: &BTreeMap<String, Vec<Repository>>,
) -> HashMap<String, Vec<String>> {
    declared
        .iter()
        .filter_map(|(origin, repos)| {
            let ids: BTreeSet<String> = repos
                .iter()
                .filter_map(|repo| {
                    rv_repo::mirrored_repository(config, repo)
                        .id
                        .or_else(|| repo.id.clone())
                })
                .collect();
            (!ids.is_empty()).then(|| (origin.clone(), ids.into_iter().collect()))
        })
        .collect()
}

/// The repository ids `mvn -o` may read a version list under: those
/// raeva.lock records, the marker ids they map to, the configured
/// repositories' and mirrors' ids, and `central`, the super POM's. A
/// tail's list under any of them can name a version the lock does not, so
/// the export writes one under each. Ids no file can carry are dropped
/// when writing.
fn query_ids(
    config: &rv_config::Config,
    lock: &Lockfile,
    repo_ids: &HashMap<String, Vec<String>>,
) -> BTreeSet<String> {
    let configured = (config.repositories().iter().map(|repo| &repo.id))
        .chain(config.mirrors().iter().map(|mirror| &mirror.id))
        .flatten();
    (lock.repo_ids.values().flatten())
        .chain(repo_ids.values().flatten())
        .chain(configured)
        .cloned()
        .chain(["central".to_string()])
        .collect()
}

/// The support POMs of every platform of raeva.lock, as a coord -> pin map.
/// The pin carries the ids the recorded repository's files are labelled
/// with now (see [`marker_ids`]), none for a repository without one. The digest
/// names the exact bytes to export. The lockfile reader already refused
/// malformed or conflicting pins, so nothing here falls back to the store's
/// last-writer-wins coordinate index for a POM the lockfile pinned.
fn lock_support_poms(
    lock: &Lockfile,
    repo_ids: &HashMap<String, Vec<String>>,
) -> HashMap<String, SupportPomPin> {
    let mut origins: HashMap<&str, HashSet<String>> = HashMap::new();
    for (coord, pin) in lock
        .platforms
        .iter()
        .flat_map(|platform| &platform.support_poms)
    {
        (origins.entry(coord).or_default()).insert(rv_lock::recorded_key(&pin.repo_url));
    }
    lock.support_poms()
        .into_iter()
        .map(|(coord, pin)| {
            let repo_ids = repo_ids
                .get(&rv_lock::recorded_key(&pin.repo_url))
                .cloned()
                .unwrap_or_default();
            let build = pin
                .snapshot
                .is_some()
                .then(|| pin.file_gav(&coord))
                .flatten()
                .map(|gav| gav.version().to_string());
            let origins = origins.remove(coord.as_str()).unwrap_or_default();
            (
                coord,
                SupportPomPin {
                    repo_ids,
                    origins,
                    sha256: pin.sha256,
                    build,
                },
            )
        })
        .collect()
}

/// Collect the companion-POM digests the lockfile's artifact rows pin, keyed
/// the way `Exporter` looks a POM up: `(group, artifact, resolved version)`.
///
/// Rows for different classifiers of one coordinate share a POM, and so do the
/// same coordinate's rows across platforms. They must therefore agree: Maven
/// has one local-repository path per GAV, so two digests describe a `~/.m2`
/// this export cannot write. `raeva sync` refuses to produce such a lockfile and
/// `Lockfile::read` rejects one; failing here as well keeps the export from
/// silently picking a winner if either ever let one through.
fn lock_pom_digests(lock: &Lockfile) -> Result<HashMap<(String, String, String), BlobId>> {
    let mut map: HashMap<(String, String, String), BlobId> = HashMap::new();
    for platform in &lock.platforms {
        for artifact in &platform.artifacts {
            // A row without a digest has no POM in any repository.
            let Some(digest) = artifact.pom_sha256.clone() else {
                continue;
            };
            let pom = artifact.pom_gav();
            let gav = (
                pom.group.to_string(),
                pom.artifact.to_string(),
                pom.version().to_string(),
            );
            match map.get(&gav) {
                Some(existing) if *existing != digest => {
                    return Err(ExportError::ConflictingPinnedPom {
                        coordinate: format!("{}:{}:{}", gav.0, gav.1, gav.2),
                        first: existing.to_string(),
                        second: digest.to_string(),
                    });
                }
                Some(_) => {}
                None => {
                    map.insert(gav, digest);
                }
            }
        }
    }
    Ok(map)
}

/// By companion POM, as [`lock_pom_digests`] keys it, the lock keys of the
/// repositories the rows that pin it record for it.
fn lock_pom_origins(lock: &Lockfile) -> HashMap<(String, String, String), HashSet<String>> {
    let mut map: HashMap<_, HashSet<_>> = HashMap::new();
    for artifact in lock
        .platforms
        .iter()
        .flat_map(|platform| &platform.artifacts)
    {
        if artifact.pom_sha256.is_some() {
            let pom = artifact.pom_gav();
            let gav = (
                pom.group.to_string(),
                pom.artifact.to_string(),
                pom.version().to_string(),
            );
            (map.entry(gav).or_default()).extend(artifact.pom_origins().map(rv_lock::recorded_key));
        }
    }
    map
}

#[cfg(test)]
mod tests;
