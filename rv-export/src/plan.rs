use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;

use rv_lock::{
    LockArtifact, LockPlatform, Lockfile, MetadataVersion, MetadataVersionKind, Platform,
};
use rv_maven_types::{ArtifactCoord, BlobId, Digest, Gav, MavenMode, SnapshotStamp, VersionReq};
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
    /// The parents on disk `raeva sync` accepts for it, compared as Maven
    /// compares them, which matches a `${revision}` parent version as
    /// written: from its parent to the farthest one, by canonical path.
    pub local_parents: Vec<PathBuf>,
}

/// Plugin goal prefixes by group and repository id: each prefix with the
/// artifact id of its plugin.
pub(crate) type GroupPrefixes = BTreeMap<(String, String), BTreeSet<(String, String)>>;

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
    /// The goal prefixes of each plugin group, by group and the id of the
    /// repository whose group metadata names them.
    pub(crate) group_prefixes: GroupPrefixes,
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
    /// The ranges the modules' resolutions listed and lost: see
    /// [`evicted_ranges`].
    pub(crate) evicted_ranges: Vec<EvictedListing>,
    /// The `<release>` and `<latest>` the resolutions read, by `(group,
    /// artifact)`: see [`markers`].
    pub(crate) markers: HashMap<(String, String), Markers>,
    /// The build plugins and extensions without a version, by `(group,
    /// artifact)`, that no plugin tables record a marker for.
    pub(crate) unversioned_plugins: BTreeSet<(String, String)>,
    /// The spellings ranges took, as `(group, artifact, version)`: see
    /// [`range_picks`].
    pub(crate) range_picks: BTreeSet<(String, String, String)>,
    /// What each module's ranges read: see [`module_range_reads`].
    pub(crate) module_range_reads: Vec<ModuleRangeRead>,
    /// The versions ranges took and the origins whose lists named them,
    /// as `(group, artifact, version, origin)`: see [`range_versions`].
    pub(crate) range_versions: BTreeSet<(String, String, String, String)>,
    /// The versions `RELEASE`, `LATEST` and plugins without a version took,
    /// as `(group, artifact, version)`.
    pub(crate) marker_versions: BTreeSet<(String, String, String)>,
    /// The Maven line raeva.lock was resolved as, which orders versions.
    pub(crate) mode: MavenMode,
}

/// The versions of `group:artifact` one module's ranges took or it holds,
/// and the origins whose lists its ranges read, a losing range's too.
#[derive(Debug, Clone)]
pub(crate) struct ModuleRangeRead {
    pub(crate) group: String,
    pub(crate) artifact: String,
    pub(crate) versions: BTreeSet<String>,
    pub(crate) origins: BTreeSet<String>,
}

/// A version range that lost mediation, with the versions a repository's
/// list offered it when raeva.lock was written, and that repository.
#[derive(Debug, Clone)]
pub(crate) struct EvictedListing {
    pub(crate) group: String,
    pub(crate) artifact: String,
    pub(crate) range: VersionReq,
    pub(crate) origin: String,
    pub(crate) versions: Vec<String>,
    /// The versions of `group:artifact` the modules that recorded the
    /// range hold: the spelling Maven took where two compare equal.
    pub(crate) held: BTreeSet<String>,
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
        let configured = configured_repositories(config, lock);
        let mut declared = declared_repositories(config, lock);
        let origins = rv_lock::LockOrigins::for_root(&config.project_root);
        // The lock's ids pick no mirror: a mirror of an id that only another
        // project declares may serve other bytes for the coordinate. Each
        // platform's settings profiles may give one id its own URL.
        let trusted: Vec<Repository> = (configured.iter().map(Repository::from))
            .chain(project.values().flatten().cloned())
            .collect();
        // The lock records no origin, and so no id, for a repository whose
        // own URL it cannot record, which a mirror serves.
        let unrecorded = (trusted.iter()).filter(|repo| {
            origins.key(&repo.url).as_deref() == Some("")
                && rv_repo::mirrored_repository(config, repo).url != repo.url
        });
        for repo in unrecorded {
            let repos = declared.entry(String::new()).or_default();
            if !repos.iter().any(|known| known.id == repo.id) {
                repos.push(repo.clone());
            }
        }
        // A mirror pattern reads the URL as written, such as a
        // `symlink+file:` one that Maven 3.10 reads as the directory the
        // lock records, so a declaration of a recorded origin under the same
        // id with such a spelling picks the mirror.
        let respelled = (trusted.iter())
            .filter(|repo| rv_lock::normalize_repo_url(repo.declared_url()) != repo.url);
        for repo in respelled {
            let Some(repos) = origins
                .key(&repo.url)
                .and_then(|key| declared.get_mut(&key))
            else {
                continue;
            };
            for known in repos.iter_mut().filter(|known| known.id == repo.id) {
                *known = repo.clone();
            }
        }
        let repo_ids = marker_ids(config, &declared);
        let mut endpoints: HashMap<String, HashSet<String>> = HashMap::new();
        for repo in &trusted {
            let endpoint = rv_repo::mirrored_repository(config, repo).url;
            if let Some(key) = origins.key(&repo.url) {
                (endpoints.entry(key).or_default()).insert(rv_lock::normalize_repo_url(&endpoint));
            }
        }
        let trusted_keys = (trusted.iter())
            .filter_map(|repo| origins.key(&repo.url))
            .collect();
        let (pom_digests, pom_origins) = lock_poms(lock)?;
        let markers = markers(lock)?;
        Ok(Self {
            items: external_artifacts(lock),
            system_scoped: system_scoped_coordinates(lock),
            support_poms: lock_support_poms(lock, &repo_ids),
            query_ids: query_ids(config, lock, &repo_ids),
            repo_ids,
            pom_digests,
            pom_origins,
            classifier_candidates: classifier_candidates(lock),
            group_prefixes: BTreeMap::new(),
            origins,
            declared: trusted_keys,
            endpoints,
            evicted_ranges: evicted_ranges(lock),
            markers,
            unversioned_plugins: BTreeSet::new(),
            range_picks: range_picks(lock),
            module_range_reads: module_range_reads(lock),
            range_versions: range_versions(lock),
            marker_versions: metadata_versions(lock)
                .filter(|read| read.kind != MetadataVersionKind::Range)
                .map(|read| {
                    let (group, artifact) = (read.group.clone(), read.artifact.clone());
                    (group, artifact, read.version.clone())
                })
                .collect(),
            mode: lock.maven,
        })
    }

    /// Refuse to write the metadata of an artifact one of `plugins`, build
    /// plugins and extensions no POM gives a version, names without a
    /// marker raeva.lock records: `mvn -o` would take its version from the
    /// locked versions, not the one Maven takes online.
    pub fn with_unversioned_plugins(
        mut self,
        plugins: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        self.unversioned_plugins.extend(plugins);
        self
    }

    /// Also write the group metadata `mvn -o` resolves a goal prefix from:
    /// for each `(groupId, repository, prefix, artifactId)`, the prefix in
    /// `<groupId>/maven-metadata-<id>.xml` under each id the repository's
    /// files are labelled with.
    pub fn with_plugin_prefixes(
        mut self,
        prefixes: impl IntoIterator<Item = (String, String, String, String)>,
    ) -> Self {
        for (group, repo_url, prefix, artifact) in prefixes {
            let ids = (self.repo_ids.get(&rv_lock::recorded_key(&repo_url)))
                .cloned()
                .unwrap_or_default();
            for id in ids {
                (self.group_prefixes.entry((group.clone(), id)).or_default())
                    .insert((prefix.clone(), artifact.clone()));
            }
        }
        self
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
            self.origins.key(repo).is_some_and(|key| {
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
/// the origins of every platform's row and those its plugin sets read it
/// from.
/// Workspace and system nodes have no row, so they are never exported.
fn external_artifacts(lock: &Lockfile) -> Vec<LockArtifact> {
    let mut artifacts = BTreeMap::new();
    for platform in &lock.platforms {
        let shared = (platform.plugins.iter()).flat_map(|tables| &tables.shared_origins);
        let shared: HashMap<_, _> = shared.collect();
        let without_pom = (platform.plugins.iter()).flat_map(|tables| &tables.shared_without_pom);
        let without_pom: HashMap<_, _> = without_pom.collect();
        for artifact in &platform.artifacts {
            let read = (shared
                .get(&artifact.coordinate)
                .into_iter()
                .copied()
                .flatten())
            .map(String::as_str);
            // An origin that served the sets the file without its POM
            // labels the file alone: `mvn -o` then reads no POM there, as
            // Maven 3.10 does online.
            let without = without_pom.get(&artifact.coordinate);
            let served = |url: &&str| without.is_none_or(|without| !without.contains(*url));
            // A row that lists the repositories its POM came from keeps
            // the list, with those of every platform's row, for the POM's
            // markers.
            let poms: BTreeSet<String> = (artifact.pom_origins())
                .chain(read.clone().filter(served))
                .map(str::to_string)
                .collect();
            match artifacts.entry(artifact.coord()) {
                Entry::Vacant(entry) => {
                    let kept = entry.insert(artifact.clone());
                    if !kept.pom_repo_urls.is_empty() || without.is_some() {
                        kept.pom_repo_urls = poms.into_iter().collect();
                    }
                    let origins: BTreeSet<&str> = (kept.other_repo_urls.iter().map(String::as_str))
                        .chain(read)
                        .collect();
                    kept.other_repo_urls = origins.into_iter().map(str::to_string).collect();
                }
                // Platforms resolve independently, so one file may come from a
                // different repository on each; its markers name every one.
                Entry::Occupied(mut entry) => {
                    let kept = entry.get_mut();
                    if !kept.pom_repo_urls.is_empty()
                        || !artifact.pom_repo_urls.is_empty()
                        || without.is_some()
                    {
                        let mut known: BTreeSet<String> =
                            kept.pom_origins().map(str::to_string).collect();
                        known.extend(poms);
                        kept.pom_repo_urls = known.into_iter().collect();
                    }
                    let origins: BTreeSet<String> =
                        (kept.other_repo_urls.iter().map(String::as_str))
                            .chain(artifact.origins())
                            .chain(read)
                            .filter(|url| *url != kept.repo_url)
                            .map(str::to_string)
                            .collect();
                    kept.other_repo_urls = origins.into_iter().collect();
                }
            }
        }
    }
    artifacts.into_values().collect()
}

/// The `<release>` and `<latest>` an export writes for one `group:artifact`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Markers {
    pub(crate) release: Option<String>,
    pub(crate) latest: Option<String>,
}

/// The modules' and the plugin tables' metadata versions of every platform.
fn metadata_versions(lock: &Lockfile) -> impl Iterator<Item = &MetadataVersion> {
    (lock.platforms.iter()).flat_map(|platform| {
        (platform.modules.iter())
            .flat_map(|module| &module.metadata_versions)
            .chain((platform.plugins.iter()).flat_map(|tables| &tables.metadata_versions))
    })
}

/// The markers each `group:artifact` a `RELEASE`, `LATEST` or a plugin
/// without a version read. `mvn -o` takes each from the metadata of the
/// repositories a node reads, so two values of one marker cannot both be
/// reproduced, but for a plugin that platforms of other JDKs took at other
/// versions from the same repositories.
fn markers(lock: &Lockfile) -> Result<HashMap<(String, String), Markers>> {
    let mut markers: HashMap<(String, String), Markers> = HashMap::new();
    let mut set = |read: &MetadataVersion| {
        let entry = markers.entry((read.group.clone(), read.artifact.clone()));
        let markers = entry.or_default();
        let marker = match read.kind {
            MetadataVersionKind::Latest => &mut markers.latest,
            _ => &mut markers.release,
        };
        match marker {
            Some(known) if *known != read.version => Err(conflict(read, known)),
            _ => {
                *marker = Some(read.version.clone());
                Ok(())
            }
        }
    };
    // Each plugin release with the JDK of the platform that took it and
    // the repositories of the sets that resolve it.
    type Taken<'a> = (Option<&'a str>, &'a MetadataVersion, BTreeSet<&'a [String]>);
    let mut plugins: BTreeMap<(&str, &str), Vec<Taken<'_>>> = BTreeMap::new();
    for platform in &lock.platforms {
        for read in (platform.modules.iter()).flat_map(|module| &module.metadata_versions) {
            if read.kind != MetadataVersionKind::Range {
                set(read)?;
            }
        }
        if let Some(tables) = &platform.plugins {
            for read in &tables.metadata_versions {
                match read.kind {
                    MetadataVersionKind::Range => continue,
                    MetadataVersionKind::Release => {}
                    _ => {
                        set(read)?;
                        continue;
                    }
                }
                let coordinate = format!("{}:{}:{}", read.group, read.artifact, read.version);
                let repos: BTreeSet<_> = (tables.sets.iter())
                    .filter(|set| set.coordinates.contains(&coordinate))
                    .map(|set| set.repo_urls.as_slice())
                    .collect();
                if repos.is_empty() {
                    set(read)?;
                    continue;
                }
                let key = (read.group.as_str(), read.artifact.as_str());
                (plugins.entry(key).or_default()).push((platform.platform.jdk(), read, repos));
            }
        }
    }
    for taken in plugins.values() {
        // Maven tries `<release>`, and where the JDK refuses it the newest
        // version it accepts, so the highest stands for every JDK when each
        // JDK took one version from the same repositories.
        let (_, first, repos) = &taken[0];
        let apart =
            (taken.iter().map(|(_, read, _)| *read)).find(|read| read.version != first.version);
        let mut highest = *first;
        for (jdk, read, sets) in taken {
            let other = |(other, at, _): &Taken<'_>| other == jdk && at.version != read.version;
            if let Some(apart) = apart
                && (sets != repos || taken.iter().any(other))
            {
                return Err(conflict(apart, &first.version));
            }
            let parse = rv_maven_types::Version::parse;
            if let (Ok(version), Ok(known)) = (parse(&read.version), parse(&highest.version))
                && version.cmp_in(&known, lock.maven).is_gt()
            {
                highest = read;
            }
        }
        set(highest)?;
    }
    Ok(markers)
}

/// Two values `first` and `read`'s of one marker.
fn conflict(read: &MetadataVersion, first: &str) -> ExportError {
    ExportError::ConflictingMarkers {
        coordinate: format!("{}:{}", read.group, read.artifact),
        marker: read.kind.as_str(),
        first: first.to_string(),
        second: read.version.clone(),
    }
}

/// The versions ranges took among spellings that compare equal, and the
/// remote parents ranges selected, whose spelling `mvn -o` takes in the
/// order of the versions listed.
fn range_picks(lock: &Lockfile) -> BTreeSet<(String, String, String)> {
    let ranges = metadata_versions(lock)
        .filter(|read| read.kind == MetadataVersionKind::Range)
        .map(|read| {
            (
                read.group.clone(),
                read.artifact.clone(),
                read.version.clone(),
            )
        });
    let parents = (lock.platforms.iter())
        .flat_map(|platform| &platform.modules)
        .flat_map(|module| &module.parent_ranges)
        .filter_map(|range| rv_lock::split_support_pom_coord(&range.selected))
        .map(|(group, artifact, version)| {
            (group.to_string(), artifact.to_string(), version.to_string())
        });
    ranges.chain(parents).collect()
}

/// For each module of every platform, what its ranges read of each
/// `group:artifact`. `mvn -o` takes a range's version from the lists of
/// every repository the module reads, so where those lists name two
/// spellings that compare equal, it takes either.
fn module_range_reads(lock: &Lockfile) -> Vec<ModuleRangeRead> {
    let mut reads = Vec::new();
    for module in (lock.platforms.iter()).flat_map(|platform| &platform.modules) {
        type Read = (BTreeSet<String>, BTreeSet<String>);
        let mut by: BTreeMap<(&str, &str), Read> = BTreeMap::new();
        for read in &module.range_versions {
            let (versions, origins) = by.entry((&read.group, &read.artifact)).or_default();
            versions.insert(read.version.clone());
            origins.insert(read.origin.clone());
        }
        for range in &module.evicted_ranges {
            let (_, origins) = by.entry((&range.group, &range.artifact)).or_default();
            origins.insert(range.origin.clone());
        }
        for ((group, artifact), (mut versions, origins)) in by {
            versions.extend(
                (module.packages.iter())
                    .map(|package| &package.coordinate)
                    .filter(|coordinate| {
                        coordinate.group_id() == group && coordinate.artifact_id() == artifact
                    })
                    .map(|coordinate| coordinate.version().to_string()),
            );
            reads.push(ModuleRangeRead {
                group: group.to_string(),
                artifact: artifact.to_string(),
                versions,
                origins,
            });
        }
    }
    reads
}

/// The versions the ranges of every module and plugin table of every
/// platform took, with the origin whose list named each. Only these, the
/// listings of evicted ranges and the markers are version lists `mvn -o`
/// reads: a version the lock pins exactly is no version a list named.
fn range_versions(lock: &Lockfile) -> BTreeSet<(String, String, String, String)> {
    (lock.platforms.iter())
        .flat_map(|platform| {
            (platform.modules.iter())
                .flat_map(|module| &module.range_versions)
                .chain((platform.plugins.iter()).flat_map(|tables| &tables.range_versions))
        })
        .map(|read| {
            let (group, artifact) = (read.group.clone(), read.artifact.clone());
            (group, artifact, read.version.clone(), read.origin.clone())
        })
        .collect()
}

/// The evicted ranges of every module of every platform, one per
/// `group:artifact`, range and origin, with the versions every module's
/// listing of that origin offered.
fn evicted_ranges(lock: &Lockfile) -> Vec<EvictedListing> {
    type Listing<'a> = (BTreeSet<&'a str>, BTreeSet<&'a str>);
    let mut ranges: BTreeMap<(&str, &str, &str, &str), Listing<'_>> = BTreeMap::new();
    for module in (lock.platforms.iter()).flat_map(|platform| &platform.modules) {
        for range in &module.evicted_ranges {
            let (versions, held) = ranges
                .entry((&range.group, &range.artifact, &range.range, &range.origin))
                .or_default();
            versions.extend(range.versions.iter().map(String::as_str));
            held.extend(
                (module.packages.iter())
                    .map(|package| &package.coordinate)
                    .filter(|coordinate| {
                        coordinate.group_id() == range.group
                            && coordinate.artifact_id() == range.artifact
                    })
                    .map(|coordinate| coordinate.version()),
            );
        }
    }
    ranges
        .into_iter()
        .filter_map(|((group, artifact, range, origin), (versions, held))| {
            Some(EvictedListing {
                group: group.to_string(),
                artifact: artifact.to_string(),
                // The reader checked that the range parses in this mode.
                range: VersionReq::parse_in(range, lock.maven).ok()?,
                origin: origin.to_string(),
                versions: versions.into_iter().map(str::to_string).collect(),
                held: held.into_iter().map(str::to_string).collect(),
            })
        })
        .collect()
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
            // The empty origin is the mirror's of a repository whose URL the
            // lock cannot record, which the selector names.
            if artifact.coordinate.extension() == "pom"
                || artifact.coordinate.classifier().is_some()
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
                let platform = &candidate.platform;
                let platform_declared = declared
                    .get(platform)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                // The repositories the settings profiles active on the
                // candidate's own platform declare, as its build reads them.
                let config =
                    config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
                rv_repo::LockRepositorySelector::new(&config, &origins, platform_declared)
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
            // A project-relative origin is the directory it names, which no
            // `external:*` mirror serves.
            let url = origins
                .project_url(origin)
                .unwrap_or_else(|| origin.clone());
            let repos = ids
                .iter()
                .map(|id| Repository::new(Some(id.clone()), url.clone(), true, true));
            (rv_lock::recorded_key(origin), repos.collect())
        })
        .collect();
    let mut configured: BTreeMap<String, Vec<Repository>> = BTreeMap::new();
    for repo in &configured_repositories(config, lock) {
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

/// The repositories the configuration declares on each platform of
/// `lock`, once by id and URL. The settings profiles of two platforms can
/// give one id two URLs, of which [`rv_config::Config::repositories`] on a
/// configuration for both keeps one.
fn configured_repositories(
    config: &rv_config::Config,
    lock: &Lockfile,
) -> Vec<rv_config::RepoConfig> {
    let mut repositories = config.repositories().to_vec();
    for entry in &lock.platforms {
        let platform = &entry.platform;
        let scoped = config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
        repositories.extend_from_slice(scoped.repositories());
    }
    let mut seen = HashSet::new();
    repositories
        .retain(|repo| seen.insert((repo.id.clone(), rv_lock::normalize_repo_url(&repo.url))));
    repositories
}

/// The `_remote.repositories` ids for each recorded origin: the declared id
/// of each repository there, and the id of the mirror that serves it under
/// the configuration now. Maven records only the id it read a file through,
/// but `mvn -o` may run with other mirrors than the export saw: in a
/// `settings.xml` without the mirror, or a `config.toml` one Maven does not
/// read, it reads the declared id. Origins without a known id are left out;
/// the exporter labels them `central`.
fn marker_ids(
    config: &rv_config::Config,
    declared: &BTreeMap<String, Vec<Repository>>,
) -> HashMap<String, Vec<String>> {
    declared
        .iter()
        .filter_map(|(origin, repos)| {
            let ids: BTreeSet<String> = repos
                .iter()
                .flat_map(|repo| {
                    (rv_repo::mirrored_repository(config, repo).id.into_iter())
                        .chain(repo.id.clone())
                })
                .collect();
            (!ids.is_empty()).then(|| (origin.clone(), ids.into_iter().collect()))
        })
        .collect()
}

/// The repository ids `mvn -o` may read a version list under: those
/// raeva.lock records, the marker ids they map to, the configured
/// repositories' and mirrors' ids, those of every settings.xml profile's
/// repositories and plugin repositories, and `central`, the super POM's. A
/// tail's list under any of them can name a version the lock does not, so
/// the export writes one under each. Ids no file can carry are reported
/// and dropped when writing.
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
        .chain(config.settings_profile_repository_ids().map(str::to_string))
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
            let origins = origins.remove(coord.as_str()).unwrap_or_default();
            // The first pin's ids, then those of the repositories other
            // platforms read the same bytes from: each build reads its own.
            let first = rv_lock::recorded_key(&pin.repo_url);
            let mut others: Vec<&String> = origins.iter().filter(|key| **key != first).collect();
            others.sort();
            let mut ids: Vec<String> = Vec::new();
            for id in std::iter::once(&first)
                .chain(others)
                .filter_map(|key| repo_ids.get(key))
                .flatten()
            {
                if !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
            let build = pin
                .snapshot
                .is_some()
                .then(|| pin.file_gav(&coord))
                .flatten()
                .map(|gav| gav.version().to_string());
            (
                coord,
                SupportPomPin {
                    repo_ids: ids,
                    origins,
                    sha256: pin.sha256,
                    repo_url: pin.repo_url,
                    build,
                },
            )
        })
        .collect()
}

/// Collect the companion-POM digests the lockfile's artifact rows pin, keyed
/// the way `Exporter` looks a POM up: `(group, artifact, resolved version)`,
/// and the lock keys of the repositories those rows record for each.
///
/// Rows for different classifiers of one coordinate share a POM, and so do the
/// same coordinate's rows across platforms. They must therefore agree: Maven
/// has one local-repository path per GAV, so two digests describe a `~/.m2`
/// this export cannot write. `raeva sync` refuses to produce such a lockfile and
/// `Lockfile::read` rejects one; failing here as well keeps the export from
/// silently picking a winner if either ever let one through.
fn lock_poms(lock: &Lockfile) -> Result<(HashMap<PomKey, BlobId>, PomOrigins)> {
    let mut digests: HashMap<PomKey, BlobId> = HashMap::new();
    let mut origins = PomOrigins::new();
    for file in lock.platforms.iter().flat_map(LockPlatform::pinned_files) {
        let (rv_lock::PinnedRow::Pom(_), Digest::Sha256(digest)) = (file.row, &file.pin) else {
            continue;
        };
        let pom = &file.key;
        let gav = (
            pom.group_id().to_string(),
            pom.artifact_id().to_string(),
            pom.version().to_string(),
        );
        let first = (digests.entry(gav.clone())).or_insert_with(|| digest.clone());
        if first != digest {
            return Err(ExportError::ConflictingPinnedPom {
                coordinate: format!("{}:{}:{}", gav.0, gav.1, gav.2),
                first: first.to_string(),
                second: digest.to_string(),
            });
        }
        (origins.entry(gav).or_default())
            .extend(file.origins.into_iter().map(rv_lock::recorded_key));
    }
    Ok((digests, origins))
}

/// A companion POM's `(group, artifact, resolved version)`.
type PomKey = (String, String, String);

/// By companion POM, the lock keys of the repositories its rows record.
type PomOrigins = HashMap<PomKey, HashSet<String>>;

#[cfg(test)]
mod tests;
