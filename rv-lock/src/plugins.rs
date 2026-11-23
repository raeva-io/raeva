//! The plugin tables: what a build reads from repositories besides its
//! dependencies, as `docs/design/plugin-locking.md` lays them out. A
//! platform writes them as `[platforms.plugins]`; their files are rows of
//! its `artifacts` and `support_poms`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rv_maven_types::{ArtifactCoord, CoordinateField, Gav, Sha256, validate_coordinate_component};
use serde::{Deserialize, Serialize};

use crate::ambient::AmbientInput;
use crate::error::{LockError, printable};
use crate::lock::{
    LockArtifact, LockModulePackage, LockPlatform, MetadataVersion, RangeVersion, RepoIds,
    SupportPom, check_origin_text, check_range_version, validate_coordinate, validate_module_path,
    validate_support_pom_coord,
};
use crate::lock_origin::{
    LockOrigins, decode_repo_id_lines, encode_repo_id_lines, is_project_relative_origin,
    normalize_repo_url, record_repo_ids, validate_project_relative_origin,
};

/// What a plugin set is resolved for, ordered as its name in raeva.lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PluginRole {
    /// A `<build><extensions>` entry or a plugin with
    /// `<extensions>true</extensions>`.
    BuildExtension,
    /// An entry of `.mvn/extensions.xml`.
    CoreExtension,
    /// A plugin of a module's build.
    Plugin,
    /// The compiler plugin's `annotationProcessorPaths` of a module.
    ProcessorPath,
    /// A piece of the test framework provider Surefire or Failsafe resolves
    /// while it runs.
    TestProvider,
    /// What the build `raeva sync` traces read while it ran.
    Trace,
}

impl PluginRole {
    const ALL: [Self; 6] = [
        Self::BuildExtension,
        Self::CoreExtension,
        Self::Plugin,
        Self::ProcessorPath,
        Self::TestProvider,
        Self::Trace,
    ];

    /// The name raeva.lock writes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plugin => "plugin",
            Self::BuildExtension => "build-extension",
            Self::CoreExtension => "core-extension",
            Self::ProcessorPath => "processor-path",
            Self::TestProvider => "test-provider",
            Self::Trace => "trace",
        }
    }
}

impl std::str::FromStr for PluginRole {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, ()> {
        (Self::ALL.into_iter())
            .find(|role| role.as_str() == text)
            .ok_or(())
    }
}

/// The plugin tables of one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginTables {
    /// SHA-256 of what the tables were resolved from besides the
    /// platform's graph; another value means they are stale.
    pub inputs: Sha256,
    /// One row per distinct set, sorted by key.
    pub sets: Vec<PluginSet>,
    /// The plugin prefixes `mvn -o` finds in a group's metadata, sorted.
    pub prefixes: Vec<PluginPrefix>,
    /// The ids of the repositories the sets resolved from, by origin.
    pub repo_ids: RepoIds,
    /// What the plugin resolution read from the host, by name or as a
    /// condition with its outcome, never a value; [`Self::inputs`] covers
    /// their values.
    pub host_inputs: BTreeSet<AmbientInput>,
    /// The version each plugin or extension without a version took, and
    /// the markers their collections read, sorted.
    pub metadata_versions: Vec<MetadataVersion>,
    /// The version each range the sets' collections read took, by the
    /// repository whose list named it, sorted: what an export lists for
    /// `mvn -o`, for ranges that lost mediation too.
    pub range_versions: Vec<RangeVersion>,
    /// For a row the modules also use, the origins the sets read its file
    /// from that the row does not record: `mvn -o` takes a plugin's file
    /// only under the id of a repository the plugin searches.
    pub shared_origins: BTreeMap<ArtifactCoord, BTreeSet<String>>,
    /// Of `shared_origins`, those that served the sets the file without
    /// the POM the row pins, as Maven 3.10 reads it there: the export labels
    /// the file with them, and the POM only with the row's origins.
    pub shared_without_pom: BTreeMap<ArtifactCoord, BTreeSet<String>>,
}

/// One plugin, extension, processor path or traced build.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginSet {
    /// `sha256:` of what decides its files.
    pub key: String,
    /// What the set is for.
    pub role: PluginRole,
    /// The plugin's coordinate, or each processor path entry's.
    pub coordinates: Vec<String>,
    /// The repositories it resolves from, in Maven's order.
    pub repo_urls: Vec<String>,
    /// The rows of [`LockPlatform::artifacts`] on its class path, in order.
    pub artifacts: Vec<ArtifactCoord>,
    /// The keys of [`LockPlatform::support_poms`] it reads, sorted.
    pub poms: Vec<String>,
    /// The POM paths of the modules that build with it, sorted.
    pub modules: Vec<String>,
}

impl PluginSet {
    /// A set with no files.
    pub fn new(key: &str, role: PluginRole) -> Self {
        Self {
            key: key.to_string(),
            role,
            coordinates: Vec::new(),
            repo_urls: Vec::new(),
            artifacts: Vec::new(),
            poms: Vec::new(),
            modules: Vec::new(),
        }
    }
}

/// A plugin prefix a group's `maven-metadata-<id>.xml` lists.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct PluginPrefix {
    /// The plugin group.
    pub group: String,
    /// The origin of the repository whose metadata was read.
    pub repo_url: String,
    /// The prefix.
    pub prefix: String,
    /// The plugin's `artifactId`.
    pub artifact: String,
}

impl PluginPrefix {
    /// The prefix `prefix` of `group:artifact`, read from `repo_url`.
    pub fn new(group: &str, repo_url: &str, prefix: &str, artifact: &str) -> Self {
        Self {
            group: group.to_string(),
            repo_url: repo_url.to_string(),
            prefix: prefix.to_string(),
            artifact: artifact.to_string(),
        }
    }
}

/// A plugin resolution of one platform: its tables and the files they
/// pin, before [`LockPlatform::set_plugins`] adds them to the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginFiles {
    /// The tables.
    pub tables: PluginTables,
    /// The artifacts the sets name.
    pub artifacts: Vec<LockArtifact>,
    /// The support POMs the sets name, by `g:a:v`.
    pub poms: BTreeMap<String, SupportPom>,
}

/// What one module's or one plugin set's resolution read, kept in memory
/// for the Maven 3.9 checks: each `group:artifact:version` whose POM it
/// read or looked for, losing versions and range candidates included, and
/// the file of each it found no POM for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PomReads {
    /// Each `group:artifact:version` whose POM it read or looked for, with
    /// the POM's digest, `None` where it found none.
    pub read: BTreeMap<Gav, Option<Sha256>>,
    /// Each it found no POM for, with the file it read.
    pub without_pom: BTreeMap<Gav, String>,
}

impl PomReads {
    /// Add what `other` read.
    pub fn extend(&mut self, other: Self) {
        for (gav, pom) in other.read {
            self.read.entry(gav).or_insert(pom);
        }
        for (gav, file) in other.without_pom {
            self.without_pom.entry(gav).or_insert(file);
        }
    }
}

/// A module's or a plugin set's [`PomReads`], by name.
#[derive(Debug, Clone, Copy)]
pub struct PomReader<'a> {
    /// The module or set, as a message names it.
    pub name: &'a str,
    /// The set's role, `None` for a module.
    pub role: Option<PluginRole>,
    /// What it read.
    pub reads: &'a PomReads,
}

/// The first file one of `readers` but a core extension read without a
/// POM, and its reader.
pub fn pomless_read<'a>(readers: &[PomReader<'a>]) -> Option<(&'a str, &'a str)> {
    (readers.iter())
        .filter(|reader| reader.role != Some(PluginRole::CoreExtension))
        .find_map(|reader| {
            let file = reader.reads.without_pom.values().next()?;
            Some((file.as_str(), reader.name))
        })
}

/// The first `group:artifact:version` a set of `readers` read another way
/// than a module or an earlier set did, with or without a POM or with
/// other bytes, as Maven 3.9 hands a later reader the first one's reading.
/// Against a core extension, which resolves in a session of its own, only
/// other bytes count, as the local repository holds one POM per version.
pub fn read_difference(readers: &[PomReader<'_>]) -> Option<DescriptorReads> {
    let core = |reader: &PomReader<'_>| reader.role == Some(PluginRole::CoreExtension);
    for (at, second) in readers.iter().enumerate() {
        if second.role.is_none() {
            continue;
        }
        for (gav, pom) in &second.reads.read {
            for first in &readers[..at] {
                let Some(other) = first.reads.read.get(gav) else {
                    continue;
                };
                let strict = !core(first) && !core(second);
                if other != pom && (strict || (other.is_some() && pom.is_some())) {
                    let file = (first.reads.without_pom.get(gav))
                        .or_else(|| second.reads.without_pom.get(gav));
                    return Some(DescriptorReads {
                        coord: file.cloned().unwrap_or_else(|| gav.to_string()),
                        first: first.name.to_string(),
                        second: second.name.to_string(),
                    });
                }
            }
        }
    }
    None
}

impl LockPlatform {
    /// What each module of the platform reads of POMs as raeva.lock records
    /// it, by path: its rows' POMs, none where a row has none,
    /// and its support POMs. A losing version's read without a POM leaves
    /// no record.
    pub fn module_pom_reads(&self) -> Vec<(String, PomReads)> {
        let rows: HashMap<&ArtifactCoord, &LockArtifact> = (self.artifacts.iter())
            .map(|row| (&row.coordinate, row))
            .collect();
        let mut found = Vec::new();
        for module in &self.modules {
            let mut reads = PomReads::default();
            let files = (module.packages.iter()).filter_map(LockModulePackage::repository_file);
            for row in files.filter_map(|coordinate| rows.get(coordinate)) {
                let gav = row.coordinate.gav.clone();
                reads.read.insert(gav.clone(), row.pom_sha256.clone());
                if row.pom_sha256.is_none() {
                    (reads.without_pom).insert(gav, row.coordinate.to_string());
                }
            }
            for key in &module.support_poms {
                let mut parts = key.splitn(3, ':');
                let (Some(group), Some(artifact), Some(version), Some(pin)) = (
                    parts.next(),
                    parts.next(),
                    parts.next(),
                    self.support_poms.get(key),
                ) else {
                    continue;
                };
                (reads.read)
                    .entry(Gav::new(group, artifact, version))
                    .or_insert_with(|| Some(pin.sha256.clone()));
            }
            found.push((module.path.clone(), reads));
        }
        found
    }
}

/// A `group:artifact:version` whose POM two readers read two ways.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorReads {
    /// The file's coordinate, or `group:artifact:version` where one read
    /// its POM alone.
    pub coord: String,
    /// The reader that read it one way.
    pub first: String,
    /// The reader that read it the other way.
    pub second: String,
}

impl PluginFiles {
    /// Empty tables resolved from `inputs`.
    pub fn new(inputs: Sha256) -> Self {
        Self {
            tables: PluginTables {
                inputs,
                sets: Vec::new(),
                prefixes: Vec::new(),
                repo_ids: RepoIds::new(),
                host_inputs: BTreeSet::new(),
                metadata_versions: Vec::new(),
                range_versions: Vec::new(),
                shared_origins: BTreeMap::new(),
                shared_without_pom: BTreeMap::new(),
            },
            artifacts: Vec::new(),
            poms: BTreeMap::new(),
        }
    }
}

impl PluginTables {
    /// Put the rows in the order the fields name, each listed once.
    pub(crate) fn sort(&mut self) {
        for set in &mut self.sets {
            let mut seen = BTreeSet::new();
            set.artifacts
                .retain(|coordinate| seen.insert(coordinate.clone()));
            set.poms.sort();
            set.poms.dedup();
            set.modules.sort();
            set.modules.dedup();
        }
        self.sets
            .sort_by(|a, b| (&a.key, a.role).cmp(&(&b.key, b.role)));
        self.prefixes.sort();
        self.prefixes.dedup();
        self.metadata_versions.sort();
        self.metadata_versions.dedup();
        self.range_versions.sort();
        self.range_versions.dedup();
    }

    /// Every repository origin the tables name, with what names it.
    pub(crate) fn origins(&self) -> impl Iterator<Item = (&str, String)> {
        let sets = self.sets.iter().flat_map(|set| {
            (set.repo_urls.iter()).map(move |url| (url.as_str(), format!("plugin set {}", set.key)))
        });
        let prefixes = self.prefixes.iter().map(|prefix| {
            (
                prefix.repo_url.as_str(),
                format!("the prefix list of plugin group '{}'", prefix.group),
            )
        });
        let ids = (self.repo_ids.keys())
            .map(|origin| (origin.as_str(), "an origin in plugins.repo_ids".to_string()));
        let shared = (self.shared_origins.values().flatten()).map(|origin| {
            (
                origin.as_str(),
                "an origin in plugins.shared_origins".to_string(),
            )
        });
        let ranges = (self.range_versions.iter()).map(|read| {
            (
                read.origin.as_str(),
                "an origin in plugins.range_versions".to_string(),
            )
        });
        sets.chain(prefixes).chain(ids).chain(shared).chain(ranges)
    }
}

impl PluginFiles {
    /// Keep the sets `keep` accepts, the rows one of them names, and the
    /// repository ids of an origin a row or set kept names, or that only
    /// what is kept named.
    pub fn retain_sets(&mut self, mut keep: impl FnMut(&PluginSet) -> bool) {
        let mut dropped: BTreeSet<String> = BTreeSet::new();
        self.tables.sets.retain(|set| {
            let kept = keep(set);
            if !kept {
                dropped.extend(set.repo_urls.iter().cloned());
            }
            kept
        });
        let sets = &self.tables.sets;
        let named: BTreeSet<&ArtifactCoord> = sets.iter().flat_map(|set| &set.artifacts).collect();
        let poms: BTreeSet<&String> = sets.iter().flat_map(|set| &set.poms).collect();
        (self.tables.shared_origins).retain(|coordinate, origins| {
            let kept = named.contains(coordinate);
            if !kept {
                dropped.extend(origins.iter().cloned());
            }
            kept
        });
        (self.tables.shared_without_pom).retain(|coordinate, _| named.contains(coordinate));
        self.artifacts.retain(|artifact| {
            let kept = named.contains(&artifact.coordinate);
            if !kept {
                dropped.extend(artifact.origins().map(str::to_string));
            }
            kept
        });
        self.poms.retain(|coordinate, pom| {
            let kept = poms.contains(coordinate);
            if !kept {
                dropped.insert(pom.repo_url.clone());
            }
            kept
        });
        // The export labels the files of an origin with its ids, so an id
        // only a dropped row's origin had labels nothing now.
        let origins: BTreeSet<&str> = (self.artifacts.iter().flat_map(LockArtifact::origins))
            .chain(self.poms.values().map(|pom| pom.repo_url.as_str()))
            .chain(
                sets.iter()
                    .flat_map(|set| set.repo_urls.iter().map(String::as_str)),
            )
            .chain(
                self.tables
                    .prefixes
                    .iter()
                    .map(|prefix| prefix.repo_url.as_str()),
            )
            .chain((self.tables.shared_origins.values().flatten()).map(String::as_str))
            .chain((self.tables.range_versions.iter()).map(|read| read.origin.as_str()))
            .collect();
        (self.tables.repo_ids)
            .retain(|origin, _| !dropped.contains(origin) || origins.contains(origin.as_str()));
    }

    /// The `group:artifact:version`s whose POM `platform`'s modules read
    /// one way and a set another, as files, parents, imports or losing
    /// versions' POMs. In the Maven 3.9 mode (`maven39`) that is any
    /// difference, with or without a POM or with other bytes, for any two
    /// files of the coordinate: Maven 3.9 gives each later reader of a file
    /// the first one's descriptor, and of another file of the coordinate
    /// the POM the first one put in the local repository. A set reading a
    /// reactor module's coordinate from a repository is listed too, as the
    /// modules after it take that reading over the module's pom.xml.
    /// Otherwise, and for a core extension, which resolves in a session of
    /// its own, it is what one local repository cannot hold: two POMs, or a
    /// POM for one file and none for another. Where a repository id names
    /// two repositories (`split_id`), a POM and none for one file count too:
    /// Maven hands the reader without a POM the one read under that id.
    pub fn descriptor_differences(
        &self,
        platform: &LockPlatform,
        maven39: bool,
        split_id: bool,
    ) -> Vec<DescriptorReads> {
        let reactor: HashMap<String, &str> = (platform.modules.iter())
            .map(|module| (module.gav.to_string(), module.path.as_str()))
            .collect();
        let rows: HashMap<&ArtifactCoord, &LockArtifact> = (platform.artifacts.iter())
            .map(|row| (&row.coordinate, row))
            .collect();
        // By `group:artifact:version`: the file read, `None` for a POM read
        // alone, its POM, and who read it.
        type Read<'a> = (Option<&'a ArtifactCoord>, Option<&'a Sha256>, &'a str);
        let mut modules: BTreeMap<String, Vec<Read<'_>>> = BTreeMap::new();
        for module in &platform.modules {
            let files = (module.packages.iter()).filter_map(LockModulePackage::repository_file);
            for row in files.filter_map(|coordinate| rows.get(coordinate)) {
                (modules.entry(row.coordinate.gav.to_string()).or_default()).push((
                    Some(&row.coordinate),
                    row.pom_sha256.as_ref(),
                    &module.path,
                ));
            }
            for key in &module.support_poms {
                let pin = platform.support_poms.get(key).map(|pin| &pin.sha256);
                (modules.entry(key.clone()).or_default()).push((None, pin, &module.path));
            }
        }
        let files: HashMap<&ArtifactCoord, Option<&Sha256>> = (self.artifacts.iter())
            .map(|artifact| (&artifact.coordinate, artifact.pom_sha256.as_ref()))
            .collect();
        let mut found = Vec::new();
        for set in (self.tables.sets.iter()).filter(|set| set.role != PluginRole::Trace) {
            let name = format!("{} {}", set.role.as_str(), set.coordinates.join(", "));
            let any = maven39 && set.role != PluginRole::CoreExtension;
            let read = (set.artifacts.iter())
                .filter_map(|coordinate| {
                    let pom = *files.get(coordinate)?;
                    Some((coordinate.gav.to_string(), Some(coordinate), pom))
                })
                .chain((set.poms.iter()).filter_map(|key| {
                    Some((key.clone(), None, Some(&self.poms.get(key)?.sha256)))
                }));
            for (key, file, pom) in read {
                if any && let Some(module) = reactor.get(&key) {
                    found.push(DescriptorReads {
                        coord: file.map_or(key, ToString::to_string),
                        first: format!("the reactor module {module}"),
                        second: name.clone(),
                    });
                    continue;
                }
                // Two POMs, or a POM for one file of the modules and the
                // set and none for the other's other file, which no pin
                // turns into one POM, or for the same file under a split id.
                // A module reads its own coordinates' model from its
                // pom.xml, so only the row's other POM counts there.
                let own = reactor.contains_key(&key);
                let one_pom_short = |other: Option<&ArtifactCoord>, read: Option<&Sha256>| {
                    let two_files = other.is_some() && file.is_some() && other != file;
                    (read.is_some() && pom.is_some())
                        || (!own && (two_files || split_id) && (read.is_some() || pom.is_some()))
                };
                let differs = (modules.get(&key).into_iter().flatten())
                    .find(|(other, read, _)| *read != pom && (any || one_pom_short(*other, *read)));
                if let Some((other, _, module)) = differs {
                    found.push(DescriptorReads {
                        coord: file.or(*other).map_or(key, ToString::to_string),
                        first: format!("module {module}"),
                        second: name.clone(),
                    });
                }
            }
        }
        found
    }

    /// Pin as a support POM the companion POM the sets read for a row
    /// `platform`'s modules use without one, where a repository the
    /// dependencies search lacks it: the row stays as the dependencies
    /// resolve it, and the export writes the POM under the repository the
    /// sets read it from, for the sets that read it.
    ///
    /// A file is refused, by coordinate, where raeva.lock cannot record
    /// which builds read its POM: the sets read the POM from repositories
    /// none of which each of them searches, by URL or id, as a support POM
    /// records one, or a support POM of its coordinate the modules or
    /// other sets pin is under one they do not search; or, beside a row
    /// the modules pin with a POM, the sets read the file without that POM
    /// from a repository the row lacks, which the export labels with the
    /// row's POM too, or read the POM from one the export does not label
    /// it with. `row_ids` are the ids of the rows' origins. A file the sets
    /// read without the row's POM is recorded by
    /// [`LockPlatform::set_plugins`] in `shared_without_pom`, as Maven 3.10
    /// reads it.
    pub fn pin_poms_rows_lack(
        &mut self,
        platform: &LockPlatform,
        row_ids: &RepoIds,
    ) -> Result<(), String> {
        let used = platform.module_rows();
        let read_ids = &self.tables.repo_ids;
        let ids = |url: &str| -> BTreeSet<&String> {
            (read_ids.iter())
                .filter(|(origin, _)| normalize_repo_url(origin) == normalize_repo_url(url))
                .flat_map(|(_, ids)| ids)
                .collect()
        };
        // `mvn -o` takes a file under any id of its repository.
        let searches = |set: &PluginSet, url: &str| {
            let held = ids(url);
            (set.repo_urls.iter()).any(|read| {
                normalize_repo_url(read) == normalize_repo_url(url) || !ids(read).is_disjoint(&held)
            })
        };
        let central = |url: &str| {
            let url = normalize_repo_url(url).to_ascii_lowercase();
            url == "https://repo1.maven.org/maven2/"
                || url == "https://repo.maven.apache.org/maven2/"
        };
        let same = |a: &str, b: &str| {
            normalize_repo_url(a) == normalize_repo_url(b) || (central(a) && central(b))
        };
        let mut added: BTreeMap<String, SupportPom> = BTreeMap::new();
        let mut pinned = Vec::new();
        for (at, artifact) in self.artifacts.iter().enumerate() {
            let Some(row) = (platform.artifacts.iter())
                .find(|row| row.coordinate == artifact.coordinate)
                .filter(|_| used.contains(&artifact.coordinate))
            else {
                continue;
            };
            if row.pom_sha256.is_some() {
                // The export labels the row's POM with the row's POM
                // origins and the file origins the sets add.
                let unrecorded: Vec<&str> =
                    unrecorded_origins(row, artifact, row_ids, read_ids).collect();
                if artifact.pom_sha256.is_none() && !unrecorded.is_empty() {
                    continue;
                }
                let poms: Vec<&str> = match artifact.pom_sha256 {
                    Some(_) => artifact.pom_origins().collect(),
                    None => Vec::new(),
                };
                let labelled = |url: &str| {
                    (row.pom_origins().chain(unrecorded.iter().copied())).any(|at| same(at, url))
                };
                if unrecorded
                    .iter()
                    .any(|url| !poms.iter().any(|pom| same(pom, url)))
                    || poms.iter().any(|url| !labelled(url))
                {
                    return Err(artifact.coordinate.to_string());
                }
                continue;
            }
            let Some(sha256) = artifact.pom_sha256.clone() else {
                continue;
            };
            let poms: Vec<&str> = artifact.pom_origins().collect();
            let reads = |set: &PluginSet| set.artifacts.contains(&artifact.coordinate);
            let mut readers: Vec<usize> = (self.tables.sets.iter().enumerate())
                .filter(|(_, set)| reads(set) && poms.iter().any(|url| searches(set, url)))
                .map(|(at, _)| at)
                .collect();
            // A POM from a repository a dependency's POM added, which no
            // set lists, serves the sets that read the file along that
            // path, which the export labels it for.
            let along = readers.is_empty();
            if along {
                readers = (self.tables.sets.iter().enumerate())
                    .filter(|(_, set)| reads(set))
                    .map(|(at, _)| at)
                    .collect();
            }
            let serves = |url: &str| match along {
                true => poms.iter().any(|pom| same(pom, url)),
                false => (readers.iter()).all(|at| searches(&self.tables.sets[*at], url)),
            };
            let coordinate = &artifact.coordinate;
            let key = format!(
                "{}:{}:{}",
                coordinate.group_id(),
                coordinate.artifact_id(),
                coordinate.version()
            );
            // A support POM of the coordinate the modules, other sets or
            // another file of it pin already keeps its repository, which
            // must serve these sets too. One only plugin tables of
            // `platform` pin is what this resolution gives again.
            let modules_read =
                (platform.modules.iter()).any(|module| module.support_poms.contains(&key));
            let held = (added.get(&key))
                .or_else(|| self.poms.get(&key))
                .or_else(|| (platform.support_poms.get(&key)).filter(|_| modules_read));
            let pom = match held {
                Some(held) => (held.sha256 == sha256
                    && held.snapshot == artifact.pom_snapshot
                    && serves(&held.repo_url))
                .then(|| held.clone()),
                None => (poms.iter()).find(|url| serves(url)).map(|url| {
                    let mut pom = SupportPom::new(*url, sha256);
                    pom.snapshot = artifact.pom_snapshot.clone();
                    pom.missing_checksum = artifact.pom_missing_checksum;
                    pom
                }),
            };
            let Some(pom) = pom else {
                return Err(artifact.coordinate.to_string());
            };
            added.insert(key.clone(), pom);
            pinned.push((at, key, readers));
        }
        for (key, pom) in added {
            self.poms.entry(key).or_insert(pom);
        }
        for (at, key, readers) in pinned {
            for set in readers {
                self.tables.sets[set].poms.push(key.clone());
            }
            let artifact = &mut self.artifacts[at];
            artifact.pom_sha256 = None;
            artifact.pom_repo_urls.clear();
            artifact.pom_missing_checksum = false;
        }
        self.tables.sort();
        Ok(())
    }

    /// [`Self::relativize_origins`] for files a resolution just read, whose
    /// origins are the URLs of the repositories they were read through. A
    /// file read through a repository whose URL the lock cannot record, such
    /// as `./repo/`, which only a mirror can serve, takes the empty origin,
    /// as a dependency row does
    /// ([`Lockfile::relativize_origins`](crate::Lockfile::relativize_origins)).
    /// A version list read through one is refused, and so are files read
    /// through several, which the empty origin cannot tell apart.
    pub fn relativize_read_origins(&mut self, origins: &LockOrigins) -> Result<(), LockError> {
        let unrecorded = |origin: &str| !origins.records_declaration(origin);
        if (self.tables.range_versions.iter()).any(|read| unrecorded(&read.origin)) {
            return Err(unrecordable_plugin_origin());
        }
        let mut read = BTreeSet::new();
        self.refuse_origins(|origin| {
            if unrecorded(origin) {
                read.insert(origin.to_string());
            }
            false
        })?;
        let ids = |origin: &String| self.tables.repo_ids.get(origin).map_or(0, BTreeSet::len);
        if read.len() > 1 || read.iter().any(|origin| ids(origin) > 1) {
            return Err(several_unrecordable_plugin_origins());
        }
        let or_none = |origin: &mut String| {
            if unrecorded(origin) {
                origin.clear();
            }
        };
        for artifact in &mut self.artifacts {
            or_none(&mut artifact.repo_url);
            for origin in (artifact.other_repo_urls.iter_mut()).chain(&mut artifact.pom_repo_urls) {
                or_none(origin);
            }
            let own = artifact.repo_url.clone();
            artifact.other_repo_urls.retain(|origin| *origin != own);
            artifact.other_repo_urls.sort();
            artifact.other_repo_urls.dedup();
            artifact.pom_repo_urls.sort();
            artifact.pom_repo_urls.dedup();
        }
        self.poms
            .values_mut()
            .for_each(|pom| or_none(&mut pom.repo_url));
        let tables = &mut self.tables;
        for set in &mut tables.sets {
            // In the order the set searched them.
            set.repo_urls.iter_mut().for_each(or_none);
            let mut seen = BTreeSet::new();
            set.repo_urls.retain(|origin| seen.insert(origin.clone()));
        }
        (tables.prefixes.iter_mut()).for_each(|prefix| or_none(&mut prefix.repo_url));
        for shared in
            (tables.shared_origins.values_mut()).chain(tables.shared_without_pom.values_mut())
        {
            *shared = std::mem::take(shared)
                .into_iter()
                .map(|mut origin| {
                    or_none(&mut origin);
                    origin
                })
                .collect();
        }
        (tables.repo_ids).retain(|origin, _| origins.records_declaration(origin));
        self.relativize_origins(origins)
    }

    fn refuse_origins(&self, mut refused: impl FnMut(&str) -> bool) -> Result<(), LockError> {
        let artifact_origins = (self.artifacts.iter()).flat_map(|artifact| {
            std::iter::once(&artifact.repo_url)
                .chain(&artifact.other_repo_urls)
                .chain(&artifact.pom_repo_urls)
        });
        let tables = &self.tables;
        let mut all = artifact_origins
            .chain(self.poms.values().map(|pom| &pom.repo_url))
            .chain(tables.sets.iter().flat_map(|set| &set.repo_urls))
            .chain(tables.prefixes.iter().map(|prefix| &prefix.repo_url))
            .chain(tables.shared_origins.values().flatten())
            .chain(tables.shared_without_pom.values().flatten())
            .chain(tables.range_versions.iter().map(|read| &read.origin));
        if all.any(|origin| refused(origin)) {
            return Err(unrecordable_plugin_origin());
        }
        Ok(())
    }

    /// Record every `file:` origin inside the project directory `origins`
    /// describes as a project-relative origin, as
    /// [`crate::Lockfile::relativize_origins`] does for the lock's rows.
    pub fn relativize_origins(&mut self, origins: &LockOrigins) -> Result<(), LockError> {
        self.refuse_origins(|origin| !origins.is_recordable(origin))?;
        for artifact in &mut self.artifacts {
            artifact.repo_url = origins.recorded(&artifact.repo_url)?;
            for origin in (artifact.other_repo_urls.iter_mut()).chain(&mut artifact.pom_repo_urls) {
                *origin = origins.recorded(origin)?;
            }
        }
        for pom in self.poms.values_mut() {
            pom.repo_url = origins.recorded(&pom.repo_url)?;
        }
        let tables = &mut self.tables;
        for url in tables.sets.iter_mut().flat_map(|set| &mut set.repo_urls) {
            *url = origins.recorded(url)?;
        }
        for prefix in &mut tables.prefixes {
            prefix.repo_url = origins.recorded(&prefix.repo_url)?;
        }
        for shared in
            (tables.shared_origins.values_mut()).chain(tables.shared_without_pom.values_mut())
        {
            *shared = (shared.iter())
                .map(|origin| origins.recorded(origin))
                .collect::<Result<_, _>>()?;
        }
        for read in &mut tables.range_versions {
            read.origin = origins.recorded(&read.origin)?;
        }
        tables.repo_ids = record_repo_ids(origins, std::mem::take(&mut tables.repo_ids))?;
        tables.sort();
        Ok(())
    }
}

impl crate::Lockfile {
    /// The lock without its plugin tables and the rows only they use, as
    /// the dependency resolution reads and writes it.
    pub fn without_plugins(&self) -> std::borrow::Cow<'_, crate::Lockfile> {
        if self.platforms.iter().all(|entry| entry.plugins.is_none()) {
            return std::borrow::Cow::Borrowed(self);
        }
        let mut lock = self.clone();
        lock.platforms
            .iter_mut()
            .for_each(LockPlatform::remove_plugins);
        std::borrow::Cow::Owned(lock)
    }
}

impl LockPlatform {
    /// The plugin tables with the rows their sets name, as
    /// [`Self::set_plugins`] takes them.
    pub fn plugin_files(&self) -> Option<PluginFiles> {
        let tables = self.plugins.clone()?;
        let named: BTreeSet<&ArtifactCoord> = (tables.sets.iter())
            .flat_map(|set| &set.artifacts)
            .collect();
        let poms: BTreeSet<&String> = (tables.sets.iter()).flat_map(|set| &set.poms).collect();
        Some(PluginFiles {
            artifacts: (self.artifacts.iter())
                .filter(|artifact| named.contains(&artifact.coordinate))
                .cloned()
                .collect(),
            poms: (self.support_poms.iter())
                .filter(|(coordinate, _)| poms.contains(coordinate))
                .map(|(coordinate, pom)| (coordinate.clone(), pom.clone()))
                .collect(),
            tables,
        })
    }

    /// Drop the plugin tables, with every artifact and support POM row only
    /// they use. A module's reactor and system packages use none. A row
    /// neither uses stays for the dependencies' checks to find.
    pub fn remove_plugins(&mut self) {
        let Some(tables) = self.plugins.take() else {
            return;
        };
        let used: BTreeSet<ArtifactCoord> = self.module_rows().into_iter().cloned().collect();
        let read: BTreeSet<&String> = (self.modules.iter())
            .flat_map(|module| &module.support_poms)
            .collect();
        let named: BTreeSet<&String> = (tables.sets.iter()).flat_map(|set| &set.poms).collect();
        let artifacts = std::mem::take(&mut self.artifacts);
        self.artifacts = artifacts
            .into_iter()
            .filter(|artifact| used.contains(&artifact.coordinate))
            .collect();
        self.support_poms
            .retain(|coord, _| read.contains(coord) || !named.contains(coord));
    }

    /// Replace the plugin tables with `files`. A file both the platform
    /// and `files` pin with other bytes is refused: `mvn -o` finds one file
    /// at a path. A row the platform holds keeps its origins, which its
    /// modules' graph digests cover, and the tables record the others.
    /// `row_ids` are the ids of the rows' origins, as `metadata.repo_ids`
    /// records them.
    pub fn set_plugins(&mut self, files: PluginFiles, row_ids: &RepoIds) -> Result<(), LockError> {
        self.remove_plugins();
        let mut tables = files.tables;
        let read_ids = tables.repo_ids.clone();
        // A trace records no POM reads, so only a resolved set's read
        // without the POM says the repository lacks it.
        let resolved: BTreeSet<ArtifactCoord> = (tables.sets.iter())
            .filter(|set| set.role != PluginRole::Trace)
            .flat_map(|set| set.artifacts.iter().cloned())
            .collect();
        let mut held: HashMap<ArtifactCoord, usize> = (self.artifacts.iter().enumerate())
            .map(|(index, artifact)| (artifact.coordinate.clone(), index))
            .collect();
        let used: BTreeSet<ArtifactCoord> = held.keys().cloned().collect();
        for artifact in files.artifacts {
            match held.get(&artifact.coordinate) {
                Some(index) => {
                    let row = &self.artifacts[*index];
                    if row.conflicts_with(&artifact)
                        || (row.pom_sha256.is_some()
                            && artifact.pom_sha256.is_some()
                            && row.pom_sha256 != artifact.pom_sha256)
                    {
                        return Err(pin_conflict(&artifact.coordinate.to_string()));
                    }
                    let unrecorded: BTreeSet<String> =
                        (unrecorded_origins(row, &artifact, row_ids, &read_ids))
                            .map(str::to_string)
                            .collect();
                    if row.pom_sha256.is_some()
                        && artifact.pom_sha256.is_none()
                        && resolved.contains(&artifact.coordinate)
                    {
                        (tables.shared_without_pom.entry(artifact.coordinate.clone()))
                            .or_default()
                            .extend(unrecorded.iter().cloned());
                    }
                    (tables
                        .shared_origins
                        .entry(artifact.coordinate.clone())
                        .or_default())
                    .extend(unrecorded);
                }
                None => {
                    held.insert(artifact.coordinate.clone(), self.artifacts.len());
                    self.artifacts.push(artifact);
                }
            }
        }
        self.artifacts
            .sort_by(|a, b| a.coordinate.cmp(&b.coordinate));
        for (coordinate, pom) in files.poms {
            match self.support_poms.get(&coordinate) {
                Some(held) if held.sha256 != pom.sha256 || held.snapshot != pom.snapshot => {
                    return Err(pin_conflict(&coordinate));
                }
                Some(_) => {}
                None => {
                    self.support_poms.insert(coordinate, pom);
                }
            }
        }
        let mut without_pom = std::mem::take(&mut tables.shared_without_pom);
        for (coordinate, origins) in std::mem::take(&mut tables.shared_origins) {
            let Ok(at) = (self.artifacts).binary_search_by(|row| row.coordinate.cmp(&coordinate))
            else {
                continue;
            };
            let row = &mut self.artifacts[at];
            let origins: BTreeSet<String> = (origins.into_iter())
                .filter(|origin| !records(row, origin, row_ids, &read_ids))
                .collect();
            if used.contains(&coordinate) {
                let without: BTreeSet<String> = (without_pom.remove(&coordinate))
                    .unwrap_or_default()
                    .intersection(&origins)
                    .cloned()
                    .collect();
                if !without.is_empty() && row.pom_sha256.is_some() {
                    tables
                        .shared_without_pom
                        .insert(coordinate.clone(), without);
                }
                if !origins.is_empty() {
                    tables.shared_origins.insert(coordinate, origins);
                }
            } else {
                // A row only the sets name records every origin they read.
                row.other_repo_urls.extend(origins);
                row.other_repo_urls.sort();
                row.other_repo_urls.dedup();
            }
        }
        tables.sort();
        self.plugins = Some(tables);
        Ok(())
    }
}

/// The origins that served `read`'s file that `row`, of the same file,
/// does not record. Maven Central's two names, raeva's default and Maven
/// 3.9's super POM's, are one repository where `mvn -o` reads the file
/// under an id the row's markers carry: where the ids `read_ids` gives
/// `read`'s origin are among those `row_ids` gives the row's.
pub fn unrecorded_origins<'a>(
    row: &'a LockArtifact,
    read: &'a LockArtifact,
    row_ids: &'a RepoIds,
    read_ids: &'a RepoIds,
) -> impl Iterator<Item = &'a str> {
    (read.file_origins()).filter(move |origin| !records(row, origin, row_ids, read_ids))
}

fn records(row: &LockArtifact, origin: &str, row_ids: &RepoIds, read_ids: &RepoIds) -> bool {
    let ids = |all: &'_ RepoIds, url: &str| {
        let url = normalize_repo_url(url);
        (all.iter())
            .find(|(known, _)| normalize_repo_url(known) == url)
            .map(|(_, ids)| ids.clone())
    };
    let central = |url: &str| {
        let url = normalize_repo_url(url).to_ascii_lowercase();
        [
            "https://repo1.maven.org/maven2/",
            "https://repo.maven.apache.org/maven2/",
        ]
        .contains(&url.as_str())
    };
    let read = ids(read_ids, origin).filter(|read| !read.is_empty());
    (row.file_origins()).any(|held| {
        normalize_repo_url(held) == normalize_repo_url(origin)
            || (central(held) && central(origin))
                && (read.as_ref())
                    .is_some_and(|read| ids(row_ids, held).is_some_and(|ids| read.is_subset(&ids)))
    })
}

fn pin_conflict(coordinate: &str) -> LockError {
    LockError::Invalid(format!(
        "the plugins and the dependencies pin different bytes for {}",
        printable(coordinate)
    ))
}

fn invalid(what: impl Into<String>) -> LockError {
    LockError::Invalid(what.into())
}

/// Check `tables` of `platform`: each set names rows the platform holds,
/// and each origin is one raeva.lock may record. Returns the indexes of the
/// artifact rows the sets name.
pub(crate) fn check(
    tables: &PluginTables,
    platform: &LockPlatform,
) -> Result<Vec<usize>, LockError> {
    let on = format!("on platform '{}'", platform.platform);
    let rows: HashMap<&ArtifactCoord, usize> = (platform.artifacts.iter().enumerate())
        .map(|(index, artifact)| (&artifact.coordinate, index))
        .collect();
    let mut used = Vec::new();
    let mut keys = BTreeSet::new();
    // A plugin file read through a repository whose URL the lock cannot
    // record is refused, so every listing here has an origin.
    for read in &tables.range_versions {
        let row = format!("the plugin tables {on}");
        if read.origin.is_empty() {
            return Err(LockError::Invalid(format!(
                "a range version of {row} names no origin"
            )));
        }
        check_range_version(read, &row)?;
    }
    for set in &tables.sets {
        let name = || format!("plugin set {} {on}", printable(&set.key));
        if !is_set_key(&set.key) {
            return Err(invalid(format!(
                "{}: a key is 'sha256:' and 64 lowercase hex characters",
                name()
            )));
        }
        if !keys.insert((&set.key, &set.role)) {
            return Err(invalid(format!("{} is listed twice", name())));
        }
        // A trace records only what the build read.
        if set.role == PluginRole::Trace
            && !(set.coordinates.is_empty() && set.repo_urls.is_empty() && set.modules.is_empty())
        {
            return Err(invalid(format!(
                "{} is a trace, which names no coordinates, repo_urls or modules",
                name()
            )));
        }
        for coordinate in &set.coordinates {
            if coordinate.is_empty() || !rv_maven_types::is_terminal_safe(coordinate) {
                return Err(invalid(format!("{} has an unreadable coordinate", name())));
            }
        }
        for artifact in &set.artifacts {
            let Some(index) = rows.get(artifact) else {
                return Err(invalid(format!(
                    "{} names artifact '{artifact}', which has no artifacts row",
                    name()
                )));
            };
            used.push(*index);
        }
        for pom in &set.poms {
            if !platform.support_poms.contains_key(pom) {
                return Err(invalid(format!(
                    "{} names support POM '{}', which has no support_poms row",
                    name(),
                    printable(pom)
                )));
            }
        }
        for module in &set.modules {
            validate_module_path(module, "plugin set module")?;
            if !(platform.modules.iter()).any(|known| known.path == *module) {
                return Err(invalid(format!(
                    "{} names module '{}', which the platform does not list",
                    name(),
                    printable(module)
                )));
            }
        }
    }
    for prefix in &tables.prefixes {
        let id = |field, text: &str| validate_coordinate_component(field, text).is_ok();
        let valid_prefix = !prefix.prefix.is_empty()
            && (prefix.prefix.bytes())
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        if !id(CoordinateField::Group, &prefix.group)
            || !valid_prefix
            || !id(CoordinateField::Artifact, &prefix.artifact)
        {
            return Err(invalid(format!(
                "invalid plugin prefix line for group {:?} {on}",
                printable(&prefix.group)
            )));
        }
    }
    let named: BTreeSet<&ArtifactCoord> = (tables.sets.iter())
        .flat_map(|set| &set.artifacts)
        .collect();
    let modules = platform.module_rows();
    for (coordinate, origins) in &tables.shared_origins {
        let row = (rows.get(coordinate)).map(|index| &platform.artifacts[*index]);
        if !named.contains(coordinate)
            || !modules.contains(coordinate)
            || origins.is_empty()
            || row.is_none_or(|row| {
                (origins.iter())
                    .any(|origin| records(row, origin, &RepoIds::new(), &RepoIds::new()))
            })
        {
            return Err(invalid(format!(
                "plugins.shared_origins {on} lists '{coordinate}', which no set and module both \
                 name, or an origin its row records"
            )));
        }
    }
    for (coordinate, origins) in &tables.shared_without_pom {
        let row = (rows.get(coordinate)).map(|index| &platform.artifacts[*index]);
        if origins.is_empty()
            || row.is_none_or(|row| row.pom_sha256.is_none())
            || (tables.shared_origins.get(coordinate))
                .is_none_or(|shared| !origins.is_subset(shared))
        {
            return Err(invalid(format!(
                "plugins.shared_without_pom {on} lists '{coordinate}', whose row pins no POM, or \
                 an origin plugins.shared_origins does not list for it"
            )));
        }
    }
    encode_repo_id_lines(&tables.repo_ids)?;
    for (origin, what) in tables.origins() {
        check_origin_text(origin, &|| format!("{what} {on}"))?;
        if is_project_relative_origin(origin) {
            validate_project_relative_origin(origin)?;
        } else if let Some(part) = rv_config::secret_url_part(origin) {
            return Err(invalid(format!(
                "{what} {on} has {part}, which may hold a credential; raeva.lock never records one"
            )));
        }
    }
    Ok(used)
}

fn is_set_key(key: &str) -> bool {
    key.strip_prefix("sha256:")
        .is_some_and(crate::codec::is_sha256_hex)
}

/// `[platforms.plugins]`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawPlugins {
    inputs: String,
    /// One prefix per line: group, prefix, artifactId and origin, tab
    /// separated.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    prefixes: String,
    /// `origin<TAB>id` lines, as `metadata.repo_ids`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    repo_ids: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    host_inputs: Vec<String>,
    /// As a module's `metadata_versions`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    metadata_versions: String,
    /// As a module's `range_versions`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    range_versions: String,
    /// One origin per line: an artifact line, a tab and the origin.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    shared_origins: String,
    /// As `shared_origins`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    shared_without_pom: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sets: Vec<RawSet>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSet {
    key: String,
    role: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    coordinates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    repo_urls: Vec<String>,
    /// One artifact per line: `group:artifact:version`, then a tab and the
    /// packaging with `:classifier` when it has one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    artifacts: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    support_poms: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    modules: String,
}

/// The keys [`RawPlugins`] and [`RawSet`] hold, for the codec's shape check.
pub(crate) const PLUGINS_SHAPE: &[&str] = &[
    "inputs",
    "prefixes?",
    "repo_ids?",
    "host_inputs?",
    "metadata_versions?",
    "range_versions?",
    "shared_origins?",
    "shared_without_pom?",
    "sets?",
];
pub(crate) const SET_SHAPE: &[&str] = &[
    "key",
    "role",
    "coordinates?",
    "repo_urls?",
    "artifacts?",
    "support_poms?",
    "modules?",
];

pub(crate) fn encode(tables: &PluginTables) -> Result<RawPlugins, LockError> {
    let mut tables = tables.clone();
    tables.sort();
    let lines = |items: &[String]| items.join("\n");
    Ok(RawPlugins {
        inputs: tables.inputs.to_string(),
        prefixes: (tables.prefixes.iter())
            .map(|prefix| {
                format!(
                    "{}\t{}\t{}\t{}",
                    prefix.group, prefix.prefix, prefix.artifact, prefix.repo_url
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        repo_ids: encode_repo_id_lines(&tables.repo_ids)?,
        host_inputs: tables.host_inputs.iter().map(ToString::to_string).collect(),
        metadata_versions: crate::codec::encode_metadata_versions(&tables.metadata_versions),
        range_versions: crate::codec::encode_range_versions(&tables.range_versions),
        shared_origins: encode_shared_origins(&tables.shared_origins),
        shared_without_pom: encode_shared_origins(&tables.shared_without_pom),
        sets: (tables.sets.iter())
            .map(|set| RawSet {
                key: set.key.clone(),
                role: set.role.as_str().to_string(),
                coordinates: set.coordinates.clone(),
                repo_urls: set.repo_urls.clone(),
                artifacts: (set.artifacts.iter())
                    .map(artifact_line)
                    .collect::<Vec<_>>()
                    .join("\n"),
                support_poms: lines(&set.poms),
                modules: lines(&set.modules),
            })
            .collect(),
    })
}

fn decode_shared_origins(
    raw: &str,
    key: &str,
    on: &str,
) -> Result<BTreeMap<ArtifactCoord, BTreeSet<String>>, LockError> {
    let mut shared: BTreeMap<ArtifactCoord, BTreeSet<String>> = BTreeMap::new();
    for line in (!raw.is_empty())
        .then(|| raw.split('\n'))
        .into_iter()
        .flatten()
    {
        let Some((artifact, origin)) = line.rsplit_once('\t') else {
            return Err(invalid(format!(
                "invalid plugins.{key} line {:?} {on}",
                printable(line)
            )));
        };
        let coordinate = parse_artifact_line(artifact, on)?;
        (shared.entry(coordinate).or_default()).insert(origin.to_string());
    }
    if encode_shared_origins(&shared) != raw {
        return Err(invalid(format!(
            "plugins.{key} {on} is not in the order raeva writes, or lists a line twice"
        )));
    }
    Ok(shared)
}

fn encode_shared_origins(shared: &BTreeMap<ArtifactCoord, BTreeSet<String>>) -> String {
    (shared.iter())
        .flat_map(|(coordinate, origins)| {
            let line = artifact_line(coordinate);
            origins
                .iter()
                .map(move |origin| format!("{line}\t{origin}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn artifact_line(coordinate: &ArtifactCoord) -> String {
    let mut line = format!(
        "{}:{}:{}\t{}",
        coordinate.group_id(),
        coordinate.artifact_id(),
        coordinate.version(),
        coordinate.extension()
    );
    if let Some(classifier) = coordinate.classifier() {
        line.push(':');
        line.push_str(classifier);
    }
    line
}

fn parse_artifact_line(line: &str, on: &str) -> Result<ArtifactCoord, LockError> {
    let bad = || {
        invalid(format!(
            "invalid plugin artifact line {:?} {on}",
            printable(line)
        ))
    };
    let (gav, kind) = line.split_once('\t').ok_or_else(bad)?;
    let mut gav = gav.split(':');
    let (Some(group), Some(artifact), Some(version), None) =
        (gav.next(), gav.next(), gav.next(), gav.next())
    else {
        return Err(bad());
    };
    let (extension, classifier) = match kind.split_once(':') {
        Some((extension, classifier)) => (extension, Some(classifier)),
        None => (kind, None),
    };
    let coordinate = ArtifactCoord::new(group, artifact, version, extension, classifier);
    validate_coordinate(&coordinate, &|| format!("plugin artifact line {on}"), false)?;
    Ok(coordinate)
}

pub(crate) fn decode(raw: RawPlugins, on: &str) -> Result<PluginTables, LockError> {
    let inputs = (crate::codec::is_sha256_hex(&raw.inputs))
        .then(|| raw.inputs.parse::<Sha256>().ok())
        .flatten()
        .ok_or_else(|| invalid(format!("plugins.inputs {on} is not a SHA-256 digest")))?;
    let lines = |text: &str| -> Vec<String> {
        match text.is_empty() {
            true => Vec::new(),
            false => text.split('\n').map(str::to_string).collect(),
        }
    };
    let mut prefixes = Vec::new();
    for line in lines(&raw.prefixes) {
        let fields: Vec<&str> = line.split('\t').collect();
        let [group, prefix, artifact, repo_url] = fields[..] else {
            return Err(invalid(format!(
                "invalid plugin prefix line {:?} {on}",
                printable(&line)
            )));
        };
        prefixes.push(PluginPrefix::new(group, repo_url, prefix, artifact));
    }
    let mut sets = Vec::new();
    for set in raw.sets {
        let poms = lines(&set.support_poms);
        for pom in &poms {
            validate_support_pom_coord(pom)?;
        }
        let role = set.role.parse().map_err(|()| {
            invalid(format!(
                "plugin set {} on {on} has role {:?}, which raeva does not write",
                printable(&set.key),
                printable(&set.role)
            ))
        })?;
        sets.push(PluginSet {
            artifacts: (lines(&set.artifacts).iter())
                .map(|line| parse_artifact_line(line, on))
                .collect::<Result<_, _>>()?,
            poms,
            modules: lines(&set.modules),
            key: set.key,
            role,
            coordinates: set.coordinates,
            repo_urls: set.repo_urls,
        });
    }
    let host_inputs = (raw.host_inputs.iter())
        .map(|text| {
            text.parse::<AmbientInput>().map_err(|err| {
                invalid(format!(
                    "plugins.host_inputs {on} lists {:?}: {err}",
                    printable(text)
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !host_inputs.is_sorted_by(|a, b| a < b) {
        return Err(invalid(format!(
            "plugins.host_inputs {on} is not in the order raeva writes, or lists an input twice"
        )));
    }
    let tables = PluginTables {
        shared_origins: decode_shared_origins(&raw.shared_origins, "shared_origins", on)?,
        shared_without_pom: decode_shared_origins(
            &raw.shared_without_pom,
            "shared_without_pom",
            on,
        )?,
        inputs,
        sets,
        prefixes,
        repo_ids: decode_repo_id_lines(&raw.repo_ids)?,
        host_inputs: host_inputs.into_iter().collect(),
        metadata_versions: crate::codec::decode_metadata_versions(
            &raw.metadata_versions,
            &format!("the plugin tables {on}"),
        )?,
        range_versions: crate::codec::decode_range_versions(
            &raw.range_versions,
            &format!("the plugin tables {on}"),
        )?,
    };
    let mut sorted = tables.clone();
    sorted.sort();
    if sorted != tables {
        return Err(invalid(format!(
            "the plugin tables {on} are not in the order raeva writes, or list a row twice"
        )));
    }
    Ok(tables)
}

/// Plugin files read through several repositories raeva.lock cannot
/// record, which the empty origin cannot tell apart.
pub fn several_unrecordable_plugin_origins() -> LockError {
    LockError::UnrecordableOrigin(
        "plugin files were read through several repositories whose URLs do not parse or have \
         a scheme raeva cannot fetch, served by mirrors, and raeva.lock records none of their \
         URLs, so it cannot tell which one served a file; correct their URLs"
            .to_string(),
    )
}

/// A plugin file read through a repository raeva.lock cannot record.
pub fn unrecordable_plugin_origin() -> LockError {
    LockError::UnrecordableOrigin(
        "a plugin file was read through a repository whose URL does not parse or has a \
         scheme raeva cannot fetch, which raeva.lock cannot record; correct that \
         repository's URL"
            .to_string(),
    )
}
#[cfg(test)]
mod tests {
    use rv_maven_types::Digest;

    use super::*;
    use crate::Lockfile;

    #[test]
    fn roles_order_as_their_names() {
        let mut roles = PluginRole::ALL;
        roles.sort_by_key(|role| role.as_str());
        assert_eq!(roles, PluginRole::ALL);
        assert!(PluginRole::ALL.is_sorted());
    }

    /// A set's repositories keep the order it searched them, with the
    /// empty origin for one raeva.lock cannot record.
    #[test]
    fn read_origins_keep_the_search_order() {
        let mut files = files();
        files.tables.sets[0].repo_urls = ["https://z.example/", "./x", "https://a.example/"]
            .map(String::from)
            .to_vec();
        let root = std::env::temp_dir();
        files
            .relativize_read_origins(&LockOrigins::for_root(&root))
            .unwrap();
        assert_eq!(
            files.tables.sets[0].repo_urls,
            ["https://z.example/", "", "https://a.example/"]
        );
    }

    /// The origins that served a file without its row's POM take the
    /// empty origin as the file's other origins do, and count as reads.
    #[test]
    fn read_origins_cover_the_origins_without_a_pom() {
        let coordinate = ArtifactCoord::new("g", "p", "1", "jar", None);
        let root = std::env::temp_dir();
        let mut files = files();
        for table in [
            &mut files.tables.shared_origins,
            &mut files.tables.shared_without_pom,
        ] {
            table.insert(coordinate.clone(), ["./x".to_string()].into());
        }
        files
            .relativize_read_origins(&LockOrigins::for_root(&root))
            .unwrap();
        assert_eq!(
            files.tables.shared_without_pom[&coordinate],
            ["".to_string()].into()
        );
        let mut files = self::files();
        for (at, origin) in ["./x", "./y"].into_iter().enumerate() {
            let table = match at {
                0 => &mut files.tables.shared_origins,
                _ => &mut files.tables.shared_without_pom,
            };
            table.insert(coordinate.clone(), [origin.to_string()].into());
        }
        assert!(
            files
                .relativize_read_origins(&LockOrigins::for_root(&root))
                .is_err()
        );
    }

    fn files() -> PluginFiles {
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        let mut set = PluginSet::new(&format!("sha256:{}", "a".repeat(64)), PluginRole::Plugin);
        set.coordinates = vec!["g:p:1".to_string()];
        set.repo_urls = vec!["https://repo.example/".to_string()];
        let coordinate = ArtifactCoord::new("g", "p", "1", "jar", None);
        set.artifacts = vec![coordinate.clone()];
        set.poms = vec!["g:parent:1".to_string()];
        set.modules = vec!["pom.xml".to_string()];
        files.tables.sets.push(set);
        let mut artifact = LockArtifact::new(coordinate, "https://repo.example/");
        artifact.checksums = vec![Digest::Sha256(Sha256::from_bytes(b"jar"))];
        artifact.pom_sha256 = Some(Sha256::from_bytes(b"pom"));
        files.artifacts.push(artifact);
        files.poms.insert(
            "g:parent:1".to_string(),
            SupportPom::new("https://repo.example/", Sha256::from_bytes(b"parent")),
        );
        files.tables.prefixes.push(PluginPrefix::new(
            "g",
            "https://repo.example/",
            "p",
            "p-maven-plugin",
        ));
        (files
            .tables
            .repo_ids
            .entry("https://repo.example/".to_string()))
        .or_default()
        .insert("central".to_string());
        files
    }

    fn lock_with(files: PluginFiles) -> Lockfile {
        let mut lock = crate::test_lock::linux_lock("1", 'a');
        lock.platforms[0]
            .set_plugins(files, &RepoIds::new())
            .unwrap();
        lock
    }

    #[test]
    fn plugin_tables_round_trip_and_their_rows_are_no_orphans() {
        let lock = lock_with(files());
        let text = lock.to_toml().unwrap();
        assert!(text.contains("[platforms.plugins]"), "{text}");
        let read = Lockfile::from_toml(&text).unwrap();
        assert_eq!(read.platforms[0].plugins, lock.platforms[0].plugins);
        assert_eq!(read.platforms[0].artifacts.len(), 2);
        assert!(read.platforms[0].support_poms.contains_key("g:parent:1"));
    }

    /// A repository inside the project is recorded as raeva.lock records
    /// the dependencies' rows: project-relative, everywhere in the tables.
    #[test]
    fn plugin_files_record_a_project_repository_relative_to_it() {
        let root = tempfile::TempDir::new().unwrap();
        let root = dunce::canonicalize(root.path()).unwrap();
        let url = format!("file://{}/repo/", root.display());
        let mut files = files();
        files.artifacts[0].repo_url = url.clone();
        files.poms.get_mut("g:parent:1").unwrap().repo_url = url.clone();
        files.tables.sets[0].repo_urls = vec![url.clone()];
        files.tables.prefixes[0].repo_url = url.clone();
        files.tables.repo_ids = [(url.clone(), ["local".to_string()].into())].into();
        files
            .relativize_origins(&LockOrigins::for_root(&root))
            .unwrap();
        assert_eq!(files.artifacts[0].repo_url, "./repo/");
        assert_eq!(files.poms["g:parent:1"].repo_url, "./repo/");
        assert_eq!(files.tables.sets[0].repo_urls, ["./repo/"]);
        assert_eq!(files.tables.prefixes[0].repo_url, "./repo/");
        assert!(files.tables.repo_ids.contains_key("./repo/"));
        let mut lock = crate::test_lock::linux_lock("1", 'a');
        lock.platforms[0]
            .set_plugins(files, &RepoIds::new())
            .unwrap();
        lock.check_origins(&LockOrigins::for_root(&root)).unwrap();
    }

    /// A set dropped from the tables takes the rows only it named along, so
    /// the platform holds no orphan row, and the ids of an origin only they
    /// named. An id of an origin no row names stays.
    #[test]
    fn a_dropped_set_takes_its_own_rows_along() {
        let base = || {
            let mut files = files();
            (files.tables.repo_ids).insert("https://idle.example/".into(), ["idle".into()].into());
            files
        };
        let mut files = base();
        let mut trace = PluginSet::new(&format!("sha256:{}", "b".repeat(64)), PluginRole::Trace);
        let coordinate = ArtifactCoord::new("g", "t", "1", "jar", None);
        trace.artifacts = vec![coordinate.clone(), files.artifacts[0].coordinate.clone()];
        trace.poms = vec!["g:tparent:1".to_string()];
        files.tables.sets.push(trace);
        (files.tables.repo_ids).insert("https://corp.example/".into(), ["corp".into()].into());
        let mut artifact = LockArtifact::new(coordinate, "https://corp.example/");
        artifact.checksums = vec![Digest::Sha256(Sha256::from_bytes(b"t"))];
        files.artifacts.push(artifact);
        files.poms.insert(
            "g:tparent:1".to_string(),
            SupportPom::new("https://repo.example/", Sha256::from_bytes(b"tparent")),
        );
        let mut lock = lock_with(files);
        let mut files = lock.platforms[0].plugin_files().unwrap();
        files.retain_sets(|set| set.role != PluginRole::Trace);
        assert_eq!(files, base());
        lock.platforms[0]
            .set_plugins(files, &RepoIds::new())
            .unwrap();
        assert_eq!(lock, lock_with(base()));
        Lockfile::from_toml(&lock.to_toml().unwrap()).unwrap();
    }

    /// A trace set names only the files and POMs the build read.
    #[test]
    fn a_trace_naming_more_than_its_files_is_refused() {
        let edits: [fn(&mut PluginSet); 3] = [
            |set| set.coordinates = vec!["g:p:1".to_string()],
            |set| set.repo_urls = vec!["https://repo.example/".to_string()],
            |set| set.modules = vec!["pom.xml".to_string()],
        ];
        for edit in edits {
            let mut files = files();
            let mut trace =
                PluginSet::new(&format!("sha256:{}", "b".repeat(64)), PluginRole::Trace);
            trace.artifacts = vec![files.artifacts[0].coordinate.clone()];
            edit(&mut trace);
            files.tables.sets.push(trace);
            let lock = lock_with(files);
            let read = (lock.to_toml()).and_then(|text| Lockfile::from_toml(&text));
            assert!(
                read.is_err_and(|error| error.to_string().contains("is a trace")),
                "{lock:?}"
            );
        }
    }

    /// Removing the tables drops the rows only they named and keeps the
    /// dependencies' rows as they were; their files put them back.
    #[test]
    fn plugin_tables_come_off_and_back_whole() {
        let mut lock = lock_with(files());
        let with = lock.platforms[0].clone();
        let files = with.plugin_files().unwrap();
        lock.platforms[0].remove_plugins();
        assert_eq!(
            lock.platforms[0],
            crate::test_lock::linux_lock("1", 'a').platforms[0]
        );
        lock.platforms[0]
            .set_plugins(files, &RepoIds::new())
            .unwrap();
        assert_eq!(lock.platforms[0], with);
    }

    #[test]
    fn a_plugin_file_with_other_bytes_than_a_dependency_is_refused() {
        let mut files = files();
        files.artifacts[0].coordinate = ArtifactCoord::new("com.example", "a", "1", "jar", None);
        files.tables.sets[0].artifacts = vec![files.artifacts[0].coordinate.clone()];
        let mut lock = crate::test_lock::linux_lock("1", 'a');
        assert!(
            lock.platforms[0]
                .set_plugins(files, &RepoIds::new())
                .is_err()
        );
    }

    /// A row the dependencies hold keeps its origins, and the tables record
    /// the one a set read it from, which goes when no set names the row.
    #[test]
    fn a_shared_row_records_the_origin_a_set_read_it_from() {
        let mut lock = crate::test_lock::linux_lock("1", 'a');
        let row = lock.platforms[0].artifacts[0].clone();
        let other = "https://plugins.example/";
        let mut files = files();
        files.tables.sets[0].artifacts.push(row.coordinate.clone());
        (files.tables.repo_ids).insert(other.into(), ["plugins".into()].into());
        let mut read = row.clone();
        read.repo_url = other.to_string();
        files.artifacts.push(read);
        lock.platforms[0]
            .set_plugins(files, &RepoIds::new())
            .unwrap();
        let platform = &lock.platforms[0];
        assert!(platform.artifacts.contains(&row));
        let tables = platform.plugins.as_ref().unwrap();
        assert_eq!(tables.shared_origins.len(), 1);
        assert_eq!(
            tables.shared_origins[&row.coordinate],
            [other.to_string()].into()
        );
        let text = lock.to_toml().unwrap();
        let read = Lockfile::from_toml(&text).unwrap();
        assert_eq!(read.platforms[0].plugins, lock.platforms[0].plugins);
        let line = format!("{}:a:1\\tjar\\t{other}", row.coordinate.group_id());
        assert!(text.contains(&line), "{line}: {text}");
        // Not named by a set, a row only the sets name, an origin the row records.
        for wrong in [
            format!("g:zz:1\\tjar\\t{other}"),
            format!("g:p:1\\tjar\\t{other}"),
            line.replace(other, &row.repo_url),
        ] {
            let message =
                (Lockfile::from_toml(&text.replace(&line, &wrong)).unwrap_err()).to_string();
            assert!(
                message.contains("which no set and module both"),
                "{message}"
            );
        }
        // A row the modules no longer use takes the origin along.
        let mut alone = lock.platforms[0].clone();
        let files = alone.plugin_files().unwrap();
        alone
            .modules
            .iter_mut()
            .for_each(|module| module.packages.clear());
        alone.set_plugins(files, &RepoIds::new()).unwrap();
        assert!(alone.plugins.as_ref().unwrap().shared_origins.is_empty());
        let kept = alone
            .artifacts
            .iter()
            .find(|kept| kept.coordinate == row.coordinate);
        assert_eq!(kept.unwrap().other_repo_urls, [other]);
        let mut files = lock.platforms[0].plugin_files().unwrap();
        files.retain_sets(|_| false);
        assert!(files.tables.shared_origins.is_empty());
        assert!(!files.tables.repo_ids.contains_key(other));
        let mut central = row.clone();
        central.repo_url = "https://repo1.maven.org/maven2/".to_string();
        let mut read = row;
        read.repo_url = "https://repo.maven.apache.org/maven2".to_string();
        // Central's two names are one repository under one id, not under two.
        let ids = |url: &str, id: &str| -> RepoIds {
            [(url.to_string(), [id.to_string()].into())].into()
        };
        let read_ids = ids("https://repo.maven.apache.org/maven2/", "central");
        let same = ids("https://repo1.maven.org/maven2/", "central");
        assert_eq!(
            unrecorded_origins(&central, &read, &same, &read_ids).count(),
            0
        );
        let other = ids("https://repo1.maven.org/maven2/", "corp");
        assert_eq!(
            unrecorded_origins(&central, &read, &other, &read_ids).count(),
            1
        );
    }

    /// A companion POM the modules' row lacks joins a support POM another
    /// set reads as a parent only where that one's repository serves the
    /// set that reads the companion.
    #[test]
    fn a_companion_pom_joins_a_parent_pin_only_from_a_repository_its_set_searches() {
        let lock = crate::test_lock::linux_lock("1", 'a');
        let mut platform = lock.platforms[0].clone();
        platform.artifacts[0].pom_sha256 = None;
        let row = platform.artifacts[0].clone();
        let gav = &row.coordinate;
        let key = format!("{}:{}:{}", gav.group_id(), gav.artifact_id(), gav.version());
        let pinned = |parent: &str| {
            let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
            let mut companion = PluginSet::new("sha256:p", PluginRole::Plugin);
            companion.artifacts = vec![row.coordinate.clone()];
            companion.repo_urls = vec!["https://a.example/".to_string()];
            let mut parents = PluginSet::new("sha256:q", PluginRole::Plugin);
            parents.poms = vec![key.clone()];
            parents.repo_urls = vec!["https://b.example/".to_string()];
            files.tables.sets = vec![companion, parents];
            let mut read = row.clone();
            read.repo_url = "https://a.example/".to_string();
            read.pom_sha256 = Some(Sha256::from_bytes(b"pom"));
            files.artifacts.push(read);
            files.poms.insert(
                key.clone(),
                SupportPom::new(parent, Sha256::from_bytes(b"pom")),
            );
            files
                .pin_poms_rows_lack(&platform, &RepoIds::new())
                .map(|()| files)
        };
        assert_eq!(
            pinned("https://b.example/").err(),
            Some(row.coordinate.to_string())
        );
        let files = pinned("https://a.example/").unwrap();
        assert_eq!(files.tables.sets[0].poms, std::slice::from_ref(&key));
        assert_eq!(files.poms[&key].repo_url, "https://a.example/");
        assert_eq!(files.artifacts[0].pom_sha256, None);
    }

    /// A SNAPSHOT build's POM keeps its stamp as a support POM, and the
    /// plugin tables join the modules' rows and support POMs only where
    /// they name the same build and bytes.
    #[test]
    fn plugin_pins_keep_and_compare_snapshot_builds() {
        let stamp = |n| crate::SnapshotStamp::new("20240101.000000", n).unwrap();
        let lock = crate::test_lock::linux_lock("1-SNAPSHOT", 'a');
        let mut platform = lock.platforms[0].clone();
        platform.artifacts[0].pom_sha256 = None;
        let row = platform.artifacts[0].clone();
        let gav = &row.coordinate;
        let key = format!("{}:{}:{}", gav.group_id(), gav.artifact_id(), gav.version());
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        let mut set = PluginSet::new("sha256:p", PluginRole::Plugin);
        set.artifacts = vec![row.coordinate.clone()];
        set.repo_urls = vec!["https://a.example/".to_string()];
        files.tables.sets = vec![set];
        let mut read = row.clone();
        read.repo_url = "https://a.example/".to_string();
        read.pom_sha256 = Some(Sha256::from_bytes(b"pom"));
        read.pom_snapshot = Some(stamp(1));
        files.artifacts.push(read);
        files
            .pin_poms_rows_lack(&platform, &RepoIds::new())
            .unwrap();
        assert_eq!(files.poms[&key].snapshot, Some(stamp(1)));

        let mut lock = crate::test_lock::linux_lock("1", 'a');
        lock.platforms[0].support_poms.insert(
            "g:parent:1-SNAPSHOT".to_string(),
            SupportPom::new("https://a.example/", Sha256::from_bytes(b"parent")),
        );
        lock.platforms[0]
            .support_poms
            .get_mut("g:parent:1-SNAPSHOT")
            .unwrap()
            .snapshot = Some(stamp(1));
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        let mut parent = SupportPom::new("https://a.example/", Sha256::from_bytes(b"parent"));
        parent.snapshot = Some(stamp(2));
        files.poms.insert("g:parent:1-SNAPSHOT".to_string(), parent);
        assert!(
            lock.platforms[0]
                .set_plugins(files, &RepoIds::new())
                .is_err()
        );

        let mut lock = crate::test_lock::linux_lock("1", 'a');
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        let mut other = lock.platforms[0].artifacts[0].clone();
        let sha1 = |digit: &str| rv_maven_types::Digest::parse("sha1", &digit.repeat(40)).unwrap();
        other.checksums.push(sha1("0"));
        lock.platforms[0].artifacts[0].checksums.push(sha1("1"));
        files.artifacts.push(other);
        assert!(
            lock.platforms[0]
                .set_plugins(files, &RepoIds::new())
                .is_err()
        );
    }

    /// A file the modules' row pins with a POM that a set reads from a
    /// repository the row lacks, which served the set no POM, is recorded:
    /// the tables keep the origin in `shared_without_pom`, and the export
    /// labels only the file with it. One that served another POM there is
    /// refused.
    #[test]
    fn a_plugin_origin_without_the_pom_of_the_modules_row_is_recorded() {
        let lock = crate::test_lock::linux_lock("1", 'a');
        let mut platform = lock.platforms[0].clone();
        platform.artifacts[0].pom_sha256 = Some(Sha256::from_bytes(b"pom"));
        let row = platform.artifacts[0].clone();
        let read = |poms: &[&str], pom: bool| {
            let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
            let mut read = row.clone();
            read.repo_url = "https://a.example/".to_string();
            read.other_repo_urls = vec!["https://b.example/".to_string()];
            read.pom_sha256 = pom.then(|| Sha256::from_bytes(b"pom"));
            read.pom_repo_urls = poms.iter().map(ToString::to_string).collect();
            files.artifacts.push(read);
            let mut set = PluginSet::new(&format!("sha256:{}", "a".repeat(64)), PluginRole::Plugin);
            set.artifacts.push(row.coordinate.clone());
            files.tables.sets.push(set);
            (files.pin_poms_rows_lack(&platform, &RepoIds::new()), files)
        };
        assert_eq!(read(&[], true).0, Ok(()));
        assert_eq!(
            read(&["https://a.example/"], true).0,
            Err(row.coordinate.to_string())
        );
        let (pinned, files) = read(&[], false);
        assert_eq!(pinned, Ok(()));
        let mut lock = lock.clone();
        lock.platforms[0] = platform.clone();
        lock.platforms[0]
            .set_plugins(files, &RepoIds::new())
            .unwrap();
        let tables = lock.platforms[0].plugins.as_ref().unwrap();
        let without =
            BTreeSet::from(["https://a.example/", "https://b.example/"].map(String::from));
        assert_eq!(tables.shared_without_pom[&row.coordinate], without);
        assert_eq!(tables.shared_origins[&row.coordinate], without);
    }

    /// As Maven 3.9 reads them, a set that reads a file's descriptor
    /// otherwise than a module, with or without a POM or with other bytes,
    /// as a row or as a parent, an import or a losing version's POM, is
    /// refused by both names. A core extension's own session reads apart.
    #[test]
    fn a_coordinate_a_module_and_a_set_read_two_ways_is_listed() {
        let lock = crate::test_lock::linux_lock("1", 'a');
        let mut platform = lock.platforms[0].clone();
        let pom = Sha256::from_bytes(b"pom");
        platform.artifacts[0].pom_sha256 = Some(pom.clone());
        let row = platform.artifacts[0].clone();
        let key = row.coordinate.gav.to_string();
        let read_split = |maven39: bool,
                          split_id: bool,
                          platform: &LockPlatform,
                          role: PluginRole,
                          read: Option<&[u8]>| {
            let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
            let mut artifact = row.clone();
            artifact.pom_sha256 = read.map(Sha256::from_bytes);
            files.artifacts.push(artifact);
            let mut set = PluginSet::new("sha256:p", role);
            set.coordinates = vec!["g:plugin:1".to_string()];
            set.artifacts.push(row.coordinate.clone());
            files.tables.sets.push(set);
            files.descriptor_differences(platform, maven39, split_id)
        };
        let read_in =
            |maven39: bool, platform: &LockPlatform, role: PluginRole, read: Option<&[u8]>| {
                read_split(maven39, false, platform, role, read)
            };
        let read_by = |platform: &LockPlatform, role: PluginRole, read: Option<&[u8]>| {
            read_in(true, platform, role, read)
        };
        let refused = vec![DescriptorReads {
            coord: row.coordinate.to_string(),
            first: format!("module {}", platform.modules[0].path),
            second: "build-extension g:plugin:1".to_string(),
        }];
        assert_eq!(
            read_by(&platform, PluginRole::BuildExtension, None),
            refused
        );
        for role in [
            PluginRole::Plugin,
            PluginRole::ProcessorPath,
            PluginRole::TestProvider,
        ] {
            assert!(!read_by(&platform, role, None).is_empty());
            assert!(!read_by(&platform, role, Some(b"other")).is_empty());
            assert_eq!(read_by(&platform, role, Some(b"pom")), []);
        }
        // A core extension, and the Maven 3.10 mode, meet only what one
        // local repository cannot hold: two POMs.
        for (maven39, role) in [
            (true, PluginRole::CoreExtension),
            (false, PluginRole::Plugin),
        ] {
            assert_eq!(read_in(maven39, &platform, role, None), []);
            assert!(!read_in(maven39, &platform, role, Some(b"other")).is_empty());
            assert_eq!(read_in(maven39, &platform, role, Some(b"pom")), []);
            // Under a split repository id, Maven hands the module the POM.
            assert!(!read_split(maven39, true, &platform, role, None).is_empty());
            assert_eq!(read_split(maven39, true, &platform, role, Some(b"pom")), []);
        }
        // Another file of the coordinate takes the POM the local repository
        // holds, and that holds one.
        let mut tests = platform.clone();
        tests.artifacts[0].coordinate = ArtifactCoord::new(
            row.coordinate.group_id(),
            row.coordinate.artifact_id(),
            row.coordinate.version(),
            "jar",
            Some("tests"),
        );
        (tests.modules[0].packages[0]) =
            crate::LockModulePackage::new(tests.artifacts[0].coordinate.clone(), None);
        assert!(!read_by(&tests, PluginRole::Plugin, None).is_empty());
        assert!(!read_in(false, &tests, PluginRole::Plugin, None).is_empty());
        assert_eq!(read_by(&tests, PluginRole::Plugin, Some(b"pom")), []);
        let mut without = platform.clone();
        without.artifacts[0].pom_sha256 = None;
        assert!(!read_by(&without, PluginRole::Plugin, Some(b"pom")).is_empty());
        assert_eq!(
            read_in(false, &without, PluginRole::Plugin, Some(b"pom")),
            []
        );
        assert_eq!(read_by(&without, PluginRole::Plugin, None), []);
        // A losing version's POM, a parent or an import.
        let mut losing = without.clone();
        losing.modules[0].packages.clear();
        losing.modules[0].support_poms = vec![key.clone()];
        losing.support_poms.insert(
            key.clone(),
            SupportPom::new("https://a.example/", pom.clone()),
        );
        assert!(!read_by(&losing, PluginRole::Plugin, None).is_empty());
        assert_eq!(read_by(&losing, PluginRole::Plugin, Some(b"pom")), []);
        // A parent or import a set reads beside a row without a POM.
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        files
            .poms
            .insert(key.clone(), SupportPom::new("https://a.example/", pom));
        let mut set = PluginSet::new("sha256:p", PluginRole::Plugin);
        set.poms.push(key);
        files.tables.sets.push(set.clone());
        assert!(
            !files
                .descriptor_differences(&without, true, false)
                .is_empty()
        );
        // A set that reads a reactor module's coordinate from a repository.
        let mut reactor = platform.clone();
        reactor.modules[0].gav = row.coordinate.gav.clone();
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        files.artifacts.push(row.clone());
        set.poms.clear();
        set.artifacts.push(row.coordinate.clone());
        files.tables.sets.push(set);
        let read = files.descriptor_differences(&reactor, true, false);
        assert_eq!(
            read[0].first,
            format!("the reactor module {}", reactor.modules[0].path)
        );
        assert_eq!(files.descriptor_differences(&reactor, false, false), []);
    }

    /// raeva.lock's record of a module's reads holds its rows' POMs, and a
    /// row without one as read without a POM.
    #[test]
    fn a_module_reads_its_rows_poms_as_recorded() {
        let lock = crate::test_lock::linux_lock("1", 'a');
        let mut platform = lock.platforms[0].clone();
        let row = platform.artifacts[0].clone();
        let path = platform.modules[0].path.clone();
        let gav = row.coordinate.gav.clone();
        platform.artifacts[0].pom_sha256 = Some(Sha256::from_bytes(b"pom"));
        let reads = platform.module_pom_reads();
        assert_eq!(reads[0].0, path);
        assert_eq!(reads[0].1.read[&gav], Some(Sha256::from_bytes(b"pom")));
        assert!(reads[0].1.without_pom.is_empty());
        platform.artifacts[0].pom_sha256 = None;
        let reads = platform.module_pom_reads();
        assert_eq!(reads[0].1.read[&gav], None);
        assert_eq!(reads[0].1.without_pom[&gav], row.coordinate.to_string());
    }

    /// A file a module or a set read without a POM is named with its
    /// reader, but not a core extension's. A set that reads a version
    /// another way than a module or an earlier set is named with it, and
    /// against a core extension only by other bytes.
    #[test]
    fn a_read_without_a_pom_or_two_ways_is_named_with_its_readers() {
        let gav = Gav::new("g", "a", "1");
        let mut without = PomReads::default();
        without.read.insert(gav.clone(), None);
        (without.without_pom).insert(gav.clone(), "g:a:1:jar".to_string());
        let mut with = PomReads::default();
        with.read
            .insert(gav.clone(), Some(Sha256::from_bytes(b"a")));
        let mut other = PomReads::default();
        other.read.insert(gav, Some(Sha256::from_bytes(b"b")));
        let reader = |name, role, reads| PomReader { name, role, reads };
        let module = reader("module m", None, &without);
        let plugin = reader("plugin p", Some(PluginRole::Plugin), &with);
        let core = |reads| reader("core-extension c", Some(PluginRole::CoreExtension), reads);
        assert_eq!(
            pomless_read(&[plugin, module]),
            Some(("g:a:1:jar", "module m"))
        );
        assert_eq!(pomless_read(&[core(&without)]), None);
        let found = read_difference(&[module, plugin]).unwrap();
        assert_eq!(
            (
                found.coord.as_str(),
                found.first.as_str(),
                found.second.as_str()
            ),
            ("g:a:1:jar", "module m", "plugin p")
        );
        assert_eq!(read_difference(&[plugin, module]), None);
        assert_eq!(read_difference(&[module, core(&with)]), None);
        assert!(read_difference(&[plugin, core(&other)]).is_some());
    }

    /// Two files of one coordinate the modules use without a POM, which
    /// two sets read with it from two repositories, share one support POM:
    /// one each set searches, or a refusal. A POM the modules pin as a
    /// parent keeps its repository, which the sets must search. A POM from
    /// a repository no set lists, which a dependency's POM added, serves
    /// every set that reads the file.
    #[test]
    fn a_companion_pom_takes_one_pin_for_every_file_and_build_of_its_coordinate() {
        let lock = crate::test_lock::linux_lock("1", 'a');
        let mut platform = lock.platforms[0].clone();
        platform.artifacts[0].pom_sha256 = None;
        let row = platform.artifacts[0].clone();
        let gav = &row.coordinate;
        let key = format!("{}:{}:{}", gav.group_id(), gav.artifact_id(), gav.version());
        let mut tests = row.clone();
        tests.coordinate = ArtifactCoord::new(
            gav.group_id(),
            gav.artifact_id(),
            gav.version(),
            "jar",
            Some("tests"),
        );
        platform.artifacts.push(tests.clone());
        (platform.modules[0].packages).push(crate::LockModulePackage::new(
            tests.coordinate.clone(),
            None,
        ));
        let read = |row: &LockArtifact, from: &str, searched: &[&str]| {
            let mut set = PluginSet::new(&format!("sha256:{from}"), PluginRole::Plugin);
            set.artifacts = vec![row.coordinate.clone()];
            set.repo_urls = searched.iter().map(ToString::to_string).collect();
            let mut read = row.clone();
            read.repo_url = from.to_string();
            read.pom_sha256 = Some(Sha256::from_bytes(b"pom"));
            (set, read)
        };
        let pinned = |platform: &LockPlatform, b: &[&str]| {
            let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
            for (set, read) in [
                read(&row, "https://a.example/", &["https://a.example/"]),
                read(&tests, "https://b.example/", b),
            ] {
                files.tables.sets.push(set);
                files.artifacts.push(read);
            }
            files
                .pin_poms_rows_lack(platform, &RepoIds::new())
                .map(|()| files)
        };
        assert!(pinned(&platform, &["https://b.example/"]).is_err());
        let both = ["https://b.example/", "https://a.example/"];
        let files = pinned(&platform, &both).unwrap();
        assert_eq!(files.poms[&key].repo_url, "https://a.example/");
        assert!(
            files
                .tables
                .sets
                .iter()
                .all(|set| set.poms == [key.clone()])
        );
        // One the plugin tables alone pin is what the sets read again, at
        // the repository they read it from.
        let mut parent = platform.clone();
        parent.support_poms.insert(
            key.clone(),
            SupportPom::new("https://c.example/", Sha256::from_bytes(b"pom")),
        );
        let files = pinned(&parent, &both).unwrap();
        assert_eq!(files.poms[&key].repo_url, "https://a.example/");
        parent.modules[0].support_poms.push(key.clone());
        assert!(pinned(&parent, &both).is_err());
        // Along a dependency's path: no set lists the repository.
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        let (set, read) = read(&row, "https://a.example/", &["https://a.example/"]);
        let mut read = read;
        read.pom_repo_urls = vec!["https://added.example/".to_string()];
        files.tables.sets.push(set);
        files.artifacts.push(read);
        files
            .pin_poms_rows_lack(&platform, &RepoIds::new())
            .unwrap();
        assert_eq!(files.poms[&key].repo_url, "https://added.example/");
        assert_eq!(files.tables.sets[0].poms, std::slice::from_ref(&key));
    }

    /// A POM the sets read from a repository the export does not label
    /// the modules' row's POM with is refused.
    #[test]
    fn a_plugin_pom_origin_the_modules_row_lacks_is_refused() {
        let lock = crate::test_lock::linux_lock("1", 'a');
        let mut platform = lock.platforms[0].clone();
        let row = &mut platform.artifacts[0];
        row.pom_sha256 = Some(Sha256::from_bytes(b"pom"));
        row.pom_repo_urls = vec!["https://c.example/".to_string()];
        let row = row.clone();
        let read = |pom: &str| {
            let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
            let mut read = row.clone();
            read.pom_repo_urls = vec![pom.to_string()];
            files.artifacts.push(read);
            files.pin_poms_rows_lack(&platform, &RepoIds::new())
        };
        assert_eq!(read("https://c.example/"), Ok(()));
        assert_eq!(read("https://b.example/"), Err(row.coordinate.to_string()));
    }

    /// Text from a checkout is held to raeva.lock's rules.
    #[test]
    fn plugin_tables_from_a_checkout_are_checked() {
        let text = lock_with(files()).to_toml().unwrap();
        for (from, to, error) in [
            ("g:p:1\\tjar", "g:q:1\\tjar", "has no artifacts row"),
            (
                "support_poms = \"g:parent:1\"",
                "support_poms = \"g:other:1\"",
                "has no support_poms row",
            ),
            (
                "repo_urls = [\"https://repo.example/\"]",
                "repo_urls = [\"https://user:secret@repo.example/\"]",
                "may hold a credential",
            ),
            ("role = \"plugin\"", "role = \"mojo\"", "does not write"),
            (
                "p\\tp-maven-plugin\\t",
                "p\\tp-maven-plugin\\tx\\t",
                "prefix line",
            ),
            (
                "g\\tp\\tp-maven-plugin",
                "g.\\tp\\tp-maven-plugin",
                "prefix line",
            ),
            ("g\\tp\\tp-maven-plugin", "g\\tp\\t..", "prefix line"),
            (
                "modules = \"pom.xml\"",
                "modules = \"ghost/pom.xml\"",
                "which the platform does not list",
            ),
        ] {
            assert!(text.contains(from), "{from}: {text}");
            let message = Lockfile::from_toml(&text.replace(from, to))
                .unwrap_err()
                .to_string();
            assert!(message.contains(error), "{error}: {message}");
            assert!(!message.contains("secret"), "{message}");
        }
    }
}
