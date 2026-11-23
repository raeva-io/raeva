//! A [`PluginResolution`] as the plugin tables of its platform.

use std::collections::{BTreeMap, BTreeSet};

use rv_lock::{
    LockArtifact, PluginFiles, PluginPrefix, PluginRole, PluginSet, RepoIds, SupportPom,
    is_recordable_repo_id,
};
use rv_maven_types::{ArtifactCoord, Sha256};

use super::{PluginResolution, ResolvedPluginSet};
use crate::error::{ResolveError, Result};

impl PluginResolution {
    /// Refuse a `group:artifact:version` two sets read two ways, as files
    /// or as parents, imports or losing versions' POMs. In the Maven 3.9
    /// mode (`maven39`) that is any difference, with or without a POM or
    /// with other bytes, for any two files of it: Maven 3.9 gives each later
    /// reader of a file the first one's descriptor, and of another file of
    /// the coordinate the POM the first one put in the local repository.
    /// Otherwise, and against a core extension, which resolves in a session
    /// of its own, it is what one local repository cannot hold: two POMs,
    /// or a POM and none where a repository id names two repositories
    /// (`split_id`), as Maven hands the POM read under it to the other.
    pub(crate) fn refuse_descriptor_reads(&self, maven39: bool, split_id: bool) -> Result<()> {
        let name = |set: &ResolvedPluginSet| {
            format!("{} {}", set.role.as_str(), set.coordinates.join(", "))
        };
        // By `group:artifact:version`: the file read, `None` for a POM read
        // alone, its POM, and the set.
        type Read<'a> = (
            Option<&'a ArtifactCoord>,
            Option<Sha256>,
            &'a ResolvedPluginSet,
        );
        let mut reads: BTreeMap<String, Vec<Read<'_>>> = BTreeMap::new();
        for set in &self.sets {
            let files = (set.artifacts.iter()).filter_map(|package| {
                let artifact = package.artifact.as_ref()?;
                let coordinate = &package.coordinate;
                Some((
                    coordinate.gav.to_string(),
                    Some(coordinate),
                    artifact.companion_pom.clone(),
                ))
            });
            let poms = (set.poms.iter())
                .filter_map(|(key, pom)| Some((key.clone(), None, Some(pom.sha256.parse().ok()?))));
            for (key, file, pom) in files.chain(poms) {
                let held = reads.entry(key.clone()).or_default();
                let differs = held.iter().find(|(_, read, by)| {
                    let any = maven39
                        && set.role != PluginRole::CoreExtension
                        && by.role != PluginRole::CoreExtension;
                    *read != pom && (any || split_id || (read.is_some() && pom.is_some()))
                });
                if let Some((other, _, by)) = differs {
                    let coord = file.or(*other).map_or(key, ToString::to_string);
                    let (first, second) = (name(by), name(set));
                    return Err(match maven39 {
                        true => ResolveError::SharedDescriptorDiffers {
                            coord,
                            first,
                            second,
                        },
                        false => ResolveError::OnePomPerVersion {
                            coord,
                            first,
                            second,
                        },
                    });
                }
                held.push((file, pom, set));
            }
        }
        Ok(())
    }

    /// The tables of this resolution, resolved from `inputs`, with their
    /// files. Two sets that read other bytes for one file are refused:
    /// `mvn -o` finds one file at a path.
    pub(crate) fn into_files(self, inputs: Sha256) -> Result<PluginFiles> {
        let mut files = PluginFiles::new(inputs);
        let tables = &mut files.tables;
        let mut artifacts: BTreeMap<ArtifactCoord, LockArtifact> = BTreeMap::new();
        // The repositories that served each file's POM, where one did.
        let mut pom_origins: BTreeMap<ArtifactCoord, BTreeSet<String>> = BTreeMap::new();
        let mut set_artifacts: Vec<Vec<ArtifactCoord>> = Vec::new();
        for set in &self.sets {
            let mut coordinates = Vec::new();
            for package in &set.artifacts {
                let Some(artifact) = package.artifact.clone() else {
                    continue;
                };
                // The jar of a SNAPSHOT plugin itself comes with no build.
                if artifact.snapshot.is_some()
                    || artifact.pom_snapshot.is_some()
                    || rv_maven_types::is_snapshot_version(package.coordinate.version())
                {
                    return Err(ResolveError::Plugin {
                        plugin: format!("{} {}", set.role.as_str(), set.coordinates.join(", ")),
                        searched: Vec::new(),
                        error: Box::new(ResolveError::PluginSnapshot {
                            coord: package.coordinate.to_string(),
                        }),
                    });
                }
                let pom_repo = artifact.pom_repo_url.clone();
                let row = crate::lock::lock_artifact(package.coordinate.clone(), artifact);
                if row.pom_sha256.is_some() {
                    (pom_origins.entry(package.coordinate.clone()).or_default())
                        .insert(pom_repo.unwrap_or_else(|| row.repo_url.clone()));
                }
                match artifacts.get_mut(&package.coordinate) {
                    Some(held) => {
                        // A repository without the POM reads the file
                        // without dependencies, which Maven does where
                        // another has it.
                        if held.pin() != row.pin()
                            || (held.pom_sha256.is_some()
                                && row.pom_sha256.is_some()
                                && held.pom_sha256 != row.pom_sha256)
                        {
                            return Err(conflict(&package.coordinate.to_string()));
                        }
                        if held.pom_sha256.is_none() {
                            held.pom_sha256 = row.pom_sha256;
                        }
                        if row.repo_url != held.repo_url
                            && !held.other_repo_urls.contains(&row.repo_url)
                        {
                            held.other_repo_urls.push(row.repo_url);
                            held.other_repo_urls.sort();
                        }
                    }
                    None => {
                        artifacts.insert(package.coordinate.clone(), row);
                    }
                }
                coordinates.push(package.coordinate.clone());
            }
            set_artifacts.push(coordinates);
            for (coordinate, provenance) in &set.poms {
                let sha256 = provenance.sha256.parse().map_err(|error| {
                    ResolveError::InternalError(format!("POM digest for {coordinate}: {error}"))
                })?;
                let mut pin = SupportPom::new(provenance.repo_url.clone(), sha256);
                pin.snapshot = provenance.snapshot.clone();
                match files.poms.get(coordinate) {
                    Some(held) if held.sha256 != pin.sha256 || held.snapshot != pin.snapshot => {
                        return Err(conflict(coordinate));
                    }
                    Some(_) => {}
                    None => {
                        files.poms.insert(coordinate.clone(), pin);
                    }
                }
                record_id(
                    &mut tables.repo_ids,
                    &provenance.repo_url,
                    &provenance.repo_id,
                );
            }
            for (url, id) in &set.repositories {
                record_id(&mut tables.repo_ids, url, id);
            }
        }
        let mut modules: Vec<Vec<String>> = vec![Vec::new(); self.sets.len()];
        for module in &self.modules {
            for set in &module.sets {
                modules[*set].push(module.pom_path.clone());
            }
        }
        for ((set, coordinates), modules) in self.sets.iter().zip(&set_artifacts).zip(modules) {
            let mut row = PluginSet::new(&set.key, set.role);
            row.coordinates.clone_from(&set.coordinates);
            row.repo_urls.clone_from(&set.repo_urls);
            row.artifacts.clone_from(coordinates);
            row.poms = set
                .poms
                .iter()
                .map(|(coordinate, _)| coordinate.clone())
                .collect();
            row.modules = modules;
            tables.sets.push(row);
        }
        tables.metadata_versions = self.metadata_versions.into_iter().collect();
        tables.range_versions = (self.sets.iter())
            .flat_map(|set| set.range_versions.iter().cloned())
            .collect();
        tables.range_versions.sort();
        tables.range_versions.dedup();
        tables.prefixes = (self.metadata.into_iter())
            .map(|prefix| {
                record_id(&mut tables.repo_ids, &prefix.repo_url, &prefix.repo_id);
                PluginPrefix::new(
                    &prefix.group_id,
                    &prefix.repo_url,
                    &prefix.prefix,
                    &prefix.artifact_id,
                )
            })
            .collect();
        // Maven's local repository holds one POM for a coordinate: a file
        // the sets read without it, from repositories that lack it, beside
        // another file of the coordinate read with it, takes that POM from
        // the repositories that served it.
        let mut served_poms = BTreeMap::new();
        for row in artifacts.values() {
            if let (Some(sha256), Some(read)) = (&row.pom_sha256, pom_origins.get(&row.coordinate))
            {
                let (_, origins, missing) = (served_poms.entry(row.coordinate.gav.clone()))
                    .or_insert_with(|| (sha256.clone(), BTreeSet::new(), false));
                origins.extend(read.iter().cloned());
                *missing |= row.pom_missing_checksum;
            }
        }
        for row in artifacts.values_mut() {
            if row.pom_sha256.is_none()
                && let Some((sha256, origins, missing)) = served_poms.get(&row.coordinate.gav)
            {
                row.pom_sha256 = Some(sha256.clone());
                row.pom_missing_checksum = *missing;
                pom_origins.insert(row.coordinate.clone(), origins.clone());
            }
        }
        // A POM some repositories of the file lack lists those that served
        // it.
        for row in artifacts.values_mut() {
            let Some(read) = pom_origins.remove(&row.coordinate) else {
                continue;
            };
            let served: BTreeSet<String> = row.file_origins().map(str::to_string).collect();
            if read != served {
                row.pom_repo_urls = read.into_iter().collect();
            }
        }
        files.artifacts = artifacts.into_values().collect();
        Ok(files)
    }
}

fn record_id(repo_ids: &mut RepoIds, url: &str, id: &str) {
    if !id.is_empty() && is_recordable_repo_id(id) && is_recordable_repo_id(url) {
        (repo_ids.entry(url.to_string()).or_default()).insert(id.to_string());
    }
}

fn conflict(coordinate: &str) -> ResolveError {
    ResolveError::ConflictingPluginBytes {
        coord: coordinate.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use rv_lock::PluginRole;
    use rv_maven_types::{ArtifactCoord, BlobId, SnapshotStamp};

    use super::super::{PluginResolution, ResolvedPluginSet};
    use crate::error::ResolveError;
    use crate::output::{ResolvedArtifact, ResolvedPackage};

    fn set(key: &str, version: &str, bytes: &[u8], snapshot: bool) -> ResolvedPluginSet {
        let coordinate = ArtifactCoord::new("t", "p", version, "jar", None);
        ResolvedPluginSet {
            key: key.to_string(),
            role: PluginRole::Plugin,
            coordinates: vec![coordinate.to_string()],
            repo_urls: vec!["https://repo.example/".to_string()],
            artifacts: vec![ResolvedPackage {
                coordinate,
                direct_scope: None,
                scope: rv_lock::Scope::Runtime,
                workspace_module: None,
                system_path: None,
                managed: None,
                artifact: Some(ResolvedArtifact {
                    version: version.to_string(),
                    snapshot: snapshot.then(|| SnapshotStamp::new("20240101.000000", 1).unwrap()),
                    pom_snapshot: None,
                    pom_base: false,
                    pom_repo_url: None,
                    repo_url: "https://repo.example/".to_string(),
                    blob: BlobId::from_bytes(bytes),
                    companion_pom: Some(BlobId::from_bytes(b"pom")),
                }),
            }],
            poms: Vec::new(),
            repositories: Vec::new(),
            metadata_versions: Vec::new(),
            range_versions: Vec::new(),
            pom_reads: Default::default(),
            reactor_later: Vec::new(),
        }
    }

    fn into_files(sets: Vec<ResolvedPluginSet>) -> ResolveError {
        let resolution = PluginResolution {
            sets,
            modules: Vec::new(),
            metadata: Vec::new(),
            metadata_versions: Default::default(),
            host_reads: Default::default(),
        };
        let inputs = rv_maven_types::Sha256::from_bytes(b"inputs");
        let ResolveError::Plugin { error, .. } = resolution.into_files(inputs).unwrap_err() else {
            panic!("not a plugin error");
        };
        *error
    }

    /// A SNAPSHOT plugin, and two sets that read other bytes for one file,
    /// are the project's or the repositories' doing, not raeva's.
    #[test]
    fn plugin_files_raeva_cannot_pin_are_resolution_errors() {
        assert!(matches!(
            into_files(vec![set("sha256:a", "1-SNAPSHOT", b"jar", true)]),
            ResolveError::PluginSnapshot { .. }
        ));
        assert!(matches!(
            into_files(vec![set("sha256:a", "1-SNAPSHOT", b"jar", false)]),
            ResolveError::PluginSnapshot { .. }
        ));
        let resolution = PluginResolution {
            sets: vec![
                set("sha256:a", "1", b"one", false),
                set("sha256:b", "1", b"two", false),
            ],
            modules: Vec::new(),
            metadata: Vec::new(),
            metadata_versions: Default::default(),
            host_reads: Default::default(),
        };
        let inputs = rv_maven_types::Sha256::from_bytes(b"inputs");
        assert!(matches!(
            resolution.into_files(inputs),
            Err(ResolveError::ConflictingPluginBytes { .. })
        ));
    }

    /// A file one set reads with a POM and another without is refused by
    /// both sets' names in the Maven 3.9 mode, for any two files of the
    /// coordinate, but not against a core extension or in the Maven 3.10
    /// mode, where a pin records it, unless a repository id names two
    /// repositories. One read with other bytes as a parent
    /// of another set is refused in either mode.
    #[test]
    fn a_file_two_sets_read_with_and_without_a_pom_is_refused() {
        let reads_split =
            |maven39: bool, split_id: bool, role: PluginRole, classifier: Option<&str>| {
                let mut without = set("sha256:b", "1", b"one", false);
                without.role = role;
                without.coordinates = vec!["t:q:1".to_string()];
                let artifact = without.artifacts[0].artifact.as_mut().unwrap();
                artifact.companion_pom = None;
                if let Some(classifier) = classifier {
                    let coordinate = &without.artifacts[0].coordinate;
                    without.artifacts[0].coordinate = ArtifactCoord::new(
                        coordinate.group_id(),
                        coordinate.artifact_id(),
                        coordinate.version(),
                        "jar",
                        Some(classifier),
                    );
                }
                let resolution = PluginResolution {
                    sets: vec![set("sha256:a", "1", b"one", false), without],
                    modules: Vec::new(),
                    metadata: Vec::new(),
                    metadata_versions: Default::default(),
                    host_reads: Default::default(),
                };
                resolution.refuse_descriptor_reads(maven39, split_id)
            };
        let reads_in = |maven39: bool, role: PluginRole, classifier: Option<&str>| {
            reads_split(maven39, false, role, classifier)
        };
        let reads = |role: PluginRole| reads_in(true, role, None);
        let Err(ResolveError::SharedDescriptorDiffers { first, second, .. }) =
            reads(PluginRole::BuildExtension)
        else {
            panic!("not refused");
        };
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("plugin t:p:1:jar", "build-extension t:q:1")
        );
        assert!(reads(PluginRole::CoreExtension).is_ok());
        // Under a split repository id, Maven hands the reader without a POM
        // the one read under it.
        assert!(reads_split(true, true, PluginRole::CoreExtension, None).is_err());
        assert!(reads_split(false, true, PluginRole::Plugin, None).is_err());
        assert!(reads_in(false, PluginRole::Plugin, None).is_ok());
        assert!(reads(PluginRole::Plugin).is_err());
        assert!(reads_in(false, PluginRole::Plugin, Some("tests")).is_ok());
        assert!(reads_in(true, PluginRole::Plugin, Some("tests")).is_err());
        let mut parent = set("sha256:b", "2", b"two", false);
        let provenance = crate::SupportPomProvenance {
            sha256: rv_maven_types::Sha256::from_bytes(b"other").to_string(),
            ..Default::default()
        };
        parent.poms.push(("t:p:1".to_string(), provenance));
        let resolution = PluginResolution {
            sets: vec![set("sha256:a", "1", b"one", false), parent],
            modules: Vec::new(),
            metadata: Vec::new(),
            metadata_versions: Default::default(),
            host_reads: Default::default(),
        };
        assert!(matches!(
            resolution.refuse_descriptor_reads(true, false),
            Err(ResolveError::SharedDescriptorDiffers { .. })
        ));
        assert!(matches!(
            resolution.refuse_descriptor_reads(false, false),
            Err(ResolveError::OnePomPerVersion { .. })
        ));
    }
}
