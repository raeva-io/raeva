//! Maven's plugin version resolver, for a plugin no model gives a version:
//! the merged metadata of the plugin repositories names a `<release>` (else
//! a `<latest>`), taken when its POM's prerequisite holds for the running
//! Maven and its descriptor's for the JDK; otherwise the newest release that passes, then
//! the newest snapshot.

use std::collections::BTreeSet;
use std::sync::Arc;

use rv_lock::MetadataVersionKind;
use rv_maven_model::{HostInput, PluginDescriptor};
use rv_maven_types::{ArtifactCoord, Coord, MavenMode, Version, VersionReq};
use rv_repo::{ArtifactRequest, RepoError, Repository};

use super::request::Planner;
use crate::context::{ListingRead, RepoContext};
use crate::error::{ResolveError, Result};
use crate::resolver::PlatformResolver;
use crate::resolver::backend::{ModelService, WorkspaceSupportPomBuffer, record_listing};
use crate::resolver::utils::{
    FetchError, fetch_artifact_from_repos, remember_search_error, stored_in_first,
};
use crate::solver::Backend;

/// The versions the plugin repositories list, merged as Maven merges them.
#[derive(Default)]
struct Versions {
    /// The newest `<release>` and `<latest>`, each with the `lastUpdated`
    /// of the metadata that named it.
    release: Option<(String, String)>,
    latest: Option<(String, String)>,
    /// Each version any repository lists.
    listed: Vec<String>,
}

impl Versions {
    /// Merge one repository's metadata as Maven does: its `<release>` and
    /// `<latest>` count only with a later `lastUpdated` than those merged,
    /// so never without one.
    fn merge(&mut self, metadata: &rv_repo::Metadata) {
        let stamp = metadata.last_updated.as_deref().unwrap_or_default().trim();
        for (named, merged) in [
            (&metadata.release, &mut self.release),
            (&metadata.latest, &mut self.latest),
        ] {
            if let Some(version) = named.as_ref().filter(|version| !version.is_empty())
                && stamp > merged.as_ref().map_or("", |(_, seen)| seen.as_str())
            {
                *merged = Some((version.clone(), stamp.to_string()));
            }
        }
        for version in &metadata.versions {
            if !self.listed.contains(version) {
                self.listed.push(version.clone());
            }
        }
    }
}

impl Planner<'_> {
    /// The version Maven resolves for `group_id:artifact_id` from
    /// `repos` of `module`, for its build extensions or plugins, recorded as
    /// the export's `<release>`.
    pub(super) async fn metadata_version(
        &mut self,
        (module, extension): (&str, bool),
        group_id: &str,
        artifact_id: &str,
        repos: &[Repository],
    ) -> Result<String> {
        // A frozen check holds the version the lock took for the module
        // when a newer one was marked since, while a repository still
        // lists it; one the module names itself, such as a goal's, only
        // when it took no other.
        let key = (
            module.to_string(),
            extension,
            format!("{group_id}:{artifact_id}"),
        );
        let held: Vec<&String> = self.held.get(&key).into_iter().flatten().collect();
        let named = |held: &&String| self.named.contains(&format!("{}:{held}", key.2));
        // Modules that list one URL with other policies or ids read other
        // metadata, and take other versions.
        let cache_key = format!(
            "{} {:?} {:?}",
            key.2,
            (repos.iter())
                .map(|repo| (
                    &repo.id,
                    &repo.url,
                    repo.releases_enabled,
                    repo.snapshots_enabled
                ))
                .collect::<Vec<_>>(),
            (held.iter())
                .map(|held| (held, named(held)))
                .collect::<Vec<_>>()
        );
        if let Some(version) = self.versions.get(&cache_key) {
            return Ok(version.clone());
        }
        let resolver = self.resolver();
        let versions = resolver
            .plugin_versions(group_id, artifact_id, repos)
            .await?;
        let mode = resolver.ctx.config.lock.maven.mode;
        let support_poms = self.support_poms.as_ref();
        let taken: Vec<&String> = held.iter().copied().filter(|held| !named(held)).collect();
        let held = (if taken.is_empty() { held } else { taken })
            .into_iter()
            .filter(|held| versions.listed.contains(*held))
            .filter_map(|held| Version::parse(held).ok())
            .max_by(|a, b| a.cmp_in(b, mode));
        let mut chosen = None;
        // The held version first, which a spelling listed before it that
        // compares equal hides from the candidates.
        let held_first = held.as_ref().map(|held| held.as_str().to_string());
        for version in held_first.into_iter().chain(candidates(&versions, mode)) {
            // Nor another spelling of the held version.
            let newer = |held: &Version| {
                Version::parse(&version).is_ok_and(|taken| {
                    taken.as_str() != held.as_str() && taken.cmp_in(held, mode).is_ge()
                })
            };
            if held.as_ref().is_some_and(newer) {
                continue;
            }
            if (resolver.compatible(group_id, artifact_id, &version, repos, support_poms)).await? {
                chosen = Some(version);
                break;
            }
        }
        if let Some(version) = chosen {
            // Written as `<release>`, which `mvn -o` tries first, whatever
            // marker or listing the version came from.
            self.markers.insert(rv_lock::MetadataVersion {
                group: group_id.to_string(),
                artifact: artifact_id.to_string(),
                kind: MetadataVersionKind::Release,
                version: version.clone(),
            });
            self.versions.insert(cache_key, version.clone());
            return Ok(version);
        }
        Err(ResolveError::VersionNotFound {
            coord: format!("{group_id}:{artifact_id}"),
            requirement: format!(
                "a plugin version whose prerequisites Maven {} meets",
                resolver.ctx.config.lock.maven.mode.version()
            ),
        })
    }
}

impl PlatformResolver {
    async fn plugin_versions(
        &self,
        group_id: &str,
        artifact_id: &str,
        repos: &[Repository],
    ) -> Result<Versions> {
        let client = self
            .ctx
            .client
            .as_ref()
            .ok_or(ResolveError::NoRepositories)?;
        let coord: Coord = format!("{group_id}:{artifact_id}:0")
            .parse()
            .map_err(ResolveError::Version)?;
        let mut versions = Versions::default();
        let mut served = Vec::new();
        let mut missing = Vec::new();
        let mut first_error = None;
        let mut skipped = Vec::new();
        for repo in repos {
            // Maven reads the metadata as a release or snapshot list from
            // each repository that enables either.
            let listing = match repo.version_listing(true) {
                Ok(Some(listing)) => listing,
                Ok(None) => continue,
                Err(error) => {
                    return Err(ResolveError::Repo {
                        coord: Some(format!("{group_id}:{artifact_id}")),
                        source: Box::new(error),
                        searched: Vec::new(),
                    });
                }
            };
            let metadata = match client.fetch_metadata(&listing, &coord).await {
                Ok(metadata) => metadata,
                Err(error) if stops_listing(&error) => {
                    return Err(ResolveError::Repo {
                        coord: Some(format!("{group_id}:{artifact_id}")),
                        source: Box::new(error),
                        searched: Vec::new(),
                    });
                }
                Err(error) => {
                    if matches!(error, RepoError::NotFound(_)) && !error.is_filtered() {
                        missing.push(client.effective_repository(&listing));
                    }
                    if !matches!(error, RepoError::NotFound(_) | RepoError::BlockedMirror(_)) {
                        skipped.push((client.effective_repository(&listing), error.to_string()));
                    }
                    remember_search_error(&mut first_error, error);
                    continue;
                }
            };
            versions.merge(&metadata);
            served.push((client.effective_repository(&listing), metadata));
        }
        let read = ListingRead::Plugin {
            among_others: served.len() > 1,
        };
        let coord = (group_id, artifact_id);
        for (repo, metadata) in &served {
            record_listing(&self.ctx.id_listings, repo, coord, read, metadata);
        }
        // A 404 is an empty listing under the id, as for a dependency.
        let none_listed = rv_repo::Metadata::default();
        for repo in &missing {
            record_listing(&self.ctx.id_listings, repo, coord, read, &none_listed);
        }
        let coordinate = format!("{group_id}:{artifact_id}");
        if served.is_empty() {
            return Err(match first_error {
                Some(source) => ResolveError::Repo {
                    coord: Some(coordinate),
                    source: Box::new(source),
                    searched: Vec::new(),
                },
                None => ResolveError::ArtifactNotFound {
                    dropped_repos: Vec::new(),
                    coord: coordinate,
                    searched: Vec::new(),
                    classifier_like: None,
                },
            });
        }
        for (repo, error) in skipped {
            warn_skipped(&repo, &coordinate, &error);
        }
        Ok(versions)
    }

    /// Whether Maven takes `version` of the plugin: its POM's prerequisite
    /// holds for the running Maven and its descriptor's
    /// `requiredJavaVersion` for the JDK. Maven reads no
    /// `requiredMavenVersion` from the descriptor. One that does not
    /// resolve, or whose POM does not build, is skipped, as Maven skips it;
    /// one whose jar has no descriptor naming it is taken unchecked, as
    /// Maven takes any version whose descriptor fails to load.
    async fn compatible(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        repos: &[Repository],
        support_poms: Option<&WorkspaceSupportPomBuffer>,
    ) -> Result<bool> {
        let Some(descriptor) = self
            .plugin_descriptor(group_id, artifact_id, version, repos)
            .await?
        else {
            return Ok(false);
        };
        let coord: Coord = format!("{group_id}:{artifact_id}:{version}")
            .parse()
            .map_err(ResolveError::Version)?;
        // A model cache of its own: the shared one is keyed by repository
        // context, not by these repositories.
        let ctx = self.ctx.for_module(self.ctx.config.clone());
        let mut backend = ModelService::new(&ctx, repos.to_vec());
        if let Some(support_poms) = support_poms {
            backend = backend.with_workspace_support_poms(Arc::clone(support_poms));
        }
        let maven =
            match Backend::fetch_project(&backend, &coord, false, &RepoContext::default()).await {
                Ok(_) if backend.pom_invalid(&coord) => return Ok(false),
                Ok(resolved) => resolved.project.prerequisites_maven.clone(),
                Err(ResolveError::ArtifactNotFound { .. }) => None,
                Err(ResolveError::Pom(_)) => return Ok(false),
                Err(error) => return Err(error),
            };
        let base = rv_maven_types::snapshot_base_version(version);
        if !descriptor.names(group_id, artifact_id, base.as_deref().unwrap_or(version)) {
            return Ok(true);
        }
        let required_java = descriptor.required_java_version.as_deref();
        // Maven checks the JDK it runs on: a `[lock] jdks` target, else the
        // host's, which the resolution then has read.
        let java = match (self.ctx.platform.jdk(), required_java) {
            (Some(jdk), _) => Some(jdk.to_string()),
            (None, Some(_)) => {
                self.ctx
                    .record_reads(&Arc::new(BTreeSet::from([HostInput::JavaVersion])));
                Some(self.ctx.config.host().java_version().to_string())
            }
            (None, None) => None,
        };
        let mode = self.ctx.config.lock.maven.mode;
        let java = match (required_java, java.as_deref()) {
            (Some(required), Some(java)) => java_meets(required, java, mode).ok_or_else(|| {
                ResolveError::InvalidVersionRequirement {
                    coord: format!("{coord} requiredJavaVersion"),
                    value: required.to_string(),
                }
            })?,
            _ => true,
        };
        Ok(meets(maven.as_deref(), Some(mode.version()), mode) && java)
    }

    /// The `plugin.xml` of a plugin version, `None` when the jar is in no
    /// repository but those a mirror blocks. A jar without one, or whose
    /// jar or descriptor does not read, passes, as Maven lets it.
    pub(super) async fn plugin_descriptor(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        repos: &[Repository],
    ) -> Result<Option<PluginDescriptor>> {
        let client = self
            .ctx
            .client
            .as_ref()
            .ok_or(ResolveError::NoRepositories)?;
        let request = ArtifactRequest {
            group_id: group_id.to_string(),
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
            packaging: "jar".to_string(),
            classifier: None,
        };
        let key = ArtifactCoord::new(group_id, artifact_id, version, "jar", None);
        let store = &self.ctx.store;
        let blob = match stored_in_first(client, store, &key, repos).await? {
            Some((blob, _)) => blob,
            None => match fetch_artifact_from_repos(client, store, &request, &key, repos).await {
                Ok((blob, ..)) => blob,
                Err(
                    FetchError::NotFound { .. }
                    | FetchError::Failed {
                        err: RepoError::BlockedMirror(_),
                        ..
                    },
                ) => return Ok(None),
                // `mvn -o` skips a version whose jar it cannot resolve.
                // raeva.lock pins the jar of the version taken, not of a
                // newer one the JDK rejected, so only a pinned one fails.
                Err(FetchError::Failed {
                    err: RepoError::OfflineNotCached(_),
                    ..
                }) if !client.pins(&key) => return Ok(None),
                Err(FetchError::Failed { err, searched }) => {
                    return Err(ResolveError::Repo {
                        coord: Some(key.to_string()),
                        source: Box::new(err),
                        searched,
                    });
                }
            },
        };
        let path = store.get_path(&blob);
        let entry = super::jar::read_entry(&path, "META-INF/maven/plugin.xml");
        // Maven passes a jar it cannot read, but one past raeva's bounds
        // Maven reads, and its prerequisites may refuse the version.
        if let Err(error @ super::jar::JarError::Limit(_)) = &entry {
            return Err(ResolveError::UnreadableJar {
                coord: format!("{group_id}:{artifact_id}:{version}"),
                entry: Some("META-INF/maven/plugin.xml".to_string()),
                reason: error.to_string(),
            });
        }
        let descriptor = (entry.ok().flatten())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| rv_maven_model::parse_plugin_descriptor(&text).ok())
            .unwrap_or_default();
        Ok(Some(descriptor))
    }
}

/// Whether a plugin metadata search stops at `error` rather than go on to
/// the next repository, as a dependency's version listing stops: on the
/// configuration's refusal, a busy answer, and bytes that fail or lack
/// their checksum or a redirect to plain HTTP. Maven reads past any failed
/// repository.
pub(super) fn stops_listing(error: &RepoError) -> bool {
    let refused = matches!(
        error.cause(),
        RepoError::ChecksumMismatch { .. }
            | RepoError::MissingChecksum(_)
            | RepoError::MissingMetadataChecksum(_)
            | RepoError::RedirectRejected { .. }
    ) && !error.moves_to_next_repository();
    matches!(error, RepoError::Config(_)) || error.is_transient() || refused
}

/// Warn that the plugin metadata of `coordinate` was read without `repo`,
/// which failed with `error`.
pub(super) fn warn_skipped(repo: &Repository, coordinate: &str, error: &str) {
    let repository =
        (repo.id.clone()).unwrap_or_else(|| rv_config::redact_repository_url(&repo.url));
    let repository = rv_maven_types::bounded(&repository).to_string();
    tracing::warn!(
        sec_code = "LISTING_REPO_SKIPPED",
        repository,
        coordinate,
        "the plugin metadata of {coordinate} was read without repository '{repository}', \
         which failed: {error}"
    );
}

/// The versions Maven tries, in its order: the merged `<release>`, else
/// `<latest>`, then the releases and then the snapshots the repositories
/// list, each newest first in the order of `mode` and, as in its `TreeSet`,
/// only the first listed of equal versions. Maven drops the first from the
/// list before it builds the set, so a version equal to it is tried.
fn candidates(versions: &Versions, mode: MavenMode) -> Vec<String> {
    let first = (versions.release.as_ref())
        .or(versions.latest.as_ref())
        .map(|(version, _)| version.clone());
    let (mut releases, mut snapshots) = (Vec::new(), Vec::new());
    for text in (versions.listed.iter()).filter(|text| Some(*text) != first.as_ref()) {
        if let Ok(version) = Version::parse(text) {
            match text.ends_with("-SNAPSHOT") {
                true => snapshots.push(version),
                false => releases.push(version),
            }
        }
    }
    let newest_first = |mut listed: Vec<Version>| {
        Version::sort_by_key_in(&mut listed, mode, |version| version);
        listed.dedup_by(|later, kept| later.cmp_in(kept, mode).is_eq());
        listed.into_iter().rev()
    };
    let listed = (newest_first(releases).chain(newest_first(snapshots)))
        .map(|version| version.as_str().to_string());
    first.into_iter().chain(listed).collect()
}

/// Whether `current` meets `required` as Maven checks a prerequisite, in
/// the version order of the resolver `mode` ships: a range must contain
/// it, a plain version be at most it. A requirement that does not parse,
/// or no known current version, passes.
fn meets(required: Option<&str>, current: Option<&str>, mode: MavenMode) -> bool {
    let (Some(required), Some(current)) = (required, current) else {
        return true;
    };
    let Ok(current) = Version::parse(current) else {
        return true;
    };
    let required = required.trim();
    if required.starts_with('[') || required.starts_with('(') {
        return (VersionReq::parse_in(required, mode))
            .map_or(true, |range| range.matches_in(&current, mode));
    }
    Version::parse(required).map_or(true, |required| required.cmp_in(&current, mode).is_le())
}

/// Whether the JDK of `java.version` `current` meets a plugin's
/// `requiredJavaVersion` as Maven's `MavenPluginJavaPrerequisiteChecker`
/// checks it in `mode`: Maven 3.9 reads `8` as `1.8`; 3.10 reads a
/// `1.8` JDK as `8` unless the requirement names `1.8`. `None` for a
/// requirement that does not parse, which fails Maven's build.
fn java_meets(required: &str, current: &str, mode: MavenMode) -> Option<bool> {
    let (required, current) = match mode {
        MavenMode::Maven39 if required == "8" => ("1.8", current),
        MavenMode::Maven310 if !required.contains("1.8") && current.starts_with("1.8") => {
            (required, &current[2..])
        }
        _ => (required, current),
    };
    let range = match required.starts_with(['[', '(']) {
        true => Some(VersionReq::parse_in(required, mode).ok()?),
        false => None,
    };
    let Ok(current) = Version::parse(current) else {
        return Some(false);
    };
    Some(match range {
        Some(range) => range.matches_in(&current, mode),
        None => {
            Version::parse(required).is_ok_and(|required| required.cmp_in(&current, mode).is_le())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{MavenMode, Versions, candidates, java_meets, meets};

    /// Maven's `TreeSet` keeps one of equal versions, the first listed, and
    /// Maven 3.10's resolver orders `alpha` below `0` where 3.9's has them
    /// equal; the merged `<release>` goes first.
    #[test]
    fn tries_versions_in_the_order_of_the_maven_line() {
        let versions = Versions {
            release: Some(("2".to_string(), "1".to_string())),
            latest: None,
            listed: ["alpha", "0", "2", "1-SNAPSHOT"].map(String::from).into(),
        };
        assert_eq!(
            candidates(&versions, MavenMode::Maven39),
            ["2", "alpha", "1-SNAPSHOT"]
        );
        assert_eq!(
            candidates(&versions, MavenMode::Maven310),
            ["2", "0", "alpha", "1-SNAPSHOT"]
        );
        let versions = Versions {
            listed: ["2", "2.0"].map(String::from).into(),
            ..versions
        };
        assert_eq!(candidates(&versions, MavenMode::Maven39), ["2", "2.0"]);
    }

    /// A `<release>` counts only with a later `lastUpdated` than the one
    /// merged, so not at all without one.
    #[test]
    fn merges_metadata_as_maven_does() {
        let metadata = |release: &str, stamp: Option<&str>| {
            let stamp = stamp.map(|stamp| format!("<lastUpdated>{stamp}</lastUpdated>"));
            let xml = format!(
                "<metadata><versioning><release>{release}</release><versions><version>\
                 {release}</version></versions>{}</versioning></metadata>",
                stamp.unwrap_or_default()
            );
            rv_repo::Metadata::from_bytes(xml.as_bytes()).unwrap()
        };
        let mut versions = Versions::default();
        versions.merge(&metadata("1", None));
        assert_eq!(versions.release, None);
        versions.merge(&metadata("3", Some("20240102000000")));
        versions.merge(&metadata("2", Some("20240101000000")));
        assert_eq!(versions.release.unwrap().0, "3");
        assert_eq!(versions.listed, ["1", "3", "2"]);
    }

    /// Maven checks a prerequisite in the version order of the resolver it
    /// ships, which differs between the lines outside ASCII.
    #[test]
    fn checks_prerequisites_as_maven_does() {
        use MavenMode::{Maven39, Maven310};
        for mode in [Maven39, Maven310] {
            assert!(meets(Some("3.6.3"), Some("3.9.12"), mode));
            assert!(!meets(Some("4.0.0-beta-3"), Some("3.9.12"), mode));
            assert!(!meets(Some("[4.0.0-beta-3,)"), Some("3.9.12"), mode));
            assert!(meets(Some("[3.2.5,4)"), Some("3.9.12"), mode));
            assert!(meets(None, Some("3.9.12"), mode));
            assert!(meets(Some(""), Some("3.9.12"), mode));
            assert!(meets(Some(" "), Some("3.9.12"), mode));
            assert!(meets(Some("not a version"), Some("3.9.12"), mode));
        }
        assert!(meets(Some("1-\u{17f}napshot"), Some("1"), Maven39));
        assert!(!meets(Some("1-\u{17f}napshot"), Some("1"), Maven310));
        assert!(!meets(Some("[1-\u{17f}napshot,)"), Some("1"), Maven310));
        assert_eq!(java_meets("1-\u{17f}napshot", "1", Maven39), Some(true));
        assert_eq!(java_meets("1-\u{17f}napshot", "1", Maven310), Some(false));
        // A range only the 3.10 order can bound, and one only 3.9's can.
        assert!(meets(Some("[alpha,0.min]"), Some("3.9.12"), Maven39));
        assert!(!meets(Some("[alpha,0.min]"), Some("3.10.0"), Maven310));
        assert!(!meets(Some("[0,alpha]"), Some("3.9.12"), Maven39));
        assert!(meets(Some("[0,alpha]"), Some("3.10.0"), Maven310));
        assert_eq!(java_meets("[alpha,0.min]", "17", Maven39), None);
        assert_eq!(java_meets("[alpha,0.min]", "17", Maven310), Some(false));
    }

    /// Maven 3.9.12 rewrites a requirement of `8` to `1.8`; 3.10.0 drops
    /// `1.` from a `1.8` JDK when the requirement does not name `1.8`. A
    /// range that does not parse fails the resolution.
    #[test]
    fn checks_the_java_requirement_as_each_maven_line_does() {
        use MavenMode::{Maven39, Maven310};
        for (required, current, v39, v310) in [
            ("1.8", "21", true, true),
            ("17", "11", false, false),
            ("8", "1.8.0_442", true, true),
            ("[8,)", "1.8.0_442", false, true),
            ("[1.8,)", "1.8.0_442", true, true),
            ("[9,)", "1.8.0_442", false, false),
            ("8", "8", true, true),
            ("[17,)", "21.0.2", true, true),
        ] {
            assert_eq!(
                java_meets(required, current, Maven39),
                Some(v39),
                "{required} {current}"
            );
            assert_eq!(
                java_meets(required, current, Maven310),
                Some(v310),
                "{required} {current}"
            );
        }
        assert_eq!(java_meets("[1.8", "21", Maven39), None);
        assert_eq!(java_meets("[1.8", "21", Maven310), None);
    }
}
