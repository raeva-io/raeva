//! `RepoBackend`: solver Backend implementation backed by remote Maven repositories.
//!
//! Owns version resolution, snapshot resolution, POM fetching, BOM constraint
//! collection, and local project loading for the solver.

use futures::stream::{self, StreamExt};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, RwLock};

use rv_maven_model::{Pom, PomError, Project, Scope};
use rv_repo::{ArtifactRequest, Metadata, RepoError, Repository};
use rv_version::{Coord, Version, VersionReq};

use crate::context::{MetadataKey, ResolveContext};
use crate::error::{RepoSearchStatus, ResolveError, Result};
use crate::parent_resolver::build_activation_context_async;
use crate::solver::{Backend, ResolvedProject, ResolvedVersion};

use super::fetcher::RepoParentResolver;
use super::utils::{dummy_coord, filter_repos_for_version, select_versions};

#[derive(Clone)]
pub(super) struct RepoBackend {
    pub(super) ctx: ResolveContext,
    /// Shared, mutable list of repositories. Maven propagates `<repositories>`
    /// from every fetched POM into the resolution context, so this list grows
    /// as transitive projects are loaded. Reads take a cheap clone snapshot
    /// (repo lists are small) so callers never hold a lock across awaits.
    pub(super) repos: Arc<RwLock<Vec<Repository>>>,
    /// Incremental dedup index for `extend_repos`. Each fetched POM can
    /// trigger an `extend_repos` call (potentially 100+ for a full Spring Boot
    /// stack); rebuilding the URL set from `repos` on every call is O(N) per
    /// call (quadratic across the resolution). Sharing this index across
    /// clones via `Arc<RwLock<_>>` keeps lookups O(1) regardless of how many
    /// transitive POMs we visit.
    pub(super) seen_repo_urls: Arc<RwLock<HashSet<String>>>,
    pub(super) strict: bool,
    /// Mirror of `ResolveContext::project` keyed by the same `Coord` but
    /// holding only the source-repository URL. The shared project cache
    /// stores only `Project`. Keeping the URL alongside lets a cache hit in
    /// `fetch_project_internal` replay the original provenance instead of
    /// returning `repo_url: None` and forcing `populate_artifacts` to
    /// rediscover the source repo, which can fetch the artifact from a
    /// different mirror than the one that served the POM.
    pub(super) project_repo_url: Arc<RwLock<HashMap<Coord, Arc<str>>>>,
    /// Source-repository id for each support POM (parent / imported BOM)
    /// fetched during resolution, keyed by `"g:a:v"`. A support POM can resolve
    /// from a different repository than the child that referenced it; recording
    /// the serving repo's id here lets `rv export-m2` label that POM's
    /// `_remote.repositories` marker with the correct id instead of guessing
    /// the child's repo. Only repositories that carry an id are recorded.
    pub(super) support_repo_ids: Arc<RwLock<HashMap<String, String>>>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum DynamicVersionSelector {
    Release,
    Integration,
}

impl DynamicVersionSelector {
    pub(super) fn from_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "release" | "latest.release" => Some(Self::Release),
            "latest" | "latest.integration" => Some(Self::Integration),
            _ => None,
        }
    }

    fn requirement_label(self) -> &'static str {
        match self {
            Self::Release => "RELEASE",
            Self::Integration => "LATEST",
        }
    }
}

impl RepoBackend {
    pub(super) fn new(ctx: &ResolveContext, repos: Vec<Repository>, strict: bool) -> Self {
        let seen: HashSet<String> = repos.iter().map(|repo| repo.url.clone()).collect();
        Self {
            ctx: ctx.clone(),
            repos: Arc::new(RwLock::new(repos)),
            seen_repo_urls: Arc::new(RwLock::new(seen)),
            strict,
            project_repo_url: Arc::new(RwLock::new(HashMap::new())),
            support_repo_ids: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Snapshot the current repo list. Cheap, since repo lists are small, and
    /// avoids holding the lock across awaits.
    pub(super) fn repos_snapshot(&self) -> Vec<Repository> {
        self.repos.read().expect("repos lock poisoned").clone()
    }

    /// Snapshot the `"g:a:v" -> repo-id` provenance recorded for support POMs.
    pub(super) fn support_repo_ids_snapshot(&self) -> Vec<(String, String)> {
        self.support_repo_ids
            .read()
            .expect("support_repo_ids lock poisoned")
            .iter()
            .map(|(coord, id)| (coord.clone(), id.clone()))
            .collect()
    }

    /// Append repositories declared by the ROOT project's POM (or by a POM
    /// the user is treating as the resolution root) to the shared list,
    /// deduplicated by URL. The root POM belongs to the user; the
    /// cross-project trust policy that gates transitive `<repositories>` does
    /// not apply here, so these entries bypass `allows_transitive_repo_url`.
    ///
    /// Transitive POMs encountered later during resolution must continue to
    /// go through [`Self::extend_repos`], which keeps the security gate.
    pub(super) fn extend_repos_trusted(&self, extra: impl IntoIterator<Item = Repository>) {
        let mut seen = self
            .seen_repo_urls
            .write()
            .expect("seen_repo_urls lock poisoned");
        let mut guard = self.repos.write().expect("repos lock poisoned");
        for repo in extra {
            if seen.insert(repo.url.clone()) {
                guard.push(repo);
            }
        }
    }

    /// Append `<repositories>` declared by a TRANSITIVE POM (i.e. not the
    /// resolution root) to the shared list, deduplicated by URL.
    ///
    /// Maven propagates `<repositories>` from every fetched POM into the
    /// resolution context, so transitive deps could otherwise introduce their
    /// own repository URLs and have subsequent fetches in the same resolution
    /// trust them silently.
    ///
    /// Raeva's default is to **ignore** transitive `<repositories>`: a hostile
    /// transitive POM should not be able to redirect later fetches. Users opt
    /// in globally via the `[security] allow_transitive_repositories` flag or
    /// narrowly via the URL-prefix `transitive_repository_allowlist`.
    pub(super) fn extend_repos(&self, extra: impl IntoIterator<Item = Repository>) {
        let policy = &self.ctx.config.security;
        let mut filtered: Vec<Repository> = Vec::new();
        let mut ignored = 0usize;
        for repo in extra {
            if policy.allows_transitive_repo_url(repo.url.as_str()) {
                filtered.push(repo);
            } else {
                ignored += 1;
                // Tag with `sec_code` so the CLI's WarningCollectorLayer
                // routes this into the JSON envelope's `data.warnings`
                // channel even when `--json` suppresses fmt output.
                tracing::warn!(
                    sec_code = "TRANSITIVE_REPO_DROPPED",
                    url = %repo.url,
                    "ignoring transitive repository declaration; not on allowlist (see [security] allow_transitive_repositories)"
                );
            }
        }
        if ignored > 0 {
            tracing::warn!(
                sec_code = "TRANSITIVE_REPO_DROPPED",
                ignored,
                "ignored {} transitive repository declarations under default-deny policy",
                ignored
            );
        }
        if filtered.is_empty() {
            return;
        }
        // Lock order: take the URL-set guard first, then the repos guard. All
        // call sites in this module follow the same order, so the pair cannot
        // deadlock.
        let mut seen = self
            .seen_repo_urls
            .write()
            .expect("seen_repo_urls lock poisoned");
        let mut guard = self.repos.write().expect("repos lock poisoned");
        for repo in filtered {
            if seen.insert(repo.url.clone()) {
                guard.push(repo);
            }
        }
    }

    pub(super) async fn resolve_version_internal(
        &self,
        group_id: &str,
        artifact_id: &str,
        req: &rv_version::VersionReq,
    ) -> Result<ResolvedVersion> {
        if let VersionReq::Exact(version) = req
            && let Some(selector) = DynamicVersionSelector::from_token(version.as_str())
        {
            return self
                .resolve_dynamic_version_internal(group_id, artifact_id, selector)
                .await;
        }

        let client = self
            .ctx
            .client
            .as_ref()
            .ok_or(ResolveError::MissingRepoClient)?;

        let repos = self.repos_snapshot();
        // BTreeSet keeps version iteration deterministic when scanning for
        // the best match below.
        let mut all_versions = BTreeSet::new();
        let mut found_metadata = false;
        let mut searched: Vec<RepoSearchStatus> = Vec::with_capacity(repos.len());
        let mut errors: Vec<RepoError> = Vec::with_capacity(repos.len());

        // Fan out metadata fetches concurrently. Sequential awaits across all
        // configured repos turn a 10-repo workspace into a 10x-latency hot
        // path on first resolve; parallelizing keeps the worst repo's RTT
        // from dominating the total. The bound mirrors
        // `Resolver::populate_artifacts` so a Pi runner with low concurrency
        // does not get a flood of sockets behind its back.
        let concurrency = self
            .ctx
            .config
            .network
            .concurrency
            .clamp(1, crate::solver::MAX_FETCH_CONCURRENCY)
            .min(repos.len().max(1));

        enum RepoOutcome {
            Hit(std::sync::Arc<Metadata>),
            NotFound(RepoSearchStatus),
            Failed(RepoSearchStatus, RepoError),
            CacheEvicted,
        }

        let dummy = dummy_coord(group_id, artifact_id)?;
        // Hoist Arc<str> allocation out of the per-repo async closure: building
        // `Arc::from(repo.url.as_str())` inside the closure would allocate once
        // per repo per future poll; building it here allocates exactly once per
        // repo regardless of how many times the future is polled.
        let repo_urls: Vec<Arc<str>> = repos.iter().map(|r| Arc::from(r.url.as_str())).collect();
        let results: Vec<(usize, RepoOutcome, bool)> = stream::iter(repos.iter().enumerate())
            .map(|(idx, repo)| {
                let url: Arc<str> = Arc::clone(&repo_urls[idx]);
                let key = MetadataKey::new(url, Arc::from(group_id), Arc::from(artifact_id));
                let dummy = &dummy;
                async move {
                    if let Some(metadata) = self.ctx.cached_metadata(&key) {
                        return (idx, RepoOutcome::Hit(metadata), false);
                    }
                    match client.fetch_metadata(repo, dummy).await {
                        Ok(metadata) => {
                            self.ctx.insert_metadata(key.clone(), metadata);
                            match self.ctx.cached_metadata(&key) {
                                Some(metadata) => (idx, RepoOutcome::Hit(metadata), true),
                                None => (idx, RepoOutcome::CacheEvicted, true),
                            }
                        }
                        Err(err) => {
                            let status = RepoSearchStatus::from_error(repo.url.as_str(), &err);
                            if matches!(err, RepoError::NotFound(_)) {
                                (idx, RepoOutcome::NotFound(status), false)
                            } else {
                                (idx, RepoOutcome::Failed(status, err), false)
                            }
                        }
                    }
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        // Re-order by repo index so `searched` reflects the configured
        // order, not arbitrary completion order. Reproducible diagnostics
        // matter for users tracing why an artifact resolved.
        let mut ordered = results;
        ordered.sort_by_key(|(idx, _, _)| *idx);

        for (idx, outcome, _) in ordered {
            let repo = &repos[idx];
            let metadata = match outcome {
                RepoOutcome::Hit(metadata) => metadata,
                RepoOutcome::NotFound(status) => {
                    searched.push(status);
                    continue;
                }
                RepoOutcome::Failed(status, err) => {
                    searched.push(status);
                    // Continue across other repos for both transient and
                    // fatal errors (fail-open), so a single broken mirror does
                    // not abort the resolve.
                    errors.push(err);
                    continue;
                }
                RepoOutcome::CacheEvicted => {
                    return Err(ResolveError::InternalError(format!(
                        "metadata cache evicted entry for {group_id}:{artifact_id} immediately after insert",
                    )));
                }
            };

            found_metadata = true;
            for candidate in select_versions(&metadata) {
                let candidate_str = candidate.as_ref();
                // Per-repo release/snapshot gating: a snapshot version from
                // a snapshot-disabled repo (or a release version from a
                // releases-disabled repo) must not contribute to a range
                // resolution. Pooling candidates across all configured repos
                // would let a `[1,2)` range select a SNAPSHOT artifact
                // published only to a snapshot mirror even when the consumer's
                // policy excluded it, so gate each candidate against the repo
                // that advertised it.
                if !repo.allows_version(candidate_str) {
                    continue;
                }
                let Ok(version) = Version::parse(candidate_str) else {
                    continue;
                };
                all_versions.insert(version);
            }
        }

        if !found_metadata {
            if let Some(err) = errors.into_iter().next() {
                return Err(ResolveError::RepoWithContext {
                    source: err,
                    searched,
                });
            }
            return Err(ResolveError::ArtifactNotFound {
                coord: format!("{group_id}:{artifact_id}"),
                searched,
            });
        }

        let mut best: Option<Version> = None;
        for version in all_versions {
            if req.matches(&version) {
                match &best {
                    Some(current) if current >= &version => {}
                    _ => best = Some(version),
                }
            }
        }

        if let Some(version) = best {
            return Ok(ResolvedVersion {
                version,
                repo_url: None,
            });
        }

        Err(ResolveError::VersionNotFound {
            coord: format!("{group_id}:{artifact_id}"),
            requirement: req.to_string(),
        })
    }

    async fn resolve_dynamic_version_internal(
        &self,
        group_id: &str,
        artifact_id: &str,
        selector: DynamicVersionSelector,
    ) -> Result<ResolvedVersion> {
        let client = self
            .ctx
            .client
            .as_ref()
            .ok_or(ResolveError::MissingRepoClient)?;

        let repos = self.repos_snapshot();
        let mut best: Option<Version> = None;
        let mut found_metadata = false;
        let mut searched: Vec<RepoSearchStatus> = Vec::with_capacity(repos.len());
        let mut errors: Vec<RepoError> = Vec::with_capacity(repos.len());

        // Mirror resolve_version_internal's fan-out so LATEST/RELEASE does
        // not serialize per-repo metadata latency.
        let concurrency = self
            .ctx
            .config
            .network
            .concurrency
            .clamp(1, crate::solver::MAX_FETCH_CONCURRENCY)
            .min(repos.len().max(1));

        enum RepoOutcome {
            Hit(std::sync::Arc<Metadata>),
            NotFound(RepoSearchStatus),
            Failed(RepoSearchStatus, RepoError),
            CacheEvicted,
        }

        let dummy = dummy_coord(group_id, artifact_id)?;
        // Hoist Arc<str> allocation out of the per-repo async closure: same
        // rationale as in resolve_version_internal, allocating once per repo
        // rather than once per future poll.
        let repo_urls: Vec<Arc<str>> = repos.iter().map(|r| Arc::from(r.url.as_str())).collect();
        let results: Vec<(usize, RepoOutcome)> = stream::iter(repos.iter().enumerate())
            .map(|(idx, repo)| {
                let url: Arc<str> = Arc::clone(&repo_urls[idx]);
                let key = MetadataKey::new(url, Arc::from(group_id), Arc::from(artifact_id));
                let dummy = &dummy;
                async move {
                    if let Some(metadata) = self.ctx.cached_metadata(&key) {
                        return (idx, RepoOutcome::Hit(metadata));
                    }
                    match client.fetch_metadata(repo, dummy).await {
                        Ok(metadata) => {
                            self.ctx.insert_metadata(key.clone(), metadata);
                            match self.ctx.cached_metadata(&key) {
                                Some(metadata) => (idx, RepoOutcome::Hit(metadata)),
                                None => (idx, RepoOutcome::CacheEvicted),
                            }
                        }
                        Err(err) => {
                            let status = RepoSearchStatus::from_error(repo.url.as_str(), &err);
                            if matches!(err, RepoError::NotFound(_)) {
                                (idx, RepoOutcome::NotFound(status))
                            } else {
                                (idx, RepoOutcome::Failed(status, err))
                            }
                        }
                    }
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        // Sort by repo index so `searched` and best-version selection are
        // independent of completion order.
        let mut ordered = results;
        ordered.sort_by_key(|(idx, _)| *idx);

        for (idx, outcome) in ordered {
            let metadata = match outcome {
                RepoOutcome::Hit(metadata) => metadata,
                RepoOutcome::NotFound(status) => {
                    searched.push(status);
                    continue;
                }
                RepoOutcome::Failed(status, err) => {
                    searched.push(status);
                    errors.push(err);
                    continue;
                }
                RepoOutcome::CacheEvicted => {
                    return Err(ResolveError::InternalError(format!(
                        "metadata cache evicted entry for {group_id}:{artifact_id} immediately after insert",
                    )));
                }
            };

            found_metadata = true;
            let repo = &repos[idx];
            let mut candidates = Vec::new();
            match selector {
                DynamicVersionSelector::Release => {
                    if let Some(release) = metadata.release.as_deref() {
                        candidates.push(release.to_string());
                    }
                }
                DynamicVersionSelector::Integration => {
                    if let Some(latest) = metadata.latest.as_deref() {
                        candidates.push(latest.to_string());
                    }
                }
            }

            for candidate in select_versions(&metadata) {
                let candidate = candidate.as_ref();
                if matches!(selector, DynamicVersionSelector::Release)
                    && rv_repo::is_snapshot_version(candidate)
                {
                    continue;
                }
                candidates.push(candidate.to_string());
            }

            for candidate in candidates {
                if matches!(selector, DynamicVersionSelector::Release)
                    && rv_repo::is_snapshot_version(&candidate)
                {
                    continue;
                }
                // Per-repo release/snapshot gating. Without this, RELEASE
                // could pick a release published only to a snapshots-only
                // mirror, and LATEST could pick a SNAPSHOT served by a
                // releases-only mirror. Mirror the gate inside the range
                // resolver above.
                if !repo.allows_version(&candidate) {
                    continue;
                }
                let Ok(version) = Version::parse(&candidate) else {
                    continue;
                };
                match &best {
                    Some(current) if current >= &version => {}
                    _ => best = Some(version),
                }
            }
        }

        if !found_metadata {
            if let Some(err) = errors.into_iter().next() {
                return Err(ResolveError::RepoWithContext {
                    source: err,
                    searched,
                });
            }
            return Err(ResolveError::ArtifactNotFound {
                coord: format!("{group_id}:{artifact_id}"),
                searched,
            });
        }

        if let Some(version) = best {
            return Ok(ResolvedVersion {
                version,
                repo_url: None,
            });
        }

        Err(ResolveError::VersionNotFound {
            coord: format!("{group_id}:{artifact_id}"),
            requirement: selector.requirement_label().to_string(),
        })
    }

    async fn resolve_snapshot_version_internal(&self, coord: &Coord) -> Result<ResolvedVersion> {
        let client = self
            .ctx
            .client
            .as_ref()
            .ok_or(ResolveError::MissingRepoClient)?;

        let version_str = coord.version.as_str();
        let repos = self.repos_snapshot();
        let eligible_repos = filter_repos_for_version(&repos, version_str, coord)?;

        let mut last_error: Option<RepoError> = None;
        let mut searched: Vec<RepoSearchStatus> = Vec::with_capacity(eligible_repos.len());
        for repo in eligible_repos {
            match client.resolve_snapshot_version(repo, coord).await {
                Ok(resolution) => {
                    let version = Version::parse(&resolution.version)?;
                    return Ok(ResolvedVersion {
                        version,
                        repo_url: Some(Arc::from(repo.url.as_str())),
                    });
                }
                Err(err) => {
                    searched.push(RepoSearchStatus::from_error(repo.url.as_str(), &err));
                    if matches!(err, RepoError::NotFound(_)) {
                        continue;
                    }
                    if err.is_transient() {
                        last_error = Some(err);
                        continue;
                    }
                    return Err(ResolveError::RepoWithContext {
                        source: err,
                        searched,
                    });
                }
            }
        }

        if let Some(err) = last_error {
            return Err(ResolveError::RepoWithContext {
                source: err,
                searched,
            });
        }

        Err(ResolveError::ArtifactNotFound {
            coord: coord.to_string(),
            searched,
        })
    }

    pub(super) async fn fetch_project_internal(
        &self,
        coord: &Coord,
        _scope: Scope,
    ) -> Result<ResolvedProject> {
        if let Some(project) = self.ctx.cached_project(coord) {
            // Replay the source repo recorded when this project was first
            // fetched. Without this, an artifact download routed through the
            // cache would pick whichever repo currently appears first in the
            // candidate list, which is not necessarily the one that served
            // the POM.
            let repo_url = self
                .project_repo_url
                .read()
                .expect("project_repo_url lock poisoned")
                .get(coord)
                .cloned();
            return Ok(ResolvedProject {
                project,
                repo_url,
                platform_constraints: None,
            });
        }

        let client = self
            .ctx
            .client
            .as_ref()
            .ok_or(ResolveError::MissingRepoClient)?;
        let req = ArtifactRequest::from_coord(coord);

        let version_str = coord.version.to_string();
        let repos = self.repos_snapshot();
        let eligible_repos = filter_repos_for_version(&repos, &version_str, coord)?;

        let mut last_error: Option<RepoError> = None;
        let mut searched: Vec<RepoSearchStatus> = Vec::with_capacity(eligible_repos.len());
        for repo in eligible_repos {
            match client.fetch_pom(repo, &req).await {
                Ok(bytes) => {
                    let xml = std::str::from_utf8(&bytes)
                        .map_err(|err| PomError::InvalidModel(err.to_string()))?;
                    let pom = Pom::parse(xml)?;
                    let resolver = RepoParentResolver::with_strict(self.clone(), None, self.strict);
                    // #5: transitive POMs are also evaluated against the TARGET
                    // platform of this resolve pass, not the host.
                    let activation = build_activation_context_async(
                        None,
                        &self.ctx.config,
                        Some(&self.ctx.platform),
                    )
                    .await;
                    let project = Project::from_pom_with_context(pom, resolver, &activation)?;
                    // Propagate any <repositories> declared by this transitive
                    // POM so later fetches in the same resolution can see them.
                    self.extend_repos(project.repositories.iter().cloned().map(Repository::from));
                    let repo_url: Arc<str> = Arc::from(repo.url.as_str());
                    self.ctx.insert_project(coord.clone(), project.clone());
                    // Record provenance so a subsequent cache hit returns the
                    // same repository instead of `None`.
                    self.project_repo_url
                        .write()
                        .expect("project_repo_url lock poisoned")
                        .insert(coord.clone(), Arc::clone(&repo_url));
                    return Ok(ResolvedProject {
                        project,
                        repo_url: Some(repo_url),
                        platform_constraints: None,
                    });
                }
                Err(err) => {
                    searched.push(RepoSearchStatus::from_error(repo.url.as_str(), &err));
                    if matches!(err, RepoError::NotFound(_)) {
                        continue;
                    }
                    if err.is_transient() {
                        last_error = Some(err);
                        continue;
                    }
                    return Err(ResolveError::RepoWithContext {
                        source: err,
                        searched,
                    });
                }
            }
        }

        if let Some(err) = last_error {
            return Err(ResolveError::RepoWithContext {
                source: err,
                searched,
            });
        }

        Err(ResolveError::ArtifactNotFound {
            coord: coord.to_string(),
            searched,
        })
    }

    /// Sync wrapper around the async POM fetch. The async body is inlined
    /// here because the parent-chain resolver (the only caller) is sync,
    /// and the async signature added no value without other async callers.
    /// When `ParentResolver` becomes async this can split back out.
    pub(super) fn fetch_pom_bytes_blocking(&self, coord: &Coord) -> Result<Vec<u8>> {
        let fut = async {
            let client = self
                .ctx
                .client
                .as_ref()
                .ok_or(ResolveError::MissingRepoClient)?;
            let req = ArtifactRequest::from_coord(coord);

            let version_str = coord.version.to_string();
            let repos = self.repos_snapshot();
            let eligible_repos = filter_repos_for_version(&repos, &version_str, coord)?;

            let mut last_error: Option<RepoError> = None;
            let mut searched: Vec<RepoSearchStatus> = Vec::with_capacity(eligible_repos.len());
            for repo in eligible_repos {
                match client.fetch_pom(repo, &req).await {
                    Ok(bytes) => {
                        // Persist this POM so `rv export-m2` can materialize it
                        // for strict offline `mvn -o`. This path fetches only
                        // *support* POMs: parent POMs and imported BOMs (graph
                        // dependencies flow through `fetch_project_internal`),
                        // which are otherwise never persisted and break
                        // offline parent/BOM resolution. It runs across every
                        // eligible repo, so a parent that lives in a different
                        // repo than its child is still captured. Best-effort:
                        // a store write must never fail resolution.
                        self.persist_support_pom(coord, repo.id.as_deref(), &bytes)
                            .await;
                        return Ok(bytes.to_vec());
                    }
                    Err(err) => {
                        searched.push(RepoSearchStatus::from_error(repo.url.as_str(), &err));
                        if matches!(err, RepoError::NotFound(_)) {
                            continue;
                        }
                        if err.is_transient() {
                            last_error = Some(err);
                            continue;
                        }
                        return Err(ResolveError::RepoWithContext {
                            source: err,
                            searched,
                        });
                    }
                }
            }
            if let Some(err) = last_error {
                return Err(ResolveError::RepoWithContext {
                    source: err,
                    searched,
                });
            }
            Err(ResolveError::ArtifactNotFound {
                coord: coord.to_string(),
                searched,
            })
        };
        crate::sync_bridge::block_on_async(fut)
    }

    /// Persist a fetched support POM (parent or imported BOM) into the content
    /// store under its `(group, artifact, version, "pom")` key, so
    /// `rv export-m2` can materialize the parent/BOM closure for offline
    /// `mvn -o`. Best-effort and never fatal: these POMs already drove
    /// resolution, so a store-write failure should not abort the resolve.
    async fn persist_support_pom(&self, coord: &Coord, repo_id: Option<&str>, bytes: &[u8]) {
        // Record which repository served this support POM so export-m2 can
        // label its marker correctly even when the parent/BOM lives in a
        // different repo than the child that referenced it.
        if let Some(id) = repo_id {
            // Key on bare "g:a:v" to match the export-side lookup. NOT
            // `coord.to_string()`: parent/BOM coords carry packaging=pom, and
            // `Coord::Display` would append it ("g:a:v:pom"), so the key would
            // never match export's `format!("{g}:{a}:{v}")` and the provenance
            // would be silently dropped.
            let key = format!("{}:{}:{}", coord.group_id, coord.artifact_id, coord.version);
            self.support_repo_ids
                .write()
                .expect("support_repo_ids lock poisoned")
                .insert(key, id.to_string());
        }
        let key = rv_config::ArtifactKey::new(
            coord.group_id.to_string(),
            coord.artifact_id.to_string(),
            coord.version.to_string(),
            "pom",
            None,
        );
        match self.ctx.store.put_bytes(bytes).await {
            Ok(blob) => {
                if let Err(err) = self.ctx.store.add_artifact(&key, &blob).await {
                    tracing::debug!(
                        coord = %coord,
                        error = %err,
                        "could not index fetched support POM in store (export-m2 may miss it)"
                    );
                }
            }
            Err(err) => {
                tracing::debug!(
                    coord = %coord,
                    error = %err,
                    "could not persist fetched support POM to store (export-m2 may miss it)"
                );
            }
        }
    }
}

impl Backend for RepoBackend {
    fn resolve_version<'b>(
        &'b self,
        group_id: &'b str,
        artifact_id: &'b str,
        req: &'b rv_version::VersionReq,
    ) -> crate::solver::BoxFuture<'b, Result<ResolvedVersion>> {
        Box::pin(async move {
            self.resolve_version_internal(group_id, artifact_id, req)
                .await
        })
    }

    fn resolve_snapshot_version<'b>(
        &'b self,
        coord: &'b Coord,
    ) -> crate::solver::BoxFuture<'b, Result<ResolvedVersion>> {
        Box::pin(async move { self.resolve_snapshot_version_internal(coord).await })
    }

    fn fetch_project<'b>(
        &'b self,
        coord: &'b Coord,
        scope: Scope,
    ) -> crate::solver::BoxFuture<'b, Result<ResolvedProject>> {
        Box::pin(async move { self.fetch_project_internal(coord, scope).await })
    }
}

#[cfg(test)]
mod test_support {
    use std::sync::{Arc, Mutex};

    use tracing::Level;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::Context;

    pub(super) type CapturedEvents = Arc<Mutex<Vec<(Level, String)>>>;

    pub(super) struct CaptureLayer {
        pub(super) events: CapturedEvents,
    }

    struct MessageVisitor(String);
    impl Visit for MessageVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "message" {
                self.0 = value.to_string();
            }
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("events lock")
                .push((*event.metadata().level(), visitor.0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_config::{Config, ResolvedPaths};
    use rv_store::Store;

    fn test_backend_with_config(config: Config) -> RepoBackend {
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_config::Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
        RepoBackend::new(&ctx, Vec::new(), false)
    }

    /// Support-POM provenance must be keyed on the bare `g:a:v`, matching the
    /// export-side lookup. Parent/BOM coords carry packaging=pom, so a
    /// `coord.to_string()` key would be `g:a:v:pom` and never match,
    /// silently dropping the provenance. This test guards against that.
    #[tokio::test]
    async fn persist_support_pom_keys_on_bare_gav() {
        let paths = ResolvedPaths::discover().expect("paths");
        let config =
            Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new());
        let backend = test_backend_with_config(config);
        let coord = Coord {
            group_id: "com.example".into(),
            artifact_id: "theparent".into(),
            version: Version::parse("2.0").unwrap(),
            packaging: Some("pom".to_string()),
            classifier: None,
        };
        assert_eq!(coord.to_string(), "com.example:theparent:2.0:pom");
        backend
            .persist_support_pom(&coord, Some("corp"), b"<project/>")
            .await;
        assert_eq!(
            backend.support_repo_ids_snapshot(),
            vec![("com.example:theparent:2.0".to_string(), "corp".to_string())],
            "provenance must key on bare g:a:v, not coord.to_string() (g:a:v:pom)"
        );
    }

    /// `extend_repos_trusted` bypasses the cross-project trust policy.
    /// The root project's POM belongs to the user, so `<repositories>` it
    /// declares must always merge, even when `allow_transitive_repositories`
    /// is the default `false`. This is the load-bearing distinction from the
    /// (gated) `extend_repos` path: a user POM hosting its parent on a
    /// custom repo must be able to resolve regardless of the transitive
    /// policy.
    #[test]
    fn extend_repos_trusted_bypasses_policy() {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        // Default policy denies transitive `<repositories>`.
        assert!(!config.security.allow_transitive_repositories);

        let backend = test_backend_with_config(config);
        backend.extend_repos_trusted(std::iter::once(Repository::new(
            Some("user-host".to_string()),
            "https://user-host.example/maven2/",
            true,
            false,
        )));
        let after = backend.repos_snapshot();
        assert!(
            after
                .iter()
                .any(|repo| repo.url == "https://user-host.example/maven2/"),
            "trusted extend must merge even under default-deny policy"
        );
    }

    /// `extend_repos_trusted` still deduplicates by URL. Calling it
    /// with the same URL twice (and with a URL already present in the
    /// configured repos) yields a single entry.
    #[test]
    fn extend_repos_trusted_is_idempotent() {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());

        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_config::Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
        let initial = vec![Repository::new(
            Some("central".to_string()),
            "https://central.example/maven2/",
            true,
            false,
        )];
        let backend = RepoBackend::new(&ctx, initial, false);

        for _ in 0..5 {
            backend.extend_repos_trusted(std::iter::once(Repository::new(
                Some("central-again".to_string()),
                "https://central.example/maven2/",
                true,
                false,
            )));
        }
        assert_eq!(backend.repos_snapshot().len(), 1);
    }

    /// Default policy: transitive `<repositories>` declared by a fetched POM
    /// must be ignored, so a hostile transitive package cannot introduce an
    /// attacker-controlled repository URL that subsequent fetches would query.
    #[test]
    fn extend_repos_default_deny_ignores_transitive_repo() {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        assert!(!config.security.allow_transitive_repositories);

        let backend = test_backend_with_config(config);
        let before = backend.repos_snapshot();
        backend.extend_repos(std::iter::once(Repository::new(
            Some("attacker".to_string()),
            "https://attacker.example/maven2/",
            true,
            false,
        )));
        let after = backend.repos_snapshot();
        assert_eq!(
            after.len(),
            before.len(),
            "expected transitive repo to be ignored"
        );
        assert!(
            !after
                .iter()
                .any(|repo| repo.url.contains("attacker.example")),
            "attacker repo must not appear in repo set under default policy",
        );
    }

    /// When the operator explicitly opts in, transitive `<repositories>` are
    /// merged into the active repo set (legacy Maven behaviour).
    #[test]
    fn extend_repos_with_global_opt_in_adds_transitive_repo() {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let mut config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        config.security.allow_transitive_repositories = true;

        let backend = test_backend_with_config(config);
        backend.extend_repos(std::iter::once(Repository::new(
            Some("vendor".to_string()),
            "https://vendor.example/maven2/",
            true,
            false,
        )));
        let after = backend.repos_snapshot();
        assert!(
            after.iter().any(|repo| repo.url.contains("vendor.example")),
            "expected vendor repo to be added when allow_transitive_repositories is true",
        );
    }

    /// Extending with the same URL many times must stay cheap. The seen
    /// set is shared on the backend, so each duplicate call is O(1) instead of
    /// rebuilding a HashSet from the (growing) repo list. We exercise 1000
    /// duplicate extends and assert the repo set stays a single entry, which
    /// is the load-bearing invariant: the index correctly absorbs duplicates
    /// without re-snapshotting `repos`.
    #[test]
    fn extend_repos_dedup_is_constant_time() {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let mut config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        config.security.allow_transitive_repositories = true;

        let backend = test_backend_with_config(config);
        let repo = Repository::new(
            Some("dup".to_string()),
            "https://dup.example/maven2/",
            true,
            false,
        );
        for _ in 0..1000 {
            backend.extend_repos(std::iter::once(repo.clone()));
        }
        let after = backend.repos_snapshot();
        assert_eq!(
            after.len(),
            1,
            "1000 identical extends should yield exactly one repo entry"
        );
        assert!(
            after
                .iter()
                .any(|repo| repo.url == "https://dup.example/maven2/"),
            "the deduped repo must be the one we inserted"
        );
    }

    /// The seen-URL set must seed from the configured repos at
    /// construction so that a transitive POM cannot re-add an already-trusted
    /// URL twice. The dedup index is built once in the constructor rather than
    /// rebuilt from `repos` on each call, so this seeding is what guarantees
    /// the invariant.
    #[test]
    fn extend_repos_seeds_seen_from_initial_repos() {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let mut config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        config.security.allow_transitive_repositories = true;

        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_config::Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
        let initial = vec![Repository::new(
            Some("central".to_string()),
            "https://central.example/maven2/",
            true,
            false,
        )];
        let backend = RepoBackend::new(&ctx, initial, false);

        // Re-extend with the same URL: must not double-insert.
        backend.extend_repos(std::iter::once(Repository::new(
            Some("central-again".to_string()),
            "https://central.example/maven2/",
            true,
            false,
        )));

        let after = backend.repos_snapshot();
        assert_eq!(
            after.len(),
            1,
            "initial repo URL must be pre-seeded in the dedup index"
        );
    }

    /// The warn-log site that fires when a transitive `<repositories>`
    /// declaration is dropped under the default-deny policy MUST keep
    /// emitting `tracing::warn!` events. The bridge that turns these
    /// warnings into the user-facing `TRANSITIVE_REPO_DROPPED` diagnostic
    /// subscribes to this event; removing or downgrading it would silently
    /// break the diagnostic.
    ///
    /// We capture tracing output through a minimal in-memory subscriber
    /// and assert both that the per-URL warn fires and that the summary
    /// warn fires. Together they cover the two warn sites at the head of
    /// `extend_repos`.
    #[test]
    fn extend_repos_warns_on_dropped_transitive_repo() {
        use std::sync::Mutex;
        use tracing::Level;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::registry::Registry;

        use super::test_support::{CaptureLayer, CapturedEvents};

        let events: CapturedEvents = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Registry::default().with(CaptureLayer {
            events: Arc::clone(&events),
        });

        // Default-deny policy; the warn must fire.
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        let backend = test_backend_with_config(config);

        tracing::subscriber::with_default(subscriber, || {
            backend.extend_repos(std::iter::once(Repository::new(
                Some("attacker".to_string()),
                "https://attacker.example/maven2/",
                true,
                false,
            )));
        });

        let captured = events.lock().expect("events lock").clone();
        let warn_msgs: Vec<&str> = captured
            .iter()
            .filter(|(level, _)| *level == Level::WARN)
            .map(|(_, msg)| msg.as_str())
            .collect();

        assert!(
            warn_msgs
                .iter()
                .any(|m| m.contains("ignoring transitive repository declaration")),
            "per-URL warn must fire for dropped transitive repo; saw: {warn_msgs:?}"
        );
        assert!(
            warn_msgs
                .iter()
                .any(|m| m.contains("ignored 1 transitive repository declarations")),
            "summary warn must fire for dropped transitive repos; saw: {warn_msgs:?}"
        );
    }

    /// Corollary: the trusted bypass path MUST NOT warn. Those
    /// repositories were declared by the user's own POM, so they are
    /// expected and should not be reported as dropped.
    #[test]
    fn extend_repos_trusted_does_not_warn() {
        use std::sync::Mutex;
        use tracing::Level;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::registry::Registry;

        use super::test_support::{CaptureLayer, CapturedEvents};

        let events: CapturedEvents = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Registry::default().with(CaptureLayer {
            events: Arc::clone(&events),
        });

        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        let backend = test_backend_with_config(config);

        tracing::subscriber::with_default(subscriber, || {
            backend.extend_repos_trusted(std::iter::once(Repository::new(
                Some("user".to_string()),
                "https://user.example/maven2/",
                true,
                false,
            )));
        });

        let captured = events.lock().expect("events lock").clone();
        let warn_msgs: Vec<&str> = captured
            .iter()
            .filter(|(level, _)| *level == Level::WARN)
            .map(|(_, msg)| msg.as_str())
            .collect();
        assert!(
            warn_msgs.is_empty(),
            "trusted extend must not emit any warn events; saw: {warn_msgs:?}"
        );
    }

    /// URL-prefix allowlist lets operators narrowly opt in to specific
    /// transitive repos without flipping the global flag.
    #[test]
    fn extend_repos_with_prefix_allowlist_adds_matching_repo() {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let mut config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        config
            .security
            .transitive_repository_allowlist
            .push("https://allowed.example/".to_string());

        let backend = test_backend_with_config(config);
        backend.extend_repos(vec![
            Repository::new(
                Some("allowed".to_string()),
                "https://allowed.example/maven2/",
                true,
                false,
            ),
            Repository::new(
                Some("attacker".to_string()),
                "https://attacker.example/maven2/",
                true,
                false,
            ),
        ]);
        let after = backend.repos_snapshot();
        assert!(
            after
                .iter()
                .any(|repo| repo.url.contains("allowed.example")),
            "expected allowlisted repo to be added",
        );
        assert!(
            !after
                .iter()
                .any(|repo| repo.url.contains("attacker.example")),
            "expected non-allowlisted repo to be ignored",
        );
    }

    /// Regression: `resolve_dynamic_version_internal` must gate each candidate
    /// with `repo.allows_version`. Without per-repo gating, `RELEASE` could
    /// pick a release version published only to a snapshots-only mirror; this
    /// test pre-populates the metadata cache so two mirrors advertise
    /// different versions and confirms only the releases-mirror version is
    /// selected.
    #[tokio::test(flavor = "multi_thread")]
    async fn dynamic_version_release_skips_snapshot_only_mirror() {
        use crate::context::MetadataKey;
        use rv_repo::{Metadata, RepoClient};

        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_config::Platform::new("linux", "x86_64").unwrap();
        let client = RepoClient::new(&config).await.expect("client");

        let releases_repo = Repository::new(
            Some("releases".to_string()),
            "https://releases.example/maven2/",
            true,
            false,
        );
        let snapshots_repo = Repository::new(
            Some("snapshots".to_string()),
            "https://snapshots.example/maven2/",
            false,
            true,
        );

        let ctx = ResolveContext::new(
            config,
            vec![releases_repo.clone(), snapshots_repo.clone()],
            store,
            platform,
            Some(client),
        );

        // Snapshots-only repo (mis)advertises a release version 2.0.0; the
        // releases-only repo offers only 1.0.0. Without per-repo gating the
        // 2.0.0 entry from the snapshots mirror would win.
        let snap_meta = Metadata {
            release: Some("2.0.0".to_string()),
            versions: vec!["2.0.0".to_string()],
            ..Metadata::default()
        };
        ctx.insert_metadata(
            MetadataKey::new(
                Arc::from(snapshots_repo.url.as_str()),
                Arc::from("com.example"),
                Arc::from("lib"),
            ),
            snap_meta,
        );

        let rel_meta = Metadata {
            release: Some("1.0.0".to_string()),
            versions: vec!["1.0.0".to_string()],
            ..Metadata::default()
        };
        ctx.insert_metadata(
            MetadataKey::new(
                Arc::from(releases_repo.url.as_str()),
                Arc::from("com.example"),
                Arc::from("lib"),
            ),
            rel_meta,
        );

        let backend = RepoBackend::new(
            &ctx,
            vec![releases_repo.clone(), snapshots_repo.clone()],
            false,
        );

        let resolved = backend
            .resolve_dynamic_version_internal("com.example", "lib", DynamicVersionSelector::Release)
            .await
            .expect("dynamic RELEASE resolves");

        assert_eq!(
            resolved.version.to_string(),
            "1.0.0",
            "RELEASE must not pick a version served only by a snapshots-only mirror"
        );
    }
}
