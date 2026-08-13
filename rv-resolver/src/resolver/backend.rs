//! `RepoBackend`: solver Backend implementation backed by remote Maven repositories.
//!
//! Owns version resolution, snapshot resolution, POM fetching, BOM constraint
//! collection, and local project loading for the solver.

use futures::stream::{self, StreamExt};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use rv_config::{ArtifactKey, BlobId};
use rv_maven_model::{Pom, PomError, Project, Scope};
use rv_repo::{ArtifactRequest, Metadata, RepoError, Repository};
use rv_version::{Coord, Version, VersionReq};

use crate::context::{MetadataKey, ResolveContext};
use crate::error::{RepoSearchStatus, ResolveError, Result};
use crate::parent_resolver::build_activation_context_async;
use crate::solver::{Backend, ResolvedProject, ResolvedVersion};
use crate::workspace::{Workspace, WorkspaceModule};

use super::WorkspaceProgress;
use super::fetcher::RepoParentResolver;
use super::utils::{dummy_coord, filter_repos_for_version, select_versions};

pub(super) type WorkspaceSupportPomBuffer = Arc<Mutex<Vec<(ArtifactKey, Vec<u8>)>>>;

/// Bare `group:artifact:version` of a POM. A companion POM is per GAV — one
/// `.pom` serves every packaging and classifier of a coordinate, and Maven has
/// one local-repository path for it — so this, not the full `Coord`, is the
/// identity a POM pin is keyed by.
pub(super) type PomGav = (String, String, String);

pub(super) fn pom_gav(coord: &Coord) -> PomGav {
    (
        coord.group_id.to_string(),
        coord.artifact_id.to_string(),
        coord.version.to_string(),
    )
}

fn format_pom_gav(gav: &PomGav) -> String {
    format!("{}:{}:{}", gav.0, gav.1, gav.2)
}

/// What `rv sync` records about one support POM (a parent or an imported BOM)
/// it fetched, so `rv export-m2` can reproduce that exact file offline.
///
/// Support POMs never become lockfile packages, so this provenance is the only
/// thing standing behind them. The coordinate it is keyed by is the
/// load-bearing part: export refuses to write an offline repository missing a
/// POM named here.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct SupportPomProvenance {
    /// Id of the repository that served the POM. Empty when that repository
    /// carries no id of its own, which says only that the POM's
    /// `_remote.repositories` marker has no id to name.
    pub repo_id: String,
    /// SHA-256 of the exact POM bytes, which is also their content-store blob
    /// id. Pins which bytes export ships for the coordinate: the store's
    /// coordinate index is last-writer-wins, so another project syncing
    /// against the same store can repoint the coordinate at other bytes.
    pub sha256: String,
}

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
    /// Provenance for each support POM (parent / imported BOM) fetched during
    /// resolution, keyed by `"g:a:v"`. A support POM can resolve from a
    /// different repository than the child that referenced it; recording the
    /// serving repo's id here lets `rv export-m2` label that POM's
    /// `_remote.repositories` marker with the correct id instead of guessing
    /// the child's repo, and recording the bytes' SHA-256 lets it export that
    /// exact blob rather than whatever the store's coordinate index points at
    /// by the time the export runs.
    pub(super) support_pom_provenance: Arc<RwLock<HashMap<String, SupportPomProvenance>>>,
    /// SHA-256 of the companion POM bytes this resolution actually parsed for
    /// each graph coordinate, recorded where those bytes are in hand.
    ///
    /// The lockfile's `pom_sha256` comes from here and never from the store's
    /// coordinate index: the index is last-writer-wins, so between the fetch
    /// that built the graph and the moment the lock is written, any other
    /// project sharing the store can repoint `(g, a, v, pom)` at different
    /// bytes. Pinning the index entry would name a POM the graph was never
    /// resolved against.
    pub(super) companion_pom_blobs: Arc<RwLock<HashMap<PomGav, BlobId>>>,
    /// Trusted reactor models available to parent/BOM/dependency resolution.
    pub(super) workspace: Option<Arc<Workspace>>,
    /// Parent/BOM bytes collected during parallel workspace model resolution.
    ///
    /// Store I/O cannot run through the synchronous model bridge without
    /// starving runtime workers, so the driver flushes this buffer before
    /// artifact population.
    pub(super) workspace_support_poms: Option<WorkspaceSupportPomBuffer>,
    /// Liveness counter for the all-reactor stall watchdog. `None` outside a
    /// workspace resolve, where there is no watchdog to feed.
    pub(super) workspace_progress: Option<Arc<WorkspaceProgress>>,
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

fn select_workspace_version(
    group_id: &str,
    artifact_id: &str,
    req: &VersionReq,
    versions: Vec<Version>,
) -> Result<ResolvedVersion> {
    versions
        .into_iter()
        .filter(|version| req.matches(version))
        .max()
        .map(|version| ResolvedVersion {
            version,
            repo_url: None,
        })
        .ok_or_else(|| ResolveError::VersionNotFound {
            coord: format!("{group_id}:{artifact_id}"),
            requirement: req.to_string(),
        })
}

fn best_workspace_dynamic_version(
    selector: DynamicVersionSelector,
    versions: Vec<Version>,
) -> Option<Version> {
    versions
        .into_iter()
        .filter(|version| {
            !matches!(selector, DynamicVersionSelector::Release)
                || !rv_repo::is_snapshot_version(version.as_str())
        })
        .max()
}

fn select_workspace_dynamic_version(
    group_id: &str,
    artifact_id: &str,
    selector: DynamicVersionSelector,
    versions: Vec<Version>,
) -> Result<ResolvedVersion> {
    best_workspace_dynamic_version(selector, versions)
        .map(|version| ResolvedVersion {
            version,
            repo_url: None,
        })
        .ok_or_else(|| ResolveError::VersionNotFound {
            coord: format!("{group_id}:{artifact_id}"),
            requirement: selector.requirement_label().to_string(),
        })
}

impl RepoBackend {
    pub(super) fn new(ctx: &ResolveContext, repos: Vec<Repository>, strict: bool) -> Self {
        let seen: HashSet<String> = repos.iter().map(|repo| repo.url.clone()).collect();
        // The starting list is not the configuration: the driver merges the
        // root POM's own `<repositories>` (and any its parent chain declared)
        // into it before the backend exists, so these are trust grants too and
        // the address screen has to hear about them.
        if let Some(client) = ctx.client.as_ref() {
            client.trust_repositories(&repos);
        }
        Self {
            ctx: ctx.clone(),
            repos: Arc::new(RwLock::new(repos)),
            seen_repo_urls: Arc::new(RwLock::new(seen)),
            strict,
            project_repo_url: Arc::new(RwLock::new(HashMap::new())),
            support_pom_provenance: Arc::new(RwLock::new(HashMap::new())),
            companion_pom_blobs: Arc::new(RwLock::new(HashMap::new())),
            workspace: None,
            workspace_support_poms: None,
            workspace_progress: None,
        }
    }

    pub(super) fn with_workspace(mut self, workspace: Arc<Workspace>) -> Self {
        self.workspace = Some(workspace);
        self
    }

    pub(super) fn with_workspace_support_poms(
        mut self,
        support_poms: WorkspaceSupportPomBuffer,
    ) -> Self {
        self.workspace_support_poms = Some(support_poms);
        self
    }

    pub(super) fn with_workspace_progress(mut self, progress: Arc<WorkspaceProgress>) -> Self {
        self.workspace_progress = Some(progress);
        self
    }

    /// Tell the all-reactor stall watchdog that something moved. One relaxed
    /// atomic add.
    ///
    /// Raised on both sides of every repository round trip: starting a request
    /// is progress (it restarts the watchdog window at the moment the wait
    /// begins, instead of leaving it running from whatever landed before), and
    /// so is a failed one — a 500, a timeout, a retry sequence — because the
    /// question this counter answers is whether the process is still alive,
    /// not whether it is succeeding. Bounding how long a single attempt may
    /// run belongs to rv-repo's request timeout.
    pub(super) fn note_progress(&self) {
        if let Some(progress) = self.workspace_progress.as_ref() {
            progress.note();
        }
    }

    fn workspace_module_for_coord(&self, coord: &Coord) -> Option<&WorkspaceModule> {
        self.workspace
            .as_deref()?
            .candidates(coord.group_id.as_str(), coord.artifact_id.as_str())
            .find(|module| module.gav().version == coord.version.as_str())
    }

    pub(super) fn workspace_pom_for_coord(&self, coord: &Coord) -> Option<Pom> {
        let module = self.workspace_module_for_coord(coord)?;
        let mut pom = module.pom().clone();
        // Parent/BOM payload validation runs before inheritance. Workspace
        // identity is the interpolated effective GAV, so expose that identity
        // instead of comparing the request with raw `${revision}` text.
        pom.group_id = Some(module.gav().group_id.clone());
        pom.artifact_id = Some(module.gav().artifact_id.clone());
        pom.version = Some(module.gav().version.clone());
        if let Some(workspace) = self.workspace.as_deref() {
            workspace.inject_root_properties(&mut pom);
        }
        Some(pom)
    }

    fn workspace_versions(&self, group_id: &str, artifact_id: &str) -> Vec<Version> {
        self.workspace
            .as_deref()
            .into_iter()
            .flat_map(|workspace| workspace.candidates(group_id, artifact_id))
            .filter_map(|module| Version::parse(&module.gav().version).ok())
            .collect()
    }

    /// Snapshot the current repo list. Cheap, since repo lists are small, and
    /// avoids holding the lock across awaits.
    pub(super) fn repos_snapshot(&self) -> Vec<Repository> {
        self.repos.read().expect("repos lock poisoned").clone()
    }

    /// Snapshot the `"g:a:v" -> provenance` records collected for support POMs.
    pub(super) fn support_pom_provenance_snapshot(&self) -> Vec<(String, SupportPomProvenance)> {
        self.support_pom_provenance
            .read()
            .expect("support_pom_provenance lock poisoned")
            .iter()
            .map(|(coord, provenance)| (coord.clone(), provenance.clone()))
            .collect()
    }

    /// The companion-POM digest recorded for one graph coordinate, if this
    /// resolution fetched (or replayed from cache) that coordinate's POM.
    pub(super) fn companion_pom_blob(&self, gav: &PomGav) -> Option<BlobId> {
        self.companion_pom_blobs
            .read()
            .expect("companion_pom_blobs lock poisoned")
            .get(gav)
            .cloned()
    }

    /// Record the bytes a POM fetch produced for `gav`.
    ///
    /// A second observation with a different digest is an error rather than a
    /// winner: both were used to build this graph, and one lockfile row (and
    /// one `~/.m2` path) can only carry one of them, so keeping either would
    /// leave part of the resolution pinned to bytes it never saw.
    fn record_companion_pom_blob(&self, gav: PomGav, blob: &BlobId) -> Result<()> {
        let mut recorded = self
            .companion_pom_blobs
            .write()
            .expect("companion_pom_blobs lock poisoned");
        match recorded.get(&gav) {
            Some(existing) if existing != blob => Err(ResolveError::ConflictingResolvedPomBytes {
                coord: format_pom_gav(&gav),
                first_sha256: existing.to_string(),
                second_sha256: blob.to_string(),
            }),
            Some(_) => Ok(()),
            None => {
                recorded.insert(gav, blob.clone());
                Ok(())
            }
        }
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
        let mut added: Vec<Repository> = Vec::new();
        {
            let mut seen = self
                .seen_repo_urls
                .write()
                .expect("seen_repo_urls lock poisoned");
            let mut guard = self.repos.write().expect("repos lock poisoned");
            for repo in extra {
                if seen.insert(repo.url.clone()) {
                    added.push(repo.clone());
                    guard.push(repo);
                }
            }
        }
        self.trust_repo_hosts(&added);
    }

    /// Tell the HTTP client that these repositories are trusted, so its address
    /// screen stops treating them as SSRF targets.
    ///
    /// Without this, a repository the configuration never named — the common
    /// case being one declared by the project's own POM — is refused the
    /// moment its hostname resolves onto a private network, which is exactly
    /// how an on-prem registry is deployed. The grant is host-level and buys a
    /// direct connection only: it confers no redirect authority, so a hostile
    /// POM cannot widen it into a probe of the private network. See
    /// [`rv_repo::RepoClient::trust_repositories`].
    fn trust_repo_hosts(&self, repos: &[Repository]) {
        if repos.is_empty() {
            return;
        }
        if let Some(client) = self.ctx.client.as_ref() {
            client.trust_repositories(repos);
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
        let mut added: Vec<Repository> = Vec::new();
        {
            // Lock order: take the URL-set guard first, then the repos guard.
            // All call sites in this module follow the same order, so the pair
            // cannot deadlock.
            let mut seen = self
                .seen_repo_urls
                .write()
                .expect("seen_repo_urls lock poisoned");
            let mut guard = self.repos.write().expect("repos lock poisoned");
            for repo in filtered {
                if seen.insert(repo.url.clone()) {
                    added.push(repo.clone());
                    guard.push(repo);
                }
            }
        }
        // Only what survived the allowlist above is trusted, so only that is
        // exempted from the address screen.
        self.trust_repo_hosts(&added);
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

        let workspace_versions = self.workspace_versions(group_id, artifact_id);
        let client = match self.ctx.client.as_ref() {
            Some(client) => client,
            None if !workspace_versions.is_empty() => {
                return select_workspace_version(group_id, artifact_id, req, workspace_versions);
            }
            None => return Err(ResolveError::MissingRepoClient),
        };

        let repos = self.repos_snapshot();
        // BTreeSet keeps version iteration deterministic when scanning for
        // the best match below.
        let mut all_versions = BTreeSet::new();
        all_versions.extend(workspace_versions);
        let mut found_metadata = !all_versions.is_empty();
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
        // Iterate indices, not `repos.iter().enumerate()`. Borrowing the
        // closure's `&Repository` argument inside the `async move` block gives
        // the block a higher-ranked lifetime that `Send` inference cannot see
        // through, and `Backend`'s futures must be `Send`.
        let results: Vec<(usize, RepoOutcome, bool)> = stream::iter(0..repos.len())
            .map(|idx| {
                let repo = &repos[idx];
                let url: Arc<str> = Arc::clone(&repo_urls[idx]);
                let key = MetadataKey::new(url, Arc::from(group_id), Arc::from(artifact_id));
                let dummy = &dummy;
                async move {
                    if let Some(metadata) = self.ctx.cached_metadata(&key) {
                        return (idx, RepoOutcome::Hit(metadata), false);
                    }
                    self.note_progress();
                    match client.fetch_metadata(repo, dummy).await {
                        Ok(metadata) => {
                            self.note_progress();
                            self.ctx.insert_metadata(key.clone(), metadata);
                            match self.ctx.cached_metadata(&key) {
                                Some(metadata) => (idx, RepoOutcome::Hit(metadata), true),
                                None => (idx, RepoOutcome::CacheEvicted, true),
                            }
                        }
                        Err(err) => {
                            // A failed response is progress too.
                            self.note_progress();
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
        let workspace_versions = self.workspace_versions(group_id, artifact_id);
        let client = match self.ctx.client.as_ref() {
            Some(client) => client,
            None if !workspace_versions.is_empty() => {
                return select_workspace_dynamic_version(
                    group_id,
                    artifact_id,
                    selector,
                    workspace_versions,
                );
            }
            None => return Err(ResolveError::MissingRepoClient),
        };

        let repos = self.repos_snapshot();
        let mut best = best_workspace_dynamic_version(selector, workspace_versions);
        let mut found_metadata = best.is_some();
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
        // Iterate indices, not `repos.iter().enumerate()`. Borrowing the
        // closure's `&Repository` argument inside the `async move` block gives
        // the block a higher-ranked lifetime that `Send` inference cannot see
        // through, and `Backend`'s futures must be `Send`.
        let results: Vec<(usize, RepoOutcome)> = stream::iter(0..repos.len())
            .map(|idx| {
                let repo = &repos[idx];
                let url: Arc<str> = Arc::clone(&repo_urls[idx]);
                let key = MetadataKey::new(url, Arc::from(group_id), Arc::from(artifact_id));
                let dummy = &dummy;
                async move {
                    if let Some(metadata) = self.ctx.cached_metadata(&key) {
                        return (idx, RepoOutcome::Hit(metadata));
                    }
                    self.note_progress();
                    match client.fetch_metadata(repo, dummy).await {
                        Ok(metadata) => {
                            self.note_progress();
                            self.ctx.insert_metadata(key.clone(), metadata);
                            match self.ctx.cached_metadata(&key) {
                                Some(metadata) => (idx, RepoOutcome::Hit(metadata)),
                                None => (idx, RepoOutcome::CacheEvicted),
                            }
                        }
                        Err(err) => {
                            // A failed response is progress too.
                            self.note_progress();
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
        if self.workspace_module_for_coord(coord).is_some() {
            return Ok(ResolvedVersion {
                version: coord.version.clone(),
                repo_url: None,
            });
        }

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
            self.note_progress();
            match client.resolve_snapshot_version(repo, coord).await {
                Ok(resolution) => {
                    self.note_progress();
                    let version = Version::parse(&resolution.version)?;
                    return Ok(ResolvedVersion {
                        version,
                        repo_url: Some(Arc::from(repo.url.as_str())),
                    });
                }
                Err(err) => {
                    // A failed response is progress too.
                    self.note_progress();
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
        if let Some(module) = self.workspace_module_for_coord(coord) {
            let workspace = self
                .workspace
                .as_deref()
                .expect("workspace module requires workspace");
            let pom_path = module.pom_path.clone();
            let base_dir = workspace
                .root()
                .join(&pom_path)
                .parent()
                .map(std::path::Path::to_path_buf);
            let resolver = RepoParentResolver::with_strict_and_trust(
                self.clone(),
                base_dir.clone(),
                Some(workspace.root().to_path_buf()),
                true,
                super::fetcher::RepoTrust::Root,
            );
            // Only the reactor root's `.mvn/maven.config` applies. Build the
            // target-platform context without probing a module-local `.mvn`,
            // then restore the module base directory for file activation and
            // `${basedir}` interpolation.
            let mut activation =
                build_activation_context_async(None, &self.ctx.config, Some(&self.ctx.platform))
                    .await;
            activation.base_dir = base_dir;
            workspace.apply_root_maven_config(&mut activation);
            let mut pom = module.pom().clone();
            workspace.inject_root_properties(&mut pom);
            let project = Project::from_pom_with_context(pom, resolver, &activation)?;
            let effective_gav = format!(
                "{}:{}:{}",
                project.group_id, project.artifact_id, project.version
            );
            if effective_gav != module.gav().to_string() {
                return Err(ResolveError::InternalError(format!(
                    "workspace model {} resolved as {}, expected {}",
                    pom_path,
                    effective_gav,
                    module.gav()
                )));
            }
            self.extend_repos_trusted(project.repositories.iter().cloned().map(Repository::from));
            return Ok(ResolvedProject {
                project,
                repo_url: None,
                workspace_module: Some(pom_path),
                platform_constraints: None,
            });
        }

        if let Some(cached) = self.ctx.cached_project(coord) {
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
            // Replay the POM identity too. The cache can be shared with
            // another backend that did the fetch, and this graph is built from
            // the cached model, so the pin has to name the bytes that model
            // came from.
            self.record_companion_pom_blob(pom_gav(coord), &cached.pom_blob)?;
            return Ok(ResolvedProject {
                project: cached.project,
                repo_url,
                workspace_module: None,
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
            self.note_progress();
            match client.fetch_pom(repo, &req).await {
                Ok(bytes) => {
                    self.note_progress();
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
                    // Persist and pin the exact bytes this graph node was
                    // parsed from, here, where they are in hand. The download
                    // pass would otherwise re-fetch the same URL and index
                    // whatever it got, and the lockfile would pin that instead.
                    let pom_blob = self.store_pom_bytes(coord, &bytes).await?;
                    self.record_companion_pom_blob(pom_gav(coord), &pom_blob)?;
                    let repo_url: Arc<str> = Arc::from(repo.url.as_str());
                    self.ctx
                        .insert_project(coord.clone(), project.clone(), pom_blob);
                    // Record provenance so a subsequent cache hit returns the
                    // same repository instead of `None`.
                    self.project_repo_url
                        .write()
                        .expect("project_repo_url lock poisoned")
                        .insert(coord.clone(), Arc::clone(&repo_url));
                    return Ok(ResolvedProject {
                        project,
                        repo_url: Some(repo_url),
                        workspace_module: None,
                        platform_constraints: None,
                    });
                }
                Err(err) => {
                    // A failed response is progress too.
                    self.note_progress();
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

    /// Sync wrapper around [`Self::fetch_pom_bytes`], for the sync
    /// parent-chain resolver (the only caller).
    ///
    /// The bridge spawns the future as a task, so it has to own everything it
    /// touches. `RepoBackend` is `Arc`-backed, so the clone is cheap and every
    /// clone shares the same repo list, caches and support-POM buffer — a
    /// borrowed `&self` and an owned clone are interchangeable here.
    pub(super) fn fetch_pom_bytes_blocking(&self, coord: &Coord) -> Result<Vec<u8>> {
        let backend = self.clone();
        let coord = coord.clone();
        crate::sync_bridge::block_on_async(async move { backend.fetch_pom_bytes(&coord).await })
    }

    async fn fetch_pom_bytes(&self, coord: &Coord) -> Result<Vec<u8>> {
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
            self.note_progress();
            match client.fetch_pom(repo, &req).await {
                Ok(bytes) => {
                    self.note_progress();
                    // Persist this POM so `rv export-m2` can materialize it
                    // for strict offline `mvn -o`. This path fetches only
                    // *support* POMs: parent POMs and imported BOMs (graph
                    // dependencies flow through `fetch_project_internal`),
                    // which are otherwise never persisted and break
                    // offline parent/BOM resolution. It runs across every
                    // eligible repo, so a parent that lives in a different
                    // repo than its child is still captured. A store-write
                    // failure is fatal, matching how artifact writes behave
                    // in `populate_artifacts`.
                    self.persist_support_pom(coord, repo.id.as_deref(), &bytes)
                        .await?;
                    return Ok(bytes.to_vec());
                }
                Err(err) => {
                    // A failed response is progress too.
                    self.note_progress();
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

    /// Persist a fetched support POM (parent or imported BOM) into the content
    /// store under its `(group, artifact, version, "pom")` key, so
    /// `rv export-m2` can materialize the parent/BOM closure for offline
    /// `mvn -o`.
    ///
    /// Nothing here fails for a remote-side reason — the POM has already been
    /// fetched — so a store error means a broken local store (unwritable
    /// directory, unusable index), which [`Self::store_pom_bytes`] treats as
    /// fatal like every other store write.
    async fn persist_support_pom(
        &self,
        coord: &Coord,
        repo_id: Option<&str>,
        bytes: &[u8],
    ) -> Result<()> {
        let blob = self.store_pom_bytes(coord, bytes).await?;

        // Record which repository served this support POM so export-m2 can
        // label its marker correctly even when the parent/BOM lives in a
        // different repo than the child that referenced it. Recorded only
        // after the bytes are stored (or queued for the workspace flush), so
        // provenance never advertises a POM the store does not hold.
        //
        // EVERY remote support POM is recorded, including one served by a
        // repository that carries no id: the empty id means "fetched remotely,
        // source repository has no id", which is what export-m2 needs to treat
        // the coordinate as one the store must hold. Recording only id'd repos
        // left those POMs outside the completeness check entirely.
        //
        // Key on bare "g:a:v" to match the export-side lookup. NOT
        // `coord.to_string()`: parent/BOM coords carry packaging=pom, and
        // `Coord::Display` would append it ("g:a:v:pom"), so the key would
        // never match export's `format!("{g}:{a}:{v}")` and the provenance
        // would be silently dropped.
        let coord_key = format!("{}:{}:{}", coord.group_id, coord.artifact_id, coord.version);
        let observed = SupportPomProvenance {
            repo_id: repo_id.unwrap_or_default().to_string(),
            sha256: blob.to_string(),
        };
        let mut recorded = self
            .support_pom_provenance
            .write()
            .expect("support_pom_provenance lock poisoned");
        match recorded.get_mut(&coord_key) {
            // Two fetches of one coordinate that returned different bytes are
            // a conflict, not a race one observation wins. The lockfile pins a
            // single digest per support POM and `rv export-m2` writes a single
            // `.pom`, so whichever observation lost would leave the part of the
            // resolution that used it exported against a POM it never read.
            // Collapsing here would also hide the conflict from the
            // reactor-level check in `rv sync`, which is meant to be the
            // cross-module backstop for exactly this.
            Some(entry) if entry.sha256 != observed.sha256 => {
                Err(ResolveError::ConflictingResolvedPomBytes {
                    coord: coord_key,
                    first_sha256: entry.sha256.clone(),
                    second_sha256: observed.sha256,
                })
            }
            // Same bytes, so only the repository id is in question. A real id
            // never loses to a later id-less hit for the same coordinate (the
            // same POM can be served by several repos across a resolution);
            // upgrading the id is safe precisely because the digests agree.
            Some(entry) => {
                if entry.repo_id.is_empty() && !observed.repo_id.is_empty() {
                    entry.repo_id = observed.repo_id;
                }
                Ok(())
            }
            None => {
                recorded.insert(coord_key, observed);
                Ok(())
            }
        }
    }

    /// Put POM bytes in the content store under their
    /// `(group, artifact, version, "pom")` key and return their content
    /// address.
    ///
    /// A store-write failure is fatal, the same severity `populate_artifacts`
    /// gives an artifact write: the alternative is a lockfile pinning a POM
    /// whose bytes never landed, which `rv export-m2` can only discover
    /// afterwards.
    async fn store_pom_bytes(&self, coord: &Coord, bytes: &[u8]) -> Result<BlobId> {
        let key = ArtifactKey::new(
            coord.group_id.to_string(),
            coord.artifact_id.to_string(),
            coord.version.to_string(),
            "pom",
            None,
        );
        // The blob id IS the SHA-256 of the bytes, so the digest returned here
        // names the same blob the deferred workspace flush will put.
        let blob = BlobId::from_bytes(bytes);
        if let Some(support_poms) = self.workspace_support_poms.as_ref() {
            support_poms
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((key, bytes.to_vec()));
        } else {
            let written = self.ctx.store.put_bytes(bytes).await?;
            self.ctx.store.add_artifact(&key, &written).await?;
            debug_assert_eq!(written, blob, "store blob id must be the bytes' SHA-256");
        }
        Ok(blob)
    }
}

impl Backend for RepoBackend {
    fn workspace_module(&self, coord: &Coord) -> Option<String> {
        self.workspace_module_for_coord(coord)
            .map(|module| module.pom_path.clone())
    }

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
    use std::str::FromStr;

    fn test_backend_with_config(config: Config) -> RepoBackend {
        let store_tmp = tempfile::tempdir().unwrap();
        test_backend_with_store(config, store_tmp.path())
    }

    /// Same as [`test_backend_with_config`] but with the store root supplied by
    /// the caller, so tests that actually exercise store I/O can keep the
    /// `TempDir` alive (and reach into it) for the duration of the test.
    fn test_backend_with_store(config: Config, store_root: &std::path::Path) -> RepoBackend {
        let store = Arc::new(Store::open(store_root).expect("store"));
        let platform = rv_config::Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
        RepoBackend::new(&ctx, Vec::new(), false)
    }

    fn test_config() -> Config {
        let paths = ResolvedPaths::discover().expect("paths");
        Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new())
    }

    /// The provenance `persist_support_pom` records for `bytes` served by
    /// `repo_id`: the digest half is always the bytes' SHA-256, which is also
    /// their content-store blob id.
    fn provenance(repo_id: &str, bytes: &[u8]) -> SupportPomProvenance {
        SupportPomProvenance {
            repo_id: repo_id.to_string(),
            sha256: BlobId::from_bytes(bytes).to_string(),
        }
    }

    fn support_pom_coord() -> Coord {
        Coord {
            group_id: "com.example".into(),
            artifact_id: "theparent".into(),
            version: Version::parse("2.0").unwrap(),
            packaging: Some("pom".to_string()),
            classifier: None,
        }
    }

    /// Support-POM provenance must be keyed on the bare `g:a:v`, matching the
    /// export-side lookup. Parent/BOM coords carry packaging=pom, so a
    /// `coord.to_string()` key would be `g:a:v:pom` and never match,
    /// silently dropping the provenance. This test guards against that.
    #[tokio::test]
    async fn persist_support_pom_keys_on_bare_gav() {
        let store_tmp = tempfile::tempdir().unwrap();
        let backend = test_backend_with_store(test_config(), store_tmp.path());
        let coord = support_pom_coord();
        assert_eq!(coord.to_string(), "com.example:theparent:2.0:pom");
        backend
            .persist_support_pom(&coord, Some("corp"), b"<project/>")
            .await
            .expect("persist");
        assert_eq!(
            backend.support_pom_provenance_snapshot(),
            vec![(
                "com.example:theparent:2.0".to_string(),
                provenance("corp", b"<project/>")
            )],
            "provenance must key on bare g:a:v, not coord.to_string() (g:a:v:pom)"
        );
    }

    /// A support POM whose bytes cannot be written to the content store must
    /// fail the resolve, the same way `populate_artifacts` fails on an artifact
    /// store write. Anything softer produces a lock whose provenance names a
    /// support POM the store does not hold, which only `rv export-m2` finds out
    /// about — long after the sync reported success.
    ///
    /// The failure is injected by replacing the store's `tmp/` staging
    /// directory with a regular file: `put_bytes` starts with a
    /// `create_dir_all` on it, which cannot succeed against a non-directory for
    /// any user (so this does not quietly pass when tests run as root).
    #[tokio::test]
    async fn persist_support_pom_store_write_failure_is_fatal() {
        let store_tmp = tempfile::tempdir().unwrap();
        let backend = test_backend_with_store(test_config(), store_tmp.path());

        let staging = store_tmp.path().join("tmp");
        std::fs::remove_dir_all(&staging).expect("remove staging dir");
        std::fs::write(&staging, b"not a directory").expect("occupy staging path");

        let coord = support_pom_coord();
        let err = backend
            .persist_support_pom(&coord, Some("corp"), b"<project/>")
            .await
            .expect_err("store write must fail the resolve, not be swallowed");
        assert!(
            matches!(err, ResolveError::Store(_)),
            "expected a store error, got {err:?}"
        );
        assert!(
            backend.support_pom_provenance_snapshot().is_empty(),
            "provenance must not advertise a support POM the store never took"
        );
    }

    /// A support POM served by a repository with no `<id>` must still be
    /// recorded, with an empty id. The coordinate is what lets `rv export-m2`
    /// refuse to write an offline repository that is missing this POM;
    /// recording only id'd repositories left those POMs unprotected. A later
    /// id-less hit must not overwrite an id that was already learned for the
    /// same coordinate, since that id is what labels the POM's marker.
    #[tokio::test]
    async fn persist_support_pom_records_idless_repository() {
        let store_tmp = tempfile::tempdir().unwrap();
        let backend = test_backend_with_store(test_config(), store_tmp.path());
        let coord = support_pom_coord();

        backend
            .persist_support_pom(&coord, None, b"<project/>")
            .await
            .expect("persist");
        assert_eq!(
            backend.support_pom_provenance_snapshot(),
            vec![(
                "com.example:theparent:2.0".to_string(),
                provenance("", b"<project/>")
            )],
            "an id-less repository's support POM must still carry its coordinate"
        );

        backend
            .persist_support_pom(&coord, Some("corp"), b"<project/>")
            .await
            .expect("persist");
        assert_eq!(
            backend.support_pom_provenance_snapshot(),
            vec![(
                "com.example:theparent:2.0".to_string(),
                provenance("corp", b"<project/>")
            )],
            "a known id must replace the id-less placeholder"
        );

        backend
            .persist_support_pom(&coord, None, b"<project/>")
            .await
            .expect("persist");
        assert_eq!(
            backend.support_pom_provenance_snapshot(),
            vec![(
                "com.example:theparent:2.0".to_string(),
                provenance("corp", b"<project/>")
            )],
            "an id-less hit must not erase an id already recorded"
        );
    }

    /// The recorded digest must be the SHA-256 of the exact bytes persisted,
    /// so `rv export-m2` can fetch that blob from the content store by hash
    /// instead of trusting the coordinate index (which any later sync sharing
    /// the store may repoint).
    #[tokio::test]
    async fn persist_support_pom_pins_the_persisted_bytes() {
        let store_tmp = tempfile::tempdir().unwrap();
        let backend = test_backend_with_store(test_config(), store_tmp.path());
        let coord = support_pom_coord();

        backend
            .persist_support_pom(&coord, Some("corp"), b"<project>first</project>")
            .await
            .expect("persist");
        let recorded = backend.support_pom_provenance_snapshot();
        assert_eq!(
            recorded,
            vec![(
                "com.example:theparent:2.0".to_string(),
                provenance("corp", b"<project>first</project>")
            )]
        );
        let blob = BlobId::from_str(&recorded[0].1.sha256).expect("digest is a blob id");
        assert!(
            backend.ctx.store.exists_async(&blob).await,
            "the pinned digest must name a blob the store holds"
        );
    }

    /// One repository serving two different POMs for one coordinate is a
    /// conflict, not a race the first observation wins. Both byte sequences
    /// went into this resolution and the lockfile can pin only one, so keeping
    /// either silently leaves part of the resolve exported against a POM it
    /// never read — and hides the disagreement from `rv sync`'s reactor-wide
    /// check, which exists to catch exactly this across modules.
    #[tokio::test]
    async fn persist_support_pom_rejects_conflicting_bytes_from_one_repo() {
        let store_tmp = tempfile::tempdir().unwrap();
        let backend = test_backend_with_store(test_config(), store_tmp.path());
        let coord = support_pom_coord();

        backend
            .persist_support_pom(&coord, Some("corp"), b"<project>first</project>")
            .await
            .expect("persist");
        let error = backend
            .persist_support_pom(&coord, Some("corp"), b"<project>second</project>")
            .await
            .expect_err("a second observation with different bytes must not be absorbed");
        match error {
            ResolveError::ConflictingResolvedPomBytes { coord, .. } => {
                assert_eq!(coord, "com.example:theparent:2.0");
            }
            other => panic!("expected ConflictingResolvedPomBytes, got {other:?}"),
        }

        assert_eq!(
            backend.support_pom_provenance_snapshot(),
            vec![(
                "com.example:theparent:2.0".to_string(),
                provenance("corp", b"<project>first</project>")
            )],
            "the rejected observation must not have overwritten the recorded pin"
        );
    }

    /// Negative control: a repeated fetch of the SAME bytes is not a conflict,
    /// and still upgrades an id-less record to the id'd one.
    #[tokio::test]
    async fn persist_support_pom_upgrades_the_id_when_bytes_agree() {
        let store_tmp = tempfile::tempdir().unwrap();
        let backend = test_backend_with_store(test_config(), store_tmp.path());
        let coord = support_pom_coord();

        backend
            .persist_support_pom(&coord, None, b"<project>same</project>")
            .await
            .expect("persist");
        backend
            .persist_support_pom(&coord, Some("corp"), b"<project>same</project>")
            .await
            .expect("agreeing bytes must not conflict");

        assert_eq!(
            backend.support_pom_provenance_snapshot(),
            vec![(
                "com.example:theparent:2.0".to_string(),
                provenance("corp", b"<project>same</project>")
            )]
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

    /// Every runtime trust grant must reach the HTTP client's address screen.
    /// Without that, a repository the configuration never named — a root-POM
    /// one, or an approved transitive one — is refused the moment its hostname
    /// resolves onto a private network, which is how on-prem registries are
    /// deployed. What the policy *dropped* must stay screened.
    #[tokio::test]
    async fn runtime_repo_trust_reaches_the_http_client() {
        use rv_repo::RepoClient;

        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::discover().expect("paths");
        let mut config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        config
            .security
            .transitive_repository_allowlist
            .push("https://approved.internal/".to_string());
        let client = RepoClient::new(&config).await.expect("client");
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_config::Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, Some(client.clone()));

        // The driver merges the root POM's own `<repositories>` into the
        // starting list before the backend exists.
        let backend = RepoBackend::new(
            &ctx,
            vec![Repository::new(
                None,
                "https://root-pom.internal/maven2/",
                true,
                false,
            )],
            false,
        );
        assert!(
            client.trusts_host("root-pom.internal"),
            "the backend's starting repositories carry root-POM trust"
        );

        backend.extend_repos_trusted(std::iter::once(Repository::new(
            None,
            "https://parent.internal/maven2/",
            true,
            false,
        )));
        assert!(
            client.trusts_host("parent.internal"),
            "a repository trusted mid-resolve must become dialable"
        );

        backend.extend_repos(vec![
            Repository::new(None, "https://approved.internal/maven2/", true, false),
            Repository::new(None, "https://attacker.example/maven2/", true, false),
        ]);
        assert!(
            client.trusts_host("approved.internal"),
            "an allowlisted transitive repository is trusted, so it is dialable"
        );
        assert!(
            !client.trusts_host("attacker.example"),
            "a transitive repository the policy dropped must stay screened"
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
