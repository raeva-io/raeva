//! High-level public resolver API: the [`Resolver`] type and helpers
//! orchestrating dependency graph construction.

mod backend;
mod fetcher;
mod utils;

use fetcher::RepoTrust;

use std::path::{Path, PathBuf};

use futures::stream::{self, StreamExt};
use petgraph::graph::NodeIndex;
use rv_config::{Checksum, LockEdge, LockPackage, LockPlatform, Lockfile, Platform};
use rv_maven_model::{Pom, Project, Scope};
use rv_repo::{ArtifactRequest, Repository};
use rv_store::{ArtifactKey, BlobId};
use rv_version::{Coord, Version};
use tokio::fs;

use crate::ResolutionStrategy;
use crate::context::ResolveContext;
use crate::error::{ResolveError, Result};
use crate::graph::Graph;
use crate::solver::{
    ConstraintVersion, PlatformConstraint, PlatformConstraints, Solver, SolverRoot,
};

use backend::RepoBackend;
use fetcher::RepoParentResolver;
use utils::{FetchError, build_lock_data, fetch_artifact_from_repos};
pub(crate) use utils::{filter_repos_for_version, merge_repos};

/// Specifies the root of a dependency resolution.
///
/// Wraps the path to a `pom.xml` on disk. Tuple-struct form leaves room
/// for future construction helpers without breaking the call sites.
pub struct RootSpec(pub PathBuf);

/// The main dependency resolver. Resolves a dependency graph from a POM.
///
/// Supports Maven (nearest-wins) and highest-wins resolution strategies. Single-module only.
#[derive(Clone)]
pub struct Resolver {
    ctx: ResolveContext,
    strategy: ResolutionStrategy,
    strict: bool,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("strategy", &self.strategy)
            .field("strict", &self.strict)
            .field("ctx", &"<ResolveContext>")
            .finish()
    }
}

/// The output of dependency resolution: a resolved graph and lockfile data.
#[derive(Debug)]
pub struct ResolutionResult {
    pub graph: Graph,
    pub platform: Platform,
    pub packages: Vec<LockPackage>,
    pub edges: Vec<LockEdge>,
    /// Repositories that backed this resolution as `(normalized_url, id)`
    /// pairs, including POM-declared `<repositories>` discovered during the
    /// solve. `rv export-m2` can't otherwise see the observed (non-config)
    /// repositories, so persisting them lets it label `_remote.repositories`
    /// markers with the correct repository id instead of defaulting to
    /// `central`. Only repositories that carry an id are recorded.
    pub repositories: Vec<(String, String)>,
    /// Source-repository id for each support POM (parent / imported BOM) as
    /// `("g:a:v", id)`. A support POM can resolve from a different repository
    /// than its referencing child, so this preserves its provenance for
    /// `rv export-m2`'s `_remote.repositories` markers. Only support POMs
    /// served from an id'd repository are recorded.
    pub support_repo_ids: Vec<(String, String)>,
}

impl Resolver {
    /// Creates a resolver with the specified conflict resolution strategy.
    pub fn with_strategy(ctx: ResolveContext, strategy: ResolutionStrategy) -> Self {
        Self {
            ctx,
            strategy,
            strict: false,
        }
    }

    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    pub fn strategy(&self) -> ResolutionStrategy {
        self.strategy
    }

    /// Resolves the full transitive dependency graph from the given root.
    ///
    /// Fetches POM metadata from configured repositories, applies BOM imports,
    /// resolves version conflicts, and returns a lockable result.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(resolver: rv_resolver::Resolver) -> Result<(), rv_resolver::ResolveError> {
    /// use rv_resolver::RootSpec;
    /// let result = resolver.resolve(RootSpec("pom.xml".into())).await?;
    /// println!("resolved {} packages", result.packages.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn resolve(&self, root: RootSpec) -> Result<ResolutionResult> {
        let RootSpec(path) = root;
        let mut repos = self.ctx.repos.clone();

        // `load_root_project` returns any extra repos observed while resolving
        // the parent chain. Parent POMs may declare `<repositories>` that host
        // their own deps; without merging them here the solver backend below
        // never sees them and resolution fails for parent-hosted artifacts.
        let (root_coord, project, observed_repos, root_support_repo_ids) =
            self.load_root_project(&path, &repos).await?;
        if !project.repositories.is_empty() {
            let extra = project
                .repositories
                .iter()
                .cloned()
                .map(Repository::from)
                .collect::<Vec<_>>();
            repos = merge_repos(repos, extra);
        }
        if !observed_repos.is_empty() {
            repos = merge_repos(repos, observed_repos);
        }
        let root_dependency_management = project.dependency_management;
        let root_spec = SolverRoot {
            coord: root_coord,
            dependencies: project.dependencies,
            scope: Scope::Compile,
        };

        tracing::debug!(
            direct_deps = root_spec.dependencies.len(),
            strategy = ?self.strategy,
            "starting dependency resolution"
        );

        let backend = RepoBackend::new(&self.ctx, repos, self.strict);

        // Apply the root project's fully-resolved dependency management as
        // platform constraints. The `dependency_management` field is already
        // fully inlined (BOM imports resolved, parent chain merged) by
        // `Project::from_pom_with_context`.
        let mut platform_constraints: Option<PlatformConstraints> = None;
        if !root_dependency_management.dependencies.is_empty() {
            let target = platform_constraints.get_or_insert_with(PlatformConstraints::new);
            for dep in &root_dependency_management.dependencies {
                // An entry with no version can still manage scope, optional
                // or exclusions (a version-less entry carrying only
                // `<exclusions>` is the canonical global-exclude pattern).
                let version = dep.version.as_deref();
                if version.is_none()
                    && dep.scope.is_none()
                    && dep.optional.is_none()
                    && dep.exclusions.is_empty()
                {
                    continue;
                }
                // `resolve_bom_imports` inlines scope=import entries upstream,
                // so encountering one here means an upstream invariant broke.
                debug_assert!(
                    dep.effective_scope() != Scope::Import,
                    "scope=import dependency leaked past BOM inlining: {}:{}",
                    dep.group_id,
                    dep.artifact_id,
                );
                target.add_constraint(PlatformConstraint {
                    group: dep.group_id.clone(),
                    module: dep.artifact_id.clone(),
                    type_: dep.effective_type().to_string(),
                    classifier: dep.effective_classifier().map(str::to_string),
                    version: ConstraintVersion {
                        requires: version.map(str::to_string),
                        strictly: None,
                    },
                    enforced: false,
                    scope: dep.scope.clone(),
                    optional: dep.optional.clone(),
                    exclusions: dep.exclusions.clone(),
                });
            }
            tracing::debug!(
                count = root_dependency_management.dependencies.len(),
                "applied root dependency management as platform constraints"
            );
        }

        let fetch_concurrency = self
            .ctx
            .config
            .network
            .concurrency
            .clamp(1, crate::solver::MAX_FETCH_CONCURRENCY);
        let solver = Solver::with_strategy(&backend, self.strategy, platform_constraints)
            .with_fetch_concurrency(fetch_concurrency)
            .with_strict_maven_compat(true);
        let mut graph = solver.solve(root_spec).await?;

        self.populate_artifacts(&backend, &mut graph).await?;

        let (packages, edges) = build_lock_data(&graph)?;

        // Record the id'd repositories that backed this resolution (config +
        // any POM-declared ones the backend accumulated during the solve) so
        // export-m2 can label markers for repos it cannot otherwise see.
        let mut repositories: Vec<(String, String)> = backend
            .repos_snapshot()
            .iter()
            .filter_map(|repo| {
                repo.id
                    .as_deref()
                    .map(|id| (rv_repo::normalize_repo_url(&repo.url), id.to_string()))
            })
            .collect();
        repositories.sort();
        repositories.dedup();

        // Merge the solver backend's support provenance (transitive deps'
        // parents/BOMs) with the root project's own (captured in
        // load_root_project on a separate backend).
        let mut support_repo_ids = backend.support_repo_ids_snapshot();
        support_repo_ids.extend(root_support_repo_ids);
        support_repo_ids.sort();
        support_repo_ids.dedup();

        Ok(ResolutionResult {
            graph,
            platform: self.ctx.platform.clone(),
            packages,
            edges,
            repositories,
            support_repo_ids,
        })
    }

    async fn load_root_project(
        &self,
        path: &Path,
        repos: &[Repository],
    ) -> Result<(Coord, Project, Vec<Repository>, Vec<(String, String)>)> {
        let contents = fs::read_to_string(path).await?;
        let mut pom = Pom::parse(&contents).map_err(|source| ResolveError::LocalPom {
            path: path.display().to_string(),
            source,
        })?;

        // Inject .mvn/maven.config properties into the POM property map.
        // These are typically used for CI-friendly versions: -Drevision=X.Y.Z
        //
        // Maven treats `-D` entries as user properties, which sit ABOVE POM
        // <properties> in the precedence chain, so `.mvn/maven.config`
        // entries override same-named POM properties. We model that here by
        // overwriting (Option A in the bug write-up). A proper user-properties
        // layer with CLI `-D key=value` plumbing is a follow-up; this minimal
        // fix unblocks the CI-friendly-version pattern that motivated the bug.
        if let Some(project_dir) = path.parent() {
            let maven_config = crate::parent_resolver::parse_maven_config_async(project_dir).await;
            for (key, value) in maven_config {
                pom.properties.insert(key, value);
            }
        }

        let base_dir = path.parent().map(Path::to_path_buf);
        // #5: resolve profiles against the TARGET platform for this pass, so a
        // `--platforms macos-aarch64` build on a Linux host activates the
        // macOS profiles (and their deps) instead of the host's.
        let activation = crate::parent_resolver::build_activation_context_async(
            base_dir.clone(),
            &self.ctx.config,
            Some(&self.ctx.platform),
        )
        .await;

        // Pre-merge the child POM's declared repositories so they are available
        // during parent resolution. Without this, a POM whose parent only exists
        // on a repo declared in the child (e.g. Jenkins → repo.jenkins-ci.org)
        // would fail because parent resolution happens before repo merging.
        let repos_with_pom = if pom.repositories.is_empty() {
            repos.to_vec()
        } else {
            let pom_repos: Vec<Repository> = pom
                .repositories
                .iter()
                .cloned()
                .map(Repository::from)
                .collect();
            merge_repos(repos.to_vec(), pom_repos)
        };

        // The user's own POM is the trusted entrypoint: its <repositories>
        // should always be honored even under default-deny
        // `allow_transitive_repositories`, because the user wrote the file.
        // Transitive POMs reached from here still go through the gated path.
        //
        // `project_root` is set to the PARENT of `base_dir` so that the
        // standard multi-module `<relativePath>../pom.xml</relativePath>`
        // pattern (child → workspace root) passes the containment check while
        // deeper escapes (e.g. `../../etc/passwd`) are rejected.
        let project_root = base_dir
            .as_deref()
            .and_then(|d| d.parent())
            .map(|p| p.to_path_buf());
        let backend = RepoBackend::new(&self.ctx, repos_with_pom, self.strict);
        let backend_clone = backend.clone();
        // The ROOT project's own parent and imported BOMs are ALWAYS resolved
        // strictly, independent of `self.strict` (which tracks `--frozen` and
        // governs transitive leniency). The root pom.xml is the user's build
        // contract: if its parent or an imported BOM cannot be resolved, Maven
        // itself fails, so `rv` must fail too rather than silently writing a
        // lock from a model Maven cannot build. Transitive parents/BOMs stay
        // lenient by default (they go through `backend`'s `self.strict`).
        let resolver = RepoParentResolver::with_strict_and_trust(
            backend,
            base_dir.clone(),
            project_root,
            true,
            RepoTrust::Root,
        );
        let project = Project::from_pom_with_context(pom, resolver, &activation)?;

        // Snapshot the backend after parent-chain resolution. Parent POMs may
        // have declared `<repositories>` via the `observe_project_repositories`
        // callback; those are needed by the solver backend that gets built
        // after this function returns. Also capture the support-POM provenance
        // recorded while resolving the ROOT's own parent/imported BOMs: those
        // are fetched here, on this backend, not the solver backend, so without
        // returning them the root closure's export markers would lose their
        // source-repo id.
        let observed_repos = backend_clone.repos_snapshot();
        let root_support_repo_ids = backend_clone.support_repo_ids_snapshot();

        let version = Version::parse(&project.version)?;
        let coord = Coord {
            group_id: project.group_id.clone().into(),
            artifact_id: project.artifact_id.clone().into(),
            version,
            packaging: Some(project.packaging.clone()),
            classifier: None,
        };
        Ok((coord, project, observed_repos, root_support_repo_ids))
    }

    async fn populate_artifacts(&self, backend: &RepoBackend, graph: &mut Graph) -> Result<()> {
        let client = self
            .ctx
            .client
            .as_ref()
            .ok_or(ResolveError::MissingRepoClient)?;

        let backend_repos = backend.repos_snapshot();
        if backend_repos.is_empty() {
            return Err(ResolveError::NoRepositories);
        }

        // Filter to root-reachable nodes. Conflict eviction leaves orphan
        // nodes in the graph (their parent's outgoing edge was removed but
        // the node itself is preserved to keep NodeIndex values stable), and
        // walking every node would re-fetch artifacts the lockfile is going
        // to drop. Matches the reachability filter `build_lock_data` already
        // applies.
        let reachable: std::collections::HashSet<NodeIndex> = {
            let mut visited = std::collections::HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(graph.root());
            visited.insert(graph.root());
            while let Some(node) = queue.pop_front() {
                for (_, target, _) in graph.edges(node) {
                    if visited.insert(target) {
                        queue.push_back(target);
                    }
                }
            }
            visited
        };

        // First pass: identify artifacts to fetch (skip root, local, and already-cached)
        let node_count = graph.node_count().saturating_sub(1);
        let mut to_fetch: Vec<(NodeIndex, ArtifactRequest, ArtifactKey, Vec<Repository>)> =
            Vec::with_capacity(node_count);
        struct CacheCandidate {
            idx: NodeIndex,
            blob: BlobId,
            fallback_repo: Option<String>,
            artifact_req: ArtifactRequest,
            key: ArtifactKey,
            repo_candidates: Vec<Repository>,
        }

        let mut cache_candidates: Vec<CacheCandidate> = Vec::with_capacity(node_count);

        for idx in graph.node_indices() {
            if idx == graph.root() {
                continue;
            }
            if !reachable.contains(&idx) {
                continue;
            }
            let Some(node) = graph.node(idx) else {
                continue;
            };
            if node.local {
                continue;
            }
            // Skip BOM dependencies with pom packaging - they have no downloadable artifact
            if node.coord.packaging.as_deref() == Some("pom") {
                continue;
            }

            let artifact_req = ArtifactRequest::from_coord(&node.coord);
            let mut repo_candidates =
                filter_repos_for_version(&backend_repos, &artifact_req.version, &node.coord)?
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>();
            if let Some(repo_url) = node.repo_url.as_deref()
                && let Some(pos) = repo_candidates.iter().position(|repo| repo.url == repo_url)
            {
                let preferred = repo_candidates.remove(pos);
                repo_candidates.insert(0, preferred);
            }

            let key = ArtifactKey::new(
                artifact_req.group_id.as_str(),
                artifact_req.artifact_id.as_str(),
                artifact_req.version.as_str(),
                artifact_req.packaging.as_str(),
                artifact_req.classifier.clone(),
            );

            // Check cache first - verify content before trusting the hit.
            if let Some(blob) = self.ctx.store.lookup_artifact(&key).await? {
                let fallback_repo = if node.repo_url.is_none() {
                    repo_candidates.first().map(|repo| repo.url.clone())
                } else {
                    None
                };
                cache_candidates.push(CacheCandidate {
                    idx,
                    blob,
                    fallback_repo,
                    artifact_req,
                    key,
                    repo_candidates,
                });
                continue;
            }

            to_fetch.push((idx, artifact_req, key, repo_candidates));
        }

        if !cache_candidates.is_empty() {
            // Verify every cache hit: sampling would let corrupted blobs flow
            // downstream.
            let all_ids: Vec<BlobId> = cache_candidates.iter().map(|c| c.blob.clone()).collect();
            // Honor user-configured `network.concurrency` so a Raspberry Pi
            // runner with `concurrency = 1` doesn't get 32 hashers spun up
            // behind its back; clamp into the store's reasonable upper bound.
            let parallelism = self.ctx.config.network.concurrency.clamp(
                1,
                rv_store::Store::default_verification_parallelism().max(1),
            );
            let verified_set = self.ctx.store.verify_blobs(&all_ids, parallelism).await?;

            let invalid_count = all_ids.len() - verified_set.len();
            if invalid_count > 0 {
                tracing::warn!(
                    invalid = invalid_count,
                    total = all_ids.len(),
                    "cache corruption detected; refetching invalid blobs"
                );
            }

            for candidate in cache_candidates {
                if !verified_set.contains(&candidate.blob) {
                    tracing::warn!(blob = %candidate.blob, "invalid cached artifact, refetching");
                    to_fetch.push((
                        candidate.idx,
                        candidate.artifact_req,
                        candidate.key,
                        candidate.repo_candidates,
                    ));
                    continue;
                }

                if let Some(node) = graph.node_mut(candidate.idx) {
                    let checksum = Checksum::new("sha256", candidate.blob.as_str());
                    node.checksum = Some(checksum);
                    if node.repo_url.is_none() {
                        node.repo_url = candidate.fallback_repo.map(|s| s.into());
                    }
                }
            }
        }

        if to_fetch.is_empty() {
            return Ok(());
        }

        // Parallel fetch with bounded concurrency (clamped to safe max)
        let concurrency = self
            .ctx
            .config
            .network
            .concurrency
            .clamp(1, crate::solver::MAX_FETCH_CONCURRENCY);
        let store = self.ctx.store.clone();
        let client = client.clone();

        let results: Vec<_> = stream::iter(to_fetch)
            .map(|(idx, artifact_req, key, repo_candidates)| {
                let client = client.clone();
                let store = store.clone();
                async move {
                    let result = fetch_artifact_from_repos(
                        &client,
                        &store,
                        &artifact_req,
                        &key,
                        &repo_candidates,
                    )
                    .await;
                    (idx, artifact_req, result)
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        // Process results and collect errors
        let mut errors: Vec<ResolveError> = Vec::with_capacity(results.len());
        for (idx, artifact_req, result) in results {
            match result {
                Ok((blob, repo_url)) => {
                    if let Some(node) = graph.node_mut(idx) {
                        let checksum = Checksum::new("sha256", blob.as_str());
                        node.checksum = Some(checksum);
                        node.repo_url = Some(repo_url.into());
                    }
                }
                Err(FetchError::NotFound { searched }) => {
                    let coord = graph
                        .node(idx)
                        .map(|node| node.coord.to_string())
                        .unwrap_or_else(|| {
                            format!("{}:{}", artifact_req.group_id, artifact_req.artifact_id)
                        });
                    errors.push(ResolveError::ArtifactNotFound { coord, searched });
                }
                Err(FetchError::Transient { err, searched }) => {
                    errors.push(ResolveError::RepoWithContext {
                        source: err,
                        searched,
                    });
                }
                Err(FetchError::Fatal { err, searched }) => {
                    errors.push(ResolveError::RepoWithContext {
                        source: err,
                        searched,
                    });
                }
            }
        }

        // Report errors - aggregate multiple errors if present
        let mut errors_iter = errors.into_iter();
        if let Some(first) = errors_iter.next() {
            let rest: Vec<_> = errors_iter.collect();
            if rest.is_empty() {
                return Err(first);
            }
            return Err(ResolveError::MultipleArtifactErrors {
                first: Box::new(first),
                rest,
            });
        }

        Ok(())
    }
}

impl ResolutionResult {
    pub fn to_lockfile(&self) -> Lockfile {
        let platform = LockPlatform {
            platform: self.platform.clone(),
            packages: self.packages.clone(),
            edges: self.edges.clone(),
            extra: std::collections::BTreeMap::new(),
        };
        let mut lock = Lockfile::new();
        lock.platforms.push(platform);
        lock
    }
}

#[cfg(test)]
mod tests;
