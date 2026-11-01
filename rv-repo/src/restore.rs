//! Restore what a lockfile pins into the store: artifacts, their companion
//! POMs, and the support POMs export needs.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use futures::stream::{self, StreamExt};
use rv_config::Config;
use rv_lock::{LockArtifact, LockOrigins, Lockfile, OriginSelection, Platform, SupportPom};
use rv_maven_model::held::{Held, Holds};
use rv_maven_types::{ArtifactCoord, BlobId, Digest, Gav, resolves_through_snapshot_metadata};

use rv_store::{Expect, PinCheck, PutError, QueuedCheck, Store, StoredFor};
use tokio::sync::OnceCell;

use crate::artifact::ArtifactRequest;
use crate::client::{FetchArtifact, RepoClient};
use crate::error::{IntegritySource, RepoError, Result};
use crate::repository::{Repository, normalize_repo_url};

/// Per-sync-call dedup map: collapses concurrent restores of the same Maven
/// coordinate (group, artifact, version, packaging, classifier) onto one
/// search. The `seen` set in `ensure_artifacts` dedupes only the top-level
/// lockfile entries; this map also collapses the companion POM that two
/// rows sharing a POM coordinate both restore.
///
/// The inner Mutex is `std::sync::Mutex` because the only critical section is
/// the `entry().or_insert_with()` bookkeeping; no `.await` is held across it.
/// `OnceCell::get_or_try_init` provides the actual cross-task rendezvous and
/// is the only place an `.await` happens with respect to a cell.
type FetchDedupMap = Arc<Mutex<HashMap<ArtifactCoord, Arc<OnceCell<()>>>>>;

/// Companion-POM pins carried by the lockfile's artifact rows, keyed by the
/// GAV with the file version: one `.pom` per GAV, shared by every packaging
/// and classifier of that coordinate.
type PomPins = HashMap<Gav, BlobId>;

/// Each file a lockfile pins, with the origins its rows on every platform
/// record for it, as [`pinned_files`] lists them.
type FileOrigins<'a> = BTreeMap<(ArtifactCoord, Digest), BTreeSet<&'a str>>;

/// The outcome of restoring one lockfile artifact row, with its companion POM,
/// or one support POM.
#[derive(Debug)]
#[non_exhaustive]
pub struct DownloadResult {
    /// The coordinate restored, in [`ArtifactCoord`]'s string form.
    pub package: String,
    /// `Ok` when the files are in the store, indexed and matching their pins.
    pub result: Result<()>,
}

/// A platform selection and the configuration, client and declarations that
/// authorize its downloads. Clients must be constructed from their own config.
pub struct RestoreContext<'a> {
    /// Configuration active for these platforms.
    pub config: &'a Config,
    /// Client with this configuration's transport and credential grants.
    pub client: &'a RepoClient,
    /// Platforms to restore through this context.
    pub platforms: &'a [Platform],
    /// Additional repositories admitted by this context's resolution or model.
    pub trusted_repositories: &'a [Repository],
}

/// Restore the artifact rows, their companion POMs and the support POMs of
/// each context's platforms, each through the contexts whose platforms
/// record it. Stored files and downloads are verified against the lock's
/// pins.
///
/// A file is asked for from the repository the lock records first. When
/// that repository is not declared now or does not have the file, the
/// other repositories the context may reach are asked in turn, as Maven
/// searches them; a SHA-256 pin decides which bytes are acceptable. A
/// repository that serves other bytes ends the search.
///
/// # Errors
///
/// [`RepoError::NotFound`] when a context selects an unrecorded platform,
/// and [`RepoError::Store`] when the store index cannot be read or written.
/// Individual download failures are reported in [`DownloadResult`].
pub async fn ensure_artifacts(
    store: &Store,
    lock: &Lockfile,
    contexts: &[RestoreContext<'_>],
) -> Result<Vec<DownloadResult>> {
    let recreated = rv_store::recreated_mid_run();
    let results = restore_pass(store, lock, contexts).await?;
    if rv_store::recreated_mid_run() == recreated {
        return Ok(results);
    }
    // A damaged index or metadata cache was recreated during the pass,
    // without the rows of the files restored and the POMs seeded before,
    // which the next command reads.
    restore_pass(store, lock, contexts).await
}

async fn restore_pass(
    store: &Store,
    lock: &Lockfile,
    contexts: &[RestoreContext<'_>],
) -> Result<Vec<DownloadResult>> {
    let pom_pins: PomPins = (lock.platforms.iter())
        .flat_map(|platform| &platform.artifacts)
        .filter_map(|artifact| Some((artifact.pom_gav(), artifact.pom_sha256.clone()?)))
        .collect();
    let file_origins = pinned_files(&lock.platforms, |_| true);
    let clients: Vec<_> = contexts
        .iter()
        .map(|context| context.client.clone().with_lock_pins(lock))
        .collect();
    let inputs: Vec<_> = contexts
        .iter()
        .zip(&clients)
        .map(|(context, client)| SyncInputs {
            config: context.config,
            store,
            client,
            selector: LockRepositorySelector::new(
                context.config,
                &LockOrigins::for_root(&context.config.project_root),
                context.trusted_repositories,
            ),
            trusted_repositories: context.trusted_repositories,
            pom_pins: &pom_pins,
            file_origins: &file_origins,
            routes: OnceLock::new(),
        })
        .collect();
    let mut packages = Vec::new();
    let mut support: BTreeMap<&str, Vec<(&SyncInputs<'_>, &SupportPom)>> = BTreeMap::new();
    for (context, input) in contexts.iter().zip(&inputs) {
        let mut seen = HashSet::new();
        for platform in context.platforms {
            let entry = lock
                .platforms
                .iter()
                .find(|entry| &entry.platform == platform)
                .ok_or_else(|| {
                    RepoError::NotFound(format!("platform '{platform}' not found in lockfile"))
                })?;
            packages.extend(
                entry
                    .artifacts
                    .iter()
                    .filter(|artifact| {
                        seen.insert((
                            artifact.coord(),
                            artifact.repo_url.as_str(),
                            &artifact.other_repo_urls,
                            &artifact.pom_repo_urls,
                        ))
                    })
                    .map(|artifact| (artifact, input)),
            );
            for (coord, pin) in &entry.support_poms {
                let owners = support.entry(coord.as_str()).or_default();
                if !owners.iter().any(|(owner, _)| std::ptr::eq(*owner, input)) {
                    owners.push((input, pin));
                }
            }
        }
    }
    let concurrency = contexts
        .first()
        .map_or(1, |context| context.config.network.fetch_concurrency());
    let dedup = FetchDedupMap::default();
    let checks = &Checks::default();
    // A file may be stored already from another repository, by another
    // context, another project or a fallback fetch; each context indexes it
    // under the repository it records, for its offline resolution.
    // A version selects a repository only by its releases or snapshots
    // policy, so one route serves every version of a kind.
    let routes = package_routes(&packages);
    // Holding logs costs a pass over every callsite, so a run that
    // downloads nothing holds none.
    let holds = &OnceLock::new();
    // How many restores each pinned blob serves: packages' artifacts and
    // POMs, and support POMs. A file is adopted by its blob, so one that
    // serves two waits for the first, as in a plain order.
    let mut uses: HashMap<&BlobId, usize> = HashMap::new();
    let package_blobs = (packages.iter()).flat_map(|&(pkg, _)| {
        [
            pkg.pin().and_then(Digest::as_sha256),
            pom_pins.get(&pkg.pom_gav()),
        ]
    });
    for blob in (package_blobs.flatten()).chain(support.values().map(|owners| &owners[0].1.sha256))
    {
        *uses.entry(blob).or_default() += 1;
    }
    // A package pinned only by SHA-1 may restore any blob.
    let unknown_blob =
        (packages.iter()).any(|(pkg, _)| pkg.pin().and_then(Digest::as_sha256).is_none());
    let packages_done = in_order(&packages, concurrency, |&(pkg, input)| {
        let dedup = &dedup;
        // A POM that serves another restore too waits for its artifact: when
        // the artifact fails, that other restore restores and logs it in its
        // own place. A `pom` package's artifact is its POM, and a SNAPSHOT
        // artifact may pick its build by whether its POM is cached.
        let alongside = !unknown_blob
            && pom_pins
                .get(&pkg.pom_gav())
                .is_some_and(|blob| uses[blob] == 1)
            && pkg.coord() != ArtifactCoord::of(pkg.pom_gav(), "pom", None)
            && !resolves_through_snapshot_metadata(pkg.coord().version());
        async move {
            let asked = AtomicBool::new(false);
            let result = ensure_package_artifacts(
                input,
                pkg,
                dedup,
                checks,
                alongside.then_some(holds),
                Some(&asked),
            )
            .await;
            let package = pkg.coord().to_string();
            (DownloadResult { package, result }, asked.into_inner())
        }
    });
    // Once any work holds its logs, the support POMs that follow it do.
    let restore_support = |entries| {
        in_order(
            entries,
            concurrency,
            |(index, (coord, owners)): (usize, (&str, Vec<_>))| async move {
                let restored = restore_support_entry(store, checks, coord, &owners);
                match holds.get() {
                    Some(holds) => (index, holds.hold(restored).await),
                    None => (index, (restored.await, Held::default())),
                }
            },
        )
    };
    // Support POMs the store lacks download alongside the packages and log
    // after them, in order. One whose bytes a package may restore waits for
    // the packages, as its owners need not serve it, and so does a SNAPSHOT
    // one, which a SNAPSHOT package's build may depend on.
    let entries: Vec<_> = (support.iter())
        .map(|(coord, owners)| (*coord, owners.clone()))
        .collect();
    let support_now = async {
        // One blocking task: a task per file costs more than its stat.
        let paths: Vec<_> = (support.values())
            .map(|owners| store.get_path(&owners[0].1.sha256))
            .collect();
        let stored = tokio::task::spawn_blocking(move || {
            (paths.iter())
                .map(|path| std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()))
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default();
        let (later, now): (Vec<_>, Vec<_>) =
            (support.into_iter().enumerate()).partition(|(index, (coord, owners))| {
                unknown_blob
                    || stored.get(*index) == Some(&true)
                    || uses[&owners[0].1.sha256] > 1
                    || (coord.rsplit(':').next()).is_some_and(resolves_through_snapshot_metadata)
            });
        if !now.is_empty() {
            holds.get_or_init(Holds::default);
        }
        (later, restore_support(now).await)
    };
    let (done, (later, mut support)) = futures::join!(packages_done, support_now);
    let (mut results, asked): (Vec<_>, Vec<_>) = done.into_iter().unzip();
    support.extend(restore_support(later).await);
    // Another context, or a support POM restored after the rows, may have
    // stored the files after this row's own search for them failed; then
    // they serve this row too, with no request. A row whose file is stored
    // but whose POM is not asks for the POM once, if its search did not
    // because the file failed first. A POM it stores may be another row's
    // file or POM, so the rows are checked until none recovers.
    let mut asked: HashSet<usize> = (asked.into_iter().enumerate())
        .filter_map(|(index, asked)| asked.then_some(index))
        .collect();
    loop {
        let mut recovered = false;
        for fetch_pom in [false, true] {
            for (index, (result, &(pkg, input))) in results.iter_mut().zip(&packages).enumerate() {
                let Some(pin) = pkg.pin().filter(|_| result.result.is_err()) else {
                    continue;
                };
                let owners: Vec<_> = pkg.file_origins().map(|origin| (input, origin)).collect();
                if !stored_intact(store, &owners, &pkg.coord(), pin).await? {
                    continue;
                }
                let pom_stored = match pom_pins.get(&pkg.pom_gav()) {
                    Some(blob) => {
                        let key = ArtifactCoord::of(pkg.pom_gav(), "pom", None);
                        let owners: Vec<_> =
                            pkg.pom_origins().map(|origin| (input, origin)).collect();
                        stored_intact(store, &owners, &key, &Digest::Sha256(blob.clone())).await?
                    }
                    None => true,
                };
                if pom_stored == fetch_pom || (fetch_pom && !asked.insert(index)) {
                    continue;
                }
                result.result =
                    ensure_package_artifacts(input, pkg, &dedup, checks, None, None).await;
                recovered |= result.result.is_ok();
            }
        }
        if !recovered {
            break;
        }
    }
    // So may a support POM that names the same file another way, as a
    // `-SNAPSHOT` version with its build and that build's timestamped
    // version do: the lock keeps them apart, so each restores on its own.
    for (index, (result, _)) in &mut support {
        let (coord, owners) = &entries[*index];
        let pin = Digest::Sha256(owners[0].1.sha256.clone());
        let origins: Vec<_> = (owners.iter())
            .map(|(input, line)| (*input, line.repo_url.as_str()))
            .collect();
        if result.result.is_err()
            && let Some(key) = support_pom_key(coord, owners[0].1)
            && stored_intact(store, &origins, &key, &pin).await?
        {
            *result = restore_support_entry(store, checks, coord, owners).await;
        }
    }
    support.sort_unstable_by_key(|(index, _)| *index);
    let support: Vec<_> = (support.into_iter())
        .map(|(_, (result, held))| {
            held.show();
            result
        })
        .collect();
    // The rows below name the files the checks found intact.
    record_checks(store, checks).await?;
    let mut indices = Vec::new();
    let mut rows = Vec::new();
    for (index, &(pkg, input)) in packages.iter().enumerate() {
        if results[index].result.is_ok() {
            index_files(pkg, input, &routes, &mut rows);
            indices.resize(rows.len(), index);
        }
    }
    for (index, outcome) in indices
        .into_iter()
        .zip(index_for_platforms(store, &rows).await?)
    {
        if results[index].result.is_ok() {
            results[index].result = outcome;
        }
    }
    results.extend(support);
    Ok(results)
}

/// [`restore_support_pom`] for the support POM `coord`, which `owners` record.
async fn restore_support_entry(
    store: &Store,
    checks: &Checks,
    coord: &str,
    owners: &[(&SyncInputs<'_>, &SupportPom)],
) -> DownloadResult {
    let (package, result) = match support_pom_key(coord, owners[0].1) {
        Some(key) => {
            let result = restore_support_pom(store, checks, owners, &key).await;
            (key.to_string(), result)
        }
        None => (
            coord.to_string(),
            Err(RepoError::InvalidCoord(coord.to_string())),
        ),
    };
    DownloadResult { package, result }
}

/// The stored files a run found intact after hashing them, as after a cache
/// restore. They are synced in one batch before a row names them or the run
/// ends, and only then is their checked stamp recorded.
type Checks = Mutex<Vec<QueuedCheck>>;

async fn record_checks(store: &Store, checks: &Checks) -> Result<()> {
    let checks = std::mem::take(&mut *checks.lock().unwrap_or_else(PoisonError::into_inner));
    Ok(store.record_checks_async(checks).await?)
}

/// `task` for every item, `concurrency` at a time, with the results in
/// input order: the caller reports the first failure and lists the others,
/// so completion order would make both differ between runs.
async fn in_order<T, R, F: std::future::Future<Output = R>>(
    items: impl IntoIterator<Item = T>,
    concurrency: usize,
    task: impl Fn(T) -> F,
) -> Vec<R> {
    let mut results: Vec<(usize, R)> = stream::iter(items.into_iter().enumerate())
        .map(|(index, item)| {
            let result = task(item);
            async move { (index, result.await) }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

/// The `pom` key of the file a support POM pins: a SNAPSHOT parent's
/// timestamped build when the lock records one. `None` for a coordinate
/// that is not `group:artifact:version`, which the strict decoder refuses.
fn support_pom_key(coord: &str, pin: &SupportPom) -> Option<ArtifactCoord> {
    Some(ArtifactCoord::of(pin.file_gav(coord)?, "pom", None))
}

/// [`ensure_artifacts`] for the one support POM `coord` that `pin` pins,
/// through every context in `contexts`.
///
/// # Errors
///
/// [`RepoError::ChecksumMismatch`] when the repositories serve other bytes
/// than the pin; the store is then unchanged.
pub async fn ensure_support_pom(
    store: &Store,
    contexts: &[RestoreContext<'_>],
    coord: &str,
    pin: &SupportPom,
) -> Result<()> {
    let (pom_pins, file_origins) = (PomPins::new(), FileOrigins::new());
    let inputs: Vec<_> = (contexts.iter())
        .map(|context| SyncInputs::of(store, context, &pom_pins, &file_origins))
        .collect();
    let owners: Vec<_> = inputs.iter().map(|input| (input, pin)).collect();
    let key = support_pom_key(coord, pin).ok_or_else(|| RepoError::InvalidCoord(coord.into()))?;
    let checks = Checks::default();
    restore_support_pom(store, &checks, &owners, &key).await?;
    record_checks(store, &checks).await
}

/// Restore the file at `key` that raeva.lock pins to `pin` and records as
/// served by `repo_urls`, through `context`, as [`ensure_artifacts`] restores
/// an artifact row or its companion POM.
///
/// # Errors
///
/// [`RepoError::ChecksumMismatch`] when a repository serves other bytes,
/// [`RepoError::UntrustedRepoUrl`] when
/// the first origin is not declared now and no other repository has the file,
/// and the errors of the last request otherwise.
pub async fn restore_pinned<'a>(
    store: &Store,
    context: &RestoreContext<'_>,
    repo_urls: impl IntoIterator<Item = &'a str>,
    key: &ArtifactCoord,
    pin: &Digest,
) -> Result<()> {
    let (pom_pins, file_origins) = (PomPins::new(), FileOrigins::new());
    let input = SyncInputs::of(store, context, &pom_pins, &file_origins);
    let owners: Vec<_> = repo_urls.into_iter().map(|url| (&input, url)).collect();
    fetch_pinned(&owners, key, pin).await
}

/// Index `artifact`, a row of `lock`, under the repository it records in
/// `context`, when the store holds its pinned bytes, as [`ensure_artifacts`]
/// does for a row another platform restored. The only request is for a POM
/// that repository did not serve, so its own copy is cached.
///
/// # Errors
///
/// [`RepoError::Store`] when the store index cannot be written.
pub async fn index_restored(
    store: &Store,
    lock: &Lockfile,
    context: &RestoreContext<'_>,
    artifact: &LockArtifact,
) -> Result<()> {
    let (pom_pins, file_origins) = (PomPins::new(), pinned_files(&lock.platforms, |_| true));
    let input = SyncInputs::of(store, context, &pom_pins, &file_origins);
    let key = artifact.coord();
    let Some(pin) = artifact.pin() else {
        return Ok(());
    };
    let owners: Vec<_> = (artifact.file_origins())
        .map(|origin| (&input, origin))
        .collect();
    if !stored_intact(store, &owners, &key, pin).await? {
        return Ok(());
    }
    let routes = package_routes(&[(artifact, &input)]);
    let mut files = Vec::new();
    index_files(artifact, &input, &routes, &mut files);
    if let Some(pom) = &artifact.pom_sha256 {
        let pom_key = ArtifactCoord::of(artifact.pom_gav(), "pom", None);
        let owners: Vec<_> = (artifact.pom_origins())
            .map(|origin| (&input, origin))
            .collect();
        if !stored_intact(store, &owners, &pom_key, &Digest::Sha256(pom.clone())).await? {
            files.retain(|file| file.key != pom_key);
        }
    }
    for outcome in index_for_platforms(store, &files).await? {
        outcome?;
    }
    Ok(())
}

async fn restore_support_pom(
    store: &Store,
    checks: &Checks,
    owners: &[(&SyncInputs<'_>, &SupportPom)],
    key: &ArtifactCoord,
) -> Result<()> {
    let coord = key.to_string();
    let blob = &owners[0].1.sha256;
    let pin = Digest::Sha256(blob.clone());
    let owners: Vec<_> = owners
        .iter()
        .map(|(input, line)| (*input, line.repo_url.as_str()))
        .collect();
    if needs_download(store, checks, &owners, key, &pin, &coord).await? {
        match fetch_pinned(&owners, key, &pin).await {
            Err(RepoError::UntrustedRepoUrl(_)) => {
                return Err(RepoError::NotFound(format!(
                    "{coord}, which raeva.lock records as served by a repository no configuration or \
                     POM declares now and no configured repository has, so add that repository to \
                     raeva.toml"
                )));
            }
            result => result?,
        }
    }
    // Platforms can record one parent under different repositories; each
    // one's offline resolution reads it from its own.
    let request = ArtifactRequest::from(key);
    for (input, repo_url) in owners {
        if let OriginSelection::Declared(repo) =
            input.selector.select(repo_url, Some(key.version()))
        {
            let client = input.client;
            if client
                .unseeded_poms(&[(&repo, request.clone(), blob)])
                .await?[0]
            {
                let endpoint = client.effective_repository(&repo).url;
                cache_route_pom(store, client, (&repo, &endpoint), key, &request, blob).await?;
            }
        }
    }
    Ok(())
}

/// Cache the POM at `key` that raeva.lock pins to `blob` for an offline
/// resolution through `route`, a repository and the endpoint serving it.
/// The stored copy is cached when that route served it: the resolution
/// reads a cached copy as the route's answer and records it as served
/// there, so another repository's copy is not. That repository is asked
/// for its own instead, unless a mirror of it served the stored one.
async fn cache_route_pom(
    store: &Store,
    client: &RepoClient,
    (repo, endpoint): (&Repository, &str),
    key: &ArtifactCoord,
    request: &ArtifactRequest,
    blob: &BlobId,
) -> Result<()> {
    let served_by = store.served_by(key, blob).await?;
    let normalized = |url: &str| normalize_repo_url(url);
    let route = (normalized(&repo.url), normalized(endpoint));
    let served = |(repo, endpoint): &(String, String)| (normalized(repo), normalized(endpoint));
    if served_by.iter().any(|row| served(row) == route) {
        return (client.seed_pinned_pom(repo, request, blob, &store.get_path(blob))).await;
    }
    if served_by.iter().any(|row| served(row).0 == route.0) {
        return Ok(());
    }
    if let Ok((bytes, _)) = client.fetch_pom_with_path(repo, request).await
        && BlobId::from_bytes(&bytes) == *blob
    {
        let served = (
            key.clone(),
            blob.clone(),
            repo.url.clone(),
            endpoint.to_string(),
        );
        store.record_served(vec![served]).await?;
    }
    Ok(())
}

/// Where to ask for one pinned file: the repository the lock records, then
/// every other repository the context may reach, once per id and URL, as Maven
/// searches them. The pin decides which bytes are acceptable, and
/// configuration decides where raeva may ask. Only a SHA-256 pin is trusted
/// to pick the bytes from another repository, and only past repositories
/// that lack the file: [`fetch_pinned`] stops at one that serves other bytes. A recorded origin no
/// declaration names gives no candidates: the lockfile is not a trust root,
/// and a resolution establishes which repositories its model authorizes.
fn pinned_candidates(
    input: &SyncInputs<'_>,
    repo_url: &str,
    version: &str,
    pin: &Digest,
) -> Result<Vec<Repository>> {
    let recorded = match input.selector.select(repo_url, Some(version)) {
        OriginSelection::Declared(repo) => repo,
        OriginSelection::Ambiguous => {
            return Err(RepoError::AmbiguousRepoOrigin(rv_lock::redact_origin(
                repo_url,
            )));
        }
        OriginSelection::Undeclared => return Ok(Vec::new()),
    };
    let mut candidates = vec![recorded];
    if pin.as_sha256().is_some() {
        // A repository that disables the version's kind is no fallback: its
        // refusal would stand in for what the recorded one answered.
        let recorded_url = normalize_repo_url(&candidates[0].url);
        candidates.extend(unique_repositories(
            input.config,
            input.trusted_repositories,
            |repo| normalize_repo_url(&repo.url) != recorded_url && repo.allows_version(version),
        ));
    }
    Ok(candidates)
}

/// Fetch the file at `key`, pinned to `pin`, through each `(input,
/// recorded origin)` in turn, as [`pinned_candidates`] lists the
/// repositories to ask. A POM goes through the client's POM read, so the
/// metadata cache holds it for an offline resolution later.
async fn fetch_pinned(
    owners: &[(&SyncInputs<'_>, &str)],
    key: &ArtifactCoord,
    pin: &Digest,
) -> Result<()> {
    let request = ArtifactRequest::from(key);
    let mut search = PinnedSearch::default();
    let mut declared = false;
    for (input, repo_url) in owners {
        let candidates = pinned_candidates(input, repo_url, key.version(), pin)?;
        declared |= !candidates.is_empty();
        for (index, repo) in candidates.iter().enumerate() {
            match fetch_from(input, repo, &request, key, pin).await {
                Ok(path) => {
                    let endpoint = input.client.effective_repository(repo);
                    search.fallback.served(&endpoint, &request, path);
                    return Ok(());
                }
                // Other bytes end the search too, as do bytes that fail or
                // lack their checksum file: a later repository that matches
                // the pin would let an edited pin choose its source.
                Err(err @ (RepoError::ChecksumMismatch { .. } | RepoError::MissingChecksum(_))) => {
                    return Err(err);
                }
                Err(err) if err.is_transient() || matches!(err.status_code(), Some(500..=599)) => {
                    return Err(err);
                }
                Err(err) => search.failed(input.client, repo, index == 0, err),
            }
        }
    }
    let undeclared = owners
        .first()
        .filter(|_| !declared)
        .map(|(_, repo_url)| RepoError::UntrustedRepoUrl(rv_lock::redact_origin(repo_url)));
    Err(search.finish(undeclared, key))
}

/// One request of [`fetch_pinned`], returning the path read.
async fn fetch_from(
    input: &SyncInputs<'_>,
    repo: &Repository,
    request: &ArtifactRequest,
    key: &ArtifactCoord,
    pin: &Digest,
) -> Result<String> {
    let fetch_pinned_artifact = || async {
        let options = FetchArtifact {
            pin: Some(pin),
            index: Some(key),
        };
        let fetched = (input.client)
            .fetch_artifact(repo, request, input.store, options)
            .await?;
        Ok(fetched.path)
    };
    let Some(expected) = pin.as_sha256().filter(|_| is_pom(key)) else {
        return fetch_pinned_artifact().await;
    };
    let (bytes, path) = match input.client.fetch_pom_with_path(repo, request).await {
        Ok(fetched) => fetched,
        // Bytes other than the pinned ones lose the pin's exemption from
        // the checksum file, whose failure would hide them; the pin check
        // reports what is wrong. A repository that fails the second request
        // otherwise keeps the first error, so a 404 cannot pass the search on.
        Err(err) if !matches!(err, RepoError::NotFound(_)) && !err.is_transient() => {
            return match fetch_pinned_artifact().await {
                Err(retry @ RepoError::ChecksumMismatch { .. }) => Err(retry),
                Err(_) => Err(err),
                fetched => fetched,
            };
        }
        Err(err) => return Err(err),
    };
    // Fetched bytes are checked against the pin before anything is stored,
    // so a repository that serves other bytes indexes nothing.
    let actual = BlobId::from_bytes(&bytes);
    if actual != *expected {
        return Err(RepoError::ChecksumMismatch {
            subject: key.to_string().into(),
            artifact: Some(Box::new(key.clone())),
            expected: pin.clone(),
            actual: Digest::Sha256(actual),
            check: IntegritySource::LockPin,
        });
    }
    let expect = Expect {
        sidecar: None,
        pin: Some(pin),
    };
    let stored = (input.store)
        .put_stream_verified(
            stream::once(async move { Ok::<_, std::io::Error>(bytes) }),
            expect,
            Some(key),
        )
        .await;
    match stored {
        Ok(_) => {
            let endpoint = input.client.effective_repository(repo).url;
            let served = (key.clone(), actual, repo.url.clone(), endpoint);
            input.store.record_served(vec![served]).await?;
            Ok(path)
        }
        Err(PutError::Store(err)) => Err(RepoError::Store(err)),
        Err(PutError::Stream(err)) => Err(RepoError::Io(err)),
        Err(PutError::Mismatch { .. }) => unreachable!("hashed above"),
    }
}

fn is_pom(key: &ArtifactCoord) -> bool {
    key.extension() == "pom" && key.classifier().is_none()
}

#[derive(Default)]
struct PinnedSearch {
    recorded: Option<RepoError>,
    failure: Option<RepoError>,
    refusal: Option<RepoError>,
    fallback: crate::AuthFallback,
}

impl PinnedSearch {
    fn failed(&mut self, client: &RepoClient, repo: &Repository, recorded: bool, err: RepoError) {
        self.fallback
            .refused(&client.effective_repository(repo), &err);
        self.keep(recorded, err);
    }

    fn keep(&mut self, recorded: bool, err: RepoError) {
        let miss = |err: &RepoError| matches!(err, RepoError::NotFound(_));
        if recorded {
            // One recorded origin's miss gives way to another's refusal.
            if self
                .recorded
                .as_ref()
                .is_none_or(|kept| miss(kept) && !miss(&err))
            {
                self.recorded = Some(err);
            }
        } else if matches!(err.status_code(), Some(401 | 403)) {
            self.refusal = Some(err);
        } else if !miss(&err) || self.failure.is_none() {
            self.failure = Some(err);
        }
    }

    /// What the recorded origin answered is reported first, then a failure
    /// that is neither a miss nor a refusal, then the recorded origin being
    /// undeclared, then the refusal or the miss.
    fn finish(self, undeclared: Option<RepoError>, key: &ArtifactCoord) -> RepoError {
        if let Some(error) = self.recorded {
            return error;
        }
        match self.failure {
            Some(failure) if !matches!(failure, RepoError::NotFound(_)) => failure,
            failure => undeclared
                .or(self.refusal)
                .or(failure)
                .unwrap_or_else(|| RepoError::NotFound(key.to_string())),
        }
    }
}

/// Configured, then trusted, repositories that `keep` accepts, one per id
/// and URL.
fn unique_repositories(
    config: &Config,
    trusted_repositories: &[Repository],
    keep: impl Fn(&Repository) -> bool,
) -> Vec<Repository> {
    let mut seen = HashSet::new();
    (config.repositories().iter().map(Repository::from))
        .chain(trusted_repositories.iter().cloned())
        .filter(|repo| {
            keep(repo)
                && !crate::policy::http_repository_blocked(config, repo, true)
                && seen.insert((normalize_repo_url(&repo.url), repo.id.clone()))
        })
        .collect()
}

/// Whether restoring the contexts' platforms needs repositories that only a
/// resolution trusts: a pinned file the content store lacks, or holds
/// corrupt, whose recorded origin no configuration or declaration of its
/// context names, typically one a dependency's POM declares.
///
/// # Errors
///
/// [`RepoError::Store`] when the store index cannot be read.
pub async fn restore_needs_discovery(
    store: &Store,
    lock: &Lockfile,
    contexts: &[RestoreContext<'_>],
) -> Result<bool> {
    for context in contexts {
        let origins = LockOrigins::for_root(&context.config.project_root);
        let selector =
            LockRepositorySelector::new(context.config, &origins, context.trusted_repositories);
        let undeclared =
            |repo_url: &str| matches!(selector.select(repo_url, None), OriginSelection::Undeclared);
        let entries =
            (lock.platforms.iter()).filter(|entry| context.platforms.contains(&entry.platform));
        if !all_stored(store, lock, context, entries, undeclared).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the store holds the pinned bytes of every file `lock` pins, as
/// restoring them through `context` would take them.
///
/// # Errors
///
/// [`RepoError::Store`] when the store index cannot be read.
pub async fn restore_complete(
    store: &Store,
    lock: &Lockfile,
    context: &RestoreContext<'_>,
) -> Result<bool> {
    all_stored(store, lock, context, &lock.platforms, |_| true).await
}

/// How many of the files `lock` pins the store lacks, how many of those it
/// holds from a repository no row or one of `contexts` allows, and how many
/// it pins. Each file is a stat, not a hash: `raeva lock verify` hashes
/// them. A stored file counts only where restoring it through one of
/// `contexts` would take it.
///
/// # Errors
///
/// [`RepoError::Store`] when the store index cannot be read.
pub async fn count_missing(
    store: &Store,
    lock: &Lockfile,
    contexts: &[RestoreContext<'_>],
) -> Result<(usize, usize, usize)> {
    let files = pinned_files(&lock.platforms, |_| true);
    let total = files.len();
    let parallelism = std::thread::available_parallelism().map_or(4, |n| n.get().clamp(1, 64));
    let pom_pins = PomPins::new();
    let inputs: Vec<_> = (contexts.iter())
        .map(|context| SyncInputs::of(store, context, &pom_pins, &files))
        .collect();
    let inputs = &inputs;
    // Whether each file is stored, and when it is not, whether its bytes are.
    let mut checks = stream::iter(files.iter())
        .map(|((key, pin), origins)| async move {
            let blob = match pin.as_sha256() {
                Some(blob) => blob.clone(),
                None => match store.lookup_artifact(key).await? {
                    Some(blob) => blob,
                    None => return Ok((false, false)),
                },
            };
            let exists = store.exists_async(&blob).await;
            if exists {
                let served_by = store.served_by(key, &blob).await?;
                let admitted = inputs.iter().any(|input| {
                    let owners: Vec<_> = origins.iter().map(|origin| (input, *origin)).collect();
                    admits(&owners, key, pin, &served_by)
                });
                return Ok((admitted, !admitted));
            }
            Ok::<_, RepoError>((exists, false))
        })
        .buffer_unordered(parallelism);
    let (mut missing, mut unserved) = (0, 0);
    while let Some(checked) = checks.next().await {
        let (stored, held) = checked?;
        missing += usize::from(!stored);
        unserved += usize::from(held);
    }
    Ok((missing, unserved, total))
}

async fn all_stored<'a>(
    store: &Store,
    lock: &Lockfile,
    context: &RestoreContext<'_>,
    entries: impl IntoIterator<Item = &'a rv_lock::LockPlatform>,
    include: impl Fn(&str) -> bool,
) -> Result<bool> {
    let parallelism = std::thread::available_parallelism().map_or(4, |n| n.get().clamp(1, 64));
    let (pom_pins, file_origins) = (PomPins::new(), pinned_files(&lock.platforms, |_| true));
    let input = &SyncInputs::of(store, context, &pom_pins, &file_origins);
    let mut checks = stream::iter(pinned_files(entries, include))
        .map(|((key, pin), origins)| async move {
            let owners: Vec<_> = origins.into_iter().map(|origin| (input, origin)).collect();
            stored_intact(store, &owners, &key, &pin).await
        })
        .buffer_unordered(parallelism);
    // A missing file decides the answer whichever check finishes first; an
    // index error is reported only when no file is known missing.
    let mut failed = None;
    while let Some(intact) = checks.next().await {
        match intact {
            Ok(true) => {}
            Ok(false) => return Ok(false),
            Err(error) => {
                failed.get_or_insert(error);
            }
        }
    }
    failed.map_or(Ok(true), Err)
}

/// The files `entries` pin from repositories `include` accepts, each once
/// (platforms share most rows), with the origins the rows record for them.
fn pinned_files<'a>(
    entries: impl IntoIterator<Item = &'a rv_lock::LockPlatform>,
    include: impl Fn(&str) -> bool,
) -> BTreeMap<(ArtifactCoord, Digest), BTreeSet<&'a str>> {
    let mut files: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
    for entry in entries {
        for artifact in &entry.artifacts {
            if artifact.file_origins().any(&include)
                && let Some(pin) = artifact.pin()
            {
                (files.entry((artifact.coord(), pin.clone())).or_default())
                    .extend(artifact.file_origins());
            }
            if artifact.pom_origins().any(&include)
                && let Some(sha256) = &artifact.pom_sha256
            {
                let pom = ArtifactCoord::of(artifact.pom_gav(), "pom", None);
                (files
                    .entry((pom, Digest::Sha256(sha256.clone())))
                    .or_default())
                .extend(artifact.pom_origins());
            }
        }
        for (coord, pin) in &entry.support_poms {
            if include(&pin.repo_url)
                && let Some(key) = support_pom_key(coord, pin)
            {
                (files
                    .entry((key, Digest::Sha256(pin.sha256.clone())))
                    .or_default())
                .insert(pin.repo_url.as_str());
            }
        }
    }
    files
}

/// Whether the store holds `pin`'s bytes for `key` as restoration through
/// `owners` takes them, [`admits`] deciding.
async fn stored_intact(
    store: &Store,
    owners: &[(&SyncInputs<'_>, &str)],
    key: &ArtifactCoord,
    pin: &Digest,
) -> Result<bool> {
    let blob = match pin.as_sha256() {
        Some(blob) => blob.clone(),
        None => match store.lookup_artifact(key).await? {
            Some(blob) => blob,
            None => return Ok(false),
        },
    };
    let checked = store.check_served_pin_async(&blob, pin, key).await;
    Ok(checked.is_ok_and(|(check, served_by)| {
        check == PinCheck::Match && admits(owners, key, pin, &served_by)
    }))
}

struct SyncInputs<'a> {
    config: &'a Config,
    store: &'a Store,
    client: &'a RepoClient,
    selector: LockRepositorySelector,
    trusted_repositories: &'a [Repository],
    pom_pins: &'a PomPins,
    file_origins: &'a FileOrigins<'a>,
    /// By lock key, the (repository, endpoint) of each configured or trusted
    /// declaration there, under each id: ids that share a URL can reach it
    /// through different mirrors.
    routes: OnceLock<HashMap<String, HashSet<(String, String)>>>,
}

impl<'a> SyncInputs<'a> {
    fn of(
        store: &'a Store,
        context: &RestoreContext<'a>,
        pom_pins: &'a PomPins,
        file_origins: &'a FileOrigins<'a>,
    ) -> Self {
        Self {
            config: context.config,
            store,
            client: context.client,
            selector: LockRepositorySelector::new(
                context.config,
                &LockOrigins::for_root(&context.config.project_root),
                context.trusted_repositories,
            ),
            trusted_repositories: context.trusted_repositories,
            pom_pins,
            file_origins,
            routes: OnceLock::new(),
        }
    }

    fn routes(&self) -> &HashMap<String, HashSet<(String, String)>> {
        self.routes.get_or_init(|| {
            let mut routes: HashMap<_, HashSet<_>> = HashMap::new();
            for repo in unique_repositories(self.config, self.trusted_repositories, |_| true) {
                if let Some(key) = self.selector.origins.declared(&repo.url) {
                    let endpoint = self.client.effective_repository(&repo).url;
                    let route = (normalize_repo_url(&repo.url), normalize_repo_url(&endpoint));
                    routes.entry(key).or_default().insert(route);
                }
            }
            routes
        })
    }
}

/// Whether a stored file that the repositories `served_by` names served may
/// stand in for `key`, which raeva.lock pins to `pin` and records as served
/// by `owners`' origins. Projects share the store, and an edited pin could
/// name bytes another project's repository served for the coordinate, so
/// only bytes a repository the row records served directly, or a repository
/// [`fetch_pinned`] would ask served through the endpoint it uses, stand in.
/// A POM too: graph digests recomputed over an edited pin would not catch
/// another project's.
fn admits(
    owners: &[(&SyncInputs<'_>, &str)],
    key: &ArtifactCoord,
    pin: &Digest,
    served_by: &[(String, String)],
) -> bool {
    let served: Vec<_> = (served_by.iter())
        .map(|(repo, endpoint)| (normalize_repo_url(repo), normalize_repo_url(endpoint)))
        .collect();
    if served.is_empty() {
        return false;
    }
    let lock_wide =
        (owners.first()).and_then(|(input, _)| input.file_origins.get(&(key.clone(), pin.clone())));
    let recorded: HashSet<_> = (owners.iter().map(|(_, origin)| *origin))
        .chain(lock_wide.into_iter().flatten().copied())
        .map(rv_lock::recorded_key)
        .collect();
    owners.iter().any(|(input, origin)| {
        let direct = |(repo, endpoint): &(String, String)| {
            repo == endpoint
                && (input.selector.origins.declared(repo))
                    .is_some_and(|key| recorded.contains(&key))
        };
        let routes = input.routes();
        let declared = |route| {
            (recorded.iter()).any(|key| routes.get(key).is_some_and(|known| known.contains(route)))
        };
        served.iter().any(|route| direct(route) || declared(route))
            || (pinned_candidates(input, origin, key.version(), pin).unwrap_or_default())
                .iter()
                .any(|repo| {
                    let endpoint = input.client.effective_repository(repo).url;
                    served.contains(&(normalize_repo_url(&repo.url), normalize_repo_url(&endpoint)))
                })
    })
}

/// Restore `key` once per call, deduping concurrent callers: the first
/// caller runs `restore`, the others await its outcome. Every caller for one
/// key passes the same pin: the lock pins one coordinate to one checksum. On
/// error the entry is dropped so the next caller retries; failures are never
/// cached.
async fn restore_once<F: std::future::Future<Output = Result<()>>>(
    dedup: &FetchDedupMap,
    key: &ArtifactCoord,
    restore: impl FnOnce() -> F,
) -> Result<()> {
    let cell: Arc<OnceCell<()>> = {
        let mut map = dedup
            .lock()
            .map_err(|_| RepoError::Internal("fetch dedup map poisoned".to_string()))?;
        Arc::clone(map.entry(key.clone()).or_default())
    };
    let result = cell.get_or_try_init(restore).await;
    result.copied().inspect_err(|_| {
        if let Ok(mut map) = dedup.lock() {
            map.remove(key);
        }
    })
}

async fn ensure_package_artifacts(
    inputs: &SyncInputs<'_>,
    package: &LockArtifact,
    dedup: &FetchDedupMap,
    checks: &Checks,
    alongside: Option<&OnceLock<Holds>>,
    pom_asked: Option<&AtomicBool>,
) -> Result<()> {
    let ask_pom = || {
        if let Some(asked) = pom_asked {
            asked.store(true, Ordering::Relaxed);
        }
        ensure_companion_pom(inputs, package, dedup, checks)
    };
    let store = inputs.store;
    let key = package.coord();
    let pin = package
        .pin()
        .ok_or_else(|| RepoError::UnpinnedLockRow(key.to_string()))?;
    let owners: Vec<_> = package
        .file_origins()
        .map(|origin| (inputs, origin))
        .collect();
    if !needs_download(store, checks, &owners, &key, pin, &key.to_string()).await? {
        return ask_pom().await;
    }
    // The pin is checked as the bytes stream and needs no repository
    // sidecar: the lockfile pin is the user's contract and always holds.
    let artifact = restore_once(dedup, &key, || fetch_pinned(&owners, &key, pin));
    let Some(holds) = alongside else {
        artifact.await?;
        return ask_pom().await;
    };
    // The POM downloads alongside and logs after the artifact, also when
    // the artifact fails: what it repaired or fetched stays in the store.
    let pom = holds.get_or_init(Holds::default);
    let pom = pom.hold(ask_pom());
    let (artifact, (pom, held)) = futures::join!(artifact, pom);
    held.show();
    artifact?;
    pom
}

/// Ensure the POM of `package` is in the store. Its parents are support
/// POMs, which the lockfile pins and `ensure_artifacts` restores. A row
/// without a POM pin is one no repository has a POM for.
async fn ensure_companion_pom(
    inputs: &SyncInputs<'_>,
    package: &LockArtifact,
    dedup: &FetchDedupMap,
    checks: &Checks,
) -> Result<()> {
    let SyncInputs {
        store, pom_pins, ..
    } = *inputs;
    let pom_key = ArtifactCoord::of(package.pom_gav(), "pom", None);
    if let Some(expected) = pom_pins.get(&pom_key.gav) {
        // The lockfile names the exact POM bytes resolution parsed. The store's
        // coordinate index is not authoritative for them (any other project
        // sharing the store repoints `(g, a, v, pom)` last-writer-wins), so
        // verify against the pin and, if the store no longer holds those
        // bytes, re-fetch and verify what comes back rather than accepting
        // whatever the index currently names. The POM may come from another
        // repository than the artifact, as Maven reads it.
        let pom_pin = Digest::Sha256(expected.clone());
        let pom_coord = pom_key.to_string();
        let owners: Vec<_> = package
            .pom_origins()
            .map(|origin| (inputs, origin))
            .collect();
        if needs_download(store, checks, &owners, &pom_key, &pom_pin, &pom_coord).await? {
            restore_once(dedup, &pom_key, || {
                fetch_pinned(&owners, &pom_key, &pom_pin)
            })
            .await?;
        }
    }

    Ok(())
}

type Route = (Repository, String);
type RouteKey<'a> = (*const (), &'a str, bool);

/// A version selects a repository only by its releases or snapshots policy.
fn route_key<'a>(input: &SyncInputs<'_>, origin: &'a str, version: &str) -> RouteKey<'a> {
    (
        std::ptr::from_ref(input).cast(),
        origin,
        rv_maven_types::is_snapshot_version(version),
    )
}

fn package_routes<'a>(
    packages: &[(&'a LockArtifact, &SyncInputs<'_>)],
) -> HashMap<RouteKey<'a>, Option<Route>> {
    let mut routes = HashMap::new();
    for &(package, input) in packages {
        for origin in package.origins() {
            let version = package.coordinate.version();
            routes
                .entry(route_key(input, origin, version))
                .or_insert_with(|| declared_route(input, origin, version));
        }
    }
    routes
}

struct IndexFile<'a> {
    key: ArtifactCoord,
    blob: &'a BlobId,
    client: &'a RepoClient,
    route: &'a Route,
}

fn index_files<'a>(
    package: &'a LockArtifact,
    input: &'a SyncInputs<'_>,
    routes: &'a HashMap<RouteKey<'a>, Option<Route>>,
    files: &mut Vec<IndexFile<'a>>,
) {
    let mut add = |key: &ArtifactCoord, blob, origin: &'a str| {
        if let Some(Some(route)) = routes.get(&route_key(input, origin, key.version())) {
            files.push(IndexFile {
                key: key.clone(),
                blob,
                client: input.client,
                route,
            });
        }
    };
    if let Some(blob) = package.pin().and_then(Digest::as_sha256) {
        let key = package.coord();
        for origin in package.file_origins() {
            add(&key, blob, origin);
        }
    }
    if let Some(blob) = &package.pom_sha256 {
        let key = ArtifactCoord::of(package.pom_gav(), "pom", None);
        for origin in package.pom_origins() {
            add(&key, blob, origin);
        }
    }
}

/// The declared repository `repo_url` names in `input`, and the URL that
/// serves it.
fn declared_route(
    input: &SyncInputs<'_>,
    repo_url: &str,
    version: &str,
) -> Option<(Repository, String)> {
    match input.selector.select(repo_url, Some(version)) {
        OriginSelection::Declared(repo) => {
            let endpoint = input.client.effective_repository(&repo).url;
            Some((repo, endpoint))
        }
        _ => None,
    }
}

/// Index each restored file under all its declared origins and seed POMs
/// under their own origins. One index read and one cache read per client
/// cover every row, which keeps a warm restore fast.
async fn index_for_platforms(store: &Store, rows: &[IndexFile<'_>]) -> Result<Vec<Result<()>>> {
    let origins = rows
        .iter()
        .map(|file| {
            let (repo, endpoint) = file.route;
            // The bytes may have come from another repository: the row
            // records its origin, and the pin decided which bytes.
            let origin = rv_store::Origin {
                repo_url: repo.url.clone(),
                endpoint_url: endpoint.clone(),
                checksum_verified: false,
                served: false,
            };
            (file.key.clone(), file.blob.clone(), origin)
        })
        .collect();
    let unrecorded = store.unrecorded_origins(origins).await?;
    store
        .record_origins(unrecorded.into_iter().flatten().collect())
        .await?;

    let poms: Vec<_> = rows
        .iter()
        .map(|file| {
            is_pom(&file.key).then(|| {
                (
                    file.client,
                    (&file.route.0, ArtifactRequest::from(&file.key), file.blob),
                )
            })
        })
        .collect();
    let mut unseeded = vec![false; rows.len()];
    let mut clients: Vec<&RepoClient> = Vec::new();
    for (client, _) in poms.iter().flatten() {
        if !clients.iter().any(|known| std::ptr::eq(*known, *client)) {
            clients.push(client);
        }
    }
    for client in clients {
        let (indices, probes): (Vec<_>, Vec<_>) = (poms.iter().enumerate())
            .filter_map(|(index, pom)| {
                let (owner, (repo, request, pin)) = pom.as_ref()?;
                std::ptr::eq(*owner, client).then(|| (index, (*repo, request.clone(), *pin)))
            })
            .unzip();
        for (index, missing) in indices
            .into_iter()
            .zip(client.unseeded_poms(&probes).await?)
        {
            unseeded[index] = missing;
        }
    }
    let mut outcomes = Vec::with_capacity(rows.len());
    for ((pom, unseeded), file) in poms.iter().zip(unseeded).zip(rows) {
        let outcome = match pom {
            Some((client, (repo, request, pom))) if unseeded => {
                let route = (*repo, file.route.1.as_str());
                cache_route_pom(store, client, route, &file.key, request, pom).await
            }
            _ => Ok(()),
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// Decide whether the artifact at `key` still needs to be downloaded.
///
/// In addition to checking presence, this re-verifies any already-present
/// blob against the lockfile pin so on-disk bit rot or tampering does NOT
/// silently approve a stale lockfile. On a verification failure we treat
/// the existing blob as discardable and return `true`, signalling the
/// caller to re-fetch from the repository.
async fn needs_download(
    store: &Store,
    checks: &Checks,
    owners: &[(&SyncInputs<'_>, &str)],
    key: &ArtifactCoord,
    pin: &Digest,
    coord: &str,
) -> Result<bool> {
    if let Some(expected) = pin.as_sha256() {
        return adopt_pinned_blob(store, checks, owners, key, expected, pin, coord).await;
    }
    if let Some(existing) = store.lookup_artifact(key).await? {
        let (found, stored) = verify_pin(store, checks, &existing, pin, coord, Some(key)).await?;
        return Ok(found != Some(true) || !admits(owners, key, pin, &stored.served_by));
    }
    Ok(true)
}

/// Point `key` at the pinned blob when the content store already holds it,
/// returning whether a download is still needed.
///
/// KNOWN LIMITATION: `exists_async`, the pin check and `add_artifact` are
/// three steps with no store lock held across them, so another process
/// removing a corrupt copy of the blob can leave a dangling index row. This
/// logs when the blob is gone after `add_artifact`, and the next sync's pin
/// check in `needs_download` repairs the row.
#[allow(clippy::too_many_arguments)]
async fn adopt_pinned_blob(
    store: &Store,
    checks: &Checks,
    owners: &[(&SyncInputs<'_>, &str)],
    key: &ArtifactCoord,
    expected: &BlobId,
    pin: &Digest,
    coord: &str,
) -> Result<bool> {
    let (found, stored) = verify_pin(store, checks, expected, pin, coord, Some(key)).await?;
    // The index names whichever bytes the last project fetched, so a match
    // there proves nothing: an edited pin could name a file another
    // project's repository served for this coordinate, or an older
    // release's jar.
    if found != Some(true) || !admits(owners, key, pin, &stored.served_by) {
        return Ok(true);
    }
    // The SHA-256 pin check also establishes durability for this file,
    // including a replacement inode under an old row, by the end of the run.
    // Avoid a redundant upsert.
    if stored.indexed {
        return Ok(false);
    }
    store.add_artifact(key, expected).await?;
    if !store.exists_async(expected).await {
        tracing::warn!(
            sec_code = "ADOPT_RACE",
            coord = %coord,
            blob = %expected,
            "blob disappeared between exists check and add_artifact (removed by another raeva process); index row will be repaired on next sync"
        );
        return Ok(true);
    }
    Ok(false)
}

/// Check `blob` against `pin` on the blocking pool, returning whether it
/// matches, or `None` when the store has no file for it, and for a match
/// what the index records for it under `key`; on a mismatch the caller must
/// re-fetch. A match it hashed joins `checks`. The file stays: a blob that still hashes to its
/// `BlobId` serves other rows, and publishing the re-fetched bytes replaces
/// a corrupt one under the store lock, where another process repairing it
/// at the same time cannot lose its copy.
async fn verify_pin(
    store: &Store,
    checks: &Checks,
    blob: &BlobId,
    pin: &Digest,
    coord: &str,
    key: Option<&ArtifactCoord>,
) -> Result<(Option<bool>, StoredFor)> {
    match store.check_pin_queued_async(blob, pin, key).await {
        Ok((PinCheck::Match, queued, stored)) => {
            (checks.lock().unwrap_or_else(PoisonError::into_inner)).extend(queued);
            return Ok((Some(true), stored?));
        }
        Ok((PinCheck::Missing, ..)) => return Ok((None, StoredFor::default())),
        // A damaged index says nothing about the file, and fails the
        // writes that a download would end with.
        Err(err) if err.db_failure() == Some(rv_store::DbFailure::Corrupt) => {
            return Err(err.into());
        }
        Ok((PinCheck::Mismatch { .. }, ..)) | Err(_) => {}
    }
    // A run never repairs the store silently, `--frozen` included: the
    // bytes it held for a locked file were not the locked ones.
    tracing::warn!(
        sec_code = "STORE_FILE_REFETCHED",
        coord = %coord,
        "the store's copy of {coord} does not match its raeva.lock checksum; downloading it again"
    );
    Ok((Some(false), StoredFor::default()))
}

/// Resolve a lockfile `repo_url` against the repositories the current
/// configuration and resolution declare. Refuse any origin none of them
/// declares: the lockfile is not a trust root, so a tampered `raeva.lock` must
/// not redirect a fetch to an attacker origin.
///
/// The repository returned is always the declared one, with its own URL. A
/// project-relative origin (`./repo/`) is compared with the key each
/// declaration would be recorded under (see [`rv_lock::LockOrigins`]), and
/// is never joined to the project root itself; one that declarations with
/// different URLs map to is refused as ambiguous rather than guessed.
///
/// This is the canonical trust policy for a lockfile origin; every caller
/// that turns a recorded `repo_url` into a repository (`raeva lock --verify
/// --download`, `raeva export-m2` classifier fetches) goes through it. Callers
/// without a resolution pass an empty `trusted_repositories`, or the
/// repositories the current local POMs declare: that slice carries origins
/// the *current* project authorizes, never anything read from the lock.
/// `origins` is [`rv_lock::LockOrigins::for_root`] of the project root, built
/// once per operation rather than per row.
pub fn repository_for_package(
    config: &Config,
    origins: &rv_lock::LockOrigins,
    package: &LockArtifact,
    trusted_repositories: &[Repository],
) -> Result<Repository> {
    let version = Some(package.coordinate.version());
    match select_lock_repository(
        config,
        origins,
        &package.repo_url,
        version,
        trusted_repositories,
    ) {
        OriginSelection::Declared(repo) => Ok(repo),
        OriginSelection::Ambiguous => Err(RepoError::AmbiguousRepoOrigin(rv_lock::redact_origin(
            &package.repo_url,
        ))),
        OriginSelection::Undeclared => Err(RepoError::UntrustedRepoUrl(rv_lock::redact_origin(
            &package.repo_url,
        ))),
    }
}

/// The origin decision behind [`repository_for_package`], for callers that
/// report an untrusted origin themselves. One URL may be declared under
/// several ids, such as one for releases and one for snapshots; a
/// declaration enabled for `version` is preferred. For multiple rows, reuse
/// a [`LockRepositorySelector`] instead.
pub fn select_lock_repository(
    config: &Config,
    origins: &rv_lock::LockOrigins,
    repo_url: &str,
    version: Option<&str>,
    trusted_repositories: &[Repository],
) -> OriginSelection<Repository> {
    LockRepositorySelector::new(config, origins, trusted_repositories).select(repo_url, version)
}

/// Repository declarations and cached origin decisions for one restore or
/// validation pass. Build a new selector when configuration or trust changes.
pub struct LockRepositorySelector {
    origins: LockOrigins,
    repositories: Vec<(String, Repository)>,
    selections: Mutex<[HashMap<String, OriginSelection<Repository>>; 3]>,
}

impl LockRepositorySelector {
    /// Capture configured and trusted declarations, applying the HTTP blocker
    /// to trusted repositories as [`select_lock_repository`] does.
    pub fn new(
        config: &Config,
        origins: &LockOrigins,
        trusted_repositories: &[Repository],
    ) -> Self {
        // The lock records declarations, never mirror endpoints.
        let configured = config
            .repositories()
            .iter()
            .map(|repo| (repo.url.clone(), Repository::from(repo)));
        let trusted = trusted_repositories
            .iter()
            .filter(|repo| !crate::policy::http_repository_blocked(config, repo, true))
            .map(|repo| (repo.url.clone(), repo.clone()));
        Self {
            origins: origins.clone(),
            repositories: configured.chain(trusted).collect(),
            selections: Mutex::default(),
        }
    }

    /// Select the first matching declaration enabled for `version`, falling
    /// back to disabled declarations while still refusing ambiguous origins.
    pub fn select(&self, repo_url: &str, version: Option<&str>) -> OriginSelection<Repository> {
        // `allows_version` depends only on snapshot status, including
        // timestamped builds. No version preserves declaration order.
        let kind = version.map_or(0, |version| {
            if rv_maven_types::is_snapshot_version(version) {
                2
            } else {
                1
            }
        });
        // A `file:` selection resolves links, which can change during a pass,
        // so only http(s) origins are cached.
        let cached = rv_lock::is_http_origin(repo_url);
        if cached
            && let Some(selection) =
                self.selections.lock().unwrap_or_else(|e| e.into_inner())[kind].get(repo_url)
        {
            return selection.clone();
        }
        let enabled = |(_, repo): &&(String, Repository)| {
            version.is_none_or(|version| repo.allows_version(version))
        };
        let repositories = self
            .repositories
            .iter()
            .filter(enabled)
            .chain(self.repositories.iter().filter(|repo| !enabled(repo)));
        let selection = match self.origins.select(
            repo_url,
            repositories.map(|(url, repo)| (url.as_str(), repo)),
        ) {
            OriginSelection::Declared(repo) => OriginSelection::Declared(repo.clone()),
            OriginSelection::Ambiguous => OriginSelection::Ambiguous,
            OriginSelection::Undeclared => OriginSelection::Undeclared,
        };
        if cached {
            self.selections.lock().unwrap_or_else(|e| e.into_inner())[kind]
                .insert(repo_url.to_string(), selection.clone());
        }
        selection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_maven_types::Sha1;
    use tempfile::tempdir;

    #[test]
    fn a_recorded_origin_answer_comes_before_a_fallback_one() {
        let refused = |url: &str| RepoError::Unauthorized {
            status: reqwest::StatusCode::UNAUTHORIZED,
            url: url.into(),
            sent: None,
        };
        let key = ArtifactCoord::of(
            rv_maven_types::Gav::new("org.test", "a", "1.0"),
            "jar",
            None,
        );
        let mut search = PinnedSearch::default();
        search.keep(true, RepoError::NotFound("recorded".into()));
        search.keep(false, refused("fallback"));
        assert!(matches!(search.finish(None, &key), RepoError::NotFound(url) if url == "recorded"));
        let mut search = PinnedSearch::default();
        search.keep(true, RepoError::NotFound("first".into()));
        search.keep(true, refused("second"));
        search.keep(true, RepoError::NotFound("third".into()));
        assert!(matches!(
            search.finish(None, &key),
            RepoError::Unauthorized { url, .. } if url == "second"
        ));
    }

    #[test]
    fn cached_selection_distinguishes_version_policies() {
        let temp = tempdir().unwrap();
        let url = "https://repo.example/maven2/";
        let mut snapshots = rv_config::RepoConfig::new(Some("snapshots"), url);
        snapshots.releases = Some(false);
        snapshots.snapshots = Some(true);
        let config = Config::for_testing_with_repos(
            temp.path().into(),
            rv_config::ResolvedPaths::for_testing().unwrap(),
            vec![snapshots],
        );
        let releases = Repository::new(Some("releases".into()), url, true, false);
        let disabled = Repository::new(
            Some("disabled".into()),
            "https://disabled.example/",
            false,
            false,
        );
        let origins = LockOrigins::for_root(temp.path());
        let selector = LockRepositorySelector::new(&config, &origins, &[releases, disabled]);
        for _ in 0..2 {
            for (version, id) in [
                (Some("1.0"), "releases"),
                (None, "snapshots"),
                (Some("1.0-SNAPSHOT"), "snapshots"),
                (Some("2.0"), "releases"),
                (Some("1.0-20260720.123253-3"), "snapshots"),
            ] {
                let repo = selector.select(url, version).declared().unwrap();
                assert_eq!(repo.id.as_deref(), Some(id), "{version:?}");
            }
            for version in [None, Some("1.0"), Some("1.0-SNAPSHOT")] {
                assert!(matches!(
                    selector.select("https://undeclared.example/", version),
                    OriginSelection::Undeclared
                ));
                let repo = selector
                    .select("https://disabled.example/", version)
                    .declared()
                    .unwrap();
                assert_eq!(repo.id.as_deref(), Some("disabled"));
            }
        }
    }

    #[test]
    fn lock_origins_cannot_bypass_the_http_blocker() {
        let temp = tempdir().unwrap();
        let config = central_config(temp.path());
        let origins = rv_lock::LockOrigins::for_root(temp.path());
        let repo = Repository::new(Some("legacy".into()), "http://lock.example/", true, false);
        // A lock origin reconstructed by the caller has no POM provenance.
        assert!(matches!(
            select_lock_repository(
                &config,
                &origins,
                &repo.url,
                None,
                std::slice::from_ref(&repo)
            ),
            OriginSelection::Undeclared
        ));
        let fallback = |config: &Config| {
            unique_repositories(config, std::slice::from_ref(&repo), |other| {
                other.url == repo.url
            })
        };
        assert!(fallback(&config).is_empty());

        let mut mirror = rv_config::MirrorConfig::new(Some("safe"), "https://mirror.example/");
        mirror.mirror_of = vec!["legacy".into()];
        let mirrored = config.with_mirrors(vec![mirror]);
        let configured = Config::for_testing_with_repos(
            temp.path().into(),
            rv_config::ResolvedPaths::for_testing().unwrap(),
            vec![rv_config::RepoConfig::new(
                Some("legacy"),
                "http://lock.example",
            )],
        );
        for config in [mirrored, configured] {
            assert!(matches!(
                select_lock_repository(
                    &config,
                    &origins,
                    &repo.url,
                    None,
                    std::slice::from_ref(&repo)
                ),
                OriginSelection::Declared(_)
            ));
            assert_eq!(fallback(&config), std::slice::from_ref(&repo));
        }
    }

    fn demo(version: &str, extension: &str) -> ArtifactCoord {
        ArtifactCoord::new("com.example", "demo", version, extension, None)
    }

    /// A stored blob is re-hashed against the pin: intact bytes need no
    /// download, tampered bytes are removed and re-fetched, and a wrong SHA-1
    /// pin re-fetches without deleting the valid, shared blob.
    #[tokio::test]
    async fn needs_download_follows_the_pin() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = demo("1.0.0", "jar");
        let coord = key.to_string();
        let payload = b"good-jar-bytes".to_vec();
        let id = store.put_bytes(&payload).await.unwrap();
        store.add_artifact(&key, &id).await.unwrap();
        let served = |blob: &BlobId, repo: &str| {
            let origin = rv_store::Origin {
                repo_url: repo.into(),
                endpoint_url: repo.into(),
                checksum_verified: true,
                served: true,
            };
            vec![(key.clone(), blob.clone(), origin)]
        };
        store
            .record_origins(served(&id, "https://repo.example/"))
            .await
            .unwrap();
        let path = store.get_path(&id);
        let sha256 = Digest::Sha256(id.clone());
        let sha1 = Digest::Sha1(Sha1::from_bytes(&payload));
        let wrong_sha1 = Digest::Sha1("0".repeat(40).parse().unwrap());

        let checks = super::Checks::default();
        // The row records repo.example; old.example is configured too.
        let paths = rv_config::ResolvedPaths::for_testing().expect("paths");
        let repos = ["repo", "old"]
            .map(|id| rv_config::RepoConfig::new(Some(id), &format!("https://{id}.example/")));
        let config = Config::for_testing_with_repos(dir.path().into(), paths, repos.into());
        let client = RepoClient::new(&config).await.unwrap();
        let context = RestoreContext {
            config: &config,
            client: &client,
            platforms: &[],
            trusted_repositories: &[],
        };
        let pom_pins = PomPins::new();
        let file_origins = FileOrigins::new();
        let input = super::SyncInputs::of(&store, &context, &pom_pins, &file_origins);
        let routes = &[(&input, "https://repo.example/")];
        assert!(
            !needs_download(&store, &checks, routes, &key, &sha256, &coord)
                .await
                .unwrap()
        );
        let check = |pin| store.check_pin_unless_unchanged_async(&id, pin);
        assert_eq!(check(&sha1).await.unwrap(), PinCheck::Match);
        assert_eq!(
            check(&wrong_sha1).await.unwrap(),
            PinCheck::Mismatch {
                actual: sha1.hex().to_string()
            }
        );
        assert!(
            needs_download(&store, &checks, routes, &key, &wrong_sha1, &coord)
                .await
                .unwrap()
        );
        assert!(path.is_file(), "a valid shared blob survives a stale pin");

        let other = store.put_bytes(b"another repository's jar").await.unwrap();
        store.add_artifact(&key, &other).await.unwrap();
        assert!(
            !needs_download(&store, &checks, routes, &key, &sha256, &coord)
                .await
                .unwrap()
        );
        assert_eq!(store.lookup_artifact(&key).await.unwrap(), Some(id.clone()));
        assert!(store.exists_async(&other).await);

        // A file no repository served for this coordinate, such as an older
        // release's jar, is not taken for it, whatever the pin says.
        let older = store.put_bytes(b"an older release's jar").await.unwrap();
        let pin = Digest::Sha256(older.clone());
        assert!(
            needs_download(&store, &checks, routes, &key, &pin, &coord)
                .await
                .unwrap()
        );
        assert_eq!(store.lookup_artifact(&key).await.unwrap(), Some(id.clone()));
        store
            .record_origins(served(&older, "https://old.example/"))
            .await
            .unwrap();
        assert!(
            !needs_download(&store, &checks, routes, &key, &pin, &coord)
                .await
                .unwrap()
        );

        // Nor is one only a repository this context does not use served,
        // such as another project's, though the index names it.
        let foreign = store.put_bytes(b"another project's jar").await.unwrap();
        store
            .record_origins(served(&foreign, "https://foreign.example/"))
            .await
            .unwrap();
        store.add_artifact(&key, &foreign).await.unwrap();
        let pin = Digest::Sha256(foreign.clone());
        assert!(
            needs_download(&store, &checks, routes, &key, &pin, &coord)
                .await
                .unwrap()
        );
        let sha1 = Digest::Sha1(Sha1::from_bytes(b"another project's jar"));
        assert!(
            needs_download(&store, &checks, routes, &key, &sha1, &coord)
                .await
                .unwrap()
        );

        // CAS blobs are read-only; re-grant write to clobber one.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&path, perms).unwrap();
        std::fs::write(&path, b"tampered-bytes").unwrap();
        assert!(
            needs_download(&store, &checks, routes, &key, &sha256, &coord)
                .await
                .unwrap()
        );
        // Another process may be repairing it; the download replaces it.
        assert!(path.is_file());
        assert_eq!(store.put_bytes(&payload).await.unwrap(), id);
        assert!(
            !needs_download(&store, &checks, routes, &key, &sha256, &coord)
                .await
                .unwrap()
        );
    }

    /// Record that `repo` served `blob` for `key`, as a download does.
    async fn served_from(store: &Store, key: &ArtifactCoord, blob: &BlobId, repo: &str) {
        let origin = rv_store::Origin {
            repo_url: repo.into(),
            endpoint_url: repo.into(),
            checksum_verified: true,
            served: true,
        };
        let served = vec![(key.clone(), blob.clone(), origin)];
        store.record_origins(served).await.unwrap();
    }

    fn central_config(root: &std::path::Path) -> Config {
        let mut central =
            rv_config::RepoConfig::new(Some("central"), "https://repo1.maven.org/maven2/");
        central.releases = Some(true);
        central.snapshots = Some(false);
        central.snapshots_update_policy = Some(rv_config::UpdatePolicy::Daily);
        let paths = rv_config::ResolvedPaths::for_testing().expect("paths");
        Config::for_testing_with_repos(root.to_path_buf(), paths, vec![central])
    }

    /// The lockfile is not a trust root: its `repo_url` must name a
    /// configured repository or one the current resolution trusts, and a
    /// refused origin is shown without credentials.
    #[test]
    fn repository_for_package_trusts_only_configured_origins() {
        let temp = tempdir().expect("temp dir");
        let config = central_config(temp.path());
        let origins = &rv_lock::LockOrigins::for_root(temp.path());
        let package = |version: &str, url: &str| {
            let mut package = LockArtifact::new(demo(version, "jar"), url);
            package.checksums = vec![Digest::parse("sha256", &"f".repeat(64)).unwrap()];
            package
        };

        let repo = repository_for_package(
            &config,
            origins,
            &package("1.0.0", "https://repo1.maven.org/maven2"),
            &[],
        )
        .expect("configured repo must resolve");
        assert_eq!(repo.id.as_deref(), Some("central"));

        let trusted = Repository::new(
            Some("snapshots".to_string()),
            "https://repository.example/snapshots",
            false,
            true,
        );
        let repo = repository_for_package(
            &config,
            origins,
            &package("1.0-SNAPSHOT", "https://repository.example/snapshots/"),
            &[trusted],
        )
        .expect("the current resolution authorizes its repository");
        assert_eq!(repo.id.as_deref(), Some("snapshots"));
        assert!(repo.snapshots_enabled);

        for (recorded, shown) in [
            ("https://untrusted.example/", "https://untrusted.example/"),
            (
                "https://user:s3cret@untrusted.example/m2/?token=s3cret#s3cret",
                "https://untrusted.example/m2/?***",
            ),
            ("s3cret not a url", rv_config::UNPARSABLE_URL),
        ] {
            match repository_for_package(&config, origins, &package("1.0.0", recorded), &[]) {
                Err(RepoError::UntrustedRepoUrl(url)) => assert_eq!(url, shown),
                other => panic!("expected UntrustedRepoUrl, got {other:?}"),
            }
        }
    }

    /// A row without a checksum is refused before any network I/O.
    #[tokio::test]
    async fn ensure_artifacts_rejects_package_without_checksum() {
        use rv_lock::{LockPlatform, Platform};

        let temp = tempdir().expect("temp dir");
        let config = central_config(temp.path());
        let store = Store::open(&temp.path().join("store")).expect("store");
        let client = RepoClient::new(&config).await.expect("client");
        let package = LockArtifact::new(demo("1.0.0", "jar"), "https://repo1.maven.org/maven2/");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform::single_module(
            Platform::current().expect("platform"),
            Gav::new("com.example", "root", "1"),
            "pom",
            vec![package],
        )];
        let platforms = vec![Platform::current().expect("platform")];

        let results = ensure_artifacts(
            &store,
            &lock,
            &[RestoreContext {
                config: &config,
                client: &client,
                platforms: &platforms,
                trusted_repositories: &[],
            }],
        )
        .await
        .expect("per-package results");
        assert_eq!(results.len(), 1);
        match &results[0].result {
            Err(err @ RepoError::UnpinnedLockRow(coord)) => {
                assert_eq!(coord, "com.example:demo:1.0.0:jar");
                assert_eq!(
                    err.to_string(),
                    "raeva.lock records no checksum for com.example:demo:1.0.0:jar, so a download \
                     of it cannot be verified"
                );
                assert_eq!(err.class(), crate::ErrorClass::Lockfile);
            }
            other => panic!("expected UnpinnedLockRow, got {other:?}"),
        }
    }

    async fn fixture_config(root: &std::path::Path, url: Option<&str>) -> (Config, RepoClient) {
        let paths = rv_config::ResolvedPaths::for_testing().expect("paths");
        let url = url.unwrap_or("https://unreachable.invalid/maven2/");
        let mut repo = rv_config::RepoConfig::new(Some("fixture"), url);
        repo.releases = Some(true);
        repo.snapshots = Some(true);
        repo.snapshots_update_policy = Some(rv_config::UpdatePolicy::Daily);
        let mut config = Config::for_testing_with_repos(root.to_path_buf(), paths, vec![repo]);
        config.network.retries = 0;
        let client = RepoClient::new(&config).await.expect("client");
        (config, client)
    }

    fn pinned_package(jar: &BlobId) -> LockArtifact {
        let mut artifact =
            LockArtifact::new(demo("1.0", "jar"), "https://unreachable.invalid/maven2/");
        artifact.checksums = vec![Digest::Sha256(jar.clone())];
        artifact
    }

    /// The row for snapshot build `timestamped` of `com.example:demo`.
    fn snapshot_build(jar: &BlobId, timestamped: &str, repo_url: &str) -> LockArtifact {
        let base = rv_maven_types::snapshot_base_version(timestamped).expect("timestamped");
        let mut artifact = LockArtifact::new(demo(&base, "jar"), repo_url);
        artifact.checksums = vec![Digest::Sha256(jar.clone())];
        artifact.snapshot = rv_maven_types::SnapshotStamp::of_version(timestamped);
        artifact
    }

    async fn sync(
        config: &Config,
        store: &Store,
        client: &RepoClient,
        pom_pins: &PomPins,
        package: &LockArtifact,
    ) -> Result<()> {
        let dedup: FetchDedupMap = Arc::new(Mutex::new(HashMap::new()));
        let origins = LockOrigins::for_root(&config.project_root);
        let inputs = SyncInputs {
            config,
            store,
            client,
            selector: LockRepositorySelector::new(config, &origins, &[]),
            trusted_repositories: &[],
            pom_pins,
            file_origins: &FileOrigins::new(),
            routes: OnceLock::new(),
        };
        ensure_package_artifacts(
            &inputs,
            package,
            &dedup,
            &super::Checks::default(),
            Some(&OnceLock::new()),
            None,
        )
        .await
        .map(drop)
    }

    /// A POM only another project's repository served for the coordinate
    /// does not stand in for the one a row records under its own
    /// repository, though the pin names it, as an edit with recomputed
    /// graph digests would: the recorded repository is asked, and its POM
    /// fails the pin. Bytes it served itself stand in.
    #[tokio::test]
    async fn a_pom_another_repository_served_does_not_stand_in() {
        use rv_test_support::http::{Response, StubServer};
        const JAR: &[u8] = b"demo jar";
        const POM: &[u8] = b"<project><artifactId>demo</artifactId></project>";
        const FOREIGN: &[u8] = b"<project><artifactId>demo</artifactId><!-- x --></project>";
        let server = StubServer::start(|req| match req.path.as_str() {
            "/m2/com/example/demo/1.0/demo-1.0.jar" => Response::new(200, JAR),
            "/m2/com/example/demo/1.0/demo-1.0.pom" => Response::new(200, POM),
            _ => Response::new(404, ""),
        });
        let url = format!("http://{}/m2/", server.addr());
        for served_by in ["https://foreign.example/m2/", url.as_str()] {
            let temp = tempdir().expect("temp dir");
            let store = Store::open(&temp.path().join("store")).expect("store");
            let (config, client) = fixture_config(temp.path(), Some(&url)).await;
            let jar = store.put_bytes(JAR).await.unwrap();
            let mut package = pinned_package(&jar);
            package.repo_url = url.clone();
            served_from(&store, &package.coord(), &jar, &url).await;
            let foreign = store.put_bytes(FOREIGN).await.unwrap();
            served_from(&store, &demo("1.0", "pom"), &foreign, served_by).await;
            package.pom_sha256 = Some(foreign.clone());
            let gav = Gav::new("com.example", "demo", "1.0");
            let pom_pins = PomPins::from([(gav, foreign)]);
            let asked = server.requests().len();
            let result = sync(&config, &store, &client, &pom_pins, &package).await;
            let pom_asked = (server.requests()[asked..].iter())
                .any(|request| request.path.ends_with("demo-1.0.pom"));
            if served_by == url {
                result.expect("bytes the recorded repository served stand in");
                assert!(!pom_asked);
            } else {
                assert!(result.is_err(), "the foreign POM stood in");
                assert!(pom_asked, "the recorded repository is asked");
            }
        }
    }

    /// The shared `(g, a, v, pom)` index row is last-writer-wins across
    /// projects. A pin in the store restores the row; no pin leaves it; a pin
    /// whose bytes are gone forces a fetch instead of adopting the row. A
    /// timestamped row never aliases the mutable base `-SNAPSHOT` row.
    #[tokio::test]
    async fn companion_pom_rows_follow_the_pin_not_the_index() {
        let resolved = b"<project>resolution parsed this</project>";
        let timestamped = "1.0-20260720.123253-3";
        for (version, pin_in_store, pinned) in [
            ("1.0", true, true),
            ("1.0", false, false),
            ("1.0", false, true),
            (timestamped, true, true),
            (timestamped, false, false),
        ] {
            let temp = tempdir().expect("temp dir");
            let store = Store::open(&temp.path().join("store")).expect("store");
            let (config, client) = fixture_config(temp.path(), None).await;
            let jar = store.put_bytes(b"demo jar").await.unwrap();
            store
                .add_artifact(&demo(version, "jar"), &jar)
                .await
                .unwrap();
            let resolved_id = if pin_in_store {
                store.put_bytes(resolved).await.unwrap()
            } else {
                BlobId::from_bytes(resolved)
            };
            let base = rv_maven_types::snapshot_base_version(version);
            let base_key = demo(base.as_deref().unwrap_or(version), "pom");
            let other_pom = store
                .put_bytes(b"<project>another project indexed this</project>")
                .await
                .unwrap();
            store.add_artifact(&base_key, &other_pom).await.unwrap();
            let pom_pins = if pinned {
                PomPins::from([(
                    Gav::new("com.example", "demo", version),
                    resolved_id.clone(),
                )])
            } else {
                PomPins::new()
            };
            let package = if base.is_some() {
                snapshot_build(&jar, version, "https://unreachable.invalid/maven2/")
            } else {
                pinned_package(&jar)
            };

            served_from(&store, &package.coord(), &jar, &package.repo_url).await;
            let pom_key = ArtifactCoord::of(package.pom_gav(), "pom", None);
            served_from(&store, &pom_key, &resolved_id, &package.repo_url).await;
            let result = sync(&config, &store, &client, &pom_pins, &package).await;
            let row = store.lookup_artifact(&demo(version, "pom")).await.unwrap();
            let case = format!("{version} {pin_in_store} {pinned}");
            if pin_in_store {
                result.expect(&case);
                assert_eq!(row, Some(resolved_id), "{case}");
            } else if !pinned {
                result.expect("a row without a POM pin has no POM to fetch");
                assert_eq!(row.as_ref(), base.is_none().then_some(&other_pom), "{case}");
            } else {
                let error = result.expect_err("the index row must not stand in");
                assert!(
                    !matches!(error, RepoError::UntrustedRepoUrl(_)),
                    "{error:?}"
                );
                assert_eq!(row.is_some(), base.is_none(), "{case}");
            }
            if base.is_some() {
                let base_row = store.lookup_artifact(&base_key).await.unwrap();
                assert_eq!(base_row, Some(other_pom), "{case}");
            }
        }
    }

    /// A jar matching the repository's sidecar but not the raeva.lock pin fails,
    /// and the store keeps neither its bytes nor an index row.
    #[tokio::test]
    async fn pin_mismatch_on_download_leaves_no_row_and_no_blob() {
        use rv_test_support::http::{Response, StubServer};

        let served = b"bytes the repository now serves".to_vec();
        let served_id = BlobId::from_bytes(&served);
        let sidecar = served_id.as_str().to_string();
        let server = StubServer::start(move |req| {
            if req.path.ends_with(".jar") {
                Response::new(200, served.clone())
            } else if req.path.ends_with(".jar.sha256") {
                Response::new(200, sidecar.clone())
            } else {
                Response::new(404, Vec::new())
            }
        });
        let url = format!("http://{}/maven2/", server.addr());
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let (config, client) = fixture_config(temp.path(), Some(&url)).await;
        let mut package = pinned_package(&BlobId::from_bytes(b"bytes the lockfile pinned"));
        package.repo_url = url;

        let err = sync(&config, &store, &client, &PomPins::new(), &package)
            .await
            .expect_err("the served jar does not match the pin");
        server.stop();
        assert!(
            matches!(
                err,
                RepoError::ChecksumMismatch {
                    check: IntegritySource::LockPin,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(
            store.lookup_artifact(&demo("1.0", "jar")).await.unwrap(),
            None
        );
        assert!(!store.get_path(&served_id).exists());
    }

    /// The repository publishes no checksum sidecar for anything. The pins
    /// verify the jar, its POM and the support POM a strict run restores,
    /// and a file that does not match its pin is still refused.
    #[tokio::test]
    async fn pinned_files_need_no_sidecar() {
        use rv_lock::Platform;
        use rv_test_support::http::{Response, StubServer};

        const JAR: &[u8] = b"demo jar";
        const POM: &[u8] = b"<project><artifactId>demo</artifactId></project>";
        const BOM: &[u8] = b"<project><artifactId>bom</artifactId></project>";
        let server = StubServer::start(|req| match req.path.as_str() {
            "/m2/com/example/demo/1.0/demo-1.0.jar" => Response::new(200, JAR),
            "/m2/com/example/demo/1.0/demo-1.0.pom" => Response::new(200, POM),
            "/m2/org/test/bom/1/bom-1.pom" => Response::new(200, BOM),
            _ => Response::new(404, ""),
        });
        let url = format!("http://{}/m2/", server.addr());
        let (good_jar, good_pom, other) = (
            BlobId::from_bytes(JAR),
            BlobId::from_bytes(POM),
            BlobId::from_bytes(b"other"),
        );
        for (jar_pin, pom_pin) in [
            (&good_jar, &good_pom),
            (&other, &good_pom),
            (&good_jar, &other),
        ] {
            let temp = tempdir().expect("temp dir");
            let store = Store::open(&temp.path().join("store")).expect("store");
            let (config, client) = fixture_config(temp.path(), Some(&url)).await;
            let mut package = pinned_package(jar_pin);
            package.repo_url.clone_from(&url);
            package.pom_sha256 = Some(pom_pin.clone());
            let platform = Platform::current().expect("platform");
            let mut lock = support_only_lock(&url, &BlobId::from_bytes(BOM));
            lock.platforms[0].artifacts = vec![package];
            // The client holds the pins of an earlier lock, as the one a sync
            // resolved with does; the pins of the lock being restored decide.
            let mut earlier = lock.clone();
            let earlier_pin = if jar_pin == &good_jar {
                &other
            } else {
                &good_jar
            };
            earlier.platforms[0].artifacts[0].checksums = vec![Digest::Sha256(earlier_pin.clone())];
            let client = client.with_lock_pins(&earlier);

            let results = ensure_artifacts(
                &store,
                &lock,
                &[RestoreContext {
                    config: &config,
                    client: &client,
                    platforms: &[platform],
                    trusted_repositories: &[],
                }],
            )
            .await
            .expect("per-package results");
            let [jar, bom] = &results[..] else {
                panic!("{results:?}")
            };
            bom.result
                .as_ref()
                .expect("the support POM matches its pin");
            if (jar_pin, pom_pin) == (&good_jar, &good_pom) {
                jar.result.as_ref().expect("the jar and its POM match");
                let pom = store.lookup_artifact(&demo("1.0", "pom")).await.unwrap();
                assert_eq!(pom, Some(BlobId::from_bytes(POM)));
                // The POMs a restore fetched resolve offline later.
                let offline = client.clone().with_lock_pins(&lock).with_offline(true);
                let repo = Repository::from(&config.repositories()[0]);
                let request = ArtifactRequest::new("com.example", "demo", "1.0");
                assert_eq!(&offline.fetch_pom(&repo, &request).await.unwrap()[..], POM);
            } else {
                let err = jar.result.as_ref().expect_err("a file does not match");
                assert!(
                    matches!(
                        err,
                        RepoError::ChecksumMismatch {
                            check: IntegritySource::LockPin,
                            ..
                        }
                    ),
                    "{err:?}"
                );
            }
        }
    }

    /// The cache holds other bytes for a POM the store holds as pinned, as
    /// after a repository served another build of it: a restore seeds the
    /// pinned bytes, so an offline resolution reads them.
    #[tokio::test]
    async fn a_pom_cached_with_other_bytes_is_seeded_with_the_pinned_ones() {
        let other = rv_maven_types::Sha256::from_bytes(b"<project/>");
        let spoil = format!(
            "UPDATE pom_cache_v3 SET content = CAST('<project/>' AS BLOB), sha256 = '{other}'"
        );
        restore_seeds_over(&spoil).await;
    }

    /// An expired copy of a pinned POM is renewed, as the per-POM seed does,
    /// so an online resolution reads it from the cache.
    #[tokio::test]
    async fn an_expired_cached_pom_is_seeded_again() {
        restore_seeds_over("UPDATE pom_cache_v3 SET expires_at = 0").await;
    }

    /// Restore twice, running `spoil` on the metadata cache in between, and
    /// check the second restore left a current copy of each pinned POM.
    async fn restore_seeds_over(spoil: &str) {
        use rv_lock::Platform;
        use rv_test_support::http::{Response, StubServer};

        const JAR: &[u8] = b"demo jar";
        const POM: &[u8] = b"<project><artifactId>demo</artifactId></project>";
        const BOM: &[u8] = b"<project><artifactId>bom</artifactId></project>";
        let server = StubServer::start(|req| match req.path.as_str() {
            "/m2/com/example/demo/1.0/demo-1.0.jar" => Response::new(200, JAR),
            "/m2/com/example/demo/1.0/demo-1.0.pom" => Response::new(200, POM),
            "/m2/org/test/bom/1/bom-1.pom" => Response::new(200, BOM),
            _ => Response::new(404, ""),
        });
        let url = format!("http://{}/m2/", server.addr());
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let (config, client) = fixture_config(temp.path(), Some(&url)).await;
        let mut package = pinned_package(&BlobId::from_bytes(JAR));
        package.repo_url.clone_from(&url);
        package.pom_sha256 = Some(BlobId::from_bytes(POM));
        let mut lock = support_only_lock(&url, &BlobId::from_bytes(BOM));
        lock.platforms[0].artifacts = vec![package];
        let client = client.with_lock_pins(&lock);
        let platforms = [Platform::current().expect("platform")];
        let contexts = [RestoreContext {
            config: &config,
            client: &client,
            platforms: &platforms,
            trusted_repositories: &[],
        }];
        for restored in ensure_artifacts(&store, &lock, &contexts)
            .await
            .expect("restore")
        {
            restored.result.expect("downloaded");
        }
        let cache = rusqlite::Connection::open(config.paths.metadata_db_path()).expect("cache");
        let rows = cache.execute(spoil, []).expect("spoil the cache");
        assert!(rows > 0, "the restore cached its POMs");
        for restored in ensure_artifacts(&store, &lock, &contexts)
            .await
            .expect("restore")
        {
            restored.result.expect("restored from the store");
        }
        // A later run's client, which has not read the POM yet.
        let offline = (RepoClient::new(&config).await.expect("client"))
            .with_lock_pins(&lock)
            .with_offline(true);
        let repo = Repository::from(&config.repositories()[0]);
        let request = ArtifactRequest::new("com.example", "demo", "1.0");
        assert_eq!(&offline.fetch_pom(&repo, &request).await.unwrap()[..], POM);
        let expired: i64 = (cache.query_row(
            "SELECT count(*) FROM pom_cache_v3 WHERE expires_at <= unixepoch()",
            [],
            |row| row.get(0),
        ))
        .expect("count expired rows");
        assert_eq!(expired, 0, "every pinned POM is cached afresh");
    }

    /// A SNAPSHOT parent or BOM is restored from the build the lock pins,
    /// not from whatever its metadata names now, and offline that build
    /// resolves although the cached metadata names another.
    #[tokio::test]
    async fn a_snapshot_support_pom_restores_its_pinned_build() {
        use rv_test_support::http::{Response, StubServer};
        use sha2::Digest as _;

        const BOM: &[u8] = b"<project><artifactId>bom</artifactId></project>";
        const METADATA: &str = "<metadata><version>1-SNAPSHOT</version><versioning><snapshot>\
            <timestamp>20230101.010101</timestamp><buildNumber>1</buildNumber></snapshot>\
            </versioning></metadata>";
        let server = StubServer::start(|req| match req.path.as_str() {
            "/m2/org/test/bom/1-SNAPSHOT/bom-1-20240101.010101-7.pom" => Response::new(200, BOM),
            "/m2/org/test/bom/1-SNAPSHOT/maven-metadata.xml" => Response::new(200, METADATA),
            "/m2/org/test/bom/1-SNAPSHOT/maven-metadata.xml.sha256" => {
                Response::new(200, hex::encode(sha2::Sha256::digest(METADATA)))
            }
            _ => Response::new(404, ""),
        });
        let url = format!("http://{}/m2/", server.addr());
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let (config, client) = fixture_config(temp.path(), Some(&url)).await;
        let repo = Repository::from(&config.repositories()[0]);
        let older = client
            .resolve_snapshot_version(&repo, &"org.test:bom:1-SNAPSHOT".parse().unwrap())
            .await
            .expect("metadata");
        assert_eq!(older.version, "1-20230101.010101-1");
        let mut lock = Lockfile::new();
        lock.platforms = support_only_lock(&url, &BlobId::from_bytes(BOM)).platforms;
        let mut pin = lock.platforms[0]
            .support_poms
            .remove("org.test:bom:1")
            .unwrap();
        pin.snapshot = rv_maven_types::SnapshotStamp::new("20240101.010101", 7);
        lock.platforms[0]
            .support_poms
            .insert("org.test:bom:1-SNAPSHOT".to_string(), pin);

        let results = ensure_artifacts(
            &store,
            &lock,
            &[RestoreContext {
                config: &config,
                client: &client,
                platforms: &[Platform::current().expect("platform")],
                trusted_repositories: &[],
            }],
        )
        .await
        .expect("per-package results");
        let [bom] = &results[..] else {
            panic!("{results:?}")
        };
        bom.result.as_ref().expect("the pinned build is restored");

        // Another platform pins a newer build that was never restored, and
        // a repository listed first never served either.
        let mut pins = lock.clone();
        let mut newer = pins.platforms[0].clone();
        newer.platform = another_platform(&pins.platforms[0].platform);
        let pin = newer
            .support_poms
            .get_mut("org.test:bom:1-SNAPSHOT")
            .unwrap();
        pin.snapshot = rv_maven_types::SnapshotStamp::new("20240101.010101", 8);
        pins.platforms.push(newer);
        let offline = client.with_lock_pins(&pins).with_offline(true);
        let request = ArtifactRequest::new("org.test", "bom", "1-SNAPSHOT");
        assert_eq!(&offline.fetch_pom(&repo, &request).await.unwrap()[..], BOM);
        let first = Repository::new(None, "https://first.example/m2/", true, true);
        let coord = "org.test:bom:1-SNAPSHOT".parse().unwrap();
        let unserved = offline.resolve_snapshot_version(&first, &coord).await;
        assert!(
            matches!(unserved, Err(RepoError::OfflineNotCached(_))),
            "{unserved:?}"
        );
    }

    /// Two platforms that record one parent under different repositories
    /// each resolve it offline after one restore, each repository's own
    /// copy cached for it. When lock verify restores it for one platform
    /// after the other platform's repository lost it, that copy does not
    /// stand in for the other. A non-unique SNAPSHOT parent resolves
    /// offline to its pinned file.
    #[tokio::test]
    async fn a_shared_support_pom_resolves_offline_on_every_platform() {
        for version in ["1", "1-SNAPSHOT"] {
            for one_by_one in [false, true] {
                check_shared_support_pom(version, one_by_one).await;
            }
        }
    }

    async fn check_shared_support_pom(version: &'static str, one_by_one: bool) {
        use rv_test_support::http::{Response, StubServer};

        const BOM: &[u8] = b"<project><artifactId>bom</artifactId></project>";
        let coord = format!("org.test:bom:{version}");
        let coord = coord.as_str();
        let serve = |serves: bool| {
            let pom = format!("/m2/org/test/bom/{version}/bom-{version}.pom");
            let metadata = format!("/m2/org/test/bom/{version}/maven-metadata.xml");
            let xml = format!("<metadata><version>{version}</version></metadata>");
            let sha1 = rv_maven_types::Sha1::from_bytes(xml.as_bytes()).to_string();
            StubServer::start(move |req| match req.path.as_str() {
                path if serves && path == pom => Response::new(200, BOM),
                path if serves && path == metadata => Response::new(200, xml.clone()),
                path if serves && path.strip_suffix(".sha1") == Some(&metadata) => {
                    Response::new(200, sha1.clone())
                }
                _ => Response::new(404, ""),
            })
        };
        let (first, second) = (serve(!one_by_one), serve(true));
        let url = |server: &StubServer| format!("http://{}/m2/", server.addr());
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let mut lock = support_only_lock(&url(&first), &BlobId::from_bytes(BOM));
        let poms = &mut lock.platforms[0].support_poms;
        let pin = poms.remove("org.test:bom:1").unwrap();
        poms.insert(coord.to_string(), pin);
        let mut mac = lock.platforms[0].clone();
        mac.platform = another_platform(&lock.platforms[0].platform);
        mac.support_poms.get_mut(coord).unwrap().repo_url = url(&second);
        lock.platforms.push(mac);
        let (linux_config, linux_client) = fixture_config(temp.path(), Some(&url(&first))).await;
        let (mac_config, mac_client) = fixture_config(temp.path(), Some(&url(&second))).await;
        let (linux_client, mac_client) = (
            linux_client.with_lock_pins(&lock),
            mac_client.with_lock_pins(&lock),
        );
        let linux = [lock.platforms[0].platform.clone()];
        let macos = [lock.platforms[1].platform.clone()];
        let contexts = [
            RestoreContext {
                config: &linux_config,
                client: &linux_client,
                platforms: &linux,
                trusted_repositories: &[],
            },
            RestoreContext {
                config: &mac_config,
                client: &mac_client,
                platforms: &macos,
                trusted_repositories: &[],
            },
        ];
        if one_by_one {
            let restore = |index: usize| {
                let pin = &lock.platforms[index].support_poms[coord];
                ensure_support_pom(&store, &contexts[index..=index], coord, pin)
            };
            restore(0).await.expect_err("the first repository lost it");
            restore(1).await.expect("the second serves it");
            restore(0)
                .await
                .expect_err("the second's copy does not stand in for the first's");
            return;
        } else {
            let results = ensure_artifacts(&store, &lock, &contexts)
                .await
                .expect("per-package results");
            assert!(
                results.iter().all(|result| result.result.is_ok()),
                "{results:?}"
            );
        }
        for (server, client, config) in [
            (&first, linux_client, linux_config),
            (&second, mac_client, mac_config),
        ] {
            let answered = server.answered();
            let repo = Repository::from(&config.repositories()[0]);
            let request = ArtifactRequest::new("org.test", "bom", version);
            let cached = client.with_offline(true).fetch_pom(&repo, &request).await;
            assert_eq!(&cached.unwrap()[..], BOM);
            assert_eq!(server.answered(), answered, "offline asks nothing");
        }
    }

    /// A row two platforms record under different repositories is indexed
    /// under each after one download, by one restore of both, or by
    /// `index_restored` after a restore for one, as lock verify does, so
    /// each platform's offline resolution finds it. Each repository's own
    /// POM is cached for it: another's copy is not its answer.
    #[tokio::test]
    async fn a_shared_row_is_indexed_for_every_platform() {
        for one_by_one in [false, true] {
            check_shared_row(one_by_one, [BOTH; 2]).await;
        }
    }

    /// The first platform's repository lost the row's files, and the
    /// second platform's restores them after the first one's search failed.
    /// The stored jar then serves the first platform too. The stored POM is
    /// the second repository's answer, not the first one's, so the first
    /// platform's offline resolution finds none.
    #[tokio::test]
    async fn a_row_another_platform_restores_is_restored_for_both() {
        let lost = Serves {
            jar: false,
            pom: false,
        };
        check_shared_row(false, [lost, BOTH]).await;
    }

    /// The first platform's repository lost the row's jar and the second
    /// one's its POM. The jar the second stores lets the first fetch the
    /// POM from its own repository, whose answer is not the second one's.
    #[tokio::test]
    async fn a_row_split_over_two_repositories_is_restored_for_both() {
        let (jar, pom) = (
            Serves {
                jar: true,
                pom: false,
            },
            Serves {
                jar: false,
                pom: true,
            },
        );
        check_shared_row(false, [pom, jar]).await;
    }

    /// A row whose file restored and whose POM failed asked for the POM
    /// already, so the checks after the restores do not ask again. The POM
    /// is missing: a repository that fails it another way is asked once
    /// more within the one ask.
    #[tokio::test]
    async fn a_failed_pom_is_asked_for_once() {
        use rv_test_support::http::{Response, StubServer};
        use std::sync::atomic::{AtomicUsize, Ordering};

        const JAR: &[u8] = b"demo jar";
        const POM: &[u8] = b"<project><artifactId>demo</artifactId></project>";
        let pom_requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&pom_requests);
        let server = StubServer::start(move |req| match req.path.as_str() {
            "/m2/com/example/demo/1.0/demo-1.0.jar" => Response::new(200, JAR),
            "/m2/com/example/demo/1.0/demo-1.0.pom" => {
                counted.fetch_add(1, Ordering::SeqCst);
                Response::new(404, "")
            }
            _ => Response::new(404, ""),
        });
        let url = format!("http://{}/m2/", server.addr());
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let mut row = pinned_package(&BlobId::from_bytes(JAR));
        row.repo_url = url.clone();
        row.pom_sha256 = Some(BlobId::from_bytes(POM));
        let mut lock = support_only_lock(&url, &BlobId::from_bytes(b"unused"));
        lock.platforms[0].support_poms.clear();
        lock.platforms[0].artifacts = vec![row];
        let (config, client) = fixture_config(temp.path(), Some(&url)).await;
        let client = client.with_lock_pins(&lock);
        let platforms = [lock.platforms[0].platform.clone()];
        let context = RestoreContext {
            config: &config,
            client: &client,
            platforms: &platforms,
            trusted_repositories: &[],
        };
        let results = ensure_artifacts(&store, &lock, &[context])
            .await
            .expect("per-package results");
        assert!(results[0].result.is_err(), "{results:?}");
        assert_eq!(pom_requests.load(Ordering::SeqCst), 1);
    }

    /// A row whose file fails after another platform's row for the same
    /// coordinate stored its bytes never asked for its POM, so the checks
    /// after the restores do.
    #[tokio::test]
    async fn a_row_failing_after_its_bytes_were_stored_asks_for_its_pom() {
        use rv_test_support::http::{Response, StubServer};

        const JAR: &[u8] = b"shared jar";
        const POM: &[u8] = b"<project><artifactId>slow</artifactId></project>";
        const SHA1_ONLY: &[u8] = b"sha1 jar";
        let servers = [
            StubServer::start(|req| match req.path.as_str() {
                "/m2/com/example/slow/1.0/slow-1.0.jar" => {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    Response::new(404, "")
                }
                "/m2/com/example/slow/1.0/slow-1.0.pom" => Response::new(200, POM),
                "/m2/com/example/sha/1.0/sha-1.0.jar" => Response::new(200, SHA1_ONLY),
                _ => Response::new(404, ""),
            }),
            StubServer::start(|req| match req.path.as_str() {
                "/m2/com/example/slow/1.0/slow-1.0.jar" => Response::new(200, JAR),
                "/m2/com/example/slow/1.0/slow-1.0.pom" => Response::new(200, POM),
                _ => Response::new(404, ""),
            }),
        ];
        let urls = servers
            .iter()
            .map(|server| format!("http://{}/m2/", server.addr()))
            .collect::<Vec<_>>();
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let row = |artifact: &str, url: &str| {
            let coord = ArtifactCoord::of(Gav::new("com.example", artifact, "1.0"), "jar", None);
            LockArtifact::new(coord, url)
        };
        let mut slow = row("slow", &urls[0]);
        slow.checksums = vec![Digest::Sha256(BlobId::from_bytes(JAR))];
        slow.pom_sha256 = Some(BlobId::from_bytes(POM));
        let mut sha1_only = row("sha", &urls[0]);
        sha1_only.checksums = vec![Digest::Sha1(rv_maven_types::Sha1::from_bytes(SHA1_ONLY))];
        let mut fast = row("slow", &urls[1]);
        fast.checksums = vec![Digest::Sha256(BlobId::from_bytes(JAR))];
        fast.pom_sha256 = Some(BlobId::from_bytes(POM));
        let mut lock = support_only_lock(&urls[0], &BlobId::from_bytes(b"unused"));
        lock.platforms[0].support_poms.clear();
        let template = lock.platforms[0].clone();
        lock.platforms = [
            ("linux-x86_64", vec![slow, sha1_only]),
            ("macos-aarch64", vec![fast]),
        ]
        .into_iter()
        .map(|(platform, rows)| {
            let mut entry = template.clone();
            entry.platform = platform.parse().unwrap();
            entry.artifacts = rows;
            entry
        })
        .collect();
        let mut fixtures = Vec::new();
        for url in &urls {
            let (config, client) = fixture_config(temp.path(), Some(url)).await;
            fixtures.push((config, client.with_lock_pins(&lock)));
        }
        fixtures[0].0.network.concurrency = 3;
        let platforms = (lock.platforms.iter())
            .map(|entry| [entry.platform.clone()])
            .collect::<Vec<_>>();
        let contexts = fixtures
            .iter()
            .zip(&platforms)
            .map(|((config, client), platforms)| RestoreContext {
                config,
                client,
                platforms,
                trusted_repositories: &[],
            })
            .collect::<Vec<_>>();
        let results = ensure_artifacts(&store, &lock, &contexts)
            .await
            .expect("per-package results");
        assert!(
            results.iter().all(|result| result.result.is_ok()),
            "{results:?}"
        );
        let asked =
            |file: &str| (servers[0].requests().iter()).any(|request| request.path.ends_with(file));
        assert!(asked("slow-1.0.jar") && asked("slow-1.0.pom"));
    }

    /// A POM one row fetches late has the bytes of another row's file, which
    /// it does not serve: no repository served them for that row's
    /// coordinate. The first platform's row `x` has the bytes of the
    /// second's POM, which only the second platform's repository serves;
    /// the third platform's serves the second's jar. A row pinned by SHA-1
    /// alone keeps every POM from downloading alongside.
    #[tokio::test]
    async fn a_pom_fetched_late_does_not_serve_another_coordinate() {
        use rv_test_support::http::{Response, StubServer};

        const JAR: &[u8] = b"demo jar";
        const POM: &[u8] = b"<project><artifactId>demo</artifactId></project>";
        const X_POM: &[u8] = b"<project><artifactId>x</artifactId></project>";
        const SHA1_ONLY: &[u8] = b"sha1 jar";
        let servers = [
            StubServer::start(|req| match req.path.as_str() {
                "/m2/com/example/x/1.0/x-1.0.pom" => Response::new(200, X_POM),
                "/m2/com/example/sha/1.0/sha-1.0.jar" => Response::new(200, SHA1_ONLY),
                _ => Response::new(404, ""),
            }),
            StubServer::start(|req| match req.path.as_str() {
                "/m2/com/example/demo/1.0/demo-1.0.pom" => Response::new(200, POM),
                _ => Response::new(404, ""),
            }),
            StubServer::start(|req| match req.path.as_str() {
                "/m2/com/example/demo/1.0/demo-1.0.jar" => Response::new(200, JAR),
                _ => Response::new(404, ""),
            }),
        ];
        let urls = servers
            .iter()
            .map(|server| format!("http://{}/m2/", server.addr()))
            .collect::<Vec<_>>();
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let row = |artifact: &str| {
            let coord = ArtifactCoord::of(Gav::new("com.example", artifact, "1.0"), "jar", None);
            LockArtifact::new(coord, &urls[0])
        };
        let mut x = row("x");
        x.checksums = vec![Digest::Sha256(BlobId::from_bytes(POM))];
        x.pom_sha256 = Some(BlobId::from_bytes(X_POM));
        let mut sha1_only = row("sha");
        sha1_only.checksums = vec![Digest::Sha1(rv_maven_types::Sha1::from_bytes(SHA1_ONLY))];
        let release = |url: &str| {
            let mut row = pinned_package(&BlobId::from_bytes(JAR));
            row.repo_url = url.to_string();
            row.pom_sha256 = Some(BlobId::from_bytes(POM));
            row
        };
        let mut lock = support_only_lock(&urls[0], &BlobId::from_bytes(b"unused"));
        lock.platforms[0].support_poms.clear();
        let template = lock.platforms[0].clone();
        lock.platforms = ["linux-x86_64", "macos-aarch64", "windows-x86_64"]
            .into_iter()
            .zip([
                vec![x, sha1_only],
                vec![release(&urls[1])],
                vec![release(&urls[2])],
            ])
            .map(|(platform, rows)| {
                let mut entry = template.clone();
                entry.platform = platform.parse().unwrap();
                entry.artifacts = rows;
                entry
            })
            .collect();
        let mut fixtures = Vec::new();
        for url in &urls {
            let (config, client) = fixture_config(temp.path(), Some(url)).await;
            fixtures.push((config, client.with_lock_pins(&lock)));
        }
        fixtures[0].0.network.concurrency = 1;
        let platforms = (lock.platforms.iter())
            .map(|entry| [entry.platform.clone()])
            .collect::<Vec<_>>();
        let contexts = fixtures
            .iter()
            .zip(&platforms)
            .map(|((config, client), platforms)| RestoreContext {
                config,
                client,
                platforms,
                trusted_repositories: &[],
            })
            .collect::<Vec<_>>();
        let results = ensure_artifacts(&store, &lock, &contexts)
            .await
            .expect("per-package results");
        assert!(
            matches!(results[0].result, Err(RepoError::NotFound(_))),
            "{results:?}"
        );
        assert!(
            results[1..].iter().all(|result| result.result.is_ok()),
            "{results:?}"
        );
    }

    /// The first platform's repository lost a `pom` row's file, which the
    /// second platform reads as a BOM from its own repository after the
    /// rows. The stored BOM then serves the row too.
    #[tokio::test]
    async fn a_support_pom_another_platform_restores_serves_a_failed_row() {
        use rv_test_support::http::{Response, StubServer};

        const POM: &[u8] = b"<project><artifactId>demo</artifactId></project>";
        let (first, second) = (
            StubServer::start(|_| Response::new(404, "")),
            StubServer::start(|req| match req.path.as_str() {
                "/m2/com/example/demo/1.0/demo-1.0.pom" => Response::new(200, POM),
                _ => Response::new(404, ""),
            }),
        );
        let url = |server: &StubServer| format!("http://{}/m2/", server.addr());
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let pom = BlobId::from_bytes(POM);
        let mut row = LockArtifact::new(demo("1.0", "pom"), url(&first));
        row.checksums = vec![Digest::Sha256(pom.clone())];
        row.pom_sha256 = Some(pom.clone());
        let mut lock = support_only_lock(&url(&first), &pom);
        lock.platforms[0].support_poms.clear();
        let mut mac = lock.platforms[0].clone();
        lock.platforms[0].artifacts = vec![row];
        mac.platform = another_platform(&lock.platforms[0].platform);
        mac.support_poms.insert(
            "com.example:demo:1.0".to_string(),
            rv_lock::SupportPom::new(url(&second), pom),
        );
        lock.platforms.push(mac);
        let (mut linux_config, linux_client) =
            fixture_config(temp.path(), Some(&url(&first))).await;
        linux_config.network.concurrency = 1;
        let (mac_config, mac_client) = fixture_config(temp.path(), Some(&url(&second))).await;
        let (linux_client, mac_client) = (
            linux_client.with_lock_pins(&lock),
            mac_client.with_lock_pins(&lock),
        );
        let linux = [lock.platforms[0].platform.clone()];
        let macos = [lock.platforms[1].platform.clone()];
        let contexts = [
            RestoreContext {
                config: &linux_config,
                client: &linux_client,
                platforms: &linux,
                trusted_repositories: &[],
            },
            RestoreContext {
                config: &mac_config,
                client: &mac_client,
                platforms: &macos,
                trusted_repositories: &[],
            },
        ];
        let results = ensure_artifacts(&store, &lock, &contexts)
            .await
            .expect("per-package results");
        assert!(
            results.iter().all(|result| result.result.is_ok()),
            "{results:?}"
        );
    }

    /// Two support POMs with the same bytes, the first lost by its
    /// platform's repository and the second served by the other platform's.
    /// The stored bytes do not serve the first: no repository served them
    /// for its coordinate.
    #[tokio::test]
    async fn a_support_pom_restored_later_does_not_serve_another_coordinate() {
        use rv_test_support::http::{Response, StubServer};

        const POM: &[u8] = b"<project><artifactId>bom</artifactId></project>";
        let (first, second) = (
            StubServer::start(|_| Response::new(404, "")),
            StubServer::start(|req| match req.path.as_str() {
                "/m2/com/example/bom/2/bom-2.pom" => Response::new(200, POM),
                _ => Response::new(404, ""),
            }),
        );
        let url = |server: &StubServer| format!("http://{}/m2/", server.addr());
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let pom = BlobId::from_bytes(POM);
        let mut lock = support_only_lock(&url(&first), &pom);
        lock.platforms[0].support_poms.clear();
        lock.platforms[0].support_poms.insert(
            "com.example:bom:1".to_string(),
            rv_lock::SupportPom::new(url(&first), pom.clone()),
        );
        let mut mac = lock.platforms[0].clone();
        mac.platform = another_platform(&lock.platforms[0].platform);
        mac.support_poms.clear();
        mac.support_poms.insert(
            "com.example:bom:2".to_string(),
            rv_lock::SupportPom::new(url(&second), pom),
        );
        lock.platforms.push(mac);
        let (mut linux_config, linux_client) =
            fixture_config(temp.path(), Some(&url(&first))).await;
        linux_config.network.concurrency = 1;
        let (mac_config, mac_client) = fixture_config(temp.path(), Some(&url(&second))).await;
        let (linux_client, mac_client) = (
            linux_client.with_lock_pins(&lock),
            mac_client.with_lock_pins(&lock),
        );
        let linux = [lock.platforms[0].platform.clone()];
        let macos = [lock.platforms[1].platform.clone()];
        let contexts = [
            RestoreContext {
                config: &linux_config,
                client: &linux_client,
                platforms: &linux,
                trusted_repositories: &[],
            },
            RestoreContext {
                config: &mac_config,
                client: &mac_client,
                platforms: &macos,
                trusted_repositories: &[],
            },
        ];
        let results = ensure_artifacts(&store, &lock, &contexts)
            .await
            .expect("per-package results");
        assert_eq!(results.len(), 2, "{results:?}");
        assert!(
            matches!(results[0].result, Err(RepoError::NotFound(_))),
            "{results:?}"
        );
        assert!(results[1].result.is_ok(), "{results:?}");
    }

    /// A `-SNAPSHOT` support POM with its build and one that names the
    /// build's timestamped version are one file, restored apart. The first
    /// one's repository lost it and the second one's serves it; the stored
    /// file then serves the first too.
    #[tokio::test]
    async fn a_snapshot_support_pom_serves_its_timestamped_spelling() {
        use rv_test_support::http::{Response, StubServer};

        const POM: &[u8] = b"<project><artifactId>bom</artifactId></project>";
        let (first, second) = (
            StubServer::start(|_| Response::new(404, "")),
            StubServer::start(|req| match req.path.as_str() {
                "/m2/com/example/bom/1-SNAPSHOT/bom-1-20240101.010101-7.pom" => {
                    Response::new(200, POM)
                }
                _ => Response::new(404, ""),
            }),
        );
        let url = |server: &StubServer| format!("http://{}/m2/", server.addr());
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let pom = BlobId::from_bytes(POM);
        let mut lock = support_only_lock(&url(&first), &pom);
        lock.platforms[0].support_poms.clear();
        lock.platforms[0].support_poms.insert(
            "com.example:bom:1-20240101.010101-7".to_string(),
            rv_lock::SupportPom::new(url(&first), pom.clone()),
        );
        let mut mac = lock.platforms[0].clone();
        mac.platform = another_platform(&lock.platforms[0].platform);
        mac.support_poms.clear();
        let mut pin = rv_lock::SupportPom::new(url(&second), pom);
        pin.snapshot = rv_maven_types::SnapshotStamp::new("20240101.010101", 7);
        mac.support_poms
            .insert("com.example:bom:1-SNAPSHOT".to_string(), pin);
        lock.platforms.push(mac);
        let (mut linux_config, linux_client) =
            fixture_config(temp.path(), Some(&url(&first))).await;
        linux_config.network.concurrency = 1;
        let (mac_config, mac_client) = fixture_config(temp.path(), Some(&url(&second))).await;
        let (linux_client, mac_client) = (
            linux_client.with_lock_pins(&lock),
            mac_client.with_lock_pins(&lock),
        );
        let linux = [lock.platforms[0].platform.clone()];
        let macos = [lock.platforms[1].platform.clone()];
        let contexts = [
            RestoreContext {
                config: &linux_config,
                client: &linux_client,
                platforms: &linux,
                trusted_repositories: &[],
            },
            RestoreContext {
                config: &mac_config,
                client: &mac_client,
                platforms: &macos,
                trusted_repositories: &[],
            },
        ];
        let results = ensure_artifacts(&store, &lock, &contexts)
            .await
            .expect("per-package results");
        assert_eq!(results.len(), 2, "{results:?}");
        assert!(
            results.iter().all(|result| result.result.is_ok()),
            "{results:?}"
        );
        assert!(
            (first.requests().iter()).any(|request| request.path.ends_with(".pom")),
            "the first repository is asked first"
        );
    }

    #[tokio::test]
    async fn a_shared_snapshot_restores_each_file_and_pom_origin() {
        const JAR: &[u8] = b"demo jar";
        const POM: &[u8] = b"<project><artifactId>demo</artifactId></project>";
        for separate_pom in [false, true] {
            for index_only in [false, true] {
                let urls: Vec<_> = (0..4)
                    .map(|index| format!("https://repo{index}.example/m2/"))
                    .collect();
                let temp = tempdir().unwrap();
                let store = Store::open(&temp.path().join("store")).unwrap();
                let mut row =
                    snapshot_build(&BlobId::from_bytes(JAR), "1.0-20261025.010101-1", &urls[0]);
                row.other_repo_urls = vec![urls[1].clone()];
                row.pom_sha256 = Some(BlobId::from_bytes(POM));
                if separate_pom {
                    row.pom_repo_urls = urls[2..].to_vec();
                }
                let mut lock = support_only_lock(&urls[0], &BlobId::from_bytes(b"unused"));
                lock.platforms[0].support_poms.clear();
                lock.platforms[0].artifacts = vec![row.clone()];
                let repos = urls
                    .iter()
                    .enumerate()
                    .map(|(index, url)| {
                        let mut repo =
                            rv_config::RepoConfig::new(Some(&format!("repo{index}")), url);
                        repo.snapshots = Some(true);
                        repo
                    })
                    .collect();
                let mut config = Config::for_testing_with_repos(
                    temp.path().into(),
                    rv_config::ResolvedPaths::for_testing().unwrap(),
                    repos,
                );
                config.network.retries = 0;
                let client = RepoClient::new(&config)
                    .await
                    .unwrap()
                    .with_lock_pins(&lock)
                    .with_offline(true);
                let platforms = [lock.platforms[0].platform.clone()];
                let context = RestoreContext {
                    config: &config,
                    client: &client,
                    platforms: &platforms,
                    trusted_repositories: &[],
                };
                // Another context supplied the blobs from another configured
                // repository, but no index row or POM cache.
                let jar = store.put_bytes(JAR).await.unwrap();
                let pom = store.put_bytes(POM).await.unwrap();
                served_from(&store, &row.coord(), &jar, &urls[3]).await;
                let pom_key = ArtifactCoord::of(row.pom_gav(), "pom", None);
                served_from(&store, &pom_key, &pom, &urls[3]).await;
                if index_only {
                    index_restored(&store, &lock, &context, &row).await.unwrap();
                } else {
                    let results = ensure_artifacts(&store, &lock, &[context]).await.unwrap();
                    assert!(
                        results.iter().all(|result| result.result.is_ok()),
                        "{results:?}"
                    );
                }
                for index in 0..4 {
                    let repo = Repository::from(&config.repositories()[index]);
                    let endpoint = client.effective_repository(&repo);
                    if index < 2 {
                        assert_eq!(
                            store
                                .lookup_artifact_from(
                                    &row.coord(),
                                    &repo.url,
                                    &endpoint.url,
                                    true,
                                    true
                                )
                                .await
                                .unwrap(),
                            Some(BlobId::from_bytes(JAR)),
                            "file origin {index}, index only: {index_only}"
                        );
                    }
                    let offline = client.clone().with_offline(true);
                    let request =
                        ArtifactRequest::from(&ArtifactCoord::of(row.pom_gav(), "pom", None));
                    // Offline, a POM origin that did not serve the POM
                    // cannot be asked for its own copy, and another's is
                    // not cached as its.
                    let cached = offline.fetch_pom(&repo, &request).await;
                    if separate_pom && index == 3 {
                        assert_eq!(
                            &cached.unwrap()[..],
                            POM,
                            "POM origin {index}, index only: {index_only}"
                        );
                    } else {
                        assert!(cached.is_err(), "POM cached under origin {index}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn a_secondary_file_origin_and_a_separate_pom_origin_can_restore_a_cold_store() {
        const JAR: &[u8] = b"demo jar";
        const POM: &[u8] = b"<project><artifactId>demo</artifactId></project>";
        let temp = tempdir().unwrap();
        let repos: Vec<_> = ["files", "poms"]
            .into_iter()
            .map(|id| {
                let root = temp.path().join(id);
                let dir = root.join("com/example/demo/1.0-SNAPSHOT");
                std::fs::create_dir_all(&dir).unwrap();
                let (extension, bytes) = if id == "files" {
                    ("jar", JAR)
                } else {
                    ("pom", POM)
                };
                std::fs::write(
                    dir.join(format!("demo-1.0-20261025.010101-1.{extension}")),
                    bytes,
                )
                .unwrap();
                let mut repo = file_repo(id, &root);
                repo.snapshots = Some(true);
                repo
            })
            .collect();
        let config = Config::for_testing_with_repos(
            temp.path().into(),
            rv_config::ResolvedPaths::for_testing().unwrap(),
            repos,
        );
        let client = RepoClient::new(&config).await.unwrap();
        let store = Store::open(&temp.path().join("store")).unwrap();
        let origins = LockOrigins::for_root(temp.path());
        let mut row = snapshot_build(&BlobId::from_bytes(JAR), "1.0-20261025.010101-1", GONE);
        row.other_repo_urls = vec![origins.declared(&config.repositories()[0].url).unwrap()];
        row.pom_repo_urls = vec![origins.declared(&config.repositories()[1].url).unwrap()];
        row.pom_sha256 = Some(BlobId::from_bytes(POM));
        let mut lock = support_only_lock(GONE, &BlobId::from_bytes(b"unused"));
        lock.platforms[0].support_poms.clear();
        lock.platforms[0].artifacts = vec![row.clone()];
        let platforms = [lock.platforms[0].platform.clone()];
        let context = RestoreContext {
            config: &config,
            client: &client,
            platforms: &platforms,
            trusted_repositories: &[],
        };
        let results = ensure_artifacts(&store, &lock, &[context]).await.unwrap();
        assert!(
            results.iter().all(|result| result.result.is_ok()),
            "{results:?}"
        );
        assert_eq!(
            store.lookup_artifact(&row.coord()).await.unwrap(),
            Some(BlobId::from_bytes(JAR))
        );
        let pom = ArtifactCoord::of(row.pom_gav(), "pom", None);
        assert_eq!(
            store.lookup_artifact(&pom).await.unwrap(),
            Some(BlobId::from_bytes(POM))
        );
    }

    /// A SNAPSHOT package's POM waits for its artifact, whose build may
    /// depend on whether the POM is cached, so a failed artifact leaves it.
    #[tokio::test]
    async fn a_snapshot_pom_waits_for_its_artifact() {
        waits_for_the_artifact(|files, poms| {
            const POM: &[u8] = b"<project><artifactId>demo</artifactId></project>";
            let mut row = LockArtifact::new(demo("1.0-SNAPSHOT", "jar"), files);
            row.pom_sha256 = Some(BlobId::from_bytes(POM));
            row.pom_repo_urls = vec![poms.to_owned()];
            (row, None)
        })
        .await;
    }

    /// So does a SNAPSHOT support POM, which a SNAPSHOT package's build may
    /// depend on likewise.
    #[tokio::test]
    async fn a_snapshot_support_pom_waits_for_the_packages() {
        waits_for_the_artifact(|files, poms| {
            let row = LockArtifact::new(demo("1.0", "jar"), files);
            let bom = rv_lock::SupportPom::new(poms, BlobId::from_bytes(b"bom"));
            (row, Some(("org.test:bom:1-SNAPSHOT", bom)))
        })
        .await;
    }

    /// Restore a package whose artifact fails slowly, and check that nothing
    /// reached the repository serving POMs before the artifact's answered.
    async fn waits_for_the_artifact(
        lock_rows: impl FnOnce(&str, &str) -> (LockArtifact, Option<(&'static str, SupportPom)>),
    ) {
        use rv_test_support::http::{Response, StubServer};
        use std::sync::atomic::{AtomicBool, Ordering};

        let answered = Arc::new(AtomicBool::new(false));
        let early = Arc::new(AtomicBool::new(false));
        let files = StubServer::start({
            let answered = Arc::clone(&answered);
            move |_| {
                std::thread::sleep(std::time::Duration::from_millis(300));
                answered.store(true, Ordering::SeqCst);
                Response::new(404, "")
            }
        });
        let poms = StubServer::start({
            let early = Arc::clone(&early);
            move |_| {
                if !answered.load(Ordering::SeqCst) {
                    early.store(true, Ordering::SeqCst);
                }
                Response::new(404, "")
            }
        });
        let url = |server: &StubServer| format!("http://{}/m2/", server.addr());
        let repos = [("files", &files), ("poms", &poms)]
            .into_iter()
            .map(|(id, server)| {
                let mut repo = rv_config::RepoConfig::new(Some(id), &url(server));
                repo.snapshots = Some(true);
                repo
            })
            .collect();
        let temp = tempdir().unwrap();
        let config = Config::for_testing_with_repos(
            temp.path().into(),
            rv_config::ResolvedPaths::for_testing().unwrap(),
            repos,
        );
        let store = Store::open(&temp.path().join("store")).unwrap();
        let (mut row, support) = lock_rows(&url(&files), &url(&poms));
        row.checksums = vec![Digest::Sha256(BlobId::from_bytes(b"never published"))];
        let mut lock = support_only_lock(&url(&files), &BlobId::from_bytes(b"unused"));
        lock.platforms[0].support_poms = support
            .map(|(coord, pom)| (coord.to_owned(), pom))
            .into_iter()
            .collect();
        lock.platforms[0].artifacts = vec![row];
        let client = RepoClient::new(&config)
            .await
            .unwrap()
            .with_lock_pins(&lock);
        let platforms = [lock.platforms[0].platform.clone()];
        let context = RestoreContext {
            config: &config,
            client: &client,
            platforms: &platforms,
            trusted_repositories: &[],
        };
        let results = ensure_artifacts(&store, &lock, &[context]).await.unwrap();
        results[0].result.as_ref().expect_err("never published");
        assert!(
            !early.load(Ordering::SeqCst),
            "a POM was fetched beside the artifact"
        );
    }

    #[tokio::test]
    async fn pinned_restore_does_not_fall_back_after_rate_limits_or_server_errors() {
        use rv_test_support::http::{Response, StubServer};

        for status in [429, 500, 502, 503, 504] {
            let first = StubServer::start(move |_| Response::new(status, ""));
            let second = StubServer::start(|_| Response::new(200, "demo jar"));
            let temp = tempdir().unwrap();
            let repos = [&first, &second]
                .iter()
                .enumerate()
                .map(|(index, server)| {
                    rv_config::RepoConfig::new(
                        Some(&format!("repo{index}")),
                        &format!("http://{}/m2/", server.addr()),
                    )
                })
                .collect();
            let mut config = Config::for_testing_with_repos(
                temp.path().into(),
                rv_config::ResolvedPaths::for_testing().unwrap(),
                repos,
            );
            config.network.retries = 0;
            let client = RepoClient::new(&config).await.unwrap();
            let store = Store::open(&temp.path().join("store")).unwrap();
            let context = RestoreContext {
                config: &config,
                client: &client,
                platforms: &[],
                trusted_repositories: &[],
            };
            let pin = Digest::Sha256(BlobId::from_bytes(b"demo jar"));
            let err = restore_pinned(
                &store,
                &context,
                [config.repositories()[0].url.as_str()],
                &demo("1.0", "jar"),
                &pin,
            )
            .await
            .unwrap_err();
            assert_eq!(err.status_code(), Some(status));
            assert_eq!(second.answered(), 0, "status {status}");
        }
    }

    /// Which of the row's files each platform's repository still serves.
    #[derive(Clone, Copy)]
    struct Serves {
        jar: bool,
        pom: bool,
    }

    const BOTH: Serves = Serves {
        jar: true,
        pom: true,
    };

    async fn check_shared_row(one_by_one: bool, serves: [Serves; 2]) {
        use rv_test_support::http::{Response, StubServer};

        const JAR: &[u8] = b"demo jar";
        const POM: &[u8] = b"<project><artifactId>demo</artifactId></project>";
        let serve = |serves: Serves| {
            StubServer::start(move |req| match req.path.as_str() {
                "/m2/com/example/demo/1.0/demo-1.0.jar" if serves.jar => Response::new(200, JAR),
                "/m2/com/example/demo/1.0/demo-1.0.pom" if serves.pom => Response::new(200, POM),
                _ => Response::new(404, ""),
            })
        };
        let (first, second) = (serve(serves[0]), serve(serves[1]));
        let url = |server: &StubServer| format!("http://{}/m2/", server.addr());
        let temp = tempdir().expect("temp dir");
        let store = Store::open(&temp.path().join("store")).expect("store");
        let row = |repo_url: String| {
            let mut row = pinned_package(&BlobId::from_bytes(JAR));
            row.repo_url = repo_url;
            row.pom_sha256 = Some(BlobId::from_bytes(POM));
            row
        };
        let mut lock = support_only_lock(&url(&first), &BlobId::from_bytes(b"unused"));
        lock.platforms[0].support_poms.clear();
        lock.platforms[0].artifacts = vec![row(url(&first))];
        let mut mac = lock.platforms[0].clone();
        mac.platform = another_platform(&lock.platforms[0].platform);
        mac.artifacts = vec![row(url(&second))];
        lock.platforms.push(mac);
        let (mut linux_config, linux_client) =
            fixture_config(temp.path(), Some(&url(&first))).await;
        // One restore at a time, in lock order: the first platform's search
        // fails before the second one's starts.
        linux_config.network.concurrency = 1;
        let (mac_config, mac_client) = fixture_config(temp.path(), Some(&url(&second))).await;
        // lock verify's clients carry the pins, as ensure_artifacts adds them.
        let (linux_client, mac_client) = (
            linux_client.with_lock_pins(&lock),
            mac_client.with_lock_pins(&lock),
        );
        let linux = [lock.platforms[0].platform.clone()];
        let macos = [lock.platforms[1].platform.clone()];
        let contexts = [
            RestoreContext {
                config: &linux_config,
                client: &linux_client,
                platforms: &linux,
                trusted_repositories: &[],
            },
            RestoreContext {
                config: &mac_config,
                client: &mac_client,
                platforms: &macos,
                trusted_repositories: &[],
            },
        ];
        let restored = if one_by_one {
            &contexts[..1]
        } else {
            &contexts[..]
        };
        let results = ensure_artifacts(&store, &lock, restored)
            .await
            .expect("per-package results");
        assert!(
            results.iter().all(|result| result.result.is_ok()),
            "{results:?}"
        );
        if one_by_one {
            let mac_row = &lock.platforms[1].artifacts[0];
            index_restored(&store, &lock, &contexts[1], mac_row)
                .await
                .unwrap();
            assert_eq!(second.answered(), 1, "the POM only");
        }

        for (config, client, server, own) in [
            (&linux_config, &linux_client, &first, serves[0]),
            (&mac_config, &mac_client, &second, serves[1]),
        ] {
            let repo = Repository::from(&config.repositories()[0]);
            let endpoint = client.effective_repository(&repo);
            let indexed = store
                .lookup_artifact_from(&demo("1.0", "jar"), &repo.url, &endpoint.url, true, true)
                .await
                .unwrap();
            assert_eq!(indexed, Some(BlobId::from_bytes(JAR)), "{}", repo.url);
            let answered = server.answered();
            let offline = client.clone().with_lock_pins(&lock).with_offline(true);
            let request = ArtifactRequest::new("com.example", "demo", "1.0");
            let pom = offline.fetch_pom(&repo, &request).await;
            if own.pom {
                assert_eq!(&pom.unwrap()[..], POM);
            } else {
                assert!(
                    matches!(pom, Err(RepoError::OfflineNotCached(_))),
                    "{pom:?}"
                );
            }
            assert_eq!(server.answered(), answered);
        }
    }

    fn file_repo(id: &str, root: &std::path::Path) -> rv_config::RepoConfig {
        let url = url::Url::from_directory_path(root).unwrap();
        let mut repo = rv_config::RepoConfig::new(Some(id), url.as_ref());
        repo.releases = Some(true);
        repo.snapshots = Some(false);
        repo
    }

    fn publish_pom(root: &std::path::Path, bytes: &[u8]) {
        let dir = root.join("org/test/bom/1");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bom-1.pom"), bytes).unwrap();
    }

    /// A platform other than `platform`, which is the host's in
    /// [`support_only_lock`], for a second platform section of a lock.
    fn another_platform(platform: &Platform) -> Platform {
        let other = match platform.to_string().as_str() {
            "macos-aarch64" => "linux-x86_64",
            _ => "macos-aarch64",
        };
        other.parse().unwrap()
    }

    fn support_only_lock(repo_url: &str, sha256: &BlobId) -> Lockfile {
        let mut lock = Lockfile::new();
        lock.platforms = vec![rv_lock::LockPlatform::single_module(
            Platform::current().expect("platform"),
            Gav::new("com.example", "root", "1"),
            "pom",
            Vec::new(),
        )];
        lock.platforms[0].support_poms.insert(
            "org.test:bom:1".to_string(),
            rv_lock::SupportPom::new(repo_url, sha256.clone()),
        );
        lock
    }

    const GONE: &str = "https://gone.example/maven2/";

    struct SupportFixture {
        _temp: tempfile::TempDir,
        store: Store,
        config: Config,
        client: RepoClient,
        pinned: BlobId,
        platforms: Vec<Platform>,
    }

    impl SupportFixture {
        fn origin(&self, id: &str) -> String {
            let repo = (self.config.repositories().iter())
                .find(|repo| repo.id.as_deref() == Some(id))
                .expect("configured");
            LockOrigins::for_root(&self.config.project_root)
                .declared(&repo.url)
                .expect("recordable")
        }

        fn context(&self) -> RestoreContext<'_> {
            RestoreContext {
                config: &self.config,
                client: &self.client,
                platforms: &self.platforms,
                trusted_repositories: &[],
            }
        }
    }

    /// Two file repositories: `stale` serves other bytes for the BOM,
    /// `current` the pinned ones. `configure` picks the configured list.
    async fn support_fixture_with(
        configure: impl FnOnce(
            rv_config::RepoConfig,
            rv_config::RepoConfig,
        ) -> Vec<rv_config::RepoConfig>,
    ) -> SupportFixture {
        let temp = tempdir().unwrap();
        let stale = temp.path().join("stale");
        let current = temp.path().join("current");
        let pinned_bytes = b"<project><artifactId>bom</artifactId></project>";
        publish_pom(&stale, b"<project><!-- republished --></project>");
        publish_pom(&current, pinned_bytes);
        let paths = rv_config::ResolvedPaths::for_testing().expect("paths");
        let mut config = Config::for_testing_with_repos(
            temp.path().to_path_buf(),
            paths,
            configure(file_repo("stale", &stale), file_repo("current", &current)),
        );
        config.network.retries = 0;
        let client = RepoClient::new(&config).await.expect("client");
        let store = Store::open(&temp.path().join("store")).unwrap();
        SupportFixture {
            _temp: temp,
            store,
            config,
            client,
            pinned: BlobId::from_bytes(pinned_bytes),
            platforms: vec![Platform::current().expect("platform")],
        }
    }

    async fn support_fixture() -> SupportFixture {
        support_fixture_with(|stale, current| vec![stale, current]).await
    }

    fn bom_key() -> ArtifactCoord {
        ArtifactCoord::new("org.test", "bom", "1", "pom", None)
    }

    async fn ensure(fixture: &SupportFixture, lock: &Lockfile) -> Vec<DownloadResult> {
        let results = ensure_artifacts(&fixture.store, lock, &[fixture.context()])
            .await
            .expect("ensure artifacts");
        assert_eq!(results.len(), 1);
        results
    }

    /// A recorded repository that now serves other bytes fails with the
    /// mismatch and stores nothing, though the next one serves the pinned
    /// bytes, and an origin no configuration declares is asked nothing.
    #[tokio::test]
    async fn support_poms_are_found_by_their_pin() {
        let fixture = support_fixture().await;
        let lock = support_only_lock(&fixture.origin("stale"), &fixture.pinned);
        let results = ensure(&fixture, &lock).await;
        let err = results[0].result.as_ref().expect_err("other bytes");
        assert!(matches!(err, RepoError::ChecksumMismatch { .. }), "{err:?}");
        assert_eq!(
            fixture.store.lookup_artifact(&bom_key()).await.unwrap(),
            None
        );

        let fixture = support_fixture().await;
        let results = ensure(&fixture, &support_only_lock(GONE, &fixture.pinned)).await;
        let err = results[0].result.as_ref().expect_err("undeclared");
        assert!(
            err.to_string().contains("no configuration or POM declares"),
            "{err}"
        );

        let fixture = support_fixture().await;
        let never = BlobId::from_bytes(b"never published");
        let results = ensure(
            &fixture,
            &support_only_lock(&fixture.origin("stale"), &never),
        )
        .await;
        let err = results[0].result.as_ref().expect_err("pin mismatch");
        assert!(
            matches!(err, RepoError::ChecksumMismatch { subject, .. } if &**subject == "org.test:bom:1:pom"),
            "{err:?}"
        );
        assert_eq!(
            fixture.store.lookup_artifact(&bom_key()).await.unwrap(),
            None
        );
    }

    /// A file the recorded repository lacks is restored from another
    /// repository that has the pinned bytes, as Maven searches every
    /// repository for a file. A repository that serves other bytes ends the
    /// search, whether its checksum file matches them or not: an edited pin
    /// must not pick its bytes from whichever repository happens to match
    /// it.
    #[tokio::test]
    async fn rows_fall_back_only_past_a_repository_without_the_file() {
        const JAR: &[u8] = b"demo jar";
        const POM: &[u8] = b"<project>resolved</project>";
        const OTHER: &[u8] = b"other bytes";
        let publish = |root: &std::path::Path, files: &[(&str, &[u8])]| {
            let dir = root.join("com/example/demo/1.0");
            std::fs::create_dir_all(&dir).unwrap();
            for (name, bytes) in files {
                std::fs::write(dir.join(name), bytes).unwrap();
                let sha1 = rv_maven_types::Sha1::from_bytes(bytes);
                std::fs::write(dir.join(format!("{name}.sha1")), sha1.as_str()).unwrap();
            }
        };
        // The extension `first` serves other bytes for, if any, and whether
        // its checksum file names the pinned bytes instead or cannot be read.
        for (first, other, sidecar) in [
            (vec![("demo-1.0.pom", POM)], None, None),
            (
                vec![("demo-1.0.jar", OTHER), ("demo-1.0.pom", POM)],
                Some("jar"),
                None,
            ),
            (
                vec![("demo-1.0.jar", JAR), ("demo-1.0.pom", OTHER)],
                Some("pom"),
                None,
            ),
            (
                vec![("demo-1.0.jar", JAR), ("demo-1.0.pom", OTHER)],
                Some("pom"),
                Some("stale"),
            ),
            (
                vec![("demo-1.0.jar", JAR), ("demo-1.0.pom", OTHER)],
                Some("pom"),
                Some("unreadable"),
            ),
        ] {
            let temp = tempdir().unwrap();
            publish(&temp.path().join("first"), &first);
            let sha1 = temp
                .path()
                .join("first/com/example/demo/1.0/demo-1.0.pom.sha1");
            match sidecar {
                Some("stale") => {
                    std::fs::write(&sha1, rv_maven_types::Sha1::from_bytes(POM).as_str()).unwrap();
                }
                Some(_) => {
                    std::fs::remove_file(&sha1).unwrap();
                    std::fs::create_dir(&sha1).unwrap();
                }
                None => {}
            }
            publish(
                &temp.path().join("second"),
                &[("demo-1.0.jar", JAR), ("demo-1.0.pom", POM)],
            );
            let repos = ["first", "second"].map(|id| file_repo(id, &temp.path().join(id)));
            let paths = rv_config::ResolvedPaths::for_testing().unwrap();
            let config = Config::for_testing_with_repos(temp.path().into(), paths, repos.into());
            let client = RepoClient::new(&config).await.unwrap();
            let store = Store::open(&temp.path().join("store")).unwrap();
            let origin = LockOrigins::for_root(temp.path())
                .declared(&config.repositories()[0].url)
                .unwrap();
            let mut package = LockArtifact::new(demo("1.0", "jar"), origin);
            package.checksums = vec![Digest::Sha256(BlobId::from_bytes(JAR))];
            package.pom_sha256 = Some(BlobId::from_bytes(POM));
            let pom_pins = PomPins::from([(package.pom_gav(), BlobId::from_bytes(POM))]);

            let result = sync(&config, &store, &client, &pom_pins, &package).await;
            if other.is_none() {
                result.expect("restored from `second`");
            } else {
                let err = result.expect_err("`first` serves other bytes");
                assert!(matches!(err, RepoError::ChecksumMismatch { .. }), "{err:?}");
            }
            for (extension, bytes) in [("jar", JAR), ("pom", POM)] {
                let row = store
                    .lookup_artifact(&demo("1.0", extension))
                    .await
                    .unwrap();
                if other.is_none() {
                    assert_eq!(row, Some(BlobId::from_bytes(bytes)), "{extension}");
                } else if other == Some(extension) {
                    assert_eq!(row, None, "{extension}");
                }
            }
        }
    }

    /// A repository that serves other POM bytes under a stale checksum file
    /// and then no POM at all still ends the search.
    #[tokio::test]
    async fn a_pom_gone_on_the_second_request_still_ends_the_search() {
        use rv_test_support::http::{Response, StubServer};
        use std::sync::atomic::{AtomicUsize, Ordering};

        const JAR: &[u8] = b"demo jar";
        const POM: &[u8] = b"<project>resolved</project>";
        let poms = Arc::new(AtomicUsize::new(0));
        let served = Arc::clone(&poms);
        let server = StubServer::start(move |req| {
            let sha1 = |bytes: &[u8]| rv_maven_types::Sha1::from_bytes(bytes).as_str().to_string();
            match req.path.rsplit('/').next().unwrap_or_default() {
                "demo-1.0.jar" => Response::new(200, JAR),
                "demo-1.0.jar.sha1" => Response::new(200, sha1(JAR)),
                "demo-1.0.pom" if served.fetch_add(1, Ordering::SeqCst) == 0 => {
                    Response::new(200, b"<project>other</project>".as_slice())
                }
                "demo-1.0.pom.sha1" => Response::new(200, sha1(POM)),
                _ => Response::new(404, Vec::new()),
            }
        });
        let temp = tempdir().unwrap();
        let dir = temp.path().join("second/com/example/demo/1.0");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("demo-1.0.jar"), JAR).unwrap();
        std::fs::write(dir.join("demo-1.0.pom"), POM).unwrap();
        let url = format!("http://{}/maven2/", server.addr());
        let mut first = rv_config::RepoConfig::new(Some("first"), &url);
        first.releases = Some(true);
        let repos = vec![first, file_repo("second", &temp.path().join("second"))];
        let paths = rv_config::ResolvedPaths::for_testing().unwrap();
        let mut config = Config::for_testing_with_repos(temp.path().into(), paths, repos);
        config.network.retries = 0;
        let client = RepoClient::new(&config).await.unwrap();
        let store = Store::open(&temp.path().join("store")).unwrap();
        let mut package = LockArtifact::new(demo("1.0", "jar"), url);
        package.checksums = vec![Digest::Sha256(BlobId::from_bytes(JAR))];
        package.pom_sha256 = Some(BlobId::from_bytes(POM));
        let pom_pins = PomPins::from([(package.pom_gav(), BlobId::from_bytes(POM))]);

        let result = sync(&config, &store, &client, &pom_pins, &package).await;
        server.stop();
        let err = result.expect_err("`first` served other bytes");
        assert!(matches!(err, RepoError::ChecksumMismatch { .. }), "{err:?}");
        assert!(
            poms.load(Ordering::SeqCst) >= 2,
            "the POM was requested again"
        );
        let row = store.lookup_artifact(&demo("1.0", "pom")).await.unwrap();
        assert_eq!(row, None);
    }

    /// A support POM that a package restores too waits for it, so its owners'
    /// repositories need not serve it.
    #[tokio::test]
    async fn support_pom_a_package_restores_waits_for_it() {
        let fixture = support_fixture().await;
        let mut lock = support_only_lock(GONE, &fixture.pinned);
        let mut package = LockArtifact::new(bom_key(), fixture.origin("current"));
        package.checksums = vec![Digest::Sha256(fixture.pinned.clone())];
        package.pom_sha256 = Some(fixture.pinned.clone());
        lock.platforms[0].artifacts.push(package);
        let results = ensure_artifacts(&fixture.store, &lock, &[fixture.context()])
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        for result in &results {
            result.result.as_ref().expect("restored");
        }
    }

    /// Bytes a package restores under another coordinate do not complete a
    /// support POM whose repository is gone: no repository served them for
    /// it.
    #[tokio::test]
    async fn support_pom_whose_bytes_a_package_restores_under_another_coordinate_fails() {
        let fixture = support_fixture().await;
        let dir = fixture._temp.path().join("current/org/test/twin/1");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(
            fixture
                ._temp
                .path()
                .join("current/org/test/bom/1/bom-1.pom"),
            dir.join("twin-1.pom"),
        )
        .unwrap();
        let mut lock = support_only_lock(GONE, &fixture.pinned);
        let twin = ArtifactCoord::new("org.test", "twin", "1", "pom", None);
        let mut package = LockArtifact::new(twin, fixture.origin("current"));
        package.checksums = vec![Digest::Sha256(fixture.pinned.clone())];
        package.pom_sha256 = Some(fixture.pinned.clone());
        lock.platforms[0].artifacts.push(package);
        let results = ensure_artifacts(&fixture.store, &lock, &[fixture.context()])
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        for result in &results {
            let twin = result.package.starts_with("org.test:twin:");
            assert_eq!(result.result.is_ok(), twin, "{result:?}");
        }
    }

    /// A `pom` package's artifact is its POM: a corrupt copy warns once.
    #[test]
    fn a_corrupt_pom_package_warns_once() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let output = rv_test_support::capture_warnings(|| {
            runtime.block_on(async {
                let fixture = support_fixture().await;
                let mut lock = support_only_lock(GONE, &fixture.pinned);
                lock.platforms[0].support_poms.clear();
                let mut package = LockArtifact::new(bom_key(), fixture.origin("current"));
                package.checksums = vec![Digest::Sha256(fixture.pinned.clone())];
                package.pom_sha256 = Some(fixture.pinned.clone());
                lock.platforms[0].artifacts.push(package);
                for _ in 0..2 {
                    ensure(&fixture, &lock).await[0]
                        .result
                        .as_ref()
                        .expect("restored");
                    let blob = fixture.store.get_path(&fixture.pinned);
                    std::fs::remove_file(&blob).unwrap();
                    std::fs::write(&blob, b"corrupt").unwrap();
                }
            });
        });
        assert_eq!(
            output.matches("STORE_FILE_REFETCHED").count(),
            1,
            "{output}"
        );
    }

    /// A repository `slow` that answers each request after 300 ms, with
    /// `body` at `path` and nothing anywhere else.
    fn slow_repo(
        path: &'static str,
        body: &'static [u8],
    ) -> (rv_test_support::http::StubServer, rv_config::RepoConfig) {
        use rv_test_support::http::{Response, StubServer};
        let server = StubServer::start(move |req| {
            std::thread::sleep(std::time::Duration::from_millis(300));
            match req.path == path {
                true => Response::new(200, body),
                false => Response::new(404, ""),
            }
        });
        let url = format!("http://{}/m2/", server.addr());
        let mut repo = rv_config::RepoConfig::new(Some("slow"), &url);
        repo.releases = Some(true);
        (server, repo)
    }

    /// Nor do bytes a package pinned by SHA-1 restores under another
    /// coordinate.
    #[tokio::test]
    async fn support_pom_whose_bytes_a_sha1_package_restores_fails() {
        const BOM: &[u8] = b"<project><artifactId>bom</artifactId></project>";
        let (_server, slow) = slow_repo("/m2/org/test/twin/1/twin-1.pom", BOM);
        let fixture = support_fixture_with(|_, current| vec![current, slow]).await;
        assert_eq!(fixture.pinned, BlobId::from_bytes(BOM));
        let mut lock = support_only_lock(GONE, &fixture.pinned);
        let twin = ArtifactCoord::new("org.test", "twin", "1", "pom", None);
        let mut package = LockArtifact::new(twin, fixture.origin("slow"));
        package.checksums = vec![Digest::Sha1(rv_maven_types::Sha1::from_bytes(BOM))];
        lock.platforms[0].artifacts.push(package);
        let results = ensure_artifacts(&fixture.store, &lock, &[fixture.context()])
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        for result in &results {
            let twin = result.package.starts_with("org.test:twin:");
            assert_eq!(result.result.is_ok(), twin, "{result:?}");
        }
    }

    /// A corrupt stored POM of an artifact that fails warns once: restored
    /// beside the artifact, or, when a support POM or a package pinned only
    /// by SHA-1 may share it, by that other restore.
    #[test]
    fn the_pom_of_a_failed_artifact_warns_once() {
        for sharer in ["none", "support", "package"] {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let output = rv_test_support::capture_warnings(|| {
                runtime.block_on(async {
                    let (_server, slow) = slow_repo("/m2/none", b"");
                    let mut fixture = support_fixture_with(|_, current| vec![current, slow]).await;
                    fixture.config.network.concurrency = 1;
                    let mut lock = support_only_lock(&fixture.origin("current"), &fixture.pinned);
                    let jar = ArtifactCoord::new("org.test", "bom", "1", "jar", None);
                    let mut package = LockArtifact::new(jar, fixture.origin("slow"));
                    package.checksums =
                        vec![Digest::Sha256(BlobId::from_bytes(b"never published"))];
                    package.pom_sha256 = Some(fixture.pinned.clone());
                    package.pom_repo_urls = vec![fixture.origin("current")];
                    lock.platforms[0].artifacts.push(package);
                    let blob = fixture.store.get_path(&fixture.pinned);
                    std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
                    std::fs::write(&blob, b"corrupt").unwrap();
                    if sharer != "support" {
                        lock.platforms[0].support_poms.clear();
                    }
                    if sharer == "package" {
                        let current = fixture._temp.path().join("current/org/test");
                        std::fs::create_dir_all(current.join("twin/1")).unwrap();
                        std::fs::copy(
                            current.join("bom/1/bom-1.pom"),
                            current.join("twin/1/twin-1.jar"),
                        )
                        .unwrap();
                        let twin = ArtifactCoord::new("org.test", "twin", "1", "jar", None);
                        let bytes = std::fs::read(current.join("twin/1/twin-1.jar")).unwrap();
                        fixture
                            .store
                            .add_artifact(&twin, &fixture.pinned)
                            .await
                            .unwrap();
                        let mut package = LockArtifact::new(twin, fixture.origin("current"));
                        package.checksums =
                            vec![Digest::Sha1(rv_maven_types::Sha1::from_bytes(&bytes))];
                        lock.platforms[0].artifacts.push(package);
                    }
                    let results = ensure_artifacts(&fixture.store, &lock, &[fixture.context()])
                        .await
                        .unwrap();
                    let (jar, others) = results.split_first().unwrap();
                    jar.result.as_ref().expect_err("never published");
                    assert_eq!(others.len(), usize::from(sharer != "none"));
                    for other in others {
                        other.result.as_ref().expect("restored");
                    }
                });
            });
            assert_eq!(
                output.matches("STORE_FILE_REFETCHED").count(),
                1,
                "shared with {sharer}: {output}"
            );
        }
    }

    /// A support POM is restored for the platforms that record it, through
    /// their contexts only.
    #[tokio::test]
    async fn support_poms_follow_their_platform() {
        let fixture = support_fixture().await;
        let mut lock = support_only_lock(GONE, &fixture.pinned);
        let mut other = lock.platforms[0].clone();
        other.platform = Platform::new("other", "arch").unwrap();
        lock.platforms[0].support_poms.clear();
        lock.platforms.push(other);
        let results = ensure_artifacts(&fixture.store, &lock, &[fixture.context()])
            .await
            .unwrap();
        assert!(results.is_empty(), "{results:?}");
    }

    #[tokio::test]
    async fn support_pom_tries_the_next_context_after_a_fetch_error() {
        let fixture = support_fixture_with(|_, current| vec![current]).await;
        let mut repo = fixture.config.repositories()[0].clone();
        repo.releases_checksum_policy = Some(rv_config::ChecksumPolicy::Unsupported);
        let config = Config::for_testing_with_repos(
            fixture.config.project_root.clone(),
            rv_config::ResolvedPaths::for_testing().unwrap(),
            vec![repo],
        );
        let client = RepoClient::new(&config).await.unwrap();
        let lock = support_only_lock(&fixture.origin("current"), &fixture.pinned);
        let results = ensure_artifacts(
            &fixture.store,
            &lock,
            &[
                RestoreContext {
                    config: &config,
                    client: &client,
                    platforms: &fixture.platforms,
                    trusted_repositories: &[],
                },
                fixture.context(),
            ],
        )
        .await
        .unwrap();
        results[0]
            .result
            .as_ref()
            .expect("second context restores the POM");
        assert_eq!(
            fixture.store.lookup_artifact(&bom_key()).await.unwrap(),
            Some(fixture.pinned)
        );
    }

    /// A repository with releases disabled is skipped like one that lacks the
    /// POM; an unsupported checksum policy for the requested kind refuses the
    /// repository, as Maven does, while the other kind's policy is ignored,
    /// so its other bytes fail the pin.
    #[tokio::test]
    async fn support_pom_search_applies_repository_policies() {
        let snapshots_only = |mut repo: rv_config::RepoConfig| {
            repo.releases = Some(false);
            repo.snapshots = Some(true);
            repo
        };
        let unsupported = |releases: bool| {
            move |mut stale: rv_config::RepoConfig, current| {
                let policy = Some(rv_config::ChecksumPolicy::Unsupported);
                if releases {
                    stale.releases_checksum_policy = policy;
                } else {
                    stale.snapshots_checksum_policy = policy;
                }
                if releases {
                    vec![stale]
                } else {
                    vec![stale, current]
                }
            }
        };
        let restored = |fixture: SupportFixture| async move {
            let lock = support_only_lock(&fixture.origin("stale"), &fixture.pinned);
            ensure(&fixture, &lock).await.remove(0).result
        };
        restored(support_fixture_with(|stale, current| vec![snapshots_only(stale), current]).await)
            .await
            .expect("restored from `current`");
        let err = restored(support_fixture_with(unsupported(false)).await)
            .await
            .expect_err("asked `stale`");
        assert!(matches!(err, RepoError::ChecksumMismatch { .. }), "{err:?}");

        let err = restored(support_fixture_with(|stale, _| vec![snapshots_only(stale)]).await)
            .await
            .expect_err("releases disabled");
        assert_eq!(err.class(), crate::ErrorClass::Config);
        assert_eq!(
            err.to_string(),
            "release version 1 cannot be fetched: repository 'stale' has releases disabled"
        );
        let err = restored(support_fixture_with(unsupported(true)).await)
            .await
            .expect_err("refused");
        assert!(matches!(err, RepoError::Config(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "invalid configuration: repository 'stale' has a <releases><checksumPolicy> that \
             is not fail, warn or ignore, so raeva does not download from it"
        );
    }

    #[tokio::test]
    async fn discovery_is_needed_only_for_a_missing_file_from_an_unconfigured_repository() {
        let fixture = support_fixture().await;
        let unmapped = support_only_lock(GONE, &fixture.pinned);
        let mapped = support_only_lock(&fixture.origin("current"), &fixture.pinned);
        let contexts = [fixture.context()];
        let needs = |lock| restore_needs_discovery(&fixture.store, lock, &contexts);
        assert!(needs(&unmapped).await.unwrap());
        assert!(!needs(&mapped).await.unwrap());
        ensure(&fixture, &mapped).await[0]
            .result
            .as_ref()
            .expect("restored");
        assert!(
            needs(&unmapped).await.unwrap(),
            "a POM another repository served does not stand in"
        );
    }

    #[tokio::test]
    async fn discovery_checks_companion_poms_under_their_own_origins() {
        let fixture = support_fixture().await;
        let mut row = pinned_package(&fixture.pinned);
        row.repo_url = fixture.origin("current");
        row.pom_sha256 = Some(BlobId::from_bytes(b"missing POM"));
        row.pom_repo_urls = vec![GONE.into()];
        let mut lock = support_only_lock(GONE, &fixture.pinned);
        lock.platforms[0].support_poms.clear();
        lock.platforms[0].artifacts = vec![row];
        let contexts = [fixture.context()];
        assert!(
            restore_needs_discovery(&fixture.store, &lock, &contexts)
                .await
                .unwrap()
        );
        lock.platforms[0].artifacts[0].pom_repo_urls.clear();
        assert!(
            !restore_needs_discovery(&fixture.store, &lock, &contexts)
                .await
                .unwrap()
        );
    }

    /// A file the store holds for another coordinate does not complete a row
    /// no repository served it for, as restoration would not take it.
    #[tokio::test]
    async fn a_file_stored_for_another_coordinate_does_not_complete_a_row() {
        let fixture = support_fixture().await;
        let (store, context) = (&fixture.store, &fixture.context());
        let jar = store.put_bytes(b"an older release's jar").await.unwrap();
        let mut lock = support_only_lock(GONE, &BlobId::from_bytes(b"unused"));
        lock.platforms[0].support_poms.clear();
        let mut row = pinned_package(&jar);
        row.repo_url = fixture.origin("current");
        lock.platforms[0].artifacts.push(row.clone());
        assert!(!restore_complete(store, &lock, context).await.unwrap());
        let contexts = std::slice::from_ref(context);
        assert_eq!(
            count_missing(store, &lock, contexts).await.unwrap(),
            (1, 1, 1)
        );
        let current = (fixture.config.repositories().iter())
            .find(|repo| repo.id.as_deref() == Some("current"))
            .map(|repo| repo.url.clone())
            .unwrap();
        // Neither does one a repository this context does not use served,
        // as another project's may have.
        for (repo, complete) in [(GONE.to_string(), false), (current, true)] {
            let origin = rv_store::Origin {
                repo_url: repo.clone(),
                endpoint_url: repo,
                checksum_verified: true,
                served: true,
            };
            let served = vec![(row.coord(), jar.clone(), origin)];
            store.record_origins(served).await.unwrap();
            assert_eq!(
                restore_complete(store, &lock, context).await.unwrap(),
                complete
            );
            let missing = usize::from(!complete);
            assert_eq!(
                count_missing(store, &lock, contexts).await.unwrap(),
                (missing, missing, 1)
            );
        }
    }

    #[tokio::test]
    async fn a_file_shared_by_platforms_is_complete_only_when_every_platform_is() {
        let fixture = support_fixture().await;
        let mut lock = support_only_lock(&fixture.origin("current"), &fixture.pinned);
        ensure(&fixture, &lock).await[0]
            .result
            .as_ref()
            .expect("restored");
        let mut other = lock.platforms[0].clone();
        other.platform = Platform::new("other", "arch").unwrap();
        lock.platforms.push(other);
        assert_eq!(pinned_files(&lock.platforms, |_| true).len(), 1);
        assert!(
            restore_complete(&fixture.store, &lock, &fixture.context())
                .await
                .unwrap()
        );

        lock.platforms[1].support_poms.insert(
            "org.test:other:1".to_string(),
            rv_lock::SupportPom::new(GONE, BlobId::from_bytes(b"absent")),
        );
        assert!(
            !restore_complete(&fixture.store, &lock, &fixture.context())
                .await
                .unwrap()
        );
    }
}
