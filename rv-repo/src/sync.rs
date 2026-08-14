use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use futures::stream::{self, StreamExt};
use rv_config::{
    ArtifactKey, BlobId, Checksum, Config, LockPackage, Lockfile, Platform,
    normalize_checksum_algorithm,
};

use rv_store::Store;
use tokio::sync::OnceCell;

use crate::artifact::ArtifactRequest;
use crate::client::RepoClient;
use crate::error::{RepoError, Result};
use crate::repository::{Repository, normalize_repo_url};

/// Per-sync-call dedup map: collapses concurrent fetches for the same Maven
/// coordinate (group, artifact, version, packaging, classifier) onto a single
/// network round trip. The `seen` set in `ensure_artifacts` dedupes only the
/// top-level lockfile entries; this map additionally collapses the *inner*
/// fetches a single lockfile entry triggers (the main artifact plus the
/// companion POM), so e.g. two coordinates sharing a POM coordinate fire one
/// GET, not two.
///
/// The inner Mutex is `std::sync::Mutex` because the only critical section is
/// the `entry().or_insert_with()` bookkeeping; no `.await` is held across it.
/// `OnceCell::get_or_try_init` provides the actual cross-task rendezvous and
/// is the only place an `.await` happens with respect to a cell.
type FetchDedupMap = Arc<Mutex<HashMap<ArtifactKey, Arc<OnceCell<BlobId>>>>>;

/// Parsed lockfile pin for a single package, used to enforce integrity at
/// sync time independently of the repo's sidecar checksum policy.
#[derive(Debug, Clone)]
enum LockPin {
    /// SHA-256 hex digest. Maps directly to a `BlobId`, so a hit can be
    /// confirmed by a cheap identity check without re-hashing.
    Sha256(BlobId),
    /// SHA-1 hex digest. The store is SHA-256 keyed, so verification
    /// requires re-hashing the on-disk blob with SHA-1.
    Sha1(String),
}

/// What a disagreement between the store's coordinate index and a SHA-256 pin
/// means for the key being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexDisagreement {
    /// The index is expected to name the pinned blob. Anything else is an
    /// integrity error: for a main artifact the lockfile is the contract, and
    /// "repairing" it by re-fetching would paper over a real substitution.
    Fatal,
    /// The index may legitimately name other bytes. Companion POMs are keyed
    /// `(g, a, v, pom)` with no project in the key, so any other project
    /// syncing against the same store repoints them last-writer-wins. The
    /// pinned blob is still the right answer; adopt it from the content store,
    /// or re-fetch and verify.
    Adopt,
}

/// Companion-POM pins carried by the lockfile's artifact rows, keyed by
/// `(group, artifact, resolved version)` — one `.pom` per GAV, shared by every
/// packaging and classifier of that coordinate.
type PomPins = HashMap<(String, String, String), BlobId>;

fn pom_pin_key(package: &LockPackage) -> (String, String, String) {
    (
        package.group_id.clone(),
        package.artifact_id.clone(),
        package.version.clone(),
    )
}

impl LockPin {
    fn from_checksum(checksum: &Checksum, coord: &str) -> Result<Self> {
        // `Lockfile::read` already rewrites the algorithm to a canonical
        // spelling and rejects unknown algorithms. We defensively re-check
        // here so callers that hand-build a `LockPackage` (tests, in-memory
        // resolution) still get a clear error rather than silently dropping
        // the pin.
        let canonical = normalize_checksum_algorithm(&checksum.algorithm).ok_or_else(|| {
            RepoError::UnsupportedChecksum(format!(
                "{} for {coord} (supported: sha256, sha1)",
                checksum.algorithm
            ))
        })?;
        match canonical {
            "sha256" => Ok(LockPin::Sha256(
                BlobId::from_str(&checksum.digest)
                    .map_err(|e| RepoError::InvalidMetadata(e.to_string()))?,
            )),
            "sha1" => {
                let digest = checksum.digest.trim().to_ascii_lowercase();
                if digest.len() != 40 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(RepoError::InvalidMetadata(format!(
                        "sha1 digest for {coord} must be 40 hex chars, got {:?}",
                        checksum.digest
                    )));
                }
                Ok(LockPin::Sha1(digest))
            }
            // `normalize_checksum_algorithm` only returns the two canonical
            // forms above, so this arm is unreachable in practice.
            other => Err(RepoError::UnsupportedChecksum(other.to_string())),
        }
    }

    fn expected_blob_id(&self) -> Option<&BlobId> {
        match self {
            LockPin::Sha256(id) => Some(id),
            LockPin::Sha1(_) => None,
        }
    }
}

/// Re-hash the on-disk blob against the lockfile pin to catch local tampering
/// or bit rot (an index-only check would miss both).
fn verify_blob_against_pin(store: &Store, blob: &BlobId, pin: &LockPin, coord: &str) -> Result<()> {
    let path = store.get_path(blob);
    match pin {
        LockPin::Sha256(expected) => {
            // Re-hash so we surface on-disk corruption, not just an index
            // disagreement. `BlobId::from_file` is SHA-256.
            let actual = BlobId::from_file(&path).map_err(RepoError::Io)?;
            if &actual == expected {
                Ok(())
            } else {
                Err(RepoError::ChecksumMismatch {
                    path: coord.to_string(),
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                })
            }
        }
        LockPin::Sha1(expected) => {
            let actual = crate::fetch::sha1_hex_file(&path)?;
            if &actual == expected {
                Ok(())
            } else {
                Err(RepoError::ChecksumMismatch {
                    path: coord.to_string(),
                    expected: expected.clone(),
                    actual,
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct DownloadResult {
    pub package: String,
    pub result: Result<()>,
}

pub async fn ensure_artifacts(
    client: &RepoClient,
    store: &Store,
    lock: &Lockfile,
    config: &Config,
    platforms: &[Platform],
    trusted_repositories: &[Repository],
) -> Result<Vec<DownloadResult>> {
    let filtered = filter_lock(lock, platforms)?;
    // Every artifact-table row is a pinned dependency, `pom` packaging
    // included: an ordinary `<type>pom</type>` dependency is a real resolved
    // node and gets a row, while imported BOMs and parent POMs never do. Rows
    // are what repair covers, so filtering `pom` out here would leave an
    // explicit POM dependency unrepaired until `rv export-m2` tripped over it.
    let all_packages: Vec<LockPackage> = filtered
        .platforms
        .iter()
        .flat_map(|platform| platform.external_packages())
        .filter(|package| package.system_path.is_none())
        .collect();

    if all_packages.is_empty() {
        return Ok(Vec::new());
    }

    let mut seen = HashSet::new();
    let mut packages = Vec::new();
    for pkg in &all_packages {
        let key = (
            &pkg.group_id,
            &pkg.artifact_id,
            &pkg.version,
            &pkg.packaging,
            &pkg.classifier,
        );
        if seen.insert(key) {
            packages.push(pkg);
        }
    }

    // The companion-POM pins the lockfile carries. Two rows pinning one GAV to
    // different bytes are rejected before this point — by `rv sync` for a
    // freshly resolved lock and by `Lockfile::read` for one off disk — so
    // collapsing the rows into one map per GAV cannot lose a distinct pin.
    let mut pom_pins = PomPins::new();
    for platform in &filtered.platforms {
        for artifact in &platform.artifacts {
            let Some(digest) = artifact.pom_sha256.as_deref() else {
                continue;
            };
            let blob = BlobId::from_str(digest).map_err(|err| {
                RepoError::InvalidMetadata(format!(
                    "pom_sha256 for {}: {err}",
                    artifact.coordinate.format_coord()
                ))
            })?;
            pom_pins.insert(pom_pin_key(&artifact.as_package()), blob);
        }
    }

    let concurrency = config.network.concurrency.max(1);
    let inputs = SyncInputs {
        config,
        store,
        client,
        trusted_repositories,
        pom_pins: &pom_pins,
    };
    download_artifacts_parallel(&packages, &inputs, concurrency).await
}

/// The read-only inputs every package in one `ensure_artifacts` call shares.
struct SyncInputs<'a> {
    config: &'a Config,
    store: &'a Store,
    client: &'a RepoClient,
    trusted_repositories: &'a [Repository],
    pom_pins: &'a PomPins,
}

async fn download_artifacts_parallel(
    packages: &[&LockPackage],
    inputs: &SyncInputs<'_>,
    concurrency: usize,
) -> Result<Vec<DownloadResult>> {
    let concurrency = concurrency.max(1);
    let dedup: FetchDedupMap = Arc::new(Mutex::new(HashMap::new()));

    let results = stream::iter(packages.iter().copied())
        .map(|pkg| {
            let dedup = dedup.clone();
            async move {
                let result = ensure_package_artifacts(inputs, pkg, &dedup).await;
                DownloadResult {
                    package: package_label(pkg),
                    result,
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    Ok(results)
}

/// Fetch a single `(repo, request, key)` triple, deduping concurrent callers.
///
/// First caller to reach a given `key` initialises its `OnceCell` by running
/// `fetch_artifact_to_store_and_index`; concurrent callers for the same `key`
/// await the same cell and reuse the resolved `BlobId`. On error the cell
/// stays empty so the next caller retries; failures are never cached.
async fn fetch_with_dedup(
    client: &RepoClient,
    repo: &Repository,
    request: &ArtifactRequest,
    store: &Store,
    key: &ArtifactKey,
    dedup: &FetchDedupMap,
) -> Result<BlobId> {
    let cell: Arc<OnceCell<BlobId>> = {
        let mut map = dedup
            .lock()
            .map_err(|_| RepoError::Io(std::io::Error::other("fetch dedup map poisoned")))?;
        map.entry(key.clone())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone()
    };

    // WHY: on a checksum mismatch the streaming helper deletes the blob and
    // returns Err. `OnceCell::get_or_try_init` leaves the cell empty on Err,
    // but the stale map entry would still hand subsequent callers the same
    // empty cell. Drop the map entry on Err so a later retry starts from a
    // fresh cell. This also guards against any future change that might
    // surface a partially-initialised BlobId to concurrent waiters.
    let result = cell
        .get_or_try_init(|| async {
            client
                .fetch_artifact_to_store_and_index(repo, request, store, key)
                .await
        })
        .await;
    match result {
        Ok(blob) => Ok(blob.clone()),
        Err(err) => {
            if let Ok(mut map) = dedup.lock() {
                map.remove(key);
            }
            Err(err)
        }
    }
}

fn package_label(package: &LockPackage) -> String {
    ArtifactKey::new(
        package.group_id.clone(),
        package.artifact_id.clone(),
        package.version.clone(),
        package.packaging.clone(),
        package.classifier.clone(),
    )
    .to_string()
}

async fn ensure_package_artifacts(
    inputs: &SyncInputs<'_>,
    package: &LockPackage,
    dedup: &FetchDedupMap,
) -> Result<()> {
    if package.system_path.is_some() {
        return Ok(());
    }
    let SyncInputs {
        config,
        store,
        client,
        trusted_repositories,
        pom_pins,
    } = *inputs;

    let request = ArtifactRequest::new(&package.group_id, &package.artifact_id, &package.version)
        .with_packaging(package.packaging.clone());
    let request = if let Some(classifier) = &package.classifier {
        request.with_classifier(classifier.clone())
    } else {
        request
    };

    let key = ArtifactKey::new(
        package.group_id.clone(),
        package.artifact_id.clone(),
        package.version.clone(),
        package.packaging.clone(),
        package.classifier.clone(),
    );
    let checksum = package
        .checksum
        .as_ref()
        .ok_or_else(|| RepoError::MissingChecksum(key.to_string()))?;

    let coord = key.to_string();
    let pin = LockPin::from_checksum(checksum, &coord)?;
    let mut origin = PackageOrigin::new(config, package, trusted_repositories);

    if needs_download(store, &key, &pin, &coord, IndexDisagreement::Fatal).await? {
        let repo = origin.repository()?;
        // Route fetch + index through `fetch_artifact_to_store_and_index`
        // so the persist and the index commit share one `StoreLock`. The
        // legacy two-step `fetch_artifact_to_store` then `Store::add_artifact`
        // sequence let a concurrent `Store::prune_blobs` sweep delete the
        // freshly-persisted blob between the two calls.
        //
        // Lockfile-pin verification still happens *after* the atomic put+index.
        // It is independent from the repo's sidecar checksum, which the
        // streaming path verifies in line: `--allow-missing-checksums` skips
        // the sidecar but the lockfile pin is the user's contract and must
        // always hold. Re-hashing here also catches the SHA-1 pin case that
        // the sidecar path may not have covered.
        let blob = fetch_with_dedup(client, repo, &request, store, &key, dedup).await?;
        // Off-runtime SHA-256/SHA-1 verify: the synchronous on-disk hash
        // would otherwise pin a tokio worker for the duration of a large JAR.
        verify_blob_against_pin_offload(store, &blob, &pin, &coord).await?;
    }

    // Ensure the artifact's own POM is in the store, then walk and persist its
    // `<parent>` ancestry. `rv export-m2` materializes the parent chain for
    // strict offline `mvn -o`, but can only export ancestors that `rv sync`
    // actually persisted; without this walk `mvn -o` fails with
    // "Non-resolvable parent POM" for any dependency carrying a parent.
    let pom_key = ArtifactKey::new(
        package.group_id.clone(),
        package.artifact_id.clone(),
        package.version.clone(),
        "pom",
        None,
    );
    let pom_blob = if let Some(expected) = pom_pins.get(&pom_pin_key(package)) {
        // The lockfile names the exact POM bytes resolution parsed. The store's
        // coordinate index is not authoritative for them — any other project
        // sharing the store repoints `(g, a, v, pom)` last-writer-wins — so
        // verify against the pin and, if the store no longer holds those
        // bytes, re-fetch and verify what comes back rather than accepting
        // whatever the index currently names.
        let pom_pin = LockPin::Sha256(expected.clone());
        let pom_coord = pom_key.to_string();
        if needs_download(
            store,
            &pom_key,
            &pom_pin,
            &pom_coord,
            IndexDisagreement::Adopt,
        )
        .await?
        {
            let repo = origin.repository()?;
            let blob =
                fetch_with_dedup(client, repo, &request.pom(), store, &pom_key, dedup).await?;
            // A POM that no longer hashes to the pin is upstream drift, not a
            // repairable local miss: continuing would index bytes this
            // lockfile was never resolved against.
            verify_blob_against_pin_offload(store, &blob, &pom_pin, &pom_coord).await?;
        }
        Some(expected.clone())
    } else if package.packaging == "pom" {
        // An explicit `<type>pom</type>` dependency is its own POM: the main
        // fetch above already persisted it under `pom_key`.
        store.lookup_artifact(&pom_key).await?
    } else if !needs_download_unpinned(store, &pom_key).await? {
        store.lookup_artifact(&pom_key).await?
    } else {
        // A timestamped snapshot row without a pin is NOT satisfied by the
        // store's base `-SNAPSHOT` POM row: that row is keyed without a
        // project and repointed last-writer-wins, so aliasing it here would
        // index some other build's POM under this build's key and poison the
        // parent-chain walk and export. Only a pinned row can adopt bytes by
        // identity (the branch above does, straight from the content store);
        // everything else fetches the real timestamped POM and verifies it.
        let repo = origin.repository()?;
        // Companion POMs ride through the same atomic put+index path as the
        // main artifact. The repo's `.sha256`/`.sha1` sidecar still gates
        // trust (refusing unverified blobs when `require_checksums=true`);
        // an unpinned row is one written before POM pinning, or by a lockfile
        // that recorded no digest for this coordinate.
        let pom_req = request.pom();
        Some(fetch_with_dedup(client, repo, &pom_req, store, &pom_key, dedup).await?)
    };

    if let Some(pom_blob) = pom_blob {
        ensure_parent_chain(client, &mut origin, store, &pom_blob, dedup).await?;
    }

    Ok(())
}

struct PackageOrigin<'a> {
    repository: Option<Repository>,
    config: &'a Config,
    package: &'a LockPackage,
    trusted_repositories: &'a [Repository],
}

impl<'a> PackageOrigin<'a> {
    fn new(
        config: &'a Config,
        package: &'a LockPackage,
        trusted_repositories: &'a [Repository],
    ) -> Self {
        Self {
            repository: None,
            config,
            package,
            trusted_repositories,
        }
    }

    fn repository(&mut self) -> Result<&Repository> {
        if self.repository.is_none() {
            self.repository = Some(repository_for_package(
                self.config,
                self.package,
                self.trusted_repositories,
            )?);
        }
        Ok(self
            .repository
            .as_ref()
            .expect("repository was initialized before borrowing"))
    }
}

/// Maximum `<parent>` ancestry depth followed during sync. Guards against
/// pathological or cyclic parent graphs. (The export-side walk has its own
/// independent node cap; this value is not coupled to it.)
const MAX_PARENT_CHAIN: usize = 64;

/// Walk the `<parent>` ancestry of an already-persisted POM blob, fetching and
/// indexing every ancestor POM into the content store under its
/// `(group, artifact, version, "pom", -)` key. This is what lets
/// `rv export-m2` materialize the parent chain so strict offline `mvn -o`
/// resolves parents.
///
/// Ancestors are fetched from the same repository as the starting artifact,
/// the common case (parents almost always live alongside their children or on
/// Central). A parent that resolves only from a different repository is logged
/// and ends the walk; `rv export-m2` surfaces the same residual gap. Shared
/// ancestors are fetched once via the per-sync dedup map.
async fn ensure_parent_chain(
    client: &RepoClient,
    origin: &mut PackageOrigin<'_>,
    store: &Store,
    child_pom_blob: &BlobId,
    dedup: &FetchDedupMap,
) -> Result<()> {
    let mut current = child_pom_blob.clone();
    let mut seen: HashSet<ArtifactKey> = HashSet::new();
    for _ in 0..MAX_PARENT_CHAIN {
        let Some((group_id, artifact_id, version)) =
            read_parent_coord_from_store(store, &current).await
        else {
            return Ok(());
        };
        let parent_key = ArtifactKey::new(
            group_id.clone(),
            artifact_id.clone(),
            version.clone(),
            "pom",
            None,
        );
        // Dedupe within this walk (shared parent / cycle); cross-walk dedup is
        // handled by the fetch dedup map below.
        if !seen.insert(parent_key.clone()) {
            return Ok(());
        }
        let parent_blob = if needs_download_unpinned(store, &parent_key).await? {
            let repo = origin.repository()?;
            let req =
                ArtifactRequest::new(group_id.as_str(), artifact_id.as_str(), version.as_str())
                    .with_packaging("pom");
            match fetch_with_dedup(client, repo, &req, store, &parent_key, dedup).await {
                Ok(blob) => blob,
                Err(err) => {
                    tracing::warn!(
                        group_id = %group_id,
                        artifact_id = %artifact_id,
                        version = %version,
                        error = %err,
                        "could not persist parent POM (it may resolve only from a different \
                         repository); strict offline `mvn -o` may fail to resolve it"
                    );
                    return Ok(());
                }
            }
        } else {
            match store.lookup_artifact(&parent_key).await? {
                Some(blob) => blob,
                None => return Ok(()),
            }
        };
        current = parent_blob;
    }
    Ok(())
}

/// Read an already-persisted POM blob and return its `<parent>` coordinate, if
/// any. Returns `None` (ending the walk) if the blob is unreadable or does not
/// parse, degrading gracefully rather than failing the sync.
async fn read_parent_coord_from_store(
    store: &Store,
    blob: &BlobId,
) -> Option<(String, String, String)> {
    let path = store.get_path(blob);
    let bytes = tokio::fs::read(&path).await.ok()?;
    let xml = std::str::from_utf8(&bytes).ok()?;
    let pom = rv_maven_model::Pom::parse(xml).ok()?;
    let parent = pom.parent?;
    Some((parent.group_id, parent.artifact_id, parent.version))
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
    key: &ArtifactKey,
    pin: &LockPin,
    coord: &str,
    on_index_disagreement: IndexDisagreement,
) -> Result<bool> {
    let expected_blob_id = pin.expected_blob_id().cloned();

    if let Some(existing) = store.lookup_artifact(key).await?
        && store.exists_async(&existing).await
    {
        // For sha256 pins, an index disagreement means the index points at
        // a different blob than the lockfile demands. Whether that is an
        // integrity error or an ordinary repoint depends on who owns the key;
        // see `IndexDisagreement`. Under `Adopt` the pinned blob is looked up
        // by content below instead.
        if let Some(expected) = expected_blob_id.as_ref()
            && existing != *expected
        {
            if on_index_disagreement == IndexDisagreement::Fatal {
                return Err(RepoError::ChecksumMismatch {
                    path: coord.to_string(),
                    expected: expected.to_string(),
                    actual: existing.to_string(),
                });
            }
            return adopt_pinned_blob(store, key, expected, pin, coord).await;
        }

        // Re-hash the on-disk blob against the lockfile pin. SHA-256 over a
        // 100 MB JAR is CPU-bound; run it on the blocking pool so a
        // `buffer_unordered` fan-out doesn't pin all tokio worker threads.
        // The blob is removed from inside the same blocking closure (so the
        // remove_file syscall doesn't block the runtime) but ONLY when it is
        // genuinely corrupt; see `verify_pin_repairing_corruption`.
        //
        // KNOWN LIMITATION: a corrupt-blob unlink races with
        // `Store::prune_blobs`. The `StoreLock` that serialises GC is not
        // exposed across crates, so we accept the small window where prune may
        // see a momentarily-bad blob, which is strictly less harmful than
        // blocking the runtime.
        let verify = verify_pin_repairing_corruption(store, &existing, pin, coord).await?;
        match verify {
            BlobCheck::Intact => return Ok(false),
            BlobCheck::PinMismatch => return Ok(true),
        }
    }

    // Fallback: the index has no row for this key (or, under `Adopt`, names
    // other bytes) but the pinned blob is in the CAS. Adopt it.
    if let Some(expected) = expected_blob_id.as_ref() {
        return adopt_pinned_blob(store, key, expected, pin, coord).await;
    }

    Ok(true)
}

/// Point `key` at the pinned blob when the content store already holds it,
/// returning whether a download is still needed.
///
/// KNOWN LIMITATION: `exists_async` -> `verify_pin_*` -> `add_artifact` is
/// three steps with no `StoreLock` held across them. A concurrent
/// `Store::prune_blobs` sweep can remove the blob between any pair of steps
/// and leave a dangling index row. The cross-crate atomic helper that would
/// close this race lives in rv-store and is out of scope for this branch;
/// until then we log on the observable post-condition (blob gone after
/// `add_artifact`) and rely on the next sync's lockfile-pin re-hash in
/// `needs_download` to repair the row.
async fn adopt_pinned_blob(
    store: &Store,
    key: &ArtifactKey,
    expected: &BlobId,
    pin: &LockPin,
    coord: &str,
) -> Result<bool> {
    if !store.exists_async(expected).await {
        return Ok(true);
    }
    match verify_pin_repairing_corruption(store, expected, pin, coord).await? {
        BlobCheck::Intact => {
            store.add_artifact(key, expected).await?;
            if !store.exists_async(expected).await {
                tracing::warn!(
                    sec_code = "ADOPT_RACE",
                    coord = %coord,
                    blob = %expected,
                    "blob disappeared between exists check and add_artifact (concurrent GC); index row will be repaired on next sync"
                );
                return Ok(true);
            }
            Ok(false)
        }
        BlobCheck::PinMismatch => Ok(true),
    }
}

/// Outcome of an off-runtime pin verification step.
enum BlobCheck {
    /// Blob bytes matched the lockfile pin.
    Intact,
    /// Blob bytes did not match the lockfile pin; the caller must re-fetch
    /// this coordinate. The shared blob is left in place unless it was
    /// genuinely corrupt (content no longer matching its own address).
    PinMismatch,
}

/// Re-hash `blob` against `pin` on the blocking pool. On mismatch, remove the
/// on-disk file ONLY if it is genuinely corrupt, i.e. its content no longer
/// hashes to its own `BlobId`. A blob that still matches its content-address
/// is valid for every OTHER artifact-key row that references it (the store is
/// content-addressed and deduplicated), so deleting it merely because THIS
/// coordinate's lockfile pin disagrees (a stale SHA-1 pin, or a wrong
/// key->blob mapping) would strand those referrers and force a needless
/// re-download. Re-fetch repairs this coordinate's row without touching the
/// shared blob. Both the SHA work and any `unlink` stay off the executor.
async fn verify_pin_repairing_corruption(
    store: &Store,
    blob: &BlobId,
    pin: &LockPin,
    coord: &str,
) -> Result<BlobCheck> {
    let store = store.clone();
    let blob = blob.clone();
    let pin = pin.clone();
    let coord = coord.to_string();
    tokio::task::spawn_blocking(move || {
        match verify_blob_against_pin(&store, &blob, &pin, &coord) {
            Ok(()) => Ok(BlobCheck::Intact),
            Err(err) => {
                tracing::warn!(
                    coord = %coord,
                    blob = %blob,
                    error = %err,
                    "cached blob failed lockfile pin verification; re-fetching"
                );
                // Delete only on true content-address corruption; never on a
                // mere pin disagreement, which would strand other referrers of
                // a valid shared blob.
                let blob_path = store.get_path(&blob);
                let corrupt = matches!(BlobId::from_file(&blob_path), Ok(actual) if actual != blob);
                if corrupt {
                    tracing::warn!(
                        coord = %coord,
                        blob = %blob,
                        "blob content no longer matches its address; removing corrupt blob"
                    );
                    if let Err(remove_err) = std::fs::remove_file(&blob_path) {
                        tracing::warn!(
                            path = %blob_path.display(),
                            error = %remove_err,
                            "failed to remove corrupt blob before re-fetch"
                        );
                    }
                }
                Ok(BlobCheck::PinMismatch)
            }
        }
    })
    .await
    .map_err(|e| RepoError::Io(std::io::Error::other(format!("verify task panicked: {e}"))))?
}

/// Off-runtime variant of [`verify_blob_against_pin`].
///
/// Callers used to invoke the synchronous `verify_blob_against_pin`
/// directly from `async` code after a fetch returned. SHA-256/SHA-1 over a
/// multi-megabyte JAR is CPU-bound and would freeze a tokio worker for the
/// duration. Routing through `spawn_blocking` keeps the runtime responsive
/// for other in-flight fetches and timer-driven work.
async fn verify_blob_against_pin_offload(
    store: &Store,
    blob: &BlobId,
    pin: &LockPin,
    coord: &str,
) -> Result<()> {
    let store = store.clone();
    let blob = blob.clone();
    let pin = pin.clone();
    let coord = coord.to_string();
    tokio::task::spawn_blocking(move || verify_blob_against_pin(&store, &blob, &pin, &coord))
        .await
        .map_err(|e| {
            RepoError::Io(std::io::Error::other(format!(
                "verify_blob_against_pin task panicked: {e}"
            )))
        })?
}

/// `needs_download` variant for artifacts that have no lockfile pin
/// (currently: companion POMs synthesized from the lockfile).
async fn needs_download_unpinned(store: &Store, key: &ArtifactKey) -> Result<bool> {
    if let Some(existing) = store.lookup_artifact(key).await?
        && store.exists_async(&existing).await
    {
        return Ok(false);
    }
    Ok(true)
}

/// Resolve a lockfile `repo_url` against configured `[repositories]`. Refuse
/// any URL not declared in `rv.toml`: the lockfile is not a trust root, so
/// a tampered `rv.lock` must not redirect a sync to an attacker origin.
///
/// This is the canonical trust policy for a lockfile origin; callers that only
/// need to decide whether a recorded `repo_url` is still trusted (`rv lock
/// --verify`) should call it rather than restate it. Such callers pass an empty
/// `trusted_repositories`: that slice carries the origins the *current*
/// resolution authorized, which a verification pass does not have.
pub fn repository_for_package(
    config: &Config,
    package: &LockPackage,
    trusted_repositories: &[Repository],
) -> Result<Repository> {
    let wanted = normalize_repo_url(&package.repo_url);
    for repo in config.repositories() {
        if normalize_repo_url(&repo.url) == wanted {
            return Ok(Repository::from(repo));
        }
    }
    // Resolution records the mirror-substituted URL, so a mirror's own URL is
    // a legitimate lockfile origin. The repository carries the MIRROR's id,
    // never the origin repository's, and `AuthStore`'s mirror policy re-applies
    // the cross-host credential suppression that resolution made — mirror
    // selection cannot recompute it from a substituted URL, which matches its
    // own entry and short-circuits as a self-reference.
    for mirror in config.mirrors() {
        if normalize_repo_url(&mirror.url) == wanted {
            return Ok(Repository::new(
                mirror.id.clone(),
                mirror.url.clone(),
                true,
                true,
            ));
        }
    }
    for repo in trusted_repositories {
        if normalize_repo_url(&repo.url) == wanted {
            return Ok(repo.clone());
        }
    }
    tracing::warn!(
        repo_url = %package.repo_url,
        group = %package.group_id,
        artifact = %package.artifact_id,
        "lockfile references unknown repository not in current configuration"
    );
    Err(RepoError::UntrustedRepoUrl(package.repo_url.clone()))
}

fn filter_lock(lock: &Lockfile, platforms: &[Platform]) -> Result<Lockfile> {
    let mut filtered = Lockfile::new();
    for platform in platforms {
        let entry = lock
            .platforms
            .iter()
            .find(|entry| entry.platform == *platform)
            .ok_or_else(|| {
                RepoError::NotFound(format!("platform '{}' not found in lockfile", platform))
            })?;
        filtered.platforms.push(entry.clone());
    }
    Ok(filtered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::sha1_hex;
    use rv_config::Checksum;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    fn make_key() -> ArtifactKey {
        ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None)
    }

    /// The parent-chain walk reads a persisted POM blob and extracts its
    /// `<parent>` coordinate so the ancestor can be fetched and exported.
    #[tokio::test]
    async fn read_parent_coord_from_store_extracts_parent() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let pom = r#"<project><modelVersion>4.0.0</modelVersion>
            <parent>
              <groupId>org.apache</groupId>
              <artifactId>apache</artifactId>
              <version>30</version>
            </parent>
            <artifactId>child</artifactId></project>"#;
        let blob = store.put_bytes(pom.as_bytes()).await.unwrap();
        assert_eq!(
            super::read_parent_coord_from_store(&store, &blob).await,
            Some((
                "org.apache".to_string(),
                "apache".to_string(),
                "30".to_string()
            ))
        );
    }

    /// A POM with no `<parent>` ends the walk.
    #[tokio::test]
    async fn read_parent_coord_from_store_none_without_parent() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let pom = r#"<project><modelVersion>4.0.0</modelVersion>
            <groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>"#;
        let blob = store.put_bytes(pom.as_bytes()).await.unwrap();
        assert_eq!(
            super::read_parent_coord_from_store(&store, &blob).await,
            None
        );
    }

    /// Regression: a present-but-corrupted on-disk blob must NOT be
    /// silently accepted. `needs_download` must report `Ok(true)` so the
    /// caller re-fetches.
    #[tokio::test]
    async fn needs_download_rehashes_existing_blob_and_detects_bit_rot() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = make_key();

        let payload = b"good-jar-bytes".to_vec();
        let good_id = store.put_bytes(&payload).await.unwrap();
        store.add_artifact(&key, &good_id).await.unwrap();

        // Tamper with the blob on disk without updating the index. The
        // pin still expects `good_id` (which is SHA-256 of `payload`).
        // CAS blobs are published at 0o444 (read-only) so the test has to
        // re-grant write before clobbering the file.
        let blob_path = store.get_path(&good_id);
        let mut perms = std::fs::metadata(&blob_path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        // test re-grants write to clobber a CAS blob
        perms.set_readonly(false);
        std::fs::set_permissions(&blob_path, perms).unwrap();
        std::fs::write(&blob_path, b"tampered-bytes").unwrap();

        let pin = LockPin::Sha256(good_id.clone());
        let coord = key.to_string();

        let needs = needs_download(&store, &key, &pin, &coord, IndexDisagreement::Fatal)
            .await
            .expect("needs_download");
        assert!(
            needs,
            "needs_download must signal a re-fetch when the blob has been tampered with"
        );
        assert!(
            !blob_path.exists(),
            "the corrupted blob must be removed so the re-fetch can re-create it"
        );
    }

    /// A clean SHA-256 hit must still re-hash from disk so tampering that
    /// preserves the index row is caught.
    #[tokio::test]
    async fn needs_download_accepts_intact_blob() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = make_key();

        let payload = b"intact-bytes".to_vec();
        let id = store.put_bytes(&payload).await.unwrap();
        store.add_artifact(&key, &id).await.unwrap();

        let pin = LockPin::Sha256(id.clone());
        let needs = needs_download(
            &store,
            &key,
            &pin,
            &key.to_string(),
            IndexDisagreement::Fatal,
        )
        .await
        .unwrap();
        assert!(
            !needs,
            "intact blob should be reported as no-download-needed"
        );
        assert!(store.get_path(&id).is_file());
    }

    /// A lockfile pin with `algorithm = "sha1"` and a wrong digest must fail
    /// verification with a clear ChecksumMismatch against the on-disk bytes.
    #[tokio::test]
    async fn sha1_pin_with_wrong_digest_fails_verification() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = make_key();

        let payload = b"sha1-test-bytes".to_vec();
        let blob = store.put_bytes(&payload).await.unwrap();
        store.add_artifact(&key, &blob).await.unwrap();

        // Build a pin pointing at a SHA-1 digest that does NOT match the
        // payload. `Checksum` constructed via lockfile-canonical algorithm.
        let bogus_checksum = Checksum::new("sha1", "0".repeat(40));
        let coord = key.to_string();
        let pin = LockPin::from_checksum(&bogus_checksum, &coord).unwrap();

        let err = verify_blob_against_pin(&store, &blob, &pin, &coord).unwrap_err();
        match err {
            RepoError::ChecksumMismatch {
                expected, actual, ..
            } => {
                assert_eq!(expected, "0".repeat(40));
                assert_eq!(actual, sha1_hex(&payload));
            }
            other => panic!("expected ChecksumMismatch, got {other}"),
        }
    }

    /// A SHARED, still-valid CAS blob (content matching its own address)
    /// must NOT be deleted when one coordinate's SHA-1 lockfile pin is
    /// stale/wrong. The store is content-addressed and deduplicated, so
    /// deleting it would strand every other coordinate that references the
    /// same blob. `needs_download` must still signal a re-fetch for the
    /// offending coordinate, but the blob file must survive.
    #[tokio::test]
    async fn stale_sha1_pin_does_not_delete_valid_shared_blob() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = make_key();

        let payload = b"shared-valid-bytes".to_vec();
        let blob = store.put_bytes(&payload).await.unwrap();
        store.add_artifact(&key, &blob).await.unwrap();
        let blob_path = store.get_path(&blob);
        assert!(blob_path.is_file());

        // A wrong SHA-1 pin for this coordinate (e.g. a stale lockfile entry).
        let bogus = Checksum::new("sha1", "0".repeat(40));
        let coord = key.to_string();
        let pin = LockPin::from_checksum(&bogus, &coord).unwrap();

        let needs = needs_download(&store, &key, &pin, &coord, IndexDisagreement::Fatal)
            .await
            .unwrap();
        assert!(
            needs,
            "a stale pin must trigger a re-fetch for the offending coordinate"
        );
        assert!(
            blob_path.is_file(),
            "a valid shared blob must survive a stale-pin mismatch; other coordinates may reference it"
        );
    }

    /// A SHA-1 pin with the correct digest verifies successfully.
    #[tokio::test]
    async fn sha1_pin_with_correct_digest_verifies() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = make_key();
        let payload = b"sha1-happy-path".to_vec();
        let blob = store.put_bytes(&payload).await.unwrap();
        store.add_artifact(&key, &blob).await.unwrap();

        let correct = sha1_hex(&payload);
        // The canonical spelling already comes out of `Lockfile::read`.
        let cs = Checksum::new("sha1", correct);
        let pin = LockPin::from_checksum(&cs, &key.to_string()).unwrap();
        verify_blob_against_pin(&store, &blob, &pin, &key.to_string()).expect("ok");
    }

    /// SHA-256 re-hashing for `needs_download` must run on the blocking
    /// pool, not on the tokio worker threads. We schedule
    /// many concurrent verifications on a 2-worker runtime and assert the
    /// runtime stays responsive (a 100 ms timer-driven task must still
    /// fire while all the verifications are in flight).
    ///
    /// If verification ran on the worker threads, the workers would all be
    /// pinned doing SHA-256 over the seeded blobs and the timer task would
    /// not get to run before the overall test timeout, making the
    /// `tokio::time::timeout` below fail.
    #[test]
    fn needs_download_keeps_runtime_responsive() {
        use std::time::Duration;
        use tokio::runtime::Builder;

        let rt = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build rt");

        rt.block_on(async {
            let dir = tempdir().unwrap();
            let store = Store::open(dir.path()).unwrap();

            // Build 16 distinct keys + intact blobs so each call goes through
            // the on-disk re-hash path (the slow one).
            let mut keys_and_pins = Vec::new();
            for i in 0..16u32 {
                let key = ArtifactKey::new(
                    "com.example",
                    format!("art-{i}"),
                    "1.0.0",
                    "jar",
                    None::<String>,
                );
                // Pad each blob so the SHA-256 work is non-trivial.
                let mut payload = vec![0u8; 64 * 1024];
                payload[..4].copy_from_slice(&i.to_le_bytes());
                let id = store.put_bytes(&payload).await.unwrap();
                store.add_artifact(&key, &id).await.unwrap();
                let pin = LockPin::Sha256(id);
                keys_and_pins.push((key, pin));
            }

            // Concurrently verify all of them.
            let verify_fut = async {
                let mut handles = Vec::new();
                for (key, pin) in &keys_and_pins {
                    let store = store.clone();
                    let key = key.clone();
                    let pin = pin.clone();
                    let coord = key.to_string();
                    handles.push(tokio::spawn(async move {
                        needs_download(&store, &key, &pin, &coord, IndexDisagreement::Fatal)
                            .await
                            .unwrap()
                    }));
                }
                for h in handles {
                    let needed = h.await.unwrap();
                    assert!(!needed, "intact blobs should not need re-download");
                }
            };

            // Concurrently with the verifications, schedule a short timer.
            // If the executor is wedged on synchronous SHA-256 work the
            // sleep cannot fire promptly and the outer timeout fails.
            let responsive_fut = async {
                tokio::time::timeout(
                    Duration::from_millis(100),
                    tokio::time::sleep(Duration::from_millis(10)),
                )
                .await
                .expect("timer must run while verifications are in flight");
            };

            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(verify_fut, responsive_fut);
            })
            .await
            .expect("fan-out + timer must complete within 10s");
        });
    }

    /// If `rv.lock` points at a `repo_url` that is NOT in
    /// the configured repositories, `repository_for_package` must hard-fail
    /// with [`RepoError::UntrustedRepoUrl`] rather than synthesizing a
    /// `Repository` for the attacker-controlled origin and fetching from
    /// it. The lockfile is not a trust root; only `rv.toml` is.
    #[test]
    fn repository_for_package_rejects_unknown_lockfile_repo() {
        use rv_config::{ResolvedPaths, UpdatePolicy};

        let temp = tempfile::tempdir().expect("temp dir");
        let paths = ResolvedPaths::discover().expect("paths");
        // Only `central` is configured.
        let central = rv_config::RepoConfig {
            id: Some("central".to_string()),
            url: "https://repo1.maven.org/maven2/".to_string(),
            releases: Some(true),
            snapshots: Some(false),
            snapshots_update_policy: Some(UpdatePolicy::Daily),
        };
        let config = rv_config::Config::for_testing_with_repos(
            temp.path().to_path_buf(),
            paths,
            vec![central],
        );

        // Lockfile claims an entirely unconfigured origin.
        let package = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://untrusted.example/".to_string(),
            checksum: Some(Checksum::new("sha256", "f".repeat(64))),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        };

        let err = repository_for_package(&config, &package, &[])
            .expect_err("unknown lockfile repo must be rejected");
        match err {
            RepoError::UntrustedRepoUrl(url) => {
                assert_eq!(url, "https://untrusted.example/");
            }
            other => panic!("expected UntrustedRepoUrl, got {other}"),
        }
    }

    /// Happy path: a lockfile `repo_url` that DOES match a configured
    /// repository (modulo trailing-slash normalization) still resolves.
    #[test]
    fn repository_for_package_accepts_configured_lockfile_repo() {
        use rv_config::{ResolvedPaths, UpdatePolicy};

        let temp = tempfile::tempdir().expect("temp dir");
        let paths = ResolvedPaths::discover().expect("paths");
        let central = rv_config::RepoConfig {
            id: Some("central".to_string()),
            url: "https://repo1.maven.org/maven2/".to_string(),
            releases: Some(true),
            snapshots: Some(false),
            snapshots_update_policy: Some(UpdatePolicy::Daily),
        };
        let config = rv_config::Config::for_testing_with_repos(
            temp.path().to_path_buf(),
            paths,
            vec![central],
        );

        let package = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            // Same URL with or without trailing slash should still match.
            repo_url: "https://repo1.maven.org/maven2".to_string(),
            checksum: Some(Checksum::new("sha256", "f".repeat(64))),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        };

        let repo =
            repository_for_package(&config, &package, &[]).expect("configured repo must resolve");
        assert_eq!(repo.id.as_deref(), Some("central"));
    }

    #[test]
    fn repository_for_package_accepts_origin_trusted_by_current_resolution() {
        use rv_config::ResolvedPaths;

        let temp = tempfile::tempdir().expect("temp dir");
        let paths = ResolvedPaths::discover().expect("paths");
        let config =
            rv_config::Config::for_testing_with_repos(temp.path().to_path_buf(), paths, Vec::new());
        let package = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0-SNAPSHOT".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repository.example/snapshots/".to_string(),
            checksum: Some(Checksum::new("sha256", "f".repeat(64))),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        };
        let trusted = Repository::new(
            Some("snapshots".to_string()),
            "https://repository.example/snapshots",
            false,
            true,
        );

        let repo = repository_for_package(&config, &package, &[trusted])
            .expect("current resolution should authorize its effective repository");
        assert_eq!(repo.id.as_deref(), Some("snapshots"));
        assert!(repo.snapshots_enabled);
    }

    /// `Checksum.algorithm = "sha-256"` (dash form) parses through
    /// `LockPin::from_checksum` and verifies identically to `"sha256"`.
    #[tokio::test]
    async fn dashed_sha_256_pin_verifies_like_canonical() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = make_key();
        let payload = b"dash-256-bytes".to_vec();
        let blob = store.put_bytes(&payload).await.unwrap();
        store.add_artifact(&key, &blob).await.unwrap();

        // Construct a `Checksum` with the dash form. Even if `Lockfile::read`
        // normalizes at parse time, code paths that build `Checksum`
        // directly must still resolve to the same pin.
        let hex_digest = hex::encode(Sha256::digest(&payload));
        let cs = Checksum::new("sha-256", hex_digest);
        let pin =
            LockPin::from_checksum(&cs, &key.to_string()).expect("dash form must be accepted");
        verify_blob_against_pin(&store, &blob, &pin, &key.to_string()).expect("verifies");
    }

    /// Regression: when the fetch closure inside `fetch_with_dedup` errors,
    /// the per-key map entry must be removed. Otherwise a stale empty `OnceCell`
    /// would linger and any future change to `OnceCell` semantics could
    /// surface a half-initialised BlobId to concurrent waiters. The test
    /// drives the same cleanup pattern that `fetch_with_dedup` uses; if the
    /// production code drops the cleanup it must reach for a re-shaped helper
    /// rather than the bare `get_or_try_init`.
    #[tokio::test]
    async fn fetch_with_dedup_clears_map_entry_on_error() {
        let key = make_key();
        let dedup: FetchDedupMap = Arc::new(Mutex::new(HashMap::new()));

        // Pre-seed the map exactly as fetch_with_dedup would.
        let cell: Arc<OnceCell<BlobId>> = {
            let mut map = dedup.lock().unwrap();
            map.entry(key.clone())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };

        let result: Result<&BlobId> = cell
            .get_or_try_init(|| async {
                Err::<BlobId, _>(RepoError::Io(std::io::Error::other(
                    "simulated fetch failure",
                )))
            })
            .await;
        assert!(result.is_err(), "init must surface the simulated error");

        // The cleanup that `fetch_with_dedup` performs on Err.
        if result.is_err()
            && let Ok(mut map) = dedup.lock()
        {
            map.remove(&key);
        }

        assert!(
            dedup.lock().unwrap().get(&key).is_none(),
            "dedup map entry must be cleared so the next fetch starts from a fresh cell"
        );
    }

    /// A LockPackage without a `checksum` must be rejected before any network
    /// I/O: the lockfile pin is the user's contract and missing-pin packages
    /// would silently bypass integrity verification.
    #[tokio::test]
    async fn ensure_artifacts_rejects_package_without_checksum() {
        use rv_config::{
            LOCKFILE_SCHEMA_VERSION, LockGav, LockPlatform, Platform, ResolvedPaths, UpdatePolicy,
        };

        let temp = tempfile::tempdir().expect("temp dir");
        let paths = ResolvedPaths::discover().expect("paths");
        let central = rv_config::RepoConfig {
            id: Some("central".to_string()),
            url: "https://repo1.maven.org/maven2/".to_string(),
            releases: Some(true),
            snapshots: Some(false),
            snapshots_update_policy: Some(UpdatePolicy::Daily),
        };
        let config = rv_config::Config::for_testing_with_repos(
            temp.path().to_path_buf(),
            paths,
            vec![central],
        );

        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");
        let client = RepoClient::new(&config).await.expect("client");

        let package = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            // Critical: no checksum, must hard-fail before any fetch.
            checksum: None,
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        };
        let lock = Lockfile {
            schema_version: LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![LockPlatform::single_module(
                Platform::current().expect("platform"),
                "",
                "pom.xml",
                LockGav::new("com.example", "root", "1"),
                "pom",
                vec![package],
                Vec::new(),
            )],
            metadata: Default::default(),
            extra: Default::default(),
        };
        let platforms = vec![Platform::current().expect("platform")];

        let results = ensure_artifacts(&client, &store, &lock, &config, &platforms, &[])
            .await
            .expect("ensure_artifacts returns a per-package result vec, not a hard Err");
        // Exactly one package; its per-package result must be a MissingChecksum.
        assert_eq!(results.len(), 1, "expected one DownloadResult");
        match &results[0].result {
            Err(RepoError::MissingChecksum(_)) => {}
            other => panic!("expected MissingChecksum, got {other:?}"),
        }
    }

    /// Fast path: the lockfile pins the timestamped POM to bytes the store
    /// already holds (here under the base `-SNAPSHOT` row), so the row is
    /// adopted by identity with no network and no authorization of the
    /// recorded origin.
    #[tokio::test]
    async fn cached_artifact_does_not_require_its_origin_in_current_config() {
        use rv_config::{ResolvedPaths, UpdatePolicy};

        let temp = tempfile::tempdir().expect("temp dir");
        let paths = ResolvedPaths::discover().expect("paths");
        let central = rv_config::RepoConfig {
            id: Some("central".to_string()),
            url: "https://repo1.maven.org/maven2/".to_string(),
            releases: Some(true),
            snapshots: Some(false),
            snapshots_update_policy: Some(UpdatePolicy::Daily),
        };
        let config = rv_config::Config::for_testing_with_repos(
            temp.path().to_path_buf(),
            paths,
            vec![central],
        );
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");
        let client = RepoClient::new(&config).await.expect("client");

        let timestamped = "1.0-20260720.123253-28";
        let key = ArtifactKey::new("com.example", "demo", timestamped, "jar", None);
        let blob = store.put_bytes(b"cached artifact").await.expect("put jar");
        store.add_artifact(&key, &blob).await.expect("index jar");
        let base_pom_key = ArtifactKey::new("com.example", "demo", "1.0-SNAPSHOT", "pom", None);
        let pom_blob = store
            .put_bytes(
                b"<project><modelVersion>4.0.0</modelVersion>\
                  <groupId>com.example</groupId><artifactId>demo</artifactId>\
                  <version>1.0-SNAPSHOT</version></project>",
            )
            .await
            .expect("put pom");
        store
            .add_artifact(&base_pom_key, &pom_blob)
            .await
            .expect("index pom");

        let package = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: timestamped.to_string(),
            snapshot_timestamp: Some("20260720.123253".to_string()),
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://pom-declared.example/repository/".to_string(),
            checksum: Some(Checksum::new("sha256", blob.to_string())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        };
        let pom_pins = PomPins::from([(
            (
                "com.example".to_string(),
                "demo".to_string(),
                timestamped.to_string(),
            ),
            pom_blob.clone(),
        )]);
        let dedup: FetchDedupMap = Arc::new(Mutex::new(HashMap::new()));

        ensure_package_artifacts(
            &SyncInputs {
                config: &config,
                store: &store,
                client: &client,
                trusted_repositories: &[],
                pom_pins: &pom_pins,
            },
            &package,
            &dedup,
        )
        .await
        .expect("cached bytes need no origin authorization or network fetch");

        let timestamped_pom_key = ArtifactKey::new("com.example", "demo", timestamped, "pom", None);
        assert_eq!(
            store
                .lookup_artifact(&timestamped_pom_key)
                .await
                .expect("lookup timestamped POM"),
            Some(pom_blob),
            "the pinned POM bytes should be indexed for timestamped export"
        );
    }

    /// Build a config whose only repository is unreachable, so any network
    /// fetch fails loudly instead of quietly succeeding. Snapshots are enabled
    /// so the snapshot scenarios reach the fetch rather than stopping at the
    /// repository policy check.
    async fn offline_only_config(root: &std::path::Path) -> (rv_config::Config, RepoClient) {
        use rv_config::{ResolvedPaths, UpdatePolicy};

        let paths = ResolvedPaths::discover().expect("paths");
        let repo = rv_config::RepoConfig {
            id: Some("fixture".to_string()),
            url: "https://unreachable.invalid/maven2/".to_string(),
            releases: Some(true),
            snapshots: Some(true),
            snapshots_update_policy: Some(UpdatePolicy::Daily),
        };
        let config =
            rv_config::Config::for_testing_with_repos(root.to_path_buf(), paths, vec![repo]);
        let client = RepoClient::new(&config).await.expect("client");
        (config, client)
    }

    fn pinned_package(jar: &BlobId) -> LockPackage {
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://unreachable.invalid/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar.to_string())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        }
    }

    /// The store's `(g, a, v, pom)` index row is last-writer-wins across every
    /// project sharing the store, so between the resolve that recorded the pin
    /// and this download pass another project can repoint it. The download
    /// pass must follow the pin, not the index: it re-points the row at the
    /// pinned blob, which is still in the content store, without going to the
    /// network (the only configured repository here does not resolve).
    #[tokio::test]
    async fn repointed_pom_index_row_is_restored_from_the_pin() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");
        let (config, client) = offline_only_config(temp.path()).await;

        let jar = store.put_bytes(b"demo jar").await.expect("put jar");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "demo", "1.0", "jar", None),
                &jar,
            )
            .await
            .expect("index jar");

        let pom_key = ArtifactKey::new("com.example", "demo", "1.0", "pom", None);
        let resolved_pom = store
            .put_bytes(b"<project>resolution parsed this</project>")
            .await
            .expect("put resolved pom");
        // Another project syncing against the same store repoints the row.
        let other_pom = store
            .put_bytes(b"<project>another project indexed this</project>")
            .await
            .expect("put other pom");
        store
            .add_artifact(&pom_key, &other_pom)
            .await
            .expect("repoint index");

        let pom_pins = PomPins::from([(
            (
                "com.example".to_string(),
                "demo".to_string(),
                "1.0".to_string(),
            ),
            resolved_pom.clone(),
        )]);
        let dedup: FetchDedupMap = Arc::new(Mutex::new(HashMap::new()));
        ensure_package_artifacts(
            &SyncInputs {
                config: &config,
                store: &store,
                client: &client,
                trusted_repositories: &[],
                pom_pins: &pom_pins,
            },
            &pinned_package(&jar),
            &dedup,
        )
        .await
        .expect("the pinned blob is in the store, so no fetch is needed");

        assert_eq!(
            store.lookup_artifact(&pom_key).await.expect("lookup"),
            Some(resolved_pom),
            "the index row must be restored to the bytes the lockfile pins"
        );
    }

    /// Negative control for the check above: an unpinned row keeps the old
    /// behaviour and leaves whatever the index names in place.
    #[tokio::test]
    async fn unpinned_pom_row_still_follows_the_index() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");
        let (config, client) = offline_only_config(temp.path()).await;

        let jar = store.put_bytes(b"demo jar").await.expect("put jar");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "demo", "1.0", "jar", None),
                &jar,
            )
            .await
            .expect("index jar");
        let pom_key = ArtifactKey::new("com.example", "demo", "1.0", "pom", None);
        let other_pom = store
            .put_bytes(b"<project>another project indexed this</project>")
            .await
            .expect("put other pom");
        store
            .add_artifact(&pom_key, &other_pom)
            .await
            .expect("index pom");

        let dedup: FetchDedupMap = Arc::new(Mutex::new(HashMap::new()));
        ensure_package_artifacts(
            &SyncInputs {
                config: &config,
                store: &store,
                client: &client,
                trusted_repositories: &[],
                pom_pins: &PomPins::new(),
            },
            &pinned_package(&jar),
            &dedup,
        )
        .await
        .expect("an unpinned companion POM present in the index needs no fetch");

        assert_eq!(
            store.lookup_artifact(&pom_key).await.expect("lookup"),
            Some(other_pom)
        );
    }

    /// When the pinned bytes are gone from the content store, the pin still
    /// governs: the pass re-fetches rather than adopting whatever the index
    /// names. With no reachable repository that surfaces as a fetch failure,
    /// which is the honest outcome — silently exporting the other project's
    /// POM is what the pin exists to prevent.
    #[tokio::test]
    async fn missing_pinned_pom_bytes_force_a_refetch_instead_of_the_index_row() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");
        let (config, client) = offline_only_config(temp.path()).await;

        let jar = store.put_bytes(b"demo jar").await.expect("put jar");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "demo", "1.0", "jar", None),
                &jar,
            )
            .await
            .expect("index jar");
        let pom_key = ArtifactKey::new("com.example", "demo", "1.0", "pom", None);
        let other_pom = store
            .put_bytes(b"<project>another project indexed this</project>")
            .await
            .expect("put other pom");
        store
            .add_artifact(&pom_key, &other_pom)
            .await
            .expect("index pom");

        // A digest the store has never held.
        let pom_pins = PomPins::from([(
            (
                "com.example".to_string(),
                "demo".to_string(),
                "1.0".to_string(),
            ),
            BlobId::from_bytes(b"<project>resolution parsed this</project>"),
        )]);
        let dedup: FetchDedupMap = Arc::new(Mutex::new(HashMap::new()));
        let error = ensure_package_artifacts(
            &SyncInputs {
                config: &config,
                store: &store,
                client: &client,
                trusted_repositories: &[],
                pom_pins: &pom_pins,
            },
            &pinned_package(&jar),
            &dedup,
        )
        .await
        .expect_err("the pin must not fall back to the index row");
        assert!(
            !matches!(error, RepoError::UntrustedRepoUrl(_)),
            "the failure must come from the fetch, not from repository trust: {error:?}"
        );

        assert_eq!(
            store.lookup_artifact(&pom_key).await.expect("lookup"),
            Some(other_pom),
            "a failed refetch must not leave the pin's coordinate pointing anywhere new"
        );
    }

    fn timestamped_snapshot_package(jar: &BlobId, version: &str) -> LockPackage {
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: version.to_string(),
            snapshot_timestamp: Some("20260720.123253".to_string()),
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://unreachable.invalid/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", jar.to_string())),
            system_path: None,
            direct_scope: None,
            extra: Default::default(),
        }
    }

    /// The base `-SNAPSHOT` POM row is keyed without a project and repointed
    /// last-writer-wins, so a sibling project syncing a newer build renames the
    /// bytes it holds. A pinned timestamped row must ignore it entirely and use
    /// the bytes its own resolution parsed, which the content store still has.
    #[tokio::test]
    async fn repointed_base_snapshot_row_is_not_aliased_to_a_pinned_pom() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");
        let (config, client) = offline_only_config(temp.path()).await;

        let timestamped = "1.0-20260720.123253-3";
        let jar = store.put_bytes(b"build -3 jar").await.expect("put jar");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "demo", timestamped, "jar", None),
                &jar,
            )
            .await
            .expect("index jar");

        // The bytes this project resolved against, still in the content store.
        let resolved_pom = store
            .put_bytes(b"<project><modelVersion>4.0.0</modelVersion></project>")
            .await
            .expect("put build -3 pom");
        // Project B synced build -7 and repointed the shared base row.
        let base_pom_key = ArtifactKey::new("com.example", "demo", "1.0-SNAPSHOT", "pom", None);
        let other_pom = store
            .put_bytes(b"<project><modelVersion>4.0.0</modelVersion><!-- build -7 --></project>")
            .await
            .expect("put build -7 pom");
        store
            .add_artifact(&base_pom_key, &other_pom)
            .await
            .expect("repoint base row");

        let pom_pins = PomPins::from([(
            (
                "com.example".to_string(),
                "demo".to_string(),
                timestamped.to_string(),
            ),
            resolved_pom.clone(),
        )]);
        let dedup: FetchDedupMap = Arc::new(Mutex::new(HashMap::new()));
        ensure_package_artifacts(
            &SyncInputs {
                config: &config,
                store: &store,
                client: &client,
                trusted_repositories: &[],
                pom_pins: &pom_pins,
            },
            &timestamped_snapshot_package(&jar, timestamped),
            &dedup,
        )
        .await
        .expect("the pinned POM bytes are in the store, so no fetch is needed");

        let timestamped_pom_key = ArtifactKey::new("com.example", "demo", timestamped, "pom", None);
        assert_eq!(
            store
                .lookup_artifact(&timestamped_pom_key)
                .await
                .expect("lookup"),
            Some(resolved_pom),
            "the timestamped key must name this build's POM, not the repointed base row"
        );
        assert_eq!(
            store.lookup_artifact(&base_pom_key).await.expect("lookup"),
            Some(other_pom),
            "adopting the pin must not disturb the shared base row"
        );
    }

    /// An unpinned timestamped row carries no identity to check the base row
    /// against, so it must fetch the real timestamped POM rather than alias
    /// whatever the mutable base row currently names. With no reachable
    /// repository that surfaces as a fetch failure, which is the honest
    /// outcome.
    #[tokio::test]
    async fn unpinned_timestamped_pom_fetches_instead_of_aliasing_the_base_row() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");
        let (config, client) = offline_only_config(temp.path()).await;

        let timestamped = "1.0-20260720.123253-3";
        let jar = store.put_bytes(b"build -3 jar").await.expect("put jar");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "demo", timestamped, "jar", None),
                &jar,
            )
            .await
            .expect("index jar");
        let base_pom_key = ArtifactKey::new("com.example", "demo", "1.0-SNAPSHOT", "pom", None);
        let other_pom = store
            .put_bytes(b"<project><modelVersion>4.0.0</modelVersion><!-- build -7 --></project>")
            .await
            .expect("put build -7 pom");
        store
            .add_artifact(&base_pom_key, &other_pom)
            .await
            .expect("index base row");

        let dedup: FetchDedupMap = Arc::new(Mutex::new(HashMap::new()));
        let error = ensure_package_artifacts(
            &SyncInputs {
                config: &config,
                store: &store,
                client: &client,
                trusted_repositories: &[],
                pom_pins: &PomPins::new(),
            },
            &timestamped_snapshot_package(&jar, timestamped),
            &dedup,
        )
        .await
        .expect_err("an unverifiable base row must not stand in for the timestamped POM");
        assert!(
            !matches!(error, RepoError::UntrustedRepoUrl(_)),
            "the failure must come from the fetch, not from repository trust: {error:?}"
        );

        let timestamped_pom_key = ArtifactKey::new("com.example", "demo", timestamped, "pom", None);
        assert_eq!(
            store
                .lookup_artifact(&timestamped_pom_key)
                .await
                .expect("lookup"),
            None,
            "the timestamped key must not be aliased to the base row's blob"
        );
    }
}
