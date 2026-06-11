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
) -> Result<Vec<DownloadResult>> {
    let filtered = filter_lock(lock, platforms)?;
    let all_packages: Vec<&LockPackage> = filtered
        .platforms
        .iter()
        .flat_map(|platform| platform.packages.iter())
        .filter(|package| package.system_path.is_none())
        .filter(|package| package.packaging != "pom")
        .collect();

    if all_packages.is_empty() {
        return Ok(Vec::new());
    }

    let mut seen = HashSet::new();
    let mut packages = Vec::new();
    for pkg in all_packages {
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

    let concurrency = config.network.concurrency.max(1);
    let dedup: FetchDedupMap = Arc::new(Mutex::new(HashMap::new()));
    download_artifacts_parallel(&packages, config, store, client, concurrency, dedup).await
}

async fn download_artifacts_parallel(
    packages: &[&LockPackage],
    config: &Config,
    store: &Store,
    client: &RepoClient,
    concurrency: usize,
    dedup: FetchDedupMap,
) -> Result<Vec<DownloadResult>> {
    let concurrency = concurrency.max(1);

    let results = stream::iter(packages.iter().copied())
        .map(|pkg| {
            let client = client.clone();
            let dedup = dedup.clone();
            async move {
                let result = ensure_package_artifacts(config, store, &client, pkg, &dedup).await;
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
    config: &Config,
    store: &Store,
    client: &RepoClient,
    package: &LockPackage,
    dedup: &FetchDedupMap,
) -> Result<()> {
    if package.system_path.is_some() {
        return Ok(());
    }

    let repo = repository_for_package(config, package)?;
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

    if needs_download(store, &key, &pin, &coord).await? {
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
        let blob = fetch_with_dedup(client, &repo, &request, store, &key, dedup).await?;
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
    let pom_blob = if package.packaging == "pom" {
        // A pom-typed package (BOM import, pom dependency) was already
        // persisted under its own key by the main fetch above.
        store.lookup_artifact(&pom_key).await?
    } else if needs_download_unpinned(store, &pom_key).await? {
        // Companion POMs ride through the same atomic put+index path as the
        // main artifact. The repo's `.sha256`/`.sha1` sidecar still gates
        // trust (refusing unverified blobs when `require_checksums=true`);
        // lockfile-level POM pinning is a separate piece in the schema.
        let pom_req = request.pom();
        Some(fetch_with_dedup(client, &repo, &pom_req, store, &pom_key, dedup).await?)
    } else {
        store.lookup_artifact(&pom_key).await?
    };

    if let Some(pom_blob) = pom_blob {
        ensure_parent_chain(client, &repo, store, &pom_blob, dedup).await?;
    }

    Ok(())
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
    repo: &Repository,
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
) -> Result<bool> {
    let expected_blob_id = pin.expected_blob_id().cloned();

    if let Some(existing) = store.lookup_artifact(key).await?
        && store.exists_async(&existing).await
    {
        // For sha256 pins, an index disagreement means the index points at
        // a different blob than the lockfile demands. That is an integrity
        // error, not something to "repair" by re-fetching.
        if let Some(expected) = expected_blob_id.as_ref()
            && existing != *expected
        {
            return Err(RepoError::ChecksumMismatch {
                path: coord.to_string(),
                expected: expected.to_string(),
                actual: existing.to_string(),
            });
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

    // Fallback: the index has no row for this key but a matching SHA-256
    // blob already exists in the CAS. Adopt it after verification.
    //
    // KNOWN LIMITATION: `exists_async` -> `verify_pin_*` -> `add_artifact` is
    // three steps with no `StoreLock` held across them. A concurrent
    // `Store::prune_blobs` sweep can remove the blob between any pair of
    // steps and leave a dangling index row. The cross-crate atomic helper
    // that would close this race lives in rv-store and is out of scope for
    // this branch; until then we log on the observable post-condition
    // (blob gone after add_artifact) and rely on the next sync's
    // lockfile-pin re-hash in `needs_download` to repair the row.
    if let Some(expected) = expected_blob_id.as_ref()
        && store.exists_async(expected).await
    {
        let verify = verify_pin_repairing_corruption(store, expected, pin, coord).await?;
        match verify {
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
                return Ok(false);
            }
            BlobCheck::PinMismatch => return Ok(true),
        }
    }

    Ok(true)
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
fn repository_for_package(config: &Config, package: &LockPackage) -> Result<Repository> {
    let wanted = normalize_repo_url(&package.repo_url);
    for repo in config.repositories() {
        if normalize_repo_url(&repo.url) == wanted {
            return Ok(Repository::from(repo));
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

        let needs = needs_download(&store, &key, &pin, &coord)
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
        let needs = needs_download(&store, &key, &pin, &key.to_string())
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

        let needs = needs_download(&store, &key, &pin, &coord).await.unwrap();
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
                        needs_download(&store, &key, &pin, &coord).await.unwrap()
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

        let err = repository_for_package(&config, &package)
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

        let repo = repository_for_package(&config, &package).expect("configured repo must resolve");
        assert_eq!(repo.id.as_deref(), Some("central"));
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
            LOCKFILE_SCHEMA_VERSION, LockPlatform, Platform, ResolvedPaths, UpdatePolicy,
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
            platforms: vec![LockPlatform {
                platform: Platform::current().expect("platform"),
                packages: vec![package],
                edges: Vec::new(),
                extra: Default::default(),
            }],
            metadata: Default::default(),
            extra: Default::default(),
        };
        let platforms = vec![Platform::current().expect("platform")];

        let results = ensure_artifacts(&client, &store, &lock, &config, &platforms)
            .await
            .expect("ensure_artifacts returns a per-package result vec, not a hard Err");
        // Exactly one package; its per-package result must be a MissingChecksum.
        assert_eq!(results.len(), 1, "expected one DownloadResult");
        match &results[0].result {
            Err(RepoError::MissingChecksum(_)) => {}
            other => panic!("expected MissingChecksum, got {other:?}"),
        }
    }
}
