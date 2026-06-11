use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use chrono::DateTime;
use clap::{Args, Subcommand};
use futures::stream::{self, StreamExt};

use rv_config::{
    Checksum, Config, LOCKFILE_SCHEMA_VERSION, LockPackage, Lockfile, normalize_checksum_algorithm,
};
use rv_repo::{ArtifactRequest, RepoClient, Repository, normalize_repo_url, sha1_hex_file};
use rv_store::{ArtifactKey, BlobId, Store};

use crate::commands::{path_to_forward_slashes, read_lockfile};
use crate::error::{CliError, Result};
use crate::output::{
    ProgressReporter, Spinner, Table, heading, is_json_mode, json_result, quiet_enabled, success,
    warning,
};

#[derive(Debug, Args)]
#[command(about = "Inspect and verify lockfile artifacts")]
pub struct LockArgs {
    #[command(subcommand)]
    pub command: LockCommand,
}

#[derive(Debug, Subcommand)]
pub enum LockCommand {
    /// Verify that artifacts in rv.lock exist in the store
    Verify(LockVerifyArgs),
    /// Show lockfile metadata and statistics
    Info,
}

#[derive(Debug, Args)]
pub struct LockVerifyArgs {
    /// Re-download missing or corrupted blobs
    #[arg(long)]
    pub download: bool,
}

pub async fn run(args: &LockArgs, project_root: &Path) -> Result<()> {
    match &args.command {
        LockCommand::Verify(verify_args) => verify(verify_args, project_root).await,
        LockCommand::Info => lock_info(project_root),
    }
}

fn lock_info(project_root: &Path) -> Result<()> {
    let config = Config::load(project_root)?;

    // Route through the shared `read_lockfile` helper so a non-file at the
    // lockfile path (a directory, FIFO, etc.) reports the precise
    // `LockfileNotAFile` diagnostic instead of the bespoke `is_file()` check
    // that collapsed every non-regular-file case into "missing".
    let lock = read_lockfile(&config)?;
    let metadata = fs::metadata(&config.lock_path)?;
    // `as i64` wraps past year 2554; fall back to "unknown" instead.
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .and_then(|secs| DateTime::from_timestamp(secs, 0))
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let platform_count = lock.platforms.len();
    let mut total_packages = 0usize;
    let mut unique_coords: HashSet<String> = HashSet::new();

    for platform in &lock.platforms {
        total_packages += platform.packages.len();
        for pkg in &platform.packages {
            unique_coords.insert(pkg.format_coord());
        }
    }

    if is_json_mode() {
        let platforms: Vec<_> = lock
            .platforms
            .iter()
            .map(|p| {
                serde_json::json!({
                    "platform": p.platform.to_string(),
                    "packages": p.packages.len(),
                })
            })
            .collect();
        json_result(
            true,
            serde_json::json!({
                "path": path_to_forward_slashes(&config.lock_path),
                "schema_version": lock.schema_version,
                "latest_schema_version": LOCKFILE_SCHEMA_VERSION,
                "last_modified": modified,
                "platform_count": platform_count,
                "total_packages": total_packages,
                "unique_artifacts": unique_coords.len(),
                "platforms": platforms,
            }),
        );
        return Ok(());
    }

    // Heading is decorative chatter -> stderr; the table is the structured
    // human payload -> stdout.
    if !quiet_enabled() {
        eprintln!("{}", heading("Lockfile info"));
    }

    let mut table = Table::new(["Property", "Value"]);
    table.add_row(["Path", &config.lock_path.display().to_string()]);
    table.add_row(["Schema version", &lock.schema_version.to_string()]);
    table.add_row([
        "Latest schema version",
        &LOCKFILE_SCHEMA_VERSION.to_string(),
    ]);
    table.add_row(["Last modified", &modified]);
    table.add_row(["Platforms", &platform_count.to_string()]);

    table.add_row(["Total packages", &total_packages.to_string()]);
    table.add_row(["Unique artifacts", &unique_coords.len().to_string()]);

    if !lock.platforms.is_empty() {
        table.add_row(["", ""]);
        table.add_row(["Platform breakdown", ""]);
        for platform in &lock.platforms {
            let key = format!("  {}", platform.platform);
            let value = format!("{} packages", platform.packages.len());
            table.add_row([&key, &value]);
        }
    }

    println!("{}", table.render());
    Ok(())
}

async fn verify(args: &LockVerifyArgs, project_root: &Path) -> Result<()> {
    let config = Config::load(project_root)?;
    verify_inner(args, &config).await?;
    Ok(())
}

async fn verify_inner(args: &LockVerifyArgs, config: &Config) -> Result<()> {
    let lock = read_lockfile(config)?;
    // Open the store once into an Arc and share that single Arc
    // through both the verification fan-out and the optional download
    // fan-out. Re-cloning the underlying `Store` into two distinct
    // `Arc<Store>` containers would defeat the Arc (each worker would
    // still hold its own clone of the inner state).
    let store: Arc<Store> = Arc::new(Store::open(&config.paths.store_dir)?);

    // Each `verify_blob` is a SHA-256 over the on-disk blob, a synchronous
    // CPU+IO call. Doing them sequentially burns multi-seconds on real
    // lockfiles. Fan them out across spawn_blocking workers, capped by the
    // user's configured network concurrency (with a sane floor) so a small
    // setting still gets some parallelism.
    let parallelism = config.network.concurrency.max(4);

    // Pre-compute the per-package verification inputs so the parallel stage
    // is pure work, with no Config / Lockfile access needed.
    //
    // The lockfile parser accepts both `sha256` and `sha1` pins. By default
    // `rv sync` verifies against the sha256 sidecar when the repository
    // publishes one and otherwise falls back to the sha1 sidecar (emitting
    // the WEAK_HASH_FALLBACK warning), so a lockfile produced against a
    // SHA-1-only repository legitimately carries SHA-1 pins. Verify must
    // accept the same set or it falsely rejects those lockfiles.
    let (prepared, no_checksum) = prepare_targets(&lock)?;

    let results: Vec<Result<(LockPackage, ArtifactKey, ExpectedPin, VerifyStatus)>> =
        stream::iter(prepared.into_iter())
            .map(|(package, key, expected)| {
                // Share the single Arc opened above instead of
                // building a fresh `Arc<Store>` wrapping yet another
                // inner clone.
                let store = Arc::clone(&store);
                async move {
                    // For SHA-1 pins the on-disk lookup needs the
                    // async index API; resolve the BlobId here, then let
                    // the blocking task focus on the hash pass.
                    let resolved_blob = match &expected {
                        ExpectedPin::Sha256(id) => Some(id.clone()),
                        ExpectedPin::Sha1(_) => store.lookup_artifact(&key).await?,
                    };
                    let expected_for_task = expected.clone();
                    let status = tokio::task::spawn_blocking(move || {
                        verify_pin(&store, resolved_blob.as_ref(), &expected_for_task)
                    })
                    .await
                    .map_err(|e| CliError::Message(format!("verify task panicked: {e}")))??;
                    Ok((package, key, expected, status))
                }
            })
            .buffer_unordered(parallelism)
            .collect()
            .await;

    let mut verified = 0usize;
    let mut missing = Vec::new();
    let mut corrupt = Vec::new();
    for entry in results {
        let (package, key, expected, status) = entry?;
        match status {
            VerifyStatus::Ok => {
                verified = verified.saturating_add(1);
            }
            VerifyStatus::Missing => missing.push(VerifyTarget {
                package,
                key,
                expected,
                actual: None,
            }),
            VerifyStatus::Corrupt { actual } => corrupt.push(VerifyTarget {
                package,
                key,
                expected,
                actual: Some(actual),
            }),
        }
    }

    let mut downloaded = 0usize;
    if args.download && (!missing.is_empty() || !corrupt.is_empty()) {
        let progress = std::sync::Arc::new(ProgressReporter::new());
        let client = RepoClient::new(config).await?.with_progress(progress);

        let mut targets = Vec::new();
        targets.append(&mut missing);
        targets.append(&mut corrupt);
        let download_count = targets.len();

        let spinner = Spinner::start("lock verify: downloading artifacts");
        // Pre-resolve the repository for each target before the fan-out so
        // the parallel task body only needs &self captures (Config is not
        // Clone, and pinning it inside an Arc would require threading it
        // through everything).
        let dispatch: Vec<(VerifyTarget, Repository)> = targets
            .into_iter()
            .map(|target| {
                let repo = repository_for_package(config, &target.package);
                (target, repo)
            })
            .collect();
        let client = Arc::new(client);
        // Keep using the single Arc<Store> from verify_inner.
        let store_arc = Arc::clone(&store);
        // Fan downloads out the same way verification did: each fetch is
        // independent and bottlenecked on the network, so a sequential
        // await chain would leave bandwidth on the floor.
        //
        // Route through the atomic `fetch_artifact_to_store_and_index`
        // so the blob persist and the artifact-key → blob index commit
        // happen under one held `StoreLock`. A two-step
        // `fetch_artifact_to_store` → `Store::add_artifact` would reopen
        // the window that `put_stream_and_index` is designed to close:
        // a concurrent `prune_blobs` could observe the freshly-persisted
        // blob with no row pointing at it and delete it before the index
        // write landed.
        //
        // No explicit pre-fetch `remove_file` call is needed either: it
        // would carry a TOCTOU between `exists_async` + `is_file` and
        // `remove_file`, and `put_stream_and_index` already replaces the
        // on-disk blob atomically.
        let download_results: Vec<Result<()>> = stream::iter(dispatch.into_iter())
            .map(|(target, repo)| {
                let client = Arc::clone(&client);
                let store = Arc::clone(&store_arc);
                async move {
                    let request = artifact_request(&target.package);
                    let blob = client
                        .fetch_artifact_to_store_and_index(&repo, &request, &store, &target.key)
                        .await?;
                    // Confirm the downloaded blob matches the lockfile
                    // pin under whichever algorithm the lockfile recorded.
                    // For SHA-256 the BlobId already *is* the digest. For
                    // SHA-1 we re-hash the on-disk blob (the store is
                    // SHA-256 keyed, so there is no shortcut).
                    match &target.expected {
                        ExpectedPin::Sha256(expected) => {
                            if &blob != expected {
                                return Err(CliError::LockfileMismatch {
                                    details: format!("checksum mismatch for {}", target.key),
                                });
                            }
                        }
                        ExpectedPin::Sha1(expected) => {
                            let path = store.get_path(&blob);
                            let expected = expected.clone();
                            let key_display = target.key.to_string();
                            tokio::task::spawn_blocking(move || -> Result<()> {
                                let actual = sha1_hex_file(&path)?;
                                if actual != expected {
                                    return Err(CliError::LockfileMismatch {
                                        details: format!(
                                            "checksum mismatch for {key_display}: \
                                             expected sha1 {expected}, got {actual}"
                                        ),
                                    });
                                }
                                Ok(())
                            })
                            .await
                            .map_err(|e| {
                                CliError::Message(format!("sha1 verify task panicked: {e}"))
                            })??;
                        }
                    }
                    Ok(())
                }
            })
            .buffer_unordered(parallelism)
            .collect()
            .await;
        for result in download_results {
            result?;
        }
        spinner.finish(success("done"));
        verified += download_count;
        downloaded = download_count;
    }

    if missing.is_empty() && corrupt.is_empty() && no_checksum.is_empty() {
        if is_json_mode() {
            json_result(
                true,
                serde_json::json!({
                    "verified": verified,
                    "missing": 0,
                    "corrupt": 0,
                    "no_checksum": 0,
                    "downloaded": downloaded,
                }),
            );
        } else if downloaded > 0 {
            eprintln!("{}", success(format!("verified {} artifacts", verified)));
        } else if !quiet_enabled() {
            eprintln!("{}", success("lockfile verified"));
        }
        return Ok(());
    }

    let summary = failure_summary(missing.len(), corrupt.len(), no_checksum.len());
    if is_json_mode() {
        // Emit a structured failure envelope (matching the success-path
        // shape) so JSON consumers see the same `data.{verified,missing,
        // corrupt,no_checksum}` fields on a failed verify as on a passing
        // one. Then return `AlreadyReported` so the top-level handler exits
        // with `LOCKFILE_MISMATCH` without printing a second envelope.
        json_result(
            false,
            serde_json::json!({
                "verified": verified,
                "missing": missing.len(),
                "corrupt": corrupt.len(),
                "no_checksum": no_checksum.len(),
                "downloaded": downloaded,
                "exit_code": crate::error::ExitCodes::LOCKFILE_MISMATCH,
                "error": summary,
            }),
        );
        return Err(CliError::AlreadyReported {
            exit_code: crate::error::ExitCodes::LOCKFILE_MISMATCH,
        });
    }

    if !quiet_enabled() {
        eprintln!("{}", heading("Lock verification failed"));
        for target in &missing {
            eprintln!("  {}", warning(format!("missing {0}", target.key)));
        }
        for target in &corrupt {
            if let Some(actual) = &target.actual {
                eprintln!(
                    "  {}",
                    warning(format!("corrupt {0} (found {1})", target.key, actual))
                );
            } else {
                eprintln!("  {}", warning(format!("corrupt {0}", target.key)));
            }
        }
        for key in &no_checksum {
            eprintln!("  {}", warning(format!("no checksum recorded for {key}")));
        }
    }
    Err(CliError::LockfileMismatch { details: summary })
}

/// Human/JSON summary line for a failed verify. The `no checksum` clause is
/// only appended when present so the established "X missing, Y corrupt"
/// message stays stable for the common cases.
fn failure_summary(missing: usize, corrupt: usize, no_checksum: usize) -> String {
    let mut summary = format!("{missing} missing, {corrupt} corrupt");
    if no_checksum > 0 {
        summary.push_str(&format!(", {no_checksum} with no checksum recorded"));
    }
    summary
}

/// Pre-compute the per-package verification inputs for the parallel stage.
///
/// Returns `(prepared, no_checksum)`: packages with a parseable pin ready to
/// verify, and the keys of packages that record no checksum at all (reported
/// as per-package findings rather than aborting the batch). Packages with a
/// `system_path` and pom-packaged packages are skipped, mirroring the
/// predicate `rv_repo::sync::ensure_artifacts` applies: neither is ever
/// downloaded into the store by sync, so on a fresh machine they are
/// legitimately absent and must not be reported as missing.
#[allow(clippy::type_complexity)]
fn prepare_targets(
    lock: &Lockfile,
) -> Result<(
    Vec<(LockPackage, ArtifactKey, ExpectedPin)>,
    Vec<ArtifactKey>,
)> {
    let mut prepared = Vec::new();
    let mut no_checksum = Vec::new();
    for platform in &lock.platforms {
        for package in &platform.packages {
            if package.system_path.is_some() || package.packaging == "pom" {
                continue;
            }
            let key = artifact_key(package);
            let Some(checksum) = package.checksum.as_ref() else {
                no_checksum.push(key);
                continue;
            };
            let expected = expected_pin(&key, checksum)?;
            prepared.push((package.clone(), key, expected));
        }
    }
    Ok((prepared, no_checksum))
}

fn artifact_request(package: &LockPackage) -> ArtifactRequest {
    let request = ArtifactRequest::new(&package.group_id, &package.artifact_id, &package.version)
        .with_packaging(package.packaging.clone());
    if let Some(classifier) = &package.classifier {
        request.with_classifier(classifier.clone())
    } else {
        request
    }
}

fn artifact_key(package: &LockPackage) -> ArtifactKey {
    ArtifactKey::new(
        package.group_id.clone(),
        package.artifact_id.clone(),
        package.version.clone(),
        package.packaging.clone(),
        package.classifier.clone(),
    )
}

fn repository_for_package(config: &Config, package: &LockPackage) -> Repository {
    let wanted = normalize_repo_url(&package.repo_url);
    for repo in config.repositories() {
        if normalize_repo_url(&repo.url) == wanted {
            return Repository::from(repo);
        }
    }
    Repository::new(None, wanted, true, true)
}

/// Parsed lockfile pin for a single package.
///
/// The lockfile parser canonicalises both `sha256` and `sha1` (see
/// `rv_config::normalize_checksum_algorithm`). By default `rv sync` falls
/// back to verifying the SHA-1 sidecar when a repository only publishes
/// SHA-1 (emitting the WEAK_HASH_FALLBACK warning), so it can write SHA-1
/// pins. Verify and the downstream consumers must accept the same set or
/// they reject lockfiles the sync path happily produced.
#[derive(Debug, Clone)]
enum ExpectedPin {
    /// Maps directly to a `BlobId`, so the store CAS path is a cheap
    /// identity check (no second hash pass needed).
    Sha256(BlobId),
    /// 40-char lowercase hex SHA-1 digest. The store is SHA-256 keyed,
    /// so verification requires re-hashing the on-disk blob with SHA-1.
    Sha1(String),
}

fn expected_pin(key: &ArtifactKey, checksum: &Checksum) -> Result<ExpectedPin> {
    let canonical = normalize_checksum_algorithm(&checksum.algorithm).ok_or_else(|| {
        CliError::LockfileMismatch {
            details: format!("unsupported checksum {} for {key}", checksum.algorithm),
        }
    })?;
    match canonical {
        "sha256" => {
            let id =
                BlobId::from_str(&checksum.digest).map_err(|e| CliError::Message(e.to_string()))?;
            Ok(ExpectedPin::Sha256(id))
        }
        "sha1" => {
            let digest = checksum.digest.trim().to_ascii_lowercase();
            if digest.len() != 40 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(CliError::LockfileMismatch {
                    details: format!(
                        "sha1 digest for {key} must be 40 hex chars, got {:?}",
                        checksum.digest
                    ),
                });
            }
            Ok(ExpectedPin::Sha1(digest))
        }
        // `normalize_checksum_algorithm` only returns the two canonical
        // spellings above, so this arm is unreachable in practice.
        other => Err(CliError::LockfileMismatch {
            details: format!("unsupported checksum {other} for {key}"),
        }),
    }
}

fn verify_pin(
    store: &Store,
    resolved_blob: Option<&BlobId>,
    expected: &ExpectedPin,
) -> Result<VerifyStatus> {
    match expected {
        ExpectedPin::Sha256(expected) => {
            let path = store.get_path(expected);
            if !path.is_file() {
                return Ok(VerifyStatus::Missing);
            }
            let actual = BlobId::from_file(&path)?;
            if &actual != expected {
                return Ok(VerifyStatus::Corrupt {
                    actual: actual.as_str().to_string(),
                });
            }
            Ok(VerifyStatus::Ok)
        }
        ExpectedPin::Sha1(expected) => {
            // The store is SHA-256 keyed, so we cannot derive the BlobId
            // from a SHA-1 digest. The caller resolved the BlobId via the
            // artifact-key index; missing means the user has never synced
            // this package against this store.
            let Some(blob) = resolved_blob else {
                return Ok(VerifyStatus::Missing);
            };
            let path = store.get_path(blob);
            if !path.is_file() {
                return Ok(VerifyStatus::Missing);
            }
            let actual = sha1_hex_file(&path)?;
            if &actual != expected {
                return Ok(VerifyStatus::Corrupt { actual });
            }
            Ok(VerifyStatus::Ok)
        }
    }
}

#[derive(Debug)]
struct VerifyTarget {
    package: LockPackage,
    key: ArtifactKey,
    expected: ExpectedPin,
    actual: Option<String>,
}

#[derive(Debug)]
enum VerifyStatus {
    Ok,
    Missing,
    Corrupt { actual: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::{Digest as _, Sha1};
    use tempfile::TempDir;

    #[tokio::test]
    async fn verify_pin_returns_ok_when_blob_exists() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let bytes = b"test content";
        let blob_id = store.put_bytes(bytes).await.expect("put bytes");

        let status = verify_pin(&store, None, &ExpectedPin::Sha256(blob_id)).expect("verify");
        assert!(matches!(status, VerifyStatus::Ok));
    }

    #[tokio::test]
    async fn verify_pin_returns_missing_when_blob_not_found() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let missing_id = BlobId::from_bytes(b"nonexistent");

        let status = verify_pin(&store, None, &ExpectedPin::Sha256(missing_id)).expect("verify");
        assert!(matches!(status, VerifyStatus::Missing));
    }

    #[tokio::test]
    async fn verify_pin_returns_corrupt_when_hash_mismatch() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");

        // Put a blob
        let bytes = b"original content";
        let blob_id = store.put_bytes(bytes).await.expect("put bytes");

        // Corrupt it by overwriting with different content.
        // CAS blobs land at 0o444 post-publish; rewind the bit so this
        // simulated tamper isn't blocked by the read-only mode.
        let path = store.get_path(&blob_id);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).expect("stat blob").permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&path, perms).expect("chmod blob");
        }
        std::fs::write(&path, b"corrupted").expect("corrupt file");

        let status = verify_pin(&store, None, &ExpectedPin::Sha256(blob_id)).expect("verify");
        assert!(matches!(status, VerifyStatus::Corrupt { .. }));
    }

    /// A SHA-1 pin should verify against the on-disk blob by
    /// SHA-1-hashing it. The store is SHA-256 keyed, so the caller must
    /// pre-resolve the BlobId via the artifact-key index.
    #[tokio::test]
    async fn verify_pin_sha1_ok_when_digest_matches() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let bytes = b"sha1-pinned content";
        let blob_id = store.put_bytes(bytes).await.expect("put bytes");

        // Compute the actual SHA-1 of the bytes to use as the pin.
        let mut hasher = Sha1::new();
        hasher.update(bytes);
        let sha1_hex = hex::encode(hasher.finalize());

        let status =
            verify_pin(&store, Some(&blob_id), &ExpectedPin::Sha1(sha1_hex)).expect("verify");
        assert!(matches!(status, VerifyStatus::Ok));
    }

    #[tokio::test]
    async fn verify_pin_sha1_missing_when_not_indexed() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let status = verify_pin(&store, None, &ExpectedPin::Sha1("a".repeat(40))).expect("verify");
        assert!(matches!(status, VerifyStatus::Missing));
    }

    #[tokio::test]
    async fn verify_pin_sha1_corrupt_when_digest_mismatches() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let blob_id = store
            .put_bytes(b"original content")
            .await
            .expect("put bytes");
        // A 40-char hex digest that cannot match the real SHA-1.
        let bad_sha1 = "0".repeat(40);
        let status =
            verify_pin(&store, Some(&blob_id), &ExpectedPin::Sha1(bad_sha1)).expect("verify");
        assert!(matches!(status, VerifyStatus::Corrupt { .. }));
    }

    fn lock_with_packages(packages: Vec<LockPackage>) -> Lockfile {
        let platform = rv_config::Platform::new("linux", "x86_64").unwrap();
        let mut lock = Lockfile::new();
        lock.platforms = vec![rv_config::LockPlatform {
            platform,
            packages,
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];
        lock
    }

    fn lock_package(
        artifact: &str,
        packaging: &str,
        checksum: Option<Checksum>,
        system_path: Option<&str>,
    ) -> LockPackage {
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: artifact.to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: packaging.to_string(),
            classifier: None,
            repo_url: "https://repo.example/m2/".to_string(),
            checksum,
            system_path: system_path.map(str::to_string),
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    const SHA256_A: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    /// Packages without a recorded checksum become per-package findings; the
    /// rest of the batch is still prepared instead of aborting on the first.
    #[test]
    fn prepare_targets_collects_checksumless_packages_and_continues() {
        let lock = lock_with_packages(vec![
            lock_package("no-pin-1", "jar", None, None),
            lock_package(
                "pinned",
                "jar",
                Some(Checksum::new("sha256", SHA256_A)),
                None,
            ),
            lock_package("no-pin-2", "jar", None, None),
        ]);
        let (prepared, no_checksum) = prepare_targets(&lock).expect("prepare");
        assert_eq!(prepared.len(), 1, "the pinned package must still verify");
        assert_eq!(prepared[0].0.artifact_id, "pinned");
        assert_eq!(no_checksum.len(), 2, "both checksum-less packages reported");
    }

    /// Pom-packaged and system-path packages are skipped, mirroring
    /// `rv_repo::sync::ensure_artifacts`: sync never stores them, so verify
    /// must not report them missing on a fresh machine.
    #[test]
    fn prepare_targets_skips_pom_and_system_path_packages() {
        let lock = lock_with_packages(vec![
            lock_package("bom", "pom", Some(Checksum::new("sha256", SHA256_A)), None),
            lock_package("pom-no-pin", "pom", None, None),
            lock_package("local", "jar", None, Some("/opt/local.jar")),
            lock_package("real", "jar", Some(Checksum::new("sha256", SHA256_A)), None),
        ]);
        let (prepared, no_checksum) = prepare_targets(&lock).expect("prepare");
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].0.artifact_id, "real");
        assert!(
            no_checksum.is_empty(),
            "skipped packages must not surface as checksum-less findings"
        );
    }

    #[test]
    fn failure_summary_appends_no_checksum_clause_only_when_present() {
        assert_eq!(failure_summary(2, 1, 0), "2 missing, 1 corrupt");
        assert_eq!(
            failure_summary(0, 0, 3),
            "0 missing, 0 corrupt, 3 with no checksum recorded"
        );
    }

    #[test]
    fn expected_pin_parses_sha256() {
        let key = ArtifactKey::new("g", "a", "1", "jar", None);
        // Use a valid 64-char hex digest (SHA256 length)
        let digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let checksum = rv_config::Checksum::new("sha256", digest);
        let result = expected_pin(&key, &checksum).expect("pin");
        match result {
            ExpectedPin::Sha256(id) => assert_eq!(id.as_str(), digest),
            other => panic!("expected sha256, got {other:?}"),
        }
    }

    /// The lockfile parser and sync path both accept SHA-1 pins, so verify
    /// must accept them too: a 40-char hex SHA-1 digest must parse to
    /// `ExpectedPin::Sha1`.
    #[test]
    fn expected_pin_parses_sha1() {
        let key = ArtifactKey::new("g", "a", "1", "jar", None);
        let digest = "aabbccddeeff00112233445566778899aabbccdd";
        let checksum = rv_config::Checksum::new("sha1", digest);
        let result = expected_pin(&key, &checksum).expect("pin");
        match result {
            ExpectedPin::Sha1(d) => assert_eq!(d, digest),
            other => panic!("expected sha1, got {other:?}"),
        }
    }

    #[test]
    fn expected_pin_rejects_unsupported_algorithm() {
        let key = ArtifactKey::new("g", "a", "1", "jar", None);
        let checksum = rv_config::Checksum::new("md5", "abc123");
        let err = expected_pin(&key, &checksum).expect_err("md5 must be rejected");
        assert!(matches!(err, CliError::LockfileMismatch { .. }));
    }

    /// Regression for the verify fan-out: 50 small blobs all verify Ok when
    /// processed through the same `stream + spawn_blocking + buffer_unordered`
    /// pattern that `verify_inner` uses. This asserts only correctness, not
    /// wall-clock speedup: a wall-clock comparison against a serial baseline
    /// is inherently flaky on single-core CI runners and container-capped
    /// hosts, where a tight serial loop over tiny blobs frequently beats the
    /// task-spawn overhead. Correctness is what the fan-out must guarantee.
    #[tokio::test]
    async fn parallel_verify_handles_many_blobs() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");

        // 50 unique small blobs.
        let mut ids = Vec::with_capacity(50);
        for i in 0..50u32 {
            let payload = format!("blob-{i:08}").repeat(64).into_bytes();
            let id = store.put_bytes(&payload).await.expect("put");
            ids.push(id);
        }

        // Parallel fan-out matching verify_inner's pattern.
        let store_arc = Arc::new(store.clone());
        let results: Vec<Result<VerifyStatus>> = stream::iter(ids.into_iter())
            .map(|id| {
                let store = Arc::clone(&store_arc);
                async move {
                    tokio::task::spawn_blocking(move || {
                        verify_pin(&store, None, &ExpectedPin::Sha256(id))
                    })
                    .await
                    .map_err(|e| CliError::Message(format!("panic: {e}")))?
                }
            })
            .buffer_unordered(8)
            .collect()
            .await;

        for r in results {
            assert!(matches!(r.expect("parallel"), VerifyStatus::Ok));
        }
    }
}
