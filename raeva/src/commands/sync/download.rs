//! Downloading the locked artifacts and mapping download failures to the
//! command's error and exit code.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::StreamExt;
use rv_config::Config;
use rv_lock::{LockOrigins, Lockfile, PinnedRow, Platform};
use rv_maven_types::{BlobId, Digest};
use rv_repo::{ArtifactRequest, LockRepositorySelector, RepoClient, Repository, RestoreContext};
use rv_resolver::RootRepositories;
use rv_store::Store;
use tokio::task::JoinSet;

use crate::commands::lock_inputs::ReactorModel;
use crate::error::report::LISTED_FAILURES;
use crate::error::{CliError, Result};
use crate::output::command_line;

pub(super) async fn ensure_artifacts(
    lock: &Lockfile,
    store: &Store,
    contexts: &[RestoreContext<'_>],
) -> Result<()> {
    let results = rv_repo::ensure_artifacts(store, lock, contexts).await?;

    // A mismatch against a lock pin means raeva.lock no longer describes what
    // the repository serves, which a new `raeva sync` fixes. Every other
    // failure, a sidecar mismatch included, keeps its own class through
    // `CliError::Download`, so a transient error still exits as a network
    // failure.
    let mut failures = Vec::new();
    let mut checksum_failure_lines = Vec::new();
    let mut first_repo_error: Option<rv_repo::RepoError> = None;
    for rv_repo::DownloadResult {
        package, result, ..
    } in results
    {
        let Err(err) = result else {
            continue;
        };
        if let rv_repo::RepoError::ChecksumMismatch {
            subject,
            expected,
            actual,
            check: rv_repo::IntegritySource::LockPin,
            ..
        } = &err
        {
            // Render the coordinate and the two hashes verbatim. The
            // coordinate the mismatch is reported under names which pin
            // failed, and it is not always the package's own artifact: a
            // package's companion POM carries a `...:pom` coordinate and its
            // own pin.
            checksum_failure_lines.push(format!(
                "{subject}: expected {} {}, got {}",
                expected.algorithm(),
                expected.hex(),
                actual.hex()
            ));
        } else {
            failures.push(format!("{package}: {err}"));
            first_repo_error.get_or_insert(err);
        }
    }

    if !checksum_failure_lines.is_empty() {
        return Err(replaced_files(format_checksum_failure_details(
            &checksum_failure_lines,
            &failures,
        )));
    }

    if let Some(first) = first_repo_error {
        return Err(CliError::Download { failures, first });
    }

    Ok(())
}

/// Fetch the POMs and files `lock` pins for the platforms of `models`
/// beside a resolution of them, which asks for each POM only once it has
/// read the one that names it, and for each file once its walk has placed
/// it. Dropping the set stops the fetches; what neither the resolution nor
/// a restore reads is neither cached nor stored. The resolution's
/// observer, when there is one, adds what the lock pins from the
/// repositories remote parents declare, once the resolution has read them.
pub(super) fn prefetch_pinned(
    config: &Config,
    client: &RepoClient,
    store: &Arc<Store>,
    lock: &Lockfile,
    models: &[ReactorModel],
) -> (JoinSet<()>, Option<RootRepositories>) {
    let mut prefetch = JoinSet::new();
    if client.is_offline() {
        return (prefetch, None);
    }
    let trusted = (client.policy())
        .admit(
            models.iter().flat_map(ReactorModel::declared_repositories),
            rv_repo::Declaration::LocalPom,
        )
        .admitted;
    let platforms: Vec<_> = models.iter().map(|model| model.platform.clone()).collect();
    let Ok(lock) = lock.select_platforms(&platforms) else {
        return (prefetch, None);
    };
    let (learned, mut root_repositories) = tokio::sync::mpsc::unbounded_channel();
    let observer: RootRepositories = Arc::new(
        move |platform: &Platform, repos: &[Repository], _: &[(String, Repository)]| {
            let _ = learned.send((platform.clone(), repos.to_vec()));
        },
    );
    let mut pinned = PinnedFetches::new(config, client, lock.into_owned(), trusted);
    let store = Arc::clone(store);
    let concurrency = config.network.fetch_concurrency();
    prefetch.spawn(async move {
        let (poms, pom_queue) = tokio::sync::mpsc::unbounded_channel();
        let (files, file_queue) = tokio::sync::mpsc::unbounded_channel();
        let produce = async {
            let mut fetches = pinned.fetches(None);
            loop {
                if !fetches.is_empty() {
                    let stored = Arc::clone(&store);
                    let Ok(missing) =
                        tokio::task::spawn_blocking(move || unstored(fetches, &stored)).await
                    else {
                        return;
                    };
                    for (fetch, file) in missing {
                        let _ = if file {
                            files.send(fetch)
                        } else {
                            poms.send(fetch)
                        };
                    }
                }
                let Some((platform, repos)) = root_repositories.recv().await else {
                    return;
                };
                fetches = pinned.fetches(Some((&platform, repos)));
            }
        };
        futures::join!(
            produce,
            run(pom_queue, file_queue, store.clone(), concurrency)
        );
    });
    (prefetch, Some(observer))
}

/// A file to fetch from a repository, the blob a lock pins for it, and the
/// client of the platform whose row pins it.
type Fetch = (Repository, ArtifactRequest, BlobId, RepoClient);

/// A list of repositories by URL and id.
type RepoKeys = Vec<(String, Option<String>)>;

/// The POMs and files a lock pins, each from the declared repository its
/// row records, and each POM also from the declared repositories a
/// resolution asks before that one, whose misses it then finds recorded.
/// A row whose origin no declaration known yet names is left to the
/// resolution and the restore, as are SNAPSHOTs, until a resolution names
/// it ([`Self::fetches`]).
struct PinnedFetches {
    config: Config,
    client: RepoClient,
    lock: Lockfile,
    origins: LockOrigins,
    /// What the project's own POMs declare.
    trusted: Vec<Repository>,
    /// Per platform, the lists of repositories a resolution has searched.
    resolved: HashMap<Platform, HashSet<RepoKeys>>,
    seen: HashSet<(String, String)>,
}

impl PinnedFetches {
    fn new(config: &Config, client: &RepoClient, lock: Lockfile, trusted: Vec<Repository>) -> Self {
        Self {
            config: config.clone(),
            client: client.clone(),
            origins: LockOrigins::for_root(&config.project_root),
            lock,
            trusted,
            resolved: HashMap::new(),
            seen: HashSet::new(),
        }
    }

    /// The fetches not listed before, with whether each is a file (or a
    /// POM): all of them at first, then, with `learned`, what the
    /// repositories one resolution of that platform searches add, in its
    /// order and with its policies.
    fn fetches(&mut self, learned: Option<(&Platform, Vec<Repository>)>) -> Vec<(Fetch, bool)> {
        if let Some((platform, repos)) = &learned {
            let keys = repos.iter().map(|repo| (repo.url.clone(), repo.id.clone()));
            if !(self.resolved.entry((*platform).clone()).or_default()).insert(keys.collect()) {
                return Vec::new();
            }
        }
        let mut fetches = Vec::new();
        for entry in &self.lock.platforms {
            let platform = &entry.platform;
            if learned
                .as_ref()
                .is_some_and(|(learned, _)| *learned != platform)
            {
                continue;
            }
            let config =
                (self.config).for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
            // In a resolution's order: the configured repositories, those the
            // project's POMs declare, those remote parents declare, then the
            // defaults, such as Central.
            let configured = config.repositories();
            let (own, defaults) =
                configured.split_at(configured.len() - config.default_repositories().len());
            let (order, trusted): (Vec<&str>, Vec<Repository>) = match &learned {
                Some((_, resolved)) => (
                    resolved.iter().map(|repo| repo.url.as_str()).collect(),
                    (resolved.iter())
                        .filter(|repo| repo.provenance() == rv_repo::Provenance::FetchedPom)
                        .chain(&self.trusted)
                        .cloned()
                        .collect(),
                ),
                None => (
                    (own.iter().map(|repo| repo.url.as_str()))
                        .chain(self.trusted.iter().map(|repo| repo.url.as_str()))
                        .chain(defaults.iter().map(|repo| repo.url.as_str()))
                        .collect(),
                    self.trusted.clone(),
                ),
            };
            let selector = LockRepositorySelector::new(&config, &self.origins, &trusted);
            let client = self.client.for_platform(&config);
            let seen = &mut self.seen;
            // The repositories to ask for the file `key` from `origin`, with
            // those searched before it when `searched`.
            let mut fetch = |origin: Option<&str>, key, blob: &BlobId, searched, file| {
                let request = ArtifactRequest::from(&key);
                let version = request.version.clone();
                let origin = origin.and_then(|url| selector.select(url, Some(&version)).declared());
                let Some(origin) = origin.filter(|repo| !repo.is_local() && !request.is_snapshot())
                else {
                    return;
                };
                let mut repos: Vec<_> = (order.iter().filter(|_| searched))
                    .filter_map(|url| selector.select(url, Some(&version)).declared())
                    .take_while(|repo| repo.url != origin.url)
                    .filter(|repo| !repo.is_local() && repo.allows_version(&version))
                    .collect();
                repos.push(origin);
                fetches.extend(
                    (repos.into_iter())
                        .filter(|repo| seen.insert((repo.url.clone(), request.to_path())))
                        .map(|repo| ((repo, request.clone(), blob.clone(), client.clone()), file)),
                );
            };
            // The parents and BOMs first, as a resolution reads them.
            let (support, rows): (Vec<_>, Vec<_>) =
                (entry.pinned_files()).partition(|file| matches!(file.row, PinnedRow::Support(..)));
            for file in support.into_iter().chain(rows) {
                if let Digest::Sha256(blob) = &file.pin {
                    // A pom-packaged file is the POM a resolution reads as
                    // its model, so it is fetched as that POM.
                    let request = ArtifactRequest::from(&file.key);
                    let is_file = matches!(file.row, PinnedRow::File(_))
                        && !(request.packaging == "pom"
                            && request.classifier.as_deref().is_none_or(str::is_empty));
                    let origin = file.origins.first().copied();
                    fetch(origin, file.key, blob, !is_file, is_file);
                }
            }
        }
        fetches
    }
}

/// Those of `fetches` whose blob the store lacks: the restore takes a
/// stored file from the store, and its POM is in the metadata cache.
fn unstored(mut fetches: Vec<(Fetch, bool)>, store: &Store) -> Vec<(Fetch, bool)> {
    fetches.retain(|((_, _, blob, _), _)| !store.get_path(blob).is_file());
    fetches
}

/// Fetch what the queues bring through their clients, which hold them until a
/// read or a restore of the same file takes them, as it holds the
/// resolution's own prefetches, and keeps a miss as the read would. The
/// POMs, small and many, go `concurrency` times four at a time, and the
/// other files `concurrency` at a time, each until it has arrived.
async fn run(
    poms: tokio::sync::mpsc::UnboundedReceiver<Fetch>,
    files: tokio::sync::mpsc::UnboundedReceiver<Fetch>,
    store: Arc<Store>,
    concurrency: usize,
) {
    let queue = |mut queue: tokio::sync::mpsc::UnboundedReceiver<Fetch>| {
        futures::stream::poll_fn(move |cx| queue.poll_recv(cx))
    };
    let poms =
        queue(poms).for_each_concurrent(concurrency * 4, |(repo, request, _, client)| async move {
            let _ = client.prefetch_pom(&repo, &request).await;
        });
    let slots = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let files = queue(files).for_each_concurrent(None, move |(repo, request, _, client)| {
        let (store, slots) = (store.clone(), Arc::clone(&slots));
        async move {
            if let Ok(slot) = slots.acquire_owned().await {
                client
                    .prefetch_artifact(&repo, &request, &store, slot)
                    .await;
            }
        }
    });
    futures::join!(poms, files);
}

/// Refuse a resolution that pins a release file or timestamped snapshot
/// build of `lock` to other bytes. A file `lock` pins by SHA-1 alone is
/// hashed in `store`, where the resolution put it.
/// Only `sync --update` accepts them, as it does for a download.
pub(super) async fn check_repinned(lock: &Lockfile, fresh: &Lockfile, store: &Store) -> Result<()> {
    let mut lines = Vec::new();
    for (path, locked, served) in lock.repinned_releases(fresh) {
        let got = if locked.as_sha256().is_some() {
            format!("got {served}")
        } else {
            match store.check_pin_async(&served, &locked).await? {
                rv_store::PinCheck::Match => continue,
                rv_store::PinCheck::Mismatch { actual } => format!("got {actual}"),
                rv_store::PinCheck::Missing => {
                    "and the resolved file is not in the store to check".to_string()
                }
            }
        };
        lines.push(format!(
            "{path}: expected {} {}, {got}",
            locked.algorithm(),
            locked.hex()
        ));
    }
    if lines.is_empty() {
        return Ok(());
    }
    Err(replaced_files(format!(
        "{} resolved file(s) do not match their checksums in raeva.lock:\n{}",
        lines.len(),
        listed(&lines, LISTED_FAILURES)
    )))
}

fn replaced_files(details: String) -> CliError {
    CliError::lockfile_mismatch_with(
        details,
        format!(
            "Ask the publisher, or the operator of the mirror, why the bytes changed: a \
             republished release, a mirror that rewrites files, and tampering look the same \
             here. If the new bytes are intended, run '{}' and review the changes to \
             raeva.lock before committing it",
            command_line("sync --update")
        ),
    )
}

/// How many non-checksum failures are listed verbatim alongside a checksum
/// mismatch before the rest collapse into a "... and N more" footer.
const OTHER_FAILURES_DISPLAY_CAP: usize = 3;

/// The first `cap` of `lines`, one per line, then "... and N more".
fn listed(lines: &[String], cap: usize) -> String {
    let mut out = (lines.iter().take(cap))
        .map(|line| crate::output::inline_text(line))
        .collect::<Vec<_>>()
        .join("\n");
    if lines.len() > cap {
        out.push_str(&format!("\n... and {} more", lines.len() - cap));
    }
    out
}

/// Render the checksum-mismatch failure message for a download batch. The
/// checksum class drives the exit code, but other failures from the same
/// batch are appended so they are not silently discarded.
fn format_checksum_failure_details(checksum_lines: &[String], other_failures: &[String]) -> String {
    let mut details = format!(
        "{} downloaded file(s) do not match their checksums in raeva.lock:\n{}",
        checksum_lines.len(),
        listed(checksum_lines, LISTED_FAILURES)
    );
    if !other_failures.is_empty() {
        details.push_str(&format!(
            "\nand {} other download failure(s):\n{}",
            other_failures.len(),
            listed(other_failures, OTHER_FAILURES_DISPLAY_CAP)
        ));
    }
    details
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use rv_test_support::http::{Response, StubServer};

    use super::format_checksum_failure_details;

    /// The files go `concurrency` at a time, each until it has arrived: the
    /// next one is asked for while the first one's checksum file, as slow as
    /// a `.sha256` miss at Central's CDN, is still pending.
    #[tokio::test]
    async fn a_file_frees_its_slot_once_it_has_arrived() {
        const HELD: Duration = Duration::from_secs(2);
        let asked: Arc<Mutex<Vec<Instant>>> = Arc::default();
        let server = StubServer::start({
            let asked = Arc::clone(&asked);
            move |request| {
                if request.path.ends_with(".jar") {
                    asked.lock().unwrap().push(Instant::now());
                    return Response::new(200, "jar");
                }
                let missing = Response::new(404, "");
                match request.path.ends_with(".sha256") {
                    true => missing.delayed(HELD),
                    false => missing,
                }
            }
        });
        let dir = tempfile::TempDir::new().unwrap();
        let config = rv_config::Config::for_testing_with_repos(
            dir.path().to_path_buf(),
            rv_config::ResolvedPaths::from_raeva_home(dir.path().join("home")),
            vec![rv_config::RepoConfig::new(
                Some("central"),
                &format!("http://{}/", server.addr()),
            )],
        );
        let client = rv_repo::RepoClient::new(&config).await.unwrap();
        let store = Arc::new(rv_store::Store::open(&dir.path().join("store")).unwrap());
        let repo = rv_repo::Repository::from(&config.repositories()[0]);
        let (_, poms) = tokio::sync::mpsc::unbounded_channel();
        let (queue, files) = tokio::sync::mpsc::unbounded_channel();
        for artifact in ["a", "b", "c", "d"] {
            let request = rv_repo::ArtifactRequest::new("t", artifact, "1");
            let blob = rv_maven_types::BlobId::from_bytes(b"jar");
            queue
                .send((repo.clone(), request, blob, client.clone()))
                .unwrap();
        }
        drop(queue);
        super::run(poms, files, store, 1).await;

        let asked = asked.lock().unwrap();
        assert_eq!(asked.len(), 4, "{asked:?}");
        let spread = asked[3].saturating_duration_since(asked[0]);
        assert!(
            spread < HELD,
            "the last file was asked for {spread:?} after the first"
        );
    }

    #[test]
    fn a_batch_of_replaced_files_lists_ten() {
        let lines: Vec<String> = (0..25).map(|n| format!("g:a:{n}:jar")).collect();
        let others: Vec<String> = (0..5).map(|n| format!("g:b:{n}")).collect();
        let details = format_checksum_failure_details(&lines, &others);
        assert!(details.starts_with("25 downloaded file(s)"), "{details}");
        assert!(
            details.contains("g:a:9:jar\n... and 15 more\n"),
            "{details}"
        );
        assert!(!details.contains("g:a:10:jar"), "{details}");
        assert!(details.ends_with("g:b:2\n... and 2 more"), "{details}");
    }
}
