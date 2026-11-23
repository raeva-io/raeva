//! POMs fetched before the resolution reads them.
//!
//! The solver reads each dependency's POM, and model building each parent
//! and imported BOM, one after another along every chain, so a cold
//! resolution would wait for one round trip per POM on its longest chain.
//! A hint names a POM the resolution is about to read; the prefetcher
//! fetches it in the background, at most [`RANGE_FETCHES_PER_SLOT`] times
//! `network.concurrency` at a time, as POMs are small and a repository
//! searched first can take far longer to answer a miss than to serve a
//! file, through [`PomSource::prefetch_pom`], which leaves the bytes where the
//! later read finds them, and then the POM's parent chain and its imported
//! BOMs the same way, all at once. Every repository the read may search is
//! asked at once, so a POM waits for no miss of a repository before it; the
//! read still takes the answers in its order.
//!
//! A range is read from its lowest version up, each version's POM in turn,
//! until one relocates, so those POMs are read for certain rather than
//! guessed at. They never wait behind guesses, in a lane of their own as
//! wide. A range a queued
//! declaration names is listed in the same lane as soon as it is queued,
//! and its versions fetched the same way.
//!
//! Artifacts are hinted as the solver places them in the graph, and
//! downloaded the same way, through [`RepoClient::prefetch_artifact`], so
//! the downloads overlap the rest of the resolution. One at the version the
//! root's management fixes is hinted as soon as its POM is fetched, from the
//! repository that served it, unless that POM names a relocation. Their
//! bytes wait, unchecked and unpublished, until the artifact pass fetches
//! them.
//!
//! Nothing here decides what the resolution reads or from where: every read
//! still goes through the usual path, with its checks, in its usual order.
//! A hint for a POM or an artifact that is never read costs only its
//! requests.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use futures::stream::{FuturesOrdered, FuturesUnordered};
use rv_maven_model::{Pom, parent_has_expression};
use rv_maven_types::{ArtifactCoord, BlobId, Coord};
use rv_repo::{ArtifactRequest, Metadata, PomArrival, RepoClient, RepoError, Repository};
use rv_store::Store;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use super::pom_source::PomSource;
use super::scope::parent_coord;
use crate::context::RepoContext;
use crate::parsed_pom_cache::ParsedPomCache;
use crate::util::lock;

const MAX_PREFETCHES: usize = 20_000;

/// How many parents or imports away from a hinted POM are prefetched.
const MAX_HOPS: usize = 16;

/// The POMs fetched at a time for guesses, and for range versions, per
/// artifact downloaded.
const RANGE_FETCHES_PER_SLOT: usize = 4;

pub(crate) struct Prefetcher {
    shared: Arc<Shared>,
    /// Dropping the prefetcher cancels what is still running.
    tasks: Mutex<JoinSet<()>>,
}

/// Whether artifacts the store lacks are downloaded.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Downloads {
    Open,
    /// Until released, with whether one was wanted meanwhile.
    Held {
        wanted: bool,
    },
    Dropped,
}

struct Shared {
    source: Arc<dyn PomSource>,
    parsed: Arc<ParsedPomCache>,
    permits: Semaphore,
    range_permits: Semaphore,
    /// Every repository URL and POM path hinted so far.
    seen: Mutex<HashSet<(String, String)>>,
    /// The POMs each repository URL served and lacked so far, per groupId
    /// and, under the empty groupId, in all.
    answered: Mutex<HashMap<(String, String), (usize, usize)>>,
    /// Every range listed so far, per repository context.
    listed: Mutex<HashSet<(String, RepoContext)>>,
    artifacts: Option<(RepoClient, Arc<Store>)>,
    artifact_permits: Semaphore,
    /// Every repository URL and artifact path hinted so far.
    artifacts_seen: Mutex<HashSet<(String, String)>>,
    downloads: watch::Sender<Downloads>,
    /// Who served each POM fetched so far, by the key of `seen`.
    served: Mutex<HashMap<(String, String), ServedBy>>,
    /// Every first repository URL and artifact path hinted early so far.
    early: Mutex<HashSet<(String, String)>>,
}

/// `None` until a POM's fetch ends, then the repository that served it, or
/// `None` when none did or the POM names a relocation.
type ServedBy = watch::Sender<Option<Option<Repository>>>;

impl Prefetcher {
    /// POMs come from `source`; artifacts come through `artifacts`, a
    /// client and the store their bytes wait in, when given. Artifacts
    /// download at most `concurrency` at a time, and guessed POMs and range
    /// versions each [`RANGE_FETCHES_PER_SLOT`] times that.
    pub(crate) fn new(
        source: Arc<dyn PomSource>,
        parsed: Arc<ParsedPomCache>,
        artifacts: Option<(RepoClient, Arc<Store>)>,
        concurrency: usize,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                source,
                parsed,
                permits: Semaphore::new(concurrency * RANGE_FETCHES_PER_SLOT),
                range_permits: Semaphore::new(concurrency * RANGE_FETCHES_PER_SLOT),
                seen: Mutex::default(),
                answered: Mutex::default(),
                listed: Mutex::default(),
                artifacts,
                artifact_permits: Semaphore::new(concurrency),
                artifacts_seen: Mutex::default(),
                downloads: watch::Sender::new(Downloads::Open),
                served: Mutex::default(),
                early: Mutex::default(),
            }),
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    /// Hold back every artifact download, hinted or not, until
    /// [`Self::release_artifacts`].
    pub(crate) fn hold_artifacts(&self) {
        self.shared
            .downloads
            .send_replace(Downloads::Held { wanted: false });
    }

    /// Start the artifact downloads held back, or, unless `start`, drop them
    /// and any later one. Only the first release counts.
    pub(crate) fn release_artifacts(&self, start: bool) {
        self.shared.downloads.send_if_modified(|downloads| {
            let held = matches!(downloads, Downloads::Held { .. });
            if held {
                *downloads = if start {
                    Downloads::Open
                } else {
                    Downloads::Dropped
                };
            }
            held
        });
    }

    /// Whether a download was held back before the release, which comes
    /// first.
    pub(crate) async fn downloads_wanted(&self) -> bool {
        let mut downloads = self.shared.downloads.subscribe();
        let wanted = downloads.wait_for(|now| *now != Downloads::Held { wanted: false });
        matches!(
            wanted.await.as_deref(),
            Ok(Downloads::Held { wanted: true })
        )
    }

    /// Once the artifacts are released.
    pub(crate) async fn downloads_released(&self) {
        let mut downloads = self.shared.downloads.subscribe();
        let released = downloads.wait_for(|now| !matches!(now, Downloads::Held { .. }));
        let _ = released.await;
    }

    /// Whether an artifact the store lacks may be downloaded, once that is
    /// decided.
    pub(crate) async fn may_download(&self) -> bool {
        self.shared.may_download().await
    }

    /// Start downloading the artifact of `request` from `repo`, unless the
    /// store already indexes one under `key`. Outside a Tokio runtime this
    /// does nothing.
    pub(crate) fn hint_artifact(
        &self,
        repo: &Repository,
        request: ArtifactRequest,
        key: ArtifactCoord,
    ) {
        if self.shared.artifacts.is_none() {
            return;
        }
        {
            let mut seen = lock(&self.shared.artifacts_seen);
            if seen.len() >= MAX_PREFETCHES || !seen.insert((repo.url.clone(), request.to_path())) {
                return;
            }
        }
        let (shared, repo) = (Arc::clone(&self.shared), repo.clone());
        self.spawn(async move { shared.prefetch_artifact(repo, request, key).await });
    }

    /// [`Self::hint_artifact`] from the repository that serves the POM of
    /// `request` among `repos`, once that POM is fetched, unless it names a
    /// relocation. The POM is hinted from `repos` before this.
    pub(crate) fn hint_artifact_after_pom(
        &self,
        repos: Vec<Repository>,
        request: ArtifactRequest,
        key: ArtifactCoord,
    ) {
        let Some(first) = repos.first() else {
            return;
        };
        if self.shared.artifacts.is_none() {
            return;
        }
        let pom = (first.url.clone(), request.pom().to_path());
        // Only a hinted POM's fetch ends with who served it.
        if !lock(&self.shared.seen).contains(&pom)
            || !lock(&self.shared.early).insert((first.url.clone(), request.to_path()))
        {
            return;
        }
        let Some(mut served) = self.shared.served_by(&pom, ServedBy::subscribe) else {
            return;
        };
        let shared = Arc::clone(&self.shared);
        self.spawn(async move {
            let repo = match served.wait_for(Option::is_some).await {
                Ok(served) => served.clone().flatten(),
                Err(_) => None,
            };
            let Some(repo) = repo else {
                return;
            };
            {
                let mut seen = lock(&shared.artifacts_seen);
                if seen.len() >= MAX_PREFETCHES
                    || !seen.insert((repo.url.clone(), request.to_path()))
                {
                    return;
                }
            }
            shared.prefetch_artifact(repo, request, key).await;
        });
    }

    fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let mut tasks = lock(&self.tasks);
        while tasks.try_join_next().is_some() {}
        tasks.spawn_on(task, &runtime);
    }

    /// Start fetching the POM of `request` from the first of `repos` that
    /// serves it, as the read searches them, then its parents and imported
    /// BOMs the same way; a `range` version's lineage skips the guesses'
    /// queue. Outside a Tokio runtime this does nothing.
    pub(crate) fn hint(&self, repos: Vec<Repository>, request: ArtifactRequest, range: bool) {
        if !self.shared.first_sight(&repos, &request) {
            return;
        }
        let shared = Arc::clone(&self.shared);
        self.spawn(shared.prefetch_lineage(repos, request, range));
    }

    /// What a read of a POM from `repos` hands its bytes to, unverified, so
    /// that the POM's parent and imported BOMs are hinted while its checksum
    /// file is still being asked for; see [`rv_repo::announcing_poms`].
    pub(crate) fn arrival(self: &Arc<Self>, repos: &[Repository]) -> PomArrival {
        let (prefetcher, repos) = (Arc::clone(self), repos.to_vec());
        Arc::new(move |bytes: &bytes::Bytes| {
            if let Some(pom) = prefetcher.shared.parse(bytes) {
                for next in lineage(&pom) {
                    prefetcher.hint(repos.clone(), next, false);
                }
            }
        })
    }

    /// Run the task `listing` makes, which lists the range `key` names
    /// through the [`RangeListing`] it is given and hints its versions,
    /// unless that range was listed before.
    pub(crate) fn hint_range<F>(
        &self,
        key: (String, RepoContext),
        listing: impl FnOnce(RangeListing) -> F,
    ) where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        {
            let mut listed = lock(&self.shared.listed);
            if listed.len() >= MAX_PREFETCHES || !listed.insert(key) {
                return;
            }
        }
        self.spawn(listing(RangeListing(Arc::clone(&self.shared))));
    }
}

/// Reads the version lists of a range for [`Prefetcher::hint_range`], in
/// the range versions' lane.
pub(crate) struct RangeListing(Arc<Shared>);

impl RangeListing {
    /// The version list of `coord` that `repo` serves, as
    /// [`PomSource::prefetch_metadata`] reads it.
    pub(crate) async fn metadata(&self, repo: &Repository, coord: &Coord) -> Option<Metadata> {
        let _permit = self.0.range_permits.acquire().await.ok()?;
        self.0.source.prefetch_metadata(repo, coord).await
    }
}

impl Shared {
    /// Whether `repo` has lacked more of the POMs of `group` asked of it
    /// than it served, or, before any was asked, of all POMs. A repository
    /// serves a few groups whole, so the group tells best.
    fn likely_lacks(&self, repo: &Repository, group: &str) -> bool {
        let answered = lock(&self.answered);
        let counts = |group: &str| answered.get(&(repo.url.clone(), group.to_string()));
        (counts(group).or_else(|| counts(""))).is_some_and(|(served, lacked)| lacked > served)
    }

    fn answered(&self, repo: &Repository, group: &str, served: bool) {
        let mut answered = lock(&self.answered);
        for group in [group, ""] {
            let (hits, misses) =
                (answered.entry((repo.url.clone(), group.to_string()))).or_default();
            *if served { hits } else { misses } += 1;
        }
    }

    /// `with` the channel of who served the POM under `key`, unless too
    /// many are kept.
    fn served_by<T>(&self, key: &(String, String), with: impl FnOnce(&ServedBy) -> T) -> Option<T> {
        let mut served = lock(&self.served);
        if served.len() >= MAX_PREFETCHES && !served.contains_key(key) {
            return None;
        }
        let sender = served.entry(key.clone());
        Some(with(sender.or_insert_with(|| watch::channel(None).0)))
    }

    /// Record that `repo` served the POM under `key`, or none did.
    fn serve(&self, key: &(String, String), repo: Option<Repository>) {
        self.served_by(key, |sender| {
            sender.send_if_modified(|now| {
                let first = now.is_none();
                if first {
                    *now = Some(repo);
                }
                first
            })
        });
    }

    /// Whether `request` from `repos` was not hinted before, recording it.
    fn first_sight(&self, repos: &[Repository], request: &ArtifactRequest) -> bool {
        let Some(first) = repos.first() else {
            return false;
        };
        let mut seen = lock(&self.seen);
        seen.len() < MAX_PREFETCHES && seen.insert((first.url.clone(), request.pom().to_path()))
    }

    async fn prefetch_lineage(
        self: Arc<Self>,
        repos: Vec<Repository>,
        request: ArtifactRequest,
        range: bool,
    ) {
        let permits = if range {
            &self.range_permits
        } else {
            &self.permits
        };
        // A POM's bytes are read for its parent and imports as soon as they
        // arrive: its checksum file may take far longer to answer, and
        // these are only hints.
        let (arrivals, mut arrived) = tokio::sync::mpsc::unbounded_channel();
        let fetch = |request: ArtifactRequest, hops: usize| {
            let (shared, repos) = (&self, &repos);
            let arrivals = arrivals.clone();
            let key = (repos.first()).map(|first| (first.url.clone(), request.pom().to_path()));
            async move {
                // The repositories are asked in the read's order, and one
                // the read has not reached yet only when every one before
                // it has mostly lacked the POMs asked of it so far and it
                // is sent no credential. The answers are taken in order, as
                // the read takes them, and so is a POM's arrival: one from
                // a repository the read has not reached waits.
                let repos: Vec<_> = (repos.iter())
                    .filter(|repo| repo.allows_version(&request.version))
                    .collect();
                let reached = Arc::new(Mutex::new((0, vec![None; repos.len()])));
                let ask = |index: usize| {
                    let (reached, arrivals) = (Arc::clone(&reached), arrivals.clone());
                    let arrival: PomArrival = Arc::new(move |bytes: &bytes::Bytes| {
                        let mut reached = lock(&reached);
                        if index <= reached.0 {
                            let _ = arrivals.send((bytes.clone(), hops));
                        } else {
                            reached.1[index] = Some(bytes.clone());
                        }
                    });
                    shared.prefetch(permits, repos[index], &request, arrival)
                };
                let (mut answers, mut asked, mut at) = (FuturesOrdered::new(), 0, 0);
                loop {
                    while asked < repos.len()
                        && (asked == at
                            || (shared.likely_lacks(repos[asked - 1], &request.group_id)
                                && !shared.source.sends_credential(repos[asked])))
                    {
                        answers.push_back(ask(asked));
                        asked += 1;
                    }
                    let Some(answer) = answers.next().await else {
                        break;
                    };
                    match answer {
                        Ok(Some(bytes)) => {
                            shared.answered(repos[at], &request.group_id, true);
                            if let Some(key) = &key {
                                let relocates = (bytes.windows(b"<relocation".len()))
                                    .any(|tag| tag == b"<relocation");
                                shared.serve(key, (!relocates).then(|| repos[at].clone()));
                            }
                            return (Some(bytes), hops);
                        }
                        // The read moves on after these, and stops after
                        // any other failure, such as a retried timeout.
                        Err(err)
                            if matches!(err, RepoError::NotFound(_))
                                || err.moves_to_next_repository() =>
                        {
                            shared.answered(repos[at], &request.group_id, false);
                            at += 1;
                            let mut reached = lock(&reached);
                            reached.0 = at;
                            if let Some(bytes) = reached.1.get_mut(at).and_then(Option::take) {
                                let _ = arrivals.send((bytes, hops));
                            }
                        }
                        _ => break,
                    }
                }
                if let Some(key) = &key {
                    shared.serve(key, None);
                }
                (None, hops)
            }
        };
        let mut pending = FuturesUnordered::new();
        pending.push(fetch(request, 0));
        loop {
            // An arrival is sent before its fetch ends, so none is missed.
            let (bytes, hops) = if pending.is_empty() {
                match arrived.try_recv() {
                    Ok(arrival) => arrival,
                    Err(_) => break,
                }
            } else {
                tokio::select! {
                    biased;
                    Some(arrival) = arrived.recv() => arrival,
                    Some((bytes, hops)) = pending.next() => match bytes {
                        Some(bytes) => (bytes, hops),
                        None => continue,
                    },
                }
            };
            let Some(pom) = self.parse(&bytes) else {
                continue;
            };
            if hops == MAX_HOPS {
                continue;
            }
            for next in lineage(&pom) {
                if self.first_sight(&repos, &next) {
                    pending.push(fetch(next, hops + 1));
                }
            }
        }
    }

    async fn prefetch_artifact(
        &self,
        repo: Repository,
        request: ArtifactRequest,
        key: ArtifactCoord,
    ) {
        let Some((client, store)) = &self.artifacts else {
            return;
        };
        let Ok(permit) = self.artifact_permits.acquire().await else {
            return;
        };
        // A -SNAPSHOT the artifact pass fetches again is fetched here too,
        // as its lookup would note the stored copy's checksum for the lock.
        let renew = client.renews(&key);
        if (renew || matches!(client.stored_artifact(store, &repo, &key).await, Ok(None)))
            && self.may_download().await
        {
            client
                .prefetch_artifact(&repo, &request, store, permit)
                .await;
        }
    }

    async fn may_download(&self) -> bool {
        self.downloads.send_if_modified(|downloads| {
            let first = *downloads == Downloads::Held { wanted: false };
            if first {
                *downloads = Downloads::Held { wanted: true };
            }
            first
        });
        let mut downloads = self.downloads.subscribe();
        let decided = downloads.wait_for(|now| !matches!(now, Downloads::Held { .. }));
        matches!(decided.await.as_deref(), Ok(Downloads::Open))
    }

    async fn prefetch(
        &self,
        permits: &Semaphore,
        repo: &Repository,
        request: &ArtifactRequest,
        arrival: PomArrival,
    ) -> Result<Option<bytes::Bytes>, RepoError> {
        let Ok(_permit) = permits.acquire().await else {
            return Ok(None);
        };
        rv_repo::announcing_poms(arrival, self.source.prefetch_pom(repo, request)).await
    }

    fn parse(&self, bytes: &[u8]) -> Option<Arc<Pom>> {
        self.parsed.parse(&BlobId::from_bytes(bytes), bytes).ok()
    }
}

/// The requests for the parent of `pom` and the BOMs it imports, as far as
/// its own text names them.
fn lineage(pom: &Pom) -> impl Iterator<Item = ArtifactRequest> + '_ {
    let parent = pom.parent.as_ref().and_then(|parent| {
        if parent_has_expression(parent) {
            return None;
        }
        parent_coord(parent)
            .ok()
            .map(|coord| ArtifactRequest::from_coord(&coord))
    });
    parent.into_iter().chain(import_requests(pom))
}

/// The requests for the BOMs `pom` imports by coordinates that are literal
/// or a single property of its own `<properties>`, as BOMs that pin their
/// imports' versions write them. Model building may still interpolate
/// them otherwise; a wrong guess costs only its request.
fn import_requests(pom: &Pom) -> impl Iterator<Item = ArtifactRequest> + '_ {
    let literal = |value: &str| -> Option<String> {
        let value = match value.strip_prefix("${").and_then(|v| v.strip_suffix('}')) {
            Some(name) => pom
                .properties
                .get(rv_maven_types::expression_key(name))?
                .trim(),
            None => value,
        };
        (!value.is_empty() && !value.contains("${")).then(|| value.to_string())
    };
    let managed = pom.dependency_management.as_ref();
    managed
        .into_iter()
        .flat_map(|management| &management.dependencies)
        .filter(|dep| dep.scope.as_deref() == Some("import") && dep.type_.as_deref() == Some("pom"))
        .filter_map(move |dep| {
            let version = literal(dep.version.as_deref()?)?;
            if version.starts_with(['[', '(']) {
                return None;
            }
            Some(ArtifactRequest {
                group_id: literal(&dep.group_id)?,
                artifact_id: literal(&dep.artifact_id)?,
                version,
                packaging: "pom".to_string(),
                classifier: None,
            })
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use futures::future::BoxFuture;
    use rv_maven_types::Coord;
    use rv_repo::{
        Admission, ArtifactRequest, Declaration, Metadata, RepoError, Repository,
        SnapshotResolution,
    };

    use super::{PomSource, Prefetcher, RANGE_FETCHES_PER_SLOT};
    use crate::parsed_pom_cache::ParsedPomCache;
    use crate::resolver::pom_source::MemoryPomSource;

    /// A [`MemoryPomSource`] that also prefetches, and holds the prefetches
    /// of the two sibling BOMs until both have started.
    struct Prefetching(MemoryPomSource, tokio::sync::Barrier);

    impl PomSource for Prefetching {
        fn admit(&self, repos: Vec<Repository>, from: Declaration) -> Admission {
            self.0.admit(repos, from)
        }
        fn effective_repository(&self, repo: &Repository) -> Repository {
            self.0.effective_repository(repo)
        }
        fn sends_credential(&self, repo: &Repository) -> bool {
            self.0.sends_credential(repo)
        }
        fn pom<'a>(
            &'a self,
            repo: &'a Repository,
            request: &'a ArtifactRequest,
        ) -> BoxFuture<'a, Result<(Bytes, String), RepoError>> {
            self.0.pom(repo, request)
        }
        fn prefetch_pom<'a>(
            &'a self,
            repo: &'a Repository,
            request: &'a ArtifactRequest,
        ) -> BoxFuture<'a, Result<Option<Bytes>, RepoError>> {
            Box::pin(async move {
                if request.artifact_id.starts_with("bom-") {
                    self.1.wait().await;
                }
                let (bytes, _) = self.0.pom(repo, request).await?;
                Ok(Some(bytes))
            })
        }
        fn metadata<'a>(
            &'a self,
            repo: &'a Repository,
            coord: &'a Coord,
        ) -> BoxFuture<'a, Result<Metadata, RepoError>> {
            self.0.metadata(repo, coord)
        }
        fn snapshot<'a>(
            &'a self,
            repo: &'a Repository,
            coord: &'a Coord,
        ) -> BoxFuture<'a, Result<SnapshotResolution, RepoError>> {
            self.0.snapshot(repo, coord)
        }
    }

    fn pom(group: &str, artifact: &str, body: &str) -> (String, Vec<u8>) {
        let path = format!("{}/{artifact}/1/{artifact}-1.pom", group.replace('.', "/"));
        let xml = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>{group}</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version>{body}</project>"
        );
        (path, xml.into_bytes())
    }

    fn import(artifact: &str, version: &str) -> String {
        format!(
            "<dependency><groupId>g</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version><type>pom</type><scope>import</scope></dependency>"
        )
    }

    /// An early jar waits for its POM only once, and only for a POM hinted
    /// before it, whose fetch ends by naming who served it.
    #[tokio::test]
    async fn an_early_jar_waits_once_and_only_for_a_hinted_pom() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = rv_config::Config::for_testing_with_repos(
            std::env::temp_dir(),
            rv_config::ResolvedPaths::for_testing().unwrap(),
            Vec::new(),
        );
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(rv_store::Store::open(store_dir.path()).unwrap());
        let client = rv_repo::RepoClient::new(&config).await.unwrap();
        let source = Arc::new(MemoryPomSource::new(rv_config::SecurityConfig::default()));
        let parsed = Arc::new(ParsedPomCache::default());
        let prefetcher = Prefetcher::new(source, parsed, Some((client, store)), 1);
        let repos = vec![Repository::new(None, "https://r.example/", true, false)];
        let request = ArtifactRequest::from_coord(&Coord::parse("g:a:1").unwrap());
        let key = rv_maven_types::ArtifactCoord::new("g", "a", "1", "jar", None);
        let early =
            || prefetcher.hint_artifact_after_pom(repos.clone(), request.clone(), key.clone());
        // The tasks run only once the test awaits.
        early();
        assert!(crate::util::lock(&prefetcher.tasks).is_empty());
        prefetcher.hint(repos.clone(), request.clone(), false);
        early();
        early();
        assert_eq!(crate::util::lock(&prefetcher.tasks).len(), 2);
    }

    /// A range version's POM is fetched while guesses hold every slot
    /// guesses have.
    #[tokio::test]
    async fn range_versions_skip_the_guesses() {
        let stuck = (0..RANGE_FETCHES_PER_SLOT).map(|i| format!("bom-stuck{i}"));
        let files: std::collections::HashMap<_, _> = (stuck.clone())
            .map(|artifact| pom("g", &artifact, ""))
            .chain([pom("g", "ranged", "")])
            .collect();
        let source = Arc::new(Prefetching(
            MemoryPomSource::new(rv_config::SecurityConfig::default())
                .with_files("https://repo.example", &files),
            tokio::sync::Barrier::new(RANGE_FETCHES_PER_SLOT + 1),
        ));
        let prefetcher = Prefetcher::new(
            Arc::clone(&source) as Arc<dyn PomSource>,
            Arc::new(ParsedPomCache::default()),
            None,
            1,
        );
        let repo = Repository::new(None, "https://repo.example", true, false);
        let request = |artifact: &str| {
            ArtifactRequest::from_coord(&Coord::parse(&format!("g:{artifact}:1")).unwrap())
        };
        let shared = &prefetcher.shared;
        let guesses: Vec<_> = stuck
            .map(|artifact| {
                let guess = Arc::clone(shared).prefetch_lineage(
                    vec![repo.clone()],
                    request(&artifact),
                    false,
                );
                tokio::spawn(guess)
            })
            .collect();
        while shared.permits.available_permits() > 0 {
            tokio::task::yield_now().await;
        }
        let range = Arc::clone(shared).prefetch_lineage(vec![repo], request("ranged"), true);
        tokio::time::timeout(std::time::Duration::from_secs(10), range)
            .await
            .expect("a range version waits for no guess");
        assert!(
            (source.0.requests().iter())
                .any(|url| url == "https://repo.example/g/ranged/1/ranged-1.pom")
        );
        guesses.iter().for_each(tokio::task::JoinHandle::abort);
    }

    /// Guesses are fetched [`RANGE_FETCHES_PER_SLOT`] per slot: POMs are
    /// small, and a guess holds its slot while a repository searched first
    /// answers its miss, which can take a far longer round trip than a hit.
    #[tokio::test]
    async fn guesses_are_fetched_several_per_slot() {
        let names: Vec<_> = (0..RANGE_FETCHES_PER_SLOT)
            .map(|i| format!("bom-{i}"))
            .collect();
        let files: std::collections::HashMap<_, _> = names
            .iter()
            .map(|artifact| pom("g", artifact, ""))
            .collect();
        let source = Arc::new(Prefetching(
            MemoryPomSource::new(rv_config::SecurityConfig::default())
                .with_files("https://repo.example", &files),
            tokio::sync::Barrier::new(RANGE_FETCHES_PER_SLOT),
        ));
        let prefetcher = Prefetcher::new(
            Arc::clone(&source) as Arc<dyn PomSource>,
            Arc::new(ParsedPomCache::default()),
            None,
            1,
        );
        let repo = Repository::new(None, "https://repo.example", true, false);
        let guesses = names.iter().map(|artifact| {
            let request =
                ArtifactRequest::from_coord(&Coord::parse(&format!("g:{artifact}:1")).unwrap());
            Arc::clone(&prefetcher.shared).prefetch_lineage(vec![repo.clone()], request, false)
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            futures::future::join_all(guesses),
        )
        .await
        .expect("the guesses are fetched at once");
    }

    /// A lineage asks the repositories the read may search at once once the
    /// earlier ones have mostly lacked POMs, so a POM waits for no miss of
    /// a repository before it; on spring-cloud-gateway each POM waited for
    /// the milestone 404 and the release 401 before Central was asked. The answers are taken as the
    /// read takes them: past a repository that lacks or refuses the POM,
    /// but not past one that kept failing a retried request, such as a 503,
    /// so the second repository's lineage is not followed then. A
    /// repository that takes no releases is not asked for one.
    #[tokio::test]
    async fn a_lineage_asks_every_repository_at_once() {
        for (code, moves_on) in [(404, true), (401, true), (500, true), (503, false)] {
            let parent = "<parent><groupId>g</groupId><artifactId>parent</artifactId>\
                          <version>1</version></parent>";
            let files: std::collections::HashMap<_, _> =
                [pom("g", "bom-app", parent), pom("g", "parent", "")].into();
            let mut source = MemoryPomSource::new(rv_config::SecurityConfig::default())
                .with_files("https://second.example", &files);
            if code != 404 {
                source = source.with_refusal("https://first.example", code);
            }
            let source = Arc::new(Prefetching(source, tokio::sync::Barrier::new(2)));
            let prefetcher = Prefetcher::new(
                Arc::clone(&source) as Arc<dyn PomSource>,
                Arc::new(ParsedPomCache::default()),
                None,
                1,
            );
            let snapshots = Repository::new(None, "https://snapshots.example", false, true);
            let repos = vec![
                Repository::new(None, "https://first.example", true, false),
                snapshots,
                Repository::new(None, "https://second.example", true, false),
            ];
            prefetcher.shared.answered(&repos[0], "g", false);
            let request = ArtifactRequest::from_coord(&Coord::parse("g:bom-app:1").unwrap());
            let lineage = Arc::clone(&prefetcher.shared).prefetch_lineage(repos, request, false);
            tokio::time::timeout(std::time::Duration::from_secs(10), lineage)
                .await
                .expect("both repositories are asked at once");
            let asked = |repo: &str, artifact: &str| {
                let url = format!("https://{repo}.example/g/{artifact}/1/{artifact}-1.pom");
                source.0.requests().contains(&url)
            };
            assert!(
                asked("first", "bom-app") && !asked("snapshots", "bom-app"),
                "{code}"
            );
            assert_eq!(asked("second", "parent"), moves_on, "{code}");
        }
    }

    /// A repository the read has not reached is asked ahead only when the
    /// one before it has lacked more POMs of the group than it served, or of
    /// all groups when it was asked none of this one, and only when it is
    /// sent no credential. The two answer only together, so the lineage ends
    /// only if the second was asked ahead.
    #[tokio::test(start_paused = true)]
    async fn a_repository_is_asked_ahead_only_after_misses_and_without_credential() {
        #[rustfmt::skip]
        let cases = [
            (0, 0, 0, false, false), (1, 0, 0, false, true), (1, 2, 0, false, false),
            (1, 0, 1, false, false), (2, 0, 1, false, false), (1, 0, 0, true, false),
        ];
        for (lacked, served, served_here, credential, ahead) in cases {
            let files: std::collections::HashMap<_, _> = [pom("g", "bom-lib", "")].into();
            let mut source = MemoryPomSource::new(rv_config::SecurityConfig::default())
                .with_files("https://first.example", &files)
                .with_files("https://second.example", &files);
            if credential {
                source = source.with_credential("https://second.example");
            }
            let together = tokio::sync::Barrier::new(2);
            let source = Arc::new(Prefetching(source, together));
            let prefetcher = Prefetcher::new(
                Arc::clone(&source) as Arc<dyn PomSource>,
                Arc::new(ParsedPomCache::default()),
                None,
                1,
            );
            let repos = ["first", "second"]
                .map(|name| Repository::new(None, format!("https://{name}.example"), true, false));
            let answers = [(lacked, "other", false), (served, "other", true)];
            for (times, group, served) in answers.into_iter().chain([(served_here, "g", true)]) {
                (0..times).for_each(|_| prefetcher.shared.answered(&repos[0], group, served));
            }
            let request = ArtifactRequest::from_coord(&Coord::parse("g:bom-lib:1").unwrap());
            let lineage =
                Arc::clone(&prefetcher.shared).prefetch_lineage(repos.to_vec(), request, false);
            let ended = tokio::time::timeout(std::time::Duration::from_secs(10), lineage).await;
            let case = format!("{lacked} {served} {served_here} {credential}");
            assert_eq!(ended.is_ok(), ahead, "{case}");
        }
    }

    /// Under `--update` a -SNAPSHOT artifact is prefetched again past its
    /// stored copy, which the artifact pass does not take either.
    #[tokio::test]
    async fn an_updated_snapshot_artifact_is_prefetched_past_its_stored_copy() {
        use rv_test_support::http::{Response, StubServer};

        const JAR: &str = "/g/a/1.0-SNAPSHOT/a-1.0-20240101.010101-1.jar";
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = StubServer::start(|request| match request.path.as_str() {
            JAR => Response::new(200, "jar"),
            "/g/a/1.0-SNAPSHOT/maven-metadata.xml" => Response::new(
                200,
                "<metadata><versioning><snapshotVersions><snapshotVersion><extension>jar\
                 </extension><value>1.0-20240101.010101-1</value></snapshotVersion>\
                 </snapshotVersions></versioning></metadata>",
            ),
            _ => Response::new(404, ""),
        });
        let url = format!("http://{}/", server.addr());
        let config = rv_config::Config::for_testing_with_repos(
            std::env::temp_dir(),
            rv_config::ResolvedPaths::for_testing().unwrap(),
            vec![rv_config::RepoConfig::new(None, &url)],
        );
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(rv_store::Store::open(store_dir.path()).unwrap());
        let repo = Repository::new(None, url, true, true);
        let request = ArtifactRequest::from_coord(&Coord::parse("g:a:1.0-SNAPSHOT").unwrap());
        let key = rv_maven_types::ArtifactCoord::new("g", "a", "1.0-SNAPSHOT", "jar", None);
        // Each run is a new client.
        let client = || async {
            (rv_repo::RepoClient::new(&config).await.unwrap()).with_allow_missing_checksums(true)
        };
        (client()
            .await
            .fetch_artifact_to_store_and_index(&repo, &request, &store, &key))
        .await
        .unwrap();
        let client = (client().await).with_freshness(rv_repo::Freshness::Update {
            since: std::time::Instant::now(),
        });
        let prefetcher = Prefetcher::new(
            Arc::new(MemoryPomSource::new(rv_config::SecurityConfig::default())),
            Arc::new(ParsedPomCache::default()),
            Some((client, store)),
            1,
        );
        prefetcher
            .shared
            .prefetch_artifact(repo, request, key)
            .await;
        let asked = || {
            (server.requests().iter())
                .filter(|request| request.path == JAR)
                .count()
        };
        for _ in 0..100 {
            if asked() == 2 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("{JAR} was not prefetched again");
    }

    /// A POM's arrival from a repository the read has not reached waits for
    /// the read to reach it. Here the first repository's copy fails its
    /// checksum, slowly, so the read stops there and never takes the
    /// second's, whose parent is not asked for either.
    #[tokio::test]
    async fn an_arrival_waits_for_the_repositories_before_it() {
        use rv_test_support::http::{Response, StubServer};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let first = StubServer::start(|request| match request.path.as_str() {
            "/g/bom-app/1/bom-app-1.pom" => Response::new(200, pom("g", "bom-app", "").1),
            "/g/bom-app/1/bom-app-1.pom.sha1" => {
                std::thread::sleep(std::time::Duration::from_millis(300));
                Response::new(200, "0".repeat(40))
            }
            _ => Response::new(404, ""),
        });
        let second = StubServer::start(|request| {
            match request.path.as_str() {
            "/g/bom-app/1/bom-app-1.pom" => Response::new(
                200,
                pom("g", "bom-app", "<parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent>").1,
            ),
            _ => Response::new(404, ""),
        }
        });
        let urls = [first.addr(), second.addr()].map(|addr| format!("http://{addr}/"));
        let config = rv_config::Config::for_testing_with_repos(
            std::env::temp_dir(),
            rv_config::ResolvedPaths::for_testing().unwrap(),
            urls.iter()
                .map(|url| rv_config::RepoConfig::new(None, url))
                .collect(),
        );
        let client =
            (rv_repo::RepoClient::new(&config).await.unwrap()).with_allow_missing_checksums(true);
        let source = Arc::new(crate::resolver::pom_source::RepoPomSource(client));
        let prefetcher = Prefetcher::new(source, Arc::new(ParsedPomCache::default()), None, 1);
        let repos = urls
            .map(|url| Repository::new(None, url, true, false))
            .to_vec();
        prefetcher.shared.answered(&repos[0], "g", false);
        let request = ArtifactRequest::from_coord(&Coord::parse("g:bom-app:1").unwrap());
        Arc::clone(&prefetcher.shared)
            .prefetch_lineage(repos, request, false)
            .await;
        let asked = [&first, &second].map(|server| server.requests());
        assert!((asked.iter().flatten()).all(|request| !request.path.contains("parent")));
        assert!(
            asked[1]
                .iter()
                .any(|request| request.path.contains("bom-app"))
        );
    }

    /// A hinted POM's parents and imported BOMs are fetched, nested imports
    /// included and sibling imports at once, when their coordinates are
    /// literal or a property of the POM's own. A range, an unknown property
    /// and a managed dependency that is not an import are left alone.
    #[tokio::test]
    async fn parents_and_imports_are_prefetched() {
        let parent = format!(
            "<properties><b.version>1</b.version></properties><dependencyManagement>\
             <dependencies>{}{}{}{}<dependency><groupId>g</groupId>\
             <artifactId>managed</artifactId><version>1</version></dependency>\
             </dependencies></dependencyManagement>",
            import("bom-a", "1"),
            import("bom-b", "${b.version}"),
            import("bom-r", "[1,2)"),
            import("bom-u", "${unknown}"),
        );
        let nested = format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            import("nested", "1")
        );
        let files: std::collections::HashMap<_, _> = [
            pom(
                "g",
                "app",
                "<parent><groupId>g</groupId><artifactId>par</artifactId><version>1</version></parent>",
            ),
            pom("g", "par", &parent),
            pom("g", "bom-a", &nested),
            pom("g", "bom-b", ""),
            pom("g", "nested", ""),
        ]
        .into_iter()
        .collect();
        let source = Arc::new(Prefetching(
            MemoryPomSource::new(rv_config::SecurityConfig::default())
                .with_files("https://repo.example", &files),
            tokio::sync::Barrier::new(2),
        ));
        let prefetcher = Prefetcher::new(
            Arc::clone(&source) as Arc<dyn PomSource>,
            Arc::new(ParsedPomCache::default()),
            None,
            4,
        );
        let repo = Repository::new(None, "https://repo.example", true, false);
        let request = ArtifactRequest::from_coord(&Coord::parse("g:app:1").unwrap());
        let lineage = Arc::clone(&prefetcher.shared).prefetch_lineage(vec![repo], request, false);
        tokio::time::timeout(std::time::Duration::from_secs(10), lineage)
            .await
            .expect("sibling imports are fetched at once");
        let mut requested = source.0.requests();
        requested.sort();
        assert_eq!(
            requested,
            ["app", "bom-a", "bom-b", "nested", "par"]
                .map(|a| format!("https://repo.example/g/{a}/1/{a}-1.pom"))
        );
    }
}
