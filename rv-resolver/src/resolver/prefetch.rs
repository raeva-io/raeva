//! POMs fetched before the resolution reads them.
//!
//! The solver reads each dependency's POM, and model building each parent
//! and imported BOM, one after another along every chain, so a cold
//! resolution would wait for one round trip per POM on its longest chain.
//! A hint names a POM the resolution is about to read; the prefetcher
//! fetches it in the background, at most `network.concurrency` at a time,
//! through [`PomSource::prefetch_pom`], which leaves the bytes where the
//! later read finds them, and then the POM's parent chain and its imported
//! BOMs the same way, all at once.
//!
//! A range is read from its lowest version up, each version's POM in turn,
//! until one relocates, so those POMs are read for certain rather than
//! guessed at. They never wait behind guesses, and as they are small and
//! read in bursts, up to [`RANGE_FETCHES_PER_SLOT`] times
//! `network.concurrency` are fetched at a time. A range a queued
//! declaration names is listed in the same lane as soon as it is queued,
//! and its versions fetched the same way.
//!
//! Artifacts are hinted as the solver places them in the graph, and
//! downloaded the same way, through [`RepoClient::prefetch_artifact`], so
//! the downloads overlap the rest of the resolution. Their bytes wait,
//! unchecked and unpublished, until the artifact pass fetches them.
//!
//! Nothing here decides what the resolution reads or from where: every read
//! still goes through the usual path, with its checks, in its usual order.
//! A hint for a POM or an artifact that is never read costs only its
//! requests.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use rv_maven_model::{Pom, parent_has_expression};
use rv_maven_types::{ArtifactCoord, BlobId, Coord};
use rv_repo::{ArtifactRequest, Metadata, PomArrival, RepoClient, RepoError, Repository};
use rv_store::Store;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::pom_source::PomSource;
use super::scope::parent_coord;
use crate::context::RepoContext;
use crate::parsed_pom_cache::ParsedPomCache;
use crate::util::lock;

const MAX_PREFETCHES: usize = 20_000;

/// How many parents or imports away from a hinted POM are prefetched.
const MAX_HOPS: usize = 16;

/// The POMs of range versions fetched at a time, per POM fetched for a
/// guess.
const RANGE_FETCHES_PER_SLOT: usize = 4;

pub(crate) struct Prefetcher {
    shared: Arc<Shared>,
    /// Dropping the prefetcher cancels what is still running.
    tasks: Mutex<JoinSet<()>>,
}

struct Shared {
    source: Arc<dyn PomSource>,
    parsed: Arc<ParsedPomCache>,
    permits: Semaphore,
    range_permits: Semaphore,
    /// Every repository URL and POM path hinted so far.
    seen: Mutex<HashSet<(String, String)>>,
    /// Every range listed so far, per repository context.
    listed: Mutex<HashSet<(String, RepoContext)>>,
    artifacts: Option<(RepoClient, Arc<Store>)>,
    artifact_permits: Semaphore,
    /// Every repository URL and artifact path hinted so far.
    artifacts_seen: Mutex<HashSet<(String, String)>>,
}

impl Prefetcher {
    /// POMs come from `source`; artifacts come through `artifacts`, a
    /// client and the store their bytes wait in, when given. Each kind
    /// downloads at most `concurrency` files at a time, and range versions
    /// [`RANGE_FETCHES_PER_SLOT`] times that.
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
                permits: Semaphore::new(concurrency),
                range_permits: Semaphore::new(concurrency * RANGE_FETCHES_PER_SLOT),
                seen: Mutex::default(),
                listed: Mutex::default(),
                artifacts,
                artifact_permits: Semaphore::new(concurrency),
                artifacts_seen: Mutex::default(),
            }),
            tasks: Mutex::new(JoinSet::new()),
        }
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
        let shared = Arc::clone(&self.shared);
        let repo = repo.clone();
        self.spawn(async move { shared.prefetch_artifact(repo, request, key).await });
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
            let arrival: PomArrival = Arc::new(move |bytes: &bytes::Bytes| {
                let _ = arrivals.send((bytes.clone(), hops));
            });
            async move {
                for repo in repos {
                    match shared.prefetch(permits, repo, &request, &arrival).await {
                        Ok(Some(bytes)) => return (Some(bytes), hops),
                        // The read moves on after these, and stops after
                        // any other failure, such as a retried timeout.
                        Err(err)
                            if matches!(err, RepoError::NotFound(_))
                                || err.moves_to_next_repository() => {}
                        _ => break,
                    }
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
        let Ok(_permit) = self.artifact_permits.acquire().await else {
            return;
        };
        if matches!(client.stored_artifact(store, &repo, &key).await, Ok(None)) {
            client.prefetch_artifact(&repo, &request, store).await;
        }
    }

    async fn prefetch(
        &self,
        permits: &Semaphore,
        repo: &Repository,
        request: &ArtifactRequest,
        arrival: &PomArrival,
    ) -> Result<Option<bytes::Bytes>, RepoError> {
        let Ok(_permit) = permits.acquire().await else {
            return Ok(None);
        };
        rv_repo::announcing_poms(arrival.clone(), self.source.prefetch_pom(repo, request)).await
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
            Some(name) => pom.properties.get(name)?.trim(),
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

    use super::{PomSource, Prefetcher};
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

    /// A range version's POM is fetched while a guess holds the only slot
    /// guesses have.
    #[tokio::test]
    async fn range_versions_skip_the_guesses() {
        let files: std::collections::HashMap<_, _> =
            [pom("g", "bom-stuck", ""), pom("g", "ranged", "")]
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
            1,
        );
        let repo = Repository::new(None, "https://repo.example", true, false);
        let request = |artifact: &str| {
            ArtifactRequest::from_coord(&Coord::parse(&format!("g:{artifact}:1")).unwrap())
        };
        let shared = &prefetcher.shared;
        let guess =
            Arc::clone(shared).prefetch_lineage(vec![repo.clone()], request("bom-stuck"), false);
        let guess = tokio::spawn(guess);
        while shared.permits.available_permits() > 0 {
            tokio::task::yield_now().await;
        }
        let range = Arc::clone(shared).prefetch_lineage(vec![repo], request("ranged"), true);
        tokio::time::timeout(std::time::Duration::from_secs(10), range)
            .await
            .expect("a range version waits for no guess");
        assert_eq!(
            source.0.requests(),
            ["https://repo.example/g/ranged/1/ranged-1.pom"]
        );
        guess.abort();
    }

    /// A lineage is searched as the read searches it: past a repository
    /// that lacks or refuses a POM, but not past one that kept failing a
    /// retried request, such as a 503, after which the read takes no POM
    /// from the next.
    #[tokio::test]
    async fn a_lineage_stops_where_the_read_stops() {
        for (code, moves_on) in [(404, true), (401, true), (500, true), (503, false)] {
            let files: std::collections::HashMap<_, _> = [pom("g", "app", "")].into();
            let mut source = MemoryPomSource::new(rv_config::SecurityConfig::default())
                .with_files("https://second.example", &files);
            if code != 404 {
                source = source.with_refusal("https://first.example", code);
            }
            let source = Arc::new(Prefetching(source, tokio::sync::Barrier::new(1)));
            let prefetcher = Prefetcher::new(
                Arc::clone(&source) as Arc<dyn PomSource>,
                Arc::new(ParsedPomCache::default()),
                None,
                1,
            );
            let repos = ["https://first.example", "https://second.example"]
                .map(|url| Repository::new(None, url, true, false))
                .to_vec();
            let request = ArtifactRequest::from_coord(&Coord::parse("g:app:1").unwrap());
            (Arc::clone(&prefetcher.shared).prefetch_lineage(repos, request, false)).await;
            let asked =
                ["first", "second"].map(|repo| format!("https://{repo}.example/g/app/1/app-1.pom"));
            let asked = if moves_on { &asked[..] } else { &asked[..1] };
            assert_eq!(source.0.requests(), asked, "{code}");
        }
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
