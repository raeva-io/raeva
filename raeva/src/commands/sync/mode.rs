use rv_config::Config;
use rv_repo::{Freshness, RepoClient};

use super::SyncArgs;
use crate::error::Result;

/// What a command was asked to do with raeva.lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Intent {
    /// Keep the lock where it is current and resolve where it is not,
    /// looking for newer SNAPSHOT builds once their update policy expired.
    Plain,
    /// `sync --update`: resolve again, renewing what the cache holds and
    /// accepting new bytes for pinned files.
    Update,
    /// `sync --frozen` and the commands that check freshness: never write
    /// the lock, and keep its SNAPSHOT builds.
    Frozen,
}

/// The effective mode of a command that reads repositories, from
/// `--frozen`, `--update`, `--offline` and `--allow-missing-checksums`, and
/// the only source of a [`RepoClient`] in the CLI. `--platforms` scopes the
/// configuration a client is built from, not its mode.
///
/// `--update --offline` re-resolves from the cache and local repositories:
/// nothing is renewed, but pins may change.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Mode {
    intent: Intent,
    offline: bool,
    allow_missing_checksums: bool,
    /// When the command started, in Unix seconds: the time of the SNAPSHOT
    /// check a resolution records.
    started: i64,
    /// When the command started, which every client of an update shares,
    /// so what it fetched since stands.
    began: std::time::Instant,
}

impl Mode {
    pub(crate) fn sync(args: &SyncArgs, offline: bool) -> Self {
        // clap refuses `--frozen` with `--update`.
        let intent = if args.frozen {
            Intent::Frozen
        } else if args.update {
            Intent::Update
        } else {
            Intent::Plain
        };
        Self::new(intent, offline, args.allow_missing_checksums)
    }

    /// A check of the lock as `sync --frozen` makes it, requiring checksums.
    pub(crate) fn check(offline: bool) -> Self {
        Self::new(Intent::Frozen, offline, false)
    }

    /// A plain read that requires checksums.
    pub(crate) fn plain(offline: bool) -> Self {
        Self::new(Intent::Plain, offline, false)
    }

    /// The plain read online of a traced build's files, which accepts files
    /// without a checksum when the sync does.
    pub(crate) fn trace(allow_missing_checksums: bool) -> Self {
        Self::new(Intent::Plain, false, allow_missing_checksums)
    }

    /// A plain read online that accepts files without a checksum, as the
    /// doctor's probes make.
    pub(crate) fn probe() -> Self {
        Self::new(Intent::Plain, false, true)
    }

    fn new(intent: Intent, offline: bool, allow_missing_checksums: bool) -> Self {
        Self {
            intent,
            offline,
            allow_missing_checksums,
            started: rv_store::metadata_cache::now_epoch_seconds(),
            began: std::time::Instant::now(),
        }
    }

    pub(crate) fn intent(&self) -> Intent {
        self.intent
    }

    pub(crate) fn offline(&self) -> bool {
        self.offline
    }

    /// When the command started, in Unix seconds.
    pub(crate) fn started(&self) -> i64 {
        self.started
    }

    /// The client that resolves for this mode.
    pub(crate) async fn client(&self, config: &Config) -> Result<RepoClient> {
        let client = RepoClient::new(config).await?;
        Ok(self.resolving(client))
    }

    /// The client that restores a lock, or resolves to establish the trust
    /// of what the lock records: it keeps the locked SNAPSHOT builds unless
    /// the run updates.
    pub(crate) async fn restore_client(&self, config: &Config) -> Result<RepoClient> {
        let client = RepoClient::new(config).await?;
        Ok(self.restoring(client))
    }

    /// `client`, which [`Self::client`] built, in the mode of
    /// [`Self::restore_client`]. Clones share their caches.
    pub(crate) fn restoring(&self, client: RepoClient) -> RepoClient {
        let freshness = match self.intent {
            Intent::Update => self.update(),
            Intent::Plain | Intent::Frozen => Freshness::Locked,
        };
        self.with(client, freshness)
    }

    fn resolving(&self, client: RepoClient) -> RepoClient {
        let freshness = match self.intent {
            Intent::Plain => Freshness::Policy,
            Intent::Update => self.update(),
            Intent::Frozen => Freshness::Locked,
        };
        self.with(client, freshness)
    }

    fn update(&self) -> Freshness {
        Freshness::Update { since: self.began }
    }

    fn with(&self, client: RepoClient, freshness: Freshness) -> RepoClient {
        client
            .with_offline(self.offline)
            .with_freshness(freshness)
            .with_allow_missing_checksums(self.allow_missing_checksums)
    }
}
