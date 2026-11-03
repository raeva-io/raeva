//! Maven repository client for Raeva.
//!
//! [`RepoClient`] fetches metadata, POMs, and artifacts with their checksum
//! sidecars, through the configured mirrors, proxies, and credentials, and
//! caches metadata and POMs in `metadata.db`. [`ensure_artifacts`] downloads
//! the artifacts a lockfile pins into the store. Bytes are verified against
//! the repository's checksum sidecar (unless missing sidecars are allowed)
//! and, where the lockfile has one, its pin before they enter the store.
//! [`RepositoryPolicy`] decides what a repository a POM declares may reach.
//!
//! This crate fetches and verifies; it does not resolve dependency graphs or
//! write the lockfile. Those are `rv-resolver` and `rv-lock`. Configuration
//! comes from an [`rv_config::Config`] the caller loads, including
//! [`rv_config::NetworkConfig::max_artifact_size`]. The one environment
//! variable read here is the one a bearer proxy names in its `token_env`
//! setting (see [`configured_proxies`]). rv-config reads `HTTPS_PROXY`,
//! `HTTP_PROXY` and `NO_PROXY` into [`rv_config::Config::proxies`], so they
//! take the same guarded path as configured proxies.

mod artifact;
mod auth;
mod client;
mod error;
mod fetch;
mod metadata;
mod mirror;
mod policy;
mod proxy;
mod repository;
mod repository_fallback;
mod restore;
mod routing;
mod transport;

pub use artifact::ArtifactRequest;
pub use auth::{CredentialFile, SentCredential};
pub use client::{
    FetchArtifact, Fetched, PomArrival, RepoClient, SnapshotResolution, announcing_poms,
};
pub use error::{ErrorClass, IntegritySource, RedirectRejectionKind, RepoError};
pub use fetch::FetchProgress;
pub use metadata::{Metadata, Snapshot, SnapshotCandidate, SnapshotVersion};
pub use policy::{Admission, Declaration, Provenance, RepositoryPolicy, secret_url_refusal};
pub use proxy::configured_proxies;
pub use repository::{Repository, fresh_secs, normalize_repo_url};
pub use repository_fallback::RepositoryFallback;
pub use restore::{
    DownloadResult, LockRepositorySelector, RestoreContext, count_missing, ensure_artifacts,
    ensure_support_pom, index_restored, repository_for_package, restore_complete,
    restore_needs_discovery, restore_pinned, select_lock_repository,
};
pub use routing::{RouteInfo, mirrored_repository};
