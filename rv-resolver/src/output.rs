//! What a module's resolution hands to the lockfile writer.

use rv_lock::{LockEdge, Platform, Scope};
use rv_maven_types::{ArtifactCoord, BlobId, Gav, SnapshotStamp};
use rv_repo::Repository;

use crate::graph::Graph;
use crate::resolver::SupportPomProvenance;

/// The resolved graph of one module on one platform, with every external
/// artifact bound to the bytes it resolved to.
#[derive(Debug)]
#[non_exhaustive]
pub struct ModuleResolution {
    pub(crate) graph: Graph,
    /// The platform this graph was resolved for.
    pub platform: Platform,
    /// The locked packages in coordinate order; [`ModuleResolution::edges`]
    /// index into this list.
    pub packages: Vec<ResolvedPackage>,
    /// Dependency edges between [`ModuleResolution::packages`], by index.
    /// Edges from the root module are not listed: they show as each direct
    /// package's [`ResolvedPackage::direct_scope`].
    pub edges: Vec<LockEdge>,
    /// Effective identity of the root module that produced this graph.
    pub module_gav: Gav,
    /// The root module's `<packaging>`, `jar` when it declares none.
    pub module_packaging: String,
    /// Repositories that backed this resolution as `(normalized_url, id)`
    /// pairs, including POM-declared `<repositories>` discovered during the
    /// solve. `raeva export-m2` can't otherwise see the observed (non-config)
    /// repositories, so persisting them lets it label `_remote.repositories`
    /// markers with the correct repository id instead of defaulting to
    /// `central`. Only repositories that carry an id are recorded.
    pub repositories: Vec<(String, String)>,
    /// Repositories approved for this resolution after applying the
    /// root-POM trust rule and the transitive-repository policy. Artifact
    /// population uses these during the same sync; they are never restored
    /// from lockfile metadata.
    pub trusted_repositories: Vec<Repository>,
    /// Provenance for each support POM (parent / imported BOM) as
    /// `("g:a:v", provenance)`. A support POM can resolve from a different
    /// repository than its referencing child, so this preserves both the
    /// serving repository id for `raeva export-m2`'s `_remote.repositories`
    /// markers and the SHA-256 of the bytes export must ship.
    ///
    /// Every remotely fetched support POM appears here; one served by a
    /// repository that carries no id is recorded with an empty id. The
    /// coordinate is the load-bearing half, since `raeva export-m2` refuses to
    /// write an offline repository that is missing a POM named here. An empty
    /// id says only that there is no repository id to put in the POM's marker.
    pub support_pom_provenance: Vec<(String, SupportPomProvenance)>,
    /// Parent range selections for each model this module built.
    pub parent_ranges: Vec<rv_lock::ParentRange>,
    /// What this module's builds read from the host, including what the
    /// builds it reused from other modules read.
    pub host_reads: std::collections::BTreeSet<rv_maven_model::HostInput>,
}

/// One locked package of a module.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ResolvedPackage {
    /// The coordinate raeva.lock records: a timestamped snapshot build under its
    /// `-SNAPSHOT` base version.
    pub coordinate: ArtifactCoord,
    /// The scope the module declares it with, for a direct dependency.
    pub direct_scope: Option<Scope>,
    /// The scope it resolves to, as Maven's JavaScopeSelector picks it.
    pub scope: Scope,
    /// The reactor module this package is, by POM path, when it is one.
    pub workspace_module: Option<String>,
    /// The interpolated `<systemPath>` of a `system` dependency.
    pub system_path: Option<String>,
    /// The bytes an external package resolved to. `None` for a reactor
    /// module and a `system` dependency.
    pub artifact: Option<ResolvedArtifact>,
}

/// An external artifact bound to the bytes this resolution resolved it to.
///
/// Both identities are recorded while the bytes are in hand, never read back
/// from the store's coordinate index: the index is last-writer-wins across
/// every project sharing the store, so it can name other bytes by the time
/// the lock is written.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedArtifact {
    /// The artifact version resolved, a timestamped build for a snapshot.
    pub version: String,
    /// The deployed build a snapshot resolved to.
    pub snapshot: Option<SnapshotStamp>,
    /// The companion POM build when it differs from the artifact build.
    pub pom_snapshot: Option<SnapshotStamp>,
    /// Whether the companion POM of a timestamped artifact is the base
    /// `-SNAPSHOT.pom`.
    pub pom_base: bool,
    /// The repository that served the artifact.
    pub repo_url: String,
    /// The repository that served the companion POM, when another than
    /// `repo_url`.
    pub pom_repo_url: Option<String>,
    /// Content-store SHA-256 of the artifact bytes. Reactor aggregation
    /// compares these instead of server checksum sidecars, which two
    /// repositories may publish under different algorithms.
    pub blob: BlobId,
    /// SHA-256 of the companion `.pom` this resolution parsed for the
    /// artifact, the lockfile's `pom_sha256`. `None` when no repository has
    /// the POM, so the artifact has no dependency information.
    pub companion_pom: Option<BlobId>,
}
