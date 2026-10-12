//! Dependency resolution and graph building.

mod context;
mod error;
mod graph;
mod parent_resolver;
mod parsed_pom_cache;
mod resolver;
mod solver;
mod sync_bridge;
mod tree;
mod util;
mod workspace;

pub use context::{ResolveContext, ResolveState};
pub use error::{ConflictingPom, DroppedRepo, RepoSearchStatus, RepoStatus, ResolveError};
pub use graph::{Edge, Graph, Node};
pub use parent_resolver::{
    accepted_local_parents, build_activation_context, local_parent_boundary, parse_maven_config,
};
pub use resolver::{
    MAX_WORKSPACE_ARTIFACT_POPULATIONS, MAX_WORKSPACE_MODULE_CONCURRENCY, ResolutionResult,
    Resolver, RootSpec, SupportPomProvenance, WorkspaceModuleResolution, WorkspaceResolution,
};
/// Depth bound shared by inheritance resolution and [`accepted_local_parents`].
pub use rv_maven_model::MAX_PARENT_CHAIN_DEPTH;
pub use tree::Tree;
pub use workspace::{Workspace, WorkspaceError, WorkspaceModule};

/// Strategy for resolving version conflicts when the same dependency is
/// requested at different versions from multiple paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, strum::Display, strum::EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum ResolutionStrategy {
    /// Maven default, among candidates that satisfy every hard version range:
    /// siblings under the same parent prefer the higher version; otherwise the
    /// shallower declaration wins, and the first one encountered wins a tie.
    #[default]
    NearestWins,
    /// Highest version wins regardless of declaration depth.
    HighestWins,
}
