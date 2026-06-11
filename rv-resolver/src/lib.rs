//! Dependency resolution and graph building.

mod context;
mod error;
mod graph;
mod parent_resolver;
mod resolver;
mod solver;
mod sync_bridge;
mod tree;
mod util;

pub use context::{ResolveContext, ResolveState};
pub use error::{RepoSearchStatus, RepoStatus, ResolveError};
pub use graph::{Edge, Graph, Node};
pub use resolver::{ResolutionResult, Resolver, RootSpec};
pub use tree::Tree;

/// Strategy for resolving version conflicts when the same dependency is
/// requested at different versions from multiple paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, strum::Display, strum::EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum ResolutionStrategy {
    /// Maven default: closest declaration to root wins; ties broken by
    /// declaration order.
    #[default]
    NearestWins,
    /// Highest version wins regardless of declaration depth.
    HighestWins,
}
