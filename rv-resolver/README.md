# rv-resolver

The dependency resolution engine for Raeva. This crate builds a dependency graph from a Maven project (`pom.xml`), handling transitive dependencies, version conflicts, exclusions, and dependency-management constraints.

## Features

*   **Maven POM resolution**: Reads `pom.xml` (and parent POMs) and resolves the transitive closure.
*   **Conflict resolution**: two strategies, `NearestWins` (Maven's default: the declaration closest to the root wins, ties broken by declaration order) and `HighestWins` (the highest version wins regardless of depth).
*   **BOM / dependency management**: `<dependencyManagement>` and BOM (`scope=import`) entries are resolved and inlined at the model layer (`rv-maven-model`) while the POM is parsed. The root project's resolved dependency management is then handed to the solver as version constraints, so managed versions and soft-pin overrides are honored across the graph.
*   **Exclusions**: Dependency exclusions (specific and wildcard) are applied as the graph is walked.
*   **Cycle detection**: Cyclic dependencies are detected and broken without aborting the resolution.
*   **Async / parallel**: POM metadata is fetched in parallel with a bounded concurrency cap.

## Architecture

Resolution is driven by a `Solver` that walks dependencies in priority order.

1.  **Priority queue**: A `BinaryHeap` of `QueueItem`s holds the frontier. Items are ordered so that Gradle-style `platform` / `enforced-platform` deps come first, then by lowest depth, then by earliest declaration (`declared_at`). This encodes Maven's nearest-wins, first-declared-wins tiebreak.
2.  **Graph**: A `petgraph` directed graph is built incrementally. On a version conflict the losing subgraph is detached in place (`Graph::replace_node_version`) and the winning version is recorded.
3.  **Batch processing**: Ready items are popped into a batch and their POMs are fetched concurrently (bounded by the configured fetch concurrency) to maximize network throughput.
4.  **Barriers**: `platform` / `enforced-platform` deps are barriers. The current batch drains before they are processed, so their constraints are established before sibling plain deps are resolved. (Plain BOM imports are not barriers; they are already inlined upstream by the model layer.)

### Platform constraints

The root project's resolved `<dependencyManagement>` is converted to platform constraints before solving. A `Backend` implementation may additionally surface platform constraints from a fetched project; the solver merges any such constraints per batch and re-queues an in-flight resolution if a newly discovered constraint changes the version it would pick. The production repository backend does not surface constraints this way (the model layer already inlined them), so for the default resolver this path is inert but remains a supported extension point.

## Usage

```rust,no_run
use rv_resolver::{ResolveContext, Resolver, ResolutionStrategy, RootSpec};

# async fn example(ctx: ResolveContext) -> Result<(), rv_resolver::ResolveError> {
// Maven's default strategy; use HighestWins for highest-version-wins.
let resolver = Resolver::with_strategy(ctx, ResolutionStrategy::NearestWins);

let result = resolver.resolve(RootSpec("pom.xml".into())).await?;
println!("resolved {} packages", result.packages.len());
# Ok(())
# }
```
