# rv-repo

The repository interaction layer for Raeva. This crate handles the "business logic" of communicating with Maven repositories (like Maven Central, Nexus, Artifactory).

## Responsibilities

*   **Metadata Fetching**: Retrieves `maven-metadata.xml` to resolve versions (snapshots, ranges).
*   **Artifact Fetching**: Downloads POMs, JARs, and other artifacts.
*   **Authentication**: Supports Basic Auth and Bearer Token authentication (configured via `rv.toml` or `settings.xml`).
*   **Mirrors & Proxies**: Handles repository mirroring (replacing one URL with another) and HTTP proxies.
*   **Metadata Caching**: Caches mutable metadata (`maven-metadata.xml`) for a configurable TTL to avoid hitting the network on every resolution.

## Repository Layout

It assumes the standard Maven 2 repository layout:
`/${group/dots/replaced/with/slashes}/${artifactId}/${version}/${artifactId}-${version}.jar`

## Usage

The main entry point is `RepoClient`, constructed from an `rv_config::Config`
and tuned with `with_*` builder methods:

```rust
use rv_repo::{ArtifactRequest, RepoClient, Repository};

// `config` is an `rv_config::Config`.
let client = RepoClient::new(&config).await?.with_offline(false);

// Repository::new(id, url, releases_enabled, snapshots_enabled).
let repo = Repository::new(
    Some("central".to_string()),
    "https://repo.maven.apache.org/maven2/",
    true,  // releases
    false, // snapshots
);

// Resolve version metadata for a coordinate (`coord` is an `rv_version::Coord`).
let metadata = client.fetch_metadata(&repo, &coord).await?;

// Fetch a POM's bytes for a specific artifact.
let req = ArtifactRequest::new("com.example", "demo", "1.0.0");
let pom_bytes = client.fetch_pom(&repo, &req).await?;
```
