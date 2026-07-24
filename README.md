# Raeva

A lockfile companion for Maven projects.

Raeva reads your existing `pom.xml`, resolves dependencies, and writes an `rv.lock` with exact versions and SHA-256 checksums. It populates `~/.m2/repository` so you can keep using Maven unchanged.

## Quick start

```bash
rv sync                # Resolve and lock dependencies
rv export-m2           # Populate ~/.m2/repository with the locked dependencies
mvn -o test            # Build with Maven offline (see Scope below re: plugins)
```

## What it does

- **Reads pom.xml directly.** No new config format, no migration.
- **Writes rv.lock** with exact versions and checksums, reproducible across machines.
- **Shared content-addressed cache.** Download once, hardlink everywhere.
- **Populates ~/.m2** so Maven works offline against locked artifacts.
- **Native binary.** Instant startup, no JVM boot penalty.

The only manifest input is `pom.xml`. `rv.toml` is optional and holds tool-only settings (repositories, mirrors, auth, network, security); it cannot declare dependencies.

## Scope

Raeva locks and exports your project's **dependency** classpath: the
`compile`/`runtime`/`test`/`provided` artifacts (and their POM ancestry and
imported BOMs) that resolution reaches from `pom.xml`. That is what makes
`mvn -o` resolve dependencies offline.

It does **not** resolve or export Maven **build plugins** (e.g.
`maven-compiler-plugin`, `maven-surefire-plugin`) or their dependencies. The
plugin classpath is out of scope for v1. A `mvn -o` build still needs its
plugins present in the local repository. In practice they are already cached
from a prior online build or your base image; if you start from a pristine
`~/.m2`, run the build online once (or otherwise pre-populate plugins) before
going offline. `rv export-m2` followed by `mvn -o` gives you a reproducible
**dependency** set, not a from-scratch clean-room offline build.

Raeva v0.2 locks single-module projects only. `rv sync` rejects a multi-module
reactor POM and tells you to run from an individual module's directory.
Multi-module reactor support is on the roadmap.

## Vulnerability scans and SBOMs

`rv vuln` scans the dependencies in `rv.lock` against OSV. It writes a table by
default and also supports JSON and SARIF 2.1.0. Exit code 0 means the scan
completed without findings at or above the `--fail-on` threshold, 1 means it
completed with findings, and 2 means the scan did not complete. CI can
distinguish a finding from a network, API, or input failure.

`rv sbom` generates CycloneDX 1.5 or SPDX 2.3 from `rv.lock`. Documents include
the locked SHA-256 hashes, stable ordering, and content-derived identifiers.
CycloneDX output is byte-identical for the same lock; SPDX includes its required
creation timestamp. Set `SOURCE_DATE_EPOCH` to a Unix timestamp for
byte-identical SPDX output. `rv.lock` does not carry license evidence, so SPDX
license fields are `NOASSERTION` and CycloneDX omits licenses.

```bash
rv vuln
rv vuln --format sarif --fail-on high
rv sbom --format cyclonedx -o bom.cdx.json
rv sbom --format spdx -o bom.spdx.json
```

## Verified against real projects

Raeva is checked against real open-source Maven projects. For each one, three
things are verified from a cold cache:

1. `rv sync` reads the project's `pom.xml` and writes `rv.lock`.
2. rv's locked set is compared against Maven's own resolution
   (`mvn dependency:list`). *Exact* means the two sets are identical,
   coordinate for coordinate.
3. Every locked artifact is deleted from a scratch `~/.m2` so rv is the sole
   provider, then `rv export-m2` and `mvn -o dependency:resolve` must succeed.
   (Build plugins are seeded separately, since they are out of scope; see
   [Scope](#scope) above.)

| Project | Dependencies | Parity | Offline `mvn -o` |
| --- | ---: | --- | --- |
| commons-lang | 23 | exact | pass |
| commons-collections | 31 | exact | pass |
| gson | 12 | exact | pass |
| guava | 5 | exact | pass |
| junit4 | 2 | exact | pass |
| jackson-databind 2.18.2 | 28 | exact | pass |
| spring-petclinic | 171 | exact | pass |

Every project's lockfile matches Maven's own resolution exactly and resolves
offline against the exported set. Tested at each project's current main branch,
with jackson-databind at release 2.18.2.

### Speed

With a warm cache, `rv` resolves an offline dependency graph in tens to a few
hundred milliseconds. The same graph through `mvn dependency:list` takes about a
second, most of it JVM startup:

| Project | Deps | `rv sync --offline` | `mvn -o dependency:list` | Speedup |
| --- | ---: | ---: | ---: | ---: |
| junit4 | 2 | 0.03 s | 0.76 s | ~26x |
| guava | 5 | 0.05 s | 0.94 s | ~20x |
| gson | 12 | 0.07 s | 0.78 s | ~11x |
| commons-lang | 23 | 0.11 s | 0.81 s | ~8x |
| commons-collections | 31 | 0.10 s | 0.79 s | ~8x |
| jackson-databind 2.18.2 | 28 | 0.10 s | 1.04 s | ~10x |
| spring-petclinic | 171 | 0.27 s | 0.99 s | ~4x |

Both read from a warm cache, so this is tool overhead, not network. Median of
five runs on one machine.

## Commands

| Command | Description |
|---------|-------------|
| `rv sync` | Resolve dependencies and update rv.lock |
| `rv sync --frozen` | CI mode: fail if lockfile would change |
| `rv sync --offline` | Use only cached metadata and artifacts |
| `rv export-m2` | Export locked artifacts to ~/.m2/repository |
| `rv tree` | Show dependency tree from rv.lock |
| `rv why <coord>` | Explain why a dependency is included |
| `rv doctor` | Diagnose connectivity, auth, and TLS issues |
| `rv lock` | Inspect or verify the lockfile |
| `rv export-checksums` | Emit lockfile checksums in Maven Trusted Checksums format |
| `rv vuln` | Scan locked dependencies against OSV |
| `rv sbom` | Generate a CycloneDX or SPDX SBOM from rv.lock |

## Authentication

Raeva reads Maven's `~/.m2/settings.xml` for mirrors, proxies, and server credentials (including encrypted passwords). You do not need to configure anything separately.

## Environment variables

| Variable | Effect |
| --- | --- |
| `RAEVA_HOME` | Root for Raeva's config, store, and cache directories. When unset, the platform config/data/cache directories are used. |
| `SOURCE_DATE_EPOCH` | Unix timestamp used as the SPDX creation time for reproducible output. |
| `RV_TIMEOUT` | Per-request network timeout in seconds. Overrides `network.timeout` from `rv.toml`. |
| `RV_RETRIES` | Number of network retry attempts. Overrides `network.retries` from `rv.toml`. |

`JAVA_VERSION` is also read as a fallback value for `${java.version}` POM interpolation, since `rv` does not run a JVM.

## Install

macOS / Linux:

```bash
curl -fsSL https://raeva.io/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raeva.io/install.ps1 | iex
```

Homebrew:

```bash
brew install raeva-io/tap/rv
```

Manual downloads, including Windows `.msi` installers, are available from
[GitHub Releases](https://github.com/raeva-io/raeva/releases).

Rust users can also install with prebuilt binaries via `cargo-binstall`:

```bash
cargo binstall rv-cli
```

or build from source:

```bash
cargo install rv-cli
```

## Raeva Cloud

A hosted private Maven registry that works with `rv`, plain Maven, and Gradle: a repository URL and a token, nothing else to run. Releases are immutable, downloads are checksummed and served from object storage. It is in private beta; join the waitlist at [raeva.io](https://raeva.io).

`rv` needs no special support for it. Point a repository or mirror at your registry URL in `rv.toml` or `settings.xml` and sync as usual.

## License

MIT OR Apache-2.0
