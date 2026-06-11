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

## Authentication

Raeva reads Maven's `~/.m2/settings.xml` for mirrors, proxies, and server credentials (including encrypted passwords). You do not need to configure anything separately.

## Environment variables

| Variable | Effect |
| --- | --- |
| `RAEVA_HOME` | Root for Raeva's config, store, and cache directories. When unset, the platform config/data/cache directories are used. |
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

## License

MIT OR Apache-2.0
