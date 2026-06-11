# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-06-11

### Added

- `dist`-based release packaging for Linux, macOS, and Windows.
- Shell and PowerShell installers for the latest GitHub Release.
- Windows MSI installers.
- Homebrew tap publishing for `brew install raeva-io/tap/rv`.
- `cargo-binstall` metadata for Rust users who want prebuilt binaries.

## [0.1.0] - 2026-06-11

Initial public release.

### Added

- `rv sync`: reads `pom.xml`, resolves dependencies transitively, downloads
  artifacts into a shared content-addressed store, and writes `rv.lock` with
  exact versions and SHA-256 checksums. Supports `--frozen` (fail if the
  lockfile would change), `--offline` (use only cached metadata and
  artifacts), `--update`, and `--platforms`.
- Checksum verification prefers a repository's `.sha256` sidecar and falls
  back to `.sha1` (with a weak-hash warning) for repositories that publish
  only SHA-1 checksums, while always pinning the locally computed SHA-256 in
  `rv.lock`. `--allow-missing-checksums` covers repositories that publish no
  sidecar at all.
- `rv sync` persists each artifact's full support-POM closure (its `<parent>`
  ancestry and import-scoped `<dependencyManagement>` BOMs), so exported
  repositories satisfy strict offline `mvn -o` resolution, including parents
  and BOMs hosted in a different repository than their children.
- `rv export-m2`: materializes locked artifacts into `~/.m2/repository`,
  including `_remote.repositories` markers with the correct repository ids,
  so Maven can run offline against the locked dependency set. Maven build
  plugins are out of scope for v1; see the README's Scope section.
- `rv tree`: renders the dependency graph from `rv.lock`.
- `rv why <coord>`: explains why a dependency is in the graph.
- `rv doctor`: diagnoses connectivity, authentication, TLS, and proxy issues.
- `rv lock`: inspects (`lock info`) and verifies (`lock verify`) the lockfile.
- `rv export-checksums`: emits Maven 4 Trusted Checksums format.
- Reads Maven's `~/.m2/settings.xml` for mirrors, proxies, and server
  credentials (including encrypted passwords). An optional `rv.toml` holds
  tool-only settings (repositories, mirrors, auth, network, security); it
  cannot declare dependencies.
- TLS trust is delegated to the OS trust store on every platform via
  `rustls-tls-native-roots`.

[0.1.1]: https://github.com/raeva-io/raeva/releases/tag/v0.1.1
[0.1.0]: https://github.com/raeva-io/raeva/releases/tag/v0.1.0
