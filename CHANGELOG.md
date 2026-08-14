# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-14

### Added

- `rv sync` supports Maven reactors. It discovers active modules recursively
  and resolves each module with its reactor siblings as workspace artifacts.
  It writes one lockfile at the reactor root.
- `rv login`, `rv logout`, and `rv auth list` manage Basic and bearer
  credentials in the OS credential store. The store keys secrets by normalized
  repository endpoint. An atomic index in the config directory holds only
  non-secret metadata for listing.

### Changed

- `rv.lock` schema 4 pins the companion `.pom` of every locked artifact and the
  parent/imported-BOM POMs behind it, to the exact bytes resolution parsed. It
  separates unique external artifact pins from per-module
  dependency graphs. A `[resolution]` table records the mediation strategy the
  lockfile was resolved under, which `--strategy` sets and no configuration
  hash covers. It writes single-module projects as one-module reactors.
  The first non-frozen sync with v0.3 rewrites an existing lockfile once. A
  schema-4 lockfile that still carries the pre-pin shape, an artifact row
  without `pom_sha256` or a two-field support-POM line, is re-resolved and
  rewritten by the next non-frozen sync in the same way. Older `rv` releases
  cannot read schema 4. Schema 1-3 locks remain readable.
- `rv sync --frozen` rediscovers the active reactor. It rejects drift in
  configuration, profiles, the module set, effective coordinates, local POMs,
  the resolution strategy, the resolved graph, and the POM pins. It validates
  schema 1-3 locks without rewriting them.
- `rv tree`, `rv why`, lock inspection and verification, checksum export,
  Maven-repository export, vulnerability scanning, and SBOM generation select
  or aggregate schema-4 module graphs explicitly.
- `rv export-m2` supports offline Maven builds from the reactor root and from
  `mvn -o -pl <module> -am`. Reactor sibling artifacts stay Maven build
  outputs. `rv` does not download or export them as repository artifacts.
  Build plugins stay outside the export contract.
- `rv` resolves repository authentication after mirror substitution. Exact OS
  store entries take precedence over project `rv.toml`, user config,
  `settings.xml`, and ID-less defaults. An origin fallback performs a separate
  lookup for the origin endpoint.
- Authentication selects one complete credential from one source. An
  incomplete higher-precedence entry fails with a configuration error instead
  of borrowing fields from a lower-precedence entry.
- If the OS credential backend is unavailable or has no entry for the expected
  endpoint, `rv` warns once and falls through to configured credentials.
  Corrupt versioned records fail closed. `rv sync` does not prompt for
  credentials.
- `rv` follows one HTTPS cross-origin redirect issued by an explicitly
  configured repository or mirror. This supports registries backed by object
  storage. `rv` still rejects other cross-origin redirects. Repeated mirror
  redirect failures now print an origin-fallback summary. Lockfiles retain the
  configured registry or mirror URL, not the presigned redirect target.

### Fixed

- A BOM imported by a child project now overrides matching dependency
  management inherited from a parent-imported BOM.
- A lower-precedence bearer token no longer survives under a higher-precedence
  Basic username/password pair.
- Credential endpoint errors and diagnostics redact URL userinfo and query
  values.
- A concurrent credential lookup now completes the keyring warning before it
  shares the warn-once state with other requests.
- Maven compatibility now covers standalone `-D` entries in
  `.mvn/maven.config`, project Maven prerequisites, default snapshot repository
  policy, explicit POM dependencies, Maven-plugin artifact mediation, and
  timestamped snapshot identity.
- `rv sync --frozen` now always resolves the graph again and compares it
  against rv.lock in canonical order, so a changed version-range or `LATEST`
  selection, or a republished release POM, is reported as drift instead of
  passing. It accepts unchanged timestamped snapshots, and reports newer
  snapshot timestamp and build identities with their affected module
  coordinates. `--frozen --offline` cannot reach a repository, so it verifies
  only the local inputs — configuration, reactor model, and resolution
  strategy — and does not detect upstream drift, with one exception: a
  lockfile that records an artifact origin the current configuration no longer
  declares is resolved again offline, from the local model and cached
  repository data, so the POMs themselves decide whether that origin is still
  authorized. An expired SNAPSHOT update policy does not trigger that offline
  resolve, since the cached metadata it would need expires on the same policy.
  A schema 1-3 lock keeps the weaker check even online, unconditionally,
  because it carries no reactor identity to resolve against: neither an expired
  SNAPSHOT update policy nor an undeclared recorded origin resolves one afresh,
  so an advanced snapshot goes unreported on it until the next non-frozen sync
  rewrites it to schema 4.
- Changing `--strategy` now forces a fresh resolution instead of reusing a
  lockfile resolved under the other mediation strategy, and `--frozen` rejects
  a lockfile whose recorded strategy differs from the requested one.
- A partial `--platforms` sync now drops an unselected platform whose graph was
  resolved under a different configuration hash or resolution strategy, instead
  of carrying it forward under the new hash on reactor-model equality alone. It
  also drops one that pins a different POM than this run resolved for the same
  coordinate, since Maven has a single local-repository path per coordinate and
  no export could satisfy both.
- `rv sync` records each locked artifact's companion POM, and each parent or
  imported BOM, by the digest of the bytes resolution parsed rather than by
  whatever the content store's coordinate index names when the lockfile is
  written. The index is last-writer-wins across every project sharing the
  store. The download pass verifies each pin and re-fetches rather than
  accepting a repointed index row, `rv sync --frozen` reports a POM whose bytes
  changed even when no dependency edge did, and two parts of one resolution
  that disagree about a POM's bytes now fail the sync naming both instead of
  one silently winning.
- `rv` rejects a lockfile whose support-POM provenance lines are malformed or
  name one coordinate twice, and one that pins two different POMs for a single
  coordinate. Such entries previously read back as an unpinned POM, sending
  `rv export-m2` to the coordinate index for a POM the lockfile had pinned by
  content.
- A deliberately selected single module now resolves its immediate external
  `../pom.xml` parent. Reactor containment for multi-module builds is
  unchanged.

## [0.2.0] - 2026-07-22

### Added

- `rv vuln` scans the locked dependency set against OSV with table, JSON, and
  SARIF 2.1.0 output. `--fail-on` selects the severity threshold; exit code 0
  means no finding met it, 1 means findings met it, and 2 means the scan did
  not complete.
- `rv sbom` generates CycloneDX 1.5 and SPDX 2.3 documents from `rv.lock`,
  includes locked SHA-256 hashes, and uses stable ordering and content-derived
  identifiers. SPDX license fields are `NOASSERTION` because `rv.lock` carries
  no license evidence.

### Fixed

- Resolution now carries a direct `test`- or `provided`-scoped dependency's own
  `compile` and `runtime` transitive dependencies, matching `mvn dependency:list`.
  They were previously dropped (for example, a `test`-scoped `guava-testlib` was
  locked without its `junit` and `hamcrest-core` transitives).
- A `<dependencyManagement>` entry no longer overrides a transitive dependency's
  explicitly declared scope, so a dependency declared `compile` whose coordinate
  the root manages as `test` is no longer forced to `test` and dropped.
- `rv export-m2` now exports an import-scoped BOM referenced by a transitive
  dependency whose version comes from a property defined in that dependency's
  parent POM, so strict offline `mvn -o` resolves it (seen with spring-petclinic's
  `spring-framework-bom`).

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

[Unreleased]: https://github.com/raeva-io/raeva/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/raeva-io/raeva/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/raeva-io/raeva/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/raeva-io/raeva/releases/tag/v0.1.1
[0.1.0]: https://github.com/raeva-io/raeva/releases/tag/v0.1.0
