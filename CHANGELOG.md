# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-10-13

Maven-compatible conflict resolution, redirects from project repositories,
faster cold syncs of large reactors, and more robust downloads. Resolution
results can differ from 0.3.0, so the first `rv sync` may rewrite `rv.lock`.

### Added

- Repositories with a `file://` URL in the root project or its parent chain
  are read from the local filesystem. `${project.basedir}` is expanded,
  checksum files are optional, and a plain `-SNAPSHOT` layout without
  `maven-metadata.xml` works. `--offline` reads these repositories too.
- `.mvn/maven.config` accepts `--activate-profiles` in addition to `-P`.
- `RV_MAX_ARTIFACT_SIZE` sets the largest artifact `rv` downloads (default
  16 GiB). Artifacts stream to disk, and `RV_TIMEOUT` limits the wait for
  response headers and the idle gap between body chunks instead of the
  whole transfer.
- Artifact downloads that stay below 1 KiB/s for 30 seconds are retried on a
  new connection. `RV_LOW_SPEED_LIMIT` and `RV_LOW_SPEED_TIME` (or
  `network.low_speed_limit` and `network.low_speed_time`) change the limits.
- `rv.toml` repository entries accept `releases-checksum-policy` and
  `snapshots-checksum-policy`.

### Changed

- Nearest-wins conflict resolution follows maven-resolver's
  `NearestVersionSelector`. It keeps every acceptable candidate and
  backtracks to the nearest one that satisfies all hard version ranges.
  Siblings prefer the higher version. A relocated artifact resolves with
  its own version, and the source coordinate's range does not constrain it.
- `rv` follows one HTTPS cross-origin redirect from a repository declared in
  the project's own POMs, including local parents and active profiles. This
  supports registries such as `repo.spring.io` that redirect downloads to
  object storage. Authorization headers are not forwarded. Repositories
  declared only by dependencies still may not redirect across origins.
- A checksum mismatch on remote `maven-metadata.xml` is retried once and
  then reported as a `METADATA_CHECKSUM_MISMATCH` warning instead of failing
  the sync, as Maven's default `warn` checksum policy does. A repository with
  `<checksumPolicy>fail</checksumPolicy>` still fails. Artifact and POM
  checksum mismatches always fail.
- A dependency POM that Maven treats as invalid, such as a system
  dependency without `systemPath`, keeps its artifact and contributes no
  transitive dependencies, with a warning. Project and reactor POMs still
  fail.
- A dependency-not-found error names ignored transitive repositories that
  a POM on the dependency path declared, and shows the `rv.toml`
  `[[repositories]]` entries that would let `rv` search them.
- Each distinct warning is reported once, in a stable order. Before, a large
  reactor could repeat one warning hundreds of thousands of times, and the
  count changed from run to run (during 0.4.0 development, apache/dubbo's
  `--json` sync output reached 137 MB). Human output groups `TRANSITIVE_REPO_DROPPED` by repository URL
  and counts `WEAK_HASH_FALLBACK` artifacts. `--json` lists each distinct
  warning once, sorted by code and context, and `TRANSITIVE_REPO_DROPPED`
  entries gain a `declared_by` context field.
- Cold syncs of large reactors are faster. Concurrent requests for the same
  POM share one download, modules divide the network budget among those
  still running, a missing snapshot is requested once per run, and a version
  range downloads only the POMs of versions that can win. Relocations in
  unselected range alternatives are not discovered, so their targets and
  target dependency management may be absent from the result.
- Large reactors resolve with much less memory and CPU. Modules and platforms
  share parsed POMs, each parent or BOM POM a reactor touches is held once
  until it is written, and a project's dependency management is indexed once
  instead of once per profile. Measured against an earlier 0.4.0
  development build, a warm offline sync of apache/dubbo (116 modules) went
  from 36 s to 29 s, from 63 s to 37 s of CPU, and from 4.8 GB to 0.7 GB of
  memory.
- TLS uses only the ring crypto provider, which `rv` already used at
  runtime. Building from source no longer compiles AWS-LC or needs CMake.

### Fixed

- `rv doctor` reports which credentials a mirrored request would carry by the
  same rule sync uses: a mirror that changes the scheme or port, not just the
  host, does not receive the origin's ID-less default credentials.
- Offline sync uses cached POMs and Maven metadata after their refresh
  interval passes, and the cache no longer deletes rows just because they
  expired.
- Inherited dependencies are ordered child first, as in Maven, which changes
  which version wins some conflicts.
- A transitive dependency that `dependencyManagement` sets to `test` or
  `provided` scope is kept with its subtree, and a managed `<optional>` is
  ignored, as in Maven.
- Parent lookups use repositories declared by already-loaded ancestors and
  by active profiles, and imported BOMs use the parent chain's
  repositories.
- CI-friendly `${revision}` parent versions resolve for reactor BOM imports
  and for published POMs that were not flattened.
- A missing `systemPath` is filled from `dependencyManagement`, and inactive
  profiles no longer fail `systemPath` validation.
- JDK profile activation matches Maven's `JdkVersionProfileActivator`,
  including open-ended ranges, negated prefixes, and early-access versions
  such as `26-ea`. Activation conditions are interpolated before parent
  lookup.
- Profile activation compares `<os><arch>` with the JVM's name for the
  target architecture (`amd64` for x86_64 on Linux and Windows), so
  `<arch>amd64</arch>` profiles activate as they do in Maven. Native
  dependencies such as brotli4j's are now locked on those platforms.
  `${os.arch}` in POMs still expands to the host's Rust architecture name.
- Relocation no longer reports a false cycle, and dependency management is
  applied again to the relocated coordinate.
- Whitespace around POM coordinates is trimmed, and POM parse errors name
  the POM.
- `rv sync --frozen --offline` treats a lockfile's mirror URLs as
  configured origins, so a mirror in `settings.xml` no longer forces a full
  re-resolve. The SNAPSHOT update policy applies to mirrored lock entries.
- `rv export-m2` labels parent and BOM POMs fetched through a mirror with
  the mirror's repository ID, as Maven does.
- A reactor sync writes each shared parent or BOM POM to the store once.
- A rare hang when two reactor modules needed the same POM at the same time
  no longer occurs.
- A download whose body stalls while the store is busy now times out and is
  retried.
- `rv sync --frozen --offline` accepts lockfile origins that the local
  project POMs declare, and an offline resolve looks in every repository's
  cache before it reports a miss. A lockfile origin that neither
  configuration nor the local POMs declare still requires resolution.
- A failed write to the metadata cache no longer aborts a sync. `rv`
  warns once and continues with the downloaded bytes.
- Log output contains ANSI color codes only when stderr is a terminal and
  `NO_COLOR` is unset.

### Security

- `file://` repository reads stay inside the repository directory. Symbolic
  links that point outside it are rejected. On Windows, confinement does not
  guard against the repository being modified during a read.
- Transitive repositories are admitted by their parsed URL scheme (`http`
  or `https`), so a URL with embedded control characters cannot reach a
  `file:` repository.
- Updated `quick-xml` (RUSTSEC-2026-0194, RUSTSEC-2026-0195), `rustls`,
  `rustls-webpki`, and `crossbeam-epoch`.

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
  plugins are out of scope for v1; see [Scope](docs/offline-builds.md#scope).
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

[Unreleased]: https://github.com/raeva-io/raeva/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/raeva-io/raeva/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/raeva-io/raeva/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/raeva-io/raeva/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/raeva-io/raeva/releases/tag/v0.1.1
[0.1.0]: https://github.com/raeva-io/raeva/releases/tag/v0.1.0
