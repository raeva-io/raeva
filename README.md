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

Raeva v0.3 locks single-module projects and multi-module Maven reactors. Run
`rv sync` at the reactor root. One lockfile records every active module. For
frozen, partial-platform, and offline-build behavior, see
[Maven reactor and offline scope](#maven-reactor-and-offline-scope).

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

Raeva is checked against real open-source Maven projects. The single-module
offline matrix verifies three things from a cold cache:

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
| commons-lang | 22 | exact | pass |
| commons-collections | 31 | exact | pass |
| gson | 12 | exact | pass |
| guava | 5 | exact | pass |
| junit4 | 2 | exact | pass |
| jackson-databind 2.18.2 | 28 | exact | pass |
| spring-petclinic | 171 | exact | pass |

The reactor corpus compares every module graph against Maven's resolution:

| Project | Modules | Parity |
| --- | ---: | --- |
| Apache PDFBox | 12 | exact |
| Dropwizard | 42 | exact |
| Apache Maven | 38 | exact |
| JaCoCo | 29 | exact |
| Gson | 8 | exact |
| AssertJ | 13 | exact |

Every listed module matches Maven's own resolution exactly. The single-module
projects also resolve offline against the exported set. Each checkout tracks the
project's current main branch, except jackson-databind, which is pinned to
release 2.18.2.

### Speed

With a warm cache, `rv` resolves an offline dependency graph in tens to a few
hundred milliseconds. The same graph through `mvn dependency:list` takes about a
second, most of it JVM startup:

| Project | Deps | `rv sync --offline` | `mvn -o dependency:list` | Speedup |
| --- | ---: | ---: | ---: | ---: |
| junit4 | 2 | 0.03 s | 0.76 s | ~26x |
| guava | 5 | 0.05 s | 0.94 s | ~20x |
| gson | 12 | 0.07 s | 0.78 s | ~11x |
| commons-lang | 22 | 0.11 s | 0.81 s | ~8x |
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
| `rv login <url-or-id>` | Store credentials in the OS credential store |
| `rv logout <url-or-id>` | Remove credentials from the OS credential store |
| `rv auth list` | List stored credential metadata (never secrets) |
| `rv export-m2` | Export locked artifacts to ~/.m2/repository |
| `rv tree` | Show dependency tree from rv.lock |
| `rv why <coord>` | Explain why a dependency is included |
| `rv doctor` | Diagnose connectivity, auth, and TLS issues |
| `rv lock` | Inspect or verify the lockfile |
| `rv export-checksums` | Emit lockfile checksums in Maven Trusted Checksums format |
| `rv vuln` | Scan locked dependencies against OSV |
| `rv sbom` | Generate a CycloneDX or SPDX SBOM from rv.lock |

## Maven reactor and offline scope

Run `rv sync` at a Maven reactor root. Raeva discovers active `<modules>`
recursively, including modules declared in profiles, and writes one schema-4
`rv.lock` at that root. Each platform section holds a graph for every active
module and one deduplicated union of external artifacts. Reactor siblings are
workspace nodes with full graph edges. Raeva does not download or export them
as repository artifacts.

`rv sync --frozen` rediscovers the active reactor and rejects drift in
configuration, active profiles, the module set, effective GAVs, local POMs, and
the resolution strategy recorded in `rv.lock`. It then resolves the dependency
graph again and compares it against the lockfile in canonical order, so a
changed version-range or `LATEST` selection, or a republished release POM, is
reported as drift rather than accepted. The comparison covers the POM pins as
well as the graph, so a companion, parent, or imported-BOM POM republished with
different bytes and identical dependency edges is reported too.

`rv sync --frozen --offline` is the weaker contract. It cannot reach a
repository, so on a schema-4 lockfile it checks the local inputs above and
stops there, and it does not detect upstream drift. One case is the exception:
when the lockfile records an artifact origin the current configuration no
longer declares, Raeva resolves the graph again offline to rediscover which
repositories the POMs themselves authorize, because repository trust comes from
the model and never from lockfile metadata. That resolve reads only the local
model and the repository data a previous sync cached, and it reports drift the
same way an online `--frozen` run does. An expired SNAPSHOT update policy is
not an exception offline: the cached metadata such a resolve would need carries
the same TTL that expired the pins, so it can only report that the data is not
cached. Run `--frozen` online to check a stale SNAPSHOT.

A schema 1-3 lockfile gets the weaker check even online, unconditionally,
because it carries no reactor identity to resolve against. Neither an expired
SNAPSHOT update policy nor a recorded origin the current configuration no
longer declares makes Raeva resolve a schema 1-3 lockfile afresh, so an
advanced snapshot goes unreported on one. Such a lockfile also records no
resolution strategy, so `--frozen` refuses a run that asks for a non-default
`--strategy` rather than reporting a check it cannot make; the default keeps
passing. The next non-frozen sync rewrites it to schema 4. Use plain `--frozen`
on a schema-4 lockfile as the CI gate.

A schema-4 lockfile written before POM pinning is read as it stands, but Raeva
does not reuse it unchanged: for each selected platform, a plain `rv sync`
resolves again and rewrites that platform's entries with the pins, once. `--frozen` never rewrites a lockfile, so an offline frozen
run accepts the older shape as it is, while an online one resolves and reports
the missing pins as drift, the same answer it gives for anything else a plain
sync would write.

A partial `--platforms` sync keeps an unselected platform only if its
rediscovered model hash still matches, it was locked under the same
configuration hash and resolution strategy, and it pins the same POMs this run
resolved for the coordinates they share. Maven reads one `.pom` per coordinate,
so two platforms pinning different bytes for one coordinate describe a local
repository no export could write. Raeva drops stale platform sections and
reports a diagnostic naming the `rv sync --platforms` command that restores
them.

After `rv export-m2`, these commands resolve dependencies offline:

- `mvn -o package` from the reactor root.
- `mvn -o -pl <module> -am package` from the reactor root.

`cd <module> && mvn -o package` is not guaranteed to resolve offline, because
Maven does not have the reactor root model in that invocation. Build plugins
fall outside the export contract and must already be present in the Maven local
repository.

Reactor support has these restrictions:

- No partial sync with `-pl` or `-am`.
- `pom.xml` models only. Polyglot models and extensions are unsupported.
- No build-plugin resolution.
- Settings-profile properties do not yet apply to POM models.
- Only the root `rv.toml` applies.
- Raeva does not model Maven build order.

## Authentication

Raeva can store Basic or bearer credentials in the OS credential store:

```bash
# Prompts for the username and password on a terminal.
rv login https://repo.example/repository/releases/

# Non-interactive Basic login. Registry tokens that act as Basic passwords,
# including Raeva registry tokens, belong here rather than under bearer auth.
printf '%s\n' "$RAEVA_TOKEN" |
  rv login corp --username "$RAEVA_USER" --password-stdin

# A repository that explicitly uses HTTP Bearer authentication.
printf '%s\n' "$BEARER_TOKEN" |
  rv login https://repo.example/maven2/ --auth-type bearer --password-stdin

rv auth list
rv logout corp
```

An ID passed to `login` or `logout` must identify exactly one configured
repository or mirror. If it does not, pass the URL instead. Raeva scopes
credentials to an exact normalized endpoint: scheme, lowercase host, non-default
port, and base path with a trailing slash. Raeva elides explicit default ports
(`http:80`, `https:443`) and rejects userinfo, query strings, and fragments.
`rv login` does not make a verification request. It reports
`stored; not remotely verified`.

`rv auth list` reads an atomic index under Raeva's config directory. The index
holds only the endpoint, display ID, username, and auth type. Secrets stay in
the OS credential store, and Raeva never enumerates or prints them.

Raeva also reads credentials from project `rv.toml`, the user config, and
Maven's `~/.m2/settings.xml` (including encrypted Maven passwords). Resolution
runs after mirror substitution and selects one complete credential in this
order:

1. OS credential store entry for the exact resolved endpoint.
2. Project `rv.toml` entry matching the resolved repository or mirror ID.
3. User config entry matching that ID.
4. `settings.xml` server entry matching that ID.
5. An ID-less default entry.

A Basic entry must contain a username and a password. A bearer entry must
contain a token. An incomplete entry at a higher precedence is an error, and
Raeva never borrows fields from a lower source. A mirror request looks up the
mirror endpoint. If Raeva falls back to the origin, it performs a separate
lookup for the origin endpoint. Raeva suppresses ID-less defaults when mirror
substitution crosses hosts.

If the OS credential store is unavailable, or an expected endpoint entry is
missing, Raeva warns once and continues with the configured sources. A corrupt
stored record is a hard error. `rv sync` never prompts on stdin.

In CI, use `settings.xml` environment interpolation rather than the OS
credential store:

```xml
<settings>
  <servers>
    <server>
      <id>corp</id>
      <username>${env.RAEVA_USER}</username>
      <password>${env.RAEVA_TOKEN}</password>
    </server>
  </servers>
</settings>
```

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
