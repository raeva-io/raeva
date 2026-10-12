# Raeva

A lockfile companion for Maven projects.

Raeva reads your existing `pom.xml`, resolves dependencies as Maven does, and
writes an `rv.lock` with exact versions and SHA-256 checksums. It then fills
`~/.m2/repository` from the lock, so you keep building with Maven.

- **No new manifest.** `pom.xml` stays the only place dependencies are
  declared. An optional `rv.toml` holds tool settings such as repositories,
  mirrors, and network limits.
- **Reproducible.** `rv sync --frozen` fails in CI when the resolved graph no
  longer matches the lock.
- **Multi-module.** One lockfile covers every active module of a reactor.
- **Native binary.** No JVM startup. Artifacts are downloaded once into a
  shared content-addressed cache.

## Install

```bash
curl -fsSL https://raeva.io/install.sh | sh    # macOS, Linux
brew install raeva-io/tap/rv                   # Homebrew
cargo binstall rv-cli                          # prebuilt, via cargo-binstall
cargo install rv-cli                           # from source
```

```powershell
irm https://raeva.io/install.ps1 | iex         # Windows PowerShell
```

Archives and Windows `.msi` installers are on
[GitHub Releases](https://github.com/raeva-io/raeva/releases).

## Quick start

At the project or reactor root:

```bash
rv sync          # resolve and write rv.lock
rv export-m2     # copy the locked dependencies into ~/.m2/repository
mvn -o package   # build offline with Maven
```

Commit `rv.lock`, and run `rv sync --frozen` in CI.

Raeva locks dependencies, not build plugins. An offline Maven build still needs
its plugins in `~/.m2`, usually from an earlier online build. See
[Offline builds](docs/offline-builds.md) for details.

## Commands

| Command | Description |
| --- | --- |
| `rv sync` | Resolve dependencies and update `rv.lock` (`--frozen`, `--offline`) |
| `rv export-m2` | Export locked artifacts to `~/.m2/repository` |
| `rv tree` | Show the dependency tree from `rv.lock` |
| `rv why <coord>` | Explain why a dependency is included |
| `rv lock` | Inspect or verify the lockfile |
| `rv login`, `rv logout`, `rv auth list` | Manage repository credentials |
| `rv doctor` | Diagnose connectivity, auth, and TLS issues |
| `rv vuln` | Scan locked dependencies against OSV |
| `rv sbom` | Generate a CycloneDX or SPDX SBOM |
| `rv export-checksums` | Write Maven Trusted Checksums files |

`rv <command> --help` lists every option.

## Documentation

- [Offline builds and the Maven reactor](docs/offline-builds.md): what is
  locked, frozen checks, and offline Maven builds.
- [Authentication](docs/authentication.md): `rv login`, `settings.xml`, and
  credential precedence.
- [Configuration](docs/configuration.md): environment variables, network
  limits, and checksum policy.
- [Vulnerability scans and SBOMs](docs/vulnerabilities-and-sboms.md)
- [Verified against real projects](docs/verification.md): parity with Maven on
  48 open-source projects, and timings.
- [Changelog](CHANGELOG.md)

## Raeva Cloud

A hosted private Maven registry that works with `rv`, Maven, and Gradle. It is
in private beta; join the waitlist at [raeva.io](https://raeva.io). `rv` needs
no special support for it: point a repository or mirror at the registry URL.

## License

MIT OR Apache-2.0
