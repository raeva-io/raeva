# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-11-26

`raeva.lock` is schema 10. After you upgrade, run `raeva sync` once and
commit `raeva.lock` in the same pull request as the version bump. Until
then, `raeva sync --frozen` refuses the schema 9 lock (exit 3) and says to
run `raeva sync`. `raeva vuln --baseline` cannot read a schema 9 base lock
either (exit 3), so on that pull request run `raeva vuln` without
`--baseline`.

### Fixed

- A cold `raeva sync` could hang when a module's dependency check failed
  while a build extension's dependencies waited to download
  (alibaba/canal).
- `-itr` in `.mvn/maven.config` is read, not refused, so Quarkus can be
  locked.
- A POM that declares ISO-8859-15 is read, as Maven reads it. raeva
  refused it, which stopped projects on Netflix's ribbon, zuul or rxnetty.
- A JitPack branch snapshot such as `main-SNAPSHOT` resolves to the build
  Maven takes, instead of failing with "missing snapshot version data".
- raeva raises its soft limit on open files toward the hard limit, as the
  JVM does for Maven. At macOS's default of 256, syncs of
  kubernetes-client/java and others failed with "Too many open files".
- A repository that redirects to a URL with userinfo, as GitHub Packages
  does, works as in Maven: the userinfo goes as Basic auth to that origin
  alone. raeva put it into the request, and GitHub reset the stream.
- A reactor whose root lists sibling modules, such as re3gistry's
  `<module>../Re3gistry2Model</module>`, is read as Maven reads it, and
  their paths in `raeva.lock` start with `../`.
- A project with several modules reads its parent at `../pom.xml`, as
  Maven does (dataease). raeva still reads no local parent more than one
  directory above the reactor root.
- The lock, `tree`, `why`, `lock diff` and the purls of `sbom` and `vuln`
  name a dependency's declared type where it differs from the file
  extension, as `mvn dependency:list` does: a test-jar shows as
  `test-jar:tests`, not `jar:tests`.
  A reactor module's own purl keeps its packaging.
- A scope with whitespace, as manifold's `<scope>provided, test</scope>`,
  is kept as written with Maven's warning; raeva refused the project.
- A SNAPSHOT without version metadata, such as the JPMS Attic's
  `checker-qual:3.43.0-SNAPSHOT`, resolves to its plain `-SNAPSHOT` files,
  as Maven does.
- A jar's SHA-1 from a response header, such as `X-Checksum-SHA1`, that
  matches the bytes is used whatever the checksum files say, as in Maven.
  Central's stale checksum files for `com.anji-plus:captcha:1.4.0`
  stopped pig.
- A file whose `.sha256` is wrong while its `.sha1`, else its `.md5`,
  from the same repository matches is used with a `SHA256_FILE_MISMATCH`
  warning, as Maven checks only those by default (maven.aliyun.com).
  `raeva.lock` still pins the SHA-256. A `.sha256` answered with an error
  counts as missing.
- A `java.vendor` profile, such as CXF 3.x's `ibmjdk`, no longer stops the
  sync. raeva reads the vendor from the JDK's `release` file and locks the
  profile's outcome. On a JDK 8, or with no JDK, pass
  `-Djava.vendor=<vendor>`.
- `raeva sbom` writes the CycloneDX scope `optional`, not `required`, for
  a component used outside tests only as an optional dependency, as the
  CycloneDX Maven plugin does.
- `[plugins] lock` locks what an `annotationProcessorPaths` entry built by
  the reactor brings in, which raeva left out with maven-compiler-plugin
  3.9.0 and later (Error Prone Support).
- A parent or imported BOM that two repositories serve with different
  bytes no longer stops the sync. As in Maven, the first module to read it
  in Maven's order decides the copy every module gets (mapstruct).
- In the Maven 3.9 mode, a dependency whose conflict group Maven sorts
  ahead of a cycle that holds its parents is kept (dynamic-tp).

### Changed

- After a redirect, a status error never names the redirected path or
  query. A 401 or 403 from a redirect target names that origin and says
  whether the userinfo went to it.
- An edited `raeva.lock` reaches fewer files outside the project: no
  command reads a file by a module path from it, and the freshness check
  skips a `<file>` path that leads out through a symbolic link.
- `schemas/raeva-lock.json` follows the `raeva.lock` reader more closely on
  paths and invisible characters.
- A module no longer takes a file another module downloaded from the same
  URL when its own repository filter keeps it from that repository. Within
  one run, it also takes none downloaded under another repository id,
  unless `raeva.lock` pins it.
- An empty repository, mirror or auth `id` is refused, as Maven refuses
  one.
- `raeva export-m2` replaces a symbolic link where an artifact goes that
  points elsewhere, without reading what it names.
- A mismatch with a checksum file names the file, the checksum file and,
  when it has one, the repository id, and says how to tell which is
  wrong. It no
  longer says to run again later (repo.osgeo.org's opendap 2.1). A missing
  checksum file puts `--allow-missing-checksums` in the JSON error's
  `hints`.
- When two modules resolve a dependency with different bytes from two
  repositories, the refusal (exit 5) names both.
- A `<module>` whose path does not exist fails naming the entry and its
  POM (onedev), and a BOM that no repository has fails with "BOM not found"
  (gravitee).
- In the Maven 3.9 mode, a dependency declared twice in a project POM gets
  Maven's `DUPLICATE_DEPENDENCY` warning.
- The library crates changed in ways that can break code using them, such
  as new enum variants and fields; see docs.rs.

## [0.6.0] - 2026-11-23

`raeva.lock` is now a lock you can review, build from, and not get past by
editing it. This is how it works now.

- `raeva sync --frozen` resolves the project again on every run and fails
  when the result differs from the lock, so a pull request that edits only
  pins, versions or edges no longer passes. While the inputs match, a
  range, `RELEASE`, SNAPSHOT or plugin without a version takes no version
  newer than the locked one
  ([Frozen checks](docs/offline-builds.md#frozen-checks)).
- `raeva lock diff` names the parent, imported BOM or property whose change
  moved the packages. `raeva.lock` is schema 9 and records where each
  managed version came from; a plain sync rewrites a schema 8 lock, and
  `--frozen` refuses one
  ([Review lock changes](docs/ci.md#review-lock-changes-in-pull-requests)).
- With `[plugins] lock = true`, the lock also pins build plugins, their
  dependencies and build extensions, and `[plugins] trace` runs the build
  once to pin what plugins fetch while they run, so `mvn -o` builds from
  one `raeva export-m2`. Plugin locking is off by default
  ([Locked plugins](docs/offline-builds.md#locked-plugins)).
- `[lock] maven = "3.10"`, or a Maven Wrapper for 3.10, resolves as Maven
  3.10.0 does. The lock records the line, and `--frozen` refuses a lock
  resolved under the other one
  ([Maven line](docs/configuration.md#maven-line)).
- raeva reads Maven's options as `mvn` does: it sources the mavenrc files
  with `/bin/sh` (`cmd` on Windows), then reads `MAVEN_ARGS`,
  `.mvn/maven.config` (`-D`, `-P` and `-s`), `.mvn/jvm.config`, and the
  `-D` options and argument files of `MAVEN_OPTS` and the JVM option
  variables. Values that decide the lock are lock inputs
  ([Maven options](docs/configuration.md#maven-options)).
- Where raeva cannot tell what Maven resolves, the sync fails with an error
  that names the cause and the fix, instead of writing a lock that may
  differ ([Where raeva refuses](docs/project-fit.md#where-raeva-refuses-and-maven-builds)).
- A cold `raeva sync` takes about as long as fetching the same files with
  curl, 8 at a time: 1.03 to 1.16 times that on guava,
  jhipster-sample-app, maven-resolver and dubbo against a replay of
  Central with 35 ms of latency (medians of 5 runs). spring-petclinic
  takes 1.27 times that, because raeva first resolves the dependencies of
  its build extension, native-maven-plugin, to read their artifact
  handlers.
- A warm `raeva sync` with an unchanged lock is slower than in 0.5.3:
  0.33 s on guava and 0.565 s on spring-petclinic, about 1.6 to 2.9 times
  0.5.3, and more on projects with build extensions. It is still 2 to 6
  times faster than Maven.

### Added

- `raeva seed key`, `seed save` and `seed restore` carry the locked files
  and cached metadata between CI jobs
  ([Seed the store](docs/ci.md#seed-the-store-and-the-maven-repository)).
- `raeva doctor` checks the project from local files: the wrapper and
  Maven line, build extensions, plugin locking, the lock's platforms, and
  whether CI runs `sync --frozen`.
- For CVE-2026-114938 (Java4Shell), `raeva doctor` warns of a JDK and CPU
  that may be exposed, and the build `[plugins] trace` runs gets
  `-XX:-UseBASE64Intrinsics` where its JDK's `release` file names 11 or
  later and not OpenJ9 ([Java4Shell](docs/ci.md#java4shell)).
- `raeva export-m2 --plan-json` lists what an export writes, for builds
  without raeva. The format is unstable.
- Maven's remote repository filters
  ([Remote repository filters](docs/configuration.md#remote-repository-filters)).
- `raeva tree` and `raeva why` take `--platform` and `--jdk`, and
  [CI](docs/ci.md#relock-dependency-bot-pull-requests) has recipes for
  Dependabot and Renovate.

### Changed

- raeva takes `~/.m2/settings.xml` and `${user.home}` from the JVM's
  `user.home`, as Maven does, instead of `HOME`; set
  `MAVEN_OPTS=-Duser.home=...` to point both at another home. A
  `user.home` raeva cannot look into holds no settings, as for Maven.
- Without `JAVA_HOME`, POMs see the version in the `release` file of the
  JDK behind the `java` on `PATH`, instead of 17
  ([The JDK version](docs/configuration.md#the-jdk-version)).
- A sync stops (exit 5) where Maven's answer depends on build order: one
  repository id that lists different versions at two URLs, or two modules
  that read different bytes for one POM
  ([Repository ids](docs/offline-builds.md#repository-ids)).
- Behind a proxy, a repository that only a fetched POM declares is skipped
  unless your configuration or the transitive allowlist names it
  ([Repositories and mirrors](docs/configuration.md#repositories-and-mirrors)).
- A home 0.5.3 used keeps its store, but 0.6 reads none of the metadata
  0.5.3 cached, since 0.6 decides a `daily` check when it reads it, in the
  zone of the run that reads. The first sync after the upgrade fetches
  that metadata again, so it needs the network, as on a new home: before
  it, `--offline` fails naming the file. Behind a mirror whose URL holds a secret-named
  `${...}`, it downloads the locked files again too, as 0.6 records that
  mirror as `mirror:<id>/`.
- The library crates changed; see docs.rs.

### Fixed

- A `<server>` with a username whose encrypted password cannot be
  decrypted, as when `settings-security.xml` is missing or unreadable, no
  longer stops the sync: unless it has a bearer token, which is still
  sent, it gives no credential for its id, so a repository that allows
  anonymous reads serves it, as it serves Maven.
- Resolution follows Maven more closely: the reactor's shared model cache,
  depth-first collection in the 3.9 line, repository order by effective
  id, unknown scopes kept as Maven keeps them, leading-dot expressions,
  `${project.reporting.outputDirectory}` and other model fields, and
  settings.xml profile conditions recorded as lock inputs.
- `export-m2` lists only the versions ranges, `RELEASE`, `LATEST` and
  plugins without a version took, so `mvn -o` takes the version Maven took
  online, and picks a `file:` repository's mirror as Maven does.
- A `file:` repository beside the project is recorded relative to it, so
  `--frozen`, seeds and `export-m2` work after the tree moves, and a
  symbolic link inside it is followed.
- `--platforms`, offline `--frozen`, seeds and locks with merge conflict
  markers handle the cases they failed on, with the exit codes
  [JSON output](docs/json-output.md) documents.
- `--frozen` refuses a property name added by hand under `[resolution]
  ambient_inputs` that no target lists as read.
- Artifact handlers of a build extension are read from every jar of its
  realm, as Maven loads them, and from a handler class that implements
  `ArtifactHandler` itself, such as `nbm-maven-plugin`'s; one raeva cannot
  read, or that reads a class two of those jars hold differently, fails the
  sync (exit 3), as does a type Maven's core defines that the realm defines
  otherwise.
- A SNAPSHOT jar of a build extension's realm is pinned at its build, as
  is each SNAPSHOT parent and BOM the realm's resolution read, so a seed
  carries them and `--frozen` keeps them after a newer deploy. With
  `[plugins] lock`, the plugin tables refuse such a jar (exit 5), as they
  pin no SNAPSHOT build.

### Security

- What raeva prints and logs shows `***` for settings.xml passwords,
  passphrases and private keys, decrypted ones included, and for the
  value of each secret-named input, from settings, `-D` options, JVM
  option variables or the mavenrc files, unless it is shorter than 4
  characters or reads as a version or a word such as `true`
  ([Repositories and mirrors](docs/configuration.md#repositories-and-mirrors)).
- A repository URL or id that takes a secret-named input, directly or
  through a settings profile property, fails the sync (exit 3) instead of
  reaching `raeva.lock`, the store or a seed.
- `sbom`, `export-m2` and `seed save` read only regular files from the
  store, so a FIFO or link put there reads as missing.
- A settings file that `-s` in `.mvn/maven.config` names is the project's:
  an `[[auth]]` entry without an id does not go to its repositories and
  mirrors, and `export-m2` does not write to its `<localRepository>`.
- raeva does not show or keep the output of the build `[plugins] trace`
  runs. A failed trace names the exit status, and the plugin, goal and
  module only as `raeva.lock` and the reactor name them; run the build to
  see its output ([Locked plugins](docs/offline-builds.md#locked-plugins)).
- A traced build fails (exit 3) before it starts where the mavenrc files
  give a value anew each time they run, so it would not run with the
  values raeva resolved with. A token they fetch anew, in a variable named
  like a secret, which no POM reads, is allowed, outside Windows
  ([Java4Shell](docs/ci.md#java4shell)).

## [0.5.3] - 2026-11-05

### Changed

- `raeva.lock` starts with two comment lines,
  `# This file is automatically @generated by raeva.` and
  `# It is not intended for manual editing.`, as Cargo.lock does, so
  license checks such as Apache RAT accept it. In apache/commons-io,
  commons-lang, commons-text, logging-log4j2 and maven-resolver, `mvn
  package` failed on a committed lock. A plain `raeva sync` adds the lines
  to an existing lock, and `--frozen` accepts a lock with or without them.
- The offline-build recipe in the README, `docs/offline-builds.md` and
  `raeva --help` puts both repositories in a new directory outside the
  checkout. Inside it, build checks that scan every file, such as Apache
  RAT and Spring's nohttp, failed on the exported POMs, `.gitignore` or
  not. After an export into the shared Maven repository, `export-m2` points
  to that recipe instead of suggesting a repository inside the project.
- The Windows install command is
  `powershell -ExecutionPolicy ByPass -c "irm https://raeva.io/install.ps1 | iex"`.
  Under the default Restricted policy, the shorter one failed.

### Fixed

- `raeva export-m2 --help` shows its description again, and `raeva lock
  --help` lists examples. A help example longer than its column no longer
  runs into its comment: `raeva lock verify --module app/pom.xml# Check one
  module` failed when copied.
- A missing-checksum error names `raeva sync --allow-missing-checksums`,
  since only `sync` takes the flag. For metadata from a repository whose
  checksum policy is `fail`, which no flag overrides, it says what has to
  change.
- The `-C` path that the module-directory messages suggest is quoted when
  it holds spaces or shell characters.
- `docs/ci.md`'s install step stops at the first failure, takes the static
  musl archive, and puts `raeva` on `PATH`. `docs/installation.md` says the
  glibc archives need glibc 2.34 or newer. `docs/offline-builds.md` says
  that an export after a `--platforms` sync stops until `raeva sync
  --frozen` restores the other platforms, and how an offline run finds
  pgpverify-maven-plugin's key cache.

## [0.5.2] - 2026-11-03

### Changed

- The store and metadata databases move to a new generation. A home that
  0.5.0 or 0.5.1 used drops the repository evidence and POM cache those
  versions recorded, since they could have kept a tampered file, and
  fetches unpinned files again; stored files are kept and still serve
  pinned restores. `DATABASE_UPGRADED` reports it once. 0.5.1 cannot open
  an upgraded home.
- `-D` options in `.mvn/jvm.config` are read as system properties, as Maven
  passes them to the JVM, so the profiles and `${...}` values they set
  reach the lock. Names the JVM or `mvn` sets itself, such as
  `java.version` or `maven.home`, keep that value. A lock written before can fail `sync --frozen` until
  `raeva sync` relocks it.
- `REPOSITORY_FALLBACK` warns when a repository whose host did not resolve,
  that refused the connection or the TLS handshake, or that answered a
  server error was skipped and a later one served the file, as
  `AUTH_FALLBACK` does for 401 and 403. A sync off a VPN no longer locks a
  public copy of an internal artifact without a word.

### Fixed

- When a repository serves other bytes, with checksum files that match
  them, for a release file or timestamped snapshot build that `raeva.lock`
  pins, raeva refuses them before the resolver reads them or the store
  keeps them, whichever repository serves them, for jars, POMs, parents
  and imported BOMs alike. It does not reuse a stored copy that differs
  from the pin, under `--update` either. 0.5.1 refused the sync but kept
  the bytes, so a later `sync --update`, or another project on the same
  machine, could lock them. A lock row that pins only a SHA-1 digest is
  held to it the same way.
- A token that a settings.xml `<mirror>` URL takes from a secret-named
  `${env.NAME}`, as docs/configuration.md suggests for such services, is
  shown as `***` where errors, warnings and logs show the URL. 0.5.1 printed
  it, for example in the repositories a failed sync searched.
- Repository host and scheme checks use the same URL parser as requests,
  so a URL such as `http://repo.example\@localhost/` no longer passes the
  plain-HTTP blocker or an `external:*` mirror as localhost.
- A project repository URL built from `${project.artifactId}` or another
  model field whose value a fetched parent chose gets the parent's trust,
  so that parent cannot pick the host that receives the id's credentials.
- `raeva export-m2` refuses coordinates whose files, checksum files,
  metadata or directories would overwrite each other, sources and javadoc
  jars included. Names that differ only in case count as one on a volume
  that folds case, and names that differ only in Unicode normalization
  count as one there and on macOS.
- A version longer than 255 bytes is no longer split into items, so a
  crafted metadata listing or POM can no longer use hundreds of MiB.
- A `<file>` condition whose path leaves the project and comes back, such
  as `${project.basedir}/../project/marker.txt`, no longer fails the sync,
  and one that a symlink leads out of the project is not recorded in
  `raeva.lock`, as a path outside it is not.
- An error on a store index that raeva cannot write says to check its
  permissions, and no store error advises deleting the store, which is not
  a cache.
- `raeva lock diff` shows every version of a dependency a module locks,
  not only the last one, and names the version an edge change affects.
- Within one module, a version range after a `RELEASE` lookup no longer
  reuses a release listing whose update policy differs, so it sees the
  versions Maven sees.
- `docs/ci.md` says what `--frozen` trusts in a pull request's lock and how
  to review lock changes. `docs/verification.md` describes the local
  parent boundary as implemented, and what `export-m2` writes for a
  SNAPSHOT version without a hyphen, such as `1.0SNAPSHOT`.

## [0.5.1] - 2026-11-02

### Changed

- Linux-target locks no longer record `os.detection.classifierWithLikes`,
  from `-D` or a settings.xml profile, unless the build reads
  `${os.detected.classifier}`, so they match locks written on macOS, and an
  unread `-D` no longer fails `--frozen`. A 0.5.0 lock written on Linux for
  a project that does not read the classifier still passes `--frozen`, and
  `raeva sync` leaves it as it is. It changes once, the next time raeva
  resolves the project, such as after a POM edit or under `--update`.
- A multi-module sync whose later module declares a dependency raeva cannot
  use, such as an undefined or unreadable version, now fails before
  downloading any jars.
- POM conflict errors name the repository behind each copy.
- `-pl`, `-am` and `-amd` in `.mvn/maven.config` warn that raeva locks the
  whole reactor.
- `docs/ci.md` lets Git merge `raeva.lock` with its default driver.
- `raeva lock diff` says "no dependency changes" when no pin moved, and it
  and the sync summary name the host inputs a lock gained or lost.
  `raeva doctor` says what a 404 leaves unchecked. Several errors give a
  clearer next step, among them a `metadata.db` from a newer raeva, which
  is a cache you can delete.

### Fixed

- `raeva sync` refuses a project repository URL whose path takes the value
  of a secret-named `-D`, settings profile property or allowlisted
  environment variable. The error names the input, never its value. Such a
  repository in a fetched POM is ignored with `REPO_URL_SECRET_REFUSED`.
- An undefined-property version that mediation drops no longer fails the
  sync, as in Maven.
- A host name lookup that fails is tried once more, for repositories and
  OSV, so a flaky CI resolver no longer fails the sync.
- raeva no longer writes to or deletes a `metadata.db` or store index that
  a newer raeva wrote, even one upgraded during the run. Opening one fails
  with an error naming the file.
- Metadata cache entries dated in the future, from clock skew or a copied
  cache, are fetched again, including under `--update`.

## [0.5.0] - 2026-11-01

Most of raeva is rewritten for 0.5.0. This is how it works now.

- **Resolution follows Maven 3.9.11**: POM models, profiles, interpolation,
  `.mvn/maven.config`, repository order and policies, mirrors, proxies,
  SNAPSHOT handling, and nearest-wins mediation. `docs/verification.md`
  lists the known differences.
- **`raeva.lock` pins everything by SHA-256**: every artifact, its POM, and
  every parent and BOM, with its SNAPSHOT build. It records the repository a
  POM or configuration declares, never the mirror that served it, and the
  host conditions resolution read, as outcomes rather than host values.
- **`--frozen` checks the lock**: `raeva sync --frozen` fails when the POMs
  or configuration no longer resolve to the locked pins, and restores the
  locked SNAPSHOT builds; `raeva sync --update` finds newer ones, as
  `mvn -U` does. POM edits that
  keep the same pins pass, and each module has its own freshness record, so
  independent POM edits merge with plain Git.
- **Speed**: with a warm cache raeva resolves 7 to 19 times faster than
  Maven. Checking an up-to-date lock takes under a second.
- **Any platform from any host**: lock for Linux, macOS, and Windows on
  x86_64 and aarch64 with `--platforms`, and for each JDK of a CI matrix
  with `[lock] jdks`. Without `--platforms`, `--frozen` on a host the lock
  has no section for fails and names `--platforms`.
- **Maven options**: every command takes `mvn`'s `-s`, `-P` and `-D`,
  merged with `.mvn/maven.config` as Maven merges them, but a `-s` there is
  ignored with a warning. The lock records property names, never values.
- **Offline builds**: `raeva export-m2 --m2-path <dir>` writes an isolated
  local repository that `mvn -o` builds from, SNAPSHOTs included, where
  ranges take the locked version; in a shared `~/.m2` it warns that the
  build is not locked. `raeva export-checksums` writes Maven's
  trusted-checksums files.
  The lock does not record plugins; `docs/offline-builds.md` covers them.
- **Trust follows who wrote the file**: mirrors, proxies and security
  allowances come only from the user's files. Credentials go only to
  repositories with their id that the configuration or the project's POMs
  declare, private addresses are screened, and plain `http:` repositories a
  POM declares are refused. Downloads are checked against the repository
  checksum and the pin, and a shared store hands a project a file only when
  a repository that project allows served it.
- **Output for people and scripts**: one progress line and one summary per
  sync, exit codes by cause, and `--json` errors with `code` and `hints`.
  Every warning has a code, listed in `docs/json-output.md`.
- **CI caches**: a damaged store index or metadata cache, as a partial cache
  restore can leave, is recreated with a `DATABASE_RECREATED` warning. Keep
  the `cache-key` file beside `metadata.db` out of shared caches.
- **Inspection and reports**: `raeva tree`, `why`, `doctor`, `lock diff`,
  `vuln` (OSV, with `--baseline` to gate only new findings and OpenVEX
  `--vex` to suppress assessed ones), and `sbom` (CycloneDX).
- **Installers**: the command is `raeva`; `rv` is an opt-in alias that
  `README.md` shows how to set up. Linux archives include static musl builds
  for x86_64 and aarch64. Building needs Rust 1.89.

`rv.toml`, `rv.lock` and the `RV_*` variables are now `raeva.toml`,
`raeva.lock` and `RAEVA_*`, and the old files are ignored: rename `rv.toml`,
run `raeva sync`, and commit `raeva.lock` before CI runs `--frozen`. `rv login`, the OS credential store,
`sync --strategy` and SPDX SBOMs are gone; credentials come from
`settings.xml` or `[[auth]]`. The library crates were reorganized; see
docs.rs.

## [0.4.1] - 2026-10-13

### Fixed

- `rv vuln` waits at least as long as an OSV `Retry-After` header asks,
  given in seconds or as an HTTP date and capped at 60 s, before retrying a
  rate-limited request. Before, it retried on its own schedule and could be
  rate-limited again. Retries are scheduled within a 120 s budget, and a
  client error other than 429 whose body cannot be read is no longer retried.
- `Retry-After` dates in the older RFC 850 and asctime forms are honored,
  for repository downloads as well as OSV requests.

### Changed

- No unmaintained dependencies remain: OSV retries use `backon`, as
  repository fetches already did, instead of `backoff` and `instant`;
  `indicatif` 0.18 drops `number_prefix`; and `tabled` is built without its
  derive macros, which pulled in `proc-macro-error2`. `lru` 0.18 and
  `anyhow` 1.0.104 fix three unsoundness advisories. CI now fails on new
  dependency advisories.
- `rv` no longer depends directly on `rand` 0.8, and `strum` and `toml` are
  on the versions the rest of the dependency tree uses, so a build compiles
  fewer duplicate crates. Library users see `toml` 1.x types in `rv-config`
  (`Lockfile::extra`, `ConfigError`) and `strum` 0.28 parse errors from
  `FromStr` on enums such as `Scope`.

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
  only the local inputs (configuration, reactor model, and resolution
  strategy) and does not detect upstream drift, with one exception: a
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

[0.6.1]: https://github.com/raeva-io/raeva/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/raeva-io/raeva/compare/v0.5.3...v0.6.0
[0.5.3]: https://github.com/raeva-io/raeva/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/raeva-io/raeva/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/raeva-io/raeva/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/raeva-io/raeva/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/raeva-io/raeva/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/raeva-io/raeva/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/raeva-io/raeva/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/raeva-io/raeva/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/raeva-io/raeva/releases/tag/v0.1.1
[0.1.0]: https://github.com/raeva-io/raeva/releases/tag/v0.1.0
