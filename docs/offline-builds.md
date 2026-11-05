# Offline builds and the Maven reactor

## Scope

Raeva locks and exports the dependency classpath: `compile`, `runtime`,
`test`, and `provided` artifacts reached from `pom.xml`, plus their parent
POMs and imported BOMs. `system` files inside the project are locked by
digest and not exported (see [`system` dependencies](#system-dependencies)).

Build plugins, their dependencies, build extensions, and artifacts a plugin
resolves from its own configuration (such as `annotationProcessorPaths`)
are not locked or exported. For an offline build, fill a second local
repository with one online Maven run and pass it as a read-only tail. Run
these at the project root:

```sh
offline="$(mktemp -d "${TMPDIR:-/tmp}/raeva-offline.XXXXXX")"
raeva export-m2 --m2-path "$offline/deps"
mvn "-Dmaven.repo.local=$offline/plugins" -DskipTests package
mvn -o "-Dmaven.repo.local=$offline/deps" "-Dmaven.repo.local.tail=$offline/plugins" -DskipTests package
```

In PowerShell:

```powershell
$offline = Join-Path ([IO.Path]::GetTempPath()) ("raeva-offline-" + [guid]::NewGuid().ToString("N"))
raeva export-m2 --m2-path "$offline/deps"
mvn "-Dmaven.repo.local=$offline/plugins" -DskipTests package
mvn -o "-Dmaven.repo.local=$offline/deps" "-Dmaven.repo.local.tail=$offline/plugins" -DskipTests package
```

Keep both repositories outside the checkout. Build checks such as Apache
RAT and Spring's nohttp scan every file in it, `.gitignore` or not, and
`mvn clean` deletes `target/`. `TMPDIR`, or `TEMP` on Windows, must not
point into the checkout either. For repeated builds, `offline` can name a
lasting directory outside the checkout instead, kept for that checkout
alone: the export rewrites its version lists to the lock, so two projects
or two concurrent builds must not share one. On GitHub Actions, use
`offline="$(mktemp -d "$RUNNER_TEMP/raeva-offline.XXXXXX")"` and run the
commands in one step.
Use the same phase for both runs, and in both the profiles and
`settings.xml` that `raeva sync` used; pass `raeva export-m2` the same `-s`
and `-P` too, since it reads the mirrors and repositories from them. Maven
resolves only the plugins that phase needs. Skip tests in both runs or in
neither: Surefire resolves its test provider only when tests run, so a
warm-up run with `-DskipTests` leaves an offline run with tests without it.
A plugin that keeps a cache in the local repository finds none in the
export: give the offline run pgpverify-maven-plugin's key cache from the
warm-up, as `"-Dpgpverify.keycache=$offline/plugins/pgpkeys-cache"`. A
plugin that downloads a tool during the build, such as a JDK for a
toolchain that the machine does not have, fails offline.

The online run resolves the dependencies too, from the repositories as they
are that day, and leaves them and their version lists in the plugin
repository. The offline run reads the tail for any file the export lacks,
and for the version list of any repository id under which the export has
no `maven-metadata-<id>.xml`. A version range, SNAPSHOT, `RELEASE` or
`LATEST` would then resolve from the tail's list, to a version `raeva.lock`
does not pin. So the export writes a list under every id the build can
read, for each locked artifact and each SNAPSHOT version: the locked
versions under the repository that served them, and a list naming nothing
under the other ids and under `local`. The ids are those `raeva.lock`
records, also as the configured mirrors relabel them, the configured
repositories and mirrors, and `central`.

This holds while Maven reads no repository that raeva does not use:

- a repository that a dependency's POM declares, which Maven searches and
  raeva skips unless `security.allow_transitive_repositories` or
  `security.transitive_repository_allowlist` admits it (`raeva sync` warns
  `TRANSITIVE_REPO_DROPPED`);
- a repository or mirror that only the Maven runs' profiles or settings
  add.

Two cases make the offline run fail rather than build another version. One
is a version range in the POM of a dependency that loses to a nearer
version of it, when no locked version is in that range ("No versions
available"). The other is a plugin without a version, or a plugin
dependency with a range, `RELEASE` or `LATEST`, on an artifact the lock
takes from a repository other than the plugin repository.

## A current lock

`raeva export-m2`, `raeva export-checksums`, `raeva sbom`, and `raeva vuln`
check `config_hash` and each recorded platform's model before using
`raeva.lock`. If a model changed, they resolve again and accept the lock
when its pins, modules and recorded profiles still match, using the same
comparison as `raeva sync --frozen`. With `--offline`, the export and SBOM
commands resolve using the local store, cache and file repositories. A missing
cached file is an error. `raeva vuln --offline` remains unsupported.
A changed lock result exits 7 (`LOCKFILE_MISMATCH`) without writing the lock
or command output files. Validation can populate the store and cache.
`raeva tree`, `raeva why`, and `raeva lock verify` use the lock as written.

`raeva lock verify` checks that the store holds every pinned artifact, its
POM, and the parent POMs and imported BOMs the lock pins, with the pinned
bytes (exit 7 otherwise). It hashes every file. `raeva sync` rehashes a
stored file only when its size, timestamps, or file identity changed since
it last matched. `--download` fetches a missing or corrupt file from the
repository the lock records, when configuration or the project's POMs
declare that repository, and then from the platform's other declared
repositories, accepting only the pinned bytes. When none has the file, it
resolves the platform once to add the repositories remote POMs declare,
and tries those too. A restore in `raeva sync` does the same.

Exports cover every platform in `raeva.lock`. A plain or `--frozen`
`raeva sync` downloads all of them. A `--platforms` sync downloads only
the named platforms. On a CI runner with an empty store, `raeva sync
--frozen --platforms` with this machine's platform downloads less, but it
leaves the other platforms' pins unchecked, since only their bytes can
check a SHA-256 pin, and `raeva export-m2` then stops (exit 7) at the first
file it lacks: run `raeva sync --frozen` without `--platforms` before an
export. `raeva export-m2` needs a section for this machine's
platform and never uses another platform's instead: without one it exits 3
(`PLATFORM_MISSING`) with the `raeva sync --platforms` command that adds it. A locked file missing from the store stops the export
(exit 7). A remote parent in POM text with no support-POM pin stops it
(exit 3). `raeva sync --update` re-resolves and records its digest.

`raeva sync --offline` keeps using cached POMs and metadata after their
update policy expires, and does not renew them. A POM a repository
answered missing stays missing, so a dependency without one resolves as
online. It takes a stored file
only as one of the dependency's repositories served it, the first in
repository order, never one that only another repository served. A SNAPSHOT that
`raeva.lock` pins resolves to its pinned build. `raeva sync --update`
fetches cached metadata and non-unique SNAPSHOT POMs again, as `mvn -U`
does. Entries stored by
`--allow-missing-checksums` are fetched again by a later run that requires
checksums, or that run refuses to go offline, unless they match their
`raeva.lock` pins.

SNAPSHOT resolution compares metadata from every eligible repository and selects
its newest `updated` value per classifier and extension; repository order breaks
ties and missing update values. Legacy metadata uses `lastUpdated`. The POM
resolves independently from the unclassified `pom` entry. When its build
differs from the artifact, the lock row records `pom_snapshot` (the same
`timestamp` and `build_number` fields as `snapshot`), so restore, verification
and export use that POM build. Metadata that lists the artifact but no `pom`
entry leaves the POM at the base `-SNAPSHOT.pom`, as in Maven, and the row
records `pom_base = true`; without that file the artifact has no dependencies.

## Where `export-m2` writes

`raeva export-m2` writes to the first of these that is set:

1. `--m2-path`
2. `-Dmaven.repo.local` given to `raeva`, as `mvn` takes it
3. `local_repository` in the user `config.toml`
4. `<localRepository>` in `~/.m2/settings.xml` (or the `-s` file)
5. `~/.m2/repository`

The project does not choose the destination. `local_repository` in its
`raeva.toml` and `-Dmaven.repo.local` in its `.mvn/maven.config` are ignored
(`PROJECT_LOCAL_REPOSITORY_IGNORED`), so a cloned project cannot make
`export-m2` write elsewhere. `raeva.lock` does not record
`-Dmaven.repo.local`, so passing it leaves the lock current.
`${user.home}` and `${env.NAME}` expand. Any other expression stops the
export. A relative path is resolved from the current directory, so run `mvn`
there too. An empty value means `~/.m2/repository`.

### A repository of its own

For a locked `mvn -o`, export into a local repository that only this build
uses, and keep the plugins in your usual one as a read-only tail. The
tail's version lists, `mvn install` output included, do not reach a locked
dependency, within the limits [Scope](#scope) describes:

```sh
deps="$(mktemp -d "${TMPDIR:-/tmp}/raeva-deps.XXXXXX")"
raeva export-m2 --m2-path "$deps"
mvn -o "-Dmaven.repo.local=$deps" "-Dmaven.repo.local.tail=$HOME/.m2/repository" package
```

As above, keep it outside the checkout and use it for this checkout alone.

The Maven local repository other builds share is `<localRepository>` from
`settings.xml`, or `~/.m2/repository`, however the destination spells it
(paths are compared after resolving links). Exporting there adds the locked
files and versions and removes nothing, so `mvn install` output and other
projects' version lists stay. `mvn -o` there can then resolve a range to a
version the lock does not name, so it is not a locked build, and
`export-m2` says so once (`EXPORT_SHARED_REPOSITORY`) and points to the
recipe in [Scope](#scope).

## What export refuses

- A coordinate whose file or directory name Windows cannot store: a device
  name such as `con` or `nul.jar`, a trailing dot or space, a reserved
  character, more than 255 UTF-16 units, or an 8.3 short name such as
  `LONGER~1`. Checked on every platform, before writing. Exit 3
  (`LOCKFILE_INVALID`).
- Planned artifacts, checksums, metadata, or repository markers that share a
  file path, or a file path that another artifact needs as a directory.
  This includes optional sources and javadoc jars. Checked before writing,
  including with `--overwrite` and `--dry-run`. Exit 3 (`LOCAL_REPOSITORY`).
- Names that differ only by letter case on a case-insensitive volume, such
  as APFS or NTFS. Exit 3 (`LOCAL_REPOSITORY`).
- On macOS or a case-insensitive volume, names equivalent under Unicode
  normalization, such as repository ids `é` and `e` followed by a
  combining acute accent. A case-insensitive volume is judged by the
  rules of both APFS and NTFS, so a pair one of them keeps apart may be
  refused. Exit 3 (`LOCAL_REPOSITORY`).
- An existing file with different bytes. Exit 1 (`EXPORT`). `--overwrite`
  replaces it. A plain `-SNAPSHOT` copy is replaced without it, as Maven
  replaces it on every update.

`--dry-run` runs the lock, store, and name checks and counts the files.
`--link hardlink` or `--link symlink` shares the store's files instead of
copying; `--link copy` replaces such links with copies. Export writes the parents and BOMs `raeva.lock` records and the
`<parent>` chain of every exported POM. More than 10,000 stops it
(`RAEVA_EXPORT_M2_MAX_SUPPORT_POMS`).

## Maven Trusted Checksums

`raeva export-checksums` writes `.mvn/checksums/checksums.sha256`, and
`checksums.sha1` for SHA-1 pins, in Maven 3.9's Trusted Checksums summary
format. They cover every pinned artifact, its POM, parents, and BOMs, and
both the timestamped copy and the `-SNAPSHOT` copy of a snapshot. The
command prints the properties that turn the check on (`--json`:
`maven_properties`):

```text
-Daether.artifactResolver.postProcessor.trustedChecksums=true
-Daether.artifactResolver.postProcessor.trustedChecksums.snapshots=true
-Daether.artifactResolver.postProcessor.trustedChecksums.checksumAlgorithms=SHA-256
-Daether.trustedChecksumsSource.summaryFile=true
-Daether.trustedChecksumsSource.summaryFile.basedir=<project>/.mvn/checksums
-Daether.trustedChecksumsSource.summaryFile.originAware=false
```

Use `SHA-256,SHA-1` when `checksums.sha1` exists. Maven fails a file whose
digest differs and accepts a file with no line, such as a plugin.
`trustedChecksums.failIfMissing=true` fails on the first plugin.

A reactor build that stops before `package`, such as `mvn test-compile`,
resolves a sibling module to `target/classes`. Trusted Checksums then fail
with `Is a directory`. Run `package` or a later phase.

## Reactor projects

Run `raeva sync` at the reactor root. Raeva walks the active `<modules>` recursively,
including profile modules, and writes one `raeva.lock` there: a graph per
module and one deduplicated artifact list per platform. Reactor modules are
not downloaded or exported. In a directory that an enclosing `pom.xml` lists
by name in its own `<modules>`, with no `raeva.lock` or `raeva.toml` there,
`raeva sync` without `-C` refuses and names the root;
`raeva -C . sync` locks that module on its own.

### Frozen checks

`raeva sync --frozen` checks configuration and the POMs against the lock.
Changed models and undeclared origins require resolution. SNAPSHOT update
policies and the lock's age do not: frozen restores the pinned SNAPSHOT
builds, and a resolution after a POM edit keeps them too.
Missing support POMs can also require resolution to establish repository
trust during restoration. It compares modules, coordinates, recorded
active profiles, artifacts and support POMs with the lock.

Local POM edits, including comments, descriptions, build plugin versions
and a new profile that is not active, pass when they resolve to the same
pins, although plain sync records new model and POM hashes. Frozen prints a
note naming changed POMs. After such an edit, a host condition only one side
consulted is not compared. Mirror changes pass when they serve the locked
bytes. An identical release file or support POM found in another
still-declared repository also passes, even when plain sync would rewrite
`repo_url`. It hashes system files of every
recorded platform, including those outside the requested platform list.

A change of the reactor's own versions, as `mvn versions:set` makes it,
also passes: frozen compares each module's references to other reactor
modules by module path and ignores their versions. Every other coordinate
is compared as it resolves, so a `${project.version}` that reaches an
external dependency fails when the bump changes its pin. `vuln`, `sbom`
and the exports use the modules at the versions the POMs give now, and a
plain `raeva sync` records them. `tree` and `why` read the lock as
written, so they show the recorded versions until then.

Online frozen resolves and downloads the same platforms as plain sync:
the `--platforms` list, or every recorded platform when no list is given. When a POM edit changes the model of a
platform not listed, frozen resolves that platform too and compares it,
as an unlisted `--frozen` does, where a plain partial sync would drop it. A platform the lock lacks is exit 3 (`PLATFORM_MISSING`). So is
a lock without this machine's platform when no list is given, since a
build here needs that section. Each
platform uses its own repository settings and policies. Downloads check
the locked pins. Resolution drift exits 7.

A new upstream SNAPSHOT build never fails `--frozen` or the freshness
checks. `raeva sync --update` finds it, and so does a plain `raeva sync`
once the repository's update policy has expired, measured from the lock
file's modification time. Projects with SNAPSHOT dependencies should run a
scheduled `raeva sync --update` (setup-raeva's `drift.yml`) to see new
builds. A cached, verified release POM is not fetched
again. With no cached copy, a republished release POM can fail its locked
pin during restoration, even without resolution.

`raeva sync --frozen --offline` resolves changed models from the local
store, cache and file repositories and makes the same comparison. When a
model of a `--platforms` platform changed, it resolves those and fails if
plain sync would drop the others, as online. A change confined to other
recorded platforms resolves every recorded platform. A missing cached file
is an error. It does not detect upstream drift. Once the lock is current,
it checks that the store holds every file the checked platforms pin, by
a lookup that reads no bytes, and exits 7 (`LOCKFILE_MISMATCH`) with the number
missing, which an online `raeva sync --frozen` or
`raeva lock verify --download` downloads. `raeva lock verify` hashes them. Unchanged models also resolve offline
if an artifact's recorded origin is not declared by the configuration or
local POMs for its platform, to see which repositories its model authorizes.
Another platform's settings cannot authorize that artifact. Trust comes from
the model, never from the lock.
A home filled by `raeva sync` or `raeva lock verify --download` resolves
offline on every platform the lock records.

### Lockfile schema

`raeva.lock` is schema 8
([`schemas/raeva-lock.json`](../schemas/raeva-lock.json)). Every artifact
row pins its `.pom`, and each platform pins the bytes, origin and SNAPSHOT
build of every parent and BOM it read. Each module writes its packages
and dependency edges one per line, which keeps a large reactor's lock small
and fast to read. A module's optional `parent_ranges` tables record only
remote parent range selections. Each table has `model` (the model's locked
coordinates, with a SNAPSHOT base version), `parent` (the declared parent
coordinates, including its version range), and `selected` (the chosen
coordinates before SNAPSHOT file expansion). These selections cover that
model's parent chain in this module's repository context. Local parents
come from the working tree and need no recorded selection. They let SBOMs
rebuild inheritance from pinned POMs without consulting version metadata.
Targets share a section only when these selections also agree.
CRLF line endings, as a Windows
checkout with `core.autocrlf` leaves them, read the same. Commands that
read the lock refuse another schema, a missing pin, an unknown key, or an
invalid field (exit 3, `LOCKFILE_INVALID`). A plain `raeva sync` writes a
new lock instead and warns `LOCKFILE_REGENERATED`. It keeps the platforms
the old text names in `targets` and `target` entries, from both sides of a
merge conflict, and takes no pin or name from it. A lock of a newer schema
is the exception: every command, plain sync included, asks for the newer
raeva that wrote it and leaves the file alone. `[lock] jdks` gives the JDK
sections, as in any plain sync. When git has a readable `raeva.lock` at
`HEAD`, the sync lists its changes against that one; otherwise it lists
none, and the warning says which. Keep other tools' data
out of `raeva.lock`. A row with an empty `checksums` list is invalid
(exit 3, `LOCKFILE_INVALID`). Run `raeva sync` to rewrite it.

### Platforms

Each `[[platforms]]` section holds one shared resolution. Its `targets`
list names every platform that resolves to the same artifacts, module graphs,
and support POM pins. A target is `linux-x86_64`, or `linux-x86_64@21`
when `[lock] jdks` selects a JDK. Targets with different model inputs can
still share a resolution.

Each target has a separate `[[inputs]]` record with its active `profiles`
and one `[[inputs.poms]]` table per local POM. Each POM table keeps its path
beside its digest. Module digests cover normalized POM bytes, effective
coordinates, active profile ids, and resolution declarations inherited from
local parents, including the public POM properties those declarations read.
They also cover the context of every reactor BOM a module imports and every
reactor module it depends on, directly or through other reactor modules.
Unread remote models can hide reactor imports, so those records
conservatively cover local public contexts.

In three cases every module record of a target covers the whole reactor, so
any POM change invalidates all of them:

- resolution reads a reactor POM through an external one, as a dependency
  (even one that loses mediation), a parent or an import;
- the project imports a reactor BOM whose import activates other profiles
  than its own build, in the BOM or a local parent;
- resolution takes os-maven-plugin's `os.detection.classifierWithLikes`
  from the project Maven sorts first.

A version range, `RELEASE` or `LATEST` alone does not count: which reactor
modules it can choose depends only on the reactor's coordinates, which every
`graph` digest below covers, and reading a chosen module's POM counts as
above.
Metadata-only changes leave that shared context unchanged; management changes
can require resolving a conflict even if an explicit dependency version wins.
A module's table also has a `graph` digest. It covers the lock's
`config_hash`, the module's record, its locked row, the POM pin of each
package, the pin of every parent and BOM its resolution read, which the row
lists as `support_poms`, the property and variable names the graph read,
which the row lists as `ambient_inputs`, the repository ids and the
conditions and host values its target read, and the coordinates of every
reactor module. A
branch that resolves upstream data again, as `raeva sync --update` does,
changes the `graph` of each module whose graph or support POMs change, and
adding or renaming a module, changing the configuration, or adding or
dropping a repository id or a condition its target read changes all of
them, so a merge with an edit to such a module conflicts in Git. A lock whose `graph`
digests do not match its rows and records is not trusted, so a conflict
resolved by taking one side of each hunk resolves again.
Local-parent digests cover normalized
bytes and the parent role. The model hash is recomputed from these records;
it is not stored alongside them. Independent edits to different modules can
merge with Git's default merge driver, including adjacent module records.
After the merge, `raeva sync --frozen` checks the combined inputs. Changes
to the shared resolution may still conflict.

`[resolution] ambient_inputs` records each consulted `user-property:NAME`
lookup, including names without a `-D` override. `config_hash` covers their
effective values from the command line, `.mvn/maven.config` and the system
properties in `.mvn/jvm.config`; the
recorded names stand for the absence of the rest. An unrelated `-Dci.note`
does not invalidate the lock, and neither does consulting another name
without an override. Adding, changing, or removing a consulted override
does. Each module's row lists the names its graph read, which its `graph`
digest covers. A name most modules of a large reactor read is listed once
for the target instead, and every graph's digest covers it. A lock whose
`[resolution] ambient_inputs` misses a listed name is stale, so a merge
conflict resolved to one side cannot drop a name a graph read without an
override. A sync lists only the names its resolution read and, when it
keeps one of the lock's platforms, the names that platform's graphs list.
A dependency POM gets `-D` values as system properties, below its own
properties, so a name it defines is not read. Lookups through project POMs, dependency POMs,
activations, and settings use the same tracking. The lock records names, never external property values. If an
external value introduces another lookup name, the lock keeps the public
POM expression and context needed to repeat the lookup, without the expanded
name. No separate hashes of value-bearing configuration parts are written
to the lock or cache.

When targets differ, an `[[inputs]]` record's `repo_ids` lists the lines of
`[metadata] repo_ids` that the target's resolution used, and its
`host_inputs` lists the conditions and host values of `[resolution]
ambient_inputs` that the target consulted (`[]` when it consulted none).
A record without them used every line and consulted every entry, so a
single-target lock, or one whose targets agree, lists neither. Every graph
digest of the target covers what it read, listed or not, so a merge or an
edit that changes the ids or conditions without the graphs is not trusted,
and a lock listing a line or entry no target read is refused. A sync of some targets replaces their lists and
keeps the other targets', so an id or a condition only a re-resolved target
used leaves the lock.

Locks built through the library without local input records may instead
supply an opaque `inputs.model_hash`. `raeva sync` always writes the POM
records described above.

Once `raeva.lock` exists, a plain `raeva sync`, `raeva sync --frozen` and
the commands that check freshness use exactly the platforms it records,
crossed with `[lock] jdks` when set, and never add this machine's platform.
A lock written on Linux is checked and rewritten for Linux on a Mac too,
but `raeva sync --frozen` there fails with `PLATFORM_MISSING` unless
`--platforms` names the platforms to check, since a build on the Mac needs
its own section.
This machine's platform is used only when there is no lock yet, or when
`--platforms` names it. The output names the platforms checked. A `--platforms`
sync keeps an unselected platform only when its model hash and configuration
hash still match, its shared pins equal this run's, and its `system` files
are unchanged. Otherwise it is dropped with `PLATFORM_DROPPED`, which names
the command that restores it.

### Offline Maven builds

With the export and the plugin repository of [Scope](#scope), the offline
run resolves from the reactor root, with or without `-pl <module> -am`. Run
in a module directory (`cd <module> && mvn -o ...`), it is not guaranteed,
because Maven then does not read the reactor root.

`export-m2` writes `_remote.repositories` with the id of every repository
that served a file to a module, as it serves that repository now: the mirror
the current configuration applies, or the declared id (`central` when the
artifact was recorded with none). It
keeps the entries already there, so artifacts that two projects reach
through different repositories resolve for both. Run `mvn -o` with those
mirrors in `settings.xml`. A mirror only in `config.toml` is unknown to
Maven.

For each artifact, parent, imported BOM and relocated dependency,
`export-m2` writes `maven-metadata-<id>.xml` listing the versions
`raeva.lock` takes from repository `<id>`, and removes the
artifact's other `maven-metadata-*.xml` files, including ones an online
Maven run or `mvn install` left. A version range then resolves offline to
the locked version. In the shared local repository it removes none and adds
the locked versions to the lists already there (see
[A repository of its own](#a-repository-of-its-own)).

A `SNAPSHOT` is exported as Maven 3.9.11 leaves one: labeled timestamped
files, unlabeled `-SNAPSHOT` copies, and `maven-metadata-<id>.xml`. It
resolves offline with or without the mirror. A version without a hyphen
before `SNAPSHOT`, such as `1.0SNAPSHOT`, is locked as a release and does
not resolve offline; see [Verified against real projects](verification.md). Outside the shared local
repository, every other repository id's `maven-metadata-<id>.xml` in its
directory, and `maven-metadata-local.xml`, lists nothing, since `mvn -o`
reads the latest build any of them names, in the export or in a tail. A
`SNAPSHOT` parent or BOM that `raeva.lock` records by its build is exported
the same way. One it pins as its `-SNAPSHOT` file is exported as that file.
Outside the shared local repository, the metadata next to it is replaced by
lists that name no build, so `mvn -o` reads that file and not a build an
earlier run or a tail names.

## Repositories inside the project

A `file:` repository inside the directory holding `raeva.lock`, such as
`file://${project.basedir}/repo/`, is recorded as `./repo/`, so the lock
works on any checkout path. A relative origin is only a lookup key. It is
used when a current configuration or POM declares a repository that maps to
it. Two declarations that map to one origin but name different directories
are exit 3 (`REPOSITORY_ORIGIN_ALIAS`).

## `system` dependencies

A `system` dependency is locked only when `<systemPath>`, after
interpolation and links, is a file inside the directory holding
`raeva.lock`. A path outside it is exit 3 (`INVALID_PROJECT_INPUT`). A
missing, blank, or relative `<systemPath>` is exit 3 (`INVALID_POM`). The
lock stores `system_path` (relative, `/` separators) and `system_sha256`.
`raeva sync --frozen` hashes the file again and exits 7 if it changed. The
dependency is included in `raeva tree`, `raeva sbom`, and `raeva vuln`.
`export-m2` skips it (`EXPORT_SYSTEM_SCOPED_SKIPPED`).

## Sources and Javadoc

`export-m2 --with-sources` and `--with-javadocs` fetch classifier jars only
from an origin the configuration or local POMs declare for that platform.
Any other origin warns `UNTRUSTED_CLASSIFIER_ORIGIN`. The jars are not
pinned. Each is checked against the repository checksum, and skipped with
`CLASSIFIER_CHECKSUM_MISSING` when there is none. A jar an earlier export
downloaded is reused while its stored file is intact, so `--offline`
exports it again; any other is skipped with `CLASSIFIER_NOT_STORED`.

## Reactor restrictions

- No subset sync with `-pl` or `-am`.
- `pom.xml` models only. No polyglot models or Maven extensions.
- No build plugins.
- `settings.xml` profile properties apply to the project's own models and
  their parents, not to dependency POMs.
- Only the root `raeva.toml` applies.
- No Maven build order.
