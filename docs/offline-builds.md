# Offline builds and the Maven reactor

## Scope

Raeva locks and exports the dependency classpath: `compile`, `runtime`,
`test`, and `provided` artifacts reached from `pom.xml`, plus their parent
POMs and imported BOMs. `system` files inside the project are locked by
digest and not exported (see [`system` dependencies](#system-dependencies)).

Build plugins, their dependencies, build extensions, and artifacts a plugin
resolves from its own configuration (such as `annotationProcessorPaths`)
are locked and exported only when `[plugins] lock = true` in `raeva.toml`
asks for them, and what plugins download while they run only with
`[plugins] trace`; see
[Locked plugins](#locked-plugins). A module that resolves a dependency
type Maven's core does not define pins its build extensions' jars either
way, but they are exported only with them. Without them, fill a second local
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
repositories and mirrors, the repositories and plugin repositories of every
`settings.xml` profile, the repositories and plugin repositories of the
project's POMs and of the parents they inherit from, remote ones included, in
every profile, active or not, and `central`.

This holds while Maven reads no repository that raeva does not use:

- a repository that a dependency's POM declares, which Maven searches and
  raeva skips unless `security.allow_transitive_repositories` or
  `security.transitive_repository_allowlist` admits it (`raeva sync --json`
  lists `TRANSITIVE_REPO_DROPPED`);
- a repository or mirror that only the Maven runs' profiles or settings
  add.

Maven lists a version range in the POM of a dependency before it mediates,
also when that dependency then loses to a nearer version of it, and fails
with "No versions available" when no list names a version in the range.
Each module's `evicted_ranges` lines record the ranges its resolution
listed whose highest version its graph does not hold, with the versions
each repository's list named, one line per repository. Maven reads such a
range in the lists of the repositories the node reads, so the export lists
under a repository's ids the highest version it named in the range whose
POM the export writes, as a relocation's, and otherwise, when no version
listed there is in the range, the lowest version that repository named, as
neither latest nor release, and warns `EXPORT_LOSING_RANGE_VERSIONS`.
`raeva.lock` pins no POM for it, so Maven warns that its POM is missing and
goes on, which only a losing node can. Every range on that artifact that
reads that repository reads the list, so a winning range whose own lists
name no higher version in it resolves to that version and fails. Into the shared local repository
the export lists nothing, and the warning says so.

In Maven 3.9 mode raeva also reads the whole tree below each losing
version, as Maven 3.9 does, so it records the ranges there and fails where
Maven fails on one. With `-Daether.dependencyCollector.impl=bf`, Maven 3.9
collects breadth first and reads nothing below a loser, and neither does
raeva.

One case still makes the offline run fail rather than build another
version: a plugin dependency with a range, `RELEASE` or `LATEST` on an
artifact the lock takes from a repository other than the plugin
repository. A locked artifact that the build also loads as a plugin or
extension without a version, with no `<release>` the lock records, makes
the export refuse, from any repository (see
[Offline Maven builds](#offline-maven-builds)).

### Locked plugins

With `[plugins] lock = true` in `raeva.toml`, `raeva sync` also locks what
Maven 3.9.12, or 3.10.0 under `[lock] maven = "3.10"`, reads to run the
build: the plugins the POMs and the packaging's lifecycle bind,
their dependencies, the Surefire and Failsafe test providers, the
annotation processor paths, build extensions and `.mvn/extensions.xml`,
with every POM Maven reads to collect them. They go in the plugin tables
of `raeva.lock`, which record the inputs they were resolved from.
`raeva sync --frozen` refuses tables that a resolution of the same inputs
does not give. A plain `raeva sync` keeps the tables without resolving
them only while each repository their rows name is one the configuration
or the project's own POMs declare and each row records the one SHA-256 a
resolution writes; otherwise, as for a remote parent's plugin repository
or a lock edited by hand, it resolves the plugins again. It first checks
the tables as `--frozen` does when raeva.lock is not the file this raeva
home last wrote or checked, such as one edited by hand or written on
another machine, and resolves them again if the check fails. Offline,
that check reads the plugin metadata as `--frozen` does, so
`raeva --offline sync` of such a lock needs it in the home: run
`raeva lock verify --download` or an online `raeva sync` first to fill it.
No request and no credential goes to a repository only `raeva.lock` names.
A plain `raeva sync` that keeps the `raeva.lock` this home
last wrote or checked does not download what that check reads, such as a
plugin group's
`maven-metadata.xml`: to make a home ready for
`raeva --offline sync --frozen`, run `raeva sync --frozen` online once, or
restore a seed. `raeva export-m2` writes their files next to the
dependencies. `goals` adds the plugins of goals given on the command line,
such as `spotless:check`. A goal named by its prefix is looked up as the
Maven line does. Maven 3.9 reads the group metadata first, of the project's
plugin groups, the `settings.xml` `<pluginGroups>` and Maven's default
groups in that order, and the project's plugins after. Maven 3.10 asks the
project's plugins first. The tables record the `<pluginGroups>` among their
inputs. Without `[plugins] lock = true`, a sync drops the tables.

What a plugin fetches while it runs, such as a formatter, a site skin or a
distribution zip, is in no model. `trace` names the Maven arguments of the
build and `mvn` its launcher, and a plain online `raeva sync` runs that
build once from an export of the tables of the platform it traces, then
pins each file Maven or a build it forks downloaded, after fetching it again and comparing the
bytes. A file the export already holds is not traced again, also when the
build downloads it anew through a repository its `_remote.repositories`
does not name, as `dependency:copy` does for a plugin's dependency it reads
through a project repository: raeva.lock keeps the repositories the
resolution read it from, so the export does not name that repository's id
and `mvn -o` refuses the file as present but unavailable. A file's
coordinate comes from its path: the extension is the part after the last
dot, or the last two after `tar`, so `a-1-jdk1.8.jar` has the classifier
`jdk1.8` and `a-1-bin.tar.gz` the classifier `bin`.
Plugin locking pins no SNAPSHOT build of a file, so the sync fails on one
the traced build downloads, as on a SNAPSHOT plugin or build extension and
on one in the dependencies of either (exit 5). A SNAPSHOT parent or BOM of a
plugin is pinned with its build, as a dependency's is. A newer build of a SNAPSHOT
dependency raeva.lock pins is left out: the export keeps the pinned one.
The trace goes on the platform of the machine's OS, architecture
and JDK, and one serves each JDK `[lock] jdks` lists; a file only another
JDK's build downloads is not traced. `--frozen` refuses a lock without a
trace of that build and launcher, and never runs it. Before the build
starts, the sync prints one line with the launcher, the number of
arguments and forwarded options, whether it added
`-XX:-UseBASE64Intrinsics` to `JDK_JAVA_OPTIONS` ([Java4Shell](ci.md#java4shell)),
not the arguments, which may hold a secret; `--quiet` and `--json` leave it
out. raeva does not show or keep the build's output: it reads it only to
match a few fixed patterns, and drops it. A build that fails stops the
sync (exit 1), and `raeva.lock` then holds no trace of it, except after
`--update`, which puts back the `raeva.lock` it found, trace included,
and says so, as it does when Ctrl-C or SIGTERM stops that build. The
error gives the exit status; the plugin, goal and module of Maven's
`Failed to execute goal` line where they are a plugin `raeva.lock` pins,
a goal its descriptor lists and a module of the reactor; and whether a
line of the output, in the words Maven 3.9 and 3.10 use, showed that a
JVM could not start, a plugin could not be resolved, a POM could not be
read or a repository refused access (401 or 403). A cause it does not
name is not ruled out. To see the output, run the build yourself. raeva adds `-B`; `-s`
with the settings file it read; its `-D` options, which the error names
without their values; its `-P` options and the `active_profiles` and
`inactive_profiles` ids; `-Dmaven.repo.local` with a new local repository of the
files `raeva.lock` pins, and empty `maven.repo.local.tail` and
`maven.repo.local.head`; `MAVEN_SKIP_RC` where it ran the mavenrc files
first (on Windows `mvn` runs them itself); and
`-XX:-UseBASE64Intrinsics` in `JDK_JAVA_OPTIONS` where the build got it. A trace of other settings stays in
`raeva.lock` until the online sync that traces again replaces it, and
holds the files it pinned to their bytes, unless that sync is `--update`;
a sync on another OS or architecture drops it. The traced build gets raeva's `-P` and `-D` options and the
`active_profiles` and `inactive_profiles` ids, as the resolution read them,
and no `maven.repo.local.tail` or `maven.repo.local.head`, wherever one is
set. The trace is keyed by those, the `-P` and `-D` options of
`.mvn/maven.config`, the `-D` options of `.mvn/jvm.config` and the
argument files it names, the profile ids as a set, `trace`, `mvn` and the
plugins the tables hold, and by most `-D` options of `MAVEN_OPTS` and the
other JVM option variables ([Configuration](configuration.md#plugins)).
The `-D` and `-P` options of `MAVEN_ARGS` count as the command line's. It
is not keyed by the plugins' configuration: after a POM change to what a traced plugin fetches,
such as its formatter version, run `raeva sync --update` to trace again,
or the offline build fails on the file the trace did not pin. A
`raeva.lock` with merge conflicts keeps the trace of each side the same
way. The traced build leaves its output, such as `target/`, in the
checkout. A check such as Apache RAT asks `raeva.toml` for the license
header it asks of every committed file. Commit `raeva.toml` and
`raeva.lock`, and run the offline build below in a fresh clone or a
`git worktree` of that commit, which holds none of the traced build's
output.

```toml
# raeva.toml
[plugins]
lock = true
trace = ["verify"]
mvn = "./mvnw"
```

```sh
raeva sync
offline="$(mktemp -d "${TMPDIR:-/tmp}/raeva-offline.XXXXXX")"
raeva export-m2 --m2-path "$offline/m2"
./mvnw -o "-Dmaven.repo.local=$offline/m2" verify
```

The tables are for the build the inputs describe: its goals, profiles and
settings. Run the offline build with the same ones. A plugin coordinate
that reads the host, such as `${java.version}` or `${env.X}`, and a
profile the JDK, OS or a property turns on that adds or changes a plugin
make the host's values inputs: the tables record their names, a plain
sync on a host with other values resolves the plugins again, and
`--frozen` and `raeva export-m2` refuse there. A plugin without a version
reads the JDK too: raeva skips a version whose `requiredJavaVersion` the
JDK does not meet, as Maven does. Without `[lock] jdks` that is the host's
JDK, whose version becomes an input when a descriptor names a requirement. List the JDKs in `[lock] jdks` to lock each one's plugins. A test that needs the
network fails offline whatever the lock holds. `<pluginRepositories>` in
`settings.xml` profiles are read as Maven reads them: those of the active
profiles come before the POMs', with their `<server>` credentials and
mirrors, and those of the profiles `<activeProfiles>` names serve
`.mvn/extensions.xml`. The tables record them among their inputs. A POM's
plugin repositories are admitted as its repositories are: one over external
HTTP is not searched, and one whose URL may hold a secret is refused in a
project POM (exit 3) and not searched in a fetched one. Maven's `central` and
the project POMs' `<pluginRepositories>` count as repositories the project
declares, as its `<repositories>` do: a sync that fetches a locked plugin
file from one again sends its `<server>` or `[[auth]]` credential, may
reach a private address and follows its redirects by the same rules, and
`raeva sbom` and the other reports no longer resolve again only because
the plugin tables' rows come from these repositories. commons-io, spring-petclinic with its tests, netty,
maven-resolver with its integration tests, log4j2 and mybatis-3 (with
`.mvn/extensions.xml`) build this way with the network off from an empty
local repository; see [Plugin locking](design/plugin-locking.md).

### Repository ids

Maven accepts a file in the local repository for a build only when its
`_remote.repositories` names a repository id that build reads it under.
The export names the id of each repository that served the file, a
plugin's repository included when a plugin and a dependency share the file,
and the id of the mirror that serves that repository under the
configuration now. For a file the export already held, a repository the
traced build downloaded it from again is not among them
([Locked plugins](#locked-plugins)).
`mvn -o` with the `settings.xml` mirror reads the mirror's id; without it,
or with a mirror only in `config.toml`, which Maven does not read, it reads
the declared id.

An origin `raeva.lock` records no id for, such as a `config.toml`
repository without an `id`, is labelled `central`, and the export warns
`EXPORT_REPOSITORY_ID_GUESSED`: `mvn -o` refuses those files where it
reads that repository under another id. Maven reads the ids of a project
POM's lineage in that POM's model, a profile's properties over those of its
POM and of the POMs above it but under those of the POMs below it, so the
export reads them that way, with the project POM's coordinates. An id no
file name can carry, or one with an expression they do not resolve, gets
no list, and the export warns `EXPORT_REPOSITORY_ID_UNUSABLE`: a tail's
list under it can still name a version the lock does not.

Maven also keeps one version list per repository id after mirror
selection, and the module that reads it first fixes it for the others,
whatever their URL. When one id serves an artifact's list at two URLs
that a range, `RELEASE`, `LATEST` or a plugin without a version would read
differently, Maven's choice depends on build order and thread timing, so
`raeva sync` stops (exit 5, `RESOLUTION`) and names the id, both URLs and
the artifact. Give the repositories distinct ids, or use one URL. Lists
that differ only in what the read ignores, such as a `lastUpdated` nothing
picks by, and Central's two names, are fine.

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
They also resolve again when `raeva.lock` names a repository that the
configuration and the local POMs do not declare, and with `[plugins] lock =
true` they refuse plugin tables made from other inputs, as `--frozen` does.
`raeva tree`, `raeva why`, and `raeva lock verify` use the lock as written,
except that `lock verify --download` first resolves as described below.

While the inputs match, `export-m2`, `export-checksums`, `sbom` and `vuln`
use the lock's pins and checksums as written and do not resolve again;
`raeva sync --frozen` does, and it is the check to run in CI before them. They write only what the lock pins:
`export-m2` hashes each file against its pin before it writes it,
`export-checksums` and `sbom` take every digest from the lock, and `vuln`
looks up the lock's coordinates. A lock edited by hand, such as one that
keeps a dependency the POMs no longer reach or names another version, passes
them and fails `raeva sync --frozen`.

`raeva lock verify` checks that the store holds every pinned artifact, its
POM, the parent POMs and imported BOMs the lock pins, and the files of the
plugin tables, with the pinned bytes (exit 7 otherwise). It hashes every
file. `raeva sync` rehashes a
stored file only when its size, timestamps, or file identity changed since
it last matched. `--download` fetches a missing or corrupt file from the
repository the lock records, when configuration or the project's POMs
declare that repository, and then from the platform's other declared
repositories, accepting only the pinned bytes. When none has the file, it
resolves the platform once to add the repositories remote POMs declare,
and tries those too. A restore in `raeva sync` does the same. Before that,
without `--offline` or `--module`, `--download` resolves every recorded
platform as `raeva sync --frozen` does. That downloads the pinned files the
resolution reaches and caches what an offline `raeva sync --frozen` reads
beyond them: version listings, the POMs of versions the lock does not pin,
and the answers of repositories that lack a file. With `--module`, it
runs that resolution when a plugin file is missing or corrupt. A file only
the plugin tables pin is fetched directly only from a repository the
configuration or the project declares; one that neither that nor the
resolution restores stays missing or corrupt. A file a dependency pins
too is repaired as the dependency's is. When that resolution
fails, for a lock that is out of date or a repository that does not answer,
the command warns with `FROZEN_RESOLUTION_FAILED` and checks the store as
written.

Exports cover every platform in `raeva.lock`. A plain or `--frozen`
`raeva sync` downloads all of them. A `--platforms` sync downloads only
the named platforms. On a CI runner with an empty store, `raeva sync
--frozen --platforms` with this machine's platform downloads less, but it
leaves the other platforms' pins unchecked, since only their bytes can
check a SHA-256 pin. `raeva export-m2` then stops (exit 7) at the first
file it lacks. Offline, an export, or a `raeva sync --frozen` of every
platform, exits 5 (`OFFLINE_NOT_CACHED`) instead when another platform's
resolution reads a file the store holds only from a route of the platforms
checked, though its pinned bytes are there. `raeva seed save` copies every
platform's files and stops (exit 7) too, naming the platforms it lacks.
Run `raeva sync --frozen` without `--platforms` before an export or a
seed. `raeva export-m2` needs a section for this machine's
platform and never uses another platform's instead: without one it exits 3
(`PLATFORM_MISSING`) with the `raeva sync --platforms` command that adds it.
With `[lock] jdks` set, it also refuses a JDK the list does not name, or
one whose version is unknown (exit 7), as `raeva sync --frozen` does. A locked file missing from the store stops the export
(exit 7). A remote parent in POM text with no support-POM pin stops it
(exit 3). `raeva sync --update` re-resolves and records its digest.

`raeva sync --offline` keeps using cached POMs and metadata after their
update policy expires, and does not renew them. When it keeps the lock as
written, it restores the lock from the store and local repositories, as
when it resolves, and exits 5 (`OFFLINE_NOT_CACHED`) on a pinned file
they lack. A POM a repository
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

A row whose file `--allow-missing-checksums` accepted records
`missing_checksum = true` (`pom_missing_checksum` for its companion POM;
`missing_checksum` on a `support_poms` row). The pin still checks the
bytes, so later runs need no flag for them, and the marker stays while the
pin does. A download of a marked file asks the repository for its
checksum file again, and `raeva sync --update` downloads marked files
again; a checksum file that matches the pinned bytes drops the marker, and
one that does not fails the command (exit 9). `raeva sync
--frozen` warns `CHECKSUM_MISSING_LOCKED` for marked rows unless
`--allow-missing-checksums` is passed again, and `raeva lock diff` lists
markers that appear or go. `--frozen` does not compare the markers: it
asks no repository for the checksum file of a pinned file, so a marker
removed by hand shows only in `raeva lock diff`.

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
4. `<localRepository>` in `~/.m2/settings.xml`, or in the file a `-s`
   on the command line or in `MAVEN_ARGS` names
5. `~/.m2/repository`

The project does not choose the destination. `local_repository` in its
`raeva.toml`, `-Dmaven.repo.local` in its `.mvn/maven.config` and
`<localRepository>` in a settings file that file names with `-s` are ignored
(`PROJECT_LOCAL_REPOSITORY_IGNORED`), so a cloned project cannot make
`export-m2` write elsewhere. `raeva.lock` does not record
`-Dmaven.repo.local`, so passing it leaves the lock current.
`${user.home}` and `${env.NAME}` expand. Any other expression stops the
export. A relative path is resolved from the current directory, so run `mvn`
there too. An empty value means `~/.m2/repository`.

### A repository of its own

For a locked `mvn -o`, export into a local repository that only this build
uses, and keep the plugins in your usual one as a read-only tail, unless
`[plugins] lock = true` exports them too. The
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
- A version range that took one of two versions that compare equal, such
  as `1.0` and `1.0-ga`, when the export lists both, as where ranges took
  each from another repository, and a version a module holds when the
  lists of the repositories its ranges read name two such spellings, a
  losing range's lists too: `mvn -o` takes between them in the order
  of every version the repositories list, which raeva.lock does not
  record. Give the artifact one version in the project. Two values of one
  recorded `<release>` or `<latest>` are refused too, and, without `[plugins] lock = true`, the metadata of a locked
  artifact that the build also loads as a plugin or extension without a
  version, when the lock records no `<release>` for it (see [Offline Maven builds](#offline-maven-builds)). Exit 3
  (`LOCKFILE_INVALID`).
- An existing file with different bytes. Exit 1 (`EXPORT`). `--overwrite`
  replaces it. Without it, a plain `-SNAPSHOT` file is replaced in a
  repository of its own, as Maven replaces it on every update. In the shared
  local repository it is replaced only when its `.sha256` names its bytes,
  as an earlier export or a Maven download leaves it. A SNAPSHOT that
  `mvn install` wrote there is refused like a release. A directory at a
  file's path is removed only with `--overwrite`.

Export checks the destination of every artifact and POM, under the lock it
holds on the local repository (`.raeva-export.lock`, which it creates with
the directory), before it writes any file, checksum, marker or metadata,
so such a refusal leaves the repository as it was. Sources and Javadoc
jars are checked with the rest. The paths of the checksum, marker and
metadata files it generates are checked against the planned paths, but not
against what is on disk: a directory in the way of one, such as at a
`.sha256` path, fails the export while it writes, after it may have
written other files. `--dry-run` runs the same checks,
writes nothing, and counts the files it would write and the ones already
there. It reads no remote repository, so it judges the sources and Javadoc
jars the store or a `file:` repository holds and warns
`CLASSIFIER_NOT_STORED` for the others.

An export keeps `.raeva-export-unfinished` in the local repository from
before its first write until after its last. One that fails partway or is
killed leaves it, and `mvn -o` there may then read files of the new lock
with metadata of the old one. The next `export-m2` into that repository
warns, hashes each linked file rather than trust its checksum files, writes
every file, checksum, marker and metadata the current lock names, as every
export does, and removes the file. `--dry-run` only warns.
Coordinates the current lock no longer names are not visited. Export does
not sync what it writes, so after a power loss or an operating system crash
run it again even when the file is not there.

`--link hardlink` or `--link symlink` shares the store's files instead of
copying; `--link copy` replaces such links with copies, and `--link
hardlink` replaces symbolic links with hard links. A hard link that cannot
be made, as across file systems, is a copy. By default Maven 3.10 does not
read a file below its local repository's root that is a symbolic link
(`aether.lrm.enhanced.verifyRealPath`), so a Maven 3.10 lock refuses
`--link symlink` (exit 2). An export of a Maven 3.9 lock that `mvn` 3.10
builds needs copies or hard links too.
Export writes the parents and BOMs `raeva.lock` records and the
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
digest differs and accepts a file with no line. Without `[plugins] lock =
true`, plugins and build extensions have no line, except the build
extension jars of a module that resolves a dependency type Maven's core
does not define, and `trustedChecksums.failIfMissing=true` fails on the
first plugin or extension POM. A Maven extension that reads `raeva.lock` instead of this
export is designed, not built ([Maven-side enforcement](design/maven-enforcement.md)).

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

`raeva sync --frozen` checks configuration and the POMs against the lock,
resolves again and compares modules, coordinates, scopes, edges, recorded
active profiles, artifacts and support POMs with the lock, and with
`[plugins] lock = true` the plugin tables. SNAPSHOT update
policies and the time of the last SNAPSHOT check do not matter: frozen
keeps the pinned SNAPSHOT builds, also after a POM edit. While the models
match the lock, a version range, `LATEST` or `RELEASE`, a plugin's own
included, takes no version newer than the locked one, nor another spelling
of it: a range is offered only the versions the lock records. A range in a
build extension's realm is offered the versions of its `extensions` lines.

Local POM edits, including comments, descriptions, build plugin versions
(unless `[plugins] lock = true` locks the plugins) and a new profile that is
not active, pass when they resolve to the same pins, although plain sync records new model and POM hashes. Frozen prints a
note naming changed POMs. After such an edit, a host condition only one side
consulted is not compared. Mirror changes pass when they serve the locked
bytes. A release file or support POM whose `repo_url` names another
repository that is still declared also passes while its pin is unchanged,
even when plain sync would rewrite `repo_url`. Frozen does not check that
this repository serves the file; the pin decides which bytes it accepts.
A support POM beside a row that pins no POM for the same file is the
exception: its `repo_url` decides which modules read it offline, so a
change of it is drift.
It hashes system files of every
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
the `--platforms` list, or every recorded platform when no list is given. When a POM edit changes any
model, frozen resolves every recorded platform and compares it,
as an unlisted `--frozen` does, where a plain partial sync would drop the
unlisted ones. A platform the lock lacks is exit 3 (`PLATFORM_MISSING`). So is
a lock without this machine's platform when no list is given, since a
build here needs that section. Each
platform uses its own repository settings and policies. Downloads check
the locked pins. Resolution drift exits 7.

A new upstream SNAPSHOT build never fails `--frozen` or the freshness
checks, with one exception: raeva.lock does not pin the build of a
SNAPSHOT of an artifact Maven's core exports, such as `maven-artifact`,
that a build extension depends on when raeva reads the extension's
handlers. A new build of it can change the extension's dependencies, and
`--frozen` then exits 7. `raeva sync --update` finds a new build, and so does a plain `raeva sync` once the repository's update
policy has expired, measured from the last sync on this machine that
asked the repositories for that platform. The store records that time in
`metadata.db`, per project and platform. An offline sync and a sync of
other `--platforms` leave it unchanged, and a platform never checked here
is due, as on a fresh clone. A non-unique `-SNAPSHOT` file replaced in
place is fetched again only by `--update`,
as Maven keeps the copy it has, or when `metadata.db` no longer holds its
POM. Either way the POM and jar are fetched together, so the lock pins
both from one build. The cached
`maven-metadata.xml` itself is shared by the projects of one `RAEVA_HOME`,
as Maven's local repository shares it, so a sync that is due can take a
copy another project fetched within the update policy. Projects with SNAPSHOT dependencies should run a
scheduled `raeva sync --update` (setup-raeva's `drift.yml`) to see new
builds. A cached, verified release POM is not fetched
again. With no cached copy, a republished release POM can fail its locked
pin during restoration, even without resolution.

`raeva sync --frozen --offline` resolves from the local store, cache and
file repositories and makes the same comparison. A changed model
resolves every recorded platform, as online. A missing cached file
is an error. It does not detect upstream drift. Once the lock is current,
it checks that the store holds every file the checked platforms pin, by
a lookup that reads no bytes, and exits 7 (`LOCKFILE_MISMATCH`) with the number
missing, which an online `raeva sync --frozen` or
`raeva lock verify --download` downloads. `raeva lock verify` hashes them.
A POM that `raeva.lock` records as missing from a remote repository counts
as missing offline only when the metadata cache holds the 404 an online
sync got for it from that repository, in this home or from a seed saved after such a sync; the lock
alone does not prove it. Otherwise the run exits 7 (`LOCKFILE_MISMATCH`)
and says to run `raeva sync --frozen` online once or restore such a seed;
a lock edited by hand does not match the project. A `file:` repository is
read directly. For a SNAPSHOT, the lock's record of its POM as missing
counts, online too, only on the repository that served its file; another
repository is asked for its own POM or SNAPSHOT metadata.
An artifact's recorded origin counts only when the configuration or the
models of its platform declare it; another platform's settings cannot
authorize that artifact. Trust comes from
the model, never from the lock. A `--platforms` run also fetches the
files the lock pins from the repositories the POMs of the platforms it
leaves out declare, since a row can take the POM another platform read;
the pins decide the bytes, and it resolves nothing through them. A file
from a repository only another platform's resolution trusts stops it
([CI](ci.md#lock-every-platform-ci-runs-on)).
A home where an online `raeva sync --frozen` passed, or an online
`raeva lock verify --download` resolved without `FROZEN_RESOLUTION_FAILED`,
or that restored a seed saved after one, resolves offline on every platform
the lock records. A plain
`raeva sync` that finds `raeva.lock` current downloads the files it pins
without resolving again, so its home can lack what the resolution reads
beyond them, as [Locked plugins](#locked-plugins) describes for the plugin
check.

### Lockfile schema

`raeva.lock` is schema 9
([`schemas/raeva-lock.json`](../schemas/raeva-lock.json)). Every artifact
row pins its `.pom`, and each platform pins the bytes, origin and SNAPSHOT
build of every parent and BOM from a repository that its modules'
dependency resolution read, and of every SNAPSHOT one a build extension's
realm read, as described below. Each module writes its packages and
dependency edges one per line, which keeps a large reactor's lock small
and fast to read. A package line gives the scope the module declares it
with and the scope it resolves to, as written when Maven does not know the
scope, and `?` for the empty scope Maven gives a package reached only in
scopes it does not know. An edge line is `from to scope`, then `optional`
for an optional dependency. A module that resolves a dependency type
Maven's core does not define, such as Jenkins' `executable-war`, reads the
type's handler from every jar Maven loads for each of its build extensions:
the extension's own and those of its dependencies, but the ones Maven's core
provides. It pins them in its `extensions` lines, a classified jar with
its classifier after the version and a SNAPSHOT one at its build, which
`--frozen` and an offline sync take again; one whose metadata names
another build for its POM is refused (exit 3). Each SNAPSHOT parent or BOM
the realm's resolution read, which decides its jars, is pinned among the
module's `support_poms` at its build, and `--frozen` and an offline sync
take that build again; the realm's release POMs are not pinned unless
`[plugins] lock` records them. A handler that reads a class two of
those jars hold with different bytes is refused (exit 3), as raeva does
not follow the order Maven loads them in. A type Maven's core defines, such
as `war`, keeps the core's handler where an extension defines it otherwise,
though Maven may take the extension's, unless the module reads the realm
for a type the core does not define; then a dependency of that type is
refused (exit 3), as is one the plugin tables of `[plugins] lock` meet,
which read every realm. The lock records no repository for
those jars, so a plain `raeva sync` that keeps the lock resolves as `--frozen`
does when the store lacks one. A module, and the plugin
tables, record in `metadata_versions` what they took from repository
metadata that the pins alone do not give `mvn -o`: the version of a
`RELEASE`, a `LATEST` or a plugin without a version, and a range's pick
among listed versions that compare equal. Their `range_versions` lines,
`group:artifact`, version and origin, sorted, record the versions ranges
and parent ranges took and every repository whose list named them; the
plugin tables record there every range their closures read, a losing one
too. `range_versions` is outside the `graph`
digest: `raeva sync --frozen` resolves again and refuses a lock whose
lines differ, unless only their repositories do: the module is otherwise
the same, its ranges took the same versions, every range of the target
took one version of that artifact, and each repository only the lock
names is one the resolution still searches. `evicted_ranges` lines may
differ the same way where each range offers the same versions and no
range took a version of the artifact. Behind a `*` mirror every
repository a range searches lists its version, and without one only those
that hold it do. The export writes or refuses
these as [Offline Maven builds](#offline-maven-builds) and [What export
refuses](#what-export-refuses) describe. A module's optional
`parent_ranges` tables record only remote parent range selections. Each
table has `model` (the model's locked coordinates, with a SNAPSHOT base
version), `parent` (the declared parent
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
merge conflict, and the pins of each side and of the `raeva.lock` at git
`HEAD`. A release file must still match them, as in any plain sync, and
two of them that pin other bytes for one file stop the sync (exit 7). When
a side, or a text without a conflict, has no platform or a row that does
not read, the sync refuses (exit 3). `raeva sync --update`, or deleting
`raeva.lock`, starts again from the bytes the repositories serve. A lock
of a newer schema is the exception: every command, plain sync included,
asks for the newer raeva that wrote it and leaves the file alone. `[lock] jdks` gives the JDK
sections, as in any plain sync. When git has a readable `raeva.lock` at
`HEAD`, the sync lists its changes against that one; otherwise it lists
none, and the warning says which. Commands read a `raeva.lock` that is a
symbolic link through the link, but a sync that must rewrite it refuses
(exit 1): replace the link with a copy of the file it names. Keep other
tools' data out of `raeva.lock`. A row with an empty `checksums` list is invalid
(exit 3, `LOCKFILE_INVALID`) and does not read, so run `raeva sync --update`
to rewrite it.

### Platforms

Each `[[platforms]]` section holds one shared resolution. Its `targets`
list names every platform that resolves to the same artifacts, module graphs,
support POM pins and plugin tables. A target is `linux-x86_64`, or `linux-x86_64@21`
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
modules it can choose depends only on the coordinates of the reactor modules
with its `group:artifact`, which the `graph` digest below covers, and
reading a chosen module's POM counts as above.
Metadata-only changes leave that shared context unchanged; management changes
can require resolving a conflict even if an explicit dependency version wins.
A module's table also has a `graph` digest. It covers the lock's
`config_hash`, the Maven line, the module's record, its path, coordinates
and locked row, the POM pin of each package, the pin of every parent and
BOM its resolution read, which the row lists as `support_poms`, the
property and variable names the graph read, which the row lists as
`ambient_inputs`, the repository ids and the conditions and host values its
target read, the path and version of every reactor module whose
`group:artifact` the module, one of its packages, support POMs, parent
ranges or evicted ranges names, the module's `managed`, `parents` (the
lineage's parents from a repository, nearest first), `evicted_ranges` and
`metadata_versions` lines, and the
packages and edges of
each reactor module it depends on. A reactor module with such a `group:artifact` would have been a
candidate for the graph, so a merge that adds one, or changes its version
or its resolution, under a graph resolved without it is not trusted. A branch that
resolves upstream data again, as `raeva sync --update` does, changes the
`graph` of each module whose graph or support POMs change. Changing the
configuration or the Maven line, or adding or dropping a repository id or a
condition its target read, changes all of them, so a merge with an edit to
such a module conflicts in Git. Adding a module changes only its own rows
and records, those of the module that lists it in `<modules>`, and the
graphs that name its `group:artifact`.

The top-level `maven` names the Maven line the lock was resolved as:
absent for Maven 3.9, and `"3.10"` when `[lock] maven` or the Maven wrapper
selects 3.10. `config_hash` and every `graph` digest cover it, so a plain
sync under another line resolves again and `--frozen` refuses the lock. A
lock whose `graph` digests do not match its rows and records is not
trusted, so a conflict resolved by taking one side of each hunk resolves
again. Git does not always merge two independent changes cleanly: artifact
rows that two branches add next to each other, or a dependency both add,
still conflict.
Local-parent digests cover normalized
bytes and the parent role. The model hash is recomputed from these records;
it is not stored alongside them. Independent edits to different modules can
merge with Git's default merge driver, including adjacent module records.
After the merge, `raeva sync --frozen` checks the combined inputs. Changes
to the shared resolution may still conflict.

`[resolution] ambient_inputs` records each consulted `user-property:NAME`
lookup, including names without a `-D` override. `config_hash` covers their
effective values from the command line, `.mvn/maven.config` and the system
properties of the JVM options; the
recorded names stand for the absence of the rest. A name the model defines
itself is recorded as `user-override:NAME`: its own value ranks above a
JVM option's, so only a `-D` on the command line or in `.mvn/maven.config`
counts for it. An unrelated `-Dci.note`
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
hash still match, its shared pins equal this run's, its `system` files
are unchanged, and it holds plugin tables of the current inputs and trace when
`[plugins] lock = true`. Otherwise it is dropped with `PLATFORM_DROPPED`, which names
the command that restores it. A row this run reads without its POM, where
the kept platform read one, takes that POM with the repositories that
served it, as a sync of every platform pins it, so for a release
coordinate a `--platforms` sync or `--frozen` check gives the lock a sync
of every platform gives. A kept row without a POM beside a POM this run
reads drops the platform, since its repository may serve the POM now,
unless the previous lock pinned that POM as a support POM from the same
repository. A SNAPSHOT whose POM build differs from its jar's can still
drop the other platform.

### Offline Maven builds

With the export and the plugin repository of [Scope](#scope), the offline
run resolves from the reactor root, with or without `-pl <module> -am`. Run
in a module directory (`cd <module> && mvn -o ...`), it is not guaranteed,
because Maven then does not read the reactor root.

`export-m2` writes `_remote.repositories` with the id of every repository
that served a file to a module, and the id of the mirror the current
configuration applies to it (see [Repository ids](#repository-ids)). It
keeps the entries already there, so artifacts that two projects reach
through different repositories resolve for both. A file whose bytes it
replaces, with `--overwrite` or as a SNAPSHOT update, loses its old entries
first, since those repositories did not serve the new bytes.

For each artifact that a version range, a `RELEASE`, a `LATEST` or a
plugin without a version read, `export-m2` writes `maven-metadata-<id>.xml`
listing the versions ranges took from repository `<id>`, with the markers
the others read, and removes
the artifact's other `maven-metadata-*.xml` files, including ones an online
Maven run or `mvn install` left. A version pinned exactly reads no list, so
it adds none: Maven resolves it offline from its files, and a list naming
it could give a range on the same artifact a version that the range's
repositories did not list online. Each module and the plugin tables record
in `range_versions` the versions ranges took and each repository whose list
named them: for a range read through several repositories, the highest
version each lists that the graph holds, beside a reactor version too, and
for a parent range, of a module, a dependency or an imported BOM, each
listed version whose POM the module read. So a range resolves offline to
the version it took online. A range that lost mediation still lists the
version it took where the export writes its POM, as for a relocation.
Its `<release>` and `<latest>` name the greatest version listed, unless a `RELEASE`, a `LATEST` or a plugin without a version
read the artifact's: raeva.lock records the marker `mvn -o` reads first
for each (`metadata_versions`): a `RELEASE`'s `<release>`, a `LATEST`'s
version as `<latest>` even where it fell back to `<release>`, and the
version a plugin took as `<release>`. The export writes those markers alone
in every list of the artifact, so `mvn -o` takes the version Maven took
online even where the lock also holds a greater one, and refuses two
values of one marker. `sync --frozen` holds a marker that moved since at
the recorded version, a plugin's too. Only plugin tables record the
version a build plugin or extension without one took, so without
`[plugins] lock = true` the export refuses to write the metadata of an
artifact such a plugin names, unless the lock records a `<release>` for
it from another read, as `mvn -o` would take the greatest locked
version for it (exit 3, `LOCKFILE_INVALID`): set `[plugins] lock = true`
and run `raeva sync`, or give the plugin a version. To find them it reads
the modules' plugin models offline, when a POM of a module's lineage
declares such a plugin; where the home cannot serve that read, it warns
`EXPORT_PLUGINS_UNCHECKED` and exports that platform without the check. In
the shared local repository it removes none and adds the locked versions
to the lists already there (see
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

## Repositories in or beside the project

A `file:` repository inside the directory holding `raeva.lock`, such as
`file://${project.basedir}/repo/`, is recorded as `./repo/`, so the lock
works on any checkout path. One outside it that shares a directory with it,
such as `file://${project.basedir}/../shared/` or `file:../shared/`, is
recorded from that directory, as `../shared/`, so the lock works wherever
the tree holding both moves. The `../` count from the project directory with
links resolved. A repository that shares only the filesystem root, a drive
or a share with the project, such as `/opt/m2`, keeps its URL, and so does
a URL written through a link that leaves it so, such as `/tmp/...` on macOS,
where the project's own path is `/private/tmp/...`. In a
directory name, `%`, `\`, `#`, `?`, whitespace and invisible characters are
percent-encoded, as in a URL, so `my repo` is recorded as `my%20repo`; a
name with `:` keeps the URL.

A relative origin is only a lookup key. It is used when a current
configuration or POM declares a repository that maps to it. A project moved
without the repository beside it fails `--frozen`: a URL that still names
the repository where it was maps to another origin from the new place
(exit 7), and one written relative to the project names a directory there
that is missing (exit 5) or holds other files (exit 7). Two declarations that map to
one origin but name different directories are exit 3
(`REPOSITORY_ORIGIN_ALIAS`).

## `system` dependencies

A `system` dependency is locked only when `<systemPath>`, after
interpolation and links, is a file inside the directory holding
`raeva.lock`. A path outside it is exit 3 (`INVALID_PROJECT_INPUT`). A
missing, blank, or relative `<systemPath>` is exit 3 (`INVALID_POM`), in a
build plugin's dependency too. raeva judges the path for each locked
platform as Maven on that OS does: on Windows a drive or UNC path is absolute
and `/opt/x.jar` is not; elsewhere only a leading `/` is. A path written
to start at the project directory, such as `${project.basedir}/lib/x.jar`,
at a directory Maven aligns to it, such as `${project.build.directory}`,
`${project.reporting.outputDirectory}` (by default
`${project.build.directory}/site`, whatever property has its name) or a
`${reporting.outputDirectory}` property, or at a property whose value
starts that way, is absolute on every platform.
The project's path on the host written out, such as
`/home/me/app/lib/x.jar`, is judged like any other, so a Windows lock
refuses it, as Maven on Windows does. A path absolute
only on another OS than the one raeva runs on names no file inside the
project, so it is exit 3 too. The
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
- `pom.xml` models only. No polyglot models, and no extensions that change
  the model.
- Build plugins are locked only with `[plugins] lock = true`, and what they
  download while they run only with `[plugins] trace`.
- `settings.xml` profile properties apply to the project's own models and
  their parents, not to dependency POMs.
- Only the root `raeva.toml` applies.
- No Maven build order.
