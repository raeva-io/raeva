# Checking the lock in CI

On GitHub Actions, use [setup-raeva](https://github.com/raeva-io/setup-raeva).
It installs a pinned raeva, caches the store, and with `check: true` runs
`raeva sync --frozen`.
Its `examples/gitlab-ci.yml` and `examples/Jenkinsfile` show the same check
on GitLab CI and Jenkins. This page lists what any other CI job needs.

## Install a pinned release

Pin the raeva version: a lock written by a newer raeva can use a schema
that an older one refuses. Use the same raeva version in every job and on
developer machines: local, relock and check. Pin the archive's SHA-256 too, taken once from the
release's `sha256.sum`, so a replaced release asset fails the job. Set both
as CI variables; this Linux shell step stops at the first failure:

```sh
set -eu
: "${RAEVA_VERSION:?set RAEVA_VERSION to the pinned release, such as 0.6.0}"
: "${RAEVA_SHA256:?set RAEVA_SHA256 to the archive's SHA-256 from sha256.sum}"
RAEVA_ARCHIVE=raeva-x86_64-unknown-linux-musl.tar.gz
curl --proto '=https' --tlsv1.2 -fsSL -o raeva.tar.gz \
  "https://github.com/raeva-io/raeva/releases/download/v$RAEVA_VERSION/$RAEVA_ARCHIVE"
echo "$RAEVA_SHA256  raeva.tar.gz" | sha256sum -c -
mkdir -p "$HOME/.local/bin"
tar -xzf raeva.tar.gz -C "$HOME/.local/bin" --strip-components=1 --wildcards '*/raeva'
export PATH="$HOME/.local/bin:$PATH"
raeva --version
```

`export PATH` lasts for this shell. In later steps, use the CI system's
path setting or call `$HOME/.local/bin/raeva`.

The musl archive is linked statically, so it runs on x86_64 Linux with glibc
or musl, of any version. On aarch64, take `aarch64-unknown-linux-musl`
([Installation](installation.md)).

## Lock every platform CI runs on

`raeva sync` locks the platform it runs on. When developers write the lock on
a Mac and CI runs Linux, lock both:

```sh
raeva sync --platforms linux-x86_64,macos-aarch64
```

Later syncs keep the platforms the lock records. The names are
`linux-x86_64`, `linux-aarch64`, `macos-x86_64`, `macos-aarch64`,
`windows-x86_64`, and `windows-aarch64`.

A job that checks one platform on a clean runner, `raeva sync --frozen
--platforms linux-x86_64`, also fetches a file the lock pins for linux from
a repository only another platform's POMs declare, as when the linux row
takes the POM windows read there, and holds it to its pin. A repository
only another platform's resolution learns, such as one a remote parent
declares in a Windows profile, is not resolved: the run stops (exit 3,
`OTHER_PLATFORM_ORIGIN`). Check such a lock with `raeva sync --frozen`
without `--platforms`. A plain `raeva sync --platforms` fetches and stops
the same way.

With `[plugins] trace`, the trace is made for the OS and architecture that
runs the sync. One trace serves all of its JDKs: the build runs on the
host's JDK, and a file only another JDK's build downloads is not traced. `--platforms` does not trace other
systems, and `raeva sync --frozen` refuses a lock with no trace for the OS
and architecture it runs on. Run an online `raeva sync` on each OS and
architecture that runs `--frozen`, and commit the result. `raeva doctor`
warns when the lock records only the platform it runs on, and, with
`[plugins] trace`, when an OS and architecture the lock records has no trace.
On Jenkins, run raeva outside a `withMaven` block, or unset
`JAVA_TOOL_OPTIONS` for it: `withMaven` adds `-D` options there that key
the trace, so `--frozen` inside the block refuses a lock traced elsewhere.

## Name the JDK

POM profiles can activate by JDK version, so raeva needs the JDK the build
uses. It takes the one `mvn` would run, from `JAVA_HOME` or else `PATH`. When
CI builds on several JDKs, list them in `raeva.toml` and run `raeva sync`;
`--frozen` then passes on each:

```toml
[lock]
jdks = ["17", "21"]
```

When `[lock] jdks` is set and the lock records this OS and architecture,
`raeva doctor` warns `HOST_JDK_NOT_LOCKED` if no listed JDK matches the one
it finds or its version is unknown. See
[The JDK version](configuration.md#the-jdk-version).

raeva reads the `-D`, `-P` and `-s` options of `MAVEN_ARGS` and
`.mvn/maven.config`, and the `-D` options of `MAVEN_OPTS` and the other
JVM option variables, as `mvn` does, after the mavenrc files ran. Pass
raeva the same `-s` as `mvn` on its command line. A `-gs` in
`MAVEN_ARGS` or `.mvn/maven.config` fails the sync (exit 3)
([Maven options](configuration.md#maven-options)).

A project or dependency profile can test `env.CI`, or another variable
the CI system sets, and change the lock, as liquibase's
`remote-repositories` profile adds a repository when `CI` is `true`.
raeva treats a variable that `[security] allow_env_substitution` does not
list as unset. Where the variable is set to a value that cannot turn the
profile on, or off, such as `CI=false` for `<value>true</value>`, raeva
goes on as if it were unset and writes or accepts the lock written
without it, byte for byte. A value that would turn it on or off, or any
value where the profile tests only that the variable is set, fails
`raeva sync`, `sync --frozen` and `export-m2` on CI (exit 3), also on a
lock written without the variable, until it is listed. List it in the
`config.toml` under `RAEVA_HOME` on every machine that syncs, so raeva
reads its value, and write the lock with the value CI sets, as `CI=true
raeva sync`; a lock written without it differs, and `--frozen` on CI
refuses it (exit 7).

## Java4Shell

CVE-2026-114938 (Java4Shell, disclosed 2026-11-17) is memory corruption in
HotSpot's Base64 decoder on x86-64 CPUs with AVX-512 VBMI, in OpenJDK
17.0.6 and later. A Java program that opens a TLS connection to a
malicious server can be compromised, and Maven fetching from a repository
is such a program. What raeva does about it:

- raeva downloads in Rust, not in a JVM, and checks each locked file
  against the checksum `raeva.lock` records.
- After `raeva export-m2`, `mvn -o` opens no repository connection. Tests
  and plugins in the build can still open connections of their own.
- raeva starts Java only through the build `[plugins] trace` names: an
  online `raeva sync` runs its launcher, and that build downloads from
  repositories. Where mavenrc files exist, `/bin/sh` sources them once,
  as the launcher would, then raeva reads back what they left, and the
  shell sources the launcher with `MAVEN_SKIP_RC` set as a shell variable,
  so the build runs with what raeva read. Only Maven's own `bin/mvn` and a
  Maven Wrapper script that sources the files itself can be started so.
  Another launcher, such as the Wrapper's only-script `mvnw` or Homebrew's
  `mvn`, which runs a `mvn` of its own, runs with `MAVEN_SKIP_RC=1`
  exported, which that `mvn` and the build's JVM then see; the trace fails
  with exit 3 where the files set a variable that `mvn` reads without
  exporting it, change a `MVNW_` variable or `MAVEN_USER_HOME`, or where
  `allow_env_substitution` names `MAVEN_SKIP_RC`. A launcher that names
  the files but not `MAVEN_SKIP_RC` fails it too (set `MAVEN_SKIP_RC=1`
  for both raeva and `mvn`). The trace fails with exit 3, before the build
  starts, where the files give a variable, or write a file raeva read (an
  option file, `.mvn/jvm.config`, `.mvn/maven.config` or a settings
  file), another value each time they run, such as a JVM option: the
  build must run with the values raeva resolved with and keyed the trace
  by. Export the value in the environment instead, or run both raeva and
  `mvn` with `MAVEN_SKIP_RC=1`. An exported variable named like a secret,
  such as a `CODEARTIFACT_AUTH_TOKEN` they fetch anew, is the exception: a
  POM cannot read it unless `allow_env_substitution` names it, and then it
  is not exempt. On Windows, where `mvn.cmd` sources `mavenrc_pre` again,
  it fails the trace too. What the files print while the trace sources
  them is dropped, as when raeva sources them. On Windows `mvn.cmd`
  sources `mavenrc_pre` again itself, so raeva runs it twice to compare;
  the trace also fails where raeva adds the option below and the files
  change or mention `JDK_JAVA_OPTIONS`.
  When the `release` file of the JDK `mvn` runs names version 11 or later,
  is not OpenJ9's, and no JVM option variable or `.mvn/jvm.config` holds
  `IgnoreUnrecognizedXXColonOptions`, raeva adds
  `-XX:-UseBASE64Intrinsics` to that build's `JDK_JAVA_OPTIONS` after the
  mavenrc files ran. The java launcher of JDK 9 and later reads it, also
  in each JVM the build forks, such as Surefire's, and prints `NOTE:
  Picked up JDK_JAVA_OPTIONS`; a JDK 8 does not read it. The JVM reads its
  command line and `_JAVA_OPTIONS` after it, so the sync fails with exit 3
  when `.mvn/jvm.config`, `MAVEN_OPTS`, `MAVEN_DEBUG_OPTS` or
  `_JAVA_OPTIONS` turn the intrinsic back on, or name an argument file
  that sets it. When the build fails and its output says the JVM does not
  know `UseBASE64Intrinsics` and could not be created, as a JDK 9 or 10
  says, raeva notes it and runs the build once more without the option.
- `raeva doctor` warns `HOST_JDK_JAVA4SHELL` when the CPU is x86-64 with
  avx512f, avx512bw, avx512vbmi and bmi2, and the JDK is 17.0.6 or later,
  not OpenJ9, with a `JAVA_VERSION_DATE` before 2026-11-17 in its `release`
  file.
  Without that date the row is `info`. It is `info` too when the options
  of the JVM `mvn` starts already turn the intrinsic off, with
  `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=` 0, 1 or 2. doctor reads
  `.mvn/jvm.config`, `MAVEN_OPTS`, `MAVEN_DEBUG_OPTS` and `_JAVA_OPTIONS`
  in that order, the order the JVM gets them, and the last option that
  sets a flag wins. It does not read an argument file they name with `@`
  or `-XX:VMOptionsFile=`, so the row can be `info` where such a file
  turns the intrinsic back on. Quotes can make an option part of a value in
  `_JAVA_OPTIONS`, and on Windows in any of them, so there an option that
  turns the intrinsic off counts only in text without quotes. The row then
  says that only the JVM `mvn` starts has
  it off: a JVM the build forks, such as Surefire's, does not read these
  options, except `_JAVA_OPTIONS`. doctor reads the variables as the
  mavenrc files leave them. The row
  says the JDK may be affected: a distribution can backport the update
  without changing `JAVA_VERSION_DATE`. A JDK dated later gets no row,
  which does not mean it is fixed. It does not detect Oracle's Java SE 8
  Performance Pack, which the advisory also lists.

For your own builds, update the JDK, or on JDK 11 and later add
`-XX:-UseBASE64Intrinsics` to `MAVEN_OPTS` or `.mvn/jvm.config`.

## Cache the store

Downloads go to the store under `RAEVA_HOME`. To cache it between jobs, set
`RAEVA_HOME` to a directory the CI system caches, and cache
`$RAEVA_HOME/store` and `$RAEVA_HOME/metadata.db`. Key the cache on the
raeva version, the OS and the architecture, then `raeva.lock`, and keep any
fallback restore within the same version, OS and architecture prefix: a
raeva refuses a database that a newer one upgraded. A job with a warm store
downloads no artifact the store already holds. `raeva sync --frozen
--offline` resolves from the store and `metadata.db` alone, and fails naming
the file when they lack a POM or a version listing the resolution reads. The
support POMs raeva.lock pins, a remote parent among them, and the POMs of its
plugin tables come from the store also when `metadata.db` lost them; the
POMs of the artifact rows and version listings do not.
Save the cache after an online `raeva sync --frozen`: with `[plugins] lock
= true`, a plain `raeva sync` that keeps `raeva.lock` does not download
what the plugin check of `raeva sync --frozen` reads, such as a plugin
group's `maven-metadata.xml`.

## Seed the store and the Maven repository

A cache restores whatever was saved under its key, and the key alone does not
show that the files are the ones the lock pins. `raeva seed` carries the
locked files between jobs and checks them when they come back:

```sh
raeva seed key                 # the cache key for this lock and configuration
raeva seed save "$SEED_DIR"    # after a passing raeva sync --frozen
raeva seed restore "$SEED_DIR" # in a later job, before raeva sync --frozen
```

`raeva seed save` copies every file `raeva.lock` pins, on every platform it
records, from the store into a new directory, with the repository that
served each one. It also copies the metadata cache rows a resolution reads:
POMs, version listings, and the files repositories answered they lack. It
checks the configuration and options of the dependencies as `raeva sync
--frozen` does, but not the `[plugins]` settings, which only `raeva sync
--frozen` checks, and takes each file from the repositories that check takes it from, so run it
with the `-P` and `-D` options of the frozen check. A repository only an
imported BOM declares serves the BOM's parents and imports alone, as in that
check. It
fails with exit 7 when the store lacks a pinned file; run `raeva sync
--frozen` first, with a `RAEVA_HOME` of the job's own, since the seed takes
every row of that home's cache. A row whose repository URL holds a
credential stays behind. A mirror whose URL holds one is saved as
`mirror:<id>/`, with each character of the id other than an ASCII letter,
digit, `.`, `_` or `-` written as `%XX`, when no other such mirror shares
its id. A file that came only through such a mirror without an id of its
own fails the save; give the mirror one in settings.xml. The restoring job's
configuration gives the URL of its mirror of that id, which must also hold
a secret; without one, the row stays behind. An endpoint that is neither the repository's URL
nor a configured mirror's, such as one an earlier token spelled, stays out.
A repository whose URL `raeva.lock` cannot record, such as one that does
not parse, which only a mirror serves, is named `unrecorded:` there, as in
the store and the metadata cache, never by its text.

`raeva seed restore` checks the configuration and options as `raeva sync
--frozen` does, and each file, and each cached POM the lock pins, against
its pin. It refuses with exit 7 a seed whose bytes differ, that
lacks a pinned file, whose rows do not match their digests, or that was saved for another lock or
configuration. A seed for another lock or configuration is refused before
the store takes anything. Otherwise, until all of it passes, the store
records no repository as serving a file, so no run uses a refused seed's
files without downloading them. The cache takes no row either, unless a
file's repository is one only a resolution of the seed's POMs trusts: the
rows go in for that resolution first, and stay if the seed is refused.
Such rows only steer later resolutions, as a cache of `metadata.db` would. The files that
matched their pins stay in the store, which keeps every file by its SHA-256:
they are the bytes the lock pins, and the download of such a file stores
nothing new. A restored home then answers `raeva sync --frozen` on the
unchanged lock, online or with `--offline`, and `raeva export-m2`, with no
request to a repository.

A version listing, or the POM of a version the resolution rejected, has no
pin. The restore takes it as the default-branch job that saved the seed
cached it, into the home's `metadata.db` unless the home holds that row
already. Every later run in that home reads it until it expires as it
would have there, or as its update policy allows from the restore if that
is sooner, and an offline run after that too. A row taken without its
checksum file, because a lock pin verified it, is the exception: a run in
which no pin covers it fetches it again online with its checksum file, and
offline refuses it until then. A `daily` row expires at the
first local midnight after the job fetched it, in the zone of the run that
reads it, as Maven decides `daily`. A verified release
POM's row does not expire. In `raeva sync --frozen`, such a row only
steers a resolution whose result must still equal `raeva.lock`, with each
range capped at the version the lock records, so a wrong row that changes
the result fails the check, and one that does not passes it. A later sync of a changed project in
that home takes the rows as they are, so restore seeds into a
`RAEVA_HOME` of the job's own. A cache of `metadata.db` carries the same
rows with no check at all.

The key covers the seed format, the raeva version, the OS and architecture,
the lock's `config_hash`, every pin in the lock, and the repositories, plugin repositories and mirrors that serve the
files, a mirror whose URL holds a secret by the name the seed gives it. Restore a seed by its exact key only, never by a prefix. A job that
seeds the Maven repository too:

1. Restore the cache entry named by `raeva seed key` into `$SEED_DIR`. On a
   hit, run `raeva seed restore "$SEED_DIR"`. If it exits 7, go on to step
   2: the online `--frozen` downloads what the seed lacked.
2. Run `raeva sync --frozen`.
3. Run `raeva export-m2 --m2-path "$DEPS"` and build with
   `-Dmaven.repo.local="$EMPTY" -Dmaven.repo.local.tail="$DEPS,$PLUGINS"`.
4. On a miss in a push to the default branch, run `raeva seed save
   "$SEED_DIR"` and save the cache entry under the key. Pull requests, forks
   among them, only restore.

Without `[plugins] lock = true`, the lock pins no Maven plugins or their
dependencies. It pins the build extension jars of a module only when the
module resolves a dependency type Maven's core does not define. Without `[plugins] trace`, it
pins nothing they download while they run. Keep them in their own cache, `$PLUGINS`
above, keyed on the build files and saved only from the default branch.
Nothing checks those files against a pin. With it, the seed carries the
plugin files, under the repositories the plugin tables read them from, and
the restore checks them and the plugin POMs' cached rows against their
pins.

On Apache Commons IO, through a proxy that logged every request to Maven
Central, a pull request job that restored the seed and the plugin cache sent
no request at all, from raeva or from Maven. The push that saved them
started from empty caches and sent 80 from raeva and 2,238 from Maven, none of
Maven's for a locked file.

A POM edit that keeps every pin keeps the key. `raeva sync --frozen` then
resolves the edited POMs from the restored rows and asks the repositories
only for what they lack; on Commons IO, a pull request that added a
property sent no request. Rows expire when they did in
the job that saved them, so an online check after a repository's update
policy has passed asks for version listings again. Maven reads
`maven-metadata.xml` from the repositories for version ranges and
SNAPSHOTs; to build such a graph from locked files only, see setup-raeva's
`examples/enforce.yml`.

## Merge the lock

Let git merge `raeva.lock` with its default driver. Edits to different
modules usually merge cleanly, and `raeva sync --frozen` checks the merged
lock. When the lock conflicts, run `raeva sync` on the merged POMs and add
the lock. The sync keeps the pins of both sides: a release file whose bytes
changed fails it (exit 7), and so do two sides that pin other bytes for one
file. Find out which bytes are right, keep that side's lock (`git checkout
--ours raeva.lock` or `--theirs`) and sync again, or run `raeva sync
--update` to lock the bytes the repositories serve now. If a side cannot be
read, the sync refuses until you resolve the conflict, take one side, run
`raeva sync --update`, or delete `raeva.lock`. Do not mark `raeva.lock`
`-merge` or `binary` in `.gitattributes`: git then leaves no conflict to merge.

## Review lock changes in pull requests

A `REPOSITORY_FALLBACK` or `AUTH_FALLBACK` warning does not fail
`--frozen`; read it before merging a lock that a resolving sync wrote.

`raeva sync --frozen` resolves the project again and fails if the result
differs from the lock: its modules, coordinates, scopes and edges, its
repositories and profiles, and its pins. An edit that resolves to the same
dependencies, such as a bump of the reactor's own version, passes. So a pull
request that edits only `raeva.lock` fails when it drops a dependency,
changes a version or a scope, or adds an edge. Every file it downloads must
match its pin. While the POMs and other inputs match the lock, the check
keeps the lock's choices: a version range, `LATEST` or `RELEASE` takes no
version newer than the locked one, and a SNAPSHOT keeps its locked build.
A range that Maven reads without choosing a version, one that loses to a
nearer declaration or one in the POM of a version that loses, takes none
newer than the versions the lock records for it in `evicted_ranges`.
It also fails, as does `raeva lock verify`, on a lock that reads the same
but is not the text raeva writes for it, such as one with a comment,
another order or other spacing, so the text a reviewer reads is what
raeva checked. CRLF line endings pass. `raeva sync` rewrites such a lock.

A lock edited alone can still choose another version inside a range, with
that version's pins, as an earlier `raeva sync --update` could have
written. Read a lock change that comes without a POM change:

```sh
git show origin/main:raeva.lock > base.lock
raeva lock diff base.lock raeva.lock
```

To collapse the lock in GitHub diffs, mark it as generated. GitHub then hides
its changes until you expand them:

```sh
printf 'raeva.lock linguist-generated=true\n' >> .gitattributes
```

## Relock dependency bot pull requests

A bot that updates a POM leaves `raeva.lock` as it was, so `raeva sync
--frozen` fails on its pull request until `raeva sync` runs on the branch and
the lock is committed. Group the Maven updates, so that one pull request
carries them and fewer locks conflict once one merges.

With `[plugins] trace`, an online `raeva sync` in a relock job runs the
project's Maven build when the lock has no trace of it for that OS and
architecture, which a POM change that changes the plugins causes. That
job then needs Maven and a JDK, and it runs the pull request's build code
with the job's credentials.

To review the relocked pull request, compare its lock with the base
branch's, as above. A parent or BOM bump comes first, as the parent or BOM
with both versions, then the packages whose versions its dependency
management supplied. Here a bump of `spring-boot-starter-parent` from 4.1.0
to 4.1.2 in spring-petclinic, shortened:

```text
  BOM org.springframework:spring-framework-bom 7.0.8 -> 7.0.10 (property spring-framework.version)
    spring-aop              7.0.8 -> 7.0.10
    spring-beans            7.0.8 -> 7.0.10
  parent org.springframework.boot:spring-boot-dependencies 4.1.0 -> 4.1.2 (direct)
    hibernate-core          7.4.1.Final -> 7.4.13.Final
    spring-boot             4.1.0 -> 4.1.2
  hibernate-models  1.1.1 -> 1.1.2
      via spring-boot-starter-data-jpa -> spring-boot-data-jpa -> spring-boot-hibernate -> hibernate-core
```

The line names the property when the BOM's import version is written as
one property, or for a parent from a repository that sets the property a
version is written as, such as `parent org.apache.maven:maven-parent 49 ->
50 (property version.maven-plugin-tools)`, and says `direct` for a parent's
own dependencyManagement,
`imported` for a BOM otherwise, and `ambiguous` when the two locks name two
bumped sources for a package. The parent named is the one whose
dependencyManagement holds the versions, here the parent of
`spring-boot-starter-parent`. A parent or BOM that is a module of the
project is named the same way, and as `changed` with its version when that
stayed, such as `BOM org.example:platform-bom 1.4.0-SNAPSHOT changed
(imported)`. A package listed after the causes moved for another reason,
such as a new version of a package that depends on it.
[JSON output](json-output.md) has the rules and the `causes` field.

**Dependabot** runs no commands. On GitHub, setup-raeva's
`examples/relock.yml` runs `raeva sync` on Dependabot pull requests and
pushes the lock as a second commit with `[dependabot skip]` in its message,
so Dependabot keeps rebasing its branch and the workflow writes the lock
again after each rebase. Its README lists the tokens it can push with. Group
the updates in `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: maven
    directory: /
    schedule:
      interval: weekly
    groups:
      maven:
        patterns: ["*"]
```

**Self-hosted Renovate** runs `raeva sync` itself after it rewrites the POMs,
and commits the lock with them. Install raeva on the Renovate host, on its
`PATH`, and allow the command in the global (admin) configuration:

```json
{
  "allowedCommands": ["^raeva sync$"]
}
```

In the repository's `renovate.json`:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "packageRules": [{ "matchManagers": ["maven"], "groupName": "maven" }],
  "postUpgradeTasks": {
    "commands": ["raeva sync"],
    "fileFilters": ["raeva.lock"],
    "executionMode": "branch"
  }
}
```

Renovate gives the command only `HOME`, `PATH`, `LANG`, `LC_ALL` and `CI`. raeva
then evaluates POM profiles for the `java` on `PATH`, which may not be the JDK
CI builds with, so a project whose profiles activate by JDK lists its JDKs in
`[lock] jdks`. `RAEVA_HOME`
defaults to a directory under that `HOME`; unless it persists between runs,
each run downloads the locked files again. A variable that `settings.xml`
reads as `${env.NAME}`, such as a private registry's token, reaches the
command only through Renovate's `env` option, which the admin
configuration's `allowedEnv` must admit; otherwise put a `settings.xml`
that works without it under that `HOME`.

**Hosted Renovate** (the Mend app) runs no commands of yours. Use the relock
workflow, accept `renovate[bot]` in its relock job's `if:`, and list the lock
commit's author in `renovate.json`, so Renovate keeps rebasing a branch that
carries it:

```json
{
  "gitIgnoredAuthors": ["41898282+github-actions[bot]@users.noreply.github.com"]
}
```

These configurations pass `renovate-config-validator --strict` of Renovate
44.203.0.
