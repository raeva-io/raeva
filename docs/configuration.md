# Configuration

Raeva reads dependencies only from `pom.xml`. Settings live in two optional
TOML files with the same format: the project `raeva.toml` next to the root
`pom.xml`, and the user `config.toml`. Neither file can declare dependencies.
Raeva also reads `~/.m2/settings.xml`, or the file `-s` names, for mirrors,
proxies, servers, profiles (their repositories, plugin repositories and
properties), `<activeProfiles>`, `<pluginGroups>`, and `<localRepository>`.

raeva finds the user settings the way Maven does, from `user.home`: the
last `-Duser.home` that Maven's JVM takes. Maven sets those of the command
line and `.mvn/maven.config` after the JVM starts, so they win. The JVM
itself takes `_JAVA_OPTIONS` over its command line, where `mvn` puts
`MAVEN_DEBUG_OPTS` over `MAVEN_OPTS` over `.mvn/jvm.config`, and those
over `JDK_JAVA_OPTIONS` (JDK 9 and later) over `JAVA_TOOL_OPTIONS`.
Without any, `user.home` is the home of the user's passwd entry on Linux
and macOS, or the profile folder on Windows; `HOME` does not count. On
macOS a non-empty `CFFIXED_USER_HOME` replaces the passwd home, as
`NSHomeDirectory()` takes it, with `.`, `..` and extra slashes removed;
a relative one, which depends on where `mvn` runs, or one with a `..` on
a path through a symbolic link, which macOS then resolves, fails the sync
(exit 3). Only where the home is missing or `/`, as for
`docker run -u <uid>`, a JDK 18 or later takes `HOME`, and JDK 17 and
earlier do not, so raeva follows the `release` file of the JDK `mvn` runs
and fails (exit 3) when it cannot tell which that is. With no home at all
the JVM's is `?`, below the working directory, and `raeva export-m2`
needs `--m2-path` (exit 3).

`~/.m2`, `${user.home}` and `~` in `settings.security` all take it.
raeva reads `.mvn/jvm.config` as `mvn` passes it: split at spaces, tabs
and line breaks only, so a no-break space stays in a value, and in the
Maven 3.10 mode with `$MAVEN_PROJECTBASEDIR` written in as its `sed` does,
an `&` in the project directory standing for the placeholder. Maven 3.9's
`mvn` writes nothing in, so `${MAVEN_PROJECTBASEDIR}` there is part of
the directory's name. raeva has `/bin/sh` source the mavenrc files
`mvn` sources (on Windows `cmd` calls `mavenrc_pre.bat` and `.cmd`, as
`mvn.cmd` does), in the project directory, where `mvn` runs, with this
environment, and takes the variables as they leave them.

The sync fails (exit 3), naming where, when raeva cannot read what Maven
takes exactly:

- a `-Duser.home` that takes `${...}`, which Maven expands where a POM or
  settings.xml takes `${user.home}`; Maven 3.9's
  `${MAVEN_PROJECTBASEDIR}` in `.mvn/jvm.config` names no property, and
  fails only where the settings.xml at that literal directory takes
  `${user.home}`;
- mavenrc files that do not finish within 120 seconds (raeva says so
  after 10), or stop the shell
  before `mvn` would start Maven, as `exit` does, or leave it in another
  directory, from which `mvn` would find the project and the JVM read a
  relative option file; also, outside Windows, ones that change `IFS`, at
  which `mvn` splits its variables, and ones that change `HOME`,
  `CFFIXED_USER_HOME` or the locale variables where the JVM would take
  Maven's user home or its encoding from them; on Windows, also
  where both the temporary directory's and raeva's cache's paths hold `%`
  or `!`, which `cmd` would expand in the path of the script that sources
  them;
- a `-gs` in `MAVEN_ARGS`, whose file Maven reads over the command line's,
  even with `-Duser.home` on the command line
  ([Environment variables](#environment-variables)); a `-s` or
  `-Duser.home` there, as the mavenrc files leave it, counts as one on the
  command line;
- a `-Duser.home` value that is not UTF-8, while bytes that are not UTF-8
  elsewhere in a variable are passed as they are;
- on Linux and macOS, a non-ASCII `user.home` or settings path unless the
  locale (`LC_ALL`, `LC_CTYPE`, `LANG`) is a UTF-8 one that is installed:
  the JVM decodes it in its native encoding, so under the C locale of most
  containers Maven reads `h??` for `hé`; raeva's musl builds ask
  `locale charmap`, and fail without one;
- a backslash in `.mvn/jvm.config` that the `echo` of `/bin/sh` expands,
  as macOS's and dash do, and in the Maven 3.10 mode a project directory
  with `\`, `|` or a line break where the file takes
  `$MAVEN_PROJECTBASEDIR`;
- on Windows, a `.mvn/jvm.config` with a `!`, a `^` or non-ASCII text,
  which `mvn.cmd` drops or reads in the console's code page, a quoted
  value beside `user.home`, or a project directory with a `!`; a `"` or
  `^` in `MAVEN_OPTS` beside `user.home`;
- an option file that cannot be read or is not a regular file, a VM
  options file that names another, a quote the JVM finds open, a
  `MAVEN_OPTS` pattern the shell may expand, or a JVM variable for an
  OpenJ9 JDK; any of these, `JDK_JAVA_OPTIONS` for a JDK raeva cannot
  tell, or a Windows `MAVEN_OPTS` with a `"` or `^`, that names an option
  file, whose options raeva then cannot read, fails whatever reads it.

Pass `-Duser.home` on the command line of both raeva and `mvn` instead,
which wins over the channels. For a mavenrc file, fix what it runs, or
run both with `MAVEN_SKIP_RC=1`. In a CI container
whose `HOME` differs from the passwd entry, set
`MAVEN_OPTS=-Duser.home=...` or pass `-s`. A `user.home` raeva cannot
look into holds no `settings.xml`, as for Maven. raeva's own directories
(`RAEVA_HOME`, the config and cache below) do not follow `user.home`. A
`-Dsettings.security` in `.mvn/jvm.config` or `MAVEN_OPTS` is not read;
it only decides how passwords decrypt.

## File locations

| Path | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Config directory (`config.toml`) | `~/.config/raeva` | `~/Library/Application Support/raeva` | `%APPDATA%\raeva` |
| Artifact store | `~/.local/share/raeva/store` | `~/Library/Application Support/raeva/store` | `%LOCALAPPDATA%\raeva\store` |
| Metadata cache (`metadata.db`) | `~/.local/share/raeva` | `~/Library/Application Support/raeva` | `%LOCALAPPDATA%\raeva` |
| Cache directory | `~/.cache/raeva` | `~/Library/Caches/raeva` | `%LOCALAPPDATA%\raeva` |

On Linux, `XDG_*` variables move these directories. With `RAEVA_HOME`
set, config and `metadata.db` are in `$RAEVA_HOME`, the store is
`$RAEVA_HOME/store`, and the cache is `$RAEVA_HOME/cache`. `RAEVA_HOME`
must be absolute (exit 3). An empty value is ignored, with a warning.

Concurrent `raeva sync` runs on one checkout take turns through a guard
file in the cache directory. Runs with different cache directories, from
another `RAEVA_HOME` or `XDG_CACHE_HOME`, do not wait for each other and
can overwrite each other's `raeva.lock`, so give concurrent syncs of one
checkout the same cache directory.

`metadata.db` only speeds up fetches, with one exception: without it, the
next sync fetches a non-unique `-SNAPSHOT` replaced in place again, POM
and jar together. Delete it, with its `-wal` and `-shm` files, while no
`raeva` is running.
A raeva older than the one that last changed the schema of `metadata.db`,
or of the store index, refuses to open that file rather than replace it.
Run the newer raeva. For `metadata.db` alone, deleting it as above also
works; the store index is not a cache, so do not delete it.

`metadata.db` also records the POMs and `maven-metadata.xml` files a repository
answered 404, 401 or 403 for, with an HMAC-SHA256 digest of the credential
sent, and a later sync does not ask
for them again until the repository's update policy expires, as Maven does
not ask again for a POM it holds. A sync that sends another credential asks
again, and so does one whose `raeva.lock` records that repository as
serving the file. The digest key is in `cache-key`, an owner-only file
beside `metadata.db`. Keep it out of shared caches: with it, the digests
in `metadata.db` let a guessed credential be checked. Without it, raeva
makes a new key and the recorded misses no longer match.
An online `raeva sync --update` fetches again what the project needs. A
row dated after the current time, as a clock that ran ahead or a cache
copied from one leaves it, counts as expired.

## `raeva.toml` and `config.toml`

Every section is optional. `local_repository` is the Maven local repository
`raeva export-m2` writes. `url` is required in `[[repositories]]` and
`[[mirrors]]`. `host` and `port` are required in `[[proxies]]`. An unknown
key is a configuration error (exit 3). Mirrors and proxies belong to the
machine, as in Maven: a project `raeva.toml` with `[[mirrors]]` or
`[[proxies]]` fails to load (exit 3), so a cloned project cannot take the
requests or the credential of your mirror.

```toml
local_repository = "${user.home}/maven-repo"
active_profiles = ["ci"]
inactive_profiles = ["slow-tests"]

[[repositories]]
id = "corp"
url = "https://repo.example/maven2/"
releases = true
snapshots = false
releases-update-policy = "daily" # always, daily, never, or interval:N (minutes)
snapshots-update-policy = "always"
releases-checksum-policy = "fail"

[[mirrors]] # config.toml only
id = "corp-mirror"
url = "https://mirror.example/maven2/"
mirror_of = ["central"]

[[auth]]
id = "corp"
username = "ci"
password = "..." # or token = "..." for bearer

[[proxies]] # config.toml only
host = "proxy.example"
port = 3128
protocol = "https" # http (default), https, or all
non_proxy_hosts = ["localhost", "*.corp.example"]

[network] # ranges and defaults: see Environment variables
timeout = 30
retries = 3
concurrency = 8 # files at once per stage, prefetched POMs and range lookups 4 times that each; 0 counts as 1, at most 128
low_speed_limit = 1024
low_speed_time = 30

[lock]
jdks = ["17", "21"]
maven = "3.9" # raeva.toml only: the Maven line to resolve as, "3.9" or "3.10"

[security]
allow_env_substitution = ["BUILD_NUMBER"]
transitive_repository_allowlist = ["https://repo.example/"]
allow_transitive_repositories = false

[plugins] # raeva.toml only
lock = true
goals = ["spotless:check"]
trace = ["verify"]
mvn = "./mvnw"
```

Search order is the project `raeva.toml`, then the user `config.toml`, then
`settings.xml`, then repositories the project's POMs declare, child before
parent. When an earlier file defines a repository `id`, a later file only
fills fields it left unset. Of two mirrors with one `id`, only the first
is used, as Maven's request keeps only the first; a `settings.xml` mirror
without an `<id>` has the id `default`, and a `config.toml` one has none.
A mirror whose `mirror_of` is exactly the
repository id wins, then the first entry whose patterns match. Patterns
match as Maven 3.9 matches `<mirrorOf>`: the `mirror_of` entries join with
`,`, the first `id` or `!id` naming the repository decides, otherwise `*`,
`external:*` or `external:http:*` matches, and entries are not trimmed.
Repository schemes and hosts are classified with the same URL parser used
for requests; an unparseable URL is treated as external. A
settings.xml mirror serves only the `<mirrorOfLayouts>` it lists
(`default,legacy` when unset), and Raeva reads the `default` layout. A mirror
with `blocked` set to true (settings.xml `<blocked>true</blocked>`) gets no
requests, nor do the repositories it matches. For `active_profiles`, `jdks`
in `[lock]`, and each `[network]` key (`timeout`, `retries`, `concurrency`,
`low_speed_limit`, `low_speed_time`), the first file that sets it wins.
`active_profiles` adds to `settings.xml` `<activeProfiles>`, as `-P` does.
`inactive_profiles` is the union of both files (user ids first, then project
ids not already listed); an empty list adds nothing. Only the
`raeva.toml` at the reactor root applies.

### Maven line

`maven` in `[lock]` names the Maven line `raeva` resolves as: `"3.9"` or
`"3.10"`. Only the project `raeva.toml` may set it; in `config.toml` it is a
configuration error (exit 3). Without it, the version that
`.mvn/wrapper/maven-wrapper.properties` downloads decides: `distributionUrl`
naming `apache-maven-3.10.x` selects 3.10, Maven 3.0 to 3.9 and mvnd 1.x
select 3.9. A wrapper that names another Maven, such as 4.0, an mvnd 2
distribution or a file `raeva` does not recognize, fails the commands that
read the project's configuration, such as `raeva sync`, `doctor`,
`export-m2` and `lock verify --download`, with exit 3 until `[lock] maven`
chooses a line. Commands that only read `raeva.lock`, such as `tree`, `why`
and `lock info`, ignore the wrapper. With neither, the line is 3.9.

`raeva.lock` records the line as the top-level `maven = "3.10"`, left out
for 3.9. A sync under another line resolves again, and `raeva sync --frozen`
refuses the lock, naming the line it was resolved as and the setting that
selects the other ([Verification](verification.md) lists how Maven 3.10
resolves differently).

The 3.10 mode also reads what Maven 3.10 adds:

- `maven.repo.central` names the URL of Maven Central. The first source
  that sets it wins, in Maven 3.10's order: a `-D` on the command line or
  in `.mvn/maven.config`, a property of an active `settings.xml` profile, a
  POM property, the `MAVEN_REPO_CENTRAL` environment variable, then a `-D`
  in `.mvn/jvm.config` or a JVM option variable. From a `-D`, the environment or `jvm.config`, a
  value with credentials, a query or a fragment, surrounding whitespace, or
  a scheme other than `http`, `https` or `file` fails with exit 3, or exit 2
  from a `-D` on the command line; the message names the source and never
  the URL. Plain `http` to a host other than `localhost` or `127.0.0.1` gets
  no request unless a mirror serves Central, as with Maven's default HTTP
  blocker (`HTTP_REPO_BLOCKED`); the other repositories are still searched.
  From a POM or a settings profile, it is checked as a repository that POM
  declares, and one that a POM fetched from a repository sets is trusted
  only as that POM's own repositories are. A repository `central` in
  `settings.xml`, `config.toml` or `raeva.toml` wins over it, and a Central
  URL from `.mvn/` gets no `[[auth]]` entry without an id
  ([Authentication](authentication.md)). `raeva doctor` names a Central
  URL from a `-D`, `MAVEN_REPO_CENTRAL` or `.mvn/jvm.config`, credentials
  hidden, and where it came from. It does not report one that a POM or a
  `settings.xml` profile sets. Raeva takes
  a `-D` in `MAVEN_OPTS` or another JVM option variable as one in
  `.mvn/jvm.config`, and a `-D` in `MAVEN_ARGS` as one on its
  command line ([Environment variables](#environment-variables)).
- Session properties with which Maven 3.10 resolves otherwise and that
  raeva does not apply are refused as a `-D` on the command line (exit 2),
  in `.mvn/maven.config`, in `.mvn/jvm.config` or in a `settings.xml`
  profile whose properties Maven's session takes, one `<activeProfiles>` or
  `-P` names or that is active by default (exit 3), so the lock
  never holds other artifacts than the build uses: `maven.relocations.entries`
  and `maven.session.versionFilter`, and, unless they keep Maven's default,
  `maven.resolver.dependencyManagerTransitivity` (`false`),
  `aether.conflictResolver.versionSelector.selectionStrategy` (`nearest`),
  `aether.system.repositoryKeyFunction` (`nid_hurl`) and
  `aether.system.dependencyVisitor` (`levelOrder`).
- `${project.rootDirectory}` (also `${pom.rootDirectory}` and
  `${rootDirectory}`) is, in a reactor module's POM and in its file
  activation, the nearest directory from the module up that holds `.mvn`,
  else the reactor root. Maven searches above the reactor root; raeva stops
  there, so a value never names a directory outside the project.
- Version and snapshot metadata that Maven 3.10 refuses is read as empty,
  with a `POM_PROBLEM` warning ([Warning codes](json-output.md#warning-codes)).
- A project whose effective model has a repository, plugin repository or
  `<distributionManagement>` repository with the id `local`, or with one
  of `\/:"<>|?*` in its id, fails with exit 3 in Maven's words, as Maven
  3.10 refuses it. The 3.9 mode warns in the same words (`POM_PROBLEM`) and
  locks, as Maven 3.9 builds it. `local` names the local repository's own
  `maven-metadata-local.xml`. Maven only warns of such an id in
  `settings.xml`, and raeva does not refuse it there.

In either line, `maven.versionRangeResolutionNature` is refused the same
way unless it is `release_or_snapshot`, Maven's default, and
`aether.dependencyCollector.impl` is read from `-D`, `.mvn/maven.config`
and `.mvn/jvm.config`; a `settings.xml` profile that sets another collector
than the line's default, and that none of those override, is refused.

In either line, a dependency keeps a scope Maven's resolver does not know,
such as `compile-only`, `RUNTIME`, `optional`, `foo:bar`, or `import` outside
`<dependencyManagement>`, in `raeva.lock`, as Maven 3.9 and 3.10 keep it:
its own dependencies resolve as `runtime`, `provided` and `test` ones below
it are left out, and a known scope wins over it in conflicts. A package
reached only in two or more such scopes gets no scope, as Maven gives it,
and its own dependencies keep theirs. Maven 3 puts all of these packages on
every classpath, so `raeva tree --scope compile`, `runtime` and `test` list
them. A project dependency's or managed dependency's scope Maven's
validator does not know gets Maven's warning, such as
`'dependencies.dependency.scope' for g:a:jar must be one of [...] but is
'...'.`, as `POM_PROBLEM`. A scope `raeva.lock` cannot record, one with
whitespace, a control or invisible character, or over 255 characters, is
refused with exit 3 (`INVALID_POM`) naming the dependency, where Maven
would follow it. So is a dependency, plugin or build extension, in the
project or a dependency's POM, or the project or its parent, whose group,
artifact, version, type, classifier, scope or exclusion takes a `-D` value (on the command line, in `.mvn/maven.config` or
`.mvn/jvm.config`), an active `settings.xml` profile property or an
allowlisted environment variable named like a secret, through any other
property: raeva.lock, the store and a repository request would hold its
value. The error names the input, not its value.

In either line, raeva reads the project's POMs, those of the reactor and
the file at each `<relativePath>` of their parents that raeva reads (see
[Verification](verification.md)), as Maven's strict model reader does: an element the model does not have at that place, such as
`<profiles>` inside `<profiles>`, an attribute it does not take, text
between elements, or a root element other than `<project>` fails the sync
with exit 3, as Maven fails the build with `Malformed POM`. Maven reads the
file at a `<relativePath>` before it compares the coordinates, so one that
declares another project fails too. A POM from a repository, a parent or
imported BOM included, is read leniently, which skips such an element, as
Maven does.

### Maven options

Every command takes the `mvn` options that change resolution, so a CI job
that runs `mvn -s ci-settings.xml -Pci -Dfoo=bar` can run
`raeva -s ci-settings.xml -Pci -Dfoo=bar sync`:

- `-s FILE` (`--settings`) reads `FILE` in place of `~/.m2/settings.xml`. A
  relative path is taken from the working directory, as `mvn` takes it.
  Given twice, the first counts.
- `-P IDS` (`--activate-profiles`) activates the comma-separated profile
  ids, of the POMs or `settings.xml`, and deactivates an id written `!id` or
  `-id` (`-P-id`, since `mvn -P -id` is an error). Repeatable.
- `-D NAME=VALUE` (`--define`) sets a user property; `-D NAME` sets it to
  `true`. Repeatable, and a later value wins.

They can go before or after the command name, and count in the order given.
A value with quotes that `mvn` reads one way in `-D"..."` and another in
`-D "..."` is refused (exit 2).
They merge with `.mvn/maven.config` as Maven 3.9 merges them: `-P` values
from the command line come first and `-D` values last, so a command-line
`-D` wins. A
deactivated id stays off whatever else activates it, `activeByDefault` and
`<activeProfiles>` included, and in any order. `${...}` in a `-s` value
expands with the command line's `-D` values. In `-s`, `-P` and `-D` values,
`${session.rootDirectory}`, `${session.topDirectory}` and
`${maven.multiModuleProjectDirectory}` are the project directory; a `-D`
value built from one that a POM reads ties `raeva.lock` to that path, so
`--frozen` in a checkout at another path reports a changed configuration.
A `-s` that names no file fails (exit 3) with Maven's message,
`The specified user settings file does not exist`; Maven exits 1. A `-s`
in `.mvn/maven.config` picks the settings file as it does for Maven: the
first `-s` of `MAVEN_ARGS` or the command line wins over it, the `-D`
values of both expand it, and a relative path is taken from the directory
raeva runs in, as `mvn` takes it from its own. That file brings its
mirrors, proxies and credentials, so review a cloned project's before a
sync. Since the project chose it, an `[[auth]]` entry without an id
does not go to the repositories and mirrors it names, and `export-m2`
does not write to its `<localRepository>`. Raeva reads no global settings file, so `-gs`
there fails the load (exit 3). It ignores the reactor selection there,
`-pl`, `-am`, `-amd`, `-rf` and `-N`, with a `SETTING_IGNORED` warning,
and locks the whole reactor, so a module the build skips can still fail
the sync. With `[plugins] trace` set, a `raeva sync` that is neither
`--frozen` nor offline fails with one (exit 3), even when raeva.lock is up
to date and no trace build runs, as that build would not build the whole
reactor. On the command
line they are a usage error (exit 2). `-f` (`--file`) in `.mvn/maven.config`, with
which `mvn` builds another POM, fails the load (exit 3). `-itr`
(`--ignore-transitive-repositories`) there makes raeva read no repository
a dependency's POM declares, as Maven 3.9 and 3.10 do: not
for its dependencies, whatever `[security]` admits, and not for that POM's
own parent and imports either, which Maven reads from such a repository
without the flag. In `MAVEN_ARGS`, a host's own, it still fails the load.
Maven 3.10's `-UA`, `-UM`, `--artifacts-update-policy` and
`--metadata-update-policy` are read and ignored, as `-U` is, also where
raeva follows Maven 3.9, which refuses them. `-o` (`--offline`)
there runs every command as `--offline` does. Everything this
page says about `-D` and `-P` in
`.mvn/maven.config` holds for the command-line options too.

raeva also reads `-Dname=value` options from `.mvn/jvm.config` and the JVM
option variables as JVM system properties, below the user properties from
`.mvn/maven.config` and the command line. The last of a name wins in the
order the JVM reads them: `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS` (JDK 9
and later), `.mvn/jvm.config`, `MAVEN_OPTS`, `MAVEN_DEBUG_OPTS`, then
`_JAVA_OPTIONS`, each as `mvn` leaves it after the mavenrc files, with the
`@` argument files and `-XX:VMOptionsFile` they name read in place, a
relative one from the directory raeva runs in, as `mvn` reads it from its
own. `[plugins] trace` runs `mvn` in the project directory, so there such a
relative file, or a relative `-Duser.home`, fails the sync (exit 3) when
raeva runs in another directory. `.mvn/jvm.config` is split at whitespace
across all lines, `MAVEN_OPTS` and `MAVEN_DEBUG_OPTS` as the shell splits
them, the JVM variables and VM options files at whitespace with quotes
removed, and argument files as the java launcher reads them, with quotes,
escapes in quotes and `#` comments; other JVM options are ignored. A value
raeva cannot read exactly, such as a `MAVEN_OPTS` pattern the shell may
expand, one beside a `^` on Windows, or any of an OpenJ9 JDK's variables,
leaves its name unread: a profile, POM or settings.xml that reads it fails
the sync (exit 3), unless a later option sets it plainly.
raeva.lock records a value only where a read takes it, so `--frozen`
fails when it changes and not for a `-D` nothing reads. `-Dname` sets an empty value, as the JVM does.
A POM takes `.mvn/jvm.config`'s `-Duser.home` only where no later channel
sets another; one from the environment is the host's, as the passwd home
is, which a profile or value of a POM cannot read (exit 3).
A name the JVM sets itself, such as `java.version`, `java.vendor`,
`java.vm.version` or `java.class.path`, keeps the JVM's value, as on JDK
17 and newer except as below, and so do those `mvn` passes after the file (`maven.home`,
`classworlds.conf`, `maven.multiModuleProjectDirectory`, and
`library.jansi.path` in 3.9 or `library.jline.path` and
`org.jline.terminal.exec.redirectPipeCreationMode` in 3.10) and
`maven.version` and `maven.build.version`, which Maven sets over any. A
command-line or `.mvn/maven.config` `-D` of one still wins. Of the names
some JVM sets, some JDKs keep their own value over the file's, as Temurin
does for `java.vendor.version` and JDK 17 for
`java.specification.maintenance.version`, so raeva answers none from
`.mvn/jvm.config`: a profile that reads one fails the sync (exit 3). JDK 8
and 11 take the file's `java.specification.version`,
`java.specification.vendor`, `java.specification.name` and
`java.class.version`, and JDK 8 its `java.vendor`, `java.vendor.url`,
`java.vendor.url.bug` and `sun.jnu.encoding`, where JDK 17 and newer, and
11 for the second group, keep their own. A `.mvn/jvm.config` `-D` of one of
the `java.specification` names, or an empty `-D` of another of these,
fails the sync (exit 3) unless every `[lock] jdks` entry is a JDK that
keeps its own value. The same `-D` from `MAVEN_OPTS` or another JVM
option variable leaves the name unread, which fails only what reads it. raeva
knows which names JVMs set from Maven 3.9.12 and 3.10.0 runs on Temurin
8 and 11 and OpenJDK 17, 21 and 27 on Linux, Temurin 21 on macOS and
Temurin 17 on Windows; any other name is the file's.
A `-D` or `-P` value expands `${...}` against these system properties as
`MavenCli` does: those raeva answers (listed below for activation, with
`java.home`) take their value on each locked platform and JDK, and
raeva.lock records the result. A `-D` value that takes one raeva does not
read, such as `${java.vendor}` or `${user.name}`, fails the sync (exit 3)
once a profile compares it with a `<value>`, and a `-P` value that takes
one always does. The same holds for `${env.NAME}` of a variable set here
but outside `allow_env_substitution`.
These properties can activate profiles and fill `${name}` expressions.
For model interpolation, settings.xml profile properties and a POM's own
properties take precedence over JVM system properties. Changes to
consulted properties make `sync --frozen` fail with exit 7, but not a JVM
option's value of a name the POM, an active settings profile or an
`activeByDefault` profile defines, which the model's own value hides. A
`-D` on the command line or in `.mvn/maven.config` ranks above the model's
value, so a change there still fails.

`raeva` searches Maven Central (`central`) last, as Maven's super POM does.
Repositories in `raeva.toml`, `config.toml`, `settings.xml` or the project
POMs add to it. A file an earlier repository serves is not requested from
Central. A version range still reads every repository's metadata, as in
Maven. A repository with id `central`, in any of these, replaces the
default, and a mirror that covers `central` serves its requests. For a
POM's `central`, Maven compares the ids that mirrors give the two: when a
mirror, the HTTP blocker included, serves only one of them, the default
Central stays beside it. The
repositories of the active `settings.xml` profiles come before the POMs':
the last active profile's first, its entry winning a shared id, as Maven
injects the profiles. Their `<pluginRepositories>` serve plugins in the
same order, and those of the profiles `<activeProfiles>` names serve core
extensions. Such a profile that `-P !id` or `inactive_profiles` turns off
keeps its `<repositories>` after Central, each unless an earlier
repository has its id, as Maven's request keeps them. A profile repository or plugin repository without an `<id>`
fails the load (exit 3), as Maven fails on one in any profile. A mirror or
server without an `<id>` is `default`, as Maven's settings model names it,
so the `<server>` with id `default` gives such a mirror its credentials; an
empty `<id>` on either fails the load. A profile without an `<id>` is
`default` too.

`settings.xml` is interpolated as Maven interpolates it: `${name}` takes a
command-line `-D` value, else a system property, and `${env.NAME}` the
environment variable, and `${.name}` reads as `${name}`. The system
properties are `user.home` and those of the JVM and `mvn` that raeva
answers: `os.name`, `os.arch`, the separators, `java.version`,
`java.specification.version`, `java.home`, `maven.version`,
`maven.build.version`, and in the 3.10 mode
`org.jline.terminal.exec.redirectPipeCreationMode`. A profile's properties
and activation take them on each locked platform and JDK, and raeva.lock
records them, so another JDK makes `--frozen` exit 7. One raeva does not
read from the host, such as `${java.vendor}` or `${user.name}`, fails the
sync (exit 3) once a profile compares it, as do a profile id, an
`<activeProfile>` or a profile repository that takes one, or one that
differs by platform or JDK, and a mirror that takes one raeva does not
read. Any other expression stays as written. As in Maven, a `-D` of
`.mvn/maven.config` or the command line expands there, the command line's
first, and then a `.mvn/jvm.config` `-D` of a name no JVM sets; so the
project's files can choose mirrors, proxies and the local repository in
settings text that takes one. Settings text that takes a `.mvn/jvm.config`
value of a name the JVM sets, which some JDKs keep their own value of,
fails the load (exit 3). The master password file comes from a
command-line `-Dsettings.security` only.
`<offline>true</offline>` runs every command as `--offline` does.

`<releases>` and `<snapshots>` in `settings.xml` are read as Maven reads
them: a missing or empty `<enabled>` enables, otherwise only `true` (any
case) does. Maven 3.9 reads `<enabled>`, `<blocked>`, `<offline>`, a
proxy's `<active>` and `<port>` before it interpolates the file, so `${...}`
there is not expanded; the 3.10 mode expands it first. In a POM, `<enabled>` is read
after interpolation and an empty one disables.

A `settings.xml` profile is active when `<activeProfiles>`, `active_profiles`
or `-P` names it, or when its `<activation>` holds, unless
`inactive_profiles` or `-P !id` turns it off, as in Maven. Its activation
sees `-D` and every environment variable
as `env.NAME`, and a `<file>` path expands as in a POM, relative to the
project root. Active `settings.xml` profiles contribute their `<properties>`
in file order to the project's models and their parent chains (below `-D`
and above POM properties), for both interpolation and
profile activation; dependency and imported BOM POMs do not see them.

### Repositories and mirrors

A `[[repositories]]` entry has `url` and optionally `id`, `releases`,
`snapshots`, `releases-update-policy`, `snapshots-update-policy`,
`releases-checksum-policy`, and `snapshots-checksum-policy`. Both update
policies default to `daily`, as in Maven, and so does an `<updatePolicy>`
a POM or `settings.xml` `<repository>` leaves out.

- A `raeva.toml` or `config.toml` repository or mirror URL must be an
  `http`, `https` or `file` URL (exit 3). A `settings.xml` repository of a
  profile active on the host or on a locked platform, or a mirror, whose
  URL does not parse or has another scheme, such as `ftp`, is kept with a
  `SETTING_IGNORED` warning, as Maven warns and skips it: it still hides a
  repository with its id, and requests to it fail without being sent, so
  the search goes on, unless a mirror serves it. Maven 3.9 fails the build
  once a request reaches some of them, a URL whose port its Wagon
  transport cannot read as a number, such as `https://[::1` or
  `https://host:x/`; `raeva` skips those too, in both Maven modes, so the
  lock and an `export-m2` of it build with `mvn -o`. A POM repository with
  a URL `raeva` does not read is skipped the same way, with a
  `REPOSITORY_IGNORED` warning.
- An `http` or `https` repository or mirror URL with a `\` in it fails the
  sync (exit 3), from the project's POMs, `settings.xml` (any profile),
  `raeva.toml` or `config.toml`: Maven's HTTP transport refuses it, each
  request or, after the port, in Maven 3.9 the build, where raeva's URL
  parser would read `/`. Outside Windows a `file:` or other URL with a `\`
  fails the same way, as Maven reads the `\` as part of a file name. A dependency's POM's is ignored with a
  `REPO_URL_BACKSLASH` warning, as its requests fail in Maven.
- Some URLs that are no absolute `file:` URL name a directory, in a
  `settings.xml` or a POM repository alike. A relative `file:` URL, such as
  `file:repo`, reads as that directory under the project, where `mvn`
  runs. In the Maven 3.10 mode a `symlink+file:` or `hardlink+file:` URL
  reads as the `file:` URL after the prefix, a URL without a scheme as a
  path, and one whose scheme is a single uppercase letter, such as
  `C:/srv/repo` or `C:repo`, as the path after the letter, `/srv/repo` or
  `repo`, on the project's drive on Windows, as Maven 3.10's file transport
  reads them. `raeva.lock` records the `file:` URL, a project-relative one
  for a directory in the project, and mirror patterns such as `external:*`
  and repository filters still read the URL as written. `bundle:` URLs
  stay skipped, as Maven cannot read them either.
- A settings.xml or POM repository whose URL does not parse, such as a
  path without a scheme in the Maven 3.9 mode, or has a scheme `raeva`
  cannot fetch, but which a
  `settings.xml` mirror serves,
  resolves through the mirror, as in Maven. `raeva.lock` records no origin
  for the files it served (`repo_url = ""`), neither URL, and `export-m2`
  labels them with the mirror's id and the repository's. A version range
  read through one records the empty origin too, and `--frozen`, seeds and
  `export-m2` take it for that mirror's route. A plugin file one served,
  from a POM's `<pluginRepository>` or an active `settings.xml` profile's,
  takes the empty origin the same way. Two such repositories, which the
  empty origin could not tell apart, or a plugin's version range listed
  through one, fail the sync (exit 3, `REPOSITORY_CONFIG`).
- Known limit: a POM repository whose URL holds an expression, such as
  `${repo.base}/maven` or `${project.baseUri}repo`, or an active
  `settings.xml` profile repository whose URL still holds one once the file is
  interpolated, which Maven injects into the project's model, may go to one
  mirror as written and to none, or another, once interpolated: `external:*`
  matches the URL as written but not a loopback or `file:` one. Maven reads
  parents and imported BOMs through the mirror of the URL as written and
  dependencies through the interpolated URL. A build that reads a parent or a
  BOM through such a repository fails (exit 3, `REPOSITORY_CONFIG`) and the
  error names the repository's id. Two mirrors at one URL are one route unless
  either is blocked, has an `[[auth]]` entry, or has a `settings.xml`
  `<server>` with more than a `<username>` and `<password>`, such as a
  `<configuration>`: Maven sends a password only once challenged, and raeva
  reads that route without it, so a BOM that only the password reads fails
  the sync. A mirror with
  the repository's own id still serves the parent lookup, but the interpolated
  URL replaces it before any BOM import. A build whose dependencies alone use
  such a repository is locked as usual, and so is a dependency's POM whose
  repository raeva does not read, or whose parent or BOM a repository the
  dependency was resolved through holds: Maven searches those first. A
  dependency's parent that only the mirror of such a URL as written holds is
  not found (exit 5), and the error names that mirror. A dependency that
  redeclares the id of a repository it was resolved through replaces that
  entry for its BOM imports in Maven 3.9.12, and keeps it in 3.10.0, so in
  3.9.12 only the others come ahead of the mirror. Name the id in the
  `<mirrorOf>` of the mirror that should serve it, exclude it with `!id`, or
  give the URL without an expression.
- A POM repository whose `<id>` takes a `${...}` resolves as in Maven,
  which matches mirrors and `<server>`s against the id as written while it
  looks a parent up and against the id once interpolated otherwise. raeva
  does the same, so a mirror of the interpolated id serves the
  dependencies, and the parent comes from the URL the id as written
  reaches. Known limit: an `<id>` that takes an environment variable
  `allow_env_substitution` does not name, which raeva treats as unset
  where Maven reads it, fails the sync (exit 3) where a mirror's
  `<mirrorOf>` names an id, or, unless a mirror serves the repository, a
  `<server>` or `[[auth]]` entry does. Maven may match the value against
  that name, and raeva does not know the value. A dependency's such
  repository fails the sync the same way once the transitive policy admits
  it; in the default configuration it is dropped (`TRANSITIVE_REPO_DROPPED`).
- Known limit: a literal `settings.xml` repository or mirror `<layout>`
  other than `default`, and an active `settings.xml` profile repository
  whose `<id>` still holds a `${...}` once the file is interpolated, fail
  the sync (exit 3). A POM repository whose layout once interpolated is
  another, such as `legacy`, is ignored (`REPOSITORY_IGNORED`) unless a
  mirror serves that layout, as Maven reaches it only through one. A layout
  that takes a `${...}` serves a parent lookup, which reads it as written,
  only through a mirror whose `<mirrorOfLayouts>` is `*`. The same holds
  for a `settings.xml` plugin repository, and a POM plugin repository's
  `<id>`, only where `[plugins] lock = true` locks the plugins they serve;
  otherwise they are left out, as they serve no dependency.
- Known limit: a `settings.xml` profile repository whose `<url>` still holds
  a `${...}` once the file is interpolated is filled in by the project, as
  Maven does: once for the whole build, the profile's own properties over
  the POM's. raeva locks it only where every project of the reactor fills
  it in alike, and where no other repository of an active `settings.xml`
  profile has its id or a literal URL. Otherwise, and for any such
  repository whose `<layout>` holds a `${...}`, the sync fails (exit 3) and
  the error names the repository. Set the property in the same
  `settings.xml` profile, or write the URL out.
- No repository or mirror URL may contain userinfo, a query, or a fragment,
  in configuration or a project POM (exit 3). The error names the entry, not
  the URL: `raeva.lock` would record it. Use `[[auth]]` or a
  `settings.xml` `<server>`. A dependency POM with such a URL is ignored
  (`REPO_URL_SECRET_REFUSED`).
- A `file:` repository or mirror URL with a host other than `localhost`,
  such as `file://server/share/repo/`, `file://server/C:/repo/` or
  `file://server`, is refused in configuration or the project's POMs and
  their parents, in either mode (exit 3), before anything is fetched from
  it. Maven drops the host and reads `/share/repo` on the machine it runs
  on, `C:\share\repo` on Windows, where `raeva` would read the network
  share or nothing, and lock other versions. The error names the
  repository's id, not the URL; give a local path or a `file:///` URL.
  A `${...}` that `raeva` leaves as written in the host part, such as
  `file://${user.dir}/repo/`, which Maven expands to a path, an
  `${env.NAME}` that is unset or not allowlisted, or an undefined property,
  is refused for that input by name, not its value (exit 3).
  `file://localhost/srv/repo/` reads as `file:///srv/repo/`. A fetched
  POM's repository with such a URL is ignored (`REPOSITORY_IGNORED`).
- A repository URL may not take an input named like a secret (`TOKEN`,
  `SECRET`, `PASS`, `KEY`, `AUTH`, `CREDENTIAL` or `ENTITLEMENT` in its
  name) anywhere: its host, port, userinfo, path or part of a path
  segment, query or fragment, of any scheme, `file:` included, since
  `raeva.lock` records the expanded URL (exit 3). This is decided by the
  name the URL takes, whatever its value: in `settings.xml` and in a
  project POM, a `${...}` named like a secret, or a property that takes a
  value from one through any chain of others, such as a `-D` alias, a POM
  property or a `settings.xml` property that takes `${env.API_KEY}`, which
  `settings.xml` reads with or without the allowlist. A project POM's URL
  is refused too when the value of a `-D` value (command line or
  `.mvn/maven.config`), an active `settings.xml` profile property or an
  allowlisted `${env.NAME}` named like a secret makes up whole segments of
  the path, or is anywhere in it when it has eight characters or more,
  with any `${...}` left in it standing for any text. A coordinate such as
  `${project.version}` counts by what its own text takes, and a
  `settings.xml` variable whose value holds a `${...}` by that name too, as
  `settings.xml` expands twice. A project POM's repository `<id>` that
  takes such an input is refused the same way, and messages show it as
  `***`. The error names the input, not its value.
  A fetched POM's repository with such a path, or whose `<id>` holds such
  a value, is ignored (`REPO_URL_SECRET_REFUSED`). A remote parent's
  repository is still searched for that parent's own lineage under its
  `<id>` as written, before interpolation, `${...}` and all, so neither the
  lock nor a message holds the value. Give such a URL to a `<mirror>`,
  whose URL the lock does not record; where messages and logs show that URL, they
  show `***` in place of the value of a secret-named `${...}` in it,
  and the store index and `metadata.db` record it as `mirror:<id>/`.
  A token written into the URL as literal text is shown as written.
  What raeva prints and logs shows `***` in place of each password,
  passphrase, `<privateKey>` and master password of `settings.xml` and
  `settings-security.xml`, as written and decrypted, and of the value a
  secret-named input takes, a secret-named `-D` in `MAVEN_OPTS`,
  `MAVEN_ARGS`, a JVM options variable, an argument file one names, a
  mavenrc file or `[plugins] trace` included, unless that value is
  shorter than 4 characters, a version such as `1.2.3` or a word such as
  `true`. raeva does not show or keep the output of the build `[plugins]
  trace` runs, so nothing that build prints reaches raeva's output or
  files ([Locked plugins](offline-builds.md#locked-plugins)). With
  `-vv` or `-vvv`, the HTTP and TLS libraries log at info at most, as they
  log the hosts they connect to unmasked; `RUST_LOG` still sets any level.
  When the
  value is not a secret, rename the input. Keep any other secret out of repository URLs too.
  A `settings.xml` `<id>`, `<activeProfile>`, or proxy `<host>` or
  `<protocol>` may not take such an input either (exit 3): messages show
  them, and the seed names an entry by its id. Nor may the `<id>` of a
  repository or plugin repository of a project POM hold the value of one,
  which `raeva.lock` records (exit 3).
- External HTTP repositories declared by any POM or a `settings.xml`
  profile are ignored, as with Maven's default HTTP blocker. One the
  project, its parents or `settings.xml` declare is reported
  (`HTTP_REPO_BLOCKED`); a dependency POM's only under `-v`, or in the
  error when an artifact is then not found. Configure a matching mirror
  that is not blocked, or declare the same URL in `raeva.toml` or user
  `config.toml` to allow it, or give a mirror of yours the blocker's id,
  `maven-default-http-blocker`, which replaces it as in Maven. The
  repositories of `raeva.toml` and `config.toml`, which Maven does not
  read, and HTTP to `localhost` or `127.0.0.1`, spelled so in the URL as
  Maven reads it, are allowed. The same rule applies when restoring
  lockfile origins.
- Credential matching: [Authentication](authentication.md#precedence).
- A dependency POM's repositories are not searched (unlike Maven) unless
  `security.transitive_repository_allowlist` covers them (same scheme, host,
  and port, path at or below the entry) or
  `security.allow_transitive_repositories = true`. `--json` lists each
  ignored one as `TRANSITIVE_REPO_DROPPED`, except Maven Central and a
  snapshot-only repository a release declares. A dependency only they have
  fails, and the error names them. An admitted repository serves only the
  declaring POM's own dependencies, their dependencies, and that POM's
  parent and imports, after the other repositories. For a dependency's
  parents and imports, and those of the BOMs it imports, raeva keeps the
  list as Maven's model resolver does, by effective id: a repository a
  mirror serves is listed under the mirror's id, and a declaration whose
  effective id is listed adds nothing. Maven 3.9.12 lets an interpolated
  declaration of an id seen before drop the entries listed under that id
  and searches it after the others; 3.10.0 keeps the entries the
  dependency was resolved through. A BOM's super POM `central` does the
  same, so with Central unmirrored, or behind a mirror whose id is
  `central`, a dependency's nested imports in 3.9.12 come from the BOM's
  repositories before Central. A redeclaration behind a mirror with
  another id drops nothing. Where Maven searches a repository raeva does
  not read, as in the default configuration, ahead of the one that holds
  a parent or import, or in place of an earlier entry, the sync fails
  (exit 3, `REPOSITORY_CONFIG`) instead of locking what raeva reads. Two
  exceptions. A declaration that reaches the endpoint of a repository the
  dependency was resolved through, such as `central` at Central's other
  name, reads the same files there. And a parent or import of a release
  version that none of the repositories raeva reads holds before Central,
  with Central the next one that does, comes from Central, as a release
  on Central is the same file everywhere: a Google Cloud BOM's copy of
  Central ahead of Central is read this way. A snapshot, a version range,
  and a POM after an entry that took another's place are refused as
  before. Known limit: a repository raeva does not read that serves a
  different POM under a release version Central also has is not noticed,
  and raeva locks Central's, as 0.5.3 did. One without an `<id>` goes to a mirror of
  `*`, as in Maven, which reads the absent id as an empty one. A `file:`
  repository a fetched POM declares, a dependency's or a plugin's, is never
  searched, even with these settings, so a parent only it holds is not found
  (exit 5).
- A fetched parent POM's repository is searched, as in Maven. It must be
  HTTP or HTTPS, or one a mirror that is not blocked serves, such as a
  `${repo.url}/releases` Maven looks the next parent up in before it
  interpolates (`FETCHED_POM_REPO_REFUSED` otherwise), and a private address
  needs the allowlist or `allow_transitive_repositories`. Repositories of a
  BOM the project imports get that trust and serve only that BOM's parents
  and imports. They join the project's list by effective id the same way,
  and a BOM's interpolated declarations and its super POM's `central` drop
  the entries under their id, which come back after the BOM's own, as in
  both Maven releases: a BOM that redeclares an id the project declares
  has its nested imports read from its URL in place of the project's, and
  with Central unmirrored, or behind a mirror whose id is `central`, a
  BOM's nested imports come from its own repositories before Central. A nested BOM
  that comes through a mirror of a repository only an imported BOM
  declares fails the sync (exit 3): raeva.lock would record a repository
  the project does not declare. Declaring that repository in the project
  or a settings profile lets it lock.
- A project repository URL taken from a fetched parent has that parent's
  trust (`PROJECT_REPO_URL_FROM_FETCHED_POM`), including through a local model
  field such as `${project.artifactId}` or `${project.packaging}` that reads
  an inherited property.
- The project's `<pluginRepositories>` and Maven's `central`, which serve
  the plugins `[plugins] lock = true` locks, get credentials, private
  addresses and redirects by the rules of the project's `<repositories>`,
  also when a sync fetches a locked plugin file again.
- Private addresses (loopback, private, link-local, and similar) are allowed
  for a repository your configuration, the project POM, or an in-project
  parent POM names, and only for that origin. A proxy resolves a host name
  where raeva cannot screen its address, so it carries a request to a host
  name only for such a repository, or one the allowlist covers; another is
  refused (the search goes on at the next repository) unless its host
  bypasses the proxy.
- Only an HTTPS repository your configuration or the project names may
  redirect to another origin, and only to HTTPS. The chain may cross
  origins again, over HTTPS, up to 5 redirects. A credential goes only to
  the origin it was configured for, and never again once a redirect leaves
  it. Userinfo in a redirect target, such as the token GitHub Packages puts
  in its download URL, is sent as Basic auth to that target's origin alone,
  as Maven does, and appears in no output. If a
  target goes through a configured proxy, its hostname must name a configured
  repository or mirror origin, since the proxy resolves it where `raeva`
  cannot screen the address. Targets that bypass proxies through
  `non_proxy_hosts`, `NO_PROXY` or scheme selection use the direct DNS
  address screen. repo.spring.io and repo.jenkins-ci.org redirect downloads
  to object storage, such as
  `https://jfrog-prod-use1-shared-virginia-main.s3.amazonaws.com`. Behind a
  proxy, trust that origin with a `config.toml` mirror of no repository,
  whose `mirror_of` is left out, or a `settings.xml` mirror with an empty
  `<mirrorOf>`, or send its host around the proxy. Such a
  mirror, or one whose `mirror_of` is blank, serves no repository: its
  origin may only be the target of a proxied redirect, and gets no
  credential or other trust:

  ```toml
  [[mirrors]] # config.toml only; serves no repository
  id = "jfrog-storage"
  url = "https://jfrog-prod-use1-shared-virginia-main.s3.amazonaws.com/"
  ```

### Remote repository filters

raeva applies maven-resolver's `groupId` and `prefixes` remote repository
filters, which keep a repository from being asked for files its rule file
leaves out. Their `aether.remoteRepositoryFilter.*` properties come, the
later winning, from the properties of the `settings.xml` profiles that
`<activeProfiles>`, `active_profiles` or `-P` names (even one that `-P !id`
or `inactive_profiles` turns off, as in Maven, and in the 3.10 mode also
each `<activeByDefault>` profile that neither turns off), `.mvn/jvm.config`, then a `-D` in
`.mvn/maven.config` or on the command line.

- `aether.remoteRepositoryFilter.groupId=true` or `.prefixes=true` enables
  a filter; `.groupId.skipped=true` or `.prefixes.skipped=true` turns it
  off again, and so does `.groupId.record=true`, with which Maven records
  rules instead of applying them (raeva writes none). Only `true`, in any
  case, counts as true.
- The rule files are `groupId-<id>.txt` and `prefixes-<id>.txt` in the
  filter's basedir, `.groupId.basedir` or `.prefixes.basedir`, which a
  relative path takes from the local repository Maven uses
  (`maven.repo.local`, else the `settings.xml` `<localRepository>`, else
  `~/.m2/repository`); unset, it is `.remoteRepositoryFilters` there. The
  `<id>` is that of the repository that gets the request: a mirror's id
  when a mirror serves it, so `groupId-confluent.txt` does nothing behind a
  mirror of `confluent` with another id, as in Maven. Central is a
  repository like any other, with the id `central`.
- A line starting with `#` or blank is skipped. In `groupId-<id>.txt` each
  other line is a groupId, matched exactly, spaces included. In
  `prefixes-<id>.txt` each is a path such as `/org/apache`; a request path
  passes when it runs through the listed elements to the end of one, and a
  longer entry narrows a shorter one. A file without entries passes
  nothing. A repository without a file passes everything, so a missing
  file does not fail the build.
- A request needs both filters to pass, judged by the path Maven's layout
  gives the file: a snapshot by the build its metadata resolves to, in
  its base version's directory. One that fails is a miss of that
  repository without a request, and the search goes on to the next; a
  copy from that repository in the cache or the store is not used. This
  covers POMs, metadata, artifacts, plugins, extensions and the files
  `export-m2` exports.

The 3.10 mode applies resolver 2.0's rules instead. Both filters are
enabled unless their property is `false`, and
`.groupId.<id>=false`, `.groupId.*=false` and the `.skipped.<id>` forms
turn one off for a repository. A groupId rule covers that group and the
groups below it; `!` before it excludes, `=` limits it to that group alone,
`*` accepts every group not otherwise listed, and the last rule for a group
wins. A prefixes file must start with `## repository-prefixes/2.0` (or the
Nexus header) and is otherwise ignored with a warning. A repository without
a file passes everything unless `.groupId.noInputOutcome` or
`.prefixes.noInputOutcome` (or its `.<id>` form) is `false`. A file is
looked up first as `<id>-<sha1 of the URL>` and then as `<id>`, with
characters a file name cannot hold replaced as resolver replaces them.
Maven 3.10 also downloads `.meta/prefixes.txt` from a repository that no
local file covers and no mirror serves; raeva does not, and asks that
repository as if it had no prefixes file, which can cost requests Maven
would not make but changes no result unless that file is stale.

A rule that resolver cannot load, such as a 3.10 groupId rule that names no
group, a rule file that is not UTF-8, a basedir that is not a directory, or
more than 1024 rule files in one, fails the load (exit 3).

### Proxies

`[[proxies]]` takes `host`, `port`, and optionally `id`, `protocol`,
`auth_type` (`basic` or `bearer`), `username`, `password`, `token`,
`token_env`, and `non_proxy_hosts`. Only the user `config.toml` may hold
them. A project `raeva.toml` with `[[proxies]]` fails to load (exit 3).
Java networking properties and a global settings file are not read.

- `protocol` selects URLs as in Maven: `http` for `http:`, `https` for
  `https:`, `all` for both. `raeva` uses the first proxy of that scheme
  whose `non_proxy_hosts` do not match. An `https:` URL with none uses the
  first such `http` proxy. Another protocol in `settings.xml` is ignored,
  with a warning. Of the active `settings.xml` proxies with one `<id>`,
  only the first counts, as in Maven, and a proxy without an `<id>` has
  the id `default`, so a second one without an id is never used.
- A `non_proxy_hosts` entry matches the whole host, ignoring case. `*`
  matches any run of characters. `.example.com` and `*.example.com` both
  match `example.com` and every host under it. Other regex syntax is literal.
  An entry keeps its spaces, as in Maven, so the `<nonProxyHosts>` list
  `localhost | 127.0.0.1` matches neither host.
- Every proxy is reached over plain HTTP. `https:` URLs use `CONNECT`, as
  Maven does. A TLS-only proxy cannot be used.
- Proxy credentials go only to the proxy, in `Proxy-Authorization`.
  `raeva sync`, `raeva vuln`, and `raeva doctor` use these proxies.

When neither `config.toml` nor `settings.xml` names a proxy, `raeva` reads
the variables curl reads, the lower-case name before the upper-case one:

- `HTTPS_PROXY` carries `https:` URLs and `HTTP_PROXY` `http:` ones. Unlike
  a Maven `http` proxy, `HTTP_PROXY` alone leaves `https:` URLs direct.
- A value is `[http://][user[:password]@]host[:port]`, port 80 when left
  out. Percent-encode `@`, `:` and `%` in the user name and password. An
  `https://` or `socks5://` proxy, a path, or a password without a user name
  stops the command (exit 3), naming the variable but not its value.
  `ALL_PROXY` is not read.
- `NO_PROXY` is a comma-separated list. `*` sends everything direct.
  `example.com`, `.example.com` and `*.example.com` each match
  `example.com` and every host under it. An IP address matches itself, and a
  CIDR range such as `10.0.0.0/8` or `fd00::/8` the addresses in it. A host
  name or address may end in `:port` to match that port only. Other
  patterns, such as `10.*`, stop the command, naming the entry by its
  position.
- `localhost`, names under `.localhost`, and loopback addresses always go
  direct.

These proxies take the same path as configured ones: the redirect and
address rules above apply to what they carry. The hints of a network error
or a proxy refusal name the proxy and its variable. A proxy that does not
answer is retried, then fails the sync without the next repository standing
in, like any other timeout. A refusal, a 407 or any other answer to the
`CONNECT` of an `https:` URL but 200, is `PROXY_AUTH` and is not retried.
After a 407 the next repository is tried, as in Maven; after another
refused `CONNECT` it is not, since the proxy's answer may only have been
misread.

### Security

- `allow_env_substitution` names the variables `${env.NAME}` (and `${NAME}`
  outside `<activation>`) in a POM may read, and the `env.NAME` its profile
  activation sees; `settings.xml` sees every variable. The default is empty. The
  lock's configuration hash covers each value read, so a short value can be
  guessed from a committed `raeva.lock`. List only variables whose values
  may be public, and set the same list on every machine that syncs the
  project. A POM that reads a set variable not listed here warns
  `ENV_VAR_HIDDEN` with its name, never its value, since Maven would read it,
  unless it is the host path `JAVA_HOME` or `PWD`. These uses fail the
  sync (exit 3) instead, naming it: a
  repository's `<enabled>`, update or checksum policy or `<layout>` that
  reads it, and the `<activation>` of a profile that matters to resolution,
  of the project or of a dependency's POM, that tests it, `JAVA_HOME` and
  `PWD` included, but for `${env.JAVA_HOME}` in a `<file>` path, which is
  the JDK home (below). A `<property>` test of `env.NAME` with a `<value>`
  that the variable's value answers as an unset variable answers it, such
  as `false` for `<value>true</value>`, reads it as unset and writes the
  lock written without it; `${env.NAME}` in a condition's text, and a
  test without a `<value>`, still fail. A repository `<id>` or `file:`
  URL that reads it can fail too, as
  [Repositories and mirrors](#repositories-and-mirrors) says. Any other
  use reads the variable as unset, with the warning: where the text it
  leaves is still valid, as in an exclusion's `<artifactId>`, and Maven's
  value would change the lock, the sync goes on and its lock differs from
  Maven's. On Windows Maven names every variable in upper
  case, so a POM reads `Path` as `env.PATH`, and `env.Path` as unset; list
  it as `PATH`. A variable `mvn` sets itself needs no listing:
  `MAVEN_PROJECTBASEDIR` is the project directory, and one whose value
  raeva cannot know, such as `MAVEN_CMD_LINE_ARGS` (`mvn`'s own arguments)
  or a `MAVEN_OPTS` that `mvn` rewrites, fails the sync where it would
  change the lock, as a hidden variable does.
- Every `[security]` key allows more as it grows, so only `config.toml` can
  allow anything. A key the project `raeva.toml` sets can only narrow the
  user value: `allow_env_substitution` and `transitive_repository_allowlist`
  keep the entries the user value also covers, and
  `allow_transitive_repositories` is true only when both set it. A wider
  request is ignored (`PROJECT_SECURITY_WIDENING_IGNORED`). On CI, put the
  allowances in the `config.toml` under `RAEVA_HOME`.

### Plugins

`[plugins]` decides what `raeva.lock` holds, so it belongs to the project:
only the `raeva.toml` at the reactor root may set it, and a `config.toml`
with `[plugins]` fails to load (exit 3).

- `lock = true` has `raeva sync` lock the build's plugins and extensions in
  the plugin tables of `raeva.lock`, `--frozen` check them, and
  `raeva export-m2` write their files. Without it, `raeva.lock` holds no
  tables: a sync drops those an older lock holds, and `--frozen` refuses
  them.
- `goals` lists goals the build runs with, such as `spotless:check`, whose
  plugins the tables add to those the POMs bind and the default goal names.
  The compiler goals `compile` and `testCompile` lock the annotation
  processor paths of their execution, as Maven configures it:
  `default-cli`, or the id after `@`, as in `compiler:compile@generate`.
- `trace` lists the Maven arguments of a build `raeva sync` runs once,
  online, to pin what plugins fetch while they run. `--frozen`, `--offline`,
  `raeva lock verify` and `raeva export-m2` never run it. raeva sets the
  build's local repository and sets `maven.repo.local.tail` and
  `maven.repo.local.head` empty, over a value from `.mvn/maven.config`,
  `settings.xml`, `MAVEN_OPTS` or a `-D` given to that sync, so the build
  reads no other local repository. An argument that sets one of the three
  is refused, as is one that starts with `"`, which Maven would join with
  the arguments after it. An online `raeva sync` without `--frozen` also refuses (exit
  2), before it resolves, an `active_profiles` or `inactive_profiles` id
  that `-P` reads otherwise: empty, with a `,`, `$`, a control character
  or outer spaces, or starting with `!`, `-`, `+`, `?` or `"`.
- `mvn` is the launcher of that build: a command name on `PATH` (default
  `mvn`) or a relative path inside the project, such as `./mvnw`. A command
  name holds only ASCII letters, digits, `.`, `_`, `+` and `-`, and is not
  `.` or `..`. A path separates its parts with `/`, holds no control
  characters, and must name a file that exists. Either is at most 1,024
  bytes. An
  absolute path, a path that leaves the project, or a link that leads out
  of it is refused, by every sync. On Windows a launcher without an
  extension runs as its `.cmd`, such as `mvn.cmd` or `./mvnw.cmd`.

The other keys need `lock = true`, and `mvn` needs `trace`. The tables record the goals among their
inputs. The traced build gets raeva's `-P` and `-D` options and the
`active_profiles` and `inactive_profiles` ids, and the trace is keyed by
them, the `-P` and `-D` options of `.mvn/maven.config` and the `-D`
options of `.mvn/jvm.config` and the argument and VM options files it
names, which `mvn` reads itself, `trace` and `mvn`,
so `--frozen` refuses a lock made with other settings or options.
The `-D` options of `MAVEN_OPTS`, `MAVEN_DEBUG_OPTS`, `JAVA_TOOL_OPTIONS`,
`JDK_JAVA_OPTIONS` and `_JAVA_OPTIONS`, and of the argument files they name,
are in the key too, since plugins read them, except `user.home`, the local
repository's, a name like a secret's,
`aether.syncContext.named.factory`, and, unless the project reads the
name, the names the JDK sets itself (`java.home`, `java.version`,
`os.name`, `os.arch`, `os.version`, `user.name`, `user.dir`, `user.region`, `user.timezone`,
`file.separator`, `path.separator`, `line.separator` and the `native`,
`stdin`, `stdout` and `stderr` encodings) and those that tune the JVM,
the transport or the console: the JDK's own (`jdk.`,
`sun.`, `com.sun.`, `https.`, `ftp.`, `socks`; under `java.` the JDK's
packages, such as `java.net.`, `java.security.` and `java.util.`, and
names such as `java.io.tmpdir` and `java.vm.`; under `javax.` its
packages, such as `javax.net.` and `javax.xml.parsers.`; the proxy,
agent, keep-alive, authentication and connection names under `http.`;
the locale's `user.language`, `user.country`, `user.script`,
`user.variant` and `user.extensions`, and `file.encoding`),
`maven.wagon.`, `aether.connector.`, `aether.transport.`,
`maven.resolver.transport`, `maven.artifact.threads`, `org.slf4j.`,
`style.` and `jansi.`. The project reads a name that a POM defines as a
property, or that an element text or attribute value of a POM (the root
`pom.xml`, its modules in any profile and their local parents) or
`.mvn/extensions.xml`, with references and CDATA sections decoded,
`.mvn/maven.config`, `.mvn/jvm.config`, the `-D` values or the trace's
arguments holds anywhere, even inside a longer name, except as the name
a `-D` option sets, which sets the property rather than reading it: for a
forked JVM in an `argLine`, or for Maven's own JVM in `.mvn/jvm.config`,
where a `MAVEN_OPTS` value for the same name wins and only keys the trace
if a project file reads the name.
So `<classifier>${user.language}</classifier>` or
`${session.systemProperties(name)}` puts the name in the key, while
surefire's `<java.awt.headless>true</java.awt.headless>`, an `argLine`
of `-Dfile.encoding=UTF-8` or a comment does not, and
`jdk.tls.client.protocols` is not in the key unless a project file names
it.
When raeva cannot list or read these files, every such name is in the
key.
Other names that start like the JDK's, such as
os-maven-plugin's `os.detected.classifier`, a POM's `java.source.version`
or `http.port`, are in the key. A tuning name that only a remote parent,
an imported BOM or a plugin's own parameter default reads is not. Where
raeva cannot read those POMs, as when a module an inactive profile lists
is missing or written with `${...}`, or a POM does not parse, all those
names are in the key, and `--frozen` names the file or module.
So give the build the same such options where it is traced and where
`--frozen` checks it, or pass them to raeva or put them in `.mvn/`. Their
other options are not in the key. The
`-D` and `-P` options of `MAVEN_ARGS` count as the command line's. The key holds the profile ids each `-P` selects or
deselects as a set, as Maven reads them, so `-Pa,b` and `-Pa -Pb` are one
trace, and the last value of each `-D` name, `true` when it has none, so
`-Dx` and `-Dx=true` are too. A `-D` for one of the three local
repository properties raeva sets is not in the key. Of `.mvn/jvm.config`
only the `-D` options are, so a change to `-Xmx` keeps the trace. There
`-Dx` sets an empty value, as the JVM does, and a name that a `-D` of the
command line or `.mvn/maven.config` also sets is not in the key, as Maven
sets that value over it. See [Locked
plugins](offline-builds.md#locked-plugins).

## Environment variables

| Variable | Effect |
| --- | --- |
| `RAEVA_HOME` | Root for the config, store, and cache ([File locations](#file-locations)). |
| `RAEVA_TIMEOUT` | Seconds, 1 to 86400 (default 30). Bounds the wait for headers and between body chunks. Connect limit is 10 seconds. |
| `RAEVA_RETRIES` | Retries, at most 100 (default 3). |
| `RAEVA_LOW_SPEED_LIMIT` | Minimum bytes per second (default 1024; 0 disables). |
| `RAEVA_LOW_SPEED_TIME` | Seconds below the limit before a retry (default 30; must be positive). |
| `RAEVA_MAX_ARTIFACT_SIZE` | Maximum bytes of one artifact (default 16 GiB). |
| `RAEVA_WORKSPACE_STALL_TIMEOUT_SECS` | Seconds without progress before a sync stops (default 900; 0 disables). |
| `RAEVA_EXPORT_M2_MAX_SUPPORT_POMS` | Maximum parent and BOM POMs `raeva export-m2` writes (default 10000). |
| `RAEVA_OSV_BASE_URL` | OSV API base URL for `raeva vuln` (default `https://api.osv.dev/v1`). |
| `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`, `NO_PROXY`, `no_proxy` | Proxies, when `config.toml` and `settings.xml` name none ([Proxies](#proxies)). |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | PEM roots to trust instead of the OS store, when either is set, even if empty. |
| `JAVA_HOME`, `JAVA_VERSION` | The JDK version POMs see ([The JDK version](#the-jdk-version)). The JDK's home is also `java.home` in profile activation, or its `jre` directory where `jre/lib` exists, as in a JDK 8. |
| `PATH` | Where raeva looks for the `java` that `mvn` runs when `JAVA_HOME` is unset ([The JDK version](#the-jdk-version)). |
| `MAVEN_SKIP_RC` | When set and not empty, `mvn` sources no mavenrc file, so raeva sources none ([The JDK version](#the-jdk-version)). |
| `MAVEN_OPTS` | Passed on to the build `[plugins] trace` runs ([Java4Shell](ci.md#java4shell)). `raeva doctor` reads it for the Java4Shell check. Its last `-Duser.home` sets Maven's user home ([Configuration](#configuration)), and its other `-D` options are system properties ([Maven options](#maven-options)). |
| `MAVEN_DEBUG_OPTS`, `_JAVA_OPTIONS` | Read by `raeva doctor` for the Java4Shell check, as options the JVM `mvn` starts gets after `MAVEN_OPTS`. The build `[plugins] trace` runs fails with exit 3 when they, or `.mvn/jvm.config` or `MAVEN_OPTS`, turn `UseBASE64Intrinsics` back on after its `JDK_JAVA_OPTIONS` ([Java4Shell](ci.md#java4shell)). Their `-D` options are system properties, and their last `-Duser.home` sets Maven's user home ([Configuration](#configuration)). |
| `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS` | Their `-D` options are system properties, below `.mvn/jvm.config` and `MAVEN_OPTS`, and their last `-Duser.home` sets Maven's user home ([Configuration](#configuration)). The build `[plugins] trace` runs gets `-XX:-UseBASE64Intrinsics` after its `JDK_JAVA_OPTIONS`, as the mavenrc files leave it, when the `release` file of the JDK `mvn` runs names 11 or later and not OpenJ9; it runs again without it if its JVM refuses it ([Java4Shell](ci.md#java4shell)). |
| `CFFIXED_USER_HOME` | On macOS, replaces the passwd home as Maven's user home when not empty ([Configuration](#configuration)). |
| `OPENJ9_JAVA_OPTIONS`, `IBM_JAVA_OPTIONS` | Read only to fail the sync when they mention `user.home` and the JDK `mvn` runs is OpenJ9 ([Configuration](#configuration)). |
| `MAVEN_ARGS` | Its `-D`, `-P` and `-s` options, read as ones on the command line before raeva's own; a few others fail the load (exit 3) (below). |
| `MAVEN_CONFIG` | Passed to Maven before its own arguments by a Maven Wrapper script of the `script` type (3.1.1 to 3.3.x), and by no `mvn` or `only-script` wrapper. When the project's `mvnw` or `mvnw.cmd`, or the `[plugins] mvn` launcher, passes it, one that holds an option `MAVEN_ARGS` would read, or refuse, fails the load (exit 3), but for the reactor selection (`-pl`, `-am`, `-amd`, `-rf`, `-N`), which is ignored as in `MAVEN_ARGS`; otherwise it is left out. |
| `LC_ALL`, `LC_CTYPE`, `LANG` | On Linux and macOS, whether the JVM `mvn` starts reads a non-ASCII `user.home` as UTF-8 ([Configuration](#configuration)). |
| `MAVEN_REPO_CENTRAL` | In the Maven 3.10 mode, the Maven Central URL, below `-D`, settings and POM values ([Maven line](#maven-line)). |
| `NO_COLOR` | No color on stderr. |
| `RUST_LOG` | `tracing` `EnvFilter`, such as `rv_repo=trace`. Overrides `-v`, and logs under `--json` too. |
| `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` | The Linux and macOS directories above. `~/.m2` and `${user.home}` take `user.home`, which is `HOME` only for a user without a passwd home on JDK 18 and later ([Configuration](#configuration)). |
| `USERPROFILE` | On Windows, moves the `AppData` folders. |
| `COMPLETE` | `bash`, `zsh`, `fish`, `elvish`, or `powershell`: a bare `raeva` prints that shell's completion script, as in `source <(COMPLETE=bash raeva)`; with arguments, raeva runs them. |

Raeva takes only the `-D` options of `MAVEN_OPTS`, as the JVM does. `mvn` splits `MAVEN_ARGS` at
white space, without removing quotes, and puts its words before its own
arguments, which Maven then cleans as `.mvn/maven.config`'s: a word that
starts and ends with `"` loses them, as does a value apart from its
option (`-P "b"`), while one inside a word stays (`-Dx="a"`). raeva reads
its `-D`, `-P` and `-s` (`--define`, `--activate-profiles`, `--settings`)
as command-line options before its own: a later `-D` of the same name on
raeva's command line wins, its `-s` wins over raeva's, as in Maven, a
`-Duser.home` there sets Maven's user home, and `--frozen` compares them
as the command line's. Options that change nothing `mvn` resolves, such as `-B`, `-ntp`,
`-o`, `-U` and `-T 4`, and arguments that are not options, are left as
they are. The reactor selection, `-pl`, `-am`, `-amd`, `-rf` and `-N`
(`--projects`, `--also-make`, `--also-make-dependents`, `--resume-from`,
`--non-recursive`), is read with its values and ignored, as in
`.mvn/maven.config`, with a `SETTING_IGNORED` warning: raeva locks the
whole reactor. With `[plugins] trace` set, a `raeva sync` that is neither
`--frozen` nor offline fails with one (exit 3), naming it, even when
raeva.lock is up to date and no trace build runs, as the trace build would
not build the whole reactor.
The load fails (exit 3), naming the option, for `-gs`, `-t`, `-gt`, `-f`,
`-itr` and `-llr`, an option neither Maven 3.9 nor 3.10 knows, a quote that no word closes, which joins
`mvn`'s own arguments, and a `*`, `?` or `[`, which the shell expands as
a file pattern. On Windows a `"`, `!`, `&`, `|`, `<`, `>`, `^`,
`%` or line break fails too, which `mvn.cmd` or the java launcher reads;
elsewhere they are part of the word, as for `mvn`, so `-P!extra`
deactivates `extra`. Pass those options to both raeva and `mvn`, or put them in
`.mvn/maven.config`.

The network variables override their `[network]` keys. A value that is not
a number, or is out of range, is exit 3. An unusable
`RAEVA_MAX_ARTIFACT_SIZE`, `RAEVA_WORKSPACE_STALL_TIMEOUT_SECS`, or
`RAEVA_EXPORT_M2_MAX_SUPPORT_POMS` is ignored, with a warning. An invalid
`RAEVA_OSV_BASE_URL` is exit 2.

`raeva` also reads the variables configuration names: `${env.NAME}` and
`env.NAME` activation in `settings.xml`, `${env.NAME}` in `local_repository`,
the allowlisted names in POMs, and
a proxy's `token_env`.

## The JDK version

raeva finds the JDK as the `mvn` launcher does, without running it:
`JAVA_HOME`, else the first `java` on `PATH` (`java.exe` on Windows) with its
links resolved. On macOS, where `/usr/bin/java` is a stub, it is the JDK
`/usr/libexec/java_home` names. An empty `JAVA_HOME` counts as unset.
`java.home` is that JDK's home, or its `jre` directory where `jre/lib`
exists, as in a JDK 8, whose `java` runs from the JRE inside it.
`java.version` is `JAVA_VERSION` from that
JDK's `release` file, else the `JAVA_VERSION` variable, else 17, with a
`JAVA_VERSION_DEFAULTED` warning when a POM reads it. Where that read
changes what is locked (a `<jdk>` condition, a `java.version` or
`java.specification.version` condition, or a `-D` value expanding one,
that decides a profile), `sync` and `sync --frozen` fail (exit 3) instead,
as does `export-m2` on a lock that reads it,
since Maven reads the JDK it runs on: set `JAVA_HOME` or `JAVA_VERSION`,
or list the JDKs in `[lock] jdks`. `export-checksums`, `sbom` and `vuln`
run where nothing names the version, as on a host without Java, and
check such a lock against the stand-in 17:
where 17 flips a recorded condition they exit 7, or exit 3 where the flip
changes the model of the project's own POMs, which they then resolve
again. `<jdk>` activation,
property conditions, `.mvn/maven.config`, and `${java.version}` see it, and
`java.specification.version` is its feature release (`1.8` for
`1.8.0_442`). A `<jdk>` range with a character that is not ASCII, such as
`[２１,)`, fails the sync (exit 3): Maven parses its bounds with Java's
`Integer.parseInt`, which takes the decimal digits of other scripts, and
more of them on newer JDKs. `maven.version` and `maven.build.version` are those of Maven
3.9.12, or 3.10.0 under `[lock] maven = "3.10"`. In the 3.10 mode
`org.jline.terminal.exec.redirectPipeCreationMode` is `native,reflection`
and `library.jline.path` is set, as 3.10.0's `mvn` passes them; in 3.9
`library.jansi.path` is set instead. A value test of `library.jline.path`
against text that does not end in `lib/jline-native` is false whatever
the Maven home is. `file.separator`,
`path.separator` and `line.separator` are those of each locked platform
unless `-D` sets them, and an `<os>` family `dos` or `unix` tests that
`path.separator`, as Maven's does. raeva.lock lists a `-Dpath.separator`
only when one is set, and adding or removing one makes the lock stale.
In a `<file>` condition, `maven.multiModuleProjectDirectory` is the
directory `mvn` sets: `MAVEN_BASEDIR`, else the nearest directory from the
project up that holds a `.mvn` directory, else the project directory;
`raeva.lock` records what the path tested, not the directory. A `<property>`
condition that compares or reads it fails the sync as below. In a `<file>`
path, `${java.home}` is the JDK's `java.home` unless `-D` or a POM property
sets it, and `raeva.lock` again records only what the path tested; with no
JDK found, the path keeps `${java.home}` as written. `${env.JAVA_HOME}`
there is the `JAVA_HOME` `mvn` picks that JDK by, so a profile such as
druid's on `${env.JAVA_HOME}/lib/jconsole.jar` is off on JDK 9 and later,
as in Maven; with `JAVA_HOME` unset the path keeps it as written. On a
host with no JDK, `sbom`, `export-checksums` and `vuln` take what such a
path in a dependency's POM tested from `raeva.lock`, while `sync --frozen`
and `export-m2` test it again. A name every measured
JVM sets to one value, `java.specification.name`,
`java.specification.vendor`, `java.vm.specification.name`,
`java.vm.specification.vendor` and `sun.java.launcher`, has that value.
A `<property>` condition that compares `java.vendor` with a `<value>`,
such as the `ibmjdk` profile of CXF 3.x's parent POM, takes the vendor of
the JDK `mvn` runs from the `IMPLEMENTOR` line of its `release` file, which
is what JDK 11 and later report as `java.vendor` (measured on Temurin,
Corretto, Zulu, Semeru and the Arch Linux builds; a JDK 8 can differ, as
Temurin 8 reports `Temurin`). raeva.lock records the condition and its
outcome, such as `property:java.vendor=IBM Corporation is false`, not the
vendor, so a host whose JDK gives the same outcome keeps the lock, and one
that gives another makes `--frozen` exit 7 and a plain sync resolve again.
Under `[lock] jdks` the condition takes the host JDK's vendor for every
listed JDK, and each host checks it with its own. On a host whose vendor
raeva cannot tell, such as one with no JDK, a JDK 8 or a JDK without an
`IMPLEMENTOR` line, `--frozen` exits 7 and a plain sync fails (exit 3)
until `-Djava.vendor=<vendor>` sets it; put that in `.mvn/maven.config`
when the team runs such JDKs, so every host takes the same value. Any
other name the JVM or `mvn` always sets, such as `os.version`,
`java.vm.vendor`, `user.name`, `user.home` or `user.dir`, and
`java.vendor` read as `${java.vendor}`, is present to a `<property>`
condition, but raeva does not read its value from the host. A name only
some JVMs set, such as `sun.cpu.isalist`, `sun.os.patch.level`,
`user.script` and `user.variant` on Windows, `http.nonProxyHosts` on macOS,
`awt.toolkit` on JDK 8 and 11, or `sun.stdout.encoding` on a terminal, is
treated the same way, its presence included. A name no measured JVM sets,
such as `jdk.version`, is unset unless the build sets it. A profile that
can change resolution fails the sync (exit 3, naming the property) unless
`-D` sets the value, when it compares the property with a `<value>`, reads
it as `${...}` in any condition, or tests `<os><version>`. So does a
settings.xml profile that sets properties or repositories, except that
`settings.xml` interpolation has already replaced `${user.home}` there,
so only the other names fail it,
and so do a presence test of a property only some JDKs or locales set, such
as `java.vendor.version` or `user.country`, and `${java.home}` in a
`<property>`, `<os>` or `<jdk>` condition. Such a condition also fails the sync on a profile
that cannot change resolution, when an `activeByDefault` profile of the same
POM can and no other profile there is activated by `-P` or its own
conditions, since the condition decides whether the default applies. The
exception is an `activeByDefault` profile that is the only one in its POM
with such a condition and the only default there that can change
resolution: while no other profile of the POM is activated by `-P` or its
own conditions, Maven activates it whether the condition holds or not. A
`java` shim on `PATH`, such as asdf's or jenv's, has no `release` file
beside it; set `JAVA_HOME` there. `mvn` sources `/usr/local/etc/mavenrc`,
`/etc/mavenrc` and `~/.mavenrc` (on Windows `%USERPROFILE%\mavenrc_pre.bat`
and `.cmd`) before it picks the JDK, unless `MAVEN_SKIP_RC` is set and not
empty, and such a file can set `JAVA_HOME` even when the environment has
it. raeva has the shell source them as `mvn` does ([Configuration](#configuration)),
so the JDK, `${env.*}` in POMs and settings.xml, and the JVM options are
those `mvn` has after them, and a `--frozen` check goes stale when they
change a value the lock read. A `JAVA_HOME` they set without `export`
picks the JDK, but a POM's `${env.JAVA_HOME}` does not see it, as in
`mvn`.
`-Djava.version` in `.mvn/maven.config` overrides it everywhere. A model's
own `java.version` property overrides it only for `${java.version}` in that
model.

`[lock] jdks = ["17", "21"]` resolves and locks each platform once per listed
JDK version. Each entry sets `java.version` for that section (including
`settings.xml` profile activation), and JDK version reads are not recorded in
`ambient_inputs`. Each host the entry covers reports its own full
`java.version`, so a test that every one of them answers alike holds, such
as `<jdk>21</jdk>`, `<jdk>[17,22)</jdk>` or a `java.specification.version`
`<value>`, and a test or a read of the full version fails the sync
(exit 3) unless `-Djava.version` sets it: `<jdk>21.0.13</jdk>`, a
`java.version` `<value>`, or `${java.version}` in a condition, a `-D`
value, settings.xml, or a dependency coordinate. `${java.version}` that
does not reach the lock, as in plugin configuration, stays as written. A
range decides by Maven's comparison of the first three version numbers, so
a bound inside the entry's releases, such as `[21.0.11,21.0.12]` or
`[021.0.11,021.0.12]`, fails the sync. `java.home` is the host's, and
recorded when read, only when `jdks` lists the host's JDK alone; otherwise
a `<file>` path that takes `${java.home}` or `${env.JAVA_HOME}` fails the
sync (exit 3), even with `JAVA_HOME` in `allow_env_substitution`. With `jdks` set, `raeva sync --frozen` passes on any host
JDK whose `java.version` equals an entry or starts with it followed by `.`,
`_`, or `-` (`21` matches `21.0.12.1`, `1.8` matches `1.8.0_442`), and exits 7
on an unlisted JDK. The entry `1`, which `1.8.0_442` also starts with, is
a configuration error (exit 3); write `1.8`. On a host where no `release` file or `JAVA_VERSION`
names the JDK's version, it exits 7 and says where it looked. Without
`jdks`, a `--frozen` run on a JDK that flips a recorded `<jdk>` or
`java.version` condition exits 7 and names the condition. A plain
`raeva sync` on an unlisted JDK, or one whose version is unknown, warns
`JDK_NOT_LOCKED` and resolves the listed JDKs.

## The target platform

`raeva sync` builds the models for each platform it locks, not for the
machine it runs on. `<os>` activation, `${os.name}`, and `${os.arch}` use
the values a JVM there reports, such as `Linux` or `Mac OS X`, and `amd64`
for x86_64 on Linux and Windows. Windows 10, 11 and Server JVMs each report
their own `os.name`, so on a Windows platform `<os><family>` and
`<os><arch>` hold, and a condition that tests the exact name or takes
`${os.name}` holds when it gives one answer under every `os.name` the
Windows JDKs 17 to 27 report, from `Windows 95` to `Windows Server 2025`,
such as `<file><missing>marker-${os.name}</missing></file>` without such
files. One the editions answer differently fails the sync (exit 3) unless
`-Dos.name` sets it.
`${os.detected.name}`, `${os.detected.arch}`, and
`${os.detected.classifier}` follow the os-maven-plugin (`macos-aarch64`
gives `osx-aarch_64`). `-Dos.name`, `-Dos.arch`, or `-Dos.version` in
`.mvn/maven.config` replace these values. Without `-Dos.version`, an
`<os><version>` condition is inactive.

A `<file>` condition tests a file on the machine raeva runs on, for every
platform it locks, as Maven on that machine would. On Windows a path that
starts at `\` or `/` without a drive, such as `\marker`, is on the drive
of the directory raeva was started in, as `java.io.File` puts it on the
drive Maven was started on, not on the project's: `raeva -C R:\app` run
from `C:\` tests `C:\marker`, as `mvn -f R:\app\pom.xml` does. On Linux
and macOS such a path starts at the file system root, for a Windows
platform too, since there is no drive to take. The same holds for a
`<build>` directory such as `<directory>\out</directory>`.

For a Linux platform, `${os.detected.release}`,
`${os.detected.release.version}`, and `${os.detected.release.like.ID}` come
from the machine's `/etc/os-release` (or `/usr/lib/os-release`, then
`/etc/redhat-release`). `os.detection.classifierWithLikes`
appends the first listed distribution it is like to
`${os.detected.classifier}`, as the plugin does (`linux-x86_64-fedora`), in
every model of the build. The plugin reads the list once, from the project
Maven builds first, else from `.mvn/maven.config`.
Such a lock lists `os-release` (see [below](#values-from-the-machine)), so
`--frozen` on another distribution fails. To lock one classifier everywhere,
set `-Dos.detected.classifier=linux-x86_64-fedora` in `.mvn/maven.config`.
When the repository does not publish the suffixed classifier, Maven fails
on that machine too, and so does raeva, with this override as the hint:
netty lists `fedora,suse,arch`, and its `netty-tcnative` 2.0.84.Final has
the Linux x86_64 classifiers `linux-x86_64` and `linux-x86_64-fedora`, so
on Arch Linux it needs `-Dos.detected.classifier=linux-x86_64`. The machine's release applies to
every Linux target, whatever its architecture. On a machine that is not
Linux there is no release: a Linux target gets the classifier without a
suffix, and `${os.detected.release}` stays unresolved.
A dependency coordinate that still holds a `${...}`, such as a classifier
`${nisse.os.classifier}` that a Maven build extension sets, fails with the
property's name and the POM that declares it; define the property with
`-D` in `.mvn/maven.config` or on the command line.
Plugin differences: [verification](verification.md).

## The configuration hash

`raeva.lock` records a hash of the settings that can change resolution:
repositories in order (URL, id, release and snapshot flags, update and
checksum policies), the `settings.xml` plugin repositories, which serve
build extensions, active and inactive profiles, `[lock] jdks`, the Maven
line, `[security]`,
effective `-P` selections from both option sources, and the definitions of
`settings.xml` profiles that have an `<activation>`, and the content of
each rule file an enabled remote repository filter reads, by file name.
The filter properties in effect, but the basedirs, count as consulted
user properties whether or not a model reads them, and the values the
requested `settings.xml` profiles give them are hashed too. Only consulted `-D`
lookups count, including names without an override, which the lock lists;
the values of those set are hashed. An unused `-DskipTests` does not make
the lock stale. A later `-D` value for a consulted name does.

A `-s` file counts by its content: its path is not hashed, so CI can keep
it anywhere. `[resolution] command_line` lists consulted `-DNAME` overrides
and explicit `-P` selections, from the command line or `.mvn/maven.config`,
as `-PID` or `-P!ID`, however `-P` spells them, without values.
`ambient_inputs` lists
`user-property:NAME` even when no override was set, so later additions are
checked, or `user-override:NAME` for a name the POM, an active settings
profile or an `activeByDefault` profile defines, which a JVM option's `-D`
does not change. When the hash or these names differ, `raeva sync --frozen` exits 7. Diagnostics
name options added or removed and conditions that changed. The lock and
cache hold no separate hashes of value-bearing configuration parts.
When an external value introduces another property name during interpolation,
`user-property-lookup:` keeps the authored expression and its public POM
context instead of the expanded name. The aggregate hash repeats that
interpolation with the current inputs and the model's property precedence,
without publishing the external name or value. This also covers activation
conditions and private file paths: file existence is checked again, including
in dependency POMs.
Mirrors, `[network]`, proxies, credentials, TLS roots, and `local_repository`
are not hashed, so CI can differ there.

`raeva.lock` records each file under the repository that configuration or a
POM declares, never under a mirror, so a lock written behind a mirror also
passes against Central. Downloads go through whatever mirror is configured
at the time. Behind a `mirror_of = ["*"]` mirror, a lock can record the
first repository searched for a file only a later one has, such as a
project `file:` repository or one an imported BOM declares for its parent,
and every repository a range searched as listing its version. `--frozen`
accepts that when the pinned release bytes agree, the ranges take the same
versions, and the current configuration and POMs still declare the
recorded repository; `raeva sync --update` records the right repository.
A lock whose range version the current repositories no longer list fails
with exit 7.

### Values from the machine

`raeva.lock` never holds a host value. `[resolution] ambient_inputs` lists
what resolution read from the host, and the hash covers the outcome:

- A profile condition on the JDK version, `java.home`, `java.vendor`, or
  an allowlisted variable is listed with the POM's text and outcome, such
  as `jdk:[17,) is true` or `property:env.CI=true is false`.
- A `<file>` condition is listed by its path relative to the project, such
  as `file:marker.txt is true`. A file outside the project, and a path
  built from a host value or from a `-D` value written with `${...}`, are
  tracked too: `--frozen` exits 7 once such a file appears or goes, and a
  plain `raeva sync` follows it, except for a condition in a parent or
  dependency POM raeva fetches, after which `raeva sync --update` does. A project path over 256 characters fails
  the sync.
- A `settings.xml` condition is listed as `settings:` and a key of its text,
  such as `settings:3f2a9c0e1b7d4a65 is true`, since the lock does not hold
  your settings. `--frozen` names it by its text where those settings are.
  With `[lock] jdks`, a `<file>` condition is listed once per JDK, since
  its path can name `${java.version}`. A profile whose `<os>` or `<property>`
  condition takes an `${env.NAME}`, a `-D` value or `${user.home}` is listed
  once per locked platform and JDK with whether it activates there, since
  Maven expands that text before it tests it.
- A value that reaches the model itself (`${java.version}`, `${env.NAME}`,
  a `settings.xml` profile property as `settings-property:NAME`, or the Linux
  release as `os-release`) is listed by name, and its value is hashed.

Only a read that can change resolution is recorded. A profile counts when
it declares dependencies, managed dependencies, repositories, or modules, or
sets a property those read. A profile that only sets build properties, such
as `maven.compiler.release`, is left out. So is one in a dependency's POM
that only adds test, provided or optional dependencies, which Maven leaves
out of the graph, unless one can make that POM invalid. A `system`
dependency at a path under `${java.home}` cannot, as Maven only warns when
the file is missing, so guava-parent's `src.zip` profiles give the same
lock on every JDK. A `-D` or POM property that sets `java.home` can make
that path relative, so the lock records that no `-D` sets it. When a profile that changes
resolution activates by `<jdk>`, set `[lock] jdks`
([The JDK version](#the-jdk-version)) so a CI JDK matrix shares one lock.
Without `[lock] jdks`, `--frozen` evaluates the listed conditions again and
exits 7 when an outcome flips, naming it, such as `jdk:[21,) was true, now
false`.

## Retries and slow downloads

`raeva` retries a timeout, a lost connection, or 429, 502, 503, or 504, up
to `retries` times, 3 by default as in Maven. After a timeout or a lost
connection the backoff is exponential, from 0.5 s to 30 s, plus jitter.
After a 429, 502, 503 or 504 it waits 5, 10, then 15 s, as Maven does, plus
up to half that again of jitter, or longer when `Retry-After` asks, up to
300 s as in Maven; the other requests to that host wait out the same window
rather than spend their own retries on it. A `Retry-After` over 300 s fails
the request at once, since asking sooner than the server said cannot
succeed, and the other requests to that host fail with it, unsent, until
that time is up. One request's waits after timeouts and lost connections
add up to at most one `timeout` per attempt, plus 5 seconds. Each wait prints a line on stderr
(not with `--quiet` or `--json`), and an error after retries says how many
attempts were made. A host name that does not resolve is looked up once
more, after the same backoff as a timeout, unless its last lookup failed
too; after two failed lookups in a row, the host gets no second lookup
until a request to it gets past the lookup. A refused connection or no
route is not retried. Neither failure stops the search as the retried ones
below do: it goes on at the next repository. When the retries run out, the
sync fails with a network error (exit 4) rather than take the file, version
list or SNAPSHOT build from the next repository, so `raeva.lock` and
`--frozen` never depend on a passing failure. Maven moves on to the next
repository instead. A restore fails the same way, but when a repository
lacks or refuses a pinned file, it may fetch the file from another, since
the pin checks it. `raeva vuln` retries OSV the same way.
The search continues at the next repository after any other failed
download, except one whose bytes fail or lack a checksum, or a redirect to
plain `http:`.
An HTTP 401 or 403 also tries the next repository, and the refusing one is
not asked for that file again in the run; if the next one serves the file,
`AUTH_FALLBACK` warns once per refusing and serving repository pair with an
example coordinate and the number of further files affected. A version
range, `RELEASE` or `LATEST` lists the versions of every repository that
answers. `REPOSITORY_FALLBACK` reports the same when a host name did not
resolve, the connection or TLS handshake failed, or a repository answered a
5xx error that raeva does not retry. It names the reason and asks you to
check the connection, such as a VPN, or the repository before committing
`raeva.lock`. Both warnings apply to artifacts, POMs, version listings and
restoration, and neither fails `sync --frozen`. Restoring a file that
`raeva.lock` pins stops at a 5xx answer instead, so a cold `--frozen` run
fails there when a resolving `raeva sync` would warn and continue. A
version listing that left out another failure reports
`LISTING_REPO_SKIPPED`. Version strings are limited to 255 bytes. Longer
entries in a repository's version listing are ignored.

A download below `low_speed_limit` for `low_speed_time` seconds is retried
on a new connection, up to `retries` times.

## Checksum policy

Each download is checked against the checksum published next to the file:
`.sha256`, else `.sha1`, else `.md5`. SHA-1 and MD5 match Maven. Each is
read as Maven reads it, by the first word of its first non-empty line, or
the hex after `= ` in a `SHA256(file)= <hex>` line, and one whose word is
no checksum, such as an HTML error page, counts as missing. So does a
`.sha256` the repository answers with an error, such as a 429 or a 5xx:
Maven never reads one, so the `.sha1` and `.md5` decide, and a long
`Retry-After` on it holds back only other `.sha256` requests.

A file whose `.sha256` does not match while the `.sha1`, else the `.md5`,
of the same repository does is used under any policy, with a
`SHA256_FILE_MISMATCH` warning naming the repository, the file and the
checksum file that matched. Those are the files Maven checks by default,
so `mvn` builds with it too. Central's snapshot repository serves a stale
`.sha256` of `maven-metadata.xml` for publishers that deploy only `.sha1`
and `.md5` files, Maven's default, and some mirrors, such as
maven.aliyun.com, serve wrong `.sha256` files for POMs and jars whose
bytes and `.sha1` match Central's. A repository's checksum files guard
against a broken download from it, which a matching one rules out;
`raeva.lock` pins the SHA-256 raeva computes of the bytes, and from then
on the pin, not the checksum files, decides, in `--frozen` and
`lock verify` too. When no checksum file matches, the `.sha256` mismatch
is the error.

A jar or other artifact whose response carries a SHA-1 that matches its
bytes is used whatever its checksum files say, as maven-resolver does:
`X-Checksum-SHA1`, which Central sends, else
`x-goog-meta-checksum-sha1` from Central's Google mirror, else a Nexus 2
`ETag` of `{SHA1{<hex>}}`. Central serves stale `.sha1` and `.md5` files
for `com.anji-plus:captcha:1.4.0`. A header that does not match fails
the file as a broken transfer would (exit 9), whatever its checksum files
say, as in Maven. POMs and metadata are still checked against their
checksum files.

When `maven-metadata.xml` does not match, `raeva` downloads both again
before it reads the `.sha1`. If no checksum file matches, the default
`warn` policy keeps the metadata and warns `METADATA_CHECKSUM_MISMATCH`.
`fail` rejects it.
`ignore` acts as `warn` for metadata. Set `releases-checksum-policy` and
`snapshots-checksum-policy` in `raeva.toml`, or `<checksumPolicy>` in a POM
or `settings.xml`. Any other value, such as `FAIL` or an empty element,
refuses every download from that repository for the versions it covers, as
in Maven (exit 3).

An artifact or POM that no checksum file matches always fails, whatever
the policy. `raeva.lock` pins those
hashes, and a sync that resolves again fails (exit 7) when it finds other
bytes for a release file or timestamped SNAPSHOT build the lock pins,
whichever repository serves it. This check precedes POM parsing and storage,
including parents, imported BOMs and relocation POMs. `raeva sync --update`
can lock new bytes for a republished file or select a newer SNAPSHOT build.
Restoration also checks pinned POMs before caching or storing them. Rejected
downloads are not cached for another project using the same home. Non-unique
`-SNAPSHOT` filenames remain mutable.
