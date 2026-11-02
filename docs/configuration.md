# Configuration

Raeva reads dependencies only from `pom.xml`. Settings live in two optional
TOML files with the same format: the project `raeva.toml` next to the root
`pom.xml`, and the user `config.toml`. Neither file can declare dependencies.
Raeva also reads `~/.m2/settings.xml`, or the file `-s` names, for mirrors,
proxies, servers, profiles (their repositories and properties), and
`<localRepository>`.

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

`metadata.db` only speeds up fetches. Delete it, with its `-wal` and `-shm`
files, while no `raeva` is running.
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
concurrency = 8 # files at once per stage, POMs of range versions 4 times that; 0 counts as 1, at most 128
low_speed_limit = 1024
low_speed_time = 30

[lock]
jdks = ["17", "21"]

[security]
allow_env_substitution = ["BUILD_NUMBER"]
transitive_repository_allowlist = ["https://repo.example/"]
allow_transitive_repositories = false
```

Search order is the project `raeva.toml`, then the user `config.toml`, then
`settings.xml`, then repositories the project's POMs declare, child before
parent. When an earlier file defines a repository `id`, a later file only
fills fields it left unset. A mirror whose `mirror_of` is exactly the
repository id wins, then the first entry whose patterns match. Patterns
match as Maven 3.9 matches `<mirrorOf>`: the `mirror_of` entries join with
`,`, the first `id` or `!id` naming the repository decides, otherwise `*`,
`external:*` or `external:http:*` matches, and entries are not trimmed. A
settings.xml mirror serves only the `<mirrorOfLayouts>` it lists
(`default,legacy` when unset), and Raeva reads the `default` layout. A mirror
with `blocked` set to true (settings.xml `<blocked>true</blocked>`) gets no
requests, nor do the repositories it matches. For profiles, `jdks` in `[lock]`,
and each `[network]` key (`timeout`, `retries`, `concurrency`,
`low_speed_limit`, `low_speed_time`), the first file that sets it wins.
`inactive_profiles` is the union of both files (user ids first, then project
ids not already listed); an empty list adds nothing. Only the
`raeva.toml` at the reactor root applies.

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
`The specified user settings file does not exist`; Maven exits 1. Unlike Maven,
raeva ignores `-s` and `-gs` in `.mvn/maven.config`, with a
`SETTING_IGNORED` warning: a settings file brings mirrors, proxies,
credentials, every environment variable and the local repository, which a
cloned project must not choose. Declare the project's repositories in
`raeva.toml`, or pass its settings file with `-s` after reviewing it, as in
`raeva -s <file> sync`. Raeva
reads no global settings file. It ignores `-pl`, `-am` and `-amd` there too,
with the same warning, and locks the whole reactor, so a module the build
skips can still fail the sync. On the command line they are a usage error
(exit 2). `-f` (`--file`) in `.mvn/maven.config`, with
which `mvn` builds another POM, fails the load (exit 3). Everything this
page says about `-D` and `-P` in
`.mvn/maven.config` holds for the command-line options too.

`raeva` searches Maven Central (`central`) last, as Maven's super POM does.
Repositories in `raeva.toml`, `config.toml`, `settings.xml` or the project
POMs add to it. A file an earlier repository serves is not requested from
Central. A version range still reads every repository's metadata, as in
Maven. A repository with id `central`, in any of these, replaces the
default, and a mirror that covers `central` serves its requests.

`<releases>` and `<snapshots>` in `settings.xml` are read as Maven reads
them: a missing or empty `<enabled>` enables, otherwise only `true` (any
case) does, and `${...}` there is not expanded. In a POM, `<enabled>` is
read after interpolation and an empty one disables.

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
`releases-checksum-policy`, and `snapshots-checksum-policy`.

- No repository or mirror URL may contain userinfo, a query, or a fragment,
  in configuration or a project POM (exit 3). The error names the entry, not
  the URL: `raeva.lock` would record it. Use `[[auth]]` or a
  `settings.xml` `<server>`. A dependency POM with such a URL is ignored
  (`REPO_URL_SECRET_REFUSED`).
- A repository URL may not take an input named like a secret (`TOKEN`,
  `SECRET`, `PASS`, `KEY`, `AUTH`, `CREDENTIAL` or `ENTITLEMENT` in its
  name) into its path, where some services put a token, since `raeva.lock`
  records the expanded URL (exit 3): in `settings.xml`, an `${env.NAME}`;
  in a project POM, a `-D` value (command line or `.mvn/maven.config`), an
  active `settings.xml` profile property or an allowlisted `${env.NAME}`
  whose value makes up whole segments of the path, with any `${...}` left
  in it standing for any text. The error names the input, not its value.
  A fetched POM's repository with such a path is ignored
  (`REPO_URL_SECRET_REFUSED`). Give such a URL to a `<mirror>`, whose URL
  the lock does not record. When the value is not a secret, rename the
  input. Keep any other secret out of repository URLs too.
- External HTTP repositories declared by any POM are ignored, as with
  Maven's default HTTP blocker. One the project or its parents declare is
  reported (`HTTP_REPO_BLOCKED`); a dependency POM's only under `-v`, or in
  the error when an artifact is then not found. Configure a matching mirror or declare
  the same URL in `raeva.toml`, user `config.toml`, or `settings.xml` to
  allow it. Configured repositories and HTTP to
  `localhost` or `127.0.0.1` are allowed. The same rule applies when restoring lockfile origins.
- Credential matching: [Authentication](authentication.md#precedence).
- A dependency POM's repositories are not searched (unlike Maven) unless
  `security.transitive_repository_allowlist` covers them (same scheme, host,
  and port, path at or below the entry) or
  `security.allow_transitive_repositories = true`. `--json` lists each
  ignored one as `TRANSITIVE_REPO_DROPPED`, except Maven Central and a
  snapshot-only repository a release declares. A dependency only they have
  fails, and the error names them. An admitted repository serves only the
  declaring POM's own dependencies, their dependencies, and that POM's
  parent and imports, after the other repositories, as in Maven. A
  dependency POM cannot redeclare an id your configuration or the project
  already declares.
- A fetched parent POM's repository is searched, as in Maven. It must be
  HTTP or HTTPS (`FETCHED_POM_REPO_REFUSED` otherwise), and a private address
  needs the allowlist or `allow_transitive_repositories`. Repositories of a
  BOM the project imports get that trust and serve only that BOM's parents
  and imports.
- A project repository URL taken from a fetched parent has that parent's
  trust (`PROJECT_REPO_URL_FROM_FETCHED_POM`).
- Private addresses (loopback, private, link-local, and similar) are allowed
  for a repository your configuration, the project POM, or an in-project
  parent POM names, and only for that origin. Through a proxy, only an IP
  address or a `localhost` name in the URL is screened.
- Only an HTTPS repository your configuration or the project names may
  redirect to another origin, once per request and only to HTTPS. If the
  target goes through a configured proxy, its hostname must name a configured
  repository or mirror origin. Targets that bypass proxies through
  `non_proxy_hosts` or scheme selection use the direct DNS address screen.

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
  with a warning.
- A `non_proxy_hosts` entry matches the whole host, ignoring case. `*`
  matches any run of characters. `.example.com` and `*.example.com` both
  match `example.com` and every host under it. Other regex syntax is literal.
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
  may be public. A POM that reads a set variable not listed here warns
  `ENV_VAR_HIDDEN` with its name, never its value, since Maven would read it,
  unless it is the host path `JAVA_HOME` or `PWD`.
- Every `[security]` key allows more as it grows, so only `config.toml` can
  allow anything. A key the project `raeva.toml` sets can only narrow the
  user value: `allow_env_substitution` and `transitive_repository_allowlist`
  keep the entries the user value also covers, and
  `allow_transitive_repositories` is true only when both set it. A wider
  request is ignored (`PROJECT_SECURITY_WIDENING_IGNORED`). On CI, put the
  allowances in the `config.toml` under `RAEVA_HOME`.

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
| `JAVA_HOME`, `JAVA_VERSION` | The JDK version POMs see ([The JDK version](#the-jdk-version)). `JAVA_HOME` is also `java.home` in profile activation. |
| `NO_COLOR` | No color on stderr. |
| `RUST_LOG` | `tracing` `EnvFilter`, such as `rv_repo=trace`. Overrides `-v`, and logs under `--json` too. |
| `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` | Home directory (`~/.m2`, `${user.home}`) and the Linux directories above. |
| `USERPROFILE` | On Windows, moves the `AppData` folders. |
| `COMPLETE` | `bash`, `zsh`, `fish`, `elvish`, or `powershell`: print that shell's completion script, as in `source <(COMPLETE=bash raeva)`. |

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

`java.version` is `JAVA_VERSION` from the `release` file under `JAVA_HOME`,
else the `JAVA_VERSION` variable, else 17, with a `JAVA_VERSION_DEFAULTED`
warning when a POM reads it. `<jdk>` activation, property conditions,
`.mvn/maven.config`, and `${java.version}` see it.
`-Djava.version` in `.mvn/maven.config` overrides it everywhere. A model's
own `java.version` property overrides it only for `${java.version}` in that
model.

`[lock] jdks = ["17", "21"]` resolves and locks each platform once per listed
JDK version. Each entry sets `java.version` for that section (including
`settings.xml` profile activation), and JDK version reads are not recorded in
`ambient_inputs`. `java.home` and `JAVA_HOME` stay the host's and are still
recorded when read. With `jdks` set, `raeva sync --frozen` passes on any host
JDK whose `java.version` equals an entry or starts with it followed by `.`,
`_`, or `-` (`21` matches `21.0.12.1`, `1.8` matches `1.8.0_442`), and exits 7
on an unlisted JDK. Without `jdks`, a `--frozen` run on a JDK that flips a
recorded `<jdk>` or `java.version` condition exits 7 and names the condition. A plain `raeva sync` on an unlisted JDK warns
`JDK_NOT_LOCKED` and resolves the listed JDKs.

## The target platform

`raeva sync` builds the models for each platform it locks, not for the
machine it runs on. `<os>` activation, `${os.name}`, and `${os.arch}` use
the values a JVM there reports, such as `Linux`, `Mac OS X`, or
`Windows 11`, and `amd64` for x86_64 on Linux and Windows.
`${os.detected.name}`, `${os.detected.arch}`, and
`${os.detected.classifier}` follow the os-maven-plugin (`macos-aarch64`
gives `osx-aarch_64`). `-Dos.name`, `-Dos.arch`, or `-Dos.version` in
`.mvn/maven.config` replace these values. Without `-Dos.version`, an
`<os><version>` condition is inactive.

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
checksum policies), active and inactive profiles, `[lock] jdks`, `[security]`,
effective `-P` selections from both option sources, and the definitions of
`settings.xml` profiles that have an `<activation>`. Only consulted `-D`
lookups count, including names without an override, which the lock lists;
the values of those set are hashed. An unused `-DskipTests` does not make
the lock stale. A later `-D` value for a consulted name does.

A `-s` file counts by its content: its path is not hashed, so CI can keep
it anywhere. `[resolution] command_line` lists consulted `-DNAME` overrides
and explicit `-PID` selections, without values. `ambient_inputs` lists
`user-property:NAME` even when no override was set, so later additions are
checked. When the hash differs, `raeva sync --frozen` exits 7. Diagnostics
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
first repository searched for a file only a later one has. `--frozen`
accepts that when the pinned release bytes agree, and `raeva sync --update`
records the right repository.

### Values from the machine

`raeva.lock` never holds a host value. `[resolution] ambient_inputs` lists
what resolution read from the host, and the hash covers the outcome:

- A profile condition on the JDK version, `java.home`, or an allowlisted
  variable is listed with the POM's text and outcome, such as
  `jdk:[17,) is true` or `property:env.CI=true is false`.
- A `<file>` condition is listed by its path relative to the project, such
  as `file:marker.txt is true`. A file outside the project, or a path
  built from a host value or from a `-D` value written with `${...}`, is
  not tracked: neither `raeva sync` nor `--frozen` notices a change to it,
  so delete `raeva.lock` or run `raeva sync --update` after one. A project
  path over 256 characters fails the sync.
- A `settings.xml` condition is listed as `settings:` and a key of its text,
  such as `settings:3f2a9c0e1b7d4a65 is true`, since the lock does not hold
  your settings. `--frozen` names it by its text where those settings are.
  With `[lock] jdks`, a `<file>` condition is listed once per JDK, since
  its path can name `${java.version}`.
- A value that reaches the model itself (`${java.version}`, `${env.NAME}`,
  a `settings.xml` profile property as `settings-property:NAME`, or the Linux
  release as `os-release`) is listed by name, and its value is hashed.

Only a read that can change resolution is recorded. A profile counts when
it declares dependencies, managed dependencies, repositories, or modules, or
sets a property those read. A profile that only sets build properties, such
as `maven.compiler.release`, is left out. When a profile that changes
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
60 s; the other requests to that host wait out the same window rather than
spend their own retries on it. A `Retry-After` over 60 s fails the request
at once, since asking sooner than the server said cannot succeed. One request's waits add up to at most one
`timeout` per attempt, plus 5 seconds. Each wait prints a line on stderr
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
answers; one that failed otherwise is named by `LISTING_REPO_SKIPPED`.

A download below `low_speed_limit` for `low_speed_time` seconds is retried
on a new connection, up to `retries` times.

## Checksum policy

Each download is checked against the checksum published next to the file:
`.sha256`, else `.sha1`, else `.md5`. SHA-1 and MD5 match Maven. When
`maven-metadata.xml` does not match, `raeva` downloads both again. If they
still disagree, the default `warn` policy keeps the metadata and warns
`METADATA_CHECKSUM_MISMATCH`. `fail` rejects it. `ignore` acts as `warn`
for metadata. Set `releases-checksum-policy` and
`snapshots-checksum-policy` in `raeva.toml`, or `<checksumPolicy>` in a POM
or `settings.xml`. Any other value, such as `FAIL` or an empty element,
refuses every download from that repository for the versions it covers, as
in Maven (exit 3).

An artifact or POM checksum mismatch always fails. `raeva.lock` pins those
hashes, and a sync that resolves again fails (exit 7) when it finds other
bytes for a release file the lock pins. `raeva sync --update` locks them.
