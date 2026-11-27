# Is raeva for my project?

Raeva adds a dependency lock check to a Maven build. It reads XML POMs,
resolves external dependencies, and pins artifacts, POMs, parents, and
imported BOMs by SHA-256 in `raeva.lock`. It supports single-module projects
and multi-module reactors. Run it at the reactor root.

`raeva --offline doctor` lists what raeva sees in the project, from local
files only: build extensions, Maven Polyglot, `.mvn/maven.config` options
it ignores, the Maven mode, a replaced Maven Central URL, whether the lock
pins the plugins, the platforms the lock records, whether CI runs the lock
check, and how `.gitattributes` treats `raeva.lock`. It prints the CI command and the `.gitattributes` line
when they are missing, and changes no file.

Start with `raeva sync`, commit the lock, and run `raeva sync --frozen`
beside the existing Maven build. POM changes that alter dependencies need
a lock update. A reactor version bump alone does not. For a JDK matrix,
list its versions in `[lock] jdks` in `raeva.toml` before writing the lock.
See [Configuration](configuration.md).

## What the lock does not control

Maven does not read `raeva.lock`. A frozen check validates the lock and
restores its files into raeva's store; an ordinary online Maven build still
resolves dependencies itself. To build with the pinned files, export them
to an isolated Maven repository and build offline. See
[Offline builds](offline-builds.md).

The lock includes build plugins, plugin dependencies and Maven extensions
only when `[plugins] lock = true` in `raeva.toml` asks for them, except the
build extension jars of a module that resolves a dependency type Maven's
core does not define,
and what
plugins fetch
while they run only from a traced build ([Locked
plugins](offline-builds.md#locked-plugins)). A Maven extension that checks
plain `mvn` builds against the lock is designed, not built ([Maven-side
enforcement](design/maven-enforcement.md)).

Raeva does not support Maven's `-pl` or `-am` project selection. It resolves
the complete active reactor. Polyglot POMs and extensions that change the
Maven model are not supported. A project that depends on those features
needs a different lock workflow.

Raeva follows the resolution rules of Maven 3.9, or 3.10 when the project
selects it. It runs build plugins only for a `[plugins] trace` build, and
does not claim compatibility with every Maven extension. The [verification
page](verification.md) lists the tested projects and known differences.

## Where raeva refuses and Maven builds

Where raeva cannot tell what Maven resolves, the sync fails instead of
writing a lock that may differ. The error names the cause and the fix,
where there is one. The main groups, all exit 3 unless noted:

- mavenrc files that run longer than 120 seconds, exit, leave the shell
  in another directory, or change `IFS`: fix the file, or run both raeva
  and `mvn` with `MAVEN_SKIP_RC=1` ([Configuration](configuration.md#configuration)).
- A Maven user home raeva cannot tell, such as a `-Duser.home` that
  takes `${...}` or that a JVM option sets in a way raeva does not read:
  pass `-Duser.home=<dir>` on the command line of both raeva and `mvn`.
  A non-ASCII home or settings path needs a UTF-8 locale.
- Options that pick files or projects raeva does not read: `-gs` or `-f`
  in `MAVEN_ARGS` or `.mvn/maven.config`, `-itr` in `MAVEN_ARGS`, and other options in
  `MAVEN_CONFIG` that a Maven Wrapper script passes: take them out, or
  unset `MAVEN_CONFIG` ([Maven options](configuration.md#maven-options)).
- A reactor selection (`-pl`, `-am`, `-amd`, `-rf` or `-N`) in
  `MAVEN_ARGS`, `.mvn/maven.config`, or a `MAVEN_CONFIG` a Maven Wrapper
  script passes, with `[plugins] trace` set: every `raeva sync` that is
  neither `--frozen` nor offline fails, even one that finds raeva.lock up
  to date, as the trace build would not build the whole reactor. Take it
  out where raeva traces.
  Otherwise raeva ignores it and locks the whole reactor.
- A JVM option raeva cannot read exactly, such as a `MAVEN_OPTS` pattern
  the shell may expand or an OpenJ9 JDK's option variables, fails only
  what reads the name it may set: pass that `-D` on the command line of
  both.
- A system property raeva does not know, or one that differs between the
  JDKs or platforms the lock covers, where a profile or a value reads it:
  set it with `-D`, or narrow `[lock] jdks`
  ([The JDK version](configuration.md#the-jdk-version)).
- A POM's `${env.NAME}` of a variable that is set but hidden, where it
  would change the lock: list the name in `[security]
  allow_env_substitution` ([Security](configuration.md#security)).
- A parent or BOM that Maven may read from a repository raeva does not
  read, ahead of the one that holds it: allow that repository with
  `[security] transitive_repository_allowlist` in `config.toml`, or
  declare it in the project POM
  ([Repositories and mirrors](configuration.md#repositories-and-mirrors)).
- One repository id that lists different versions at two URLs, which
  Maven reads in build order (exit 5): give the repositories distinct ids
  ([Repository ids](offline-builds.md#repository-ids)).
- A secret-named value in a repository URL or id: give the URL to a
  `<mirror>`, or rename the input when it is not a secret.
- A dependency type whose handler a build extension defines in code raeva
  does not read, such as a getter that computes its value, that two jars
  Maven loads for one extension define differently, or whose handler reads
  a class two of those jars hold with different bytes, as raeva does not
  follow the order Maven loads them in. Also a type Maven's core defines,
  such as `war`, that an extension whose handlers raeva reads defines
  otherwise, as Maven may take either handler. There is no workaround but
  not depending on the type.
- A SNAPSHOT jar Maven loads for a build extension whose handlers raeva
  reads, when its metadata names another build for its POM than for the
  jar: deploy the jar and its POM again as one build.
- A `[plugins] trace` launcher that reads the mavenrc files its own way,
  or mavenrc files that give a value anew each time they run, such as a
  JVM option, or on Windows a token they fetch: set the value in the
  environment and have the files keep it rather than make it again, or run
  both with `MAVEN_SKIP_RC=1`
  ([Java4Shell](ci.md#java4shell)).
- With `[plugins] trace`, an argument file or `-Duser.home` given by a
  relative path while raeva runs outside the project directory: run raeva
  in the project directory.

## Before adding a required CI check

Check the JDKs, active profiles, settings, and resolution properties used
by the build. Pass the same settings to raeva. Commit lock updates with
POM updates, including dependency-bot changes. Start setup-raeva with its
report-only lock check, then make it blocking once that update path works.

SNAPSHOTs and version ranges need deliberate updates. Use `raeva sync
--update` to check for newer resolutions; `--frozen` restores existing
pins. A private registry must retain those files for as long as the lock
needs them.

Vulnerability reports query OSV with dependency coordinates. SBOMs and VEX
statements describe dependency evidence and assessments. See [Vulnerability scans and
SBOMs](vulnerabilities-and-sboms.md).

## Remove raeva

Remove the raeva steps and jobs from CI, including any relock or scheduled
drift workflow. Delete `raeva.lock`, project `raeva.toml`, and any raeva
entry in `.gitattributes`. Remove an `rv` alias if you added one. Uninstall
the binary with the package manager that installed it, or remove the
standalone executable from your installation directory.

If you used `export-m2`, remove the isolated repository you created for it
and restore the Maven command's original repository options. Keep a shared
`~/.m2/repository`: it may hold artifacts from other builds.

Raeva's cache and configuration can remain without affecting Maven. To
reclaim the space, remove the store and configuration directories you chose
under `RAEVA_HOME`, or their default locations listed in
[Configuration](configuration.md#file-locations). Check whether other
projects share that store before deleting it.
