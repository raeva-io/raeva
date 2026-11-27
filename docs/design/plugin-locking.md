# Plugin locking

Status: raeva 0.6 writes the plugin tables of [Lock schema 10](#lock-schema-10)
when `[plugins] lock = true` in `raeva.toml` asks for them.

The goal: `raeva sync` pins every file a Maven 3.9 build of the project reads
from a repository, plugins included, so that `raeva export-m2` fills an empty
local repository from which `mvn -o` builds with the network off.

## What Maven 3.9.12 resolves for a build

In the order Maven reads it. "Repositories" is where each piece comes from.

1. **Core extensions** (`.mvn/extensions.xml`), before any project is read.
   - Each `<extension>` is collected as a plugin is (below), from the
     plugin repositories of the settings and central, not of any POM.
   - Coordinates expand `${...}` from user and system properties only.
   - Artifacts Maven's core exports are filtered from the result: their POMs
     are read, their jars are not downloaded. Only core extensions are
     filtered so; a build extension downloads them too.
2. **The project model.** Parents, imported BOMs and the super POM, as for
   dependency resolution. The plugin sections are merged in the same pass:
   - per POM, a repeated `<plugin>` is merged into the first
     (`DefaultModelNormalizer`);
   - each active profile's plugins and managed plugins are merged over the
     POM's, its `<pluginRepositories>` put first (`ProfileModelMerger`);
     activation is the dependency side's, and a presence check of a
     property every JVM sets (`user.home`) holds (commons-parent's
     `parse-target-version` profile binds build-helper that way);
   - inheritance (`InheritanceModelMerger`): a parent plugin with
     `<inherited>false</inherited>` is dropped unless it has executions;
     with them it is kept, coordinates, version and dependencies included,
     with only the executions marked inherited (possibly none) and no
     configuration; the
     child's plugins are placed before the first parent plugin they share,
     the rest after; plugin dependencies merge child first; extensions are
     keyed by `groupId:artifactId`; plugin repositories child first;
   - the super POM, merged into the topmost ancestor first, adds four managed
     plugins (antrun, assembly, dependency, release; Maven 3.10's adds none)
     and the `central` plugin repository with snapshots off;
   - after interpolation (configuration included, unresolved expressions left
     as written): plugin management is merged into `<build><plugins>`
     (managed executions first), then the default lifecycle bindings of the
     packaging (below; their executions come before the declared and managed
     ones), then each execution's configuration is merged over its plugin's
     (`Xpp3Dom` merge with `combine.children` and `combine.self`);
   - `<reporting>` (not read by raeva yet) adds `maven-site-plugin` to plugin
     management (`DefaultReportingConverter`).
3. **Build extensions**, when the project is built: each `<build><extensions>`
   entry and each plugin with `<extensions>true</extensions>`, in that order,
   collected as plugins from the plugin repositories. They can define new
   packagings and lifecycles (for example `bundle`), so the bindings of such a
   packaging are known only by loading the extension. A version-less
   `<build><extensions>` entry takes its version from the metadata only. An
   extension whose `META-INF/maven/extension.xml` lists `exportedArtifacts`
   filters them out of every plugin closure of that module. Their
   `ArtifactHandler` components also define dependency types, which the
   project's dependency resolution reads (below), plugin locking or not.
4. **Plugin versions and prefixes.**
   - A plugin without a version takes the one in `<build><plugins>`, then in
     plugin management, then from the plugin repositories' metadata: its
     `<release>`, else `<latest>`, else the `<versions>` from the newest
     down, the first that passes the prerequisites check. The check reads
     the candidate's jar (`requiredJavaVersion` in `plugin.xml`, against
     the `[lock] jdks` target, else the host JDK, whose version the tables
     then record) and POM (`<prerequisites>`), each in the version order
     of the line's resolver, and passes over a candidate whose POM does not
     build. A jar without a `plugin.xml` naming its coordinates passes
     unchecked, and Maven 3.9.12 and 3.10.0 do not read the
     `requiredMavenVersion` of `plugin.xml`:
     netty downloads `maven-install-plugin` 4.0.0-beta-3, -2 and -1, POMs and
     jars, before taking 3.2.0.
   - A goal given by prefix (`javadoc:javadoc`, or the root project's
     `<defaultGoal>`; a module's is not read) first resolves the version of
     every version-less declared and managed plugin, then reads the group
     metadata (`<groupId>/maven-metadata-<repo>.xml`) of the `pluginGroups`
     (settings.xml's, then `org.apache.maven.plugins` and `org.codehaus.mojo`;
     a changed list resolves the plugin tables again) and of every group of a declared or managed plugin, accepting from the
     latter only a plugin the project names. With no match, also offline,
     Maven loads the descriptor of each declared plugin, then each managed
     one, until a prefix matches, warning for each it cannot load. Maven
     3.10.0 loads the descriptors first, those of the declared and managed
     plugins whose artifactId holds the prefix, then the other declared
     ones, and reads the group metadata only when none matches.
   - A mojo with `@Execute` forks a lifecycle or goal; its descriptor names
     it. raeva does not follow the fork, so only a trace pins the plugins it
     runs.
5. **The default lifecycle bindings** (maven-core 3.9.12
   `default-bindings.xml`, `components.xml`): clean 3.2.0, resources 3.3.1,
   compiler 3.13.0, surefire 3.2.5, jar 3.4.1, install and deploy 3.1.2,
   site 3.12.1, and ejb 3.2.1, war 3.4.0, ear 3.3.0, rar 3.0.0 and
   plugin-plugin 3.13.1 for their packagings. Under `[lock] maven = "3.10"`
   they are maven-core 3.10.0's: clean 3.5.0, resources 3.5.0, compiler
   3.16.0, surefire 3.6.0, jar 3.5.1, install and deploy 3.2.0, site 3.22.0,
   ejb 3.3.0, war 3.5.1, ear 3.4.0, rar 3.1.0 and plugin-plugin 3.16.0. A declared plugin of the same
   key wins, and takes the default version only when it has none.
6. **Plugin closures** (`DefaultPluginDependenciesResolver`), for each plugin
   whose mojo is in the build plan, and for every plugin with an execution
   without `<phase>`, whose descriptor Maven loads to find the phase:
   - the root is the plugin artifact; the plugin's own `<dependencies>` come
     first, at `runtime` scope (unless `system`), then its POM's except
     `test`, `provided` and those of the same key, so the plugin's own win
     depth ties too (petclinic: checkstyle 12.3.1 brings
     `doxia-module-xdoc` 1.12.0, not the plugin's 2.0.0);
   - the plugin POM's dependency management manages depth 2 and below; the
     plugin's own `<dependencies>` at depth 1 are not managed; direct
     optional dependencies are kept; `WagonExcluder` drops
     `org.apache.maven.wagon:wagon-*` below `org.apache.maven:maven-*` 2.x;
   - from the project's plugin repositories (and repositories the closure's
     POMs declare), through the settings mirrors;
   - the collector reads the POM of every version it meets, losers of
     mediation included, and their parents, and expands the losers'
     subtrees as well, reading those POMs too. Offline, a POM missing there
     is a warning ("The POM for ... is missing"), not a failure.
7. **Execution-time resolution**: what a mojo resolves while it runs, through
   Maven's repository system or its own code. This is not in any model.
   - surefire and failsafe resolve their test framework provider
     (`surefire-junit-platform`, `common-java5`) from the test classpath;
   - the compiler resolves `annotationProcessorPaths` from the project
     repositories as its version does: before 3.9.0 one legacy request
     rooted at the first path, whose POM's dependencies, optional ones too,
     and management count; 3.9.0 to 3.10.1 each path alone the same way;
     3.11 and later all paths in one collection, a missing version from the
     project's dependency management entry of the same type and classifier
     and, with `annotationProcessorPathsUseDepMgmt`, that management below
     the paths (3.12 and later); each execution that runs `compile` or
     `testCompile` resolves its own paths with its own setting, so each is
     a set of its own; a path the reactor builds gives its POM from the
     reactor, and its dependencies are collected by the same rule, not as
     that module's own graph holds them;
   - comparison and report plugins resolve other versions of the project
     (japicmp, bnd-baseline, revapi), skins and site descriptors
     (`commons-skin`, `*-site.xml`), Checkstyle and PMD rule artifacts,
     SpotBugs plugins, the project graph again without its management
     (commons-io: `byte-buddy` 1.12.19 below `mockito-inline`), and version
     ranges through metadata;
   - Spotless resolves its formatter (`palantir-java-format`,
     `google-java-format`) and sortpom its sorter; Quarkus' build resolves
     the application's deployment artifacts through its own bootstrap
     resolver; Karaf's plugin downloads a distribution zip;
   - toolchains select a local JDK and resolve nothing.

What a build needs is set by the goals and profiles it runs with: `verify`
needs no install, deploy or site plugin; `-Prun-its` adds the invoker's
closure. A plugin or extension a reactor module builds comes from the
reactor, not a repository.

## What raeva can lock statically

| Mechanism | Static? | How |
|---|---|---|
| Lifecycle defaults per packaging | yes | table in `rv-maven-model` (`default_lifecycle_bindings`) |
| `<build><plugins>`, plugin management, inheritance, profiles | yes | `Project::plugins()`, Maven's merge order (tests against `help:effective-pom`) |
| Plugin `<dependencies>` and plugin repositories | yes | plugin closure with the solver, plugin repositories as its root repositories |
| `<build><extensions>`, `extensions=true` | yes | same closure; the lifecycle mapping of a packaging they define is read from their `META-INF/plexus/components.xml` |
| `.mvn/extensions.xml` | yes | `parse_core_extensions`, closure from the plugin repositories of the `<activeProfiles>` settings profiles and central; core exports filtered |
| `annotationProcessorPaths` | yes | read from the effective compiler configuration, resolved as dependencies from the project repositories |
| Version-less plugins | yes, pinned | metadata resolution with the prerequisites check at sync time, for the Maven version in use; the version pinned, the metadata written by the export; none of the gate projects declares one, but netty's `jlink` packaging binds a version-less install plugin |
| Version ranges in a plugin closure | yes, pinned | the solver resolves them; the export writes metadata listing only the locked version (petclinic: git-commit-id's `bcutil-jdk18on [1.81,1.82)`) |
| Prefix goals and `<defaultGoal>` | partly | needs the goals: from `<defaultGoal>`, from a configured goal list, or every managed plugin |
| Execution-time resolution | no | trace (below) |

Execution-time artifacts come from two sources:

- **A static rule for the test framework provider.** Surefire and
  Failsafe 3 pick a provider for each execution that runs the tests,
  from the module's test class path and that execution's configuration,
  as `AbstractSurefireMojo` does (JUnit Platform when
  `junit-platform-commons` is on it, then TestNG, JUnit 4.7 with
  `parallel` or groups, JUnit 4, JUnit 3), and resolve each piece as
  `SurefireDependencyResolver` does: a root-less request at `runtime`, the
  provider from the plugin repositories, the Jupiter or Vintage engine and
  the launcher aligned to the platform version from the project's. From
  Surefire 3.6 the JUnit Platform provider is the only one: it also runs
  JUnit 4 tests, with the Vintage engine at the Jupiter API's version or
  Surefire's built-in default without one, and TestNG tests with
  `testng-engine`; an execution whose `junit` property is false adds no
  engine. A provider declared among the plugin's dependencies is resolved
  as Surefire resolves it: a declared JUnit Platform provider with the
  engines above, before 3.6 another known one at the plugin's version, and
  otherwise each declared dependency on its own. Where Surefire fails the
  run, the lock holds what it resolved first: nothing with a TestNG below
  6.14.3 (4.7 before 3.6) or, from 3.6, with JUnit below 4.12 alone, and
  only the provider, the plugin's dependencies and the Jupiter engine with
  JUnit 4.0 to 4.11 beside another framework, unless a plugin dependency
  brings the platform engine. The class path comes from
  the module's rows in raeva.lock.
- **A trace for the rest.** The build runs once, online, with the goals the
  lock is for, on a local repository that `export-m2` filled from the
  static tables. Each file Maven adds that a remote repository served (its
  `_remote.repositories` names one) is fetched again through raeva's
  client, its bytes compared with Maven's, and pinned by SHA-256 in a
  `trace` set. The set's key covers the build's launcher and arguments
  and every static set key, so a changed plugin, plugin dependency or repository makes the
  trace stale, and `--frozen` refuses a stale one. A failed build fails the
  trace. Attribution to one plugin through `.tracking` was dropped: one
  key for the whole trace is coarser but cannot keep a file a changed
  plugin no longer reads.

The trace runs the build, so only a plain online `sync` of a project whose
`raeva.toml` sets `[plugins] trace` runs it, never `--frozen`, `--offline`,
`lock verify` or `export-m2`.

### Unpicked-dependency POMs

Maven 3.9 collects depth first and builds the whole dirty tree before it
mediates, so it reads the POM of every candidate: losers, every version a
range accepts, and everything below them. raeva collects a plugin set the
same way and pins what it read as the set's support POMs. A module pins the
POMs of its losing nodes at the versions their declarations named; a version
a range lists is read offline only where the export lists it. A POM no
repository serves is left out, as Maven leaves it with a warning.

### Opting in

The tables are written only when `[plugins] lock = true` in `raeva.toml`
asks for them, so a lock without them keeps its bytes. The settings are
committed with the project, so every machine and CI job locks alike: a
plain `sync` keeps tables whose `inputs` digest matches and resolves the
others again, and puts the files they pin in the store; `--frozen` refuses
stale tables, tables a resolution of the same inputs does not give, and
tables `raeva.toml` does not ask for, and fetches each file against its
pin. Without `[plugins]`, a sync drops the tables and the rows only they
use.

## Rejected alternatives

- **Lock only what a trace downloads.** Exact for one goal list and one host,
  but a trace runs the build (tests, network, minutes), cannot run in
  `--frozen` CI without the network, and attributes files only through
  Maven's tracking. The static set covers 93 to 98 percent of the files the
  gate builds read (Quarkus 89), and most of the rest are
  POMs Maven reads only to warn about; the trace is for the execution-time
  jars.
- **Put plugin closures into the project graph.** Each plugin is its own
  resolution root with its own mediation and management, so one
  `groupId:artifactId` resolves to different versions in different plugins
  (commons-io: seven `plexus-utils` versions). Merging them would change the
  project's graph and lock bytes.

## Lock schema 10

The plugin tables are a `[platforms.plugins]` table of each platform. Their
files are ordinary rows of the platform's `artifacts` and `support_poms`, so
every check raeva.lock makes of a row (path collisions, POM digests, origins,
secrets) covers them, and the export writes them with the dependencies. A
row only plugin sets name is no orphan; `LockPlatform::remove_plugins`
drops the tables and those rows, which is the view the dependency
resolution, its `--frozen` comparison and lock diff's dependency lines read.

```toml
[platforms.plugins]
inputs = "..."                 # SHA-256 of what the tables were resolved from
host_inputs = ["env.CI", "jdk:[21,) is true"]   # what the plugin models read from the host
prefixes = "org.apache.maven.plugins\tclean\tmaven-clean-plugin\thttps://repo.maven.apache.org/maven2"
repo_ids = "https://repo.maven.apache.org/maven2\tcentral"
metadata_versions = "org.example:ext\trelease\t1.2"   # versions taken from repository metadata
range_versions = "org.example:util\t2.1\thttps://repo.maven.apache.org/maven2/"   # a range's pick and each origin that listed it
shared_origins = "org.example:util:1.0\tjar\thttps://plugins.example/"   # where a set read a row the modules use
shared_without_pom = "org.example:util:1.0\tjar\thttps://plugins.example/"   # of those, where it found no POM

[[platforms.plugins.sets]]     # one per distinct set, sorted by key
key = "sha256:..."             # of role, coordinates, plugin <dependencies>, repo_urls
role = "plugin"                # plugin | build-extension | core-extension | processor-path | test-provider | trace
coordinates = ["org.apache.maven.plugins:maven-compiler-plugin:3.13.0"]
repo_urls = ["https://repo.maven.apache.org/maven2"]   # in Maven's order
artifacts = "org.codehaus.plexus:plexus-utils:4.0.3\tjar"   # class path rows, in order
support_poms = "org.codehaus.plexus:plexus-utils:3.0.24"     # parents, BOMs, losers, their subtrees
modules = "pom.xml\ncore/pom.xml"
```

- A coordinate can be a winner in one set and a loser in another: a set
  lists the jars it uses in `artifacts` and the POMs it only reads in
  `support_poms`, so no row carries a per-set flag.
- `inputs` covers the Maven version the tables follow, `config_hash`, the
  Maven line, the platform's `model_hash`, `.mvn/extensions.xml`, the
  goals, each module's packages, and the current value of each
  `host_inputs` entry.
- `host_inputs` names what the plugin resolution read from the host, as
  `[resolution] ambient_inputs` does for the dependencies: an environment
  variable, a system, settings or user property, `.mvn/extensions.xml`'s
  included, or a profile condition of a profile that changes the plugins. A plugin `<configuration>` is read by
  the mojo, so its reads are left out, apart from the compiler plugin's
  `annotationProcessorPaths` and Surefire's and Failsafe's `parallel`,
  `groups`, `excludedGroups` and `properties`, which change what resolves; so are those of a managed plugin the build
  does not run, unless a goal on the command line looks up a prefix or a
  managed plugin. The lock holds the names only, never the values.
- A `trace` set holds what a traced build's mojos resolved. Its key covers
  the build's arguments and the other sets' keys; it records no
  coordinates, since the arguments may hold a secret.
- A row the modules use keeps the origins their graph digests cover. When
  a set read its file from another repository, `shared_origins` records
  that origin, and the export labels the file with both ids: `mvn -o`
  takes a plugin's file only under a repository the plugin searches.
- A POM goes only to the builds that read it, since `mvn -o` adds its
  dependencies. A row whose POM some of its repositories lack lists those
  that served it in `pom_repo_urls`. In the Maven 3.10 mode, a POM the
  plugins read for a file the modules read without one is a support POM
  under a repository each set that reads it searches, by URL or id. A sync refuses (exit 5) a POM no
  one such repository serves. A plugin's file from a repository that
  served it without the POM the modules' row pins is recorded in
  `shared_without_pom` in the Maven 3.10 mode, and the export labels the
  file with it and the POM only with the row's origins, so `mvn -o` reads
  no POM for the plugin, as Maven 3.10 does online.
- Maven 3.9 keeps one descriptor per artifact for the session (the
  resolver's `DataPool`), a reading without a POM, a losing version's and
  a range candidate's included, which the modules' dependencies, every
  build plugin's realm, every build extension's and every plugin with
  `<extensions>true</extensions>` take from whichever reads it first. A
  later reader of another file of the version, a tests jar or a
  `type=pom` dependency, takes the POM the first put in the local
  repository. An extension's realm is built with the projects, before the
  reactor serves its modules, so a module collected after it gets the
  extension's reading, a reactor module's coordinate too, and a plugin run
  after the modules gets theirs. The build's order, `-T` and `-pl` decide
  what each gets, so with `[plugins] lock = true` the 3.9 mode refuses
  (exit 5), naming the coordinate and the readers:
  - a file any module or set but a core extension reads without a POM,
    whatever read it: a winner, a losing version, a range's candidate or
    a relocation's target. The modules' reads come from the resolution of
    the same run, which a plugin table resolved again therefore repeats. A
    `--frozen` run, and a sync that checks tables it keeps, take them as
    raeva.lock records them, which holds no losing version's read: a lock
    a sync wrote has none without a POM;
  - a version the modules read one way and a set another, or two sets two
    ways: with and without a POM, an empty one too, or with other bytes,
    for any two of its files, as a row or as a parent, a BOM, a losing
    version's or a range candidate's POM. This check runs first, so a reader without a POM beside
    one with it is named by both. A core extension resolves in a session
    of its own, so only its POM's bytes are compared, as the local
    repository is shared;
  - a build extension's or an `<extensions>true</extensions>` plugin's
    read of a reactor module's coordinate from a repository;
  - a reactor module a plugin reaches neither as a dependency the project
    declares for it nor below another reactor module: Maven orders the
    reactor by those alone, so the module may build after the plugin runs,
    which then reads its POM from the reactor and its jar from a
    repository.

  Declare a repository that serves the POM for every reader, declare the
  reactor module as the plugin's dependency, or resolve as Maven 3.10
  does, which reads each apart. The refusal does not track which reads
  Maven caches: some of these shapes Maven 3.9.12 builds the same in any
  order, such as a module's read without a POM no plugin reads.
- In either mode, two POMs of one version, or the modules' or a set's POM
  for one file and none for the other's other file of it, are refused
  (exit 5) by both readers: a local repository holds one POM per
  version, so raeva.lock cannot record both.
- A `--frozen` run takes a release row, prefix or support POM recorded
  under another declared repository, as a `mirrorOf *` mirror records it,
  while the pins agree and the same sets read each file and POM there.
- `repo_ids` are labels for the export's markers. A sync fetches from a
  recorded origin only as the configuration or the project's POMs declare
  it, and from any other as a fetched POM's repository: no credential by
  id, no private address, HTTP(S) only.

## Freshness

- The tables' `inputs` digest covers `config_hash` and the platform's
  `model_hash`, so any POM, profile or configuration change that makes the
  dependencies stale makes the tables stale too, as do `.mvn/extensions.xml`,
  the goals and a changed dependency set (test frameworks pick Surefire's
  providers). So does another value of a `host_inputs` entry, such as the
  JDK a `${java.version}` plugin version reads, a JDK whose profile adds a
  plugin, or a `-D` value `.mvn/extensions.xml` reads. An unused `-D` does
  not.
- A `sync` keeps a platform's one trace set while its key is current and
  drops any other. With `[plugins] trace` set, a plain online sync traces
  again when no platform of the host's OS and architecture holds a current
  one, on the platform of the host's JDK, which serves the other JDKs of
  that OS and architecture. `sync --frozen` refuses a lock without a
  current trace for the host, or with a trace of other settings or that
  `raeva.toml` does not name. Without it, a sync drops the trace.
- A `--frozen` run fails on stale tables, and on tables a resolution of the
  same inputs does not give. Remote files are checked against the pins as
  for dependencies.

## Export layout

`export-m2` writes the plugin artifacts, their support POMs and traced
files (jars and their POMs) into the same local repository as the dependencies,
with `_remote.repositories` markers naming the id Maven will look them up
under: the mirror's when the settings mirror the repository, computed from
`repo_url` at export time. A marker naming `central` for a mirrored build is
refused offline ("present, but unavailable").

Metadata is written, never copied from upstream: per `(group, artifact,
repository id)` one `maven-metadata-<id>.xml` listing the locked versions of
dependencies and plugins together, with `<release>` and `<latest>` set to the
locked plugin version for a version-less plugin, so `mvn -o` neither tries a
newer candidate (netty's 4.0.0 betas) nor picks one under another Maven; and
per group a group metadata file with the locked plugins' prefixes only.

The losers' subtree POMs keep `mvn -o` free of "The POM for ... is
missing" warnings. Files the dependency and plugin sets share are written
once; their bytes are equal by construction (same pin), and a mismatch is an
error.

## Hard parts

- **Execution-time resolution** has no static source and is where the
  remaining gaps are.
- **Goals are an input.** `<defaultGoal>`, prefixes on the command line and
  `-P` decide which plugins run; locking every managed plugin is the safe
  default and costs download time (commons-io manages 20 plugins its build
  does not declare, one of them `javadoc`, which its `<defaultGoal>` runs as
  `javadoc:javadoc`).
- **Plugin version resolution** for version-less plugins depends on the
  running Maven version (prerequisites); the pin must record it.
- **Extension-defined packagings** (`bundle`, `quarkus`, netty's `jlink` and
  `feature`) bind plugins only the extension knows; raeva reads them from
  the extension jar's `META-INF/plexus/components.xml`.
- **Extension-defined dependency types.** Maven looks each dependency's
  `<type>` up in the artifact handlers the project realm sees, its build
  extensions' included, for the file's extension and classifier and whether
  the collector walks its dependencies (`includesDependencies`). Jenkins'
  plugin parent declares `jenkins-war` as `executable-war`, which
  maven-hpi-plugin maps to the `.war` with its dependencies walked. When a
  module's resolution meets a type no core handler defines, raeva reads the
  handlers of each build extension's own jar: the `components.xml`
  components, and the Sisu `@Named` classes whose constructor only passes
  constants to `DefaultArtifactHandler` and its setters. A handler in other
  code is refused when its type is met. The first definition of a type
  counts; a core type keeps its core handler. The module's `extensions`
  lines pin each jar raeva read: Maven loads every build extension, and
  which one's handler counts depends on all of them. A seed carries the
  release jars among these pins, so a home that restored it passes
  `raeva --offline sync --frozen` without plugin locking too. What decides
  the extensions is an input of the graph: a host value their coordinates or plugin
  repositories read (a `-D`, `.mvn/jvm.config`, settings.xml or
  environment value), and the condition of a profile that adds an
  extension plugin or sets the version of one. A plugin's dependencies,
  the compiler's processor path and Surefire's provider pieces take the
  same handlers, as Maven resolves them in the project's build; their handlers are part of the set key. The
  compiler (3.11 and later) gives the resolver a processor path by its
  type's extension alone: no classifier the type implies, and its
  dependencies walked, so a `test-jar` path is the plain jar; before 3.11
  the legacy resolver walks none for a type whose handler includes them,
  such as `war`. Not modeled: handlers in the extension's dependencies or
  in `.mvn/extensions.xml`, and Maven's cache of a handler across the
  projects of one build.
- **Reactor modules on a plugin path.** log4j2 puts its own `log4j-core` on
  the compiler's processor path; it comes from the reactor, and only its
  dependencies need locking. A plugin or extension built by the reactor is
  the same case.
- **Cost.** Keeping each POM's text to read its plugin sections costs about
  5 percent of a warm resolve, so a sync reads them only when it locks
  plugins.
