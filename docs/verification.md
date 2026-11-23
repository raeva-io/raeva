# Verified against real projects

Raeva is checked against 48 open-source Maven projects (about 1,300 modules,
including dubbo, netty, quarkus, spring-ai, tika, and langchain4j). It locks
46 of them with no configuration. apache/struts needs a repository that only
a transitive POM declares (see below). flyway reads GitHub Packages, which
asks for credentials, and Maven fails it too without them. Each module's
locked set is compared with `mvn dependency:list` from Maven 3.10.0, except
in OpenFeign/feign, apache/zookeeper and iluwatar/java-design-patterns,
where that Maven run fails at this commit. Every compared module matches. Offline builds are checked by deleting
the locked artifacts from `~/.m2`, running `raeva export-m2`, and building with
`mvn -o`.

Known differences:

- Raeva does not trust repositories that only a transitive POM declares
  (apache/struts needs one). The error lists the repositories Maven would search
  and the `raeva.toml` entries that admit them.
- Maven 3.10 collects dependencies breadth-first (Maven Resolver 2),
  validates the project being built more strictly, and reads POMs from a
  repository under narrower rules (interpolation, profile activation, the
  `fatjar` type). Raeva has a Maven 3.10 mode that does the same, checked
  with constructed graphs against Maven 3.10.0 and 3.9.12
  (`test-fixtures/maven-modes`), and applies when `[lock] maven` or the
  Maven wrapper selects 3.10. The tested projects resolve the same either
  way, but a constructed graph with evictions and relocations can differ. Maven 3.10 with
  `-Daether.dependencyCollector.impl=df` gives the 3.9 result.
- The 3.10 mode looks for `${project.rootDirectory}` no higher than the
  reactor root ([Configuration](configuration.md#maven-line)).
- A version that starts with text, such as `alpha`, `final` or `foo`, equals
  `0` in Maven 3.9 and in raeva's 3.9 mode, and sorts below `0` in Maven
  3.10 (Resolver 2.0.24) and raeva's 3.10 mode. That order is not
  transitive: `alpha` and `beta` both equal `0` but not each other. Raeva
  lists a range's equal spellings in the order of Maven 3.9's hash map, but
  sorts them with another algorithm, so a 3.9 pick among such versions can
  differ.
- When a path that excludes a dependency and another path that declares it
  meet, and the dependency's own subtree has a range or relocation that
  constrains one of its ancestors, Maven 3.9's result depends on how its
  conflict resolver orders that cycle. Raeva can differ there, as Maven 3.10
  does.
- When the highest version a range admits has two equal spellings, such as
  `1.0` and `1.0-ga` or `1.0` and `1.0.0`, Maven 3.10.0 takes the spelling
  whose POM it reads last. Two builds, or two modules of one build, can
  take different spellings, with `-T 1` too. Maven 3.9.12, and Maven 3.10
  with `-Daether.dependencyCollector.impl=df`, always take the same one.
  Raeva's 3.10 mode always takes the spelling that comes last in the order
  of Maven 3.9's hash map of the listed versions. In most of the cases
  checked, Maven 3.10 took that spelling in most runs. Publish or depend
  on one spelling to make the build repeatable.
- os-maven-plugin reads `os.detection.classifierWithLikes` from the project
  Maven sorts first, and raeva finds that project as Maven's sorter does
  from dependency and parent links. It does not follow the links Maven adds
  for build plugins and extensions built in the reactor, or pick among
  several reactor versions of one module that a version range links to, so
  it can take another project's list in such a reactor.
- Maven 3.9 keeps one POM reading per artifact and type for a whole
  build, whatever repositories a module asks, losing versions' and
  SNAPSHOT builds' included, so which module reads it first decides what
  the others get, and that changes with the module order, `-T` and `-pl`.
  Raeva's 3.9 mode refuses (exit 5), naming the coordinate and two
  modules, when the modules read different bytes for one, or one finds no
  POM and another a POM with dependencies, managed dependencies, a
  relocation or repositories. Declare the repository that serves the POM
  for every module that uses it, or, where one module finds no POM,
  resolve as Maven 3.10. Plugin locking compares the plugins' reads too,
  as below.
- Maven 3.10 reads each module's POM of an artifact from that module's
  repositories. Raeva's 3.10 mode locks a module that finds no POM beside
  one that finds a POM, also one with dependencies, and the export labels
  the POM with the repositories that served it, so `mvn -o` reads it only
  for the modules that read it online. When two modules read different
  bytes for one POM, as a dependency, a parent, an imported BOM or a
  version that loses mediation, raeva refuses in either mode (exit 5),
  naming the coordinate and the modules, though Maven 3.10.0 builds such a
  project: raeva.lock pins one file for each POM path, as a local
  repository holds one. Declare the repository that serves the POM for
  every module that uses it. One exception ends in exit 3
  (`LOCKFILE_INVALID`) without naming the modules: a SNAPSHOT support POM
  beside a row that finds no POM for it, which raeva refuses in either
  mode. With plugin locking, a version whose POM the modules read for one
  file and a plugin another, or a POM for one file and none for another,
  such as a plugin's jar beside a `type=pom` dependency, is refused
  in either mode (exit 5), naming both readers: a local repository holds
  one POM per version. A locked plugin that reads a module's file from a
  repository without its POM is locked in the 3.10 mode, as for modules.
- Maven 3.9.12 keeps a reading without a POM for the whole build, a
  losing version's and a range candidate's too, and a later reader of
  another file of a version takes the POM the first reader put in the
  local repository. Maven 3.9.12 hands each later reader the first one's
  reading, in either direction, so the build order decides what each
  gets. With plugin locking, the 3.9 mode refuses (exit 5), naming the
  coordinate and the readers:
  - any file a module, a plugin, a build extension, a plugin with
    `<extensions>true</extensions>`, a processor path or a test provider
    reads without a POM, as a winner, a losing version, a range's
    candidate or a relocation's target. A core extension's is not, as it
    resolves in a session of its own;
  - a version the modules read one way and a plugin set another, or two
    sets two ways, with and without a POM, an empty one too, or with
    other bytes, for any two files of it, as a row or as a parent, a BOM
    or a losing version's POM. A core extension's POM is compared by its
    bytes, as the local repository is shared;
  - a build extension or a plugin with `<extensions>true</extensions>`
    that reads a reactor module's coordinate from a repository, which the
    modules after it take over the module's `pom.xml`;
  - a plugin that reaches a reactor module through an artifact from a
    repository, rather than as a dependency the project declares for the
    plugin, as Maven 3.9.12 may build that module after the plugin runs.

  Some of these Maven 3.9.12 builds the same in any order, such as a
  module's read without a POM that no plugin reads, or a build extension
  at a reactor module's coordinate that no module depends on: the refusal
  is conservative there. Declare a repository that serves the POM, or
  resolve as Maven 3.10, which reads each module's and plugin's POMs
  apart.
- Raeva reads a local `<relativePath>` parent only inside the project
  directory or, when the project is a single module, inside the directory
  that holds it, such as `../parent/pom.xml`, after resolving symlinks, and
  only when its coordinates match the declared parent. Such a parent's
  properties and repositories count as the project's own, so keep an
  untrusted single-module checkout in a directory of its own. Maven reads
  the parent wherever the path points. Run raeva from a directory that
  contains the parent, or publish the parent to a repository.
- During resolution, Maven moves on to the next repository after any failed
  download of an artifact or POM, and so does raeva, except when the file
  fails its checksum, when the repository publishes no checksum for it, when
  the repository redirects to plain `http:`, or when it keeps failing in a
  way raeva retries, such as a 429, a 503 or a timeout. Raeva then stops and
  names the repository rather than hide it behind another, so the lock does
  not depend on which repository answered that day. Maven's default checksum policy uses
  the file with a warning in the first two cases, and it follows the
  redirect. During restoration, raeva may try other currently authorized
  repositories when the recorded one lacks a file, and accepts only content
  that matches the lock's SHA-256 pin. A repository that serves other bytes
  stops the restoration, whatever its checksum files say, so an edited pin
  cannot pick its bytes from another repository while the recorded one
  serves the file. When a later repository serves a file after an earlier
  one was unreachable or returned a non-retried 5xx response,
  `REPOSITORY_FALLBACK` names the skipped repository, the reason, an example
  coordinate and the serving repository, once per repository pair. Check
  the connection (VPN) or repository before committing `raeva.lock`.
  HTTP 401 and 403 fallbacks use `AUTH_FALLBACK` instead.
- In a POM's values, raeva resolves the model fields `${project.groupId}`,
  `artifactId`, `version`, `packaging`, `parent.*`, `basedir` and
  `baseUri`, the single `<build>` values such as
  `${project.build.directory}` and `${project.build.finalName}`,
  `${project.reporting.outputDirectory}`, and the plain text fields `name`,
  `description`, `inceptionYear`, `modelVersion`, `organization.name` and
  `organization.url`, inherited as Maven inherits them. Other model
  fields, such as `${project.url}`, which a module inherits with its path
  added, `${project.scm.url}`, `${project.parent.relativePath}`, and lists
  or objects such as `${project.licenses}` or `${project.build.resources}`,
  stay unresolved, even where a property has the name, since Maven reads
  the model first. Maven resolves the fields, and a list or object to
  Java's text for it. They matter where a POM uses them in a version, a
  `systemPath` or a repository URL.
- A `<file>` profile condition in a parent or dependency POM that raeva
  fetches, on a path outside the project, makes `--frozen` exit 7 once the
  file appears or goes, but a plain `raeva sync` keeps the lock: run
  `raeva sync --update` after such a file changes. See
  [Values from the machine](configuration.md#values-from-the-machine).
- Raeva reads every repository in the `default` layout. A settings.xml
  mirror or active profile repository with another `<layout>` fails the
  sync (exit 3). A POM repository with another layout is ignored
  (`REPOSITORY_IGNORED`) unless a mirror whose `<mirrorOfLayouts>` includes
  that layout serves it, as Maven reaches it only through one.
- Build plugins are locked and exported only with `[plugins] lock = true`,
  and what they fetch while they run only from a traced build; see
  [Locked plugins](offline-builds.md#locked-plugins).
- A SNAPSHOT version without a hyphen before `SNAPSHOT`, such as
  `1.0SNAPSHOT`, resolves to a build such as `1.020240101.010101-1`, as in
  Maven. The lock records that build as a release version, so
  `raeva export-m2` writes no `1.0SNAPSHOT` metadata for it, and `mvn -o`
  on the exported repository cannot resolve the declaration. Use a
  hyphenated version, such as `1.0-SNAPSHOT`, for offline builds.
