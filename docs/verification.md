# Verified against real projects

Raeva is checked against 48 open-source Maven projects (about 1,300 modules,
including dubbo, netty, quarkus, spring-ai, tika, and langchain4j). It locks
46 of them with no configuration. apache/struts needs a repository that only
a transitive POM declares (see below). flyway reads GitHub Packages, which
asks for credentials, and Maven fails it too without them. Each module's
locked set is compared with `mvn dependency:list` from Maven 3.9.11, 3.9.16,
and 3.10.0. Every compared module matches. Offline builds are checked by deleting
the locked artifacts from `~/.m2`, running `raeva export-m2`, and building with
`mvn -o`.

Known differences:

- Raeva does not trust repositories that only a transitive POM declares
  (apache/struts needs one). The error lists the repositories Maven would search
  and the `raeva.toml` entries that admit them.
- Two Maven 3.10 changes are not covered because no tested project triggers
  them: stricter validation of the project being built, and the narrower rules
  for POMs that come from a repository (interpolation, profile activation, and
  `system` scope).
- Maven 3.10 collects dependencies breadth-first (Maven Resolver 2), and
  raeva mediates as Maven 3.9's depth-first collector does. The tested
  projects resolve the same either way, but a constructed graph with
  evictions and relocations can differ. Maven 3.10 with
  `-Daether.dependencyCollector.impl=df` gives the 3.9 result.
- A version that starts with text, such as `alpha`, `final` or `foo`, equals
  `0` in Maven 3.9 and in raeva, and sorts below `0` in Maven 3.10 (Resolver
  2.0.24). That order is not transitive: `alpha` and `beta` both equal `0`
  but not each other. Raeva lists a range's equal spellings in the order of
  Maven 3.9's hash map, but sorts them with another algorithm, so a pick
  among such versions can differ, as can one among nine or more equal
  spellings that share a hash bucket.
- When a path that excludes a dependency and another path that declares it
  meet, and the dependency's own subtree has a range or relocation that
  constrains one of its ancestors, Maven 3.9's result depends on how its
  conflict resolver orders that cycle. Raeva can differ there, as Maven 3.10
  does.
- os-maven-plugin reads `os.detection.classifierWithLikes` from the project
  Maven sorts first, and raeva finds that project as Maven's sorter does
  from dependency and parent links. It does not follow the links Maven adds
  for build plugins and extensions built in the reactor, or pick among
  several reactor versions of one module that a version range links to, so
  it can take another project's list in such a reactor.
- Raeva reads a local `<relativePath>` parent only inside the project
  directory, or one directory above it when the project is a single module,
  so a cloned project cannot make it read other files. Maven reads the parent
  wherever the path points. Run raeva from a directory that contains the
  parent, or publish the parent to a repository.
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
  serves the file.
- In a POM's values, raeva resolves the model fields `${project.groupId}`,
  `artifactId`, `version`, `packaging`, `parent.*`, `basedir` and
  `baseUri`, and the single `<build>` values such as
  `${project.build.directory}` and `${project.build.finalName}`. Other model
  fields, such as `${project.name}` or `${project.reporting.outputDirectory}`,
  and `<build>` lists such as `${project.build.resources}`, stay
  unresolved. Maven resolves the fields, and a list to Java's text for it.
  They matter where a POM uses them in a version, a `systemPath` or a
  repository URL.
- A `<file>` profile condition on a path outside the project, or on a path
  built from a host value or a `${...}` `-D` value even inside it, is not
  tracked, an accepted freshness limit: run `raeva sync --update` after
  such a file changes. See
  [Values from the machine](configuration.md#values-from-the-machine).
- Raeva reads every repository in the `default` layout and ignores
  `<layout>`. Maven 3.9 cannot read a `legacy` repository, so it skips one
  unless a mirror whose `<mirrorOfLayouts>` includes `legacy` serves it.
- Locking build plugins is a deferred feature: they are neither locked nor
  exported; see [Scope](offline-builds.md#scope).
