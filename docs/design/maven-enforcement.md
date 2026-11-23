# Maven-side enforcement

Status: a design for raeva 0.7. Nothing on this page is built.

The goal: plain `mvn`, with no raeva binary on the path, fails or warns when
what it resolves differs from `raeva.lock`. Today the lock binds only builds
that run raeva (`raeva sync --frozen`, or `export-m2` and `mvn -o`); a job
that runs `mvn` alone resolves on its own. A Maven core extension committed
in `.mvn/extensions.xml` closes that bypass. Removing the extension stays
possible, as `--dependency-verification off` is in Gradle, but it is then a
visible change to the project.

## What Maven checks today

`raeva export-checksums` writes the lock's pins in the Trusted Checksums
format ([Maven Trusted Checksums](../offline-builds.md#maven-trusted-checksums)).
With its properties in `.mvn/maven.config`, plain `mvn` 3.9 refuses a
dependency, POM, parent or BOM whose bytes differ from the pin, also when
the file is already in `~/.m2` and also offline. Resolver 1.9.25 (Maven
3.9.12) adds `aether.artifactResolver.postProcessor.trustedChecksums.scope=project`,
which with `failIfMissing=true` also refuses a project dependency the lock
does not pin, and leaves plugins alone. That needs no Java code, but the
summary file is an export that goes stale when the lock changes, it checks
bytes, not the graph, and it has no notion of modules or platforms. The
extension uses the same hook and adds the rest.

## Hook points

Paths are in apache/maven at the tags `maven-3.9.12`, `maven-3.10.0` and
`maven-4.0.0-rc-7`, and in apache/maven-resolver at `maven-resolver-1.9.25`
(in Maven 3.9.12) and `maven-resolver-2.0.24` (in Maven 3.10.0).

### Maven 3.9 and Resolver 1.9

- **Core extension.** `MavenCli` (`maven-embedder/src/main/java/org/apache/maven/cli/MavenCli.java`)
  reads `.mvn/extensions.xml` and loads each entry through
  `BootstrapCoreExtensionManager` before any POM is read. The extension's
  realm has the core realm as its parent (`setupContainerRealm`), so it sees
  the resolver SPI; a build extension sees only the packages that
  `maven-core/src/main/resources/META-INF/maven/extension.xml` exports, and
  loads after the projects are read. The design uses a core extension only.
- **`AbstractMavenLifecycleParticipant`** (`maven-core/src/main/java/org/apache/maven/AbstractMavenLifecycleParticipant.java`).
  `DefaultMaven.doExecute` calls `afterSessionStart` on core extensions,
  then `buildGraph`, which reads every POM and resolves remote parents,
  imported BOMs and build extensions, then `repoSession.setReadOnly()` and
  `afterProjectsRead`. Both callbacks may throw `MavenExecutionException`.
  The extension reads `raeva.lock`, checks its schema and Maven line and
  selects the platform in the first, so the files `buildGraph` resolves are
  checked too. In the second it maps `session.getProjects()` to the lock's
  modules, and checks each module's build extension class paths, which
  `DefaultMavenPluginManager` keeps under `KEY_EXTENSIONS_REALMS` in the
  project's context values. `afterSessionEnd` runs after the build, too
  late to stop anything.
- **`ArtifactResolverPostProcessor`** (`maven-resolver-spi/src/main/java/org/eclipse/aether/spi/resolution/ArtifactResolverPostProcessor.java`).
  `DefaultArtifactResolver` calls every post-processor, a named component,
  on each batch of results, downloaded, found in the local repository or in
  the reactor, before returning them; a post-processor can unresolve a
  result and attach an exception. The extension supplies its own, which
  answers from `raeva.lock` itself, so no exported file can go stale. This
  is the file check. Supplying only a `TrustedChecksumsSource`
  (`maven-resolver-spi/src/main/java/org/eclipse/aether/spi/checksums/TrustedChecksumsSource.java`)
  to `TrustedChecksumsArtifactResolverPostProcessor` does not do: that
  processor is off unless its properties are set, hashes each file before
  it asks a source (so `target/classes` fails with `Is a directory`), and
  unresolves every mismatch, which leaves no room for a warning mode.
- **`MojoExecutionListener`** (`maven-core/src/main/java/org/apache/maven/execution/MojoExecutionListener.java`).
  `MojoExecutor.doExecute` resolves the module's dependencies for the mojo
  (`ensureDependenciesAreResolved`), then `DefaultBuildPluginManager.executeMojo`
  sets up the plugin realm and calls `beforeMojoExecution`, which may throw
  `MojoExecutionException`. There `PluginDescriptor.getArtifacts()` holds
  the plugin's class path, and, for a mojo that requires dependency
  resolution or collection, `MavenProject.getArtifacts()` holds what Maven
  resolved for the module, filtered by the mojo's cumulative scope; for any
  other mojo it is empty. This is the graph check.
- **`EventSpy` and `RepositoryListener`.** `EventSpyDispatcher` hands every
  spy each `RepositoryEvent` (through `EventSpyRepositoryListener`) and the
  `DependencyResolutionRequest` and `DependencyResolutionResult` of
  `LifecycleDependencyResolver`, but its `onEvent` catches and logs what a
  spy throws, as `DefaultRepositoryEventDispatcher` does for listeners. They
  can record a report, not refuse a file.
- **`RepositoryConnector`, `TransferListener` and `ChecksumPolicy`.** A
  connector (`maven-resolver-spi/src/main/java/org/eclipse/aether/spi/connector/RepositoryConnector.java`)
  and the transfer listener see downloads only; a file already in the local
  repository never reaches them. `ProvidedChecksumsSource`
  (`maven-resolver-spi/src/main/java/org/eclipse/aether/spi/checksums/ProvidedChecksumsSource.java`)
  feeds expected checksums to the connector, and
  `TrustedToProvidedChecksumsSourceAdapter` already derives them from the
  trusted sources. A mismatch there goes to the
  `ChecksumPolicy` in force, and under Maven's default `warn` policy
  `WarnChecksumPolicy.onTransferChecksumFailure` keeps the file with a
  warning. A connector or policy of raeva's own adds nothing the
  post-processor does not refuse later.

### Maven 3.10 and Resolver 2

The same interfaces exist at `maven-resolver-2.0.24`, with the
`trustedChecksums` property names and the `scope` option unchanged.
`DefaultRepositorySystemSessionFactory` builds the session through
`RepositorySystemSession.SessionBuilder`, and `DefaultMaven` wraps it in a
mutable `DefaultRepositorySystemSession` that it makes read-only before
`afterProjectsRead`, as 3.9 does. The deprecated
`org.eclipse.aether.spi.connector.checksum.ProvidedChecksumsSource` is
gone, and `extension.xml` also exports `org.eclipse.aether.scope`. What
changes is the graph: the breadth-first collector can pick other versions
([Verified against real projects](../verification.md)). The extension
compares only against a lock whose Maven line (`maven = "3.10"`, or none for
3.9) matches the running Maven, which `RuntimeInformation.getMavenVersion()`
gives, and refuses otherwise, as `sync --frozen` does.

### Maven 4

At `maven-4.0.0-rc-7`, Maven 4 reads `extensions.xml` from the project, the
user and the installation (`Constants.MAVEN_PROJECT_EXTENSIONS`,
`MAVEN_USER_EXTENSIONS`, `MAVEN_INSTALLATION_EXTENSIONS` in
`api/maven-api-core`), and lets an entry name a `classLoadingStrategy`
(`impl/maven-cli/src/main/java/org/apache/maven/cling/extensions/BootstrapCoreExtensionManager.java`).
The new API has no veto on resolution: `org.apache.maven.api.Listener` is
experimental and receives session, project and mojo events
(`EventType`) only, and the `api/maven-api-spi` providers extend the model,
packagings and lifecycles. The old hooks remain in `impl/maven-core`, not
deprecated: lifecycle participants, `EventSpy`, and `MojoExecutionListener`,
which `DefaultBuildPluginManager` also calls for Maven 4 API mojos. Resolver
2.0.23 brings the post-processor. One jar built for Java 8 can run on all
three lines, but raeva has no Maven 4 line, so the extension refuses to
compare under Maven 4 until it does.

## What it checks

- **Files.** Every artifact Maven resolves through the repository system,
  POMs, parents and BOMs included, against the SHA-256 the lock pins for
  that coordinate on the selected platform (SHA-1 for a row that a
  SHA-1-only repository served), and a `system` file against its digest,
  in the local repository and online alike. A coordinate the lock does
  not pin is a miss. Reactor modules, which Maven resolves from the build
  (`target/classes` before `package`), are skipped.
- **The graph.** Before each mojo that requires dependency resolution, the
  module's resolved artifacts, by coordinate, type, classifier and scope,
  against the module's rows in the lock, filtered by the same cumulative
  scope. The module is found by its POM path from the reactor root, and
  references to other reactor modules are compared by path, as `--frozen`
  compares them.
- **Plugins**, only when the lock has plugin tables (`[plugins] lock =
  true`): the plugin's class path against its set, build extensions against
  theirs, and files a mojo resolves at run time against the processor-path,
  test-provider and trace sets. Without plugin tables, plugin resolutions
  are out of scope, as Trusted Checksums' `scope=project` leaves them.
- **A miss** fails the build by default. `-Draeva.enforce=warn` logs each
  miss and a count at the end, as Gradle's lenient mode does, and `off`
  turns the extension off. A missing or unreadable `raeva.lock`, a newer
  schema, another Maven line, or no platform for this host's OS,
  architecture and JDK fails in every mode but `off`.
- **Offline and online** take the same checks; none needs the network.
  Online, a file with other bytes is already in `~/.m2` when it is refused,
  and is refused again on every later resolution. A newer SNAPSHOT build
  that Maven's update policy picks is a miss, where `--frozen` keeps the
  pinned build.

## What it cannot see

The extension checks the build that runs, against a lock it trusts. Raeva
keeps the rest:

- **Resolution equivalence.** `--frozen` resolves every module, scope and
  recorded platform again from the POMs and compares edges, profiles and
  support POMs. The extension sees only what this invocation resolves: the
  modules `-pl` selects, the scopes its goals need, the active profiles,
  this host's platform. A lock that matches today's build but is stale for
  another platform or a profile passes, and a build whose mojos require no
  dependency resolution, such as `mvn clean`, gets no graph check.
- **Freshness.** It does not recompute `config_hash` or the model digests;
  a POM edit that leaves the resolution unchanged passes, as under
  `--frozen`, and one that changes it fails as a miss, without raeva's
  cause.
- **Upstream drift** and **writing the lock** stay with `raeva sync`,
  `--update` and `lock diff`.
- **Core extensions.** `MavenCli.loadCoreExtensions` resolves every entry
  of `.mvn/extensions.xml`, its own jar included, in a bootstrap container
  that it disposes before any extension's components exist, so the
  extension checks none of them. The Trusted Checksums properties in
  `.mvn/maven.config` apply to that bootstrap session too
  (`BootstrapCoreExtensionManager` asks `DefaultRepositorySystemSessionFactory`
  for it), which would cover them, still to test.
- **Resolution outside the session.** A plugin that downloads over its own
  HTTP client, or builds its own resolver, never reaches the post-processor.
  Only a traced `raeva sync` pins those.

## Packaging and publishing

The extension is one jar, `io.raeva:raeva-maven-extension`, Java 8
bytecode, with its components indexed for Sisu and a small TOML reader
shaded in. A user adds it to `.mvn/extensions.xml`, and Maven fetches it
from Central, the only repository a core extension reads without a
`settings.xml` change. That means:

- a Central Portal account and the `io.raeva` namespace, verified by a DNS
  TXT record on `raeva.io` (`io.github.raeva-io` is the fallback);
- a GPG key for the project, `.asc` signatures, sources and Javadoc jars,
  and the POM metadata Central requires;
- a Maven build, which raeva does not have: the workspace is Cargo only, and
  `ci.yml` and `release.yml` build Rust. Integration tests run the
  extension under Maven 3.9.12, 3.10.0 and 4.0.0-rc-7 on the gate
  projects, on JDK 8, 17 and 21;
- a release with each lock schema, since the extension refuses schemas it
  does not know.

Volume is no issue: a few releases a year are far below the free tier's
monthly limits. The tier is the question. Sonatype requires Publisher Pro from
1 October 2026 for any artifact of a "commercial nature", one that
"supports the adoption, integration, or operation of your organization's
commercial product or service", and lists build tooling and developer
tools ([2026-09-08](https://central.sonatype.org/news/20260908_publisher_tiers_commercial_use/)).
The extension is open source and reads a file the open-source CLI writes,
but the same organization sells Raeva Cloud. Before the first release, ask
Sonatype for the per-group-ID review the notice offers, and keep the
extension free of any Cloud feature. A jar committed under `.mvn/` and named
by `-Dmaven.ext.class.path` in `.mvn/maven.config` avoids Central, at the
cost of a binary in every repository that uses it; `MavenCli` resolves that
path against the working directory, so the entry needs
`${session.rootDirectory}`.

## Prior art

- **[maven-lockfile](https://github.com/chains-project/maven-lockfile)**
  (chains-project, 5.18.7). One `lockfile.json` per module, with SHA-256 and
  plugins. `validate` (`ValidateMojo.java`) is a mojo, default phase
  `compile`, `requiresOnline = true`, that builds a lock from the project
  again and compares; a core extension (`DynamicResolutionSpy`, an
  `EventSpy`) records run-time resolutions.
- **[dependency-lock-maven-plugin](https://github.com/vandmo/dependency-lock-maven-plugin)**
  (vandmo, 1.4.0). `check` (`mojos/CheckMojo.java`) binds to `validate`
  with test-scope resolution and compares versions and integrity per
  dependency set; `lockBuild` adds parents, plugins and extensions.
- **[Gradle dependency verification](https://docs.gradle.org/current/userguide/securing_dependencies.html)**,
  the model to match. A committed `gradle/verification-metadata.xml` turns
  it on for every build, plugins and POMs included, SNAPSHOTs left out;
  `strict` is the default, `lenient` reports, `off` skips
  (`DependencyVerificationMode`). Dependency locking (`gradle.lockfile`)
  fails a resolution that differs. Both run inside the build tool.

Raeva differs in three ways. Both plugins are mojos: they run only in a
build that reaches the phase the POM binds them to, or names their goal,
and only after Maven has resolved their own class path and the plugins
before them. The extension runs from `.mvn/extensions.xml` for every goal
and refuses a file at resolution, before any mojo uses it. The lock is
written by raeva's resolver, not by the build it checks, and covers every module and platform
in one file, so the extension only reads. And the check is offline: it
compares local bytes with the pins and never asks a repository for a
checksum.

## Open questions

- Strict by default, or `warn` for the first release, while users learn
  what a miss looks like?
- SNAPSHOTs: fail on a newer build, as now planned, or warn?
- Platform selection in Java must name the platform as raeva does (OS,
  architecture, `@<jdk>` with `[lock] jdks`); share test vectors with the
  Rust code.
- Does the bootstrap session's post-processor cover the extension's own
  jar? Test before relying on it.
- Commercial nature on Central, above: settle with Sonatype first.

Condition to start: a contact asks for plain `mvn` enforcement.
