# Is raeva for my project?

Raeva adds a dependency lock check to a Maven build. It reads XML POMs,
resolves external dependencies, and pins artifacts, POMs, parents, and
imported BOMs by SHA-256 in `raeva.lock`. It supports single-module projects
and multi-module reactors. Run it at the reactor root.

Start with `raeva sync`, commit the lock, and run `raeva sync --frozen`
beside the existing Maven build. POM changes that alter dependencies need
a lock update. A reactor version bump alone does not. For a JDK matrix,
list its versions in `[lock] jdks` in `raeva.toml` before writing the lock.
See [Configuration](configuration.md).

## What the lock does not control

Maven does not read `raeva.lock`. A frozen check validates the lock and
restores its files into raeva's store; an ordinary online Maven build still
resolves dependencies itself. To build with the pinned files, export them
to an isolated Maven repository and build offline. Plugins need separate
preparation. See [Offline builds](offline-builds.md).

The lock does not include build plugins, plugin dependencies, or Maven
extensions. Plugin and extension locking, and a Java Maven extension that
reads the lock, are planned.

Raeva does not support Maven's `-pl` or `-am` project selection. It resolves
the complete active reactor. Polyglot POMs and extensions that change the
Maven model are not supported. A project that depends on those features
needs a different lock workflow.

Raeva follows Maven 3.9 resolution rules. It does not run build plugins or
claim compatibility with every Maven extension. The [verification
page](verification.md) lists the tested projects and known differences.

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
