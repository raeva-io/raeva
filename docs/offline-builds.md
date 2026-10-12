# Offline builds and the Maven reactor

## Scope

Raeva locks and exports your project's **dependency** classpath: the
`compile`/`runtime`/`test`/`provided` artifacts (and their POM ancestry and
imported BOMs) that resolution reaches from `pom.xml`. That is what makes
`mvn -o` resolve dependencies offline.

It does **not** resolve or export Maven **build plugins** (e.g.
`maven-compiler-plugin`, `maven-surefire-plugin`) or their dependencies. The
plugin classpath is out of scope. A `mvn -o` build still needs its
plugins present in the local repository. In practice they are already cached
from a prior online build or your base image; if you start from a pristine
`~/.m2`, run the build online once (or otherwise pre-populate plugins) before
going offline. `rv export-m2` followed by `mvn -o` gives you a reproducible
**dependency** set, not a from-scratch clean-room offline build.

Raeva locks single-module projects and multi-module Maven reactors. Run
`rv sync` at the reactor root. One lockfile records every active module. For
frozen, partial-platform, and offline-build behavior, see
[Reactor projects](#reactor-projects).

`rv sync --offline` uses cached POMs and Maven metadata even after their
refresh interval has passed, including SNAPSHOTs with an `always` update
policy. Offline reads do not renew cache timestamps. Online runs still
refresh expired entries according to the repository's update policy, and
expired entries are retained for later offline use.

`metadata.db` only accelerates fetches and can be deleted while no `rv`
process is running. An online re-resolution such as `rv sync --update`
repopulates the entries a project needs; a plain `rv sync` that reuses a
fresh lockfile may not. Deleting it can leave an offline resolve without
the cached POMs or metadata it needs, even when artifact bytes are stored
locally. Local `file://` repositories are read directly and are not cached.

## Reactor projects

Run `rv sync` at a Maven reactor root. Raeva discovers active `<modules>`
recursively, including modules declared in profiles, and writes one schema-4
`rv.lock` at that root. Each platform section holds a graph for every active
module and one deduplicated union of external artifacts. Reactor siblings are
workspace nodes with full graph edges. Raeva does not download or export them
as repository artifacts.

`rv sync --frozen` rediscovers the active reactor and rejects drift in
configuration, active profiles, the module set, effective GAVs, local POMs, and
the resolution strategy recorded in `rv.lock`. It then resolves the dependency
graph again and compares it against the lockfile in canonical order, so a
changed version-range or `LATEST` selection, or a republished release POM, is
reported as drift rather than accepted. The comparison covers the POM pins as
well as the graph, so a companion, parent, or imported-BOM POM republished with
different bytes and identical dependency edges is reported too.

`rv sync --frozen --offline` is the weaker contract. It blocks remote access
but permits local file repositories. On a schema-4 lockfile it checks the local
inputs above and does not detect upstream drift. One case is the exception:
when the lockfile records an artifact origin that neither configuration nor the
local project model declares, Raeva resolves the graph again offline to
rediscover which repositories the POMs authorize. Repository trust comes from
the model, never from lockfile metadata. The already loaded root POM, reactor
modules, and accepted local parents contribute their repositories and active
profile repositories after interpolation, including effective mirror URLs.
Transitive repository allowlists alone do not declare an origin in that local
model.

The offline resolve uses cached repository data or local file repositories and
reports drift the same way an online `--frozen` run does; missing cache entries
cause an offline error. An expired SNAPSHOT update policy alone does not trigger
resolution: cached metadata cannot establish upstream drift. An unknown
origin still requires resolution even when SNAPSHOT pins are stale. Run
`--frozen` online to check a stale SNAPSHOT for upstream drift.

A schema 1-3 lockfile gets the weaker check even online, unconditionally,
because it carries no reactor identity to resolve against. Neither an expired
SNAPSHOT update policy nor a recorded origin the current configuration no
longer declares makes Raeva resolve a schema 1-3 lockfile afresh, so an
advanced snapshot goes unreported on one. Such a lockfile also records no
resolution strategy, so `--frozen` refuses a run that asks for a non-default
`--strategy` rather than reporting a check it cannot make; the default keeps
passing. The next non-frozen sync rewrites it to schema 4. Use plain `--frozen`
on a schema-4 lockfile as the CI gate.

A schema-4 lockfile written before POM pinning is read as it stands, but Raeva
does not reuse it unchanged: for each selected platform, a plain `rv sync`
resolves again and rewrites that platform's entries with the pins, once. `--frozen` never rewrites a lockfile, so an offline frozen
run accepts the older shape as it is, while an online one resolves and reports
the missing pins as drift, the same answer it gives for anything else a plain
sync would write.

A partial `--platforms` sync keeps an unselected platform only if its
rediscovered model hash still matches, it was locked under the same
configuration hash and resolution strategy, and it pins the same POMs this run
resolved for the coordinates they share. Maven reads one `.pom` per coordinate,
so two platforms pinning different bytes for one coordinate describe a local
repository no export could write. Raeva drops stale platform sections and
reports a diagnostic naming the `rv sync --platforms` command that restores
them.

After `rv export-m2`, these commands resolve dependencies offline:

- `mvn -o package` from the reactor root.
- `mvn -o -pl <module> -am package` from the reactor root.

`cd <module> && mvn -o package` is not guaranteed to resolve offline, because
Maven does not have the reactor root model in that invocation. Build plugins
fall outside the export contract and must already be present in the Maven local
repository.

When a mirror in `settings.xml` serves a download, `export-m2` records its ID
in `_remote.repositories`, as Maven does.
Run `mvn -o` with the same mirror configuration. Without it, Maven
treats those files as cached from an unavailable repository.

Reactor support has these restrictions:

- No partial sync with `-pl` or `-am`.
- `pom.xml` models only. Polyglot models and extensions are unsupported.
- No build-plugin resolution.
- Settings-profile properties do not yet apply to POM models.
- Only the root `rv.toml` applies.
- Raeva does not model Maven build order.
