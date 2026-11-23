# JSON output, error codes, and warnings

## The envelope

With `--json`, a command prints one JSON object, the envelope, on stdout.
Logs go to stderr. `--json` turns tracing off unless `-v`/`-vv` or `RUST_LOG`
is set, so `raeva --json … | jq` still sees one JSON value. A successful run
prints:

```json
{"success": true, "data": {"warnings": []}}
```

`data` is the command's result. `data.warnings` lists the run's warnings. A
failed run sets `success` to false and adds:

| Field | Value |
| --- | --- |
| `exit_code` | Process exit status ([Exit codes](#exit-codes)). |
| `error` | The error message, as text output prints it, without the suggestions. |
| `code` | A stable code from the [error table](#error-codes). |
| `hints` | The suggestions text output lists, one string each. |
| `location` | For a failure in a module's dependencies: `module`, the reactor module's POM path, and `via`, the `group:artifact:version` of each POM from the module's direct dependency down to the one that declares the failed dependency or whose own model failed, such as through a missing parent (empty when the module declares the failed dependency, or for a failure of the whole graph). Text output prints it as an `In <module>, through <via>` line. |

If the command produced a result before failing, that result stays in
`data`. `raeva --json why` reports `found: false` and fails with `NOT_FOUND`.

`raeva sbom` without `-o`, and `raeva vuln --format sarif`, print their
document instead of an envelope, `--json` included. Warnings and errors go
to stderr. `raeva sbom -o` writes the document to that file and prints an
envelope. A failure before a document exists prints the envelope. A rejected
option (exit 2), Ctrl-C, and a startup failure print no envelope.

A warning has a `code` from the [warning table](#warning-codes), a
`message`, and a `context` object (details such as a coordinate or a
redacted URL, or `null`). Distinct warnings are kept once and sorted.
`--json` lists each, except `WEAK_HASH_FALLBACK`, which is one warning
whose `context.count` counts the files. Text mode prints one `warning: CODE: ...` line per code
on stderr at the end: the first warning, and `and N more` when that code
fired for several things (`'raeva --json <command>' lists them`).
`AUTH_FALLBACK` and `REPOSITORY_FALLBACK` print each skipped/serving
repository pair, naming an example coordinate and counting further files. The text
summary omits `WEAK_HASH_FALLBACK` and `TRANSITIVE_REPO_DROPPED`. Without
`-v`, `HTTP_REPO_BLOCKED` for a repository that a dependency's POM declares
is left out of both.

## `raeva tree` and `raeva why`

Both commands return a `modules` list with one entry per selected module,
even for a single module. Each entry has `module` (the POM path) and `gav`
(`group:artifact:version`).

Both show one lock section: this machine's by default, or the one recorded
target that `--platform` and `--jdk` select. A selection that matches no
recorded target, or several, is a usage error (exit 2) that lists them.
Without `--platform` and `--jdk`, a lock with no section for this machine
falls back to another, with a `PLATFORM_FALLBACK` warning.

`raeva --json tree` returns `project`, `platform`, `jdk` (when the lock
section has a target JDK), and `modules`. Each module has `dependencies`.
Each dependency has `coordinate`, `scope` (the scope the package resolves to
in the module, as `mvn dependency:list` shows it), `optional` (that of the
declaration that brings it in on this path),
`workspace`, `workspace_module` for a project module, and `children`. A later
appearance of a dependency whose dependencies were listed where it first
appeared has `repeated` true and empty `children`. A dependency without
dependencies is listed again, without `repeated`. An edge back into the
current path has `cycle` true and empty `children`. `repeated` and `cycle`
are present only when true. `--depth 1` lists only direct dependencies.
A tree more than 256 levels deep is a usage error (exit 2); `--depth`
prints it in part.

`raeva --json why` returns `target`, `platform`, `jdk` (when the lock section
has a target JDK), `found`, `truncated`, and
`modules`. Each module has `found`, `truncated`, and `paths`: up to 10 paths
(10000 with `--all`), shortest first, from a direct dependency to the target.
`found` is true when a path exists. `truncated` is true when more paths exist
or a search limit is reached. The top-level flags are true when any module's
corresponding flag is true.

Tree's `coordinate` and each element of why's paths use
`group:artifact:version:type[:classifier]`, without workspace or system labels.

## `raeva sync`

`raeva --json sync` returns `resolved` (the distinct external artifacts in
the locked graph of `platforms`, reactor modules and `system` files left out, as text and `raeva lock info` count them),
`platforms` (the lock sections this run checked or resolved, named as in
`raeva lock diff`), and `duration_ms`.
A `CHECKSUM_MISSING_LOCKED` warning has `files`, the repository paths of
the files `raeva.lock` marks as accepted without a checksum file, in its
`context`.

## `raeva doctor`

`raeva --json doctor` returns `issues` (failed checks), `checks` and
`snippets`. Each check has `check`, `status`, `class`, `code`, and
`details`. `status` is `ok`, `fail`, `warn` (the project uses something
raeva does not lock or check, or the JDK may be open to a known attack; it
does not change the exit status), `info`
(context for the other checks), or `inconclusive` (the check could not tell;
see [Checking credentials](authentication.md#checking-credentials)). `class`
is `config`, `auth`, `network`, or `other` for a failed check, else `null`.
`code` is a stable code from the [warning codes](#warning-codes) for a
project or JDK check, else `null`.

The project checks read local files only and run first, also under
`--offline`, which skips the repository probes. In a Maven project they
cover the Maven mode, the Maven Central URL that `maven.repo.central` replaces in the 3.10 mode, Maven Polyglot, build extensions, ignored
`.mvn/maven.config` options, plugins, the platforms `raeva.lock` records,
and, in a git work tree, whether a CI file runs `raeva sync --frozen` and
how `.gitattributes` treats `raeva.lock`. Each `snippets` entry has `file`
(`CI` or `.gitattributes`) and `text` to add there. `raeva doctor` prints
these and writes no file.

## `raeva lock info`

`raeva --json lock info` returns `path`, `schema_version`, `last_modified`, `platform_count`, `platforms`,
`total_packages`, and `unique_artifacts`. Each platform has `platform`, `jdk`
(when set), `modules`, `packages`, and `external_artifacts`.

## `raeva lock verify`

`raeva --json lock verify` returns `verified`, `downloaded`, `missing`,
`corrupt`, `pin_mismatch`, `no_checksum`, `untrusted_origin`,
`workspace_skipped`, `workspace_entries`, and the lists
`missing_artifacts`, `corrupt_artifacts`, `pin_mismatch_artifacts`,
`no_checksum_artifacts`, and `untrusted_origin_artifacts`.
Each list entry has `coordinate` and `affected_modules` (POM paths that
reach it). Missing, corrupt, and pin-mismatch entries also have `actual`
(the digest found, or `null` when the file is missing). Untrusted-origin
entries have `repo_url` (redacted). Each `workspace_entries` item has
`module`, `workspace_module`, `coordinate`, and `reason`; text output gives
their count and lists them only with `-v`.

## `raeva lock diff`

`raeva lock diff OLD [NEW]` compares two lockfiles and reads nothing else:
no resolution, store, or network. `NEW` defaults to the project's
`raeva.lock`. It exits 0 whether or not the locks differ; a file that is
not a valid lock fails as in other commands.

`raeva --json lock diff` returns `old` and `new` (the paths), `changed`,
`causes`, `platforms_added` and `platforms_removed` (platforms only one lock
records), `module_changes`, `profile_changes`, `changes`, `edge_changes`,
`pom_changes`, `plugin_changes`, `checksum_markers`, `changed_inputs`, and
`via_limited`. Hashes and order alone do
not set `changed`. `changed_inputs` lists the inputs whose recorded hashes
differ, so an edit that leaves the dependencies alone (a POM comment, say)
still shows: `config_hash` for the configuration, then each reactor POM path
whose hash differs on a platform both locks record, then each host input
name in `[resolution] ambient_inputs` that only one lock records. When
nothing else changed, text says `no dependency changes` and prints them on a
`changed inputs:` line, which `raeva sync` also prints when it updates
raeva.lock; more than three POMs, or host inputs, are a count. Other
bookkeeping, such as a module's `graph` digest, can still differ. Text also
counts the support POMs (parents and BOMs) added or removed along with
dependency changes; `-v` lists each one.
A lock section for a `[lock] jdks` entry is its own platform, named
`os-arch (JDK n)` there and in each item's `platform`.

Each `module_changes` item is one reactor module on a platform both locks
record whose coordinates changed, as a project version bump does:
`platform`, `module` (the POM path), `change` (`added`, `removed`, or
`coordinate`), `old` and `new` (`group:artifact:version`), and
`old_packaging` and `new_packaging`; `null` on the side that lacks the
module. Each `profile_changes` item is a platform whose active profiles
changed, for example a JDK-activated profile: `platform`, and `old` and
`new` (profile ids).

Each `changes` item is one package on one platform both locks record, in
one module: `platform`, `module` (the POM path), `coordinate`
(`group:artifact:type[:classifier]`), `kind` (`external`, `workspace`, or
`system`), `change`, `old_version` and `new_version` (file versions, `null`
on the side that lacks the package), `old` and `new`, `via`, and
`via_truncated`. `change` is the first of `added`, `removed`, `version`,
`snapshot`, `checksum`, `origin`, and `scope` that applies; `old` and `new`
hold the SNAPSHOT build, the redacted origin (the file path for `system`),
or the scope the package resolves to for the last three, after `transitive `
when the package is not direct and as `<direct scope> resolving to <scope>`
when its direct declaration says otherwise, else
`null`. `via` holds
up to three shortest paths from a direct dependency of the module to the
package, in the spelling of `why`'s paths, from `NEW` (from `OLD` for a
removed package); `via_truncated` is true when more exist or a search limit
was reached. Only the first 500 changes get paths, and `via_limited` is true
when there were more.

Each `causes` item is a parent or BOM bump behind `version` changes that
dependency management supplied, or that a property of a parent from a
repository set, as the modules' `managed` lines record it
(see [offline builds](offline-builds.md)). A version written as one
`${name}`, in a dependency the lineage declares or in the dependencyManagement
of a POM of the project, records the parent from a repository that sets
`name`: the nearest POM of the lineage whose properties, its active
profiles' included, hold it, unless a user or `settings.xml` property sets
it or its value reads another property. A managed entry of a parent from
a repository records the parent that holds its value, when that is another
POM. A package's source in either
lock is a cause when the module reads it at other versions in the two
locks: `old_versions` and `new_versions` are the versions of it among the
module's support POMs for a BOM, and among the parents of its lineage
(the module's `parents` lines) for a parent, both non-empty and not equal.
A dependency's lineage may read other versions of the same parent, which
do not count. A source that is no
support POM of the module in either lock and is the one module of the
reactor with its `group:artifact` in both, other than the module itself,
is a cause when the package took its version from it in both locks and its
recorded digest (`inputs.poms`) changed, as its version moving changes it
too. Its `old_versions` and `new_versions` are that module's version,
equal when it stayed. A user property or a profile changes no digest, so
it names no such source, and where a digest covers the whole reactor, an
edit of any module changes it. `sources` holds that source, or both when
the two locks name two such sources for a package: `kind` (`pom` for a
parent's dependencyManagement, `import` for a BOM the lineage imports, the
outermost one, `property` for a parent that sets the property), `pom` (its
`group:artifact`), `old_versions` and `new_versions`. `cause` is
`ambiguous` for two sources, `property` for a parent that sets the
property `property` names, one cause for each property, or for a BOM
outside the reactor whose import version is written as the one property
`property` names for every package it moved, else `imported` for a BOM and
`direct` for a parent; `property` is `null` unless `cause` is
`property`. `changes` holds the indexes of the `changes` items it moved:
those the source manages, and, for `property`, those that a POM of the
same module's lineage manages with that property, since it has one value
there, unless two such causes in the module share the property. A version
the module declares itself is in no cause, unless a parent from a
repository sets the one property it is written as. A BOM that the module also
reads at its old version, say as a dependency's parent, can look unchanged
and is then no cause either.

Text prints each cause before the other lines: `parent` or `BOM`, the
`group:artifact`, the versions that left and came (all of one side's
versions when none left or came on it, or the version and `changed` for a
module of the reactor whose version stayed), and `cause`, or `property`
and its name, in parentheses. The packages it moved follow beneath it,
indented, without `via` lines. The other changes follow as before, and the
count of support POMs added or removed leaves out the versions a cause
names. A `--frozen` mismatch and `raeva sync` print the same lines:

```text
  BOM org.junit:junit-bom 5.10.0 -> 5.10.1 (property junit.version)
    junit-jupiter-api     5.10.0 -> 5.10.1
    junit-jupiter-engine  5.10.0 -> 5.10.1 (in core)
  parent org.example:corp-parent 7 -> 8 (direct)
    guava  33.3.0-jre -> 33.4.0-jre
  commons-io  2.15.0 -> 2.16.0
```

Versions are paired as a `version` change only when each lock records exactly
one version of the package key in that module. If either side records multiple
versions, each full coordinate is compared separately, with additions and
removals for versions present on only one side.

Each `plugin_changes` item is one set of the plugin tables on a platform
both locks record: `platform`, `role` (`plugin`, `build-extension`,
`core-extension`, `processor-path`, `test-provider`, or `trace`), `name`
(its coordinates, `group:artifact` for a `version` change, or a trace's
key), `change` (`added`, `removed`, `version`, or `files` when a set with
the same coordinates pins other files), and `old` and `new` (the versions of
a `version` change, else `null`). The plugin tables' artifact rows and
support POMs show only here, not in `changes` or `pom_changes`.

Each `edge_changes` item names `platform`, `module`, `from` and `to` (package
coordinates as in `changes`), `change` (`added`, `removed`, `scope`, or `optional`),
and `old` and `new` (scope or boolean strings, or scope and optional details for
an added or removed edge; `null` when absent). When several edges join the
same packages, one whose scope changed is `removed` and another `added`.
Edges with an added or removed endpoint package are covered by that package's
row.
If an endpoint's package key has multiple versions in that module in either
lock, `from_version` or `to_version` identifies the affected version. These
fields are absent for endpoints with a single version on both sides. Text
appends the version to the affected endpoint's name.

Each `pom_changes` item is one POM pin change on a platform both locks
record: `platform`, `coordinate`, `change` (`pom` for an artifact's POM,
`support_pom` for a parent or BOM added or changed, `support_pom_origin`, or
`support_pom_removed`), `old` and `new` (SHA-256 digests, or redacted origins
for `support_pom_origin`; `null` on the side that lacks the pin), and
`old_snapshot` and `new_snapshot` (the companion POM, parent, or BOM SNAPSHOT
build stamps, also shown in text).

A `pom_changes` item with `change: "parent_range"` records a selected-parent
change, even when every POM pin is unchanged. `coordinate` is the declared
parent, including its range. `module` is the module POM path, and `model`
is the model whose lineage used it. `old` and `new` are the selected parent
coordinates, or `null` when absent. Both snapshot fields are `null`; the
support POM pin records the file build. Other POM changes omit `module`
and `model`.

Each `checksum_markers` item is a locked file whose `missing_checksum`
marker changed: `path` (its repository path) and `change`, `marked` when
the new lock records it as accepted without a checksum file and the old
lock did not, or `cleared` when the new lock still pins the file and a
checksum file now verifies it. Text shows each as one line.

Text groups modules with the same platform set, as `sync` does, with the
first path for a package that is not a direct dependency, and shows digests
by their first 12 hex digits.

## `raeva export-m2`

`raeva --json export-m2` returns `m2_path`, `exported`, `sources`, and
`javadocs`.

`raeva export-m2 --plan-json` writes nothing and prints a plan instead of an
envelope, `--json` or not: what an export into an empty directory writes, so
that a tool which cannot run raeva in its build, such as a Nix or Flatpak
build, can fetch the files and write the repository itself. The format is
unstable: `version` is 1 now, and a later raeva may change the format and
the number.

| Field | Value |
| --- | --- |
| `version` | The format of the plan. |
| `files` | Each file a repository serves, by `path`: `path` below the repository, `url` to fetch it from where raeva.lock records one, and its `sha256` in hex. |
| `generated` | Each file the export writes itself, by `path`: the `.sha1` and `.sha256` sidecars, the `_remote.repositories` markers and the `maven-metadata-*.xml` files, with its text as `content`. |

`url` is the URL of the repository raeva.lock records for the file, with the
file's path below it. It is never a mirror's, whose URL may hold a token, and
it holds no credentials, as raeva.lock holds none: fetch through a mirror or
with credentials of your own, and check `sha256`. A plain `-SNAPSHOT` copy has
the URL of the build it copies. A repository in or beside the project gives a URL
relative to the directory of raeva.lock, such as `./repo/org/...` or
`../shared/org/...`, with `%`, `\`, `#`, `?`, whitespace and invisible
characters in a directory name percent-encoded. A file that only the mirror of a repository whose URL
raeva.lock cannot record served, such as one that does not parse, has no
`url`: fetch it through that mirror.

The plan covers every platform raeva.lock records, also when it records none
for this machine, and the jars `--with-sources` and `--with-javadocs` add
that the store holds: it downloads none and warns `CLASSIFIER_NOT_STORED` for
the others. Each digest comes from raeva's store, so the store must hold every locked file
intact, as for an export: a missing or damaged file fails the plan with exit 7
until `raeva sync` restores it. The plan is for an empty directory, so
`--m2-path`, `--dry-run`, `--overwrite` and `--link` are refused with exit 2.
Names that differ only in letter case are refused on every volume. A
repository rebuilt from the plan holds the bytes of an export, without its
`.raeva-export.lock`; the export also dates `maven-metadata-local.xml` files
to 1970, which only an online Maven run reads.

## `raeva export-checksums`

`raeva --json export-checksums` returns `path` (the SHA-256 file), `paths`
(every file written), `count`, `sha256_count`, `sha1_count`, and
`maven_properties` (the `-D` flags that make Maven enforce the files).

## `raeva seed key`, `raeva seed save` and `raeva seed restore`

`raeva --json seed key` returns `key`. `raeva --json seed save` and
`raeva --json seed restore` return `key`, `path` (the seed directory),
`files` (the files raeva.lock pins), `blobs` (the distinct files among
them), `bytes` (their size), and `metadata` (the metadata cache rows).

## `raeva vuln`

`raeva --json vuln` returns `targets` (all scanned targets, sorted by platform
and target JDK), `threshold`, `threshold_exceeded`,
`complete`, `summary`, `results`, `failed_records`, and `metadata`.
Each `targets` item has `platform` (`os-arch`) and `jdk` when a target JDK
is recorded. For a single target, top-level `platform` and optional `jdk`
are also present. SARIF puts the same list in `runs[].properties.targets`.
`--platform` and `--jdk` filter recorded targets without a host fallback.
`--include-test` includes test-only dependencies, in a baseline scan too;
the target selectors do not apply to the baseline.
`summary` counts `total_dependencies` (scanned), `test_only_dependencies`
(left out), `vulnerable_dependencies`, `total_vulnerabilities`,
`suppressed`, `findings_at_or_above_threshold`, and by severity `critical`,
`high`, `medium`, `low`, `none`, and `unknown`. A finding is one advisory
on one dependency. The severity counts and the threshold count leave out
suppressed findings, so the severity counts and `suppressed` add up to
`total_vulnerabilities`. Each `results` item has `purl`,
`affected_modules`, `vulnerabilities` (OSV records), `findings`,
`suppressed` (the ids `--vex` suppresses in every module), and `vex`. Each
`findings` item has the record's `id`, its `severity` as the table shows it,
such as `High` or `Unknown (no CVSS score)`, and `fixed`: the nearest
version above the locked one that the record names as fixed, or null. Each
`vex` item is one matching statement and module, with `id`, `module`,
`status`, `justification`, and `impact_statement`. Each `failed_records` item has `id` and `purls`.
`metadata` has `query_timestamp`, `tool` (`name`, `version`), and
`scanner` (`provider`, `database_snapshot`). `raeva vuln --format sarif`
prints a SARIF document instead, as above, with one result per finding.

With `--baseline FILE`, `data.baseline` names the supplied file and every
`results[].findings[]` item also has `new` (boolean), including suppressed
findings. A finding is existing when its exact purl (version and qualifiers
included) occurs in any module or platform/JDK section of the baseline.
Targets are not part of the finding identity. Only the current inventory is
queried, so a new advisory on an unchanged dependency is existing. The `--module`, `--platform` and `--jdk` selectors apply only to
the current inventory.

`threshold_exceeded` and `summary.findings_at_or_above_threshold` count only
new, unsuppressed findings that meet `--fail-on`. All other summary counts
and `results` still cover the current inventory. `baseline` and `new` are
absent without `--baseline`. SARIF sets each current result's standard
`baselineState` to `new` or `unchanged`; VEX `suppressions` remain separate.
SARIF marks an incomplete scan `executionSuccessful: false` as usual. An
unusable baseline returns exit 3 with `INVALID_PROJECT_INPUT`, never a
successful comparison.

`raeva --json vuln triage` returns `path`, `written` (false when the
statement was already there), `version` (the document's), `vulnerability`,
`module`, `product` and `subcomponent` (the purls written; `product` has no
version unless `--product-version` was given), and `justification`.

## `raeva sbom`

`raeva --json sbom` without `-o` prints a CycloneDX document, as above.
With `-o`, it writes the document to that file and the envelope's `data`
has `format` (`cyclonedx`), `path`, and `targets`. Each target has `platform`
(the OS and architecture) and, when recorded, `jdk` (the exact target JDK
string). Selectors restrict this list; unmatched selectors fail without a
fallback.

The CycloneDX document records the same coverage as `raeva:target` entries
in `metadata.properties`, such as `linux-x86_64 and JDK 21`. Coverage,
component data, effective licenses, and VEX analyses contribute to its
deterministic `serialNumber`. Licenses appear in the root and library
components as SPDX `license.id` values when unambiguous, otherwise as
`license.name`. Library components carry `scope` (`required`, or
`excluded` when every selected module that reaches them resolves them to
`test`) and `raeva:maven:scope` properties: one with the scope, such as
`compile`, when those modules agree, else one per module, such as `test
app/pom.xml`, and none for a module that resolves them to no scope; see [SBOMs](vulnerabilities-and-sboms.md#raeva-sbom).
Extraction uses the locked dependency and parent POM
bytes in the content store; missing or damaged pinned evidence is an error.
A dependency resolved without a POM has no license metadata to emit.

With `--vex`, analyses combine the selected modules conservatively:
`affected` wins, then missing assessments or `under_investigation` keep
triage. All `fixed` resolves; all `not_affected` marks unaffected; mixed
`fixed` and `not_affected` stays in triage. Differing assessments retain
per-module evidence in `analysis.detail`. Contradictions within one module
remain errors. See [SBOMs](vulnerabilities-and-sboms.md#raeva-sbom).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | General error, such as a local store or file that cannot be used, or an internal error in `raeva`. `raeva why` found no path. `raeva vuln` found unsuppressed vulnerabilities at or above `--fail-on`. The build `[plugins] trace` runs failed. |
| 2 | Usage error, such as an unknown option, a `--module` that matches no module, or `--offline` with `raeva vuln`. Also a `raeva vuln` scan that failed for a cause no other code describes. `raeva vuln` keeps 1 for findings. |
| 3 | Configuration error, such as an invalid `raeva.toml`, credentials a repository or proxy refused (401, 403, or 407), an untrusted server certificate, or a missing or invalid `raeva.lock` that must be regenerated. |
| 4 | Network error, such as a timeout, a refused connection, a stalled download, or a 429, 502, 503, or 504 answer. |
| 5 | Resolution failed, such as an artifact no repository has, no cached copy under `--offline`, invalid repository metadata, or a 500 or other answer `raeva` does not retry. |
| 6 | Could not start: the TLS crypto provider or the async runtime failed to set up. |
| 7 | `raeva.lock` is out of date or does not match: POM edits that change the locked result or a configuration change since the last sync, `--frozen` drift, a download or stored file that does not match its pin, or a failed `raeva lock verify`. |
| 8 | `raeva doctor`: some checks passed and others failed. |
| 9 | A repository file does not match the checksum published next to it. The file was altered or damaged on the way, or the repository published a wrong checksum. |
| 130 | Interrupted with Ctrl-C. |
| 143 | Stopped by SIGTERM, as CI runners and `timeout` send to cancel a job (Unix). |

## Error codes

Scripts should test `code` rather than parse `error`. The exit column is the
usual status. `raeva vuln` exits 2 instead of 1, since its 1 means findings.

| Code | Exit | Meaning |
| --- | --- | --- |
| `USAGE` | 2 | An option or argument `raeva` refuses, such as a `--module` that matches no module. |
| `CONFIG` | 3 | Invalid configuration, such as `raeva.toml`, `config.toml`, `settings.xml`, an environment variable, or a platform name. An unreadable `raeva.lock` is `IO`. |
| `AUTH` | 3 | A repository refused the credentials (401 or 403), or they could not be set up. |
| `PROXY_AUTH` | 3 | A proxy refused the request: a 407, or an answer other than 200 to the `CONNECT` of an `https:` URL. |
| `TLS` | 3 | A server certificate failed verification. |
| `REPOSITORY_CONFIG` | 3 | A repository `raeva` refuses: a rejected URL, snapshots disabled for a snapshot, releases disabled for a release, a checksum policy Maven does not support, an origin no configuration declares, or a mirrored repository whose URL `raeva.lock` cannot record that served a version list or a plugin file, or that another such repository shares the empty origin with. |
| `NO_REPOSITORIES` | 3 | No repository is configured. |
| `INVALID_POM` | 3 or 5 | A POM `raeva` cannot use. 3: a refused project model, such as coordinates Maven rejects, a dependency or build plugin dependency without a version, a missing, blank, or relative `<systemPath>`, a property cycle, a repository URL scheme other than `http`, `https`, or `file`, a dependency scope `raeva.lock` cannot record, such as one with a space, or a dependency coordinate that holds a `${...}` of a JVM system property raeva does not answer, such as `${java.vendor}`, or one that takes a `-D` value, settings.xml property or environment variable named like a secret, in the project or a dependency's POM, or a model of the project or of a dependency that Maven builds and raeva cannot lock the same way, such as one with a relevant profile whose activation tests a value raeva does not read. 5: a malformed or invalid POM from a repository, and other model errors. |
| `INVALID_PROJECT_INPUT` | 3 | Refused project input, such as a malformed project POM, a module that does not exist or lies outside the project, a `<systemPath>` outside it, or a `--vex` file `raeva` does not read or whose statements disagree. |
| `PROJECT_FILE_MISSING` | 3 | There is no `pom.xml`. |
| `REPOSITORY_ORIGIN_ALIAS` | 3 | Two `file:` repositories that `raeva.lock` would record as one origin name different directories. |
| `LOCAL_REPOSITORY` | 3 | The export destination cannot hold the lock: no Maven user home for the default `~/.m2/repository`, a configured path `raeva` cannot expand, a directory `raeva` cannot create or write to, names that collide on the volume, or a link that leads out of it. |
| `LOCKFILE_MISSING` | 3 | There is no `raeva.lock`. Run `raeva sync` in the directory of the root `pom.xml`. |
| `LOCKFILE_NOT_A_FILE` | 3 | `raeva.lock` is not a regular file. |
| `LOCKFILE_INVALID` | 3 | Another schema, or a value `raeva` refuses or cannot export. The error says what to change. An older schema, or a malformed lock whose rows read: `raeva sync` without `--frozen`. A row that does not read, such as an empty `checksums` list: `raeva sync --update`. A newer schema: upgrade `raeva`. |
| `PLATFORM_MISSING` | 3 | No lock section for this platform. The error names the platforms it records. `hints` gives the `raeva sync --platforms` command that adds it. |
| `OTHER_PLATFORM_ORIGIN` | 3 | A `--platforms` run must fetch a file the lock pins from a repository that only a platform it does not check trusts, as a remote parent's profile declares it. `raeva sync --frozen` without `--platforms` checks it. |
| `NETWORK` | 4 | A repository or OSV could not be reached: a timeout, a refused connection, a stalled download, or a 429, 502, 503, or 504 answer after retries. |
| `RESOLUTION` | 5 | Dependency resolution failed, such as a version range nothing satisfies, a dependency coordinate that holds a `${...}` no property defines and the JVM does not own, or one repository id that lists different versions of an artifact at two URLs. |
| `ARTIFACT_NOT_FOUND` | 5 | No repository has a dependency. |
| `VERSION_CONFLICT` | 5 | A selected version does not satisfy a requirement. |
| `NOT_FOUND` | 5 or 1 | 5: a repository answered 404. 1: `raeva why` found no path to the coordinate. |
| `OFFLINE_NOT_CACHED` | 5 | `--offline`, and a needed file is not cached. The hint says to run `raeva sync` online once; for the plugin check of `raeva sync --frozen`, which a plain sync that keeps the plugin tables does not prepare, to run `raeva sync --frozen` online once or restore a seed. |
| `REPOSITORY` | 5 | Another repository failure, such as invalid metadata, a refused redirect, an address that is not public, or a 500 answer. |
| `LOCKFILE_MISMATCH` | 7 | `raeva.lock` is valid but out of date for the project, its configuration, a fresh resolution, or the stored files. `hints` gives the update command, usually `raeva sync`; when a repository served other bytes than a pin, it says to check with the publisher before `raeva sync --update`. Offline, a POM `raeva.lock` records as missing from a remote repository that no kept 404 from that repository confirms fails here too, and `hints` says to run `raeva sync --frozen` online once or restore a seed saved after one. |
| `DOCTOR_CHECKS_FAILED` | 8, 3, 4, or 1 | `raeva doctor` checks failed: 8 when others passed, 3 when every failure is an authentication, TLS or configuration failure, 4 when every failure is a network failure, and 1 otherwise. |
| `INTEGRITY` | 9 | A file does not match the checksum the repository publishes next to it. |
| `STORE` | 1 | The artifact store or the metadata cache failed. |
| `IO` | 1 | A local file could not be read or written. |
| `EXPORT` | 1 | `raeva export-m2` could not write the local repository. |
| `SBOM` | 1 | `raeva sbom` could not build the document. |
| `LOCKFILE_BUSY` | 1 | Another `raeva` process is using `raeva.lock`. Wait and run the command again. |
| `VULNERABILITIES_FOUND` | 1 | `raeva vuln` found unsuppressed vulnerabilities at or above `--fail-on`, restricted to new findings with `--baseline`. |
| `VULNERABILITY_SERVICE` | 2 | OSV returned an error other than 429, 502, 503, or 504, or a response `raeva` cannot use, or the missed records of an incomplete scan failed with causes that exit differently. |
| `INTERNAL` | 1 | A bug in `raeva`, or a sync that made no progress for `RAEVA_WORKSPACE_STALL_TIMEOUT_SECS`. |
| `ERROR` | 1 | Another failure, such as a link where `raeva export-checksums` writes. |

## Warning codes

A warning does not change the exit status. Codes are stable. Messages may change.

| Code | Meaning |
| --- | --- |
| `ADOPT_RACE` | Another `raeva` process removed a store file while this run indexed it. The next sync repairs the index. |
| `AUTH_FALLBACK` | A later repository served files after an HTTP 401 or 403 refusal; one warning per repository pair names an example and counts further files. `context.unset_variables` lists, comma-separated, the unset variables of `${env.NAME}` references in the refused `settings.xml` credential. |
| `BUILD_EXTENSIONS` | A `raeva doctor` check: `.mvn/extensions.xml`, a `<build><extensions>` entry, or a plugin with `<extensions>true</extensions>` in a reactor POM or a local parent loads a build extension, which `raeva` does not run. os-maven-plugin is not listed, since `raeva` sets its properties. Also when such a file cannot be read, so the check was not done. |
| `CACHE_ENTRY_DAMAGED` | A `metadata.db` entry no longer matched the checksum it was written with, as damage inside the file or an edit leaves it, so `raeva` dropped it and fetches the file again; an offline run reports it as not cached. |
| `CACHE_KEY_UNAVAILABLE` | The `cache-key` file beside `metadata.db` could not be read or written. The answers this run keeps for the credentials it sends are not matched by a later run. |
| `CHECKSUM_MISSING` | No checksum was published, and `--allow-missing-checksums` accepted the download. A file matching its `raeva.lock` pin needs no checksum file and gets no warning. |
| `CHECKSUM_MISSING_LOCKED` | `raeva sync --frozen` checked a `raeva.lock` that marks files as accepted without a checksum file, and `--allow-missing-checksums` was not passed again. The pins still check the bytes. `context.files` lists the repository paths. |
| `CI_CHECK_MISSING` | A `raeva doctor` check: no CI file at the git root runs `raeva sync --frozen` or setup-raeva with `check: true`. A snippet gives the command. |
| `CLASSIFIER_CHECKSUM_MISSING` | `raeva export-m2` skipped a sources or Javadoc jar with no published checksum. |
| `CLASSIFIER_NOT_STORED` | `raeva export-m2 --offline`, `--dry-run` or `--plan-json` skipped a sources or Javadoc jar the store does not hold intact: no earlier export downloaded it, the repository does not have it, or the stored file is damaged. |
| `CLEARTEXT_AUTH` | Credentials went over plain HTTP to a non-loopback host. |
| `CREDENTIAL_DROPPED` | A `settings.xml` password could not be decrypted and was dropped. `context.entry_kind` (`server` or `proxy`) and `context.entry_id` name the entry, and `context.reason` says why. A `<server>` with a username whose password was dropped gives no credential for its id unless it has a bearer token ([Authentication](authentication.md)). |
| `CROSS_HOST_MIRROR` | A mirror on another host serves a repository, so an `[[auth]]` entry without an `id` was not sent. |
| `DATABASE_RECREATED` | The store index or the metadata cache was damaged or was not an SQLite database, as a partial CI cache restore can leave it, so `raeva` deleted it and started a new one. `context.path` names it. A damaged file that another raeva process has open is recreated once that process closes it. raeva waits about 2 s for that, and otherwise fails and names the file. Stored files are still checked against `raeva.lock`; what the lost entries held is hashed or downloaded again. |
| `DEFAULT_CREDENTIAL_WITHHELD` | An `[[auth]]` entry without an `id` was not sent to an origin your own files do not name ([Authentication](authentication.md#precedence)). |
| `ENV_VALUE_IN_LOCKFILE` | A `raeva.lock` field holds the value of an allowlisted environment variable. |
| `ENV_VAR_HIDDEN` | A POM reads an environment variable other than `JAVA_HOME` and `PWD` that is set, as `${env.NAME}`, `${NAME}` in the model, or an `env.NAME` activation, and that `allow_env_substitution` does not list, so `raeva` treats it as unset where Maven reads its value. `context.variable` names it; the value is never shown. Allow it in `[security] allow_env_substitution` in `config.toml` if the value may be public; this is part of `raeva.lock`'s configuration, so set it on every machine that syncs, or on none. |
| `EXPORT_LOSING_RANGE_VERSIONS` | Version ranges that lose mediation name no version `raeva export-m2` lists otherwise. Into a repository of its own it lists the lowest version a repository listed for each under that repository's ids, so `mvn -o` resolves the ranges, and Maven warns that their POMs are missing; into the shared local repository it lists none. `context.coordinates` names the versions and `context.listed` says whether they were listed. See [Offline builds](offline-builds.md). |
| `EXPORT_PERMISSIONS_NOT_SET` | `raeva export-m2` could not make an exported file owner-writable. |
| `EXPORT_PLUGINS_UNCHECKED` | Without `[plugins] lock = true`, `raeva export-m2` could not read the modules' build plugins and extensions offline, so for that platform it did not check those without a version, whose artifacts it otherwise refuses to list (exit 3) when the lock records no `<release>` for them. `context.platform` names the platform and `context.reason` the error. See [Offline builds](offline-builds.md#offline-maven-builds). |
| `EXPORT_REPOSITORY_ID_GUESSED` | `raeva.lock` records no repository id for some origins, so `raeva export-m2` labelled their files `central` in `_remote.repositories`. `mvn -o` rejects such a file where it reads it under another id. `context.origins` names the origins, with credentials redacted. See [Offline builds](offline-builds.md#repository-ids). |
| `EXPORT_REPOSITORY_ID_UNUSABLE` | `raeva export-m2` wrote no version list under some repository ids `mvn -o` may read: ids no file name can carry, or ids a project POM or a parent it inherits from spells with an expression the lineage's properties do not resolve. `mvn -o` may then resolve a range, `SNAPSHOT`, `RELEASE` or `LATEST` from another build's list under them. `context.ids` names them. See [Offline builds](offline-builds.md#repository-ids). |
| `EXPORT_SHARED_REPOSITORY` | `raeva export-m2` wrote into the Maven local repository other builds share, so it removed no metadata and `mvn -o` there is not a locked build. `context.m2_path` names it. See [Offline builds](offline-builds.md#a-repository-of-its-own). |
| `EXPORT_SYSTEM_SCOPED_SKIPPED` | `raeva export-m2` skipped `system` dependencies. Their files are not in the store. |
| `EXPORT_UNFINISHED` | An earlier `raeva export-m2` into the local repository did not finish, as its `.raeva-export-unfinished` file shows. `context.m2_path` names the repository, and `context.repaired` is true when this export repaired it; under `--dry-run` it is false. See [Offline builds](offline-builds.md). |
| `EXPORT_WARNING` | An export warning this `raeva` has no specific code for. |
| `FETCHED_POM_REPO_REFUSED` | A parent POM from a repository declared a repository that is not HTTP or HTTPS. `raeva` ignored it. |
| `FROZEN_RESOLUTION_FAILED` | `raeva lock verify --download` could not resolve `raeva.lock` again as `raeva sync --frozen` does, so `raeva --offline sync --frozen` fails until it can. The message gives the error; the command still checks and repairs the store as the lock is written. |
| `HOST_JDK_JAVA4SHELL` | A `raeva doctor` check of the JDK `mvn` runs: on an x86-64 CPU with avx512f, avx512bw, avx512vbmi and bmi2, a JDK of 17.0.6 or later whose `release` file does not name OpenJ9 and has a `JAVA_VERSION_DATE` before 2026-11-17 may be affected by CVE-2026-114938 (Java4Shell), unless it carries that day's security update. `warn` with such a date, `info` without one, and `info` when the options of the JVM `mvn` starts already turn the intrinsic off with `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=` 0 to 2: `.mvn/jvm.config`, `MAVEN_OPTS`, `MAVEN_DEBUG_OPTS` and `_JAVA_OPTIONS`, the last option that sets a flag winning. The details say to update the JDK or add `-XX:-UseBASE64Intrinsics` to `MAVEN_OPTS` or `.mvn/jvm.config`, or, when it is off, name the option ([Java4Shell](ci.md#java4shell)). |
| `HOST_JDK_NOT_LOCKED` | A `raeva doctor` check: `raeva.toml` sets `[lock] jdks` and lists no JDK that matches this one, or this JDK's version is unknown, so `raeva sync --frozen` fails here. The details say which JDK to use or what to add to `[lock] jdks`. |
| `HOST_PLATFORM_NOT_LOCKED` | A `raeva doctor` check: `raeva.lock` records no section for this machine's OS and architecture, or no platform at all, so `raeva sync --frozen` and `raeva export-m2` fail here. The details name the `raeva sync --platforms` command that adds it. |
| `HOST_PLATFORM_ONLY` | A `raeva doctor` check: `raeva.lock` records only this machine's OS and architecture, so `raeva sync --frozen` fails on any other. The details name a `raeva sync --platforms` command ([CI](ci.md)). |
| `HTTP_REPO_BLOCKED` | A repository a POM or a `settings.xml` profile declares uses plain HTTP to a host other than `localhost` or `127.0.0.1`, and nothing in your configuration names its URL or serves it through a mirror that is not blocked, so it was ignored, as Maven's default HTTP blocker does; or the Maven 3.10 Central a `-D`, `MAVEN_REPO_CENTRAL` or `.mvn/jvm.config` gives does, and no mirror serves it. Reported for the project and its parents, and for a dependency's POM only with `-v`: a dependency that only such a repository has fails with an error that names it. See [Configuration](configuration.md). |
| `ID_CREDENTIAL_WITHHELD` | An id credential was not sent to a repository a fetched POM declares, on an origin neither your configuration nor the project's POMs name, or, in the Maven 3.10 mode, a `settings.xml` username and password to an origin Maven's credential scope does not bind to the id, or to a repository a dependency's POM declares, while collecting the dependencies below it ([Authentication](authentication.md#precedence)). |
| `JAVA_VERSION_DEFAULTED` | A POM, a `settings.xml` profile, a `.mvn/maven.config` value or the version check of a plugin without a version reads `java.version` where it can change resolution, and neither the `release` file of the JDK (`JAVA_HOME`, else the `java` on `PATH`) nor `JAVA_VERSION` names a version, so `raeva` used 17. `context.pom` names the POM when a POM profile condition read it. Where the read changes what is locked, the sync then fails (exit 3). Set `JAVA_HOME`, or list the JDKs in `[lock] jdks`. |
| `JDK_NOT_LOCKED` | `raeva sync` ran on a host JDK that matches no entry in `[lock] jdks`, or whose version neither a `release` file nor `JAVA_VERSION` names. It resolved the listed JDKs. |
| `LISTING_REPO_SKIPPED` | A version range, `RELEASE` or `LATEST`, or the version or prefix of a plugin, was resolved without a repository that failed, other than with a 404 or a failure reported by `AUTH_FALLBACK` or `REPOSITORY_FALLBACK`, while another repository answered. |
| `LOCKFILE_REGENERATED` | `raeva sync` replaced a `raeva.lock` it cannot read, such as an older schema or one with merge conflict markers, keeping the platforms it names and the pins of each side and of the `raeva.lock` at git `HEAD`, or no pins under `--update`. The message says whether the change list compares with the `raeva.lock` at git `HEAD`. |
| `LOCK_MERGE_DISABLED` | A `raeva doctor` check: a `.gitattributes` line marks `raeva.lock` `-merge` or `binary`, which keeps git from merging it ([CI](ci.md#merge-the-lock)). |
| `LOCK_NOT_MARKED_GENERATED` | A `raeva doctor` check, as `info`: no `.gitattributes` marks `raeva.lock` `linguist-generated`. A snippet gives the line. |
| `LOCK_UNREADABLE` | A `raeva doctor` check: `raeva.lock` does not read, for example after a merge left conflict markers in it, so `raeva sync --frozen` fails. The details give the error and what to do, as `raeva sync --frozen` does: run `raeva sync`, which regenerates it; for a lock too large or not UTF-8, delete it and run `raeva sync`; for a lock of a newer schema, upgrade `raeva`. |
| `LOW_DISK_SPACE` | Less than 100 MiB free on the store volume. |
| `METADATA_CHECKSUM_MISMATCH` | `maven-metadata.xml` still mismatched its checksum after a second download, and the repository's checksum policy accepted it. |
| `PLATFORM_DROPPED` | `raeva sync --platforms` dropped an unselected platform whose pins no longer match. The warning names the command that restores it. |
| `PLATFORM_FALLBACK` | No lock section matches this machine's platform and JDK, and no `--platform` or `--jdk` was given. The command used another section from the lock. |
| `PLUGINS_NOT_LOCKED` | A `raeva doctor` check, as `info`: `raeva.lock` holds no plugin tables, so it does not pin Maven plugins or what they fetch, and pins a module's build extensions only when it resolves a dependency type Maven's core does not define; `[plugins] lock = true` in `raeva.toml` locks them ([Locked plugins](offline-builds.md#locked-plugins)). |
| `PLUGIN_TABLES_STALE` | A `raeva doctor` check: `raeva.toml` sets `[plugins] lock = true` and a platform of `raeva.lock` has no plugin tables, or `raeva.toml` does not set it and `raeva.lock` holds some, or `[plugins] trace` is set and an OS and architecture of `raeva.lock` has no trace of that build, so `raeva sync --frozen` fails until `raeva sync` rewrites the lock, online on that OS for a trace. |
| `POLYGLOT_MAVEN` | A `raeva doctor` check: `.mvn/extensions.xml` loads a Maven Polyglot extension, or the project has a polyglot POM such as `pom.yaml` and no `pom.xml`. `raeva` reads `pom.xml` files only. |
| `POM_PROBLEM` | Invalid POM, unreadable local parent, a scope of a project dependency or managed dependency that Maven's validator does not know, which Maven warns of in the same words and builds with, in the Maven 3.9 mode a repository id of the project's effective model that is `local` or holds one of `\/:"<>|?*`, which Maven 3.10 refuses, or, in the Maven 3.10 mode, version or snapshot metadata with a version, timestamp or plugin name that Maven 3.10 refuses, such as one with `/`, `\`, `:` or a control character. `raeva` drops that POM's dependencies, looks the parent up in the repositories, or takes no version from that metadata, so a `-SNAPSHOT` no other repository names a build of stays at its base version. An invalid dependency POM is reported only when the resolution selects its version, not for each version a range reads. |
| `PROFILE_NOT_FOUND` | A profile id that `-P`, `.mvn/maven.config`, `raeva.toml`, `config.toml` or `settings.xml` `<activeProfiles>` requests is not the id of a profile any reactor POM or its parents activates, nor of a `settings.xml` profile, so it activates nothing, as Maven warns. A project with a parent POM that is not in the reactor gets no warning, since that parent may have the profile. |
| `PROJECT_LOCAL_REPOSITORY_IGNORED` | `raeva export-m2` ignored `local_repository` in the project `raeva.toml`, `-Dmaven.repo.local` in `.mvn/maven.config`, or `<localRepository>` in a settings file `.mvn/maven.config` names with `-s`. |
| `PROJECT_REPO_URL_FROM_FETCHED_POM` | A project POM repository URL comes from a fetched parent, so the repository has that parent's trust. |
| `PROJECT_SECURITY_WIDENING_IGNORED` | Project `raeva.toml` set `[security]` wider than the user `config.toml`. That part was ignored. |
| `REPOSITORY_FALLBACK` | A later repository served files after an earlier repository was unreachable or returned a non-retried 5xx response. One warning per repository pair names an example coordinate, the reason and the serving repository, and counts further files. Check the connection (VPN) or repository before committing `raeva.lock`. `context` holds `skipped`, `skipped_endpoint`, `serving`, `serving_endpoint`, `reason`, `coordinate` and an example `file`. |
| `REPOSITORY_IGNORED` | A POM repository has a URL that is not `http`, `https` or `file` and no mirror serves it, such as `bundle:` or, in the Maven 3.9 mode, `symlink+file:`. Maven skips it too: its requests fail and the search goes on. Also a fetched POM's repository that the transitive policy admits but raeva does not read: its layout is not `default` and no mirror serves it, as Maven reaches it only through one, or its `file:` URL takes a value raeva does not read. `context.repository` names its id, and `context.declared_by` the declaring POM, when known. |
| `REPO_URL_BACKSLASH` | A fetched POM's `http` or `https` repository URL has a `\` in it, which Maven's HTTP transport refuses, so each request to it fails in Maven and the search goes on. Ignored. In the Maven 3.9 mode, a `\` after the port of one raeva admits fails the sync once a search reaches the repository, as Maven 3.9 fails the build. `context` holds `repository` and `declared_by`. |
| `REPO_URL_SECRET_REFUSED` | A fetched POM's repository URL has userinfo, a query, or a fragment, or the value of an input named like a secret in its path, or its id holds such a value (see [Configuration](configuration.md#repositories-and-mirrors)), which may hold a credential. Ignored, and the URL is not shown, nor an id that holds the value. `context` holds `repository` (the id) and `declared_by` (the declaring POM, when known). |
| `SETTING_IGNORED` | An unusable setting was ignored: an environment variable such as `RAEVA_MAX_ARTIFACT_SIZE`, `RAEVA_HOME`, `SSL_CERT_FILE`, or `SSL_CERT_DIR` with a value `raeva` cannot use; `settings-security.xml` that is not valid XML or that `raeva` cannot read; a `settings.xml` proxy protocol other than `http`, `https`, or `all`, or a proxy `<port>` that is not a number, read as 0 as Maven reads it; a `settings.xml` repository or mirror URL that does not parse or is not `http`, `https` or `file`, which Maven skips too unless a mirror serves the repository; a `<mirrorOf>` pattern Maven does not know; or `-pl`, `-am`, `-amd`, `-rf` or `-N` in `.mvn/maven.config`, `MAVEN_ARGS`, or a `MAVEN_CONFIG` a Maven Wrapper script passes, since `raeva` locks the whole reactor; or, in the Maven 3.10 mode, a remote repository prefixes file without the `## repository-prefixes/2.0` header. `context.env` names the variable. |
| `STORE_FILE_REFETCHED` | A stored locked file did not match its `raeva.lock` checksum and was downloaded again. Every mode reports it, including `--frozen`. |
| `SYSTEM_SCOPE` | A `system` dependency names a local file. |
| `TRANSITIVE_REPO_DROPPED` | A repository dependency POMs declare was ignored. Not reported for Maven Central, which is searched anyway, or for a snapshot-only repository that a release POM declares. One warning per repository: `context` holds `url` (redacted) and `declared_by`, the POMs that declare it, sorted. See `security.transitive_repository_allowlist` in [Configuration](configuration.md). |
| `UNTRUSTED_CLASSIFIER_ORIGIN` | `raeva export-m2` skipped a sources or Javadoc jar whose recorded origin the configuration and the project's POMs do not declare. |
| `VEX_STATEMENT_UNUSED` | A `--vex` statement matched no finding (`raeva vuln`) or no dependency (`raeva sbom`), for example because the dependency changed version, and every module it names, in any version, was covered. `context` has `path`, `statement` and `vulnerability`. |
| `WEAK_HASH_FALLBACK` | No SHA-256 was published, so `raeva` verified with SHA-1 or, failing that, MD5. One warning per run: for several files, `context` has the `count` and one example `path`. |
