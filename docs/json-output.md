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
`AUTH_FALLBACK` prints each refusing/serving repository pair. The text
summary omits `WEAK_HASH_FALLBACK` and `TRANSITIVE_REPO_DROPPED`. Without
`-v`, `HTTP_REPO_BLOCKED` for a repository that a dependency's POM declares
is left out of both.

## `raeva tree` and `raeva why`

Both commands return a `modules` list with one entry per selected module,
even for a single module. Each entry has `module` (the POM path) and `gav`
(`group:artifact:version`).

`raeva --json tree` returns `project`, `platform`, `jdk` (when the lock
section has a target JDK), and `modules`. Each module has `dependencies`.
Each dependency has `coordinate`, `scope` (the scope the package resolves to
in the module, as `mvn dependency:list` shows it), `optional` (that of the
declaration that brings it in on this path),
`workspace`, `workspace_module` for a project module, and `children`. A later
appearance of a dependency whose dependencies were listed where it first
appeared has `repeated` true and empty `children`. A dependency without
dependencies is just listed again. An edge back into the current path has
`cycle` true and empty `children`. `--depth 1` lists only direct dependencies.
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
the locked graph, reactor modules and `system` files left out, as text and `raeva lock info` count them),
`platforms` (the lock sections this run checked or resolved, named as in
`raeva lock diff`), and `duration_ms`.

## `raeva doctor`

`raeva --json doctor` returns `issues` (failed checks) and `checks`. Each
check has `check`, `status`, `class`, and `details`. `status` is `ok`,
`fail`, `info` (context for the other checks), or `inconclusive` (the check
could not tell; see [Checking credentials](authentication.md#checking-credentials)).
`class` is `config`, `auth`, `network`, or `other` for a failed check, else
`null`.

## `raeva lock info`

`raeva --json lock info` returns `path`, `schema_version`,
`latest_schema_version`, `last_modified`, `platform_count`, `platforms`,
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
`platforms_added` and `platforms_removed` (platforms only one lock
records), `module_changes`, `profile_changes`, `changes`, `edge_changes`,
`pom_changes`, `changed_inputs`, and `via_limited`. Hashes and order alone do
not set `changed`. `changed_inputs` lists the inputs whose recorded hashes
differ, so an edit that leaves the dependencies alone (a POM comment, say)
still shows: `config_hash` for the configuration, then each reactor POM path
whose hash differs on a platform both locks record. When nothing else
changed, text prints them on a `changed inputs:` line, which `raeva sync` also
prints when it updates raeva.lock; more than three POMs are a count. Text also
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

Each `edge_changes` item names `platform`, `module`, `from` and `to` (package
coordinates as in `changes`), `change` (`added`, `removed`, `scope`, or `optional`),
and `old` and `new` (scope or boolean strings, or scope and optional details for
an added or removed edge; `null` when absent). Edges with an added or removed
endpoint package are covered by that package's row.

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

Text groups modules with the same platform set, as `sync` does, with the
first path for a package that is not a direct dependency, and shows digests
by their first 12 hex digits.

## `raeva export-m2`

`raeva --json export-m2` returns `m2_path`, `exported`, `sources`, and
`javadocs`.

## `raeva export-checksums`

`raeva --json export-checksums` returns `path` (the SHA-256 file), `paths`
(every file written), `count`, `sha256_count`, `sha1_count`, and
`maven_properties` (the `-D` flags that make Maven enforce the files).

## `raeva vuln`

`raeva --json vuln` returns `targets` (all scanned targets, sorted by platform
and target JDK), `threshold`, `threshold_exceeded`,
`complete`, `summary`, `results`, `failed_records`, and `metadata`.
Each `targets` item has `platform` (`os-arch`) and `jdk` when a target JDK
is recorded. For a single target, top-level `platform` and optional `jdk`
are also present. SARIF puts the same list in `runs[].properties.targets`.
`--platform` and `--jdk` filter recorded targets without a host fallback.
`--include-test` includes test-only dependencies. Scope and target choices
also apply to a baseline scan.
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
findings. The identity is the exact purl (version and qualifiers included)
and OSV advisory ID, across all modules and platform/JDK sections of the
baseline. Targets are not part of the finding identity. Only the current
inventory is queried, so a new advisory on an unchanged dependency is
existing. The `--module`, `--platform` and `--jdk` selectors apply only to
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
`license.name`. Extraction uses the locked dependency and parent POM
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
| 1 | General error, such as a local store or file that cannot be used, or an internal error in `raeva`. `raeva why` found no path. `raeva vuln` found unsuppressed vulnerabilities at or above `--fail-on`. |
| 2 | Usage error, such as an unknown option, a `--module` that matches no module, or `--offline` with `raeva doctor` or `raeva vuln`. Also a `raeva vuln` scan that failed for a cause no other code describes. `raeva vuln` keeps 1 for findings. |
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
| `REPOSITORY_CONFIG` | 3 | A repository `raeva` refuses: a rejected URL, snapshots disabled for a snapshot, releases disabled for a release, a checksum policy Maven does not support, or an origin no configuration declares. |
| `NO_REPOSITORIES` | 3 | No repository is configured. |
| `INVALID_POM` | 3 or 5 | A POM `raeva` cannot use. 3: a refused project model, such as coordinates Maven rejects, a missing, blank, or relative `<systemPath>`, a property cycle, or a repository URL scheme other than `http`, `https`, or `file`. 5: a malformed or invalid POM from a repository, and other model errors. |
| `INVALID_PROJECT_INPUT` | 3 | Refused project input, such as a malformed project POM, a module that does not exist or lies outside the project, a `<systemPath>` outside it, or a `--vex` file `raeva` does not read or whose statements disagree. |
| `PROJECT_FILE_MISSING` | 3 | There is no `pom.xml`. |
| `REPOSITORY_ORIGIN_ALIAS` | 3 | Two `file:` repositories that `raeva.lock` would record as one origin name different directories. |
| `LOCAL_REPOSITORY` | 3 | The export destination cannot hold the lock: a configured path `raeva` cannot expand, a directory `raeva` cannot create or write to, names that collide on the volume, or a link that leads out of it. |
| `LOCKFILE_MISSING` | 3 | There is no `raeva.lock`. Run `raeva sync`. |
| `LOCKFILE_NOT_A_FILE` | 3 | `raeva.lock` is not a regular file. |
| `LOCKFILE_INVALID` | 3 | Another schema, or a value `raeva` refuses or cannot export. The error says what to change. Malformed lock (including an empty `checksums` list) or an older schema: `raeva sync` without `--frozen`. A newer schema: upgrade `raeva`. |
| `PLATFORM_MISSING` | 3 | No lock section for this platform. The error names the platforms it records. `hints` gives the `raeva sync --platforms` command that adds it. |
| `NETWORK` | 4 | A repository or OSV could not be reached: a timeout, a refused connection, a stalled download, or a 429, 502, 503, or 504 answer after retries. |
| `RESOLUTION` | 5 | Dependency resolution failed, such as a version range nothing satisfies, or a dependency coordinate that holds a `${...}` no property defines. |
| `ARTIFACT_NOT_FOUND` | 5 | No repository has a dependency. |
| `VERSION_CONFLICT` | 5 | A selected version does not satisfy a requirement. |
| `NOT_FOUND` | 5 or 1 | 5: a repository answered 404. 1: `raeva why` found no path to the coordinate. |
| `OFFLINE_NOT_CACHED` | 5 | `--offline`, and a needed file is not cached. The hint says to run `raeva sync` online once. |
| `REPOSITORY` | 5 | Another repository failure, such as invalid metadata, a refused redirect, an address that is not public, or a 500 answer. |
| `LOCKFILE_MISMATCH` | 7 | `raeva.lock` is valid but out of date for the project, its configuration, a fresh resolution, or the stored files. `hints` gives the update command, usually `raeva sync`. |
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
| `CACHE_ENTRY_DAMAGED` | A `metadata.db` entry no longer matched the checksum it was written with, as damage inside the file or an edit leaves it, so `raeva` dropped it and fetches the file again; an offline run reports it as not cached. |
| `CACHE_KEY_UNAVAILABLE` | The `cache-key` file beside `metadata.db` could not be read or written. The answers this run keeps for the credentials it sends are not matched by a later run. |
| `CHECKSUM_MISSING` | No checksum was published, and `--allow-missing-checksums` accepted the download. A file matching its `raeva.lock` pin needs no checksum file and gets no warning. |
| `CLASSIFIER_CHECKSUM_MISSING` | `raeva export-m2` skipped a sources or Javadoc jar with no published checksum. |
| `CLASSIFIER_NOT_STORED` | `raeva export-m2 --offline` skipped a sources or Javadoc jar the store does not hold intact: no earlier export downloaded it, the repository does not have it, or the stored file is damaged. |
| `CLEARTEXT_AUTH` | Credentials went over plain HTTP to a non-loopback host. |
| `CREDENTIAL_DROPPED` | A `settings.xml` password could not be decrypted and was dropped. `context.reason` says why. |
| `CROSS_HOST_MIRROR` | A mirror on another host serves a repository, so an `[[auth]]` entry without an `id` was not sent. |
| `DATABASE_RECREATED` | The store index or the metadata cache was damaged or was not an SQLite database, as a partial CI cache restore can leave it, so `raeva` deleted it and started a new one. `context.path` names it. Stored files are still checked against `raeva.lock`; what the lost entries held is hashed or downloaded again. |
| `DEFAULT_CREDENTIAL_WITHHELD` | An `[[auth]]` entry without an `id` was not sent to an origin your own files do not name ([Authentication](authentication.md#precedence)). |
| `ENV_VALUE_IN_LOCKFILE` | A `raeva.lock` field holds the value of an allowlisted environment variable. |
| `ENV_VAR_HIDDEN` | A POM reads an environment variable other than `JAVA_HOME` and `PWD` that is set, as `${env.NAME}`, `${NAME}` in the model, or an `env.NAME` activation, and that `allow_env_substitution` does not list, so `raeva` treats it as unset where Maven reads its value. `context.variable` names it; the value is never shown. Allow it in `[security] allow_env_substitution` in `config.toml` if the value may be public. |
| `EXPORT_PERMISSIONS_NOT_SET` | `raeva export-m2` could not make an exported file owner-writable. |
| `EXPORT_SHARED_REPOSITORY` | `raeva export-m2` wrote into the Maven local repository other builds share, so it removed no metadata and `mvn -o` there is not a locked build. `context.m2_path` names it. See [Offline builds](offline-builds.md#a-repository-of-its-own). |
| `EXPORT_SYSTEM_SCOPED_SKIPPED` | `raeva export-m2` skipped `system` dependencies. Their files are not in the store. |
| `EXPORT_WARNING` | An export warning this `raeva` has no specific code for. |
| `FETCHED_POM_REPO_REFUSED` | A parent POM from a repository declared a repository that is not HTTP or HTTPS. `raeva` ignored it. |
| `HTTP_REPO_BLOCKED` | A repository a POM declares uses plain HTTP to a host other than `localhost` or `127.0.0.1`, and nothing in your configuration names its URL or mirrors it, so it was ignored, as Maven's default HTTP blocker does. Reported for the project and its parents, and for a dependency's POM only with `-v`: a dependency that only such a repository has fails with an error that names it. See [Configuration](configuration.md). |
| `ID_CREDENTIAL_WITHHELD` | An id credential was not sent to a repository a fetched POM declares, on an origin neither your configuration nor the project's POMs name ([Authentication](authentication.md#precedence)). |
| `JAVA_VERSION_DEFAULTED` | A POM, a `settings.xml` profile or a `.mvn/maven.config` value reads `java.version` where it can change resolution, and neither `JAVA_HOME` nor `JAVA_VERSION` names a JDK, so `raeva` used 17. `context.pom` names the POM when a POM profile condition read it. Set `JAVA_HOME`, or list the JDKs in `[lock] jdks`. |
| `JDK_NOT_LOCKED` | `raeva sync` ran on a host JDK that matches no entry in `[lock] jdks`. It resolved the listed JDKs. |
| `LISTING_REPO_SKIPPED` | A version range, `RELEASE` or `LATEST` was resolved without a repository that failed, other than with a 404 or a 401 or 403 (which `AUTH_FALLBACK` reports), while another repository answered. |
| `LOCKFILE_REGENERATED` | `raeva sync` replaced a `raeva.lock` it cannot read, such as an older schema or one with merge conflict markers, keeping the platforms it names. The message says whether the change list compares with the `raeva.lock` at git `HEAD`. |
| `LOW_DISK_SPACE` | Less than 100 MiB free on the store volume. |
| `METADATA_CHECKSUM_MISMATCH` | `maven-metadata.xml` still mismatched its checksum after a second download, and the repository's checksum policy accepted it. |
| `PLATFORM_DROPPED` | `raeva sync --platforms` dropped an unselected platform whose pins no longer match. The warning names the command that restores it. |
| `PLATFORM_FALLBACK` | No lock section matches this machine's platform and JDK. The command used another section from the lock. |
| `POM_PROBLEM` | Invalid POM, unreadable local parent, or a scope Maven does not know. `raeva` continues as Maven does: it drops that POM's dependencies, looks the parent up in the repositories, or treats the scope as `compile`. An invalid dependency POM is reported only when the resolution selects its version, not for each version a range reads. |
| `PROFILE_NOT_FOUND` | A profile id that `-P`, `.mvn/maven.config`, `raeva.toml`, `config.toml` or `settings.xml` `<activeProfiles>` requests is not the id of a profile any reactor POM or its parents activates, nor of a `settings.xml` profile, so it activates nothing, as Maven warns. A project with a parent POM that is not in the reactor gets no warning, since that parent may have the profile. |
| `PROJECT_LOCAL_REPOSITORY_IGNORED` | `raeva export-m2` ignored `local_repository` in the project `raeva.toml`, or `-Dmaven.repo.local` in `.mvn/maven.config`. |
| `PROJECT_REPO_URL_FROM_FETCHED_POM` | A project POM repository URL comes from a fetched parent, so the repository has that parent's trust. |
| `PROJECT_SECURITY_WIDENING_IGNORED` | Project `raeva.toml` set `[security]` wider than the user `config.toml`. That part was ignored. |
| `REPO_URL_SECRET_REFUSED` | A POM repository URL has userinfo, a query, or a fragment, which may hold a credential. Ignored, and the URL is not shown. `context` holds `repository` (the id) and `declared_by` (the declaring POM, when known). |
| `SETTING_IGNORED` | An unusable setting was ignored: an environment variable such as `RAEVA_MAX_ARTIFACT_SIZE`, `RAEVA_HOME`, `SSL_CERT_FILE`, or `SSL_CERT_DIR` with a value `raeva` cannot use; `settings-security.xml` that is not valid XML; a `settings.xml` proxy protocol other than `http`, `https`, or `all`; a `<mirrorOf>` pattern Maven does not know; `-s` or `-gs` in `.mvn/maven.config`, since a project cannot choose the settings file; or an `rv.toml` or `rv.lock`, the names older releases used, where no `raeva.toml` or `raeva.lock` exists. `context.env` names the variable. |
| `STORE_FILE_REFETCHED` | A stored locked file did not match its `raeva.lock` checksum and was downloaded again. Every mode reports it, including `--frozen`. |
| `SYSTEM_SCOPE` | A `system` dependency names a local file. |
| `TRANSITIVE_REPO_DROPPED` | A repository dependency POMs declare was ignored. Not reported for Maven Central, which is searched anyway, or for a snapshot-only repository that a release POM declares. One warning per repository: `context` holds `url` (redacted) and `declared_by`, the POMs that declare it, sorted. See `security.transitive_repository_allowlist` in [Configuration](configuration.md). |
| `UNTRUSTED_CLASSIFIER_ORIGIN` | `raeva export-m2` skipped a sources or Javadoc jar whose recorded origin the configuration and the project's POMs do not declare. |
| `VEX_STATEMENT_UNUSED` | A `--vex` statement matched no finding (`raeva vuln`) or no dependency (`raeva sbom`), for example because the dependency changed version, and every module it names, in any version, was covered. `context` has `path`, `statement` and `vulnerability`. |
| `WEAK_HASH_FALLBACK` | No SHA-256 was published, so `raeva` verified with SHA-1 or, failing that, MD5. One warning per run: for several files, `context` has the `count` and one example `path`. |
