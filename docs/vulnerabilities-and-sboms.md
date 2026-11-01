# Vulnerability scans and SBOMs

```bash
raeva vuln
raeva vuln --format sarif --fail-on critical
raeva vuln --vex vex.json
raeva vuln --baseline base.lock
raeva sbom -o bom.cdx.json
```

## `raeva vuln`

`raeva vuln` checks `raeva.lock` against OSV. The default is a table ordered
by severity, after a line naming every platform and target JDK scanned.
By default, it scans the union of every recorded target. Exact dependency
purls are deduplicated across modules, platforms, and JDKs. The Fixed column is the nearest version above the locked one that the
advisory names as fixed, and a note names `raeva why` for the dependency
that tops the table. JSON lists each result's `findings` with `id`,
`severity` and `fixed`; SARIF puts the severity and fixed version in the
message and in `properties`. `--format sarif` writes SARIF 2.1.0 on stdout (even with
`--json`; errors go to stderr). `raeva --json vuln` uses the JSON envelope.
See [Exit codes](json-output.md#exit-codes).

| Code | Meaning |
| --- | --- |
| 0 | No unsuppressed findings counted toward `--fail-on` meet its threshold. |
| 1 | Unsuppressed findings counted toward `--fail-on` meet its threshold (`VULNERABILITIES_FOUND`). |
| 2 | The scan did not complete for a cause no other code describes, such as an OSV error answer or a response `raeva` cannot use. |
| 3, 4, 7 | Incomplete scan: 3 for invalid configuration, a missing or invalid `raeva.lock`, `--baseline`, or `--vex` file, or an untrusted certificate; 4 when OSV cannot be reached or keeps answering 429, 502, 503 or 504; 7 when `raeva.lock` is out of date. |

When OSV names a record that `raeva vuln` then cannot fetch, the scan is
incomplete. It prints the findings it has, names the missing records, and
exits with the fetch-error code (2 when those codes differ), never 0 or 1.
`raeva --json vuln` sets `complete` to false and lists `failed_records`.
SARIF gets `executionSuccessful: false`.

`--fail-on` takes `any`, `low`, `medium`, `high` (default), `critical`, or
`never`. Unknown severity, shown as `Unknown (no CVSS score)`, meets every
threshold but `never`. A CVSS score of 0.0 is None, which only `any` meets.
`never` reports the findings and exits 0, but an incomplete scan or invalid
configuration still fails. A record's severity comes from its newest CVSS version,
scored on the base metrics, or from `database_specific.severity` when no
CVSS score is usable. `--offline` is a usage error (exit
2). OSV uses the configured proxies, timeout, and retries, and follows
redirects only within the same origin. `RAEVA_OSV_BASE_URL` selects another
OSV API.

### Compare against a baseline

`raeva vuln --baseline base.lock` applies `--fail-on` only to new findings.
Every current finding is still reported. The table labels each as `New` or
`Existing`, including findings suppressed by VEX. JSON adds `new` to each
finding, and SARIF sets `baselineState` to `new` or `unchanged`.
Without `--baseline`, the threshold applies to every unsuppressed finding.

A finding is one exact dependency purl paired with one OSV advisory ID.
The purl includes the version, type, and classifier. A finding is existing
when that pair occurs anywhere in the baseline, in any of its platform/JDK
sections and modules. Module names, paths, targets, reachability, and VEX
statements do not change its identity. `--module`, `--platform` and `--jdk`
select from the current inventory only. Dependencies reached only at test
scope are left out of both inventories unless `--include-test` is given.

Only the current inventory is queried, each distinct purl once, and batch
advisory records are fetched once per ID. The baseline counts only by its
purls, so a newly published advisory on an unchanged dependency counts as
existing.
Adding a dependency, changing its version, type, or classifier, or moving it
from test-only to a scanned scope can introduce a new finding. An advisory
already present on another dependency does not make that finding existing.
Severity and fixed-version changes alone do not make a finding new.

VEX applies to current findings as usual. A new finding suppressed in every
current module does not count toward the threshold. Existing findings can
remain unsuppressed and still pass. The baseline needs no POMs, freshness
check or matching targets, but it must be a valid lockfile. A pull request
that adds a platform or a `[lock] jdks` entry still compares: adding a
package to another target, or moving it there, does not make its findings
new. A missing, unreadable, empty, malformed, or incompatible baseline fails
with exit 3 (`INVALID_PROJECT_INPUT`). Relative baseline paths are relative
to the working directory. Query or record-fetch failures fail the scan.

For a pull request, save the base branch's `raeva.lock` as `base.lock`, then
run `raeva vuln --baseline base.lock`. If the base has no lock, choose
explicitly whether to run a full scan without `--baseline` or to skip the
comparison. A missing file never silently means that every finding is new.
Also run `raeva vuln` without `--baseline` on the main branch and on a
schedule, so that advisories newly disclosed in unchanged dependencies are
caught.

### Choose platforms and JDKs

`--platform linux-x86_64` limits the scan to that recorded OS and
architecture. `--jdk 21` limits it to that exact recorded target JDK string.
Combine them to scan one target, or give either one to scan all matching
targets. A lock without named target JDKs cannot match `--jdk`. An unmatched
selector fails with exit 2 and lists available targets. There is no host
fallback. A JDK-less target is reported without a JDK; the scan does not
infer the JDK used to write it from the current host.

Selectors apply to the current inventory only, and `--include-test` to both
inventories. A finding's identity excludes the target, so moving the same
purl between targets leaves the finding existing. Selecting one target
compares that target's inventory against the whole baseline. `--module` must match a
module in each selected current target; narrow the targets when a module
exists only in part of the lock.

VEX is assessed against each selected module identity that reaches the
exact dependency. A finding stays active if any such identity lacks a
suppressing statement, even when module paths are the same across targets.
`vuln triage` accepts the same target and scope options.

### Test dependencies

By default, `raeva vuln` leaves out what a module has only on its test classpath: the
packages that resolve to `test`, the scope `mvn dependency:list` shows for
them, which raeva.lock records for each package. A package takes the scope
of its direct declaration, else the widest scope of its paths, so one that a
test dependency and a compile dependency both bring in is compile, and so
are its own dependencies. `compile`,
`runtime`, `provided`, and `system` dependencies are scanned. Each module is
filtered before the modules are combined, so a library that one module uses
in tests and another at compile scope is scanned and listed for the second
module only. The count of dependencies
left out is `test_only_dependencies` in JSON and a `Not scanned` line in
the table. `--include-test` scans those dependencies too, with the same
threshold, baseline comparison, and VEX rules. It sets the skipped count to
zero. Workspace modules remain excluded from OSV queries.

## VEX

`--vex FILE` reads an [OpenVEX](https://github.com/openvex/spec) document
and can be repeated. Nothing is read unless you name a file. A statement
applies to a finding when all of these hold:

- one of its `products` is the module's purl, as `raeva sbom` writes it,
  for example `pkg:maven/com.acme/app@1.0` (with `?type=war` for a `war`
  module), or that purl without its version, `pkg:maven/com.acme/app`,
  which covers every version of the module;
- one of that product's `subcomponents` is the dependency's purl, version
  included, so upgrading or downgrading the dependency ends the statement;
- `vulnerability.name` or one of its `aliases` is the OSV id or one of the
  record's aliases.

A product or subcomponent is named by `identifiers.purl` or a purl `@id`.
Only `not_affected` with a `justification` suppresses: the finding is shown
apart, counted as `suppressed`, gets a SARIF `suppressions` entry, and does
not count toward `--fail-on`. `affected`, `fixed`, and
`under_investigation` are shown next to the finding and suppress nothing.
Suppression is per module: a finding in two modules stays active in the
one without a statement, and its SARIF result lists only that module. An
incomplete scan fails as before. A statement that matched no finding warns
`VEX_STATEMENT_UNUSED`, so a stale one can be removed, when every module it
names, in any version, was scanned; `raeva sbom --vex` warns for a statement
that names no dependency of those modules.

`raeva` reads a subset of OpenVEX 0.2.0 (`@context`
`https://openvex.dev/ns/v0.2.0`) and fails with exit 3
(`INVALID_PROJECT_INPUT`) on anything else: another version, a product
without subcomponents, a purl with a `#` subpath, `not_affected` without a
justification, or a justification on another status. Two statements that say different things
about one finding fail too, even when their timestamps differ; OpenVEX
would let the newer one win, and raeva does not order statements by time.

### Recording a statement

```bash
raeva vuln triage CVE-2024-0001 --justification vulnerable_code_not_in_execute_path \
  --vex vex.json --author "Example Team" --module app/pom.xml \
  --impact-statement "the parser is never called"
```

`raeva vuln triage ID` scans like `raeva vuln`, finds the advisory by id or
alias, and adds a `not_affected` statement for it to the `--vex` file.
`--justification` takes one of the OpenVEX values:
`component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary`, or
`inline_mitigations_already_exist`. The finding must be unique: when the
advisory affects several modules or dependencies, the command lists them
and `--module` and `--component` (the purl, or the coordinate as the table
shows it) pick one. The statement names the module without its version, so
it still applies after a release; `--product-version` names this module
version only. A statement that is already there leaves the file
unchanged; one that says something else for the same finding fails, and
the file is not touched. A new file needs `--author`, checked before the
scan, and gets `@context`,
`@id`, `author`, `timestamp`, and `version`. Each write raises `version`,
sets `last_updated`, and replaces the file in one step. The file is
rewritten with sorted keys; every field is kept.

## Platform and module

`raeva vuln` and `raeva sbom` cover every recorded platform and JDK by
default and print their coverage on stderr. `--platform OS-ARCH` and
`--jdk VERSION` restrict coverage to matching recorded targets. The JDK
string must match exactly. An unmatched target is an error; neither command
falls back to the host or another target.

`--module` limits either command to one reactor module, by root-relative
`pom.xml` path or unique `groupId:artifactId`. A selector that matches none
or several exits 2.

## `raeva sbom`

`raeva sbom` writes CycloneDX 1.5 JSON from `raeva.lock` to stdout, or to
the file `-o` names. It includes locked SHA-256 hashes. An artifact pinned
only by SHA-1 has none. It does not query OSV.

By default, the document combines all recorded targets when their selected
module graphs and evidence agree. Identical graphs are deduplicated;
disjoint inventories can be combined. If a shared module has different
dependencies, or a shared component has different hashes, POM pins,
dependency edges, or effective licenses, the command fails. Use
`--platform linux-x86_64 --jdk 21` to select a target. Module selection
applies before these checks, so an unrelated module's graph cannot block
`--module app/pom.xml`.

Each covered target appears in `metadata.properties` as a `raeva:target`
entry, such as `linux-x86_64 and JDK 21`. The same target coverage,
components, licenses, VEX analyses, and `raeva` version produce the same
bytes and document identity. Changing coverage changes the identity even
when the component inventory stays the same.

Licenses come from each component's effective POM, including inherited
licenses and target-specific property interpolation. This includes the
root component in `metadata.component`. An unambiguous SPDX name,
identifier, or known URL becomes `license.id` when CycloneDX 1.5 accepts
that identifier. Otherwise, `license.name` keeps the supplied name. Unknown URLs without a name are retained as names.
Components with no declared licenses omit `licenses`. Dependencies locked
without a POM, including system-path dependencies, also omit licenses.

License extraction needs local reactor POMs and the SHA-256-pinned
dependency and parent POMs in the content store. It reads the locked bytes,
not the coordinate cache, and makes no network requests. Missing or damaged
pinned evidence exits 7 (`LOCKFILE_MISMATCH`), and a lock without a pin or
range selection a model needs exits 3. Parent ranges use the selections recorded
when each module locked its models, including inherited parent chains.
Other modules' pins do not change those selections. Run `raeva sync --frozen` to restore locked POMs.
Imported BOMs are not needed for license extraction.

`raeva sbom --vex FILE` adds each statement about a selected module's
dependency as a CycloneDX `vulnerabilities` entry, with `analysis.state`
(`not_affected`, `exploitable` for `affected`, `resolved` for `fixed`,
`in_triage` for `under_investigation`), `analysis.justification`, and the
impact statement as `analysis.detail`. Justifications map to
`code_not_present` (`component_not_present`, `vulnerable_code_not_present`),
`code_not_reachable`, `requires_environment` (cannot be controlled by an
adversary), and `protected_by_mitigating_control`. Statements whose names
or aliases overlap, directly or through another statement, are about one
vulnerability and are exported once.

A dependency appears once across the selected modules. An `affected`
assessment takes precedence over every other status. Otherwise, a missing
assessment or `under_investigation` keeps the combined analysis in triage.
All `fixed` assessments resolve it; all `not_affected` assessments mark it
unaffected. A mixture of `fixed` and `not_affected` stays in triage.
Justification is kept only when every module agrees on status and
justification. When assessments differ, `analysis.detail` records each
module's path, assessment, and impact statement, including modules with no
assessment. Identical assessments keep their original detail. Contradictory
statements within one module remain an error. `--module` limits both the
inventory and the module evidence used for the combined analysis.
