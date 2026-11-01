# Test fixtures

Copied POMs from open-source projects, synthetic reactors, projects with
recorded Maven results, golden output, and TLS material. A version in the
Source column is the POM published to Maven Central for that release; a
version ending in `.x` names the development line a source POM came from.

## Copied POMs

`rv-maven-model/tests/real_fixtures.rs` parses every POM here (`pom.xml` and
`*-pom.xml`; the malformed files under `maven-parity/pom-markup` are skipped)
and checks some of them field by field.

| File | Source | Exercises |
| --- | --- | --- |
| `simple-single-module/commons-lang3-pom.xml` | Apache Commons Lang | `commons-parent` inheritance, test-scoped dependencies, profiles |
| `dependency-types/maven-shade-plugin-pom.xml` | Apache Maven Shade Plugin | `maven-plugin` packaging, provided Maven APIs, `<prerequisites>` |
| `bom-usage/spring-boot-dependencies-pom.xml` | Spring Boot Dependencies 3.3.0 | A large BOM with version properties |
| `bom-usage/jackson-bom-pom.xml` | Jackson BOM | A BOM with a parent and version properties |
| `bom-usage/guava-bom-pom.xml` | Google Guava BOM | A small BOM without a parent |
| `profile-based/netty-parent-pom.xml` | Netty 4.2.x | Activation by file and JDK version, profile properties |
| `complex-deps/quarkus-bom-pom.xml` | Quarkus BOM 3.11.0 | A large BOM with `json` and `properties` types, classifiers, and exclusions |

## Synthetic fixtures

| Directory | Contents |
| --- | --- |
| `reactor-discovery/` | Small reactors for module discovery. They cover nested and profile-declared modules, inherited properties, deduplication, and external parents. A module cycle, a duplicate GAV, and a symlink that leaves the project are the error cases. |
| `reactor-resolution/` | Reactors that `rv-resolver` resolves end to end. Modules use BOMs, classifiers, version ranges, snapshots, `${revision}`, and their own repositories. The reactors also include a remote parent and a module cycle. |
| `reactor-cli/` | Reactors that the `raeva` integration tests sync: a basic reactor, the Maven repository its tests serve (`basic-repository/`), and a reactor checked out with CRLF and with LF line endings. |
| `maven-parity/` | Small projects with the results Maven 3.9.11 recorded for them in `maven-3.9.11-<platform>.txt`: success or the error, module coordinates, active profiles, artifacts or classifiers, and package scopes. `raeva/tests/cli/maven_parity.rs` syncs each project and compares. A case where `raeva` knowingly differs, such as a POM in EBCDIC that declares an EBCDIC code page, which `raeva` refuses, states `raeva`'s outcome in the same keys in `raeva-differs.txt` and says why there. The groups cover OS activation, `os.detected.*`, parent and module coordinates, interpolation, `.mvn/maven.config`, profile selection, snapshot versions, dependency scopes, and the scope of repositories that fetched POMs declare. A case with a `srv/` directory is served over HTTP, with `@BASE@` standing for the server's address, since `raeva` takes repositories from fetched POMs only over HTTP or HTTPS. |
| `lock-golden/` | Golden lock bytes. `repository/` is a small Maven repository with SHA-256 and SHA-1 sidecars. Each sync case holds a `project/` and the `raeva.lock` an offline `raeva sync` of it must write byte for byte (`raeva/tests/cli/lock_golden.rs`). `api-built/raeva.lock` is the lock `rv-lock/tests/lock_bytes.rs` builds through the library API, and `round-trip/raeva.lock` is a reactor lock with both metadata blocks. Every `raeva.lock` here must read and write back unchanged. |
| `maven-snapshot-layout/` | What Maven 3.9.11 left in a fresh local repository after `mvn test-compile` downloaded `com.example:snaplib:1.0-SNAPSHOT` (build `1.0-20261017.210153-2`, with a sources jar) from a repository with id `snaps`: the file list, `_remote.repositories` and the version metadata, in `plain/` without a mirror and in `mirror/` behind a `mirrorOf=*` mirror with id `corp`. `rv-export/src/export/tests.rs` exports the same snapshot and compares. |
| `json-payloads/` | The `--json` output of each command, one success and one failure, with volatile values replaced by placeholders (`raeva/tests/cli/json_payloads.rs`). |
| `error-golden/` | `diagnostics.txt`: the error code, exit status and human text of each `raeva` error (`errors_render_as_the_golden_file_shows` in `raeva/src/error/diagnose.rs`). |
| `help/` | The `--help` output of `raeva` and of `sync`, `lock diff`, `vuln` and `vuln triage` (`help_matches_the_snapshots` in `raeva/tests/cli/command_help.rs`). |
| `lock-diff/` | Edited copies of `lock-golden/` locks, and `frozen.txt`, the `--frozen` diff raeva prints between each pair (`raeva/src/commands/sync/diff.rs`). |
| `lock-input-hashes/` | Projects, each with a `project/`, whose `config_hash` and `model_hash` `raeva/src/commands/lock_inputs/golden_hashes.rs` pins. A change to one breaks every committed lock. A `home/` directory, when present, is the user's Raeva and Maven homes. |
| `tls/` | A test CA (`ca.pem`), a server certificate for `127.0.0.1` and `localhost` signed by it (`server.pem`, `server.key`), and an unrelated CA (`other-ca.pem`). The key is for tests only. |
| `nearest-backtracking/` | `reproduce.py` builds local Maven fixtures and compares Maven's verbose dependency trees with the expected trees in the script. The tests in `rv-resolver/src/solver/tests/nearest.rs` cover the same cases. It needs Maven and JDK 21. |

## Golden files

`lock-golden/`, `json-payloads/`, `error-golden/`, `lock-diff/` and `help/`
hold expected output. A test fails and shows the first differing lines when the
output changes. When a change is intended, regenerate the files and commit the
reviewed diff together with the change that caused it:

```sh
RAEVA_TEST_BLESS=1 cargo test -p raeva --test cli -- lock_golden json_payloads help_matches
RAEVA_TEST_BLESS=1 cargo test -p raeva --bin raeva -- errors_render frozen_diffs
RAEVA_TEST_BLESS=1 cargo test -p rv-lock --test lock_bytes
```

The tests copy fixtures with CRLF folded to LF, and the `.gitattributes` files
in `lock-golden/`, `json-payloads/`, `lock-diff/` and `help/` keep Git from
converting line endings, so the bytes are the same on every platform.
