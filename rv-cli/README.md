# rv-cli

The command-line interface for Raeva. This crate is the entry point for the application, handling argument parsing, logging initialization, and command dispatch.

## Binary

This crate produces a single binary, **`rv`**, a lockfile companion for Maven projects. It reads your existing `pom.xml`, writes an `rv.lock` with exact versions and checksums, and populates `~/.m2` so you can keep building with Maven.

## Commands

`rv` exposes seven subcommands:

*   **`sync`**: Resolve dependencies, download and verify artifacts, and write/update `rv.lock`.
*   **`export-m2`**: Populate `~/.m2/repository` from the locked artifacts so `mvn -o` can build offline.
*   **`tree`**: Show the dependency tree recorded in `rv.lock` (supports `--scope` and `--depth`).
*   **`why`**: Explain why a dependency is present by listing the paths from a root to the given coordinate.
*   **`doctor`**: Diagnose repository connectivity, TLS, auth, and proxy configuration.
*   **`lock`**: Inspect (`lock info`) or verify (`lock verify [--download]`) the lockfile against the content store.
*   **`export-checksums`**: Write Maven 4 Trusted Checksums sidecars to `.mvn/checksums/`.

Global flags (available on every subcommand): `-C/--project-root <PATH>`, `-v/--verbose`, `-q/--quiet`, and `--json` (machine-readable output; implies `--quiet`).

## Structure

*   `src/bin/`: Binary entry point (`rv.rs`).
*   `src/commands/`: Implementation of individual subcommands. Each command has its own module and argument struct.
*   `src/dispatch.rs`: `clap` definitions and the main dispatch switch.
*   `src/output.rs`: Helpers for terminal output: spinners, colors, tables, and the JSON envelope.
*   `src/error.rs`: The typed error hierarchy and stable numeric exit codes.

## Adding a Command

1.  Create a new module in `src/commands/`.
2.  Define the argument struct using `clap`.
3.  Implement a `run` function.
4.  Add the variant to the `Commands` enum in `src/dispatch.rs`.
5.  Add the dispatch arm in the `rv()` function in `src/dispatch.rs`.
