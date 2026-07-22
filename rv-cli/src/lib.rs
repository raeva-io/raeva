//! Command-line interface for Raeva (`rv`).
//!
//! This crate wires together the dispatch entry point, individual subcommand
//! implementations (`sync`, `tree`, `why`, `doctor`, `lock`, `export-m2`,
//! `export-checksums`, `vuln`, `sbom`), the typed error hierarchy with stable exit codes, and
//! the human/JSON output layer. The library is consumed by the `rv` binary in
//! `src/bin/rv.rs`. Everything user-facing (flag parsing, exit codes, stdout
//! vs stderr discipline, JSON envelope shape) is part of the v0.1 CLI
//! contract once tagged.
//!
//! The only public entry point is [`run_cli`]; all submodules are
//! `pub(crate)`. rv-cli is a binary-only crate (no consumers other than its
//! own `bin/rv.rs`), so a single typed entry point gives us room to refactor
//! the internals freely without breaking downstream callers.

pub(crate) mod commands;
pub(crate) mod dispatch;
pub(crate) mod error;
pub(crate) mod output;

use std::process::ExitCode;

use clap::CommandFactory;
use clap_complete::CompleteEnv;

/// Entry point used by `bin/rv.rs`. Owns the tokio runtime, signal
/// handling, and final exit-envelope rendering.
pub fn run_cli() -> ExitCode {
    CompleteEnv::with_factory(dispatch::RvCli::command).complete();

    if let Err(err) = rustls::crypto::ring::default_provider().install_default() {
        // Route startup-class failures through `STARTUP_ERROR` so CI
        // tooling can tell host-environment problems apart from a
        // command's own exit-1 failure path.
        eprintln!("failed to install rustls crypto provider: {err:?}");
        return ExitCode::from(error::ExitCodes::STARTUP_ERROR as u8);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to initialize async runtime: {}", e);
            return ExitCode::from(error::ExitCodes::STARTUP_ERROR as u8);
        }
    };

    let outcome = runtime.block_on(async {
        // On ctrl_c, drop the in-flight main future so tokio cancels its
        // tasks and RAII guards (file locks, temp files, SQLite WAL) get
        // a chance to run. A brief grace window after the runtime stops
        // lets those drops complete before we exit 130.
        tokio::select! {
            biased;
            result = dispatch::rv() => Some(result),
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nInterrupted.");
                None
            }
        }
    });

    let Some(result) = outcome else {
        runtime.shutdown_timeout(std::time::Duration::from_secs(2));
        return ExitCode::from(130);
    };

    if let Err(err) = result {
        let code = err.exit_code();
        // `AlreadyReported` means the command has already written its full
        // user-facing report (e.g. doctor's structured JSON envelope) and
        // only needs the process to exit. Printing another envelope here
        // would give JSON consumers two root objects on stdout.
        if matches!(err, error::CliError::AlreadyReported { .. }) {
            return ExitCode::from(code as u8);
        }
        if output::is_json_mode() {
            output::json_result(
                false,
                serde_json::json!({
                    "error": err.user_message(),
                    "exit_code": code,
                }),
            );
        } else {
            output::error(err.user_message());
        }
        return ExitCode::from(code as u8);
    }
    ExitCode::SUCCESS
}
