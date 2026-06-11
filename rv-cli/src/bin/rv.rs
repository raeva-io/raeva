//! Main entry point for the `rv` CLI binary.
//!
//! All wiring lives in [`rv_cli::run_cli`]; this binary is a thin shim.

use std::process::ExitCode;

fn main() -> ExitCode {
    rv_cli::run_cli()
}
