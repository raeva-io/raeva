//! The `raeva` command-line interface for Raeva.
//!
//! This package builds only the `raeva` binary. Its contract is the behavior of
//! that binary: flags, exit codes, the split between stdout and stderr, and
//! the shape of the JSON envelope.

#![allow(missing_docs)]

mod commands;
mod dispatch;
mod error;
mod output;
mod session;

use std::process::ExitCode;

use clap_complete::CompleteEnv;

/// The stack of the thread that runs the CLI and of each runtime thread. A
/// main thread has 1 MiB on Windows and `ulimit -s` elsewhere, and tokio's
/// default is 2 MiB, while a debug build's async frames take over 2 MiB and
/// fifty nested BOM imports take over 1 MiB in a release build.
const STACK_SIZE: usize = 8 << 20;

fn main() -> ExitCode {
    let cli = std::thread::Builder::new()
        .name("main".to_string())
        .stack_size(STACK_SIZE)
        .spawn(run);
    match cli {
        Ok(cli) => cli
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
        Err(err) => {
            eprintln!("failed to start the main thread: {err}");
            error::ExitStatus::Startup.into()
        }
    }
}

/// Owns the tokio runtime, signal handling, and final exit-envelope
/// rendering.
fn run() -> ExitCode {
    CompleteEnv::with_factory(dispatch::command).complete();

    if let Err(err) = rustls::crypto::ring::default_provider().install_default() {
        // A startup failure has its own status, so CI tooling can tell
        // host-environment problems apart from a command's own failure.
        eprintln!("failed to install rustls crypto provider: {err:?}");
        return error::ExitStatus::Startup.into();
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(STACK_SIZE)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to initialize async runtime: {}", e);
            return error::ExitStatus::Startup.into();
        }
    };

    let outcome = runtime.block_on(async {
        // On Ctrl-C or SIGTERM, drop the in-flight main future so tokio
        // cancels its tasks and RAII guards (file locks, temp files, SQLite
        // WAL) get a chance to run. A brief grace window after the runtime
        // stops lets those drops complete before we exit.
        tokio::select! {
            biased;
            result = dispatch::raeva() => Ok(result),
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nInterrupted.");
                Err(130)
            }
            () = terminated() => {
                eprintln!("\nTerminated.");
                Err(143)
            }
        }
    });

    let (result, output, session) = match outcome {
        Ok(finished) => finished,
        Err(code) => {
            runtime.shutdown_timeout(std::time::Duration::from_secs(2));
            return ExitCode::from(code);
        }
    };
    let hints = session
        .map(|session| session.hint_env())
        .unwrap_or_else(error::HintEnv::discover);
    output.finish(result, &hints)
}

/// Resolves on SIGTERM, which CI runners and `timeout` send to cancel a job.
/// Never resolves where SIGTERM cannot be caught.
async fn terminated() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                if term.recv().await.is_some() {
                    return;
                }
            }
            Err(err) => eprintln!(
                "warning: cannot handle SIGTERM ({err}); a run stopped with it skips its cleanup"
            ),
        }
    }
    std::future::pending().await
}
