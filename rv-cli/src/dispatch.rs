use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::commands;
use crate::error::Result;
use crate::output::WarningCollectorLayer;

#[derive(Debug, Parser)]
#[command(
    name = "rv",
    version,
    about = "A lockfile companion for Maven projects",
    long_about = "Raeva reads your existing pom.xml, writes an rv.lock with exact versions and checksums, \
and populates ~/.m2 so you can keep using Maven.\n\n\
Quick start:\n  \
rv sync          Resolve and lock dependencies\n  \
rv export-m2     Populate ~/.m2/repository\n  \
mvn -o test      Build with Maven (offline, using locked deps)"
)]
pub struct RvCli {
    #[arg(
        long,
        short = 'C',
        value_name = "PATH",
        default_value = ".",
        global = true,
        help = "Your project directory (default: current folder)"
    )]
    pub project_root: PathBuf,
    #[arg(
        long,
        short = 'v',
        action = ArgAction::Count,
        global = true,
        help = "Show more output for debugging (repeatable; set RUST_LOG to override verbosity entirely)"
    )]
    pub verbose: u8,
    #[arg(
        long,
        short = 'q',
        global = true,
        help = "Show only essential output (no spinners or progress bars)"
    )]
    pub quiet: bool,
    #[arg(
        long,
        global = true,
        help = "Produce machine-readable JSON output (implies --quiet)"
    )]
    pub json: bool,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Resolve dependencies, download artifacts, and update rv.lock
    Sync(commands::SyncArgs),
    /// Export lockfile artifacts to ~/.m2/repository
    ExportM2(commands::ExportM2Args),
    /// Show the dependency tree from rv.lock
    Tree(commands::TreeArgs),
    /// Explain why a dependency is included
    Why(commands::WhyArgs),
    /// Diagnose connectivity, auth, and TLS issues
    Doctor(commands::DoctorArgs),
    /// Inspect or verify the lockfile
    Lock(commands::LockArgs),
    /// Export checksums in Maven Trusted Checksums format
    ExportChecksums(commands::ExportChecksumsArgs),
    /// Scan locked dependencies for known vulnerabilities
    Vuln(commands::VulnArgs),
    /// Generate a software bill of materials from rv.lock
    Sbom(commands::SbomArgs),
}

pub async fn rv() -> Result<()> {
    let cli = RvCli::parse();
    let json_mode = cli.json
        || matches!(
            &cli.command,
            Commands::Vuln(args) if args.json_output()
        );
    if json_mode {
        crate::output::set_quiet(true);
        crate::output::set_json_mode(true);
    } else {
        crate::output::set_quiet(cli.quiet);
    }
    init_tracing(cli.verbose, json_mode);

    match cli.command {
        Commands::Sync(args) => commands::sync::run(&args, &cli.project_root).await?,
        Commands::ExportM2(args) => commands::export_m2::run(&args, &cli.project_root).await?,
        // tree / why / export-checksums are pure sync filesystem readers
        // (no .await internally). Run them on a blocking worker so their
        // std::fs reads don't park the runtime's IO thread.
        Commands::Tree(args) => {
            let project_root = cli.project_root.clone();
            spawn_blocking_command(move || commands::tree::run(&args, &project_root)).await?
        }
        Commands::Why(args) => {
            let project_root = cli.project_root.clone();
            spawn_blocking_command(move || commands::why::run(&args, &project_root)).await?
        }
        Commands::Doctor(args) => commands::doctor::run(&args, &cli.project_root).await?,
        Commands::Lock(args) => commands::lock_verify::run(&args, &cli.project_root).await?,
        Commands::ExportChecksums(args) => {
            let project_root = cli.project_root.clone();
            spawn_blocking_command(move || commands::export_checksums::run(&args, &project_root))
                .await?
        }
        Commands::Vuln(args) => commands::vuln::run(&args, &cli.project_root).await?,
        Commands::Sbom(args) => {
            let project_root = cli.project_root.clone();
            spawn_blocking_command(move || commands::sbom::run(&args, &project_root)).await?
        }
    }

    Ok(())
}

async fn spawn_blocking_command<F>(f: F) -> Result<()>
where
    F: FnOnce() -> Result<()> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| crate::error::CliError::Message(format!("command task panicked: {e}")))?
}

fn init_tracing(verbosity: u8, json_mode: bool) {
    // In JSON mode without an explicit verbose flag, suppress tracing output
    // entirely so structured `warn!`/`info!` lines from library crates never
    // bleed onto stderr next to the single JSON envelope on stdout. Verbose
    // still wins so operators can debug `--json -v` runs. An explicit
    // `RUST_LOG` also wins, preserving the existing escape hatch.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = match (json_mode, verbosity) {
            (true, 0) => "off",
            (_, 0) => "warn",
            (_, 1) => "info",
            (_, 2) => "debug",
            _ => "trace",
        };
        EnvFilter::new(level)
    });

    // Pin tracing output to stderr to keep stdout reserved for command results.
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(filter);

    // Carries its own WARN filter so `sec_code` events still reach the
    // JSON envelope when the fmt layer is set to `off` in `--json` mode.
    let warn_layer = WarningCollectorLayer::global().with_filter(LevelFilter::WARN);

    let _ = tracing_subscriber::registry()
        .with(fmt_layer)
        .with(warn_layer)
        .try_init();
}
