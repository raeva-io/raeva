use std::path::PathBuf;

use clap::{ArgAction, ArgMatches, Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use tracing_subscriber::filter::{FilterExt, LevelFilter, filter_fn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use rv_config::maven_config::CommandLine;

use crate::commands;
use crate::error::Result;
use crate::output::{Mode, Output, Report};
use crate::session::Session;

/// The help heading of the options every command takes, so a command's own
/// options come first.
const GLOBAL: &str = "Global Options";

#[derive(Debug, Parser)]
#[command(
    name = "raeva",
    bin_name = "raeva",
    version,
    about = "A lockfile companion for Maven projects"
)]
pub(crate) struct Cli {
    #[arg(
        long,
        short = 'C',
        value_name = "PATH",
        default_value = ".",
        global = true,
        help_heading = GLOBAL,
        help = "The project directory, which holds the root pom.xml"
    )]
    pub project_root: PathBuf,
    #[arg(
        long,
        short = 'v',
        action = ArgAction::Count,
        global = true,
        help_heading = GLOBAL,
        help = "Show more output for debugging (repeatable; set RUST_LOG to override verbosity entirely)"
    )]
    pub verbose: u8,
    #[arg(
        long,
        short = 'q',
        global = true,
        help_heading = GLOBAL,
        help = "Show only essential output (no spinners or progress bars)"
    )]
    pub quiet: bool,
    #[arg(
        long,
        global = true,
        help_heading = GLOBAL,
        help = "Produce machine-readable JSON output (implies --quiet)"
    )]
    pub json: bool,
    #[arg(
        long,
        global = true,
        help_heading = GLOBAL,
        help = "Use cached data and file repositories only; commands that need the network fail"
    )]
    pub offline: bool,
    #[command(subcommand)]
    pub command: Commands,
}

// The `mvn` options every command takes. Each command level gets its own
// copy instead of a global argument, whose values clap keeps from one level
// only, and `maven_options` joins them in order. A `///` comment here would
// become the `about` of every command.
#[derive(Debug, Args)]
#[command(next_help_heading = GLOBAL, next_display_order = 100)]
struct MavenArgs {
    #[arg(
        long,
        short = 's',
        value_name = "FILE",
        help = "Read this Maven settings file instead of ~/.m2/settings.xml, as mvn -s does"
    )]
    settings: Vec<String>,
    #[arg(
        long = "activate-profiles",
        short = 'P',
        value_name = "IDS",
        help = "Activate Maven profiles, or deactivate one written !id, as mvn -P does (repeatable)"
    )]
    profiles: Vec<String>,
    #[arg(
        long = "define",
        short = 'D',
        value_name = "NAME=VALUE",
        help = "Set a Maven user property, as mvn -D does (repeatable)"
    )]
    defines: Vec<String>,
}

fn with_maven_args(command: clap::Command) -> clap::Command {
    MavenArgs::augment_args(command).mut_subcommands(with_maven_args)
}

/// The `-D`, `-P` and `-s` values of every command level, outermost first,
/// which is the order they were given in.
fn maven_options(matches: &ArgMatches) -> Result<CommandLine> {
    let mut options = MavenArgs {
        settings: Vec::new(),
        profiles: Vec::new(),
        defines: Vec::new(),
    };
    let mut level = Some(matches);
    while let Some(matches) = level {
        if let Ok(args) = MavenArgs::from_arg_matches(matches) {
            options.settings.extend(args.settings);
            options.profiles.extend(args.profiles);
            options.defines.extend(args.defines);
        }
        level = matches.subcommand().map(|(_, matches)| matches);
    }
    CommandLine::new(options.defines, options.profiles, options.settings)
        .map_err(|err| crate::error::CliError::Usage(format!("invalid -D, -P or -s option: {err}")))
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Resolve dependencies, download artifacts, and update raeva.lock
    Sync(commands::SyncArgs),
    /// Export lockfile artifacts to the Maven local repository
    ExportM2(commands::ExportM2Args),
    /// Show the dependency tree from raeva.lock
    Tree(commands::TreeArgs),
    /// Explain why raeva.lock includes a dependency
    Why(commands::WhyArgs),
    /// Check repository connectivity, TLS and authentication
    Doctor(commands::DoctorArgs),
    /// Inspect, compare or verify raeva.lock
    Lock(commands::LockArgs),
    /// Export the locked checksums to .mvn/checksums/ for Maven's Trusted Checksums
    ExportChecksums(commands::ExportChecksumsArgs),
    /// Scan locked dependencies for known vulnerabilities
    Vuln(Box<commands::VulnArgs>),
    /// Generate a software bill of materials from raeva.lock
    Sbom(commands::SbomArgs),
}

pub(crate) fn command() -> clap::Command {
    with_maven_args(Cli::command()).long_about(
        "Raeva reads your existing pom.xml and writes raeva.lock, which pins every artifact, POM, \
         parent and BOM by SHA-256. Maven still runs the build.\n\n\
         Quick start:\n  \
         raeva sync           Resolve dependencies and write raeva.lock\n  \
         raeva sync --frozen  Fail when raeva.lock is out of date, as in CI\n\n\
         Offline build: export the locked dependencies to a repository of their own, and fill \
         another with Maven's plugins (plugins are not locked):\n  \
         raeva export-m2 --m2-path /build/deps\n  \
         mvn -Dmaven.repo.local=/build/plugins -DskipTests package\n  \
         mvn -o -Dmaven.repo.local=/build/deps -Dmaven.repo.local.tail=/build/plugins \
         -DskipTests package",
    )
}

pub(crate) async fn raeva() -> (Result<Report>, Output, Option<Session>) {
    let mut matches = command().get_matches();
    let maven_options = maven_options(&matches);
    let default_root =
        matches.value_source("project_root") == Some(clap::parser::ValueSource::DefaultValue);
    let subcommand = matches
        .subcommand()
        .map(|(name, args)| match args.subcommand_name() {
            Some(nested) => format!("{name} {nested}"),
            None => name.to_string(),
        })
        .unwrap_or_default();
    let cli = Cli::from_arg_matches_mut(&mut matches)
        .unwrap_or_else(|err| err.format(&mut command()).exit());
    let output = Output::new(
        if cli.json {
            Mode::Json
        } else {
            Mode::Human { quiet: cli.quiet }
        },
        subcommand,
        cli.verbose > 0,
    );
    init_tracing(cli.verbose, &output);

    let session = match maven_options.and_then(|maven_options| {
        Session::with_options(
            &cli.project_root,
            cli.offline,
            maven_options,
            output.clone(),
        )
    }) {
        Ok(session) => session,
        Err(err) => return (Err(err), output, None),
    };
    if default_root && matches!(cli.command, Commands::Sync(_)) {
        let refused = commands::sync::refuse_module_directory(session.project_root());
        if let Err(err) = refused {
            return (Err(err), output, Some(session));
        }
    }
    let mut result = run_command(cli.command, &session).await;
    let failure = match &mut result {
        Err(err) => Some(err),
        Ok(report) => report.failure_mut(),
    };
    if let Some(err) = failure
        && default_root
    {
        name_the_reactor(err, session.project_root());
    }
    (result, output, Some(session))
}

/// The project's own raeva.lock is missing; a module directory's
/// dependencies are in the enclosing reactor's.
fn name_the_reactor(err: &mut crate::error::CliError, root: &std::path::Path) {
    use crate::error::CliError;
    match err {
        CliError::VulnerabilityScan(cause) => name_the_reactor(cause, root),
        CliError::LockfileMissing {
            sync_creates: true,
            reactor,
            ..
        } => *reactor = commands::sync::enclosing_reactor(root),
        _ => {}
    }
}

async fn run_command(command: Commands, session: &Session) -> Result<Report> {
    match command {
        Commands::Sync(args) => commands::sync::run(&args, session).await,
        Commands::ExportM2(args) => commands::export_m2::run(&args, session).await,
        Commands::Tree(args) => blocking(session, "tree", args, commands::tree::run).await,
        Commands::Why(args) => blocking(session, "why", args, commands::why::run).await,
        Commands::Doctor(args) => commands::doctor::run(&args, session).await,
        Commands::Lock(args) => commands::lock_verify::run(&args, session).await,
        Commands::ExportChecksums(args) => {
            blocking(
                session,
                "export-checksums",
                args,
                commands::export_checksums::run,
            )
            .await
        }
        Commands::Vuln(args) => commands::vuln::run(&args, session).await,
        Commands::Sbom(args) => blocking(session, "sbom", args, commands::sbom::run).await,
    }
}

/// Run a command that reads files only on a blocking worker, so its std::fs
/// reads don't park the runtime's IO thread.
async fn blocking<A: Send + 'static>(
    session: &Session,
    what: &str,
    args: A,
    run: fn(&A, &Session) -> Result<Report>,
) -> Result<Report> {
    session
        .blocking(what, move |session| run(&args, session))
        .await
}

fn init_tracing(verbosity: u8, output: &Output) {
    let json_mode = output.is_json();
    // In JSON mode without an explicit verbose flag, suppress tracing output
    // entirely so structured `warn!`/`info!` lines from library crates never
    // bleed onto stderr next to the single JSON envelope on stdout. Verbose
    // still wins so operators can debug `--json -v` runs. An explicit
    // `RUST_LOG` also wins, preserving the existing escape hatch.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = match (json_mode, verbosity) {
            (true, 0) => "off",
            // The platform verifier logs each rejected certificate at error
            // level; the command's own error already names the TLS cause.
            (_, 0) => "warn,rustls_platform_verifier=off",
            (_, 1) => "info",
            (_, 2) => "debug",
            _ => "trace",
        };
        EnvFilter::new(level)
    });

    // The log goes to stderr, keeping stdout for command results. Warnings
    // with a `sec_code` are printed in the summary at exit; printing them
    // here as well would show each twice.
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(output.color())
        .with_writer(output.stderr_writer())
        .with_filter(filter.and(filter_fn(|meta| meta.fields().field("sec_code").is_none())));

    // Carries its own WARN filter so `sec_code` events still reach the
    // JSON envelope when the fmt layer is set to `off` in `--json` mode.
    let warn_layer = output.warning_layer().with_filter(LevelFilter::WARN);

    let _ = tracing_subscriber::registry()
        .with(fmt_layer)
        .with(warn_layer)
        .try_init();
}
