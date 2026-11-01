//! Everything raeva prints. One [`Output`] per run, made from the global flags
//! and carried by the [`crate::session::Session`], holds the output mode,
//! the colour decision, the run's warnings and its progress bars. Commands
//! return a [`Report`], and [`Output::finish`] prints it, the warnings and
//! the error, if any, in the run's mode.

use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;

use indicatif::MultiProgress;

use crate::error::{CliError, Diagnostic, ExitStatus, HintEnv};

mod escape;
mod human;
mod progress;
mod report;
mod table;
mod warnings;

pub(crate) use escape::{inline_text, json_document, terminal_text};
#[cfg(test)]
pub(crate) use human::testing;
pub(crate) use human::{Human, Style};
pub(crate) use progress::ProgressReporter;
pub(crate) use report::{CommandOutput, Report};
pub(crate) use table::{Table, stdout_width};
pub(crate) use warnings::{Warning, WarningCode, WarningCollector, WarningCollectorLayer};

use report::Body;

pub(crate) fn command_line(args: &str) -> String {
    format!("raeva {args}")
}

/// How a run prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Text. `quiet` drops progress, notes and the summary lines.
    Human { quiet: bool },
    /// One JSON envelope on stdout and nothing on stderr, unless `-v` or
    /// `RUST_LOG` asks for a log. A document report, such as an SBOM, is
    /// all of stdout instead, and its warnings and error go to stderr.
    Json,
}

#[derive(Clone)]
pub(crate) struct Output(Arc<Inner>);

struct Inner {
    mode: Mode,
    command: String,
    /// `-v` was given.
    verbose: bool,
    style: Style,
    warnings: WarningCollector,
    bars: MultiProgress,
    activity: progress::Activity,
}

impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Output")
            .field("mode", &self.0.mode)
            .field("color", &self.0.style.color)
            .finish_non_exhaustive()
    }
}

impl Output {
    pub(crate) fn new(mode: Mode, command: String, verbose: bool) -> Self {
        Self::with_color(
            mode,
            command,
            verbose,
            supports_color(io::stderr().is_terminal(), console::Term::stderr),
        )
    }

    fn with_color(mode: Mode, command: String, verbose: bool, color: bool) -> Self {
        Self(Arc::new(Inner {
            mode,
            command,
            verbose,
            style: Style { color },
            warnings: WarningCollector::default(),
            bars: MultiProgress::new(),
            activity: progress::Activity::default(),
        }))
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self::with_color(
            Mode::Human { quiet: true },
            "sync".to_string(),
            false,
            false,
        )
    }

    pub(crate) fn is_json(&self) -> bool {
        self.0.mode == Mode::Json
    }

    /// No notes, progress or summary lines: `--quiet`, or `--json`.
    pub(crate) fn is_quiet(&self) -> bool {
        match self.0.mode {
            Mode::Human { quiet } => quiet,
            Mode::Json => true,
        }
    }

    /// `-v` was given.
    pub(crate) fn is_verbose(&self) -> bool {
        self.0.verbose
    }

    pub(crate) fn color(&self) -> bool {
        self.0.style.color
    }

    pub(crate) fn style(&self) -> Style {
        self.0.style
    }

    fn bars(&self) -> &MultiProgress {
        &self.0.bars
    }

    fn shows_progress(&self) -> bool {
        !self.is_quiet() && io::stderr().is_terminal()
    }

    /// Record a warning for the summary at exit, or the envelope.
    /// `HTTP_REPO_BLOCKED` for a repository that a dependency's POM
    /// declares is kept only at `-v`: most dependency trees have one, Maven
    /// refuses it as well, and a dependency that only such a repository has
    /// fails with an error that names it.
    pub(crate) fn warn(&self, warning: Warning) {
        if warning.code == WarningCode::HttpRepoBlocked
            && warning.context["project"] != true
            && !self.0.verbose
        {
            return;
        }
        self.0.warnings.push(warning);
    }

    #[cfg(test)]
    pub(crate) fn take_warnings(&self) -> Vec<Warning> {
        self.0.warnings.take()
    }

    /// The step a run is at, such as `Resolving dependencies...`: the
    /// progress line on a terminal, and a line on stderr otherwise.
    pub(crate) fn step(&self, text: &str) {
        let text = terminal_text(text);
        if self.shows_progress() {
            self.0.activity.step(self, &text);
        } else {
            self.note_styled(text.into_owned());
        }
    }

    pub(crate) fn note(&self, text: &str) {
        self.note_styled(terminal_text(text).into_owned());
    }

    pub(crate) fn progress(&self) -> Arc<ProgressReporter> {
        Arc::new(ProgressReporter::new(self))
    }

    fn note_styled(&self, line: String) {
        if !self.is_quiet() {
            self.eprint(line);
        }
    }

    fn eprint(&self, line: impl std::fmt::Display) {
        // eprintln! panics when stderr is full or closed; the line is lost
        // either way.
        self.bars()
            .suspend(|| drop(writeln!(io::stderr().lock(), "{line}")));
    }

    pub(crate) fn stderr_writer(&self) -> impl Fn() -> StderrWriter + Send + Sync + 'static {
        let bars = self.bars().clone();
        move || StderrWriter { bars: bars.clone() }
    }

    pub(crate) fn warning_layer(&self) -> WarningCollectorLayer {
        let output = self.clone();
        WarningCollectorLayer::new(move |warning| output.warn(warning))
    }

    /// Print the outcome of a run and return its exit code: the report, the
    /// warnings, and the error the run ended with, if any.
    pub(crate) fn finish(
        &self,
        outcome: crate::error::Result<Report>,
        hints: &HintEnv,
    ) -> ExitCode {
        self.0.activity.clear(self);
        let report = outcome.unwrap_or_else(Report::error);
        let mut failure = report.failure.map(|error| error.diagnose(hints));
        let written = match report.body {
            Body::Document(text) => self.print_document(&text, failure.as_ref()),
            body if self.is_json() => match payload(body) {
                Ok(data) => self.print_envelope(data, failure.as_ref()),
                Err(error) => {
                    failure = Some(error.diagnose(hints));
                    self.print_envelope(None, failure.as_ref())
                }
            },
            body => self.print_human(body, failure.as_ref()),
        };
        let status = failure.map_or(ExitStatus::Success, |failure| failure.status);
        match written {
            Ok(()) => status.into(),
            // A reader such as `head` that stops early is not a failure.
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => status.into(),
            Err(error) => {
                self.print_error(&format!("cannot write the output: {error}"));
                if status == ExitStatus::Success {
                    ExitStatus::Failure.into()
                } else {
                    status.into()
                }
            }
        }
    }

    fn print_envelope(
        &self,
        data: Option<serde_json::Map<String, serde_json::Value>>,
        failure: Option<&Diagnostic>,
    ) -> io::Result<()> {
        let warnings = self.0.warnings.take();
        let envelope = report::envelope(data, failure, &warnings);
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{}", json_document(envelope.to_string()))?;
        stdout.flush()
    }

    fn print_document(&self, text: &str, failure: Option<&Diagnostic>) -> io::Result<()> {
        let mut stdout = io::stdout().lock();
        let written =
            writeln!(stdout, "{}", json_document(text.to_string())).and_then(|()| stdout.flush());
        drop(stdout);
        self.print_warnings_and_error(failure, true);
        written
    }

    fn print_human(&self, body: Body, failure: Option<&Diagnostic>) -> io::Result<()> {
        let written = match body {
            Body::Data(output) => {
                let mut stdout = io::stdout().lock();
                let mut stderr = io::stderr().lock();
                let mut human = Human::new(
                    &mut stdout,
                    &mut stderr,
                    self.style(),
                    self.is_quiet(),
                    stdout_width(),
                );
                human.stdout_color =
                    supports_color(io::stdout().is_terminal(), console::Term::stdout);
                output
                    .render_human(&mut human)
                    .and_then(|()| stdout.flush())
            }
            _ => Ok(()),
        };
        // The warnings and the error go to stderr also when stdout was
        // closed early, as `raeva vuln | head` closes it.
        self.print_warnings_and_error(failure, false);
        written
    }

    /// After a `document`, such as an SBOM on stdout, the warnings are not in
    /// a JSON envelope, so the line that says how to list them names one
    /// that has it.
    fn print_warnings_and_error(&self, failure: Option<&Diagnostic>, document: bool) {
        let command = &self.0.command;
        let list_all = match (document, command.as_str()) {
            (false, _) => format!("'raeva --json {command}' lists them"),
            (true, "sbom") => "'raeva --json sbom -o FILE' lists them".to_string(),
            (true, _) => format!("'raeva --json {command}' without --format lists them"),
        };
        for line in warnings::summarize(&self.0.warnings.take(), &list_all) {
            self.eprint(self.style().warning(&line));
        }
        if let Some(failure) = failure {
            self.print_error(&failure.human());
        }
    }

    fn print_error(&self, message: &str) {
        self.eprint(format!(
            "{} {}",
            self.style().error_prefix(),
            terminal_text(message)
        ));
    }
}

fn payload(body: Body) -> crate::error::Result<Option<serde_json::Map<String, serde_json::Value>>> {
    match body {
        Body::Data(output) => match output.to_json()? {
            serde_json::Value::Object(map) => Ok(Some(map)),
            _ => Err(CliError::Internal(
                "a command's JSON payload is not an object".to_string(),
            )),
        },
        Body::Document(_) | Body::Empty => Ok(None),
    }
}

/// Stderr for the log, with the progress bars moved out of the way.
pub(crate) struct StderrWriter {
    bars: MultiProgress,
}

impl io::Write for StderrWriter {
    // The fmt layer formats each event into one buffer and writes it with
    // one `write_all`, so a log line is never split around a redraw.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bars.suspend(|| io::stderr().write(buf))
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.bars.suspend(|| io::stderr().write_all(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

/// True when a stream should receive ANSI colour escapes: it is a terminal
/// and `NO_COLOR` is unset.
fn supports_color(terminal: bool, term: fn() -> console::Term) -> bool {
    // A Windows console prints escapes as text until its escape sequence
    // support is turned on, which `colors_supported` does.
    std::env::var_os("NO_COLOR").is_none()
        && terminal
        && (!cfg!(windows) || term().features().colors_supported())
}
