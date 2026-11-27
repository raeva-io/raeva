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
pub(crate) mod secrets;
mod table;
mod warnings;

pub(crate) use escape::{inline_text, json_document, terminal_text};
#[cfg(test)]
pub(crate) use human::testing;
pub(crate) use human::{Human, Style};
pub(crate) use progress::ProgressReporter;
pub(crate) use report::{CommandOutput, Report};
pub(crate) use secrets::redact_secrets_in_json;
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
    warnings: Arc<WarningCollector>,
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
            warnings: Arc::default(),
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

    /// This output without notes, progress or summary lines, for a step
    /// inside the run: its warnings stay this run's.
    pub(crate) fn quieted(&self) -> Self {
        let mode = match self.0.mode {
            Mode::Human { .. } => Mode::Human { quiet: true },
            Mode::Json => Mode::Json,
        };
        Self(Arc::new(Inner {
            mode,
            command: self.0.command.clone(),
            verbose: self.0.verbose,
            style: self.0.style,
            warnings: Arc::clone(&self.0.warnings),
            bars: self.0.bars.clone(),
            activity: progress::Activity::default(),
        }))
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

    /// Whether the progress line shows: on a terminal, and not quiet.
    pub(crate) fn shows_progress(&self) -> bool {
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
        let text = secrets::redact_secrets(text);
        let text = terminal_text(&text);
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
        let line = line.to_string();
        let line = secrets::redact_secrets(&line);
        // eprintln! panics when stderr is full or closed; the line is lost
        // either way.
        self.bars()
            .suspend(|| drop(writeln!(io::stderr().lock(), "{line}")));
    }

    pub(crate) fn stderr_writer(
        &self,
    ) -> impl Fn() -> Redacting<StderrWriter> + Send + Sync + 'static {
        let bars = self.bars().clone();
        move || Redacting(StderrWriter { bars: bars.clone() })
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
        // `raeva vuln` and `raeva vuln triage` exit 1 for findings alone.
        if let Some(failure) = &mut failure
            && self.0.command.split(' ').next() == Some("vuln")
            && failure.code != "VULNERABILITIES_FOUND"
        {
            failure.status = failure.status.of_failed_scan();
        }
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
        self.write_envelope(&mut io::stdout().lock(), data, failure)
    }

    fn write_envelope(
        &self,
        out: &mut impl Write,
        data: Option<serde_json::Map<String, serde_json::Value>>,
        failure: Option<&Diagnostic>,
    ) -> io::Result<()> {
        let warnings = self.0.warnings.take();
        let envelope = report::envelope(data, failure, &warnings);
        writeln!(out, "{}", json_document(envelope.to_string()))?;
        out.flush()
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
                // Recorded whole before it is redacted, as a value may span
                // two writes, and replayed in the order it was written.
                let recorded = std::cell::RefCell::new(Vec::new());
                let (mut stdout, mut stderr) = (
                    Recorder {
                        writes: &recorded,
                        stderr: false,
                    },
                    Recorder {
                        writes: &recorded,
                        stderr: true,
                    },
                );
                let mut human = Human::new(
                    &mut stdout,
                    &mut stderr,
                    self.style(),
                    self.is_quiet(),
                    stdout_width(),
                );
                human.stdout_color =
                    supports_color(io::stdout().is_terminal(), console::Term::stdout);
                let rendered = output.render_human(&mut human);
                let mut out = io::stdout().lock();
                let mut written = rendered;
                for (stderr, bytes) in recorded.into_inner() {
                    let text =
                        secrets::redact_secrets(&String::from_utf8_lossy(&bytes)).into_owned();
                    if stderr {
                        // A full stderr does not fail the command.
                        drop(out.flush());
                        drop(io::stderr().lock().write_all(text.as_bytes()));
                    } else if written.is_ok() {
                        written = out.write_all(text.as_bytes());
                    }
                }
                written.and_then(|()| out.flush())
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
        let list_all = list_all(&self.0.command, document);
        let mut warnings = self.0.warnings.take();
        if self.is_quiet() {
            warnings.retain(|warning| warning.code != warnings::WarningCode::DuplicateDependency);
        }
        for line in warnings::summarize(&warnings, &list_all) {
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

/// A writer that hides the value of each secret the configuration took
/// ([`secrets::redact_secrets`]) from what goes through it. Each write is
/// redacted whole, as the log writes each line in one.
pub(crate) struct Redacting<W>(pub(crate) W);

impl<W: io::Write> io::Write for Redacting<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(buf);
        self.0.write_all(secrets::redact_secrets(&text).as_bytes())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// What a human report writes to stdout or, with `stderr`, to stderr, in
/// order, each run of writes to one stream kept together.
struct Recorder<'a> {
    writes: &'a std::cell::RefCell<Vec<(bool, Vec<u8>)>>,
    stderr: bool,
}

impl io::Write for Recorder<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut writes = self.writes.borrow_mut();
        match writes.last_mut() {
            Some((stderr, bytes)) if *stderr == self.stderr => bytes.extend_from_slice(buf),
            _ => writes.push((self.stderr, buf.to_vec())),
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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

/// The command that lists every warning of `command` in a JSON envelope.
fn list_all(command: &str, document: bool) -> String {
    match (document, command) {
        (false, _) => format!("'raeva --json {command}' lists them"),
        (true, "sbom") => "'raeva --json sbom -o FILE' lists them".to_string(),
        // A plan writes nothing, and so does the dry run that lists them.
        (true, "export-m2") => "'raeva --json export-m2 --dry-run' lists them".to_string(),
        (true, _) => format!("'raeva --json {command}' without --format lists them"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    /// A secret no other test registers, as the registry is global.
    const SECRET: &str = "zqOUTPUTzq";

    #[test]
    fn the_json_envelope_hides_a_registered_secret() {
        super::secrets::register_secret(SECRET);
        let mut data = serde_json::Map::new();
        data.insert("url".into(), format!("http://h/{SECRET}/a.pom").into());
        let mut out = Vec::new();
        (super::Output::for_tests())
            .write_envelope(&mut out, Some(data), None)
            .expect("written");
        let out = String::from_utf8(out).expect("UTF-8");
        // Other tests register short secrets too, so only this one's
        // absence is certain.
        let envelope: serde_json::Value = serde_json::from_str(&out).expect("JSON");
        let url = envelope["data"]["url"].as_str().expect("url");
        assert!(!out.contains(SECRET) && url.contains("/***/"), "{out}");
    }

    #[test]
    fn the_log_hides_a_registered_secret() {
        #[derive(Clone, Default)]
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Shared {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("buffer").write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        super::secrets::register_secret(SECRET);
        let log = Shared::default();
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || super::Redacting(writer.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(url = %format!("http://h/{SECRET}/"), "rejected {SECRET}");
        });
        let log = String::from_utf8(log.0.lock().expect("buffer").clone()).expect("UTF-8");
        assert!(!log.contains(SECRET) && log.contains("/***/"), "{log}");
    }

    #[test]
    fn the_warning_list_after_a_document_writes_nothing() {
        assert_eq!(
            super::list_all("export-m2", true),
            "'raeva --json export-m2 --dry-run' lists them"
        );
        assert_eq!(
            super::list_all("vuln", true),
            "'raeva --json vuln' without --format lists them"
        );
    }
}
