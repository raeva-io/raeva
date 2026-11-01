//! The one progress line a run shows on a terminal: a spinner that names the
//! current step and, while files download, the bytes received. It is cleared
//! before the report prints, so a finished run leaves only its summary.
//! Without a terminal each step prints one plain line instead.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use rv_repo::{FetchProgress, RepoError};

use super::Output;
use super::escape::terminal_text;

const STEP_TEMPLATE: &str = "{spinner:.cyan} {msg}";
const DOWNLOAD_TEMPLATE: &str = "{spinner:.cyan} {msg} {bytes} {prefix}";
#[cfg(not(windows))]
const SPINNER_TICKS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
// The fonts Windows consoles use by default have no braille patterns.
// indicatif shows the last string only once the spinner has finished.
#[cfg(windows)]
const SPINNER_TICKS: &[&str] = &["|", "/", "-", "\\", "|"];

fn style(template: &str) -> ProgressStyle {
    ProgressStyle::default_spinner()
        .tick_strings(SPINNER_TICKS)
        .template(template)
        .expect("valid template")
}

#[derive(Default)]
pub(super) struct Activity {
    bar: Mutex<Option<ProgressBar>>,
}

impl Activity {
    fn bar(&self, output: &Output) -> ProgressBar {
        let mut bar = self.bar.lock().unwrap_or_else(|e| e.into_inner());
        bar.get_or_insert_with(|| {
            let bar = output.bars().add(ProgressBar::new_spinner());
            bar.set_style(style(STEP_TEMPLATE));
            bar.enable_steady_tick(Duration::from_millis(100));
            bar
        })
        .clone()
    }

    pub(super) fn step(&self, output: &Output, text: &str) {
        self.bar(output).set_message(text.to_string());
    }

    pub(super) fn clear(&self, output: &Output) {
        let bar = self.bar.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(bar) = bar {
            bar.finish_and_clear();
            output.bars().remove(&bar);
        }
    }
}

/// What a `RepoClient` reports downloads to. From the first transfer on, the
/// progress line adds the bytes received so far, and the file name of the
/// transfer that started last while any is in flight. Transfers run
/// concurrently. Each wait before a retry prints a note, also without a
/// terminal, so a CI log shows why a run is slow.
pub(crate) struct ProgressReporter {
    output: Output,
    /// Whether the progress line shows; not without a terminal.
    shows_progress: bool,
    in_flight: Mutex<usize>,
    started: AtomicBool,
}

impl ProgressReporter {
    pub(super) fn new(output: &Output) -> Self {
        Self {
            output: output.clone(),
            shows_progress: output.shows_progress(),
            in_flight: Mutex::new(0),
            started: AtomicBool::new(false),
        }
    }

    fn bar(&self) -> Option<ProgressBar> {
        (self.shows_progress).then(|| self.output.0.activity.bar(&self.output))
    }
}

impl FetchProgress for ProgressReporter {
    fn on_start(&self, url: &str, total: Option<u64>) {
        let Some(bar) = self.bar() else {
            return;
        };
        let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        if !self.started.swap(true, Ordering::Relaxed) {
            bar.set_style(style(DOWNLOAD_TEMPLATE));
        }
        *in_flight += 1;
        bar.inc_length(total.unwrap_or(0));
        bar.set_prefix(progress_label(url));
    }

    fn on_chunk(&self, bytes: usize) {
        if let Some(bar) = self.bar() {
            bar.inc(bytes as u64);
        }
    }

    fn on_finish(&self, _url: &str, _total: Option<usize>) {
        let Some(bar) = self.bar() else {
            return;
        };
        let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        *in_flight = in_flight.saturating_sub(1);
        if *in_flight == 0 {
            bar.set_prefix("");
        }
    }

    fn on_retry(
        &self,
        _url: &str,
        error: &RepoError,
        wait: Duration,
        attempt: usize,
        attempts: usize,
    ) {
        self.output
            .note(&retry_note(error, wait, attempt, attempts));
    }
}

/// The note for a wait before a retry. The error names the URL.
fn retry_note(error: &RepoError, wait: Duration, attempt: usize, attempts: usize) -> String {
    format!(
        "Retrying in {:.1} s (attempt {attempt} of {attempts}): {error}",
        wait.as_secs_f64()
    )
}

/// The file name a download URL ends with. `url` arrives redacted; redacting
/// again keeps the label safe whatever calls it.
fn progress_label(url: &str) -> String {
    let redacted = rv_config::redact_url(url);
    let path = redacted.split(['?', '#']).next().unwrap_or_default();
    let name = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    terminal_text(&trim_name(name)).into_owned()
}

fn trim_name(name: &str) -> String {
    const MAX: usize = 48;
    let chars: Vec<char> = name.chars().collect();
    if chars.len() <= MAX {
        return name.to_string();
    }
    let start: String = chars.iter().take(20).collect();
    let end: String = chars.iter().skip(chars.len() - (MAX - 23)).collect();
    format!("{start}...{end}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn progress_label_names_the_file() {
        let url = "https://alice:s3cret@repo.example/a/b.jar?token=t0k";
        assert_eq!(super::progress_label(url), "b.jar");
    }

    #[test]
    fn a_retry_note_names_the_wait_the_attempt_and_the_failure() {
        let error = rv_repo::RepoError::HttpStatus {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            url: "https://repo.example/a.pom".to_string(),
            retry_after: None,
        };
        let note = super::retry_note(&error, std::time::Duration::from_millis(5200), 2, 4);
        assert_eq!(
            note,
            "Retrying in 5.2 s (attempt 2 of 4): unexpected response: 503 Service Unavailable \
             for https://repo.example/a.pom"
        );
    }

    #[test]
    fn long_names_keep_their_ends() {
        let name = format!("{}-end.jar", "a".repeat(80));
        let trimmed = super::trim_name(&name);
        assert_eq!(trimmed.chars().count(), 48);
        assert!(trimmed.starts_with("aaaa"), "{trimmed}");
        assert!(trimmed.ends_with("-end.jar"), "{trimmed}");
    }
}
