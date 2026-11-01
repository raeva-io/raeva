//! Text output for people. Every method here escapes the text it is given
//! with [`terminal_text`] before it adds colour, so a command passes values
//! from POMs, raeva.lock, servers and file names straight in.

use std::io::{self, Write};

use owo_colors::OwoColorize;

use super::escape::terminal_text;
use super::table::Table;

/// Colour for stderr, when stderr is a terminal that shows it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Style {
    pub(super) color: bool,
}

impl Style {
    fn paint(self, text: &str, paint: impl Fn(&str) -> String) -> String {
        let text = terminal_text(text);
        if self.color {
            paint(&text)
        } else {
            text.into_owned()
        }
    }

    pub(crate) fn success(self, text: &str) -> String {
        self.paint(text, |text| text.green().to_string())
    }

    pub(crate) fn warning(self, text: &str) -> String {
        self.paint(text, |text| text.yellow().to_string())
    }

    pub(crate) fn heading(self, text: &str) -> String {
        self.paint(text, |text| text.bold().to_string())
    }

    pub(super) fn error_prefix(self) -> String {
        self.paint("error:", |text| text.red().to_string())
    }
}

/// Where a command's report goes in text mode: its result on stdout, and
/// headings, notes and findings on stderr, which `--quiet` silences.
pub(crate) struct Human<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
    style: Style,
    quiet: bool,
    width: usize,
    pub(super) stdout_color: bool,
}

impl<'a> Human<'a> {
    pub(crate) fn new(
        stdout: &'a mut dyn Write,
        stderr: &'a mut dyn Write,
        style: Style,
        quiet: bool,
        width: usize,
    ) -> Self {
        Self {
            stdout,
            stderr,
            style,
            quiet,
            width,
            stdout_color: false,
        }
    }

    pub(crate) fn width(&self) -> usize {
        self.width
    }

    pub(crate) fn line(&mut self, text: impl AsRef<str>) -> io::Result<()> {
        writeln!(self.stdout, "{}", terminal_text(text.as_ref()))
    }

    pub(crate) fn blank_line(&mut self) -> io::Result<()> {
        writeln!(self.stdout)
    }

    pub(crate) fn table(&mut self, table: &Table) -> io::Result<()> {
        writeln!(self.stdout, "{}", table.render())
    }

    pub(crate) fn fitted_table(&mut self, table: &Table) -> io::Result<()> {
        writeln!(self.stdout, "{}", table.render_to_width(self.width))
    }

    /// A table on stdout, wrapped to the terminal width, with each line
    /// after the header passed through `paint` when stdout shows colour.
    /// The cells were escaped when they were added, and `paint` only adds
    /// escapes for colour.
    pub(crate) fn painted_table(
        &mut self,
        table: &Table,
        paint: impl Fn(&str) -> String,
    ) -> io::Result<()> {
        let rendered = table.render_to_width(self.width);
        for (index, line) in rendered.lines().enumerate() {
            if index > 0 && self.stdout_color {
                writeln!(self.stdout, "{}", paint(line))?;
            } else {
                writeln!(self.stdout, "{line}")?;
            }
        }
        Ok(())
    }

    pub(crate) fn note(&mut self, text: impl AsRef<str>) -> io::Result<()> {
        let text = terminal_text(text.as_ref());
        self.styled(&text)
    }

    pub(crate) fn heading(&mut self, text: impl AsRef<str>) -> io::Result<()> {
        let text = self.style.heading(text.as_ref());
        self.styled(&text)
    }

    pub(crate) fn success(&mut self, text: impl AsRef<str>) -> io::Result<()> {
        let text = self.style.success(text.as_ref());
        self.styled(&text)
    }

    pub(crate) fn warning(&mut self, text: impl AsRef<str>) -> io::Result<()> {
        let text = self.style.warning(text.as_ref());
        self.styled(&text)
    }

    /// `Label detail`, such as `Wrote sbom.json`.
    pub(crate) fn done(&mut self, label: &str, detail: impl AsRef<str>) -> io::Result<()> {
        let line = format!(
            "{} {}",
            self.style.success(label),
            terminal_text(detail.as_ref())
        );
        self.styled(&line)
    }

    fn styled(&mut self, text: &str) -> io::Result<()> {
        // A note that cannot be written is lost, as in `Output::eprint`;
        // the report on stdout and the exit status still stand.
        if !self.quiet {
            drop(writeln!(self.stderr, "{text}"));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::{Human, Style};

    /// What a report renders, as `(stdout, stderr)` text without colour, at
    /// 80 columns.
    pub(crate) fn render(
        quiet: bool,
        render: impl FnOnce(&mut Human<'_>) -> std::io::Result<()>,
    ) -> (String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut human = Human::new(&mut stdout, &mut stderr, Style { color: false }, quiet, 80);
        render(&mut human).expect("render");
        (
            String::from_utf8(stdout).expect("utf-8 stdout"),
            String::from_utf8(stderr).expect("utf-8 stderr"),
        )
    }
}

#[cfg(test)]
mod tests {

    use super::testing::render;

    #[test]
    fn every_method_escapes_its_text() {
        let hostile = "a\u{1b}[2Jb";
        let (stdout, stderr) = render(false, |h| {
            h.line(hostile)?;
            h.note(hostile)?;
            h.heading(hostile)?;
            h.success(hostile)?;
            h.warning(hostile)?;
            h.done(hostile, hostile)
        });
        assert!(!stdout.contains('\u{1b}'), "{stdout:?}");
        assert!(!stderr.contains('\u{1b}'), "{stderr:?}");
        assert_eq!(stdout, "a\\u{1b}[2Jb\n");
        assert_eq!(stderr.matches("a\\u{1b}[2Jb").count(), 6, "{stderr:?}");
    }
}
