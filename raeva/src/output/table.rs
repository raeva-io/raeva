//! Plain-text tables, fitted to the terminal width.

use super::escape::terminal_text;

pub(crate) struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub(crate) fn new<I, S>(headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            headers: headers.into_iter().map(escape_cell).collect(),
            rows: Vec::new(),
        }
    }

    pub(crate) fn add_row<I, S>(&mut self, row: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.rows.push(row.into_iter().map(escape_cell).collect());
    }

    pub(crate) fn render(&self) -> String {
        let rendered = self.build().to_string();
        let lines: Vec<&str> = rendered.lines().map(str::trim_end).collect();
        lines.join("\n")
    }

    /// Renders the table to fit `width` columns by wrapping the last column
    /// at spaces. Its continuation lines stay in that column while it gets
    /// at least [`MIN_WRAPPED_COLUMN`] columns; otherwise each row's last
    /// cell goes on indented lines below the row, and the widest other
    /// column wraps too when the row is still wider than `width`. A word
    /// longer than the space it gets stays whole and overflows, and so does
    /// a table narrower than [`MIN_TABLE_WIDTH`].
    pub(crate) fn render_to_width(&self, width: usize) -> String {
        let width = width.max(MIN_TABLE_WIDTH);
        let rendered = self.render();
        if rendered.lines().all(|line| text_width(line) <= width) || self.headers.len() < 2 {
            return rendered;
        }
        let last = self.headers.len() - 1;
        let mut leading: Vec<usize> = (0..last)
            .map(|column| {
                std::iter::once(&self.headers)
                    .chain(&self.rows)
                    .filter_map(|row| row.get(column))
                    .flat_map(|cell| cell.lines())
                    .map(text_width)
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        // `Style::blank` pads every cell with a space on both sides and
        // separates columns with one more.
        let indent = 1 + leading.iter().map(|width| width + 3).sum::<usize>();
        let available = width.saturating_sub(indent + 1);
        if available >= MIN_WRAPPED_COLUMN.max(text_width(&self.headers[last])) {
            let mut wrapped = Table::new(self.headers.clone());
            for row in &self.rows {
                let mut row = row.clone();
                if let Some(cell) = row.get_mut(last) {
                    *cell = wrap_words(cell, available).join("\n");
                }
                wrapped.add_row(row);
            }
            return wrapped.render();
        }

        let row_width = indent - 3;
        if row_width > width {
            let widest = (0..last).max_by_key(|&column| leading[column]).unwrap_or(0);
            leading[widest] = leading[widest]
                .saturating_sub(row_width - width)
                .max(MIN_WRAPPED_LEADING_COLUMN);
        }
        let render_leading = |cells: &[String]| -> Vec<String> {
            let wrapped: Vec<Vec<String>> = (0..last)
                .map(|column| {
                    let cell = cells.get(column).map_or("", String::as_str);
                    wrap_words(cell, leading[column])
                })
                .collect();
            let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
            (0..height)
                .map(|line| {
                    let mut out = String::new();
                    for (column, lines) in wrapped.iter().enumerate() {
                        let text = lines.get(line).map_or("", String::as_str);
                        out.push_str(if column == 0 { " " } else { "   " });
                        out.push_str(text);
                        let pad = leading[column].saturating_sub(text_width(text));
                        out.extend(std::iter::repeat_n(' ', pad));
                    }
                    out.trim_end().to_string()
                })
                .collect()
        };
        let mut out = render_leading(&self.headers).join("\n");
        for row in &self.rows {
            for line in render_leading(row) {
                out.push('\n');
                out.push_str(&line);
            }
            for detail in wrap_words(row.get(last).map_or("", String::as_str), width - 5) {
                out.push_str("\n     ");
                out.push_str(&detail);
            }
        }
        out
    }

    fn build(&self) -> tabled::Table {
        let mut builder = tabled::builder::Builder::default();
        let headers = Some(&self.headers).filter(|headers| !headers.is_empty());
        for row in headers.into_iter().chain(&self.rows) {
            builder.push_record(row);
        }
        let mut table = builder.build();
        table.with(tabled::settings::Style::blank());
        table
    }
}

fn escape_cell(cell: impl Into<String>) -> String {
    terminal_text(&cell.into()).into_owned()
}

pub(super) const MIN_WRAPPED_COLUMN: usize = 40;

pub(super) const MIN_TABLE_WIDTH: usize = 20;

const MIN_WRAPPED_LEADING_COLUMN: usize = 10;

fn text_width(text: &str) -> usize {
    tabled::grid::util::string::get_text_width(text)
}

/// Greedy wrap at spaces. A word wider than `width` gets a line of its own.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && text_width(&line) + 1 + text_width(word) > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

pub(crate) fn stdout_width() -> usize {
    // A Windows console moves to the next line after a character in its
    // last column, so a line that fills the width would be followed by an
    // empty one.
    const RESERVED: usize = if cfg!(windows) { 1 } else { 0 };
    console::Term::stdout()
        .size_checked()
        .map_or(80, |(_, columns)| {
            usize::from(columns).saturating_sub(RESERVED)
        })
}

#[cfg(test)]
mod tests {
    use super::Table;

    fn doctor_like_table() -> Table {
        let mut table = Table::new(["Check", "Status", "Details"]);
        table.add_row(["TLS trust roots", "info", "operating system trust store"]);
        table.add_row([
            "repository corp-releases (pom.xml)",
            "fail",
            "401 (no credentials were sent for https://repo.example.com/artifactory/\
             libs-release-local/; add a <server> entry with id 'corp-releases' to \
             ~/.m2/settings.xml)",
        ]);
        table
    }

    /// Every line fits, unless it is a single word wider than its space.
    fn assert_fits(rendered: &str, width: usize) {
        for line in rendered.lines() {
            let line = line.trim_end();
            assert!(
                line.chars().count() <= width || line.split_whitespace().count() == 1,
                "{width}: {line:?} in\n{rendered}"
            );
        }
    }

    fn words(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Without room for a readable column, each detail goes below its row.
    #[test]
    fn table_moves_the_last_column_below_narrow_rows() {
        let table = doctor_like_table();
        for width in [80, 60, 44] {
            let rendered = table.render_to_width(width);
            assert_fits(&rendered, width);
            let lines: Vec<&str> = rendered.lines().collect();
            assert_eq!(
                lines[0], " Check                                Status",
                "{rendered}"
            );
            assert!(!rendered.contains("Details"), "{rendered}");
            assert_eq!(
                lines[1], " TLS trust roots                      info",
                "{rendered}"
            );
            assert_eq!(lines[2], "     operating system trust store", "{rendered}");
            assert_eq!(
                lines[3], " repository corp-releases (pom.xml)   fail",
                "{rendered}"
            );
            let detail: Vec<&str> = lines[4..].to_vec();
            for line in &detail {
                assert!(
                    line.starts_with("     ") && !line[5..].starts_with(' '),
                    "{rendered}"
                );
            }
            assert_eq!(
                words(&detail.join(" ")),
                words(&table.rows[1][2]),
                "{rendered}"
            );
        }
    }
}
