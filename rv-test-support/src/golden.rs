//! Golden files: compare test output with a committed file, or rewrite the
//! file when [`BLESS_ENV`] is set.
//!
//! A golden file changes only on purpose. Regenerate with
//! `RAEVA_TEST_BLESS=1 cargo test -p <crate> --test <target>`, then review
//! the diff before committing it.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const BLESS_ENV: &str = "RAEVA_TEST_BLESS";

/// Lines shown before the first difference, and from each side after it.
const CONTEXT: usize = 3;

/// Assert that `actual` equals the golden file at `path`, byte for byte.
///
/// The committed file is read with CRLF line endings folded to LF, so a
/// checkout that converts line endings does not fail the comparison; `actual`
/// is compared as given. Under [`BLESS_ENV`] the file is written instead.
///
/// # Panics
///
/// When the file is missing or differs, with a line diff and the command that
/// regenerates it.
pub fn assert_golden(path: &Path, actual: &str) {
    if std::env::var_os(BLESS_ENV).is_some_and(|value| value == "1") {
        let parent = path.parent().expect("golden file directory");
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("create {}: {err}", parent.display()));
        fs::write(path, actual).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
        return;
    }
    let expected = match fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .unwrap_or_else(|err| panic!("golden file {} is not UTF-8: {err}", path.display()))
            .replace("\r\n", "\n"),
        Err(err) => panic!(
            "golden file {} cannot be read ({err}); run with {BLESS_ENV}=1 to create it",
            path.display()
        ),
    };
    if expected != actual {
        panic!(
            "output differs from golden file {}\n\
             (- golden, + actual; rerun with {BLESS_ENV}=1 to accept the actual output)\n{}",
            path.display(),
            line_diff(&expected, actual)
        );
    }
}

/// The first difference between `expected` and `actual` by line: up to
/// three lines of context, then up to three lines from each side, under the
/// 1-based golden file line number the context starts at. A missing or extra
/// final newline shows as a removed or added empty last line.
pub fn line_diff(expected: &str, actual: &str) -> String {
    let old: Vec<&str> = expected.split('\n').collect();
    let new: Vec<&str> = actual.split('\n').collect();
    let first = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
    let start = first.saturating_sub(CONTEXT);
    let mut out = format!("@@ golden line {} @@\n", start + 1);
    let context = old[start..first].iter().map(|line| (' ', line));
    let removed = old[first..].iter().take(CONTEXT).map(|line| ('-', line));
    let added = new[first..].iter().take(CONTEXT).map(|line| ('+', line));
    for (mark, line) in context.chain(removed).chain(added) {
        let _ = writeln!(out, "{mark}{}", show(line));
    }
    out
}

fn show(line: &str) -> String {
    if line.ends_with('\r') || line.contains('\t') {
        format!("{line:?}")
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn diff_shows_the_first_change_with_context() {
        let diff = super::line_diff("a\nb\nc\nd\ne\n", "a\nb\nc\nd\nE\r\n");
        assert_eq!(
            diff,
            "@@ golden line 2 @@\n b\n c\n d\n-e\n-\n+\"E\\r\"\n+\n"
        );
    }
}
