//! Text that a project, a POM or a repository supplied, for messages.

use std::fmt;

use crate::component::is_unsafe_char;

/// How many characters of such text a message shows.
const MAX_SHOWN_CHARS: usize = 120;

/// Untrusted text for an error or log message. A character that would steer
/// a terminal or hide text (see [`crate::is_terminal_safe`]) is written as a
/// `\u{...}` escape, and text longer than 120 characters is cut and followed
/// by `...` and its size in bytes, so a hostile POM can neither rewrite the
/// terminal nor flood a message.
#[derive(Debug, Clone, Copy)]
pub struct Untrusted<'a> {
    text: &'a str,
    quote: bool,
}

/// `text` escaped and cut, without quotes. Ordinary short text prints as it
/// is, so a message that showed the value plainly keeps its wording.
pub fn bounded(text: &str) -> Untrusted<'_> {
    Untrusted { text, quote: false }
}

/// `text` escaped and cut like [`bounded`], in double quotes, with `"` and
/// `\` inside escaped too.
pub fn quoted(text: &str) -> Untrusted<'_> {
    Untrusted { text, quote: true }
}

impl fmt::Display for Untrusted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write;
        if self.quote {
            f.write_char('"')?;
        }
        let mut chars = self.text.chars();
        for c in chars.by_ref().take(MAX_SHOWN_CHARS) {
            if is_unsafe_char(c) {
                write!(f, "{}", c.escape_unicode())?;
            } else if self.quote && matches!(c, '"' | '\\') {
                write!(f, "{}", c.escape_default())?;
            } else {
                f.write_char(c)?;
            }
        }
        if self.quote {
            f.write_char('"')?;
        }
        if chars.next().is_some() {
            write!(f, "... ({} bytes)", self.text.len())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{bounded, quoted};

    #[test]
    fn ordinary_text_is_unchanged() {
        assert_eq!(bounded("com.example:demo").to_string(), "com.example:demo");
        assert_eq!(quoted("1.0-SNAPSHOT").to_string(), "\"1.0-SNAPSHOT\"");
    }

    #[test]
    fn steering_characters_are_escaped() {
        assert_eq!(
            bounded("a\u{1b}[31mb\nc\u{202e}d").to_string(),
            "a\\u{1b}[31mb\\u{a}c\\u{202e}d"
        );
        assert_eq!(
            quoted("say \"hi\" \\").to_string(),
            "\"say \\\"hi\\\" \\\\\""
        );
    }

    #[test]
    fn long_text_is_cut_and_sized() {
        let long = "é".repeat(300);
        let shown = quoted(&long).to_string();
        assert_eq!(shown, format!("\"{}\"... (600 bytes)", "é".repeat(120)));
        assert_eq!(bounded(&"x".repeat(120)).to_string(), "x".repeat(120));
    }
}
