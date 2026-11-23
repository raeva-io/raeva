//! Escaping for text raeva prints that may hold untrusted input: coordinates,
//! repository ids and URLs from POMs, server responses, file names.
//!
//! A raw control character can move the cursor, rewrite earlier lines or
//! change the terminal title, and the bidirectional controls reorder what a
//! reader sees, so a hostile POM could make a warning look like something
//! else. They are shown as Rust escapes such as `\u{1b}` instead.

use std::borrow::Cow;

fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// `text` with the value of each secret the configuration took hidden
/// ([`super::secrets::redact_secrets`]), before escaping, truncation or wrapping
/// can split or respell it, and then the characters `escape` picks escaped.
fn escape_where(text: &str, escape: impl Fn(char) -> bool) -> Cow<'_, str> {
    match super::secrets::redact_secrets(text) {
        Cow::Borrowed(text) => escape_chars(text, escape),
        Cow::Owned(text) => Cow::Owned(escape_chars(&text, escape).into_owned()),
    }
}

fn escape_chars(text: &str, escape: impl Fn(char) -> bool) -> Cow<'_, str> {
    if !text.chars().any(&escape) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if escape(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Text for the terminal. Line breaks and tabs stay, every other control
/// and bidirectional character is escaped.
pub(crate) fn terminal_text(text: &str) -> Cow<'_, str> {
    escape_where(text, |c| {
        (c.is_control() && c != '\n' && c != '\t') || is_bidi_control(c)
    })
}

/// Text that has to stay on one line, such as a value quoted in a snippet
/// to paste into a file: line breaks and tabs are escaped too.
pub(crate) fn inline_text(text: &str) -> Cow<'_, str> {
    escape_where(text, |c| c.is_control() || is_bidi_control(c))
}

/// A serialized JSON document, with the characters serde_json leaves raw
/// that a terminal still acts on written as `\u` escapes: DEL, the C1
/// controls and the bidirectional controls. serde_json escapes U+0000 to
/// U+001F itself, and outside strings JSON holds only ASCII, so every
/// character replaced here sits inside a string and the document parses to
/// the same value.
///
/// The value of each secret the configuration took is hidden first
/// ([`super::secrets::redact_secrets_in_json`]).
pub(crate) fn json_document(json: String) -> String {
    let redacted = match super::secrets::redact_secrets_in_json(&json) {
        Cow::Owned(redacted) => Some(redacted),
        Cow::Borrowed(_) => None,
    };
    let json = redacted.unwrap_or(json);
    let escape = |c: char| ('\u{7F}'..='\u{9F}').contains(&c) || is_bidi_control(c);
    if !json.chars().any(escape) {
        return json;
    }
    let mut out = String::with_capacity(json.len() + 8);
    for c in json.chars() {
        if escape(c) {
            out.push_str(&format!("\\u{:04x}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{inline_text, json_document, terminal_text};

    /// A secret is hidden before escaping or wrapping could respell or
    /// split it: one with a control character, and one of words a table
    /// would wrap.
    #[test]
    fn a_secret_is_hidden_before_it_is_escaped_or_wrapped() {
        super::super::secrets::register_secret("zqCTL\rzq");
        super::super::secrets::register_secret("zqwrap one two three four five six seven eight zq");
        assert_eq!(terminal_text("a zqCTL\rzq b"), "a *** b");
        assert_eq!(inline_text("a zqCTL\rzq b"), "a *** b");
        let mut table = crate::output::Table::new(["store", "path"]);
        table.add_row([
            "home",
            "/srv/zqwrap one two three four five six seven eight zq/store",
        ]);
        let rendered = table.render_to_width(30);
        assert!(
            !rendered.contains("zqwrap") && !rendered.contains("eight"),
            "{rendered}"
        );
        assert!(rendered.contains("***"), "{rendered}");
    }

    #[test]
    fn terminal_text_keeps_layout_and_escapes_controls() {
        assert_eq!(terminal_text("a\n\tb"), "a\n\tb");
        assert_eq!(terminal_text("x\u{1b}[2Jy"), "x\\u{1b}[2Jy");
        assert_eq!(terminal_text("a\rb"), "a\\rb");
        assert_eq!(terminal_text("del\u{7f}"), "del\\u{7f}");
        assert_eq!(terminal_text("c1\u{9b}"), "c1\\u{9b}");
        assert_eq!(terminal_text("\u{202E}gpj.exe"), "\\u{202e}gpj.exe");
        assert_eq!(terminal_text("\u{2066}x\u{2069}"), "\\u{2066}x\\u{2069}");
        assert_eq!(terminal_text("\u{200F}\u{061C}"), "\\u{200f}\\u{61c}");
        assert_eq!(terminal_text("Grüße → ok"), "Grüße → ok");
    }

    #[test]
    fn escaping_is_idempotent() {
        let once = terminal_text("\u{1b}]0;title\u{7}").into_owned();
        assert_eq!(terminal_text(&once), once);
    }

    #[test]
    fn inline_text_escapes_line_breaks() {
        assert_eq!(inline_text("a\nb\tc\u{1b}"), "a\\nb\\tc\\u{1b}");
    }

    #[test]
    fn json_document_escapes_what_serde_leaves_raw() {
        let value = serde_json::json!({
            "text": "a\u{1b}b\u{7f}c\u{85}d\u{202E}e\u{2067}f\u{200E}g",
            "plain": "Grüße",
        });
        let json = json_document(serde_json::to_string(&value).expect("json"));
        for raw in [
            '\u{1b}', '\u{7f}', '\u{85}', '\u{202E}', '\u{2067}', '\u{200E}',
        ] {
            assert!(!json.contains(raw), "{raw:?} left raw in {json}");
        }
        assert!(
            json.contains("\\u007f") && json.contains("\\u202e"),
            "{json}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parses");
        assert_eq!(parsed, value);
    }
}
