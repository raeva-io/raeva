//! Access to the checked-in `test-fixtures/` tree.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// UTF-8 text of `relative` under [`workspace_root`]. Completeness tests
/// read docs and READMEs through this so a missing file names the path.
pub fn workspace_file(relative: &str) -> String {
    fs::read_to_string(workspace_root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

pub fn root() -> PathBuf {
    workspace_root().join("test-fixtures")
}

/// `test-fixtures/<relative>` in the workspace checkout.
pub fn path(relative: &str) -> PathBuf {
    root().join(relative)
}

/// Text of `heading` in `text` up to the next ATX heading of the same or
/// higher level. Nested headings belong to the section. Completeness tests
/// parse a section's table or links so a name that only appears in prose
/// elsewhere does not count. Fenced code is skipped, so a `#` line in an
/// example is not a heading. A `#not-a-heading` line is not a heading. A
/// heading with no body, including one at the end of the file, is empty.
/// LF and CRLF line endings both work.
pub fn markdown_section<'a>(text: &'a str, heading: &str) -> &'a str {
    let mut fence = None;
    let mut pos = 0;
    let mut start = None;
    let mut level = 0;
    loop {
        let rest = &text[pos..];
        let line_end = rest.find('\n').unwrap_or(rest.len());
        let line = rest[..line_end].trim_end_matches('\r');
        if let Some((ch, len)) = fence {
            if fence_closer(line, ch, len) {
                fence = None;
            }
        } else if let Some(open) = fence_opener(line) {
            fence = Some(open);
        } else if start.is_none() && heading_line_matches(line, heading) {
            if line_end == rest.len() {
                return "";
            }
            start = Some(pos + line_end + 1);
            level = atx_heading(line).map(|(hashes, _)| hashes).unwrap_or(0);
        } else if let Some(from) = start
            && let Some((hashes, _)) = atx_heading(line)
            && hashes <= level
        {
            let end = pos.saturating_sub(1);
            return if end < from { "" } else { &text[from..end] };
        }
        if line_end == rest.len() {
            return start
                .map(|from| &text[from..])
                .unwrap_or_else(|| panic!("no `{heading}` heading"));
        }
        pos += line_end + 1;
    }
}

/// CommonMark opening fences and ATX headings may be indented at most three
/// spaces. A four-space indent is an indented code block, not a fence or a
/// heading, so completeness tests must not treat it as one.
fn atx_indent(line: &str) -> Option<&str> {
    let spaces = line.bytes().take_while(|&byte| byte == b' ').count();
    (spaces <= 3).then_some(&line[spaces..])
}

/// Opening fence: indent at most three, then three or more backticks or
/// tildes. An info string is allowed. Completeness tests share this with
/// [`fence_closer`] so a `~~~` line does not close a backtick fence and a
/// ` ```json ` line does not close a ` ``` ` fence.
fn fence_opener(line: &str) -> Option<(u8, usize)> {
    let rest = atx_indent(line)?;
    let bytes = rest.as_bytes();
    let ch = *bytes.first()?;
    if ch != b'`' && ch != b'~' {
        return None;
    }
    let len = bytes.iter().take_while(|&&byte| byte == ch).count();
    (len >= 3).then_some((ch, len))
}

/// Closing fence for an opener of `ch` × `len`: the same character, at
/// least as long, and only whitespace after the markers.
fn fence_closer(line: &str, ch: u8, len: usize) -> bool {
    let Some(rest) = atx_indent(line) else {
        return false;
    };
    let bytes = rest.as_bytes();
    if bytes.first() != Some(&ch) {
        return false;
    }
    let close = bytes.iter().take_while(|&&byte| byte == ch).count();
    close >= len
        && rest[close..]
            .bytes()
            .all(|byte| byte == b' ' || byte == b'\t')
}

/// `line` is `heading`, or both are ATX headings of the same level and
/// text, so `## Foo` matches `## Foo ##` and trailing spaces.
fn heading_line_matches(line: &str, heading: &str) -> bool {
    line == heading
        || matches!(
            (atx_heading(line), atx_heading(heading)),
            (Some(left), Some(right)) if left == right
        )
}

/// ATX heading level (1 to 6) and text when `line` is `#` to `######` plus
/// whitespace, optionally indented by at most three spaces. Completeness
/// tests and [`markdown_heading_slugs`] share this so a `#not-a-heading`
/// line is not a section boundary and not a fragment slug.
fn atx_heading(line: &str) -> Option<(usize, &str)> {
    let line = atx_indent(line)?;
    let hashes = line.bytes().take_while(|&byte| byte == b'#').count();
    if !(1..=6).contains(&hashes) {
        return None;
    }
    let rest = &line[hashes..];
    if !rest.starts_with(' ') && !rest.starts_with('\t') {
        return None;
    }
    Some((hashes, rest.trim().trim_end_matches('#').trim()))
}

/// Lines of `text` that are not fenced code (and not the fence markers).
/// Completeness tests walk docs this way so an example is not a heading or
/// a link.
pub fn markdown_prose_lines(text: &str) -> Vec<&str> {
    markdown_lines(text, false)
}

/// Lines of `text` inside fenced code blocks. Completeness tests collect
/// commands from a README fence this way so a prose mention does not count.
pub fn markdown_fenced_lines(text: &str) -> Vec<&str> {
    markdown_lines(text, true)
}

fn markdown_lines(text: &str, fenced: bool) -> Vec<&str> {
    let mut fence = None;
    let mut lines = Vec::new();
    for line in text.lines() {
        if let Some((ch, len)) = fence {
            if fence_closer(line, ch, len) {
                fence = None;
                continue;
            }
        } else if let Some(open) = fence_opener(line) {
            fence = Some(open);
            continue;
        }
        if fence.is_some() == fenced {
            lines.push(line);
        }
    }
    lines
}

/// Whether prose of `text` names `name` in backticks. Completeness tests use
/// this so a key that only appears in a fenced example does not count. A
/// TOML table may be written `` `[[name]]` `` or `` `[name]` ``.
pub fn markdown_names(text: &str, name: &str) -> bool {
    let needles = [
        format!("`{name}`"),
        format!("`[[{name}]]`"),
        format!("`[{name}]`"),
    ];
    markdown_prose_lines(text)
        .iter()
        .any(|line| needles.iter().any(|needle| line.contains(needle)))
}

/// Completeness tests require each name in backticks in `text`.
pub fn assert_markdown_names(
    text: &str,
    what: &str,
    keys: impl IntoIterator<Item = impl AsRef<str>>,
) {
    for key in keys {
        let key = key.as_ref();
        assert!(
            markdown_names(text, key),
            "{what} must name `{key}` in backticks"
        );
    }
}

/// Body rows of the first Markdown table under `heading` in `text`. Cells
/// have backticks stripped. Completeness tests use this so a README table is
/// the list of fixtures, not a substring that can match prose. Fenced tables
/// are skipped, so an example is not the list.
pub fn markdown_table(text: &str, heading: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = markdown_prose_lines(markdown_section(text, heading))
        .into_iter()
        .filter_map(table_row)
        .collect();
    assert!(
        rows.len() >= 2 && is_table_separator(&rows[1]),
        "the `{heading}` section has no table"
    );
    rows.split_off(2)
}

fn table_row(line: &str) -> Option<Vec<String>> {
    let rest = atx_indent(line)?.strip_prefix('|')?;
    let rest = rest.strip_suffix('|').unwrap_or(rest);
    Some(
        rest.split('|')
            .map(|cell| cell.trim().replace('`', ""))
            .collect(),
    )
}

fn is_table_separator(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|cell| {
            let cell = cell.trim();
            let cell = cell.strip_prefix(':').unwrap_or(cell);
            let cell = cell.strip_suffix(':').unwrap_or(cell);
            !cell.is_empty() && cell.bytes().all(|byte| byte == b'-')
        })
}

pub fn markdown_first_column(text: &str, heading: &str) -> Vec<String> {
    markdown_table(text, heading)
        .into_iter()
        .map(|row| row.into_iter().next().unwrap_or_default())
        .collect()
}

/// [`markdown_first_column`] cells split on commas. Completeness tests use
/// this so a table cell that lists several names, such as two commands or
/// two environment variables, still counts each one.
pub fn markdown_first_column_parts(text: &str, heading: &str) -> Vec<String> {
    markdown_first_column(text, heading)
        .into_iter()
        .flat_map(|cell| {
            cell.split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Local Markdown links `](path)`, `](<path>)`, `](path#anchor)`, or
/// `](#anchor)` in `text`. Fenced code and inline code are skipped, so an
/// example is not a link. Completeness tests use this so a relative target
/// that does not exist, or a heading fragment that is not a slug, fails.
/// URL and mailto targets are dropped. `path` is empty for a same-file
/// `#anchor`.
pub fn markdown_local_links(text: &str) -> Vec<(String, Option<String>)> {
    let mut links = Vec::new();
    for line in markdown_prose_lines(text) {
        collect_markdown_local_links(&strip_inline_code(line), &mut links);
    }
    links
}

fn strip_inline_code(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    loop {
        let Some((before, after)) = rest.split_once('`') else {
            out.push_str(rest);
            break;
        };
        out.push_str(before);
        match after.split_once('`') {
            Some((_, rest2)) => rest = rest2,
            None => {
                out.push('`');
                out.push_str(after);
                break;
            }
        }
    }
    out
}

fn collect_markdown_local_links(text: &str, links: &mut Vec<(String, Option<String>)>) {
    let mut rest = text;
    while let Some((_, after)) = rest.split_once("](") {
        let raw = after.split(')').next().unwrap_or("");
        rest = after;
        let target = markdown_link_destination(raw);
        if target.starts_with("http://")
            || target.starts_with("https://")
            || target.starts_with("mailto:")
        {
            continue;
        }
        let (path, fragment) = match target.split_once('#') {
            Some((path, fragment)) => (path.to_string(), Some(fragment.to_string())),
            None => (target.to_string(), None),
        };
        if path.is_empty() && fragment.is_none() {
            continue;
        }
        links.push((path, fragment));
    }
}

fn markdown_link_destination(raw: &str) -> &str {
    let raw = raw.trim();
    if let Some(inner) = raw.strip_prefix('<') {
        inner.split('>').next().unwrap_or("")
    } else {
        raw.split([' ', '?']).next().unwrap_or("")
    }
}

/// GitHub heading slugs of ATX headings in `text`, in file order. A duplicate
/// heading gets `-1`, `-2`, … as GitHub does. Completeness tests use this so
/// a `#fragment` that is not a heading fails.
pub fn markdown_heading_slugs(text: &str) -> Vec<String> {
    let mut slugs = Vec::new();
    let mut seen = std::collections::HashMap::<String, usize>::new();
    for line in markdown_prose_lines(text) {
        let Some((_, heading)) = atx_heading(line) else {
            continue;
        };
        let base = github_slug(heading);
        let count = seen.entry(base.clone()).or_insert(0);
        let slug = if *count == 0 {
            base
        } else {
            format!("{base}-{count}")
        };
        *count += 1;
        slugs.push(slug);
    }
    slugs
}

fn github_slug(heading: &str) -> String {
    let mut slug = String::new();
    let mut pending_hyphen = false;
    for character in heading
        .chars()
        .map(|character| character.to_ascii_lowercase())
    {
        if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
            if pending_hyphen && !slug.is_empty() {
                slug.push('-');
            }
            pending_hyphen = false;
            slug.push(character);
        } else if character.is_whitespace() {
            pending_hyphen = true;
        }
    }
    slug
}

/// The `"..."` argument after each `prefix` in `source`, with whitespace
/// allowed between them. A match inside a string, char literal, raw
/// string, or `//` / `/* */` comment is ignored, so writing `prefix` as a
/// string or an example in a comment is not a use. A match whose string
/// spans lines is ignored. Completeness tests collect `include_str!("path")`
/// and `Env::check("name")` this way so a skip-list does not have to repeat
/// the names.
pub fn quoted_after(source: &str, prefix: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let prefix_bytes = prefix.as_bytes();
    if prefix_bytes.is_empty() {
        return Vec::new();
    }
    let mut values = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(after) = skip_string_or_comment(bytes, i) {
            i = after;
            continue;
        }
        if bytes[i..].starts_with(prefix_bytes) {
            i += prefix_bytes.len();
            loop {
                while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
                    i += 1;
                }
                if bytes.get(i) == Some(&b'/')
                    && let Some(after) = skip_string_or_comment(bytes, i)
                {
                    i = after;
                    continue;
                }
                break;
            }
            if bytes.get(i) == Some(&b'"') {
                let inner = i + 1;
                if let Some(rel) = source.get(inner..).and_then(|rest| rest.find('"')) {
                    let value = &source[inner..inner + rel];
                    if !value.contains(['\n', '\r']) {
                        values.push(value.to_string());
                    }
                    i = inner + rel + 1;
                    continue;
                }
            }
            continue;
        }
        i += 1;
    }
    values
}

/// Source with comments blanked (spaces, newlines kept) so a match in a
/// `//` or `/* */` comment is not a use. Strings are kept, so `"key":` in
/// `json!` still counts.
fn without_comments(source: &str) -> String {
    blank_spans(source, false)
}

/// Source with comments and strings blanked (spaces, newlines kept) so a
/// match in either is not a use. Completeness scans that look for `warn!(`
/// or `println!(` use this; line numbers stay aligned.
pub fn without_strings_and_comments(source: &str) -> String {
    blank_spans(source, true)
}

fn blank_spans(source: &str, strings: bool) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < bytes.len() {
        if let Some(after) = skip_string_or_comment(bytes, i) {
            let after = after.min(bytes.len());
            if bytes[i] == b'/' || strings {
                for &byte in &bytes[i..after] {
                    out.push(if byte == b'\n' { '\n' } else { ' ' });
                }
            } else {
                out.push_str(&source[i..after]);
            }
            i = after;
            continue;
        }
        let ch = source[i..].chars().next().expect("byte in source");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// `source` with every `#[cfg(...)]` item whose cfg enables `test` removed:
/// an inline `mod name { ... }`, a `fn` / `impl` / `const` / `struct`,
/// including `pub` / `pub(crate)` and `all(test, …)`. Completeness tests
/// drop those items so a `json!` or `insert(` in a test is not a payload
/// field. Production after a test item is kept. A `#[cfg(test)] mod name;`
/// declaration is not that module. `#[cfg(not(test))]` is kept.
pub fn without_inline_test_module(source: &str) -> String {
    let bytes = source.as_bytes();
    let needle = b"#[cfg(";
    let mut out = String::new();
    let mut offset = 0;
    let mut i = 0;
    while i < bytes.len() {
        if let Some(after) = skip_string_or_comment(bytes, i) {
            i = after;
            continue;
        }
        if bytes[i..].starts_with(needle) {
            if let Some(after) = skip_cfg_test_item(&source[i..]) {
                out.push_str(&source[offset..i]);
                offset = source.len() - after.len();
                i = offset;
                continue;
            }
            i += needle.len();
            continue;
        }
        i += 1;
    }
    out.push_str(&source[offset..]);
    out
}

/// When `from_attr` starts with `#[cfg(...)]` that enables `test`, the text
/// after the attribute. `not(test)` does not enable `test`.
fn cfg_attr_after_if_test(from_attr: &str) -> Option<&str> {
    let (cfg, after) = attribute_list(from_attr, "cfg")?;
    cfg_enables_test(cfg).then_some(after)
}

/// When `from_attr` starts with `#[name(...)]`, the tokens inside the
/// parentheses and the text after the attribute. Nested parentheses in the
/// list are kept; `name` must be followed by `(`, so `cfg` does not match
/// `cfg_attr`.
fn attribute_list<'a>(from_attr: &'a str, name: &str) -> Option<(&'a str, &'a str)> {
    let after = skip_attribute(from_attr)?;
    let attr = &from_attr[..from_attr.len() - after.len()];
    let rest = attr
        .strip_prefix("#[")?
        .strip_prefix(name)?
        .strip_prefix('(')?;
    let inner = rest.strip_suffix(']')?.strip_suffix(')')?;
    Some((inner, after))
}

/// True when `test` is required, so a non-test production build omits the
/// item: `test` or `all(test, …)`. `any(test, feature = "testing")` stays;
/// those items ship with the feature.
fn cfg_enables_test(cfg: &str) -> bool {
    test_is_required(&strip_cfg_not(cfg))
}

fn test_is_required(cfg: &str) -> bool {
    let cfg = cfg.trim();
    if cfg == "test" {
        return true;
    }
    let Some(after_all) = cfg.strip_prefix("all") else {
        return false;
    };
    let after_all = after_all.trim_start();
    if !after_all.starts_with('(') {
        return false;
    }
    let Some(end) = matching_close(after_all, b'(', b')') else {
        return false;
    };
    cfg_args(&after_all[1..end])
        .iter()
        .any(|part| test_is_required(part))
}

/// Comma-separated cfg arguments at depth 0, so `all(test, any(unix, windows))`
/// is `test` and `any(unix, windows)`.
fn cfg_args(inner: &str) -> Vec<&str> {
    let bytes = inner.as_bytes();
    let mut args = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if let Some(after) = skip_string_or_comment(bytes, i) {
            i = after;
            continue;
        }
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                args.push(inner[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    args.push(inner[start..].trim());
    args
}

fn strip_cfg_not(cfg: &str) -> String {
    let mut out = String::new();
    let mut rest = cfg;
    while let Some(at) = rest.find("not(") {
        out.push_str(&rest[..at]);
        let from_paren = &rest[at + 3..];
        match matching_close(from_paren, b'(', b')') {
            Some(end) => rest = &from_paren[end + 1..],
            None => {
                out.push_str(&rest[at..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// When `from_attr` starts with `#[cfg(...)]` that enables `test` and a
/// `mod name`, the module name and the text after it (comments skipped).
fn cfg_test_mod(from_attr: &str) -> Option<(&str, &str)> {
    let after_attr = cfg_attr_after_if_test(from_attr)?;
    let after = strip_visibility(skip_leading_noise(after_attr));
    let name = after.strip_prefix("mod ")?;
    let ident = name
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    if ident == 0 {
        return None;
    }
    Some((&name[..ident], skip_leading_noise(&name[ident..])))
}

/// When `from_attr` starts with a `#[cfg(...)]` item whose cfg enables
/// `test`, the text after that item. A `mod name;` file-module declaration
/// is left in place; an inline module, `fn`, `impl`, or other `;` / `{ }`
/// item is dropped.
fn skip_cfg_test_item(from_attr: &str) -> Option<&str> {
    if let Some((_, after_name)) = cfg_test_mod(from_attr) {
        if after_name.starts_with(';') {
            return None;
        }
        return after_brace_block(after_name);
    }
    let after_attr = cfg_attr_after_if_test(from_attr)?;
    skip_item_body(strip_visibility(skip_leading_noise(after_attr)))
}

/// Text after the first `;` or `{ ... }` in `item`, skipping strings and
/// comments so a `';'` in a signature does not end it.
fn skip_item_body(item: &str) -> Option<&str> {
    let bytes = item.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(after) = skip_string_or_comment(bytes, i) {
            i = after;
            continue;
        }
        match bytes[i] {
            b'{' => return after_brace_block(&item[i..]),
            b';' => return Some(&item[i + 1..]),
            _ => i += 1,
        }
    }
    None
}

/// When `from_attr` starts with `#[cfg(...)] mod name;`, the module name.
fn cfg_test_file_module(from_attr: &str) -> Option<&str> {
    let (name, after_name) = cfg_test_mod(from_attr)?;
    after_name.starts_with(';').then_some(name)
}

/// Names of `#[cfg(test)] mod name;` file modules in `source`. Completeness
/// tests skip those files so a test-only sibling is not production.
fn cfg_test_file_modules(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let needle = b"#[cfg(";
    let mut names = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(after) = skip_string_or_comment(bytes, i) {
            i = after;
            continue;
        }
        if bytes[i..].starts_with(needle) {
            if let Some(name) = cfg_test_file_module(&source[i..]) {
                names.push(name);
            }
            i += needle.len();
            continue;
        }
        i += 1;
    }
    names
}

/// `item` after leading `#[...]` attributes, `//` comments (including
/// `///`), nested `/* */` comments, and blank lines, so a derive or
/// `#[cfg(test)]` with docs in between still names the item.
fn skip_leading_noise(item: &str) -> &str {
    let mut rest = item;
    loop {
        rest = rest.trim_start();
        if rest.starts_with("#[") {
            let Some(after) = skip_attribute(rest) else {
                return rest;
            };
            rest = after;
            continue;
        }
        if rest.starts_with("//") {
            rest = rest.split_once('\n').map_or("", |(_, after)| after);
            continue;
        }
        if rest.starts_with("/*") {
            let Some(after) = skip_block_comment(rest) else {
                return rest;
            };
            rest = after;
            continue;
        }
        return rest;
    }
}

/// Rust block comments nest. Unclosed comments return `None`.
fn skip_block_comment(item: &str) -> Option<&str> {
    let rest = item.strip_prefix("/*")?;
    let bytes = rest.as_bytes();
    let mut depth = 1usize;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            depth += 1;
            i += 2;
            continue;
        }
        if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
            depth -= 1;
            if depth == 0 {
                return Some(&rest[i + 2..]);
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

fn skip_attribute(from: &str) -> Option<&str> {
    let rest = from.strip_prefix('#')?;
    matching_close(rest, b'[', b']').map(|end| &rest[end + 1..])
}

/// `item` after `pub`, `pub(crate)`, `pub(super)`, or `pub(in ...)`.
fn strip_visibility(item: &str) -> &str {
    let item = item.trim_start();
    if let Some(from) = item.strip_prefix("pub") {
        let from = from.trim_start();
        if from.starts_with('(') {
            return matching_close(from, b'(', b')')
                .map(|end| from[end + 1..].trim_start())
                .unwrap_or(item);
        }
    }
    item.strip_prefix("pub ").unwrap_or(item)
}

/// Names of `struct`s in `source` that derive `Deserialize`. Enums are
/// omitted: their variants are values, not keys. Completeness tests collect
/// `raeva.toml` table types this way so a new struct fails until the docs
/// name its fields.
pub fn serde_deserialize_structs(source: &str) -> Vec<String> {
    serde_derive_structs(source, "Deserialize")
}

/// Names of `struct`s in `source` that derive `Serialize`. Completeness
/// tests collect JSON payload types this way so a `skip_serializing_if`
/// field still counts.
pub fn serde_serialize_structs(source: &str) -> Vec<String> {
    serde_derive_structs(source, "Serialize")
}

/// Field names of every `Serialize` struct in `source` before an inline
/// test module, using `rename` and omitting `serde(skip)` /
/// `skip_serializing` fields. Completeness tests use this so a dummy
/// value does not have to list the fields.
pub fn serde_serialize_fields(source: &str) -> Vec<String> {
    let source = without_inline_test_module(source);
    let mut keys = Vec::new();
    for name in serde_serialize_structs(&source) {
        keys.extend(serde_struct_fields(&source, &name));
    }
    keys.sort();
    keys.dedup();
    assert!(!keys.is_empty(), "source has no serializable fields");
    keys
}

fn serde_derive_structs(source: &str, derive: &str) -> Vec<String> {
    let source = without_comments(source);
    let mut names = Vec::new();
    let mut rest = source.as_str();
    let needle = "#[derive(";
    while let Some(at) = rest.find(needle) {
        let after = &rest[at..];
        let Some((list, after_attr)) = attribute_list(after, "derive") else {
            rest = &rest[at + needle.len()..];
            continue;
        };
        rest = after_attr;
        if !derive_contains(list, derive) {
            continue;
        }
        let item = strip_visibility(skip_leading_noise(after_attr));
        let Some(name) = item.strip_prefix("struct ") else {
            continue;
        };
        let ident: String = name
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect();
        if !ident.is_empty() {
            names.push(ident);
        }
    }
    names
}

fn derive_contains(list: &str, name: &str) -> bool {
    list.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| token == name)
}

/// Field names a `Deserialize` struct accepts, using `rename = "..."` when
/// present and skipping `serde(skip)` / `skip_deserializing` fields.
/// Completeness tests collect `raeva.toml` keys this way so a new field
/// fails until the docs name it.
pub fn serde_struct_fields(source: &str, name: &str) -> Vec<String> {
    let source = without_comments(source);
    let body = serde_struct_body(&source, name);
    let mut fields = Vec::new();
    let mut rename = None;
    let mut skip = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(value) = serde_rename_value(trimmed) {
            rename = Some(value);
        }
        if serde_skip_field(trimmed) {
            skip = true;
        }
        let Some(field) = rust_field_name(trimmed) else {
            continue;
        };
        if !skip {
            fields.push(rename.take().unwrap_or(field));
        } else {
            rename = None;
        }
        skip = false;
    }
    assert!(
        !fields.is_empty(),
        "struct {name} has no deserializable fields"
    );
    fields
}

fn serde_struct_body<'a>(source: &'a str, name: &str) -> &'a str {
    let header = format!("struct {name}");
    let mut rest = source;
    loop {
        let at = rest
            .find(&header)
            .unwrap_or_else(|| panic!("no struct {name}"));
        let after_name = at + header.len();
        let next = rest[after_name..].chars().next();
        if next.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_') {
            let after = &rest[after_name..];
            let open = after
                .find('{')
                .unwrap_or_else(|| panic!("struct {name} has no body"));
            return struct_block(&after[open..]);
        }
        rest = &rest[after_name..];
    }
}

fn struct_block(source: &str) -> &str {
    let end = closing_brace(source).unwrap_or_else(|| panic!("unclosed struct body"));
    &source[1..end]
}

/// Index of the `}` that closes the `{` `source` starts with. Comments,
/// strings, raw strings, and char literals are skipped so a `}` in `'"'`
/// or `// }` does not close the block.
fn closing_brace(source: &str) -> Option<usize> {
    matching_close(source, b'{', b'}')
}

/// Index of `close` that matches the `open` `source` starts with. Comments,
/// strings, raw strings, and char literals are skipped so a closer in `')'`
/// or `// )` does not end the pair. Completeness tests use this so a
/// `warn!(...)` call is the call, not a `)` in its message.
pub fn matching_close(source: &str, open: u8, close: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.first() != Some(&open) {
        return None;
    }
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if let Some(after) = skip_string_or_comment(bytes, i) {
            i = after;
            continue;
        }
        match bytes[i] {
            b if b == open => depth += 1,
            b if b == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// When `bytes[i]` starts a comment, string, raw string, or char literal,
/// the index after it. Nested `/* */` comments are skipped.
fn skip_string_or_comment(bytes: &[u8], i: usize) -> Option<usize> {
    match bytes[i] {
        b'/' if bytes.get(i + 1) == Some(&b'/') => {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            Some(j)
        }
        b'/' if bytes.get(i + 1) == Some(&b'*') => {
            let rest = std::str::from_utf8(&bytes[i..]).ok()?;
            Some(skip_block_comment(rest).map_or(bytes.len(), |after| bytes.len() - after.len()))
        }
        b'b' if bytes.get(i + 1) == Some(&b'\'') => skip_char_literal(bytes, i + 1),
        b'b' if bytes.get(i + 1) == Some(&b'"') => skip_quoted(bytes, i + 1),
        b'b' if bytes.get(i + 1) == Some(&b'r') => skip_raw_string(bytes, i + 1),
        b'r' if bytes.get(i + 1) == Some(&b'"') || bytes.get(i + 1) == Some(&b'#') => {
            skip_raw_string(bytes, i)
        }
        b'\'' => skip_char_literal(bytes, i),
        b'"' => skip_quoted(bytes, i),
        _ => None,
    }
}

fn skip_char_literal(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    if j >= bytes.len() {
        return Some(j);
    }
    if bytes[j] == b'\\' {
        j += 1;
        match bytes.get(j) {
            Some(b'u') if bytes.get(j + 1) == Some(&b'{') => {
                j += 2;
                while j < bytes.len() && bytes[j] != b'}' {
                    j += 1;
                }
                if j < bytes.len() {
                    j += 1;
                }
            }
            Some(b'x') => {
                j += 1;
                j = j.saturating_add(2).min(bytes.len());
            }
            Some(_) => j += 1,
            None => {}
        }
        if bytes.get(j) == Some(&b'\'') {
            j += 1;
        }
        return Some(j);
    }
    let width = std::str::from_utf8(&bytes[j..])
        .ok()
        .and_then(|rest| rest.chars().next())
        .map_or(1, char::len_utf8);
    let after = (j + width).min(bytes.len());
    if bytes.get(after) == Some(&b'\'') {
        return Some(after + 1);
    }
    while j < bytes.len() && ident_byte(bytes[j]) {
        j += 1;
    }
    Some(j)
}

fn ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_quoted(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    let mut escaped = false;
    while j < bytes.len() {
        match (escaped, bytes[j]) {
            (true, _) => escaped = false,
            (false, b'\\') => escaped = true,
            (false, b'"') => return Some(j + 1),
            _ => {}
        }
        j += 1;
    }
    Some(j)
}

fn skip_raw_string(bytes: &[u8], i: usize) -> Option<usize> {
    let rest = bytes.get(i + 1)?;
    if *rest != b'#' && *rest != b'"' {
        return None;
    }
    let mut j = i + 1;
    let mut hashes = 0usize;
    while bytes.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if bytes.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while j < bytes.len() {
        if bytes[j] == b'"' {
            let mut k = j + 1;
            let mut n = 0usize;
            while n < hashes && bytes.get(k) == Some(&b'#') {
                n += 1;
                k += 1;
            }
            if n == hashes {
                return Some(k);
            }
        }
        j += 1;
    }
    Some(j)
}

fn after_brace_block(source: &str) -> Option<&str> {
    closing_brace(source).map(|end| &source[end + 1..])
}

fn serde_rename_value(line: &str) -> Option<String> {
    let after = line.split_once("rename = \"")?.1;
    let value = after.split('"').next().unwrap_or("");
    (!value.is_empty()).then(|| value.to_string())
}

fn serde_skip_field(line: &str) -> bool {
    let serde_skip = line.contains("serde(skip)")
        || line.contains("serde(skip,")
        || line.contains("serde(skip ");
    serde_skip
        || line.contains("skip_deserializing")
        || line.contains("skip_serializing)")
        || line.contains("skip_serializing,")
        || line.contains("skip_serializing ")
        || line == "skip"
        || line.starts_with("skip,")
        || line == "skip_serializing"
        || line.starts_with("skip_serializing,")
}

fn rust_field_name(line: &str) -> Option<String> {
    let line = strip_visibility(line);
    let ident = line
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect::<String>();
    if ident.is_empty() {
        return None;
    }
    line[ident.len()..]
        .trim_start()
        .starts_with(':')
        .then_some(ident)
}

/// Object keys written as `"key":` in `source`. Completeness tests collect
/// `json!({ "field": ... })` keys this way so a field that only appears
/// when a list is non-empty still counts. A match in a `//` comment is
/// ignored.
pub fn json_macro_keys(source: &str) -> Vec<String> {
    let stripped = without_comments(source);
    let mut keys = Vec::new();
    let mut rest = stripped.as_str();
    while let Some((_, after)) = rest.split_once('"') {
        let Some((key, after_key)) = after.split_once('"') else {
            break;
        };
        rest = after_key;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            continue;
        }
        let trimmed = rest.trim_start_matches([' ', '\t', '\n', '\r']);
        if trimmed.starts_with(':') {
            keys.push(key.to_string());
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

/// `"CODE"` string literals in `source`: two or more ASCII uppercase
/// letters or underscores. A match in a comment, char literal, or raw
/// string is ignored. Completeness tests collect error codes this way so
/// a quoted name in a comment is not a code.
pub fn uppercase_string_literals(source: &str) -> Vec<(usize, &str)> {
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(after) = skip_string_or_comment(bytes, i) {
            if bytes[i] == b'"' && after > i + 1 {
                let inner = &source[i + 1..after - 1];
                if inner.len() >= 2
                    && inner
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
                {
                    literals.push((i, inner));
                }
            }
            i = after;
            continue;
        }
        i += 1;
    }
    literals
}

/// Names of `mod name;` file-module declarations in `source`. Inline
/// `mod name { ... }` items, comments, and strings are skipped.
/// Indentation and `pub` / `pub(crate)` are allowed. Completeness tests
/// compare these to a directory's children so a new file fails until it
/// is declared.
pub fn rust_mod_declarations(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut names = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(after) = skip_string_or_comment(bytes, i) {
            i = after;
            continue;
        }
        if bytes[i..].starts_with(b"mod") {
            let ident_before = i > 0 && ident_byte(bytes[i - 1]);
            let after_mod = i + 3;
            let ident_after = bytes.get(after_mod).copied().is_some_and(ident_byte);
            if !ident_before && !ident_after {
                let rest = skip_leading_noise(&source[after_mod..]);
                let ident: String = rest
                    .chars()
                    .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                    .collect();
                if !ident.is_empty() {
                    let after_name = skip_leading_noise(&rest[ident.len()..]);
                    if after_name.starts_with(';') {
                        names.push(ident);
                    } else if after_name.starts_with('{')
                        && let Some(after) = after_brace_block(after_name)
                    {
                        i = source.len() - after.len();
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    names.sort();
    names
}

/// Start offsets of `name!(...)` in `source` for each name in `names`
/// (`warn!`, `println!`, …). Whitespace is allowed between `!` and `(`.
/// A match that continues an identifier is ignored. Completeness tests
/// pass [`without_strings_and_comments`] text so a name in a string is
/// not a call.
pub fn rust_macro_calls<'a>(source: &str, names: &[&'a str]) -> Vec<(usize, &'a str)> {
    let bytes = source.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let mut matched = None;
        for name in names {
            let needle = name.as_bytes();
            if !bytes[i..].starts_with(needle) || needle.last() != Some(&b'!') {
                continue;
            }
            let ident_before = source[..i]
                .chars()
                .next_back()
                .is_some_and(|character| character.is_alphanumeric() || character == '_');
            if ident_before {
                continue;
            }
            let mut j = i + needle.len();
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
                j += 1;
            }
            if bytes.get(j) == Some(&b'(') {
                matched = Some((i, *name));
                break;
            }
        }
        if let Some(hit) = matched {
            found.push(hit);
        }
        i += 1;
    }
    found
}

/// Whether `rel` (a `/`-separated path) is a test source: a `tests.rs`
/// file, a `tests` directory (including at the `src/` root), or a `test_*`
/// file or directory. Completeness tests skip these so a name only tests
/// use is not a production key.
pub fn is_test_source_path(rel: &str) -> bool {
    rel.split('/')
        .any(|part| part == "tests" || part == "tests.rs" || part.starts_with("test_"))
}

/// Production `.rs` files of workspace crates other than `rv-test-support`,
/// as `(crate/src/relative.rs, text)`. Completeness tests walk these so a
/// new crate is included and a test file is not.
pub fn workspace_production_sources() -> Vec<(String, String)> {
    let workspace = workspace_root();
    let mut sources = Vec::new();
    for crate_dir in sorted_child_names(&workspace, |path| {
        path.is_dir() && path.join("Cargo.toml").is_file()
    }) {
        if crate_dir == "rv-test-support" {
            continue;
        }
        let src = workspace.join(&crate_dir).join("src");
        if !src.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        for rel in sorted_relative_files(&src) {
            if !rel.ends_with(".rs") || is_test_source_path(&rel) {
                continue;
            }
            let text = fs::read_to_string(src.join(&rel))
                .unwrap_or_else(|error| panic!("read {crate_dir}/src/{rel}: {error}"));
            files.push((rel, text));
        }
        let mut skip = Vec::new();
        for (rel, text) in &files {
            let dir = rel
                .rsplit_once('/')
                .map(|(parent, _)| format!("{parent}/"))
                .unwrap_or_default();
            for name in cfg_test_file_modules(text) {
                skip.push(format!("{dir}{name}.rs"));
                skip.push(format!("{dir}{name}/"));
            }
        }
        for (rel, text) in files {
            if skip.iter().any(|prefix| {
                rel == prefix.as_str() || (prefix.ends_with('/') && rel.starts_with(prefix))
            }) {
                continue;
            }
            sources.push((format!("{crate_dir}/src/{rel}"), text));
        }
    }
    sources
}

/// Names of `dir`'s children that `keep` accepts, sorted. Completeness tests
/// use this so a new fixture fails until it is listed.
pub fn sorted_child_names(dir: &Path, keep: impl Fn(&Path) -> bool) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("entry in {}: {error}", dir.display()))
                .path()
        })
        .filter(|path| keep(path))
        .map(|path| {
            path.file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// `dir`'s immediate directories and files must be exactly `dirs` and `files`
/// (both already sorted). Completeness tests use this so a stray file or an
/// extra directory fails until it is listed.
pub fn assert_children(dir: &Path, dirs: &[&str], files: &[&str]) {
    assert_eq!(
        sorted_child_names(dir, |path| path.is_dir()),
        dirs,
        "directories in {}",
        dir.display()
    );
    assert_eq!(
        sorted_child_names(dir, |path| path.is_file()),
        files,
        "files in {}",
        dir.display()
    );
}

/// File paths relative to `dir`, sorted, with `/` separators. Completeness
/// tests that walk a tree use this so a nested extra file fails until it is
/// listed.
pub fn sorted_relative_files(dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    collect_relative_files(dir, dir, &mut files);
    files.sort();
    files
}

fn collect_relative_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    for name in sorted_child_names(dir, |_| true) {
        let path = dir.join(&name);
        if path.is_dir() {
            collect_relative_files(root, &path, out);
        } else {
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            out.push(rel);
        }
    }
}

/// Copy the directory `source` into `target`, creating `target`, with CRLF
/// line endings folded to LF in every file. Fixture files are LF text that
/// tests hash; a checkout that converts line endings would otherwise change
/// their bytes.
///
/// # Panics
///
/// On any I/O error, naming the path.
pub fn copy_tree_lf(source: &Path, target: &Path) {
    copy_filtered(source, target, &|_| false, true);
}

/// Copy the directory `source` into `target` byte for byte, omitting any
/// entry whose file name `skip` accepts, at every directory level.
pub fn copy_tree_skipping(source: &Path, target: &Path, skip: impl Fn(&OsStr) -> bool) {
    copy_filtered(source, target, &skip, false);
}

fn copy_filtered(source: &Path, target: &Path, skip: &dyn Fn(&OsStr) -> bool, fold_crlf: bool) {
    fs::create_dir_all(target).unwrap_or_else(|err| panic!("create {}: {err}", target.display()));
    let mut entries: Vec<_> = fs::read_dir(source)
        .unwrap_or_else(|err| panic!("read {}: {err}", source.display()))
        .map(|entry| entry.unwrap_or_else(|err| panic!("read {}: {err}", source.display())))
        .collect();
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        if skip(&entry.file_name()) {
            continue;
        }
        let from = entry.path();
        let to = target.join(entry.file_name());
        let kind = entry
            .file_type()
            .unwrap_or_else(|err| panic!("stat {}: {err}", from.display()));
        if kind.is_dir() {
            copy_filtered(&from, &to, skip, fold_crlf);
        } else {
            let bytes =
                fs::read(&from).unwrap_or_else(|err| panic!("read {}: {err}", from.display()));
            let bytes = if fold_crlf { lf(&bytes) } else { bytes };
            fs::write(&to, bytes).unwrap_or_else(|err| panic!("write {}: {err}", to.display()));
        }
    }
}

fn lf(bytes: &[u8]) -> Vec<u8> {
    let crlf = |index: usize| bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n');
    (0..bytes.len())
        .filter(|&index| !crlf(index))
        .map(|index| bytes[index])
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn quoted_after_allows_whitespace_before_the_quote() {
        let source = r#"
            include_str!("a.json")
            env.check(
                "b/c",
            );
        "#;
        assert_eq!(super::quoted_after(source, "include_str!("), ["a.json"]);
        assert_eq!(super::quoted_after(source, ".check("), ["b/c"]);
    }

    #[test]
    fn quoted_after_skips_a_string_that_spans_lines() {
        let source = r#"
            quoted_after(include_str!("file.rs"), ".check(");
            env.check("b/c", output);
        "#;
        assert_eq!(super::quoted_after(source, ".check("), ["b/c"]);
        let same_line = r#"let _ = ".check("gone")"; env.check("kept");"#;
        assert_eq!(super::quoted_after(same_line, ".check("), ["kept"]);
    }

    #[test]
    fn quoted_after_skips_a_match_in_a_comment() {
        let source = r#"
            // env.check("commented");
            env.check("kept");
            env.check("also"); // env.check("trailing")
            let _ = '"'; // env.check("char")
            /* env.check("block") */
            env.check("after");
            env.check(/* x */ "comment-between");
        "#;
        assert_eq!(
            super::quoted_after(source, ".check("),
            ["kept", "also", "after", "comment-between"]
        );
    }

    #[test]
    fn markdown_local_links_keeps_relative_files_same_file_anchors_and_drops_urls() {
        let text = r#"
See [Configuration](configuration.md#keys) and [the schema](../schemas/raeva-lock.json).
Skip [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), [mail](mailto:a@b).
Same file: [here](#anchor).
Angle brackets: [wrapped](<offline-builds.md#scope>).
Inline code is not a link: `[gone](missing.md)`.
```
[fenced](also-missing.md)
```
"#;
        assert_eq!(
            super::markdown_local_links(text),
            [
                ("configuration.md".into(), Some("keys".into())),
                ("../schemas/raeva-lock.json".into(), None),
                (String::new(), Some("anchor".into())),
                ("offline-builds.md".into(), Some("scope".into())),
            ]
        );
    }

    #[test]
    fn markdown_section_and_heading_slugs_skip_fenced_headings() {
        let text = r#"
## Real

```
## Fenced
[gone](missing.md)
```

~~~
## Also fenced
~~~

    ```
    ## Indented-code-fence
    ```

  ## Indented

## Next
"#;
        let section = super::markdown_section(text, "## Real");
        assert!(section.contains("## Fenced"), "{section}");
        assert!(section.contains("## Also fenced"), "{section}");
        assert!(section.contains("## Indented-code-fence"), "{section}");
        assert!(!section.contains("## Next"), "{section}");
        assert_eq!(
            super::markdown_heading_slugs(text),
            ["real", "indented", "next"]
        );
        assert!(super::markdown_local_links(text).is_empty());
        assert_eq!(
            super::markdown_fenced_lines(text),
            ["## Fenced", "[gone](missing.md)", "## Also fenced"]
        );
        let mixed = "## Real\n```\n## Still fenced\n~~~\n## Also still\n```\n## After\n";
        let mixed_section = super::markdown_section(mixed, "## Real");
        assert!(mixed_section.contains("## Still fenced"), "{mixed_section}");
        assert!(mixed_section.contains("## Also still"), "{mixed_section}");
        assert!(!mixed_section.contains("## After"), "{mixed_section}");
        assert_eq!(super::markdown_heading_slugs(mixed), ["real", "after"]);
        let info = "## Real\n```\n## Fenced\n```json\n## Still fenced\n```\n## After\n";
        let info_section = super::markdown_section(info, "## Real");
        assert!(info_section.contains("## Still fenced"), "{info_section}");
        assert!(!info_section.contains("## After"), "{info_section}");
    }

    #[test]
    fn markdown_section_ends_at_the_next_atx_heading() {
        assert_eq!(super::markdown_section("## Real\n## Next\n", "## Real"), "");
        assert_eq!(super::markdown_section("## Real", "## Real"), "");
        assert_eq!(super::markdown_section("## Real\n", "## Real"), "");
        let section = super::markdown_section("## Real\n#not-a-heading\n## Next\n", "## Real");
        assert!(section.contains("#not-a-heading"), "{section}");
        assert!(!section.contains("## Next"), "{section}");
        let nested =
            super::markdown_section("## Real\nintro\n### Nested\nnested\n## Next\n", "## Real");
        assert!(nested.contains("### Nested"), "{nested}");
        assert!(nested.contains("nested"), "{nested}");
        assert!(!nested.contains("## Next"), "{nested}");
        assert_eq!(
            super::markdown_section("### Nested\nbody\n## Next\n", "### Nested"),
            "body"
        );
        assert_eq!(
            super::markdown_section("## Real ##\nbody\n## Next\n", "## Real"),
            "body"
        );
    }

    #[test]
    fn json_macro_keys_keeps_object_keys_and_skips_comments() {
        let source = r#"
            serde_json::json!({
                "kept": 1,
                "also": "x",
            });
            // "gone": 1
            /* "block": 1 */
            let _ = "not-a-key";
        "#;
        assert_eq!(super::json_macro_keys(source), ["also", "kept"]);
    }

    #[test]
    fn without_inline_test_module_keeps_a_tests_declaration() {
        let source = r#"
#[cfg(test)]
mod tests;
json!({ "kept": 1 })
#[cfg(test)]
mod tests {
json!({ "gone": 1 })
}
"#;
        let kept = super::without_inline_test_module(source);
        assert_eq!(super::json_macro_keys(&kept), ["kept"]);
    }

    #[test]
    fn without_inline_test_module_drops_any_inline_test_module_name() {
        let source = r#"
json!({ "kept": 1 })
#[cfg(test)]
pub(crate) mod parse_tests {
json!({ "gone": 1 })
}
"#;
        let kept = super::without_inline_test_module(source);
        assert_eq!(super::json_macro_keys(&kept), ["kept"]);
    }

    #[test]
    fn without_inline_test_module_drops_cfg_all_test_and_keeps_not_test() {
        let all_test = r#"
json!({ "kept": 1 })
#[cfg(all(test, unix))]
mod tests {
json!({ "gone": 1 })
}
"#;
        assert_eq!(
            super::json_macro_keys(&super::without_inline_test_module(all_test)),
            ["kept"]
        );
        let not_test = r#"
#[cfg(not(test))]
mod production {
json!({ "kept": 1 })
}
"#;
        assert_eq!(
            super::json_macro_keys(&super::without_inline_test_module(not_test)),
            ["kept"]
        );
        let any_test = r#"
json!({ "kept": 1 })
#[cfg(any(test, feature = "testing"))]
fn for_testing() {
    json!({ "also": 1 })
}
"#;
        assert_eq!(
            super::json_macro_keys(&super::without_inline_test_module(any_test)),
            ["also", "kept"]
        );
    }

    #[test]
    fn without_inline_test_module_skips_attributes_between_cfg_and_mod() {
        let source = r#"
json!({ "kept": 1 })
#[cfg(test)]
/* nested /* comment */ */
#[allow(dead_code)]
pub(super) mod tests {
json!({ "gone": 1 })
}
"#;
        assert_eq!(
            super::json_macro_keys(&super::without_inline_test_module(source)),
            ["kept"]
        );
    }

    #[test]
    fn without_inline_test_module_keeps_production_between_test_modules() {
        let source = r#"
json!({ "before": 1 })
#[cfg(test)]
mod first {
json!({ "gone": 1 })
}
json!({ "middle": 1 })
#[cfg(test)]
mod second {
json!({ "also-gone": 1 })
}
json!({ "after": 1 })
"#;
        assert_eq!(
            super::json_macro_keys(&super::without_inline_test_module(source)),
            ["after", "before", "middle"]
        );
    }

    #[test]
    fn without_inline_test_module_drops_a_cfg_test_fn() {
        let source = r#"
json!({ "kept": 1 })
#[cfg(test)]
fn helper() {
    json!({ "gone": 1 })
}
#[cfg(test)]
impl Foo {
    json!({ "also-gone": 1 })
}
json!({ "after": 1 })
"#;
        assert_eq!(
            super::json_macro_keys(&super::without_inline_test_module(source)),
            ["after", "kept"]
        );
    }

    #[test]
    fn without_inline_test_module_skips_braces_inside_literals_and_comments() {
        let source = r##"
json!({ "kept": 1 })
#[cfg(test)]
mod tests {
    let _ = '"';
    let _ = '}';
    // }
    /* } */
    let _ = r#"}"#;
    json!({ "gone": 1 })
}
json!({ "after": 1 })
"##;
        assert_eq!(
            super::json_macro_keys(&super::without_inline_test_module(source)),
            ["after", "kept"]
        );
        assert_eq!(super::matching_close("{ '}' }", b'{', b'}'), Some(6));
        assert_eq!(super::matching_close("( ')' )", b'(', b')'), Some(6));
        assert_eq!(super::matching_close("( /* ) */ x )", b'(', b')'), Some(12));
        let unicode = "{ let _ = '\\u{1b}'; }";
        assert_eq!(
            super::matching_close(unicode, b'{', b'}'),
            Some(unicode.len() - 1)
        );
        let hex = "{ let _ = '\\x41'; }";
        assert_eq!(super::matching_close(hex, b'{', b'}'), Some(hex.len() - 1));
        let lifetime = "{ fn f<'static>() {} }";
        assert_eq!(
            super::matching_close(lifetime, b'{', b'}'),
            Some(lifetime.len() - 1)
        );
    }

    #[test]
    fn without_inline_test_module_skips_unicode_char_escapes() {
        let source = r#"
json!({ "kept": 1 })
let _ = '\u{1b}';
let _ = '\x41';
fn ident<'static>(c: char) -> char { c }
#[cfg(test)]
mod tests {
    json!({ "gone": 1 })
    let _ = '\u{1b}';
}
json!({ "after": 1 })
"#;
        assert_eq!(
            super::json_macro_keys(&super::without_inline_test_module(source)),
            ["after", "kept"]
        );
    }

    #[test]
    fn serde_struct_fields_uses_rename_and_skips_serde_skip() {
        let source = r#"
            // struct File is named in a comment
            struct Other {
                gone: u8,
            }
            struct File {
                pub id: Option<String>,
                #[serde(
                    default,
                    skip_serializing_if = "Option::is_none",
                    rename = "releases-update-policy"
                )]
                pub releases_update_policy: Option<String>,
                #[serde(skip)]
                display_path: String,
                #[serde(
                    skip
                )]
                pub(super) hidden: String,
                #[serde(skip_serializing)]
                human_only: String,
            }
            struct FileToml {
                extra: u8,
            }
        "#;
        assert_eq!(
            super::serde_struct_fields(source, "File"),
            ["id", "releases-update-policy"]
        );
    }

    #[test]
    fn serde_deserialize_structs_keeps_structs_and_skips_enums() {
        let source = r#"
            #[derive(Debug, Deserialize)]
            /// kept despite the docs
            pub(crate) struct Kept {
                field: u8,
            }
            #[derive(Deserialize, Default)]
            pub enum Gone {
                A,
            }
            #[derive(Debug)]
            struct AlsoGone {
                field: u8,
            }
            #[derive(Serialize, Deserialize)]
            #[serde(deny_unknown_fields)]
            #[non_exhaustive]
            pub struct Nested {
                inner: u8,
            }
        "#;
        assert_eq!(super::serde_deserialize_structs(source), ["Kept", "Nested"]);
        assert_eq!(super::serde_serialize_structs(source), ["Nested"]);
        assert_eq!(super::serde_serialize_fields(source), ["inner"]);
    }

    #[test]
    fn is_test_source_path_names_root_test_files() {
        assert!(super::is_test_source_path("test_warnings.rs"));
        assert!(super::is_test_source_path("foo/tests.rs"));
        assert!(super::is_test_source_path("foo/tests/bar.rs"));
        assert!(super::is_test_source_path("tests/foo.rs"));
        assert!(super::is_test_source_path("foo/test_bar.rs"));
        assert!(!super::is_test_source_path("settings.rs"));
        assert!(!super::is_test_source_path("config.rs"));
        let sources = super::workspace_production_sources();
        assert!(
            sources
                .iter()
                .any(|(path, _)| path == "rv-config/src/config.rs"),
            "workspace crates must be included"
        );
        assert!(
            sources
                .iter()
                .all(|(path, _)| !super::is_test_source_path(path)),
            "test sources must be omitted"
        );
        assert!(
            sources
                .iter()
                .all(|(path, _)| !path.ends_with("/golden_hashes.rs")),
            "#[cfg(test)] file modules must be omitted"
        );
    }

    #[test]
    fn markdown_table_skips_a_fenced_table() {
        let text = r#"
## Files

```
| Path |
| --- |
| `gone.md` |
```

| Path |
| --- |
| `kept.md` |
"#;
        assert_eq!(super::markdown_first_column(text, "## Files"), ["kept.md"]);
        assert_eq!(
            super::markdown_first_column(
                "## Files\n\n  | Path |\n  | ---: |\n  | `indented.md` |\n",
                "## Files"
            ),
            ["indented.md"]
        );
        assert_eq!(
            super::markdown_first_column_parts(
                "## Vars\n\n| Variable |\n| --- |\n| `FOO`, `BAR` |\n| `BAZ` |\n",
                "## Vars"
            ),
            ["FOO", "BAR", "BAZ"]
        );
        assert!(super::markdown_names(text, "kept.md"));
        assert!(!super::markdown_names(text, "gone.md"));
        assert!(super::markdown_names(
            "see `[[repositories]]` and `[network]`.",
            "repositories"
        ));
        assert!(super::markdown_names(
            "see `[[repositories]]` and `[network]`.",
            "network"
        ));
        assert!(!super::markdown_names(
            "see [[repositories]] here",
            "repositories"
        ));
    }

    #[test]
    fn markdown_heading_slugs_strip_punctuation_and_number_duplicates() {
        let text = r#"
# Configuration
## `raeva.toml` and `config.toml`
## `system` dependencies
## Exit codes
## Exit codes
"#;
        assert_eq!(
            super::markdown_heading_slugs(text),
            [
                "configuration",
                "raevatoml-and-configtoml",
                "system-dependencies",
                "exit-codes",
                "exit-codes-1",
            ]
        );
        assert_eq!(
            super::markdown_heading_slugs("## Foo  Bar\n## foo - bar\n"),
            ["foo-bar", "foo---bar"]
        );
    }

    #[test]
    fn rust_mod_declarations_skips_comments_strings_and_inline_modules() {
        let source = r#"
mod kept;
pub(crate) mod also;
    mod indented;
// mod gone;
/* mod block; */
let _ = "mod string;";
mod inline { mod nested; }
"#;
        assert_eq!(
            super::rust_mod_declarations(source),
            ["also", "indented", "kept"]
        );
    }

    #[test]
    fn rust_macro_calls_allow_whitespace_before_the_paren() {
        let source = "warn!(\n  x\n)\nmy_warn!(y)\nerror! (z)\n";
        let names: Vec<_> = super::rust_macro_calls(source, &["warn!", "error!"])
            .into_iter()
            .map(|(_, name)| name)
            .collect();
        assert_eq!(names, ["warn!", "error!"]);
    }

    #[test]
    fn uppercase_string_literals_skip_comments() {
        let source = r#"
            Diagnostic::plain(S::Failure, "STORE", message);
            // "GONE"
            /* "BLOCK" */
            let _ = '"';
        "#;
        let codes: Vec<_> = super::uppercase_string_literals(source)
            .into_iter()
            .map(|(_, code)| code)
            .collect();
        assert_eq!(codes, ["STORE"]);
    }
}
