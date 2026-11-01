//! Java's regular expressions for `<os><version>regex:`, translated for
//! `fancy-regex`.

use super::ActivationError;

/// Java's `String.matches`, with a backtracking engine for the lookaround
/// and backreferences Java accepts. A pattern Java cannot compile is a model
/// error in Maven; so is one raeva cannot compile or finish matching, rather
/// than a guess at the outcome.
pub(super) fn full_regex_match(
    pattern: &str,
    actual: Option<&str>,
) -> Result<bool, ActivationError> {
    let length = pattern.chars().count();
    if length > MAX_REGEX_LENGTH {
        return Err(ActivationError::RegexTooLong { length });
    }
    let build = |pattern: &str| {
        fancy_regex::RegexBuilder::new(pattern)
            .delegate_size_limit(1 << 20)
            .build()
            .map_err(|error| ActivationError::Regex(error.to_string()))
    };
    let quoted = expand_java_quotes(pattern);
    let pattern = translate_java_regex(&quoted, actual.is_none_or(str::is_ascii))?;
    if pattern.len() > MAX_TRANSLATED_REGEX_LENGTH {
        return Err(ActivationError::UnsupportedRegex {
            construct: format!(
                "a pattern over {MAX_TRANSLATED_REGEX_LENGTH} bytes once raeva spells out `$`, `.`, \
                 classes and literals"
            ),
            why: "since raeva bounds the size of a pattern",
        });
    }
    // The bare pattern first, so an error names its own positions.
    build(&pattern)?;
    let regex = build(&format!("\\A(?:{pattern})\\z"))?;
    match actual {
        Some(actual) => regex
            .is_match(actual)
            .map_err(|error| ActivationError::Regex(error.to_string())),
        None => Ok(false),
    }
}

/// Rewrite a Java pattern, after [`expand_java_quotes`], into one
/// `fancy-regex` matches the same way, or name the construct that would
/// match differently.
///
/// The pattern is parsed against a subset of Java's syntax that is enough
/// for a version pattern, and every construct outside it is refused rather
/// than handed to an engine that reads it otherwise:
///
/// - Java's `\d`, `\s` and `\w` are ASCII, its `.` stops at `\r`, U+0085,
///   U+2028 and U+2029 as well as `\n`, and its `$` also matches before a
///   final line terminator; those are spelled out.
/// - Every literal but an ASCII letter is written as a hex escape, so no
///   character means more to `fancy-regex` than it did to Java.
/// - A quantifier must follow a character, class, `.` or group, and a count
///   must be complete. Java's loops differ where a group can match nothing
///   or is possessive, so a count of two or more on a group that can match
///   nothing, a possessive group, and a backreference into a repeated group
///   are refused, as is an unbounded repeat in a lookbehind, whose length
///   Java bounds its own way, and a repeat there of a group with
///   alternatives or a ranged repeat inside, whose length Java does not
///   work out. A backreference into a lookbehind is refused too, since Java
///   keeps the capture of the shortest match there. The counts of a pattern
///   may make at most [`MAX_REGEX_COPIES`] copies, nested ones multiplied. In a class, a `-`
///   makes a range as Java reads it, never a set operation.
/// - The inline flags are `i` and `x`, and an unscoped one only outside
///   every group, since `fancy-regex` keeps it past the group's end.
/// - `(?i)`, `\b`, `\B` and lookbehinds agree only on ASCII, so they are
///   refused when `ascii_input` is false, and `(?i)` also when the pattern
///   names a character that is not ASCII.
/// - After `(?x)`, unescaped whitespace and `#` are refused: Java skips only
///   ASCII whitespace, `fancy-regex` all of it.
fn translate_java_regex(pattern: &str, ascii_input: bool) -> Result<String, ActivationError> {
    let mut translator = JavaRegex {
        chars: pattern.chars().collect(),
        at: 0,
        out: String::with_capacity(pattern.len() * 2),
        ascii_input,
        groups: Vec::new(),
        group_starts: Vec::new(),
        last_group: None,
        sequences: vec![Alternatives::default()],
        repeated: Vec::new(),
        unrepeatable: None,
        opened: 0,
        closed: Vec::new(),
        names: Vec::new(),
        behind: Vec::new(),
        copies: 0,
        quantifiable: false,
        case_insensitive: false,
        comments: false,
        non_ascii: false,
    };
    translator.pattern()?;
    Ok(translator.out)
}

const REGEX_DOT: &str = r"[^\n\r\x{85}\x{2028}\x{2029}]";
// Java's `$` without MULTILINE: the end, or before one line terminator that
// ends the text, but never between `\r` and `\n`.
const REGEX_DOLLAR: &str = r"(?:\z|(?=[\r\x{85}\x{2028}\x{2029}]\z)|(?<!\r)(?=\n\z)|(?=\r\n\z))";
const REGEX_DIGIT: &str = "0-9";
const REGEX_SPACE: &str = r"\t\n\x0B\x0C\r\x20";
const REGEX_WORD: &str = "a-zA-Z0-9_";
const MAX_REGEX_COUNT: u32 = 1000;
/// The longest `regex:` pattern raeva compiles, in characters. Compile memory
/// grows with length: a lookahead alternation of 400,000 characters peaks
/// near 300 MB, while every pattern shape measured at this length stays
/// under 15 MB or is refused by the other limits.
pub(super) const MAX_REGEX_LENGTH: usize = 4096;
/// The longest translation of a pattern raeva compiles, in bytes. A `$` is
/// written out as 63 bytes of lookarounds, so 4096 of them peak near 160 MB;
/// at this length one compiles in about 16 MB.
const MAX_TRANSLATED_REGEX_LENGTH: usize = 16 * 1024;
const MAX_REGEX_COPIES: u64 = 100_000;
const MAX_REGEX_GROUP_DEPTH: usize = 64;

enum RegexGroup {
    Capturing { number: usize, name: Option<String> },
    Lookaround { behind: bool },
    Other,
}

/// Whether the alternatives of a pattern or group can match no text: one of
/// the finished ones can, or every item of the current one can. Also
/// whether Java sees no single length for them: they are two or more, or
/// an item is repeated by a range rather than an exact count. And how many
/// copies of one item the nested counts inside them make at most.
struct Alternatives {
    any: bool,
    before_last: bool,
    last: bool,
    variable: bool,
    copies: u64,
}

impl Default for Alternatives {
    fn default() -> Self {
        Self {
            any: false,
            before_last: true,
            last: true,
            variable: false,
            copies: 1,
        }
    }
}

impl Alternatives {
    fn item(&mut self, nullable: bool) {
        self.before_last &= self.last;
        self.last = nullable;
    }

    fn alternative(&mut self) {
        self.any |= self.nullable();
        *self = Self {
            any: self.any,
            variable: true,
            copies: self.copies,
            ..Self::default()
        };
    }

    fn nullable(&self) -> bool {
        self.any || self.before_last && self.last
    }
}

/// A group that closed: where it ended in `out`, its captures, whether it
/// can match no text, whether Java sees no single length for it, and the
/// copies its nested counts make.
struct ClosedGroup {
    end: usize,
    captures: std::ops::RangeInclusive<usize>,
    nullable: bool,
    variable: bool,
    copies: u64,
}

enum ClassItem {
    Char(char),
    Set(&'static str),
}

struct JavaRegex {
    chars: Vec<char>,
    at: usize,
    out: String,
    ascii_input: bool,
    groups: Vec<RegexGroup>,
    group_starts: Vec<usize>,
    last_group: Option<ClosedGroup>,
    sequences: Vec<Alternatives>,
    /// Captures inside a group a quantifier repeats.
    repeated: Vec<usize>,
    /// Where the last backreference, anchor or lookaround ended in `out`,
    /// and what it was.
    unrepeatable: Option<(usize, &'static str)>,
    opened: usize,
    closed: Vec<usize>,
    names: Vec<(String, usize, bool)>,
    /// Captures inside a lookbehind.
    behind: Vec<usize>,
    copies: u64,
    quantifiable: bool,
    case_insensitive: bool,
    comments: bool,
    non_ascii: bool,
}

fn unsupported(construct: &str, why: &'static str) -> ActivationError {
    ActivationError::UnsupportedRegex {
        construct: construct.to_string(),
        why,
    }
}

impl JavaRegex {
    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.at + offset).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.at += 1;
        Some(c)
    }

    fn check_comments(&self, c: char) -> Result<(), ActivationError> {
        if self.comments && (c.is_whitespace() || c == '#') {
            return Err(unsupported(
                "whitespace or # after (?x)",
                "since Java and raeva skip different whitespace there; escape it or quote it",
            ));
        }
        Ok(())
    }

    fn literal(&mut self, c: char) {
        self.non_ascii |= !c.is_ascii();
        // A digit stays escaped: after a backreference it would extend it.
        if c.is_ascii_alphabetic() {
            self.out.push(c);
        } else {
            self.out.push_str(&format!("\\x{{{:X}}}", u32::from(c)));
        }
    }

    fn in_lookbehind(&self) -> bool {
        self.groups
            .iter()
            .any(|group| matches!(group, RegexGroup::Lookaround { behind: true }))
    }

    fn pattern(&mut self) -> Result<(), ActivationError> {
        while let Some(c) = self.next() {
            self.check_comments(c)?;
            match c {
                '\\' => self.escape()?,
                '[' => {
                    self.class()?;
                    self.atom(false);
                }
                '.' => {
                    self.out.push_str(REGEX_DOT);
                    self.atom(false);
                }
                '^' => {
                    self.out.push('^');
                    self.unrepeatable("an anchor");
                }
                '$' => {
                    self.out.push_str(REGEX_DOLLAR);
                    self.unrepeatable("an anchor");
                }
                '|' => {
                    self.out.push('|');
                    self.quantifiable = false;
                    if let Some(sequence) = self.sequences.last_mut() {
                        sequence.alternative();
                    }
                }
                '*' | '+' | '?' => self.quantifier(&c.to_string())?,
                '{' => {
                    let count = self.count()?;
                    self.quantifier(&count)?;
                }
                '(' => self.open_group()?,
                ')' => self.close_group()?,
                c => {
                    self.literal(c);
                    self.atom(false);
                }
            }
        }
        if !self.groups.is_empty() {
            return Err(unsupported(
                "a group that is never closed",
                "since Java refuses it",
            ));
        }
        if self.case_insensitive && self.non_ascii {
            return Err(unsupported(
                "(?i) with a character that is not ASCII",
                "since Java folds only ASCII letters unless told otherwise",
            ));
        }
        Ok(())
    }

    /// Record an item of the current alternative, which matches no text
    /// when `nullable`. Only an item that matches text can be repeated.
    fn atom(&mut self, nullable: bool) {
        if let Some(sequence) = self.sequences.last_mut() {
            sequence.item(nullable);
        }
        self.quantifiable = !nullable;
    }

    fn unrepeatable(&mut self, what: &'static str) {
        self.unrepeatable = Some((self.out.len(), what));
        self.atom(true);
    }

    fn quantifier(&mut self, quantifier: &str) -> Result<(), ActivationError> {
        if !self.quantifiable {
            let construct = match self.unrepeatable {
                Some((end, what)) if end == self.out.len() => format!("{quantifier} after {what}"),
                _ => format!("{quantifier} with nothing it can repeat before it"),
            };
            return Err(unsupported(
                &construct,
                "since Java and raeva read it differently",
            ));
        }
        let unbounded = matches!(quantifier, "*" | "+") || quantifier.ends_with(",}");
        if unbounded && self.in_lookbehind() {
            return Err(unsupported(
                &format!("{quantifier} in a lookbehind"),
                "since Java bounds the length of a lookbehind its own way; give it a maximum",
            ));
        }
        let group = self
            .last_group
            .take()
            .filter(|group| group.end == self.out.len());
        let variable_group = group.as_ref().is_some_and(|group| group.variable);
        if variable_group && quantifier != "?" && self.in_lookbehind() {
            // Java repeats such a group with a loop whose length it does
            // not work out, and refuses the lookbehind.
            return Err(unsupported(
                &format!("{quantifier} on a group of no single length in a lookbehind"),
                "since Java finds no maximum length for the lookbehind",
            ));
        }
        let modifier = self.peek(0).filter(|c| matches!(c, '?' | '+'));
        if modifier == Some('+') && group.is_some() {
            return Err(unsupported(
                &format!("{quantifier}+ on a group"),
                "since Java and raeva repeat a group that can match nothing differently",
            ));
        }
        let minimum = match quantifier {
            "*" | "?" => 0,
            "+" => 1,
            count => count[1..]
                .split([',', '}'])
                .next()
                .and_then(|low| low.parse::<u32>().ok())
                .unwrap_or(0),
        };
        if minimum >= 2 && group.as_ref().is_some_and(|group| group.nullable) {
            // Java ends a loop at the first iteration that matches nothing,
            // even before the minimum, where raeva tries further iterations.
            return Err(unsupported(
                &format!("{quantifier} on a group that can match nothing"),
                "since Java stops repeating it at the first empty match",
            ));
        }
        let exact = quantifier.starts_with('{')
            && quantifier[1..quantifier.len() - 1]
                .split_once(',')
                .is_none_or(|(low, high)| low == high);
        let most = match quantifier {
            "*" | "?" | "+" => 1,
            count => count[1..count.len() - 1]
                .split(',')
                .filter_map(|bound| bound.parse::<u64>().ok())
                .max()
                .unwrap_or(1),
        };
        let copies = group
            .as_ref()
            .map_or(1, |group| group.copies)
            .saturating_mul(most.max(1));
        // Each delegate regex has its own size limit, so the copies of the
        // whole pattern are bounded too.
        if quantifier.starts_with('{') {
            self.copies = self.copies.saturating_add(copies);
        }
        if self.copies > MAX_REGEX_COPIES {
            return Err(unsupported(
                &format!("counts that make more than {MAX_REGEX_COPIES} copies"),
                "since raeva bounds the size of a pattern",
            ));
        }
        if let Some(sequence) = self.sequences.last_mut() {
            if minimum == 0 {
                sequence.last = true;
            }
            sequence.variable |= variable_group || !exact;
            sequence.copies = sequence.copies.max(copies);
        }
        self.out.push_str(quantifier);
        if let Some(modifier) = modifier {
            self.at += 1;
            self.out.push(modifier);
        }
        if let Some(group) = group {
            self.repeated.extend(group.captures);
        }
        self.quantifiable = false;
        Ok(())
    }

    fn count(&mut self) -> Result<String, ActivationError> {
        let incomplete = || {
            unsupported(
                "a { that does not start a complete count",
                "since Java refuses it where raeva may read it literally",
            )
        };
        let number = |translator: &mut Self| -> Result<Option<u32>, ActivationError> {
            let start = translator.at;
            while translator.peek(0).is_some_and(|c| c.is_ascii_digit()) {
                translator.at += 1;
            }
            if translator.at == start {
                return Ok(None);
            }
            let digits: String = translator.chars[start..translator.at].iter().collect();
            match digits.parse::<u32>() {
                Ok(value) if value <= MAX_REGEX_COUNT => Ok(Some(value)),
                _ => Err(unsupported(
                    &format!("a count over {MAX_REGEX_COUNT}"),
                    "since raeva bounds the size of a pattern",
                )),
            }
        };
        let low = number(self)?.ok_or_else(incomplete)?;
        let count = match self.next() {
            Some('}') => format!("{{{low}}}"),
            Some(',') => match number(self)? {
                None if self.next() == Some('}') => format!("{{{low},}}"),
                Some(high) if self.next() == Some('}') => {
                    if high < low {
                        return Err(unsupported(
                            "a count whose maximum is below its minimum",
                            "since Java refuses it",
                        ));
                    }
                    format!("{{{low},{high}}}")
                }
                _ => return Err(incomplete()),
            },
            _ => return Err(incomplete()),
        };
        Ok(count)
    }

    fn escape(&mut self) -> Result<(), ActivationError> {
        let Some(escaped) = self.next() else {
            return Err(unsupported(
                "a \\ that ends the pattern",
                "since Java refuses it",
            ));
        };
        match escaped {
            'd' | 's' | 'w' | 'D' | 'S' | 'W' => {
                let set = shorthand_set(escaped.to_ascii_lowercase());
                let negated = if escaped.is_ascii_uppercase() {
                    "^"
                } else {
                    ""
                };
                self.out.push_str(&format!("[{negated}{set}]"));
                self.atom(false);
            }
            'b' | 'B' => {
                if !self.ascii_input {
                    return Err(unsupported(
                        &format!("\\{escaped} on text that is not ASCII"),
                        "since Java and raeva disagree there on what a word character is",
                    ));
                }
                self.out.push('\\');
                self.out.push(escaped);
                self.unrepeatable("an anchor");
            }
            'A' | 'z' => {
                self.out.push('\\');
                self.out.push(escaped);
                self.unrepeatable("an anchor");
            }
            'k' => {
                let name = self.group_name("\\k")?;
                let Some(number) = self
                    .names
                    .iter()
                    .find(|(known, _, closed)| *known == name && *closed)
                    .map(|(_, number, _)| *number)
                else {
                    return Err(unsupported(
                        "\\k<name> before its group closes",
                        "since Java and raeva read it differently",
                    ));
                };
                self.backreference("\\k<name>", &format!("\\k<{name}>"), number)?;
            }
            '1'..='9' => {
                if self.peek(0).is_some_and(|c| c.is_ascii_digit()) {
                    return Err(unsupported(
                        &format!("a backreference \\{escaped} followed by a digit"),
                        "since Java decides by the number of groups whether the digit belongs \
                         to it; write the digit as [0-9] or quote it",
                    ));
                }
                let number = escaped as usize - '0' as usize;
                if !self.closed.contains(&number) {
                    return Err(unsupported(
                        &format!("\\{escaped} before group {number} closes"),
                        "since Java and raeva read it differently",
                    ));
                }
                let reference = format!("\\{escaped}");
                self.backreference(&reference, &reference, number)?;
            }
            escaped => {
                let c = self.escaped_char(escaped)?;
                self.literal(c);
                self.atom(false);
            }
        }
        Ok(())
    }

    fn backreference(
        &mut self,
        reference: &str,
        written: &str,
        number: usize,
    ) -> Result<(), ActivationError> {
        if self.in_lookbehind() {
            return Err(unsupported(
                "a backreference in a lookbehind",
                "since Java refuses it",
            ));
        }
        if self.behind.contains(&number) {
            return Err(unsupported(
                &format!("{reference} to a group inside a lookbehind"),
                "since Java and raeva may remember different text for it",
            ));
        }
        if self.repeated.contains(&number) {
            return Err(unsupported(
                &format!("{reference} to a group inside a repeated group"),
                "since Java and raeva may remember different text for it",
            ));
        }
        self.out.push_str(written);
        self.unrepeatable("a backreference");
        Ok(())
    }

    /// The character an escape other than a class, anchor or backreference
    /// stands for.
    fn escaped_char(&mut self, escaped: char) -> Result<char, ActivationError> {
        let hex = |digits: &str| {
            u32::from_str_radix(digits, 16)
                .ok()
                .filter(|_| !digits.is_empty())
                .and_then(char::from_u32)
        };
        let c = match escaped {
            't' => Some('\t'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            'f' => Some('\u{C}'),
            'a' => Some('\u{7}'),
            'e' => Some('\u{1B}'),
            'x' if self.peek(0) == Some('{') => {
                self.at += 1;
                let start = self.at;
                while self.peek(0).is_some_and(|c| c != '}') {
                    self.at += 1;
                }
                let digits: String = self.chars[start..self.at].iter().collect();
                if self.next() == Some('}') && digits.len() <= 8 {
                    hex(&digits)
                } else {
                    None
                }
            }
            'x' | 'u' => {
                let width = if escaped == 'x' { 2 } else { 4 };
                let digits: String = self.chars[self.at..]
                    .iter()
                    .take(width)
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                self.at += digits.len();
                if digits.len() == width {
                    hex(&digits)
                } else {
                    None
                }
            }
            escaped if escaped.is_ascii_alphanumeric() => {
                return Err(unsupported(
                    &format!("\\{escaped}"),
                    "since Java and raeva read it differently or raeva does not read it",
                ));
            }
            escaped => Some(escaped),
        };
        c.ok_or_else(|| {
            unsupported(
                &format!("a \\{escaped} escape that is not one whole character"),
                "since Java and raeva read it differently",
            )
        })
    }

    fn class(&mut self) -> Result<(), ActivationError> {
        self.out.push('[');
        if self.peek(0) == Some('^') {
            self.at += 1;
            self.out.push('^');
        }
        if self.peek(0) == Some(']') {
            return Err(unsupported(
                "] first in a class",
                "since Java and raeva read it differently",
            ));
        }
        loop {
            let Some(c) = self.peek(0) else {
                return Err(unsupported(
                    "a class that is never closed",
                    "since Java refuses it",
                ));
            };
            self.check_comments(c)?;
            match c {
                ']' => {
                    self.at += 1;
                    self.out.push(']');
                    return Ok(());
                }
                '[' => {
                    return Err(unsupported(
                        "a class nested in a class",
                        "since Java and raeva combine nested classes differently",
                    ));
                }
                '&' if self.peek(1) == Some('&') => {
                    return Err(unsupported(
                        "&& in a class",
                        "since Java and raeva intersect classes differently",
                    ));
                }
                _ => {
                    // Java's rule: a character followed by `-` and then
                    // anything but `]` or `[` starts a range; any other `-`
                    // is itself a character.
                    let item = self.class_item()?;
                    let range = self.peek(0) == Some('-')
                        && self.peek(1).is_some_and(|next| next != ']' && next != '[');
                    match (item, range) {
                        (ClassItem::Char(low), true) => {
                            self.at += 1;
                            let ClassItem::Char(high) = self.class_item()? else {
                                return Err(unsupported(
                                    "a range that ends in a class such as \\w",
                                    "since Java refuses it",
                                ));
                            };
                            if high < low {
                                return Err(unsupported(
                                    "a range whose end is before its start",
                                    "since Java refuses it",
                                ));
                            }
                            self.literal(low);
                            self.out.push('-');
                            self.literal(high);
                        }
                        (ClassItem::Char(c), false) => self.literal(c),
                        (ClassItem::Set(set), _) => self.out.push_str(set),
                    }
                }
            }
        }
    }

    fn class_item(&mut self) -> Result<ClassItem, ActivationError> {
        let Some(c) = self.next() else {
            return Err(unsupported(
                "a class that is never closed",
                "since Java refuses it",
            ));
        };
        self.check_comments(c)?;
        if c == '[' {
            return Err(unsupported(
                "a class nested in a class",
                "since Java and raeva combine nested classes differently",
            ));
        }
        if c != '\\' {
            return Ok(ClassItem::Char(c));
        }
        let Some(escaped) = self.next() else {
            return Err(unsupported(
                "a \\ that ends the pattern",
                "since Java refuses it",
            ));
        };
        match escaped {
            'd' | 's' | 'w' => Ok(ClassItem::Set(shorthand_set(escaped))),
            'D' | 'S' | 'W' => Err(unsupported(
                &format!("\\{escaped} inside a character class"),
                "since raeva spells it out as a class of its own",
            )),
            'b' | 'B' | 'A' | 'z' | 'k' | '0'..='9' => Err(unsupported(
                &format!("\\{escaped} inside a character class"),
                "since Java refuses it where raeva may read it",
            )),
            escaped => self.escaped_char(escaped).map(ClassItem::Char),
        }
    }

    fn group_name(&mut self, construct: &str) -> Result<String, ActivationError> {
        let invalid = || {
            unsupported(
                &format!("{construct} without a <name> of a letter and then letters or digits"),
                "since Java refuses it where raeva may read it",
            )
        };
        if self.next() != Some('<') {
            return Err(invalid());
        }
        let start = self.at;
        while self.peek(0).is_some_and(|c| c.is_ascii_alphanumeric()) {
            self.at += 1;
        }
        let name: String = self.chars[start..self.at].iter().collect();
        if !name.starts_with(|c: char| c.is_ascii_alphabetic()) || self.next() != Some('>') {
            return Err(invalid());
        }
        Ok(name)
    }

    fn open_group(&mut self) -> Result<(), ActivationError> {
        if self.groups.len() >= MAX_REGEX_GROUP_DEPTH {
            return Err(unsupported(
                &format!("groups nested more than {MAX_REGEX_GROUP_DEPTH} deep"),
                "since raeva bounds the size of a pattern",
            ));
        }
        self.quantifiable = false;
        if self.peek(0) != Some('?') {
            self.opened += 1;
            self.push_group(RegexGroup::Capturing {
                number: self.opened,
                name: None,
            });
            self.out.push('(');
            return Ok(());
        }
        self.at += 1;
        let group = match (self.peek(0), self.peek(1)) {
            (Some(':'), _) => {
                self.at += 1;
                self.out.push_str("(?:");
                RegexGroup::Other
            }
            (Some('>'), _) => {
                self.at += 1;
                self.out.push_str("(?>");
                RegexGroup::Other
            }
            (Some(kind @ ('=' | '!')), _) => {
                self.at += 1;
                self.out.push_str(&format!("(?{kind}"));
                RegexGroup::Lookaround { behind: false }
            }
            (Some('<'), Some(kind @ ('=' | '!'))) => {
                if !self.ascii_input {
                    return Err(unsupported(
                        "a lookbehind on text that is not ASCII",
                        "since Java steps back through text in UTF-16 units and raeva in characters",
                    ));
                }
                self.at += 2;
                self.out.push_str(&format!("(?<{kind}"));
                RegexGroup::Lookaround { behind: true }
            }
            (Some('<'), _) => {
                let name = self.group_name("a named group")?;
                if self.names.iter().any(|(known, _, _)| *known == name) {
                    return Err(unsupported(
                        "a second group with the same name",
                        "since Java refuses it",
                    ));
                }
                self.opened += 1;
                self.names.push((name.clone(), self.opened, false));
                self.out.push_str(&format!("(?<{name}>"));
                RegexGroup::Capturing {
                    number: self.opened,
                    name: Some(name),
                }
            }
            _ => return self.flags(),
        };
        self.push_group(group);
        Ok(())
    }

    fn push_group(&mut self, group: RegexGroup) {
        let first = match &group {
            RegexGroup::Capturing { number, .. } => {
                if self.in_lookbehind() {
                    self.behind.push(*number);
                }
                *number
            }
            _ => self.opened + 1,
        };
        self.groups.push(group);
        self.group_starts.push(first);
        self.sequences.push(Alternatives::default());
    }

    /// Inline flags, after `(?`: `(?flags)` or `(?flags:`.
    fn flags(&mut self) -> Result<(), ActivationError> {
        let start = self.at;
        while self
            .peek(0)
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '-')
        {
            self.at += 1;
        }
        let flags: String = self.chars[start..self.at].iter().collect();
        let scoped = match self.next() {
            Some(':') if !flags.is_empty() => true,
            Some(')') if !flags.is_empty() => false,
            _ => {
                return Err(unsupported(
                    "a group that opens with (? in a form Java does not name",
                    "since Java refuses it where raeva may read it",
                ));
            }
        };
        if !scoped && !self.groups.is_empty() {
            return Err(unsupported(
                &format!("(?{flags}) inside a group"),
                "since Java ends it with the group and raeva does not",
            ));
        }
        for flag in flags.chars().filter(|flag| *flag != '-') {
            match flag {
                'x' => self.comments = true,
                'i' if self.ascii_input => self.case_insensitive = true,
                'i' => {
                    return Err(unsupported(
                        "(?i) on text that is not ASCII",
                        "since Java folds only ASCII letters unless told otherwise",
                    ));
                }
                flag => {
                    return Err(unsupported(
                        &format!("the inline flag {flag}"),
                        "since Java and raeva read it differently or raeva does not read it",
                    ));
                }
            }
        }
        if scoped {
            self.out.push_str(&format!("(?{flags}:"));
            self.push_group(RegexGroup::Other);
        } else {
            self.out.push_str(&format!("(?{flags})"));
        }
        Ok(())
    }

    fn close_group(&mut self) -> Result<(), ActivationError> {
        let Some(group) = self.groups.pop() else {
            return Err(unsupported(
                "a ) that closes no group",
                "since Java refuses it",
            ));
        };
        let first = self.group_starts.pop().unwrap_or(self.opened + 1);
        let (nullable, variable, copies) =
            self.sequences.pop().map_or((true, false, 1), |sequence| {
                (sequence.nullable(), sequence.variable, sequence.copies)
            });
        if let Some(sequence) = self.sequences.last_mut() {
            sequence.copies = sequence.copies.max(copies);
        }
        self.out.push(')');
        match group {
            RegexGroup::Capturing { number, name } => {
                self.closed.push(number);
                if let Some(name) = name
                    && let Some(entry) = self.names.iter_mut().find(|(known, _, _)| *known == name)
                {
                    entry.2 = true;
                }
            }
            RegexGroup::Lookaround { .. } => {
                self.unrepeatable("a lookaround");
                return Ok(());
            }
            RegexGroup::Other => {}
        }
        if let Some(sequence) = self.sequences.last_mut() {
            sequence.item(nullable);
            sequence.variable |= variable;
        }
        // A group that can match nothing may still be repeated.
        self.quantifiable = true;
        self.last_group = Some(ClosedGroup {
            end: self.out.len(),
            captures: first..=self.opened,
            nullable,
            variable,
            copies,
        });
        Ok(())
    }
}

fn shorthand_set(class: char) -> &'static str {
    match class {
        'd' => REGEX_DIGIT,
        's' => REGEX_SPACE,
        _ => REGEX_WORD,
    }
}

/// Java's `\\Q...\\E` quoting, which `fancy-regex` lacks, rewritten as
/// escaped literals. A quote runs to `\\E` or the end of the pattern, and an
/// escaped backslash outside one does not start a quote.
fn expand_java_quotes(pattern: &str) -> std::borrow::Cow<'_, str> {
    if !pattern.contains("\\Q") {
        return std::borrow::Cow::Borrowed(pattern);
    }
    let mut out = String::with_capacity(pattern.len() * 2);
    let mut rest = pattern;
    while let Some(index) = rest.find('\\') {
        out.push_str(&rest[..index]);
        let after = &rest[index + 1..];
        match after.chars().next() {
            Some('Q') => {
                let quoted = &after[1..];
                let (literal, tail) = match quoted.find("\\E") {
                    Some(end) => (&quoted[..end], &quoted[end + 2..]),
                    None => (quoted, ""),
                };
                // A hex escape stays literal inside a character class, under
                // `(?x)` and after a backreference, where an escaped
                // punctuation mark, a space or a digit may not.
                for c in literal.chars() {
                    out.push_str(&format!("\\x{{{:X}}}", u32::from(c)));
                }
                rest = tail;
            }
            Some(escaped) => {
                out.push('\\');
                out.push(escaped);
                rest = &after[escaped.len_utf8()..];
            }
            None => {
                out.push('\\');
                rest = "";
            }
        }
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}
