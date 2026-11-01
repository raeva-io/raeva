//! The markup around a POM's elements, read as Maven 3.9's XML parser,
//! plexus-utils 3.6.0's `MXParser`, reads it.
//!
//! quick-xml reads the root element into the model. This module finds the
//! root element and refuses what `MXParser` refuses around it and in its
//! comments and processing instructions, which quick-xml lets through: text
//! or markup after the root element, an XML declaration anywhere but at the
//! start, a declaration `MXParser` cannot read, a second document type
//! declaration, and comments or processing instructions it does not accept.
//! It follows `MXParser`'s rules, not the XML specification's, where the two
//! differ: one character may come before the XML declaration, and the text
//! after the root element may end inside a document type declaration or
//! after a lone `<`. It does not model `MXParser`'s 8192-character read
//! buffer, which makes `MXParser` take `<?xml` for the declaration when the
//! buffer happens to start just before it.

use quick_xml::events::Event;

use crate::PomError;
use rv_maven_types::bounded;

/// The root element of a POM's text, from its start tag to the end of its
/// end tag, once the markup around it, and the comments and processing
/// instructions in it, read as `MXParser` reads them.
///
/// When quick-xml cannot read the root element to its end tag, the slice
/// runs to the end of the text, so that the model reader reports the
/// error in its own words.
pub(crate) fn root_element(xml: &str) -> Result<&str, PomError> {
    let mut scanner = Scanner { text: xml, pos: 0 };
    let start = match scanner.prolog() {
        Ok(start) => start,
        Err(Stop::Eof) => return Err(scanner.error(NO_ROOT)),
        Err(Stop::Bad(reason)) => return Err(scanner.error(reason)),
    };
    let Some(end) = root_end(xml, start)? else {
        return Ok(&xml[start..]);
    };
    scanner.pos = end;
    match scanner.epilog() {
        Ok(()) | Err(Stop::Eof) => Ok(&xml[start..end]),
        Err(Stop::Bad(reason)) => Err(scanner.error(reason)),
    }
}

const NO_ROOT: &str = "no root element";
const TEXT_BEFORE_ROOT: &str = "text before the root element";
const MARKUP_BEFORE_ROOT: &str = "markup before the root element that is not an element";
const SECOND_DOCTYPE: &str = "a second document type declaration";
const DOCTYPE_IN_ROOT: &str = "a document type declaration inside the root element";
const INVALID_DOCTYPE: &str = "an invalid document type declaration";
const BYTE_SWAPPED: &str = "a byte order mark in the wrong byte order";
const UTF16_BOM_AS_UTF8: &str = "a UTF-16 byte order mark read as UTF-8";
const TEXT_AFTER_ROOT: &str = "text after the root element";
const ELEMENT_AFTER_ROOT: &str = "an element after the root element";
const MARKUP_AFTER_ROOT: &str = "markup after the root element";
const RESERVED_TARGET: &str =
    "a processing instruction whose name starts with xml after the start of the document";
const UPPERCASE_DECLARATION: &str = "an XML declaration named in upper case";
const INVALID_DECLARATION: &str = "an invalid XML declaration";
const DECLARED_VERSION: &str = "an XML declaration of a version other than 1.0";
const PI_WITHOUT_TARGET: &str = "a processing instruction without a target";
const UNCLOSED_PI: &str = "a processing instruction that is not closed";
const INVALID_COMMENT: &str = "an invalid comment";
const DOUBLE_HYPHEN: &str = "a comment with -- inside it";
const COMMENT_CHARACTER: &str = "a character XML does not allow in a comment";
const UNCLOSED_COMMENT: &str = "a comment that is not closed";

/// Where quick-xml ends the root element that starts at `start`, after
/// checking the comments and processing instructions in it, or `None` when
/// it cannot read the element to its end for a reason other than its
/// markup.
fn root_end(xml: &str, start: usize) -> Result<Option<usize>, PomError> {
    let root = &xml[start..];
    let mut reader = quick_xml::Reader::from_str(root);
    // The elements open at this point, by name and start offset.
    let mut open: Vec<(&[u8], usize)> = Vec::new();
    loop {
        let before = start + position(&reader, root.len());
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(error) => {
                let at = start + usize::try_from(reader.error_position()).unwrap_or(0);
                return match malformed_reason(&error) {
                    Some(reason) => Err(malformed(xml, at.min(xml.len()), reason)),
                    None => Ok(None),
                };
            }
        };
        let after = start + position(&reader, root.len());
        // A comment or processing instruction is scanned within the bounds
        // quick-xml found for it, so one that MXParser would read past them
        // fails as not closed.
        let mut markup = Scanner {
            text: &xml[..after],
            pos: before,
        };
        let checked = match event {
            Event::Start(tag) => {
                let name = &root.as_bytes()[before - start..after - start];
                let name_len = tag.name().as_ref().len();
                open.push((name.get(1..1 + name_len).unwrap_or_default(), before));
                Ok(())
            }
            Event::End(_) => {
                open.pop();
                if open.is_empty() {
                    return Ok(Some(after));
                }
                Ok(())
            }
            Event::Empty(_) if open.is_empty() => return Ok(Some(after)),
            Event::Comment(_) => {
                markup.pos += "<!-".len();
                markup.comment()
            }
            Event::PI(_) | Event::Decl(_) => {
                markup.pos += "<?".len();
                markup.pi(false)
            }
            Event::DocType(_) => Err(Stop::Bad(DOCTYPE_IN_ROOT)),
            Event::Eof => {
                return match open.last() {
                    Some((name, at)) => Err(malformed(
                        xml,
                        *at,
                        format!(
                            "<{}> without an end tag",
                            bounded(&String::from_utf8_lossy(name))
                        ),
                    )),
                    None => Ok(None),
                };
            }
            _ => Ok(()),
        };
        match checked {
            Ok(()) => {}
            Err(Stop::Eof) => return Err(markup.error(UNCLOSED_COMMENT)),
            Err(Stop::Bad(reason)) => return Err(markup.error(reason)),
        }
    }
}

fn malformed_reason(error: &quick_xml::Error) -> Option<String> {
    use quick_xml::errors::{IllFormedError as I, SyntaxError as S};
    let reason = match error {
        quick_xml::Error::Syntax(syntax) => match syntax {
            S::InvalidBangMarkup => {
                "markup starting with <! that is not a comment, CDATA section or document \
                 type declaration"
            }
            S::UnclosedPI | S::UnclosedXmlDecl => UNCLOSED_PI,
            S::UnclosedComment => UNCLOSED_COMMENT,
            S::UnclosedDoctype => "a document type declaration that is not closed",
            S::UnclosedCData => "a CDATA section that is not closed",
            S::UnclosedTag => "a tag without its closing >",
            S::UnclosedSingleQuotedAttributeValue | S::UnclosedDoubleQuotedAttributeValue => {
                "an attribute value without its closing quote"
            }
        }
        .to_string(),
        quick_xml::Error::IllFormed(ill_formed) => match ill_formed {
            I::MissingEndTag(name) => format!("<{}> without an end tag", bounded(name)),
            I::UnmatchedEndTag(name) => {
                format!("the end tag </{}> without a start tag", bounded(name))
            }
            I::MismatchedEndTag { found, .. } => format!(
                "the end tag </{}>, which does not match the open element",
                bounded(found)
            ),
            I::DoubleHyphenInComment => DOUBLE_HYPHEN.to_string(),
            I::MissingDeclVersion(_) | I::UnknownVersion => INVALID_DECLARATION.to_string(),
            I::MissingDoctypeName => INVALID_DOCTYPE.to_string(),
            I::UnclosedReference => "an entity reference without its closing ;".to_string(),
        },
        _ => return None,
    };
    Some(reason)
}

fn malformed(xml: &str, at: usize, reason: String) -> PomError {
    let mut at = at.min(xml.len());
    while !xml.is_char_boundary(at) {
        at -= 1;
    }
    let before = &xml[..at];
    let line_start = before.rfind('\n').map_or(0, |index| index + 1);
    PomError::Malformed {
        reason,
        line: before.matches('\n').count() + 1,
        column: before[line_start..].chars().count() + 1,
    }
}

fn position(reader: &quick_xml::Reader<&[u8]>, len: usize) -> usize {
    usize::try_from(reader.buffer_position()).map_or(len, |pos| pos.min(len))
}

/// Why a scan stopped: the text ended, which `MXParser` accepts in some
/// places after the root element, or the markup is not well-formed.
enum Stop {
    Eof,
    Bad(&'static str),
}

impl From<&'static str> for Stop {
    fn from(reason: &'static str) -> Self {
        Stop::Bad(reason)
    }
}

/// A port of the `MXParser` methods that read the prolog and epilog,
/// processing instructions, the XML declaration, comments and document type
/// declarations, over the text `MXParser` gets from plexus-utils'
/// `XmlStreamReader`, that is the decoded POM without its byte order mark.
struct Scanner<'a> {
    text: &'a str,
    pos: usize,
}

impl Scanner<'_> {
    fn more(&mut self) -> Result<char, Stop> {
        let ch = self.text[self.pos..].chars().next().ok_or(Stop::Eof)?;
        self.pos += ch.len_utf8();
        Ok(ch)
    }

    fn error(&self, reason: &'static str) -> PomError {
        let line = self.text[..self.pos].matches('\n').count() + 1;
        PomError::NotWellFormed { reason, line }
    }

    /// `parseProlog`: up to the root element's `<`, which it returns.
    fn prolog(&mut self) -> Result<usize, Stop> {
        let mut ch = self.more()?;
        match ch {
            '\u{FFFE}' => return Err(BYTE_SWAPPED.into()),
            '\u{FEFF}' => ch = self.more()?,
            '\u{FFFD}' => {
                ch = self.more()?;
                if ch == '\u{FFFD}' {
                    return Err(UTF16_BOM_AS_UTF8.into());
                }
            }
            _ => {}
        }
        let mut seen_doctype = false;
        loop {
            if ch == '<' {
                let start = self.pos - 1;
                match self.more()? {
                    // MXParser reads `<?xml` as the declaration only when
                    // at most one character comes before it.
                    '?' => self.pi(self.text[..start].chars().nth(1).is_none())?,
                    '!' => match self.more()? {
                        'D' if seen_doctype => return Err(SECOND_DOCTYPE.into()),
                        'D' => {
                            seen_doctype = true;
                            self.doctype()?;
                        }
                        '-' => self.comment()?,
                        _ => return Err(MARKUP_BEFORE_ROOT.into()),
                    },
                    next if is_name_start(next) => return Ok(start),
                    _ => return Err(MARKUP_BEFORE_ROOT.into()),
                }
            } else if !is_s(ch) {
                return Err(TEXT_BEFORE_ROOT.into());
            }
            ch = self.more()?;
        }
    }

    /// `parseEpilog`: from the end of the root element to the end of the
    /// text. Where the text ends inside markup, `MXParser` accepts it,
    /// except inside a comment or a processing instruction.
    fn epilog(&mut self) -> Result<(), Stop> {
        loop {
            let ch = self.more()?;
            if ch == '<' {
                match self.more()? {
                    '?' => self.pi(false)?,
                    '!' => match self.more()? {
                        'D' => self.doctype()?,
                        '-' => self.comment()?,
                        _ => return Err(MARKUP_AFTER_ROOT.into()),
                    },
                    next if is_name_start(next) => return Err(ELEMENT_AFTER_ROOT.into()),
                    _ => return Err(MARKUP_AFTER_ROOT.into()),
                }
            } else if !is_s(ch) {
                return Err(TEXT_AFTER_ROOT.into());
            }
        }
    }

    /// `parsePI`, after `<?`. A target that starts with `xml` in any case
    /// and is followed by whitespace is the XML declaration where
    /// `declaration_allowed`, and an error elsewhere.
    fn pi(&mut self, declaration_allowed: bool) -> Result<(), Stop> {
        match self.pi_body(declaration_allowed) {
            Err(Stop::Eof) => Err(UNCLOSED_PI.into()),
            result => result,
        }
    }

    fn pi_body(&mut self, declaration_allowed: bool) -> Result<(), Stop> {
        let target_start = self.pos;
        let mut target_ended = false;
        let (mut seen_target, mut seen_inner_tag, mut seen_q) = (false, false, false);
        let mut ch = self.more()?;
        if is_s(ch) {
            return Err(PI_WITHOUT_TARGET.into());
        }
        loop {
            match ch {
                '?' if !seen_target => return Err(PI_WITHOUT_TARGET.into()),
                '?' => seen_q = true,
                '>' if seen_q => return Ok(()),
                '>' if !seen_target => return Err(PI_WITHOUT_TARGET.into()),
                '>' if !seen_inner_tag => return Err(UNCLOSED_PI.into()),
                '>' => seen_inner_tag = false,
                '<' => seen_inner_tag = true,
                _ => {
                    if !target_ended && is_s(ch) {
                        target_ended = true;
                        let mut name = self.text[target_start..].chars();
                        let (x, m, l) = (name.next(), name.next(), name.next());
                        let reserved = x.is_some_and(|c| c.eq_ignore_ascii_case(&'x'))
                            && m.is_some_and(|c| c.eq_ignore_ascii_case(&'m'))
                            && l.is_some_and(|c| c.eq_ignore_ascii_case(&'l'));
                        if reserved {
                            if !declaration_allowed {
                                return Err(RESERVED_TARGET.into());
                            }
                            // MXParser refuses only a name with no letter
                            // in lower case.
                            if x != Some('x') && m != Some('m') && l != Some('l') {
                                return Err(UPPERCASE_DECLARATION.into());
                            }
                            return self.declaration(ch);
                        }
                    }
                    seen_q = false;
                }
            }
            seen_target = true;
            ch = self.more()?;
        }
    }

    /// `parseXmlDecl`, from the whitespace after the target to `?>`.
    fn declaration(&mut self, ch: char) -> Result<(), Stop> {
        let mut ch = self.skip_s(ch)?;
        ch = self.require(ch, "version")?;
        let quote = self.quote(ch)?;
        let version_start = self.pos;
        ch = self.more()?;
        while ch != quote {
            if !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':' | '-')) {
                return Err(INVALID_DECLARATION.into());
            }
            ch = self.more()?;
        }
        if &self.text[version_start..self.pos - 1] != "1.0" {
            return Err(DECLARED_VERSION.into());
        }
        ch = self.more()?;
        let mut before = ch;
        ch = self.skip_s(ch)?;
        if !matches!(ch, 'e' | 's' | '?' | '>') {
            return Err(INVALID_DECLARATION.into());
        }
        if ch == 'e' {
            if !is_s(before) {
                return Err(INVALID_DECLARATION.into());
            }
            ch = self.more()?;
            ch = self.require(ch, "ncoding")?;
            let quote = self.quote(ch)?;
            ch = self.more()?;
            if !ch.is_ascii_alphabetic() {
                return Err(INVALID_DECLARATION.into());
            }
            ch = self.more()?;
            while ch != quote {
                if !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')) {
                    return Err(INVALID_DECLARATION.into());
                }
                ch = self.more()?;
            }
            ch = self.more()?;
            before = ch;
            ch = self.skip_s(ch)?;
        }
        if ch == 's' {
            if !is_s(before) {
                return Err(INVALID_DECLARATION.into());
            }
            ch = self.more()?;
            ch = self.require(ch, "tandalone")?;
            let quote = self.quote(ch)?;
            ch = self.more()?;
            ch = match ch {
                'y' => self.require(ch, "yes")?,
                'n' => self.require(ch, "no")?,
                _ => return Err(INVALID_DECLARATION.into()),
            };
            if ch != quote {
                return Err(INVALID_DECLARATION.into());
            }
            ch = self.more()?;
            ch = self.skip_s(ch)?;
        }
        if ch != '?' || self.more()? != '>' {
            return Err(INVALID_DECLARATION.into());
        }
        Ok(())
    }

    /// `S? '=' S?` and the opening quote of a declaration value, from the
    /// character after its name.
    fn quote(&mut self, ch: char) -> Result<char, Stop> {
        if self.skip_s(ch)? != '=' {
            return Err(INVALID_DECLARATION.into());
        }
        let ch = self.more()?;
        match self.skip_s(ch)? {
            quote @ ('\'' | '"') => Ok(quote),
            _ => Err(INVALID_DECLARATION.into()),
        }
    }

    /// `requireInput`: `ch` and the characters after it spell `word`; the
    /// character after it.
    fn require(&mut self, mut ch: char, word: &str) -> Result<char, Stop> {
        for expected in word.chars() {
            if ch != expected {
                return Err(INVALID_DECLARATION.into());
            }
            ch = self.more()?;
        }
        Ok(ch)
    }

    fn skip_s(&mut self, mut ch: char) -> Result<char, Stop> {
        while is_s(ch) {
            ch = self.more()?;
        }
        Ok(ch)
    }

    /// `parseComment`, after `<!-`.
    fn comment(&mut self) -> Result<(), Stop> {
        if self.more()? != '-' {
            return Err(INVALID_COMMENT.into());
        }
        let (mut dash, mut dash_dash) = (false, false);
        loop {
            let ch = match self.more() {
                Ok(ch) => ch,
                Err(Stop::Eof) => return Err(UNCLOSED_COMMENT.into()),
                Err(stop) => return Err(stop),
            };
            if dash_dash && ch != '>' {
                return Err(DOUBLE_HYPHEN.into());
            }
            match ch {
                '-' if dash => dash_dash = true,
                '-' => dash = true,
                '>' if dash_dash => return Ok(()),
                '>' => dash = false,
                _ if is_xml_char(ch) => dash = false,
                _ => return Err(COMMENT_CHARACTER.into()),
            }
        }
    }

    /// `parseDocdecl`, after `<!D`: `MXParser` skips to the `>` outside
    /// brackets and checks only the syntax of references.
    fn doctype(&mut self) -> Result<(), Stop> {
        for expected in "OCTYPE".chars() {
            if self.more()? != expected {
                return Err(INVALID_DOCTYPE.into());
            }
        }
        let mut brackets = 0i64;
        loop {
            match self.more()? {
                '[' => brackets += 1,
                ']' => brackets -= 1,
                '>' if brackets == 0 => return Ok(()),
                '&' => self.reference()?,
                _ => {}
            }
        }
    }

    /// `parseCharOrPredefinedEntityRef`, after `&`, as a document type
    /// declaration uses it: a character reference must name a character
    /// XML allows, and an entity reference must be a name.
    fn reference(&mut self) -> Result<(), Stop> {
        let mut ch = self.more()?;
        if ch == '#' {
            ch = self.more()?;
            let radix = if ch == 'x' { 16 } else { 10 };
            if radix == 16 {
                ch = self.more()?;
            }
            let digits = self.pos - ch.len_utf8();
            while ch != ';' {
                if !ch.is_digit(radix) {
                    return Err(INVALID_DOCTYPE.into());
                }
                ch = self.more()?;
            }
            let valid = u32::from_str_radix(&self.text[digits..self.pos - 1], radix)
                .ok()
                .and_then(char::from_u32)
                .is_some_and(is_xml_char);
            return if valid {
                Ok(())
            } else {
                Err(INVALID_DOCTYPE.into())
            };
        }
        if !is_name_start(ch) {
            return Err(INVALID_DOCTYPE.into());
        }
        loop {
            ch = self.more()?;
            if ch == ';' {
                return Ok(());
            }
            if !is_name_char(ch) {
                return Err(INVALID_DOCTYPE.into());
            }
        }
    }
}

/// `MXParser.isS`, which knows four whitespace characters.
fn is_s(ch: char) -> bool {
    matches!(ch, ' ' | '\n' | '\r' | '\t')
}

/// XML's `Char` production, as `MXParser.isValidCodePoint` checks it.
fn is_xml_char(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}')
        || ch > '\u{FFFF}'
}

/// `MXParser.isNameStartChar`. It tests UTF-16 code units, and both halves
/// of a surrogate pair fall in a range it accepts.
fn is_name_start(ch: char) -> bool {
    match u32::from(ch) {
        0..0x400 => matches!(
            ch,
            ':' | 'A'..='Z' | '_' | 'a'..='z'
                | '\u{C0}'..='\u{2FF}'
                | '\u{370}'..='\u{37D}'
                | '\u{37F}'..='\u{3FF}'
        ),
        code => {
            code <= 0x2027
                || (0x202A..=0x218F).contains(&code)
                || (0x2800..=0xFFEF).contains(&code)
                || code > 0xFFFF
        }
    }
}

/// `MXParser.isNameChar`.
fn is_name_char(ch: char) -> bool {
    is_name_start(ch)
        || matches!(
            ch,
            '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}'
        )
}

#[cfg(test)]
mod tests {
    use super::root_element;
    use crate::PomError;

    const ROOT: &str = "<project><a>1</a></project>";

    fn refused(xml: &str) -> &'static str {
        match root_element(xml) {
            Err(PomError::NotWellFormed { reason, .. }) => reason,
            other => panic!("{xml:?}: {other:?}"),
        }
    }

    #[test]
    fn the_root_element_is_cut_from_the_markup_around_it() {
        for (xml, root) in [
            (ROOT.to_string(), ROOT),
            (format!("<?xml version=\"1.0\"?>\n{ROOT}\n"), ROOT),
            (format!("\u{FEFF}{ROOT}"), ROOT),
            (
                format!("<!-- c --><?pi x?><!DOCTYPE project>\n{ROOT}"),
                ROOT,
            ),
            ("<project/>  <!-- c -->".to_string(), "<project/>"),
        ] {
            assert_eq!(root_element(&xml).expect(&xml), root, "{xml:?}");
        }
    }

    /// What MXParser accepts although the XML specification does not, or
    /// quick-xml would not.
    #[test]
    fn markup_mxparser_accepts_is_accepted() {
        for xml in [
            format!(" <?xml version=\"1.0\"?>{ROOT}"),
            format!("\n<?xml version='1.0' encoding='UTF-8' standalone='no' ?>{ROOT}"),
            format!("\u{FEFF}<?xml version=\"1.0\"?>{ROOT}"),
            format!("\u{FFFD}{ROOT}"),
            format!("<?xml-stylesheet?>{ROOT}"),
            format!("<?Xml version=\"1.0\"?>{ROOT}"),
            format!("<?xmlfoo version=\"1.0\"?>{ROOT}"),
            format!("{ROOT}<?pi x?><?xml?><!DOCTYPE p><!DOCTYPE q [<!ENTITY a \"&#38;&b;\">]>"),
            format!("{ROOT}\n<"),
            format!("{ROOT}<!"),
            format!("{ROOT}<!-"),
            format!("{ROOT}<!DOCTYPE project"),
            format!("{ROOT}<!DOCTYPE project [<!ENTITY a \"&#"),
            format!("{ROOT}<!---x-->"),
            "<project><?pi <a> ?><!-- a - b --></project>".to_string(),
            "<project><!--->x--></project>".to_string(),
        ] {
            root_element(&xml).expect(&xml);
        }
    }

    #[test]
    fn markup_mxparser_refuses_is_named() {
        for (xml, reason) in [
            (String::new(), super::NO_ROOT),
            ("<!-- c -->".to_string(), super::NO_ROOT),
            (format!("x{ROOT}"), super::TEXT_BEFORE_ROOT),
            (format!("&#32;{ROOT}"), super::TEXT_BEFORE_ROOT),
            (format!("<![CDATA[x]]>{ROOT}"), super::MARKUP_BEFORE_ROOT),
            (format!("</x>{ROOT}"), super::MARKUP_BEFORE_ROOT),
            (format!("\u{FEFF}\u{FEFF}{ROOT}"), super::TEXT_BEFORE_ROOT),
            (format!("\u{FFFE}{ROOT}"), super::BYTE_SWAPPED),
            (format!("\u{FFFD}\u{FFFD}{ROOT}"), super::UTF16_BOM_AS_UTF8),
            (
                format!("<!DOCTYPE p><!DOCTYPE p>{ROOT}"),
                super::SECOND_DOCTYPE,
            ),
            (format!("<!DOCTYPX p>{ROOT}"), super::INVALID_DOCTYPE),
            (
                format!("<!DOCTYPE p [<!ENTITY a \"AT&T\">]>{ROOT}"),
                super::INVALID_DOCTYPE,
            ),
            (
                format!("<!DOCTYPE p [<!ENTITY a \"&#0;\">]>{ROOT}"),
                super::INVALID_DOCTYPE,
            ),
            (
                format!("<!DOCTYPE p [<!ENTITY a \"&#x110000;\">]>{ROOT}"),
                super::INVALID_DOCTYPE,
            ),
            (
                format!("  <?xml version=\"1.0\"?>{ROOT}"),
                super::RESERVED_TARGET,
            ),
            (
                format!("\r\n<?xml version=\"1.0\"?>{ROOT}"),
                super::RESERVED_TARGET,
            ),
            (
                format!("<!-- c --><?xml version=\"1.0\"?>{ROOT}"),
                super::RESERVED_TARGET,
            ),
            (
                format!("<?xml version=\"1.0\"?><?xml version=\"1.0\"?>{ROOT}"),
                super::RESERVED_TARGET,
            ),
            (
                format!("\n\n<?xml-stylesheet href=\"a\"?>{ROOT}"),
                super::RESERVED_TARGET,
            ),
            (
                format!("{ROOT}<?xml version=\"1.0\"?>"),
                super::RESERVED_TARGET,
            ),
            (
                "<project><?XmL version=\"1.0\"?></project>".to_string(),
                super::RESERVED_TARGET,
            ),
            (
                format!("<?XML version=\"1.0\"?>{ROOT}"),
                super::UPPERCASE_DECLARATION,
            ),
            (
                format!("<?xml version=\"1.1\"?>{ROOT}"),
                super::DECLARED_VERSION,
            ),
            (
                format!("<?xml encoding=\"UTF-8\"?>{ROOT}"),
                super::INVALID_DECLARATION,
            ),
            (
                format!("<?xml-stylesheet href=\"a\"?>{ROOT}"),
                super::INVALID_DECLARATION,
            ),
            (
                format!("<?xml version=\"1.0\"encoding=\"UTF-8\"?>{ROOT}"),
                super::INVALID_DECLARATION,
            ),
            (
                format!("<?xml version=\"1.0\" encoding=\"8bit\"?>{ROOT}"),
                super::INVALID_DECLARATION,
            ),
            (
                format!("<?xml version=\"1.0\" standalone=\"maybe\"?>{ROOT}"),
                super::INVALID_DECLARATION,
            ),
            (
                format!("<?xml version=\"1.0\">{ROOT}"),
                super::INVALID_DECLARATION,
            ),
            (format!("{ROOT}x"), super::TEXT_AFTER_ROOT),
            (format!("{ROOT}\u{0}"), super::TEXT_AFTER_ROOT),
            (format!("{ROOT}\u{C}"), super::TEXT_AFTER_ROOT),
            (format!("{ROOT}&amp;"), super::TEXT_AFTER_ROOT),
            (format!("{ROOT}{ROOT}"), super::ELEMENT_AFTER_ROOT),
            (format!("{ROOT}<x/>"), super::ELEMENT_AFTER_ROOT),
            (format!("{ROOT}</project>"), super::MARKUP_AFTER_ROOT),
            (format!("{ROOT}<![CDATA[x]]>"), super::MARKUP_AFTER_ROOT),
            (format!("{ROOT}<? x?>"), super::PI_WITHOUT_TARGET),
            (format!("{ROOT}<??>"), super::PI_WITHOUT_TARGET),
            (format!("{ROOT}<?pi a > b?>"), super::UNCLOSED_PI),
            (format!("{ROOT}<?pi x"), super::UNCLOSED_PI),
            (format!("{ROOT}<!-- a -- b -->"), super::DOUBLE_HYPHEN),
            (format!("{ROOT}<!-- a --->"), super::DOUBLE_HYPHEN),
            (format!("{ROOT}<!-- \u{1} -->"), super::COMMENT_CHARACTER),
            (format!("{ROOT}<!-- c"), super::UNCLOSED_COMMENT),
            (format!("{ROOT}<!-x-->"), super::INVALID_COMMENT),
            (format!("<!-- a -- b -->{ROOT}"), super::DOUBLE_HYPHEN),
            (
                "<project><!-- a -- b --></project>".to_string(),
                super::DOUBLE_HYPHEN,
            ),
            (
                "<project><!-- \u{1} --></project>".to_string(),
                super::COMMENT_CHARACTER,
            ),
            (
                "<project><?xml-stylesheet href=\"a\"?></project>".to_string(),
                super::RESERVED_TARGET,
            ),
            (
                "<project><?pi a > b?></project>".to_string(),
                super::UNCLOSED_PI,
            ),
            (
                "<project><!DOCTYPE project></project>".to_string(),
                super::DOCTYPE_IN_ROOT,
            ),
        ] {
            assert_eq!(refused(&xml), reason, "{xml:?}");
        }
    }

    #[test]
    fn a_refusal_names_the_line() {
        let error = root_element(&format!("{ROOT}\n\n  text")).expect_err("text");
        assert_eq!(
            error.to_string(),
            "the POM is not well-formed XML: text after the root element at line 3"
        );
    }

    /// Columns count characters, an offset inside a character counts from
    /// its start, and offsets at either end of the text are positions too.
    #[test]
    fn malformed_positions_count_characters() {
        let position = |xml: &str, at: usize| match super::malformed(xml, at, String::new()) {
            PomError::Malformed { line, column, .. } => (line, column),
            other => panic!("{other:?}"),
        };
        assert_eq!(position("<a>", 0), (1, 1));
        assert_eq!(position("é\néé", 5), (2, 2));
        assert_eq!(position("é\néé", 4), (2, 1));
        assert_eq!(position("é\néé", 6), (2, 2));
        assert_eq!(position("é\néé", 99), (2, 3));
    }

    /// Markup quick-xml refuses inside the root element is named in plain
    /// words with its line and column.
    #[test]
    fn malformed_markup_names_its_line_and_column() {
        for (xml, reason, line, column) in [
            (
                "<project>\n  <a></b>\n</project>",
                "the end tag </b>, which does not match the open element",
                2,
                6,
            ),
            (
                "<project>\n<a>1</a>\n  <b\n",
                "a tag without its closing >",
                3,
                3,
            ),
            (
                "<project>\n  <parent>\n    <groupId>org",
                "<groupId> without an end tag",
                3,
                5,
            ),
            (
                "<project>\n  <名前></b>\n</project>",
                "the end tag </b>, which does not match the open element",
                2,
                7,
            ),
        ] {
            match root_element(xml) {
                Err(error @ PomError::Malformed { .. }) => {
                    assert!(error.is_malformed_xml());
                    assert_eq!(
                        error.to_string(),
                        format!(
                            "the POM is not well-formed XML: {reason} at line {line}, column \
                             {column}"
                        )
                    );
                }
                other => panic!("{xml:?}: {other:?}"),
            }
        }
    }
}
