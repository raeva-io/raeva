//! Reading POM bytes the way Maven 3.9's model reader does: the character
//! encoding plexus-utils' `XmlStreamReader` picks, and the entities its
//! `MXParser` knows.

use std::borrow::Cow;

use quick_xml::de::EntityResolver;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::BytesText;

use crate::PomError;

/// Decode a POM's bytes to text as Maven reads them.
///
/// Without a byte order mark, a document that starts with `<?xml` uses the
/// `encoding` its declaration names, read in UTF-16 when the document
/// starts that way, where `UTF-16` means the byte order it starts in.
/// Anything else, including UTF-16 text that declares no encoding, is
/// UTF-8. A byte order mark decides the encoding of the text after it
/// unless the declaration names another one, which then wins, as in
/// plexus-utils' lenient mode. As with Java's decoders, a byte sequence the
/// encoding does not allow becomes U+FFFD instead of an error.
///
/// # Errors
///
/// [`PomError::UnsupportedEncoding`] when the declaration names an encoding
/// other than UTF-8, UTF-16, ISO-8859-1, US-ASCII or windows-1252, which
/// Maven might read but raeva does not, [`PomError::Ebcdic`] when the document
/// starts with `<?xm` in EBCDIC and declares such an encoding, which Maven
/// reads it in, [`PomError::UnknownEncoding`] when it names
/// `default`, which Java does not read, [`PomError::EncodingMismatch`] when a
/// UTF-16 byte order mark comes before text in another encoding, and
/// [`PomError::UnterminatedDeclaration`] when a document that starts with
/// `<?xm` has no `>` in its first 4096 bytes.
pub fn decode_pom(bytes: &[u8]) -> Result<Cow<'_, str>, PomError> {
    let (bom, rest) = if let Some(rest) = bytes.strip_prefix(b"\xEF\xBB\xBF") {
        (Some(Charset::Utf8), rest)
    } else if let Some(rest) = bytes.strip_prefix(b"\xFE\xFF") {
        (Some(Charset::Utf16Be), rest)
    } else if let Some(rest) = bytes.strip_prefix(b"\xFF\xFE") {
        (Some(Charset::Utf16Le), rest)
    } else {
        (None, bytes)
    };
    // plexus-utils reads the declaration of an EBCDIC start in EBCDIC, then
    // the document in the encoding it names, or UTF-8 when it names none.
    if bom.is_none() && rest.starts_with(EBCDIC_START) {
        let window = ebcdic_prolog(&rest[..rest.len().min(PROLOG_WINDOW)]);
        let end = window.find('>').ok_or(PomError::UnterminatedDeclaration)?;
        return match declared_encoding(&window[..end]) {
            None => Ok(String::from_utf8_lossy(bytes)),
            Some(name)
                if name.eq_ignore_ascii_case("default") || Charset::named(&name).is_some() =>
            {
                decode_as(bytes, &name)
            }
            Some(name) => Err(PomError::Ebcdic(shown_name(name.as_bytes()))),
        };
    }
    let guess = if rest.starts_with(b"\x00<\x00?") {
        Some(Charset::Utf16Be)
    } else if rest.starts_with(b"<\x00?\x00") {
        Some(Charset::Utf16Le)
    } else if rest.starts_with(b"<?xm") {
        Some(Charset::Utf8)
    } else {
        None
    };
    // The declaration is read in the encoding the first bytes suggest, and
    // must end within the bytes plexus-utils reads for it.
    let declared = match guess {
        Some(charset) => {
            let window = charset.decode(&rest[..rest.len().min(PROLOG_WINDOW)]);
            let end = window.find('>').ok_or(PomError::UnterminatedDeclaration)?;
            declared_encoding(&window[..end])
        }
        None => None,
    };
    let says_utf16 = declared
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case("UTF-16"));
    match bom {
        Some(bom) if bom != Charset::Utf8 && guess.is_some_and(|guess| guess != bom) => {
            Err(PomError::EncodingMismatch {
                bom: bom.name(),
                text: guess.map_or("", Charset::name),
            })
        }
        Some(bom) => {
            let agrees = guess.is_none_or(|guess| guess == bom)
                && declared.as_deref().is_none_or(|name| {
                    Charset::named(name) == Some(bom) || (bom != Charset::Utf8 && says_utf16)
                });
            if agrees {
                Ok(bom.decode(rest))
            } else {
                decode_as(rest, declared.as_deref().unwrap_or("UTF-8"))
            }
        }
        None => match (guess, declared) {
            // Only a declaration that says UTF-16 keeps a UTF-16 start.
            (Some(charset @ (Charset::Utf16Be | Charset::Utf16Le)), _) if says_utf16 => {
                Ok(charset.decode(bytes))
            }
            (_, Some(name)) => decode_as(bytes, &name),
            (_, None) => Ok(String::from_utf8_lossy(bytes)),
        },
    }
}

fn decode_as<'a>(bytes: &'a [u8], name: &str) -> Result<Cow<'a, str>, PomError> {
    if name.eq_ignore_ascii_case("default") {
        return Err(PomError::UnknownEncoding(shown_name(name.as_bytes())));
    }
    Charset::named(name)
        .map(|charset| charset.decode(bytes))
        .ok_or_else(|| PomError::UnsupportedEncoding(shown_name(name.as_bytes())))
}

/// `<?xm` in EBCDIC, which plexus-utils takes as the start of an EBCDIC
/// document.
const EBCDIC_START: &[u8] = b"\x4C\x6F\xA7\x94";

fn ebcdic_prolog(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0x81..=0x89 => char::from(b'a' + (b - 0x81)),
            0x91..=0x99 => char::from(b'j' + (b - 0x91)),
            0xA2..=0xA9 => char::from(b's' + (b - 0xA2)),
            0xC1..=0xC9 => char::from(b'A' + (b - 0xC1)),
            0xD1..=0xD9 => char::from(b'J' + (b - 0xD1)),
            0xE2..=0xE9 => char::from(b'S' + (b - 0xE2)),
            0xF0..=0xF9 => char::from(b'0' + (b - 0xF0)),
            0x05 => '\t',
            0x0D => '\r',
            0x15 | 0x25 => '\n',
            0x40 => ' ',
            0x4B => '.',
            0x4C => '<',
            0x4D => '(',
            0x4E => '+',
            0x5D => ')',
            0x60 => '-',
            0x61 => '/',
            0x6B => ',',
            0x6D => '_',
            0x6E => '>',
            0x6F => '?',
            0x7A => ':',
            0x7D => '\'',
            0x7E => '=',
            0x7F => '"',
            _ => char::REPLACEMENT_CHARACTER,
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Charset {
    Utf8,
    Utf16Be,
    Utf16Le,
    Latin1,
    Ascii,
    Windows1252,
}

impl Charset {
    fn name(self) -> &'static str {
        match self {
            Charset::Utf8 => "UTF-8",
            Charset::Utf16Be => "UTF-16BE",
            Charset::Utf16Le => "UTF-16LE",
            Charset::Latin1 => "ISO-8859-1",
            Charset::Ascii => "US-ASCII",
            Charset::Windows1252 => "windows-1252",
        }
    }

    fn decode(self, bytes: &[u8]) -> Cow<'_, str> {
        match self {
            Charset::Utf8 => String::from_utf8_lossy(bytes),
            Charset::Latin1 => Cow::Owned(bytes.iter().map(|&b| char::from(b)).collect()),
            Charset::Ascii => Cow::Owned(
                bytes
                    .iter()
                    .map(|&b| {
                        if b.is_ascii() {
                            char::from(b)
                        } else {
                            char::REPLACEMENT_CHARACTER
                        }
                    })
                    .collect(),
            ),
            Charset::Windows1252 => Cow::Owned(bytes.iter().map(|&b| windows_1252(b)).collect()),
            // Declared over ASCII bytes, as Java decodes it: big-endian
            // unless the name says otherwise. The text that results is not
            // XML.
            Charset::Utf16Be => Cow::Owned(utf16(bytes, u16::from_be_bytes)),
            Charset::Utf16Le => Cow::Owned(utf16(bytes, u16::from_le_bytes)),
        }
    }

    fn named(name: &str) -> Option<Self> {
        let name = name.to_ascii_lowercase();
        Some(match name.as_str() {
            "utf-8" | "utf8" | "unicode-1-1-utf-8" => Self::Utf8,
            "utf-16" | "utf_16" | "utf16" | "unicode" | "utf-16be" | "utf_16be" | "x-utf-16be"
            | "iso-10646-ucs-2" | "unicodebigunmarked" => Self::Utf16Be,
            "utf-16le" | "utf_16le" | "x-utf-16le" | "unicodelittleunmarked" => Self::Utf16Le,
            "iso-8859-1" | "iso8859-1" | "iso_8859-1" | "iso8859_1" | "iso_8859_1"
            | "iso_8859-1:1987" | "iso-ir-100" | "8859_1" | "latin1" | "l1" | "ibm819"
            | "ibm-819" | "cp819" | "819" | "csisolatin1" => Self::Latin1,
            "us-ascii" | "ascii" | "us" | "iso646-us" | "iso_646.irv:1983" | "ansi_x3.4-1968"
            | "ansi_x3.4-1986" | "ascii7" | "646" | "cp367" | "ibm367" | "csascii" | "iso-ir-6" => {
                Self::Ascii
            }
            "windows-1252" | "cp1252" | "cp5348" => Self::Windows1252,
            _ => return None,
        })
    }
}

/// How many bytes after a byte order mark plexus-utils reads for the XML
/// declaration.
const PROLOG_WINDOW: usize = 4096;

/// The `encoding` of the XML declaration in `prolog`, the text before the
/// first `>`, as plexus-utils finds it: with line breaks removed, the last
/// `encoding` after `<?xml` and on its line that has `=` and a quoted value
/// after it. The value is its first character and the rest up to the
/// closing quote.
fn declared_encoding(prolog: &str) -> Option<String> {
    let is_space = |c: char| matches!(c, ' ' | '\t' | '\u{B}' | '\u{C}');
    let ends_line = |c: char| matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}');
    let line: String = prolog
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n'))
        .collect();
    let value = |tail: &str| -> Option<String> {
        let tail = tail.trim_start_matches(is_space).strip_prefix('=')?;
        let mut chars = tail.trim_start_matches(is_space).chars();
        let quote = chars.next().filter(|c| matches!(c, '"' | '\''))?;
        let first = chars.next().filter(|c| !ends_line(*c))?;
        let rest = chars.as_str();
        let end = rest.find(quote)?;
        Some(format!("{first}{}", &rest[..end]))
    };
    line.match_indices("<?xml").find_map(|(start, _)| {
        let from = start + "<?xml".len();
        let reach = line[from..]
            .find(ends_line)
            .map_or(line.len(), |end| from + end);
        line[from..reach]
            .rmatch_indices("encoding")
            .find_map(|(at, _)| value(&line[from + at + "encoding".len()..]))
    })
}

/// UTF-16 as Java decodes it: a high surrogate followed by a unit that is
/// not a low surrogate is one malformed unit pair, so both become a single
/// U+FFFD, and an odd final byte becomes one too unless it follows a final
/// high surrogate.
fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let pairs = bytes.chunks_exact(2);
    let odd = !pairs.remainder().is_empty();
    let mut units = pairs.map(|pair| unit([pair[0], pair[1]]));
    let mut text = String::with_capacity(bytes.len() / 2);
    let mut dangling = false;
    while let Some(first) = units.next() {
        let decoded = match first {
            0xD800..=0xDBFF => match units.next() {
                Some(second) => char::decode_utf16([first, second])
                    .next()
                    .and_then(Result::ok),
                None => {
                    dangling = true;
                    None
                }
            },
            0xDC00..=0xDFFF => None,
            _ => char::from_u32(u32::from(first)),
        };
        text.push(decoded.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    // A final high surrogate and an odd byte after it are one malformed
    // input.
    if odd && !dangling {
        text.push(char::REPLACEMENT_CHARACTER);
    }
    text
}

/// windows-1252 as Java decodes it: five bytes it leaves undefined become
/// U+FFFD.
fn windows_1252(byte: u8) -> char {
    const HIGH: [char; 32] = [
        '\u{20AC}', '\u{FFFD}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{FFFD}',
        '\u{017D}', '\u{FFFD}', '\u{FFFD}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}',
        '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}',
        '\u{0153}', '\u{FFFD}', '\u{017E}', '\u{0178}',
    ];
    match byte {
        0x80..=0x9F => HIGH[usize::from(byte - 0x80)],
        _ => char::from(byte),
    }
}

fn shown_name(name: &[u8]) -> String {
    let mut shown: String = name
        .iter()
        .take(40)
        .map(|&b| {
            if b.is_ascii_graphic() {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect();
    if name.len() > 40 {
        shown.push_str("...");
    }
    shown
}

/// The entities Maven's model and settings readers resolve: XML's five and
/// the XHTML Latin-1, special and symbol sets. A DTD is read past, as
/// Maven's parser does, and the entities it declares stay unknown.
#[derive(Clone, Copy, Debug, Default)]
pub struct MavenEntities;

impl EntityResolver for MavenEntities {
    type Error = std::convert::Infallible;

    fn capture(&mut self, _doctype: BytesText<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn resolve(&self, entity: &str) -> Option<&str> {
        resolve_predefined_entity(entity).or_else(|| {
            XHTML_ENTITIES
                .binary_search_by(|(name, _)| (*name).cmp(entity))
                .ok()
                .map(|index| XHTML_ENTITIES[index].1)
        })
    }
}

/// plexus-utils 3.6.0 `EntityReplacementMap.defaultEntityReplacementMap`,
/// sorted by name.
const XHTML_ENTITIES: [(&str, &str); 248] = [
    ("AElig", "\u{C6}"),
    ("Aacute", "\u{C1}"),
    ("Acirc", "\u{C2}"),
    ("Agrave", "\u{C0}"),
    ("Alpha", "\u{391}"),
    ("Aring", "\u{C5}"),
    ("Atilde", "\u{C3}"),
    ("Auml", "\u{C4}"),
    ("Beta", "\u{392}"),
    ("Ccedil", "\u{C7}"),
    ("Chi", "\u{3A7}"),
    ("Dagger", "\u{2021}"),
    ("Delta", "\u{394}"),
    ("ETH", "\u{D0}"),
    ("Eacute", "\u{C9}"),
    ("Ecirc", "\u{CA}"),
    ("Egrave", "\u{C8}"),
    ("Epsilon", "\u{395}"),
    ("Eta", "\u{397}"),
    ("Euml", "\u{CB}"),
    ("Gamma", "\u{393}"),
    ("Iacute", "\u{CD}"),
    ("Icirc", "\u{CE}"),
    ("Igrave", "\u{CC}"),
    ("Iota", "\u{399}"),
    ("Iuml", "\u{CF}"),
    ("Kappa", "\u{39A}"),
    ("Lambda", "\u{39B}"),
    ("Mu", "\u{39C}"),
    ("Ntilde", "\u{D1}"),
    ("Nu", "\u{39D}"),
    ("OElig", "\u{152}"),
    ("Oacute", "\u{D3}"),
    ("Ocirc", "\u{D4}"),
    ("Ograve", "\u{D2}"),
    ("Omega", "\u{3A9}"),
    ("Omicron", "\u{39F}"),
    ("Oslash", "\u{D8}"),
    ("Otilde", "\u{D5}"),
    ("Ouml", "\u{D6}"),
    ("Phi", "\u{3A6}"),
    ("Pi", "\u{3A0}"),
    ("Prime", "\u{2033}"),
    ("Psi", "\u{3A8}"),
    ("Rho", "\u{3A1}"),
    ("Scaron", "\u{160}"),
    ("Sigma", "\u{3A3}"),
    ("THORN", "\u{DE}"),
    ("Tau", "\u{3A4}"),
    ("Theta", "\u{398}"),
    ("Uacute", "\u{DA}"),
    ("Ucirc", "\u{DB}"),
    ("Ugrave", "\u{D9}"),
    ("Upsilon", "\u{3A5}"),
    ("Uuml", "\u{DC}"),
    ("Xi", "\u{39E}"),
    ("Yacute", "\u{DD}"),
    ("Yuml", "\u{178}"),
    ("Zeta", "\u{396}"),
    ("aacute", "\u{E1}"),
    ("acirc", "\u{E2}"),
    ("acute", "\u{B4}"),
    ("aelig", "\u{E6}"),
    ("agrave", "\u{E0}"),
    ("alefsym", "\u{2135}"),
    ("alpha", "\u{3B1}"),
    ("and", "\u{2227}"),
    ("ang", "\u{2220}"),
    ("aring", "\u{E5}"),
    ("asymp", "\u{2248}"),
    ("atilde", "\u{E3}"),
    ("auml", "\u{E4}"),
    ("bdquo", "\u{201E}"),
    ("beta", "\u{3B2}"),
    ("brvbar", "\u{A6}"),
    ("bull", "\u{2022}"),
    ("cap", "\u{2229}"),
    ("ccedil", "\u{E7}"),
    ("cedil", "\u{B8}"),
    ("cent", "\u{A2}"),
    ("chi", "\u{3C7}"),
    ("circ", "\u{2C6}"),
    ("clubs", "\u{2663}"),
    ("cong", "\u{2245}"),
    ("copy", "\u{A9}"),
    ("crarr", "\u{21B5}"),
    ("cup", "\u{222A}"),
    ("curren", "\u{A4}"),
    ("dArr", "\u{21D3}"),
    ("dagger", "\u{2020}"),
    ("darr", "\u{2193}"),
    ("deg", "\u{B0}"),
    ("delta", "\u{3B4}"),
    ("diams", "\u{2666}"),
    ("divide", "\u{F7}"),
    ("eacute", "\u{E9}"),
    ("ecirc", "\u{EA}"),
    ("egrave", "\u{E8}"),
    ("empty", "\u{2205}"),
    ("emsp", "\u{2003}"),
    ("ensp", "\u{2002}"),
    ("epsilon", "\u{3B5}"),
    ("equiv", "\u{2261}"),
    ("eta", "\u{3B7}"),
    ("eth", "\u{F0}"),
    ("euml", "\u{EB}"),
    ("euro", "\u{20AC}"),
    ("exist", "\u{2203}"),
    ("fnof", "\u{192}"),
    ("forall", "\u{2200}"),
    ("frac12", "\u{BD}"),
    ("frac14", "\u{BC}"),
    ("frac34", "\u{BE}"),
    ("frasl", "\u{2044}"),
    ("gamma", "\u{3B3}"),
    ("ge", "\u{2265}"),
    ("hArr", "\u{21D4}"),
    ("harr", "\u{2194}"),
    ("hearts", "\u{2665}"),
    ("hellip", "\u{2026}"),
    ("iacute", "\u{ED}"),
    ("icirc", "\u{EE}"),
    ("iexcl", "\u{A1}"),
    ("igrave", "\u{EC}"),
    ("image", "\u{2111}"),
    ("infin", "\u{221E}"),
    ("int", "\u{222B}"),
    ("iota", "\u{3B9}"),
    ("iquest", "\u{BF}"),
    ("isin", "\u{2208}"),
    ("iuml", "\u{EF}"),
    ("kappa", "\u{3BA}"),
    ("lArr", "\u{21D0}"),
    ("lambda", "\u{3BB}"),
    ("lang", "\u{2329}"),
    ("laquo", "\u{AB}"),
    ("larr", "\u{2190}"),
    ("lceil", "\u{2308}"),
    ("ldquo", "\u{201C}"),
    ("le", "\u{2264}"),
    ("lfloor", "\u{230A}"),
    ("lowast", "\u{2217}"),
    ("loz", "\u{25CA}"),
    ("lrm", "\u{200E}"),
    ("lsaquo", "\u{2039}"),
    ("lsquo", "\u{2018}"),
    ("macr", "\u{AF}"),
    ("mdash", "\u{2014}"),
    ("micro", "\u{B5}"),
    ("middot", "\u{B7}"),
    ("minus", "\u{2212}"),
    ("mu", "\u{3BC}"),
    ("nabla", "\u{2207}"),
    ("nbsp", "\u{A0}"),
    ("ndash", "\u{2013}"),
    ("ne", "\u{2260}"),
    ("ni", "\u{220B}"),
    ("not", "\u{AC}"),
    ("notin", "\u{2209}"),
    ("nsub", "\u{2284}"),
    ("ntilde", "\u{F1}"),
    ("nu", "\u{3BD}"),
    ("oacute", "\u{F3}"),
    ("ocirc", "\u{F4}"),
    ("oelig", "\u{153}"),
    ("ograve", "\u{F2}"),
    ("oline", "\u{203E}"),
    ("omega", "\u{3C9}"),
    ("omicron", "\u{3BF}"),
    ("oplus", "\u{2295}"),
    ("or", "\u{2228}"),
    ("ordf", "\u{AA}"),
    ("ordm", "\u{BA}"),
    ("oslash", "\u{F8}"),
    ("otilde", "\u{F5}"),
    ("otimes", "\u{2297}"),
    ("ouml", "\u{F6}"),
    ("para", "\u{B6}"),
    ("part", "\u{2202}"),
    ("permil", "\u{2030}"),
    ("perp", "\u{22A5}"),
    ("phi", "\u{3C6}"),
    ("pi", "\u{3C0}"),
    ("piv", "\u{3D6}"),
    ("plusmn", "\u{B1}"),
    ("pound", "\u{A3}"),
    ("prime", "\u{2032}"),
    ("prod", "\u{220F}"),
    ("prop", "\u{221D}"),
    ("psi", "\u{3C8}"),
    ("rArr", "\u{21D2}"),
    ("radic", "\u{221A}"),
    ("rang", "\u{232A}"),
    ("raquo", "\u{BB}"),
    ("rarr", "\u{2192}"),
    ("rceil", "\u{2309}"),
    ("rdquo", "\u{201D}"),
    ("real", "\u{211C}"),
    ("reg", "\u{AE}"),
    ("rfloor", "\u{230B}"),
    ("rho", "\u{3C1}"),
    ("rlm", "\u{200F}"),
    ("rsaquo", "\u{203A}"),
    ("rsquo", "\u{2019}"),
    ("sbquo", "\u{201A}"),
    ("scaron", "\u{161}"),
    ("sdot", "\u{22C5}"),
    ("sect", "\u{A7}"),
    ("shy", "\u{AD}"),
    ("sigma", "\u{3C3}"),
    ("sigmaf", "\u{3C2}"),
    ("sim", "\u{223C}"),
    ("spades", "\u{2660}"),
    ("sub", "\u{2282}"),
    ("sube", "\u{2286}"),
    ("sum", "\u{2211}"),
    ("sup", "\u{2283}"),
    ("sup1", "\u{B9}"),
    ("sup2", "\u{B2}"),
    ("sup3", "\u{B3}"),
    ("supe", "\u{2287}"),
    ("szlig", "\u{DF}"),
    ("tau", "\u{3C4}"),
    ("there4", "\u{2234}"),
    ("theta", "\u{3B8}"),
    ("thetasym", "\u{3D1}"),
    ("thinsp", "\u{2009}"),
    ("thorn", "\u{FE}"),
    ("tilde", "\u{2DC}"),
    ("times", "\u{D7}"),
    ("trade", "\u{2122}"),
    ("uArr", "\u{21D1}"),
    ("uacute", "\u{FA}"),
    ("uarr", "\u{2191}"),
    ("ucirc", "\u{FB}"),
    ("ugrave", "\u{F9}"),
    ("uml", "\u{A8}"),
    ("upsih", "\u{3D2}"),
    ("upsilon", "\u{3C5}"),
    ("uuml", "\u{FC}"),
    ("weierp", "\u{2118}"),
    ("xi", "\u{3BE}"),
    ("yacute", "\u{FD}"),
    ("yen", "\u{A5}"),
    ("yuml", "\u{FF}"),
    ("zeta", "\u{3B6}"),
    ("zwj", "\u{200D}"),
    ("zwnj", "\u{200C}"),
];

#[cfg(test)]
mod tests {
    use super::{MavenEntities, XHTML_ENTITIES, decode_pom};
    use crate::PomError;
    use quick_xml::de::EntityResolver;

    #[test]
    fn the_entity_table_is_sorted_for_lookup() {
        assert!(XHTML_ENTITIES.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(MavenEntities.resolve("copy"), Some("\u{A9}"));
        assert_eq!(MavenEntities.resolve("amp"), Some("&"));
        assert_eq!(MavenEntities.resolve("euro"), Some("\u{20AC}"));
        assert_eq!(MavenEntities.resolve("unknown"), None);
    }

    #[test]
    fn a_declaration_chooses_the_encoding() {
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><p>Caf\xE9</p>";
        assert_eq!(
            decode_pom(latin1).unwrap(),
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><p>Caf\u{E9}</p>"
        );
        let cp1252 = b"<?xml version='1.0' encoding='windows-1252'?><p>\x93q\x94\x80\x81</p>";
        assert_eq!(
            decode_pom(cp1252).unwrap(),
            "<?xml version='1.0' encoding='windows-1252'?><p>\u{201C}q\u{201D}\u{20AC}\u{FFFD}</p>"
        );
        let ascii = b"<?xml version=\"1.0\" encoding=\"US-ASCII\"?><p>\xE9</p>";
        assert_eq!(
            decode_pom(ascii).unwrap(),
            "<?xml version=\"1.0\" encoding=\"US-ASCII\"?><p>\u{FFFD}</p>"
        );
    }

    #[test]
    fn without_a_declaration_utf8_is_read_leniently() {
        assert_eq!(decode_pom(b"<p>Caf\xE9</p>").unwrap(), "<p>Caf\u{FFFD}</p>");
        assert_eq!(
            decode_pom(b"\xEF\xBB\xBF<p>\xC3\xA9</p>").unwrap(),
            "<p>\u{E9}</p>"
        );
        assert_eq!(
            decode_pom(b"<p encoding=\"latin1\">\xE9</p>").unwrap(),
            "<p encoding=\"latin1\">\u{FFFD}</p>"
        );
    }

    #[test]
    fn utf16_is_read_with_or_without_a_byte_order_mark() {
        let text = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><p>\u{E9}\u{1F600}</p>";
        let le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let be: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(decode_pom(&le).unwrap(), text);
        assert_eq!(decode_pom(&be).unwrap(), text);
        assert_eq!(
            decode_pom(&[&[0xFF, 0xFE][..], &le].concat()).unwrap(),
            text
        );
        assert_eq!(
            decode_pom(&[&[0xFE, 0xFF][..], &be].concat()).unwrap(),
            text
        );
        let odd = [&[0xFF, 0xFE][..], &le, &[0x41][..]].concat();
        assert_eq!(decode_pom(&odd).unwrap(), format!("{text}\u{FFFD}"));
        // Without a byte order mark, Maven 3.9.11 keeps UTF-16 only when the
        // declaration says UTF-16, and otherwise fails on the NUL bytes.
        let lower = text.replace("UTF-16", "utf-16");
        let lower: Vec<u8> = lower.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(
            decode_pom(&lower).unwrap(),
            text.replace("UTF-16", "utf-16")
        );
        for declaration in ["", " encoding=\"UTF-8\""] {
            let text = format!("<?xml version=\"1.0\"{declaration}?><p/>");
            for bytes in [
                text.encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<u8>>(),
                text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
            ] {
                let decoded = decode_pom(&bytes).unwrap();
                assert!(decoded.contains('\0'), "{decoded:?}");
                assert!(crate::Pom::parse(&decoded).is_err());
            }
        }
    }

    /// What plexus-utils 3.6.0, the reader in Maven 3.9.11, makes of a
    /// byte order mark next to a declaration or text that disagrees.
    /// Java reads a high surrogate and the unit after it as one malformed
    /// pair when that unit is not a low surrogate, so the unit is lost.
    #[test]
    fn an_unpaired_surrogate_takes_the_next_unit_as_java_does() {
        let le = |units: &[u16]| -> Vec<u8> {
            [
                &b"\xFF\xFE"[..],
                &units
                    .iter()
                    .flat_map(|u| u.to_le_bytes())
                    .collect::<Vec<_>>(),
            ]
            .concat()
        };
        let a = u16::from(b'a');
        let dash = u16::from(b'-');
        assert_eq!(
            decode_pom(&le(&[a, 0xD800, dash, a])).unwrap(),
            "a\u{fffd}a"
        );
        assert_eq!(
            decode_pom(&le(&[a, 0xD800, 0xD800, a])).unwrap(),
            "a\u{fffd}a"
        );
        assert_eq!(decode_pom(&le(&[a, 0xDC00, a])).unwrap(), "a\u{fffd}a");
        assert_eq!(decode_pom(&le(&[a, 0xD83D, 0xDE00])).unwrap(), "a\u{1f600}");
        assert_eq!(decode_pom(&le(&[a, 0xD800])).unwrap(), "a\u{fffd}");
        let mut odd = le(&[a, 0xD800]);
        odd.push(b'A');
        assert_eq!(decode_pom(&odd).unwrap(), "a\u{fffd}");
    }

    /// Cases checked against plexus-utils 3.6.0's `XmlStreamReader`.
    #[test]
    fn the_declaration_is_read_as_plexus_reads_it() {
        let latin1 = |text: &str| -> Vec<u8> { text.chars().map(|c| c as u8).collect() };
        let padded = |spaces: usize| format!("<?xml version=\"1.0\"{}?><p/>", " ".repeat(spaces));
        // The `>` must come within the first 4096 bytes after a byte order
        // mark.
        for bom in [&b""[..], b"\xEF\xBB\xBF"] {
            assert!(decode_pom(&[bom, padded(4075).as_bytes()].concat()).is_ok());
            assert!(matches!(
                decode_pom(&[bom, padded(4076).as_bytes()].concat()),
                Err(PomError::UnterminatedDeclaration)
            ));
        }
        for truncated in [&b"<?xm"[..], b"\xEF\xBB\xBF<?xm", b"<\x00?\x00x\x00m\x00"] {
            assert!(matches!(
                decode_pom(truncated),
                Err(PomError::UnterminatedDeclaration)
            ));
        }
        // A UTF-16 declaration has the same 4096 bytes.
        let utf16 = format!(
            "<?xml version=\"1.0\"{} encoding=\"UTF-16\"?><p/>",
            " ".repeat(1000)
        );
        let le: Vec<u8> = utf16.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode_pom(&le).unwrap(), utf16);
        for (declaration, latin1_wins) in [
            ("<?xml version=\"1.0\" enc\noding=\"ISO-8859-1\"?>", true),
            (
                "<?xml version=\"1.0\" encoding\r\n=\u{b}\"ISO-8859-1\"?>",
                true,
            ),
            ("<?xml encoding=\"ISO-8859-1\" encoding=bad?>", true),
            ("<?xml encoding='ISO-8859-1' encoding=\"UTF-8\"?>", false),
            ("<?xmz encoding=\"ISO-8859-1\"?>", false),
            ("<?xml version=\"1.0\" encoding=\"ISO>8859\"?>", false),
            ("<?xml version=\"1.0\" encoding=\"\"?>", false),
        ] {
            let text = format!("{declaration}<p>\u{e9}</p>");
            let bytes = latin1(&text);
            let decoded = decode_pom(&bytes).unwrap();
            assert_eq!(
                decoded.ends_with("<p>\u{e9}</p>"),
                latin1_wins,
                "{declaration:?}"
            );
        }
        // A line separator ends the search for `encoding`.
        let mut separated = "<?xml version=\"1.0\"\u{2028} encoding=\"ISO-8859-1\"?>"
            .as_bytes()
            .to_vec();
        separated.extend_from_slice(b"<p>\xe9</p>");
        assert!(decode_pom(&separated).unwrap().ends_with("<p>\u{fffd}</p>"));
    }

    #[test]
    fn a_declaration_wins_over_a_byte_order_mark() {
        let le =
            |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let be =
            |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_be_bytes).collect() };
        let with = |bom: &[u8], rest: &[u8]| [bom, rest].concat();
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><p>\xe9</p>";
        assert_eq!(
            decode_pom(&with(b"\xEF\xBB\xBF", latin1)).unwrap(),
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><p>\u{e9}</p>"
        );
        let cp1252 = b"<?xml version=\"1.0\" encoding=\"windows-1252\"?><p>\x80</p>";
        assert!(
            decode_pom(&with(b"\xEF\xBB\xBF", cp1252))
                .unwrap()
                .ends_with("<p>\u{20ac}</p>")
        );
        // UTF-16 text read as the UTF-8 it declares keeps its NUL bytes.
        let utf8 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><p/>";
        assert_eq!(
            decode_pom(&with(b"\xFF\xFE", &le(utf8))).unwrap(),
            String::from_utf8(le(utf8)).unwrap()
        );
        let utf16le = "<?xml version=\"1.0\" encoding=\"UTF-16LE\"?><p/>";
        let swapped: String = char::decode_utf16(
            be(utf16le)
                .chunks(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
        )
        .map(Result::unwrap)
        .collect();
        assert_eq!(
            decode_pom(&with(b"\xFE\xFF", &be(utf16le))).unwrap(),
            swapped
        );
        // A declaration that agrees, or none, keeps the byte order mark's.
        for declaration in ["UTF-16", "utf-16le", ""] {
            let text = format!("<?xml version=\"1.0\" encoding=\"{declaration}\"?><p>\u{e9}</p>");
            let text = text.replace(" encoding=\"\"", "");
            assert_eq!(decode_pom(&with(b"\xFF\xFE", &le(&text))).unwrap(), text);
        }
        assert_eq!(
            decode_pom(&with(b"\xFE\xFF", &be("<p>\u{e9}</p>"))).unwrap(),
            "<p>\u{e9}</p>"
        );
        assert_eq!(
            decode_pom(&with(b"\xEF\xBB\xBF", &le("<?xml version=\"1.0\"?><p/>"))).unwrap(),
            String::from_utf8(le("<?xml version=\"1.0\"?><p/>")).unwrap()
        );
        // Maven refuses a UTF-16 byte order mark before text that starts
        // as UTF-8 does.
        let error = decode_pom(b"\xFF\xFE<?xml encoding=\"ISO-8859-1\"?><p>\xe9</p>").unwrap_err();
        assert!(
            matches!(error, PomError::EncodingMismatch { .. }),
            "{error}"
        );
        assert!(error.is_malformed_xml());
    }

    /// Maven 3.9.11 reads an EBCDIC POM in the encoding it declares; raeva
    /// refuses one that declares an EBCDIC code page instead of reading the
    /// bytes as UTF-8. One that declares no encoding, or one raeva reads, is
    /// read in that as Maven reads it, which leaves text that is not XML.
    #[test]
    fn an_ebcdic_pom_is_read_as_maven_reads_it() {
        let ebcdic = |text: &str| -> Vec<u8> {
            text.bytes()
                .map(|b| match b {
                    b'a'..=b'i' => 0x81 + (b - b'a'),
                    b'j'..=b'r' => 0x91 + (b - b'j'),
                    b's'..=b'z' => 0xA2 + (b - b's'),
                    b'A'..=b'I' => 0xC1 + (b - b'A'),
                    b'J'..=b'R' => 0xD1 + (b - b'J'),
                    b'S'..=b'Z' => 0xE2 + (b - b'S'),
                    b'0'..=b'9' => 0xF0 + (b - b'0'),
                    b' ' => 0x40,
                    b'.' => 0x4B,
                    b'<' => 0x4C,
                    b'>' => 0x6E,
                    b'?' => 0x6F,
                    b'=' => 0x7E,
                    b'"' => 0x7F,
                    b'/' => 0x61,
                    b'-' => 0x60,
                    _ => panic!("no test mapping for {b}"),
                })
                .collect()
        };
        let error =
            decode_pom(&ebcdic("<?xml version=\"1.0\" encoding=\"IBM037\"?><p/>")).unwrap_err();
        assert!(
            matches!(&error, PomError::Ebcdic(name) if name == "IBM037"),
            "{error:?}"
        );
        assert!(!error.is_malformed_xml());
        assert_eq!(
            error.to_string(),
            "the POM is in EBCDIC, declared as IBM037, which raeva does not read; raeva reads UTF-8, \
             UTF-16, ISO-8859-1, US-ASCII and windows-1252"
        );
        for pom in [
            "<?xml version=\"1.0\"?><p/>",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><p/>",
        ] {
            let bytes = ebcdic(pom);
            let text = decode_pom(&bytes).expect(pom);
            assert!(!text.starts_with("<?xml"), "{pom}");
        }
        assert!(matches!(
            decode_pom(&ebcdic("<?xml version=\"1.0\" encoding=\"default\"?><p/>")),
            Err(PomError::UnknownEncoding(_))
        ));
        assert!(matches!(
            decode_pom(&ebcdic("<?xml version=\"1.0\"")),
            Err(PomError::UnterminatedDeclaration)
        ));
    }

    /// Java 27, which Maven 3.9.11 was checked on, has no charset named
    /// `default`; Maven reports the POM as unreadable and drops it as a
    /// dependency's model, as it does malformed XML.
    #[test]
    fn the_default_encoding_name_is_unreadable() {
        for name in ["default", "DEFAULT"] {
            let pom = format!("<?xml version=\"1.0\" encoding=\"{name}\"?><p/>");
            let error = decode_pom(pom.as_bytes()).unwrap_err();
            assert!(
                matches!(&error, PomError::UnknownEncoding(shown) if shown == name),
                "{error:?}"
            );
            assert!(error.is_malformed_xml());
        }
    }

    #[test]
    fn an_encoding_rv_does_not_read_is_named() {
        let error = decode_pom(b"<?xml version=\"1.0\" encoding=\"Shift_JIS\"?><p/>").unwrap_err();
        assert!(
            matches!(&error, PomError::UnsupportedEncoding(name) if name == "Shift_JIS"),
            "{error}"
        );
        let error = decode_pom(b"<?xml encoding=\"\x1b[31mred\"?><p/>").unwrap_err();
        assert!(
            matches!(&error, PomError::UnsupportedEncoding(name) if name == "?[31mred"),
            "{error}"
        );
    }
}
