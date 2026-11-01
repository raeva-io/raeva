//! The maven-artifact 3.9.12 order used by DefaultModelBuilder for local parents.

use std::cmp::Ordering::{self, Equal, Greater, Less};

#[derive(Debug)]
enum Item {
    Number(u8, String),
    String(String),
    List(Vec<Item>),
}

impl Item {
    fn number(text: &str) -> Self {
        // ComparableVersion keeps an all-zero token's original length when
        // choosing IntItem, LongItem or BigIntegerItem. Their types sort first.
        let stripped = text.trim_start_matches('0');
        let stripped = if stripped.is_empty() { text } else { stripped };
        let kind = match stripped.chars().count() {
            0..=9 => 0,
            10..=18 => 1,
            _ => 2,
        };
        let digits: String = stripped
            .chars()
            .map(|ch| char::from(b'0' + digit(ch).expect("numeric token")))
            .collect();
        let digits = digits.trim_start_matches('0');
        Self::Number(kind, if digits.is_empty() { "0" } else { digits }.into())
    }

    fn string(text: &str, followed_by_digit: bool) -> Self {
        Self::String(
            match text {
                "a" if followed_by_digit => "alpha",
                "b" if followed_by_digit => "beta",
                "m" if followed_by_digit => "milestone",
                "ga" | "final" | "release" => "",
                "cr" => "rc",
                _ => text,
            }
            .into(),
        )
    }

    fn token(text: &str, numeric: bool) -> Self {
        if numeric {
            Self::number(text)
        } else {
            Self::string(text, false)
        }
    }

    fn is_null(&self) -> bool {
        match self {
            Self::Number(_, value) => value == "0",
            Self::String(value) => value.is_empty(),
            Self::List(items) => items.is_empty(),
        }
    }

    fn compare(&self, other: Option<&Self>) -> Ordering {
        let Some(other) = other else {
            return match self {
                Self::Number(_, value) => {
                    if value == "0" {
                        Equal
                    } else {
                        Greater
                    }
                }
                Self::String(value) => qualifier(value).cmp(&qualifier("")),
                Self::List(items) => items
                    .iter()
                    .map(|item| item.compare(None))
                    .find(|order| *order != Equal)
                    .unwrap_or(Equal),
            };
        };
        match (self, other) {
            (Self::Number(ak, a), Self::Number(bk, b)) => ak
                .cmp(bk)
                .then_with(|| a.len().cmp(&b.len()))
                .then_with(|| a.cmp(b)),
            (Self::String(a), Self::String(b)) => qualifier(a)
                .cmp(&qualifier(b))
                .then_with(|| a.encode_utf16().cmp(b.encode_utf16())),
            (Self::List(a), Self::List(b)) => (0..a.len().max(b.len()))
                .map(|i| match (a.get(i), b.get(i)) {
                    (Some(a), b) => a.compare(b),
                    (None, Some(b)) => b.compare(None).reverse(),
                    (None, None) => Equal,
                })
                .find(|order| *order != Equal)
                .unwrap_or(Equal),
            (Self::Number(..), _) | (Self::List(_), Self::String(_)) => Greater,
            _ => Less,
        }
    }
}

fn qualifier(value: &str) -> u8 {
    match value {
        "alpha" => 0,
        "beta" => 1,
        "milestone" => 2,
        "rc" => 3,
        "snapshot" => 4,
        "" => 5,
        "sp" => 6,
        _ => 7,
    }
}

// Character.isDigit(char) and Java's numeric parsers recognize BMP decimal
// digits; supplementary characters are visited as two non-digit surrogates.
fn digit(ch: char) -> Option<u8> {
    const ZEROES: &[u32] = &[
        0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
        0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
        0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0,
        0xff10,
    ];
    let value = u32::from(ch);
    ZEROES.iter().find_map(|zero| {
        value
            .checked_sub(*zero)
            .filter(|n| *n < 10)
            .map(|n| n as u8)
    })
}

/// Nested lists deeper than this are refused, so comparing and dropping one
/// cannot exhaust the stack.
const MAX_NESTING: usize = 256;

fn parse(version: &str) -> Option<Item> {
    let version = version.to_lowercase();
    let mut stack = Vec::new();
    let mut list = Vec::new();
    let mut numeric = false;
    let mut start = 0;
    for (at, ch) in version.char_indices() {
        if matches!(ch, '.' | '-') {
            list.push(if at == start {
                Item::number("0")
            } else {
                Item::token(&version[start..at], numeric)
            });
            start = at + 1;
            if ch == '-' {
                stack.push(std::mem::take(&mut list));
            }
        } else if digit(ch).is_some() {
            if !numeric && at > start {
                if !list.is_empty() {
                    stack.push(std::mem::take(&mut list));
                }
                list.push(Item::string(&version[start..at], true));
                start = at;
                stack.push(std::mem::take(&mut list));
            }
            numeric = true;
        } else {
            if numeric && at > start {
                list.push(Item::number(&version[start..at]));
                start = at;
                stack.push(std::mem::take(&mut list));
            }
            numeric = false;
        }
    }
    if start < version.len() {
        if !numeric && !list.is_empty() {
            stack.push(std::mem::take(&mut list));
        }
        list.push(Item::token(&version[start..], numeric));
    }
    if stack.len() > MAX_NESTING {
        return None;
    }
    loop {
        // Normalization continues past nested lists, removing preceding zeroes
        // and release qualifiers too, until it reaches a non-null scalar.
        for i in (0..list.len()).rev() {
            if list[i].is_null() {
                list.remove(i);
            } else if !matches!(list[i], Item::List(_)) {
                break;
            }
        }
        let item = Item::List(list);
        let Some(mut parent) = stack.pop() else {
            return Some(item);
        };
        parent.push(item);
        list = parent;
    }
}

fn trim(text: &str) -> &str {
    text.trim_matches(|ch| ch <= '\u{20}')
}

/// None means createFromVersionSpec rejects the range, or a version nests
/// too deeply, allowing the caller to preserve its existing handling.
pub(crate) fn contains(version: &str, mut spec: &str) -> Option<bool> {
    let version = parse(version)?;
    let mut matched = false;
    let mut restricted = false;
    let mut previous_upper: Option<Item> = None;
    while spec.starts_with(['[', '(']) {
        let end = spec.find([')', ']'])?;
        let include_lower = spec.starts_with('[');
        let include_upper = spec.as_bytes()[end] == b']';
        let inner = trim(&spec[1..end]);
        let (lower, upper) = if let Some((lower, upper)) = inner.split_once(',') {
            let bound = |text| match trim(text) {
                "" => Some(None),
                text => parse(text).map(Some),
            };
            (bound(lower)?, bound(upper)?)
        } else {
            if !include_lower || !include_upper {
                return None;
            }
            (Some(parse(inner)?), Some(parse(inner)?))
        };
        if let (Some(lower), Some(upper)) = (&lower, &upper) {
            match lower.compare(Some(upper)) {
                Greater => return None,
                Equal if !include_lower || !include_upper => return None,
                _ => {}
            }
        }
        if let Some(previous) = &previous_upper
            && lower
                .as_ref()
                .is_none_or(|lower| lower.compare(Some(previous)) == Less)
        {
            return None;
        }
        matched |= lower.as_ref().is_none_or(|lower| {
            let order = lower.compare(Some(&version));
            order == Less || (order == Equal && include_lower)
        }) && upper.as_ref().is_none_or(|upper| {
            let order = upper.compare(Some(&version));
            order == Greater || (order == Equal && include_upper)
        });
        restricted = true;
        previous_upper = upper;
        spec = trim(&spec[end + 1..]);
        if let Some(rest) = spec.strip_prefix(',') {
            spec = trim(rest);
        }
    }
    if !spec.is_empty() {
        if restricted {
            return None;
        }
        // A bare version recommends a version, with Restriction.EVERYTHING.
        return Some(true);
    }
    Some(matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Recorded with DefaultArtifactVersion and VersionRange from the
    // maven-artifact 3.9.12 jar, including the resolver table's differing rows.
    #[test]
    fn compares_like_maven_artifact() {
        for (a, expected, b) in [
            ("1-1", Less, "1.1"),
            ("1.0-1", Less, "1.0.1"),
            ("1.0-1", Equal, "1-1"),
            ("1.0_alpha", Greater, "1.0"),
            ("1.0-final-1", Greater, "1.0-sp-1"),
            ("1.0-alpha.1", Greater, "1.0-alpha2"),
            ("1.0.0.1", Greater, "1.0.0-1"),
            ("2.0-1", Less, "2.0.1"),
            ("1-a", Less, "1-0.a"),
            ("0-alpha", Greater, "alpha"),
            ("1.0-alpha-1", Greater, "1.0-alpha"),
            ("1.0a1", Equal, "1.0-alpha-1"),
            ("1.0-b1", Equal, "1.0-beta-1"),
            ("1.0-M1", Less, "1.0-RC1"),
            ("1.0-rc1", Equal, "1.0-cr1"),
            ("1.0-SNAPSHOT", Greater, "1.0-rc"),
            ("1.0-SNAPSHOT", Less, "1.0"),
            ("1.0", Equal, "1.0.0"),
            ("1-ga", Equal, "1"),
            ("1.0.0.RELEASE", Equal, "1.0.0"),
            ("1.0.Final", Equal, "1"),
            ("1.0-sp", Greater, "1.0"),
            ("1.0-sp", Less, "1.0-abc"),
            ("1.0.1", Greater, "1.0-sp"),
            ("1.0-abc", Less, "1.0.1"),
            ("2.0.a", Greater, "2.0"),
            ("31.0-android", Less, "31.0-jre"),
            ("1.0-xyz", Equal, "1.0-XYZ"),
            ("1.12345678901", Greater, "1.2"),
            ("1.0-alpha2snapshot", Less, "1.0-alpha2"),
            ("1-foo1", Equal, "1-foo-1"),
            ("0", Equal, "ga"),
            ("alpha3", Greater, "alpha2"),
            ("0-alpha", Greater, "alpha2"),
            ("r09", Less, "1.0"),
            ("1.min", Greater, "1-alpha"),
            ("1.max", Less, "1.99"),
            ("1.max", Less, "2"),
            ("1.max.1", Less, "1.99"),
            ("1.min.1", Greater, "1"),
            ("1.0.max", Equal, "1.max"),
            ("1..1", Less, "1.1"),
            ("1--1", Less, "1-1"),
            ("1_1", Less, "1.1"),
            ("0001", Equal, "1"),
            ("999999999", Less, "1000000000"),
            ("999999999999999999", Less, "1000000000000000000"),
            (
                "1234567890123456789012345678901234567890",
                Greater,
                "1000000000000000000",
            ),
            ("1.0000000000.1", Greater, "1.1"),
            ("1.0000000000000000000.1", Greater, "1.0000000000.1"),
            ("${revision}", Less, "1"),
            ("1.0${changelist}", Greater, "1.0"),
            ("1.0${changelist}", Less, "1.0-custom"),
            ("1.١٢", Equal, "1.１２"),
            ("1.😀", Less, "1.\u{e000}"),
        ] {
            let (pa, pb) = (parse(a).unwrap(), parse(b).unwrap());
            assert_eq!(pa.compare(Some(&pb)), expected, "{a} vs {b}");
            assert_eq!(pb.compare(Some(&pa)), expected.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn contains_like_maven_artifact() {
        for (range, version, expected) in [
            ("[1.0,2.0)", "1.0", Some(true)),
            ("[1.0,2.0)", "2", Some(false)),
            ("(,1.0]", "1", Some(true)),
            ("(,1.0]", "1-1", Some(false)),
            ("[1-1]", "1.0-1", Some(true)),
            ("[1-1]", "1.1", Some(false)),
            ("[1.0,1-1]", "1-1", Some(true)),
            ("[1.0,1-1]", "1.1", Some(false)),
            ("[1,2),(3,4]", "2", Some(false)),
            ("[1,2),(3,4]", "3", Some(false)),
            ("[1,2),(3,4]", "4", Some(true)),
            ("[1.0,1.1)", "1-1", Some(true)),
            ("1.0", "4", Some(true)),
            ("", "1", Some(false)),
            ("[1.0,1.0)", "1", None),
            ("[2,1]", "1", None),
            ("[1,3],[2,4]", "3", None),
            ("[1,2],[2,3]", "2", Some(true)),
            ("[1,2][3,4]", "3", Some(true)),
            ("[1,2],", "1", Some(true)),
            ("[1,2],junk", "1", None),
            ("[1.2.*]", "1", Some(false)),
            ("[1,2,3]", "1", Some(true)),
            ("[]", "0", Some(true)),
            ("(,)", "${revision}", Some(true)),
            ("[1-alpha.1,1-alpha2]", "1", None),
        ] {
            assert_eq!(contains(version, range), expected, "{version} in {range}");
        }
        let deep = format!("{}1", "1-".repeat(100_000));
        assert_eq!(contains(&deep, "[1,2)"), None);
        assert_eq!(contains("1", &format!("[{deep},)")), None);
        assert_eq!(
            contains(&format!("{}1", "1-".repeat(255)), "[1,2)"),
            Some(true)
        );
    }
}
