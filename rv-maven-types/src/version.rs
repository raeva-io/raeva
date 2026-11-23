use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::{MAX_COMPONENT_BYTES, MavenMode, VersionError};

/// A parsed Maven version ordered like maven-resolver's `GenericVersion`, the
/// ordering Maven 3.9 uses for range matching, version listing and conflict
/// mediation.
///
/// `.`, `-` and `_` separate items, and a switch between digits and letters
/// starts a new one. Numbers compare by value. The known qualifiers order
/// `alpha < beta < milestone < rc = cr < snapshot < ga = final = release <
/// sp`, below any other text, and a single `a`, `b` or `m` followed by a digit
/// stands for alpha, beta or milestone. Trailing zeros and release qualifiers
/// do not count, so `1 == 1.0 == 1-ga`, and `1-1 == 1.1`.
///
/// A version that starts with text equals any version whose numbers are all
/// zero, whatever its text, so `alpha == 0 == beta` while `alpha < beta`. The
/// order is not transitive: sort with [`Version::sort_by_key`], which
/// tolerates that, and not with `slice::sort`, which may panic.
///
/// `Ord` is Maven 3.9's order. [`Version::cmp_in`] compares in the order of a
/// [`MavenMode`]: maven-resolver 2.0.24, which Maven 3.10 ships, puts a
/// version that starts with text below one that starts with a number, so
/// `alpha < 0`.
///
/// # Examples
///
/// ```
/// use rv_maven_types::Version;
///
/// let v1 = Version::parse("1.0-alpha").unwrap();
/// let v2 = Version::parse("1.0").unwrap();
/// assert!(v1 < v2);
/// ```
#[derive(Clone, Debug)]
pub struct Version {
    original: String,
    items: Vec<Item>,
}

impl Version {
    /// Parses a Maven version string, without its surrounding whitespace.
    ///
    /// # Errors
    ///
    /// [`VersionError::InvalidVersion`] when it is empty, whitespace only or
    /// longer than [`MAX_COMPONENT_BYTES`] after trimming, and
    /// [`VersionError::UnresolvedProperty`] when it holds a `${`.
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_COMPONENT_BYTES {
            return Err(VersionError::InvalidVersion(s.to_string()));
        }
        // `${revision}` would parse, and then match no artifact.
        if trimmed.contains("${") {
            return Err(VersionError::UnresolvedProperty(trimmed.to_string()));
        }
        Ok(Self {
            original: trimmed.to_string(),
            items: parse_items(trimmed, MavenMode::Maven39),
        })
    }

    /// `s` as Maven's collector reads a version that still holds a `${...}`,
    /// which [`Self::parse`] refuses: compared as written. It names no
    /// artifact. One longer than [`MAX_COMPONENT_BYTES`] is not split into
    /// items, so a crafted POM cannot make it allocate one per separator.
    pub fn unresolved(s: &str) -> Self {
        let trimmed = s.trim();
        Self {
            original: trimmed.to_string(),
            items: if trimmed.len() > MAX_COMPONENT_BYTES {
                Vec::new()
            } else {
                parse_items(trimmed, MavenMode::Maven39)
            },
        }
    }

    /// The version as given to [`Self::parse`], trimmed.
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Sorts `items` ascending by the version `key` gives, keeping equal ones
    /// in their order, with a merge sort, which any comparison satisfies.
    pub fn sort_by_key<T>(items: &mut Vec<T>, key: impl Fn(&T) -> &Version) {
        Self::sort_by_key_in(items, MavenMode::Maven39, key);
    }

    /// [`Self::sort_by_key`] in the order of `mode`.
    pub fn sort_by_key_in<T>(items: &mut Vec<T>, mode: MavenMode, key: impl Fn(&T) -> &Version) {
        fn merge_sort<T>(mut left: Vec<T>, less: &impl Fn(&T, &T) -> bool) -> Vec<T> {
            if left.len() < 2 {
                return left;
            }
            let right = merge_sort(left.split_off(left.len() / 2), less);
            let left = merge_sort(left, less);
            let mut merged = Vec::with_capacity(left.len() + right.len());
            let (mut left, mut right) = (left.into_iter().peekable(), right.into_iter().peekable());
            while let (Some(first), Some(second)) = (left.peek(), right.peek()) {
                let next = if less(second, first) {
                    &mut right
                } else {
                    &mut left
                };
                merged.extend(next.next());
            }
            merged.extend(left.chain(right));
            merged
        }
        let less = |a: &T, b: &T| key(a).cmp_in(key(b), mode).is_lt();
        *items = merge_sort(std::mem::take(items), &less);
    }

    /// `GenericVersion.compareTo` of the maven-resolver that `mode` ships.
    /// Of two ASCII versions, equal in the 3.10 order implies equal in the
    /// 3.9 order, so one `Hash` serves both.
    pub fn cmp_in(&self, other: &Self, mode: MavenMode) -> Ordering {
        if mode == MavenMode::Maven39 {
            return self.cmp(other);
        }
        let (these, those) = (self.items_in(mode), other.items_in(mode));
        let (these, those) = (&these[..], &those[..]);
        if starts_with_text(these) != starts_with_text(those)
            && let (Some(this), Some(that)) = (these.first(), those.first())
        {
            // It compares the first items by kind when one is a number and
            // the other text.
            return this.cmp(that);
        }
        compare(these, those)
    }

    /// The items the maven-resolver of `mode` splits this version into:
    /// 2.0.24 splits one as 1.9 does but outside ASCII.
    fn items_in(&self, mode: MavenMode) -> std::borrow::Cow<'_, [Item]> {
        if mode == MavenMode::Maven310
            && !self.original.is_ascii()
            && self.original.len() <= MAX_COMPONENT_BYTES
        {
            return std::borrow::Cow::Owned(parse_items(&self.original, mode));
        }
        std::borrow::Cow::Borrowed(&self.items)
    }

    /// maven-resolver 1.9's `GenericVersion.hashCode`, which orders the
    /// ranges of a union in its `HashSet`. Java lowers text outside ASCII
    /// by locale, which this does not follow.
    #[cfg(test)]
    pub(crate) fn java_hash(&self) -> i32 {
        self.java_hash_in(MavenMode::Maven39)
    }

    /// The `GenericVersion.hashCode` of the maven-resolver `mode` ships,
    /// from the items it splits this version into, as [`Self::cmp_in`].
    pub(crate) fn java_hash_in(&self, mode: MavenMode) -> i32 {
        let string = |text: &str| {
            (text.encode_utf16()).fold(0i32, |hash, unit| {
                hash.wrapping_mul(31).wrapping_add(i32::from(unit))
            })
        };
        self.items_in(mode).iter().fold(1i32, |hash, item| {
            let (value, kind) = match item {
                Item::Min => (string("min"), 0),
                Item::Qualifier(value) => (i32::from(*value), 2),
                Item::Text(text) => (string(text), 3),
                Item::Number(Number(digits)) if digits.len() < 10 => {
                    (digits.parse().unwrap_or_default(), 4)
                }
                Item::Number(Number(digits)) => (big_integer_hash(digits), 5),
                Item::Max => (string("max"), 8),
            };
            hash.wrapping_mul(31)
                .wrapping_add(value.wrapping_add(kind * 31))
        })
    }

    /// Starts with text, or has no number but zero: equal to `0`.
    fn is_zero(&self) -> bool {
        self.items.first().is_some_and(|item| !item.is_number())
            || (self.items.iter())
                .filter(|item| item.is_number())
                .all(|item| item.cmp_padding().is_eq())
    }
}

impl std::str::FromStr for Version {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Version::parse(s)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.original)
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// `GenericVersion.compareTo`.
impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        compare(&self.items, &other.items)
    }
}

/// The first item is text or a qualifier.
fn starts_with_text(items: &[Item]) -> bool {
    items.first().is_some_and(|item| !item.is_number())
}

fn compare(these: &[Item], those: &[Item]) -> Ordering {
    let mut number = true;
    let mut index = 0;
    loop {
        let (this, that) = match (these.get(index), those.get(index)) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return compare_padding(those, index, None).reverse(),
            (Some(_), None) => return compare_padding(these, index, None),
            (Some(this), Some(that)) => (this, that),
        };
        if this.is_number() != that.is_number() {
            return if this.is_number() == number {
                compare_padding(these, index, Some(number))
            } else {
                compare_padding(those, index, Some(number)).reverse()
            };
        }
        match this.cmp(that) {
            Ordering::Equal => number = this.is_number(),
            rel => return rel,
        }
        index += 1;
    }
}

/// Trimmed item lists compare equal only when they are the same, or when both
/// versions equal `0`.
impl Hash for Version {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if !self.is_zero() {
            self.items.hash(state);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Item {
    Min,
    Qualifier(i8),
    Text(String),
    Number(Number),
    Max,
}

impl Item {
    fn is_number(&self) -> bool {
        matches!(self, Item::Min | Item::Number(_) | Item::Max)
    }

    fn cmp_padding(&self) -> Ordering {
        match self {
            Item::Min => Ordering::Less,
            Item::Qualifier(value) => value.cmp(&0),
            Item::Number(Number(digits)) if digits == "0" => Ordering::Equal,
            Item::Number(_) | Item::Text(_) | Item::Max => Ordering::Greater,
        }
    }
}

/// `BigInteger.hashCode` of `digits`, over its 32-bit words from the most
/// significant.
fn big_integer_hash(digits: &str) -> i32 {
    let mut words: Vec<u32> = Vec::new();
    for digit in digits.bytes().map(|byte| u64::from(byte - b'0')) {
        let mut carry = digit;
        for word in &mut words {
            let next = u64::from(*word) * 10 + carry;
            *word = next as u32;
            carry = next >> 32;
        }
        if carry > 0 {
            words.push(carry as u32);
        }
    }
    (words.iter().rev()).fold(0i32, |hash, word| {
        hash.wrapping_mul(31).wrapping_add(*word as i32)
    })
}

/// Digits without leading zeros, so the longer number is the larger.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Number(String);

impl Ord for Number {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// `GenericVersion.comparePadding`: the first item from `index` on, of the
/// given kind, that differs from the padding.
fn compare_padding(items: &[Item], index: usize, number: Option<bool>) -> Ordering {
    items[index..]
        .iter()
        .filter(|item| number.is_none_or(|number| item.is_number() == number))
        .map(Item::cmp_padding)
        .find(|rel| rel.is_ne())
        .unwrap_or(Ordering::Equal)
}

/// `GenericVersion.parse`, with its `Tokenizer`, as the maven-resolver
/// `mode` ships reads digits and qualifiers. Separators are ASCII.
fn parse_items(version: &str, mode: MavenMode) -> Vec<Item> {
    let mut chars = version.char_indices().peekable();
    let mut items = Vec::new();
    while let Some(&(start, _)) = chars.peek() {
        // -2 before the first character, -1 in text, 0 in leading zeros, 1 in a number.
        let mut state = -2;
        let mut digits = String::new();
        let mut end = version.len();
        let mut before_digit = false;
        while let Some(&(index, ch)) = chars.peek() {
            if matches!(ch, '.' | '-' | '_') {
                end = index;
                chars.next();
                break;
            }
            if let Some(digit) = digit(ch, mode) {
                if state == -1 {
                    end = index;
                    before_digit = true;
                    break;
                }
                state = if state > 0 || digit > 0 { 1 } else { 0 };
                if state > 0 {
                    digits.push(char::from(b'0' + digit));
                }
            } else {
                if state >= 0 {
                    end = index;
                    break;
                }
                state = -1;
            }
            chars.next();
        }
        let last = chars.peek().is_none();
        items.push(if state == -1 {
            text_item(&version[start..end], last, before_digit, mode)
        } else if digits.is_empty() {
            Item::Number(Number("0".to_string()))
        } else {
            Item::Number(Number(digits))
        });
    }
    trim_padding(&mut items);
    items
}

/// The zeros of the BMP decimal digits Java's `Character.digit` reads
/// outside ASCII, each the first of ten.
const DIGIT_ZEROS: [u32; 36] = [
    0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66, 0xDE6,
    0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50,
    0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
];

/// The value of `ch` as a digit: maven-resolver 1.9 takes the decimal
/// digits `Character.digit` reads in a Java `char`, 2.0 the ASCII ones.
fn digit(ch: char, mode: MavenMode) -> Option<u8> {
    if let Some(digit) = ch.to_digit(10) {
        return u8::try_from(digit).ok();
    }
    if mode == MavenMode::Maven310 || ch.is_ascii() {
        return None;
    }
    let code = u32::from(ch);
    let index = DIGIT_ZEROS
        .partition_point(|&zero| zero <= code)
        .checked_sub(1)?;
    u8::try_from(code - DIGIT_ZEROS[index])
        .ok()
        .filter(|digit| *digit < 10)
}

/// A text token: Java lower-cases it, then compares it ignoring case, and
/// maven-resolver 1.9 looks it up among the qualifiers ignoring case, 2.0
/// by its lower case.
fn text_item(token: &str, last: bool, before_digit: bool, mode: MavenMode) -> Item {
    let lower = token.to_lowercase();
    let folded = match token.is_ascii() {
        true => Cow::Borrowed(lower.as_str()),
        false => Cow::Owned(token.chars().map(fold).collect()),
    };
    match &*folded {
        "min" if last => return Item::Min,
        "max" if last => return Item::Max,
        _ => {}
    }
    let name = match mode {
        MavenMode::Maven39 => &*folded,
        MavenMode::Maven310 => lower.as_str(),
    };
    let qualifier = match name {
        "a" if before_digit && token.len() == 1 => -5,
        "b" if before_digit && token.len() == 1 => -4,
        "m" if before_digit && token.len() == 1 => -3,
        "alpha" => -5,
        "beta" => -4,
        "milestone" => -3,
        "cr" | "rc" => -2,
        "snapshot" => -1,
        "ga" | "final" | "release" => 0,
        "sp" => 1,
        _ if token.is_ascii() => return Item::Text(lower),
        _ => return Item::Text(lower.chars().map(fold).collect()),
    };
    Item::Qualifier(qualifier)
}

/// `c` as `String.compareToIgnoreCase` compares it: the lower case of its
/// upper case, each as `Character` maps one character.
fn fold(c: char) -> char {
    fn single(mut mapped: impl Iterator<Item = char>, c: char) -> char {
        match (mapped.next(), mapped.next()) {
            (Some(one), None) => one,
            _ => c,
        }
    }
    if c.is_ascii() {
        return c.to_ascii_lowercase();
    }
    match single(c.to_uppercase(), c) {
        '\u{130}' => 'i',
        upper => single(upper.to_lowercase(), upper),
    }
}

/// `GenericVersion.trimPadding`: drop padding items from the end of each run
/// of numbers or of text, keeping the first item of a run unless nothing
/// follows it, and always the first item.
fn trim_padding(items: &mut Vec<Item>) {
    let mut keep = vec![true; items.len()];
    let mut run = None;
    let mut end = 0;
    let mut tail_dropped = true;
    for i in (1..items.len()).rev() {
        let number = items[i].is_number();
        if run != Some(number) {
            end = i;
            run = Some(number);
        }
        if end == i
            && (tail_dropped || items[i - 1].is_number() == number)
            && items[i].cmp_padding().is_eq()
        {
            keep[i] = false;
            end -= 1;
        } else {
            tail_dropped = false;
        }
    }
    let mut keep = keep.into_iter();
    items.retain(|_| keep.next().unwrap_or(true));
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering::{self, Equal, Greater, Less};
    use std::hash::BuildHasher;

    use super::Version;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn parsing_keeps_the_text_and_refuses_expressions() {
        let version = v(" 1.0-SNAPSHOT ");
        assert_eq!(version.as_str(), "1.0-SNAPSHOT");
        assert_eq!(version.to_string(), "1.0-SNAPSHOT");
        for text in ["${revision}", "1.0-${qualifier}"] {
            assert!(matches!(
                Version::parse(text),
                Err(crate::VersionError::UnresolvedProperty(_))
            ));
        }
        assert!(Version::parse("  ").is_err());
    }

    #[test]
    fn parsing_refuses_versions_over_the_component_limit() {
        let longest = format!("{}1", "1.".repeat(127));
        assert_eq!(v(&format!(" {longest} ")).as_str(), longest);
        for text in [
            "1".repeat(256),
            "1.".repeat(128),
            "1-".repeat(128),
            "1_".repeat(128),
            "1a".repeat(128),
            "é".repeat(128),
            "1.".repeat(100_000),
        ] {
            assert!(matches!(
                Version::parse(&text),
                Err(crate::VersionError::InvalidVersion(value)) if value == text
            ));
        }
    }

    #[test]
    fn an_unresolved_version_over_the_limit_is_not_split() {
        let text = format!("${{x}}{}", ".".repeat(1_000_000));
        let version = Version::unresolved(&text);
        assert_eq!(version.as_str(), text);
        assert!(version.items.is_empty());
        assert!(!Version::unresolved("${x}.1").items.is_empty());
    }

    /// Each row is what `GenericVersionScheme` from maven-resolver 1.9.25,
    /// shipped with Maven 3.9.12, returns. The comment marks rows where
    /// maven-artifact's `ComparableVersion` differs.
    const MAVEN: &[(&str, Ordering, &str)] = &[
        ("1-1", Equal, "1.1"),               // CV <
        ("1.0-1", Equal, "1.0.1"),           // CV <
        ("1.0-1", Less, "1-1"),              // CV ==
        ("1.0_alpha", Less, "1.0"),          // CV >
        ("1.0-final-1", Less, "1.0-sp-1"),   // CV >
        ("1.0-alpha.1", Less, "1.0-alpha2"), // CV >
        ("1.0.0.1", Equal, "1.0.0-1"),       // CV >
        ("2.0-1", Equal, "2.0.1"),           // CV <
        ("1-a", Equal, "1-0.a"),             // CV <
        ("0-alpha", Equal, "alpha"),         // CV >
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
        ("0-alpha", Equal, "alpha2"),
        ("r09", Less, "1.0"),
        ("1.min", Less, "1-alpha"),
        ("1.max", Greater, "1.99"),
        ("1.max", Less, "2"),
        ("1.max.1", Less, "1.99"),
        ("1.min.1", Greater, "1"),
        ("1.0.max", Less, "1.max"),
    ];

    /// A version that starts with text equals one whose numbers are all zero,
    /// and compares by its text against another that starts with text.
    const TEXT_FIRST: &[(&str, Ordering, &str)] = &[
        ("alpha", Equal, "0"),
        ("final", Equal, "0"),
        ("foo", Equal, "0.0.0"),
        ("foo", Equal, "0-bar"),
        ("alpha1", Equal, "0-alpha0"),
        ("alpha", Less, "beta"),
        ("final", Greater, "alpha"),
        ("alpha", Less, "0.1"),
        ("beta", Less, "0-alpha-1"),
        ("r09", Less, "1.0"),
        ("alpha", Greater, "0.min"),
        ("foo", Less, "0.max"),
    ];

    #[test]
    fn text_first_versions_equal_zero() {
        let hasher = std::collections::hash_map::RandomState::new();
        for &(a, expected, b) in TEXT_FIRST {
            assert_eq!(v(a).cmp(&v(b)), expected, "{a} vs {b}");
            assert_eq!(v(b).cmp(&v(a)), expected.reverse(), "{b} vs {a}");
            if expected.is_eq() {
                assert_eq!(hasher.hash_one(v(a)), hasher.hash_one(v(b)), "{a} and {b}");
            }
        }
        // The order is not transitive, which `slice::sort` may panic on.
        let mut corpus: Vec<Version> = [
            "0", "0-a", "0-b", "a", "b", "c", "0-c", "a1", "b2", "0.0-x", "x", "0-y", "1", "1-a",
            "z0", "min", "0.min", "0-b-min", "0-a-5", "ga", "sp", "0.max", "2", "1.5",
        ]
        .into_iter()
        .map(v)
        .collect();
        for _ in 0..4 {
            Version::sort_by_key(&mut corpus, |version| version);
            for pair in corpus.windows(2) {
                let [a, b] = pair else { unreachable!() };
                assert!(a <= b, "{a} and {b} are out of order");
            }
            corpus.rotate_left(7);
        }
    }

    /// Rows where `GenericVersionScheme` from maven-resolver 2.0.24, shipped
    /// with Maven 3.10.0, differs from 1.9.25 (the 3.9 order is in the
    /// comment), and rows it keeps.
    const RESOLVER_2: &[(&str, Ordering, &str)] = &[
        ("alpha", Less, "0"),          // 3.9 ==
        ("final", Less, "0"),          // 3.9 ==
        ("foo", Less, "0.0.0"),        // 3.9 ==
        ("foo", Less, "0-bar"),        // 3.9 ==
        ("alpha1", Less, "0-alpha0"),  // 3.9 ==
        ("alpha", Less, "0.min"),      // 3.9 >
        ("ga", Less, "0"),             // 3.9 ==
        ("sp", Less, "0"),             // 3.9 ==
        ("0-alpha", Greater, "alpha"), // 3.9 ==
        ("alpha2", Less, "0-alpha"),   // 3.9 ==
        ("a1", Less, "0"),             // 3.9 ==
        ("snapshot", Less, "0"),       // 3.9 ==
        ("alpha", Less, "beta"),
        ("final", Greater, "alpha"),
        ("alpha", Less, "0.1"),
        ("beta", Less, "0-alpha-1"),
        ("r09", Less, "1.0"),
        ("foo", Less, "0.max"),
        ("min", Less, "alpha"),
        ("max", Greater, "foo"),
        ("min", Less, "0"),
        ("1", Greater, "alpha"),
        ("foo", Equal, "FOO"),
        ("1.0", Equal, "1"),
    ];

    #[test]
    fn orders_like_maven_resolver_2_in_the_310_mode() {
        use crate::MavenMode::Maven310;
        for &(a, expected, b) in RESOLVER_2 {
            assert_eq!(v(a).cmp_in(&v(b), Maven310), expected, "{a} vs {b}");
            assert_eq!(
                v(b).cmp_in(&v(a), Maven310),
                expected.reverse(),
                "{b} vs {a}"
            );
        }
        for &(a, expected, b) in MAVEN {
            if !super::starts_with_text(&v(a).items) && !super::starts_with_text(&v(b).items) {
                assert_eq!(v(a).cmp_in(&v(b), Maven310), expected, "{a} vs {b}");
            }
        }
        let mut corpus: Vec<Version> = ["1", "alpha", "0", "beta", "0.1", "a1", "min", "foo"]
            .into_iter()
            .map(v)
            .collect();
        Version::sort_by_key_in(&mut corpus, Maven310, |version| version);
        let sorted: Vec<&str> = corpus.iter().map(Version::as_str).collect();
        assert_eq!(
            sorted,
            ["min", "alpha", "a1", "beta", "foo", "0", "0.1", "1"]
        );
        for pair in corpus.windows(2) {
            assert!(pair[0].cmp_in(&pair[1], Maven310).is_le(), "{pair:?}");
        }
    }

    /// Rows outside ASCII, where maven-resolver 1.9.25 reads more decimal
    /// digits and qualifiers than 2.0.24 does: the order of each, 3.9 first.
    const UNICODE: &[(&str, Ordering, Ordering, &str)] = &[
        ("١", Equal, Less, "1"),
        ("1٠", Equal, Less, "10"),
        ("٠١", Equal, Less, "1"),
        ("１.１", Equal, Less, "1.1"),
        ("𝟙", Less, Less, "1"),
        ("1.0-ſ", Equal, Equal, "1.0-s"),
        ("1.0-ſ", Less, Less, "1.0-t"),
        ("1-ſnapshot", Equal, Greater, "1-snapshot"),
        ("1-ſnapshot", Less, Greater, "1"),
        ("1-ı", Equal, Equal, "1-i"),
        ("1-İ", Greater, Greater, "1-i"),
        ("1-mİlestone", Equal, Greater, "1-milestone"),
        ("1-MİN", Equal, Equal, "1-min"),
        ("1.ς", Equal, Equal, "1.σ"),
        ("1.ß", Greater, Greater, "1.ss"),
    ];

    #[test]
    fn orders_unicode_digits_and_case_as_each_resolver() {
        use crate::MavenMode::Maven310;
        let hasher = std::collections::hash_map::RandomState::new();
        for &(a, maven39, maven310, b) in UNICODE {
            assert_eq!(v(a).cmp(&v(b)), maven39, "{a} vs {b}");
            assert_eq!(v(b).cmp(&v(a)), maven39.reverse(), "{b} vs {a}");
            assert_eq!(v(a).cmp_in(&v(b), Maven310), maven310, "{a} vs {b}");
            assert_eq!(
                v(b).cmp_in(&v(a), Maven310),
                maven310.reverse(),
                "{b} vs {a}"
            );
            if maven39.is_eq() {
                assert_eq!(hasher.hash_one(v(a)), hasher.hash_one(v(b)), "{a} and {b}");
            }
        }
    }

    #[test]
    fn orders_like_maven_resolver() {
        let hasher = std::collections::hash_map::RandomState::new();
        for &(a, expected, b) in MAVEN {
            assert_eq!(v(a).cmp(&v(b)), expected, "{a} vs {b}");
            assert_eq!(v(b).cmp(&v(a)), expected.reverse(), "{b} vs {a}");
            if expected.is_eq() {
                assert_eq!(hasher.hash_one(v(a)), hasher.hash_one(v(b)), "{a} and {b}");
            }
        }
    }
}
