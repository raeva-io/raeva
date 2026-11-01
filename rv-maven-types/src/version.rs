use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::VersionError;

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
    /// [`VersionError::InvalidVersion`] when it is empty or whitespace only,
    /// and [`VersionError::UnresolvedProperty`] when it holds a `${`.
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(VersionError::InvalidVersion(s.to_string()));
        }
        // `${revision}` would parse, and then match no artifact.
        if trimmed.contains("${") {
            return Err(VersionError::UnresolvedProperty(trimmed.to_string()));
        }
        Ok(Self {
            original: trimmed.to_string(),
            items: parse_items(trimmed),
        })
    }

    /// The version as given to [`Self::parse`], trimmed.
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Sorts `items` ascending by the version `key` gives, keeping equal ones
    /// in their order, with a merge sort, which any comparison satisfies.
    pub fn sort_by_key<T>(items: &mut Vec<T>, key: impl Fn(&T) -> &Version) {
        fn merge_sort<T>(mut left: Vec<T>, key: &impl Fn(&T) -> &Version) -> Vec<T> {
            if left.len() < 2 {
                return left;
            }
            let right = merge_sort(left.split_off(left.len() / 2), key);
            let left = merge_sort(left, key);
            let mut merged = Vec::with_capacity(left.len() + right.len());
            let (mut left, mut right) = (left.into_iter().peekable(), right.into_iter().peekable());
            while let (Some(first), Some(second)) = (left.peek(), right.peek()) {
                let next = if key(second) < key(first) {
                    &mut right
                } else {
                    &mut left
                };
                merged.extend(next.next());
            }
            merged.extend(left.chain(right));
            merged
        }
        *items = merge_sort(std::mem::take(items), &key);
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
        let (these, those) = (&self.items, &other.items);
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

/// `GenericVersion.parse`, with its `Tokenizer`. Separators and digits are
/// ASCII, so walking bytes splits only between characters.
fn parse_items(version: &str) -> Vec<Item> {
    let chars = version.as_bytes();
    let mut items = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        // -2 before the first character, -1 in text, 0 in leading zeros, 1 in a number.
        let mut state = -2;
        let mut start = index;
        let mut end = chars.len();
        let mut before_digit = false;
        while index < chars.len() {
            let ch = chars[index];
            if matches!(ch, b'.' | b'-' | b'_') {
                end = index;
                index += 1;
                break;
            }
            if ch.is_ascii_digit() {
                if state == -1 {
                    end = index;
                    before_digit = true;
                    break;
                }
                if state == 0 {
                    start += 1;
                }
                state = if state > 0 || ch != b'0' { 1 } else { 0 };
            } else {
                if state >= 0 {
                    end = index;
                    break;
                }
                state = -1;
            }
            index += 1;
        }
        let token = &version[start..end];
        items.push(if token.is_empty() {
            Item::Number(Number("0".to_string()))
        } else if state >= 0 {
            Item::Number(Number(token.to_string()))
        } else {
            text_item(token, index >= chars.len(), before_digit)
        });
    }
    trim_padding(&mut items);
    items
}

fn text_item(token: &str, last: bool, before_digit: bool) -> Item {
    let token = token.to_lowercase();
    let qualifier = match token.as_str() {
        "min" if last => return Item::Min,
        "max" if last => return Item::Max,
        "a" if before_digit => -5,
        "b" if before_digit => -4,
        "m" if before_digit => -3,
        "alpha" => -5,
        "beta" => -4,
        "milestone" => -3,
        "cr" | "rc" => -2,
        "snapshot" => -1,
        "ga" | "final" | "release" => 0,
        "sp" => 1,
        _ => return Item::Text(token),
    };
    Item::Qualifier(qualifier)
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
