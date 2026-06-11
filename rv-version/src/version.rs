use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Qualifier, VersionError};

/// A parsed Maven version with comparison semantics matching Maven's `ComparableVersion`.
///
/// Versions are compared using Maven's qualifier ordering (alpha < beta < milestone < rc <
/// snapshot < release < sp) and numeric segment comparison. Trailing zeros and release
/// aliases (ga, final) are normalized for equality.
///
/// # Compatibility target
///
/// This implementation targets **pre-MNG-6240 (pre-Maven-3.6) `ComparableVersion`
/// semantics**. Maven 3.6 (MNG-6240) reworked `ComparableVersion` to make its
/// ordering a total order; the pre-3.6 algorithm reproduced here is **not
/// transitive** for mixed-style qualifier metadata (e.g. the triple
/// `1.0.alpha`, `1.0.final`, `1.0-sp`). A port to the Maven 3.6+ algorithm is
/// planned post-launch. Until then, the known divergence is pinned by the
/// regression test in this module (search for "KNOWN DIVERGENCE") so the port
/// can flip it deliberately rather than by accident.
///
/// # Examples
///
/// ```
/// use rv_version::Version;
///
/// let v1 = Version::parse("1.0-alpha").unwrap();
/// let v2 = Version::parse("1.0").unwrap();
/// assert!(v1 < v2);
/// ```
#[derive(Clone, Debug)]
pub struct Version {
    original: String,
    items: ListItem,
}

impl Version {
    /// Parses a Maven version string.
    ///
    /// # Errors
    ///
    /// Returns an error if the version string is empty or contains only whitespace.
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(VersionError::InvalidVersion(s.to_string()));
        }

        // Reject unresolved Maven property placeholders. Strings like
        // `${revision}` are technically parseable as a "version" and would
        // become a `Soft` pin that never matches a real artifact; the
        // resolver later fails with a misleading "version not found"
        // error. Surfacing this as a distinct variant lets callers tell
        // the user the right thing (interpolate the property first).
        if trimmed.contains("${") {
            return Err(VersionError::UnresolvedProperty(trimmed.to_string()));
        }

        let items = parse_items(trimmed)?;

        Ok(Self {
            original: trimmed.to_string(),
            items,
        })
    }

    /// Returns the original version string as provided to `parse`.
    pub fn as_str(&self) -> &str {
        &self.original
    }

    fn cmp_items(&self, other: &Version) -> Ordering {
        self.items.cmp_list(&other.items)
    }
}

impl FromStr for Version {
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
        self.items == other.items
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_items(other)
    }
}

impl Hash for Version {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.items.hash(state);
    }
}

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.original)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Version::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
enum Item {
    Integer(IntegerItem),
    String(StringItem),
    List(ListItem),
}

impl Item {
    fn cmp_opt(&self, other: Option<&Item>) -> Ordering {
        match self {
            Item::Integer(item) => item.cmp_opt(other),
            Item::String(item) => item.cmp_opt(other),
            Item::List(item) => item.cmp_opt(other),
        }
    }

    fn is_null(&self) -> bool {
        match self {
            Item::Integer(item) => item.is_null(),
            Item::String(item) => item.is_null(),
            Item::List(item) => item.is_null(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct IntegerItem {
    value: String,
}

impl IntegerItem {
    fn new(value: &str) -> Self {
        Self {
            value: normalize_digits(value).into_owned(),
        }
    }

    fn cmp_opt(&self, other: Option<&Item>) -> Ordering {
        match other {
            None => {
                if self.is_null() {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                }
            }
            Some(Item::Integer(other)) => cmp_numeric(&self.value, &other.value),
            Some(Item::String(_) | Item::List(_)) => Ordering::Greater,
        }
    }

    fn is_null(&self) -> bool {
        self.value == "0"
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct StringItem {
    qualifier: Qualifier,
}

impl StringItem {
    fn new(value: &str, followed_by_digit: bool) -> Self {
        Self {
            qualifier: Qualifier::new(value, followed_by_digit),
        }
    }

    fn cmp_opt(&self, other: Option<&Item>) -> Ordering {
        match other {
            None => self.qualifier.cmp(&Qualifier::release()),
            Some(Item::Integer(_)) => Ordering::Less,
            Some(Item::String(other)) => self.qualifier.cmp(&other.qualifier),
            // Maven's `StringItem.compareTo(ListItem) == -1`: a bare qualifier
            // segment sorts BEFORE a hyphen-introduced sub-list. Returning
            // `Greater` here inverts `1.alpha` vs `1-alpha` and every other
            // case where a String segment meets a List segment at the same
            // position.
            Some(Item::List(_)) => Ordering::Less,
        }
    }

    fn is_null(&self) -> bool {
        self.qualifier.is_release()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct ListItem {
    items: Vec<Item>,
}

impl ListItem {
    fn new() -> Self {
        Self { items: Vec::new() }
    }

    fn normalize(&mut self) {
        for item in &mut self.items {
            if let Item::List(list) = item {
                list.normalize();
            }
        }
        while let Some(last) = self.items.last() {
            if last.is_null() {
                self.items.pop();
            } else {
                break;
            }
        }
    }

    fn cmp_list(&self, other: &ListItem) -> Ordering {
        let mut index = 0;
        loop {
            let left = self.items.get(index);
            let right = other.items.get(index);

            if left.is_none() && right.is_none() {
                return Ordering::Equal;
            }

            let result = match left {
                Some(item) => item.cmp_opt(right),
                None => match right {
                    Some(item) => item.cmp_opt(None).reverse(),
                    None => Ordering::Equal,
                },
            };

            if result != Ordering::Equal {
                return result;
            }

            index += 1;
        }
    }

    fn cmp_opt(&self, other: Option<&Item>) -> Ordering {
        match other {
            None => self.cmp_null(),
            Some(Item::List(other)) => self.cmp_list(other),
            // Maven's `ListItem.compareTo(IntegerItem) == -1` (list < integer)
            // but `ListItem.compareTo(StringItem) == +1` (list > string). The
            // two cases need separate arms; collapsing them into a single
            // `Less` arm inverts the string-vs-list ordering relative to Maven.
            Some(Item::Integer(_)) => Ordering::Less,
            Some(Item::String(_)) => Ordering::Greater,
        }
    }

    fn cmp_null(&self) -> Ordering {
        for item in &self.items {
            let result = item.cmp_opt(None);
            if result != Ordering::Equal {
                return result;
            }
        }
        Ordering::Equal
    }

    fn is_null(&self) -> bool {
        self.items.is_empty()
    }
}

fn parse_items(version: &str) -> Result<ListItem, VersionError> {
    let mut root = ListItem::new();
    let mut path: Vec<usize> = Vec::new();

    let mut start = 0usize;
    let mut is_digit = false;

    for (idx, ch) in version.char_indices() {
        if ch == '.' || ch == '-' {
            if idx == start {
                push_item(&mut root, &path, Item::Integer(IntegerItem::new("0")))?;
            } else {
                let segment = &version[start..idx];
                push_item(&mut root, &path, parse_segment(segment, is_digit, false))?;
            }
            start = idx + ch.len_utf8();
            if ch == '-' {
                push_list(&mut root, &mut path)?;
            }
            is_digit = false;
        } else if ch.is_ascii_digit() {
            if !is_digit && idx > start {
                let segment = &version[start..idx];
                push_item(&mut root, &path, parse_segment(segment, false, true))?;
                start = idx;
                // A letter->digit transition opens a sub-list exactly like a
                // `-` separator does (`alpha1` parses as `alpha-1`). Maven has
                // done this in every release; skipping it inverts orderings
                // like `1.0-alpha-2` vs `1.0-alpha1`.
                push_list(&mut root, &mut path)?;
            }
            is_digit = true;
        } else {
            if is_digit && idx > start {
                let segment = &version[start..idx];
                push_item(&mut root, &path, parse_segment(segment, true, false))?;
                start = idx;
                // Digit->letter transition: same sub-list rule as above.
                push_list(&mut root, &mut path)?;
            }
            is_digit = false;
        }
    }

    if start < version.len() {
        let segment = &version[start..];
        push_item(&mut root, &path, parse_segment(segment, is_digit, false))?;
    } else {
        push_item(&mut root, &path, Item::Integer(IntegerItem::new("0")))?;
    }

    root.normalize();
    Ok(root)
}

fn parse_segment(segment: &str, is_digit: bool, followed_by_digit: bool) -> Item {
    if is_digit {
        Item::Integer(IntegerItem::new(segment))
    } else {
        Item::String(StringItem::new(segment, followed_by_digit))
    }
}

fn push_item(root: &mut ListItem, path: &[usize], item: Item) -> Result<(), VersionError> {
    let list = current_list_mut(root, path)?;
    list.items.push(item);
    Ok(())
}

/// Maximum nested list depth tolerated while parsing a Maven version
/// string. Real versions never exceed a couple of levels of grouping;
/// this guards against pathological inputs that would otherwise stack-blow.
const MAX_VERSION_DEPTH: usize = 50;

fn push_list(root: &mut ListItem, path: &mut Vec<usize>) -> Result<(), VersionError> {
    if path.len() >= MAX_VERSION_DEPTH {
        return Err(VersionError::InvalidVersion(
            "version nesting too deep".to_string(),
        ));
    }
    let list = current_list_mut(root, path)?;
    // Maven's `ComparableVersion.parseItem` trims trailing null integer (zero) and
    // null string (release/alias) items from the current list before descending
    // into a hyphen-delimited sub-list. This makes `1.0-SNAPSHOT` equivalent to
    // `1.0.0-SNAPSHOT`, matching the canonical Maven semantics.
    trim_trailing_nulls(list);
    let idx = list.items.len();
    list.items.push(Item::List(ListItem::new()));
    path.push(idx);
    Ok(())
}

/// Drop trailing null integer (zero) and null string (release-alias) items.
/// Empty nested lists are left alone; they represent an open hyphen sub-list
/// that is normalized when parsing finishes.
fn trim_trailing_nulls(list: &mut ListItem) {
    while let Some(last) = list.items.last() {
        match last {
            Item::Integer(item) if item.is_null() => {
                list.items.pop();
            }
            Item::String(item) if item.is_null() => {
                list.items.pop();
            }
            _ => break,
        }
    }
}

fn current_list_mut<'a>(
    root: &'a mut ListItem,
    path: &[usize],
) -> Result<&'a mut ListItem, VersionError> {
    let mut list = root;
    for &idx in path {
        let Item::List(inner) = &mut list.items[idx] else {
            return Err(VersionError::InvalidVersion(format!(
                "internal error: version path contains non-list item at index {idx}"
            )));
        };
        list = inner;
    }
    Ok(list)
}

fn normalize_digits(value: &str) -> Cow<'_, str> {
    let trimmed = value.trim_start_matches('0');
    if trimmed.is_empty() {
        Cow::Borrowed("0")
    } else if trimmed.len() == value.len() {
        Cow::Borrowed(value)
    } else {
        Cow::Owned(trimmed.to_string())
    }
}

/// Compare numeric segments by length first, then lex. Leading zeros are
/// already stripped, so the shorter string is the smaller number.
fn cmp_numeric(a: &str, b: &str) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.cmp(b),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::Version;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn qualifier_ordering() {
        let ordered = [
            "1.0-alpha",
            "1.0-beta",
            "1.0-milestone",
            "1.0-rc",
            "1.0-snapshot",
            "1.0",
            "1.0-sp",
        ];
        for pair in ordered.windows(2) {
            assert!(v(pair[0]) < v(pair[1]));
        }
    }

    #[test]
    fn numeric_segments_compare_numerically() {
        assert!(v("1.0-alpha-1") < v("1.0-alpha-2"));
        assert!(v("1.0-alpha-2") < v("1.0-alpha-10"));
    }

    /// A versioned release-candidate (`rc1`, `rc2`, ...) must order before the
    /// release proper. The `qualifier_ordering` test only covers the unversioned
    /// `rc` form; in practice users almost always tag `rc1`/`rc2`/`-RC1`.
    #[test]
    fn versioned_rc_orders_before_release() {
        assert!(v("1.0-rc1") < v("1.0"));
        assert!(v("2.0-RC1") < v("2.0"));
        assert!(v("1.0-rc1") < v("1.0-rc2"));
        assert!(v("3.0-rc9") < v("3.0-rc10"));
    }

    #[test]
    fn trailing_zeros_are_ignored() {
        assert_eq!(v("1"), v("1.0"));
        assert_eq!(v("1.0"), v("1.0.0"));
        assert_eq!(v("1.0-0"), v("1.0"));
    }

    #[test]
    fn trailing_zeros_trimmed_before_qualifier_sublist() {
        // Maven `ComparableVersion` trims trailing null items in the current list
        // before opening a `-` sub-list. `1.0-SNAPSHOT` must equal `1.0.0-SNAPSHOT`.
        assert_eq!(v("1.0-SNAPSHOT"), v("1.0.0-SNAPSHOT"));
        assert_eq!(v("1.0-rc1"), v("1.0.0-rc1"));
        assert_eq!(v("1.0-alpha1"), v("1.0.0.0-alpha1"));
        // Already-passing case kept as regression guard.
        assert_eq!(v("1.0.0.Final"), v("1.0"));
        // Numeric qualifier sub-list (the sub-list contains an Integer item).
        assert_eq!(v("1.0-1"), v("1.0.0-1"));
        // Chained sub-lists: trim happens at every `-` boundary, not just the top level.
        assert_eq!(v("1.0-foo-bar"), v("1.0.0-foo-bar"));
    }

    #[test]
    fn non_zero_segments_are_not_trimmed_before_sublist() {
        // Only trailing zeros (and release-aliases) are trimmed. A non-zero
        // segment must remain in the current list so that `1.0.1-SNAPSHOT` is
        // NOT considered equal to `1.0-SNAPSHOT`.
        assert_ne!(v("1.0.1-SNAPSHOT"), v("1.0-SNAPSHOT"));
        assert!(v("1.0-SNAPSHOT") < v("1.0.1-SNAPSHOT"));
    }

    #[test]
    fn qualifier_aliases_match_release() {
        assert_eq!(v("1.0-ga"), v("1.0"));
        assert_eq!(v("1.0-final"), v("1.0"));
        assert_eq!(v("1.0-release"), v("1.0"));
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(v("1.0-ALPHA"), v("1.0-alpha"));
    }

    #[test]
    fn preserves_original_case() {
        let version = v("1.0-SNAPSHOT");
        assert_eq!(version.as_str(), "1.0-SNAPSHOT");
        assert_eq!(version.to_string(), "1.0-SNAPSHOT");
    }

    #[test]
    fn unknown_qualifiers_sort_after_known() {
        assert!(v("1.0-sp") < v("1.0-zzz"));
        assert!(v("1.0-zzz") > v("1.0"));
    }

    #[test]
    fn hyphen_has_lower_precedence_than_dot() {
        assert!(v("1-1") < v("1.1"));
        assert!(v("1-1") > v("1"));
    }

    #[test]
    fn numeric_is_greater_than_string() {
        assert!(v("1.0-1") > v("1.0-alpha"));
    }

    #[test]
    fn single_letter_alias_with_digit() {
        assert_eq!(v("1.0-a1"), v("1.0-alpha1"));
    }

    #[test]
    fn leading_zeros_ignored() {
        assert_eq!(v("1.01"), v("1.1"));
    }

    #[test]
    fn jre_and_android_versions() {
        // Common pattern from Guava and other libraries
        assert!(v("31.0") < v("31.0-jre"));
        assert!(v("31.0") < v("31.0-android"));
        // "android" sorts before "jre" alphabetically (both are unknown qualifiers)
        assert!(v("31.0-android") < v("31.0-jre"));

        // Version numbers still take precedence
        assert!(v("31.0-android") < v("32.0"));
        assert!(v("31.0-jre") < v("32.0-android"));
    }

    #[test]
    fn large_version_numbers() {
        // Test hash consistency with very large version numbers
        use std::collections::HashSet;

        let v1 = v("999999999999999999999.0");
        let v2 = v("999999999999999999999.0");
        let v3 = v("999999999999999999998.0");

        // Same versions should be equal
        assert_eq!(v1, v2);
        // Different versions should not be equal
        assert_ne!(v1, v3);

        // Hash should be consistent
        let mut set = HashSet::new();
        set.insert(v1.clone());
        assert!(set.contains(&v2));
        assert!(!set.contains(&v3));

        // Ordering should work correctly
        assert!(v3 < v1);
    }

    #[test]
    fn hash_eq_consistency() {
        // The hash must be consistent with equality:
        // if a == b, then hash(a) == hash(b)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn compute_hash(v: &Version) -> u64 {
            let mut hasher = DefaultHasher::new();
            v.hash(&mut hasher);
            hasher.finish()
        }

        // Versions that are semantically equal must have the same hash
        let pairs = [
            ("1", "1.0"),
            ("1.0", "1.0.0"),
            ("1.0-ga", "1.0"),
            ("1.0-final", "1.0"),
            ("1.0-release", "1.0"),
            ("1.0-ALPHA", "1.0-alpha"),
            ("1.01", "1.1"),
            ("01.0", "1.0"),
            ("1.0-a1", "1.0-alpha1"),
        ];

        for (a, b) in pairs {
            let va = v(a);
            let vb = v(b);
            assert_eq!(va, vb, "Expected {} == {}", a, b);
            assert_eq!(
                compute_hash(&va),
                compute_hash(&vb),
                "Hash mismatch for {} and {}",
                a,
                b
            );
        }
    }

    /// Regression: an unresolved Maven property like `${revision}`
    /// used to parse successfully as a "version" that becomes a `Soft` pin
    /// matching nothing. The resolver then failed with a generic "version
    /// not found" error. Parsing must reject `${...}` outright with a
    /// distinct variant so callers can produce a useful diagnostic.
    #[test]
    fn unresolved_property_is_rejected() {
        use crate::VersionError;

        let err = Version::parse("${revision}").unwrap_err();
        assert!(
            matches!(err, VersionError::UnresolvedProperty(_)),
            "expected UnresolvedProperty, got {err:?}"
        );

        let err = Version::parse("1.0-${qualifier}").unwrap_err();
        assert!(matches!(err, VersionError::UnresolvedProperty(_)));
    }

    /// Regression for the String-vs-List ordering finding: a `StringItem`
    /// sorts BEFORE a `ListItem` (Maven `ComparableVersion` semantics).
    ///
    /// `1.alpha` parses as `[Integer(1), String(alpha)]`; `1-alpha` parses as
    /// `[Integer(1), List([String(alpha)])]`. At the second index we compare
    /// a bare `String` against a `List`, which Maven defines as `string < list`.
    /// An earlier inversion made `1.alpha > 1-alpha`.
    #[test]
    fn string_item_sorts_before_list_item() {
        assert!(v("1.alpha") < v("1-alpha"));
        // Mirror: `ListItem.compareTo(StringItem) == +1`.
        assert!(v("1-alpha") > v("1.alpha"));
    }

    #[test]
    fn hash_works_in_hashset() {
        use std::collections::HashSet;

        let mut set = HashSet::new();

        // Insert various equivalent forms
        set.insert(v("1.0"));

        // All equivalent forms should be found
        assert!(set.contains(&v("1")));
        assert!(set.contains(&v("1.0.0")));
        assert!(set.contains(&v("1.0-ga")));
        assert!(set.contains(&v("1.0-final")));

        // Non-equivalent versions should not be found
        assert!(!set.contains(&v("1.1")));
        assert!(!set.contains(&v("1.0-alpha")));
    }

    // ===================================================================
    // KNOWN DIVERGENCE FROM MAVEN 3.6+ (post-MNG-6240) ComparableVersion
    //
    // This crate targets the pre-Maven-3.6 ComparableVersion algorithm,
    // whose ordering is NOT transitive for mixed-style qualifier metadata.
    // The test below pins the CURRENT (pre-3.6) behavior so a future port
    // to the 3.6+ total order flips it deliberately, not by accident. The
    // assertion documents the divergence, not a claim that the behavior is
    // "correct" under modern Maven. Tracked for post-launch port.
    // ===================================================================

    /// KNOWN DIVERGENCE FROM MAVEN 3.6+ ComparableVersion. Tracked for
    /// post-launch port.
    ///
    /// The classic non-transitive triple. With a transitive order, the chain
    /// `1.0.alpha < 1.0.final < 1.0-sp` would force `1.0.alpha < 1.0-sp`, but
    /// the pre-3.6 algorithm yields `1.0.alpha > 1.0-sp`, so `<` is not a total
    /// order over these three. We assert the current (intransitive) outcome.
    #[test]
    fn known_divergence_non_transitive_alpha_final_sp() {
        // First two comparisons of the chain.
        assert!(v("1.0.alpha") < v("1.0.final"));
        assert!(v("1.0.final") < v("1.0-sp"));
        // Transitivity would imply `1.0.alpha < 1.0-sp`; pre-3.6 yields the
        // opposite. THIS IS THE DIVERGENCE.
        assert!(v("1.0.alpha") > v("1.0-sp"));

        // Anti-symmetry of the pairwise results is still internally consistent.
        assert!(v("1.0.final") > v("1.0.alpha"));
        assert!(v("1.0-sp") > v("1.0.final"));
        assert!(v("1.0-sp") < v("1.0.alpha"));
    }

    /// A digit/letter transition opens a sub-list exactly like a `-`
    /// separator, in every Maven release: `1.0-alpha1` parses identically to
    /// `1.0-alpha-1`, so the trailing numbers compare numerically across the
    /// two spellings.
    #[test]
    fn transition_opens_sublist_like_hyphen() {
        assert_eq!(v("1.0-alpha1"), v("1.0-alpha-1"));
        assert!(v("1.0-alpha1") < v("1.0-alpha-2"));
        assert!(v("1-alpha2") < v("1-alpha-123"));
        assert_eq!(v("1.0alpha1"), v("1.0-alpha1"));
        // Pairs from Maven's own ComparableVersionTest ordered corpus.
        assert!(v("2.1-a") < v("2.1b"));
        assert!(v("1a") == v("1.0.0-a"));
        assert!(v("1a1") == v("1-a1"));
        // A known qualifier still outranks an unknown one across spellings.
        assert!(v("1.0-SNAPSHOT") < v("1x"));
    }

    /// Range endpoints written in the two transition spellings must agree
    /// now that they parse identically; before the sub-list fix this range
    /// failed its lower<upper sanity check.
    #[test]
    fn transition_spellings_interoperate_in_ranges() {
        let req = crate::VersionReq::parse("[1.0-alpha1,1.0-alpha-5)").unwrap();
        assert!(req.matches(&v("1.0-alpha-2")));
        assert!(req.matches(&v("1.0-alpha2")));
        assert!(req.matches(&v("1.0a2")));
        assert!(!req.matches(&v("1.0-alpha-5")));
    }
}
