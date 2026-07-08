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
/// This implementation targets **current Apache Maven `ComparableVersion`
/// semantics** (Maven 3.9.x), including the transitivity/normalization fixes
/// [MNG-6524], [MNG-6964], and [MNG-7644]. In particular a string qualifier that
/// is attached with a `.` (or directly, as in `1.0.alpha` or `1.0.0RC1`) is
/// treated exactly like a `-`-introduced qualifier (`1.0-alpha`): it is parsed
/// into its own sub-list rather than left as a bare item in the parent list.
/// This is the piece that makes the ordering a genuine, transitive total order
/// (e.g. `1.0.alpha < 1.0 < 1.0-sp` and, transitively, `1.0.alpha < 1.0-sp`).
/// The transitivity guarantee is exercised by the property test in this module
/// (search for `transitivity`).
///
/// [MNG-6524]: https://issues.apache.org/jira/browse/MNG-6524
/// [MNG-6964]: https://issues.apache.org/jira/browse/MNG-6964
/// [MNG-7644]: https://issues.apache.org/jira/browse/MNG-7644
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
            // item sorts BEFORE a sub-list at the same position (e.g. `1-a` vs
            // `1-0.a`, which parse as `[1,[a]]` and `[1,[[a]]]`). Returning
            // `Greater` here would invert that ordering relative to Maven.
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
            // Maven's `ListItem.compareTo(IntegerItem) == -1` (list < integer,
            // "1-1 < 1.0.x") but `ListItem.compareTo(StringItem) == +1` (list >
            // string, "1-1 > 1-sp"). The two cases need separate arms;
            // collapsing them into a single `Less` arm would invert the
            // string-vs-list ordering relative to Maven.
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
                // MNG-7644: a letter run that is glued to a following digit
                // (`X1`) is treated exactly like the `-`-introduced form `-X1`.
                // Maven puts the qualifier `X` into its own sub-list first when
                // the current list is not empty, so `1.0.0.rc1` (dot-attached)
                // parses identically to `1.0.0-rc1` (hyphen-attached). Without
                // this, `1.0.0.rc1` would keep `rc` as a bare item in the parent
                // list and mis-order against `1.0.0-rc2`.
                if !current_list_is_empty(&root, &path)? {
                    push_list(&mut root, &mut path)?;
                }
                push_item(&mut root, &path, parse_segment(segment, false, true))?;
                start = idx;
                // The digit run that follows opens its own sub-list, exactly like
                // a `-` separator does (`alpha1` parses as `alpha-1`).
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
        // MNG-7644: a trailing qualifier attached with a `.` (or glued directly,
        // as in `1.0.alpha` or `2.0.a`) is treated like the `-`-introduced form
        // (`1.0-alpha`). When the current list already has items, the qualifier
        // goes into its own sub-list so that `2.0.alpha` parses identically to
        // `2-alpha`. This is what makes the order transitive: the qualifier is
        // always compared list-against-list, never bare-item-against-list.
        if !is_digit && !current_list_is_empty(&root, &path)? {
            push_list(&mut root, &mut path)?;
        }
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

/// Whether the list at `path` currently holds no items. Checked *before*
/// opening a sub-list (i.e. before any trailing-null trimming), matching
/// Maven's raw `!list.isEmpty()` guard in the MNG-7644 handling: a qualifier
/// only gets its own sub-list when the list it would join is non-empty.
fn current_list_is_empty(root: &ListItem, path: &[usize]) -> Result<bool, VersionError> {
    let mut list = root;
    for &idx in path {
        let Item::List(inner) = &list.items[idx] else {
            return Err(VersionError::InvalidVersion(format!(
                "internal error: version path contains non-list item at index {idx}"
            )));
        };
        list = inner;
    }
    Ok(list.items.is_empty())
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

    /// A dot-attached qualifier parses identically to the hyphen-attached form
    /// (Maven MNG-7644): `1.alpha` and `1-alpha` both parse as
    /// `[Integer(1), List([String(alpha)])]`, so they are equal. (Before the
    /// MNG-7644 fix `1.alpha` kept `alpha` as a bare `StringItem` in the parent
    /// list and sorted strictly below `1-alpha`.)
    #[test]
    fn dot_attached_qualifier_equals_hyphen_attached() {
        assert_eq!(v("1.alpha"), v("1-alpha"));
        assert_eq!(v("2.0.alpha"), v("2-alpha"));
        assert_eq!(v("1.0.0.RC1"), v("1.0.0-rc1"));
    }

    /// A `StringItem` still sorts BEFORE a `ListItem` at the same position
    /// (Maven `StringItem.compareTo(ListItem) == -1`). This arm is exercised by
    /// structures where a bare qualifier meets a sub-list, e.g. `1-a`
    /// (`[1, [a]]`) vs `1-0.a` (`[1, [[a]]]`): at the sub-list's first index a
    /// bare `String(a)` is compared against a `List([a])`.
    #[test]
    fn string_item_sorts_before_list_item() {
        assert!(v("1-a") < v("1-0.a"));
        // Mirror: `ListItem.compareTo(StringItem) == +1`.
        assert!(v("1-0.a") > v("1-a"));
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

    /// The classic non-transitive triple, now transitive under the MNG-7644
    /// parse fix. Before the fix `1.0.alpha` kept `alpha` as a bare item glued
    /// to the trailing `0`, so it compared `Integer(0)`-against-`List` and
    /// sorted ABOVE `1.0-sp` even though `1.0.alpha < 1.0 < 1.0-sp`. Now
    /// `1.0.alpha` parses as `[1, [alpha]]` and the chain is consistent.
    #[test]
    fn alpha_final_sp_triple_is_transitive() {
        // `1.0.final` == `1.0` == `1` (final is a release alias, trailing zeros
        // trimmed), so the middle of the chain is the plain release.
        assert_eq!(v("1.0.final"), v("1.0"));

        assert!(v("1.0.alpha") < v("1.0.final"));
        assert!(v("1.0.final") < v("1.0-sp"));
        // Transitivity now holds: alpha < final < sp implies alpha < sp.
        assert!(v("1.0.alpha") < v("1.0-sp"));

        // Anti-symmetry.
        assert!(v("1.0.final") > v("1.0.alpha"));
        assert!(v("1.0-sp") > v("1.0.final"));
        assert!(v("1.0-sp") > v("1.0.alpha"));
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

    // ===================================================================
    // Differential tests against Apache Maven `ComparableVersion`
    // (maven-artifact 3.9.x). Every expectation below is taken verbatim
    // from Maven's own `ComparableVersionTest`, so this crate's ordering is
    // pinned to the reference implementation's behavior.
    // ===================================================================

    /// Assert that `versions` is strictly increasing under `<` for EVERY pair
    /// `i < j` (not just adjacent pairs), plus antisymmetry of `>`. This mirrors
    /// Maven's `checkVersionsOrder(String[])`, and an all-pairs strict order is
    /// exactly a transitive total order over the list.
    fn assert_strictly_increasing_all_pairs(versions: &[&str]) {
        let parsed: Vec<Version> = versions.iter().map(|s| v(s)).collect();
        for i in 0..parsed.len() {
            for j in (i + 1)..parsed.len() {
                assert!(
                    parsed[i] < parsed[j],
                    "expected {} < {}",
                    versions[i],
                    versions[j]
                );
                assert!(
                    parsed[j] > parsed[i],
                    "expected {} > {}",
                    versions[j],
                    versions[i]
                );
            }
        }
    }

    /// Maven `VERSIONS_QUALIFIER` ordered corpus (testVersionsQualifier).
    #[test]
    fn maven_qualifier_corpus_is_ordered() {
        assert_strictly_increasing_all_pairs(&[
            "1-alpha2snapshot",
            "1-alpha2",
            "1-alpha-123",
            "1-beta-2",
            "1-beta123",
            "1-m2",
            "1-m11",
            "1-rc",
            "1-cr2",
            "1-rc123",
            "1-SNAPSHOT",
            "1",
            "1-sp",
            "1-sp2",
            "1-sp123",
            "1-abc",
            "1-def",
            "1-pom-1",
            "1-1-snapshot",
            "1-1",
            "1-2",
            "1-123",
        ]);
    }

    /// Maven `VERSIONS_NUMBER` ordered corpus (testVersionsNumber). Includes the
    /// dot-attached qualifier forms (`2.0.a`, `11.a2`, `11.a`) that only order
    /// correctly with the MNG-7644 parse fix.
    #[test]
    fn maven_number_corpus_is_ordered() {
        assert_strictly_increasing_all_pairs(&[
            "2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1",
            "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11",
            "11", "11.a", "11b", "11c", "11m",
        ]);
    }

    /// Maven `testVersionComparing` pairs.
    #[test]
    fn maven_version_comparing_pairs() {
        let less_pairs = [
            ("1", "2"),
            ("1.5", "2"),
            ("1", "2.5"),
            ("1.0", "1.1"),
            ("1.1", "1.2"),
            ("1.0.0", "1.1"),
            ("1.0.1", "1.1"),
            ("1.1", "1.2.0"),
            ("1.0-alpha-1", "1.0"),
            ("1.0-alpha-1", "1.0-alpha-2"),
            ("1.0-alpha-1", "1.0-beta-1"),
            ("1.0-beta-1", "1.0-SNAPSHOT"),
            ("1.0-SNAPSHOT", "1.0"),
            ("1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"),
            ("1.0", "1.0-1"),
            ("1.0-1", "1.0-2"),
            ("1.0.0", "1.0-1"),
            ("2.0-1", "2.0.1"),
            ("2.0.1-klm", "2.0.1-lmn"),
            ("2.0.1", "2.0.1-xyz"),
            ("2.0.1", "2.0.1-123"),
            ("2.0.1-xyz", "2.0.1-123"),
        ];
        for (a, b) in less_pairs {
            assert!(v(a) < v(b), "expected {a} < {b}");
            assert!(v(b) > v(a), "expected {b} > {a}");
        }
    }

    /// Maven `checkVersionsEqual` corpus (testVersionsEqual + testVersionsEqualNumber
    /// + testVersionsEqualQualifier) plus the case-insensitivity assertions.
    #[test]
    fn maven_equal_pairs() {
        let equal_pairs = [
            ("1", "1.0"),
            ("1", "1.0.0"),
            ("1.0", "1.0.0"),
            ("1", "1-0"),
            ("1", "1.0-0"),
            ("1.0", "1.0-0"),
            // no separator between number and qualifier
            ("1a", "1-a"),
            ("1a", "1.0-a"),
            ("1a", "1.0.0-a"),
            ("1.0a", "1-a"),
            ("1.0.0a", "1-a"),
            ("1x", "1-x"),
            ("1x", "1.0-x"),
            ("1x", "1.0.0-x"),
            ("1.0x", "1-x"),
            ("1.0.0x", "1-x"),
            // aliases
            ("1ga", "1"),
            ("1release", "1"),
            ("1final", "1"),
            ("1cr", "1rc"),
            // special "aliases" a, b and m for alpha, beta and milestone
            ("1a1", "1-alpha-1"),
            ("1b2", "1-beta-2"),
            ("1m3", "1-milestone-3"),
            // case-insensitive
            ("1X", "1x"),
            ("1A", "1a"),
            ("1B", "1b"),
            ("1M", "1m"),
            ("1Ga", "1"),
            ("1GA", "1"),
            ("1RELEASE", "1"),
            ("1RELeaSE", "1"),
            ("1Final", "1"),
            ("1FINAL", "1"),
            ("1Cr", "1Rc"),
            ("1m3", "1Milestone3"),
            ("1m3", "1MILESTONE3"),
        ];
        for (a, b) in equal_pairs {
            assert_eq!(v(a), v(b), "expected {a} == {b}");
            // Hash must agree with equality.
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut ha = DefaultHasher::new();
            let mut hb = DefaultHasher::new();
            v(a).hash(&mut ha);
            v(b).hash(&mut hb);
            assert_eq!(ha.finish(), hb.finish(), "hash mismatch for {a} and {b}");
        }
    }

    /// Maven MNG-5568: `6.1.0rc3 < 6.1.0` and `6.1.0rc3 < 6.1H.5-beta < ...`
    /// with the transitive consequence `6.1.0 < 6.1H.5-beta`.
    #[test]
    fn mng5568() {
        let (a, b, c) = ("6.1.0", "6.1.0rc3", "6.1H.5-beta");
        assert!(v(b) < v(a));
        assert!(v(b) < v(c));
        assert!(v(a) < v(c));
    }

    /// Maven MNG-6572: large-magnitude numeric segments order by value.
    #[test]
    fn mng6572() {
        let a = "20190126.230843";
        let b = "1234567890.12345";
        let c = "123456789012345.1H.5-beta";
        let d = "12345678901234567890.1H.5-beta";
        assert!(v(a) < v(b));
        assert!(v(b) < v(c));
        assert!(v(a) < v(c));
        assert!(v(c) < v(d));
        assert!(v(b) < v(d));
        assert!(v(a) < v(d));
    }

    /// Maven MNG-6964: qualifiers that start with `-0.` used to make `A == C` and
    /// `B == C` while `A < B` (a non-transitive triple). They must all order.
    #[test]
    fn mng6964() {
        let (a, b, c) = ("1-0.alpha", "1-0.beta", "1");
        assert!(v(a) < v(c));
        assert!(v(b) < v(c));
        assert!(v(a) < v(b));
    }

    /// Deliberate Maven parity, NOT a bug: Apache Maven's `ComparableVersion`
    /// (through 3.9.x) is still not a perfect total order for the pathological
    /// `-0.<qualifier>` form. `1-0.alpha` normalizes to a doubly-nested list
    /// `[1, [[alpha]]]` (the leading `0` is trimmed), so at the second position
    /// it is compared list-against-list, and its inner `[alpha]` meets `sp`'s
    /// bare `String(sp)` as `List > String`. The result is the intransitive
    /// chain `1-0.alpha < 1 < 1-sp` with `1-0.alpha > 1-sp`.
    ///
    /// We reproduce Maven exactly here rather than "repairing" the order:
    /// diverging would mis-resolve these versions relative to real Maven, which
    /// is worse than mirroring Maven's own (rare, pathological) quirk. Realistic
    /// versions never hit this shape; `total_order_is_transitive` guards the
    /// forms that actually occur.
    #[test]
    fn residual_maven_non_total_order_for_nested_zero_qualifier() {
        assert!(v("1-0.alpha") < v("1"));
        assert!(v("1") < v("1-sp"));
        // Maven 3.9.x yields this; a repaired total order would flip it.
        assert!(v("1-0.alpha") > v("1-sp"));
        // The `.`/`-` leading-zero spellings still agree with each other.
        assert_eq!(v("1-0.alpha"), v("1.0-0.alpha"));
    }

    /// Maven MNG-7644: `1.0.0.X1 < 1.0.0-X2` for any string X, and
    /// `2.0.X == 2-X == 2.0.0.X`. This is the fix at the heart of this change.
    #[test]
    fn mng7644() {
        for x in [
            "abc",
            "alpha",
            "a",
            "beta",
            "b",
            "def",
            "milestone",
            "m",
            "RC",
        ] {
            assert!(
                v(&format!("1.0.0.{x}1")) < v(&format!("1.0.0-{x}2")),
                "expected 1.0.0.{x}1 < 1.0.0-{x}2"
            );
            assert_eq!(
                v(&format!("2-{x}")),
                v(&format!("2.0.{x}")),
                "expected 2-{x} == 2.0.{x}"
            );
            assert_eq!(
                v(&format!("2-{x}")),
                v(&format!("2.0.0.{x}")),
                "expected 2-{x} == 2.0.0.{x}"
            );
            assert_eq!(
                v(&format!("2.0.{x}")),
                v(&format!("2.0.0.{x}")),
                "expected 2.0.{x} == 2.0.0.{x}"
            );
        }
    }

    /// The core regression guard: the comparator induces a genuine transitive
    /// total order. Over a mixed corpus (releases, snapshots, every qualifier
    /// class, SPs, unknown qualifiers, and both `-` and `.`/glued transition
    /// spellings, including the shapes that broke before MNG-7644) verify, for
    /// every triple, that ordering is antisymmetric, transitive, and consistent
    /// with equality — the properties `Ord` requires and that a corrupt
    /// comparator would violate.
    #[test]
    fn total_order_is_transitive() {
        use std::cmp::Ordering;

        let corpus = [
            "0.9",
            "1.0-alpha2snapshot",
            "1.0-alpha",
            "1.0.alpha",
            "1.0-alpha-1",
            "1.0-alpha1",
            "1.0-alpha-1-SNAPSHOT",
            "1.0-beta",
            "1.0-milestone",
            "1.0-milestone-2",
            "1.0-rc",
            "1.0-rc1",
            "1.0-cr1",
            "1.0-snapshot",
            "1.0-SNAPSHOT",
            "1",
            "1.0",
            "1.0.0",
            "1.0.final",
            "1.0-ga",
            "1.0-sp",
            "1.0-sp1",
            "1.0-a",
            "1.0-abc",
            "1.0-1",
            "1.0-2",
            "1.0.0.rc1",
            "1.0.0-rc2",
            "1.0.1",
            "1.1",
            "2-alpha",
            "2.0.alpha",
            "2.0",
        ];
        let parsed: Vec<Version> = corpus.iter().map(|s| v(s)).collect();

        let n = parsed.len();
        // Reflexivity + antisymmetry + equality/hash consistency.
        for i in 0..n {
            assert_eq!(parsed[i].cmp(&parsed[i]), Ordering::Equal);
            for j in 0..n {
                assert_eq!(
                    parsed[i].cmp(&parsed[j]),
                    parsed[j].cmp(&parsed[i]).reverse(),
                    "antisymmetry violated for {} vs {}",
                    corpus[i],
                    corpus[j]
                );
                if parsed[i] == parsed[j] {
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let (mut hi, mut hj) = (DefaultHasher::new(), DefaultHasher::new());
                    parsed[i].hash(&mut hi);
                    parsed[j].hash(&mut hj);
                    assert_eq!(
                        hi.finish(),
                        hj.finish(),
                        "equal versions {} and {} must hash the same",
                        corpus[i],
                        corpus[j]
                    );
                }
            }
        }

        // Transitivity of `<`, and equality-consistency: for every triple,
        // a < b && b < c => a < c, and a == b => cmp(a, c) == cmp(b, c).
        for i in 0..n {
            for j in 0..n {
                for k in 0..n {
                    if parsed[i] < parsed[j] && parsed[j] < parsed[k] {
                        assert!(
                            parsed[i] < parsed[k],
                            "transitivity violated: {} < {} < {} but not {} < {}",
                            corpus[i],
                            corpus[j],
                            corpus[k],
                            corpus[i],
                            corpus[k]
                        );
                    }
                    if parsed[i] == parsed[j] {
                        assert_eq!(
                            parsed[i].cmp(&parsed[k]),
                            parsed[j].cmp(&parsed[k]),
                            "equality inconsistency: {} == {} but they order differently vs {}",
                            corpus[i],
                            corpus[j],
                            corpus[k]
                        );
                    }
                }
            }
        }
    }
}
