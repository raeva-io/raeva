use std::borrow::Cow;
use std::cmp::Ordering;

/// Maven qualifier ordering.
///
/// Pre-release qualifiers come before "" (release), post-release qualifiers come after.
/// Unknown qualifiers sort after all known qualifiers, using lexical ordering among themselves.
///
/// Order:
/// - Pre-release: alpha < beta < milestone < rc < snapshot
/// - Release: "" (or aliases: ga, final, release)
/// - Post-release: sp
///
/// NOTE: "jre" and "android" are intentionally omitted from the known qualifier list.
/// Maven treats them as unknown qualifiers with lexical ordering, not as fixed post-release
/// qualifiers. Treating them as known with a fixed order would diverge from Maven's behavior.
/// For example, Guava "31.0-jre" vs "31.0-android" uses lexical ordering in Maven
/// ("android" < "jre" lexically), not a fixed position.
const QUALIFIER_ORDER: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Qualifier {
    value: String,
}

impl Qualifier {
    pub fn new(value: &str, followed_by_digit: bool) -> Self {
        let normalized = normalize_qualifier(value, followed_by_digit);
        Self {
            value: normalized.into_owned(),
        }
    }

    pub fn is_release(&self) -> bool {
        self.value.is_empty()
    }

    pub fn release() -> Self {
        Self {
            value: String::new(),
        }
    }
}

fn normalize_qualifier(value: &str, followed_by_digit: bool) -> Cow<'static, str> {
    let trimmed = value.trim();

    if let Some(ch) = trimmed
        .chars()
        .next()
        .filter(|_| followed_by_digit && trimmed.len() == 1)
    {
        match ch.to_ascii_lowercase() {
            'a' => return Cow::Borrowed("alpha"),
            'b' => return Cow::Borrowed("beta"),
            'm' => return Cow::Borrowed("milestone"),
            _ => {}
        }
    }

    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "cr" => Cow::Borrowed("rc"),
        "ga" | "final" | "release" => Cow::Borrowed(""),
        _ => Cow::Owned(lower),
    }
}

fn qualifier_index(q: &str) -> Option<usize> {
    QUALIFIER_ORDER.iter().position(|&v| v == q)
}

impl Ord for Qualifier {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = self.value.as_str();
        let b = other.value.as_str();
        match (qualifier_index(a), qualifier_index(b)) {
            (Some(ai), Some(bi)) => ai.cmp(&bi),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => a.cmp(b),
        }
    }
}

impl PartialOrd for Qualifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Qualifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::Qualifier;

    fn q(v: &str, followed: bool) -> Qualifier {
        Qualifier::new(v, followed)
    }

    #[test]
    fn qualifier_ordering() {
        assert!(q("alpha", false) < q("beta", false));
        assert!(q("beta", false) < q("milestone", false));
        assert!(q("milestone", false) < q("rc", false));
        assert!(q("rc", false) < q("snapshot", false));
        assert!(q("snapshot", false) < q("", false));
        assert!(q("", false) < q("sp", false));
    }

    #[test]
    fn qualifier_aliases() {
        assert_eq!(q("ga", false), q("", false));
        assert_eq!(q("final", false), q("", false));
        assert_eq!(q("release", false), q("", false));
        assert_eq!(q("cr", false), q("rc", false));
    }

    #[test]
    fn single_letter_alias_with_digit() {
        assert_eq!(q("a", true), q("alpha", false));
        assert_eq!(q("b", true), q("beta", false));
        assert_eq!(q("m", true), q("milestone", false));
        assert_ne!(q("a", false), q("alpha", false));
    }

    #[test]
    fn unknown_qualifiers_sort_after_known() {
        assert!(q("sp", false) < q("foo", false));
        assert!(q("bar", false) < q("foo", false));
    }

    #[test]
    fn jre_and_android_qualifiers() {
        // jre and android are treated as unknown qualifiers (Maven-compatible behavior).
        // Unknown qualifiers sort after all known qualifiers, using lexical order among
        // themselves. "android" < "jre" lexically, matching Maven's behavior.
        assert!(q("", false) < q("jre", false));
        assert!(q("", false) < q("android", false));
        assert!(q("sp", false) < q("jre", false));
        // Lexical ordering: "android" < "jre"
        assert!(q("android", false) < q("jre", false));
    }

    #[test]
    fn jre_and_android_case_insensitive() {
        // Should be case insensitive (normalization to lowercase)
        assert_eq!(q("JRE", false), q("jre", false));
        assert_eq!(q("ANDROID", false), q("android", false));
        assert_eq!(q("Jre", false), q("jre", false));
        assert_eq!(q("Android", false), q("android", false));
    }
}
