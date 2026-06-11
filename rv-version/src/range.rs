use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Version, VersionError};

/// A bounded Maven version range such as `[1.0,2.0)` or `[1.5]`. Fields are
/// crate-private so the representation can evolve; use [`Self::parse`],
/// [`Self::matches`], and the public accessors.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VersionRange {
    pub(crate) lower: Option<Version>,
    pub(crate) upper: Option<Version>,
    pub(crate) include_lower: bool,
    pub(crate) include_upper: bool,
}

impl VersionRange {
    /// Parses a Maven version range string.
    ///
    /// Supported formats:
    /// - `[1.0,2.0]` - inclusive range (1.0 <= v <= 2.0)
    /// - `[1.0,2.0)` - half-open range (1.0 <= v < 2.0)
    /// - `(1.0,2.0)` - exclusive range (1.0 < v < 2.0)
    /// - `[1.0,)` - lower bound only (v >= 1.0)
    /// - `(,2.0]` - upper bound only (v <= 2.0)
    /// - `[1.0]` - exact version
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The string is too short (fewer than 2 characters)
    /// - The string doesn't start with `[` or `(` and end with `]` or `)`
    /// - The version bounds cannot be parsed
    /// - The lower bound is greater than the upper bound
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        if trimmed.len() < 2 {
            return Err(VersionError::InvalidRange(trimmed.to_string()));
        }

        let bytes = trimmed.as_bytes();
        let first = bytes[0] as char;
        let last = bytes[bytes.len() - 1] as char;

        if (first != '[' && first != '(') || (last != ']' && last != ')') {
            return Err(VersionError::InvalidRange(trimmed.to_string()));
        }

        let include_lower = first == '[';
        let include_upper = last == ']';
        let inner = &trimmed[1..trimmed.len() - 1];

        if inner.contains(',') {
            // A bounded range has exactly two bounds. Splitting on every comma
            // (rather than `splitn(2, ',')`) lets us reject malformed inputs
            // like `[1.0,2.0,3.0]`. A limited split would fold the trailing
            // `3.0` into the upper bound string and build a range with a bogus
            // `2.0,3.0` upper bound. Maven has no 3+ bound range form.
            let mut parts = inner.split(',');
            let lower_str = parts
                .next()
                .ok_or_else(|| VersionError::InvalidRange(trimmed.to_string()))?
                .trim();
            let upper_str = parts
                .next()
                .ok_or_else(|| VersionError::InvalidRange(trimmed.to_string()))?
                .trim();
            if parts.next().is_some() {
                return Err(VersionError::InvalidRange(trimmed.to_string()));
            }

            // Maven's canonical syntax marks an absent lower bound with `(`
            // and an absent upper bound with `)`, but its parser also accepts
            // an inclusive bracket on an absent bound (`[,2.0]`, `[1.0,]`,
            // `[,]` all parse in every Maven release). Inclusivity of a bound
            // that does not exist has no effect, so these are tolerated the
            // same way and behave as the unbounded side.
            let lower = if lower_str.is_empty() {
                None
            } else {
                Some(
                    Version::parse(lower_str)
                        .map_err(|_| VersionError::InvalidRange(trimmed.to_string()))?,
                )
            };

            let upper = if upper_str.is_empty() {
                None
            } else {
                Some(
                    Version::parse(upper_str)
                        .map_err(|_| VersionError::InvalidRange(trimmed.to_string()))?,
                )
            };

            if let (Some(l), Some(u)) = (&lower, &upper)
                && l > u
            {
                return Err(VersionError::InvalidRange(trimmed.to_string()));
            }

            Ok(Self {
                lower,
                upper,
                include_lower,
                include_upper,
            })
        } else {
            // Without a comma, only [x] is valid as an exact version.
            // (x), [x), and (x] are malformed; Maven does not define these forms.
            if !include_lower || !include_upper {
                return Err(VersionError::InvalidRange(trimmed.to_string()));
            }
            let exact = inner.trim();
            if exact.is_empty() {
                return Err(VersionError::InvalidRange(trimmed.to_string()));
            }

            let v = Version::parse(exact)
                .map_err(|_| VersionError::InvalidRange(trimmed.to_string()))?;
            // For exact versions, we need two independent owned copies for lower and upper bounds.
            // Since Version contains a String, we must clone for one and move for the other.
            Ok(Self {
                lower: Some(v.clone()),
                upper: Some(v),
                include_lower: true,
                include_upper: true,
            })
        }
    }

    /// Returns true if the given version falls within this range.
    pub fn matches(&self, v: &Version) -> bool {
        if let Some(lower) = &self.lower {
            match v.cmp(lower) {
                std::cmp::Ordering::Less => return false,
                std::cmp::Ordering::Equal if !self.include_lower => return false,
                _ => {}
            }
        }

        if let Some(upper) = &self.upper {
            match v.cmp(upper) {
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal if !self.include_upper => return false,
                _ => {}
            }
        }

        true
    }

    /// Returns true if this range matches exactly one version.
    pub fn is_exact(&self) -> bool {
        match (&self.lower, &self.upper) {
            (Some(l), Some(u)) => l == u && self.include_lower && self.include_upper,
            _ => false,
        }
    }

    /// Check if this range is empty (no versions can satisfy it).
    pub fn is_empty(&self) -> bool {
        match (&self.lower, &self.upper) {
            (Some(l), Some(u)) => match l.cmp(u) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Equal => !self.include_lower || !self.include_upper,
                std::cmp::Ordering::Less => false,
            },
            _ => false,
        }
    }

    /// Returns `None` if the intersection is empty.
    pub fn intersect(&self, other: &VersionRange) -> Option<VersionRange> {
        use std::cmp::Ordering;

        // Determine which lower bound wins (take the higher of the two)
        // We use references to avoid cloning until we know the result is non-empty
        enum BoundSource {
            SelfBound,
            OtherBound,
            None,
        }

        let (lower_source, new_include_lower) = match (&self.lower, &other.lower) {
            (None, None) => (BoundSource::None, true),
            (Some(_), None) => (BoundSource::SelfBound, self.include_lower),
            (None, Some(_)) => (BoundSource::OtherBound, other.include_lower),
            (Some(l1), Some(l2)) => match l1.cmp(l2) {
                Ordering::Greater => (BoundSource::SelfBound, self.include_lower),
                Ordering::Less => (BoundSource::OtherBound, other.include_lower),
                Ordering::Equal => {
                    // Same version: inclusive only if both are inclusive
                    (
                        BoundSource::SelfBound,
                        self.include_lower && other.include_lower,
                    )
                }
            },
        };

        // Determine which upper bound wins (take the lower of the two)
        let (upper_source, new_include_upper) = match (&self.upper, &other.upper) {
            (None, None) => (BoundSource::None, true),
            (Some(_), None) => (BoundSource::SelfBound, self.include_upper),
            (None, Some(_)) => (BoundSource::OtherBound, other.include_upper),
            (Some(u1), Some(u2)) => match u1.cmp(u2) {
                Ordering::Less => (BoundSource::SelfBound, self.include_upper),
                Ordering::Greater => (BoundSource::OtherBound, other.include_upper),
                Ordering::Equal => {
                    // Same version: inclusive only if both are inclusive
                    (
                        BoundSource::SelfBound,
                        self.include_upper && other.include_upper,
                    )
                }
            },
        };

        // Get references to the winning bounds for emptiness check
        let lower_ref: Option<&Version> = match lower_source {
            BoundSource::SelfBound => self.lower.as_ref(),
            BoundSource::OtherBound => other.lower.as_ref(),
            BoundSource::None => None,
        };

        let upper_ref: Option<&Version> = match upper_source {
            BoundSource::SelfBound => self.upper.as_ref(),
            BoundSource::OtherBound => other.upper.as_ref(),
            BoundSource::None => None,
        };

        // Check if the result would be empty before cloning
        let is_empty = match (lower_ref, upper_ref) {
            (Some(l), Some(u)) => match l.cmp(u) {
                Ordering::Greater => true,
                Ordering::Equal => !new_include_lower || !new_include_upper,
                Ordering::Less => false,
            },
            _ => false,
        };

        if is_empty {
            return None;
        }

        // Only clone when we know the result is non-empty
        let new_lower = match lower_source {
            BoundSource::SelfBound => self.lower.clone(),
            BoundSource::OtherBound => other.lower.clone(),
            BoundSource::None => None,
        };

        let new_upper = match upper_source {
            BoundSource::SelfBound => self.upper.clone(),
            BoundSource::OtherBound => other.upper.clone(),
            BoundSource::None => None,
        };

        Some(VersionRange {
            lower: new_lower,
            upper: new_upper,
            include_lower: new_include_lower,
            include_upper: new_include_upper,
        })
    }
}

impl fmt::Display for VersionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A single exact range emits the full `[X,X]` form rather than the
        // short `[X]` form. The short form re-parses as `VersionReq::Exact`
        // when wrapped in a `Ranges` union, which silently demotes the
        // variant and breaks pattern matching that distinguishes the two.
        // The full form round-trips back to `Ranges`.
        let start = if self.include_lower { '[' } else { '(' };
        let end = if self.include_upper { ']' } else { ')' };

        write!(f, "{start}")?;
        if let Some(lower) = &self.lower {
            write!(f, "{lower}")?;
        }
        write!(f, ",")?;
        if let Some(upper) = &self.upper {
            write!(f, "{upper}")?;
        }
        write!(f, "{end}")
    }
}

impl FromStr for VersionRange {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        VersionRange::parse(s)
    }
}

impl Serialize for VersionRange {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for VersionRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        VersionRange::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A Maven version requirement: either an exact version or a union of ranges.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VersionReq {
    /// Match a single exact version. Produced from explicit Maven range syntax
    /// such as `[1.0]` where the version is hard-pinned.
    Exact(Version),
    /// A soft version hint such as a bare `<version>1.0</version>`. Maven treats
    /// these as a preferred version that may be overridden.
    ///
    /// Current behavior:
    /// - At depth=1 (direct root dependency): the soft hint is overridable by
    ///   `<dependencyManagement>` / BOM constraints. See `Resolver::resolve`,
    ///   where root dependency-management entries become platform constraints
    ///   that take precedence over a child's soft pin.
    /// - At depth>1 (transitive): `Soft` is treated like `Exact` and conflict
    ///   mediation falls back to nearest-wins. Transitive-soft-pin escalation
    ///   (allowing a transitive soft pin to be overridden by a sibling's harder
    ///   constraint) is a follow-up.
    Soft(Version),
    /// Match any version within one or more ranges.
    Ranges(Vec<VersionRange>),
}

impl VersionReq {
    /// Parses a Maven version requirement string.
    ///
    /// Accepts either:
    /// - A plain version string (e.g., `1.2.3`) for exact matching
    /// - One or more comma-separated ranges (e.g., `[1.0,2.0),[3.0,)`)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The string is empty
    /// - Any version range in the string is malformed
    /// - Any version within a range cannot be parsed
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(VersionError::InvalidRange(trimmed.to_string()));
        }

        if trimmed.starts_with('[') || trimmed.starts_with('(') {
            let ranges = split_union_ranges(trimmed)?;
            let only_short_exact = ranges.len() == 1 && !ranges[0].contains(',');
            let mut parsed = Vec::with_capacity(ranges.len());
            for r in ranges {
                parsed.push(VersionRange::parse(r)?);
            }

            // Maven's `[X]` short form is the canonical hard-pin syntax and
            // collapses to `VersionReq::Exact`. The explicit two-bound form
            // `[X,X]` keeps its `Ranges` shape so a Ranges with a single
            // exact range round-trips losslessly via Display.
            if only_short_exact
                && parsed[0].is_exact()
                && let Some(lower) = &parsed[0].lower
            {
                return Ok(VersionReq::Exact(lower.clone()));
            }

            Ok(VersionReq::Ranges(parsed))
        } else {
            // Bare versions without bracketed range syntax are Maven "soft"
            // requirements: a preferred version that another node's hard
            // requirement or a dependency-management override may replace.
            //
            // A string that contains range punctuation but does not OPEN with a
            // bracket is malformed range syntax, not a soft version: a bare `]`,
            // a stray `1.0)`, or an unmatched `1.0,2.0]` must be a clean parse
            // error rather than a `Soft` pin that can never match a real
            // artifact. Reject any soft-path input carrying `[`, `]`, `(`, `)`
            // or a top-level `,`.
            if trimmed.contains(['[', ']', '(', ')', ',']) {
                return Err(VersionError::InvalidRange(trimmed.to_string()));
            }
            Ok(VersionReq::Soft(Version::parse(trimmed)?))
        }
    }

    /// Returns true if the given version satisfies this requirement.
    pub fn matches(&self, v: &Version) -> bool {
        match self {
            VersionReq::Exact(exact) | VersionReq::Soft(exact) => v == exact,
            VersionReq::Ranges(ranges) => ranges.iter().any(|range| range.matches(v)),
        }
    }

    /// Returns true if this requirement is a Maven "soft" version hint
    /// (a bare `<version>X</version>` without bracketed range syntax).
    #[cfg(test)]
    pub(crate) fn is_soft(&self) -> bool {
        matches!(self, VersionReq::Soft(_))
    }

    /// Returns the pinned version, if this is an `Exact` or `Soft` requirement.
    #[cfg(test)]
    pub(crate) fn pinned_version(&self) -> Option<&Version> {
        match self {
            VersionReq::Exact(v) | VersionReq::Soft(v) => Some(v),
            VersionReq::Ranges(_) => None,
        }
    }

    /// Returns `None` if the intersection is empty.
    pub fn intersect(&self, other: &VersionReq) -> Option<VersionReq> {
        // Soft requirements participate in intersection with the same semantics
        // as Exact for now. Mediation-aware behaviour (preferring overrides for
        // soft pins) is a separate concern handled by the resolver.
        match (self, other) {
            // Two exact / soft versions: must be the same
            (
                VersionReq::Exact(v1) | VersionReq::Soft(v1),
                VersionReq::Exact(v2) | VersionReq::Soft(v2),
            ) => {
                if v1 == v2 {
                    // If either side is hard, the result is hard.
                    let hard = matches!(self, VersionReq::Exact(_))
                        || matches!(other, VersionReq::Exact(_));
                    if hard {
                        Some(VersionReq::Exact(v1.clone()))
                    } else {
                        Some(VersionReq::Soft(v1.clone()))
                    }
                } else {
                    None
                }
            }

            // Exact / soft version with ranges: check if version is in any
            // range. A `Soft` pin that satisfies the range stays `Soft` so
            // downstream dependency-management overrides can still replace
            // it (Maven's nearest-wins mediation behaves this way); a hard
            // `Exact` pin keeps its hard semantics.
            (VersionReq::Exact(v), VersionReq::Ranges(ranges))
            | (VersionReq::Ranges(ranges), VersionReq::Exact(v)) => {
                if ranges.iter().any(|r| r.matches(v)) {
                    Some(VersionReq::Exact(v.clone()))
                } else {
                    None
                }
            }
            (VersionReq::Soft(v), VersionReq::Ranges(ranges))
            | (VersionReq::Ranges(ranges), VersionReq::Soft(v)) => {
                if ranges.iter().any(|r| r.matches(v)) {
                    Some(VersionReq::Soft(v.clone()))
                } else {
                    None
                }
            }

            // Two range sets: compute pairwise intersections
            (VersionReq::Ranges(ranges1), VersionReq::Ranges(ranges2)) => {
                let mut result_ranges = Vec::new();

                // For union ranges, we need to intersect each range from the first set
                // with each range from the second set
                for r1 in ranges1 {
                    for r2 in ranges2 {
                        if let Some(intersection) = r1.intersect(r2) {
                            result_ranges.push(intersection);
                        }
                    }
                }

                // WHY: do not collapse a single exact range into VersionReq::Exact.
                // Parsing reserves the `[X]` short form for Exact and keeps the
                // explicit `[X,X]` form as Ranges; collapsing here would break
                // the parse/Display round-trip for any caller who started from
                // the latter shape.
                if result_ranges.is_empty() {
                    None
                } else {
                    Some(VersionReq::Ranges(result_ranges))
                }
            }
        }
    }
}

impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Hard pins are rendered using Maven's bracket syntax so the
            // canonical string round-trips back to `Exact` on parse.
            VersionReq::Exact(v) => write!(f, "[{}]", v),
            // Soft pins render as a bare version, mirroring the input form
            // Maven uses in `<version>X</version>`.
            VersionReq::Soft(v) => write!(f, "{}", v),
            VersionReq::Ranges(ranges) => {
                for (idx, range) in ranges.iter().enumerate() {
                    if idx > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", range)?;
                }
                Ok(())
            }
        }
    }
}

impl FromStr for VersionReq {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        VersionReq::parse(s)
    }
}

impl Serialize for VersionReq {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for VersionReq {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        VersionReq::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Splits a comma-joined union of bracketed ranges (e.g. `[1.0,2.0),[3.0,)`)
/// into one slice per range. Internal commas inside a range are not separators;
/// the bracket pair delimits each range. Errors on empty input, missing brackets,
/// or content between ranges that is not itself a bracketed range.
fn split_union_ranges(input: &str) -> Result<Vec<&str>, VersionError> {
    let mut ranges = Vec::new();
    let mut chars = input.char_indices().peekable();

    loop {
        // Skip separators: commas and whitespace between ranges
        while let Some(&(_, ch)) = chars.peek() {
            if ch == ',' || ch.is_ascii_whitespace() {
                chars.next();
            } else {
                break;
            }
        }

        // Check if we've reached the end
        let Some((range_start, open_bracket)) = chars.next() else {
            break;
        };

        // Validate opening bracket
        if open_bracket != '[' && open_bracket != '(' {
            return Err(VersionError::InvalidRange(input.to_string()));
        }

        // Find the matching closing bracket
        // Note: We don't need to handle nesting since version strings
        // cannot contain brackets (they're alphanumeric with dots/hyphens)
        let mut range_end = None;
        for (idx, ch) in chars.by_ref() {
            if ch == ']' || ch == ')' {
                range_end = Some(idx);
                break;
            }
        }

        // Ensure we found a closing bracket
        let range_end = range_end.ok_or_else(|| VersionError::InvalidRange(input.to_string()))?;

        // Extract the complete range including both brackets
        ranges.push(&input[range_start..=range_end]);
    }

    // At least one range is required
    if ranges.is_empty() {
        return Err(VersionError::InvalidRange(input.to_string()));
    }

    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::{VersionRange, VersionReq};
    use crate::Version;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn parse_basic_range() {
        let r = VersionRange::parse("[1.0,2.0)").unwrap();
        assert!(r.matches(&v("1.0")));
        assert!(r.matches(&v("1.5")));
        assert!(!r.matches(&v("2.0")));
    }

    #[test]
    fn parse_open_ended_range() {
        let r = VersionRange::parse("(,1.5]").unwrap();
        assert!(r.matches(&v("1.5")));
        assert!(r.matches(&v("0.9")));
        assert!(!r.matches(&v("1.6")));
    }

    #[test]
    fn parse_exact_range() {
        let r = VersionRange::parse("[1.0]").unwrap();
        assert!(r.matches(&v("1.0")));
        assert!(!r.matches(&v("1.0.1")));
    }

    #[test]
    fn parse_union_req() {
        let req = VersionReq::parse("[1.0,2.0),[3.0,)").unwrap();
        assert!(req.matches(&v("1.5")));
        assert!(req.matches(&v("3.1")));
        assert!(!req.matches(&v("2.5")));
    }

    #[test]
    fn parse_exact_req() {
        let req = VersionReq::parse("1.2.3").unwrap();
        assert!(req.matches(&v("1.2.3")));
        assert!(!req.matches(&v("1.2.4")));
    }

    /// Bare versions like Maven's `<version>1.0</version>` carry "soft"
    /// semantics and must stay distinguishable from hard pins so mediation
    /// (overrides win over soft pins) can act on them; matching is identical.
    #[test]
    fn bare_version_parses_as_soft_not_exact() {
        let req = VersionReq::parse("1.0").unwrap();
        assert!(req.is_soft(), "expected Soft, got {:?}", req);
        assert!(matches!(req, VersionReq::Soft(_)));
    }

    #[test]
    fn bracketed_exact_version_parses_as_exact() {
        let req = VersionReq::parse("[1.0]").unwrap();
        assert!(!req.is_soft(), "expected Exact, got {:?}", req);
        assert!(matches!(req, VersionReq::Exact(_)));
    }

    #[test]
    fn range_version_does_not_become_soft() {
        let req = VersionReq::parse("[1.0,2.0)").unwrap();
        assert!(!req.is_soft(), "ranges are never soft, got {:?}", req);
        assert!(matches!(req, VersionReq::Ranges(_)));
    }

    #[test]
    fn soft_and_exact_match_the_same_versions() {
        let soft = VersionReq::parse("1.0").unwrap();
        let exact = VersionReq::parse("[1.0]").unwrap();
        for input in &["1.0", "1.0.0", "0.9", "1.1"] {
            assert_eq!(soft.matches(&v(input)), exact.matches(&v(input)));
        }
    }

    #[test]
    fn soft_display_round_trips_as_soft() {
        let original = VersionReq::parse("1.2.3").unwrap();
        let rendered = original.to_string();
        let reparsed = VersionReq::parse(&rendered).unwrap();
        assert!(reparsed.is_soft(), "expected Soft, got {:?}", reparsed);
        assert_eq!(original, reparsed);
    }

    /// A `Ranges([single_exact])` rendered as the short `[X]` re-parses as
    /// `Exact`, flipping the variant across the round-trip so downstream
    /// matchers diverge. Display emits `[X,X]` to preserve the variant.
    #[test]
    fn ranges_with_single_exact_range_round_trips_as_ranges() {
        let single_exact = VersionRange {
            lower: Some(v("1.0")),
            upper: Some(v("1.0")),
            include_lower: true,
            include_upper: true,
        };
        let original = VersionReq::Ranges(vec![single_exact]);
        let rendered = original.to_string();
        let reparsed = VersionReq::parse(&rendered).unwrap();
        assert!(
            matches!(reparsed, VersionReq::Ranges(_)),
            "expected Ranges, got {:?} (rendered as {rendered:?})",
            reparsed
        );
        assert_eq!(original, reparsed);
    }

    #[test]
    fn exact_display_round_trips_as_exact() {
        let original = VersionReq::parse("[1.2.3]").unwrap();
        let rendered = original.to_string();
        let reparsed = VersionReq::parse(&rendered).unwrap();
        assert!(!reparsed.is_soft(), "expected Exact, got {:?}", reparsed);
        assert_eq!(original, reparsed);
    }

    #[test]
    fn pinned_version_returns_inner_version() {
        let soft = VersionReq::parse("1.0").unwrap();
        let exact = VersionReq::parse("[1.0]").unwrap();
        let range = VersionReq::parse("[1.0,2.0)").unwrap();
        assert!(soft.pinned_version().is_some());
        assert!(exact.pinned_version().is_some());
        assert!(range.pinned_version().is_none());
    }

    #[test]
    fn invalid_range_is_error() {
        VersionRange::parse("[1.0,2.0").expect_err("unterminated bracket");
    }

    /// Regression for #53: a range with three or more comma-separated bounds
    /// such as `[1.0,2.0,3.0]` is malformed. The old `splitn(2, ',')` folded
    /// the extra `3.0` into the upper-bound string and silently accepted a
    /// range with a bogus `2.0,3.0` upper bound; it must now be a parse error.
    #[test]
    fn three_or_more_bounds_is_error() {
        for s in ["[1.0,2.0,3.0]", "(1.0,2.0,3.0)", "[1.0,2.0,)", "[,2.0,3.0]"] {
            VersionRange::parse(s).expect_err(s);
        }
        // Also reject through the VersionReq path.
        VersionReq::parse("[1.0,2.0,3.0]").expect_err("[1.0,2.0,3.0] via VersionReq");
    }

    /// Regression for #61: a bare `]`, a stray closing bracket, or any other
    /// string that carries range punctuation but does not open with `[`/`(`
    /// used to slip through `VersionReq::parse` as a `Soft` pin (a "version"
    /// that never matches a real artifact). It must be a clean parse error.
    #[test]
    fn unmatched_bracket_is_not_soft() {
        for s in ["]", ")", "1.0]", "1.0)", "1.0,2.0]", "1.0,2.0", "[1.0"] {
            VersionReq::parse(s).expect_err(s);
        }
    }

    /// An inclusive bracket paired with an empty bound (`[,2.0]`, `[1.0,]`,
    /// `[,]`) is accepted by every Maven release and behaves as the
    /// unbounded form; inclusivity of an absent bound has no effect.
    #[test]
    fn inclusive_bracket_with_empty_bound_is_accepted() {
        for s in ["[,2.0]", "[,2.0)", "[1.0,]", "(1.0,]", "[,]", "[,)", "(,]"] {
            VersionRange::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"));
        }
        let req = VersionRange::parse("[,2.0]").unwrap();
        assert!(req.matches(&v("0.1")));
        assert!(req.matches(&v("2.0")));
        assert!(!req.matches(&v("2.1")));
        let req = VersionRange::parse("[1.0,]").unwrap();
        assert!(req.matches(&v("1.0")));
        assert!(req.matches(&v("99")));
        assert!(!req.matches(&v("0.9")));
    }

    /// Open-bound forms that use exclusive brackets on the absent side are
    /// still accepted (this is the Maven-canonical syntax).
    #[test]
    fn exclusive_bracket_with_empty_bound_is_ok() {
        for s in ["(,2.0]", "(,2.0)", "[1.0,)", "(1.0,)", "(,)"] {
            VersionRange::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"));
        }
    }

    #[test]
    fn range_intersect_overlapping() {
        // [1.0,2.0) ∩ [1.5,3.0) = [1.5,2.0)
        let r1 = VersionRange::parse("[1.0,2.0)").unwrap();
        let r2 = VersionRange::parse("[1.5,3.0)").unwrap();
        let intersection = r1.intersect(&r2).unwrap();

        assert!(intersection.matches(&v("1.5")));
        assert!(intersection.matches(&v("1.9")));
        assert!(!intersection.matches(&v("1.0")));
        assert!(!intersection.matches(&v("2.0")));
        assert!(!intersection.matches(&v("2.5")));
    }

    #[test]
    fn range_intersect_contained() {
        // [1.0,3.0) ∩ [1.5,2.0) = [1.5,2.0)
        let r1 = VersionRange::parse("[1.0,3.0)").unwrap();
        let r2 = VersionRange::parse("[1.5,2.0)").unwrap();
        let intersection = r1.intersect(&r2).unwrap();

        assert!(intersection.matches(&v("1.5")));
        assert!(intersection.matches(&v("1.9")));
        assert!(!intersection.matches(&v("1.0")));
        assert!(!intersection.matches(&v("2.0")));
    }

    #[test]
    fn range_intersect_non_overlapping() {
        // [1.0,2.0) ∩ [3.0,4.0) = empty
        let r1 = VersionRange::parse("[1.0,2.0)").unwrap();
        let r2 = VersionRange::parse("[3.0,4.0)").unwrap();
        assert!(r1.intersect(&r2).is_none());
    }

    #[test]
    fn range_intersect_touching_exclusive() {
        // [1.0,2.0) ∩ [2.0,3.0) = empty (2.0 is excluded in first)
        let r1 = VersionRange::parse("[1.0,2.0)").unwrap();
        let r2 = VersionRange::parse("[2.0,3.0)").unwrap();
        assert!(r1.intersect(&r2).is_none());
    }

    #[test]
    fn range_intersect_touching_inclusive() {
        // [1.0,2.0] ∩ [2.0,3.0) = [2.0]
        let r1 = VersionRange::parse("[1.0,2.0]").unwrap();
        let r2 = VersionRange::parse("[2.0,3.0)").unwrap();
        let intersection = r1.intersect(&r2).unwrap();

        assert!(intersection.matches(&v("2.0")));
        assert!(!intersection.matches(&v("1.9")));
        assert!(!intersection.matches(&v("2.1")));
    }

    #[test]
    fn range_intersect_same_bound_different_inclusivity() {
        // [1.0,2.0] ∩ [1.5,2.0) = [1.5,2.0)
        let r1 = VersionRange::parse("[1.0,2.0]").unwrap();
        let r2 = VersionRange::parse("[1.5,2.0)").unwrap();
        let intersection = r1.intersect(&r2).unwrap();

        assert!(intersection.matches(&v("1.5")));
        assert!(intersection.matches(&v("1.9")));
        assert!(!intersection.matches(&v("2.0"))); // Exclusive from r2
    }

    #[test]
    fn range_intersect_open_ended() {
        // [1.0,) ∩ (,2.0] = [1.0,2.0]
        let r1 = VersionRange::parse("[1.0,)").unwrap();
        let r2 = VersionRange::parse("(,2.0]").unwrap();
        let intersection = r1.intersect(&r2).unwrap();

        assert!(intersection.matches(&v("1.0")));
        assert!(intersection.matches(&v("1.5")));
        assert!(intersection.matches(&v("2.0")));
        assert!(!intersection.matches(&v("0.9")));
        assert!(!intersection.matches(&v("2.1")));
    }

    #[test]
    fn range_intersect_exact_within_range() {
        // [1.5] ∩ [1.0,2.0) = [1.5]
        let r1 = VersionRange::parse("[1.5]").unwrap();
        let r2 = VersionRange::parse("[1.0,2.0)").unwrap();
        let intersection = r1.intersect(&r2).unwrap();

        assert!(intersection.is_exact());
        assert!(intersection.matches(&v("1.5")));
    }

    #[test]
    fn range_intersect_exact_outside_range() {
        // [2.5] ∩ [1.0,2.0) = empty
        let r1 = VersionRange::parse("[2.5]").unwrap();
        let r2 = VersionRange::parse("[1.0,2.0)").unwrap();
        assert!(r1.intersect(&r2).is_none());
    }

    #[test]
    fn range_is_empty() {
        // Test the is_empty method
        let empty = VersionRange {
            lower: Some(v("2.0")),
            upper: Some(v("1.0")),
            include_lower: true,
            include_upper: true,
        };
        assert!(empty.is_empty());

        // [1.0,1.0) is empty (can't include both exclusively)
        let empty2 = VersionRange {
            lower: Some(v("1.0")),
            upper: Some(v("1.0")),
            include_lower: true,
            include_upper: false,
        };
        assert!(empty2.is_empty());

        // [1.0,1.0] is not empty (exact version)
        let not_empty = VersionRange {
            lower: Some(v("1.0")),
            upper: Some(v("1.0")),
            include_lower: true,
            include_upper: true,
        };
        assert!(!not_empty.is_empty());
    }

    #[test]
    fn req_intersect_exact_same() {
        let r1 = VersionReq::parse("1.5").unwrap();
        let r2 = VersionReq::parse("1.5").unwrap();
        let intersection = r1.intersect(&r2).unwrap();

        assert!(intersection.matches(&v("1.5")));
    }

    #[test]
    fn req_intersect_exact_different() {
        let r1 = VersionReq::parse("1.5").unwrap();
        let r2 = VersionReq::parse("2.0").unwrap();
        assert!(r1.intersect(&r2).is_none());
    }

    #[test]
    fn req_intersect_exact_with_range_inside() {
        // 1.5 ∩ [1.0,2.0) = 1.5
        let r1 = VersionReq::parse("1.5").unwrap();
        let r2 = VersionReq::parse("[1.0,2.0)").unwrap();
        let intersection = r1.intersect(&r2).unwrap();

        assert!(intersection.matches(&v("1.5")));
        assert!(!intersection.matches(&v("1.0")));
    }

    /// A `Soft` pin intersected with a `Ranges` containing the pinned version
    /// used to collapse to `Exact`, discarding the soft semantics that lets
    /// dependency-management overrides win.
    #[test]
    fn req_intersect_soft_with_range_preserves_soft() {
        let soft = VersionReq::parse("1.5").unwrap();
        let range = VersionReq::parse("[1.0,2.0)").unwrap();

        let intersection = soft.intersect(&range).unwrap();
        assert!(
            intersection.is_soft(),
            "expected Soft, got {:?}",
            intersection
        );
        assert!(matches!(intersection, VersionReq::Soft(_)));

        // Commutative: same result whichever side carries the soft pin.
        let reverse = range.intersect(&soft).unwrap();
        assert!(reverse.is_soft(), "expected Soft, got {:?}", reverse);
        assert_eq!(intersection, reverse);
    }

    /// An `Exact` pin (hard) intersected with a satisfying `Ranges` stays
    /// hard. The soft-preserving rule is asymmetric.
    #[test]
    fn req_intersect_exact_with_range_stays_exact() {
        let exact = VersionReq::parse("[1.5]").unwrap();
        let range = VersionReq::parse("[1.0,2.0)").unwrap();
        let intersection = exact.intersect(&range).unwrap();
        assert!(!intersection.is_soft());
        assert!(matches!(intersection, VersionReq::Exact(_)));
    }

    #[test]
    fn req_intersect_exact_with_range_outside() {
        // 2.5 ∩ [1.0,2.0) = empty
        let r1 = VersionReq::parse("2.5").unwrap();
        let r2 = VersionReq::parse("[1.0,2.0)").unwrap();
        assert!(r1.intersect(&r2).is_none());
    }

    #[test]
    fn req_intersect_ranges() {
        // [1.0,2.0) ∩ [1.5,3.0) = [1.5,2.0)
        let r1 = VersionReq::parse("[1.0,2.0)").unwrap();
        let r2 = VersionReq::parse("[1.5,3.0)").unwrap();
        let intersection = r1.intersect(&r2).unwrap();

        assert!(intersection.matches(&v("1.5")));
        assert!(intersection.matches(&v("1.9")));
        assert!(!intersection.matches(&v("1.0")));
        assert!(!intersection.matches(&v("2.0")));
    }

    #[test]
    fn req_intersect_union_ranges() {
        // [1.0,2.0),[4.0,5.0) ∩ [1.5,4.5) = [1.5,2.0),[4.0,4.5)
        let r1 = VersionReq::parse("[1.0,2.0),[4.0,5.0)").unwrap();
        let r2 = VersionReq::parse("[1.5,4.5)").unwrap();
        let intersection = r1.intersect(&r2).unwrap();

        assert!(intersection.matches(&v("1.5")));
        assert!(intersection.matches(&v("1.9")));
        assert!(intersection.matches(&v("4.0")));
        assert!(intersection.matches(&v("4.4")));
        assert!(!intersection.matches(&v("1.0")));
        assert!(!intersection.matches(&v("2.5")));
        assert!(!intersection.matches(&v("4.5")));
    }

    #[test]
    fn req_intersect_commutative() {
        // Intersection should be commutative
        let r1 = VersionReq::parse("[1.0,2.0)").unwrap();
        let r2 = VersionReq::parse("[1.5,3.0)").unwrap();

        let int1 = r1.intersect(&r2).unwrap();
        let int2 = r2.intersect(&r1).unwrap();

        // Both should match the same versions
        for version in &["1.5", "1.7", "1.9"] {
            assert_eq!(int1.matches(&v(version)), int2.matches(&v(version)));
        }
        for version in &["1.0", "2.0", "3.0"] {
            assert_eq!(int1.matches(&v(version)), int2.matches(&v(version)));
        }
    }

    // ==================== split_union_ranges tests ====================

    #[test]
    fn split_single_range() {
        let ranges = super::split_union_ranges("[1.0,2.0)").unwrap();
        assert_eq!(ranges, vec!["[1.0,2.0)"]);
    }

    #[test]
    fn split_two_ranges() {
        let ranges = super::split_union_ranges("[1.0,2.0),[3.0,)").unwrap();
        assert_eq!(ranges, vec!["[1.0,2.0)", "[3.0,)"]);
    }

    #[test]
    fn split_three_ranges() {
        let ranges = super::split_union_ranges("[1.0,2.0),(3.0,4.0],[5.0,)").unwrap();
        assert_eq!(ranges, vec!["[1.0,2.0)", "(3.0,4.0]", "[5.0,)"]);
    }

    #[test]
    fn split_with_whitespace() {
        let ranges = super::split_union_ranges("[1.0,2.0) , [3.0,4.0)").unwrap();
        assert_eq!(ranges, vec!["[1.0,2.0)", "[3.0,4.0)"]);
    }

    #[test]
    fn split_exact_version() {
        let ranges = super::split_union_ranges("[1.5]").unwrap();
        assert_eq!(ranges, vec!["[1.5]"]);
    }

    #[test]
    fn split_multiple_exact_versions() {
        let ranges = super::split_union_ranges("[1.0],[2.0],[3.0]").unwrap();
        assert_eq!(ranges, vec!["[1.0]", "[2.0]", "[3.0]"]);
    }

    #[test]
    fn split_open_ended_ranges() {
        let ranges = super::split_union_ranges("(,2.0],[3.0,)").unwrap();
        assert_eq!(ranges, vec!["(,2.0]", "[3.0,)"]);
    }

    #[test]
    fn split_all_bracket_combinations() {
        // Test all four bracket combinations
        let ranges = super::split_union_ranges("[1,2],[3,4),(5,6],(7,8)").unwrap();
        assert_eq!(ranges, vec!["[1,2]", "[3,4)", "(5,6]", "(7,8)"]);
    }

    #[test]
    fn split_rejects_malformed_inputs() {
        // Empty/whitespace, missing brackets, bare versions and mixed-with-garbage
        // forms must all fail; otherwise the parser would silently accept them.
        for s in [
            "",
            "   ",
            ",,,",
            "[1.0,2.0",
            "1.0,2.0]",
            "1.0",
            "[1.0,2.0),invalid",
        ] {
            super::split_union_ranges(s).expect_err(s);
        }
    }

    #[test]
    fn split_leading_whitespace() {
        let ranges = super::split_union_ranges("  [1.0,2.0)").unwrap();
        assert_eq!(ranges, vec!["[1.0,2.0)"]);
    }

    #[test]
    fn split_trailing_whitespace() {
        let ranges = super::split_union_ranges("[1.0,2.0)  ").unwrap();
        assert_eq!(ranges, vec!["[1.0,2.0)"]);
    }

    #[test]
    fn split_enterprise_version_ranges() {
        // Test with realistic enterprise version strings
        let ranges =
            super::split_union_ranges("[1.0.0-SNAPSHOT,2.0.0-RELEASE),[3.0.0.Final,)").unwrap();
        assert_eq!(
            ranges,
            vec!["[1.0.0-SNAPSHOT,2.0.0-RELEASE)", "[3.0.0.Final,)"]
        );
    }

    #[test]
    fn split_preserves_internal_structure() {
        // Ensure internal commas within ranges are preserved
        let ranges = super::split_union_ranges("[1.0,2.0)").unwrap();
        assert_eq!(ranges[0], "[1.0,2.0)");
        // The internal comma should be preserved for later parsing by VersionRange::parse
        assert!(ranges[0].contains(','));
    }

    #[test]
    fn split_integration_with_version_req() {
        // End-to-end test: split then parse each range
        let input = "[1.0,2.0),[3.0,4.0],(5.0,)";
        let req = VersionReq::parse(input).unwrap();

        // Should match versions in each range
        assert!(req.matches(&v("1.5"))); // In [1.0,2.0)
        assert!(req.matches(&v("3.5"))); // In [3.0,4.0]
        assert!(req.matches(&v("6.0"))); // In (5.0,)

        // Should not match versions outside all ranges
        assert!(!req.matches(&v("2.5"))); // Between ranges
        assert!(!req.matches(&v("5.0"))); // Exactly at exclusive bound
    }

    /// Regression: `VersionReq::intersect` used to collapse a single-exact
    /// range result into `VersionReq::Exact`, breaking the parse/Display
    /// round-trip for the explicit `[X,X]` shape (which `VersionReq::parse`
    /// keeps as `Ranges`). The intersection of two Ranges must stay a Ranges.
    #[test]
    fn intersect_round_trips_via_display() {
        let a = VersionReq::parse("[1.0,2.0]").unwrap();
        let b = VersionReq::parse("[2.0,3.0]").unwrap();
        let result = a.intersect(&b).expect("non-empty intersection");
        // The intersection is the single point 2.0; both inputs are Ranges,
        // so the result must stay a Ranges to round-trip back to Ranges.
        let rendered = result.to_string();
        let reparsed = VersionReq::parse(&rendered).expect("re-parse intersect Display");
        assert_eq!(result, reparsed, "intersect/Display must round-trip");
        assert!(
            matches!(result, VersionReq::Ranges(_)),
            "intersect of two Ranges must stay a Ranges; got {:?}",
            result
        );
    }
}
