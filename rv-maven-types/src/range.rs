use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use crate::{MavenMode, Version, VersionError};

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
        Self::parse_in(s, MavenMode::Maven39)
    }

    /// [`Self::parse`], with the bounds ordered as `mode` orders versions.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`].
    pub fn parse_in(s: &str, mode: MavenMode) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        let invalid = || VersionError::InvalidRange(trimmed.to_string());
        let include_lower = trimmed.starts_with('[');
        let include_upper = trimmed.ends_with(']');
        let inner = trimmed
            .strip_prefix(['[', '('])
            .and_then(|rest| rest.strip_suffix([']', ')']))
            .ok_or_else(invalid)?;
        // An absent bound may still be written inclusive (`[,2.0]`, `[1.0,]`),
        // which every Maven release accepts.
        let bound = |text: &str| match text.trim() {
            "" => Ok(None),
            text => Version::parse(text).map(Some).map_err(|_| invalid()),
        };
        match inner.split(',').collect::<Vec<_>>()[..] {
            [lower, upper] => {
                let (lower, upper) = (bound(lower)?, bound(upper)?);
                if let (Some(l), Some(u)) = (&lower, &upper)
                    && l.cmp_in(u, mode).is_gt()
                {
                    return Err(invalid());
                }
                Ok(Self {
                    lower,
                    upper,
                    include_lower,
                    include_upper,
                })
            }
            // Without a comma only `[x]` is a range, and `[1.2.*]` is
            // `[1.2.min,1.2.max]`.
            [exact] if include_lower && include_upper => {
                if let Some(prefix) = exact.trim().strip_suffix('*').filter(|p| p.ends_with('.')) {
                    return Ok(Self {
                        lower: bound(&format!("{prefix}min"))?,
                        upper: bound(&format!("{prefix}max"))?,
                        include_lower,
                        include_upper,
                    });
                }
                let exact = bound(exact)?.ok_or_else(invalid)?;
                Ok(Self {
                    lower: Some(exact.clone()),
                    upper: Some(exact),
                    include_lower,
                    include_upper,
                })
            }
            _ => Err(invalid()),
        }
    }

    /// Returns true if the given version falls within this range.
    pub fn matches(&self, v: &Version) -> bool {
        self.matches_in(v, MavenMode::Maven39)
    }

    /// [`Self::matches`] in the version order of `mode`.
    pub fn matches_in(&self, v: &Version, mode: MavenMode) -> bool {
        let above = self
            .lower
            .as_ref()
            .is_none_or(|lower| match v.cmp_in(lower, mode) {
                Ordering::Less => false,
                Ordering::Equal => self.include_lower,
                Ordering::Greater => true,
            });
        let below = self
            .upper
            .as_ref()
            .is_none_or(|upper| match v.cmp_in(upper, mode) {
                Ordering::Greater => false,
                Ordering::Equal => self.include_upper,
                Ordering::Less => true,
            });
        above && below
    }

    fn is_exact_in(&self, mode: MavenMode) -> bool {
        match (&self.lower, &self.upper) {
            (Some(l), Some(u)) => {
                l.cmp_in(u, mode).is_eq() && self.include_lower && self.include_upper
            }
            _ => false,
        }
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

/// A Maven version requirement: a hard-pinned version, a soft version or a
/// union of ranges.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VersionReq {
    /// Match a single exact version. Produced from explicit Maven range syntax
    /// such as `[1.0]` where the version is hard-pinned.
    Exact(Version),
    /// A soft version from a bare version string such as
    /// `<version>1.0</version>` (no bracketed range syntax). Distinct from
    /// [`VersionReq::Exact`], which comes from short-form `[1.0]`.
    /// [`VersionReq::matches`] treats Soft and Exact the same: equality
    /// against the pinned version.
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
        Self::parse_in(s, MavenMode::Maven39)
    }

    /// [`Self::parse`], with range bounds ordered as `mode` orders versions:
    /// maven-resolver refuses a range whose lower bound is above its upper
    /// one, and `[0,alpha]` is one for Maven 3.10 only.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`].
    pub fn parse_in(s: &str, mode: MavenMode) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(VersionError::InvalidRange(trimmed.to_string()));
        }

        if trimmed.starts_with('[') || trimmed.starts_with('(') {
            let ranges = split_union_ranges(trimmed)?;
            let only_short_exact = ranges.len() == 1 && !ranges[0].contains(',');
            let mut parsed = Vec::with_capacity(ranges.len());
            for r in ranges {
                parsed.push(VersionRange::parse_in(r, mode)?);
            }

            // Maven's `[X]` short form is the canonical hard-pin syntax and
            // collapses to `VersionReq::Exact`. The explicit two-bound form
            // `[X,X]` keeps its `Ranges` shape so a Ranges with a single
            // exact range round-trips losslessly via Display.
            if only_short_exact
                && parsed[0].is_exact_in(mode)
                && let Some(lower) = &parsed[0].lower
            {
                return Ok(VersionReq::Exact(lower.clone()));
            }

            Ok(VersionReq::Ranges(parsed))
        } else {
            // Bare versions without bracketed range syntax are Maven "soft"
            // requirements: a preferred version that another node's hard
            // requirement or a dependency-management override may replace.
            // maven-resolver reads `1.0,2.0` and `1.0]` as such versions too.
            Ok(VersionReq::Soft(Version::parse(trimmed)?))
        }
    }

    /// The one version a hard pin such as `[1.0]` or `[1.0,1.0]` admits.
    pub fn exact_version(&self) -> Option<&Version> {
        self.exact_version_in(MavenMode::Maven39)
    }

    /// [`Self::exact_version`] in the version order of `mode`. maven-resolver
    /// 1.9 and 2.0 alike bound a union by its lowest lower and highest upper
    /// bound, the first of equal ones its `HashSet` walks, and take one
    /// whose two are one version as that version, so `[0,0],[ga,ga]` and
    /// `[ga,ga],[0,0]` are both `ga` in the 3.9 mode. That version need not
    /// be in the range: `(1,1)` is `1`.
    pub fn exact_version_in(&self, mode: MavenMode) -> Option<&Version> {
        match self {
            VersionReq::Exact(exact) => Some(exact),
            VersionReq::Ranges(ranges) => union_bound(ranges, mode),
            VersionReq::Soft(_) => None,
        }
    }

    /// Returns true if the given version satisfies this requirement.
    pub fn matches(&self, v: &Version) -> bool {
        self.matches_in(v, MavenMode::Maven39)
    }

    /// [`Self::matches`] in the version order of `mode`.
    pub fn matches_in(&self, v: &Version, mode: MavenMode) -> bool {
        match self {
            VersionReq::Exact(exact) | VersionReq::Soft(exact) => v.cmp_in(exact, mode).is_eq(),
            VersionReq::Ranges(ranges) => ranges.iter().any(|range| range.matches_in(v, mode)),
        }
    }
}

/// The one version maven-resolver's `UnionVersionRange` of `ranges` bounds
/// in `mode`, if its bounds are one: it walks them in `HashSet` order, by
/// the bucket each range's hash spreads to and then as added, and takes the
/// first lowest lower and highest upper bound. Its version order is not
/// transitive, so the walk decides `[0,0],[foo,foo],[bar,bar]` too.
fn union_bound(ranges: &[VersionRange], mode: MavenMode) -> Option<&Version> {
    let bound = |version: &Option<Version>, inclusive: bool| {
        version.as_ref().map_or(0, |version| {
            (17i32 * 31)
                .wrapping_add(version.java_hash_in(mode))
                .wrapping_mul(31)
                .wrapping_add(i32::from(inclusive))
        })
    };
    let hashes: Vec<u32> = (ranges.iter())
        .map(|range| {
            let hash = (17i32 * 31)
                .wrapping_add(bound(&range.upper, range.include_upper))
                .wrapping_mul(31)
                .wrapping_add(bound(&range.lower, range.include_lower))
                as u32;
            hash ^ (hash >> 16)
        })
        .collect();
    // A `HashSet` keeps the first of two equal ranges.
    let same = |a: &Option<Version>, b: &Option<Version>| match (a, b) {
        (Some(a), Some(b)) => a.cmp_in(b, mode).is_eq(),
        (None, None) => true,
        _ => false,
    };
    let mut walk: Vec<(&VersionRange, &u32)> = Vec::new();
    for (range, hash) in ranges.iter().zip(&hashes) {
        let equal = |(kept, kept_hash): &(&VersionRange, &u32)| {
            *kept_hash == hash
                && kept.include_lower == range.include_lower
                && kept.include_upper == range.include_upper
                && same(&kept.lower, &range.lower)
                && same(&kept.upper, &range.upper)
        };
        if !walk.iter().any(equal) {
            walk.push((range, hash));
        }
    }
    let mut buckets = (ranges.len() * 4 / 3 + 1).max(16).next_power_of_two();
    // A bin that would hold a ninth entry doubles a table under 64.
    while buckets < 64 && {
        let mut bins = BTreeMap::<usize, usize>::new();
        for (_, hash) in &walk {
            *bins.entry(**hash as usize & (buckets - 1)).or_default() += 1;
        }
        bins.values().any(|bin| *bin > 8)
    } {
        buckets *= 2;
    }
    walk.sort_by_key(|(_, hash)| **hash as usize & (buckets - 1));
    // The first lowest lower and highest upper bound it walks, an equal one
    // replacing an exclusive one; an unbounded range leaves none.
    fn extreme<'a>(
        bounds: impl Iterator<Item = Option<(&'a Version, bool)>>,
        toward: Ordering,
        mode: MavenMode,
    ) -> Option<(&'a Version, bool)> {
        let bounds: Vec<_> = bounds.collect::<Option<_>>()?;
        bounds
            .into_iter()
            .reduce(|kept, found| match found.0.cmp_in(kept.0, mode) {
                Ordering::Equal if !kept.1 => found,
                order if order == toward => found,
                _ => kept,
            })
    }
    let lowers = (walk.iter()).map(|(range, _)| Some((range.lower.as_ref()?, range.include_lower)));
    let uppers = (walk.iter()).map(|(range, _)| Some((range.upper.as_ref()?, range.include_upper)));
    let (low, low_inclusive) = extreme(lowers, Ordering::Less, mode)?;
    let (high, high_inclusive) = extreme(uppers, Ordering::Greater, mode)?;
    (low.cmp_in(high, mode).is_eq() && low_inclusive == high_inclusive).then_some(low)
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

/// Splits a union of bracketed ranges (e.g. `[1.0,2.0),[3.0,)`) into one
/// slice per range, as `GenericVersionScheme.parseVersionConstraint` does:
/// the first closing bracket ends a range, and one comma may follow it.
fn split_union_ranges(input: &str) -> Result<Vec<&str>, VersionError> {
    let invalid = || VersionError::InvalidRange(input.to_string());
    let mut ranges = Vec::new();
    let mut rest = input.trim();
    while rest.starts_with(['[', '(']) {
        let end = rest.find([']', ')']).ok_or_else(invalid)?;
        ranges.push(&rest[..=end]);
        rest = rest[end + 1..].trim();
        rest = rest.strip_prefix(',').map_or(rest, str::trim);
    }
    if !rest.is_empty() {
        return Err(invalid());
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::VersionReq;
    use crate::{MavenMode, Version};

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn requirements_match_like_maven() {
        // (requirement, versions it matches, versions it does not)
        let cases: &[(&str, &[&str], &[&str])] = &[
            ("[1.0,2.0)", &["1.0", "1.5"], &["0.9", "2.0"]),
            ("(,1.5]", &["0.9", "1.5"], &["1.6"]),
            ("(1.0,2.0)", &["1.5"], &["1.0", "2.0"]),
            ("[1.0]", &["1.0", "1.0.0"], &["1.0.1"]),
            ("1.0", &["1.0", "1.0.0"], &["0.9", "1.1"]),
            ("[,2.0]", &["0.1", "2.0"], &["2.1"]),
            ("[1.0,]", &["1.0", "99"], &["0.9"]),
            ("[,]", &["1"], &[]),
            (
                "[1.2.*]",
                &["1.2", "1.2.1", "1.2-SNAPSHOT"],
                &["1.1.9", "1.3"],
            ),
            ("[1,2],[3,4],", &["1.5", "3.5"], &["2.5"]),
            // `1-1 == 1.1` and `1.0_alpha < 1.0`, as in Maven 3.9.
            ("[1.1,2.0)", &["1-1"], &["1.0"]),
            ("[1.0,2.0)", &["1.0"], &["1.0_alpha"]),
            (
                " [1.0,2.0) , [3.0,4.0],(5.0,) ",
                &["1.5", "3.5", "4.0", "6.0"],
                &["2.5", "5.0"],
            ),
            (
                "[1.0.0-SNAPSHOT,2.0.0-RELEASE),[3.0.0.Final,)",
                &["1.0.0", "3.0.0"],
                &["2.0.0", "0.9"],
            ),
        ];
        for (text, matching, other) in cases {
            let req = VersionReq::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            for version in *matching {
                assert!(req.matches(&v(version)), "{text} should match {version}");
            }
            for version in *other {
                assert!(
                    !req.matches(&v(version)),
                    "{text} should not match {version}"
                );
            }
        }
    }

    #[test]
    fn requirement_kinds_round_trip_through_display() {
        for (text, rendered) in [
            ("1.2.3", "1.2.3"),
            ("[1.2.3]", "[1.2.3]"),
            ("[1.0,1.0]", "[1.0,1.0]"),
            ("[1.0,2.0),(3,]", "[1.0,2.0),(3,]"),
        ] {
            let req = VersionReq::parse(text).unwrap();
            assert_eq!(req.to_string(), rendered);
            assert_eq!(VersionReq::parse(rendered).unwrap(), req);
        }
        assert!(matches!(VersionReq::parse("1.0"), Ok(VersionReq::Soft(_))));
        assert!(matches!(
            VersionReq::parse("[1.0]"),
            Ok(VersionReq::Exact(_))
        ));
        assert!(matches!(
            VersionReq::parse("[1.0,1.0]"),
            Ok(VersionReq::Ranges(_))
        ));
    }

    #[test]
    fn malformed_requirements_are_refused() {
        for text in [
            "",
            "   ",
            "[1.0,2.0",
            "[1.0",
            "[1.0,2.0),invalid",
            "[1.0,2.0],,",
            "[1.0,2.0],,[3.0,4.0]",
            "[1.0,2.0,3.0]",
            "(1.0,2.0,3.0)",
            "[1.0,2.0,)",
            "[,2.0,3.0]",
            "[2.0,1.0]",
            "(1.0)",
            "[1.0)",
            "[]",
            "${v}",
        ] {
            VersionReq::parse(text).expect_err(text);
        }
    }

    /// A requirement that does not open with a bracket is a soft version,
    /// whatever punctuation it holds.
    #[test]
    fn a_requirement_without_an_opening_bracket_is_soft() {
        for text in ["1.0,2.0", "1.0]", "1.0)", "1.0,2.0]", "]", ",,,"] {
            let req = VersionReq::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(req, VersionReq::Soft(v(text)), "{text}");
            assert!(!req.matches(&v("1.0")), "{text}");
        }
    }

    /// The ranges of a union may be joined by a comma, with whitespace
    /// around it, or follow each other.
    #[test]
    fn union_ranges_take_an_optional_comma() {
        for text in [
            "[1.0,2.0),[3.0,)",
            "[1.0,2.0) , [3.0,)",
            "[1.0,2.0)[3.0,)",
            "[1.0,2.0) [3.0,)",
        ] {
            let req = VersionReq::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert!(req.matches(&v("1.5")), "{text}");
            assert!(req.matches(&v("3.0")), "{text}");
            assert!(!req.matches(&v("2.5")), "{text}");
        }
        let pins = VersionReq::parse("[1.0][2.0]").unwrap();
        assert!(pins.matches(&v("2.0")) && !pins.matches(&v("1.5")));
    }

    /// Maven 3.10 sorts a version that starts with text below 0, which
    /// changes what a range admits and which ranges parse.
    #[test]
    fn requirements_follow_the_order_of_the_mode() {
        let (v39, v310) = (MavenMode::Maven39, MavenMode::Maven310);
        let range = VersionReq::parse("[0,1)").unwrap();
        assert!(range.matches_in(&v("alpha"), v39));
        assert!(!range.matches_in(&v("alpha"), v310));
        assert!(range.matches_in(&v("0.5"), v310));
        let soft = VersionReq::parse("0").unwrap();
        assert!(soft.matches_in(&v("ga"), v39));
        assert!(!soft.matches_in(&v("ga"), v310));

        // `0 == alpha` in 3.9 only.
        let pin = VersionReq::parse("[0,alpha]").unwrap();
        assert_eq!(pin.exact_version_in(v39), Some(&v("0")));
        assert_eq!(
            VersionReq::parse("[1,1.0]").unwrap().exact_version_in(v310),
            Some(&v("1"))
        );
        VersionReq::parse_in("[0,alpha]", v310).expect_err("3.10 bounds out of order");
        VersionReq::parse("[alpha,0.min]").expect_err("3.9 bounds out of order");
        let reversed = VersionReq::parse_in("[alpha,0.min]", v310).unwrap();
        assert_eq!(reversed.exact_version_in(v310), None);
        assert!(reversed.matches_in(&v("beta"), v310));
    }

    /// Maven 3.9.12 takes the spelling of the range its `HashSet` walks
    /// first, whichever comes first in the POM.
    #[test]
    fn a_union_of_one_version_takes_the_spelling_maven_39_walks_first() {
        for (text, exact) in [
            ("[0,0],[ga,ga]", "ga"),
            ("[ga,ga],[0,0]", "ga"),
            ("[0,ga],[ga,0]", "ga"),
            ("[ga,0],[0,ga]", "ga"),
            ("[0,0],[alpha,alpha]", "alpha"),
            ("[alpha,alpha],[0,0]", "alpha"),
            ("[foo,foo],[0,0]", "foo"),
            ("[0,0],[foo,foo]", "foo"),
            ("[0.0,0.0],[ga,ga]", "ga"),
            ("[ga,ga],[0.0,0.0]", "ga"),
            ("[0,0],[0-ga,0-ga]", "0"),
            ("[0-ga,0-ga],[0,0]", "0-ga"),
            // Equal ranges are one entry, the first.
            ("(1,1),(1.0,1.0)", "1"),
            ("(1.0,1.0),(1,1)", "1.0"),
            ("(1,1),[1.0,1.0]", "1.0"),
        ] {
            let req = VersionReq::parse(text).unwrap();
            let found = req
                .exact_version_in(MavenMode::Maven39)
                .map(Version::as_str);
            assert_eq!(found, Some(exact), "{text}");
        }
        // Its order is not transitive: `0` equals `x` and `y`, which differ,
        // so the walk decides whether the bounds meet. Nine entries in one
        // bin grow the table, which walks `[0,0]` after the others.
        let crowd = "[0,0],[cc,cc],[cd,cd],[ce,ce],[cf,cf],[cg,cg],[ch,ch],[ci,ci]";
        for (text, exact) in [
            ("[0,0],[x,x],[y,y]", None),
            ("[y,y],[x,x],[0,0]", None),
            ("[0,0],[x,x],[0,0]", Some("x")),
            (crowd, Some("0")),
            (&format!("{crowd},[cj,cj]"), None),
        ] {
            let req = VersionReq::parse(text).unwrap();
            let found = req
                .exact_version_in(MavenMode::Maven39)
                .map(Version::as_str);
            assert_eq!(found, exact, "{text}");
        }
        let union = VersionReq::parse_in("[1,1],[1.0,1.0]", MavenMode::Maven310).unwrap();
        assert_eq!(union.exact_version_in(MavenMode::Maven310), Some(&v("1")));
    }

    /// maven-resolver-util 2.0.24 walks a union's `HashSet` as 1.9.25
    /// does, and the range resolver takes bounds that are one version,
    /// inclusive or not, as it: Maven 3.9.12 and 3.10.0 both take a
    /// transitive `[1.0,1.0),[1.0.0,1.0.0]` as `1.0`, in either order, and
    /// `(1.0,1.0)` as `1.0`, which mediation then refuses.
    #[test]
    fn both_modes_bound_a_union_as_their_hash_set_walks_it() {
        for mode in [MavenMode::Maven39, MavenMode::Maven310] {
            for (text, exact) in [
                ("[1.0,1.0),[1.0.0,1.0.0]", Some("1.0")),
                ("[1.0.0,1.0.0],[1.0,1.0)", Some("1.0")),
                ("[1.0,1.0],[1.0.0,1.0.0]", Some("1.0")),
                ("[1.0.0],[1.0]", Some("1.0.0")),
                ("(1.0,1.0)", Some("1.0")),
                ("[1.0,1.0)", None),
                ("(1.0,1.0),[2.0,2.0]", None),
            ] {
                let req = VersionReq::parse_in(text, mode).unwrap();
                let found = req.exact_version_in(mode).map(Version::as_str);
                assert_eq!(found, exact, "{text} {mode}");
            }
        }
    }

    /// The hashes maven-resolver-util 1.9.25 gives, `BigInteger` numbers
    /// and `min` among them.
    #[test]
    fn versions_hash_as_maven_resolver_19() {
        for (text, hash) in [
            ("0", 155),
            ("0.0.0", 155),
            ("ga", 93),
            ("1-ga-0", 156),
            ("1.0-SNAPSHOT", 4897),
            ("1234567890", 1_234_568_076),
            ("98765432109876543210", -550_835_151),
            ("1-foo", 106_503),
            ("max", 108_155),
            ("1.0.min", 261_874),
        ] {
            assert_eq!(v(text).java_hash(), hash, "{text}");
        }
    }

    /// maven-resolver's union of ranges is bounded by its lowest lower and
    /// highest upper bound, and the range resolver takes a union whose two
    /// are one inclusive version as that version: of equal ranges, the one
    /// its set walks first.
    #[test]
    fn a_union_of_one_version_is_that_version() {
        for mode in [MavenMode::Maven39, MavenMode::Maven310] {
            for (text, exact) in [
                ("[1.0][1.0]", Some("1.0")),
                ("[1.0,1.0],[1.0,1.0]", Some("1.0")),
                ("[1.0,1.0],[1.0.0,1.0.0]", Some("1.0")),
                ("[1.0.0],[1.0]", Some("1.0.0")),
                ("[1,1],[2,2]", None),
                ("[1,1],[1,2]", None),
            ] {
                let req = VersionReq::parse_in(text, mode).unwrap();
                let found = req.exact_version_in(mode).map(Version::as_str);
                assert_eq!(found, exact, "{text} {mode}");
            }
        }
    }
}
