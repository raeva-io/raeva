use std::fmt;

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
                    && l > u
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
        use std::cmp::Ordering;
        let above = self.lower.as_ref().is_none_or(|lower| match v.cmp(lower) {
            Ordering::Less => false,
            Ordering::Equal => self.include_lower,
            Ordering::Greater => true,
        });
        let below = self.upper.as_ref().is_none_or(|upper| match v.cmp(upper) {
            Ordering::Greater => false,
            Ordering::Equal => self.include_upper,
            Ordering::Less => true,
        });
        above && below
    }

    pub(crate) fn is_exact(&self) -> bool {
        match (&self.lower, &self.upper) {
            (Some(l), Some(u)) => l == u && self.include_lower && self.include_upper,
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

    /// The one version a hard pin such as `[1.0]` or `[1.0,1.0]` admits.
    pub fn exact_version(&self) -> Option<&Version> {
        match self {
            VersionReq::Exact(exact) => Some(exact),
            VersionReq::Ranges(ranges) => match &ranges[..] {
                [range] if range.is_exact() => range.lower.as_ref(),
                _ => None,
            },
            VersionReq::Soft(_) => None,
        }
    }

    /// Returns true if the given version satisfies this requirement.
    pub fn matches(&self, v: &Version) -> bool {
        match self {
            VersionReq::Exact(exact) | VersionReq::Soft(exact) => v == exact,
            VersionReq::Ranges(ranges) => ranges.iter().any(|range| range.matches(v)),
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

/// Splits a comma-joined union of bracketed ranges (e.g. `[1.0,2.0),[3.0,)`)
/// into one slice per range. Internal commas inside a range are not separators;
/// the bracket pair delimits each range. After the first range, exactly one
/// comma (optional whitespace around it) is required before the next range.
/// Errors on empty input, missing brackets, missing commas between ranges, or
/// content between ranges that is not itself a bracketed range.
fn split_union_ranges(input: &str) -> Result<Vec<&str>, VersionError> {
    let invalid = || VersionError::InvalidRange(input.to_string());
    let mut ranges = Vec::new();
    let mut rest = input.trim();
    // `GenericVersionScheme.parseVersionConstraint`: one comma may follow
    // each range. Adjacent ranges without a comma are refused.
    while rest.starts_with(['[', '(']) {
        let end = rest.find([']', ')']).ok_or_else(invalid)?;
        ranges.push(&rest[..=end]);
        rest = rest[end + 1..].trim();
        if rest.is_empty() {
            break;
        }
        let Some(after) = rest.strip_prefix(',') else {
            return Err(invalid());
        };
        rest = after.trim();
        if rest.is_empty() {
            break;
        }
        if !rest.starts_with(['[', '(']) {
            return Err(invalid());
        }
    }
    if ranges.is_empty() || !rest.is_empty() {
        return Err(invalid());
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::VersionReq;
    use crate::Version;

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
            ",,,",
            "[1.0,2.0",
            "[1.0",
            "]",
            ")",
            "1.0]",
            "1.0)",
            "1.0,2.0]",
            "1.0,2.0",
            "[1.0,2.0),invalid",
            "[1.0,2.0],,",
            "[1.0,2.0],,[3.0,4.0]",
            // Maven rejects adjacent ranges with no comma between them.
            "[1.0,2.0)[3.0,)",
            "[1.0,2.0)[3.0,](4.0,)",
            "[1.0][2.0]",
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

    /// Union ranges must be joined by a comma; whitespace around the comma is fine.
    #[test]
    fn union_ranges_require_a_comma() {
        VersionReq::parse("[1.0,2.0)[3.0,)").expect_err("no comma between ranges");
        let with_comma = VersionReq::parse("[1.0,2.0),[3.0,)").unwrap();
        let with_spaces = VersionReq::parse("[1.0,2.0) , [3.0,)").unwrap();
        assert!(with_comma.matches(&v("1.5")));
        assert!(with_comma.matches(&v("3.0")));
        assert!(!with_comma.matches(&v("2.5")));
        assert!(with_spaces.matches(&v("1.5")));
        assert!(with_spaces.matches(&v("3.0")));
        assert!(!with_spaces.matches(&v("2.5")));
    }
}
