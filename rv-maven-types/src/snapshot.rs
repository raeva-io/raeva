//! Maven SNAPSHOT version shapes, as maven-resolver 1.9 decides them for
//! the repository requests Maven 3.9 makes.
//!
//! `AbstractArtifact.isSnapshot` calls a version a snapshot when it ends in
//! `SNAPSHOT`, case-sensitively and with or without a hyphen, or when it
//! matches `^(.*-)?([0-9]{8}\.[0-9]{6}-[0-9]+)$`, a deployed snapshot file
//! version such as `1.0-20240101.010101-7`. The timestamp is checked for
//! shape only, digits are ASCII, and the part before it may be empty:
//! `20240101.010101-7` is a snapshot whose directory is `SNAPSHOT`.
//! `DefaultVersionResolver` reads snapshot metadata only for a version that
//! ends in `SNAPSHOT`.
//!
//! The listing of a version range is filtered by repository policy with
//! Maven's own `ArtifactUtils.isSnapshot` instead, which ignores case and
//! requires a hyphen before a timestamp; see [`is_listed_snapshot_version`].

const SNAPSHOT: &str = "SNAPSHOT";

/// A timestamped snapshot version split into its parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampedSnapshot<'a> {
    /// Everything before the timestamp: empty, or ending in `-`.
    prefix: &'a str,
    timestamp: &'a str,
    build: &'a str,
}

impl<'a> TimestampedSnapshot<'a> {
    /// Splits `[<base>-]<YYYYMMDD.HHMMSS>-<build>`. Returns `None` for any
    /// other shape, including `SNAPSHOT` versions.
    pub fn parse(version: &'a str) -> Option<Self> {
        let (rest, build) = version.rsplit_once('-')?;
        let split = rest.len().checked_sub(TIMESTAMP_LEN)?;
        if !is_ascii_digits(build) || !rest.is_char_boundary(split) {
            return None;
        }
        let (prefix, timestamp) = rest.split_at(split);
        if !is_snapshot_timestamp(timestamp) || !(prefix.is_empty() || prefix.ends_with('-')) {
            return None;
        }
        Some(Self {
            prefix,
            timestamp,
            build,
        })
    }

    /// The `YYYYMMDD.HHMMSS` part.
    pub fn timestamp(&self) -> &'a str {
        self.timestamp
    }

    /// The build part as written.
    pub fn build(&self) -> &'a str {
        self.build
    }

    /// The build part as a number, or `None` when it does not fit in `u32`.
    pub fn build_number(&self) -> Option<u32> {
        self.build.parse().ok()
    }

    /// The `SNAPSHOT` version naming the directory this file lives in, e.g.
    /// `1.0-SNAPSHOT`, or `SNAPSHOT` when nothing precedes the timestamp.
    pub(crate) fn base_version(&self) -> String {
        format!("{}{SNAPSHOT}", self.prefix)
    }
}

const TIMESTAMP_LEN: usize = "YYYYMMDD.HHMMSS".len();

/// True for versions ending in `SNAPSHOT` and timestamped snapshot versions.
pub fn is_snapshot_version(version: &str) -> bool {
    version.ends_with(SNAPSHOT) || TimestampedSnapshot::parse(version).is_some()
}

/// True for a version that is resolved through its snapshot metadata,
/// `maven-metadata.xml` in its own directory: one ending in `SNAPSHOT`.
pub fn resolves_through_snapshot_metadata(version: &str) -> bool {
    version.ends_with(SNAPSHOT)
}

/// Maven's `ArtifactUtils.isSnapshot`, which filters the versions a
/// repository lists for a version range by that repository's policy: a
/// version ending in `SNAPSHOT` in any case, or `<base>-<timestamp>-<build>`
/// with a hyphen before the timestamp and a possibly empty base.
pub fn is_listed_snapshot_version(version: &str) -> bool {
    ends_in_snapshot_ignoring_case(version)
        || TimestampedSnapshot::parse(version).is_some_and(|snapshot| !snapshot.prefix.is_empty())
}

/// Java's `String.regionMatches(true, ...)` on the last eight UTF-16 units:
/// two characters match when they are equal, when their upper cases are,
/// or when the lower cases of those are, so `ſnapshot` (with U+017F) counts.
fn ends_in_snapshot_ignoring_case(version: &str) -> bool {
    let units: Vec<u16> = version.encode_utf16().collect();
    let Some(start) = units.len().checked_sub(SNAPSHOT.len()) else {
        return false;
    };
    units[start..]
        .iter()
        .zip(SNAPSHOT.chars())
        .all(|(&unit, expected)| {
            // A surrogate half is never one of these ASCII letters.
            let Some(actual) = char::from_u32(u32::from(unit)) else {
                return false;
            };
            let (actual_upper, expected_upper) = (java_upper(actual), java_upper(expected));
            actual == expected
                || actual_upper == expected_upper
                || java_lower(actual_upper) == java_lower(expected_upper)
        })
}

/// `Character.toUpperCase(char)`, which keeps a character whose upper case
/// is more than one character, such as `ß`.
fn java_upper(c: char) -> char {
    single(c.to_uppercase()).unwrap_or(c)
}

fn java_lower(c: char) -> char {
    single(c.to_lowercase()).unwrap_or(c)
}

fn single(mut chars: impl Iterator<Item = char>) -> Option<char> {
    let first = chars.next()?;
    chars.next().is_none().then_some(first)
}

/// The `SNAPSHOT` directory version for a snapshot, or `None` for a
/// release. `1.0-SNAPSHOT` maps to itself and `1.0-20240101.010101-7` maps
/// to `1.0-SNAPSHOT`.
pub fn snapshot_base_version(version: &str) -> Option<String> {
    if let Some(snapshot) = TimestampedSnapshot::parse(version) {
        return Some(snapshot.base_version());
    }
    version.ends_with(SNAPSHOT).then(|| version.to_string())
}

/// The file version a `SNAPSHOT` version resolves to from snapshot metadata
/// that has only a `<snapshot>` timestamp and build number, as
/// `DefaultVersionResolver` builds it: the version without `SNAPSHOT`,
/// followed by `<timestamp>-<build>`. `None` when `version` does not end in
/// `SNAPSHOT`.
pub fn timestamped_snapshot_version(version: &str, timestamp: &str, build: u32) -> Option<String> {
    let base = version.strip_suffix(SNAPSHOT)?;
    Some(format!("{base}{timestamp}-{build}"))
}

/// The timestamp and build number of one deployed snapshot file, the
/// `20240101.010101-7` in `1.0-20240101.010101-7`.
///
/// The timestamp always has the `YYYYMMDD.HHMMSS` shape. The order is
/// timestamp, then build number.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SnapshotStamp {
    timestamp: Box<str>,
    build: u32,
}

impl SnapshotStamp {
    /// A stamp from its parts. `None` unless `timestamp` has the
    /// `YYYYMMDD.HHMMSS` shape.
    pub fn new(timestamp: &str, build: u32) -> Option<Self> {
        is_snapshot_timestamp(timestamp).then(|| Self {
            timestamp: timestamp.into(),
            build,
        })
    }

    /// The stamp of a timestamped snapshot version such as
    /// `1.0-20240101.010101-7`. `None` for any other version, and when the
    /// build number does not fit in `u32`.
    pub fn of_version(version: &str) -> Option<Self> {
        let parsed = TimestampedSnapshot::parse(version)?;
        Self::new(parsed.timestamp(), parsed.build_number()?)
    }

    /// The stamp of `file_version`, a file version the `SNAPSHOT` version
    /// `version` resolved to: the inverse of [`Self::resolved_version`], so
    /// `1.020240101.010101-7` for `1.0SNAPSHOT` too. `None` for any other
    /// pair.
    pub fn of_file_version(version: &str, file_version: &str) -> Option<Self> {
        let base = version.strip_suffix(SNAPSHOT)?;
        let (timestamp, build) = file_version.strip_prefix(base)?.rsplit_once('-')?;
        // A padded build number would not name the same file again.
        let number: u32 = build.parse().ok()?;
        if !is_ascii_digits(build) || number.to_string() != build {
            return None;
        }
        Self::new(timestamp, number)
    }

    /// The `YYYYMMDD.HHMMSS` part.
    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }

    /// The build number, the part after the last `-`.
    pub fn build(&self) -> u32 {
        self.build
    }

    /// The file version this stamp gives the `SNAPSHOT` version
    /// `base_version`, e.g. `1.0-20240101.010101-7` for `1.0-SNAPSHOT`.
    /// `None` when `base_version` does not end in `SNAPSHOT`.
    pub fn resolved_version(&self, base_version: &str) -> Option<String> {
        timestamped_snapshot_version(base_version, &self.timestamp, self.build)
    }
}

/// `YYYYMMDD.HHMMSS-build`.
impl std::fmt::Display for SnapshotStamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.timestamp, self.build)
    }
}

/// True when `value` has the `YYYYMMDD.HHMMSS` shape of a snapshot
/// timestamp.
pub fn is_snapshot_timestamp(value: &str) -> bool {
    value.split_once('.').is_some_and(|(date, time)| {
        date.len() == 8 && time.len() == 6 && is_ascii_digits(date) && is_ascii_digits(time)
    })
}

fn is_ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{
        SnapshotStamp, TimestampedSnapshot, is_listed_snapshot_version, is_snapshot_timestamp,
        is_snapshot_version, resolves_through_snapshot_metadata, snapshot_base_version,
        timestamped_snapshot_version,
    };

    /// maven-resolver's `^(.*-)?([0-9]{8}\.[0-9]{6})-([0-9]+)$`: the greedy
    /// base keeps earlier hyphens and may be empty, the calendar is not
    /// checked, and an oversized build has no number.
    #[test]
    fn parses_timestamped_snapshots() {
        for (version, base, number) in [
            ("1.0-20240101.010101-7", "1.0-SNAPSHOT", Some(7)),
            (
                "1.0-beta-1-20240101.010101-12",
                "1.0-beta-1-SNAPSHOT",
                Some(12),
            ),
            ("-20240101.010101-7", "-SNAPSHOT", Some(7)),
            ("20240101.010101-7", "SNAPSHOT", Some(7)),
            ("1.0-20240230.250000-1", "1.0-SNAPSHOT", Some(1)),
            ("1.0-20240101.010101-99999999999", "1.0-SNAPSHOT", None),
        ] {
            let snapshot = TimestampedSnapshot::parse(version).unwrap();
            let stamp = format!("-{}-{}", snapshot.timestamp(), snapshot.build());
            assert!(format!("-{version}").ends_with(&stamp), "{version}");
            assert_eq!(snapshot.timestamp().len(), 15, "{version}");
            assert_eq!(snapshot.base_version(), base, "{version}");
            assert_eq!(snapshot.build_number(), number, "{version}");
        }
    }

    #[test]
    fn rejects_shapes_maven_rejects() {
        for version in [
            "1.0",
            "1.0-SNAPSHOT",
            "1.0-20240101.010101",
            "1.0-20240101.010101-",
            "1.0-20240101.010101-x",
            "1.0-20240101.010101-+7",
            "1.0-20240101010101-7",
            "1.0-2024010.0101011-7",
            "1.0-20240101.01010A-7",
            "1.0-20240101.0101011-7",
            "1.020240101.010101-7",
            "1.0-\u{0661}0240101.010101-7",
            "1.0-20240101.010101-\u{0667}",
            "\u{e9}20240101.010101-7",
        ] {
            assert!(
                TimestampedSnapshot::parse(version).is_none(),
                "{version} must not parse"
            );
        }
    }

    #[test]
    fn classifies_snapshot_versions_as_maven_does() {
        // (version, resolver snapshot, through metadata, ArtifactUtils listed)
        for (version, snapshot, metadata, listed) in [
            ("1.0-SNAPSHOT", true, true, true),
            ("1.0SNAPSHOT", true, true, true),
            ("SNAPSHOT", true, true, true),
            ("1.0-20231115.123456-1", true, false, true),
            ("20231115.123456-1", true, false, false),
            ("-20231115.123456-1", true, false, true),
            ("1.0-snapshot", false, false, true),
            ("1.0", false, false, false),
            ("NAPSHOT", false, false, false),
            // Java's case-insensitive comparison also folds U+017F to `S`.
            ("1.0-\u{17f}napshot", false, false, true),
            ("1.0-\u{df}napshot", false, false, false),
        ] {
            assert_eq!(is_snapshot_version(version), snapshot, "{version}");
            assert_eq!(
                resolves_through_snapshot_metadata(version),
                metadata,
                "{version}"
            );
            assert_eq!(is_listed_snapshot_version(version), listed, "{version}");
        }
        assert!(is_snapshot_timestamp("20240101.010101"));
        for text in [
            "20240101",
            "20240101-010101",
            "20240101.01010A",
            "",
            "20240101.010101.1",
        ] {
            assert!(!is_snapshot_timestamp(text), "{text}");
        }
    }

    #[test]
    fn maps_snapshots_between_directory_and_timestamped_versions() {
        let base = |version| snapshot_base_version(version);
        assert_eq!(base("1.0-SNAPSHOT").as_deref(), Some("1.0-SNAPSHOT"));
        assert_eq!(base("1.0SNAPSHOT").as_deref(), Some("1.0SNAPSHOT"));
        assert_eq!(
            base("1.0-20240101.010101-7").as_deref(),
            Some("1.0-SNAPSHOT")
        );
        assert_eq!(base("1.0"), None);
        let stamped = |version| timestamped_snapshot_version(version, "20240101.010101", 7);
        assert_eq!(
            stamped("1.0-SNAPSHOT").as_deref(),
            Some("1.0-20240101.010101-7")
        );
        assert_eq!(
            stamped("1.0SNAPSHOT").as_deref(),
            Some("1.020240101.010101-7")
        );
        assert_eq!(stamped("1.0"), None);
        let stamp = SnapshotStamp::of_version("1.0-20240101.010101-7").unwrap();
        assert_eq!((stamp.timestamp(), stamp.build()), ("20240101.010101", 7));
        assert_eq!(stamp.to_string(), "20240101.010101-7");
        assert_eq!(
            stamp.resolved_version("1.0-SNAPSHOT").as_deref(),
            Some("1.0-20240101.010101-7")
        );
        assert_eq!(stamp.resolved_version("1.0"), None);
        assert_eq!(SnapshotStamp::of_version("1.0-SNAPSHOT"), None);
        let of_file = |version, file| SnapshotStamp::of_file_version(version, file);
        assert_eq!(
            of_file("1.0-SNAPSHOT", "1.0-20240101.010101-7"),
            Some(stamp.clone())
        );
        assert_eq!(
            of_file("1.0SNAPSHOT", "1.020240101.010101-7"),
            Some(stamp.clone())
        );
        assert_eq!(of_file("1.0-SNAPSHOT", "1.0-SNAPSHOT"), None);
        assert_eq!(of_file("1.0-SNAPSHOT", "1.0-20240101.010101-+7"), None);
        assert_eq!(of_file("1.0-SNAPSHOT", "1.0-20240101.010101-007"), None);
        assert_eq!(of_file("1.0-SNAPSHOT", "2.0-20240101.010101-7"), None);
        assert_eq!(of_file("1.0", "1.0-20240101.010101-7"), None);
        assert_eq!(
            SnapshotStamp::of_version("1.0-20240101.010101-99999999999"),
            None
        );
        assert_eq!(SnapshotStamp::new("2024-01-01", 1), None);
    }
}
