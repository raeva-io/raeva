//! The Git merge conflicts a lock's text can hold.
//!
//! Git writes 7-character markers by default and longer ones under the
//! `conflict-marker-size` attribute or for the base of a recursive merge, so
//! a marker here is any run of 7 or more.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use crate::error::LockError;
use crate::lock::{LockPlatform, Lockfile};

/// The versions of a text that Git merge conflicts split it into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sides {
    /// No line of the text is a conflict marker.
    Clean,
    /// The text with each conflict replaced by our side, then by their
    /// side. A diff3 base belongs to neither.
    Conflicted {
        /// Our side.
        ours: String,
        /// Their side.
        theirs: String,
    },
    /// A marker, at this line counted from 1, that opens, splits or closes
    /// no conflict, or a conflict the text does not close.
    Malformed {
        /// The line of the marker, or one past the last line.
        line: usize,
    },
}

/// One side of a merge conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The side of the branch merged into.
    Ours,
    /// The side of the branch merged in.
    Theirs,
}

impl std::fmt::Display for Side {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ours => "our side",
            Self::Theirs => "their side",
        })
    }
}

/// The pins of each version of a lock that `text` holds: each side of its
/// merge conflicts, or the text itself, with no side, when it has none.
///
/// Each is a lockfile of artifact rows, support POMs and the modules' build
/// extension jars alone, read whatever its schema version: what
/// [`Lockfile::pinned_paths`], [`Lockfile::pinned_snapshots`] and
/// [`Lockfile::repinned_releases`] need of a lock that does not read whole.
/// It fails every check of a written lock and is never written. `Err` says
/// which version cannot be read and why: a part that is not TOML, a row
/// that does not decode or a conflict marker out of place, whose pins are
/// then lost.
pub fn recover_pins(text: &str) -> Result<Vec<(Option<Side>, Lockfile)>, String> {
    let versions = match sides(text) {
        Sides::Clean => vec![(None, text.replace("\r\n", "\n"))],
        Sides::Conflicted { ours, theirs } => {
            vec![(Some(Side::Ours), ours), (Some(Side::Theirs), theirs)]
        }
        Sides::Malformed { line } => {
            return Err(format!(
                "its merge conflict markers do not pair up at line {line}"
            ));
        }
    };
    (versions.into_iter())
        .map(|(side, text)| {
            let platforms = crate::codec::decode_pins(&text).map_err(|err| {
                let err = match err {
                    LockError::Toml { message, .. } => message,
                    err => err.to_string(),
                };
                match side {
                    Some(side) => format!("{side} of its merge conflict does not read: {err}"),
                    None => format!("its rows do not read: {err}"),
                }
            })?;
            if platforms.is_empty() {
                return Err(match side {
                    Some(side) => format!("{side} of its merge conflict has no platform"),
                    None => "it has no platform".to_string(),
                });
            }
            let mut pins = Lockfile::new();
            pins.platforms = platforms;
            Ok((side, pins))
        })
        .collect()
}

/// A file that two rows of the locks [`disagreements`] compares record
/// differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disagreement {
    /// The file's path below a Maven repository root.
    pub path: String,
    /// The index of the first lock and what it records: a digest, as
    /// `sha256 <hex>`, or `no POM`.
    pub first: (usize, String),
    /// The same for the second, which may be the same lock.
    pub second: (usize, String),
}

/// Each release file or timestamped snapshot build that rows of `locks`, in
/// one lock or across them, pin to other bytes by one algorithm, or that
/// one row pins as a companion POM and another records as missing. Only
/// non-unique snapshot filenames, which can be redeployed, are left out.
pub fn disagreements(locks: &[&Lockfile]) -> Vec<Disagreement> {
    let mut seen: BTreeMap<(String, &'static str), (usize, String)> = BTreeMap::new();
    let mut found: BTreeMap<String, Disagreement> = BTreeMap::new();
    for (index, lock) in locks.iter().enumerate() {
        let platforms = &lock.platforms;
        let rows = platforms.iter().flat_map(|platform| &platform.artifacts);
        let mut records: Vec<(String, &'static str, String)> = Vec::new();
        for row in rows {
            for digest in &row.checksums {
                let algorithm = digest.algorithm().as_str();
                records.push((
                    row.repository_path(),
                    algorithm,
                    format!("{algorithm} {}", digest.hex()),
                ));
            }
            match &row.pom_sha256 {
                Some(pom) => {
                    records.push((row.pom_path(), "sha256", format!("sha256 {pom}")));
                    records.push((row.pom_path(), "pom", "a POM".to_string()));
                }
                None if !row.is_own_pom() => {
                    records.push((row.pom_path(), "pom", "no POM".to_string()));
                }
                None => {}
            }
        }
        for (path, jar) in lock.platforms.iter().flat_map(LockPlatform::extension_jars) {
            records.push((path, "sha256", format!("sha256 {}", jar.sha256)));
        }
        for platform in platforms {
            for (coord, pin) in &platform.support_poms {
                if let Some(path) = pin.repository_path(coord) {
                    records.push((path.clone(), "sha256", format!("sha256 {}", pin.sha256)));
                    records.push((path, "pom", "a POM".to_string()));
                }
            }
        }
        for (path, kind, value) in records {
            if rv_maven_types::layout::is_mutable_snapshot_path(&path) || found.contains_key(&path)
            {
                continue;
            }
            match seen.entry((path.clone(), kind)) {
                Entry::Vacant(entry) => {
                    entry.insert((index, value));
                }
                Entry::Occupied(entry) if entry.get().1 != value => {
                    let first = entry.get().clone();
                    found.insert(
                        path.clone(),
                        Disagreement {
                            path,
                            first,
                            second: (index, value),
                        },
                    );
                }
                Entry::Occupied(_) => {}
            }
        }
    }
    found.into_values().collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Marker {
    Open,
    Base,
    Split,
    Close,
}

/// The kind and length of the conflict marker `line` is: 7 or more of one
/// marker character, then the end of the line or a space and a label.
fn marker(line: &str) -> Option<(Marker, usize)> {
    let kind = match line.as_bytes().first()? {
        b'<' => Marker::Open,
        b'|' => Marker::Base,
        b'=' => Marker::Split,
        b'>' => Marker::Close,
        _ => return None,
    };
    let first = line.as_bytes()[0];
    let size = line.bytes().take_while(|&byte| byte == first).count();
    let rest = &line[size..];
    (size >= 7 && (rest.is_empty() || rest.starts_with(' '))).then_some((kind, size))
}

/// The highest top-level `schema_version` above this raeva's that `text`
/// declares, on either side of a merge conflict, or, when its markers do
/// not pair up, in any part between them. A part that does not parse
/// declares the ones its lines before the first table set.
pub fn newer_schema(text: &str) -> Option<u32> {
    let versions = match sides(text) {
        Sides::Clean => vec![text.to_string()],
        Sides::Conflicted { ours, theirs } => vec![ours, theirs],
        Sides::Malformed { .. } => (text.lines().collect::<Vec<_>>())
            .split(|line| marker(line).is_some())
            .map(|part| part.join("\n"))
            .collect(),
    };
    (versions.iter())
        .filter_map(|side| match side.parse::<toml::Table>() {
            Ok(table) => u32::try_from(table.get("schema_version")?.as_integer()?).ok(),
            Err(_) => (side.lines())
                .take_while(|line| !line.trim_start().starts_with('['))
                .filter_map(schema_line)
                .max(),
        })
        .filter(|&found| found > crate::LOCKFILE_SCHEMA_VERSION)
        .max()
}

/// The version a `schema_version = <integer>` line sets.
fn schema_line(line: &str) -> Option<u32> {
    let value = (line
        .trim_start()
        .strip_prefix("schema_version")?
        .trim_start())
    .strip_prefix('=')?;
    let value = value.split_once('#').map_or(value, |(value, _)| value);
    value.trim().parse().ok()
}

/// The first line, counted from 1, that is a conflict marker.
pub(crate) fn first_marker_line(text: &str) -> Option<usize> {
    text.lines()
        .position(|line| marker(line).is_some())
        .map(|index| index + 1)
}

/// Split `text` into the versions its merge conflicts hold. A conflict opens
/// with `<`, may hold a diff3 base after `|`, splits at `=` and closes with
/// `>`, all of one length; a marker of another length inside it is a line
/// of the conflict.
pub fn sides(text: &str) -> Sides {
    #[derive(Clone, Copy)]
    enum In {
        Both,
        Ours(usize),
        Base(usize),
        Theirs(usize),
    }
    let (mut ours, mut theirs) = (String::new(), String::new());
    let (mut state, mut conflicted, mut lines) = (In::Both, false, 0);
    for line in text.lines() {
        lines += 1;
        let next = match (state, marker(line)) {
            (In::Both, Some((Marker::Open, size))) => Some(In::Ours(size)),
            (In::Both, Some(_)) => return Sides::Malformed { line: lines },
            (In::Ours(open), Some((Marker::Base, size))) if size == open => Some(In::Base(open)),
            (In::Ours(open) | In::Base(open), Some((Marker::Split, size))) if size == open => {
                Some(In::Theirs(open))
            }
            (In::Theirs(open), Some((Marker::Close, size))) if size == open => Some(In::Both),
            (In::Ours(open) | In::Base(open) | In::Theirs(open), Some((_, size)))
                if size == open =>
            {
                return Sides::Malformed { line: lines };
            }
            _ => None,
        };
        if let Some(next) = next {
            conflicted = true;
            state = next;
            continue;
        }
        let (to_ours, to_theirs) = match state {
            In::Both => (true, true),
            In::Ours(_) => (true, false),
            In::Base(_) => (false, false),
            In::Theirs(_) => (false, true),
        };
        for (side, keep) in [(&mut ours, to_ours), (&mut theirs, to_theirs)] {
            if keep {
                side.push_str(line);
                side.push('\n');
            }
        }
    }
    match state {
        In::Both if conflicted => Sides::Conflicted { ours, theirs },
        In::Both => Sides::Clean,
        _ => Sides::Malformed { line: lines + 1 },
    }
}

#[cfg(test)]
mod tests {
    use super::{Disagreement, Side, Sides, disagreements, first_marker_line, recover_pins, sides};
    use crate::test_lock::{linux_lock, lock, locked_platform, package, set_support_pom};

    fn conflicted(ours: &str, theirs: &str) -> Sides {
        Sides::Conflicted {
            ours: ours.to_string(),
            theirs: theirs.to_string(),
        }
    }

    /// A newer schema stops a sync even when its text does not parse, so
    /// not even `--update` replaces it.
    #[test]
    fn a_newer_schema_is_found_in_a_text_that_does_not_parse() {
        let newer = crate::LOCKFILE_SCHEMA_VERSION + 1;
        let line = format!("schema_version = {newer} # a comment\n");
        for text in [
            format!("{line}{line}"),
            format!("{line}not toml\n"),
            format!("=======\n{line}"),
            format!("<<<<<<< ours\n{line}"),
            format!("<<<<<<< ours\nschema_version = 9\n[[platforms]]\n=======\n{line}"),
            format!(
                "<<<<<<< ours\nschema_version = 9\n[[platforms]]\nx = 1\n=======\n{line}{line}"
            ),
        ] {
            assert_eq!(super::newer_schema(&text), Some(newer), "{text:?}");
        }
        let current = format!("schema_version = {}\n", crate::LOCKFILE_SCHEMA_VERSION);
        let nested = format!("{current}not toml\n[x]\n{line}");
        assert_eq!(super::newer_schema(&nested), None);
    }

    #[test]
    fn each_side_keeps_the_lines_outside_the_conflicts() {
        let text = "a\n<<<<<<< HEAD\nb\n=======\nc\n>>>>>>> topic\nd\n";
        assert_eq!(sides(text), conflicted("a\nb\nd\n", "a\nc\nd\n"));
        let diff3 = "a\n<<<<<<< HEAD\nb\n||||||| base\nx\n=======\nc\n>>>>>>> topic\n";
        assert_eq!(sides(diff3), conflicted("a\nb\n", "a\nc\n"));
        assert_eq!(sides("a\n=====\nb\n"), Sides::Clean);
        assert_eq!(first_marker_line("a\n=====\n<<<<<<<x\n"), None);
    }

    /// Git writes longer markers under `conflict-marker-size`, and a
    /// recursive merge's base can hold markers of another length, which are
    /// lines of the conflict.
    #[test]
    fn markers_of_any_length_from_seven_split_a_conflict() {
        let long = "<<<<<<<<< HEAD\nb\n=========\nc\n>>>>>>>>> topic\n";
        assert_eq!(sides(long), conflicted("b\n", "c\n"));
        assert_eq!(first_marker_line(long), Some(1));
        let nested = "<<<<<<< HEAD\nb\n||||||| base\n<<<<<<<<< x\n=========\n\
                      >>>>>>>>> y\n=======\nc\n>>>>>>> topic\n";
        assert_eq!(sides(nested), conflicted("b\n", "c\n"));
        let inner = "<<<<<<<<< HEAD\n=======\n=========\nc\n>>>>>>>>> topic\n";
        assert_eq!(sides(inner), conflicted("=======\n", "c\n"));
    }

    #[test]
    fn a_marker_out_of_place_or_a_conflict_left_open_is_malformed() {
        for (text, line) in [
            ("a\n=======\n", 2),
            ("a\n>>>>>>> topic\n", 2),
            ("<<<<<<< HEAD\nb\n>>>>>>> topic\n", 3),
            ("<<<<<<< HEAD\nb\n=======\n<<<<<<< again\n", 4),
            ("<<<<<<< HEAD\nb\n=======\nc\n", 5),
        ] {
            assert_eq!(sides(text), Sides::Malformed { line }, "{text:?}");
        }
        assert_eq!(
            sides("a\r\n<<<<<<< HEAD\r\nb\r\n=======\r\nc\r\n>>>>>>> topic\r\n"),
            conflicted("a\nb\n", "a\nc\n")
        );
    }

    /// `text` with the checksums of its first row left out.
    fn unpinned(text: &str) -> String {
        let start = text.find("[[platforms.artifacts.checksums]]").unwrap();
        let end = start + text[start..].find("\n\n").unwrap() + 2;
        let text = format!("{}{}", &text[..start], &text[end..]);
        text.replacen(
            "[[platforms.artifacts]]\n",
            "[[platforms.artifacts]]\nchecksums = []\n",
            1,
        )
    }

    /// Each side keeps its rows' pins, read without the checks a whole lock
    /// passes, and a side with an unreadable or unpinned row, no platform
    /// or no module is lost.
    #[test]
    fn the_pins_of_each_side_are_recovered() {
        let ours = linux_lock("1.0", 'a').to_toml().unwrap();
        let theirs = linux_lock("2.0", 'b').to_toml().unwrap();
        let both = format!("<<<<<<< ours\n{ours}=======\n{theirs}>>>>>>> theirs\n");
        let versions = recover_pins(&both).unwrap();
        let sides: Vec<_> = versions.iter().map(|(side, _)| *side).collect();
        assert_eq!(sides, [Some(Side::Ours), Some(Side::Theirs)]);
        let paths = |index: usize| {
            let mut paths: Vec<String> = versions[index].1.pinned_paths().into_keys().collect();
            paths.sort();
            paths
        };
        assert_eq!(
            paths(1),
            ["com/example/a/2.0/a-2.0.jar", "com/example/a/2.0/a-2.0.pom"]
        );
        // Modules and inputs are not read, so a side that breaks them keeps
        // its pins.
        let broken = theirs.replace("com.example:a:2.0", "com.example:a:9.9");
        let pins = recover_pins(&broken).unwrap();
        assert_eq!(pins[0].0, None);
        assert!(pins[0].1.check().is_err());
        assert_eq!(pins[0].1.pinned_paths().len(), 2);

        let mut parent = linux_lock("1.0", 'a');
        set_support_pom(&mut parent, "com.example:parent:1.0", '7');
        let parent = parent.to_toml().unwrap();
        let row = "coordinate = \"com.example:parent:1.0\"\n";
        assert!(parent.contains(row), "{parent}");
        let stamp = "snapshot = { timestamp = \"20240101.010101\", build_number = 1 }\n";
        for (text, lost) in [
            (
                parent.replace(row, "coordinate = \"com.example:parent:1.0:extra\"\n"),
                "its rows do not read: invalid lockfile: support POM coordinate \
                 \"com.example:parent:1.0:extra\" must be 'group:artifact:version'",
            ),
            (
                parent.replace(row, &format!("{row}{stamp}")),
                "its rows do not read: invalid lockfile: support POM 'com.example:parent:1.0' \
                 on platform 'linux-x86_64' records a snapshot build",
            ),
            (
                ours.replace(
                    "[[platforms.modules]]\n",
                    "[[platforms.modules]]\nextensions = 1\n",
                ),
                "its rows do not read: invalid lockfile: a module on platform 'linux-x86_64' \
                 must be a table whose extensions are a string",
            ),
            (
                format!("<<<<<<< ours\n{ours}=======\nnot toml\n>>>>>>> theirs\n"),
                "their side of its merge conflict does not read",
            ),
            (
                format!("<<<<<<< ours\n{ours}=======\nschema_version = 8\n>>>>>>> theirs\n"),
                "their side of its merge conflict has no platform",
            ),
            (
                ours.replace(
                    "[[platforms.artifacts]]\n",
                    "[[platforms.artifacts]]\nextra = 1\n",
                ),
                "its rows do not read: unknown field `extra`",
            ),
            (
                format!("{ours}=======\n"),
                "its merge conflict markers do not pair up at line",
            ),
            (
                ours[..ours.find("[[platforms.modules]]").unwrap()].to_string(),
                "its rows do not read: invalid lockfile: a platform graph lists no module",
            ),
            (
                unpinned(&ours),
                "its rows do not read: invalid lockfile: artifact 'com.example:a:1.0:jar' has \
                 no checksum",
            ),
        ] {
            let err = recover_pins(&text).unwrap_err();
            assert!(err.starts_with(lost), "{lost}: {err}");
        }
    }

    /// A module's build extension jar pins its bytes outside the rows, so
    /// each side keeps it and two sides that pin other bytes disagree.
    #[test]
    fn a_build_extension_jar_keeps_its_pin() {
        let side = |digest: char| {
            let mut lock = linux_lock("1.0", 'a');
            lock.platforms[0].modules[0].extensions = vec![crate::ExtensionJar {
                gav: rv_maven_types::Gav::new("t", "ext", "2"),
                classifier: None,
                sha256: digest.to_string().repeat(64).parse().unwrap(),
            }];
            lock.to_toml().unwrap()
        };
        let both = format!(
            "<<<<<<< ours\n{}=======\n{}>>>>>>> theirs\n",
            side('c'),
            side('d')
        );
        let versions = recover_pins(&both).unwrap();
        let (pin, _) = &versions[0].1.pinned_paths()["t/ext/2/ext-2.jar"];
        assert_eq!(pin.hex(), "c".repeat(64));
        let locks: Vec<_> = versions.iter().map(|(_, lock)| lock).collect();
        assert_eq!(disagreements(&locks)[0].path, "t/ext/2/ext-2.jar");
    }

    #[test]
    fn rows_that_pin_one_file_two_ways_disagree() {
        let path = "com/example/a/1.0/a-1.0.jar";
        let (good, other) = (linux_lock("1.0", 'a'), linux_lock("1.0", 'b'));
        let found = disagreements(&[&good, &good, &other]);
        assert_eq!(
            found,
            [Disagreement {
                path: path.to_string(),
                first: (0, format!("sha256 {}", "a".repeat(64))),
                second: (2, format!("sha256 {}", "b".repeat(64))),
            }]
        );
        // Two rows of one lock, a SHA-1 pin and a POM recorded as missing.
        let mut both = good.clone();
        both.platforms.extend(other.platforms.clone());
        assert_eq!(disagreements(&[&both])[0].second.0, 0);
        let sha1 = |digest: char| {
            let mut lock = linux_lock("1.0", 'a');
            lock.platforms[0].artifacts[0].checksums = vec![
                rv_maven_types::Digest::parse("sha1", &digest.to_string().repeat(40)).unwrap(),
            ];
            lock
        };
        assert_eq!(disagreements(&[&sha1('d'), &sha1('e')])[0].path, path);
        assert!(disagreements(&[&sha1('d'), &good]).is_empty());
        let mut missing = good.clone();
        missing.platforms[0].artifacts[0].pom_sha256 = None;
        let found = disagreements(&[&good, &missing]);
        assert_eq!(found[0].path, "com/example/a/1.0/a-1.0.pom");
        assert_eq!(found[0].second.1, "no POM");
        let mut support = lock(vec![locked_platform("linux-x86_64", Vec::new(), '7')]);
        set_support_pom(&mut support, "com.example:a:1.0", '7');
        assert_eq!(disagreements(&[&support, &missing])[0].first.1, "a POM");
        // A non-unique snapshot filename can be redeployed.
        let snapshot = |digest| {
            let packages = vec![package("a", "1.0-SNAPSHOT", digest)];
            lock(vec![locked_platform("linux-x86_64", packages, '7')])
        };
        assert!(disagreements(&[&snapshot('a'), &snapshot('b')]).is_empty());
    }
}
