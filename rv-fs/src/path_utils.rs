//! Filesystem path helpers shared across crates.
//!
//! These utilities deal with resolving user-supplied paths to absolute,
//! symlink-aware locations without requiring the path to exist yet.

use std::path::{Path, PathBuf};

/// Resolve `path` to an absolute, symlink-resolved form even when the path
/// does not (yet) exist on disk. The deepest existing ancestor is
/// canonicalized; any remaining components are appended lexically.
///
/// This is the building block for containment checks: callers can compare
/// a not-yet-created destination against an existing root while still
/// refusing symlinked ancestors that escape the root (a symlinked
/// ancestor canonicalizes to its real target, so a subsequent
/// `starts_with` check will fail).
///
/// Returns an error only if the path is relative and the current working
/// directory cannot be read.
pub fn canonicalize_existing_prefix(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut existing = absolute.as_path();
    let mut remainder = Vec::new();
    while !existing.exists() {
        let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
            return Ok(absolute);
        };
        remainder.push(name);
        existing = parent;
    }
    let mut result = canonicalize_plain(existing)
        .unwrap_or_else(|_| strip_verbatim_disk(existing.to_path_buf()));
    result.extend(remainder.into_iter().rev());
    Ok(result)
}

/// Canonicalize an existing path for comparison only: symlinks resolved and,
/// on Windows, no `\\?\` prefix on a local drive path, whatever its length.
/// Two results compare as their canonical paths do, but the plain text can
/// name a different file than the canonical one (a trailing dot, a reserved
/// device name), so never open or interpolate it.
fn canonicalize_plain(path: &Path) -> std::io::Result<PathBuf> {
    dunce::canonicalize(path).map(strip_verbatim_disk)
}

/// The form of a canonical path to show users or interpolate as
/// `${project.basedir}`. On Windows the `\\?\` prefix of a local drive path
/// is dropped when the plain path names the same file, by the rules `dunce`
/// simplifies with; otherwise the path is returned unchanged. Unlike `dunce`,
/// a path over 260 characters is simplified too: programs open a long plain
/// path by normalizing it the same way and adding the prefix back, so its
/// length does not change which file it names.
///
/// Filesystem access and comparisons use the canonical path itself.
pub fn plain_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let mut components = path.components();
        let verbatim_disk = matches!(
            components.next(),
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::VerbatimDisk(_))
        );
        let safe = verbatim_disk
            && components.all(|component| match component {
                Component::RootDir => true,
                Component::Normal(name) => plain_name_is_safe(name),
                _ => false,
            });
        if safe && let Some(plain) = path.to_str().and_then(|text| text.get(4..)) {
            return PathBuf::from(plain);
        }
    }
    path.to_path_buf()
}

/// Whether Windows reads `name` back unchanged outside a `\\?\` path: `dunce`'s
/// checks for invalid characters, a trailing dot or space, and DOS device
/// names, which Win32 path normalization would trim or redirect. A name over
/// 255 UTF-16 units is refused too, since NTFS cannot store one.
pub fn plain_name_is_safe(name: &std::ffi::OsStr) -> bool {
    let Some(text) = name.to_str() else {
        return false;
    };
    if text.is_empty()
        || text.encode_utf16().count() > 255
        || text.ends_with(['.', ' '])
        || text.bytes().any(|byte| {
            matches!(
                byte,
                0..=31 | b'<' | b'>' | b':' | b'"' | b'/' | b'\\' | b'|' | b'?' | b'*'
            )
        })
    {
        return false;
    }
    // Everything from the first dot is ignored, so `con.txt`, `con .. .txt`
    // and `nul.tar.gz` name devices too.
    let stem = text.split('.').next().unwrap_or(text).trim_end_matches(' ');
    !is_device_name(&stem.to_ascii_uppercase())
}

/// `AUX`, `NUL`, `PRN`, `CON`, and `COM` or `LPT` followed by a digit 1 to 9
/// or a superscript 1, 2 or 3.
fn is_device_name(stem: &str) -> bool {
    matches!(stem, "AUX" | "NUL" | "PRN" | "CON")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|number| {
                let mut chars = number.chars();
                matches!(
                    (chars.next(), chars.next()),
                    (Some('1'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
                )
            })
}

/// Whether `name` has the form NTFS gives a generated 8.3 short name: one to
/// six characters, `~` and a number (fewer characters as the number grows,
/// eight in all), then at most a three-character extension, as in `LONGAR~1`
/// or `PROGRA~1.EXE`.
///
/// On a volume that generates short names, opening such a name in a directory
/// can reach a different file of that directory, the one whose long name got
/// the alias, so a name an untrusted source chooses must not have this form.
/// The test does not depend on the platform: a tree written on Linux can be
/// read on NTFS later.
pub fn is_short_name_alias(name: &str) -> bool {
    let (stem, extension) = name
        .rsplit_once('.')
        .map_or((name, None), |(stem, extension)| (stem, Some(extension)));
    if stem.contains('.') || extension.is_some_and(|ext| ext.is_empty() || ext.chars().count() > 3)
    {
        return false;
    }
    let Some((prefix, number)) = stem.rsplit_once('~') else {
        return false;
    };
    !prefix.is_empty()
        && !number.is_empty()
        && number.bytes().all(|byte| byte.is_ascii_digit())
        && prefix.chars().count() + 1 + number.len() <= 8
}

/// The path a `<module>` or `<relativePath>` entry names below `base`, the
/// directory of the POM that declares it, as Maven finds it on this platform.
///
/// Maven joins the entry to a plain directory path, so on Windows Win32 path
/// normalization trims trailing dots and spaces from it, while raeva reads
/// through `\\?\` paths that keep every name as written. The entry is
/// normalized that way first there; elsewhere a trailing dot or
/// space is part of the name and the entry is joined as written.
pub fn join_pom_entry(base: &Path, entry: &str) -> PathBuf {
    if cfg!(windows) {
        base.join(win32_entry(entry))
    } else {
        base.join(entry)
    }
}

/// The `pom.xml` Maven reads when [`join_pom_entry`] names a directory. On
/// Windows the entry's last segment is then followed by `\pom.xml` and
/// trimmed as an inner segment, so `module..` names the directory `module`
/// but its POM is read from `module..\pom.xml`.
pub fn join_pom_entry_pom_xml(base: &Path, entry: &str) -> PathBuf {
    if cfg!(windows) {
        base.join(win32_entry(&format!("{entry}/pom.xml")))
    } else {
        base.join(entry).join("pom.xml")
    }
}

/// The module POM Maven reads once [`join_pom_entry`] found `pom_entry`, a
/// `<module>` entry followed by `/pom.xml` when it names a directory.
///
/// On Windows Maven reads modules through `File.getCanonicalFile`, which
/// looks each segment up the way Win32 looks up a final one. A segment still
/// spelled with trailing spaces, such as `tail ` from `tail .`, then names
/// its trimmed sibling `tail` if that exists, and from the first segment not
/// found the rest is kept as written. The JDK refuses to canonicalize a path
/// with a segment that ends in a dot, such as `module..`, and Maven then
/// reads the path as written. Elsewhere this is the path [`join_pom_entry`]
/// gives.
pub fn join_module_pom(base: &Path, pom_entry: &str) -> PathBuf {
    if !cfg!(windows) {
        return base.join(pom_entry);
    }
    let normalized = win32_entry(pom_entry);
    if is_rooted(&normalized)
        || normalized
            .split('/')
            .any(|segment| segment != ".." && segment.ends_with('.'))
    {
        return base.join(normalized);
    }
    let mut path = base.to_path_buf();
    let mut segments = normalized.split('/').filter(|segment| !segment.is_empty());
    while let Some(segment) = segments.next() {
        let trimmed = segment.trim_end_matches(['.', ' ']);
        if segment == ".." || trimmed == segment {
            path.push(segment);
        } else if !trimmed.is_empty() && std::fs::symlink_metadata(path.join(trimmed)).is_ok() {
            path.push(trimmed);
        } else {
            path.push(segment);
            path.extend(segments);
            break;
        }
    }
    path
}

/// Whether Windows reads `entry` from a root or drive of its own rather
/// than below the directory it is joined to.
fn is_rooted(entry: &str) -> bool {
    let bytes = entry.as_bytes();
    entry.starts_with(['/', '\\'])
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

/// Normalize a relative POM entry the way `java.io.File` and Win32 path
/// normalization (`GetFullPathNameW`) do once Maven joins it to a directory:
///
/// - `/` and `\` both separate segments and empty segments are dropped, so
///   the last named segment is the final one even before a trailing slash,
///   which `java.io.File` removes;
/// - `.` is dropped and `..` removes the segment before it;
/// - an inner segment that ends in a single dot loses that dot, so
///   `module.` becomes `module` while `module..`, `...` and `module. ` stay;
/// - the final segment loses all trailing dots and spaces, and names the
///   directory itself when nothing is left, so `...` and `.. ` are not `..`.
///
/// An entry with a root or drive prefix is returned unchanged.
fn win32_entry(entry: &str) -> String {
    if is_rooted(entry) {
        return entry.to_string();
    }
    let segments: Vec<&str> = entry
        .split(['/', '\\'])
        .filter(|segment| !segment.is_empty())
        .collect();
    let mut normalized: Vec<&str> = Vec::with_capacity(segments.len());
    for (index, segment) in segments.iter().enumerate() {
        match *segment {
            "." => {}
            ".." if normalized.last().is_some_and(|last| *last != "..") => {
                normalized.pop();
            }
            ".." => normalized.push(".."),
            name if index + 1 == segments.len() => {
                let name = name.trim_end_matches(['.', ' ']);
                if !name.is_empty() {
                    normalized.push(name);
                }
            }
            name => normalized.push(
                name.strip_suffix('.')
                    .filter(|stripped| !stripped.ends_with('.'))
                    .unwrap_or(name),
            ),
        }
    }
    normalized.join("/")
}

/// `dunce` keeps the `\\?\` prefix on paths longer than `MAX_PATH`, so a
/// short root and a long path below it would canonicalize to different
/// forms. Comparisons only need one form, so drop the prefix for local
/// drives in every case.
#[cfg(windows)]
fn strip_verbatim_disk(path: PathBuf) -> PathBuf {
    use std::path::{Component, Prefix};
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return path;
    };
    let Prefix::VerbatimDisk(letter) = prefix.kind() else {
        return path;
    };
    let mut plain = PathBuf::from(format!("{}:", char::from(letter)));
    plain.extend(path.components().skip(1));
    plain
}

#[cfg(not(windows))]
fn strip_verbatim_disk(path: PathBuf) -> PathBuf {
    path
}

#[cfg(test)]
mod tests {
    use super::{
        canonicalize_existing_prefix, is_short_name_alias, plain_name_is_safe, win32_entry,
    };
    use std::path::Path;

    #[test]
    fn canonicalizes_the_existing_prefix_and_appends_the_rest() {
        let dir = tempfile::TempDir::new().unwrap();
        let real = dunce::canonicalize(dir.path()).unwrap();
        let target = dir.path().join("does/not/exist");
        assert_eq!(
            canonicalize_existing_prefix(&target).unwrap(),
            real.join("does/not/exist")
        );
        let relative = canonicalize_existing_prefix(Path::new("__rv_no_such_dir__")).unwrap();
        assert!(relative.is_absolute());

        // A deep path keeps the form of its root, without `\\?\` on Windows.
        let deep = dir.path().join("d".repeat(200)).join("e".repeat(100));
        std::fs::create_dir_all(&deep).unwrap();
        let resolved = canonicalize_existing_prefix(&deep.join("pom.xml")).unwrap();
        assert!(resolved.starts_with(&real) && resolved.as_os_str().len() > 260);
        assert!(!resolved.to_string_lossy().starts_with(r"\\?\"));

        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&deep, &link).unwrap();
            let resolved = canonicalize_existing_prefix(&link.join("child")).unwrap();
            assert_eq!(
                resolved,
                std::fs::canonicalize(&deep).unwrap().join("child")
            );
        }
    }

    #[test]
    fn plain_names_exclude_what_windows_normalizes() {
        for name in ["project", "a.b", "COM10", ".con", "con-utils", "lpt"] {
            assert!(plain_name_is_safe(name.as_ref()), "{name} must be safe");
        }
        for name in [
            "project.",
            "project ",
            "CON",
            "con.txt",
            "Nul .. .xml",
            "NUL.tar.gz",
            "aux.d.ts",
            "COM\u{b9}",
            "lpt\u{b3}.log",
            "com1",
            "a:b",
            "a?b",
            "",
        ] {
            assert!(!plain_name_is_safe(name.as_ref()), "{name} must be unsafe");
        }
        assert!(plain_name_is_safe("x".repeat(255).as_ref()));
        assert!(!plain_name_is_safe("x".repeat(256).as_ref()));
    }

    #[test]
    fn short_name_aliases_are_the_generated_forms() {
        let aliases =
            "PROGRA~1 progra~1 LONGAR~1.JAR A~1 AB1234~2.xml ABCDE~10 x~9.a a~b~1 1~ABCD~1";
        for name in aliases.split(' ') {
            assert!(is_short_name_alias(name), "{name} must be an alias");
        }
        let plain = "~1 plain artifact-1.0.jar ABCDEFG~1 ABCDEF~1.JAVA ABCDEF~10 a~b a~1b a~ \
                     a~b~12345 a.b~1 a.b~1.jar a~1. 1.0~1";
        for name in plain.split_whitespace().chain([""]) {
            assert!(!is_short_name_alias(name), "{name} must not be an alias");
        }
    }

    /// Entries and what `GetFullPathNameW` makes of them below a directory,
    /// after `java.io.File` has dropped a trailing separator.
    const WIN32_ENTRIES: [(&str, &str); 39] = [
        ("module", "module"),
        ("module.", "module"),
        ("module..", "module"),
        ("module...", "module"),
        ("module. .", "module"),
        ("module .", "module"),
        ("module  ", "module"),
        ("module./", "module"),
        ("module../", "module"),
        ("module./pom.xml", "module/pom.xml"),
        ("module.\\pom.xml", "module/pom.xml"),
        ("module../pom.xml", "module../pom.xml"),
        ("module.../pom.xml", "module.../pom.xml"),
        ("module ./pom.xml", "module /pom.xml"),
        ("module. /pom.xml", "module. /pom.xml"),
        ("module. ./pom.xml", "module. /pom.xml"),
        ("a./b./c.", "a/b/c"),
        ("../parent./pom.xml", "../parent/pom.xml"),
        ("../parent. /pom.xml", "../parent. /pom.xml"),
        ("../parent.", "../parent"),
        ("../../x", "../../x"),
        ("x/../y", "y"),
        ("x./../y", "y"),
        ("x/..", ""),
        ("..", ".."),
        ("./x", "x"),
        ("a//b\\\\c", "a/b/c"),
        ("...", ""),
        (".../x", ".../x"),
        ("x/...", "x"),
        ("x/.. ", "x"),
        ("x/. ", "x"),
        ("x/..  .", "x"),
        (". /x", ". /x"),
        (".. /x", ".. /x"),
        ("..x.", "..x"),
        (" x/ /y", " x/ /y"),
        ("x.\t", "x.\t"),
        ("x.\u{3000}", "x.\u{3000}"),
    ];

    #[test]
    fn pom_entries_lose_what_win32_normalization_trims() {
        for (entry, expected) in WIN32_ENTRIES {
            assert_eq!(win32_entry(entry), expected, "{entry:?}");
        }
        for absolute in [
            r"C:\work\module.",
            "c:module.",
            "/work/module.",
            r"\\server\share\module.",
            r"\\?\C:\work\module.",
        ] {
            assert_eq!(win32_entry(absolute), absolute);
        }
    }

    #[cfg(windows)]
    #[test]
    fn pom_entries_match_get_full_path_name() {
        let base = Path::new(r"C:\base\dir");
        for (entry, _) in WIN32_ENTRIES {
            let java = entry.trim_end_matches(['/', '\\']);
            let expected = std::path::absolute(base.join(java)).unwrap();
            let mut actual = base.to_path_buf();
            for segment in win32_entry(entry).split('/') {
                match segment {
                    "" => {}
                    ".." => assert!(actual.pop()),
                    name => actual.push(name),
                }
            }
            assert_eq!(
                expected.to_str().unwrap().trim_end_matches('\\'),
                actual.to_str().unwrap(),
                "{entry:?}"
            );
        }
    }
}
