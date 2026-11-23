use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use rv_lock::conflict::Sides;
use rv_lock::{Lockfile, MAX_LOCKFILE_BYTES, Platform};

use crate::commands::parse_platform;
use crate::commands::util::{join_and, plural};
use crate::error::{CliError, Result};
use crate::output::command_line;

/// What a plain sync keeps of a raeva.lock it cannot read, which it replaces
/// whole: the targets its `targets` and `target` lines name, in both sides of a
/// merge conflict, the pins of each side, and the lock git has at `HEAD`, to
/// list the changes against.
pub(super) struct Unreadable {
    pub(super) platforms: Vec<Platform>,
    pub(super) head: Option<Lockfile>,
    /// The pins of each version of the text and of the lock at `HEAD`, which
    /// other bytes must not replace, with the plugin traces that pin some
    /// of them: a lock of rows alone, never written. `None` under
    /// `--update`, which locks the bytes the repositories serve.
    pub(super) pins: Option<Lockfile>,
}

impl Unreadable {
    /// Refuses a text that cannot be read whole, since a part not read may
    /// name a platform the new lock must keep, and without `update`, a
    /// version of the text whose pins cannot be read, or two rows that pin
    /// other bytes for one release file.
    pub(super) fn read(path: &Path, reason: &str, update: bool) -> Result<Self> {
        let refuse = |why: String, hint: String| {
            // A text that is not TOML fails the rows' read as it failed
            // `reason`'s, which says why once.
            let why = match why.split_once(": ") {
                Some((head, detail)) if reason.ends_with(detail) => head.to_string(),
                _ => why,
            };
            CliError::LockfileUnreplaced {
                reason: format!("{reason}; {why}"),
                hint,
            }
        };
        let text = read_bounded(path, MAX_LOCKFILE_BYTES).ok_or_else(|| {
            refuse(
                "a sync cannot read it whole to keep the platforms it names".to_string(),
                "Delete raeva.lock and run 'raeva sync'".to_string(),
            )
        })?;
        let platforms = recover_platforms(&text);
        let head_text = head_text(path);
        let head = (head_text.as_deref()).and_then(|text| Lockfile::from_toml(text).ok());
        let pins = (!update)
            .then(|| keep_pins(&text, head_text.as_deref(), refuse))
            .transpose()?;
        let kept = if platforms.is_empty() {
            "it names no platform this raeva supports".to_string()
        } else {
            format!("keeping its platforms {}", super::platform_list(&platforms))
        };
        let pinned = match &pins {
            Some((_, names)) => format!("keeping the pins of {}", join_and(names.clone())),
            None => "keeping none of its pins, as --update asks".to_string(),
        };
        let compared = if head.is_some() {
            "the changes listed are against raeva.lock at git HEAD"
        } else {
            "git has no readable raeva.lock at HEAD to list the changes against"
        };
        tracing::warn!(
            sec_code = "LOCKFILE_REGENERATED",
            "regenerating raeva.lock, which this raeva cannot use: {reason}; {kept}; {pinned}; {compared}"
        );
        Ok(Self {
            platforms,
            head,
            pins: pins.map(|(pins, _)| pins),
        })
    }
}

/// The pins of every version of `text` and of `head`, the lock at git
/// `HEAD`, in one lock, with the name of each version. The text's must all
/// read; `head`'s are kept when they do.
fn keep_pins(
    text: &str,
    head: Option<&str>,
    refuse: impl FnOnce(String, String) -> CliError,
) -> Result<(Lockfile, Vec<String>)> {
    let name = |side: Option<rv_lock::conflict::Side>| {
        side.map_or("raeva.lock".to_string(), |side| side.to_string())
    };
    let recovered = rv_lock::conflict::recover_pins(text).map_err(|lost| {
        // Without conflict markers there is no side to take.
        let next = match rv_lock::conflict::sides(text) {
            Sides::Clean => "Run",
            Sides::Conflicted { .. } | Sides::Malformed { .. } => {
                "Resolve the conflict or take one side's lock ('git checkout --ours raeva.lock' \
                 or '--theirs'), run"
            }
        };
        refuse(
            format!("a sync cannot keep its pins, since {lost}"),
            format!(
                "{next} '{}' to lock the bytes the repositories serve now, or delete raeva.lock \
                 to start again without its pins",
                command_line("sync --update")
            ),
        )
    })?;
    let mut versions: Vec<(String, Lockfile)> = (recovered.into_iter())
        .map(|(side, lock)| (name(side), lock))
        .collect();
    if let Some(Ok(head)) = head.map(rv_lock::conflict::recover_pins) {
        versions.extend(head.into_iter().map(|(side, lock)| {
            let side = side.map_or(String::new(), |side| format!(", {side}"));
            (format!("raeva.lock at git HEAD{side}"), lock)
        }));
    }
    let locks: Vec<&Lockfile> = versions.iter().map(|(_, lock)| lock).collect();
    let lines: Vec<String> = (rv_lock::conflict::disagreements(&locks).into_iter())
        .map(|found| {
            let ((first, one), (second, other)) = (found.first, found.second);
            let (first, second) = (&versions[first].0, &versions[second].0);
            if first == second {
                format!("{}: {one} and {other} in {first}", found.path)
            } else {
                format!("{}: {one} in {first}, {other} in {second}", found.path)
            }
        })
        .collect();
    if !lines.is_empty() {
        return Err(CliError::lockfile_mismatch_with(
            format!(
                "the versions of raeva.lock disagree on {}:\n{}",
                plural(lines.len(), "file", "files"),
                lines.join("\n")
            ),
            format!(
                "Find out which bytes are right, keep the lock that pins them, and run 'raeva \
                 sync'. A republished release, a mirror that rewrites files, and tampering \
                 look the same here. To lock the bytes the repositories serve now, run '{}' \
                 and review the changes to raeva.lock before committing it",
                command_line("sync --update")
            ),
        ));
    }
    let names = versions.iter().map(|(name, _)| name.clone()).collect();
    let mut pins = Lockfile::new();
    pins.platforms = (versions.into_iter())
        .flat_map(|(_, lock)| lock.platforms)
        .collect();
    Ok((pins, names))
}

fn read_bounded(path: &Path, limit: u64) -> Option<String> {
    let mut bytes = Vec::new();
    (std::fs::File::open(path).ok()?.take(limit + 1))
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// The platforms the `targets` and `target` entries of each side of the
/// text's merge conflicts name, or of the whole text when its markers split
/// no conflict.
fn recover_platforms(text: &str) -> Vec<Platform> {
    let mut platforms = Vec::new();
    match rv_lock::conflict::sides(text) {
        Sides::Conflicted { ours, theirs } => {
            side_platforms(&ours, &mut platforms);
            side_platforms(&theirs, &mut platforms);
        }
        Sides::Clean | Sides::Malformed { .. } => side_platforms(text, &mut platforms),
    }
    platforms.sort_by_key(ToString::to_string);
    platforms
}

/// Add the platforms `text` names to `platforms`. A `targets` array runs to
/// the next key or table header.
fn side_platforms(text: &str, platforms: &mut Vec<Platform>) {
    let mut targets = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with(|c: char| c.is_ascii_alphabetic() || c == '[') {
            targets = line == "targets = [";
        }
        let entry = if targets && line.starts_with(['"', '\'']) {
            format!("target = {}", line.trim_end_matches(','))
        } else if line.starts_with("target") {
            line.to_string()
        } else {
            continue;
        };
        let Ok(table) = entry.parse::<toml::Table>() else {
            continue;
        };
        let names: Vec<&str> =
            if let Some(targets) = table.get("targets").and_then(toml::Value::as_array) {
                targets.iter().filter_map(toml::Value::as_str).collect()
            } else {
                table
                    .get("target")
                    .and_then(toml::Value::as_str)
                    .into_iter()
                    .collect()
            };
        for name in names {
            let (os_arch, jdk) = name
                .split_once('@')
                .map_or((name, None), |(p, j)| (p, Some(j)));
            if let Ok(mut platform) = parse_platform(os_arch) {
                if let Some(jdk) = jdk {
                    if !rv_config::is_valid_jdk(jdk) {
                        continue;
                    }
                    platform = platform.with_jdk(jdk);
                }
                if !platforms.contains(&platform) {
                    platforms.push(platform);
                }
            }
        }
    }
}

/// The text of the lock committed at `HEAD` of the git work tree holding
/// `path`, when git is installed and it is UTF-8 within raeva.lock's size
/// limit.
fn head_text(path: &Path) -> Option<String> {
    let dir = path.parent()?;
    let name = path.file_name()?.to_str()?;
    // `cat-file blob` applies no textconv or filter and reads no index. A
    // partial clone's missing blob would make git fetch it, running what the
    // repository's configuration names, so that is off.
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["cat-file", "blob", &format!("HEAD:./{name}")])
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut bytes = Vec::new();
    let read = (child.stdout.take()?)
        .take(MAX_LOCKFILE_BYTES + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > MAX_LOCKFILE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    if !child.wait().ok()?.success() {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::{read_bounded, recover_platforms};

    #[test]
    fn a_text_past_the_limit_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raeva.lock");
        std::fs::write(&path, "0123456789").unwrap();
        assert_eq!(read_bounded(&path, 10).as_deref(), Some("0123456789"));
        assert_eq!(read_bounded(&path, 9), None);
        std::fs::write(&path, b"\xff").unwrap();
        assert_eq!(read_bounded(&path, 10), None);
    }

    #[test]
    fn platforms_come_from_both_sides_of_a_conflict() {
        let text = "schema_version = 8\n<<<<<<< ours\n[[platforms]]\ntargets = [\"linux-x86_64@17\"]\n=======\n[[platforms]]\ntargets = [\"windows-x86_64@21\", \"linux-x86_64@17\"]\n>>>>>>> theirs\n[[inputs]]\ntarget = \"linux-x86_64@17\"\n";
        let names: Vec<String> = (recover_platforms(text).iter())
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["linux-x86_64 (JDK 17)", "windows-x86_64 (JDK 21)"]);
        let closed = "targets = [\n<<<<<<< ours\n    \"linux-x86_64\",\n]\n=======\n    \"macos-aarch64\",\n]\n>>>>>>> theirs\nprofiles = [\n    \"windows-x86_64\",\n]\n[[inputs]]\n<<<<<<< ours\ntarget = \"linux-x86_64\"\n=======\ntarget = \"macos-aarch64\"\n>>>>>>> theirs\n";
        let names: Vec<String> = (recover_platforms(closed).iter())
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["linux-x86_64", "macos-aarch64"]);
        // Each side is read alone, so a `targets` array one side opens does
        // not take in the other side's lines.
        let split = "profiles = [\n<<<<<<<<< ours\n]\ntargets = [\n    \"linux-x86_64\",\n=========\n    \"macos-aarch64\",\n>>>>>>>>> theirs\n]\n";
        let names: Vec<String> = (recover_platforms(split).iter())
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["linux-x86_64"]);
    }
}
