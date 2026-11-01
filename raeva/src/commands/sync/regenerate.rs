use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use rv_lock::{Lockfile, MAX_LOCKFILE_BYTES, Platform};

use crate::commands::parse_platform;

/// What a plain sync keeps of a raeva.lock it cannot read, which it replaces
/// whole: the targets its `targets` and `target` lines name, in both sides of a
/// merge conflict, and the lock git has at `HEAD`, to list the changes
/// against. No pin comes from the unreadable text.
pub(super) struct Unreadable {
    pub(super) platforms: Vec<Platform>,
    pub(super) head: Option<Lockfile>,
}

impl Unreadable {
    /// `None` when the text cannot be read whole: a part not read may name
    /// a platform the new lock must keep.
    pub(super) fn read(path: &Path, reason: &str) -> Option<Self> {
        let text = read_bounded(path, MAX_LOCKFILE_BYTES)?;
        let platforms = recover_platforms(&text);
        let head = head_lock(path);
        let kept = if platforms.is_empty() {
            "it names no platform this raeva supports".to_string()
        } else {
            format!("keeping its platforms {}", super::platform_list(&platforms))
        };
        let compared = if head.is_some() {
            "the changes listed are against raeva.lock at git HEAD"
        } else {
            "git has no readable raeva.lock at HEAD to list the changes against"
        };
        tracing::warn!(
            sec_code = "LOCKFILE_REGENERATED",
            "regenerating raeva.lock, which this raeva cannot use: {reason}; {kept}; {compared}"
        );
        Some(Self { platforms, head })
    }
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

/// The platforms the text's `targets` and `target` entries name. A `targets`
/// array runs to the next key or table header: a conflict can close it on
/// one side and keep listing it on the other.
fn recover_platforms(text: &str) -> Vec<Platform> {
    let mut platforms = Vec::new();
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
    platforms.sort_by_key(ToString::to_string);
    platforms
}

/// The lock committed at `HEAD` of the git work tree holding `path`, when
/// git is installed and it reads within raeva.lock's size limit.
fn head_lock(path: &Path) -> Option<Lockfile> {
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
    Lockfile::from_toml(std::str::from_utf8(&bytes).ok()?).ok()
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
    }
}
