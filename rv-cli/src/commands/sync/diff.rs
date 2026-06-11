//! Lockfile diff rendering for the post-sync "Dependency changes" report.

use std::collections::{HashMap, HashSet};

use rv_config::{LockPackage, Lockfile, Platform};

use crate::output::{heading, is_json_mode, quiet_enabled};

/// Maximum number of changed entries shown inline in a `--frozen` mismatch
/// error. Beyond this, a "... and N more" summary keeps the message concise.
pub(super) const FROZEN_DIFF_DISPLAY_CAP: usize = 10;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct DepKey {
    platform: String,
    group_id: String,
    artifact_id: String,
    packaging: String,
    classifier: Option<String>,
}

impl DepKey {
    fn from_package(package: &LockPackage, platform: &Platform) -> Self {
        Self {
            platform: platform.to_string(),
            group_id: package.group_id.clone(),
            artifact_id: package.artifact_id.clone(),
            packaging: package.packaging.clone(),
            classifier: package.classifier.clone(),
        }
    }

    fn format_coord(&self, version: &str) -> String {
        let mut coord = format!("{}:{}:{}", self.group_id, self.artifact_id, version);
        let has_classifier = self
            .classifier
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if self.packaging != "jar" || has_classifier {
            coord.push(':');
            coord.push_str(&self.packaging);
            if let Some(classifier) = &self.classifier
                && !classifier.is_empty()
            {
                coord.push(':');
                coord.push_str(classifier);
            }
        }
        coord
    }
}

/// Produce a compact textual summary of what changed between `old` and `new`
/// lockfiles, limited to `cap` entries with a "... and N more" footer.
///
/// This is used by the `--frozen` mismatch error message so the user can see
/// which packages drifted without having to run `rv sync` just to find out.
/// Unlike [`print_lock_diff`] this function considers ALL platforms in both
/// lockfiles, not just the currently-requested ones.
pub(super) fn format_frozen_diff(old: &Lockfile, new: &Lockfile) -> String {
    let old_map = lock_dep_map_all(old);
    let new_map = lock_dep_map_all(new);

    let mut lines: Vec<String> = Vec::new();

    for (key, new_pkg) in &new_map {
        match old_map.get(key) {
            None => lines.push(format!(
                "  + {} ({})",
                key.format_coord(&new_pkg.version),
                key.platform
            )),
            Some(old_pkg) if old_pkg.version != new_pkg.version => lines.push(format!(
                "  ~ {} -> {} ({})",
                key.format_coord(&old_pkg.version),
                key.format_coord(&new_pkg.version),
                key.platform
            )),
            // A same-version pin whose bytes drifted would otherwise leave
            // the diff empty and the mismatch error with no entries at all.
            Some(old_pkg) if super::checksum_drifted(old_pkg, new_pkg) => lines.push(format!(
                "  ~ checksum changed for {} ({})",
                key.format_coord(&new_pkg.version),
                key.platform
            )),
            _ => {}
        }
    }
    for (key, old_pkg) in &old_map {
        if !new_map.contains_key(key) {
            lines.push(format!(
                "  - {} ({})",
                key.format_coord(&old_pkg.version),
                key.platform
            ));
        }
    }

    if lines.is_empty() {
        return String::new();
    }

    lines.sort();
    let total = lines.len();
    let shown = lines.len().min(FROZEN_DIFF_DISPLAY_CAP);
    let mut out = String::new();
    for line in &lines[..shown] {
        out.push_str(line);
        out.push('\n');
    }
    if total > FROZEN_DIFF_DISPLAY_CAP {
        out.push_str(&format!(
            "  ... and {} more (run 'rv sync' to see full diff)\n",
            total - FROZEN_DIFF_DISPLAY_CAP
        ));
    }
    out
}

/// Like [`lock_dep_map`] but covers every platform in the lockfile instead of
/// filtering to a caller-supplied list, and keeps the whole package so the
/// frozen diff can also name checksum-only drift. Used by
/// [`format_frozen_diff`].
fn lock_dep_map_all(lock: &Lockfile) -> HashMap<DepKey, &LockPackage> {
    let mut map = HashMap::new();
    for platform in &lock.platforms {
        for package in &platform.packages {
            map.insert(DepKey::from_package(package, &platform.platform), package);
        }
    }
    map
}

pub(super) fn lock_dep_map(lock: &Lockfile, platforms: &[Platform]) -> HashMap<DepKey, String> {
    let mut map = HashMap::new();
    let allowed: HashSet<String> = platforms.iter().map(|p| p.to_string()).collect();
    for platform in &lock.platforms {
        let platform_str = platform.platform.to_string();
        if !allowed.contains(&platform_str) {
            continue;
        }
        for package in &platform.packages {
            map.insert(
                DepKey::from_package(package, &platform.platform),
                package.version.clone(),
            );
        }
    }
    map
}

pub(super) fn print_lock_diff(old: &Lockfile, new: &Lockfile, platforms: &[Platform]) {
    // Bail out before doing any work in JSON mode. The diff is never
    // rendered to JSON output, so computing both maps and the category
    // vectors only to drop them wastes CPU on every sync.
    if is_json_mode() {
        return;
    }
    if quiet_enabled() {
        return;
    }

    let old_map = lock_dep_map(old, platforms);
    let new_map = lock_dep_map(new, platforms);

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut updated = Vec::new();

    for (key, new_version) in &new_map {
        match old_map.get(key) {
            None => {
                added.push(format!(
                    "  + {} ({})",
                    key.format_coord(new_version),
                    key.platform
                ));
            }
            Some(old_version) if old_version != new_version => {
                updated.push(format!(
                    "  ~ {} -> {} ({})",
                    key.format_coord(old_version),
                    key.format_coord(new_version),
                    key.platform
                ));
            }
            _ => {}
        }
    }

    for (key, old_version) in &old_map {
        if !new_map.contains_key(key) {
            removed.push(format!(
                "  - {} ({})",
                key.format_coord(old_version),
                key.platform
            ));
        }
    }

    added.sort();
    removed.sort();
    updated.sort();

    eprintln!("{}", heading("Dependency changes"));
    if added.is_empty() && removed.is_empty() && updated.is_empty() {
        // Print an explicit "no changes" line so the fast-path UX
        // matches the resolve path. An unchanged sync otherwise looks
        // indistinguishable from a no-op cache hit, leaving users unable
        // to tell whether the diff ran at all.
        eprintln!("  (no changes)");
        return;
    }
    for line in added {
        eprintln!("{}", line);
    }
    for line in removed {
        eprintln!("{}", line);
    }
    for line in updated {
        eprintln!("{}", line);
    }
}
