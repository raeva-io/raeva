//! Module-aware lockfile diff rendering for the post-sync change report.

use std::collections::{HashMap, HashSet};

use rv_config::{LOCK_SUPPORT_POMS_KEY, LockPackage, Lockfile, Platform, decode_support_pom_lines};

use crate::output::{heading, is_json_mode, quiet_enabled};

/// Maximum number of changed entries shown inline in a `--frozen` mismatch
/// error. Beyond this, a "... and N more" summary keeps the message concise.
pub(super) const FROZEN_DIFF_DISPLAY_CAP: usize = 10;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct DepKey {
    platform: String,
    module_path: String,
    kind: DepKind,
    group_id: String,
    artifact_id: String,
    packaging: String,
    classifier: Option<String>,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
enum DepKind {
    External,
    Workspace,
    System,
}

impl DepKind {
    fn label(self) -> &'static str {
        match self {
            Self::External => "external",
            Self::Workspace => "workspace",
            Self::System => "system",
        }
    }
}

impl DepKey {
    fn format_coord(&self, version: &str) -> String {
        let mut coord = format!("{}:{}:{}", self.group_id, self.artifact_id, version);
        let has_classifier = self
            .classifier
            .as_deref()
            .is_some_and(|classifier| !classifier.is_empty());
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

    fn format_entry(&self, version: &str) -> String {
        format!(
            "[{}] {} {} ({})",
            self.module_path,
            self.kind.label(),
            self.format_coord(version),
            self.platform
        )
    }
}

#[derive(Debug, Clone)]
struct DepEntry {
    package: LockPackage,
}

impl DepEntry {
    fn version(&self) -> &str {
        &self.package.version
    }
}

/// Produce a compact module-aware summary for a frozen graph mismatch.
pub(super) fn format_frozen_diff(old: &Lockfile, new: &Lockfile) -> String {
    let old_map = lock_dep_map_all(old);
    let new_map = lock_dep_map_all(new);
    let mut lines = change_lines(&old_map, &new_map);
    lines.extend(pom_pin_change_lines(old, new));
    if lines.is_empty() {
        return String::new();
    }

    lines.sort();
    let total = lines.len();
    let shown = total.min(FROZEN_DIFF_DISPLAY_CAP);
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

fn lock_dep_map_all(lock: &Lockfile) -> HashMap<DepKey, DepEntry> {
    lock_dep_map_filtered(lock, None)
}

fn lock_dep_map(lock: &Lockfile, platforms: &[Platform]) -> HashMap<DepKey, DepEntry> {
    let allowed: HashSet<String> = platforms.iter().map(ToString::to_string).collect();
    lock_dep_map_filtered(lock, Some(&allowed))
}

fn lock_dep_map_filtered(
    lock: &Lockfile,
    allowed: Option<&HashSet<String>>,
) -> HashMap<DepKey, DepEntry> {
    let mut map = HashMap::new();
    for platform in &lock.platforms {
        let platform_id = platform.platform.to_string();
        if allowed.is_some_and(|allowed| !allowed.contains(&platform_id)) {
            continue;
        }

        let artifacts: HashMap<_, _> = platform
            .artifacts
            .iter()
            .map(|artifact| (&artifact.coordinate, artifact))
            .collect();
        for module in &platform.modules {
            for package in &module.packages {
                let (kind, legacy) = if let Some(workspace) = package.workspace_module.as_ref() {
                    let mut legacy = synthetic_package(package);
                    legacy.repo_url = workspace.clone();
                    (DepKind::Workspace, legacy)
                } else if package.system_path.is_some() {
                    (DepKind::System, synthetic_package(package))
                } else {
                    let mut legacy = artifacts
                        .get(&package.coordinate)
                        .map(|artifact| artifact.as_package())
                        .unwrap_or_else(|| synthetic_package(package));
                    legacy.direct_scope = package.direct_scope.clone();
                    (DepKind::External, legacy)
                };
                insert_package(&mut map, &platform_id, &module.path, kind, legacy);
            }
        }
    }
    map
}

fn synthetic_package(package: &rv_config::LockModulePackage) -> LockPackage {
    LockPackage {
        group_id: package.coordinate.group.clone(),
        artifact_id: package.coordinate.artifact.clone(),
        version: package.coordinate.version.clone(),
        snapshot_timestamp: None,
        packaging: package.coordinate.packaging.clone(),
        classifier: package.coordinate.classifier.clone(),
        repo_url: String::new(),
        checksum: None,
        system_path: package.system_path.clone(),
        direct_scope: package.direct_scope.clone(),
        extra: package.extra.clone(),
    }
}

fn insert_package(
    map: &mut HashMap<DepKey, DepEntry>,
    platform: &str,
    module_path: &str,
    kind: DepKind,
    package: LockPackage,
) {
    map.insert(
        DepKey {
            platform: platform.to_string(),
            module_path: module_path.to_string(),
            kind,
            group_id: package.group_id.clone(),
            artifact_id: package.artifact_id.clone(),
            packaging: package.packaging.clone(),
            classifier: package.classifier.clone(),
        },
        DepEntry { package },
    );
}

fn change_lines(
    old_map: &HashMap<DepKey, DepEntry>,
    new_map: &HashMap<DepKey, DepEntry>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for (key, new_entry) in new_map {
        match old_map.get(key) {
            None => lines.push(format!("  + {}", key.format_entry(new_entry.version()))),
            Some(old_entry) if old_entry.version() != new_entry.version() => {
                lines.push(format!(
                    "  ~ [{}] {} {} -> {} ({})",
                    key.module_path,
                    key.kind.label(),
                    key.format_coord(old_entry.version()),
                    key.format_coord(new_entry.version()),
                    key.platform
                ));
            }
            Some(old_entry)
                if old_entry.package.snapshot_timestamp != new_entry.package.snapshot_timestamp =>
            {
                lines.push(format!(
                    "  ~ [{}] {} snapshot changed for {}: {} -> {} ({})",
                    key.module_path,
                    key.kind.label(),
                    key.format_coord(new_entry.version()),
                    old_entry
                        .package
                        .snapshot_timestamp
                        .as_deref()
                        .unwrap_or("none"),
                    new_entry
                        .package
                        .snapshot_timestamp
                        .as_deref()
                        .unwrap_or("none"),
                    key.platform
                ));
            }
            Some(old_entry) if super::checksum_drifted(&old_entry.package, &new_entry.package) => {
                lines.push(format!(
                    "  ~ [{}] {} checksum changed for {} ({})",
                    key.module_path,
                    key.kind.label(),
                    key.format_coord(new_entry.version()),
                    key.platform
                ));
            }
            Some(old_entry)
                if key.kind == DepKind::External
                    && old_entry.package.repo_url != new_entry.package.repo_url =>
            {
                lines.push(format!(
                    "  ~ [{}] {} origin changed for {}: {} -> {} ({})",
                    key.module_path,
                    key.kind.label(),
                    key.format_coord(new_entry.version()),
                    old_entry.package.repo_url,
                    new_entry.package.repo_url,
                    key.platform
                ));
            }
            Some(old_entry) if old_entry.package.direct_scope != new_entry.package.direct_scope => {
                lines.push(format!(
                    "  ~ [{}] {} scope changed for {}: {} -> {} ({})",
                    key.module_path,
                    key.kind.label(),
                    key.format_coord(new_entry.version()),
                    old_entry
                        .package
                        .direct_scope
                        .as_deref()
                        .unwrap_or("transitive"),
                    new_entry
                        .package
                        .direct_scope
                        .as_deref()
                        .unwrap_or("transitive"),
                    key.platform
                ));
            }
            _ => {}
        }
    }
    for (key, old_entry) in old_map {
        if !new_map.contains_key(key) {
            lines.push(format!("  - {}", key.format_entry(old_entry.version())));
        }
    }
    lines
}

/// Render POM-pin drift, which `change_lines` cannot see.
///
/// A companion POM and a parent/BOM POM can both be republished with different
/// bytes and an unchanged dependency graph, so this drift shows up in the pins
/// alone. Without these lines a `--frozen` failure caused by it would report
/// "dependencies would change" and then list nothing.
fn pom_pin_change_lines(old: &Lockfile, new: &Lockfile) -> Vec<String> {
    let mut lines = Vec::new();
    for platform in &new.platforms {
        let previous: HashMap<_, _> = old
            .platforms
            .iter()
            .find(|candidate| candidate.platform == platform.platform)
            .into_iter()
            .flat_map(|candidate| candidate.artifacts.iter())
            .map(|artifact| (&artifact.coordinate, artifact))
            .collect();
        for artifact in &platform.artifacts {
            let Some(old_artifact) = previous.get(&artifact.coordinate) else {
                continue;
            };
            if old_artifact.pom_sha256 != artifact.pom_sha256 {
                lines.push(format!(
                    "  ~ POM changed for {}: {} -> {} ({})",
                    artifact.coordinate.format_coord(),
                    old_artifact.pom_sha256.as_deref().unwrap_or("none"),
                    artifact.pom_sha256.as_deref().unwrap_or("none"),
                    platform.platform
                ));
            }
        }
    }

    let old_support = decode_support_pom_lines(
        old.metadata
            .get(LOCK_SUPPORT_POMS_KEY)
            .map(String::as_str)
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    let new_support = decode_support_pom_lines(
        new.metadata
            .get(LOCK_SUPPORT_POMS_KEY)
            .map(String::as_str)
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    for (coord, new_line) in &new_support {
        let old_digest = old_support
            .get(coord)
            .and_then(|line| line.sha256.as_deref());
        if old_digest != new_line.sha256.as_deref() {
            lines.push(format!(
                "  ~ support POM changed for {coord}: {} -> {}",
                old_digest.unwrap_or("none"),
                new_line.sha256.as_deref().unwrap_or("none")
            ));
        }
    }
    lines
}

pub(super) fn print_lock_diff(old: &Lockfile, new: &Lockfile, platforms: &[Platform]) {
    if is_json_mode() || quiet_enabled() {
        return;
    }

    let old_map = lock_dep_map(old, platforms);
    let new_map = lock_dep_map(new, platforms);
    let mut lines = change_lines(&old_map, &new_map);
    lines.sort();

    eprintln!("{}", heading("Dependency changes"));
    if lines.is_empty() {
        eprintln!("  (no changes)");
        return;
    }
    for line in lines {
        eprintln!("{line}");
    }
}
