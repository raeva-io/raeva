use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use rv_lock::{LockArtifact, LockModule, LockPlatform, Lockfile, Platform, PluginRole, Scope};
use rv_maven_types::{ManagedKind, ManagedSource};
use serde::Serialize;

use crate::commands::util::{join_and, modules_phrase, plural};
use crate::commands::{path_to_forward_slashes, why};
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Report};
use crate::session::Session;

const VIA_CHANGE_CAP: usize = 500;
const VIA_PATH_CAP: usize = 3;

#[derive(Debug, Clone, Args)]
#[command(after_long_help = format!(
    "{}  git show main:raeva.lock > \"${{TMPDIR:-/tmp}}/main.lock\" && \
     raeva lock diff \"${{TMPDIR:-/tmp}}/main.lock\"\n",
    crate::commands::util::help_examples(&[
        ("lock diff old.lock", "old.lock against the project's raeva.lock"),
        ("lock diff old.lock new.lock", ""),
        ("-v lock diff old.lock", "also list each support POM added or removed"),
    ])
))]
pub(crate) struct LockDiffArgs {
    /// Previous lockfile
    #[arg(value_name = "OLD")]
    old: PathBuf,
    /// New lockfile (defaults to the project raeva.lock)
    #[arg(value_name = "NEW")]
    new: Option<PathBuf>,
}

pub(super) fn run(args: &LockDiffArgs, session: &Session) -> Result<Report> {
    let root = session.project_root();
    if args.new.is_none() && !root.exists() {
        return Err(rv_config::ConfigError::ProjectRootMissing(root.to_path_buf()).into());
    }
    let new = (args.new.clone()).unwrap_or_else(|| root.join("raeva.lock"));
    // Only the project's own raeva.lock is one 'raeva sync' creates.
    let read = |path: &PathBuf, project: bool| {
        super::util::read_lockfile_at(path).map_err(|err| match err {
            CliError::LockfileMissing {
                path,
                sync_creates,
                reactor,
            } => CliError::LockfileMissing {
                path,
                sync_creates: project && sync_creates,
                reactor,
            },
            err => err,
        })
    };
    let old_lock = read(&args.old, false)?;
    let new_lock = read(&new, args.new.is_none())?;
    Ok(Report::data(LockDiffReport::between(
        path_to_forward_slashes(&args.old),
        path_to_forward_slashes(&new),
        &old_lock,
        &new_lock,
        session.output().is_verbose(),
    )?))
}

#[derive(Serialize)]
struct LockDiffReport {
    old: String,
    new: String,
    changed: bool,
    causes: Vec<Cause>,
    platforms_added: Vec<String>,
    platforms_removed: Vec<String>,
    module_changes: Vec<ModuleChange>,
    profile_changes: Vec<ProfileChange>,
    changes: Vec<PackageChange>,
    edge_changes: Vec<EdgeChange>,
    pom_changes: Vec<PomChange>,
    plugin_changes: Vec<PluginChange>,
    checksum_markers: Vec<ChecksumMarker>,
    changed_inputs: Vec<String>,
    via_limited: bool,
    #[serde(skip)]
    host_inputs: Vec<String>,
    /// Each text line, with the indexes into `changes` of the packages it
    /// stands for.
    #[serde(skip)]
    lines: Vec<(String, Vec<usize>)>,
}

#[derive(Serialize)]
struct ModuleChange {
    platform: String,
    module: String,
    change: &'static str,
    old: Option<String>,
    new: Option<String>,
    old_packaging: Option<String>,
    new_packaging: Option<String>,
}

impl ModuleChange {
    fn line(&self) -> String {
        let side = |value: &Option<String>| value.as_deref().unwrap_or("none").to_string();
        match self.change {
            "added" => format!("  module {} added: {}", self.module, side(&self.new)),
            "removed" => format!("  module {} removed: {}", self.module, side(&self.old)),
            _ => {
                let packaging = if self.old_packaging == self.new_packaging {
                    String::new()
                } else {
                    format!(
                        " ({} -> {})",
                        side(&self.old_packaging),
                        side(&self.new_packaging)
                    )
                };
                format!(
                    "  module {}: {} -> {}{packaging}",
                    self.module,
                    side(&self.old),
                    side(&self.new)
                )
            }
        }
    }
}

/// A locked file that `--allow-missing-checksums` accepted without a
/// checksum file in the new lock only, or whose marker the new lock drops.
#[derive(Serialize)]
struct ChecksumMarker {
    path: String,
    change: &'static str,
}

impl ChecksumMarker {
    fn between(old: &Lockfile, new: &Lockfile) -> Vec<Self> {
        let (was, now) = (old.missing_checksum_files(), new.missing_checksum_files());
        let pinned = new.pinned_paths();
        let marked = (now.keys())
            .filter(|path| !was.contains_key(*path))
            .map(|path| (path, "marked"));
        let cleared = (was.keys())
            .filter(|path| !now.contains_key(*path) && pinned.contains_key(*path))
            .map(|path| (path, "cleared"));
        let mut markers: Vec<Self> = marked
            .chain(cleared)
            .map(|(path, change)| Self {
                path: path.clone(),
                change,
            })
            .collect();
        markers.sort_by(|a, b| a.path.cmp(&b.path));
        markers
    }

    fn line(&self) -> String {
        match self.change {
            "marked" => format!("  accepted without a checksum file: {}", self.path),
            _ => format!("  now verified by a checksum file: {}", self.path),
        }
    }
}

#[derive(Serialize)]
struct ProfileChange {
    platform: String,
    old: Vec<String>,
    new: Vec<String>,
}

impl ProfileChange {
    fn line(&self) -> String {
        let side = |profiles: &[String]| {
            if profiles.is_empty() {
                "none".to_string()
            } else {
                profiles.join(", ")
            }
        };
        format!(
            "  active profiles: {} -> {}",
            side(&self.old),
            side(&self.new)
        )
    }
}

/// A parent or BOM bump behind version changes that dependency management
/// supplied, or a parent's property, from the `managed` lines: a source of
/// the package in either lock whose versions among the module's support
/// POMs differ between the locks, or a module of the reactor that changed
/// (see [`ReactorPoms::source`]). A package whose two locks name two such
/// sources has both, as `ambiguous`.
#[derive(Serialize)]
struct Cause {
    sources: Vec<CauseSource>,
    /// `property` for a parent that sets `property`, or when a BOM's import
    /// version is written as `property` for every package it moved, else
    /// `direct` for a parent, `imported` for a BOM, or `ambiguous`.
    cause: &'static str,
    property: Option<String>,
    /// Indexes into `changes`: what the sources manage, and for `property`
    /// what the module's lineage manages with it.
    changes: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct CauseSource {
    kind: &'static str,
    pom: String,
    old_versions: Vec<String>,
    new_versions: Vec<String>,
    /// A module of the reactor, which counts only where it changed.
    #[serde(skip)]
    reactor: bool,
}

impl CauseSource {
    fn moved(&self) -> bool {
        self.reactor
            || (!self.old_versions.is_empty()
                && !self.new_versions.is_empty()
                && self.old_versions != self.new_versions)
    }

    /// The role, the `group:artifact`, and the versions that left and came;
    /// a side where none did shows all of its versions. A reactor module
    /// whose version stayed shows it once, as changed.
    fn text(&self) -> String {
        let (old, new) = (&self.old_versions, &self.new_versions);
        let role = if self.kind == ManagedKind::Import.as_str() {
            "BOM"
        } else {
            "parent"
        };
        if old == new {
            return format!("{role} {} {} changed", self.pom, old.join(", "));
        }
        let gone: Vec<&str> = (old.iter())
            .filter(|v| !new.contains(v))
            .map(String::as_str)
            .collect();
        let came: Vec<&str> = (new.iter())
            .filter(|v| !old.contains(v))
            .map(String::as_str)
            .collect();
        let side = |changed: Vec<&str>, all: &[String]| {
            if changed.is_empty() {
                all.join(", ")
            } else {
                changed.join(", ")
            }
        };
        format!(
            "{role} {} {} -> {}",
            self.pom,
            side(gone, old),
            side(came, new)
        )
    }
}

/// Whether the package has two moved sources, its moved sources, and the
/// property of a parent that sets it, which keeps one cause per property.
type CauseKey = (bool, Vec<CauseSource>, Option<String>);

impl Cause {
    fn of(
        old: &Lockfile,
        new: &Lockfile,
        changes: &[(DepKey, Change)],
        old_map: &HashMap<DepKey, DepEntry>,
        new_map: &HashMap<DepKey, DepEntry>,
    ) -> Vec<Self> {
        let (before, after) = (SupportPoms::of(old), SupportPoms::of(new));
        let reactor = (ReactorPoms::of(old), ReactorPoms::of(new));
        let mut grouped: BTreeMap<CauseKey, (Vec<usize>, BTreeSet<Option<String>>)> =
            BTreeMap::new();
        for (index, (key, change)) in changes.iter().enumerate() {
            if !matches!(change, Change::Version { .. }) {
                continue;
            }
            let (Some(was), Some(now)) = (old_map.get(key), new_map.get(key)) else {
                continue;
            };
            let place = (key.platform.as_str(), key.module_path.as_str());
            let mut sources: Vec<(CauseSource, Vec<Option<String>>)> = Vec::new();
            for managed in [&was.managed, &now.managed].into_iter().flatten() {
                let kind = managed.kind.as_str();
                let (old_versions, new_versions) = (
                    before.versions(place, managed),
                    after.versions(place, managed),
                );
                let source = if old_versions.is_empty() && new_versions.is_empty() {
                    ReactorPoms::source(&reactor, place, managed, was, now)
                } else {
                    Some(CauseSource {
                        kind,
                        pom: managed.pom.clone(),
                        old_versions,
                        new_versions,
                        reactor: false,
                    })
                };
                let Some(source) = source else {
                    continue;
                };
                // A reactor module's version is the reactor's, which its
                // property names for the whole lineage.
                let property = (!source.reactor)
                    .then(|| managed.property.clone())
                    .flatten();
                match (sources.iter_mut()).find(|(s, _)| s.kind == kind && s.pom == managed.pom) {
                    Some((_, properties)) => properties.push(property),
                    None => sources.push((source, vec![property])),
                }
            }
            sources.retain(|(source, _)| source.moved());
            if sources.is_empty() {
                continue;
            }
            // The new lock's property, which a parent bump may have renamed.
            let set_by = match &sources[..] {
                [(source, properties)] if source.kind == ManagedKind::Property.as_str() => {
                    properties.last().cloned().flatten()
                }
                _ => None,
            };
            let key = (
                sources.len() > 1,
                sources.iter().map(|(source, _)| source.clone()).collect(),
                set_by,
            );
            let (indexes, seen) = grouped.entry(key).or_default();
            indexes.push(index);
            seen.extend(sources.into_iter().flat_map(|(_, properties)| properties));
        }
        let mut causes: Vec<Self> = grouped
            .into_iter()
            .map(|((ambiguous, sources, set_by), (changes, seen))| {
                let import = sources[0].kind == ManagedKind::Import.as_str();
                let property = match seen.iter().collect::<Vec<_>>()[..] {
                    _ if set_by.is_some() => set_by,
                    [Some(property)] if import && !ambiguous => Some(property.clone()),
                    _ => None,
                };
                let cause = match (ambiguous, &property, import) {
                    (true, _, _) => "ambiguous",
                    (false, Some(_), _) => "property",
                    (false, None, true) => "imported",
                    (false, None, false) => "direct",
                };
                Self {
                    sources,
                    cause,
                    property,
                    changes,
                }
            })
            .collect();
        // A property has one value in a module's lineage, so the BOM bump
        // it caused also moved what the module's own POMs manage with it.
        let mut by_property = HashMap::new();
        for (at, cause) in causes.iter().enumerate() {
            for &index in &cause.changes {
                let key = &changes[index].0;
                if let Some(property) = &cause.property {
                    // Two BOM bumps with one property leave it to neither.
                    by_property
                        .entry((&key.platform, &key.module_path, property.clone()))
                        .and_modify(|owner: &mut Option<usize>| {
                            if *owner != Some(at) {
                                *owner = None;
                            }
                        })
                        .or_insert(Some(at));
                }
            }
        }
        let caused: HashSet<usize> = (causes.iter())
            .flat_map(|cause| cause.changes.iter().copied())
            .collect();
        for (index, (key, change)) in changes.iter().enumerate() {
            if caused.contains(&index) || !matches!(change, Change::Version { .. }) {
                continue;
            }
            let (Some(was), Some(now)) = (old_map.get(key), new_map.get(key)) else {
                continue;
            };
            let (Some(a), Some(b)) = (&was.managed, &now.managed) else {
                continue;
            };
            if a != b || a.kind != ManagedKind::Pom {
                continue;
            }
            if let Some(property) = &a.property
                && let Some(&Some(at)) =
                    by_property.get(&(&key.platform, &key.module_path, property.clone()))
            {
                causes[at].changes.push(index);
            }
        }
        for cause in &mut causes {
            cause.changes.sort_unstable();
        }
        causes
    }

    fn line(&self) -> String {
        let sources: Vec<String> = self.sources.iter().map(CauseSource::text).collect();
        let cause = match &self.property {
            Some(property) => format!("property {property}"),
            None => self.cause.to_string(),
        };
        format!("  {} ({cause})", sources.join(" and "))
    }
}

/// Each lock's reactor modules, by platform and `group:artifact`, and its
/// recorded POM digests, by platform and path.
struct ReactorPoms<'a> {
    modules: HashMap<(String, String), Vec<&'a rv_lock::LockModule>>,
    digests: HashMap<(String, &'a str), &'a rv_maven_types::Sha256>,
}

impl<'a> ReactorPoms<'a> {
    fn of(lock: &'a Lockfile) -> Self {
        let (mut modules, mut digests) = (HashMap::<_, Vec<_>>::new(), HashMap::new());
        for platform in &lock.platforms {
            let id = platform.platform.to_string();
            for module in &platform.modules {
                let ga = format!("{}:{}", module.gav.group, module.gav.artifact);
                modules.entry((id.clone(), ga)).or_default().push(module);
            }
            for (path, digest) in (platform.model_inputs.iter()).flat_map(|m| &m.pom_hashes) {
                digests.insert((id.clone(), path.as_str()), digest);
            }
        }
        Self { modules, digests }
    }

    /// The one reactor module `managed` names on the platform.
    fn module(&self, platform: &str, managed: &ManagedSource) -> Option<&'a rv_lock::LockModule> {
        match self
            .modules
            .get(&(platform.to_string(), managed.pom.clone()))?[..]
        {
            [module] => Some(module),
            _ => None,
        }
    }

    /// `managed` as a cause when it is the one module of the reactor with
    /// its `group:artifact` in both locks, wherever it is, other than the
    /// module at `place`, the package took its version from it in both
    /// locks, and its recorded digest changed, which its version moving
    /// does too. A user
    /// property or a profile changes no digest, so it names no module; a
    /// digest that covers the whole reactor changes with any module.
    fn source(
        (before, after): &(Self, Self),
        (platform, path): (&str, &str),
        managed: &ManagedSource,
        was: &DepEntry,
        now: &DepEntry,
    ) -> Option<CauseSource> {
        let (old, new) = (
            before.module(platform, managed)?,
            after.module(platform, managed)?,
        );
        let kept = [&was.managed, &now.managed].iter().all(|source| {
            (source.as_deref()).is_some_and(|s| (s.kind, &s.pom) == (managed.kind, &managed.pom))
        });
        if old.path == path || new.path == path || !kept {
            return None;
        }
        let digest = |pom: &Self, module: &LockModule| {
            (pom.digests
                .get(&(platform.to_string(), module.path.as_str())))
            .copied()
        };
        (digest(before, old) != digest(after, new)).then(|| CauseSource {
            kind: managed.kind.as_str(),
            pom: managed.pom.clone(),
            old_versions: vec![old.gav.version().to_string()],
            new_versions: vec![new.gav.version().to_string()],
            reactor: true,
        })
    }
}

/// Each lock module's support POMs, by platform and path.
struct SupportPoms<'a>(HashMap<(String, &'a str), &'a LockModule>);

impl<'a> SupportPoms<'a> {
    fn of(lock: &'a Lockfile) -> Self {
        let mut modules = HashMap::new();
        for platform in &lock.platforms {
            let id = platform.platform.to_string();
            for module in &platform.modules {
                modules.insert((id.clone(), module.path.as_str()), module);
            }
        }
        Self(modules)
    }

    /// The versions of `managed.pom` the module at `place` read: of a BOM,
    /// every one its resolution read; of a parent, the lineage's, since a
    /// dependency's lineage may read others.
    fn versions(&self, (platform, path): (&str, &str), managed: &ManagedSource) -> Vec<String> {
        let Some(module) = self.0.get(&(platform.to_string(), path)) else {
            return Vec::new();
        };
        let coordinates = match managed.kind {
            ManagedKind::Import => &module.support_poms,
            ManagedKind::Pom | ManagedKind::Property => &module.parents,
        };
        (coordinates.iter())
            .filter_map(|coordinate| {
                coordinate
                    .strip_prefix(managed.pom.as_str())?
                    .strip_prefix(':')
            })
            .map(str::to_string)
            .collect()
    }
}

#[derive(Serialize)]
struct PackageChange {
    platform: String,
    module: String,
    coordinate: String,
    kind: &'static str,
    change: &'static str,
    old_version: Option<String>,
    new_version: Option<String>,
    old: Option<String>,
    new: Option<String>,
    via: Vec<Vec<String>>,
    via_truncated: bool,
    #[serde(skip)]
    display_via: Vec<String>,
}

impl LockDiffReport {
    fn between(
        old: String,
        new: String,
        old_lock: &Lockfile,
        new_lock: &Lockfile,
        detail: bool,
    ) -> Result<Self> {
        let diff = LockChanges::between(old_lock, new_lock, None);
        let mut changes = Vec::with_capacity(diff.changes.len());
        let mut graphs = HashMap::new();
        for (index, (key, change)) in diff.changes.iter().enumerate() {
            let (name, old_detail, new_detail) = match change {
                Change::Added { .. } => ("added", None, None),
                Change::Removed { .. } => ("removed", None, None),
                Change::Version { .. } => ("version", None, None),
                Change::Checksum { .. } => ("checksum", None, None),
                Change::Snapshot { old, new, .. } => {
                    ("snapshot", Some(old.clone()), Some(new.clone()))
                }
                Change::Origin { old, new, .. } => ("origin", Some(old.clone()), Some(new.clone())),
                Change::Scope { old, new, .. } => ("scope", Some(old.clone()), Some(new.clone())),
            };
            let mut row = PackageChange {
                platform: key.platform.clone(),
                module: key.module_path.clone(),
                coordinate: key.package.coordinate(),
                kind: match key.package.kind {
                    DepKind::External => "external",
                    DepKind::Workspace => "workspace",
                    DepKind::System => "system",
                },
                change: name,
                old_version: diff.old_map.get(key).map(DepEntry::version),
                new_version: diff.new_map.get(key).map(DepEntry::version),
                old: old_detail,
                new: new_detail,
                via: Vec::new(),
                via_truncated: false,
                display_via: Vec::new(),
            };
            if index < VIA_CHANGE_CAP {
                let removed = matches!(change, Change::Removed { .. });
                let lock = if removed { old_lock } else { new_lock };
                let module = lock
                    .platforms
                    .iter()
                    .find(|platform| platform.platform.to_string() == key.platform)
                    .and_then(|platform| {
                        platform
                            .modules
                            .iter()
                            .find(|module| module.path == key.module_path)
                    });
                if let Some(module) = module {
                    let graph_key = (removed, key.platform.as_str(), key.module_path.as_str());
                    if let std::collections::hash_map::Entry::Vacant(entry) =
                        graphs.entry(graph_key)
                    {
                        let (graph, mut roots) = why::build_graph(module)?;
                        roots.retain(|&root| module.packages[root].direct_scope.is_some());
                        entry.insert((graph, roots));
                    }
                    let (graph, roots) = &graphs[&graph_key];
                    let targets: Vec<_> = module
                        .packages
                        .iter()
                        .enumerate()
                        .filter(|(_, package)| {
                            PackageKey::of(package) == key.package
                                && key
                                    .version
                                    .as_deref()
                                    .is_none_or(|version| package.coordinate.version() == version)
                        })
                        .map(|(index, _)| index)
                        .collect();
                    let (paths, truncated) =
                        why::collect_paths(graph, roots, &targets, VIA_PATH_CAP);
                    row.via_truncated = truncated;
                    // Text names the packages that lead to this one by name.
                    if let Some((_, leading)) = paths.first().and_then(|path| path.split_last()) {
                        row.display_via = (leading.iter())
                            .map(|&index| PackageKey::of(&module.packages[index]).short_name())
                            .collect();
                    }
                    row.via = paths
                        .iter()
                        .map(|path| {
                            path.iter()
                                .map(|&index| {
                                    crate::commands::util::package_coordinate(
                                        &module.packages[index],
                                    )
                                })
                                .collect()
                        })
                        .collect();
                }
            }
            changes.push(row);
        }
        let platforms_added: Vec<_> = diff
            .new_platforms
            .difference(&diff.old_platforms)
            .cloned()
            .collect();
        let platforms_removed: Vec<_> = diff
            .old_platforms
            .difference(&diff.new_platforms)
            .cloned()
            .collect();
        let mut lines = diff.lines(detail);
        let checksum_markers = ChecksumMarker::between(old_lock, new_lock);
        lines.extend((checksum_markers.iter()).map(|marker| (marker.line(), vec![])));
        Ok(Self {
            old,
            new,
            changed: !lines.is_empty(),
            platforms_added,
            platforms_removed,
            via_limited: changes.len() > VIA_CHANGE_CAP,
            causes: diff.causes,
            module_changes: diff.module_changes,
            profile_changes: diff.profile_changes,
            changes,
            edge_changes: diff.edge_changes,
            pom_changes: diff.pom_changes,
            plugin_changes: diff.plugin_changes,
            checksum_markers,
            changed_inputs: diff.changed_inputs,
            host_inputs: diff.host_inputs,
            lines,
        })
    }
}

impl CommandOutput for LockDiffReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::to_value(self)
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        human.heading("Lockfile diff")?;
        if !self.changed {
            return human.line(match inputs_line(&self.changed_inputs, &self.host_inputs) {
                Some(inputs) => format!("  no dependency changes;{}", &inputs[1..]),
                None => "  no dependency changes".to_string(),
            });
        }
        for (line, at) in &self.lines {
            human.line(line)?;
            // A direct dependency has no path to it, and the places a line
            // groups may reach the package by different paths.
            let mut vias =
                (at.iter()).filter_map(|&index| Some(&self.changes.get(index)?.display_via));
            if let Some(via) = vias.next()
                && !via.is_empty()
                && vias.all(|other| other == via)
            {
                human.line(format!("      via {}", via.join(" -> ")))?;
            }
        }
        Ok(())
    }
}

/// The inputs whose recorded hashes changed, then the host inputs a
/// resolution reads now or no longer reads, as one line.
fn inputs_line(inputs: &[String], host: &[String]) -> Option<String> {
    const LISTED_POMS: usize = 3;
    let config = inputs.iter().any(|input| input == "config_hash");
    let poms: Vec<&String> = inputs
        .iter()
        .filter(|input| *input != "config_hash" && !host.contains(input))
        .collect();
    // A POM's record covers its parents, so a parent edit changes many.
    let poms = if poms.len() > LISTED_POMS {
        vec![format!("the records of {} reactor POMs", poms.len())]
    } else {
        poms.into_iter().cloned().collect()
    };
    let config = config.then(|| "the configuration (config_hash)".to_string());
    let host = match host {
        [] => None,
        [one] => Some(format!("the host input {one}")),
        many if many.len() <= LISTED_POMS => Some(format!(
            "the host inputs {}",
            join_and(many.iter().cloned())
        )),
        many => Some(format!("{} host inputs", many.len())),
    };
    let names: Vec<String> = config.into_iter().chain(poms).chain(host).collect();
    (!names.is_empty()).then(|| format!("  changed inputs: {}", join_and(names.into_iter())))
}

/// `config_hash` when the configuration hashes differ, then each reactor
/// POM whose recorded hash differs on a platform both locks record, then
/// the [`host_inputs`].
fn changed_inputs(
    old: &Lockfile,
    new: &Lockfile,
    allowed: Option<&HashSet<String>>,
) -> Vec<String> {
    let mut inputs = BTreeSet::new();
    for platform in matching_platforms(new, allowed) {
        let previous = (old.platforms.iter())
            .find(|candidate| candidate.platform == platform.platform)
            .and_then(|previous| previous.model_inputs.as_ref());
        let (Some(before), Some(after)) = (previous, platform.model_inputs.as_ref()) else {
            continue;
        };
        for (path, hash) in &after.pom_hashes {
            if before.pom_hashes.get(path).is_some_and(|old| old != hash) {
                inputs.insert(path.clone());
            }
        }
    }
    let config = (old.config_hash != new.config_hash).then(|| "config_hash".to_string());
    (config.into_iter().chain(inputs))
        .chain(host_inputs(old, new))
        .collect()
}

/// The `[resolution] ambient_inputs` names only one of the locks records,
/// as the lock writes them.
fn host_inputs(old: &Lockfile, new: &Lockfile) -> Vec<String> {
    (old.resolution.ambient_inputs)
        .symmetric_difference(&new.resolution.ambient_inputs)
        .map(ToString::to_string)
        .collect()
}

/// Maximum number of changed entries shown inline in a `--frozen` mismatch
/// error. Beyond this, a "... and N more" summary keeps the message concise.
const FROZEN_DIFF_DISPLAY_CAP: usize = 10;

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct DepKey {
    platform: String,
    module_path: String,
    /// The package, which the rendered line names without the platform and
    /// module unless they matter.
    package: PackageKey,
    version: Option<String>,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum DepKind {
    External,
    Workspace,
    System,
}

impl DepKind {
    fn label(self) -> Option<&'static str> {
        match self {
            Self::External => None,
            Self::Workspace => Some("workspace module"),
            Self::System => Some("system"),
        }
    }
}

impl PackageKey {
    fn of(package: &rv_lock::LockModulePackage) -> Self {
        let coordinate = &package.coordinate;
        Self {
            kind: if package.workspace_module.is_some() {
                DepKind::Workspace
            } else if package.system_path.is_some() {
                DepKind::System
            } else {
                DepKind::External
            },
            group_id: coordinate.group_id().to_string(),
            artifact_id: coordinate.artifact_id().to_string(),
            packaging: package.maven_type().to_string(),
            extension: coordinate.extension().to_string(),
            classifier: coordinate.classifier().map(str::to_string),
        }
    }

    fn coordinate(&self) -> String {
        let base = format!("{}:{}:{}", self.group_id, self.artifact_id, self.packaging);
        self.classifier
            .as_ref()
            .map_or_else(|| base.clone(), |classifier| format!("{base}:{classifier}"))
    }

    /// `group:artifact`, with the type and classifier when the package is
    /// not a plain jar.
    fn name(&self) -> String {
        let base = format!("{}:{}", self.group_id, self.artifact_id);
        let classifier = self.classifier.as_deref().filter(|c| !c.is_empty());
        if self.packaging == "jar" && classifier.is_none() {
            return base;
        }
        self.coordinate()
    }

    fn short_name(&self) -> String {
        let mut name = self.artifact_id.clone();
        let classifier = self.classifier.as_deref().filter(|c| !c.is_empty());
        if self.packaging != "jar" || classifier.is_some() {
            name.push(':');
            name.push_str(&self.packaging);
            if let Some(classifier) = classifier {
                name.push(':');
                name.push_str(classifier);
            }
        }
        name
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct PackageKey {
    kind: DepKind,
    group_id: String,
    artifact_id: String,
    packaging: String,
    /// The file's, which a type no longer names: another one is another
    /// file.
    extension: String,
    classifier: Option<String>,
}

/// A package as the diff compares it: an external package's artifact row,
/// or a synthetic row with a workspace module's path or a system package's
/// path and checksum.
#[derive(Debug, Clone)]
struct DepEntry {
    artifact: LockArtifact,
    direct_scope: Option<Scope>,
    scope: Scope,
    managed: Option<Arc<ManagedSource>>,
}

impl DepEntry {
    fn version(&self) -> String {
        self.artifact.file_version()
    }

    fn snapshot(&self) -> Option<String> {
        self.artifact.snapshot.as_ref().map(ToString::to_string)
    }

    fn scope(&self) -> String {
        match self.direct_scope {
            Some(direct) if direct == self.scope => direct.to_string(),
            Some(direct) => format!("{direct} resolving to {}", self.scope),
            None => format!("transitive {}", self.scope),
        }
    }
}

struct LockChanges {
    old_map: HashMap<DepKey, DepEntry>,
    new_map: HashMap<DepKey, DepEntry>,
    old_platforms: BTreeSet<String>,
    new_platforms: BTreeSet<String>,
    changes: Vec<(DepKey, Change)>,
    module_changes: Vec<ModuleChange>,
    profile_changes: Vec<ProfileChange>,
    edge_changes: Vec<EdgeChange>,
    pom_changes: Vec<PomChange>,
    plugin_changes: Vec<PluginChange>,
    causes: Vec<Cause>,
    changed_inputs: Vec<String>,
    /// The [`host_inputs`], which `changed_inputs` ends with too.
    host_inputs: Vec<String>,
}

impl LockChanges {
    fn between(old: &Lockfile, new: &Lockfile, allowed: Option<&HashSet<String>>) -> Self {
        let plugin_changes = plugin_changes(old, new, allowed);
        // The plugin tables' rows are compared as their sets.
        let (old, new) = (&old.without_plugins(), &new.without_plugins());
        let old_map = dep_map(old, allowed);
        let new_map = dep_map(new, allowed);
        let mut versions = HashMap::<DepKey, [usize; 2]>::new();
        for (side, map) in [&old_map, &new_map].into_iter().enumerate() {
            for key in map.keys() {
                let mut key = key.clone();
                key.version = None;
                versions.entry(key).or_default()[side] += 1;
            }
        }
        // Pair versions only when each module has one on both sides.
        let pair = |(mut key, entry): (DepKey, DepEntry)| {
            let version = key.version.take();
            if versions[&key] != [1, 1] {
                key.version = version;
            }
            (key, entry)
        };
        let old_map: HashMap<_, _> = old_map.into_iter().map(pair).collect();
        let new_map: HashMap<_, _> = new_map.into_iter().map(pair).collect();
        let old_platforms = platform_ids(old, allowed);
        let new_platforms = platform_ids(new, allowed);
        let keys: BTreeSet<&DepKey> = old_map.keys().chain(new_map.keys()).collect();
        let changes: Vec<(DepKey, Change)> = keys
            .into_iter()
            .filter(|key| {
                old_platforms.contains(&key.platform) && new_platforms.contains(&key.platform)
            })
            .filter_map(|key| {
                Change::of(key, old_map.get(key), new_map.get(key))
                    .map(|change| (key.clone(), change))
            })
            .collect();
        let (module_changes, profile_changes) = model_changes(old, new, allowed);
        let edge_changes = edge_changes(old, new, allowed, &old_map, &new_map);
        let causes = Cause::of(old, new, &changes, &old_map, &new_map);
        Self {
            old_map,
            new_map,
            old_platforms,
            new_platforms,
            changes,
            module_changes,
            profile_changes,
            edge_changes,
            pom_changes: pom_pin_changes(old, new, allowed),
            plugin_changes,
            causes,
            changed_inputs: changed_inputs(old, new, allowed),
            host_inputs: host_inputs(old, new),
        }
    }

    /// Each cause, then the packages it moved beneath it.
    fn cause_lines(&self) -> Vec<(String, Vec<usize>)> {
        let mut lines = Vec::new();
        for cause in &self.causes {
            lines.push((cause.line(), Vec::new()));
            lines.extend(change_lines(self, &cause.changes, "    ", false));
        }
        lines
    }

    /// The text lines. Without `detail`, the support POMs added or removed
    /// along with changed packages are one count.
    fn lines(&self, detail: bool) -> Vec<(String, Vec<usize>)> {
        // A module, profile, or pin change is one line for every platform
        // both locks record; a platform only one side records is already one
        // line of its own.
        let compared: BTreeSet<&String> = self
            .old_platforms
            .intersection(&self.new_platforms)
            .collect();
        let grouped = |changes: Vec<(String, &String)>| {
            let mut grouped: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
            for (line, platform) in changes {
                if compared.contains(platform) {
                    grouped.entry(line).or_default().insert(platform);
                }
            }
            grouped
                .into_iter()
                .map(|(line, platforms)| {
                    let line = if platforms.len() < compared.len() {
                        format!(
                            "{line} (on {})",
                            join_and(platforms.into_iter().map(str::to_string))
                        )
                    } else {
                        line
                    };
                    (line, Vec::new())
                })
                .collect::<Vec<(String, Vec<usize>)>>()
        };
        let mut lines = self.cause_lines();
        lines.extend(grouped(
            self.module_changes
                .iter()
                .map(|change| (change.line(), &change.platform))
                .chain(
                    self.profile_changes
                        .iter()
                        .map(|change| (change.line(), &change.platform)),
                )
                .collect(),
        ));
        let caused: HashSet<usize> = (self.causes.iter())
            .flat_map(|cause| cause.changes.iter().copied())
            .collect();
        let uncaused: Vec<usize> = (0..self.changes.len())
            .filter(|index| !caused.contains(index))
            .collect();
        let package_lines = change_lines(self, &uncaused, "  ", true);
        let platform_lines = platform_lines(self);
        let collapse = !detail && (!self.changes.is_empty() || !platform_lines.is_empty());
        lines.extend(package_lines);
        lines.extend(platform_lines);
        lines.extend(grouped(
            self.edge_changes
                .iter()
                .map(|change| (change.line(), &change.platform))
                .collect(),
        ));
        let churn = |change: &&PomChange| {
            collapse
                && compared.contains(&change.platform)
                && (change.change == "support_pom_removed"
                    || (change.change == "support_pom" && change.old.is_none()))
        };
        lines.extend(grouped(
            (self.pom_changes.iter())
                .filter(|change| !churn(change))
                .map(|change| (change.line(), &change.platform))
                .collect(),
        ));
        lines.extend(grouped(
            (self.plugin_changes.iter())
                .map(|change| (change.line(), &change.platform))
                .collect(),
        ));
        // A cause line already names the versions of its parents and BOMs.
        let named: HashSet<String> = (self.causes.iter())
            .flat_map(|cause| &cause.sources)
            .flat_map(|source| {
                (source.old_versions.iter())
                    .chain(&source.new_versions)
                    .map(|version| format!("{}:{version}", source.pom))
            })
            .collect();
        let mut added = BTreeSet::new();
        let mut removed = BTreeSet::new();
        for change in (self.pom_changes.iter())
            .filter(churn)
            .filter(|change| !named.contains(&change.coordinate))
        {
            let side = if change.change == "support_pom" {
                &mut added
            } else {
                &mut removed
            };
            side.insert(change.coordinate.as_str());
        }
        let counts: Vec<String> = [(added.len(), "added"), (removed.len(), "removed")]
            .into_iter()
            .filter(|(count, _)| *count > 0)
            .map(|(count, word)| format!("{count} {word}"))
            .collect();
        if !counts.is_empty() {
            lines.push((
                format!(
                    "  support POMs (parents and BOMs): {}; -v lists them",
                    counts.join(", ")
                ),
                Vec::new(),
            ));
        }
        lines
    }
}

fn lock_change_lines(
    old: &Lockfile,
    new: &Lockfile,
    allowed: Option<&HashSet<String>>,
) -> Vec<String> {
    LockChanges::between(old, new, allowed)
        .lines(true)
        .into_iter()
        .map(|(line, _)| line)
        .collect()
}

/// The changed entries for a `--frozen` mismatch, one per line, at most
/// [`FROZEN_DIFF_DISPLAY_CAP`] of them; empty when nothing changed.
pub(super) fn format_frozen_diff(old: &Lockfile, new: &Lockfile) -> String {
    let lines = lock_change_lines(old, new, None);
    if lines.is_empty() {
        return String::new();
    }

    let total = lines.len();
    let shown = total.min(FROZEN_DIFF_DISPLAY_CAP);
    let mut out = String::new();
    for line in &lines[..shown] {
        out.push_str(line);
        out.push('\n');
    }
    if total > FROZEN_DIFF_DISPLAY_CAP {
        out.push_str(&format!(
            "  ... and {} more; 'raeva sync' lists every change\n",
            total - FROZEN_DIFF_DISPLAY_CAP
        ));
    }
    out
}

fn matching_platforms<'a>(
    lock: &'a Lockfile,
    allowed: Option<&'a HashSet<String>>,
) -> impl Iterator<Item = &'a LockPlatform> + 'a {
    lock.platforms.iter().filter(move |platform| {
        allowed.is_none_or(|allowed| allowed.contains(&platform.platform.to_string()))
    })
}

fn platform_ids(lock: &Lockfile, allowed: Option<&HashSet<String>>) -> BTreeSet<String> {
    matching_platforms(lock, allowed)
        .map(|platform| platform.platform.to_string())
        .collect()
}

fn dep_map(lock: &Lockfile, allowed: Option<&HashSet<String>>) -> HashMap<DepKey, DepEntry> {
    let mut map = HashMap::new();
    for platform in matching_platforms(lock, allowed) {
        let platform_id = platform.platform.to_string();

        let artifacts: HashMap<_, _> = platform
            .artifacts
            .iter()
            .map(|artifact| (&artifact.coordinate, artifact))
            .collect();
        for module in &platform.modules {
            for package in &module.packages {
                let artifact = if let Some(workspace) = package.workspace_module.as_ref() {
                    LockArtifact::new(package.coordinate.clone(), workspace.clone())
                } else if let Some(path) = &package.system_path {
                    let mut artifact = LockArtifact::new(package.coordinate.clone(), path.clone());
                    artifact.checksums = package
                        .system_sha256
                        .clone()
                        .into_iter()
                        .map(Into::into)
                        .collect();
                    artifact
                } else {
                    artifacts.get(&package.coordinate).map_or_else(
                        || LockArtifact::new(package.coordinate.clone(), ""),
                        |artifact| (*artifact).clone(),
                    )
                };
                let key = DepKey {
                    platform: platform_id.clone(),
                    module_path: module.path.clone(),
                    package: PackageKey::of(package),
                    version: Some(package.coordinate.version().to_string()),
                };
                let entry = DepEntry {
                    artifact,
                    direct_scope: package.direct_scope,
                    scope: package.scope,
                    managed: package.managed.clone(),
                };
                map.insert(key, entry);
            }
        }
    }
    map
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Change {
    Version {
        old: String,
        new: String,
    },
    Added {
        version: String,
    },
    Removed {
        version: String,
    },
    Snapshot {
        version: String,
        old: String,
        new: String,
    },
    Checksum {
        version: String,
    },
    Origin {
        version: String,
        old: String,
        new: String,
    },
    Scope {
        version: String,
        old: String,
        new: String,
    },
}

impl Change {
    fn of(key: &DepKey, old: Option<&DepEntry>, new: Option<&DepEntry>) -> Option<Self> {
        let (old, new) = match (old, new) {
            (None, Some(new)) => {
                return Some(Self::Added {
                    version: new.version(),
                });
            }
            (Some(old), None) => {
                return Some(Self::Removed {
                    version: old.version(),
                });
            }
            (Some(old), Some(new)) => (old, new),
            (None, None) => return None,
        };
        let version = new.version();
        if old.version() != version {
            Some(Self::Version {
                old: old.version(),
                new: version,
            })
        } else if old.artifact.snapshot != new.artifact.snapshot {
            Some(Self::Snapshot {
                version,
                old: old.snapshot().unwrap_or_else(|| "none".to_string()),
                new: new.snapshot().unwrap_or_else(|| "none".to_string()),
            })
        } else if rv_lock::drift::checksum_drifted(&old.artifact, &new.artifact) {
            Some(Self::Checksum { version })
        } else if key.package.kind != DepKind::Workspace
            && (old.artifact.repo_url != new.artifact.repo_url
                || old.artifact.other_repo_urls != new.artifact.other_repo_urls
                || old.artifact.pom_repo_urls != new.artifact.pom_repo_urls)
        {
            let origin = |artifact: &LockArtifact| {
                if key.package.kind == DepKind::System {
                    artifact.repo_url.clone()
                } else {
                    let files = artifact
                        .file_origins()
                        .map(rv_lock::redact_origin)
                        .collect::<Vec<_>>()
                        .join(", ");
                    if artifact.pom_repo_urls.is_empty() {
                        files
                    } else {
                        let poms = artifact
                            .pom_repo_urls
                            .iter()
                            .map(|url| rv_lock::redact_origin(url))
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!("{files}; pom: {poms}")
                    }
                }
            };
            Some(Self::Origin {
                version,
                old: origin(&old.artifact),
                new: origin(&new.artifact),
            })
        } else if (old.direct_scope, old.scope) != (new.direct_scope, new.scope) {
            Some(Self::Scope {
                version,
                old: old.scope(),
                new: new.scope(),
            })
        } else {
            None
        }
    }

    fn describe(&self) -> (String, Option<&'static str>) {
        match self {
            Self::Version { old, new } => (format!("{old} -> {new}"), None),
            Self::Added { version } => (version.clone(), Some("added")),
            Self::Removed { version } => (version.clone(), Some("removed")),
            Self::Snapshot { version, old, new } => {
                (format!("{version}, snapshot {old} -> {new}"), None)
            }
            Self::Checksum { version } => (format!("{version}, checksum changed"), None),
            Self::Origin { version, old, new } => {
                (format!("{version}, origin {old} -> {new}"), None)
            }
            Self::Scope { version, old, new } => (format!("{version}, scope {old} -> {new}"), None),
        }
    }
}

/// One line per change of `indexes`, sorted by package: the artifact ID
/// (with the group ID when two of these packages share it), the change, and
/// in parentheses the modules of a multi-module project and the platforms it
/// applies to, when it is not all of them. `indent` leads each line, and
/// `via` keeps the changes' indexes for the text's `via` line.
fn change_lines(
    diff: &LockChanges,
    indexes: &[usize],
    indent: &str,
    via: bool,
) -> Vec<(String, Vec<usize>)> {
    let LockChanges {
        old_map,
        new_map,
        old_platforms,
        new_platforms,
        ..
    } = diff;
    let compared: BTreeSet<&String> = old_platforms.intersection(new_platforms).collect();
    let modules: BTreeSet<&str> = old_map
        .keys()
        .chain(new_map.keys())
        .map(|key| key.module_path.as_str())
        .collect();
    let multi_module = modules.len() > 1;

    type Places = BTreeMap<String, (BTreeSet<String>, Vec<usize>)>;
    let mut grouped: BTreeMap<(PackageKey, Change), Places> = BTreeMap::new();
    for &index in indexes {
        let (key, change) = &diff.changes[index];
        let (platforms, at) = grouped
            .entry((key.package.clone(), change.clone()))
            .or_default()
            .entry(key.module_path.clone())
            .or_default();
        platforms.insert(key.platform.clone());
        at.push(index);
    }

    let mut groups_by_artifact: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    for (package, _) in grouped.keys() {
        groups_by_artifact
            .entry(&package.artifact_id)
            .or_default()
            .insert(&package.group_id);
    }
    let mut rows = Vec::new();
    for ((package, change), places) in &grouped {
        let name = if groups_by_artifact[package.artifact_id.as_str()].len() > 1 {
            format!("{}:{}", package.group_id, package.short_name())
        } else {
            package.short_name()
        };
        let mut row = |in_modules: BTreeSet<String>, on_platforms: &BTreeSet<String>, at| {
            let (text, word) = change.describe();
            let mut notes: Vec<String> = word.into_iter().map(str::to_string).collect();
            notes.extend(package.kind.label().map(str::to_string));
            if multi_module && in_modules.len() < modules.len() {
                notes.push(format!("in {}", modules_phrase(&in_modules)));
            }
            if on_platforms.len() < compared.len() {
                notes.push(format!("on {}", join_and(on_platforms.iter().cloned())));
            }
            let text = if notes.is_empty() {
                text
            } else {
                format!("{text} ({})", notes.join(", "))
            };
            rows.push((name.clone(), text, at));
        };
        let (platforms, _) = places.values().next().expect("change has a module");
        if places.values().all(|(on, _)| on == platforms) {
            let at = (places.values()).flat_map(|(_, at)| at.iter().copied());
            row(places.keys().cloned().collect(), platforms, at.collect());
        } else {
            for (module, (platforms, at)) in places {
                row(BTreeSet::from([module.clone()]), platforms, at.clone());
            }
        }
    }

    let width = rows
        .iter()
        .map(|(name, _, _)| name.chars().count())
        .filter(|&width| width <= NAME_COLUMN_MAX)
        .max()
        .unwrap_or(0);
    rows.into_iter()
        .map(|(name, text, at)| {
            let at = if via { at } else { Vec::new() };
            (format!("{indent}{name:<width$}  {text}"), at)
        })
        .collect()
}

/// A platform that only one side records, as one line with its dependency
/// count.
fn platform_lines(diff: &LockChanges) -> Vec<(String, Vec<usize>)> {
    let LockChanges {
        old_map,
        new_map,
        old_platforms,
        new_platforms,
        ..
    } = diff;
    let mut lines = Vec::new();
    for (platform, map, word) in [
        (new_platforms.difference(old_platforms), new_map, "added"),
        (old_platforms.difference(new_platforms), old_map, "removed"),
    ]
    .into_iter()
    .flat_map(|(platforms, map, word)| platforms.map(move |platform| (platform, map, word)))
    {
        let count = map
            .keys()
            .filter(|key| &key.platform == platform && key.package.kind == DepKind::External)
            .map(|key| (&key.package, &key.version))
            .collect::<BTreeSet<_>>()
            .len();
        let count = plural(count, "dependency", "dependencies");
        lines.push((
            format!("  platform {platform} {word} ({count})"),
            Vec::new(),
        ));
    }
    lines
}

/// Names wider than this do not widen the column for the others.
const NAME_COLUMN_MAX: usize = 40;

#[derive(Serialize)]
struct EdgeChange {
    platform: String,
    module: String,
    from: String,
    to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to_version: Option<String>,
    change: &'static str,
    old: Option<String>,
    new: Option<String>,
    #[serde(skip)]
    from_name: String,
    #[serde(skip)]
    to_name: String,
    /// The scope, and whether optional, of an added or removed edge, for
    /// text.
    #[serde(skip)]
    state: String,
    /// Another edge between the same packages stays, with another scope or
    /// optional flag.
    #[serde(skip)]
    others: bool,
}

impl EdgeChange {
    fn line(&self) -> String {
        let (from, to) = (&self.from_name, &self.to_name);
        let side = |value: &Option<String>| value.clone().unwrap_or_else(|| "none".to_string());
        let state = &self.state;
        let change = match (self.change, self.others) {
            ("added", false) => format!("{from} now depends on {to} ({state})"),
            ("added", true) => format!("{from} now also depends on {to} ({state})"),
            ("removed", false) => format!("{from} no longer depends on {to}"),
            ("removed", true) => {
                format!("{from} no longer depends on {to} as {state}; another dependency stays")
            }
            (change, _) => format!(
                "{from}'s dependency on {to} changed {change} {} -> {}",
                side(&self.old),
                side(&self.new)
            ),
        };
        format!("  in {}: {change}", self.module)
    }
}

type EdgeState = (Scope, bool);
type EdgeMap = BTreeMap<(DepKey, DepKey), BTreeSet<EdgeState>>;

/// The edges of `lock`'s modules, but for those `other` records the same:
/// a module's edges only ever compare with its own.
fn edge_map(
    lock: &Lockfile,
    other: &Lockfile,
    allowed: Option<&HashSet<String>>,
    old_map: &HashMap<DepKey, DepEntry>,
    new_map: &HashMap<DepKey, DepEntry>,
) -> EdgeMap {
    let mut edges: EdgeMap = BTreeMap::new();
    for platform in matching_platforms(lock, allowed) {
        let platform_id = platform.platform.to_string();
        let other_modules = (other.platforms.iter())
            .find(|other| other.platform == platform.platform)
            .map_or(&[][..], |other| &other.modules[..]);
        for module in &platform.modules {
            if other_modules.contains(module) {
                continue;
            }
            let key = |index| {
                module.packages.get(index).map(|package| {
                    let mut key = DepKey {
                        platform: platform_id.clone(),
                        module_path: module.path.clone(),
                        package: PackageKey::of(package),
                        version: Some(package.coordinate.version().to_string()),
                    };
                    if !old_map.contains_key(&key) && !new_map.contains_key(&key) {
                        key.version = None;
                    }
                    key
                })
            };
            for edge in &module.edges {
                let (Some(from), Some(to)) = (key(edge.from), key(edge.to)) else {
                    continue;
                };
                // A package row already covers an added or removed endpoint.
                if [&from, &to]
                    .iter()
                    .all(|key| old_map.contains_key(key) && new_map.contains_key(key))
                {
                    edges
                        .entry((from, to))
                        .or_default()
                        .insert((edge.scope, edge.optional));
                }
            }
        }
    }
    edges
}

fn edge_changes(
    old: &Lockfile,
    new: &Lockfile,
    allowed: Option<&HashSet<String>>,
    old_map: &HashMap<DepKey, DepEntry>,
    new_map: &HashMap<DepKey, DepEntry>,
) -> Vec<EdgeChange> {
    let before = edge_map(old, new, allowed, old_map, new_map);
    let after = edge_map(new, old, allowed, old_map, new_map);
    let mut changes = Vec::new();
    let empty = BTreeSet::new();
    let describe = |(scope, optional): &EdgeState| format!("scope {scope}, optional {optional}");
    let name = |key: &DepKey| match &key.version {
        Some(version) => format!("{}:{version}", key.package.name()),
        None => key.package.name(),
    };
    for (from, to) in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
        let key = (from.clone(), to.clone());
        let old = before.get(&key).unwrap_or(&empty);
        let new = after.get(&key).unwrap_or(&empty);
        let mut added: Vec<_> = new.difference(old).collect();
        let others = |change| match change {
            "added" => !old.is_empty(),
            "removed" => !new.is_empty(),
            _ => false,
        };
        let mut push = |change, old, new, state: Option<&EdgeState>| {
            changes.push(EdgeChange {
                platform: from.platform.clone(),
                module: from.module_path.clone(),
                from: from.package.coordinate(),
                to: to.package.coordinate(),
                from_version: from.version.clone(),
                to_version: to.version.clone(),
                change,
                old,
                new,
                from_name: name(from),
                to_name: name(to),
                others: others(change),
                state: state.map_or_else(String::new, |(scope, optional)| {
                    if *optional {
                        format!("{scope}, optional")
                    } else {
                        scope.to_string()
                    }
                }),
            });
        };
        // The one edge between the packages changed, or one of several
        // turned optional or back. Any other difference is an edge removed
        // and another added.
        let single = old.len() == 1 && new.len() == 1;
        for a in old.difference(new) {
            let Some(index) = added.iter().position(|b| single || b.0 == a.0) else {
                push("removed", Some(describe(a)), None, Some(a));
                continue;
            };
            let b = added.remove(index);
            if a.0 != b.0 {
                push("scope", Some(a.0.to_string()), Some(b.0.to_string()), None);
            }
            if a.1 != b.1 {
                push(
                    "optional",
                    Some(a.1.to_string()),
                    Some(b.1.to_string()),
                    None,
                );
            }
        }
        for b in added {
            push("added", None, Some(describe(b)), Some(b));
        }
    }
    changes
}

#[derive(Serialize)]
struct PomChange {
    platform: String,
    coordinate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    change: &'static str,
    old: Option<String>,
    new: Option<String>,
    old_snapshot: Option<String>,
    new_snapshot: Option<String>,
}

impl PomChange {
    /// The line without its platform. Text shows a digest by its first 12
    /// hex digits; JSON keeps the whole digest.
    fn line(&self) -> String {
        let short = |digest: &Option<String>| {
            digest
                .as_deref()
                .map_or("none", |digest| digest.get(..12).unwrap_or(digest))
                .to_string()
        };
        let snapshot = |stamp: &Option<String>| {
            stamp
                .as_ref()
                .map_or_else(String::new, |stamp| format!(" (snapshot {stamp})"))
        };
        let coordinate = &self.coordinate;
        match (self.change, &self.old) {
            ("parent_range", _) => format!(
                "  parent range {coordinate} for {} in {}: {} -> {}",
                self.model.as_deref().unwrap_or_default(),
                self.module.as_deref().unwrap_or_default(),
                self.old.as_deref().unwrap_or("none"),
                self.new.as_deref().unwrap_or("none"),
            ),
            ("pom", _) => format!(
                "  POM changed for {coordinate}: {}{} -> {}{}",
                short(&self.old),
                snapshot(&self.old_snapshot),
                short(&self.new),
                snapshot(&self.new_snapshot)
            ),
            ("support_pom", None) => format!(
                "  support POM added for {coordinate}{}",
                snapshot(&self.new_snapshot)
            ),
            ("support_pom", Some(_)) => {
                format!(
                    "  support POM changed for {coordinate}: {}{} -> {}{}",
                    short(&self.old),
                    snapshot(&self.old_snapshot),
                    short(&self.new),
                    snapshot(&self.new_snapshot)
                )
            }
            ("support_pom_origin", _) => format!(
                "  support POM origin changed for {coordinate}: {} -> {}",
                self.old.as_deref().unwrap_or("none"),
                self.new.as_deref().unwrap_or("none")
            ),
            _ => format!(
                "  support POM removed for {coordinate}{}",
                snapshot(&self.old_snapshot)
            ),
        }
    }
}

/// Compute POM-pin drift, which `change_lines` cannot see.
///
/// A companion POM and a parent/BOM POM can both be republished with different
/// bytes and an unchanged dependency graph, so this drift shows up in the pins
/// alone. Without these lines a `--frozen` failure caused by it would report
/// "dependencies would change" and then list nothing.
fn pom_pin_changes(
    old: &Lockfile,
    new: &Lockfile,
    allowed: Option<&HashSet<String>>,
) -> Vec<PomChange> {
    let mut changes = Vec::new();
    for platform in matching_platforms(new, allowed) {
        // A platform only the new lock records is reported as added.
        let Some(previous) = old
            .platforms
            .iter()
            .find(|candidate| candidate.platform == platform.platform)
        else {
            continue;
        };
        let previous_artifacts: HashMap<_, _> = previous
            .artifacts
            .iter()
            .map(|artifact| (&artifact.coordinate, artifact))
            .collect();
        for artifact in &platform.artifacts {
            let Some(old_artifact) = previous_artifacts.get(&artifact.coordinate) else {
                continue;
            };
            let old_snapshot = old_artifact.pom_build();
            let new_snapshot = artifact.pom_build();
            // A new build of the artifact itself is its package row's
            // snapshot change, which covers the POM stamp that follows it.
            let stamp_changed =
                old_snapshot != new_snapshot && old_artifact.snapshot == artifact.snapshot;
            if old_artifact.pom_sha256 != artifact.pom_sha256 || stamp_changed {
                changes.push(PomChange {
                    module: None,
                    model: None,
                    platform: platform.platform.to_string(),
                    coordinate: artifact.coordinate.to_string(),
                    change: "pom",
                    old: old_artifact.pom_sha256.as_ref().map(ToString::to_string),
                    new: artifact.pom_sha256.as_ref().map(ToString::to_string),
                    old_snapshot: old_snapshot.map(ToString::to_string),
                    new_snapshot: new_snapshot.map(ToString::to_string),
                });
            }
        }
        let previous_poms = &previous.support_poms;
        for (coord, new_line) in &platform.support_poms {
            let old_line = previous_poms.get(coord);
            let pin_changed = old_line.map(|line| (&line.sha256, &line.snapshot))
                != Some((&new_line.sha256, &new_line.snapshot));
            let origin_changed = old_line.is_some_and(|line| line.repo_url != new_line.repo_url);
            if pin_changed || origin_changed {
                changes.push(PomChange {
                    module: None,
                    model: None,
                    platform: platform.platform.to_string(),
                    coordinate: coord.clone(),
                    change: if pin_changed {
                        "support_pom"
                    } else {
                        "support_pom_origin"
                    },
                    old: old_line.map(|line| {
                        if pin_changed {
                            line.sha256.to_string()
                        } else {
                            rv_lock::redact_origin(&line.repo_url)
                        }
                    }),
                    new: Some(if pin_changed {
                        new_line.sha256.to_string()
                    } else {
                        rv_lock::redact_origin(&new_line.repo_url)
                    }),
                    old_snapshot: old_line
                        .and_then(|line| line.snapshot.as_ref())
                        .map(ToString::to_string),
                    new_snapshot: new_line.snapshot.as_ref().map(ToString::to_string),
                });
            }
        }
        for (coord, pin) in previous_poms {
            if !platform.support_poms.contains_key(coord) {
                changes.push(PomChange {
                    module: None,
                    model: None,
                    platform: platform.platform.to_string(),
                    coordinate: coord.clone(),
                    change: "support_pom_removed",
                    old: Some(pin.sha256.to_string()),
                    new: None,
                    old_snapshot: pin.snapshot.as_ref().map(ToString::to_string),
                    new_snapshot: None,
                });
            }
        }
        let before = parent_range_selections(previous);
        let after = parent_range_selections(platform);
        for key in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
            let old = before.get(key);
            let new = after.get(key);
            if old.map(|s| &s.selected) == new.map(|s| &s.selected) {
                continue;
            }
            changes.push(PomChange {
                platform: platform.platform.to_string(),
                coordinate: key.2.to_string(),
                module: Some(key.0.to_string()),
                model: new.or(old).map(|s| s.model.clone()),
                change: "parent_range",
                old: old.map(|s| s.selected.clone()),
                new: new.map(|s| s.selected.clone()),
                old_snapshot: None,
                new_snapshot: None,
            });
        }
    }
    changes.sort_by(|a, b| {
        (&a.platform, &a.module, &a.model, &a.coordinate, a.change).cmp(&(
            &b.platform,
            &b.module,
            &b.model,
            &b.coordinate,
            b.change,
        ))
    });
    changes
}

/// A plugin, extension, processor path or trace that one lock's plugin
/// tables hold and the other's do not, or holds with other files.
#[derive(Serialize)]
struct PluginChange {
    platform: String,
    #[serde(serialize_with = "role_name")]
    role: PluginRole,
    name: String,
    change: &'static str,
    old: Option<String>,
    new: Option<String>,
}

impl PluginChange {
    fn line(&self) -> String {
        let role = match self.role {
            PluginRole::Trace => "plugin trace",
            role => &role.as_str().replace('-', " "),
        };
        let side = |value: &Option<String>| value.as_deref().unwrap_or("none").to_string();
        match self.change {
            "added" => format!("  {role} {} added", self.name),
            "removed" => format!("  {role} {} removed", self.name),
            "version" => format!(
                "  {role} {}: {} -> {}",
                self.name,
                side(&self.old),
                side(&self.new)
            ),
            _ => format!("  {role} {}: its files changed", self.name),
        }
    }
}

/// The plugin sets of each platform both locks record, by role and name,
/// each with the pinned files of its copies.
fn role_name<S: serde::Serializer>(
    role: &PluginRole,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(role.as_str())
}

fn plugin_sets(entry: &LockPlatform) -> BTreeMap<(PluginRole, String), Vec<Vec<String>>> {
    let mut sets: BTreeMap<(PluginRole, String), Vec<Vec<String>>> = BTreeMap::new();
    let Some(files) = entry.plugin_files() else {
        return sets;
    };
    let pins: HashMap<_, _> = (files.artifacts.iter())
        .map(|artifact| (&artifact.coordinate, artifact))
        .collect();
    for set in &files.tables.sets {
        let name = match set.coordinates.is_empty() {
            true => set.key.clone(),
            false => set.coordinates.join(", "),
        };
        let mut pinned: Vec<String> = (set.artifacts.iter())
            .map(|coordinate| {
                let artifact = pins.get(coordinate);
                let pin = artifact.and_then(|row| row.pin()).map(ToString::to_string);
                let pom = artifact.and_then(|row| row.pom_sha256.as_ref());
                format!(
                    "{coordinate} {} {}",
                    pin.unwrap_or_default(),
                    pom.map(ToString::to_string).unwrap_or_default()
                )
            })
            .chain(set.poms.iter().map(|pom| {
                let pin = files.poms.get(pom).map(|row| row.sha256.to_string());
                format!("{pom} {}", pin.unwrap_or_default())
            }))
            .collect();
        pinned.sort();
        sets.entry((set.role, name)).or_default().push(pinned);
    }
    for copies in sets.values_mut() {
        copies.sort();
    }
    sets
}

fn plugin_changes(
    old: &Lockfile,
    new: &Lockfile,
    allowed: Option<&HashSet<String>>,
) -> Vec<PluginChange> {
    let mut changes = Vec::new();
    for entry in matching_platforms(new, allowed) {
        let Some(previous) = (old.platforms.iter()).find(|other| other.platform == entry.platform)
        else {
            continue;
        };
        let (before, after) = (plugin_sets(previous), plugin_sets(entry));
        let platform = entry.platform.to_string();
        let change = |(role, name): &(PluginRole, String), change, old, new| PluginChange {
            platform: platform.clone(),
            role: *role,
            name: name.clone(),
            change,
            old,
            new,
        };
        let mut added = Vec::new();
        let mut removed = Vec::new();
        for key in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
            match (before.get(key), after.get(key)) {
                (Some(a), Some(b)) if a != b => changes.push(change(key, "files", None, None)),
                (Some(_), None) => removed.push(key),
                (None, Some(_)) => added.push(key),
                _ => {}
            }
        }
        // One version of a plugin on each side is a version change.
        let split_version = |(role, name): &(PluginRole, String)| {
            let parts: Vec<&str> = name.split(':').collect();
            let versioned = !matches!(role, PluginRole::Trace | PluginRole::ProcessorPath);
            (parts.len() == 3 && versioned).then(|| {
                let base = format!("{}:{}", parts[0], parts[1]);
                (*role, base, parts[2].to_string())
            })
        };
        let count = |keys: &[&(PluginRole, String)], key: &(PluginRole, String)| {
            (keys.iter())
                .filter(|other| split_version(other).map(|(r, n, _)| (r, n)) == Some(key.clone()))
                .count()
        };
        let mut paired = BTreeSet::new();
        for old_key in &removed {
            let Some((role, name, old_version)) = split_version(old_key) else {
                continue;
            };
            let base = (role, name.clone());
            if count(&removed, &base) != 1 || count(&added, &base) != 1 {
                continue;
            }
            let new_key = (added.iter())
                .find(|key| split_version(key).is_some_and(|(r, n, _)| (r, n) == base))
                .expect("counted");
            let new_version = split_version(new_key).expect("counted").2;
            paired.insert(*new_key);
            paired.insert(*old_key);
            changes.push(change(
                &base,
                "version",
                Some(old_version),
                Some(new_version),
            ));
        }
        for key in removed.into_iter().filter(|key| !paired.contains(key)) {
            changes.push(change(key, "removed", None, None));
        }
        for key in added.into_iter().filter(|key| !paired.contains(key)) {
            changes.push(change(key, "added", None, None));
        }
    }
    changes.sort_by(|a, b| (&a.platform, &a.role, &a.name).cmp(&(&b.platform, &b.role, &b.name)));
    changes
}

fn parent_range_selections(
    platform: &LockPlatform,
) -> BTreeMap<(&str, String, &str), &rv_lock::ParentRange> {
    platform
        .modules
        .iter()
        .flat_map(|module| {
            module.parent_ranges.iter().map(move |selection| {
                let model = platform
                    .modules
                    .iter()
                    .find(|m| m.gav.to_string() == selection.model)
                    .map(|m| format!("module:{}", m.path))
                    .unwrap_or_else(|| selection.model.clone());
                (
                    (module.path.as_str(), model, selection.parent.as_str()),
                    selection,
                )
            })
        })
        .collect()
}

/// Reactor modules added, removed, or given other coordinates, and active
/// profile changes, on each platform both locks record. A project version
/// bump changes only these.
fn model_changes(
    old: &Lockfile,
    new: &Lockfile,
    allowed: Option<&HashSet<String>>,
) -> (Vec<ModuleChange>, Vec<ProfileChange>) {
    let mut modules = Vec::new();
    let mut profiles = Vec::new();
    for platform in matching_platforms(new, allowed) {
        let Some(previous) = old
            .platforms
            .iter()
            .find(|candidate| candidate.platform == platform.platform)
        else {
            continue;
        };
        let platform_id = platform.platform.to_string();
        let before: BTreeMap<&str, &rv_lock::LockModule> = previous
            .modules
            .iter()
            .map(|module| (module.path.as_str(), module))
            .collect();
        let after: BTreeMap<&str, &rv_lock::LockModule> = platform
            .modules
            .iter()
            .map(|module| (module.path.as_str(), module))
            .collect();
        for path in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
            let (change, old_module, new_module) = match (before.get(path), after.get(path)) {
                (None, Some(module)) => ("added", None, Some(module)),
                (Some(module), None) => ("removed", Some(module), None),
                (Some(a), Some(b)) if a.gav != b.gav || a.packaging != b.packaging => {
                    ("coordinate", Some(a), Some(b))
                }
                _ => continue,
            };
            modules.push(ModuleChange {
                platform: platform_id.clone(),
                module: (*path).to_string(),
                change,
                old: old_module.map(|module| module.gav.to_string()),
                new: new_module.map(|module| module.gav.to_string()),
                old_packaging: old_module.map(|module| module.packaging.clone()),
                new_packaging: new_module.map(|module| module.packaging.clone()),
            });
        }
        // A lock written before model inputs were recorded has no profiles
        // to compare.
        if let (Some(a), Some(b)) = (&previous.model_inputs, &platform.model_inputs)
            && a.profiles != b.profiles
        {
            profiles.push(ProfileChange {
                platform: platform_id,
                old: a.profiles.clone(),
                new: b.profiles.clone(),
            });
        }
    }
    (modules, profiles)
}

/// The lines that list what a sync changed in raeva.lock, on the platforms it
/// resolved; empty when nothing changed.
pub(super) fn lock_diff(
    old: &Lockfile,
    new: &Lockfile,
    platforms: &[Platform],
    detail: bool,
) -> Vec<String> {
    let allowed: HashSet<String> = platforms.iter().map(ToString::to_string).collect();
    let diff = LockChanges::between(old, new, Some(&allowed));
    let markers = ChecksumMarker::between(old, new);
    let lines: Vec<String> = (diff.lines(detail).into_iter())
        .map(|(line, _)| line)
        .chain(markers.iter().map(ChecksumMarker::line))
        .collect();
    if lines.is_empty() {
        inputs_line(&diff.changed_inputs, &diff.host_inputs)
            .into_iter()
            .collect()
    } else {
        lines
    }
}

#[cfg(test)]
mod tests {
    use rv_lock::{LockArtifact, LockPlatform, Lockfile, Platform};
    use rv_maven_types::{ArtifactCoord, Gav};

    use super::{LockDiffReport, VIA_CHANGE_CAP};
    use crate::output::CommandOutput;
    use crate::output::testing::render;
    use rv_lock::{LockEdge, LockModulePackage, Scope, SupportPom};
    use serde_json::json;

    fn report(old: &Lockfile, new: &Lockfile) -> LockDiffReport {
        LockDiffReport::between("old.lock".into(), "new.lock".into(), old, new, true).unwrap()
    }

    #[test]
    fn the_docs_name_every_lock_diff_field() {
        let keys = rv_test_support::fixtures::serde_serialize_fields(include_str!("lock_diff.rs"));
        let docs = rv_test_support::fixtures::workspace_file("docs/json-output.md");
        let section = rv_test_support::fixtures::markdown_section(&docs, "## `raeva lock diff`");
        rv_test_support::fixtures::assert_markdown_names(
            section,
            "docs/json-output.md lock diff section",
            &keys,
        );
    }

    #[test]
    fn identical_locks_have_an_empty_report() {
        let lock = lock_from("https://repo.example/");
        let report = report(&lock, &lock);
        assert_eq!(
            report.to_json().unwrap(),
            json!({
                "old": "old.lock", "new": "new.lock", "changed": false, "causes": [],
                "platforms_added": [], "platforms_removed": [], "module_changes": [], "profile_changes": [],
                "changes": [], "edge_changes": [], "pom_changes": [], "plugin_changes": [],
                "checksum_markers": [],
                "changed_inputs": [],
                "via_limited": false,
            })
        );
        let (stdout, stderr) = render(false, |human| report.render_human(human));
        assert_eq!(stdout, "  no dependency changes\n");
        assert_eq!(stderr, "Lockfile diff\n");
    }

    /// A package whose type stays while its handler's extension changes is
    /// another file, as it was when the extension named the package.
    #[test]
    fn a_new_extension_under_the_same_type_is_a_change() {
        let typed = |extension: &str| {
            let mut lock = lock_from("https://repo.example/");
            let coordinate = ArtifactCoord::new("com.example", "lib", "1.0", extension, None);
            lock.platforms[0].artifacts[0].coordinate = coordinate.clone();
            let package = &mut lock.platforms[0].modules[0].packages[0];
            package.coordinate = coordinate;
            package.type_ = Some("my type".into());
            lock
        };
        assert!(report(&typed("jar"), &typed("zip")).changed);
        assert!(!report(&typed("jar"), &typed("jar")).changed);
    }

    #[test]
    fn system_checksum_and_path_changes_use_package_rows() {
        let mut old = lock_from("https://repo.example/");
        let package = &mut old.platforms[0].modules[0].packages[0];
        package.direct_scope = Some(Scope::System);
        package.scope = Scope::System;
        package.system_path = Some("lib/old?build=1#tools.jar".into());
        package.system_sha256 = Some("a".repeat(64).parse().unwrap());
        old.platforms[0].artifacts.clear();
        let mut new = old.clone();
        new.platforms[0].modules[0].packages[0].system_sha256 =
            Some("b".repeat(64).parse().unwrap());
        let checksum = report(&old, &new);
        assert!(checksum.changed);
        assert_eq!(checksum.changes.len(), 1);
        let json = checksum.to_json().unwrap();
        assert_eq!(json["changes"][0]["kind"], "system");
        assert_eq!(json["changes"][0]["change"], "checksum");
        assert_eq!(
            super::format_frozen_diff(&old, &new),
            "  lib  1.0, checksum changed (system)\n"
        );

        new = old.clone();
        new.platforms[0].modules[0].packages[0].system_path =
            Some("lib/new?build=2#tools.jar".into());
        let path = report(&old, &new);
        assert!(path.changed);
        let json = path.to_json().unwrap();
        assert_eq!(json["changes"][0]["change"], "origin");
        assert_eq!(json["changes"][0]["old"], "lib/old?build=1#tools.jar");
        assert_eq!(json["changes"][0]["new"], "lib/new?build=2#tools.jar");
        assert_eq!(
            super::format_frozen_diff(&old, &new),
            "  lib  1.0, origin lib/old?build=1#tools.jar -> lib/new?build=2#tools.jar (system)\n"
        );

        // A range keeps the same system file while the direct declaration
        // changes scope.
        old.platforms[0].modules[0].packages[0].direct_scope = Some(Scope::Compile);
        new = old.clone();
        new.platforms[0].modules[0].packages[0].direct_scope = Some(Scope::Test);
        assert_eq!(
            super::format_frozen_diff(&old, &new),
            "  lib  1.0, scope compile resolving to system -> test resolving to system (system)\n"
        );
    }

    fn edge_lock() -> Lockfile {
        let mut lock = lock_from("https://repo.example/");
        for name in ["one", "two"] {
            lock.platforms[0].modules[0]
                .packages
                .push(LockModulePackage::new(
                    ArtifactCoord::new("g", name, "1", "jar", Some("tests")),
                    None,
                ));
        }
        lock.platforms[0].modules[0].edges = vec![LockEdge::new(0, 1, Scope::Compile, false)];
        lock
    }

    /// Edges to packages with the same artifact id stay apart, and dropping
    /// one of two edges between the same packages says which one went.
    #[test]
    fn edge_lines_name_groups_and_the_edge_that_went() {
        let mut old = edge_lock();
        let module = &mut old.platforms[0].modules[0];
        module.packages.push(LockModulePackage::new(
            ArtifactCoord::new("h", "one", "1", "jar", Some("tests")),
            None,
        ));
        module
            .edges
            .push(LockEdge::new(0, 3, Scope::Compile, false));
        module
            .edges
            .push(LockEdge::new(0, 1, Scope::Runtime, false));
        let mut new = old.clone();
        new.platforms[0].modules[0].edges = vec![LockEdge::new(0, 1, Scope::Compile, false)];
        assert_eq!(
            super::format_frozen_diff(&old, &new),
            "  in pom.xml: com.example:lib no longer depends on g:one:jar:tests as runtime; \
             another dependency stays\n  \
             in pom.xml: com.example:lib no longer depends on h:one:jar:tests\n"
        );
        assert_eq!(
            super::format_frozen_diff(&new, &old),
            "  in pom.xml: com.example:lib now also depends on g:one:jar:tests (runtime)\n  \
             in pom.xml: com.example:lib now depends on h:one:jar:tests (compile)\n"
        );
    }

    /// With another edge between the same packages kept, a changed edge is
    /// one removed and one added, not a scope change; one that only turns
    /// optional is still an optional change.
    #[test]
    fn a_second_edge_that_changes_scope_is_removed_and_added() {
        let mut old = edge_lock();
        let edges = |scopes: [(Scope, bool); 2]| {
            scopes.map(|(scope, optional)| LockEdge::new(0, 1, scope, optional))
        };
        old.platforms[0].modules[0].edges =
            edges([(Scope::Compile, false), (Scope::Runtime, false)]).to_vec();
        let mut new = old.clone();
        new.platforms[0].modules[0].edges =
            edges([(Scope::Compile, false), (Scope::Test, false)]).to_vec();
        assert_eq!(
            super::format_frozen_diff(&old, &new),
            "  in pom.xml: com.example:lib no longer depends on g:one:jar:tests as runtime; \
             another dependency stays\n  \
             in pom.xml: com.example:lib now also depends on g:one:jar:tests (test)\n"
        );
        new.platforms[0].modules[0].edges =
            edges([(Scope::Compile, false), (Scope::Runtime, true)]).to_vec();
        assert_eq!(
            super::format_frozen_diff(&old, &new),
            "  in pom.xml: com.example:lib's dependency on g:one:jar:tests changed optional \
             false -> true\n"
        );
    }

    #[test]
    fn edge_scope_and_optional_changes_group_compared_platforms() {
        for (change, edge, old_value, new_value, detail) in [
            (
                "scope",
                LockEdge::new(0, 1, Scope::Runtime, false),
                json!("compile"),
                json!("runtime"),
                "scope compile -> runtime",
            ),
            (
                "optional",
                LockEdge::new(0, 1, Scope::Compile, true),
                json!("false"),
                json!("true"),
                "optional false -> true",
            ),
        ] {
            let mut old = edge_lock();
            let mut windows = old.platforms[0].clone();
            windows.platform = Platform::new("windows", "x86_64").unwrap();
            old.platforms.push(windows);
            let mut new = old.clone();
            new.platforms[0].modules[0].edges[0] = edge.clone();
            let partial = report(&old, &new);
            assert!(partial.changed);
            assert!(partial.changes.is_empty());
            assert_eq!(
                partial.to_json().unwrap()["edge_changes"],
                json!([{
                    "platform": "linux-x86_64", "module": "pom.xml", "from": "com.example:lib:jar",
                    "to": "g:one:jar:tests", "change": change, "old": old_value, "new": new_value,
                }])
            );
            let line = format!(
                "  in pom.xml: com.example:lib's dependency on g:one:jar:tests changed {detail}"
            );
            assert_eq!(
                super::format_frozen_diff(&old, &new),
                format!("{line} (on linux-x86_64)\n")
            );
            new.platforms[1].modules[0].edges[0] = edge;
            let mut added = new.platforms[0].clone();
            added.platform = Platform::new("darwin", "aarch64").unwrap();
            new.platforms.push(added);
            let all = report(&old, &new);
            assert_eq!(all.edge_changes.len(), 2);
            assert_eq!(
                all.lines.iter().filter(|(text, _)| text == &line).count(),
                1
            );
        }
    }

    #[test]
    fn edge_additions_and_removals_follow_packages_across_index_changes() {
        let old = edge_lock();
        let mut new = old.clone();
        new.platforms[0].modules[0].packages.swap(1, 2);
        new.platforms[0].modules[0].edges[0].to = 2;
        assert!(!report(&old, &new).changed);
        new.platforms[0].modules[0].edges[0].to = 1;
        let changes = report(&old, &new);
        assert!(changes.changed);
        assert!(changes.changes.is_empty());
        assert_eq!(
            changes.to_json().unwrap()["edge_changes"],
            json!([
                {"platform": "linux-x86_64", "module": "pom.xml", "from": "com.example:lib:jar",
                 "to": "g:one:jar:tests", "change": "removed", "old": "scope compile, optional false", "new": null},
                {"platform": "linux-x86_64", "module": "pom.xml", "from": "com.example:lib:jar",
                 "to": "g:two:jar:tests", "change": "added", "old": null, "new": "scope compile, optional false"},
            ])
        );
        assert_eq!(
            super::format_frozen_diff(&old, &new),
            "  in pom.xml: com.example:lib no longer depends on g:one:jar:tests\n  in pom.xml: com.example:lib now depends on g:two:jar:tests (compile)\n"
        );

        new.platforms[0].modules[0].packages.remove(2);
        let mut old = old;
        old.platforms[0].modules[0].packages.pop();
        for (old, new) in [(&old, &new), (&new, &old)] {
            let changes = report(old, new);
            assert!(changes.changed);
            assert!(changes.edge_changes.is_empty());
            assert_eq!(changes.changes.len(), 2);
        }
    }

    #[test]
    fn companion_pom_snapshot_changes_with_the_same_digest_have_details() {
        use rv_maven_types::SnapshotStamp;

        let mut old = lock_from("https://repo.example/");
        let artifact = &mut old.platforms[0].artifacts[0];
        artifact.coordinate = ArtifactCoord::new("com.example", "lib", "1.0-SNAPSHOT", "jar", None);
        artifact.snapshot = SnapshotStamp::new("20240101.010101", 1);
        artifact.pom_sha256 = Some("a".repeat(64).parse().unwrap());
        old.platforms[0].modules[0].packages[0].coordinate = artifact.coordinate.clone();
        for previous in [None, SnapshotStamp::new("20240202.020202", 2)] {
            old.platforms[0].artifacts[0].pom_snapshot = previous;
            let mut new = old.clone();
            new.platforms[0].artifacts[0].pom_snapshot = SnapshotStamp::new("20240303.030303", 3);
            for (a, b) in [(&old, &new), (&new, &old)] {
                let changes = report(a, b);
                assert!(changes.changed);
                assert!(changes.changes.is_empty());
                let old_stamp = a.platforms[0].artifacts[0]
                    .pom_snapshot
                    .as_ref()
                    .or(a.platforms[0].artifacts[0].snapshot.as_ref())
                    .unwrap()
                    .to_string();
                let new_stamp = b.platforms[0].artifacts[0]
                    .pom_snapshot
                    .as_ref()
                    .or(b.platforms[0].artifacts[0].snapshot.as_ref())
                    .unwrap()
                    .to_string();
                assert_eq!(
                    changes.to_json().unwrap()["pom_changes"],
                    json!([{
                        "platform": "linux-x86_64", "coordinate": "com.example:lib:1.0-SNAPSHOT:jar", "change": "pom",
                        "old": "a".repeat(64), "new": "a".repeat(64), "old_snapshot": old_stamp, "new_snapshot": new_stamp,
                    }])
                );
                assert_eq!(
                    super::format_frozen_diff(a, b),
                    format!(
                        "  POM changed for com.example:lib:1.0-SNAPSHOT:jar: aaaaaaaaaaaa (snapshot {old_stamp}) -> aaaaaaaaaaaa (snapshot {new_stamp})\n"
                    )
                );
            }
        }
    }

    #[test]
    fn crossed_module_platform_changes_keep_their_places_and_via_indexes() {
        let mut old = lock_from("https://repo.example/");
        old.platforms[0].modules[0].path = "api/pom.xml".into();
        let mut app = old.platforms[0].modules[0].clone();
        app.path = "app/pom.xml".into();
        old.platforms[0].modules.push(app);
        let mut windows = old.platforms[0].clone();
        windows.platform = Platform::new("windows", "x86_64").unwrap();
        old.platforms.push(windows);
        let mut new = old.clone();
        new.platforms[0].modules[0].packages[0].direct_scope = Some(Scope::Test);
        new.platforms[0].modules[0].packages[0].scope = Scope::Test;
        new.platforms[1].modules[1].packages[0].direct_scope = Some(Scope::Test);
        new.platforms[1].modules[1].packages[0].scope = Scope::Test;
        let changes = report(&old, &new);
        let api = "  lib  1.0, scope compile -> test (in api, on linux-x86_64)";
        let app = "  lib  1.0, scope compile -> test (in app, on windows-x86_64)";
        assert_eq!(
            changes.lines,
            [(api.into(), vec![0]), (app.into(), vec![1])]
        );
        assert_eq!(
            super::format_frozen_diff(&old, &new),
            format!("{api}\n{app}\n")
        );
        for (line, index) in &changes.lines {
            let row = &changes.changes[index[0]];
            assert!(line.contains(row.module.trim_end_matches("/pom.xml")));
            assert!(line.contains(&row.platform));
        }
        new.platforms[1] = old.platforms[1].clone();
        new.platforms[0].modules[1].packages[0].direct_scope = Some(Scope::Test);
        new.platforms[0].modules[1].packages[0].scope = Scope::Test;
        let uniform = report(&old, &new);
        assert_eq!(
            uniform.lines,
            [(
                "  lib  1.0, scope compile -> test (on linux-x86_64)".into(),
                vec![0, 1]
            )]
        );
    }

    #[test]
    fn structured_fixture_changes_and_grouped_rendering_share_the_diff() {
        let read = |path| Lockfile::read(&rv_test_support::fixtures::path(path)).unwrap();
        let old = read("lock-golden/round-trip/raeva.lock");
        let new = read("lock-diff/round-trip.lock");
        let report = report(&old, &new);
        let json = report.to_json().unwrap();
        assert_eq!(
            json["changes"][0],
            json!({
                "platform": "linux-x86_64", "module": "api/pom.xml", "coordinate": "org.golden:util:jar",
                "kind": "external", "change": "scope", "old_version": "2.0", "new_version": "2.0",
                "old": "compile", "new": "test", "via": [["org.golden:util:2.0:jar"]], "via_truncated": false,
            })
        );
        assert_eq!(report.changes.len(), 4);
        assert_eq!(report.pom_changes.len(), 4);
        assert!(
            report
                .changes
                .iter()
                .any(|row| row.change == "version" && row.new_version.as_deref() == Some("1.2"))
        );
        assert_eq!(
            report
                .changes
                .iter()
                .filter(|row| row.change == "checksum")
                .count(),
            2
        );
        let (stdout, _) = render(false, |human| report.render_human(human));
        assert_eq!(stdout.matches("checksum changed").count(), 1);
        assert!(!stdout.contains("via org.golden:core"), "{stdout}");
        let without_via = stdout
            .lines()
            .filter(|line| !line.starts_with("      via "))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            format!("{without_via}\n"),
            super::format_frozen_diff(&old, &new)
        );
    }

    #[test]
    fn structured_origins_are_redacted_for_packages_and_support_poms() {
        let mut old = lock_from("https://alice:s3cret@old.example/m2/?token=old-token");
        let mut new = lock_from("https://new.example/m2/?token=new-token");
        let pin = |url| SupportPom::new(url, "a".repeat(64).parse().unwrap());
        old.platforms[0].support_poms.insert(
            "g:parent:1".into(),
            pin("https://alice:s3cret@old.example/m2/?token=old-token"),
        );
        new.platforms[0].support_poms.insert(
            "g:parent:1".into(),
            pin("https://new.example/m2/?token=new-token"),
        );
        let json = report(&old, &new).to_json().unwrap();
        assert_eq!(json["changes"][0]["old"], "https://old.example/m2/?***");
        assert_eq!(json["changes"][0]["new"], "https://new.example/m2/?***");
        assert_eq!(json["pom_changes"][0]["change"], "support_pom_origin");
        assert_eq!(json["pom_changes"][0]["old"], "https://old.example/m2/?***");
        for secret in ["alice", "s3cret", "old-token", "new-token", "?token"] {
            assert!(!json.to_string().contains(secret), "{json}");
        }
    }

    #[test]
    fn support_pom_snapshot_changes_and_removals_have_details() {
        let mut old = lock_from("https://repo.example/");
        let mut pin = SupportPom::new("https://repo.example/", "a".repeat(64).parse().unwrap());
        pin.snapshot = rv_maven_types::SnapshotStamp::new("20240101.010101", 1);
        old.platforms[0]
            .support_poms
            .insert("g:parent:1-SNAPSHOT".into(), pin);
        let mut new = old.clone();
        new.platforms[0]
            .support_poms
            .get_mut("g:parent:1-SNAPSHOT")
            .unwrap()
            .snapshot = rv_maven_types::SnapshotStamp::new("20240202.020202", 2);
        let changed = report(&old, &new);
        assert!(changed.changed);
        assert!(changed.changes.is_empty());
        let pin = &changed.pom_changes[0];
        assert_eq!(pin.change, "support_pom");
        assert_eq!(pin.old, pin.new);
        assert_eq!(pin.old_snapshot.as_deref(), Some("20240101.010101-1"));
        assert_eq!(pin.new_snapshot.as_deref(), Some("20240202.020202-2"));
        new.platforms[0].support_poms.clear();
        let removed = report(&old, &new);
        assert!(removed.changed);
        let pin = &removed.pom_changes[0];
        assert_eq!(pin.change, "support_pom_removed");
        assert_eq!(pin.new, None);
        assert_eq!(pin.old_snapshot.as_deref(), Some("20240101.010101-1"));
        assert_eq!(
            pin.line(),
            "  support POM removed for g:parent:1-SNAPSHOT (snapshot 20240101.010101-1)"
        );
        let added = report(&new, &old);
        assert_eq!(
            added.pom_changes[0].line(),
            "  support POM added for g:parent:1-SNAPSHOT (snapshot 20240101.010101-1)"
        );
    }

    fn fan_lock() -> Lockfile {
        let mut lock = lock_from("https://repo.example/");
        let module = &mut lock.platforms[0].modules[0];
        module.packages[0].direct_scope = None;
        for index in 1..=5 {
            module.packages.push(LockModulePackage::new(
                ArtifactCoord::new("g", &format!("root{index}"), "1", "jar", None),
                Some(Scope::Compile),
            ));
            module
                .edges
                .push(LockEdge::new(index, 0, Scope::Compile, false));
        }
        module
            .edges
            .push(LockEdge::new(0, 1, Scope::Compile, false));
        lock
    }

    #[test]
    fn via_is_bounded_shortest_and_uses_the_side_containing_the_package() {
        let old = fan_lock();
        let mut new = old.clone();
        new.platforms[0].modules[0].packages[0].direct_scope = Some(Scope::Test);
        new.platforms[0].modules[0].packages[0].scope = Scope::Test;
        let changed = report(&old, &new);
        assert_eq!(changed.changes.len(), 1);
        assert_eq!(changed.changes[0].via[0], ["com.example:lib:1.0:jar"]);
        assert_eq!(changed.changes[0].via.len(), 3);
        assert!(changed.changes[0].via_truncated);

        new.platforms[0].modules.clear();
        new.platforms[0].artifacts.clear();
        let removed = report(&old, &new);
        let row = removed
            .changes
            .iter()
            .find(|row| row.coordinate == "com.example:lib:jar")
            .unwrap();
        assert_eq!(row.change, "removed");
        assert_eq!(row.new_version, None);
        assert!(row.via_truncated);
        assert_eq!(row.via.len(), 3);
        assert!(row.via.iter().all(|path| path.len() == 2));
        let (stdout, _) = render(false, |human| removed.render_human(human));
        assert_eq!(
            stdout
                .lines()
                .filter(|line| line.starts_with("      via "))
                .count(),
            1,
            "{stdout}"
        );
        // Text names the packages before this one, by artifact id.
        assert!(stdout.contains("      via root"), "{stdout}");
        assert!(!stdout.contains("via root1 -> lib"), "{stdout}");
        let added = report(&new, &old);
        let added = added
            .changes
            .iter()
            .find(|row| row.coordinate == "com.example:lib:jar")
            .unwrap();
        assert_eq!(added.change, "added");
        assert_eq!(added.old_version, None);
        assert_eq!(added.via, row.via);
    }

    /// A line for several modules shows a `via` only when every module
    /// reaches the package the same way.
    #[test]
    fn a_line_for_modules_with_other_paths_shows_no_via() {
        let text = |throughs: [&str; 2]| {
            let mut old = lock_from("https://repo.example/");
            let base = old.platforms[0].modules.remove(0);
            for (path, through) in ["a/pom.xml", "b/pom.xml"].into_iter().zip(throughs) {
                let mut module = base.clone();
                module.path = path.into();
                module.packages[0].direct_scope = None;
                module.packages.push(LockModulePackage::new(
                    ArtifactCoord::new("g", through, "1", "jar", None),
                    Some(Scope::Compile),
                ));
                module.edges = vec![LockEdge::new(1, 0, Scope::Compile, false)];
                old.platforms[0].modules.push(module);
            }
            let mut new = old.clone();
            for module in &mut new.platforms[0].modules {
                module.packages[0].scope = Scope::Test;
            }
            let changed = report(&old, &new);
            assert_eq!(changed.lines.len(), 1, "{:?}", changed.lines);
            render(false, |human| changed.render_human(human)).0
        };
        let other = text(["core", "other"]);
        assert!(!other.contains("via"), "{other}");
        let same = text(["core", "core"]);
        assert!(same.contains("      via core\n"), "{same}");
    }

    #[test]
    fn via_work_is_capped_without_dropping_changes() {
        let mut new = lock_from("https://repo.example/");
        let module = &mut new.platforms[0].modules[0];
        module.packages = (0..=VIA_CHANGE_CAP)
            .map(|index| {
                LockModulePackage::new(
                    ArtifactCoord::new("g", &format!("lib{index:04}"), "1", "jar", None),
                    Some(Scope::Compile),
                )
            })
            .collect();
        let mut old = new.clone();
        old.platforms[0].modules.clear();
        let report = report(&old, &new);
        assert!(report.via_limited);
        assert_eq!(report.changes.len(), VIA_CHANGE_CAP + 1);
        assert!(
            report.changes[..VIA_CHANGE_CAP]
                .iter()
                .all(|row| row.via.len() == 1)
        );
        assert!(report.changes[VIA_CHANGE_CAP].via.is_empty());
        assert!(!report.changes[VIA_CHANGE_CAP].via_truncated);
        let report =
            super::LockDiffReport::between("a".into(), "b".into(), &new, &new, true).unwrap();
        assert!(!report.via_limited);
    }

    #[test]
    fn empty_modules_missing_artifacts_and_invalid_edges_do_not_panic() {
        let old = lock_from("https://repo.example/");
        let mut new = old.clone();
        new.platforms[0].artifacts.clear();
        new.platforms[0].modules[0].packages[0].direct_scope = Some(Scope::Test);
        new.platforms[0].modules[0].packages[0].scope = Scope::Test;
        assert_eq!(report(&old, &new).changes[0].via.len(), 1);
        new.platforms[0].modules[0].edges.push(LockEdge::new(
            0,
            usize::MAX,
            rv_lock::Scope::Compile,
            false,
        ));
        assert!(LockDiffReport::between("a".into(), "b".into(), &old, &new, true).is_err());
        new.platforms[0].modules.clear();
        assert!(report(&old, &new).changed);
        new.platforms.clear();
        let removed = report(&old, &new);
        assert_eq!(removed.platforms_removed, ["linux-x86_64"]);
        assert!(removed.changes.is_empty());
        assert_eq!(report(&new, &old).platforms_added, ["linux-x86_64"]);
    }

    fn lock_from(repo_url: &str) -> Lockfile {
        let package = LockArtifact::new(
            ArtifactCoord::new("com.example", "lib", "1.0", "jar", None),
            repo_url.to_string(),
        );
        let mut lock = Lockfile::new();
        lock.platforms.push(LockPlatform::single_module(
            Platform::new("linux", "x86_64").expect("platform"),
            Gav::new("com.example", "root", "1"),
            "pom",
            vec![package],
        ));
        lock
    }

    fn with_plugins(plugins: &[(&str, &str, &[u8])]) -> Lockfile {
        use rv_maven_types::{Digest, Sha256};
        let mut lock = lock_from("https://repo.example/");
        let mut files = rv_lock::PluginFiles::new(Sha256::from_bytes(b"inputs"));
        for (index, (role, gav, bytes)) in plugins.iter().enumerate() {
            let mut parts = gav.split(':');
            let (group, artifact, version) = (
                parts.next().unwrap(),
                parts.next().unwrap(),
                parts.next().unwrap(),
            );
            let key = format!("sha256:{}", format!("{index:x}").repeat(64));
            let mut set = rv_lock::PluginSet::new(&key, role.parse().unwrap());
            set.coordinates = vec![gav.to_string()];
            let coordinate = ArtifactCoord::new(group, artifact, version, "jar", None);
            set.artifacts = vec![coordinate.clone()];
            set.modules = vec!["pom.xml".to_string()];
            files.tables.sets.push(set);
            let mut row = LockArtifact::new(coordinate, "https://repo.example/".to_string());
            row.checksums = vec![Digest::Sha256(Sha256::from_bytes(bytes))];
            files.artifacts.push(row);
        }
        lock.platforms[0]
            .set_plugins(files, &rv_lock::RepoIds::new())
            .unwrap();
        lock
    }

    /// A plugin's sets show as plugin changes, its version paired, and
    /// their rows as no dependency or POM change.
    #[test]
    fn plugin_sets_are_compared_as_sets() {
        let old = with_plugins(&[
            ("plugin", "p:surefire:1", b"a"),
            ("plugin", "p:jar:1", b"a"),
            ("core-extension", "e:old:1", b"a"),
        ]);
        let new = with_plugins(&[
            ("plugin", "p:surefire:2", b"a"),
            ("plugin", "p:jar:1", b"b"),
            ("build-extension", "e:new:1", b"a"),
        ]);
        let report = report(&old, &new);
        let json = report.to_json().unwrap();
        assert_eq!(json["changes"], json!([]));
        assert_eq!(json["pom_changes"], json!([]));
        let lines: Vec<&str> = (report.lines.iter())
            .map(|(line, _)| line.as_str())
            .collect();
        assert_eq!(
            lines,
            [
                "  build extension e:new:1 added",
                "  core extension e:old:1 removed",
                "  plugin p:jar:1: its files changed",
                "  plugin p:surefire: 1 -> 2",
            ]
        );
        assert_eq!(json["plugin_changes"][3]["change"], "version");
        assert_eq!(json["plugin_changes"][3]["new"], "2");
        assert!(!self::report(&old, &old).changed);
        let bare = lock_from("https://repo.example/");
        let added = self::report(&bare, &old);
        assert_eq!(added.plugin_changes.len(), 3);
        assert_eq!(added.to_json().unwrap()["changes"], json!([]));
    }

    #[test]
    fn checksum_markers_added_and_cleared_are_listed() {
        let lock = |marked: bool, pom: bool| {
            let mut lock = lock_from("https://repo.example/");
            let artifact = &mut lock.platforms[0].artifacts[0];
            artifact.checksums = vec![rv_maven_types::Digest::Sha256(
                "a".repeat(64).parse().unwrap(),
            )];
            artifact.pom_sha256 = Some("b".repeat(64).parse().unwrap());
            artifact.missing_checksum = marked;
            artifact.pom_missing_checksum = pom;
            lock
        };
        let report = report(&lock(false, true), &lock(true, false));
        let json = report.to_json().unwrap();
        assert_eq!(json["changed"], true);
        assert_eq!(
            json["checksum_markers"],
            json!([
                {"path": "com/example/lib/1.0/lib-1.0.jar", "change": "marked"},
                {"path": "com/example/lib/1.0/lib-1.0.pom", "change": "cleared"},
            ])
        );
        let (stdout, _) = render(false, |human| report.render_human(human));
        assert_eq!(
            stdout,
            "  accepted without a checksum file: com/example/lib/1.0/lib-1.0.jar\n  \
             now verified by a checksum file: com/example/lib/1.0/lib-1.0.pom\n"
        );
        let removed = lock_from("https://repo.example/");
        let json = super::LockDiffReport::between(
            "old".into(),
            "new".into(),
            &lock(true, true),
            &removed,
            true,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(json["checksum_markers"], json!([]));
    }

    /// A POM edit that leaves the dependencies alone, such as a comment,
    /// changes only recorded hashes; the diff names the POM instead of
    /// saying nothing changed.
    #[test]
    fn changed_input_hashes_are_named() {
        use rv_lock::ModelInputs;
        let with_hash = |digit: &str, config: &str| {
            let mut lock = lock_from("https://repo.example/");
            let mut inputs = ModelInputs::default();
            inputs
                .pom_hashes
                .insert("app/pom.xml".into(), digit.repeat(64).parse().unwrap());
            lock.platforms[0].model_inputs = Some(inputs);
            lock.config_hash = Some(config.to_string());
            lock
        };
        let report = report(&with_hash("a", "c1"), &with_hash("b", "c2"));
        let json = report.to_json().unwrap();
        assert_eq!(json["changed"], false);
        assert_eq!(
            json["changed_inputs"],
            json!(["config_hash", "app/pom.xml"])
        );
        let (stdout, stderr) = render(false, |human| report.render_human(human));
        assert_eq!(
            stdout,
            "  no dependency changes; changed inputs: the configuration (config_hash) and \
             app/pom.xml\n"
        );
        assert_eq!(stderr, "Lockfile diff\n");
        let sync = super::lock_diff(
            &with_hash("a", "c"),
            &with_hash("b", "c"),
            &[Platform::new("linux", "x86_64").unwrap()],
            true,
        );
        assert_eq!(sync, ["  changed inputs: app/pom.xml"]);
    }

    /// A host input a resolution no longer reads, as the 0.5.0 Linux
    /// classifier likes, rewrites the lock with no dependency change; the
    /// diff and the sync summary name it instead of saying nothing changed.
    #[test]
    fn host_inputs_read_or_no_longer_read_are_named() {
        use rv_lock::AmbientInput;
        let likes = "user-property:os.detection.classifierWithLikes";
        let old = {
            let mut lock = lock_from("https://repo.example/");
            lock.resolution.ambient_inputs = [
                AmbientInput::UserProperty("os.detection.classifierWithLikes".into()),
                AmbientInput::JavaVersion,
            ]
            .into();
            lock
        };
        let mut new = lock_from("https://repo.example/");
        new.resolution.ambient_inputs = [AmbientInput::JavaVersion].into();
        let report = report(&old, &new);
        let json = report.to_json().unwrap();
        assert_eq!(json["changed"], false);
        assert_eq!(json["changed_inputs"], json!([likes]));
        let (stdout, _) = render(false, |human| report.render_human(human));
        assert_eq!(
            stdout,
            format!("  no dependency changes; changed inputs: the host input {likes}\n")
        );
        let sync = super::lock_diff(
            &old,
            &new,
            &[Platform::new("linux", "x86_64").unwrap()],
            true,
        );
        assert_eq!(sync, [format!("  changed inputs: the host input {likes}")]);
    }

    /// A `[lock] jdks` section is its own platform: a change in one JDK's
    /// section names that section, and a JDK added to the list is a platform
    /// added.
    #[test]
    fn jdk_sections_are_compared_apart() {
        let with_jdks = |urls: &[(&str, &str)]| {
            let mut lock = Lockfile::new();
            for (jdk, url) in urls {
                let mut section = lock_from(url).platforms.remove(0);
                section.platform = section.platform.with_jdk(*jdk);
                lock.platforms.push(section);
            }
            lock
        };
        let old = with_jdks(&[
            ("17", "https://repo.example/"),
            ("21", "https://repo.example/"),
        ]);
        let new = with_jdks(&[
            ("17", "https://repo.example/"),
            ("21", "https://other.example/"),
        ]);
        assert_eq!(
            super::format_frozen_diff(&old, &new),
            "  lib  1.0, origin https://repo.example/ -> https://other.example/ \
             (on linux-x86_64 (JDK 21))\n"
        );
        let json = report(&old, &new).to_json().unwrap();
        assert_eq!(json["changes"][0]["platform"], "linux-x86_64 (JDK 21)");

        let added = with_jdks(&[
            ("17", "https://repo.example/"),
            ("21", "https://repo.example/"),
            ("25", "https://repo.example/"),
        ]);
        let report = report(&old, &added);
        assert_eq!(
            report.to_json().unwrap()["platforms_added"],
            json!(["linux-x86_64 (JDK 25)"])
        );
        assert!(report.changes.is_empty());
    }

    #[test]
    fn origin_change_redacts_both_urls() {
        let old = lock_from("https://alice:s3cret@old.example/m2/");
        let new = lock_from("https://new.example/m2/?token=t0k");
        let diff = super::format_frozen_diff(&old, &new);
        assert!(
            diff.contains("https://old.example/m2/ -> https://new.example/m2/"),
            "{diff}"
        );
        for secret in ["alice", "s3cret", "t0k"] {
            assert!(!diff.contains(secret), "{diff}");
        }
    }

    #[test]
    fn origin_lists_are_reported_and_redacted() {
        for pom in [false, true] {
            let mut old = lock_from("https://repo.example/");
            let origins = |lock: &mut Lockfile, url: &str| {
                let row = &mut lock.platforms[0].artifacts[0];
                if pom {
                    row.pom_repo_urls = vec![url.into()];
                } else {
                    row.other_repo_urls = vec![url.into()];
                }
            };
            origins(
                &mut old,
                "https://alice:s3cret@old.example/m2/?token=old-token",
            );
            let mut new = old.clone();
            origins(&mut new, "https://new.example/m2/?token=new-token");
            let changed = report(&old, &new);
            assert!(changed.changed, "pom origins: {pom}");
            let json = changed.to_json().unwrap();
            assert_eq!(json["changes"][0]["change"], "origin");
            for text in [json.to_string(), super::format_frozen_diff(&old, &new)] {
                assert!(text.contains("https://old.example/m2/?***"), "{text}");
                assert!(text.contains("https://new.example/m2/?***"), "{text}");
                if pom {
                    assert!(text.contains("pom"), "{text}");
                }
                for secret in ["alice", "s3cret", "old-token", "new-token", "?token"] {
                    assert!(!text.contains(secret), "{text}");
                }
            }
        }
    }

    /// Every kind of change between two locks, from the edited copies of
    /// golden locks in `test-fixtures/lock-diff`.
    #[test]
    fn frozen_diffs_name_every_kind_of_change() {
        use rv_test_support::fixtures::path;
        let read = |file: &str| Lockfile::read(&path(file)).expect(file);
        let mut out = String::new();
        for (old, new) in [
            (
                "lock-golden/round-trip/raeva.lock",
                "lock-diff/round-trip.lock",
            ),
            ("lock-golden/snapshot/raeva.lock", "lock-diff/snapshot.lock"),
            ("lock-diff/bom-before.lock", "lock-diff/bom-after.lock"),
            (
                "lock-golden/single-module/raeva.lock",
                "lock-golden/round-trip/raeva.lock",
            ),
        ] {
            let diff = super::format_frozen_diff(&read(old), &read(new));
            out.push_str(&format!("{old} -> {new}\n{diff}\n"));
        }
        rv_test_support::golden::assert_golden(&path("lock-diff/frozen.txt"), &out);
    }

    #[test]
    fn lock_diff_lists_support_pom_origin_changes_on_resolved_platforms_only() {
        use rv_lock::SupportPom;

        let sha: rv_maven_types::Sha256 = "a".repeat(64).parse().unwrap();
        let platform = |os: &str, arch: &str, url: &str| {
            let mut entry = LockPlatform::single_module(
                Platform::new(os, arch).expect("platform"),
                Gav::new("com.example", "root", "1"),
                "pom",
                vec![LockArtifact::new(
                    ArtifactCoord::new("com.example", "lib", "1.0", "jar", None),
                    "https://repo.example/",
                )],
            );
            entry.support_poms.insert(
                "com.example:parent:1".into(),
                SupportPom::new(url, sha.clone()),
            );
            entry
        };
        let mut old = Lockfile::new();
        old.platforms.push(platform(
            "linux",
            "x86_64",
            "https://alice:s3cret@old.example/m2/",
        ));
        old.platforms
            .push(platform("darwin", "aarch64", "https://old.example/"));
        let mut new = Lockfile::new();
        new.platforms.push(platform(
            "linux",
            "x86_64",
            "https://new.example/m2/?token=t0k",
        ));
        new.platforms
            .push(platform("darwin", "aarch64", "https://other.example/"));

        let frozen = super::format_frozen_diff(&old, &new);
        assert!(
            frozen.contains(
                "support POM origin changed for com.example:parent:1: https://old.example/m2/ -> https://new.example/m2/"
            ),
            "{frozen}"
        );
        for secret in ["alice", "s3cret", "t0k"] {
            assert!(!frozen.contains(secret), "{frozen}");
        }

        let lines = super::lock_diff(
            &old,
            &new,
            &[Platform::new("linux", "x86_64").unwrap()],
            true,
        );
        let joined = lines.join("\n");
        // One resolved platform, so the line names none.
        assert!(!joined.contains("(on "), "{joined}");
        assert!(
            joined.contains("https://old.example/m2/ -> https://new.example/m2/"),
            "{joined}"
        );
        assert!(!joined.contains("darwin"), "{joined}");
        assert!(!joined.contains("other.example"), "{joined}");
    }

    #[test]
    fn lock_diff_lists_removed_support_poms_on_resolved_platforms_only() {
        use rv_lock::SupportPom;

        let sha: rv_maven_types::Sha256 = "a".repeat(64).parse().unwrap();
        let platform = |os: &str, arch: &str, parent: bool| {
            let mut entry = LockPlatform::single_module(
                Platform::new(os, arch).expect("platform"),
                Gav::new("com.example", "root", "1"),
                "pom",
                vec![LockArtifact::new(
                    ArtifactCoord::new("com.example", "lib", "1.0", "jar", None),
                    "https://repo.example/",
                )],
            );
            if parent {
                entry.support_poms.insert(
                    "com.example:parent:1".into(),
                    SupportPom::new("https://old.example/", sha.clone()),
                );
            }
            entry
        };
        let mut old = Lockfile::new();
        old.platforms.push(platform("linux", "x86_64", true));
        old.platforms.push(platform("darwin", "aarch64", true));
        let mut new = Lockfile::new();
        new.platforms.push(platform("linux", "x86_64", false));
        new.platforms.push(platform("darwin", "aarch64", false));

        let frozen = super::format_frozen_diff(&old, &new);
        // The same change on every platform is one line naming none.
        assert_eq!(
            frozen, "  support POM removed for com.example:parent:1\n",
            "{frozen}"
        );

        let lines = super::lock_diff(
            &old,
            &new,
            &[Platform::new("linux", "x86_64").unwrap()],
            true,
        );
        let joined = lines.join("\n");
        assert_eq!(joined, "  support POM removed for com.example:parent:1");
    }

    #[test]
    fn module_coordinates_and_profiles_are_changes_of_their_own() {
        use rv_lock::{LockModule, ModelInputs};

        let platform = |os: &str, arch: &str, version: &str, profiles: &[&str]| {
            let mut entry = LockPlatform::single_module(
                Platform::new(os, arch).expect("platform"),
                Gav::new("com.example", "root", version),
                "jar",
                vec![LockArtifact::new(
                    ArtifactCoord::new("com.example", "lib", "1.0", "jar", None),
                    "https://repo.example/",
                )],
            );
            let mut inputs = ModelInputs::default();
            inputs.profiles = profiles.iter().map(|id| (*id).to_string()).collect();
            entry.model_inputs = Some(inputs);
            entry
        };
        let mut old = Lockfile::new();
        old.platforms
            .push(platform("linux", "x86_64", "1.0.0", &["jdk21"]));
        old.platforms
            .push(platform("darwin", "aarch64", "1.0.0", &["jdk21"]));
        let mut new = Lockfile::new();
        new.platforms
            .push(platform("linux", "x86_64", "1.0.1", &[]));
        new.platforms
            .push(platform("darwin", "aarch64", "1.0.1", &["jdk21"]));
        new.platforms[0].modules.push(LockModule::new(
            "app/pom.xml",
            Gav::new("com.example", "app", "1.0.1"),
            "war",
        ));
        new.platforms[1].modules[0].packaging = "pom".into();

        let report = report(&old, &new);
        assert!(report.changed);
        assert!(report.changes.is_empty());
        let lines: Vec<_> = report.lines.iter().map(|(line, _)| line.as_str()).collect();
        assert_eq!(
            lines,
            [
                "  active profiles: jdk21 -> none (on linux-x86_64)",
                "  module app/pom.xml added: com.example:app:1.0.1 (on linux-x86_64)",
                "  module pom.xml: com.example:root:1.0.0 -> com.example:root:1.0.1 (on linux-x86_64)",
                "  module pom.xml: com.example:root:1.0.0 -> com.example:root:1.0.1 (jar -> pom) (on darwin-aarch64)",
            ]
        );
        let json = report.to_json().unwrap();
        let darwin = json["module_changes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|change| change["platform"] == "darwin-aarch64")
            .unwrap();
        assert_eq!(
            darwin,
            &json!({
                "platform": "darwin-aarch64", "module": "pom.xml", "change": "coordinate",
                "old": "com.example:root:1.0.0", "new": "com.example:root:1.0.1",
                "old_packaging": "jar", "new_packaging": "pom",
            })
        );
        assert_eq!(
            json["profile_changes"],
            json!([{"platform": "linux-x86_64", "old": ["jdk21"], "new": []}])
        );
        assert!(super::format_frozen_diff(&old, &new).contains("module pom.xml: "));
    }

    #[test]
    fn pin_lines_group_platforms_and_skip_an_added_platform() {
        use rv_lock::SupportPom;

        let pin = |digit: &str| {
            SupportPom::new("https://repo.example/", digit.repeat(64).parse().unwrap())
        };
        let platform = |os: &str, arch: &str, digit: &str| {
            let mut entry = LockPlatform::single_module(
                Platform::new(os, arch).expect("platform"),
                Gav::new("com.example", "root", "1"),
                "pom",
                vec![LockArtifact::new(
                    ArtifactCoord::new("com.example", "lib", "1.0", "jar", None),
                    "https://repo.example/",
                )],
            );
            entry
                .support_poms
                .insert("com.example:parent:1".into(), pin(digit));
            entry
        };
        let mut old = Lockfile::new();
        old.platforms.push(platform("linux", "x86_64", "a"));
        old.platforms.push(platform("darwin", "aarch64", "a"));
        let mut new = Lockfile::new();
        new.platforms.push(platform("linux", "x86_64", "b"));
        new.platforms.push(platform("darwin", "aarch64", "c"));
        new.platforms.push(platform("windows", "x86_64", "b"));
        new.platforms[0]
            .support_poms
            .insert("com.example:bom:1".into(), pin("d"));

        let report = report(&old, &new);
        assert!(
            report
                .pom_changes
                .iter()
                .all(|change| change.platform != "windows-x86_64")
        );
        let lines: Vec<_> = report.lines.iter().map(|(line, _)| line.as_str()).collect();
        assert_eq!(
            lines,
            [
                "  platform windows-x86_64 added (1 dependency)",
                "  support POM added for com.example:bom:1 (on linux-x86_64)",
                "  support POM changed for com.example:parent:1: aaaaaaaaaaaa -> bbbbbbbbbbbb (on linux-x86_64)",
                "  support POM changed for com.example:parent:1: aaaaaaaaaaaa -> cccccccccccc (on darwin-aarch64)",
            ]
        );
        // Without -v, the support POMs that come and go with dependency
        // changes are a count; a changed pin stays a line.
        let brief: Vec<String> = (super::LockChanges::between(&old, &new, None).lines(false))
            .into_iter()
            .map(|(line, _)| line)
            .collect();
        assert_eq!(
            brief,
            [
                "  platform windows-x86_64 added (1 dependency)",
                "  support POM changed for com.example:parent:1: aaaaaaaaaaaa -> bbbbbbbbbbbb (on linux-x86_64)",
                "  support POM changed for com.example:parent:1: aaaaaaaaaaaa -> cccccccccccc (on darwin-aarch64)",
                "  support POMs (parents and BOMs): 1 added; -v lists them",
            ]
        );
    }

    #[test]
    fn many_changed_pom_records_are_a_count() {
        let inputs: Vec<String> = [
            "config_hash",
            "a/pom.xml",
            "b/pom.xml",
            "c/pom.xml",
            "pom.xml",
        ]
        .map(str::to_string)
        .into();
        assert_eq!(
            super::inputs_line(&inputs, &[]).unwrap(),
            "  changed inputs: the configuration (config_hash) and the records of 4 reactor POMs"
        );
        assert_eq!(
            super::inputs_line(&inputs[1..3], &[]).unwrap(),
            "  changed inputs: a/pom.xml and b/pom.xml"
        );
        // Host inputs end changed_inputs, and more than three are a count.
        let host: Vec<String> = ["env.A", "env.B", "java.version", "os-release"]
            .map(str::to_string)
            .into();
        let with = |host: &[String]| {
            let all: Vec<String> = inputs[1..2].iter().chain(host).cloned().collect();
            super::inputs_line(&all, host).unwrap()
        };
        assert_eq!(
            with(&host[..2]),
            "  changed inputs: a/pom.xml and the host inputs env.A and env.B"
        );
        assert_eq!(with(&host), "  changed inputs: a/pom.xml and 4 host inputs");
    }
}
