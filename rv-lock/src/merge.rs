//! Merging a fresh resolution with the previous lockfile before it is
//! written: which preserved platforms survive and which lockfile-wide data
//! is carried forward.
//!
//! A platform that a run did not resolve again can be carried into the new
//! lockfile only when nothing it pins contradicts the fresh resolution and
//! its reactor model and system-scoped files are unchanged. The pin rules
//! are decided here from the two lockfiles alone; the rest needs the
//! project on disk, so the caller decides it for each candidate
//! [`preservation`] leaves open and passes the survivors to
//! [`carry_forward`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use rv_maven_types::{Gav, Sha256, resolves_through_snapshot_metadata};

use crate::error::LockError;
use crate::lock::{LockPlatform, Lockfile, SupportPom, TargetReads, split_support_pom_coord};
use crate::platform::Platform;

/// Companion-POM pins keyed by the GAV whose single `.pom` they name;
/// `None` for a row that pins none, which names the same path.
pub(crate) type PomPins = HashMap<Gav, Option<Sha256>>;

/// The companion POM build each artifact GAV's rows name.
type PomBuilds = HashMap<Gav, Gav>;

/// Why a platform of the previous lockfile is left out of the new one.
/// `Display` is the reason as raeva reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropReason {
    /// The configuration hash differs from the one the platform was
    /// resolved under.
    Reconfigured,
    /// The platform pins another POM for a GAV than this run resolved.
    ConflictingPom {
        /// The `group:artifact:version` the two POM pins disagree on.
        coord: String,
    },
    /// The platform pins other bytes or another snapshot build for a
    /// coordinate than this run resolved.
    ConflictingArtifact {
        /// The coordinate the two pins disagree on, as text.
        coord: String,
    },
    /// The platform's reactor model changed.
    ModelChanged,
    /// A system-scoped file the platform pins changed or cannot be read.
    SystemFileChanged {
        /// The file's path relative to the directory that holds raeva.lock.
        path: String,
    },
    /// The platform's reactor model could not be discovered again.
    ModelUnavailable {
        /// Why discovery failed, as the caller reports it.
        error: String,
    },
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reconfigured => {
                f.write_str("resolution configuration changed since it was locked")
            }
            Self::ConflictingPom { coord } => write!(
                f,
                "it pins a different POM for {coord} than this run resolved, and Maven has one \
                 local-repository path per coordinate"
            ),
            Self::ConflictingArtifact { coord } => write!(
                f,
                "it pins different bytes or another snapshot build of {coord} than this run \
                 resolved, and Maven has one local-repository path per coordinate"
            ),
            Self::ModelChanged => f.write_str("reactor model changed"),
            Self::SystemFileChanged { path } => {
                write!(f, "the system-scoped file {path} changed or cannot be read")
            }
            Self::ModelUnavailable { error } => {
                write!(f, "reactor model could not be rediscovered ({error})")
            }
        }
    }
}

/// A platform of the previous lockfile that is left out, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedPlatform {
    /// The platform left out.
    pub platform: Platform,
    /// Why it is left out.
    pub reason: DropReason,
}

/// The verdict [`preservation`] reaches on one platform of the previous
/// lockfile that this run did not resolve again.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Candidate {
    /// A platform of the previous lockfile.
    pub platform: Platform,
    /// `None` when its pins agree with the fresh resolution: it survives if
    /// its reactor model is unchanged. `Some` when it is dropped regardless.
    pub dropped: Option<DropReason>,
}

/// Decide, for every platform of `previous` that `fresh` does not hold, in
/// the order `previous` lists them, whether its pins allow carrying it into
/// `fresh`.
///
/// `config_hash` is the one the new lock claims for every platform.
pub fn preservation(fresh: &Lockfile, previous: &Lockfile, config_hash: &str) -> Vec<Candidate> {
    let resolved_platforms: HashSet<&Platform> =
        fresh.platforms.iter().map(|p| &p.platform).collect();
    // Carrying a platform forward republishes its graph under this run's
    // resolution inputs. An equal `model_hash` only says the local reactor
    // model is unchanged; if the configuration changed, that graph was
    // never resolved against the inputs the new top-level `config_hash`
    // claims, so it has to be dropped and re-synced.
    let resolution_inputs_unchanged = previous
        .config_hash
        .as_deref()
        .is_some_and(|stored| stored == config_hash);
    let fresh_pom_pins = companion_pom_pins(fresh);
    let fresh_support = fresh.support_poms();
    let fresh_pom_builds: PomBuilds = fresh
        .platforms
        .iter()
        .flat_map(|platform| &platform.artifacts)
        .map(|artifact| (artifact.coordinate.gav.clone(), artifact.pom_gav()))
        .collect();

    let mut candidates = Vec::new();
    for prev_platform in &previous.platforms {
        if resolved_platforms.contains(&prev_platform.platform) {
            continue;
        }
        // A preserved platform keeps the parents and BOMs it read. One that
        // this run resolved to another file, or that a freshly resolved row
        // pins otherwise, would put two pins on one local-repository path.
        let dropped = if !resolution_inputs_unchanged {
            Some(DropReason::Reconfigured)
        } else if let Some(coord) =
            conflicting_support_pom(&prev_platform.support_poms, &fresh_support)
                .or_else(|| {
                    conflicting_support_companion_pin(&prev_platform.support_poms, &fresh_pom_pins)
                })
                .or_else(|| conflicting_snapshot_pom(&prev_platform.support_poms, &fresh.platforms))
                .or_else(|| conflicting_snapshot_pom(&fresh_support, [prev_platform]))
        {
            Some(DropReason::ConflictingPom { coord })
        } else if let Some(coord) =
            conflicting_companion_pom_pin(&fresh_pom_pins, &fresh_pom_builds, prev_platform)
        {
            // Maven has one local-repository path per GAV, so a preserved
            // platform pinning a different POM than a freshly resolved one
            // describes a `~/.m2` that cannot exist. Export would silently
            // pick one of them; drop the stale platform instead.
            Some(DropReason::ConflictingPom { coord })
        } else if let Some(coordinate) = fresh
            .platforms
            .iter()
            .find_map(|fresh| prev_platform.conflicting_artifact_pin(fresh))
        {
            // The same rule for the artifact files themselves. A snapshot
            // that moved since the preserved platform was locked is the
            // usual case: this run pins the new build, and the old one names
            // another file under the same coordinate.
            Some(DropReason::ConflictingArtifact {
                coord: coordinate.to_string(),
            })
        } else {
            // The same one-path-per-GAV rule across the two maps: a
            // preserved platform's artifact row and this run's support-POM
            // closure can name the same `.pom` from independent
            // observations.
            conflicting_support_companion_pin(
                &fresh_support,
                &platform_companion_pom_pins(prev_platform),
            )
            .map(|coord| DropReason::ConflictingPom { coord })
        };
        candidates.push(Candidate {
            platform: prev_platform.platform.clone(),
            dropped,
        });
    }
    candidates
}

/// Carry the platforms named in `kept` from `previous` into `fresh`, each
/// with its own support POMs and the repository ids it used.
pub fn carry_forward(
    fresh: &mut Lockfile,
    previous: &Lockfile,
    kept: &[Platform],
) -> Result<(), LockError> {
    let mut reads: HashMap<Platform, TargetReads> = (fresh.platforms.iter())
        .map(|entry| entry.platform.clone())
        .zip(fresh.target_reads())
        .collect();
    for (platform, read) in previous.platforms.iter().zip(previous.target_reads()) {
        if kept.contains(&platform.platform) {
            fresh.platforms.push(platform.clone());
            reads.insert(platform.platform.clone(), read);
        }
    }
    fresh
        .platforms
        .sort_by_key(|entry| entry.platform.to_string());
    let reads: Vec<_> = (fresh.platforms.iter())
        .map(|entry| reads.remove(&entry.platform).unwrap_or_default())
        .collect();
    fresh.set_target_reads(&reads)
}

impl Lockfile {
    /// The first coordinate this lockfile pins two POMs for: one in its
    /// support-POM block and another in an artifact row's `pom_sha256`.
    ///
    /// The support-POM block and the artifact rows record the same file
    /// (Maven keeps one `.pom` per GAV) from two independent observations, so
    /// the two agreeing is what makes the lockfile describe a `~/.m2` that
    /// can exist. Writing refuses a lockfile where they do not.
    pub fn support_companion_conflict(&self) -> Option<String> {
        conflicting_support_companion_pin(&self.support_poms(), &companion_pom_pins(self))
    }
}

/// The first support POM `kept` and `fresh` both record and pin to another
/// file or other bytes, by coordinate or by the file it names. A
/// coordinate only one side reached says nothing.
fn conflicting_support_pom(
    kept: &BTreeMap<String, SupportPom>,
    fresh: &BTreeMap<String, SupportPom>,
) -> Option<String> {
    let fresh_files: HashMap<Gav, &Sha256> = fresh
        .iter()
        .filter_map(|(coord, pin)| Some((pin.file_gav(coord)?, &pin.sha256)))
        .collect();
    kept.iter()
        .find(|(coord, pin)| {
            fresh.get(*coord).is_some_and(|fresh_pin| {
                fresh_pin.sha256 != pin.sha256 || fresh_pin.snapshot != pin.snapshot
            }) || pin
                .file_gav(coord)
                .and_then(|file| fresh_files.get(&file))
                .is_some_and(|digest| **digest != pin.sha256)
        })
        .map(|(coord, _)| coord.clone())
}

pub(crate) fn companion_pom_pins(lock: &Lockfile) -> PomPins {
    lock.platforms
        .iter()
        .flat_map(platform_companion_pom_pins)
        .collect()
}

pub(crate) fn platform_companion_pom_pins(platform: &LockPlatform) -> PomPins {
    platform
        .artifacts
        .iter()
        .map(|artifact| (artifact.pom_gav(), artifact.pom_sha256.clone()))
        .collect()
}

pub(crate) fn conflicting_support_companion_pin(
    support_poms: &BTreeMap<String, SupportPom>,
    companions: &PomPins,
) -> Option<String> {
    support_poms.iter().find_map(|(coord, pin)| {
        let companion = companions.get(&pin.file_gav(coord)?)?;
        (companion.as_ref() != Some(&pin.sha256)).then(|| coord.clone())
    })
}

/// The first `-SNAPSHOT` support POM whose bytes differ from the POM an
/// artifact row of `platforms` pins for the same coordinate, whatever
/// builds they name. Export leaves both at the plain `-SNAPSHOT.pom` path.
pub(crate) fn conflicting_snapshot_pom<'a>(
    support_poms: &BTreeMap<String, SupportPom>,
    platforms: impl IntoIterator<Item = &'a LockPlatform>,
) -> Option<String> {
    let builds: HashMap<Gav, (&String, &SupportPom)> = support_poms
        .iter()
        .filter_map(|(coord, pin)| {
            let (group, artifact, version) = split_support_pom_coord(coord)?;
            resolves_through_snapshot_metadata(version)
                .then(|| (Gav::new(group, artifact, version), (coord, pin)))
        })
        .collect();
    platforms
        .into_iter()
        .flat_map(|platform| &platform.artifacts)
        .find_map(|artifact| {
            let row = &artifact.coordinate;
            let gav = Gav::new(row.group_id(), row.artifact_id(), row.version());
            let (coord, pin) = builds.get(&gav)?;
            // A row without a POM would get the support POM's from export,
            // or name a missing POM build in the build list the support POM
            // is read through: export picks that list by repository id,
            // which mirrors and configuration decide after the lock.
            (artifact.pom_sha256.as_ref() != Some(&pin.sha256)).then(|| (*coord).clone())
        })
}

pub(crate) fn conflicting_companion_pom_pin(
    fresh: &PomPins,
    fresh_builds: &PomBuilds,
    candidate: &LockPlatform,
) -> Option<String> {
    candidate.artifacts.iter().find_map(|artifact| {
        let digest = artifact.pom_sha256.as_ref();
        let gav = artifact.pom_gav();
        if fresh_builds
            .get(&artifact.coordinate.gav)
            .is_some_and(|build| *build != gav)
        {
            return Some(artifact.coordinate.gav.to_string());
        }
        (fresh.get(&gav)?.as_ref() != digest).then(|| gav.to_string())
    })
}

#[cfg(test)]
mod tests;
