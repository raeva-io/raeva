//! The versions raeva.lock records for each `groupId:artifactId`, which a
//! frozen check of an unchanged project can replay its version listings
//! against: a version published after the lock was written does not move a
//! range, `LATEST` or `RELEASE` the lock already chose.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use indexmap::IndexSet;
use rv_lock::{
    LockPlatform, MetadataVersion, MetadataVersionKind, PluginRole, split_support_pom_coord,
};
use rv_maven_types::{MavenMode, Version, VersionReq, snapshot_base_version};

/// The versions one platform records for each `(groupId, artifactId)`:
/// for its dependencies, artifact rows, module graph nodes, support POMs,
/// parent range selections and the versions ranges listed; for its plugin
/// tables, the rows and POMs of their sets and the versions their ranges
/// took.
#[derive(Debug, Default)]
pub(crate) struct VersionCaps {
    /// Each spelling once: two that one mode takes as equal may differ in
    /// the other.
    versions: HashMap<(String, String), Vec<Version>>,
    /// The `RELEASE` and `LATEST` versions each `(groupId, artifactId)`
    /// recorded, which a moved marker is capped at instead, and the
    /// spellings ranges took among listed versions that compare equal.
    markers: HashMap<(String, String, MetadataVersionKind), Vec<Version>>,
    /// The spellings parent ranges took, as dependency ranges' are in
    /// `markers`.
    parents: HashMap<(String, String), Vec<Version>>,
    /// The versions a plugin or build extension without a version is held
    /// at, by module POM path, whether a build extension, and
    /// `groupId:artifactId`.
    pub(crate) held: BTreeMap<(String, bool, String), Vec<String>>,
    /// The `(groupId, artifactId, version)` of each artifact row, a
    /// SNAPSHOT build under its base version.
    rows: HashSet<(String, String, String)>,
    /// Whether a cap left out a listed version or replaced a marked one.
    applied: AtomicBool,
    /// The caps of the build extensions' realms, which only the jars the
    /// modules' extensions lines pin give, and which cap no other range.
    realms: Option<Arc<VersionCaps>>,
}

impl VersionCaps {
    /// The caps of `platform`'s dependency resolution.
    pub(crate) fn of(platform: &LockPlatform) -> Self {
        let mut caps = Self::default();
        let coordinates = (platform
            .artifacts
            .iter()
            .map(|artifact| &artifact.coordinate))
        .chain(
            platform
                .modules
                .iter()
                .flat_map(|module| module.packages.iter().map(|package| &package.coordinate)),
        );
        for artifact in &platform.artifacts {
            let gav = &artifact.coordinate.gav;
            let version = gav.version();
            let base = snapshot_base_version(version).unwrap_or_else(|| version.to_string());
            (caps.rows).insert((gav.group.to_string(), gav.artifact.to_string(), base));
        }
        for coordinate in coordinates {
            let gav = &coordinate.gav;
            caps.record(gav.group.as_str(), gav.artifact.as_str(), gav.version());
        }
        // A range that lost still lists the versions it listed then.
        for range in (platform.modules.iter()).flat_map(|module| &module.evicted_ranges) {
            for version in &range.versions {
                caps.record(&range.group, &range.artifact, version);
            }
        }
        for read in (platform.modules.iter()).flat_map(|module| &module.range_versions) {
            caps.record(&read.group, &read.artifact, &read.version);
        }
        let selections = (platform.modules.iter())
            .flat_map(|module| &module.parent_ranges)
            .map(|range| range.selected.as_str());
        for gav in (platform.support_poms.keys().map(String::as_str))
            .chain(selections)
            .filter_map(split_support_pom_coord)
        {
            caps.record(gav.0, gav.1, gav.2);
        }
        caps.record_markers((platform.modules.iter()).flat_map(|module| &module.metadata_versions));
        let parents = (platform.modules.iter())
            .flat_map(|module| &module.parent_ranges)
            .filter_map(|range| split_support_pom_coord(&range.selected));
        for (group, artifact, version) in parents {
            if let Ok(version) = Version::parse(version) {
                let key = (group.to_string(), artifact.to_string());
                caps.parents.entry(key).or_default().push(version);
            }
        }
        for module in &platform.modules {
            for jar in &module.extensions {
                let key = format!("{}:{}", jar.gav.group, jar.gav.artifact);
                // A SNAPSHOT's build is listed as its base version.
                let version = jar.gav.version();
                let version = snapshot_base_version(version).unwrap_or_else(|| version.to_string());
                let held = caps.held.entry((module.path.clone(), true, key));
                held.or_default().push(version);
            }
        }
        caps.realms = Some(Self::of_realms(platform));
        caps
    }

    /// The caps of the realms of `platform`'s build extensions: the
    /// versions of the jars the modules' extensions lines pin. A reactor's
    /// modules share a realm, so they are the platform's.
    fn of_realms(platform: &LockPlatform) -> Arc<Self> {
        let mut caps = Self::default();
        for jar in (platform.modules.iter()).flat_map(|module| &module.extensions) {
            let gav = &jar.gav;
            caps.record(gav.group.as_str(), gav.artifact.as_str(), gav.version());
        }
        Arc::new(caps)
    }

    /// The caps of a build extension's realm.
    pub(crate) fn realms(&self) -> Option<Arc<Self>> {
        self.realms.clone()
    }

    /// The caps of `platform`'s plugin resolution, from its plugin tables:
    /// the rows and POMs their sets read, the versions their ranges took
    /// and the markers they read, and each plugin and build extension
    /// without a version held, for each module that builds with it, at the
    /// version it took.
    pub(crate) fn of_plugins(platform: &LockPlatform) -> Self {
        let mut caps = Self {
            realms: Some(Self::of_realms(platform)),
            ..Self::default()
        };
        let Some(tables) = &platform.plugins else {
            return caps;
        };
        let sets = (tables.sets.iter()).filter(|set| set.role != PluginRole::Trace);
        for set in sets.clone() {
            for coordinate in &set.artifacts {
                let gav = &coordinate.gav;
                caps.record(gav.group.as_str(), gav.artifact.as_str(), gav.version());
            }
            for (group, artifact, version) in set
                .poms
                .iter()
                .filter_map(|pom| split_support_pom_coord(pom))
            {
                caps.record(group, artifact, version);
            }
        }
        for read in &tables.range_versions {
            caps.record(&read.group, &read.artifact, &read.version);
        }
        // The tables keep no parent range selections: a range that took a
        // POM a set reads as a parent or import took a parent's spelling.
        let poms: std::collections::BTreeSet<&str> = (sets.clone())
            .flat_map(|set| set.poms.iter().map(String::as_str))
            .collect();
        for read in &tables.range_versions {
            let coordinate = format!("{}:{}:{}", read.group, read.artifact, read.version);
            if poms.contains(coordinate.as_str())
                && let Ok(version) = Version::parse(&read.version)
            {
                let key = (read.group.clone(), read.artifact.clone());
                let parents = caps.parents.entry(key).or_default();
                if !parents.iter().any(|kept| kept.as_str() == version.as_str()) {
                    parents.push(version);
                }
            }
        }
        caps.record_markers(&tables.metadata_versions);
        let taken: std::collections::BTreeSet<String> = (tables.metadata_versions.iter())
            .filter(|read| read.kind == MetadataVersionKind::Release)
            .map(|read| format!("{}:{}:{}", read.group, read.artifact, read.version))
            .collect();
        let sets =
            sets.filter(|set| matches!(set.role, PluginRole::Plugin | PluginRole::BuildExtension));
        for set in sets {
            let extension = set.role == PluginRole::BuildExtension;
            let taken = (set.coordinates.iter()).filter(|coordinate| taken.contains(*coordinate));
            for (key, version) in taken.filter_map(|coordinate| coordinate.rsplit_once(':')) {
                for module in &set.modules {
                    let held = caps
                        .held
                        .entry((module.clone(), extension, key.to_string()));
                    held.or_default().push(version.to_string());
                }
            }
        }
        caps
    }

    fn record_markers<'a>(&mut self, markers: impl IntoIterator<Item = &'a MetadataVersion>) {
        for marker in markers {
            self.record(&marker.group, &marker.artifact, &marker.version);
            let Ok(version) = Version::parse(&marker.version) else {
                continue;
            };
            let key = (marker.group.clone(), marker.artifact.clone(), marker.kind);
            self.markers.entry(key).or_default().push(version);
        }
    }

    /// The highest `kind` marker of `group:artifact` the lock records, in
    /// `mode`'s order, that `admits` accepts, if any.
    pub(crate) fn marker(
        &self,
        group: &str,
        artifact: &str,
        kind: MetadataVersionKind,
        mode: MavenMode,
        admits: impl Fn(&Version) -> bool,
    ) -> Option<&Version> {
        let recorded = self.markers_of(group, artifact, kind);
        (recorded.iter().filter(|version| admits(version))).max_by(|a, b| a.cmp_in(b, mode))
    }

    fn markers_of(&self, group: &str, artifact: &str, kind: MetadataVersionKind) -> &[Version] {
        let key = (group.to_string(), artifact.to_string(), kind);
        self.markers.get(&key).map_or(&[], Vec::as_slice)
    }

    fn record(&mut self, group: &str, artifact: &str, version: &str) {
        // A SNAPSHOT build is listed under its base version.
        let base = snapshot_base_version(version);
        let Ok(version) = Version::parse(base.as_deref().unwrap_or(version)) else {
            return;
        };
        let key = (group.to_string(), artifact.to_string());
        let versions = self.versions.entry(key).or_default();
        if !versions
            .iter()
            .any(|held| held.as_str() == version.as_str())
        {
            versions.push(version);
        }
    }

    /// Whether the lock has an artifact row of `version` of
    /// `group:artifact`.
    pub(crate) fn has_row(&self, group: &str, artifact: &str, version: &str) -> bool {
        let base = snapshot_base_version(version).unwrap_or_else(|| version.to_string());
        (self.rows).contains(&(group.to_string(), artifact.to_string(), base))
    }

    /// The highest version of `group:artifact` the lock records, in `mode`'s
    /// order, that `admits` accepts, if any.
    pub(crate) fn cap(
        &self,
        group: &str,
        artifact: &str,
        mode: MavenMode,
        admits: impl Fn(&Version) -> bool,
    ) -> Option<&Version> {
        let versions = (self.versions).get(&(group.to_string(), artifact.to_string()))?;
        (versions.iter().filter(|version| admits(version))).max_by(|a, b| a.cmp_in(b, mode))
    }

    /// Note that a cap changed what a listing offers.
    pub(crate) fn applied(&self) {
        self.applied.store(true, Ordering::Relaxed);
    }

    /// Whether a cap changed what a listing offered, a realm's included.
    pub(crate) fn was_applied(&self) -> bool {
        self.applied.load(Ordering::Relaxed)
            || self.realms.as_deref().is_some_and(Self::was_applied)
    }

    /// Whether a listed `version` of `group:artifact` may be chosen for
    /// `req`: the lock records that very spelling. Nothing published since
    /// moves a replayed range, and [`Self::order_taken`] keeps the order
    /// the whole listing gives equal spellings from moving it. A range
    /// that matches no locked version is not capped.
    pub(crate) fn admits(
        &self,
        group: &str,
        artifact: &str,
        req: &VersionReq,
        version: &Version,
        mode: MavenMode,
    ) -> bool {
        let Some(recorded) = (self.versions).get(&(group.to_string(), artifact.to_string())) else {
            return true;
        };
        if !recorded.iter().any(|locked| req.matches_in(locked, mode)) {
            return true;
        }
        let admitted = recorded
            .iter()
            .any(|other| other.as_str() == version.as_str());
        if !admitted {
            self.applied();
        }
        admitted
    }

    /// Move the spelling of `group:artifact` a range took, as the lock
    /// records, to the place among the others of `listing`, sorted as Maven
    /// lists them, that compare equal where a range takes it: the first
    /// when `first`, else the last. The order of equal spellings changes as
    /// a listing grows, and the others stay, as Maven reads their POMs too.
    pub(crate) fn order_taken<T>(
        &self,
        (group, artifact): (&str, &str),
        listing: &mut [T],
        version: impl Fn(&T) -> &Version,
        mode: MavenMode,
        first: bool,
    ) {
        let taken = self.markers_of(group, artifact, MetadataVersionKind::Range);
        self.order(taken, listing, version, mode, first);
    }

    /// [`Self::order_taken`] for a parent range, which takes the last of
    /// equal spellings, at the spelling a parent range took.
    pub(crate) fn order_parent_taken(
        &self,
        (group, artifact): (&str, &str),
        listing: &mut [Version],
        mode: MavenMode,
    ) {
        let key = (group.to_string(), artifact.to_string());
        let taken = self.parents.get(&key).map_or(&[][..], Vec::as_slice);
        self.order(taken, listing, |version| version, mode, false);
    }

    /// Two spellings taken among one set of equal ones, by uses whose
    /// listings ordered it apart, leave its order as listed.
    fn order<T>(
        &self,
        taken: &[Version],
        listing: &mut [T],
        version: impl Fn(&T) -> &Version,
        mode: MavenMode,
        first: bool,
    ) {
        for spelling in taken {
            let equal = |item: &T| version(item).cmp_in(spelling, mode).is_eq();
            let Some(start) = listing.iter().position(equal) else {
                continue;
            };
            let end = start
                + (listing[start..].iter())
                    .take_while(|item| equal(item))
                    .count();
            let group = &listing[start..end];
            let position = |taken: &Version| {
                (group.iter()).position(|item| version(item).as_str() == taken.as_str())
            };
            let Some(at) = position(spelling).map(|at| start + at) else {
                continue;
            };
            if taken
                .iter()
                .filter(|other| position(other).is_some())
                .count()
                > 1
            {
                continue;
            }
            let place = if first { start } else { end - 1 };
            if at != place {
                match first {
                    true => listing[start..=at].rotate_right(1),
                    false => listing[at..end].rotate_left(1),
                }
                self.applied();
            }
        }
    }

    /// Whether a range that took `version` of `group:artifact` took it
    /// among listed spellings that compare equal, as the lock records,
    /// where [`Self::admits`] left the others of `listed` out.
    pub(crate) fn tied(
        &self,
        group: &str,
        artifact: &str,
        version: &Version,
        listed: &IndexSet<String>,
        mode: MavenMode,
    ) -> bool {
        let taken = self.markers_of(group, artifact, MetadataVersionKind::Range);
        taken.iter().any(|taken| taken.as_str() == version.as_str())
            && (listed.iter()).any(|other| {
                other != version.as_str()
                    && Version::parse(other).is_ok_and(|other| other.cmp_in(version, mode).is_eq())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `alpha` and `0` are one version in Maven 3.9 and two in 3.10, which
    /// sorts `alpha` below `0`: the caps keep both spellings.
    #[test]
    fn versions_equal_in_one_mode_are_both_kept() {
        let mut caps = VersionCaps::default();
        for version in ["alpha", "0"] {
            caps.record("g", "a", version);
        }
        let req = VersionReq::parse("[0,1)").unwrap();
        let cap = caps.cap("g", "a", MavenMode::Maven310, |locked| {
            req.matches_in(locked, MavenMode::Maven310)
        });
        assert_eq!(cap.map(Version::as_str), Some("0"));
        assert!(!caps.admits(
            "g",
            "a",
            &req,
            &Version::parse("0.9").unwrap(),
            MavenMode::Maven310
        ));
    }

    #[test]
    fn a_range_is_capped_at_the_highest_locked_version_it_matches() {
        let mut caps = VersionCaps::default();
        for version in ["1.2", "2.0", "3.1-SNAPSHOT"] {
            caps.record("g", "a", version);
        }
        caps.record("g", "b", "9");
        let admits = |req: &str, version: &str| {
            let req = VersionReq::parse(req).unwrap();
            caps.admits(
                "g",
                "a",
                &req,
                &Version::parse(version).unwrap(),
                MavenMode::Maven39,
            )
        };
        assert!(admits("[1,2)", "1.2") && admits("[2,3)", "2.0"));
        assert!(!caps.was_applied());
        // Neither a version above nor one below a locked one is offered,
        // nor another spelling of one.
        assert!(!admits("[1,2)", "1.3") && !admits("[1,2)", "1.1"));
        assert!(!admits("[1,2)", "1.2-ga"));
        assert!(caps.was_applied());
        assert!(admits("[1,)", "3.1-SNAPSHOT") && !admits("[1,)", "3.2"));
        // A range that matches no locked version, or a coordinate the lock
        // lacks, is offered every listed version.
        assert!(admits("[4,5)", "4.9"));
        let req = VersionReq::parse("[1,2)").unwrap();
        assert!(caps.admits(
            "g",
            "c",
            &req,
            &Version::parse("1.9").unwrap(),
            MavenMode::Maven39
        ));
    }

    /// A build extension's realm is capped at the jars the extensions
    /// lines pin, and those caps leave a dependency's range alone.
    #[test]
    fn an_extension_jar_caps_only_a_realm() {
        let mut module =
            rv_lock::LockModule::new("pom.xml", rv_maven_types::Gav::new("t", "app", "1"), "jar");
        module.extensions.push(rv_lock::ExtensionJar {
            gav: rv_maven_types::Gav::new("g", "a", "1"),
            classifier: None,
            sha256: rv_maven_types::Sha256::from_bytes(b"a"),
        });
        let mut platform = LockPlatform::new("linux-x86_64".parse().unwrap(), String::new());
        platform.modules.push(module);
        let req = VersionReq::parse("[1,)").unwrap();
        let two = Version::parse("2").unwrap();
        for caps in [
            VersionCaps::of(&platform),
            VersionCaps::of_plugins(&platform),
        ] {
            assert!(caps.admits("g", "a", &req, &two, MavenMode::Maven39));
            let realms = caps.realms().unwrap();
            assert!(!realms.admits("g", "a", &req, &two, MavenMode::Maven39));
            assert!(caps.was_applied());
        }
    }

    /// Of two locked spellings that compare equal, a range is offered both,
    /// with the one the lock records a range took where the collector
    /// takes it, and replays its tie where the listing holds another.
    #[test]
    fn a_tie_is_offered_the_spelling_a_range_took() {
        let mut caps = VersionCaps::default();
        caps.record("g", "a", "1.0-alpha-1");
        let taken = MetadataVersion {
            group: "g".to_string(),
            artifact: "a".to_string(),
            kind: MetadataVersionKind::Range,
            version: "1.0-a1".to_string(),
        };
        caps.record_markers([&taken]);
        let req = VersionReq::parse("[1.0-alpha-1,2.0)").unwrap();
        for mode in [MavenMode::Maven39, MavenMode::Maven310] {
            let admits = |version: &str| {
                caps.admits("g", "a", &req, &Version::parse(version).unwrap(), mode)
            };
            assert!(admits("1.0-a1") && admits("1.0-alpha-1"), "{mode:?}");
            for first in [true, false] {
                let mut listing: Vec<_> = ["0.1", "1.0-a1", "1.0-alpha-1", "1.5"]
                    .map(|version| Version::parse(version).unwrap())
                    .into();
                caps.order_taken(("g", "a"), &mut listing, |version| version, mode, first);
                let spelled: Vec<_> = listing.iter().map(Version::as_str).collect();
                let tie = match first {
                    true => ["1.0-a1", "1.0-alpha-1"],
                    false => ["1.0-alpha-1", "1.0-a1"],
                };
                assert_eq!(spelled, ["0.1", tie[0], tie[1], "1.5"], "{mode:?}");
            }
            // Two uses that took both spellings leave them as listed.
            let mut both = VersionCaps::default();
            let alpha = MetadataVersion {
                version: "1.0-alpha-1".to_string(),
                ..taken.clone()
            };
            both.record_markers([&taken, &alpha]);
            let mut listing: Vec<_> = ["1.0-alpha-1", "1.0-a1"]
                .map(|version| Version::parse(version).unwrap())
                .into();
            both.order_taken(("g", "a"), &mut listing, |version| version, mode, true);
            let spelled: Vec<_> = listing.iter().map(Version::as_str).collect();
            assert_eq!(spelled, ["1.0-alpha-1", "1.0-a1"], "{mode:?}");
            let a1 = Version::parse("1.0-a1").unwrap();
            let listed = |versions: &[&str]| versions.iter().map(|v| v.to_string()).collect();
            assert!(caps.tied(
                "g",
                "a",
                &a1,
                &listed(&["0.1", "1.0-alpha-1", "1.0-a1"]),
                mode
            ));
            assert!(!caps.tied("g", "a", &a1, &listed(&["0.1", "1.0-a1"]), mode));
            let alpha = Version::parse("1.0-alpha-1").unwrap();
            assert!(!caps.tied("g", "a", &alpha, &listed(&["1.0-alpha-1", "1.0-a1"]), mode));
        }
    }
}
