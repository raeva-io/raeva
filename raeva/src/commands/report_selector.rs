use std::collections::BTreeMap;

use clap::Args;
use rv_lock::{LockPlatform, Lockfile, Platform};
use serde::Serialize;

use crate::commands::lock_adapter::{adapt_sbom_modules_listing, listed_module_purls};
use crate::commands::module_selector::ModuleSelector;
use crate::error::{CliError, Result};

#[derive(Clone, Debug, Default, Args)]
pub(crate) struct ReportSelector {
    #[arg(
        long,
        value_name = "OS-ARCH",
        help = "Report only this recorded platform (default: all platforms)"
    )]
    platform: Option<Platform>,
    #[arg(
        long,
        value_name = "VERSION",
        help = "Report only this exact recorded target JDK (default: all JDKs)"
    )]
    jdk: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ReportTarget {
    pub platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jdk: Option<String>,
}

impl std::fmt::Display for ReportTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.platform)?;
        if let Some(jdk) = &self.jdk {
            write!(f, " and JDK {jdk}")?;
        }
        Ok(())
    }
}

pub(crate) struct ReportSelection<'a> {
    pub platforms: Vec<&'a LockPlatform>,
}

impl ReportSelector {
    /// Select recorded targets without a host-platform fallback.
    pub(crate) fn select<'a>(&self, lock: &'a Lockfile) -> Result<ReportSelection<'a>> {
        let mut platforms: Vec<_> = lock
            .platforms
            .iter()
            .filter(|entry| {
                self.platform
                    .as_ref()
                    .is_none_or(|p| *p == entry.platform.without_jdk())
                    && self
                        .jdk
                        .as_deref()
                        .is_none_or(|jdk| entry.platform.jdk() == Some(jdk))
            })
            .collect();
        platforms.sort_by_key(|entry| entry.platform.to_string());
        if platforms.is_empty() {
            let mut available = lock
                .platforms
                .iter()
                .map(|p| p.platform.to_string())
                .collect::<Vec<_>>();
            available.sort();
            return Err(CliError::Usage(format!(
                "no recorded target matches {}; available targets: {}",
                self.asked(),
                if available.is_empty() {
                    "none".to_string()
                } else {
                    available.join(", ")
                }
            )));
        }
        Ok(ReportSelection { platforms })
    }

    fn asked(&self) -> String {
        [
            (
                "--platform",
                self.platform.as_ref().map(ToString::to_string),
            ),
            ("--jdk", self.jdk.clone()),
        ]
        .into_iter()
        .filter_map(|(flag, value)| Some(format!("{flag} {}", value?)))
        .collect::<Vec<_>>()
        .join(" and ")
    }
}

/// The one target `tree` and `why` show.
#[derive(Clone, Debug, Default, Args)]
pub(crate) struct TargetSelector {
    #[arg(
        long,
        value_name = "OS-ARCH",
        help = "Show this recorded platform (default: this machine's)"
    )]
    platform: Option<Platform>,
    #[arg(
        long,
        value_name = "VERSION",
        help = "Show this exact recorded target JDK (default: this machine's)"
    )]
    jdk: Option<String>,
}

impl TargetSelector {
    /// The host's target without selectors, as [`select_platform`] picks it.
    /// Selectors must match exactly one recorded target and never fall back.
    ///
    /// [`select_platform`]: crate::commands::select_platform
    pub(crate) fn select<'a>(
        &self,
        lock: &'a Lockfile,
        host_jdk: Option<&str>,
    ) -> Result<&'a LockPlatform> {
        if self.platform.is_none() && self.jdk.is_none() {
            return crate::commands::select_platform(lock, host_jdk);
        }
        let selector = ReportSelector {
            platform: self.platform.clone(),
            jdk: self.jdk.clone(),
        };
        match selector.select(lock)?.platforms.as_slice() {
            [one] => Ok(one),
            several => Err(CliError::Usage(format!(
                "{} matches {} recorded targets: {}; pass {} to select one",
                selector.asked(),
                several.len(),
                several
                    .iter()
                    .map(|entry| entry.platform.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                if self.platform.is_none() {
                    "--platform"
                } else {
                    "--jdk"
                }
            ))),
        }
    }
}

impl ReportSelection<'_> {
    pub(crate) fn targets(&self) -> Vec<ReportTarget> {
        self.platforms
            .iter()
            .map(|entry| ReportTarget {
                platform: entry.platform.os_arch(),
                jdk: entry.platform.jdk().map(str::to_string),
            })
            .collect()
    }

    /// Merge inventories only when shared module graphs and component pins agree.
    /// Host inputs are kept from the first target and must not be used for freshness checks.
    pub(crate) fn sbom_platform(&self, selector: &ModuleSelector) -> Result<LockPlatform> {
        let mut merged = (*self.platforms[0]).clone();
        if self.platforms.len() == 1 {
            // One target has no other to disagree with.
            merged
                .modules
                .sort_by(|left, right| left.path.cmp(&right.path));
            return Ok(merged);
        }
        // Select across the union before comparing target-specific graphs.
        let mut inventory = BTreeMap::new();
        for platform in &self.platforms {
            for module in &platform.modules {
                inventory
                    .entry(module.path.clone())
                    .or_insert_with(|| module.clone());
            }
        }
        merged.modules = inventory.into_values().collect();
        let selected = selector.select(&merged)?;
        // The document lists the modules every target selects.
        let listed = listed_module_purls(&merged, selected.modules())?;
        let paths: std::collections::BTreeSet<_> =
            selected.modules().iter().map(|m| m.path.clone()).collect();
        let mut modules = BTreeMap::new();
        let mut artifacts = BTreeMap::new();
        let mut identities = BTreeMap::new();
        let mut components = BTreeMap::<String, rv_sbom::Component>::new();
        let ambiguous = |detail: String| {
            CliError::Usage(format!(
                "cannot combine the selected SBOM targets: {detail}; pass --platform and --jdk to select one target"
            ))
        };
        for platform in &self.platforms {
            let selected: Vec<_> = platform
                .modules
                .iter()
                .filter(|m| paths.contains(&m.path))
                .collect();
            for module in &selected {
                let module = *module;
                if let Some(old) = modules.insert(module.path.clone(), module.clone())
                    && old != *module
                {
                    return Err(ambiguous(format!(
                        "module {} has different identities or dependency graphs",
                        module.path
                    )));
                }
            }
            for module in selected.iter().copied().chain(
                selected
                    .iter()
                    .flat_map(|m| &m.packages)
                    .filter_map(|p| p.workspace_module.as_deref())
                    .filter_map(|path| platform.modules.iter().find(|m| m.path == path)),
            ) {
                let path = module.path.as_str();
                let identity = (&module.gav, &module.packaging);
                if let Some(old) = identities.insert(path, identity)
                    && old != identity
                {
                    return Err(ambiguous(format!(
                        "workspace module {path} has different identities"
                    )));
                }
            }
            let coordinates: std::collections::BTreeSet<_> = selected
                .iter()
                .flat_map(|m| &m.packages)
                .filter_map(rv_lock::LockModulePackage::repository_file)
                .collect();
            for artifact in platform
                .artifacts
                .iter()
                .filter(|a| coordinates.contains(&a.coordinate))
            {
                if let Some(old) = artifacts.insert(artifact.coordinate.clone(), artifact.clone())
                    && (old.checksums != artifact.checksums
                        || old.snapshot != artifact.snapshot
                        || old.pom_snapshot != artifact.pom_snapshot
                        || old.pom_base != artifact.pom_base
                        || old.pom_sha256 != artifact.pom_sha256)
                {
                    return Err(ambiguous(format!(
                        "{} has different artifact or POM pins",
                        artifact.coordinate
                    )));
                }
            }
            if selected.is_empty() {
                continue;
            }
            let adapted = adapt_sbom_modules_listing(platform, &selected, &listed)?;
            for component in std::iter::once(adapted.root).chain(adapted.components) {
                if let Some(old) =
                    components.insert(component.reference().to_string(), component.clone())
                    && (old.hashes != component.hashes
                        || old.dependencies != component.dependencies)
                {
                    return Err(ambiguous(format!(
                        "{} has different hashes or dependency edges",
                        component.reference()
                    )));
                }
            }
        }
        for module in &mut merged.modules {
            if let Some(selected) = modules.remove(&module.path) {
                *module = selected;
            } else if let Some((gav, packaging)) = identities.get(module.path.as_str()) {
                module.gav = (*gav).clone();
                module.packaging = (*packaging).clone();
            }
        }
        merged.artifacts = artifacts.into_values().collect();
        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use rv_lock::{LockArtifact, LockModule, LockModulePackage};
    use rv_maven_types::{ArtifactCoord, Gav};

    use super::*;

    fn lock() -> Lockfile {
        let mut lock = Lockfile::new();
        for jdk in ["17", "21"] {
            let mut target = LockPlatform::new(
                Platform::new("linux", "x86_64").unwrap().with_jdk(jdk),
                "a".repeat(64),
            );
            target.modules.push(LockModule::new(
                "pom.xml",
                Gav::new("com.example", "app", "1"),
                "jar",
            ));
            lock.platforms.push(target);
        }
        lock
    }

    #[test]
    fn selectors_cover_all_targets_or_fail_without_fallback() {
        let lock = lock();
        assert_eq!(
            ReportSelector::default()
                .select(&lock)
                .unwrap()
                .targets()
                .len(),
            2
        );
        let selected = ReportSelector {
            platform: Some("linux-x86_64".parse().unwrap()),
            jdk: Some("21".into()),
        };
        assert_eq!(
            selected.select(&lock).unwrap().targets()[0].jdk.as_deref(),
            Some("21")
        );
        for (selector, asked) in [
            (
                ReportSelector {
                    jdk: Some("22".into()),
                    ..Default::default()
                },
                "--jdk 22",
            ),
            (
                ReportSelector {
                    platform: Some("macos-aarch64".parse().unwrap()),
                    ..Default::default()
                },
                "--platform macos-aarch64",
            ),
        ] {
            let error = selector.select(&lock).err().unwrap().to_string();
            assert!(
                error.starts_with(&format!(
                    "no recorded target matches {asked}; available targets: "
                )),
                "{error}"
            );
        }
    }

    #[test]
    fn a_shown_target_is_the_one_the_selectors_match() {
        let lock = lock();
        let jdk = |jdk: &str| TargetSelector {
            jdk: Some(jdk.into()),
            ..Default::default()
        };
        let shown = jdk("21").select(&lock, Some("17")).unwrap();
        assert_eq!(shown.platform.jdk(), Some("21"));
        let error = jdk("22").select(&lock, Some("22")).unwrap_err();
        assert!(matches!(error, CliError::Usage(_)));
        assert!(
            error
                .to_string()
                .starts_with("no recorded target matches --jdk 22; available targets: "),
            "{error}"
        );
        let platform = TargetSelector {
            platform: Some("linux-x86_64".parse().unwrap()),
            ..Default::default()
        };
        let error = platform.select(&lock, Some("21")).unwrap_err().to_string();
        assert_eq!(
            error,
            "--platform linux-x86_64 matches 2 recorded targets: linux-x86_64 (JDK 17), \
             linux-x86_64 (JDK 21); pass --jdk to select one"
        );
    }

    #[test]
    fn sbom_merges_identical_and_disjoint_graphs_but_refuses_contradictions() {
        let mut lock = lock();
        assert_eq!(
            ReportSelector::default()
                .select(&lock)
                .unwrap()
                .sbom_platform(&ModuleSelector::default())
                .unwrap()
                .modules
                .len(),
            1
        );
        lock.platforms[1].modules[0].path = "other/pom.xml".into();
        lock.platforms[1].modules[0].gav = Gav::new("com.example", "other", "1");
        assert_eq!(
            ReportSelector::default()
                .select(&lock)
                .unwrap()
                .sbom_platform(&ModuleSelector::default())
                .unwrap()
                .modules
                .len(),
            2
        );
        lock.platforms[1].modules[0].path = "pom.xml".into();
        let error = ReportSelector::default()
            .select(&lock)
            .unwrap()
            .sbom_platform(&ModuleSelector::default())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("different identities")
                && error.contains("--platform")
                && error.contains("--jdk")
        );
    }

    #[test]
    fn selected_module_uses_its_targets_workspace_identity() {
        use clap::Parser;
        #[derive(Parser)]
        struct Args {
            #[command(flatten)]
            module: ModuleSelector,
        }
        let selector = Args::parse_from(["test", "--module", "app/pom.xml"]).module;
        let mut lock = lock();
        lock.platforms[0].modules[0].path = "lib/pom.xml".into();
        lock.platforms[0].modules[0].gav = Gav::new("com.example", "lib", "1");
        lock.platforms[1].modules[0].path = "app/pom.xml".into();
        lock.platforms[1].modules.push(LockModule::new(
            "lib/pom.xml",
            Gav::new("com.example", "lib", "2"),
            "jar",
        ));
        let mut package = LockModulePackage::new(
            ArtifactCoord::new("com.example", "lib", "2", "jar", None),
            Some(rv_lock::Scope::Compile),
        );
        package.workspace_module = Some("lib/pom.xml".into());
        lock.platforms[1].modules[0].packages.push(package);
        let merged = ReportSelector::default()
            .select(&lock)
            .unwrap()
            .sbom_platform(&selector)
            .unwrap();
        let selected = selector.select(&merged).unwrap();
        let adapted =
            crate::commands::lock_adapter::adapt_sbom_modules(&merged, selected.modules()).unwrap();
        assert_eq!(adapted.root.dependencies, ["pkg:maven/com.example/lib@2"]);
        assert_eq!(adapted.components[0].version, "2");
    }

    #[test]
    fn sbom_refuses_different_pins_and_edges_for_shared_components() {
        let mut lock = lock();
        let coord = ArtifactCoord::new("org.example", "lib", "1", "jar", None);
        for target in &mut lock.platforms {
            target.modules[0].packages.push(LockModulePackage::new(
                coord.clone(),
                Some(rv_lock::Scope::Compile),
            ));
            target
                .artifacts
                .push(LockArtifact::new(coord.clone(), "https://repo.example/"));
        }
        lock.platforms[1].artifacts[0]
            .checksums
            .push(rv_maven_types::Digest::parse("sha256", &"a".repeat(64)).unwrap());
        let error = ReportSelector::default()
            .select(&lock)
            .unwrap()
            .sbom_platform(&ModuleSelector::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("different artifact or POM pins"));
        lock.platforms[1].artifacts[0].checksums.clear();
        lock.platforms[1].modules[0].packages.clear();
        let error = ReportSelector::default()
            .select(&lock)
            .unwrap()
            .sbom_platform(&ModuleSelector::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("dependency graphs"));
    }
    #[test]
    fn sbom_refuses_conflicting_edges_even_across_distinct_modules() {
        let mut lock = lock();
        let shared = ArtifactCoord::new("org.example", "shared", "1", "jar", None);
        let leaf = ArtifactCoord::new("org.example", "leaf", "1", "jar", None);
        for (index, target) in lock.platforms.iter_mut().enumerate() {
            target.modules[0].path = format!("module{index}/pom.xml");
            target.modules[0].gav = Gav::new("com.example", &format!("module{index}"), "1");
            for coordinate in [&shared, &leaf] {
                target.modules[0].packages.push(LockModulePackage::new(
                    coordinate.clone(),
                    Some(rv_lock::Scope::Compile),
                ));
                target.artifacts.push(LockArtifact::new(
                    coordinate.clone(),
                    "https://repo.example/",
                ));
            }
        }
        lock.platforms[0].modules[0]
            .edges
            .push(rv_lock::LockEdge::new(0, 1, rv_lock::Scope::Compile, false));
        let error = ReportSelector::default()
            .select(&lock)
            .unwrap()
            .sbom_platform(&ModuleSelector::default())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("shared@1") && error.contains("dependency edges"),
            "{error}"
        );
    }
}
