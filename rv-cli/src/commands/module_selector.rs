use clap::Args;
use rv_config::{LockModule, LockPlatform};

use crate::error::{CliError, Result};

#[derive(Clone, Debug, Args, Default)]
pub(crate) struct ModuleSelector {
    #[arg(
        long,
        value_name = "MODULE",
        help = "Select a module by root-relative pom.xml path or unique groupId:artifactId"
    )]
    module: Option<String>,
}

impl ModuleSelector {
    pub(crate) fn select<'a>(&self, platform: &'a LockPlatform) -> Result<ModuleSelection<'a>> {
        let Some(selector) = self.module.as_deref() else {
            return Ok(ModuleSelection {
                modules: platform.modules.iter().collect(),
                aggregate: true,
            });
        };

        // Lock paths are always forward-slash normalized (the schema's
        // `pomPath`), so accept the native Windows spelling of the same path.
        // Only the path comparison is normalized: a backslash inside a GAV
        // selector is left exactly as typed.
        let path_selector = selector.replace('\\', "/");
        let path_matches = platform
            .modules
            .iter()
            .filter(|module| module.path == path_selector)
            .collect::<Vec<_>>();
        if path_matches.len() == 1 {
            return Ok(ModuleSelection {
                modules: path_matches,
                aggregate: false,
            });
        }

        // A legacy-adapted root carries a placeholder GAV, so it is selectable
        // by path only; matching it here would advertise the sentinel as a
        // coordinate.
        let gav_matches = platform
            .modules
            .iter()
            .filter(|module| !module.is_legacy_placeholder() && module.ga() == selector)
            .collect::<Vec<_>>();
        match gav_matches.len() {
            1 => Ok(ModuleSelection {
                modules: gav_matches,
                aggregate: false,
            }),
            count if count > 1 => Err(CliError::Message(format!(
                "module selector '{selector}' is ambiguous; candidates: {}",
                format_candidates(&gav_matches)
            ))),
            _ => Err(CliError::Message(format!(
                "module selector '{selector}' did not match; available modules: {}",
                format_candidates(&platform.modules.iter().collect::<Vec<_>>())
            ))),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ModuleSelection<'a> {
    modules: Vec<&'a LockModule>,
    aggregate: bool,
}

impl<'a> ModuleSelection<'a> {
    pub(crate) fn modules(&self) -> &[&'a LockModule] {
        &self.modules
    }

    pub(crate) fn is_aggregate(&self) -> bool {
        self.aggregate
    }
}

pub(crate) trait LockModuleExt {
    fn ga(&self) -> String;
    fn gav(&self) -> String;
    fn display_gav(&self) -> String;
    fn display_label(&self) -> String;
}

impl LockModuleExt for LockModule {
    fn ga(&self) -> String {
        format!("{}:{}", self.gav.group, self.gav.artifact)
    }

    fn gav(&self) -> String {
        format!(
            "{}:{}:{}",
            self.gav.group, self.gav.artifact, self.gav.version
        )
    }

    /// Human-facing identity. A lockfile adapted from schema 1-3 has no module
    /// coordinates, so the synthetic root is named by its POM rather than by
    /// the placeholder GAV rv minted for it.
    fn display_gav(&self) -> String {
        if self.is_legacy_placeholder() {
            format!("{} (legacy lockfile root)", self.path)
        } else {
            self.gav()
        }
    }

    /// `path (gav)` label for module headers and candidate lists.
    fn display_label(&self) -> String {
        if self.is_legacy_placeholder() {
            self.display_gav()
        } else {
            format!("{} ({})", self.path, self.gav())
        }
    }
}

fn format_candidates(modules: &[&LockModule]) -> String {
    modules
        .iter()
        .map(|module| module.display_label())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rv_config::{LockGav, LockModule, LockPlatform, Platform};

    use super::ModuleSelector;

    fn module(path: &str, artifact: &str, version: &str) -> LockModule {
        LockModule {
            path: path.to_string(),
            gav: LockGav::new("com.example", artifact, version),
            packaging: "jar".to_string(),
            packages: Vec::new(),
            edges: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    fn platform() -> LockPlatform {
        LockPlatform {
            platform: Platform::new("linux", "x86_64").expect("platform"),
            model_hash: "a".repeat(64),
            artifacts: Vec::new(),
            modules: vec![
                module("app/pom.xml", "app", "1"),
                module("lib-v1/pom.xml", "lib", "1"),
                module("lib-v2/pom.xml", "lib", "2"),
            ],
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn aggregate_selects_every_module() {
        let platform = platform();
        let selection = ModuleSelector::default().select(&platform).expect("select");
        assert!(selection.is_aggregate());
        assert_eq!(selection.modules().len(), 3);
    }

    #[test]
    fn selects_by_path_or_unique_ga() {
        let platform = platform();
        let by_path = ModuleSelector {
            module: Some("lib-v1/pom.xml".to_string()),
        }
        .select(&platform)
        .expect("select path");
        assert_eq!(by_path.modules()[0].path, "lib-v1/pom.xml");

        let by_ga = ModuleSelector {
            module: Some("com.example:app".to_string()),
        }
        .select(&platform)
        .expect("select GA");
        assert_eq!(by_ga.modules()[0].path, "app/pom.xml");
    }

    /// Lock paths are always forward-slash; a Windows-native spelling of the
    /// same path must still select, and a backslash inside a GAV selector must
    /// reach the GAV comparison untouched.
    #[test]
    fn path_selector_accepts_native_separators() {
        let platform = platform();
        let by_native_path = ModuleSelector {
            module: Some("lib-v1\\pom.xml".to_string()),
        }
        .select(&platform)
        .expect("select native path");
        assert_eq!(by_native_path.modules()[0].path, "lib-v1/pom.xml");

        let by_posix_path = ModuleSelector {
            module: Some("lib-v1/pom.xml".to_string()),
        }
        .select(&platform)
        .expect("select posix path");
        assert_eq!(by_posix_path.modules()[0].path, "lib-v1/pom.xml");

        // A GAV selector is compared verbatim: the backslash is not a
        // separator here, so nothing matches and nothing is rewritten.
        let missing = ModuleSelector {
            module: Some("com.example:a\\pp".to_string()),
        }
        .select(&platform)
        .expect_err("backslash in a GA must not be normalized into a match");
        assert!(missing.to_string().contains("com.example:a\\pp"));
    }

    #[test]
    fn legacy_placeholder_is_selectable_by_path_but_never_by_gav() {
        let platform = LockPlatform {
            modules: vec![LockModule {
                path: "pom.xml".to_string(),
                gav: LockGav::legacy_root(),
                ..module("pom.xml", "root", "1")
            }],
            ..platform()
        };

        let by_path = ModuleSelector {
            module: Some("pom.xml".to_string()),
        }
        .select(&platform)
        .expect("legacy root selects by path");
        assert_eq!(by_path.modules()[0].path, "pom.xml");

        // The sentinel is not a coordinate, so it must not resolve as one and
        // must not be advertised as a candidate.
        let err = ModuleSelector {
            module: Some("__legacy__:__root__".to_string()),
        }
        .select(&platform)
        .expect_err("sentinel GA must not select");
        let err = err.to_string();
        assert!(!err.contains("__root__:0"), "sentinel GAV leaked: {err}");
        assert!(err.contains("pom.xml (legacy lockfile root)"), "got {err}");
    }

    #[test]
    fn selector_errors_name_candidates_and_available_modules() {
        let ambiguous = ModuleSelector {
            module: Some("com.example:lib".to_string()),
        }
        .select(&platform())
        .expect_err("ambiguous GA");
        let ambiguous = ambiguous.to_string();
        assert!(ambiguous.contains("ambiguous"));
        assert!(ambiguous.contains("lib-v1/pom.xml"));
        assert!(ambiguous.contains("lib-v2/pom.xml"));

        let missing = ModuleSelector {
            module: Some("com.example:missing".to_string()),
        }
        .select(&platform())
        .expect_err("missing module");
        let missing = missing.to_string();
        assert!(missing.contains("available modules"));
        assert!(missing.contains("app/pom.xml"));
        assert!(missing.contains("lib-v1/pom.xml"));
    }
}
