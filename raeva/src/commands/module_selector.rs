use clap::Args;
use rv_lock::{LockModule, LockPlatform};

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
        let Some(raw) = self.module.as_deref() else {
            return Ok(ModuleSelection {
                modules: platform.modules.iter().collect(),
                aggregate: true,
            });
        };
        // Surrounding whitespace is ignored the same way `--scope` and
        // `--platforms` ignore it. A whitespace-only value matches nothing.
        let selector = raw.trim();

        // Lock paths are always forward-slash normalized (the schema's
        // `pomPath`), so accept the native Windows spelling of the same path.
        // Only the path comparison is normalized: a backslash inside a GAV
        // selector is left exactly as typed.
        let path_selector = selector.replace('\\', "/");
        let modules = || platform.modules.iter();
        let mut matches: Vec<_> = modules()
            .filter(|module| module.path == path_selector)
            .collect();
        if matches.len() != 1 {
            matches = modules().filter(|module| module.ga() == selector).collect();
        }
        match matches.len() {
            1 => Ok(ModuleSelection {
                modules: matches,
                aggregate: false,
            }),
            0 => Err(CliError::Usage(unknown_module_message(
                selector,
                &modules().collect::<Vec<_>>(),
            ))),
            _ => Err(CliError::Usage(format!(
                "module selector '{selector}' is ambiguous; candidates: {}",
                format_candidates(&matches)
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
        self.aggregate && self.modules.len() > 1
    }
}

pub(crate) trait LockModuleExt {
    fn ga(&self) -> String;
    fn gav(&self) -> String;
    fn display_label(&self) -> String;
}

impl LockModuleExt for LockModule {
    fn ga(&self) -> String {
        format!("{}:{}", self.gav.group, self.gav.artifact)
    }

    fn gav(&self) -> String {
        self.gav.to_string()
    }

    /// `path (gav)` label for module headers and candidate lists.
    fn display_label(&self) -> String {
        format!("{} ({})", self.path, self.gav())
    }
}

/// How many modules an unmatched selector's error lists.
const SHOWN_CANDIDATES: usize = 10;

/// The error for a selector no module matches. A reactor can have hundreds
/// of modules, so it lists the ones whose path or GA contains the selector,
/// or else the first few, and counts the rest.
fn unknown_module_message(selector: &str, modules: &[&LockModule]) -> String {
    let needle = selector.to_ascii_lowercase();
    let similar: Vec<&LockModule> = modules
        .iter()
        .copied()
        .filter(|module| {
            module.path.to_ascii_lowercase().contains(&needle)
                || module.ga().to_ascii_lowercase().contains(&needle)
        })
        .collect();
    let (label, listed) = if similar.is_empty() {
        ("modules", modules)
    } else {
        ("similar modules", similar.as_slice())
    };
    let shown = listed.len().min(SHOWN_CANDIDATES);
    let mut message = format!(
        "module selector '{selector}' matches no module of the {} in raeva.lock; {label}: {}",
        modules.len(),
        format_candidates(&listed[..shown])
    );
    if listed.len() > shown {
        message.push_str(&format!(" and {} more", listed.len() - shown));
    }
    message
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

    use rv_lock::{LockModule, LockPlatform, Platform};
    use rv_maven_types::Gav;

    use super::ModuleSelector;

    fn module(path: &str, artifact: &str, version: &str) -> LockModule {
        LockModule::new(
            path.to_string(),
            Gav::new("com.example", artifact, version),
            "jar".to_string(),
        )
    }

    fn platform() -> LockPlatform {
        let mut platform = LockPlatform::new(
            Platform::new("linux", "x86_64").expect("platform"),
            "a".repeat(64),
        );
        platform.modules = vec![
            module("app/pom.xml", "app", "1"),
            module("lib-v1/pom.xml", "lib", "1"),
            module("lib-v2/pom.xml", "lib", "2"),
        ];
        platform
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

    /// Surrounding whitespace is ignored the same way `--scope` and
    /// `--platforms` ignore it, so a pasted path still selects.
    #[test]
    fn selects_after_trimming_surrounding_space() {
        let platform = platform();
        let by_path = ModuleSelector {
            module: Some("  lib-v1/pom.xml  ".to_string()),
        }
        .select(&platform)
        .expect("select trimmed path");
        assert_eq!(by_path.modules()[0].path, "lib-v1/pom.xml");

        let by_ga = ModuleSelector {
            module: Some("  com.example:app  ".to_string()),
        }
        .select(&platform)
        .expect("select trimmed GA");
        assert_eq!(by_ga.modules()[0].path, "app/pom.xml");
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
        assert!(missing.contains("matches no module of the 3"), "{missing}");
        assert!(missing.contains("app/pom.xml"));
        assert!(missing.contains("lib-v1/pom.xml"));
    }
}
