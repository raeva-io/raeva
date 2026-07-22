//! System-scope policy enforcement and warnings (warn-only for v0.1).

use std::path::Path;

use rv_config::Lockfile;
use rv_maven_model::{Dependency, Pom};

use crate::error::{CliError, Result};
use crate::output::{is_json_mode, warning};

#[derive(Debug, Clone)]
pub(super) struct SystemScopeEntry {
    coords: String,
    path: String,
}

pub(super) fn enforce_system_scope_policy(pom_path: &Path) -> Result<()> {
    let entries = collect_system_scope_entries(pom_path)?;
    if entries.is_empty() {
        return Ok(());
    }

    warn_system_scope_entries(&entries);
    Ok(())
}

fn collect_system_scope_entries(pom_path: &Path) -> Result<Vec<SystemScopeEntry>> {
    let xml = rv_config::read_project_input_string(pom_path)?;
    let pom = Pom::parse(&xml).map_err(|err| {
        CliError::Message(format!("invalid pom.xml at {}: {err}", pom_path.display()))
    })?;
    Ok(system_scope_entries_from_dependencies(&pom.dependencies))
}

fn system_scope_entries_from_dependencies(dependencies: &[Dependency]) -> Vec<SystemScopeEntry> {
    dependencies
        .iter()
        .filter_map(|dep| {
            let scope = dep
                .scope
                .as_deref()
                .map(str::trim)
                .unwrap_or("compile")
                .to_ascii_lowercase();
            if scope != "system" {
                return None;
            }
            // Skip the "non-portable" warning when the entry is invalid
            // (missing or empty `<systemPath>`, or a relative path). The
            // resolver is about to surface a focused `InvalidModel` error
            // for the same dependency, and emitting a generic warning
            // first just duplicates the report. Log at debug level so the
            // skip is still observable under `RUST_LOG`.
            let path = dep.system_path.as_deref().map(str::trim).unwrap_or("");
            if path.is_empty() || !std::path::Path::new(path).is_absolute() {
                tracing::debug!(
                    coord = %dependency_coords(dep),
                    system_path = path,
                    "skipping system-scope warning; resolver will surface invalid <systemPath> error"
                );
                return None;
            }
            Some(SystemScopeEntry {
                coords: dependency_coords(dep),
                path: path.to_string(),
            })
        })
        .collect()
}

fn dependency_coords(dep: &Dependency) -> String {
    match dep.version.as_deref() {
        Some(version) => format!("{}:{}:{}", dep.group_id, dep.artifact_id, version),
        None => format!("{}:{}", dep.group_id, dep.artifact_id),
    }
}

fn warn_system_scope_entries(entries: &[SystemScopeEntry]) {
    if !is_json_mode() {
        for entry in entries {
            eprintln!(
                "{}",
                warning(format!(
                    "System-scoped dependency {} is non-portable (path: {})",
                    entry.coords, entry.path
                ))
            );
        }
    }
}

pub(super) fn warn_system_scope_from_lock(lock: &Lockfile) {
    let mut entries = Vec::new();
    for platform in &lock.platforms {
        for package in &platform.packages {
            let Some(path) = package.system_path.as_deref() else {
                continue;
            };
            entries.push(SystemScopeEntry {
                coords: format!(
                    "{}:{}:{}",
                    package.group_id, package.artifact_id, package.version
                ),
                path: {
                    let trimmed = path.trim();
                    if trimmed.is_empty() {
                        "<unspecified>".to_string()
                    } else {
                        trimmed.to_string()
                    }
                },
            });
        }
    }
    warn_system_scope_entries(&entries);
}

#[cfg(test)]
mod tests {
    use super::system_scope_entries_from_dependencies;
    use rv_maven_model::Dependency;

    fn system_dep(coord: (&str, &str, &str), system_path: Option<&str>) -> Dependency {
        Dependency {
            group_id: coord.0.to_string(),
            artifact_id: coord.1.to_string(),
            version: Some(coord.2.to_string()),
            scope: Some("system".to_string()),
            optional: None,
            classifier: None,
            type_: None,
            exclusions: Vec::new(),
            system_path: system_path.map(str::to_string),
        }
    }

    #[test]
    fn invalid_system_path_is_skipped_in_warning_set() {
        // Missing, empty, and relative paths all defer to the resolver's
        // focused `<systemPath>` error so we don't print a generic
        // "non-portable" warning that duplicates the upcoming failure.
        let deps = vec![
            system_dep(("com.example", "missing", "1.0"), None),
            system_dep(("com.example", "empty", "1.0"), Some("   ")),
            system_dep(("com.example", "relative", "1.0"), Some("lib/foo.jar")),
        ];
        let entries = system_scope_entries_from_dependencies(&deps);
        assert!(
            entries.is_empty(),
            "expected no warning entries for invalid system-scope deps, got {entries:?}"
        );
    }

    #[test]
    fn absolute_system_path_still_warns() {
        // A correctly-configured system-scope dependency still gets the
        // non-portability warning because the resolver will accept it
        // without error.
        let abs_path = if cfg!(windows) {
            r"C:\opt\libs\tools.jar"
        } else {
            "/opt/libs/tools.jar"
        };
        let deps = vec![system_dep(("com.example", "ok", "1.0"), Some(abs_path))];
        let entries = system_scope_entries_from_dependencies(&deps);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].coords, "com.example:ok:1.0");
        assert_eq!(entries[0].path, abs_path);
    }
}
