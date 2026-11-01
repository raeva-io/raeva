use serde_json::json;

use rv_export::{ExportFailure, ExportWarning};

use crate::error::CliError;
use crate::output::{Output, Warning, WarningCode};

/// Hand the warnings of an export to the warning summary and the JSON
/// envelope. The values in them come from POMs and raeva.lock; the summary
/// and envelope escape them when they print.
pub(super) fn report_warnings(output: &Output, warnings: &[ExportWarning]) {
    for warning in warnings {
        output.warn(warning_entry(warning));
    }
}

/// Report the warnings a failed export collected, and return its error.
pub(super) fn report_failure(output: &Output, failure: ExportFailure) -> CliError {
    report_warnings(output, &failure.warnings);
    CliError::Export(failure.error)
}

fn warning_entry(warning: &ExportWarning) -> Warning {
    match warning {
        ExportWarning::SystemScopedSkipped { coordinates } => Warning::new(
            WarningCode::ExportSystemScopedSkipped,
            "system-scoped dependencies not exported (systemPath artifacts are not in the content-addressed store)",
        )
        .with_context(json!({
            "count": coordinates.len(),
            "coordinates": coordinates.join(", "),
        })),
        ExportWarning::PermissionsNotSet { path, reason } => Warning::new(
            WarningCode::ExportPermissionsNotSet,
            "could not make an exported artifact writable by its owner",
        )
        .with_context(json!({
            "path": path.display().to_string(),
            "reason": reason,
        })),
        ExportWarning::SupportPomLimitIgnored { variable, value } => Warning::new(
            WarningCode::SettingIgnored,
            "the support-POM limit is not a positive number; using the default",
        )
        .with_context(json!({ "env": variable, "value": value })),
        ExportWarning::UntrustedClassifierOrigin {
            group_id,
            artifact_id,
            version,
            origin,
        } => Warning::new(
            WarningCode::UntrustedClassifierOrigin,
            "skipping classifier jars: raeva.lock records an origin that no configured repository, mirror or project POM declares",
        )
        .with_context(json!({
            "coordinate": format!("{group_id}:{artifact_id}:{version}"),
            "origin": origin,
        })),
        // `ExportWarning` is non-exhaustive: a variant this build predates
        // still reaches the user, under a generic code.
        other => Warning::new(WarningCode::ExportWarning, other.to_string()),
    }
}
