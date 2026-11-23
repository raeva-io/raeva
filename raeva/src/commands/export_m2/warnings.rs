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

/// The warning that the modules' plugin models of `platform` could not be
/// read, so the export did not check their plugins without a version.
pub(super) fn plugins_unchecked(
    platform: &rv_lock::Platform,
    error: &rv_resolver::ResolveError,
) -> Warning {
    Warning::new(
        WarningCode::ExportPluginsUnchecked,
        "could not read the build plugins and extensions of the modules, so the export does not \
         check those without a version",
    )
    .with_context(json!({
        "platform": platform.to_string(),
        "reason": error.to_string(),
    }))
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
        ExportWarning::UnfinishedExport { path, repaired } => Warning::new(
            WarningCode::ExportUnfinished,
            if *repaired {
                "an earlier export-m2 into this local repository did not finish; this one repaired it"
            } else {
                "an earlier export-m2 into this local repository did not finish; run export-m2 \
                 without --dry-run to repair it"
            },
        )
        .with_context(json!({
            "m2_path": path.display().to_string(),
            "repaired": repaired,
        })),
        ExportWarning::LosingRangeVersions {
            coordinates,
            listed,
        } => Warning::new(
            WarningCode::ExportLosingRangeVersions,
            if *listed {
                "version ranges that lose mediation name no locked version; export-m2 listed \
                 the lowest version of each so `mvn -o` resolves the ranges, and Maven warns that \
                 their POMs, which raeva.lock does not pin, are missing"
            } else {
                "version ranges that lose mediation name no locked version, and export-m2 lists \
                 their versions only in a repository of its own; `mvn -o` here may fail with \
                 \"No versions available\""
            },
        )
        .with_context(json!({
            "count": coordinates.len(),
            "coordinates": coordinates.join(", "),
            "listed": listed,
        })),
        ExportWarning::UnusableRepositoryIds { ids } => Warning::new(
            WarningCode::ExportRepositoryIdUnusable,
            "export-m2 wrote no version list under repository ids no file name can carry or \
             that hold an expression; `mvn -o` may resolve a range, SNAPSHOT, RELEASE or LATEST \
             from another build's list under them",
        )
        .with_context(json!({
            "count": ids.len(),
            "ids": ids.join(", "),
        })),
        ExportWarning::RepositoryIdGuessed { origins } => Warning::new(
            WarningCode::ExportRepositoryIdGuessed,
            "raeva.lock records no repository id for these origins, so export-m2 labelled their \
             files central; `mvn -o` rejects them where it reads them under another id",
        )
        .with_context(json!({
            "count": origins.len(),
            "origins": origins.join(", "),
        })),
        // `ExportWarning` is non-exhaustive: a variant this build predates
        // still reaches the user, under a generic code.
        other => Warning::new(WarningCode::ExportWarning, other.to_string()),
    }
}
