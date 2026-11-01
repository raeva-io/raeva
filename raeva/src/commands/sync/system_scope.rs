//! Warnings for `system`-scope dependencies, which tie a build to a file
//! outside any repository. The warning names the file as `raeva.lock` records
//! it, after interpolation, such as `lib/tools.jar` for
//! `${project.basedir}/lib/tools.jar`.

use std::collections::BTreeSet;

use rv_lock::Lockfile;

/// Warns once for each system file `lock` records, however many platforms
/// and modules record it.
pub(super) fn warn_system_scope_from_lock(lock: &Lockfile) {
    let mut seen = BTreeSet::new();
    let packages = lock
        .platforms
        .iter()
        .flat_map(|platform| &platform.modules)
        .flat_map(|module| &module.packages);
    for package in packages {
        let Some(path) = package.system_path.as_deref() else {
            continue;
        };
        let coords = package.coordinate.gav.to_string();
        let path = match path.trim() {
            "" => "<unspecified>".to_string(),
            trimmed => trimmed.to_string(),
        };
        if seen.insert((coords.clone(), path.clone())) {
            tracing::warn!(
                sec_code = "SYSTEM_SCOPE",
                coordinate = %coords,
                path = %path,
                "system-scoped dependency {coords} is non-portable"
            );
        }
    }
}
