use std::collections::HashSet;

use rv_config::{Config, UpdatePolicy};
use rv_lock::{LockArtifact, LockOrigins, Lockfile};
use rv_repo::Repository;

use crate::commands::lock_inputs::{ReactorModel, frozen_models_match};

/// Whether a freshness check must resolve again: model drift, or an origin
/// that configuration and the local POMs do not declare. Like `--frozen`, it
/// never resolves for a SNAPSHOT update policy: the locked builds stand.
pub(crate) fn lock_needs_fresh_resolution(
    lock: &Lockfile,
    config: &Config,
    models: &[ReactorModel],
) -> bool {
    !frozen_models_match(lock, models) || lock_references_unconfigured_origin(lock, config, models)
}

/// Whether a plain sync must resolve again to look for newer SNAPSHOT
/// builds: the lock is as old as the shortest update interval of a
/// repository a locked SNAPSHOT may come from. The lockfile's modification
/// time stands for the time of the last check, as the local repository's
/// does for Maven.
pub(super) fn lock_requires_snapshot_refresh(
    lock: &Lockfile,
    config: &Config,
    models: &[ReactorModel],
) -> bool {
    let written = config.lock_path.metadata().and_then(|m| m.modified()).ok();
    let lockfile_age_secs = written
        .and_then(|modified| modified.elapsed().ok())
        .map(|elapsed| elapsed.as_secs() as i64)
        // Treat missing/unreadable mtime as "infinitely old" so a configured
        // TTL fires and we re-fetch SNAPSHOT metadata.
        .unwrap_or(i64::MAX);
    let written = written.map_or_else(chrono::Local::now, chrono::DateTime::from);

    let origins = LockOrigins::for_root(&config.project_root);
    let default_ttl = UpdatePolicy::default().ttl_secs();
    if models.is_empty() {
        return lock.snapshot_refresh_due(
            &origins,
            lockfile_age_secs,
            default_ttl,
            &snapshot_policies(config, &written, []),
        );
    }
    models.iter().any(|model| {
        let config = config.for_platforms([(
            model.platform.os(),
            model.platform.arch(),
            model.platform.jdk(),
        )]);
        let Some(platform) = lock.platforms.iter().find(|p| p.platform == model.platform) else {
            return false;
        };
        model.workspace.modules().iter().any(|module| {
            let Some(locked) = platform.modules.iter().find(|m| m.path == module.pom_path) else {
                return false;
            };
            let coordinates: HashSet<_> = locked.packages.iter().map(|p| &p.coordinate).collect();
            let rows = (platform.artifacts.iter())
                .filter(|a| coordinates.contains(&a.coordinate))
                .flat_map(LockArtifact::versioned_origins);
            rv_lock::drift::snapshot_refresh_due(
                rows.chain(platform.support_files()),
                &origins,
                lockfile_age_secs,
                default_ttl,
                &snapshot_policies(
                    &config,
                    &written,
                    module
                        .descriptor
                        .repositories
                        .iter()
                        .filter(|repo| repo.root_declared),
                ),
            )
        })
    })
}

fn snapshot_policies<'a>(
    config: &Config,
    written: &chrono::DateTime<chrono::Local>,
    declared: impl IntoIterator<Item = &'a rv_maven_model::Repository>,
) -> Vec<(String, i64)> {
    let declared: Vec<_> = declared.into_iter().collect();
    let admitted: HashSet<_> = rv_repo::RepositoryPolicy::screen(
        config,
        declared.iter().map(|repo| Repository::from(*repo)),
        rv_repo::Declaration::LocalPom,
    )
    .admitted
    .into_iter()
    .map(|repo| (repo.url, repo.id))
    .collect();
    let configured = config.repositories();
    // Defaults are searched after the POMs' repositories, so a POM
    // declaration under their id replaces them.
    let (own, defaults) =
        configured.split_at(configured.len() - config.default_repositories().len());
    let as_configured = |repo: &rv_config::RepoConfig| (Repository::from(repo), false, true);
    let mut seen = HashSet::new();
    own.iter()
        .map(as_configured)
        .chain(declared.into_iter().map(|repo| {
            let unresolved = repo.snapshot_policy_has_expression();
            let repo = Repository::from(repo);
            let admitted = admitted.contains(&(repo.url.clone(), repo.id.clone()));
            (repo, unresolved, admitted)
        }))
        .chain(defaults.iter().map(as_configured))
        // As in resolution, the first declaration of an id holds it, a
        // refused one too, before enablement counts. An unresolved snapshot
        // policy needs resolution instead of the parsed default.
        .filter(|(repo, _, _)| {
            seen.insert(match repo.id.as_deref().filter(|id| !id.is_empty()) {
                Some(id) => (None, Some(id.to_string())),
                None => (Some(repo.url.clone()), None),
            })
        })
        .filter(|(repo, unresolved, admitted)| *admitted && (repo.snapshots_enabled || *unresolved))
        .map(|(repo, unresolved, _)| {
            (
                repo.url,
                if unresolved {
                    0
                } else {
                    rv_repo::fresh_secs(repo.snapshots_update_policy, written)
                },
            )
        })
        .collect()
}

/// Check whether configuration or the already loaded local model declares the
/// lock's recorded URLs. Transitive allowlists do not declare root repositories;
/// those origins still require model resolution to establish their provenance.
/// The lock records declared repositories, never mirrors, so a mirror change
/// leaves every recorded URL matched.
pub(super) fn lock_references_unconfigured_origin(
    lock: &Lockfile,
    config: &Config,
    models: &[ReactorModel],
) -> bool {
    lock.platforms.iter().any(|entry| {
        let config = config.for_platforms([(
            entry.platform.os(),
            entry.platform.arch(),
            entry.platform.jdk(),
        )]);
        let configured: Vec<_> = config
            .repositories()
            .iter()
            .map(|repo| repo.url.clone())
            .collect();
        let declared: Vec<_> = models
            .iter()
            .filter(|model| model.platform == entry.platform)
            .map(|model| {
                (
                    model.platform.clone(),
                    model.declared_repositories().map(|repo| repo.url).collect(),
                )
            })
            .collect();
        let selected = lock
            .select_platforms(std::slice::from_ref(&entry.platform))
            .expect("recorded platform");
        selected
            .undeclared_origin(
                &LockOrigins::for_root(&config.project_root),
                &configured,
                &declared,
            )
            .is_some()
    })
}
