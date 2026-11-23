use std::collections::HashSet;

use rv_config::{Config, UpdatePolicy};
use rv_lock::{LockArtifact, LockOrigins, Lockfile, Platform};
use rv_repo::Repository;
use rv_store::metadata_cache::SnapshotCheck;

use crate::commands::lock_inputs::{ReactorModel, frozen_models_match, reads_hidden_env};

/// Whether a freshness check must resolve again: model drift, an origin
/// that configuration and the local POMs do not declare, or a recorded
/// variable now set but hidden. Like `--frozen`, it never resolves for a
/// SNAPSHOT update policy: the locked builds stand.
pub(crate) fn lock_needs_fresh_resolution(
    lock: &Lockfile,
    config: &Config,
    models: &[ReactorModel],
) -> bool {
    !frozen_models_match(lock, models)
        || lock_references_unconfigured_origin(lock, config, models)
        || reads_hidden_env(config, lock)
}

/// Whether a plain sync must resolve again to look for newer SNAPSHOT
/// builds: the last check of a platform, `checked` in Unix seconds, is as
/// old as the shortest update interval of a repository a locked SNAPSHOT of
/// that platform may come from. A platform never checked, or checked in the
/// future by a clock that ran ahead, is due.
pub(super) fn lock_requires_snapshot_refresh(
    lock: &Lockfile,
    config: &Config,
    models: &[ReactorModel],
    checked: impl Fn(&Platform) -> Option<SnapshotCheck>,
) -> bool {
    let now = chrono::Local::now();
    // The age of a platform's last check, and when it was, which a `daily`
    // policy counts from.
    let since = |platform: &Platform| {
        checked(platform)
            .map(|check| check.checked_at)
            .filter(|at| *at <= now.timestamp())
            .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
            .map_or((i64::MAX, now), |at| {
                let at = at.with_timezone(&chrono::Local);
                ((now - at).num_seconds(), at)
            })
    };
    // A row a resolution took from the cache may be older than the check,
    // and under a longer policy than the shortest one, so it is due by its
    // own expiry.
    let rows_due = |platform: &Platform| {
        checked(platform).is_some_and(|check| check.rows.due(now.timestamp()))
    };
    if lock.platforms.iter().any(|entry| rows_due(&entry.platform)) {
        return true;
    }

    let origins = LockOrigins::for_root(&config.project_root);
    let default_ttl =
        |at: &chrono::DateTime<chrono::Local>| rv_repo::fresh_secs(UpdatePolicy::default(), at);
    if models.is_empty() {
        return lock.platforms.iter().any(|entry| {
            let (age, at) = since(&entry.platform);
            rv_lock::drift::snapshot_refresh_due(
                entry.locked_files(),
                &origins,
                age,
                default_ttl(&at),
                &snapshot_policies(config, &at, [], false),
            ) || (entry.modules.iter().any(snapshot_extension) && age >= default_ttl(&at))
        });
    }
    models.iter().any(|model| {
        let (age, at) = since(&model.platform);
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
            // A SNAPSHOT build extension is checked by the plugin
            // repositories' policies; the lock records none of its origins.
            if snapshot_extension(locked) {
                let declared = (module.descriptor.plugin_repositories.iter())
                    .filter(|repo| repo.root_declared);
                let ttl = (snapshot_policies(&config, &at, declared, true).into_iter())
                    .map(|(_, ttl)| ttl)
                    .min();
                if age >= ttl.unwrap_or_else(|| default_ttl(&at)) {
                    return true;
                }
            }
            let coordinates: HashSet<_> = (locked.packages.iter())
                .filter_map(rv_lock::LockModulePackage::repository_file)
                .collect();
            let rows = (platform.artifacts.iter())
                .filter(|a| coordinates.contains(&a.coordinate))
                .flat_map(LockArtifact::versioned_origins);
            // The parents and BOMs the module read, and those no module
            // lists.
            let support = (platform.support_poms.iter())
                .filter(|(coord, _)| {
                    locked.support_poms.contains(coord)
                        || !(platform.modules.iter())
                            .any(|module| module.support_poms.contains(coord))
                })
                .filter_map(|(coord, pin)| {
                    let (_, _, version) = rv_lock::split_support_pom_coord(coord)?;
                    Some((version, pin.repo_url.as_str()))
                });
            rv_lock::drift::snapshot_refresh_due(
                rows.chain(support),
                &origins,
                age,
                default_ttl(&at),
                &snapshot_policies(
                    &config,
                    &at,
                    module
                        .descriptor
                        .repositories
                        .iter()
                        .filter(|repo| repo.root_declared),
                    false,
                ),
            )
        })
    })
}

/// Whether `module` pins a build extension at a SNAPSHOT build, which
/// Maven takes from the metadata of the plugin repositories.
fn snapshot_extension(module: &rv_lock::LockModule) -> bool {
    (module.extensions.iter()).any(|jar| rv_maven_types::is_snapshot_version(jar.gav.version()))
}

/// The snapshot update interval of each snapshot-enabled repository a
/// module resolves from: its dependency repositories, or with `plugins` its
/// plugin repositories, `declared` by its POMs.
fn snapshot_policies<'a>(
    config: &Config,
    written: &chrono::DateTime<chrono::Local>,
    declared: impl IntoIterator<Item = &'a rv_maven_model::Repository>,
    plugins: bool,
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
    // declaration under their id replaces them. Plugin repositories come
    // from the settings.xml profiles, the POMs, then Maven's request.
    let (own, defaults) = match plugins {
        true => (
            config.profile_plugin_repositories(),
            config.plugin_repositories(),
        ),
        false => configured.split_at(configured.len() - config.default_repositories().len()),
    };
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
        // Plugin rows come from the settings.xml plugin repositories too,
        // and from the POMs'.
        let configured: Vec<_> = (config.all_repositories())
            .map(|repo| repo.url.clone())
            .collect();
        let declared: Vec<_> = models
            .iter()
            .filter(|model| model.platform == entry.platform)
            .map(|model| {
                let plugins = model.declared_plugin_repositories();
                (
                    model.platform.clone(),
                    (model.declared_repositories().chain(plugins))
                        .map(|repo| repo.url)
                        .collect(),
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
