//! Repository list interpolation for the effective project model.

use crate::PomError;
use crate::properties::{ProjectInfo, PropertyMap};
use crate::repository::Repository;

pub(crate) fn resolve_repositories(
    repos: Vec<Repository>,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Vec<Repository>, PomError> {
    repos
        .into_iter()
        .map(|repo| {
            Ok(Repository {
                root_declared: repo.root_declared,
                id: properties.interpolate_opt(repo.id.as_deref(), project)?,
                url: properties.interpolate_str(&repo.url, project)?,
                releases_enabled: repo.releases_enabled,
                snapshots_enabled: repo.snapshots_enabled,
                releases_update_policy: repo.releases_update_policy,
                snapshots_update_policy: repo.snapshots_update_policy,
                releases_checksum_policy: properties
                    .interpolate_opt(repo.releases_checksum_policy.as_deref(), project)?,
                snapshots_checksum_policy: properties
                    .interpolate_opt(repo.snapshots_checksum_policy.as_deref(), project)?,
            })
        })
        .collect()
}
