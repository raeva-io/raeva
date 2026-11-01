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
        .filter(|repo| !repo.url.is_empty())
        .map(|repo| {
            let mut repo = Repository {
                id: properties.interpolate_opt(repo.id.as_deref(), project)?,
                url: properties.interpolate_str(&repo.url, project)?,
                ..repo
            };
            repo.interpolate_policies(|text| properties.interpolate_str(text, project))?;
            Ok(repo)
        })
        .collect()
}
