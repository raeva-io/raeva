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
            let (url, reads) = properties.interpolate_str_reading(&repo.url, project)?;
            let (id, id_reads) = match repo.id.as_deref() {
                Some(written) => {
                    let (id, mut reads) = properties.interpolate_str_reading(written, project)?;
                    // A model value such as `${project.artifactId}` reads no
                    // property, but the id takes an expression all the same.
                    if reads.is_empty() {
                        reads.extend(expression_names(written));
                    }
                    (Some(id), reads)
                }
                None => (None, Default::default()),
            };
            let mut repo = Repository {
                id,
                url,
                url_reads: (repo.url_reads.into_iter()).chain(reads).collect(),
                id_reads: (repo.id_reads.into_iter()).chain(id_reads).collect(),
                ..repo
            };
            repo.interpolate_policies(|text| properties.interpolate_str(text, project))?;
            let environment = &project.environment;
            if let Some(var) = hidden_policy_variable(&repo, environment) {
                // An id that takes an expression may hold a secret.
                let repository = match repo.id.as_deref() {
                    Some(id) if repo.id_reads.is_empty() => {
                        format!("repository '{}'", rv_maven_types::bounded(id))
                    }
                    _ => "a repository".to_string(),
                };
                return Err(PomError::Unlockable(format!(
                    "a policy or the layout of {repository} reads the environment variable \
                     {var}, which raeva treats as unset where Maven reads its value; {}",
                    crate::environment::allow_env_fix(var),
                )));
            }
            if let Some(base) = environment.reactor_root()
                && let Some(url) =
                    crate::file_transport::directory_url(&repo.url, environment.maven_mode(), base)
            {
                repo.declared_url = Some(std::mem::replace(&mut repo.url, url));
            }
            Ok(repo)
        })
        .collect()
}

/// A variable that an `<enabled>`, update or checksum policy or the
/// `<layout>` of `repo` still reads once interpolated, as `${env.NAME}` or,
/// as Maven looks a model's names up, `${NAME}`, and that is set here but
/// hidden from POMs. A Maven 3.10 model it reads from a repository reads
/// no variable.
fn hidden_policy_variable<'a>(
    repo: &'a Repository,
    environment: &crate::ModelEnvironment,
) -> Option<&'a str> {
    if environment.is_restricted() {
        return None;
    }
    [
        &repo.layout,
        &repo.releases_enabled_text,
        &repo.snapshots_enabled_text,
        &repo.releases_update_policy,
        &repo.snapshots_update_policy,
        &repo.releases_checksum_policy,
        &repo.snapshots_checksum_policy,
    ]
    .into_iter()
    .flatten()
    .flat_map(|text| crate::properties::expression_names(text))
    .map(|name| name.strip_prefix("env.").unwrap_or(name))
    .find(|var| environment.hides_env(var))
}

/// The name in each `${...}` of `text`.
fn expression_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            break;
        };
        names.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    names
}
