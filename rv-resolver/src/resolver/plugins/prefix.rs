//! Maven's plugin prefix resolver: a goal's prefix names the plugin whose
//! group metadata (`<groupId>/maven-metadata.xml`) lists it, searched in
//! the groups of [`Planner::prefix_candidates`] and, in each, the plugin
//! repositories in order, or the descriptor of a project plugin has it.

use std::collections::BTreeSet;

use rv_maven_model::{EffectivePlugins, Plugin};
use rv_maven_types::MavenMode;
use rv_repo::{RepoError, Repository};

use super::PluginMetadata;
use super::request::Planner;
use super::versions::{stops_listing, warn_skipped};
use crate::error::{ResolveError, Result};

impl Planner<'_> {
    /// The `groupId` and `artifactId` of the plugin `prefix` names for
    /// `module` with `model`, recorded for the export's group metadata.
    pub(super) async fn resolve_prefix(
        &mut self,
        module: &str,
        prefix: &str,
        model: &EffectivePlugins,
        repos: &[Repository],
    ) -> Result<(String, String)> {
        let groups = self.resolver().ctx.config.plugin_groups();
        let candidates = Self::prefix_candidates(model, groups);
        // The project's plugins decide too, those of the plugin groups among
        // them.
        let declared: Vec<_> = (model.plugins.iter())
            .map(|plugin| ("plugin", plugin.key(), &plugin.version))
            .chain(
                (model.plugin_management.iter())
                    .map(|plugin| ("managed", plugin.key(), &plugin.version)),
            )
            .collect();
        let cache_key = format!("{prefix} {candidates:?} {repos:?} {declared:?}");
        if let Some(found) = self.prefixes.get(&cache_key) {
            return Ok(found.clone());
        }
        let declared = || model.plugins.iter().chain(&model.plugin_management);
        let found = match self.resolver().ctx.config.lock.maven.mode {
            // Maven 3.10.0 asks the project first: the declared and managed
            // plugins whose artifactId holds the prefix, then the other
            // declared ones, managed ones not among them.
            MavenMode::Maven310 => {
                let mut plugins: Vec<&Plugin> = Vec::new();
                let named = declared().filter(|plugin| plugin.artifact_id.contains(prefix));
                for plugin in named.chain(&model.plugins) {
                    if !plugins.iter().any(|known| known.key() == plugin.key()) {
                        plugins.push(plugin);
                    }
                }
                match (self.prefix_from_project(module, prefix, plugins, model, repos)).await? {
                    Some(found) => Some(found),
                    None => {
                        self.prefix_from_metadata(prefix, &candidates, repos)
                            .await?
                    }
                }
            }
            // Maven 3.9.12 asks the project's plugins only when no group
            // metadata lists the prefix.
            MavenMode::Maven39 => match self
                .prefix_from_metadata(prefix, &candidates, repos)
                .await?
            {
                Some(found) => Some(found),
                None => {
                    let plugins = declared().collect();
                    (self.prefix_from_project(module, prefix, plugins, model, repos)).await?
                }
            },
        };
        let found = found.ok_or_else(|| ResolveError::ArtifactNotFound {
            dropped_repos: Vec::new(),
            coord: format!("plugin prefix {prefix}"),
            searched: Vec::new(),
            classifier_like: None,
        })?;
        self.prefixes.insert(cache_key, found.clone());
        Ok(found)
    }

    /// The plugin the group metadata of `candidates` lists under `prefix`.
    async fn prefix_from_metadata(
        &mut self,
        prefix: &str,
        candidates: &[(String, Option<BTreeSet<String>>)],
        repos: &[Repository],
    ) -> Result<Option<(String, String)>> {
        let client = (self.resolver().ctx.client.as_ref()).ok_or(ResolveError::NoRepositories)?;
        for (group_id, artifacts) in candidates {
            for repo in repos {
                let metadata = match client.fetch_group_metadata(repo, group_id).await {
                    Ok(metadata) => metadata,
                    Err(error) if stops_listing(&error) => {
                        return Err(ResolveError::Repo {
                            coord: Some(group_id.clone()),
                            source: Box::new(error),
                            searched: Vec::new(),
                        });
                    }
                    Err(
                        RepoError::NotFound(_)
                        | RepoError::ReleasesDisabled { .. }
                        | RepoError::BlockedMirror(_),
                    ) => continue,
                    Err(error) => {
                        let repo = client.effective_repository(repo);
                        warn_skipped(&repo, group_id, &error.to_string());
                        continue;
                    }
                };
                let found = (metadata.plugins.iter()).find_map(|(artifact_id, named)| {
                    let artifact_id = artifact_id.as_ref()?;
                    (named.as_deref() == Some(prefix)
                        && (artifacts.as_ref()).is_none_or(|names| names.contains(artifact_id)))
                    .then_some(artifact_id)
                });
                if let Some(artifact_id) = found {
                    self.metadata.insert(PluginMetadata {
                        group_id: group_id.clone(),
                        repo_url: repo.url.clone(),
                        repo_id: repo.id.clone().unwrap_or_default(),
                        prefix: prefix.to_string(),
                        artifact_id: artifact_id.clone(),
                    });
                    return Ok(Some((group_id.clone(), artifact_id.clone())));
                }
            }
        }
        Ok(None)
    }

    /// The first of `plugins` of `module` whose descriptor names it and has
    /// the goal prefix `prefix`. One without a version takes the one Maven resolves
    /// for it first, and is skipped when it has none.
    async fn prefix_from_project(
        &mut self,
        module: &str,
        prefix: &str,
        plugins: Vec<&Plugin>,
        model: &EffectivePlugins,
        repos: &[Repository],
    ) -> Result<Option<(String, String)>> {
        for plugin in plugins {
            let versioned = self
                .with_version(module, plugin.clone(), model, repos)
                .await;
            let version = match versioned {
                Ok(versioned) => versioned.version.unwrap_or_default(),
                Err(
                    ResolveError::ArtifactNotFound { .. } | ResolveError::VersionNotFound { .. },
                ) => {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let descriptor = (self.resolver())
                .plugin_descriptor(&plugin.group_id, &plugin.artifact_id, &version, repos)
                .await?;
            // Maven skips a plugin whose descriptor names another.
            let base = rv_maven_types::snapshot_base_version(&version).unwrap_or(version);
            if descriptor.is_some_and(|descriptor| {
                descriptor.names(&plugin.group_id, &plugin.artifact_id, &base)
                    && descriptor.goal_prefix.as_deref() == Some(prefix)
            }) {
                return Ok(Some((plugin.group_id.clone(), plugin.artifact_id.clone())));
            }
        }
        Ok(None)
    }
}
