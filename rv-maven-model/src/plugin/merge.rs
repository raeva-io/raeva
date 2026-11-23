//! Maven 3.9's merge rules for plugins, as its `MavenModelMerger` and the
//! mergers built on it apply them: duplicate declarations in one POM, a
//! profile injected into its POM, a child inheriting from its parent, plugin
//! management injected into `<build><plugins>`, the default lifecycle
//! bindings added, and each execution's configuration expanded.

use indexmap::IndexMap;

use super::{BuildPlugins, ConfigNode, Plugin, PluginExecution};
use crate::Repository;
use crate::dependency::Dependency;

/// How a plugin merge treats the executions of the two sides, after the
/// merger whose rule it follows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Executions {
    /// `MavenModelMerger`: the source's executions first, those it does
    /// not inherit dropped unless it is dominant, then the target's, an
    /// execution of an id already listed merged in its place.
    Model,
    /// `ProfileModelMerger`: the target's executions first, then the
    /// profile's, merged into an execution of the same id.
    Profile,
    /// `ManagementModelMerger`: the managed executions first, every one of
    /// them, then the plugin's, merged in place.
    Management,
}

/// A list merged as `ModelMerger`'s merging list merges it: the target's
/// entries, a repeated key replacing the earlier entry in place, then each
/// source entry with a new key appended, and one with a listed key put in
/// place of it only when the source is dominant.
fn merge_list<T: Clone, K: std::hash::Hash + Eq>(
    target: Vec<T>,
    source: &[T],
    source_dominant: bool,
    key: impl Fn(&T) -> K,
) -> Vec<T> {
    if source.is_empty() {
        return target;
    }
    let mut merged: IndexMap<K, T> = IndexMap::with_capacity(target.len() + source.len());
    for item in target {
        merged.insert(key(&item), item);
    }
    for item in source {
        match merged.get_mut(&key(item)) {
            Some(existing) if source_dominant => *existing = item.clone(),
            Some(_) => {}
            None => {
                merged.insert(key(item), item.clone());
            }
        }
    }
    merged.into_values().collect()
}

fn merge_dependencies(
    target: Vec<Dependency>,
    source: &[Dependency],
    source_dominant: bool,
) -> Vec<Dependency> {
    merge_list(target, source, source_dominant, Dependency::raw_key)
}

/// `mergeConfigurationContainer_Configuration`: the dominant side's
/// configuration over the other's.
fn merge_configuration(
    target: &mut Option<ConfigNode>,
    source: Option<&ConfigNode>,
    source_dominant: bool,
) {
    let Some(source) = source else {
        return;
    };
    match target {
        Some(target) if !source_dominant => target.merge_from(source),
        _ => {
            let mut merged = source.clone();
            if let Some(recessive) = target.as_ref() {
                merged.merge_from(recessive);
            }
            *target = Some(merged);
        }
    }
}

/// A scalar the source fills when it is dominant or the target has none.
fn merge_value(target: &mut Option<String>, source: &Option<String>, source_dominant: bool) {
    if source.is_some() && (source_dominant || target.is_none()) {
        target.clone_from(source);
    }
}

/// `mergeConfigurationContainer`: `<inherited>` and `<configuration>`.
fn merge_container(
    target_inherited: &mut Option<String>,
    target_configuration: &mut Option<ConfigNode>,
    source_inherited: &Option<String>,
    source_configuration: Option<&ConfigNode>,
    source_dominant: bool,
) {
    merge_value(target_inherited, source_inherited, source_dominant);
    merge_configuration(target_configuration, source_configuration, source_dominant);
}

/// `mergePluginExecution`, with `MavenModelMerger`'s goals: the target's,
/// then the source's it lacks.
fn merge_execution(target: &mut PluginExecution, source: &PluginExecution, source_dominant: bool) {
    merge_container(
        &mut target.inherited,
        &mut target.configuration,
        &source.inherited,
        source.configuration.as_ref(),
        source_dominant,
    );
    if source_dominant {
        target.id.clone_from(&source.id);
    }
    merge_value(&mut target.phase, &source.phase, source_dominant);
    for goal in &source.goals {
        if !target.goals.contains(goal) {
            target.goals.push(goal.clone());
        }
    }
}

fn merge_executions(target: &mut Plugin, source: &Plugin, source_dominant: bool, rule: Executions) {
    if source.executions.is_empty() {
        return;
    }
    let own = std::mem::take(&mut target.executions);
    let mut merged: IndexMap<String, PluginExecution> =
        IndexMap::with_capacity(own.len() + source.executions.len());
    match rule {
        Executions::Model | Executions::Management => {
            let source_inherited = source.is_inherited();
            for execution in &source.executions {
                if rule == Executions::Management
                    || source_dominant
                    || execution.is_inherited(source_inherited)
                {
                    merged.insert(execution.id.clone(), execution.clone());
                }
            }
            for mut execution in own {
                if let Some(existing) = merged.get(&execution.id) {
                    merge_execution(&mut execution, existing, source_dominant);
                }
                merged.insert(execution.id.clone(), execution);
            }
        }
        Executions::Profile => {
            for execution in own {
                merged.insert(execution.id.clone(), execution);
            }
            for execution in &source.executions {
                match merged.get_mut(&execution.id) {
                    Some(existing) => merge_execution(existing, execution, source_dominant),
                    None => {
                        merged.insert(execution.id.clone(), execution.clone());
                    }
                }
            }
        }
    }
    target.executions = merged.into_values().collect();
}

/// `ModelMerger.mergePlugin` with the executions of `rule`. Inheritance
/// skips the configuration of a plugin the parent does not let children
/// inherit (`inherit_configuration` false).
fn merge_plugin(
    target: &mut Plugin,
    source: &Plugin,
    source_dominant: bool,
    rule: Executions,
    inherit_configuration: bool,
) {
    if inherit_configuration {
        merge_container(
            &mut target.inherited,
            &mut target.configuration,
            &source.inherited,
            source.configuration.as_ref(),
            source_dominant,
        );
    }
    if source_dominant {
        target.group_id.clone_from(&source.group_id);
        target.artifact_id.clone_from(&source.artifact_id);
    }
    merge_value(&mut target.version, &source.version, source_dominant);
    merge_value(&mut target.extensions, &source.extensions, source_dominant);
    target.dependencies = merge_dependencies(
        std::mem::take(&mut target.dependencies),
        &source.dependencies,
        source_dominant,
    );
    merge_executions(target, source, source_dominant, rule);
}

/// `DefaultModelNormalizer.mergeDuplicates`: a plugin a POM declares again
/// in its `<build><plugins>` is merged over the first declaration and takes
/// its place.
pub(crate) fn merge_duplicates(plugins: &mut Vec<Plugin>) {
    if plugins.len() < 2 {
        return;
    }
    let mut normalized: IndexMap<String, Plugin> = IndexMap::with_capacity(plugins.len());
    for mut plugin in std::mem::take(plugins) {
        let key = plugin.key();
        if let Some(first) = normalized.get(&key) {
            merge_plugin(&mut plugin, first, false, Executions::Model, true);
        }
        normalized.insert(key, plugin);
    }
    *plugins = normalized.into_values().collect();
}

/// Put the plugins in `source` before or into those of `target`, keeping
/// `target`'s order: a source plugin `target` lacks goes just before the
/// next one it shares with `target`, after the last if there is none. This
/// is the order both `ProfileModelMerger` and `InheritanceModelMerger` give.
fn interleave(
    target: Vec<Plugin>,
    source: &[Plugin],
    mut merge_into: impl FnMut(&mut Plugin, &Plugin),
) -> Vec<Plugin> {
    let mut master: IndexMap<String, Plugin> = target
        .into_iter()
        .map(|plugin| (plugin.key(), plugin))
        .collect();
    let mut predecessors: IndexMap<String, Vec<Plugin>> = IndexMap::new();
    let mut pending = Vec::new();
    for plugin in source {
        let key = plugin.key();
        match master.get_mut(&key) {
            Some(existing) => {
                merge_into(existing, plugin);
                if !pending.is_empty() {
                    predecessors.insert(key, std::mem::take(&mut pending));
                }
            }
            None => pending.push(plugin.clone()),
        }
    }
    let mut result = Vec::with_capacity(master.len() + source.len());
    for (key, plugin) in master {
        if let Some(before) = predecessors.shift_remove(&key) {
            result.extend(before);
        }
        result.push(plugin);
    }
    result.extend(pending);
    result
}

/// `DefaultProfileInjector` for the plugin parts of an active profile: its
/// plugins and managed plugins merged over the POM's, the profile winning,
/// and its plugin repositories put before the POM's.
pub(crate) fn inject_profile(
    build: &mut BuildPlugins,
    repositories: &mut Vec<Repository>,
    profile: &BuildPlugins,
    profile_repositories: &[Repository],
) {
    let inject = |own: Vec<Plugin>, injected: &[Plugin]| {
        if injected.is_empty() {
            return own;
        }
        interleave(own, injected, |existing, plugin| {
            merge_plugin(existing, plugin, true, Executions::Profile, true);
        })
    };
    build.plugins = inject(std::mem::take(&mut build.plugins), &profile.plugins);
    build.plugin_management = inject(
        std::mem::take(&mut build.plugin_management),
        &profile.plugin_management,
    );
    if !profile_repositories.is_empty() {
        *repositories = merge_repositories(profile_repositories.to_vec(), repositories);
    }
}

/// `MavenModelMerger.mergeModelBase_PluginRepositories`: the dominant list
/// keyed by id, a repeated id replacing the earlier entry in place, then
/// the recessive entries with a new id.
pub(crate) fn merge_repositories(
    dominant: Vec<Repository>,
    recessive: &[Repository],
) -> Vec<Repository> {
    let mut merged: IndexMap<Option<String>, Repository> =
        IndexMap::with_capacity(dominant.len() + recessive.len());
    for repository in dominant {
        merged.insert(repository.id.clone(), repository);
    }
    for repository in recessive {
        merged
            .entry(repository.id.clone())
            .or_insert_with(|| repository.clone());
    }
    merged.into_values().collect()
}

/// `InheritanceModelMerger`'s plugin containers: the parent's plugins a
/// child inherits, those with `<inherited>false</inherited>` dropped unless
/// they have executions, which come without their configuration and only
/// for executions that say they are inherited; the child's plugins merged
/// over them and placed as [`interleave`] places them.
fn inherit_plugins(child: Vec<Plugin>, parent: &[Plugin]) -> Vec<Plugin> {
    if parent.is_empty() {
        return child;
    }
    let inherited: Vec<Plugin> = parent
        .iter()
        .filter(|plugin| plugin.is_inherited() || !plugin.executions.is_empty())
        .map(|plugin| {
            let mut copy = Plugin::new("", "", None);
            copy.group_id.clone_from(&plugin.group_id);
            copy.artifact_id.clone_from(&plugin.artifact_id);
            merge_plugin(
                &mut copy,
                plugin,
                false,
                Executions::Model,
                plugin.is_inherited(),
            );
            copy
        })
        .collect();
    // The parent's order leads; the child's plugins are placed among them.
    interleave(inherited, &child, |parent_copy, own| {
        let mut own = own.clone();
        merge_plugin(
            &mut own,
            parent_copy,
            false,
            Executions::Model,
            parent_copy.is_inherited(),
        );
        *parent_copy = own;
    })
}

/// Merge `parent`'s plugin sections into `child`'s as Maven's inheritance
/// assembly does, and the parent's plugin repositories after the child's.
pub(crate) fn inherit(
    child: &mut BuildPlugins,
    child_repositories: &mut Vec<Repository>,
    parent: &BuildPlugins,
    parent_repositories: &[Repository],
) {
    child.plugins = inherit_plugins(std::mem::take(&mut child.plugins), &parent.plugins);
    child.plugin_management = inherit_plugins(
        std::mem::take(&mut child.plugin_management),
        &parent.plugin_management,
    );
    child.extensions = merge_list(
        std::mem::take(&mut child.extensions),
        &parent.extensions,
        false,
        |extension| (extension.group_id.clone(), extension.artifact_id.clone()),
    );
    *child_repositories =
        merge_repositories(std::mem::take(child_repositories), parent_repositories);
}

/// `DefaultPluginManagementInjector`: each plugin of `<build><plugins>`
/// takes what its managed entry adds, the plugin winning.
pub(crate) fn inject_management(plugins: &mut [Plugin], management: &[Plugin]) {
    if management.is_empty() {
        return;
    }
    let managed: IndexMap<String, &Plugin> = management
        .iter()
        .map(|plugin| (plugin.key(), plugin))
        .collect();
    for plugin in plugins {
        if let Some(managed) = managed.get(&plugin.key()) {
            merge_plugin(plugin, managed, false, Executions::Management, true);
        }
    }
}

/// `DefaultLifecycleBindingsInjector`: each default lifecycle plugin is
/// merged into the declared plugin of its key, which wins, or else added
/// after the declared plugins, from its managed entry when there is one.
pub(crate) fn inject_lifecycle(
    plugins: &mut Vec<Plugin>,
    management: &[Plugin],
    defaults: &[Plugin],
) {
    let mut merged: IndexMap<String, Plugin> = std::mem::take(plugins)
        .into_iter()
        .map(|plugin| (plugin.key(), plugin))
        .collect();
    let mut added = Vec::new();
    for default in defaults {
        let key = default.key();
        match merged.get_mut(&key) {
            Some(existing) => merge_plugin(existing, default, false, Executions::Model, true),
            None => {
                merged.insert(key.clone(), default.clone());
                added.push(key);
            }
        }
    }
    for managed in management {
        let key = managed.key();
        if !added.contains(&key) {
            continue;
        }
        let Some(default) = defaults.iter().find(|plugin| plugin.key() == key) else {
            continue;
        };
        let mut plugin = managed.clone();
        merge_plugin(&mut plugin, default, false, Executions::Model, true);
        merged.insert(key, plugin);
    }
    *plugins = merged.into_values().collect();
}

/// `DefaultPluginConfigurationExpander`: each execution's configuration
/// takes its plugin's below it.
pub(crate) fn expand_configuration(plugins: &mut [Plugin]) {
    for plugin in plugins {
        let Some(configuration) = &plugin.configuration else {
            continue;
        };
        for execution in &mut plugin.executions {
            match &mut execution.configuration {
                Some(own) => own.merge_from(configuration),
                None => execution.configuration = Some(configuration.clone()),
            }
        }
    }
}

#[cfg(test)]
mod tests;
