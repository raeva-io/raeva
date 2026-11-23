//! The descriptors Maven 3.9 reads from plugin and extension jars, as far as
//! they decide which artifacts a build resolves: `META-INF/maven/plugin.xml`
//! (goal prefix and prerequisites), the lifecycle mappings
//! of `META-INF/plexus/components.xml`, and the exported artifacts of
//! `META-INF/maven/extension.xml`.

use rv_maven_types::{java_set_order, java_string_hash};
use serde::Deserialize;

use super::ConfigNode;
use crate::PomError;

/// The parts of a `plugin.xml` plugin locking reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginDescriptor {
    /// `<groupId>`, `<artifactId>` and `<version>`.
    pub coordinates: [Option<String>; 3],
    /// `<goalPrefix>`.
    pub goal_prefix: Option<String>,
    /// `<requiredJavaVersion>`, a version or range the running JDK must
    /// match before the plugin is taken for a version-less declaration.
    /// Maven 3.9.12 and 3.10.0 read no `<requiredMavenVersion>` here, only
    /// the POM's prerequisite.
    pub required_java_version: Option<String>,
    /// The `<goal>` of each `<mojo>`.
    pub goals: Vec<String>,
}

impl PluginDescriptor {
    /// Whether it names the plugin it came from, which Maven's
    /// `MavenPluginValidator` requires before it loads the plugin: its
    /// group, artifact and base version.
    pub fn names(&self, group_id: &str, artifact_id: &str, base_version: &str) -> bool {
        let [group, artifact, version] = self.coordinates.each_ref().map(Option::as_deref);
        (group, artifact, version) == (Some(group_id), Some(artifact_id), Some(base_version))
    }
}

pub(crate) fn root(xml: &str, what: &str) -> Result<ConfigNode, PomError> {
    if xml.len() > crate::Pom::MAX_SIZE {
        return Err(PomError::InvalidModel(format!(
            "{what} exceeds the 5MB limit"
        )));
    }
    let root = crate::document::root_element(xml)?;
    let mut deserializer =
        quick_xml::de::Deserializer::from_str_with_resolver(root, crate::xml::MavenEntities);
    Ok(ConfigNode::deserialize(&mut deserializer)?)
}

fn text(node: &ConfigNode, name: &str) -> Option<String> {
    node.child_value(name)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Parse a `META-INF/maven/plugin.xml`.
pub fn parse_plugin_descriptor(xml: &str) -> Result<PluginDescriptor, PomError> {
    let plugin = root(xml, "plugin.xml")?;
    Ok(PluginDescriptor {
        coordinates: ["groupId", "artifactId", "version"].map(|name| text(&plugin, name)),
        goal_prefix: text(&plugin, "goalPrefix"),
        required_java_version: text(&plugin, "requiredJavaVersion"),
        goals: (plugin.child("mojos").into_iter())
            .flat_map(|mojos| &mojos.children)
            .filter(|mojo| mojo.name == "mojo")
            .filter_map(|mojo| text(mojo, "goal"))
            .collect(),
    })
}

/// A mojo a lifecycle mapping binds to a phase, as written in the mapping:
/// `groupId:artifactId[:version]:goal`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MappedMojo {
    /// The phase.
    pub phase: String,
    /// The plugin's `groupId`.
    pub group_id: String,
    /// The plugin's `artifactId`.
    pub artifact_id: String,
    /// The version, absent when the mapping leaves it to the project or to
    /// the plugin version resolver.
    pub version: Option<String>,
    /// The goal.
    pub goal: String,
}

/// The `LifecycleMapping` components of a `META-INF/plexus/components.xml`,
/// by packaging (the role hint): the mojos of the `default` lifecycle in
/// the order Maven binds them. Maven 3.9 reads either a `<lifecycles>` list or, from
/// Maven 2 mappings, bare `<phases>`.
pub fn parse_lifecycle_mappings(xml: &str) -> Result<Vec<(String, Vec<MappedMojo>)>, PomError> {
    let set = root(xml, "components.xml")?;
    let mut mappings = Vec::new();
    let components = (set.child("components").into_iter()).flat_map(|list| &list.children);
    for component in components.filter(|component| component.name == "component") {
        if component.child_value("role")
            != Some("org.apache.maven.lifecycle.mapping.LifecycleMapping")
        {
            continue;
        }
        let Some(hint) = text(component, "role-hint") else {
            continue;
        };
        let Some(configuration) = component.child("configuration") else {
            continue;
        };
        let phases = match configuration.child("lifecycles") {
            Some(lifecycles) => (lifecycles.children.iter())
                .find(|lifecycle| lifecycle.child_value("id").is_none_or(|id| id == "default"))
                .and_then(|lifecycle| lifecycle.child("phases")),
            None => configuration.child("phases"),
        };
        // Plexus reads the phases into a HashMap, a repeated phase
        // replacing the earlier value, and Maven binds them in its order.
        let mut ordered: Vec<(&str, Option<&String>)> = Vec::new();
        for phase in phases.into_iter().flat_map(|phases| &phases.children) {
            match ordered.iter_mut().find(|(name, _)| *name == phase.name) {
                Some(entry) => entry.1 = phase.value.as_ref(),
                None => ordered.push((&phase.name, phase.value.as_ref())),
            }
        }
        java_set_order(&mut ordered, |(name, _)| java_string_hash(name));
        let mut mojos = Vec::new();
        for (phase, value) in ordered {
            let Some(value) = value else {
                continue;
            };
            for spec in value
                .split(',')
                .map(str::trim)
                .filter(|spec| !spec.is_empty())
            {
                // Maven splits on `:` without empty parts and ignores, with
                // a warning, a spec that is not `g:a[:v]:goal`.
                let parts: Vec<&str> = (spec.split(':').map(str::trim))
                    .filter(|part| !part.is_empty())
                    .collect();
                let (group_id, artifact_id, version, goal) = match parts[..] {
                    [group_id, artifact_id, goal] => (group_id, artifact_id, None, goal),
                    [group_id, artifact_id, version, goal] => {
                        (group_id, artifact_id, Some(version), goal)
                    }
                    _ => continue,
                };
                mojos.push(MappedMojo {
                    phase: phase.to_string(),
                    group_id: group_id.to_string(),
                    artifact_id: artifact_id.to_string(),
                    version: version.map(str::to_string),
                    goal: goal.to_string(),
                });
            }
        }
        mappings.push((hint, mojos));
    }
    Ok(mappings)
}

/// The `<exportedArtifacts>` of a `META-INF/maven/extension.xml`, each
/// `groupId:artifactId`, which Maven filters out of the plugin class paths
/// the extension's realm then provides.
pub fn parse_exported_artifacts(xml: &str) -> Result<Vec<String>, PomError> {
    let extension = root(xml, "extension.xml")?;
    Ok((extension.child("exportedArtifacts").into_iter())
        .flat_map(|list| &list.children)
        .filter_map(|artifact| artifact.value.clone())
        .filter(|artifact| !artifact.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_plugin_descriptor() {
        let descriptor = parse_plugin_descriptor(
            "<?xml version='1.0'?><plugin><groupId>org.apache.maven.plugins</groupId>\
             <artifactId>maven-javadoc-plugin</artifactId><version>3.6.3</version>\
             <goalPrefix>javadoc</goalPrefix>\
             <requiredMavenVersion>3.6.3</requiredMavenVersion>\
             <requiredJavaVersion>1.8</requiredJavaVersion><mojos>\
             <mojo><goal>jar</goal><phase>package</phase>\
             <executePhase>generate-sources</executePhase></mojo>\
             <mojo><goal>javadoc</goal></mojo></mojos></plugin>",
        )
        .unwrap();
        assert_eq!(descriptor.goal_prefix.as_deref(), Some("javadoc"));
        assert_eq!(descriptor.required_java_version.as_deref(), Some("1.8"));
        assert_eq!(descriptor.goals, ["jar", "javadoc"]);
        assert!(descriptor.names("org.apache.maven.plugins", "maven-javadoc-plugin", "3.6.3"));
        assert!(!descriptor.names("org.apache.maven.plugins", "maven-javadoc-plugin", "3.6.2"));
    }

    /// A goal spec that is not `g:a[:v]:goal` once empty parts are gone is
    /// left out, as Maven 3.9.12 and 3.10.0 leave it out with a warning.
    #[test]
    fn reads_lifecycle_mappings_of_both_shapes() {
        let mappings = parse_lifecycle_mappings(
            "<component-set><components>\
             <component><role>org.apache.maven.lifecycle.mapping.LifecycleMapping</role>\
             <role-hint>jlink</role-hint><configuration><lifecycles><lifecycle>\
             <id>default</id><phases>\
             <package>org.apache.maven.plugins:maven-jlink-plugin:3.2.0:jlink</package>\
             <install>org.apache.maven.plugins:maven-install-plugin:install</install>\
             </phases></lifecycle></lifecycles></configuration></component>\
             <component><role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
             <role-hint>jlink</role-hint></component>\
             <component><role>org.apache.maven.lifecycle.mapping.LifecycleMapping</role>\
             <role-hint>bundle</role-hint><configuration><phases>\
             <compile>a:b:1:compile, compile, c:d:2:x, e::f:g, h:i::j</compile></phases>\
             </configuration></component>\
             </components></component-set>",
        )
        .unwrap();
        let summary: Vec<String> = (mappings.iter())
            .flat_map(|(hint, mojos)| {
                mojos.iter().map(move |mojo| {
                    format!(
                        "{hint} {} {}:{}:{}:{}",
                        mojo.phase,
                        mojo.group_id,
                        mojo.artifact_id,
                        mojo.version.as_deref().unwrap_or("-"),
                        mojo.goal
                    )
                })
            })
            .collect();
        assert_eq!(
            summary,
            [
                "jlink package org.apache.maven.plugins:maven-jlink-plugin:3.2.0:jlink",
                "jlink install org.apache.maven.plugins:maven-install-plugin:-:install",
                "bundle compile a:b:1:compile",
                "bundle compile c:d:2:x",
                "bundle compile e:f:-:g",
                "bundle compile h:i:-:j",
            ]
        );
    }

    #[test]
    fn reads_exported_artifacts() {
        assert_eq!(
            parse_exported_artifacts(
                "<extension><exportedPackages><exportedPackage>a</exportedPackage>\
                 </exportedPackages><exportedArtifacts>\
                 <exportedArtifact>org.example:api</exportedArtifact>\
                 </exportedArtifacts></extension>"
            )
            .unwrap(),
            ["org.example:api"]
        );
    }
}
