//! What Maven adds to every model before it builds: the default lifecycle
//! bindings of each packaging, from maven-core 3.9.12's
//! `META-INF/plexus/default-bindings.xml` and the `clean` and `site`
//! lifecycles of its `components.xml` or from maven-core 3.10.0's lifecycle
//! providers, and the plugin parts of the super POM.

use std::collections::BTreeSet;

use super::{Plugin, PluginExecution};
use rv_maven_types::MavenMode;

use crate::activation::{Activation, ActivationProperty};
use crate::{ActivationContext, HostInput, PomError, Repository};

/// A mojo a lifecycle binds to a phase by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LifecycleMojo {
    /// The phase the goal runs in.
    pub phase: &'static str,
    /// The plugin's `groupId`.
    pub group_id: &'static str,
    /// The plugin's `artifactId`.
    pub artifact_id: &'static str,
    /// The plugin version the binding names.
    pub version: &'static str,
    /// The goal.
    pub goal: &'static str,
}

const fn mojo(
    phase: &'static str,
    artifact_id: &'static str,
    version: &'static str,
    goal: &'static str,
) -> LifecycleMojo {
    LifecycleMojo {
        phase,
        group_id: super::DEFAULT_PLUGIN_GROUP,
        artifact_id,
        version,
        goal,
    }
}

/// The plugin versions a Maven line binds by default.
struct Versions {
    clean: &'static str,
    site: &'static str,
    resources: &'static str,
    compiler: &'static str,
    surefire: &'static str,
    jar: &'static str,
    install: &'static str,
    deploy: &'static str,
    ejb: &'static str,
    plugin: &'static str,
    war: &'static str,
    rar: &'static str,
    ear: &'static str,
}

const MAVEN_39: Versions = Versions {
    clean: "3.2.0",
    site: "3.12.1",
    resources: "3.3.1",
    compiler: "3.13.0",
    surefire: "3.2.5",
    jar: "3.4.1",
    install: "3.1.2",
    deploy: "3.1.2",
    ejb: "3.2.1",
    plugin: "3.13.1",
    war: "3.4.0",
    rar: "3.0.0",
    ear: "3.3.0",
};

/// maven-core 3.10.0's `plugin-versions.properties`.
const MAVEN_310: Versions = Versions {
    clean: "3.5.0",
    site: "3.22.0",
    resources: "3.5.0",
    compiler: "3.16.0",
    surefire: "3.6.0",
    jar: "3.5.1",
    install: "3.2.0",
    deploy: "3.2.0",
    ejb: "3.3.0",
    plugin: "3.16.0",
    war: "3.5.1",
    rar: "3.1.0",
    ear: "3.4.0",
};

/// The mojos Maven binds by default for `packaging`, over its `clean`,
/// `default` and `site` lifecycles in that order and in the order it visits
/// each one's phases, or `None` for a packaging only a build extension can
/// map.
///
/// Maven reads each mapping's phases from a `HashMap`, so its bindings come
/// in that map's order, which this keeps: it decides which plugin comes
/// first and the order of a plugin's executions. The `jar` mapping, with
/// `package` bound to the packager, is shared by `ejb`, `war`, `rar` and
/// `maven-plugin`, which adds its descriptor goal in `process-classes`.
/// Maven 3.10 sizes the `ear` map for its five phases, which orders them
/// otherwise.
pub(crate) fn default_lifecycle_bindings(
    packaging: &str,
    mode: MavenMode,
) -> Option<Vec<LifecycleMojo>> {
    let v = versions(mode);
    let java = |packager: LifecycleMojo, process_classes: Option<LifecycleMojo>| {
        [
            mojo(
                "process-test-resources",
                "maven-resources-plugin",
                v.resources,
                "testResources",
            ),
            packager,
            mojo("compile", "maven-compiler-plugin", v.compiler, "compile"),
            mojo("test", "maven-surefire-plugin", v.surefire, "test"),
            mojo("install", "maven-install-plugin", v.install, "install"),
            mojo(
                "process-resources",
                "maven-resources-plugin",
                v.resources,
                "resources",
            ),
        ]
        .into_iter()
        .chain(process_classes)
        .chain([
            mojo(
                "test-compile",
                "maven-compiler-plugin",
                v.compiler,
                "testCompile",
            ),
            mojo("deploy", "maven-deploy-plugin", v.deploy, "deploy"),
        ])
        .collect::<Vec<_>>()
    };
    let package = |artifact_id, version, goal| mojo("package", artifact_id, version, goal);
    let default = match packaging {
        "pom" => vec![
            mojo("install", "maven-install-plugin", v.install, "install"),
            mojo("deploy", "maven-deploy-plugin", v.deploy, "deploy"),
        ],
        "jar" => java(package("maven-jar-plugin", v.jar, "jar"), None),
        "ejb" => java(package("maven-ejb-plugin", v.ejb, "ejb"), None),
        "maven-plugin" => java(
            package("maven-jar-plugin", v.jar, "jar"),
            Some(mojo(
                "process-classes",
                "maven-plugin-plugin",
                v.plugin,
                "descriptor",
            )),
        ),
        "war" => java(package("maven-war-plugin", v.war, "war"), None),
        "rar" => java(package("maven-rar-plugin", v.rar, "rar"), None),
        "ear" => {
            let generate = mojo(
                "generate-resources",
                "maven-ear-plugin",
                v.ear,
                "generate-application-xml",
            );
            let package = package("maven-ear-plugin", v.ear, "ear");
            let install = mojo("install", "maven-install-plugin", v.install, "install");
            let resources = mojo(
                "process-resources",
                "maven-resources-plugin",
                v.resources,
                "resources",
            );
            let deploy = mojo("deploy", "maven-deploy-plugin", v.deploy, "deploy");
            match mode {
                MavenMode::Maven39 => vec![generate, package, install, resources, deploy],
                MavenMode::Maven310 => vec![generate, resources, package, install, deploy],
            }
        }
        _ => return None,
    };
    let (clean, site) = clean_and_site(mode);
    Some(std::iter::once(clean).chain(default).chain(site).collect())
}

fn versions(mode: MavenMode) -> &'static Versions {
    match mode {
        MavenMode::Maven39 => &MAVEN_39,
        MavenMode::Maven310 => &MAVEN_310,
    }
}

/// The `clean` and `site` lifecycles' default bindings.
fn clean_and_site(mode: MavenMode) -> (LifecycleMojo, [LifecycleMojo; 2]) {
    let v = versions(mode);
    (
        mojo("clean", "maven-clean-plugin", v.clean, "clean"),
        [
            mojo("site", "maven-site-plugin", v.site, "site"),
            mojo("site-deploy", "maven-site-plugin", v.site, "deploy"),
        ],
    )
}

/// The plugins of [`default_lifecycle_bindings`], each with an execution
/// `default-<goal>` per goal, as maven-core's `DefaultLifecyclePluginAnalyzer`
/// builds them. A plugin bound twice keeps the first version.
pub(crate) fn lifecycle_plugins(packaging: &str, mode: MavenMode) -> Option<Vec<Plugin>> {
    let bindings = default_lifecycle_bindings(packaging, mode)?;
    Some(bound_plugins(bindings.iter().map(|mojo| {
        (
            mojo.phase,
            mojo.group_id,
            mojo.artifact_id,
            Some(mojo.version),
            mojo.goal,
        )
    })))
}

/// The plugins a build extension's lifecycle mapping of the `default`
/// lifecycle binds, with the `clean` and `site` lifecycles' defaults
/// around them, as for [`lifecycle_plugins`]. A mapping may leave a
/// version out.
pub(crate) fn mapped_lifecycle_plugins(
    mapping: &[super::MappedMojo],
    mode: MavenMode,
) -> Vec<Plugin> {
    let defaults = |mojos: &[LifecycleMojo]| {
        (mojos.iter())
            .map(|mojo| {
                (
                    mojo.phase,
                    mojo.group_id,
                    mojo.artifact_id,
                    Some(mojo.version),
                    mojo.goal,
                )
            })
            .collect::<Vec<_>>()
    };
    let (clean, site) = clean_and_site(mode);
    let mapped = mapping.iter().map(|mojo| {
        (
            mojo.phase.as_str(),
            mojo.group_id.as_str(),
            mojo.artifact_id.as_str(),
            mojo.version.as_deref(),
            mojo.goal.as_str(),
        )
    });
    bound_plugins(
        (defaults(&[clean]).into_iter())
            .chain(mapped)
            .chain(defaults(&site)),
    )
}

fn bound_plugins<'a>(
    mojos: impl Iterator<Item = (&'a str, &'a str, &'a str, Option<&'a str>, &'a str)>,
) -> Vec<Plugin> {
    let mut plugins: Vec<Plugin> = Vec::new();
    for (phase, group_id, artifact_id, version, goal) in mojos {
        let position = (plugins.iter())
            .position(|plugin| plugin.group_id == group_id && plugin.artifact_id == artifact_id);
        let plugin = match position {
            Some(position) => {
                let plugin = &mut plugins[position];
                if plugin.version.is_none() {
                    plugin.version = version.map(str::to_string);
                }
                plugin
            }
            None => {
                plugins.push(Plugin::new(group_id, artifact_id, version));
                plugins.last_mut().expect("just pushed")
            }
        };
        let base = format!("default-{goal}");
        let mut id = base.clone();
        let mut index = 1;
        while plugin.executions.iter().any(|execution| execution.id == id) {
            id = format!("{base}-{index}");
            index += 1;
        }
        let execution = PluginExecution::new(&id, Some(phase), &[goal]);
        plugin.executions.push(execution);
    }
    plugins
}

/// The super POM's `<pluginManagement>`: Maven 3.10's has none.
pub(crate) fn super_pom_plugin_management(mode: MavenMode) -> Vec<Plugin> {
    if mode == MavenMode::Maven310 {
        return Vec::new();
    }
    [
        ("maven-antrun-plugin", "3.1.0"),
        ("maven-assembly-plugin", "3.7.1"),
        ("maven-dependency-plugin", "3.7.0"),
        ("maven-release-plugin", "3.0.1"),
    ]
    .into_iter()
    .map(|(artifact_id, version)| {
        Plugin::new(super::DEFAULT_PLUGIN_GROUP, artifact_id, Some(version))
    })
    .collect()
}

/// The plugins of Maven 3.9's super POM `release-profile`, which
/// `performRelease=true` or `-P release-profile` activates, and the host
/// values its condition read.
pub(crate) fn super_pom_release_plugins(
    ctx: &ActivationContext,
) -> Result<(Vec<Plugin>, BTreeSet<HostInput>), PomError> {
    const ID: &str = "release-profile";
    let selected = |ids: &[String]| ids.iter().any(|id| id == ID);
    // Unset, the property is no input, so a lock made without it keeps
    // its inputs as before.
    if ctx.environment.maven_mode() != MavenMode::Maven39
        || selected(&ctx.inactive_profiles)
        || (!selected(&ctx.active_profiles) && ctx.property("performRelease").is_none())
    {
        return Ok(Default::default());
    }
    let (active, reads) = if selected(&ctx.active_profiles) {
        (true, BTreeSet::new())
    } else {
        let activation = Activation {
            property: Some(ActivationProperty {
                name: Some("performRelease".to_string()),
                value: Some("true".to_string()),
            }),
            ..Default::default()
        };
        activation.evaluate(ID, ctx)?
    };
    let plugins = [
        ("maven-source-plugin", "attach-sources", "jar-no-fork"),
        ("maven-javadoc-plugin", "attach-javadocs", "jar"),
    ]
    .into_iter()
    .filter(|_| active)
    .map(|(artifact_id, id, goal)| {
        let mut plugin = Plugin::new(super::DEFAULT_PLUGIN_GROUP, artifact_id, None);
        plugin
            .executions
            .push(PluginExecution::new(id, None, &[goal]));
        plugin
    })
    .chain(active.then(|| Plugin::new(super::DEFAULT_PLUGIN_GROUP, "maven-deploy-plugin", None)))
    .collect();
    Ok((plugins, reads))
}

/// The super POM's `<pluginRepositories>`: `central`, releases only, whose
/// URL Maven 3.10 reads from `maven.repo.central`.
pub(crate) fn super_pom_plugin_repository(mode: MavenMode) -> Repository {
    let url = match mode {
        MavenMode::Maven39 => "https://repo.maven.apache.org/maven2",
        MavenMode::Maven310 => "${maven.repo.central}",
    };
    let mut central = Repository::new(Some("central"), url);
    central.snapshots_enabled = false;
    central.snapshots_enabled_text = Some("false".to_string());
    central
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings(packaging: &str) -> Vec<String> {
        bindings_of(packaging, MavenMode::Maven39)
    }

    fn bindings_of(packaging: &str, mode: MavenMode) -> Vec<String> {
        default_lifecycle_bindings(packaging, mode)
            .unwrap()
            .iter()
            .map(|mojo| {
                format!(
                    "{} {}:{}:{}",
                    mojo.phase, mojo.artifact_id, mojo.version, mojo.goal
                )
            })
            .collect()
    }

    /// The table matches maven-core 3.9.12's `default-bindings.xml` and the
    /// `clean` and `site` default phases of its `components.xml`.
    #[test]
    fn bindings_are_maven_3_9_12s() {
        assert_eq!(
            bindings("jar"),
            [
                "clean maven-clean-plugin:3.2.0:clean",
                "process-test-resources maven-resources-plugin:3.3.1:testResources",
                "package maven-jar-plugin:3.4.1:jar",
                "compile maven-compiler-plugin:3.13.0:compile",
                "test maven-surefire-plugin:3.2.5:test",
                "install maven-install-plugin:3.1.2:install",
                "process-resources maven-resources-plugin:3.3.1:resources",
                "test-compile maven-compiler-plugin:3.13.0:testCompile",
                "deploy maven-deploy-plugin:3.1.2:deploy",
                "site maven-site-plugin:3.12.1:site",
                "site-deploy maven-site-plugin:3.12.1:deploy",
            ]
        );
        assert_eq!(
            bindings("pom")[1..3],
            [
                "install maven-install-plugin:3.1.2:install",
                "deploy maven-deploy-plugin:3.1.2:deploy"
            ]
        );
        assert!(
            bindings("maven-plugin")
                .contains(&"process-classes maven-plugin-plugin:3.13.1:descriptor".to_string())
        );
        assert_eq!(bindings("ear").len(), 8);
        assert!(default_lifecycle_bindings("bundle", MavenMode::Maven39).is_none());
    }

    /// Each plugin and its executions as `help:effective-pom` of Maven
    /// 3.9.12 lists them for a POM that declares no plugin.
    #[test]
    fn plugins_come_in_maven_3_9_12s_order() {
        let summary = |packaging: &str| -> Vec<String> {
            (lifecycle_plugins(packaging, MavenMode::Maven39)
                .unwrap()
                .iter())
            .map(|plugin| {
                let ids: Vec<_> = plugin.executions.iter().map(|e| e.id.as_str()).collect();
                format!("{} {}", plugin.artifact_id, ids.join(","))
            })
            .collect()
        };
        assert_eq!(
            summary("jar"),
            [
                "maven-clean-plugin default-clean",
                "maven-resources-plugin default-testResources,default-resources",
                "maven-jar-plugin default-jar",
                "maven-compiler-plugin default-compile,default-testCompile",
                "maven-surefire-plugin default-test",
                "maven-install-plugin default-install",
                "maven-deploy-plugin default-deploy",
                "maven-site-plugin default-site,default-deploy",
            ]
        );
        assert_eq!(
            summary("maven-plugin")[6],
            "maven-plugin-plugin default-descriptor"
        );
        assert_eq!(
            summary("ear"),
            [
                "maven-clean-plugin default-clean",
                "maven-ear-plugin default-generate-application-xml,default-ear",
                "maven-install-plugin default-install",
                "maven-resources-plugin default-resources",
                "maven-deploy-plugin default-deploy",
                "maven-site-plugin default-site,default-deploy",
            ]
        );
        assert_eq!(
            summary("pom")[1..],
            [
                "maven-install-plugin default-install",
                "maven-deploy-plugin default-deploy",
                "maven-site-plugin default-site,default-deploy",
            ]
        );
    }

    /// Each plugin with its version and executions as `help:effective-pom`
    /// of Maven 3.10.0 lists them for a POM that declares no plugin, and
    /// its super POM manages none.
    #[test]
    fn plugins_come_in_maven_3_10_0s_order() {
        let summary = |packaging: &str| -> Vec<String> {
            (lifecycle_plugins(packaging, MavenMode::Maven310)
                .unwrap()
                .iter())
            .map(|plugin| {
                let ids: Vec<_> = plugin.executions.iter().map(|e| e.id.as_str()).collect();
                let version = plugin.version.as_deref().unwrap_or("-");
                format!("{} {version} {}", plugin.artifact_id, ids.join(","))
            })
            .collect()
        };
        assert_eq!(
            summary("jar"),
            [
                "maven-clean-plugin 3.5.0 default-clean",
                "maven-resources-plugin 3.5.0 default-testResources,default-resources",
                "maven-jar-plugin 3.5.1 default-jar",
                "maven-compiler-plugin 3.16.0 default-compile,default-testCompile",
                "maven-surefire-plugin 3.6.0 default-test",
                "maven-install-plugin 3.2.0 default-install",
                "maven-deploy-plugin 3.2.0 default-deploy",
                "maven-site-plugin 3.22.0 default-site,default-deploy",
            ]
        );
        assert_eq!(
            summary("ear"),
            [
                "maven-clean-plugin 3.5.0 default-clean",
                "maven-ear-plugin 3.4.0 default-generate-application-xml,default-ear",
                "maven-resources-plugin 3.5.0 default-resources",
                "maven-install-plugin 3.2.0 default-install",
                "maven-deploy-plugin 3.2.0 default-deploy",
                "maven-site-plugin 3.22.0 default-site,default-deploy",
            ]
        );
        assert!(
            bindings_of("maven-plugin", MavenMode::Maven310)
                .contains(&"process-classes maven-plugin-plugin:3.16.0:descriptor".to_string())
        );
        assert!(super_pom_plugin_management(MavenMode::Maven310).is_empty());
    }

    /// An extension's mapping binds its phases in Maven's HashMap order, and
    /// a later binding gives the version an earlier one left out, as
    /// `help:effective-pom` of Maven 3.9.12 and 3.10.0 shows.
    #[test]
    fn a_mapping_binds_in_hash_map_order() {
        let mappings = crate::parse_lifecycle_mappings(
            "<component-set><components><component>\
             <role>org.apache.maven.lifecycle.mapping.LifecycleMapping</role>\
             <role-hint>foo</role-hint><configuration><phases>\
             <compile>x:p1:1.0:compile</compile><package>x:p1:2.0:pkg</package>\
             <process-test-resources>x:p2:a</process-test-resources>\
             <install>x:p2:3.0:b</install><test>x:p3:1:t</test>\
             </phases></configuration></component></components></component-set>",
        )
        .unwrap();
        let plugins = mapped_lifecycle_plugins(&mappings[0].1, MavenMode::Maven39);
        let versions: Vec<_> = (plugins.iter().filter(|plugin| plugin.group_id == "x"))
            .map(|plugin| (plugin.artifact_id.as_str(), plugin.version.as_deref()))
            .collect();
        assert_eq!(
            versions,
            [("p2", Some("3.0")), ("p1", Some("2.0")), ("p3", Some("1"))]
        );
    }
}
