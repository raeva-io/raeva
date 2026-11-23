//! The plugin model of project builds, checked against what
//! `help:effective-pom` of Maven 3.9.12 prints for the same POMs.

use crate::{
    ActivationContext, ConfigNode, EffectivePlugins, HostInput, MemorySource, ModelPolicy, Plugin,
    Pom, Project, ready,
};

fn effective(pom: &str, source: &MemorySource) -> EffectivePlugins {
    let pom = Pom::parse_with_plugins(pom).unwrap();
    let ctx = ActivationContext::default();
    let project = ready(Project::build(
        pom,
        source,
        ModelPolicy::PROJECT_PLUGINS,
        &ctx,
    ))
    .unwrap();
    project.plugins().unwrap().unwrap()
}

/// A configuration as compact XML, without the `<configuration>` element.
fn xml(node: &Option<ConfigNode>) -> String {
    fn element(node: &ConfigNode, out: &mut String) {
        out.push_str(&format!("<{}>", node.name));
        out.push_str(node.value.as_deref().unwrap_or(""));
        node.children.iter().for_each(|child| element(child, out));
        out.push_str(&format!("</{}>", node.name));
    }
    let mut out = String::new();
    for child in node.iter().flat_map(|node| &node.children) {
        element(child, &mut out);
    }
    out
}

/// `artifactId:version`, then each execution as `id[goals]`.
fn summary(plugins: &[Plugin]) -> Vec<String> {
    plugins
        .iter()
        .map(|plugin| {
            let mut text = format!(
                "{}:{}",
                plugin.artifact_id,
                plugin.version.as_deref().unwrap_or("?")
            );
            for execution in &plugin.executions {
                text.push_str(&format!(" {}[{}]", execution.id, execution.goals.join(",")));
            }
            text
        })
        .collect()
}

const PARENT: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>
<properties><p.version>5.1.9</p.version></properties>
<build>
 <pluginManagement><plugins>
   <plugin><artifactId>maven-compiler-plugin</artifactId><version>3.14.0</version>
     <configuration><release>17</release><annotationProcessorPaths><path><groupId>org.projectlombok</groupId><artifactId>lombok</artifactId><version>1.18.30</version></path></annotationProcessorPaths></configuration></plugin>
   <plugin><groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId><version>3.1.0</version>
     <dependencies><dependency><groupId>d</groupId><artifactId>x</artifactId><version>1</version></dependency></dependencies>
     <executions><execution><id>m1</id><goals><goal>java</goal></goals><configuration><mainClass>M</mainClass></configuration></execution></executions></plugin>
   <plugin><artifactId>maven-surefire-plugin</artifactId><version>3.5.2</version></plugin>
   <plugin><artifactId>maven-jar-plugin</artifactId><version>3.4.2</version><configuration><skipIfEmpty>true</skipIfEmpty></configuration></plugin>
 </plugins></pluginManagement>
 <plugins>
   <plugin><groupId>p</groupId><artifactId>a-plugin</artifactId><version>1</version><executions><execution><id>e1</id><goals><goal>g1</goal></goals></execution></executions></plugin>
   <plugin><groupId>p</groupId><artifactId>b-plugin</artifactId><version>1</version><inherited>false</inherited></plugin>
   <plugin><groupId>p</groupId><artifactId>c-plugin</artifactId><version>1</version><inherited>false</inherited><executions><execution><id>c1</id><inherited>true</inherited><goals><goal>g</goal></goals></execution><execution><id>c2</id><goals><goal>g</goal></goals></execution></executions><configuration><x>1</x></configuration></plugin>
   <plugin><groupId>p</groupId><artifactId>d-plugin</artifactId><version>1</version><dependencies><dependency><groupId>d</groupId><artifactId>y</artifactId><version>1</version></dependency><dependency><groupId>d</groupId><artifactId>w</artifactId><version>1</version></dependency></dependencies></plugin>
 </plugins>
 <extensions><extension><groupId>kr.motd.maven</groupId><artifactId>os-maven-plugin</artifactId><version>1.7.1</version></extension></extensions>
</build>
<pluginRepositories><pluginRepository><id>parent-plugins</id><url>https://example.invalid/p</url></pluginRepository></pluginRepositories>
</project>";

const CHILD: &str = "<project><modelVersion>4.0.0</modelVersion>
<parent><groupId>t</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId>
<build><plugins>
  <plugin><groupId>p</groupId><artifactId>z-plugin</artifactId><version>1</version></plugin>
  <plugin><groupId>p</groupId><artifactId>d-plugin</artifactId><dependencies><dependency><groupId>d</groupId><artifactId>y</artifactId><version>2</version></dependency><dependency><groupId>d</groupId><artifactId>z</artifactId><version>1</version></dependency></dependencies></plugin>
  <plugin><artifactId>maven-compiler-plugin</artifactId><configuration><release>21</release></configuration><executions><execution><id>default-testCompile</id><configuration><release>11</release></configuration></execution></executions></plugin>
  <plugin><groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId><executions><execution><id>m1</id><configuration><args>a</args></configuration></execution><execution><id>m2</id><goals><goal>exec</goal></goals></execution></executions></plugin>
  <plugin><groupId>p</groupId><artifactId>dup</artifactId><version>1</version><configuration><a>1</a></configuration></plugin>
  <plugin><groupId>p</groupId><artifactId>dup</artifactId><version>2</version><configuration><b>1</b></configuration></plugin>
  <plugin><groupId>org.codehaus.mojo</groupId><artifactId>build-helper-maven-plugin</artifactId></plugin>
  <plugin><groupId>org.apache.felix</groupId><artifactId>maven-bundle-plugin</artifactId><version>${p.version}</version><extensions>true</extensions></plugin>
  <plugin><artifactId>maven-surefire-plugin</artifactId></plugin>
</plugins></build>
<profiles><profile><id>prof</id><activation><activeByDefault>true</activeByDefault></activation>
  <build><plugins><plugin><groupId>p</groupId><artifactId>prof-plugin</artifactId><version>1</version></plugin>
     <plugin><groupId>p</groupId><artifactId>a-plugin</artifactId><version>2</version><executions><execution><id>e2</id><goals><goal>g2</goal></goals></execution></executions></plugin></plugins>
  <pluginManagement><plugins><plugin><artifactId>maven-surefire-plugin</artifactId><version>3.5.3</version></plugin></plugins></pluginManagement></build>
  <pluginRepositories><pluginRepository><id>prof-plugins</id><url>https://example.invalid/q</url></pluginRepository></pluginRepositories>
</profile></profiles>
</project>";

fn fixture() -> EffectivePlugins {
    let parent = Pom::parse_with_plugins(PARENT).unwrap();
    let source = MemorySource::new().with_parent("t", "parent", "1", parent);
    effective(CHILD, &source)
}

/// The order: the child's own plugins with the profile's after them, put
/// before the first parent plugin they share; then the parent's; then the
/// default lifecycle plugins the model lacks.
#[test]
fn plugins_merge_in_maven_3_9_12s_order() {
    let plugins = fixture();
    assert_eq!(
        summary(&plugins.plugins),
        [
            "maven-compiler-plugin:3.14.0 default-compile[compile] default-testCompile[testCompile]",
            "exec-maven-plugin:3.1.0 m1[java] m2[exec]",
            "dup:2",
            "build-helper-maven-plugin:?",
            "maven-bundle-plugin:5.1.9",
            "maven-surefire-plugin:3.5.3 default-test[test]",
            "prof-plugin:1",
            "a-plugin:2 e1[g1] e2[g2]",
            "c-plugin:1 c1[g]",
            "z-plugin:1",
            "d-plugin:1",
            "maven-clean-plugin:3.2.0 default-clean[clean]",
            "maven-resources-plugin:3.3.1 default-testResources[testResources] default-resources[resources]",
            "maven-jar-plugin:3.4.2 default-jar[jar]",
            "maven-install-plugin:3.1.2 default-install[install]",
            "maven-deploy-plugin:3.1.2 default-deploy[deploy]",
            "maven-site-plugin:3.12.1 default-site[site] default-deploy[deploy]",
        ]
    );
    assert!(plugins.lifecycle_mapped);
    assert_eq!(plugins.packaging, "jar");
    assert_eq!(
        summary(&plugins.plugin_management),
        [
            "maven-antrun-plugin:3.1.0",
            "maven-assembly-plugin:3.7.1",
            "maven-dependency-plugin:3.7.0",
            "maven-release-plugin:3.0.1",
            "maven-compiler-plugin:3.14.0",
            "exec-maven-plugin:3.1.0 m1[java]",
            "maven-surefire-plugin:3.5.3",
            "maven-jar-plugin:3.4.2",
        ]
    );
}

#[test]
fn configurations_merge_and_expand_into_executions() {
    let plugins = fixture();
    let lombok = "<annotationProcessorPaths><path><groupId>org.projectlombok</groupId>\
                  <artifactId>lombok</artifactId><version>1.18.30</version></path>\
                  </annotationProcessorPaths>";
    let compiler = plugins.plugin("org.apache.maven.plugins", "maven-compiler-plugin");
    let compiler = compiler.unwrap();
    assert_eq!(
        xml(&compiler.configuration),
        format!("<release>21</release>{lombok}")
    );
    let executions: Vec<_> = (compiler.executions.iter())
        .map(|execution| xml(&execution.configuration))
        .collect();
    assert_eq!(
        executions,
        [
            format!("<release>21</release>{lombok}"),
            format!("<release>11</release>{lombok}")
        ]
    );
    let sets = compiler.processor_paths(true, &[]);
    assert_eq!(sets.len(), 1);
    let paths = &sets[0].paths;
    assert_eq!(paths.len(), 1);
    assert_eq!(
        (paths[0].artifact_id.as_str(), paths[0].version.as_deref()),
        ("lombok", Some("1.18.30"))
    );

    let exec = plugins
        .plugin("org.codehaus.mojo", "exec-maven-plugin")
        .unwrap();
    assert_eq!(
        xml(&exec.executions[0].configuration),
        "<args>a</args><mainClass>M</mainClass>"
    );
    assert_eq!(exec.executions[1].configuration, None);
    assert_eq!(
        xml(&plugins.plugin("p", "dup").unwrap().configuration),
        "<b>1</b><a>1</a>"
    );
    let jar = plugins
        .plugin("org.apache.maven.plugins", "maven-jar-plugin")
        .unwrap();
    assert_eq!(
        xml(&jar.executions[0].configuration),
        "<skipIfEmpty>true</skipIfEmpty>"
    );
}

/// A parent plugin with `<inherited>false</inherited>` reaches the child
/// only for executions that say they are inherited, without its
/// configuration.
#[test]
fn a_plugin_not_inherited_keeps_only_its_inherited_executions() {
    let plugins = fixture();
    assert!(plugins.plugin("p", "b-plugin").is_none());
    let c = plugins.plugin("p", "c-plugin").unwrap();
    assert_eq!(c.configuration, None);
    assert_eq!(c.executions.len(), 1);
    assert_eq!(c.executions[0].configuration, None);
}

#[test]
fn dependencies_extensions_and_repositories_merge() {
    let plugins = fixture();
    let dependencies = |plugin: &Plugin| -> Vec<String> {
        (plugin.dependencies.iter())
            .map(|dependency| {
                format!(
                    "{}:{}",
                    dependency.artifact_id,
                    dependency.version.as_deref().unwrap_or("?")
                )
            })
            .collect()
    };
    let d = plugins.plugin("p", "d-plugin").unwrap();
    assert_eq!(dependencies(d), ["y:2", "z:1", "w:1"]);
    let exec = plugins
        .plugin("org.codehaus.mojo", "exec-maven-plugin")
        .unwrap();
    assert_eq!(dependencies(exec), ["x:1"]);

    let extensions: Vec<_> = (plugins.build_extensions().iter())
        .map(|plugin| {
            format!(
                "{}:{}",
                plugin.artifact_id,
                plugin.version.as_deref().unwrap()
            )
        })
        .collect();
    assert_eq!(
        extensions,
        ["os-maven-plugin:1.7.1", "maven-bundle-plugin:5.1.9"]
    );

    let repositories: Vec<_> = (plugins.plugin_repositories.iter())
        .map(|repository| {
            (
                repository.id.as_deref().unwrap(),
                repository.snapshots_enabled,
            )
        })
        .collect();
    assert_eq!(
        repositories,
        [
            ("prof-plugins", true),
            ("parent-plugins", true),
            ("central", false)
        ]
    );
    assert_eq!(
        plugins.plugin_repositories[2].url,
        "https://repo.maven.apache.org/maven2"
    );
}

/// A dependency's model keeps no plugin model, and its build reads nothing
/// for one.
#[test]
fn only_a_project_build_has_a_plugin_model() {
    let pom = Pom::parse_with_plugins(
        "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
         <build><plugins><plugin><artifactId>maven-jar-plugin</artifactId></plugin>\
         </plugins></build></project>",
    )
    .unwrap();
    let ctx = ActivationContext::default();
    let source = MemorySource::new();
    for policy in [ModelPolicy::DEPENDENCY, ModelPolicy::PROJECT] {
        let project = ready(Project::build(pom.clone(), &source, policy, &ctx)).unwrap();
        assert_eq!(project.plugins().unwrap(), None);
    }
    let project = ready(Project::build(
        pom,
        &source,
        ModelPolicy::PROJECT_PLUGINS,
        &ctx,
    ))
    .unwrap();
    assert!(project.plugins().unwrap().is_some());
}

/// `-DperformRelease=true` or `-Prelease-profile`, but not with
/// `-P!release-profile`, activates Maven 3.9.12's super POM
/// `release-profile`, whose source and javadoc plugins resolve their
/// version as `help:effective-pom` shows, and a profile can manage them.
#[test]
fn perform_release_binds_the_super_poms_release_plugins() {
    let pom = "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
               <profiles><profile><id>p</id><activation><property><name>ci</name></property>\
               </activation><build><pluginManagement><plugins><plugin>\
               <artifactId>maven-javadoc-plugin</artifactId><version>3.11.2</version></plugin>\
               </plugins></pluginManagement></build></profile></profiles></project>";
    let mut ctx = ActivationContext::default();
    ctx.properties
        .insert("performRelease".into(), "true".into());
    let plugins = |ctx: &ActivationContext| {
        let pom = Pom::parse_with_plugins(pom).unwrap();
        let project = ready(Project::build(
            pom,
            &MemorySource::new(),
            ModelPolicy::PROJECT_PLUGINS,
            ctx,
        ))
        .unwrap();
        summary(&project.plugins().unwrap().unwrap().plugins)[..3].to_vec()
    };
    assert_eq!(
        plugins(&ctx),
        [
            "maven-source-plugin:? attach-sources[jar-no-fork]",
            "maven-javadoc-plugin:? attach-javadocs[jar]",
            "maven-deploy-plugin:3.1.2 default-deploy[deploy]",
        ]
    );
    let read = |name: &str| HostInput::UserProperty(name.into());
    assert_eq!(
        ctx.environment.take_reads(),
        [read("ci"), read("performRelease")].into()
    );
    ctx.properties.insert("ci".into(), "true".into());
    assert_eq!(
        plugins(&ctx)[1],
        "maven-javadoc-plugin:3.11.2 attach-javadocs[jar]"
    );
    ctx.inactive_profiles.push("release-profile".into());
    assert_eq!(
        plugins(&ctx)[0],
        "maven-clean-plugin:3.2.0 default-clean[clean]"
    );
    let mut ctx = ActivationContext::default();
    ctx.active_profiles.push("release-profile".into());
    assert_eq!(
        plugins(&ctx)[0],
        "maven-source-plugin:? attach-sources[jar-no-fork]"
    );
    assert_eq!(ctx.environment.take_reads(), [read("ci")].into());
    let ctx = ActivationContext::default();
    assert_eq!(
        plugins(&ctx)[0],
        "maven-clean-plugin:3.2.0 default-clean[clean]"
    );
    assert!(ctx.environment.take_reads().is_empty());
}

/// A packaging Maven does not map gets no default plugins, and a declared
/// plugin without a version takes the lifecycle's.
#[test]
fn lifecycle_plugins_follow_the_packaging() {
    let source = MemorySource::new();
    let bundle = effective(
        "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
         <packaging>bundle</packaging><build><plugins><plugin><groupId>org.apache.felix\
         </groupId><artifactId>maven-bundle-plugin</artifactId><version>5.1.9</version>\
         <extensions>true</extensions></plugin></plugins></build></project>",
        &source,
    );
    assert!(!bundle.lifecycle_mapped);
    assert_eq!(summary(&bundle.plugins), ["maven-bundle-plugin:5.1.9"]);

    let pom = effective(
        "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
         <packaging>pom</packaging><build><plugins><plugin><artifactId>maven-install-plugin\
         </artifactId><executions><execution><id>more</id><goals><goal>install-file</goal>\
         </goals></execution></executions></plugin></plugins></build></project>",
        &source,
    );
    assert_eq!(
        summary(&pom.plugins),
        [
            "maven-install-plugin:3.1.2 default-install[install] more[install-file]",
            "maven-clean-plugin:3.2.0 default-clean[clean]",
            "maven-deploy-plugin:3.1.2 default-deploy[deploy]",
            "maven-site-plugin:3.12.1 default-site[site] default-deploy[deploy]",
        ]
    );
}

/// The plugin model interpolates with the project's properties and
/// coordinates; a configuration value it cannot expand stays as written,
/// and the host values it reads are reported, not recorded in the build,
/// except the configuration's.
#[test]
fn the_plugin_model_interpolates_on_its_own() {
    let source = MemorySource::new();
    let pom = Pom::parse_with_plugins(
        "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
         <packaging>pom</packaging><properties><v>2</v></properties><build><plugins><plugin>\
         <groupId>${project.groupId}.p</groupId><artifactId>x</artifactId><version>${v}\
         </version><dependencies><dependency><groupId>d</groupId><artifactId>d</artifactId>\
         <version>${env.RAEVA_PLUGIN_TEST_DEP}</version></dependency></dependencies>\
         <configuration><home>${env.RAEVA_PLUGIN_TEST_HOME}</home><late>${mojo.only}\
         </late></configuration></plugin></plugins></build></project>",
    )
    .unwrap();
    let ctx = ActivationContext::default();
    let project = ready(Project::build(
        pom,
        &source,
        ModelPolicy::PROJECT_PLUGINS,
        &ctx,
    ))
    .unwrap();
    let plugins = project.plugins().unwrap().unwrap();
    let plugin = plugins.plugin("g.p", "x").unwrap();
    assert_eq!(plugin.version.as_deref(), Some("2"));
    assert_eq!(
        xml(&plugin.configuration),
        "<home>${env.RAEVA_PLUGIN_TEST_HOME}</home><late>${mojo.only}</late>"
    );
    let reads = format!("{:?}", plugins.host_reads);
    assert!(reads.contains("RAEVA_PLUGIN_TEST_DEP"), "{reads}");
    assert!(!reads.contains("RAEVA_PLUGIN_TEST_HOME"), "{reads}");
}

/// A project build refuses plugin sections that do not parse, as Maven
/// refuses a POM it cannot parse.
#[test]
fn a_project_build_refuses_an_unreadable_plugin_section() {
    let pom = Pom::parse_with_plugins(
        "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
         <dependencies><dependency><groupId>g</groupId><artifactId>b</artifactId>\
         <version>1</version></dependency></dependencies><build><plugins><plugin>\
         <artifactId>x</artifactId><configuration><v>&undefined;</v></configuration>\
         </plugin></plugins></build></project>",
    )
    .unwrap();
    let ctx = ActivationContext::default();
    let source = MemorySource::new();
    let error = ready(Project::build(
        pom,
        &source,
        ModelPolicy::PROJECT_PLUGINS,
        &ctx,
    ))
    .unwrap_err()
    .to_string();
    assert!(error.contains("undefined"), "{error}");
}

/// The super POM merges into the topmost ancestor before the child
/// inherits, so a parent's `inherited=false` hides a super POM plugin too,
/// and the parent's own managed plugins stay after the super POM's.
#[test]
fn the_super_pom_merges_into_the_topmost_ancestor() {
    let parent = Pom::parse_with_plugins(
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
         <build><pluginManagement><plugins>\
         <plugin><artifactId>maven-release-plugin</artifactId><version>3.1.1</version><inherited>false</inherited></plugin>\
         <plugin><groupId>p</groupId><artifactId>p-plugin</artifactId><version>1</version></plugin>\
         </plugins></pluginManagement></build></project>",
    )
    .unwrap();
    let source = MemorySource::new().with_parent("t", "parent", "1", parent);
    let plugins = effective(
        "<project><modelVersion>4.0.0</modelVersion>\
         <parent><groupId>t</groupId><artifactId>parent</artifactId><version>1</version></parent>\
         <artifactId>child</artifactId><packaging>pom</packaging>\
         <build><pluginManagement><plugins>\
         <plugin><groupId>p</groupId><artifactId>c-plugin</artifactId><version>1</version></plugin>\
         <plugin><artifactId>maven-antrun-plugin</artifactId><version>3.2.0</version></plugin>\
         </plugins></pluginManagement></build></project>",
        &source,
    );
    assert_eq!(
        summary(&plugins.plugin_management),
        [
            "c-plugin:1",
            "maven-antrun-plugin:3.2.0",
            "maven-assembly-plugin:3.7.1",
            "maven-dependency-plugin:3.7.0",
            "p-plugin:1",
        ]
    );
}

/// A property cycle in a configuration fails the plugin model, as Maven's
/// interpolation reports it, and an unknown expression stays as written.
#[test]
fn a_configuration_property_cycle_fails_the_plugin_model() {
    let pom = |value: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId><artifactId>a</artifactId>\
             <version>1</version><properties><a>${{b}}</a><b>${{a}}</b></properties>\
             <build><plugins><plugin><groupId>p</groupId><artifactId>x</artifactId><version>1</version>\
             <configuration><v>{value}</v></configuration></plugin></plugins></build></project>"
        )
    };
    let plugins = effective(&pom("${unknown}"), &MemorySource::new());
    assert_eq!(xml(&plugins.plugins[0].configuration), "<v>${unknown}</v>");

    let project = Pom::parse_with_plugins(&pom("${a}")).unwrap();
    let ctx = ActivationContext::default();
    let project = ready(Project::build(
        project,
        &MemorySource::new(),
        ModelPolicy::PROJECT_PLUGINS,
        &ctx,
    ))
    .unwrap();
    assert!(project.plugins().is_err());
}

/// `Pom::parse` drops the plugin sections, so a plugin model built from
/// such a POM fails instead of coming out empty.
#[test]
fn a_pom_parsed_without_plugin_sections_has_no_plugin_model() {
    let pom = Pom::parse(
        "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
         <build><plugins><plugin><artifactId>maven-jar-plugin</artifactId></plugin>\
         </plugins></build></project>",
    )
    .unwrap();
    let ctx = ActivationContext::default();
    let project = ready(Project::build(
        pom,
        &MemorySource::new(),
        ModelPolicy::PROJECT_PLUGINS,
        &ctx,
    ))
    .unwrap();
    let error = project.plugins().unwrap_err().to_string();
    assert!(error.contains("without its plugin sections"), "{error}");
}

/// The build extensions a POM declares itself, read without a build: the
/// `<build><extensions>`, then each plugin that it, a profile, or the
/// plugin management marks `<extensions>true</extensions>`.
#[test]
fn a_pom_lists_the_build_extensions_it_declares() {
    let plugin = |artifact: &str, extensions: &str| {
        format!(
            "<plugin><groupId>x</groupId><artifactId>{artifact}</artifactId>{extensions}</plugin>"
        )
    };
    let mut pom = Pom::parse_with_plugins(&format!(
        "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
         <build><extensions><extension><groupId>e</groupId><artifactId>wagon</artifactId>\
         <version>1</version></extension></extensions><plugins>{}{}{}{}</plugins>\
         <pluginManagement><plugins>{}{}</plugins></pluginManagement></build>\
         <profiles><profile><id>off</id><build><plugins>{}</plugins></build></profile></profiles>\
         </project>",
        plugin("own", "<extensions>TRUE</extensions>"),
        plugin("plain", ""),
        plugin("managed", ""),
        plugin("refused", "<extensions>false</extensions>"),
        plugin("managed", "<extensions>true</extensions>"),
        plugin("refused", "<extensions>true</extensions>"),
        plugin("profiled", "<extensions>true</extensions>"),
    ))
    .unwrap();
    let keys: Vec<String> = (pom.declared_build_extensions(&[]).unwrap().iter())
        .map(Plugin::key)
        .collect();
    assert_eq!(keys, ["e:wagon", "x:own", "x:managed", "x:profiled"]);
    assert!(
        Pom::parse("<project/>")
            .unwrap()
            .declared_build_extensions(&[])
            .is_err()
    );
}

/// A parent's plugin management marks a plugin the child declares bare,
/// unless the entry is not inherited or nearer management decides.
#[test]
fn a_parent_manages_the_build_extensions_of_its_child() {
    let plugin = |artifact: &str, body: &str| {
        format!("<plugin><groupId>x</groupId><artifactId>{artifact}</artifactId>{body}</plugin>")
    };
    let pom = |build: &str| {
        Pom::parse_with_plugins(&format!(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <build>{build}</build></project>"
        ))
        .unwrap()
    };
    let mut parent = pom(&format!(
        "<pluginManagement><plugins>{}{}{}</plugins></pluginManagement>",
        plugin("bundle", "<extensions>true</extensions>"),
        plugin(
            "kept",
            "<extensions>true</extensions><inherited>false</inherited>"
        ),
        plugin("versioned", "<extensions>true</extensions>"),
    ));
    let mut child = pom(&format!(
        "<plugins>{}{}{}</plugins><pluginManagement><plugins>{}</plugins></pluginManagement>",
        plugin("bundle", ""),
        plugin("kept", ""),
        plugin("versioned", ""),
        plugin("versioned", "<version>2</version>"),
    ));
    let inherited = parent.inherited_plugin_management().unwrap();
    let keys: Vec<String> = (child.declared_build_extensions(&inherited).unwrap().iter())
        .map(Plugin::key)
        .collect();
    assert_eq!(keys, ["x:bundle", "x:versioned"]);
}

/// Maven 3.9.12 resolved the processor path of the execution bound to
/// `compile` and not those of one bound to `none` or to a phase no
/// lifecycle has.
#[test]
fn an_execution_that_never_runs_has_no_processor_paths() {
    let execution = |id: &str, phase: &str| {
        format!(
            "<execution><id>{id}</id><phase>{phase}</phase><goals><goal>compile</goal></goals>\
             <configuration><annotationProcessorPaths><path><groupId>g</groupId>\
             <artifactId>{id}</artifactId><version>1</version></path></annotationProcessorPaths>\
             </configuration></execution>"
        )
    };
    let plugins = effective(
        &format!(
            "<project><groupId>t</groupId><artifactId>apt</artifactId><version>1</version>\
             <build><plugins><plugin><artifactId>maven-compiler-plugin</artifactId>\
             <version>3.13.0</version><executions>{}{}{}</executions></plugin></plugins>\
             </build></project>",
            execution("off", "none"),
            execution("bogus", "bogus"),
            execution("on", "compile"),
        ),
        &MemorySource::new(),
    );
    let compiler = plugins.plugin("org.apache.maven.plugins", "maven-compiler-plugin");
    let sets = compiler.unwrap().processor_paths(true, &[]);
    let ids: Vec<_> = (sets.iter().flat_map(|set| &set.paths))
        .map(|path| path.artifact_id.as_str())
        .collect();
    assert_eq!(ids, ["on"]);
}

/// Maven keys a plugin dependency with an empty `<classifier>` apart from
/// one without, as it does a project's, through the plugin's
/// pluginManagement entry too, and collects both.
#[test]
fn a_plugin_dependency_twin_stays_a_dependency_of_its_own() {
    let y = |extra: &str| {
        format!("<dependency><groupId>d</groupId><artifactId>y</artifactId>{extra}</dependency>")
    };
    let plugin = |version: &str, dependencies: &str| {
        format!(
            "<plugin><groupId>p</groupId><artifactId>d-plugin</artifactId>{version}\
             <dependencies>{dependencies}</dependencies></plugin>"
        )
    };
    let classifiers = |build: &str| {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>app</artifactId><version>1</version><build>{build}</build></project>"
        );
        let pom = Pom::parse_with_plugins(&pom).unwrap();
        let ctx = ActivationContext::default();
        let project = ready(Project::build(
            pom,
            &MemorySource::new(),
            ModelPolicy::PROJECT_PLUGINS,
            &ctx,
        ))
        .unwrap();
        let plugins = project.plugins().unwrap().unwrap().plugins;
        let plugin = (plugins.iter())
            .find(|p| p.artifact_id == "d-plugin")
            .unwrap();
        (plugin.dependencies.iter())
            .map(|dependency| dependency.classifier.clone())
            .collect::<Vec<_>>()
    };
    let empty = "<version>1</version><classifier/>";
    for second in ["1", "2"] {
        let own = plugin(
            "<version>1</version>",
            &format!("{}{}", y(empty), y(&format!("<version>{second}</version>"))),
        );
        assert_eq!(
            classifiers(&format!("<plugins>{own}</plugins>")),
            [Some(String::new()), None]
        );
    }
    let managed = format!(
        "<pluginManagement><plugins>{}</plugins></pluginManagement><plugins>{}</plugins>",
        plugin("<version>1</version>", &y(empty)),
        plugin("", &y("<version>2</version>"))
    );
    assert_eq!(classifiers(&managed).len(), 2);
}

/// A build plugin's dependency without a version, or in another scope than
/// compile, runtime or system, fails the build, as in
/// Maven 3.9.12 and 3.10.0: neither the project's dependency management
/// nor the plugin's pluginManagement entry supplies one. A managed plugin
/// no build plugin takes is not checked.
#[test]
fn a_plugin_dependency_without_a_version_is_refused() {
    let x = |version: &str| {
        format!("<dependency><groupId>d</groupId><artifactId>x</artifactId>{version}</dependency>")
    };
    let plugin = |version: &str, dependencies: &str| {
        format!(
            "<plugin><groupId>p</groupId><artifactId>d-plugin</artifactId>{version}\
             <dependencies>{dependencies}</dependencies></plugin>"
        )
    };
    let built_on = |body: &str, os: Option<&str>| {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>app</artifactId><version>1</version>{body}</project>"
        );
        let pom = Pom::parse_with_plugins(&pom).unwrap();
        let ctx = match os {
            Some(os) => ActivationContext::new(
                crate::ModelEnvironment::builder()
                    .platform(os, "x86_64")
                    .build(),
            ),
            None => ActivationContext::default(),
        };
        let project = ready(Project::build(
            pom,
            &MemorySource::new(),
            ModelPolicy::PROJECT_PLUGINS,
            &ctx,
        ))
        .unwrap();
        project
            .plugins()
            .map(drop)
            .map_err(|error| error.to_string())
    };
    let built = |body: &str| built_on(body, None);
    let refused = Err(
        "invalid model: 'build.plugins.plugin[p:d-plugin].dependencies.dependency.\
         version' for d:x:jar is missing."
            .to_string(),
    );
    let versioned = "<version>1</version>";
    let own = plugin(versioned, &x(""));
    for body in [
        format!("<build><plugins>{own}</plugins></build>"),
        format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
             <build><plugins>{own}</plugins></build>",
            x("<version>2</version>")
        ),
        format!(
            "<build><pluginManagement><plugins>{}</plugins></pluginManagement>\
             <plugins>{own}</plugins></build>",
            plugin("", &x("<version>2</version>"))
        ),
        format!(
            "<build><plugins>{}</plugins></build>",
            plugin(versioned, &x("<version/>"))
        ),
    ] {
        assert_eq!(built(&body), refused, "{body}");
    }
    let managed_only =
        format!("<build><pluginManagement><plugins>{own}</plugins></pluginManagement></build>");
    assert_eq!(built(&managed_only), Ok(()));
    // A scope other than compile, runtime or system is refused too, after
    // the version, and an empty one is none.
    let scoped = |scope: &str| {
        let dependency = x(&format!("<version>1</version><scope>{scope}</scope>"));
        built(&format!(
            "<build><plugins>{}</plugins></build>",
            plugin(versioned, &dependency)
        ))
    };
    for scope in ["test", "provided", "import", "bogus"] {
        assert_eq!(
            scoped(scope),
            Err(format!(
                "invalid model: 'build.plugins.plugin[p:d-plugin].dependencies.dependency.scope' \
                 for d:x:jar must be one of [compile, runtime, system] but is '{scope}'."
            ))
        );
    }
    for scope in ["", "compile", "runtime"] {
        assert_eq!(scoped(scope), Ok(()), "{scope}");
    }
    let unversioned = x("<scope>test</scope>");
    assert_eq!(
        built(&format!(
            "<build><plugins>{}</plugins></build>",
            plugin(versioned, &unversioned)
        )),
        refused
    );
    // So is a system path a system dependency lacks or has relative, or one
    // another scope has.
    let pathed = |scope: &str, path: &str| {
        let dependency = x(&format!("<version>1</version><scope>{scope}</scope>{path}"));
        built(&format!(
            "<build><plugins>{}</plugins></build>",
            plugin(versioned, &dependency)
        ))
    };
    let system = |path: &str| pathed("system", path);
    let path_problem = |problem: &str| {
        Err(format!(
            "invalid model: 'build.plugins.plugin[p:d-plugin].dependencies.dependency.\
             systemPath' for d:x:jar {problem}"
        ))
    };
    assert_eq!(system(""), path_problem("is missing."));
    assert_eq!(
        system("<systemPath>lib/x.jar</systemPath>"),
        path_problem("must specify an absolute path but is lib/x.jar")
    );
    assert_eq!(
        pathed("compile", "<systemPath>/opt/x.jar</systemPath>"),
        path_problem(
            "must be omitted. This field may only be specified for a dependency with system \
             scope."
        )
    );
    // Absolute as java.io.File takes it on the locked platform's OS, or on
    // either without a platform, once Maven has expanded what it knows: a
    // variable the environment lacks stays as written.
    let on = |os: Option<&str>, path: &str, absolute: bool| {
        let expected = match (absolute, os) {
            (true, _) => Ok(()),
            (false, Some(os)) => path_problem(&format!(
                "must specify an absolute path but is {path}, for the locked platform \
                 {os}-x86_64"
            )),
            (false, None) => path_problem(&format!("must specify an absolute path but is {path}")),
        };
        let pathed = |path: &str| {
            let dependency = x(&format!(
                "<version>1</version><scope>system</scope><systemPath>{path}</systemPath>"
            ));
            let body = format!(
                "<build><plugins>{}</plugins></build>",
                plugin(versioned, &dependency)
            );
            built_on(&body, os)
        };
        assert_eq!(pathed(path), expected, "{os:?} {path}");
    };
    for (path, windows, unix) in [
        ("C:/lib/x.jar", true, false),
        ("C:\\lib\\x.jar", true, false),
        ("\\\\server\\share\\x.jar", true, false),
        ("//server/share/x.jar", true, true),
        ("/opt/x.jar", false, true),
        ("/C:/lib/x.jar", true, true),
        ("//C:lib/x.jar", false, true),
        ("lib/x.jar", false, false),
    ] {
        on(Some("windows"), path, windows);
        on(Some("linux"), path, unix);
        on(Some("macos"), path, unix);
        on(None, path, windows || unix);
    }
    // A path raeva could not fully interpolate is not judged: Maven may
    // have the value, and fails the build itself when it does not.
    for path in [
        "${java.home}/lib/x.jar",
        "${env.RAEVA_TEST_UNSET_SYSTEM_PATH}/x.jar",
        "${PATH}/x.jar",
    ] {
        on(Some("windows"), path, true);
        on(Some("linux"), path, true);
    }
    on(None, "lib/${os.name}/x.jar", true);
    assert_eq!(
        pathed(
            "compile",
            "<systemPath>${env.RAEVA_TEST_UNSET_SYSTEM_PATH}</systemPath>"
        ),
        Ok(())
    );
    // Literal whitespace around the path is no part of it.
    assert!(system("<systemPath> /opt/x.jar </systemPath>").is_ok());
    // Maven refuses it even past another plugin's twins.
    let twins = format!(
        "<plugin><groupId>p</groupId><artifactId>a-plugin</artifactId>{versioned}\
         <dependencies>{}{}</dependencies></plugin>",
        x("<version>1</version>"),
        x("<version>2</version><classifier/>")
    );
    assert_eq!(
        built(&format!("<build><plugins>{twins}{own}</plugins></build>")),
        refused
    );
}
