//! Tests of the effective project model, built from POMs held in memory.

use super::*;
use crate::ActivationContext;
use crate::pom::Pom;
use crate::source::{MemorySource, MemorySourceError, ModelPolicy, ModelSource, ready};

fn build<S: ModelSource>(
    pom: Pom,
    source: S,
    ctx: &ActivationContext,
) -> Result<Project, S::Error> {
    build_with(pom, &source, ModelPolicy::DEPENDENCY, ctx)
}

fn build_with<S: ModelSource>(
    pom: Pom,
    source: &S,
    policy: ModelPolicy,
    ctx: &ActivationContext,
) -> Result<Project, S::Error> {
    ready(Project::build(pom, source, policy, ctx))
}

fn pom(xml: &str) -> Pom {
    Pom::parse(xml).unwrap()
}

fn dep(group: &str, artifact: &str, extra: &str) -> String {
    format!(
        "<dependency><groupId>{group}</groupId><artifactId>{artifact}</artifactId>{extra}</dependency>"
    )
}

fn import(artifact: &str, version: &str) -> String {
    dep(
        "g",
        artifact,
        &format!("<version>{version}</version><type>pom</type><scope>import</scope>"),
    )
}

fn project_pom(artifact: &str, body: &str) -> Pom {
    pom(&format!(
        "<project><groupId>g</groupId><artifactId>{artifact}</artifactId><version>1</version>\
         {body}</project>"
    ))
}

/// Each dependency as `artifact:version`, with `:scope` when it has one.
fn summary(dependencies: &[Dependency]) -> Vec<String> {
    dependencies
        .iter()
        .map(|dep| {
            let mut text = format!(
                "{}:{}",
                dep.artifact_id,
                dep.version.as_deref().unwrap_or("?")
            );
            if let Some(scope) = &dep.scope {
                text.push_str(&format!(":{scope}"));
            }
            text
        })
        .collect()
}

fn model_error(error: MemorySourceError) -> String {
    match error {
        MemorySourceError::Model(error) => error.to_string(),
        other => panic!("expected a model error, got {other:?}"),
    }
}

#[test]
fn resolves_properties_inheritance_and_managed_versions() {
    let parent = project_pom(
        "parent",
        &format!(
            "<packaging>pom</packaging><properties><lib.version>1.2</lib.version>\
             <shared>parent</shared></properties>\
             <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
             <dependencies>{}{}</dependencies>",
            dep("org", "managed", "<version>${lib.version}</version>"),
            dep("org", "inherited", "<version>1</version>"),
            dep("org", "overridden", "<version>1</version>"),
        ),
    );
    let child = pom(&format!(
        "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
         <version>1</version></parent><artifactId>app</artifactId>\
         <properties><shared>child</shared></properties><dependencies>{}{}{}</dependencies>\
         </project>",
        dep("org", "managed", ""),
        dep("org", "overridden", "<version>${shared}</version>"),
        dep(
            "org",
            "own",
            "<version>${project.version}-${project.parent.artifactId}</version>"
        ),
    ));
    let source = MemorySource::new().with_parent("g", "parent", "1", parent);
    let project = build(child, source, &ActivationContext::default()).unwrap();
    assert_eq!(
        (project.group_id.as_str(), project.version.as_str()),
        ("g", "1")
    );
    assert_eq!(project.packaging, "jar");
    assert_eq!(
        summary(&project.dependencies),
        [
            "managed:1.2",
            "overridden:child",
            "own:1-parent",
            "inherited:1"
        ]
    );
}

/// Maven orders dependencies from the child POM to its ancestors, each POM's
/// own before its active profiles', and an override keeps the child's
/// position. This order decides nearest-wins ties.
#[test]
fn orders_child_dependencies_before_inherited_ones() {
    let version = |v: &str| format!("<version>{v}</version>");
    let default_profile = |id: &str, artifact: &str| {
        format!(
            "<profiles><profile><id>{id}</id><activation><activeByDefault>true\
             </activeByDefault></activation><dependencies>{}</dependencies></profile>\
             </profiles>",
            dep("g", artifact, &version("1"))
        )
    };
    let parent = project_pom(
        "par",
        &format!(
            "<packaging>pom</packaging><dependencies>{}{}{}</dependencies>{}",
            dep("g", "p1", &version("1")),
            dep("g", "p2", &version("1")),
            dep("g", "p3", &version("1")),
            default_profile("pp", "pprof"),
        ),
    );
    let child = pom(&format!(
        "<project><parent><groupId>g</groupId><artifactId>par</artifactId>\
         <version>1</version></parent><artifactId>ch</artifactId>\
         <dependencies>{}{}{}</dependencies>{}</project>",
        dep("g", "c1", &version("1")),
        dep("g", "p2", &version("2")),
        dep("g", "c2", &version("1")),
        default_profile("cp", "cprof"),
    ));
    let source = MemorySource::new().with_parent("g", "par", "1", parent);
    let project = build(child, source, &ActivationContext::default()).unwrap();
    assert_eq!(
        summary(&project.dependencies),
        ["c1:1", "p2:2", "c2:1", "cprof:1", "p1:1", "p3:1", "pprof:1"]
    );
}

/// Maven selects the profiles of each POM on its own: `-P` and `-P!` win
/// over conditions, a POM's own properties never satisfy a `<property>`
/// condition, and an `activeByDefault` profile applies only when no other
/// profile of its POM is active.
#[test]
fn profiles_are_selected_per_pom_like_maven() {
    let profile = |id: &str, activation: &str| {
        format!(
            "<profile><id>{id}</id><activation>{activation}</activation><dependencies>{}\
             </dependencies></profile>",
            dep("g", id, "<version>1</version>")
        )
    };
    let default = "<activeByDefault>true</activeByDefault>";
    let parent = project_pom(
        "parent",
        &format!(
            "<packaging>pom</packaging><profiles>{}</profiles>",
            profile("parent-default", default)
        ),
    );
    let child = pom(&format!(
        "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
         <version>1</version></parent><artifactId>app</artifactId>\
         <properties><feature>on</feature></properties><profiles>{}{}{}</profiles></project>",
        profile("conditional", "<property><name>feature</name></property>"),
        profile("absent", "<property><name>!feature</name></property>"),
        profile("default", default),
    ));
    // (-Dfeature, -P, -P!, the dependencies the profiles bring)
    for (feature, active, inactive, expected) in [
        (false, "", "", "absent:1 parent-default:1"),
        (true, "", "", "conditional:1 parent-default:1"),
        (true, "", "conditional", "default:1 parent-default:1"),
        (false, "", "absent", "default:1 parent-default:1"),
        (
            false,
            "conditional",
            "",
            "conditional:1 absent:1 parent-default:1",
        ),
        (false, "", "parent-default", "absent:1"),
    ] {
        let mut ctx = ActivationContext::default();
        if feature {
            ctx.properties.insert("feature".into(), "yes".into());
        }
        ctx.active_profiles
            .extend((!active.is_empty()).then(|| active.to_string()));
        ctx.inactive_profiles
            .extend((!inactive.is_empty()).then(|| inactive.to_string()));
        let source = MemorySource::new().with_parent("g", "parent", "1", parent.clone());
        let project = build(child.clone(), source, &ctx).unwrap();
        assert_eq!(
            summary(&project.dependencies).join(" "),
            expected,
            "-Dfeature={feature} -P{active} -P!{inactive}"
        );
    }
}

/// A declaration takes its version, scope, type, classifier, system path
/// and exclusions from the first management entry with its group, artifact,
/// type and classifier, but not `<optional>`; its own values win, and the
/// managed exclusions apply only to a declaration without any, as in
/// Maven's `DefaultDependencyManagementInjector`. Coordinates are trimmed
/// before the lookup.
#[test]
fn dependency_management_fills_in_declarations() {
    let exclusion = |group: &str| {
        format!(
            "<exclusions><exclusion><groupId>{group}</groupId><artifactId>x</artifactId>\
             </exclusion></exclusions>"
        )
    };
    let managed = [
        dep("m", "lib", "<version>1</version>"),
        dep(
            "m",
            "lib",
            "<version>2</version><classifier>tests</classifier>",
        ),
        dep("m", "lib", "<version>3</version><type>zip</type>"),
        dep("m", "lib", "<version>9</version>"),
        dep(
            "m",
            "scoped",
            &format!(
                "<version>4</version><scope>test</scope><optional>true</optional>{}",
                exclusion("managed")
            ),
        ),
        dep(
            "m",
            "sys",
            "<version>5</version><scope>system</scope><systemPath>C:/lib/sys.jar</systemPath>",
        ),
    ];
    let declared = [
        dep(" m ", "lib ", ""),
        dep("m", "lib", "<classifier>tests</classifier>"),
        dep("m", "lib", "<type>zip</type>"),
        dep("m", "scoped", &exclusion("own")),
        dep(
            "m",
            "scoped",
            "<classifier>c</classifier><scope>runtime</scope>",
        ),
        dep("m", "sys", "<scope>system</scope>"),
    ];
    let pom = project_pom(
        "app",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
             <dependencies>{}</dependencies>",
            managed.concat(),
            declared.concat()
        ),
    );
    let project = build_with(
        pom,
        &MemorySource::new(),
        ModelPolicy::PROJECT,
        &ActivationContext::default(),
    )
    .unwrap();
    assert_eq!(
        summary(&project.dependencies),
        [
            "lib:1",
            "lib:2",
            "lib:3",
            "scoped:4:test",
            "scoped:?:runtime",
            "sys:5:system"
        ]
    );
    let scoped = &project.dependencies[3];
    assert_eq!(scoped.optional, None);
    let excluded: Vec<&str> = scoped
        .exclusions
        .iter()
        .map(|e| e.group_id.as_str())
        .collect();
    assert_eq!(excluded, ["own"]);
    assert_eq!(
        project.dependencies[5].system_path.as_deref(),
        Some("C:/lib/sys.jar")
    );
    assert_eq!(project.dependency_management.dependencies.len(), 6);
    assert_eq!(
        project.dependency_management.dependencies[3]
            .version
            .as_deref(),
        Some("9")
    );
}

/// Entries that share a key only after interpolation each fill in what the
/// earlier ones left unset, the exclusions from the first that has any. Once
/// the POM imports a BOM, Maven keys the management first: the last local
/// entry for a key replaces the others, and a BOM entry under a local key is
/// dropped. Maven 3.9.12 locks `foo:2.0:runtime`, `foo:1.0:runtime` and
/// `foo:2.0` here.
#[test]
fn managed_entries_sharing_a_key_merge_like_maven() {
    let unwanted = "<exclusions><exclusion><groupId>p</groupId><artifactId>unwanted</artifactId>\
        </exclusion></exclusions>";
    let parent = project_pom(
        "parent",
        &format!(
            "<packaging>pom</packaging><properties><lib.name>foo</lib.name></properties>\
             <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            dep(
                "p",
                "${lib.name}",
                &format!("<version>1.0</version><scope>runtime</scope>{unwanted}")
            ),
        ),
    );
    let other = project_pom(
        "other",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            dep("p", "bar", "<version>1</version>")
        ),
    );
    let colliding = project_pom(
        "colliding",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            dep(
                "p",
                "foo",
                &format!("<version>1.0</version><scope>runtime</scope>{unwanted}")
            )
        ),
    );
    let child = |parent: &str, managed: &str| {
        pom(&format!(
            "<project>{parent}<groupId>g</groupId><artifactId>app</artifactId><version>1</version>\
             <dependencyManagement><dependencies>{}{managed}</dependencies>\
             </dependencyManagement><dependencies>{}</dependencies></project>",
            dep("p", "foo", "<version>2.0</version>"),
            dep("p", "foo", ""),
        ))
    };
    let inherit = "<parent><groupId>g</groupId><artifactId>parent</artifactId>\
        <version>1</version></parent>";
    for (child, expected, excluded) in [
        (child(inherit, ""), "foo:2.0:runtime", &["unwanted"][..]),
        (
            child(inherit, &import("other", "1")),
            "foo:1.0:runtime",
            &["unwanted"],
        ),
        (child("", &import("colliding", "1")), "foo:2.0", &[]),
    ] {
        let source = MemorySource::new()
            .with_parent("g", "parent", "1", parent.clone())
            .with_import("g", "other", "1", other.clone())
            .with_import("g", "colliding", "1", colliding.clone());
        let project = build(child, source, &ActivationContext::default()).unwrap();
        assert_eq!(summary(&project.dependencies), [expected]);
        let exclusions: Vec<&str> = project.dependencies[0]
            .exclusions
            .iter()
            .map(|e| e.artifact_id.as_str())
            .collect();
        assert_eq!(exclusions, excluded, "{expected}");
    }
}

/// A BOM that imports nothing keeps every entry, so its importer takes the
/// first for a key: Maven 3.9.12 locks `foo:1.0:runtime`.
#[test]
fn a_bom_without_imports_keeps_entries_sharing_a_key() {
    let bom = project_pom(
        "dupes",
        &format!(
            "<properties><lib.name>foo</lib.name></properties>\
             <dependencyManagement><dependencies>{}{}</dependencies></dependencyManagement>",
            dep(
                "p",
                "${lib.name}",
                "<version>1.0</version><scope>runtime</scope>"
            ),
            dep("p", "foo", "<version>2.0</version>"),
        ),
    );
    let child = project_pom(
        "app",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
             <dependencies>{}</dependencies>",
            import("dupes", "1"),
            dep("p", "foo", ""),
        ),
    );
    let source = MemorySource::new().with_import("g", "dupes", "1", bom);
    let project = build(child, source, &ActivationContext::default()).unwrap();
    assert_eq!(summary(&project.dependencies), ["foo:1.0:runtime"]);
}

/// An active profile's management replaces the POM's entry of the same key,
/// while its dependencies take the POM's management before the profile's
/// own. An inactive profile is not interpolated, so its system dependency
/// may lack a `<systemPath>` and its version may name a chain of properties
/// deeper than raeva expands.
#[test]
fn active_profiles_merge_their_dependencies_and_management() {
    let pom = project_pom(
        "app",
        &format!(
            "<properties>{}</properties>\
             <dependencyManagement><dependencies>{}{}</dependencies></dependencyManagement>\
             <dependencies>{}</dependencies><profiles>\
             <profile><id>on</id><activation><activeByDefault>true</activeByDefault>\
             </activation><dependencyManagement><dependencies>{}{}</dependencies>\
             </dependencyManagement><dependencies>{}{}</dependencies></profile>\
             <profile><id>off</id><activation><property><name>never</name></property>\
             </activation><dependencies>{}{}</dependencies></profile></profiles>",
            (0..200)
                .map(|n| format!("<p{n}>${{p{}}}</p{n}>", n + 1))
                .collect::<String>(),
            dep("m", "base", "<version>1</version>"),
            dep("m", "both", "<version>1</version>"),
            dep("m", "both", ""),
            dep("m", "both", "<version>2</version>"),
            dep("m", "profile", "<version>3</version>"),
            dep("m", "base", ""),
            dep("m", "profile", ""),
            dep("m", "sys", "<version>1</version><scope>system</scope>"),
            dep("m", "deep", "<version>${p0}</version>"),
        ),
    );
    let project = build(pom, MemorySource::new(), &ActivationContext::default()).unwrap();
    assert_eq!(
        summary(&project.dependencies),
        ["both:2", "base:1", "profile:3"]
    );
}

#[test]
fn system_dependencies_need_an_absolute_path() {
    for (path, ok) in [
        ("", false),
        ("<systemPath>lib/x.jar</systemPath>", false),
        ("<systemPath>C:\\x.jar</systemPath>", true),
    ] {
        let pom = project_pom(
            "app",
            &format!(
                "<dependencies>{}</dependencies>",
                dep(
                    "m",
                    "sys",
                    &format!("<version>1</version><scope>system</scope>{path}")
                )
            ),
        );
        let result = build_with(
            pom,
            &MemorySource::new(),
            ModelPolicy::PROJECT,
            &ActivationContext::default(),
        );
        assert_eq!(result.is_ok(), ok, "{path}: {result:?}");
    }
}

/// A `-D` user property overlaid on the POM wins over an active profile's
/// property of the same name, in the coordinates as everywhere else, while
/// the profile's other properties apply; a profile module the POM lists
/// already is not added twice.
#[test]
fn user_properties_win_over_injected_profile_properties() {
    let mut pom = Pom::parse(
        r"<project>
          <groupId>g</groupId><artifactId>app</artifactId><version>${revision}</version>
          <properties><revision>1.0</revision></properties>
          <modules><module>core</module></modules>
          <profiles><profile><id>p</id>
            <activation><activeByDefault>true</activeByDefault></activation>
            <properties><revision>2.0</revision><extra>on</extra></properties>
            <modules><module>core</module><module>tools</module></modules>
          </profile></profiles>
        </project>",
    )
    .unwrap();
    // Only the overlay, without the context's user properties that the
    // effective properties apply again at the end.
    pom.overlay_user_properties([("revision", "3.0")]);
    let project = build(pom, MemorySource::new(), &ActivationContext::default()).unwrap();
    assert_eq!(project.version, "3.0");
    assert_eq!(
        project.properties.get("extra").map(String::as_str),
        Some("on")
    );
    assert_eq!(project.modules, ["core", "tools"]);
}

/// Aggregation is not inherited: a parent's profile modules stay the
/// parent's.
#[test]
fn modules_are_not_inherited() {
    let parent = project_pom(
        "parent",
        "<packaging>pom</packaging><modules><module>a</module></modules><profiles><profile>\
         <id>p</id><activation><activeByDefault>true</activeByDefault></activation><modules>\
         <module>b</module></modules></profile></profiles>",
    );
    let child = pom(
        "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
         <version>1</version></parent><artifactId>app</artifactId><packaging>pom</packaging>\
         <modules><module>${project.artifactId}-core</module></modules></project>",
    );
    let source = MemorySource::new().with_parent("g", "parent", "1", parent);
    let project = build(child, source, &ActivationContext::default()).unwrap();
    assert_eq!(project.modules, ["app-core"]);
}

/// Each active profile is injected in turn, so the repositories of a later
/// one come first, and a profile repository replaces the POM's with its id.
#[test]
fn profile_repositories_are_injected_ahead_of_the_pom_ones() {
    let repo = |id: &str, url: &str| {
        format!(
            "<repositories><repository><id>{id}</id><url>{url}</url></repository></repositories>"
        )
    };
    let profile = |id: &str, repositories: String| {
        format!(
            "<profile><id>{id}</id><activation><activeByDefault>true</activeByDefault>\
             </activation>{repositories}</profile>"
        )
    };
    let pom = project_pom(
        "app",
        &format!(
            "<repositories><repository><id>shared</id><url>https://pom.example/shared</url>\
             </repository><repository><id>own</id><url>https://pom.example/own</url>\
             </repository></repositories><profiles>{}{}</profiles>",
            profile("a", repo("shared", "https://a.example/shared")),
            profile("b", repo("b", "https://b.example/b")),
        ),
    );
    let project = build(pom, MemorySource::new(), &ActivationContext::default()).unwrap();
    let urls: Vec<&str> = project
        .repositories
        .iter()
        .map(|r| r.url.as_str())
        .collect();
    assert_eq!(
        urls,
        [
            "https://b.example/b",
            "https://a.example/shared",
            "https://pom.example/own"
        ]
    );
}

#[test]
fn active_profile_repositories_serve_the_parent_lookup() {
    let child = |activation: &str| {
        pom(&format!(
            "<project><groupId>g</groupId><artifactId>c</artifactId><version>1</version>\
             <parent><groupId>g</groupId><artifactId>par</artifactId><version>1</version>\
             <relativePath/></parent><profiles><profile><id>spring</id>{activation}\
             <repositories><repository><id>snap</id><url>https://snap.example/</url>\
             </repository></repositories></profile></profiles></project>"
        ))
    };
    let source = || {
        MemorySource::new()
            .with_parent("g", "par", "1", project_pom("par", ""))
            .with_gate("par", "https://snap.example/")
    };
    let explicit = ActivationContext {
        active_profiles: vec!["spring".to_string()],
        ..ActivationContext::default()
    };
    build(child(""), source(), &explicit).expect("-P profile repository");
    let default = "<activation><activeByDefault>true</activeByDefault></activation>";
    build(child(default), source(), &ActivationContext::default()).expect("default profile");
    let error = build(child(""), source(), &ActivationContext::default()).unwrap_err();
    assert!(model_error(error).starts_with("parent not found"));
}

/// Inherited repositories reach the source before the BOM imports, so a BOM
/// hosted only in a parent's repository, whose URL is a property, resolves.
#[test]
fn parent_repositories_are_observed_before_bom_imports() {
    let parent = pom(
        "<project><groupId>com.base</groupId><artifactId>parent</artifactId>\
         <version>2</version><packaging>pom</packaging>\
         <properties><snap.url>https://snap.example/repo/</snap.url></properties>\
         <repositories><repository><id>snap</id><url>${snap.url}</url></repository>\
         </repositories></project>",
    );
    let child = pom(&format!(
        "<project><groupId>com.example</groupId><artifactId>child</artifactId>\
         <parent><groupId>com.base</groupId><artifactId>parent</artifactId>\
         <version>2</version></parent><dependencyManagement><dependencies>{}\
         </dependencies></dependencyManagement></project>",
        import("bom", "1")
    ));
    let source = MemorySource::new()
        .with_parent("com.base", "parent", "2", parent)
        .with_import(
            "g",
            "bom",
            "1",
            project_pom("bom", "<packaging>pom</packaging>"),
        )
        .with_gate("bom", "https://snap.example/repo/");
    let project = build(child, source, &ActivationContext::default()).expect("BOM resolves");
    assert_eq!(project.repositories[0].url, "https://snap.example/repo/");
}

#[test]
fn parent_is_looked_up_by_raw_coordinates() {
    let raw = "${revision}${sha1}${changelist}";
    let parent = pom(&format!(
        "<project><groupId>com.example</groupId><artifactId>parent</artifactId>\
         <version>{raw}</version><packaging>pom</packaging><properties>\
         <revision>0.0</revision><sha1/><changelist>-SNAPSHOT</changelist></properties>\
         </project>"
    ));
    let child = pom(&format!(
        "<project><parent><groupId>com.example</groupId><artifactId>parent</artifactId>\
         <version>{raw}</version></parent><artifactId>child</artifactId>\
         <properties><revision>2.0.0</revision></properties><dependencies>{}</dependencies>\
         </project>",
        dep(
            "com.example",
            "sibling",
            "<version>${project.parent.version}</version>"
        )
    ));
    let source = MemorySource::new().with_parent("com.example", "parent", raw, parent);
    let project = build_with(
        child.clone(),
        &source,
        ModelPolicy::DEPENDENCY,
        &ActivationContext::default(),
    )
    .unwrap();
    assert_eq!(
        source.lookups(),
        [format!("parent com.example:parent:{raw} (Project)")]
    );
    assert_eq!(
        (project.group_id.as_str(), project.version.as_str()),
        ("com.example", "2.0.0-SNAPSHOT")
    );
    assert_eq!(summary(&project.dependencies), ["sibling:2.0.0-SNAPSHOT"]);

    // The expression cannot be fetched from a repository.
    let error = build(child, MemorySource::new(), &ActivationContext::default()).unwrap_err();
    assert!(
        matches!(&error, MemorySourceError::Model(PomError::ParentExpression(coord))
            if *coord == format!("com.example:parent:{raw}")),
        "{error}"
    );
}

/// Maven imports BOMs after inheritance and interpolation, in declaration
/// order: the model's own entries win, then the first import that manages a
/// coordinate. An import's coordinates come from the importer's properties;
/// a BOM's managed versions are interpolated
/// with its own lineage's properties, and neither its properties nor its
/// profiles reach the importer.
#[test]
fn boms_are_imported_like_maven() {
    let bom_parent = project_pom(
        "bom-parent",
        "<packaging>pom</packaging><properties><lib.version>1.5</lib.version></properties>",
    );
    let first = pom(&format!(
        "<project><parent><groupId>g</groupId><artifactId>bom-parent</artifactId>\
         <version>1</version></parent><artifactId>first</artifactId><packaging>pom</packaging>\
         <properties><leaked>yes</leaked></properties><dependencyManagement><dependencies>\
         {}{}{}</dependencies></dependencyManagement><profiles><profile><id>bom-profile\
         </id><activation><activeByDefault>true</activeByDefault></activation><dependencies>\
         {}</dependencies></profile></profiles></project>",
        dep("m", "shared", "<version>${lib.version}</version>"),
        dep("m", "local", "<version>9</version>"),
        import("nested", "1"),
        dep("m", "from-bom-profile", "<version>1</version>"),
    ));
    let nested = project_pom(
        "nested",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            dep("m", "deep", "<version>7</version>")
        ),
    );
    let second = project_pom(
        "second",
        &format!(
            "<dependencyManagement><dependencies>{}{}</dependencies></dependencyManagement>",
            dep("m", "shared", "<version>2</version>"),
            dep("m", "only-second", "<version>3</version>"),
        ),
    );
    let importer = project_pom(
        "app",
        &format!(
            "<properties><second.version>1</second.version><bom.type>pom</bom.type>\
             </properties>\
             <dependencyManagement><dependencies>{}{}{}</dependencies>\
             </dependencyManagement><dependencies>{}{}{}{}</dependencies>",
            import("first", "1"),
            dep("m", "local", "<version>1</version>"),
            dep(
                "g",
                "second",
                "<version>${second.version}</version><type>${bom.type}</type>\
                 <scope>import</scope>"
            ),
            dep("m", "shared", ""),
            dep("m", "local", ""),
            dep("m", "only-second", ""),
            dep("m", "deep", ""),
        ),
    );
    let source = MemorySource::new()
        .with_import("g", "first", "1", first)
        .with_import("g", "nested", "1", nested)
        .with_import("g", "second", "1", second)
        .with_parent("g", "bom-parent", "1", bom_parent);
    let project = build(importer, source, &ActivationContext::default()).unwrap();
    assert_eq!(
        summary(&project.dependencies),
        ["shared:1.5", "local:1", "only-second:3", "deep:7"]
    );
    assert_eq!(
        summary(&project.dependency_management.dependencies),
        ["local:1", "shared:1.5", "deep:7", "only-second:3"]
    );
    assert_eq!(project.properties.get("leaked"), None);
}

/// An import whose version only a sibling BOM defines, a cycle of imports,
/// a BOM the source does not have, an import without a version, and a BOM
/// whose own dependency has no artifactId, no version even from the BOM's
/// management, or a system scope without a path fail the build.
#[test]
fn bom_imports_fail_like_maven() {
    let sibling = project_pom(
        "sibling",
        "<packaging>pom</packaging><properties><other.version>1</other.version></properties>",
    );
    let cycle_a = project_pom(
        "a",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            import("b", "1")
        ),
    );
    let cycle_b = project_pom(
        "b",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            import("a", "1")
        ),
    );
    let source = || {
        MemorySource::new()
            .with_import("g", "sibling", "1", sibling.clone())
            .with_import("g", "other", "1", project_pom("other", ""))
            .with_import("g", "a", "1", cycle_a.clone())
            .with_import("g", "b", "1", cycle_b.clone())
            .with_import(
                "g",
                "invalid",
                "1",
                project_pom(
                    "invalid",
                    "<dependencies><dependency><groupId>g</groupId><version>1</version>\
                     </dependency></dependencies>",
                ),
            )
            .with_import(
                "g",
                "unversioned",
                "1",
                project_pom(
                    "unversioned",
                    &format!("<dependencies>{}</dependencies>", dep("g", "unused", "")),
                ),
            )
            .with_import(
                "g",
                "pathless",
                "1",
                project_pom(
                    "pathless",
                    &format!(
                        "<dependencies>{}</dependencies>",
                        dep("g", "tools", "<version>1</version><scope>system</scope>")
                    ),
                ),
            )
            .with_import(
                "g",
                "unexpanded",
                "1",
                project_pom(
                    "unexpanded",
                    &format!(
                        "<dependencies>{}</dependencies>",
                        dep(
                            "g",
                            "tools",
                            "<version>1</version><scope>system</scope>\
                             <systemPath>${missing}/x.jar</systemPath>"
                        )
                    ),
                ),
            )
            .with_import(
                "g",
                "badid",
                "1",
                project_pom(
                    "badid",
                    &format!(
                        "<dependencies>{}</dependencies>",
                        dep("g", "bad+id", "<version>1</version>")
                    ),
                ),
            )
            .with_import(
                "g",
                "pathed",
                "1",
                project_pom(
                    "pathed",
                    &format!(
                        "<dependencies>{}</dependencies>",
                        dep(
                            "g",
                            "x",
                            "<version>1</version><systemPath>/opt/unused.jar</systemPath>"
                        )
                    ),
                ),
            )
    };
    for (imports, message) in [
        (
            format!(
                "{}{}",
                import("sibling", "1"),
                import("other", "${other.version}")
            ),
            "BOM import g:other:${other.version} has an unresolved expression",
        ),
        (
            import("${other.group}", "1"),
            "BOM import g:${other.group}:1 has an unresolved expression",
        ),
        (import("a", "1"), "BOM import cycle detected for g:a:1:pom"),
        (import("missing", "1"), "BOM not found: g:missing:1"),
        (
            import("invalid", "1"),
            "'dependencies.dependency.artifactId' for g::jar is missing",
        ),
        (
            import("unversioned", "1"),
            "'dependencies.dependency.version' for g:unused:jar is missing",
        ),
        (import("pathless", "1"), "systemPath"),
        (
            import("unexpanded", "1"),
            "requires an absolute <systemPath>",
        ),
        (
            import("badid", "1"),
            "'dependencies.dependency.artifactId' for g:bad+id:jar with value 'bad+id' does not \
             match a valid id pattern.",
        ),
        (
            import("pathed", "1"),
            "'dependencies.dependency.systemPath' for g:x:jar must be omitted.",
        ),
        (
            dep("g", "a", "<type>pom</type><scope>import</scope>"),
            "import scope requires a version for g:a",
        ),
    ] {
        let importer = project_pom(
            "app",
            &format!(
                "<dependencyManagement><dependencies>{imports}</dependencies></dependencyManagement>"
            ),
        );
        let error = build(importer, source(), &ActivationContext::default()).unwrap_err();
        let error = model_error(error);
        assert!(error.contains(message), "{error}");
    }
}

/// Maven tries every import before it reports a model error, so a missing
/// BOM fails the model even after an invalid one, at any depth. An import
/// is checked only for the coordinates it looks up.
#[test]
fn a_missing_import_fails_over_an_invalid_one() {
    let management = |imports: &str| {
        format!(
            "<dependencyManagement><dependencies>{imports}</dependencies></dependencyManagement>"
        )
    };
    let source = || {
        MemorySource::new()
            .with_import(
                "g",
                "invalid",
                "1",
                project_pom(
                    "invalid",
                    &format!("<dependencies>{}</dependencies>", dep("g", "unused", "")),
                ),
            )
            .with_import(
                "g",
                "wrapper",
                "1",
                project_pom("wrapper", &management(&import("invalid", "1"))),
            )
            .with_import(
                "g",
                "fine",
                "1",
                project_pom(
                    "fine",
                    &management(&dep("g", "lib", "<version>2</version>")),
                ),
            )
    };
    for imports in [
        [import("invalid", "1"), import("missing", "1")],
        [import("missing", "1"), import("invalid", "1")],
        [import("wrapper", "1"), import("missing", "1")],
        [
            import("fine", "1"),
            import("missing", "1").replace("<groupId>g</groupId>", "<groupId>bad+g</groupId>"),
        ],
    ] {
        let importer = project_pom("app", &management(&imports.concat()));
        let error = build(importer, source(), &ActivationContext::default()).unwrap_err();
        let error = model_error(error);
        assert!(error.contains("BOM not found: "), "{error}");
        assert!(error.contains(":missing:1"), "{error}");
    }
    let unused_path = import("fine", "1").replace(
        "<scope>import</scope>",
        "<scope>import</scope><systemPath>/opt/unused.jar</systemPath>",
    );
    let importer = project_pom("app", &management(&unused_path));
    let project = build(importer, source(), &ActivationContext::default()).unwrap();
    assert_eq!(
        summary(&project.dependency_management.dependencies),
        ["lib:2"]
    );
}

/// Each BOM interpolates its entries with its own properties; neither a
/// BOM it imports nor the importer fills them.
#[test]
fn an_imported_boms_properties_stay_in_it() {
    let management = |entries: &str| {
        format!(
            "<dependencyManagement><dependencies>{entries}</dependencies></dependencyManagement>"
        )
    };
    let source = MemorySource::new()
        .with_import(
            "g",
            "props",
            "1",
            project_pom(
                "props",
                &format!(
                    "<properties><lib.version>9</lib.version></properties>{}",
                    management(&dep("g", "other", "<version>1</version>"))
                ),
            ),
        )
        .with_import(
            "g",
            "platform",
            "1",
            project_pom(
                "platform",
                &management(&format!(
                    "{}{}",
                    dep("g", "lib", "<version>${lib.version}</version>"),
                    import("props", "1")
                )),
            ),
        );
    let importer = project_pom(
        "app",
        &format!(
            "<properties><lib.version>5</lib.version></properties>{}",
            management(&import("platform", "1"))
        ),
    );
    let project = build(importer, source, &ActivationContext::default()).unwrap();
    assert_eq!(
        summary(&project.dependency_management.dependencies),
        ["lib:${lib.version}", "other:1"]
    );
}

/// A BOM's own dependency may take its version from the BOM's management.
#[test]
fn a_bom_dependency_may_take_its_version_from_the_bom() {
    let bom = project_pom(
        "bom",
        &format!(
            "<packaging>pom</packaging><dependencyManagement><dependencies>{}</dependencies>\
             </dependencyManagement><dependencies>{}</dependencies>",
            dep("g", "leaf", "<version>2</version>"),
            dep("g", "leaf", ""),
        ),
    );
    let importer = project_pom(
        "app",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            import("bom", "1")
        ),
    );
    let source = MemorySource::new().with_import("g", "bom", "1", bom);
    let project = build(importer, source, &ActivationContext::default()).unwrap();
    assert_eq!(
        summary(&project.dependency_management.dependencies),
        ["leaf:2"]
    );
}

/// Maven cannot convert a managed `<type/>` entry to an artifact and fails
/// the build, even when nothing uses the entry.
#[test]
fn an_empty_managed_type_fails() {
    let importer = project_pom(
        "app",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            dep("g", "lib", "<version>2</version><type/>"),
        ),
    );
    let error = build(importer, MemorySource::new(), &ActivationContext::default()).unwrap_err();
    assert!(
        matches!(error, MemorySourceError::Model(PomError::EmptyManagedType(ref key)) if key == "g:lib:"),
        "{error:?}"
    );
}

/// Maven interpolates the importer's properties on an import's scope before
/// it decides whether the entry is an import. A scope of `${import.scope}`
/// that becomes `import` is imported.
#[test]
fn an_import_scope_property_is_interpolated_before_import() {
    let bom = project_pom(
        "bom",
        &format!(
            "<packaging>pom</packaging><dependencyManagement><dependencies>{}</dependencies>\
             </dependencyManagement>",
            dep("g", "leaf", "<version>2</version>")
        ),
    );
    let importer = pom(
        "<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>\
         <properties><import.scope>import</import.scope></properties>\
         <dependencyManagement><dependencies>\
         <dependency><groupId>g</groupId><artifactId>bom</artifactId>\
         <version>1</version><type>pom</type><scope>${import.scope}</scope></dependency>\
         </dependencies></dependencyManagement></project>",
    );
    let source = MemorySource::new().with_import("g", "bom", "1", bom);
    let project = build(importer, source, &ActivationContext::default()).unwrap();
    assert_eq!(
        summary(&project.dependency_management.dependencies),
        ["leaf:2"]
    );
}

/// Maven imports only an entry whose type is `pom`: one without a `<type>`,
/// or with `jar` or `platform`, stays a managed dependency.
#[test]
fn only_a_pom_typed_entry_is_imported() {
    let bom = project_pom(
        "bom",
        &format!(
            "<packaging>pom</packaging><dependencyManagement><dependencies>{}</dependencies>\
             </dependencyManagement>",
            dep("g", "leaf", "<version>2</version>")
        ),
    );
    for type_ in ["", "<type>jar</type>", "<type>platform</type>"] {
        let importer = project_pom(
            "app",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
                 <dependencies>{}</dependencies>",
                dep(
                    "g",
                    "bom",
                    &format!("<version>1</version>{type_}<scope>import</scope>")
                ),
                dep("g", "leaf", "<version>1</version>"),
            ),
        );
        let source = MemorySource::new().with_import("g", "bom", "1", bom.clone());
        let project = build(importer, source, &ActivationContext::default()).unwrap();
        assert_eq!(summary(&project.dependencies), ["leaf:1"], "{type_}");
        assert_eq!(
            summary(&project.dependency_management.dependencies),
            ["bom:1:import"],
            "{type_}"
        );
    }
}

/// An imported BOM is built in a scope of its own, as Maven builds it with
/// a copy of the model resolver: its own repositories, then its parent's,
/// then its effective ones are observed inside the scope, before its parent
/// and nested imports are requested, and the scope ends with the BOM.
#[test]
fn an_imported_boms_repositories_are_observed_in_its_scope() {
    let bom_parent = project_pom(
        "bp",
        "<packaging>pom</packaging><repositories><repository><id>parent</id>\
         <url>https://bom-parent.example/</url></repository></repositories>",
    );
    let bom = pom(&format!(
        "<project><parent><groupId>g</groupId><artifactId>bp</artifactId>\
         <version>1</version></parent><artifactId>b</artifactId>\
         <packaging>pom</packaging><repositories><repository><id>own</id>\
         <url>https://bom.example/</url></repository></repositories>\
         <dependencyManagement><dependencies>{}</dependencies>\
         </dependencyManagement></project>",
        import("nested", "1")
    ));
    let pom = project_pom(
        "app",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            import("b", "1")
        ),
    );
    let source = MemorySource::new()
        .with_parent("g", "bp", "1", bom_parent)
        .with_import("g", "b", "1", bom)
        .with_import(
            "g",
            "nested",
            "1",
            project_pom("nested", "<packaging>pom</packaging>"),
        );
    build_with(
        pom,
        &source,
        ModelPolicy::DEPENDENCY,
        &ActivationContext::default(),
    )
    .expect("build");
    assert_eq!(
        source.events(),
        [
            "prefetch g:b:1",
            "import g:b:1",
            "enter",
            "observe https://bom.example/",
            "parent g:bp:1 (Import)",
            "observe https://bom-parent.example/",
            "effective https://bom.example/,https://bom-parent.example/",
            "prefetch g:nested:1",
            "import g:nested:1",
            "enter",
            "leave",
            "leave",
        ]
    );
}

#[test]
fn repository_provenance_survives_inheritance_without_trusting_remote_parents() {
    let parent = pom(
        r#"<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>
        <repositories><repository><id>remote</id><url>https://remote.example/</url><root_declared>true</root_declared><rootDeclared>true</rootDeclared></repository></repositories>
        </project>"#,
    );
    let pom = Pom::parse(r#"<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>root</artifactId>
        <properties><registry>https://root.example/</registry></properties>
        <profiles><profile><id>active</id><activation><activeByDefault>true</activeByDefault></activation>
        <repositories><repository><id>local</id><url>${registry}</url></repository></repositories></profile></profiles>
        </project>"#).unwrap();
    let source = MemorySource::new().with_parent("g", "parent", "1", parent);
    let project = build_with(
        pom,
        &source,
        ModelPolicy::PROJECT,
        &ActivationContext::default(),
    )
    .unwrap();
    let repository = |id: &str| {
        project
            .repositories
            .iter()
            .find(|r| r.id.as_deref() == Some(id))
            .unwrap()
    };
    assert!(repository("local").root_declared);
    assert_eq!(repository("local").url, "https://root.example/");
    assert!(!repository("remote").root_declared);
}

/// `${os.name}`, `${os.arch}`, `${os.version}` and `${os.family}` in the
/// `os-activation` fixture interpolate as `help:effective-pom` recorded them
/// on each platform, with that fixture's `-Dos.version=10.0` user property.
/// The recording machine runs Windows 10; raeva assumes Windows 11.
#[test]
fn os_properties_interpolate_like_maven_on_each_platform() {
    let pom = Pom::parse(include_str!(
        "../../../test-fixtures/maven-parity/os-activation/pom.xml"
    ))
    .unwrap();
    for (rust_os, rust_arch, recorded) in [
        (
            "linux",
            "x86_64",
            include_str!(
                "../../../test-fixtures/maven-parity/os-activation/maven-3.9.11-linux-x86_64.txt"
            ),
        ),
        (
            "macos",
            "aarch64",
            include_str!(
                "../../../test-fixtures/maven-parity/os-activation/maven-3.9.11-macos-aarch64.txt"
            ),
        ),
        (
            "windows",
            "x86_64",
            include_str!(
                "../../../test-fixtures/maven-parity/os-activation/maven-3.9.11-windows-x86_64.txt"
            ),
        ),
    ] {
        let mut ctx = ActivationContext::default();
        ctx.set_platform(rust_os, rust_arch);
        let mut pom = pom.clone();
        pom.properties.insert("os.version", "10.0");
        let info = crate::model::project_info(&pom, &pom.properties, &ctx).unwrap();
        for line in recorded.lines() {
            let Some((key, expected)) = line.split_once('=') else {
                continue;
            };
            if !matches!(key, "n" | "a" | "v" | "f") {
                continue;
            }
            let actual = pom
                .properties
                .interpolate_str(&format!("${{{key}}}"), &info)
                .unwrap();
            if rust_os == "windows" && key == "n" {
                assert_eq!(expected, "Windows 10");
                assert_eq!(actual, "Windows 11");
            } else {
                assert_eq!(actual, expected, "${{{key}}} on {rust_os}");
            }
        }
    }
}

/// The coordinates interpolate before they are known, so one naming
/// itself is empty and refused; a `<parent>` interpolates with the platform
/// being locked, `${java.version}` with the known JDK, and the model's
/// `prerequisites.maven` is a property.
#[test]
fn coordinates_and_model_values_interpolate_like_maven() {
    for (group, version, field) in [
        ("${project.groupId}", "1", "groupId"),
        ("g", "${project.version}", "version"),
    ] {
        let xml = format!(
            "<project><groupId>{group}</groupId><artifactId>a</artifactId>\
             <version>{version}</version></project>"
        );
        let error = build(
            pom(&xml),
            MemorySource::new(),
            &ActivationContext::default(),
        );
        assert_eq!(
            model_error(error.unwrap_err()),
            format!("invalid model: {field} must not be empty")
        );
    }
    // Maven reads a coordinate naming itself from the property of that
    // name, as in com.aliyun.mns:aliyun-sdk-mns:2.0.0, even when it
    // differs from the requested coordinate.
    let project = build(
        pom("<project><properties><project.groupId>p</project.groupId>\
             <project.artifactId>${x}</project.artifactId><x>a</x>\
             <project.version>2</project.version></properties>\
             <groupId>${project.groupId}</groupId><artifactId>${project.artifactId}</artifactId>\
             <version>${project.version}</version></project>"),
        MemorySource::new(),
        &ActivationContext::default(),
    )
    .unwrap();
    assert_eq!(
        (
            project.group_id.as_str(),
            project.artifact_id.as_str(),
            project.version.as_str()
        ),
        ("p", "a", "2")
    );
    // A property that reads its own coordinate again is a cycle, which
    // Maven 3.9.12 refuses too (parity fixture j2a).
    let error = build(
        pom(
            "<project><properties><project.groupId>com.${project.groupId}</project.groupId>\
             </properties><groupId>${project.groupId}</groupId><artifactId>a</artifactId>\
             <version>1</version></project>",
        ),
        MemorySource::new(),
        &ActivationContext::default(),
    );
    assert!(error.is_err(), "{error:?}");

    let project = build(
        pom("<project><groupId>g</groupId><artifactId>foo</artifactId>\
             <version>${project.artifactId}-1</version></project>"),
        MemorySource::new(),
        &ActivationContext::default(),
    )
    .unwrap();
    assert_eq!(project.version, "foo-1");

    let pom_xml = format!(
        "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
         <version>${{os.arch}}</version></parent><artifactId>child</artifactId>\
         <version>${{project.parent.version}}</version><prerequisites><maven>3.0</maven>\
         </prerequisites><dependencies>{}{}</dependencies><profiles><profile><id>jdk</id>\
         <activation><jdk>${{java.version}}</jdk></activation><dependencies>{}</dependencies>\
         </profile></profiles></project>",
        dep(
            "m",
            "api",
            "<version>${project.prerequisites.maven}</version>"
        ),
        dep("m", "core", "<version>${pom.prerequisites.maven}</version>"),
        dep("m", "on-jdk", "<version>1</version>"),
    );
    let mut ctx = ActivationContext {
        environment: crate::ModelEnvironment::builder().jdk_version("27").build(),
        ..ActivationContext::default()
    };
    ctx.set_platform("macos", "aarch64");
    let parent = pom(
        "<project><groupId>g</groupId><artifactId>parent</artifactId>\
         <version>${os.arch}</version></project>",
    );
    let source = MemorySource::new().with_parent("g", "parent", "${os.arch}", parent);
    let project = build(pom(&pom_xml), source, &ctx).unwrap();
    assert_eq!(project.version, "aarch64");
    assert_eq!(
        summary(&project.dependencies),
        ["api:3.0", "core:3.0", "on-jdk:1"]
    );
}

/// Maven 3.9.11's `DefaultModelValidator.validateEffectiveModel` messages for
/// the coordinates of a project it builds.
#[test]
fn build_coordinates_are_validated_like_maven() {
    let project = |group: &str, artifact: &str, version: &str| {
        let xml = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>{group}</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version></project>"
        );
        build(
            pom(&xml),
            MemorySource::new(),
            &ActivationContext::default(),
        )
        .unwrap()
    };
    let error = |project: Project| match project.validate_build_coordinates() {
        Err(PomError::InvalidModel(message)) => message,
        other => panic!("expected an invalid model, got {other:?}"),
    };

    assert!(
        project("org.ex_1-a", "A.b_c-9", "1.0:x")
            .validate_build_coordinates()
            .is_ok(),
        "a colon in the version is only a Maven warning"
    );
    assert_eq!(
        error(project("org.v", "a+b", "1")),
        "'artifactId' with value 'a+b' does not match a valid id pattern."
    );
    assert_eq!(
        error(project("${undefined.group}", "a", "1")),
        "'groupId' with value '${undefined.group}' does not match a valid id pattern."
    );
    assert_eq!(
        error(project("org.v", "a", "1-${undefined}-2")),
        "'version' must be a constant version but is '1-${undefined}-2'."
    );
    assert_eq!(
        error(project("org.v", "\u{e9}", "1")),
        "'artifactId' with value '\u{e9}' does not match a valid id pattern."
    );

    // POM text in the message is escaped and cut. A raw control character
    // is refused earlier, but a bidirectional override is not.
    let version = format!("${{x}}\u{202e}{}", "9".repeat(300));
    let message = error(project("org.v", "a", &version));
    assert!(!message.contains('\u{202e}'), "{message}");
    assert!(message.contains("${x}\\u{202e}99"), "{message}");
    assert!(message.ends_with("9... (307 bytes)'."), "{message}");
    assert!(message.len() < 250, "{message}");
}

/// Maven 3.9.12 refuses a project dependency version with a character it
/// bans in file names, such as the `*` of `[1.2.*]`.
#[test]
fn project_dependency_versions_are_validated_like_maven() {
    let xml = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
               <artifactId>app</artifactId><version>1</version><dependencies>\
               <dependency><groupId>p</groupId><artifactId>vlib</artifactId>\
               <version>[1.2.*]</version></dependency></dependencies></project>";
    let project = build(pom(xml), MemorySource::new(), &ActivationContext::default()).unwrap();
    match project.validate_build_coordinates() {
        Err(PomError::InvalidModel(message)) => assert_eq!(
            message,
            "'dependencies.dependency.version' for p:vlib:jar must not contain any of these \
             characters \\/:\"<>|?* but found *"
        ),
        other => panic!("expected an invalid model, got {other:?}"),
    }
}

/// Maven fails a project whose parent read through `<relativePath>` repeats
/// a profile id, and only warns when the parent comes from a repository.
#[test]
fn a_local_parent_with_a_repeated_profile_id_fails_the_project() {
    let ctx = ActivationContext::default();
    let parent = |provenance| {
        let mut parent = pom(
            "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
             <packaging>pom</packaging><profiles><profile><id>p</id></profile><profile>\
             <id>p</id></profile></profiles></project>",
        );
        parent.provenance = Some(provenance);
        MemorySource::new().with_parent("g", "parent", "1", parent)
    };
    let child = || {
        pom(
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><artifactId>app</artifactId></project>",
        )
    };
    let local = parent(crate::provenance::Provenance::LocalParent {
        path: "parent/pom.xml".into(),
    });
    let message = model_error(build_with(child(), &local, ModelPolicy::PROJECT, &ctx).unwrap_err());
    assert!(
        message.contains("must be unique but found duplicate profile with id p"),
        "{message}"
    );
    let remote = parent(crate::provenance::Provenance::RemoteParentOfRoot);
    assert!(build_with(child(), &remote, ModelPolicy::PROJECT, &ctx).is_ok());
}

/// Maven validates the project's POMs, not those of its imports or its
/// dependencies: their profile ids must be unique, and every repository they
/// declare, in an inactive profile too, needs an id.
#[test]
fn only_the_project_poms_are_validated() {
    let ctx = ActivationContext::default();
    let error = |pom: Pom, source: MemorySource| {
        model_error(build_with(pom, &source, ModelPolicy::PROJECT, &ctx).unwrap_err())
    };
    let bom = project_pom(
        "bom",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
             <profiles><profile/><profile/></profiles>",
            dep("g", "lib", "<version>2</version>")
        ),
    );
    let root = project_pom(
        "app",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
             <dependencies>{}</dependencies>",
            import("bom", "1"),
            dep("g", "lib", "")
        ),
    );
    let source = MemorySource::new().with_import("g", "bom", "1", bom);
    let project = build_with(root, &source, ModelPolicy::PROJECT, &ctx).unwrap();
    assert_eq!(summary(&project.dependencies), ["lib:2"]);
    let message = error(
        project_pom("app", "<profiles><profile/><profile/></profiles>"),
        MemorySource::new(),
    );
    assert!(
        message.contains("must be unique but found duplicate profile with id default"),
        "{message}"
    );

    let no_id = "<repositories><repository><url>https://repo.example/</url>\
                 </repository></repositories>";
    let empty_id = "<repositories><repository><id> </id><url>https://repo.example/</url>\
                    </repository></repositories>";
    for body in [no_id, empty_id] {
        let message = error(project_pom("app", body), MemorySource::new());
        assert!(
            message.contains("'repositories.repository.id' is missing"),
            "{message}"
        );
    }
    let no_url = "<repositories><repository><id>r</id></repository></repositories>";
    let message = error(project_pom("app", no_url), MemorySource::new());
    assert!(
        message.contains("'repositories.repository.[r].url' is missing"),
        "{message}"
    );
    let no_artifact = "<dependencies><dependency><groupId>g</groupId><version>1</version>\
                       </dependency></dependencies>";
    let message = error(project_pom("app", no_artifact), MemorySource::new());
    assert!(
        message.contains("'dependencies.dependency.artifactId' for g::jar is missing."),
        "{message}"
    );
    let in_profile = format!("<profiles><profile><id>off</id>{no_id}</profile></profiles>");
    let message = error(project_pom("app", &in_profile), MemorySource::new());
    assert!(
        message.contains("'profiles.profile[off].repositories.repository.id' is missing"),
        "{message}"
    );
    let parent = project_pom("parent", &format!("<packaging>pom</packaging>{no_id}"));
    let child = pom(
        "<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>\
         <parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
         </parent></project>",
    );
    let source = || MemorySource::new().with_parent("g", "parent", "1", parent.clone());
    let message = error(child.clone(), source());
    assert!(
        message.contains("'repositories.repository.id' is missing in g:parent:1"),
        "{message}"
    );
    build(child, source(), &ctx)
        .expect("a dependency's POM may declare a repository without an id");
}

/// Maven 3.9 builds a project lineage only with `<modelVersion>4.0.0`; a
/// dependency or an imported BOM is not checked.
#[test]
fn a_project_needs_model_version_4_0_0() {
    let ctx = ActivationContext::default();
    let versioned = |artifact: &str, model_version: &str| {
        project_pom(
            artifact,
            &format!("<modelVersion>{model_version}</modelVersion><packaging>pom</packaging>"),
        )
    };
    for (model_version, expected) in [
        (
            "4.1.0",
            "'modelVersion' of '4.1.0' is newer than the versions supported",
        ),
        (
            "3.0.0",
            "'modelVersion' of '3.0.0' is older than the versions supported",
        ),
        ("4.0", "'modelVersion' must be one of [4.0.0] but is '4.0'."),
        (
            "four",
            "'modelVersion' must be one of [4.0.0] but is 'four'.",
        ),
    ] {
        let error = build_with(
            versioned("app", model_version),
            &MemorySource::new(),
            ModelPolicy::PROJECT,
            &ctx,
        )
        .unwrap_err();
        let message = model_error(error);
        assert!(message.contains(expected), "{message}");
    }
    let child = pom(
        "<project><modelVersion>\n 4.0.0\n</modelVersion><artifactId>app</artifactId>\
         <parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
         </parent></project>",
    );
    let source =
        || MemorySource::new().with_parent("g", "parent", "1", versioned("parent", "4.1.0"));
    let message =
        model_error(build_with(child.clone(), &source(), ModelPolicy::PROJECT, &ctx).unwrap_err());
    assert!(message.contains("'4.1.0' is newer"), "{message}");
    build(child, source(), &ctx).expect("a dependency's lineage is not checked");
    build_with(
        project_pom("app", ""),
        &MemorySource::new(),
        ModelPolicy::PROJECT,
        &ctx,
    )
    .expect("a POM without modelVersion is read as 4.0.0");
}

/// The project model and the reactor descriptor take their coordinates from
/// one computation: a `-D` value wins over a parent's property there, as it
/// does for the rest of the model, even when the caller did not overlay it.
#[test]
fn project_and_descriptor_agree_on_the_coordinates() {
    let parent = pom(
        r#"<project><groupId>corp</groupId><artifactId>parent</artifactId><version>1</version>
        <packaging>pom</packaging><properties><revision>1.0</revision></properties></project>"#,
    );
    let child = pom(
        r#"<project><parent><groupId>corp</groupId><artifactId>parent</artifactId>
        <version>1</version></parent><artifactId>app</artifactId>
        <version>${revision}</version></project>"#,
    );
    let source = MemorySource::new().with_parent("corp", "parent", "1", parent);
    let mut ctx = ActivationContext::default();
    ctx.properties.insert("revision".into(), "2.0".into());

    let project = build_with(child.clone(), &source, ModelPolicy::DEPENDENCY, &ctx).unwrap();
    let descriptor = ready(crate::EffectiveDescriptor::build(
        child,
        &source,
        ModelPolicy::DEPENDENCY,
        &ctx,
    ))
    .unwrap();
    assert_eq!(
        (
            project.group_id.as_str(),
            project.artifact_id.as_str(),
            project.version.as_str()
        ),
        ("corp", "app", "2.0")
    );
    assert_eq!(descriptor.gav.to_string(), "corp:app:2.0");
}

/// `${project.build.*}` reads the effective `<build>`: a child's own value,
/// even an empty one, else its parent's, with each POM's active profile
/// over its own `directory`, `finalName` and `defaultGoal` only, else the
/// super POM's, as Maven 3.9.12 printed them for a dependency's POM.
#[test]
fn build_values_inherit_and_profiles_set_three_of_them() {
    let active = "<activation><activeByDefault>true</activeByDefault></activation>";
    let parent = project_pom(
        "parent",
        &format!(
            "<packaging>pom</packaging><build><finalName>${{project.artifactId}}-pfn</finalName>\
             <defaultGoal>install</defaultGoal><sourceDirectory>psrc</sourceDirectory>\
             </build><profiles><profile><id>p</id>{active}\
             <build><directory>pdir</directory></build></profile></profiles>"
        ),
    );
    let versions = [
        "${project.build.finalName}",
        "${project.build.directory}",
        "${project.build.outputDirectory}",
        "${project.build.defaultGoal}",
        "${build.sourceDirectory}",
        "${pom.build.testOutputDirectory}",
    ];
    let dependencies: String = versions
        .iter()
        .enumerate()
        .map(|(index, version)| {
            dep(
                "org",
                &format!("d{index}"),
                &format!("<version>v{version}</version>"),
            )
        })
        .collect();
    let child = |build: &str| {
        pom(&format!(
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><artifactId>app</artifactId>{build}\
             <dependencies>{dependencies}</dependencies></project>"
        ))
    };
    let source = MemorySource::new().with_parent("g", "parent", "1", parent);
    let versions_of = |pom: Pom| {
        let project = build_with(
            pom,
            &source,
            ModelPolicy::DEPENDENCY,
            &ActivationContext::default(),
        )
        .unwrap();
        project
            .dependencies
            .iter()
            .map(|dep| dep.version.clone().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        versions_of(child("")),
        [
            "vapp-pfn",
            "vpdir",
            "vpdir/classes",
            "vinstall",
            "vpsrc",
            "vpdir/test-classes"
        ]
    );
    assert_eq!(
        versions_of(child(&format!(
            "<build><directory>own</directory><defaultGoal/></build><profiles><profile>\
             <id>c</id>{active}<build><finalName>prof</finalName>\
             <outputDirectory>ignored</outputDirectory></build></profile></profiles>"
        ))),
        [
            "vprof",
            "vown",
            "vown/classes",
            "v",
            "vpsrc",
            "vown/test-classes"
        ]
    );
}

/// A project's `os.detection.classifierWithLikes` is the model's own value,
/// from its profile, its POM or its parent, interpolated, as os-maven-plugin
/// reads it: a user property does not override it, and stands in only where
/// the model has none. An active settings.xml profile's value is the
/// model's.
#[test]
fn classifier_likes_are_the_models_own() {
    const LIKES: &str = "os.detection.classifierWithLikes";
    let parent = project_pom(
        "parent",
        &format!(
            "<packaging>pom</packaging><properties><{LIKES}>${{distro}},parent</{LIKES}><distro>fedora</distro></properties>"
        ),
    );
    let source = MemorySource::new().with_parent("g", "parent", "1", parent);
    let child = |body: &str, user: bool| {
        let mut pom = pom(&format!(
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><artifactId>app</artifactId>{body}</project>"
        ));
        let mut ctx = ActivationContext::default();
        if user {
            pom.overlay_user_properties([(LIKES, "user"), ("distro", "arch")]);
            ctx.properties.insert(LIKES.to_string(), "user".to_string());
            ctx.properties
                .insert("distro".to_string(), "arch".to_string());
        }
        build_with(pom, &source, ModelPolicy::PROJECT, &ctx)
            .unwrap()
            .classifier_with_likes
    };
    let own = format!("<properties><{LIKES}>own</{LIKES}></properties>");
    let profile = format!(
        "{own}<profiles><profile><id>p</id><activation><activeByDefault>true</activeByDefault>\
         </activation><properties><{LIKES}>profile</{LIKES}></properties></profile></profiles>"
    );
    for (body, user, expected) in [
        ("", false, "fedora,parent"),
        ("", true, "arch,parent"),
        (own.as_str(), true, "own"),
        (profile.as_str(), true, "profile"),
        (profile.as_str(), false, "profile"),
    ] {
        assert_eq!(
            child(body, user).as_deref(),
            Some(expected),
            "{body} {user}"
        );
    }
    let lone = pom(
        "<project><groupId>g</groupId><artifactId>lone</artifactId><version>1</version></project>",
    );
    let mut ctx = ActivationContext::default();
    ctx.properties.insert(LIKES.to_string(), "user".to_string());
    let project = build_with(lone.clone(), &source, ModelPolicy::PROJECT, &ctx).unwrap();
    assert_eq!(project.classifier_with_likes, None);
    // An active settings.xml profile's value is the model's, over the
    // POM's and a `-D` value.
    ctx.settings_properties.insert(LIKES, "${distro},settings");
    ctx.settings_properties.insert("distro", "suse");
    let project = build_with(lone, &source, ModelPolicy::PROJECT, &ctx).unwrap();
    assert_eq!(
        project.classifier_with_likes.as_deref(),
        Some("suse,settings")
    );
}
