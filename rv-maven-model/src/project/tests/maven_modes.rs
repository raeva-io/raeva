//! How the Maven line changes the models raeva builds.

use super::*;
use crate::{ModelEnvironment, PropertySource};
use rv_maven_types::MavenMode;

fn context(
    mode: MavenMode,
    source: PropertySource,
    properties: &[(&str, &str)],
) -> ActivationContext {
    let environment = ModelEnvironment::builder()
        .env("RAEVA_MODE_TEST", Some("env"))
        .build()
        .with_maven_mode(mode);
    let mut ctx = ActivationContext::new(environment);
    let properties = properties
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()));
    ctx.set_external_properties(properties.collect(), source);
    ctx
}

const VERSIONS: [&str; 6] = [
    "${foo}",
    "${revision}",
    "${env.RAEVA_MODE_TEST}",
    "${RAEVA_MODE_TEST}",
    "${packaging}",
    "${maven.repo.central}",
];

fn versions(project: &Project) -> Vec<String> {
    (project.dependencies.iter())
        .map(|dep| dep.version.clone().unwrap_or_default())
        .collect()
}

/// Maven 3.10 interpolates a model it reads from a repository with only
/// the JVM's, Maven's and the CI-friendly properties, and no environment
/// variable, unless `maven.model.dependencyInterpolation.full` is `true`.
#[test]
fn maven_310_interpolates_repository_models_with_safe_properties_only() {
    let deps: String = (VERSIONS.iter().enumerate())
        .map(|(i, version)| {
            dep(
                "g",
                &format!("d{i}"),
                &format!("<version>{version}</version>"),
            )
        })
        .collect();
    let pom = || project_pom("lib", &format!("<dependencies>{deps}</dependencies>"));
    let user = [("foo", "bar"), ("revision", "7")];
    let full = [
        ("foo", "bar"),
        ("revision", "7"),
        ("maven.model.dependencyInterpolation.full", "TRUE"),
    ];
    let built = |mode, source, properties: &[(&str, &str)]| {
        versions(
            &build(
                pom(),
                MemorySource::new(),
                &context(mode, source, properties),
            )
            .unwrap(),
        )
    };
    let all = ["bar", "7", "env", "env", "jar", "${maven.repo.central}"];
    let central = "https://repo.maven.apache.org/maven2";
    for source in [PropertySource::System, PropertySource::User] {
        assert_eq!(built(MavenMode::Maven39, source, &user), all, "{source:?}");
    }
    assert_eq!(
        built(MavenMode::Maven310, PropertySource::System, &user),
        // `${packaging}` still reads the model's own field.
        [
            "${foo}",
            "7",
            "${env.RAEVA_MODE_TEST}",
            "${RAEVA_MODE_TEST}",
            "jar",
            central
        ]
    );
    assert_eq!(
        built(MavenMode::Maven310, PropertySource::System, &full),
        ["bar", "7", "env", "env", "jar", central]
    );
    assert_eq!(
        built(MavenMode::Maven310, PropertySource::User, &user),
        ["bar", "7", "env", "env", "jar", central]
    );
}

/// A BOM a project imports is a repository model too: the project's user
/// properties no longer reach it, and its own properties win again.
#[test]
fn maven_310_imports_a_bom_without_the_projects_user_properties() {
    let bom = project_pom(
        "bom",
        &format!(
            "<properties><foo>own</foo></properties><dependencyManagement><dependencies>{}{}\
             </dependencies></dependencyManagement>",
            dep("g", "a", "<version>${foo}</version>"),
            dep("g", "b", "<version>${bar}</version>"),
        ),
    );
    let app = project_pom(
        "app",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            import("bom", "1")
        ),
    );
    let managed = |mode| {
        let ctx = context(
            mode,
            PropertySource::User,
            &[("foo", "user"), ("bar", "user")],
        );
        let source = MemorySource::new().with_import("g", "bom", "1", bom.clone());
        let project = build_with(app.clone(), &source, ModelPolicy::PROJECT, &ctx).unwrap();
        summary(&project.dependency_management.dependencies)
    };
    assert_eq!(managed(MavenMode::Maven39), ["a:user", "b:user"]);
    assert_eq!(managed(MavenMode::Maven310), ["a:own", "b:${bar}"]);
}

/// Maven 3.10 activates the profiles of a model it reads from a repository
/// without its `<file>` profiles and with the POM's own properties below the
/// system properties, which hold every `-D` but not the `packaging` Maven
/// adds.
#[test]
fn maven_310_activates_repository_model_profiles_apart() {
    let profile = |id: &str, activation: &str| {
        format!(
            "<profile><id>{id}</id><activation>{activation}</activation><dependencies>{}\
             </dependencies></profile>",
            dep("g", id, "<version>1</version>")
        )
    };
    let property = |name: &str, value: &str| {
        format!("<property><name>{name}</name><value>{value}</value></property>")
    };
    let existing = env!("CARGO_MANIFEST_DIR");
    let profiles = [
        profile("file", &format!("<file><exists>{existing}</exists></file>")),
        profile("own", &property("own", "yes")),
        profile("user", &property("user", "yes")),
        profile("packaging", &property("packaging", "jar")),
        profile("java", &property("java.version", "own")),
        profile("jdk", &property("jdk.version", "own")),
        profile("os", &property("os.detected.name", "own")),
        profile("home", &property("os.name", "own")),
    ]
    .concat();
    let pom_of = |profiles: &str| {
        project_pom(
            "lib",
            &format!(
                "<properties><own>yes</own><java.version>own</java.version>\
                 <jdk.version>own</jdk.version><os.detected.name>own</os.detected.name>\
                 <os.name>own</os.name></properties><profiles>{profiles}</profiles>"
            ),
        )
    };
    // No measured JVM sets `jdk.version`, so Maven 3.9, which does not
    // read the POM's own, finds it unset.
    let pom = pom_of(&profiles);
    let active = |mode, source| {
        let ctx = context(mode, source, &[("user", "yes")]);
        let pom = pom.clone();
        let project = build(pom, MemorySource::new(), &ctx).unwrap();
        (project.dependencies.iter())
            .map(|dep| dep.artifact_id.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        active(MavenMode::Maven39, PropertySource::System),
        ["file", "user", "packaging"]
    );
    assert_eq!(
        active(MavenMode::Maven39, PropertySource::Import),
        ["file", "user", "packaging"]
    );
    // Of the POM's own properties, only those the JVM sets lose to the
    // system ones.
    for source in [PropertySource::System, PropertySource::Import] {
        assert_eq!(
            active(MavenMode::Maven310, source),
            ["own", "user", "jdk", "os"]
        );
    }
    assert_eq!(
        active(MavenMode::Maven310, PropertySource::User),
        ["file", "user", "packaging"]
    );
}

/// What Maven 3.9 only warns about in a project's POM and Maven 3.10
/// refuses.
#[test]
fn maven_310_refuses_what_maven_39_warns_about_in_a_project() {
    let twice = |a: &str, b: &str| format!("{}{}", dep("g", "foo", a), dep("g", "foo", b));
    let cases = [
        (
            format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                twice(
                    "<version>2</version>",
                    "<version>1</version><scope>runtime</scope>"
                )
            ),
            "'dependencyManagement.dependencies.dependency.(groupId:artifactId:type:classifier)' \
             must be unique: g:foo:jar -> version 2 vs 1",
        ),
        (
            format!(
                "<profiles><profile><id>p</id><dependencies>{}</dependencies></profile></profiles>",
                twice("<version>1</version>", "<version>1</version>")
            ),
            "'profiles.profile[p].dependencies.dependency.(groupId:artifactId:type:classifier)' \
             must be unique: g:foo:jar -> duplicate declaration of version 1",
        ),
        (
            format!(
                "<dependencies>{}</dependencies>",
                twice(
                    "<classifier>x</classifier>",
                    "<classifier>x</classifier><version>1</version>"
                )
            ),
            "'dependencies.dependency.(groupId:artifactId:type:classifier)' must be unique: \
             g:foo:jar:x -> version (?) vs 1",
        ),
    ];
    let built = |mode, body: &str| {
        let ctx = context(mode, PropertySource::User, &[]);
        build_with(
            project_pom("app", body),
            &MemorySource::new(),
            ModelPolicy::PROJECT,
            &ctx,
        )
    };
    for (body, error) in &cases {
        assert!(built(MavenMode::Maven39, body).is_ok(), "{body}");
        assert_eq!(
            model_error(built(MavenMode::Maven310, body).unwrap_err()),
            format!("invalid model: {error}")
        );
    }
    // An empty <classifier> is a key of its own, so twins alike apart from
    // it are no duplicate.
    let twins = format!(
        "<dependencies>{}{}</dependencies>",
        dep("g", "foo", "<version>1</version><classifier/>"),
        dep("g", "foo", "<version>1</version>")
    );
    assert!(built(MavenMode::Maven310, &twins).is_ok());

    let child = |relative_path: &str| {
        pom(&format!(
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
             <version>1</version><relativePath>{relative_path}</relativePath></parent>\
             <artifactId>app</artifactId></project>"
        ))
    };
    let source = MemorySource::new().with_parent("g", "parent", "1", project_pom("parent", ""));
    let with_parent = |mode, relative_path: &str| {
        let ctx = context(mode, PropertySource::User, &[]);
        build_with(child(relative_path), &source, ModelPolicy::PROJECT, &ctx)
    };
    assert!(with_parent(MavenMode::Maven39, "g:parent:1").is_ok());
    assert_eq!(
        model_error(with_parent(MavenMode::Maven310, "g:parent:1").unwrap_err()),
        "invalid model: 'parent.relativePath' must not contain any of these characters \
         :\"<>|?* but found :"
    );
    assert!(with_parent(MavenMode::Maven310, "../parent").is_ok());
    // The check reads the text as written, not the path a loader anchored.
    let anchored = |relative_path: &str, anchored: &str| {
        let mut pom = child(relative_path);
        pom.anchor_relative_path(anchored.to_string());
        pom.anchor_relative_path("/twice".to_string());
        let ctx = context(MavenMode::Maven310, PropertySource::User, &[]);
        build_with(pom, &source, ModelPolicy::PROJECT, &ctx)
    };
    assert!(anchored("../parent", r"C:\work\parent").is_ok());
    assert!(anchored("g:parent:1", "/work/parent").is_err());

    let project = |version: &str, repository: &str| {
        let repositories = format!(
            "<repositories><repository><id>{repository}</id><url>https://r.example/</url>\
             </repository></repositories>"
        );
        let pom = pom(&format!(
            "<project><groupId>g</groupId><artifactId>app</artifactId><version>{version}\
             </version>{repositories}</project>"
        ));
        let ctx = context(MavenMode::Maven310, PropertySource::User, &[]);
        build_with(pom, &MemorySource::new(), ModelPolicy::PROJECT, &ctx).unwrap()
    };
    let errors = |version: &str, repository: &str| {
        let project = project(version, repository);
        assert!(
            project
                .validate_build_coordinates(MavenMode::Maven39)
                .is_ok()
        );
        let error = project.validate_build_coordinates(MavenMode::Maven310);
        error.err().map(|error| error.to_string())
    };
    assert_eq!(errors("1.0-SNAPSHOT", "r"), None);
    let invalid = |message: &str| Some(format!("invalid model: {message}"));
    assert_eq!(
        errors("1.0SNAPSHOT", "r"),
        invalid(
            "'version' uses an unsupported snapshot version format, should be '*-SNAPSHOT' instead."
        )
    );
    assert_eq!(
        errors("1|0", "r"),
        invalid("'version' must not contain any of these characters \\/:\"<>|?* but found |")
    );
    assert_eq!(
        errors("1", "a/b"),
        invalid(
            "'repositories.repository.id' must not contain any of these characters \\/:\"<>|?* but found /"
        )
    );
    assert_eq!(
        errors("1", "local"),
        invalid(
            "'repositories.repository.id' must not be 'local', this identifier is reserved for \
             the local repository, using it for other repositories will corrupt your repository \
             metadata."
        )
    );
}

/// A remote parent's range is read in the mode's version order: `alpha`
/// sorts below `0` in 3.10, so `[0,alpha]` is no range there.
#[test]
fn a_parent_range_is_read_in_the_mode_order() {
    let parent = crate::Parent {
        group_id: "p".to_string(),
        artifact_id: "par".to_string(),
        version: "[0,alpha]".to_string(),
        relative_path: None,
    };
    assert!(crate::parent_version_range(&parent, MavenMode::Maven39).is_some());
    assert!(crate::parent_version_range(&parent, MavenMode::Maven310).is_none());
}

/// Maven 3.10 refuses a plugin declared twice in one `<build>` section of
/// the project or a local parent, in any profile, active or not, and a
/// plugin repository of the effective model whose id is `local` or has a
/// character it bans. Maven 3.9 warns of both and builds.
#[test]
fn maven_310_refuses_duplicate_plugins_and_invalid_plugin_repository_ids() {
    let plugin = |group: &str| {
        format!("<plugin>{group}<artifactId>p</artifactId><version>1</version></plugin>")
    };
    let twice = format!(
        "{}{}",
        plugin("<groupId>x</groupId>"),
        plugin("<groupId>x</groupId>")
    );
    let defaulted = format!(
        "{}{}",
        plugin(""),
        plugin("<groupId>org.apache.maven.plugins</groupId>")
    );
    let unique = "must be unique but found duplicate declaration of plugin";
    let local_id = "must not be 'local', this identifier is reserved for the local repository, \
                    using it for other repositories will corrupt your repository metadata.";
    let plugin_repository = |id: &str| {
        format!(
            "<pluginRepositories><pluginRepository><id>{id}</id><url>https://r.example/</url>\
             </pluginRepository></pluginRepositories>"
        )
    };
    let cases = [
        (
            format!("<build><plugins>{twice}</plugins></build>"),
            Some(format!(
                "'build.plugins.plugin.(groupId:artifactId)' {unique} x:p"
            )),
        ),
        (
            format!(
                "<build><pluginManagement><plugins>{twice}</plugins></pluginManagement></build>"
            ),
            Some(format!(
                "'build.pluginManagement.plugins.plugin.(groupId:artifactId)' {unique} x:p"
            )),
        ),
        (
            format!(
                "<profiles><profile><id>pr</id><build><plugins>{defaulted}</plugins></build></profile></profiles>"
            ),
            Some(format!(
                "'profiles.profile[pr].plugins.plugin.(groupId:artifactId)' {unique} \
                 org.apache.maven.plugins:p"
            )),
        ),
        (
            format!(
                "<build><plugins>{}</plugins></build>",
                plugin("<groupId>x</groupId>")
            ),
            None,
        ),
        (
            plugin_repository("local"),
            Some(format!(
                "'pluginRepositories.pluginRepository.id' {local_id}"
            )),
        ),
        (
            plugin_repository("${repo}").replace(
                "<pluginRepositories>",
                "<properties><repo>a:b</repo></properties><pluginRepositories>",
            ),
            Some(
                "'pluginRepositories.pluginRepository.id' must not contain any of these \
                 characters \\/:\"<>|?* but found :"
                    .to_string(),
            ),
        ),
        (
            format!(
                "<profiles><profile><id>on</id><activation><activeByDefault>true\
                 </activeByDefault></activation>{}</profile></profiles>",
                plugin_repository("x?y")
            ),
            Some(
                "'pluginRepositories.pluginRepository.id' must not contain any of these \
                 characters \\/:\"<>|?* but found ?"
                    .to_string(),
            ),
        ),
        (
            format!(
                "<profiles><profile><id>off</id>{}</profile></profiles>",
                plugin_repository("local")
            ),
            None,
        ),
    ];
    let built = |mode, pom: Pom, source: &MemorySource| {
        let ctx = context(mode, PropertySource::User, &[]);
        build_with(pom, source, ModelPolicy::PROJECT, &ctx)
            .map_err(model_error)
            .and_then(|project| {
                (project.validate_build_coordinates(mode)).map_err(|error| error.to_string())
            })
    };
    let with_plugins = |artifact: &str, body: &str| {
        Pom::parse_with_plugins(&format!(
            "<project><groupId>g</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version>{body}</project>"
        ))
        .unwrap()
    };
    for (body, error) in &cases {
        let source = MemorySource::new();
        assert_eq!(
            built(MavenMode::Maven39, with_plugins("app", body), &source),
            Ok(()),
            "{body}"
        );
        assert_eq!(
            built(MavenMode::Maven310, with_plugins("app", body), &source).err(),
            error
                .as_ref()
                .map(|error| format!("invalid model: {error}")),
            "{body}"
        );
        // From a parent: a local one is validated as the project is, and
        // only the plugin repositories of one from a repository are.
        for local in [true, false] {
            let mut parent = with_plugins("parent", body);
            if local {
                parent.set_provenance(crate::Provenance::LocalParent {
                    path: "parent/pom.xml".into(),
                });
            }
            let source = MemorySource::new().with_parent("g", "parent", "1", parent);
            let child = with_plugins(
                "app",
                "<parent><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version></parent>",
            );
            let expected = error
                .as_ref()
                .filter(|error| local || error.starts_with("'pluginRepositories."))
                .map(|error| format!("invalid model: {error}"));
            assert_eq!(
                built(MavenMode::Maven310, child, &source).err(),
                expected,
                "local {local}: {body}"
            );
        }
    }
}

/// Maven 3.9.12 and 3.10.0 both refuse, in a project build, a repository
/// or plugin repository without an id or a URL, an id one list names twice,
/// and plugin sections their reader cannot parse, in the POM's profiles
/// too, active or not. The messages are Maven's, from runs of both.
#[test]
fn both_modes_refuse_invalid_plugin_repositories_and_plugin_sections() {
    let repository = |id: &str, url: &str| {
        format!("<pluginRepository><id>{id}</id><url>{url}</url></pluginRepository>")
    };
    let a = repository("x", "https://a.example/");
    let b = repository("x", "https://b.example/");
    let unique = "'pluginRepositories.pluginRepository.id' must be unique: x -> \
                  https://a.example/ vs https://b.example/";
    let cases = [
        (
            "<pluginRepositories><pluginRepository><url>https://a.example/</url>\
             </pluginRepository></pluginRepositories>"
                .to_string(),
            Some("'pluginRepositories.pluginRepository.id' is missing".to_string()),
        ),
        (
            "<pluginRepositories><pluginRepository><id> </id><url>https://a.example/</url>\
             </pluginRepository></pluginRepositories>"
                .to_string(),
            Some("'pluginRepositories.pluginRepository.id' is missing".to_string()),
        ),
        (
            "<pluginRepositories><pluginRepository><id>x</id></pluginRepository>\
             </pluginRepositories>"
                .to_string(),
            Some("'pluginRepositories.pluginRepository.[x].url' is missing".to_string()),
        ),
        (
            format!("<pluginRepositories>{a}{b}</pluginRepositories>"),
            Some(unique.to_string()),
        ),
        (
            format!(
                "<profiles><profile><id>off</id><pluginRepositories>{a}{b}\
                 </pluginRepositories></profile></profiles>"
            ),
            Some(format!("'profiles.profile[off].{}", &unique[1..])),
        ),
        (
            format!(
                "<pluginRepositories>{a}</pluginRepositories><profiles><profile><id>off</id>\
                 <pluginRepositories>{b}</pluginRepositories></profile></profiles>"
            ),
            None,
        ),
        (
            "<repositories><repository><id>x</id><url>https://a.example/</url></repository>\
             <repository><id>x</id><url>https://b.example/</url></repository></repositories>"
                .to_string(),
            Some(
                "'repositories.repository.id' must be unique: x -> https://a.example/ vs \
                 https://b.example/"
                    .to_string(),
            ),
        ),
        (
            "<build><plugins><plugin><artifactId>p</artifactId><version>1</version>\
             <version>2</version></plugin></plugins></build>"
                .to_string(),
            Some("deserialization error: duplicate field `version`".to_string()),
        ),
        (
            "<profiles><profile><id>off</id><build><extensions><extension><groupId>g\
             </groupId><artifactId>e</artifactId><version><v/></version></extension>\
             </extensions></build></profile></profiles>"
                .to_string(),
            Some("deserialization error: unexpected `Event::Start(\"v\")`".to_string()),
        ),
    ];
    let built = |mode, pom: Pom, source: &MemorySource, policy| {
        let ctx = context(mode, PropertySource::User, &[]);
        build_with(pom, source, policy, &ctx)
            .map(drop)
            .map_err(model_error)
    };
    let pom = |artifact: &str, body: &str, plugins: bool| {
        let xml = format!(
            "<project><groupId>g</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version>{body}</project>"
        );
        match plugins {
            true => Pom::parse_with_plugins(&xml).unwrap(),
            false => Pom::parse(&xml).unwrap(),
        }
    };
    let invalid = |error: &str| match error.starts_with("deserialization") {
        true => error.to_string(),
        false => format!("invalid model: {error}"),
    };
    for (body, error) in &cases {
        for mode in [MavenMode::Maven39, MavenMode::Maven310] {
            let source = MemorySource::new();
            for policy in [ModelPolicy::PROJECT, ModelPolicy::PROJECT_PLUGINS] {
                assert_eq!(
                    built(mode, pom("app", body, true), &source, policy).err(),
                    error.as_deref().map(invalid),
                    "{mode:?} {body}"
                );
            }
            // A dependency's POM is not validated.
            assert_eq!(
                built(
                    mode,
                    pom("app", body, true),
                    &source,
                    ModelPolicy::DEPENDENCY
                ),
                Ok(()),
                "{mode:?} {body}"
            );
            // A parent's POM is, when its plugin sections were kept.
            let parent = pom("parent", body, true);
            let source = MemorySource::new().with_parent("g", "parent", "1", parent);
            let child = pom(
                "app",
                "<parent><groupId>g</groupId><artifactId>parent</artifactId>\
                 <version>1</version></parent>",
                true,
            );
            let expected = error.as_deref().map(|error| match error {
                error if error.starts_with("deserialization") => invalid(error),
                error => invalid(&format!("{error} in g:parent:1")),
            });
            assert_eq!(
                built(mode, child, &source, ModelPolicy::PROJECT).err(),
                expected,
                "{mode:?} parent {body}"
            );
        }
    }
}

/// Maven 3.10's super POM names `central` by `${maven.repo.central}`. A
/// project or settings.xml profile property gives the project a `central`
/// of that URL, which a `-D` value overrides and which wins over a system
/// property; the configuration's Central carries the `-D` and system values
/// alone. The plugin repository reads the property in each case. A project
/// that declares `central` keeps its own, and the 3.9 mode reads nothing.
#[test]
fn maven_310_reads_central_from_maven_repo_central() {
    let default = "https://repo.maven.apache.org/maven2";
    let property = "<properties><maven.repo.central>https://pom.example/m2</maven.repo.central>\
                    </properties>";
    let declared = "<repositories><repository><id>central</id>\
                    <url>https://declared.example/m2</url></repository></repositories>";
    let built_with = |mode,
                      body: &str,
                      user: &[(&str, &str)],
                      settings: bool,
                      system: bool,
                      configured: bool| {
        let mut ctx = context(mode, PropertySource::User, user);
        ctx.configured_central = configured;
        if settings {
            (ctx.settings_properties).insert("maven.repo.central", "https://settings.example/m2");
        }
        if system {
            (ctx.system_properties).insert(
                "maven.repo.central".to_string(),
                "https://system.example/m2".to_string(),
            );
        }
        let pom = Pom::parse_with_plugins(&format!(
            "<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>\
             {body}</project>"
        ))
        .unwrap();
        let project = build_with(
            pom,
            &MemorySource::new(),
            ModelPolicy::PROJECT_PLUGINS,
            &ctx,
        )
        .unwrap();
        let central = (project.repositories.iter())
            .find(|repo| repo.id.as_deref() == Some("central"))
            .map(|repo| (repo.url.clone(), repo.snapshots_enabled));
        let plugins = project.plugins().unwrap().unwrap();
        let plugin = plugins.plugin_repositories.last().unwrap().url.clone();
        (
            central.map(|(url, snapshots)| {
                assert!(!snapshots || url.contains("declared"));
                url
            }),
            plugin,
        )
    };
    let built = |mode, body: &str, user: &[(&str, &str)], settings: bool, system: bool| {
        built_with(mode, body, user, settings, system, false)
    };
    let user = [("maven.repo.central", "https://user.example/m2")];
    let some = |url: &str| Some(url.to_string());
    for (mode, body, user, settings, system, central, plugin) in [
        (
            MavenMode::Maven310,
            property,
            &[][..],
            false,
            false,
            some("https://pom.example/m2"),
            "https://pom.example/m2",
        ),
        (
            MavenMode::Maven310,
            property,
            &[][..],
            false,
            true,
            some("https://pom.example/m2"),
            "https://pom.example/m2",
        ),
        (
            MavenMode::Maven310,
            property,
            &user[..],
            false,
            false,
            None,
            "https://user.example/m2",
        ),
        (
            MavenMode::Maven310,
            property,
            &[][..],
            true,
            false,
            some("https://settings.example/m2"),
            "https://settings.example/m2",
        ),
        (
            MavenMode::Maven310,
            "",
            &[][..],
            true,
            false,
            some("https://settings.example/m2"),
            "https://settings.example/m2",
        ),
        (
            MavenMode::Maven310,
            "",
            &[][..],
            false,
            true,
            None,
            "https://system.example/m2",
        ),
        (
            MavenMode::Maven310,
            "",
            &[][..],
            false,
            false,
            None,
            default,
        ),
        (
            MavenMode::Maven310,
            &format!("{property}{declared}"),
            &[][..],
            false,
            false,
            some("https://declared.example/m2"),
            "https://pom.example/m2",
        ),
        (
            MavenMode::Maven39,
            property,
            &[][..],
            true,
            true,
            None,
            default,
        ),
    ] {
        let got = built(mode, body, user, settings, system);
        assert_eq!(
            got,
            (central, plugin.to_string()),
            "{mode:?} {body} {user:?} {settings} {system}"
        );
    }
    // A `central` that settings.xml or raeva's configuration names wins
    // over the super POM's, as an active settings profile's does in Maven.
    let (central, _) = built_with(MavenMode::Maven310, property, &[], true, false, true);
    assert_eq!(central, None);
}
