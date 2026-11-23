//! `lock diff` leads with the parent or BOM whose change moved packages,
//! with both versions, then the packages it moved.

use std::fs;

use serde_json::{Value, json};

use crate::common::assert_success;
use crate::offline_project::Project;

/// The project's `repository/`, by absolute path, which a remote parent's
/// lookup can use offline.
fn repositories(project: &Project) -> String {
    format!(
        "<repositories><repository><id>project-repo</id>\
         <url>file://{}/repository/</url></repository></repositories>",
        project.root().display()
    )
}

fn dependency(artifact: &str, version: Option<&str>) -> String {
    let version = version.map_or(String::new(), |v| format!("<version>{v}</version>"));
    format!(
        "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>{version}</dependency>"
    )
}

fn import(artifact: &str, version: &str) -> String {
    format!(
        "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
         <version>{version}</version><type>pom</type><scope>import</scope></dependency>"
    )
}

fn managing(entries: &[String]) -> String {
    format!(
        "<packaging>pom</packaging><dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
        entries.concat()
    )
}

/// `a` to `e` at versions 1 and 2.
fn project_with_libraries() -> Project {
    let project = Project::synced_with(&[(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>empty</artifactId><version>1</version></project>",
    )]);
    for artifact in ["a", "b", "c", "d", "e"] {
        for version in ["1", "2"] {
            project.publish(&format!("org.test:{artifact}:{version}"), "");
        }
    }
    project
}

/// Writes `files`, syncs, keeps the lock as `old.lock`, writes `changed`,
/// syncs again and returns the text and the JSON data of the diff.
fn diff_after(
    project: &Project,
    files: &[(&str, String)],
    changed: &[(&str, String)],
) -> (String, Value) {
    let write = |files: &[(&str, String)]| {
        for (path, text) in files {
            let path = project.root().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
    };
    write(files);
    assert_success(&project.raeva(&["sync", "--offline"]), "first sync");
    fs::copy(
        project.root().join("raeva.lock"),
        project.root().join("old.lock"),
    )
    .unwrap();
    write(changed);
    assert_success(&project.raeva(&["sync", "--offline"]), "second sync");
    let old = project.root().join("old.lock");
    let old = old.to_str().unwrap();
    let text = project.raeva(&["lock", "diff", old]);
    assert_success(&text, "lock diff");
    let json = project.raeva(&["--json", "lock", "diff", old]);
    assert_success(&json, "lock diff --json");
    let envelope: Value = serde_json::from_slice(&json.stdout).unwrap();
    (
        String::from_utf8(text.stdout).unwrap(),
        envelope["data"].clone(),
    )
}

fn root(project: &Project, artifact: &str, body: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>{artifact}</artifactId><version>1</version>{}{body}</project>",
        repositories(project)
    )
}

fn dependencies(list: &[String]) -> String {
    format!("<dependencies>{}</dependencies>", list.concat())
}

/// The packages a cause moved, by artifact, from `data`'s `changes`.
fn moved(data: &Value, cause: &Value) -> Vec<String> {
    (cause["changes"].as_array().unwrap().iter())
        .map(|index| {
            let change = &data["changes"][index.as_u64().unwrap() as usize];
            format!(
                "{} {} {} -> {}",
                change["module"].as_str().unwrap(),
                change["coordinate"].as_str().unwrap(),
                change["old_version"].as_str().unwrap(),
                change["new_version"].as_str().unwrap()
            )
        })
        .collect()
}

/// A bump of the parent moves the versions its dependencyManagement writes;
/// `c`, declared with its own version, stays in the listing.
#[test]
fn a_parent_bump_leads_with_the_parent_and_both_versions() {
    let project = project_with_libraries();
    for version in ["1", "2"] {
        project.publish(
            &format!("org.test:corp-parent:{version}"),
            &managing(&[
                dependency("a", Some(version)),
                dependency("b", Some(version)),
            ]),
        );
    }
    let app = |parent: &str, c: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>\
             <parent><groupId>org.test</groupId><artifactId>corp-parent</artifactId>\
             <version>{parent}</version><relativePath/></parent>\
             <artifactId>app</artifactId><version>1</version>{}{}</project>",
            repositories(&project),
            dependencies(&[
                dependency("a", None),
                dependency("b", None),
                dependency("c", Some(c)),
            ]),
        )
    };
    let (text, data) = diff_after(
        &project,
        &[("pom.xml", app("1", "1"))],
        &[("pom.xml", app("2", "2"))],
    );
    assert_eq!(
        text,
        "  parent org.test:corp-parent 1 -> 2 (direct)\n    \
         a  1 -> 2\n    \
         b  1 -> 2\n  \
         c  1 -> 2\n",
        "{text}"
    );
    let causes = data["causes"].as_array().unwrap();
    assert_eq!(causes.len(), 1, "{data}");
    assert_eq!(
        causes[0]["sources"],
        json!([{"kind": "pom", "pom": "org.test:corp-parent", "old_versions": ["1"], "new_versions": ["2"]}])
    );
    assert_eq!(causes[0]["cause"], "direct");
    assert_eq!(causes[0]["property"], Value::Null);
    assert_eq!(
        moved(&data, &causes[0]),
        [
            "pom.xml org.test:a:jar 1 -> 2",
            "pom.xml org.test:b:jar 1 -> 2"
        ]
    );
}

/// A BOM that the reactor root imports with a written version moves the
/// packages of every module that takes their versions from it.
#[test]
fn a_bom_import_bump_groups_the_packages_of_every_module() {
    let project = project_with_libraries();
    for version in ["1", "2"] {
        project.publish(
            &format!("org.test:bom:{version}"),
            &managing(&[
                dependency("a", Some(version)),
                dependency("b", Some(version)),
            ]),
        );
    }
    let parent = |bom: &str| {
        root(
            &project,
            "root",
            &format!(
                "<packaging>pom</packaging><modules><module>app</module><module>lib</module></modules>{}",
                managing(&[import("bom", bom)]).replace("<packaging>pom</packaging>", "")
            ),
        )
    };
    let module = |artifact: &str, deps: &[String]| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>\
             <parent><groupId>org.test</groupId><artifactId>root</artifactId><version>1</version></parent>\
             <artifactId>{artifact}</artifactId>{}{}</project>",
            repositories(&project),
            dependencies(deps),
        )
    };
    let modules = [
        (
            "app/pom.xml",
            module("app", &[dependency("a", None), dependency("b", None)]),
        ),
        ("lib/pom.xml", module("lib", &[dependency("a", None)])),
    ];
    let mut files = vec![("pom.xml", parent("1"))];
    files.extend(modules.iter().cloned());
    let (text, data) = diff_after(&project, &files, &[("pom.xml", parent("2"))]);
    assert_eq!(
        text,
        "  BOM org.test:bom 1 -> 2 (imported)\n    \
         a  1 -> 2\n    \
         b  1 -> 2 (in app)\n",
        "{text}"
    );
    let causes = data["causes"].as_array().unwrap();
    assert_eq!(causes.len(), 1, "{data}");
    assert_eq!(causes[0]["cause"], "imported");
    assert_eq!(
        moved(&data, &causes[0]),
        [
            "app/pom.xml org.test:a:jar 1 -> 2",
            "app/pom.xml org.test:b:jar 1 -> 2",
            "lib/pom.xml org.test:a:jar 1 -> 2",
        ]
    );
}

/// A bump of the property an import's version is written as names the
/// property, and moves what the module's own dependencyManagement writes
/// with that property too. Another property or a written version there,
/// and a version the module declares, stay in the listing.
#[test]
fn a_property_bump_names_the_property() {
    let project = project_with_libraries();
    for version in ["1", "2"] {
        project.publish(
            &format!("org.test:bom:{version}"),
            &managing(&[dependency("a", Some(version))]),
        );
    }
    let app = |version: &str| {
        root(
            &project,
            "app",
            &format!(
                "<properties><bom.version>{version}</bom.version><b.version>{version}</b.version></properties>\
                 <dependencyManagement><dependencies>{}{}{}{}</dependencies></dependencyManagement>{}",
                import("bom", "${bom.version}"),
                dependency("b", Some("${b.version}")),
                dependency("c", Some(version)),
                dependency("e", Some("${bom.version}")),
                dependencies(&[
                    dependency("a", None),
                    dependency("b", None),
                    dependency("c", None),
                    dependency("d", Some(version)),
                    dependency("e", None),
                ]),
            ),
        )
    };
    let (text, data) = diff_after(&project, &[("pom.xml", app("1"))], &[("pom.xml", app("2"))]);
    assert_eq!(
        text,
        "  BOM org.test:bom 1 -> 2 (property bom.version)\n    \
         a  1 -> 2\n    \
         e  1 -> 2\n  \
         b  1 -> 2\n  \
         c  1 -> 2\n  \
         d  1 -> 2\n",
        "{text}"
    );
    let causes = data["causes"].as_array().unwrap();
    assert_eq!(causes.len(), 1, "{data}");
    assert_eq!(causes[0]["cause"], "property");
    assert_eq!(causes[0]["property"], "bom.version");
    assert_eq!(
        moved(&data, &causes[0]),
        [
            "pom.xml org.test:a:jar 1 -> 2",
            "pom.xml org.test:e:jar 1 -> 2"
        ]
    );
}

/// Two BOMs imported with one property both move, so what the module's own
/// dependencyManagement writes with it is neither's and stays listed.
#[test]
fn a_property_two_boms_share_leaves_the_lineage_listed() {
    let project = project_with_libraries();
    for (bom, artifact) in [("bom-a", "a"), ("bom-b", "b")] {
        for version in ["1", "2"] {
            project.publish(
                &format!("org.test:{bom}:{version}"),
                &managing(&[dependency(artifact, Some(version))]),
            );
        }
    }
    let app = |version: &str| {
        root(
            &project,
            "app",
            &format!(
                "<properties><p>{version}</p></properties>\
                 <dependencyManagement><dependencies>{}{}{}</dependencies></dependencyManagement>{}",
                import("bom-a", "${p}"),
                import("bom-b", "${p}"),
                dependency("e", Some("${p}")),
                dependencies(&[
                    dependency("a", None),
                    dependency("b", None),
                    dependency("e", None),
                ]),
            ),
        )
    };
    let (text, _) = diff_after(&project, &[("pom.xml", app("1"))], &[("pom.xml", app("2"))]);
    assert_eq!(
        text,
        "  BOM org.test:bom-a 1 -> 2 (property p)\n    \
         a  1 -> 2\n  \
         BOM org.test:bom-b 1 -> 2 (property p)\n    \
         b  1 -> 2\n  \
         e  1 -> 2\n",
        "{text}"
    );
}

/// The second BOM takes `a` over from the first, and both moved: the two
/// locks name two bumped sources for `a`, so the cause is ambiguous. When
/// only the first moved, `a` is its alone.
#[test]
fn a_package_with_two_bumped_sources_is_ambiguous() {
    let project = project_with_libraries();
    project.publish("org.test:bom-a:1", &managing(&[dependency("a", Some("1"))]));
    project.publish("org.test:bom-a:2", &managing(&[dependency("d", Some("2"))]));
    for version in ["1", "2"] {
        project.publish(
            &format!("org.test:bom-b:{version}"),
            &managing(&[dependency("a", Some("2"))]),
        );
    }
    let app = |a: &str, b: &str| {
        root(
            &project,
            "app",
            &format!(
                "<dependencyManagement><dependencies>{}{}</dependencies></dependencyManagement>{}",
                import("bom-a", a),
                import("bom-b", b),
                dependencies(&[dependency("a", None)]),
            ),
        )
    };
    let (text, data) = diff_after(
        &project,
        &[("pom.xml", app("1", "1"))],
        &[("pom.xml", app("2", "2"))],
    );
    assert_eq!(
        text,
        "  BOM org.test:bom-a 1 -> 2 and BOM org.test:bom-b 1 -> 2 (ambiguous)\n    \
         a  1 -> 2\n",
        "{text}"
    );
    let causes = data["causes"].as_array().unwrap();
    assert_eq!(causes.len(), 1, "{data}");
    assert_eq!(causes[0]["cause"], "ambiguous");
    assert_eq!(causes[0]["property"], Value::Null);
    assert_eq!(
        causes[0]["sources"],
        json!([
            {"kind": "import", "pom": "org.test:bom-a", "old_versions": ["1"], "new_versions": ["2"]},
            {"kind": "import", "pom": "org.test:bom-b", "old_versions": ["1"], "new_versions": ["2"]},
        ])
    );

    let (text, _) = diff_after(
        &project,
        &[("pom.xml", app("1", "1"))],
        &[("pom.xml", app("2", "1"))],
    );
    assert_eq!(
        text,
        "  BOM org.test:bom-a 1 -> 2 (imported)\n    \
         a  1 -> 2\n",
        "{text}"
    );
}

/// A parent from a repository that sets the property a version is written
/// as is named with the property, for a dependency the module declares
/// and for an entry of the project's own dependencyManagement. A property
/// the project sets itself names no parent.
#[test]
fn a_parent_property_bump_names_the_parent_and_the_property() {
    let project = project_with_libraries();
    for version in ["1", "2"] {
        project.publish(
            &format!("org.test:corp-parent:{version}"),
            &format!(
                "<packaging>pom</packaging><properties><a.version>{version}</a.version>\
                 <b.version>{version}</b.version></properties>"
            ),
        );
    }
    let app = |parent: &str, c: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>\
             <parent><groupId>org.test</groupId><artifactId>corp-parent</artifactId>\
             <version>{parent}</version><relativePath/></parent>\
             <artifactId>app</artifactId><version>1</version>{}\
             <properties><c.version>{c}</c.version></properties>\
             <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>{}</project>",
            repositories(&project),
            dependency("b", Some("${b.version}")),
            dependencies(&[
                dependency("a", Some("${a.version}")),
                dependency("b", None),
                dependency("c", Some("${c.version}")),
            ]),
        )
    };
    let (text, data) = diff_after(
        &project,
        &[("pom.xml", app("1", "1"))],
        &[("pom.xml", app("2", "2"))],
    );
    assert_eq!(
        text,
        "  parent org.test:corp-parent 1 -> 2 (property a.version)\n    \
         a  1 -> 2\n  \
         parent org.test:corp-parent 1 -> 2 (property b.version)\n    \
         b  1 -> 2\n  \
         c  1 -> 2\n",
        "{text}"
    );
    let lock = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
    let lock = serde_json::to_value(toml::from_str::<toml::Value>(&lock).unwrap()).unwrap();
    let schema = crate::schemas::validator(crate::schemas::RAEVA_LOCK_SCHEMA);
    crate::schemas::assert_schema_valid(&schema, &lock);
    let causes = data["causes"].as_array().unwrap();
    assert_eq!(causes.len(), 2, "{data}");
    assert_eq!(
        causes[0]["sources"],
        json!([{"kind": "property", "pom": "org.test:corp-parent", "old_versions": ["1"], "new_versions": ["2"]}])
    );
    for (cause, property, package) in [
        (&causes[0], "a.version", "pom.xml org.test:a:jar 1 -> 2"),
        (&causes[1], "b.version", "pom.xml org.test:b:jar 1 -> 2"),
    ] {
        assert_eq!(cause["cause"], "property");
        assert_eq!(cause["property"], property);
        assert_eq!(moved(&data, cause), [package]);
    }
}

/// A parent bump that comes with another property for the version is named
/// with the property the new lock reads.
#[test]
fn a_parent_bump_with_a_renamed_property_names_the_new_one() {
    let project = project_with_libraries();
    for (version, property) in [("1", "a.version"), ("2", "a.next")] {
        project.publish(
            &format!("org.test:corp-parent:{version}"),
            &format!(
                "<packaging>pom</packaging><properties><{property}>{version}</{property}>\
                 </properties>"
            ),
        );
    }
    let app = |parent: &str, property: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>\
             <parent><groupId>org.test</groupId><artifactId>corp-parent</artifactId>\
             <version>{parent}</version><relativePath/></parent>\
             <artifactId>app</artifactId><version>1</version>{}{}</project>",
            repositories(&project),
            dependencies(&[dependency("a", Some(&format!("${{{property}}}")))]),
        )
    };
    let (text, data) = diff_after(
        &project,
        &[("pom.xml", app("1", "a.version"))],
        &[("pom.xml", app("2", "a.next"))],
    );
    assert_eq!(
        text, "  parent org.test:corp-parent 1 -> 2 (property a.next)\n    a  1 -> 2\n",
        "{text}"
    );
    assert_eq!(data["causes"][0]["property"], "a.next", "{data}");
}

/// A parent bump names the lineage's two versions, not every version of
/// that parent the module read: here the old `x` has parent 0 and the new
/// one parent 1, which the project's lineage moved from.
#[test]
fn a_parent_bump_names_the_lineage_versions() {
    let project = project_with_libraries();
    let parent = |version: &str| {
        format!(
            "<parent><groupId>org.test</groupId><artifactId>corp-parent</artifactId>\
             <version>{version}</version><relativePath/></parent>"
        )
    };
    for version in ["0", "1", "2"] {
        project.publish(
            &format!("org.test:corp-parent:{version}"),
            &format!(
                "<packaging>pom</packaging><properties><x.version>{version}</x.version>\
                 </properties>"
            ),
        );
    }
    project.publish("org.test:x:1", &parent("0"));
    project.publish("org.test:x:2", &parent("1"));
    let app = |version: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{}\
             <artifactId>app</artifactId><version>1</version>{}{}</project>",
            parent(version),
            repositories(&project),
            dependencies(&[dependency("x", Some("${x.version}"))]),
        )
    };
    let (text, data) = diff_after(&project, &[("pom.xml", app("1"))], &[("pom.xml", app("2"))]);
    assert_eq!(
        text,
        "  parent org.test:corp-parent 1 -> 2 (property x.version)\n    x  1 -> 2\n  \
         support POMs (parents and BOMs): 1 removed; -v lists them\n",
        "{text}"
    );
    assert_eq!(
        data["causes"][0]["sources"],
        json!([{"kind": "property", "pom": "org.test:corp-parent", "old_versions": ["1"], "new_versions": ["2"]}])
    );
}

/// A version the module declares itself has no recorded cause, so the diff
/// stays as it was.
#[test]
fn a_direct_change_has_no_cause() {
    let project = project_with_libraries();
    let app = |version: &str| {
        root(
            &project,
            "app",
            &dependencies(&[dependency("a", Some(version))]),
        )
    };
    let (text, data) = diff_after(&project, &[("pom.xml", app("1"))], &[("pom.xml", app("2"))]);
    assert_eq!(text, "  a  1 -> 2\n", "{text}");
    assert_eq!(data["causes"], json!([]));
}

/// A reactor of `root` with `properties` and the modules `boms` and `app`
/// (all at `version`): `app` declares `a` and `b` without versions and
/// takes them from the `app_management` its own dependencyManagement holds.
fn reactor_files(
    project: &Project,
    version: &str,
    properties: &str,
    root_management: &[String],
    boms: &[(&str, String)],
    app_management: &[String],
) -> Vec<(&'static str, String)> {
    let parent = format!(
        "<parent><groupId>org.test</groupId><artifactId>root</artifactId>\
         <version>{version}</version></parent>"
    );
    let modules: String = (boms.iter().map(|(name, _)| *name))
        .chain(["app"])
        .map(|name| format!("<module>{name}</module>"))
        .collect();
    let mut files = vec![(
        "pom.xml",
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>{version}</version>{}\
             <modules>{modules}</modules><properties>{properties}</properties></project>",
            managing(root_management)
        ),
    )];
    for (name, body) in boms {
        let path: &'static str = Box::leak(format!("{name}/pom.xml").into_boxed_str());
        files.push((
            path,
            format!(
                "<project><modelVersion>4.0.0</modelVersion>{parent}\
                 <artifactId>{name}</artifactId>{}{body}</project>",
                repositories(project)
            ),
        ));
    }
    files.push((
        "app/pom.xml",
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{parent}<artifactId>app</artifactId>{}{}{}</project>",
            repositories(project),
            managing(app_management).replace("<packaging>pom</packaging>", ""),
            dependencies(&[dependency("a", None), dependency("b", None)]),
        ),
    ));
    files
}

/// A BOM of the reactor that the module imports is named as an external
/// one is when its version moves, without the `project.version` property
/// that names the whole reactor's version.
#[test]
fn a_reactor_bom_bump_leads_with_the_bom() {
    let project = project_with_libraries();
    let files = |version: &str| {
        reactor_files(
            &project,
            version,
            "",
            &[dependency("b", Some("1"))],
            &[("bom", managing(&[dependency("a", Some(version))]))],
            &[import("bom", "${project.version}")],
        )
    };
    let (text, data) = diff_after(&project, &files("1"), &files("2"));
    assert_eq!(
        text,
        "  BOM org.test:bom 1 -> 2 (imported)\n    a  1 -> 2\n  \
         module app/pom.xml: org.test:app:1 -> org.test:app:2\n  \
         module bom/pom.xml: org.test:bom:1 -> org.test:bom:2\n  \
         module pom.xml: org.test:root:1 -> org.test:root:2\n",
        "{text}"
    );
    let causes = data["causes"].as_array().unwrap();
    assert_eq!(causes.len(), 1, "{data}");
    assert_eq!(
        causes[0]["sources"],
        json!([{"kind": "import", "pom": "org.test:bom", "old_versions": ["1"], "new_versions": ["2"]}])
    );
    assert_eq!(causes[0]["cause"], "imported");
    assert_eq!(causes[0]["property"], Value::Null);
    assert_eq!(
        moved(&data, &causes[0]),
        ["app/pom.xml org.test:a:jar 1 -> 2"]
    );
}

/// A reactor BOM is named also when its module moved to another directory
/// along with its version.
#[test]
fn a_moved_reactor_bom_is_named() {
    let project = project_with_libraries();
    let files = |version: &str| {
        reactor_files(
            &project,
            version,
            "",
            &[dependency("b", Some("1"))],
            &[("bom", managing(&[dependency("a", Some(version))]))],
            &[import("bom", "${project.version}")],
        )
    };
    let moved_files: Vec<_> = (files("2").into_iter())
        .map(|(path, text)| match path {
            "bom/pom.xml" => ("platform/pom.xml", text),
            "pom.xml" => (
                path,
                text.replace("<module>bom</module>", "<module>platform</module>"),
            ),
            _ => (path, text),
        })
        .collect();
    let (text, data) = diff_after(&project, &files("1"), &moved_files);
    assert!(
        text.starts_with("  BOM org.test:bom 1 -> 2 (imported)\n    a  1 -> 2\n"),
        "{text}"
    );
    let causes = data["causes"].as_array().unwrap();
    assert_eq!(causes.len(), 1, "{data}");
    assert_eq!(
        moved(&data, &causes[0]),
        ["app/pom.xml org.test:a:jar 1 -> 2"]
    );
}

/// A reactor BOM whose version stayed is named when what it manages moved,
/// and so is the reactor's root as the parent whose property moved what it
/// manages, though not where the module itself wrote over the property.
#[test]
fn a_changed_reactor_bom_or_parent_at_the_same_version_is_named() {
    let project = project_with_libraries();
    let files = |a: &str, b: &str| {
        reactor_files(
            &project,
            "1",
            &format!("<b.version>{b}</b.version>"),
            &[dependency("b", Some("${b.version}"))],
            &[("bom", managing(&[dependency("a", Some(a))]))],
            &[import("bom", "1")],
        )
    };
    let (text, data) = diff_after(&project, &files("1", "1"), &files("2", "1"));
    assert_eq!(
        text, "  BOM org.test:bom 1 changed (imported)\n    a  1 -> 2\n",
        "{text}"
    );
    let causes = data["causes"].as_array().unwrap();
    assert_eq!(
        causes[0]["sources"],
        json!([{"kind": "import", "pom": "org.test:bom", "old_versions": ["1"], "new_versions": ["1"]}])
    );
    assert_eq!(causes[0]["cause"], "imported");
    assert_eq!(
        moved(&data, &causes[0]),
        ["app/pom.xml org.test:a:jar 1 -> 2"]
    );

    let (text, data) = diff_after(&project, &files("2", "1"), &files("2", "2"));
    assert_eq!(
        text, "  parent org.test:root 1 changed (direct)\n    b  1 -> 2\n",
        "{text}"
    );
    let causes = data["causes"].as_array().unwrap();
    assert_eq!(
        causes[0]["sources"],
        json!([{"kind": "pom", "pom": "org.test:root", "old_versions": ["1"], "new_versions": ["1"]}])
    );
    assert_eq!(causes[0]["cause"], "direct");
    assert_eq!(causes[0]["property"], Value::Null);
    assert_eq!(
        moved(&data, &causes[0]),
        ["app/pom.xml org.test:b:jar 1 -> 2"]
    );

    let mut overridden = files("2", "2");
    let app = &mut overridden.last_mut().unwrap().1;
    *app = app.replace(
        "<artifactId>app</artifactId>",
        "<artifactId>app</artifactId><properties><b.version>1</b.version></properties>",
    );
    let (text, data) = diff_after(&project, &files("2", "2"), &overridden);
    assert_eq!(text, "  b  2 -> 1\n", "{text}");
    assert_eq!(data["causes"], json!([]));
}

/// The outermost BOM the module imports is the one named: a reactor BOM
/// whose import of another one, of the reactor or not, moved.
#[test]
fn a_reactor_bom_is_named_for_the_boms_it_imports() {
    let project = project_with_libraries();
    for version in ["1", "2"] {
        project.publish(
            &format!("org.test:ext-bom:{version}"),
            &managing(&[dependency("b", Some(version))]),
        );
    }
    let files = |version: &str| {
        reactor_files(
            &project,
            "1",
            "",
            &[],
            &[
                ("inner", managing(&[dependency("a", Some(version))])),
                (
                    "outer",
                    managing(&[import("inner", "1"), import("ext-bom", version)]),
                ),
            ],
            &[import("outer", "1")],
        )
    };
    let (text, data) = diff_after(&project, &files("1"), &files("2"));
    assert_eq!(
        text,
        "  BOM org.test:outer 1 changed (imported)\n    a  1 -> 2\n    b  1 -> 2\n  \
         support POMs (parents and BOMs): 1 added, 1 removed; -v lists them\n",
        "{text}"
    );
    let causes = data["causes"].as_array().unwrap();
    assert_eq!(causes.len(), 1, "{data}");
    assert_eq!(
        causes[0]["sources"],
        json!([{"kind": "import", "pom": "org.test:outer", "old_versions": ["1"], "new_versions": ["1"]}])
    );
    assert_eq!(
        moved(&data, &causes[0]),
        [
            "app/pom.xml org.test:a:jar 1 -> 2",
            "app/pom.xml org.test:b:jar 1 -> 2"
        ]
    );
}

/// A module whose artifactId is written with a property still names the
/// BOM it imports.
#[test]
fn a_module_with_an_expression_in_its_artifact_id_names_its_bom() {
    let project = project_with_libraries();
    for version in ["1", "2"] {
        project.publish(
            &format!("org.test:bom:{version}"),
            &managing(&[dependency("a", Some(version))]),
        );
    }
    let app = |bom: &str| {
        root(
            &project,
            "app-${suffix}",
            &format!(
                "<properties><suffix>x</suffix></properties>{}{}",
                managing(&[import("bom", bom)]).replace("<packaging>pom</packaging>", ""),
                dependencies(&[dependency("a", None)])
            ),
        )
    };
    let (text, data) = diff_after(&project, &[("pom.xml", app("1"))], &[("pom.xml", app("2"))]);
    assert_eq!(
        text, "  BOM org.test:bom 1 -> 2 (imported)\n    a  1 -> 2\n",
        "{text}"
    );
    assert_eq!(data["causes"][0]["cause"], "imported");
}
