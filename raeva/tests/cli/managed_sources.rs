//! Which part of a module's dependency management supplied each locked
//! version: a POM of its lineage or a BOM the lineage imports, and the
//! property the version is written as.

use std::fs;

use rv_lock::Lockfile;
use rv_maven_types::{ManagedKind, ManagedSource};

use crate::common::assert_success;
use crate::offline_project::Project;

const REPOSITORY: &str = "<repositories><repository><id>project-repo</id><url>file://${project.basedir}/REL</url></repository></repositories>";

fn dependency(artifact: &str, version: Option<&str>) -> String {
    let version = version.map_or(String::new(), |v| format!("<version>{v}</version>"));
    format!(
        "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>{version}</dependency>"
    )
}

/// The root manages `lib` through a property and `dep` with a literal, and
/// imports a BOM that manages `mid` through the property of the import.
/// `app` takes `lib` and `mid` from that management, `dep` reaches it below
/// `mid`, where management overrides `mid`'s `1.0`, and `own` keeps the
/// version `app` declares. Both Maven lines record the same sources.
#[test]
fn each_locked_version_names_the_management_that_supplied_it() {
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
         <modules><module>app</module></modules>\
         <properties><lib.version>1.0</lib.version><bom.version>3</bom.version></properties>{}\
         <dependencyManagement><dependencies>\
         <dependency><groupId>org.test</groupId><artifactId>lib</artifactId><version>${{lib.version}}</version></dependency>\
         <dependency><groupId>org.test</groupId><artifactId>dep</artifactId><version>2.0</version></dependency>\
         <dependency><groupId>org.test</groupId><artifactId>bom</artifactId><version>${{bom.version}}</version><type>pom</type><scope>import</scope></dependency>\
         </dependencies></dependencyManagement></project>",
        REPOSITORY.replace("REL", "repository/")
    );
    let app = format!(
        "<project><modelVersion>4.0.0</modelVersion>\
         <parent><groupId>org.test</groupId><artifactId>root</artifactId><version>1</version></parent>\
         <artifactId>app</artifactId>{}<dependencies>{}{}{}</dependencies></project>",
        REPOSITORY.replace("REL", "../repository/"),
        dependency("lib", None),
        dependency("mid", None),
        dependency("own", Some("1.0")),
    );
    let project = Project::synced_with(&[(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId><artifactId>empty</artifactId><version>1</version></project>",
    )]);
    project.publish("org.test:dep:1.0", "");
    project.publish("org.test:dep:2.0", "");
    project.publish("org.test:own:1.0", "");
    project.publish(
        "org.test:mid:1.0",
        &format!(
            "<dependencies>{}</dependencies>",
            dependency("dep", Some("1.0"))
        ),
    );
    project.publish("org.test:bom:3",
        &format!(
            "<packaging>pom</packaging><dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            dependency("mid", Some("1.0"))
        ),
    );
    fs::write(project.root().join("pom.xml"), root).unwrap();
    fs::create_dir_all(project.root().join("app")).unwrap();
    fs::write(project.root().join("app/pom.xml"), app).unwrap();

    let source = |kind, pom: &str, property: Option<&str>| ManagedSource {
        kind,
        pom: pom.to_string(),
        property: property.map(str::to_string),
    };
    let expected = [
        ("dep", Some(source(ManagedKind::Pom, "org.test:root", None))),
        (
            "lib",
            Some(source(
                ManagedKind::Pom,
                "org.test:root",
                Some("lib.version"),
            )),
        ),
        (
            "mid",
            Some(source(
                ManagedKind::Import,
                "org.test:bom",
                Some("bom.version"),
            )),
        ),
        ("own", None),
    ];
    for mode in ["3.9", "3.10"] {
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .unwrap();
        assert_success(&project.raeva(&["sync", "--offline"]), mode);
        let lock = Lockfile::read(&project.root().join("raeva.lock")).unwrap();
        let module = (lock.platforms[0].modules.iter())
            .find(|module| module.path == "app/pom.xml")
            .unwrap();
        let found: Vec<_> = (module.packages.iter())
            .map(|package| {
                let artifact = package.coordinate.artifact_id().to_string();
                (artifact, package.managed.as_deref().cloned())
            })
            .collect();
        let expected: Vec<_> = (expected.iter())
            .map(|(artifact, source)| (artifact.to_string(), source.clone()))
            .collect();
        assert_eq!(found, expected, "{mode}");
        let dep = (module.packages.iter())
            .find(|package| package.coordinate.artifact_id() == "dep")
            .unwrap();
        assert_eq!(dep.coordinate.version(), "2.0", "{mode}");
        let text = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
        assert!(
            text.contains(r"import\torg.test:bom\tbom.version\t2"),
            "{mode}: {text}"
        );
    }
}

/// A transitive version that management chose keeps that source through
/// relocations: `old`, managed through `old.version`, relocates to `new`;
/// `x` relocates to the managed `mid`, whose managed version relocates to
/// `fin`. Below `k:1`, which relocates to `k:2` in its own group and
/// artifact, Maven 3.10 keeps the versions `k:2` declares, so `c` names a
/// source only where management chose its version.
#[test]
fn a_relocated_version_keeps_the_management_that_chose_it() {
    let relocation = |artifact: Option<&str>, version: Option<&str>| {
        let artifact = artifact.map_or(String::new(), |a| format!("<artifactId>{a}</artifactId>"));
        let version = version.map_or(String::new(), |v| format!("<version>{v}</version>"));
        format!(
            "<distributionManagement><relocation>{artifact}{version}</relocation></distributionManagement>"
        )
    };
    let deps = |list: &[String]| format!("<dependencies>{}</dependencies>", list.concat());
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version>\
         <properties><old.version>1</old.version></properties>{}\
         <dependencyManagement><dependencies>{}{}{}</dependencies></dependencyManagement>{}</project>",
        REPOSITORY.replace("REL", "repository/"),
        dependency("old", Some("${old.version}")),
        dependency("mid", Some("2")),
        dependency("c", Some("3")),
        deps(&[
            dependency("d1", Some("1")),
            dependency("d2", Some("1")),
            dependency("d3", Some("1")),
        ]),
    );
    let project = Project::synced_with(&[(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId><artifactId>empty</artifactId><version>1</version></project>",
    )]);
    project.publish("org.test:d1:1", &deps(&[dependency("old", Some("0"))]));
    project.publish("org.test:old:1", &relocation(Some("new"), None));
    project.publish("org.test:new:1", "");
    project.publish("org.test:d2:1", &deps(&[dependency("x", Some("1"))]));
    project.publish("org.test:x:1", &relocation(Some("mid"), None));
    project.publish("org.test:mid:1", "");
    project.publish("org.test:mid:2", &relocation(Some("fin"), None));
    project.publish("org.test:fin:2", "");
    project.publish("org.test:d3:1", &deps(&[dependency("k", Some("1"))]));
    project.publish("org.test:k:1", &relocation(None, Some("2")));
    project.publish("org.test:k:2", &deps(&[dependency("c", Some("1"))]));
    project.publish("org.test:c:1", "");
    project.publish("org.test:c:3", "");
    fs::write(project.root().join("pom.xml"), root).unwrap();

    let root_source = |property: Option<&str>| {
        Some(ManagedSource {
            kind: ManagedKind::Pom,
            pom: "org.test:app".to_string(),
            property: property.map(str::to_string),
        })
    };
    for mode in ["3.9", "3.10"] {
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\n"),
        )
        .unwrap();
        assert_success(&project.raeva(&["sync", "--offline"]), mode);
        let lock = Lockfile::read(&project.root().join("raeva.lock")).unwrap();
        let found: std::collections::BTreeMap<_, _> = (lock.platforms[0].modules[0].packages)
            .iter()
            .map(|package| {
                let coordinate = &package.coordinate;
                (
                    coordinate.artifact_id().to_string(),
                    (
                        coordinate.version().to_string(),
                        package.managed.as_deref().cloned(),
                    ),
                )
            })
            .collect();
        assert_eq!(
            found["new"],
            ("1".to_string(), root_source(Some("old.version"))),
            "{mode}: {found:?}"
        );
        assert_eq!(
            found["fin"],
            ("2".to_string(), root_source(None)),
            "{mode}: {found:?}"
        );
        assert_eq!(found["d1"].1, None, "{mode}");
        let (version, source) = &found["c"];
        assert_eq!(
            *source,
            (version == "3").then(|| root_source(None)).flatten(),
            "{mode}: {found:?}"
        );
        eprintln!("{mode}: c {version}");
    }
}
