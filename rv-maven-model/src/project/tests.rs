//! Unit tests for the `Project` effective-model assembly.

#![allow(clippy::field_reassign_with_default)]

use super::bom::resolve_bom_imports;
use super::dep_management::{
    apply_managed_dependency, build_managed_dep_index, find_managed_dependency_indexed,
    resolve_dependencies,
};
use super::*;
use crate::Activation;
use crate::activation::ActivationProperty;
use crate::dependency::{Dependency, Exclusion};
use crate::pom::{Parent, Pom};
use std::collections::HashMap;
use std::path::Path;

/// Helper function for tests to find a managed dependency.
/// Uses the indexed lookup internally for efficiency.
fn find_managed_dependency<'a>(
    dep: &Dependency,
    management: &'a DependencyManagement,
) -> Option<&'a Dependency> {
    let index = build_managed_dep_index(management);
    find_managed_dependency_indexed(dep, &index)
}

struct TestResolver {
    parent: Pom,
}

impl ParentResolver for TestResolver {
    fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
        Ok(Some(self.parent.clone()))
    }
}

struct BomResolver {
    boms: HashMap<(String, String, String, String, Option<String>), Pom>,
}

impl ParentResolver for BomResolver {
    fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
        Ok(None)
    }

    fn resolve_import_pom(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        type_: Option<&str>,
        classifier: Option<&str>,
    ) -> Result<Option<Pom>, PomError> {
        let type_ = type_
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("pom");
        let classifier = classifier
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string());
        let key = (
            group_id.to_string(),
            artifact_id.to_string(),
            version.to_string(),
            type_.to_string(),
            classifier,
        );
        Ok(self.boms.get(&key).cloned())
    }
}

struct ParentChainBomResolver {
    parents: HashMap<(String, String, String), Pom>,
    boms: HashMap<(String, String, String, String, Option<String>), Pom>,
}

impl ParentResolver for ParentChainBomResolver {
    fn resolve_parent(&self, parent: &Parent) -> Result<Option<Pom>, PomError> {
        let key = (
            parent.group_id.clone(),
            parent.artifact_id.clone(),
            parent.version.clone(),
        );
        Ok(self.parents.get(&key).cloned())
    }

    fn resolve_import_pom(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        type_: Option<&str>,
        classifier: Option<&str>,
    ) -> Result<Option<Pom>, PomError> {
        let type_ = type_
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("pom");
        let classifier = classifier
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string());
        let key = (
            group_id.to_string(),
            artifact_id.to_string(),
            version.to_string(),
            type_.to_string(),
            classifier,
        );
        Ok(self.boms.get(&key).cloned())
    }
}

fn load_fixture(path: &str) -> Pom {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-fixtures")
        .join(path);
    let xml = std::fs::read_to_string(path).unwrap();
    Pom::parse(&xml).unwrap()
}

#[test]
fn resolves_properties_and_managed_versions() {
    let mut parent = Pom::default();
    parent.group_id = Some("com.base".to_string());
    parent.artifact_id = Some("parent".to_string());
    parent.version = Some("1.0.0".to_string());
    parent.properties.insert("revision", "1.2.3");
    parent.dependency_management = Some(DependencyManagement {
        dependencies: vec![Dependency {
            group_id: "org.sample".to_string(),
            artifact_id: "lib".to_string(),
            version: Some("${revision}".to_string()),
            type_: None,
            classifier: None,
            scope: None,
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        }],
    });

    let mut child = Pom::default();
    child.parent = Some(Parent {
        group_id: "com.base".to_string(),
        artifact_id: "parent".to_string(),
        version: "1.0.0".to_string(),
        relative_path: None,
    });
    child.artifact_id = Some("child".to_string());
    child.version = Some("${revision}".to_string());
    child.dependencies.push(Dependency {
        group_id: "org.sample".to_string(),
        artifact_id: "lib".to_string(),
        version: None,
        type_: None,
        classifier: None,
        scope: None,
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    });

    let resolver = TestResolver { parent };
    let project = Project::from_pom(child, resolver).unwrap();

    assert_eq!(project.group_id, "com.base");
    assert_eq!(project.version, "1.2.3");
    assert_eq!(project.dependencies[0].version.as_deref(), Some("1.2.3"));
}

struct EmptyResolver;

impl ParentResolver for EmptyResolver {
    fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
        Ok(None)
    }
}

#[test]
fn merges_profile_dependencies_when_active() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencies>
        <dependency>
          <groupId>org.sample</groupId>
          <artifactId>base</artifactId>
          <version>1.0.0</version>
        </dependency>
      </dependencies>
      <profiles>
        <profile>
          <id>feature</id>
          <activation>
            <property>
              <name>feature</name>
              <value>on</value>
            </property>
          </activation>
          <properties>
            <flag>yes</flag>
          </properties>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>profile</artifactId>
              <version>2.0.0</version>
            </dependency>
          </dependencies>
        </profile>
      </profiles>
    </project>
    ";

    let mut ctx = ActivationContext::default();
    ctx.properties
        .insert("feature".to_string(), "on".to_string());

    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();

    assert_eq!(project.dependencies.len(), 2);
    assert!(
        project
            .dependencies
            .iter()
            .any(|dep| dep.artifact_id == "profile")
    );
    assert_eq!(
        project.properties.get("flag").map(String::as_str),
        Some("yes")
    );
}

/// Maven scopes the `activeByDefault` suppression rule to each POM's own
/// profile set: a child profile activating by condition must not suppress
/// the parent's default profile, nor the reverse. (Maven runs profile
/// selection per raw model in the lineage before inheritance assembly.)
#[test]
fn active_by_default_suppression_is_scoped_per_pom() {
    let parent_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>parent</artifactId>
      <version>1.0.0</version>
      <packaging>pom</packaging>
      <profiles>
        <profile>
          <id>parent-default</id>
          <activation>
            <activeByDefault>true</activeByDefault>
          </activation>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>from-parent-default</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
        </profile>
      </profiles>
    </project>
    ";
    let child_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <artifactId>app</artifactId>
      <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>1.0.0</version>
      </parent>
      <profiles>
        <profile>
          <id>child-conditional</id>
          <activation>
            <property>
              <name>feature</name>
            </property>
          </activation>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>from-child-conditional</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
        </profile>
        <profile>
          <id>child-default</id>
          <activation>
            <activeByDefault>true</activeByDefault>
          </activation>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>from-child-default</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
        </profile>
      </profiles>
    </project>
    ";

    let resolver = TestResolver {
        parent: Pom::parse(parent_xml).unwrap(),
    };

    // The child's conditional profile activates: it must suppress the
    // child's OWN default profile but not the parent's.
    let mut ctx = ActivationContext::default();
    ctx.properties
        .insert("feature".to_string(), "yes".to_string());
    let project =
        Project::from_pom_with_context(Pom::parse(child_xml).unwrap(), resolver, &ctx).unwrap();
    let has = |artifact: &str| {
        project
            .dependencies
            .iter()
            .any(|d| d.artifact_id == artifact)
    };

    assert!(has("from-child-conditional"), "conditional profile active");
    assert!(
        !has("from-child-default"),
        "the child's own default profile is suppressed by its sibling"
    );
    assert!(
        has("from-parent-default"),
        "a child profile activating must not suppress the parent's default profile"
    );

    // Nothing activates: both defaults contribute.
    let resolver = TestResolver {
        parent: Pom::parse(parent_xml).unwrap(),
    };
    let project = Project::from_pom_with_context(
        Pom::parse(child_xml).unwrap(),
        resolver,
        &ActivationContext::default(),
    )
    .unwrap();
    let has = |artifact: &str| {
        project
            .dependencies
            .iter()
            .any(|d| d.artifact_id == artifact)
    };
    assert!(has("from-child-default"));
    assert!(has("from-parent-default"));
}

/// Maven's PropertyProfileActivator consults only user/system properties:
/// a POM's own `<properties>` never satisfy a `<property>` activation
/// condition, and the inverse `!prop` form must not be defeated by a POM
/// defining that name.
#[test]
fn pom_properties_do_not_drive_property_activation() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <properties>
        <feature>on</feature>
      </properties>
      <profiles>
        <profile>
          <id>gated-on-pom-prop</id>
          <activation>
            <property>
              <name>feature</name>
              <value>on</value>
            </property>
          </activation>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>gated</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
        </profile>
        <profile>
          <id>active-unless-prop</id>
          <activation>
            <property>
              <name>!feature</name>
            </property>
          </activation>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>unless</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
        </profile>
      </profiles>
    </project>
    ";

    let ctx = ActivationContext::default();
    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();

    assert!(
        !project
            .dependencies
            .iter()
            .any(|d| d.artifact_id == "gated"),
        "a POM <properties> entry must not activate a property-gated profile"
    );
    assert!(
        project
            .dependencies
            .iter()
            .any(|d| d.artifact_id == "unless"),
        "a POM <properties> entry must not defeat a !prop activation"
    );

    // The same profile still activates from a user/system property.
    let mut user_ctx = ActivationContext::default();
    user_ctx
        .properties
        .insert("feature".to_string(), "on".to_string());
    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &user_ctx)
            .unwrap();
    assert!(
        project
            .dependencies
            .iter()
            .any(|d| d.artifact_id == "gated"),
        "a user property must still activate the profile"
    );
}

#[test]
fn merges_profile_dependency_management_when_active() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencies>
        <dependency>
          <groupId>org.sample</groupId>
          <artifactId>managed</artifactId>
        </dependency>
      </dependencies>
      <profiles>
        <profile>
          <id>feature</id>
          <activation>
            <property>
              <name>feature</name>
              <value>on</value>
            </property>
          </activation>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>org.sample</groupId>
                <artifactId>managed</artifactId>
                <version>2.0.0</version>
                <scope>runtime</scope>
              </dependency>
            </dependencies>
          </dependencyManagement>
        </profile>
      </profiles>
    </project>
    ";

    let mut ctx = ActivationContext::default();
    ctx.properties
        .insert("feature".to_string(), "on".to_string());

    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();

    assert_eq!(project.dependencies.len(), 1);
    assert_eq!(project.dependencies[0].version.as_deref(), Some("2.0.0"));
    assert_eq!(project.dependencies[0].scope.as_deref(), Some("runtime"));
    assert_eq!(project.dependency_management.dependencies.len(), 1);
}

#[test]
fn active_by_default_only_when_no_other_profiles_active() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <profiles>
        <profile>
          <id>explicit</id>
          <activation>
            <property>
              <name>feature</name>
              <value>on</value>
            </property>
          </activation>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>explicit</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
        </profile>
        <profile>
          <id>fallback</id>
          <activation>
            <activeByDefault>true</activeByDefault>
          </activation>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>default</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
        </profile>
      </profiles>
    </project>
    ";

    let mut ctx = ActivationContext::default();
    ctx.properties
        .insert("feature".to_string(), "on".to_string());
    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();
    assert!(
        project
            .dependencies
            .iter()
            .any(|dep| dep.artifact_id == "explicit")
    );
    assert!(
        !project
            .dependencies
            .iter()
            .any(|dep| dep.artifact_id == "default")
    );

    let ctx = ActivationContext::default();
    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();
    assert!(
        project
            .dependencies
            .iter()
            .any(|dep| dep.artifact_id == "default")
    );
    assert!(
        !project
            .dependencies
            .iter()
            .any(|dep| dep.artifact_id == "explicit")
    );
}

#[test]
fn explicit_profile_activation_overrides_conditions() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <profiles>
        <profile>
          <id>explicit</id>
          <activation>
            <property>
              <name>feature</name>
              <value>on</value>
            </property>
          </activation>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>explicit</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
        </profile>
      </profiles>
    </project>
    ";

    let mut ctx = ActivationContext::default();
    ctx.active_profiles.push("explicit".to_string());

    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();

    assert!(
        project
            .dependencies
            .iter()
            .any(|dep| dep.artifact_id == "explicit")
    );
}

#[test]
fn explicit_profile_deactivation_overrides_active_by_default() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <profiles>
        <profile>
          <id>default</id>
          <activation>
            <activeByDefault>true</activeByDefault>
          </activation>
          <dependencies>
            <dependency>
              <groupId>org.sample</groupId>
              <artifactId>default</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
        </profile>
      </profiles>
    </project>
    ";

    let mut ctx = ActivationContext::default();
    ctx.inactive_profiles.push("default".to_string());
    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();
    assert!(
        !project
            .dependencies
            .iter()
            .any(|dep| dep.artifact_id == "default")
    );

    let ctx = ActivationContext::default();
    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();
    assert!(
        project
            .dependencies
            .iter()
            .any(|dep| dep.artifact_id == "default")
    );
}

#[test]
fn parent_profile_modules_are_not_inherited_into_child_aggregation() {
    let parent = Pom::parse(
        r#"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>com.example</groupId>
          <artifactId>parent</artifactId>
          <version>1</version>
          <packaging>pom</packaging>
          <modules><module>parent-base</module></modules>
          <profiles>
            <profile>
              <id>parent-modules</id>
              <activation><activeByDefault>true</activeByDefault></activation>
              <modules><module>parent-profile</module></modules>
            </profile>
          </profiles>
        </project>
        "#,
    )
    .expect("parse parent");
    let child = Pom::parse(
        r#"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <parent>
            <groupId>com.example</groupId>
            <artifactId>parent</artifactId>
            <version>1</version>
          </parent>
          <artifactId>child</artifactId>
          <packaging>pom</packaging>
          <modules><module>child-base</module></modules>
          <profiles>
            <profile>
              <id>child-modules</id>
              <activation><activeByDefault>true</activeByDefault></activation>
              <modules><module>child-profile</module></modules>
            </profile>
          </profiles>
        </project>
        "#,
    )
    .expect("parse child");

    let project = Project::from_pom_with_context(
        child,
        TestResolver { parent },
        &ActivationContext::default(),
    )
    .expect("effective project");

    assert_eq!(project.modules, ["child-base", "child-profile"]);
}

#[test]
fn filters_dependencies_by_scope() {
    let project = Project {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: "1".to_string(),
        packaging: "jar".to_string(),
        properties: PropertyMap::new(),
        dependency_management: DependencyManagement::default(),
        dependencies: vec![
            Dependency {
                group_id: "g".to_string(),
                artifact_id: "compile".to_string(),
                version: Some("1".to_string()),
                type_: None,
                classifier: None,
                scope: None,
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            },
            Dependency {
                group_id: "g".to_string(),
                artifact_id: "runtime".to_string(),
                version: Some("1".to_string()),
                type_: None,
                classifier: None,
                scope: Some("runtime".to_string()),
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            },
            Dependency {
                group_id: "g".to_string(),
                artifact_id: "test".to_string(),
                version: Some("1".to_string()),
                type_: None,
                classifier: None,
                scope: Some("test".to_string()),
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            },
        ],
        repositories: Vec::new(),
        profiles: Vec::new(),
        modules: Vec::new(),
        relocation: None,
    };

    let runtime = project.dependencies(Scope::Runtime);
    assert_eq!(runtime.len(), 2);
    let test = project.dependencies(Scope::Test);
    assert_eq!(test.len(), 3);
}

#[test]
fn managed_versions_match_classifier_and_type() {
    let management = DependencyManagement {
        dependencies: vec![
            Dependency {
                group_id: "g".to_string(),
                artifact_id: "a".to_string(),
                version: Some("1".to_string()),
                type_: None,
                classifier: None,
                scope: None,
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            },
            Dependency {
                group_id: "g".to_string(),
                artifact_id: "a".to_string(),
                version: Some("2".to_string()),
                type_: Some("jar".to_string()),
                classifier: Some("tests".to_string()),
                scope: None,
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            },
            Dependency {
                group_id: "g".to_string(),
                artifact_id: "a".to_string(),
                version: Some("3".to_string()),
                type_: Some("pom".to_string()),
                classifier: None,
                scope: None,
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            },
        ],
    };

    let dep = Dependency {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: None,
        type_: None,
        classifier: Some("tests".to_string()),
        scope: None,
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    };
    assert_eq!(
        find_managed_dependency(&dep, &management).and_then(|managed| managed.version.as_deref()),
        Some("2")
    );

    let dep_jar = Dependency {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: None,
        type_: Some("jar".to_string()),
        classifier: None,
        scope: None,
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    };
    assert_eq!(
        find_managed_dependency(&dep_jar, &management)
            .and_then(|managed| managed.version.as_deref()),
        Some("1")
    );

    let dep_pom = Dependency {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: None,
        type_: Some("pom".to_string()),
        classifier: None,
        scope: None,
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    };
    assert_eq!(
        find_managed_dependency(&dep_pom, &management)
            .and_then(|managed| managed.version.as_deref()),
        Some("3")
    );
}

#[test]
fn managed_scope_applies_when_missing() {
    let management = DependencyManagement {
        dependencies: vec![Dependency {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: None,
            type_: None,
            classifier: None,
            scope: Some("runtime".to_string()),
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        }],
    };

    let dep = Dependency {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: Some("1".to_string()),
        type_: None,
        classifier: None,
        scope: None,
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    };

    let project = ProjectInfo {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: "1".to_string(),
        packaging: "jar".to_string(),
        parent: None,
        basedir: None,
        local_repository: None,
    };

    let resolved =
        resolve_dependencies(vec![dep], &management, &PropertyMap::new(), &project).unwrap();
    assert_eq!(resolved[0].scope.as_deref(), Some("runtime"));
}

#[test]
fn managed_optional_applies_when_unspecified() {
    let management = DependencyManagement {
        dependencies: vec![Dependency {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: None,
            type_: None,
            classifier: None,
            scope: None,
            optional: Some("true".to_string()),
            exclusions: Vec::new(),
            system_path: None,
        }],
    };

    let dep_unspecified = Dependency {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: Some("1".to_string()),
        type_: None,
        classifier: None,
        scope: None,
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    };
    let dep_explicit_false = Dependency {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: Some("1".to_string()),
        type_: None,
        classifier: None,
        scope: None,
        optional: Some("false".to_string()),
        exclusions: Vec::new(),
        system_path: None,
    };

    let project = ProjectInfo {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: "1".to_string(),
        packaging: "jar".to_string(),
        parent: None,
        basedir: None,
        local_repository: None,
    };

    let resolved = resolve_dependencies(
        vec![dep_unspecified, dep_explicit_false],
        &management,
        &PropertyMap::new(),
        &project,
    )
    .unwrap();
    assert_eq!(resolved[0].optional.as_deref(), Some("true"));
    assert_eq!(resolved[1].optional.as_deref(), Some("false"));
}

#[test]
fn managed_exclusions_merge() {
    let management = DependencyManagement {
        dependencies: vec![Dependency {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: None,
            type_: None,
            classifier: None,
            scope: None,
            optional: None,
            exclusions: vec![Exclusion {
                group_id: "bad".to_string(),
                artifact_id: "lib".to_string(),
            }],
            system_path: None,
        }],
    };

    let dep = Dependency {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: Some("1".to_string()),
        type_: None,
        classifier: None,
        scope: None,
        optional: None,
        exclusions: vec![Exclusion {
            group_id: "ugly".to_string(),
            artifact_id: "util".to_string(),
        }],
        system_path: None,
    };

    let project = ProjectInfo {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: "1".to_string(),
        packaging: "jar".to_string(),
        parent: None,
        basedir: None,
        local_repository: None,
    };

    let resolved =
        resolve_dependencies(vec![dep], &management, &PropertyMap::new(), &project).unwrap();
    // Maven semantics: managed and dep-level exclusions are UNIONed.
    assert_eq!(resolved[0].exclusions.len(), 2);
    assert!(resolved[0].exclusions.contains(&Exclusion {
        group_id: "ugly".to_string(),
        artifact_id: "util".to_string(),
    }));
    assert!(resolved[0].exclusions.contains(&Exclusion {
        group_id: "bad".to_string(),
        artifact_id: "lib".to_string(),
    }));
}

#[test]
fn managed_type_applies_when_missing() {
    let management = DependencyManagement {
        dependencies: vec![Dependency {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: None,
            type_: Some("jar".to_string()),
            classifier: None,
            scope: None,
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        }],
    };

    let dep = Dependency {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: Some("1".to_string()),
        type_: None,
        classifier: None,
        scope: None,
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    };

    let project = ProjectInfo {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: "1".to_string(),
        packaging: "jar".to_string(),
        parent: None,
        basedir: None,
        local_repository: None,
    };

    let resolved =
        resolve_dependencies(vec![dep], &management, &PropertyMap::new(), &project).unwrap();
    assert_eq!(resolved[0].type_.as_deref(), Some("jar"));
}

#[test]
fn managed_dependencies_first_declaration_wins() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>g</groupId>
      <artifactId>a</artifactId>
      <version>1</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>g</groupId>
            <artifactId>a</artifactId>
            <version>1.0</version>
          </dependency>
          <dependency>
            <groupId>g</groupId>
            <artifactId>a</artifactId>
            <version>2.0</version>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    ";

    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), EmptyResolver).unwrap();

    let dep = Dependency {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        version: None,
        type_: None,
        classifier: None,
        scope: None,
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    };

    // Maven behavior: First declaration wins.
    assert_eq!(
        find_managed_dependency(&dep, &project.dependency_management)
            .and_then(|managed| managed.version.as_deref()),
        Some("1.0"),
        "Expected version 1.0 (first declaration), but got something else"
    );
}

#[test]
fn bom_import_first_wins() {
    let bom1 = {
        let mut p = Pom::default();
        p.group_id = Some("g".to_string());
        p.artifact_id = Some("bom1".to_string());
        p.version = Some("v".to_string());
        p.dependency_management = Some(DependencyManagement {
            dependencies: vec![Dependency {
                group_id: "g".to_string(),
                artifact_id: "target".to_string(),
                version: Some("1.0".to_string()),
                type_: None,
                classifier: None,
                scope: None,
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            }],
        });
        p
    };
    let bom2 = {
        let mut p = Pom::default();
        p.group_id = Some("g".to_string());
        p.artifact_id = Some("bom2".to_string());
        p.version = Some("v".to_string());
        p.dependency_management = Some(DependencyManagement {
            dependencies: vec![Dependency {
                group_id: "g".to_string(),
                artifact_id: "target".to_string(),
                version: Some("2.0".to_string()),
                type_: None,
                classifier: None,
                scope: None,
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            }],
        });
        p
    };

    let mut boms = HashMap::new();
    boms.insert(
        (
            "g".to_string(),
            "bom1".to_string(),
            "v".to_string(),
            "pom".to_string(),
            None,
        ),
        bom1,
    );
    boms.insert(
        (
            "g".to_string(),
            "bom2".to_string(),
            "v".to_string(),
            "pom".to_string(),
            None,
        ),
        bom2,
    );
    let resolver = BomResolver { boms };

    // BOM1 is imported BEFORE BOM2. BOM1 should win.
    let management = DependencyManagement {
        dependencies: vec![
            Dependency {
                group_id: "g".to_string(),
                artifact_id: "bom1".to_string(),
                version: Some("v".to_string()),
                type_: Some("pom".to_string()),
                classifier: None,
                scope: Some("import".to_string()),
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            },
            Dependency {
                group_id: "g".to_string(),
                artifact_id: "bom2".to_string(),
                version: Some("v".to_string()),
                type_: Some("pom".to_string()),
                classifier: None,
                scope: Some("import".to_string()),
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            },
        ],
    };

    let resolved = resolve_bom_imports(
        management,
        &PropertyMap::new(),
        &ProjectInfo {
            group_id: "app".into(),
            artifact_id: "app".into(),
            version: "1".into(),
            packaging: "jar".into(),
            parent: None,
            basedir: None,
            local_repository: None,
        },
        &resolver,
    )
    .unwrap();

    let dep = Dependency {
        group_id: "g".to_string(),
        artifact_id: "target".to_string(),
        version: None,
        type_: None,
        classifier: None,
        scope: None,
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    };

    assert_eq!(
        find_managed_dependency(&dep, &resolved.management)
            .and_then(|managed| managed.version.as_deref()),
        Some("1.0"),
        "Expected version 1.0 (from first BOM), but got something else"
    );
}
#[test]
fn bom_import_merges_versions() {
    let bom = load_fixture("bom-usage/guava-bom-pom.xml");
    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.google.guava".to_string(),
            "guava-bom".to_string(),
            "999.0.0-HEAD-jre-SNAPSHOT".to_string(),
            "pom".to_string(),
            None,
        ),
        bom,
    );
    let resolver = BomResolver { boms };

    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava-bom</artifactId>
            <version>999.0.0-HEAD-jre-SNAPSHOT</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>com.google.guava</groupId>
          <artifactId>guava</artifactId>
        </dependency>
      </dependencies>
    </project>
    ";

    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver).unwrap();
    assert_eq!(project.dependencies.len(), 1);
    assert_eq!(
        project.dependencies[0].version.as_deref(),
        Some("999.0.0-HEAD-jre-SNAPSHOT")
    );
}

#[test]
fn bom_import_defaults_type_pom() {
    let bom = load_fixture("bom-usage/guava-bom-pom.xml");
    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.google.guava".to_string(),
            "guava-bom".to_string(),
            "999.0.0-HEAD-jre-SNAPSHOT".to_string(),
            "pom".to_string(),
            None,
        ),
        bom,
    );
    let resolver = BomResolver { boms };

    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava-bom</artifactId>
            <version>999.0.0-HEAD-jre-SNAPSHOT</version>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>com.google.guava</groupId>
          <artifactId>guava</artifactId>
        </dependency>
      </dependencies>
    </project>
    ";

    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver).unwrap();
    assert_eq!(project.dependencies.len(), 1);
    assert_eq!(
        project.dependencies[0].version.as_deref(),
        Some("999.0.0-HEAD-jre-SNAPSHOT")
    );
}

#[test]
fn bom_properties_do_not_leak_into_importer() {
    // Per Maven spec, BOM imports contribute only managed dependencies,
    // NOT properties. BOM properties should not be available in the
    // importing project for dependency version resolution.
    let bom = load_fixture("bom-usage/guava-bom-pom.xml");
    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.google.guava".to_string(),
            "guava-bom".to_string(),
            "999.0.0-HEAD-jre-SNAPSHOT".to_string(),
            "pom".to_string(),
            None,
        ),
        bom,
    );
    let resolver = BomResolver { boms };

    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <properties>
        <maven-gpg-plugin.version>9.9.9</maven-gpg-plugin.version>
      </properties>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava-bom</artifactId>
            <version>999.0.0-HEAD-jre-SNAPSHOT</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>org.example</groupId>
          <artifactId>central</artifactId>
          <version>${central-publishing-maven-plugin.version}</version>
        </dependency>
        <dependency>
          <groupId>org.example</groupId>
          <artifactId>gpg</artifactId>
          <version>${maven-gpg-plugin.version}</version>
        </dependency>
      </dependencies>
    </project>
    ";

    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver).unwrap();
    // BOM property should NOT leak; version stays as unresolved reference
    let central = project
        .dependencies
        .iter()
        .find(|dep| dep.artifact_id == "central")
        .unwrap();
    assert_eq!(
        central.version.as_deref(),
        Some("${central-publishing-maven-plugin.version}"),
        "BOM properties should not leak into the importer"
    );
    // POM's own property should still resolve
    let gpg = project
        .dependencies
        .iter()
        .find(|dep| dep.artifact_id == "gpg")
        .unwrap();
    assert_eq!(gpg.version.as_deref(), Some("9.9.9"));
}

#[test]
fn bom_profiles_do_not_leak_into_importer() {
    // Per Maven spec, BOM profiles and their properties should NOT
    // be available in the importing project.
    let mut bom = load_fixture("bom-usage/guava-bom-pom.xml");
    let profile = bom.profiles.get_mut(0).expect("guava bom profile missing");
    profile.activation = Some(Activation {
        active_by_default: false,
        property: Some(ActivationProperty {
            name: Some("bom.profile".to_string()),
            value: Some("on".to_string()),
        }),
        os: None,
        jdk: None,
        file: None,
    });
    profile.properties.insert("bom.profile.version", "5.5.5");

    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.google.guava".to_string(),
            "guava-bom".to_string(),
            "999.0.0-HEAD-jre-SNAPSHOT".to_string(),
            "pom".to_string(),
            None,
        ),
        bom,
    );
    let resolver = BomResolver { boms };

    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava-bom</artifactId>
            <version>999.0.0-HEAD-jre-SNAPSHOT</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>from-profile</artifactId>
          <version>${bom.profile.version}</version>
        </dependency>
      </dependencies>
    </project>
    ";

    let mut ctx = ActivationContext::default();
    ctx.properties
        .insert("bom.profile".to_string(), "on".to_string());
    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), resolver, &ctx).unwrap();
    let dep = project
        .dependencies
        .iter()
        .find(|dep| dep.artifact_id == "from-profile")
        .unwrap();
    // BOM profile property should NOT leak into the importer
    assert_eq!(
        dep.version.as_deref(),
        Some("${bom.profile.version}"),
        "BOM profile properties should not leak into the importer"
    );
}

#[test]
fn local_dependency_management_overrides_bom() {
    let bom = load_fixture("bom-usage/guava-bom-pom.xml");
    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.google.guava".to_string(),
            "guava-bom".to_string(),
            "999.0.0-HEAD-jre-SNAPSHOT".to_string(),
            "pom".to_string(),
            None,
        ),
        bom,
    );
    let resolver = BomResolver { boms };

    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava-bom</artifactId>
            <version>999.0.0-HEAD-jre-SNAPSHOT</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
          <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>1.2.3</version>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>com.google.guava</groupId>
          <artifactId>guava</artifactId>
        </dependency>
      </dependencies>
    </project>
    ";

    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver).unwrap();
    assert_eq!(project.dependencies.len(), 1);
    assert_eq!(project.dependencies[0].version.as_deref(), Some("1.2.3"));
}

#[test]
fn child_bom_overrides_coordinates_from_inherited_bom() {
    let parent = Pom::parse(
        r"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>g</groupId>
          <artifactId>parent</artifactId>
          <version>1</version>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>g</groupId>
                <artifactId>parent-bom</artifactId>
                <version>1</version>
                <type>pom</type>
                <scope>import</scope>
              </dependency>
            </dependencies>
          </dependencyManagement>
        </project>
        ",
    )
    .unwrap();
    let parent_bom = Pom::parse(
        r"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>g</groupId>
          <artifactId>parent-bom</artifactId>
          <version>1</version>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>g</groupId>
                <artifactId>target</artifactId>
                <version>1</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
        </project>
        ",
    )
    .unwrap();
    let child_bom = Pom::parse(
        r"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>g</groupId>
          <artifactId>child-bom</artifactId>
          <version>1</version>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>g</groupId>
                <artifactId>target</artifactId>
                <version>2</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
        </project>
        ",
    )
    .unwrap();
    let child = Pom::parse(
        r"
        <project>
          <modelVersion>4.0.0</modelVersion>
          <parent>
            <groupId>g</groupId>
            <artifactId>parent</artifactId>
            <version>1</version>
          </parent>
          <artifactId>child</artifactId>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>g</groupId>
                <artifactId>child-bom</artifactId>
                <version>1</version>
                <type>pom</type>
                <scope>import</scope>
              </dependency>
            </dependencies>
          </dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>g</groupId>
              <artifactId>target</artifactId>
            </dependency>
          </dependencies>
        </project>
        ",
    )
    .unwrap();

    let mut parents = HashMap::new();
    parents.insert(
        ("g".to_string(), "parent".to_string(), "1".to_string()),
        parent,
    );
    let mut boms = HashMap::new();
    for (artifact, pom) in [("parent-bom", parent_bom), ("child-bom", child_bom)] {
        boms.insert(
            (
                "g".to_string(),
                artifact.to_string(),
                "1".to_string(),
                "pom".to_string(),
                None,
            ),
            pom,
        );
    }
    let resolver = ParentChainBomResolver { parents, boms };

    let project = Project::from_pom(child, resolver).unwrap();
    assert_eq!(project.dependencies[0].version.as_deref(), Some("2"));
}

#[test]
fn bom_import_cycle_respects_classifier() {
    let bom_a_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.test</groupId>
      <artifactId>bom</artifactId>
      <version>1.0</version>
      <packaging>pom</packaging>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.test</groupId>
            <artifactId>bom</artifactId>
            <version>1.0</version>
            <type>pom</type>
            <classifier>tests</classifier>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    ";
    let bom_b_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.test</groupId>
      <artifactId>bom</artifactId>
      <version>1.0</version>
      <packaging>pom</packaging>
    </project>
    ";

    let bom_a = Pom::parse(bom_a_xml).unwrap();
    let bom_b = Pom::parse(bom_b_xml).unwrap();
    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.test".to_string(),
            "bom".to_string(),
            "1.0".to_string(),
            "pom".to_string(),
            None,
        ),
        bom_a,
    );
    boms.insert(
        (
            "com.test".to_string(),
            "bom".to_string(),
            "1.0".to_string(),
            "pom".to_string(),
            Some("tests".to_string()),
        ),
        bom_b,
    );
    let resolver = BomResolver { boms };

    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.test</groupId>
            <artifactId>bom</artifactId>
            <version>1.0</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    ";

    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver).unwrap();
    assert!(project.dependency_management.dependencies.is_empty());
}

/// Test that parent version properties are interpolated before resolving the parent.
/// Projects that use the ${revision} pattern in the parent version rely on this.
#[test]
fn parent_version_property_interpolated_before_resolution() {
    struct RevisionParentResolver {
        parent: Pom,
    }

    impl ParentResolver for RevisionParentResolver {
        fn resolve_parent(&self, parent: &Parent) -> Result<Option<Pom>, PomError> {
            // Verify the version has been interpolated
            if parent.version.contains("${") {
                panic!(
                    "Parent version should be interpolated before resolution, got: {}",
                    parent.version
                );
            }
            if parent.version == "2.0.0" {
                Ok(Some(self.parent.clone()))
            } else {
                Ok(None)
            }
        }
    }

    let parent_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>parent</artifactId>
      <version>2.0.0</version>
      <packaging>pom</packaging>
    </project>
    "#;

    let parent = Pom::parse(parent_xml).unwrap();
    let resolver = RevisionParentResolver { parent };

    // Child POM uses ${revision} for parent version - a common CI/CD pattern
    let child_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <properties>
        <revision>2.0.0</revision>
      </properties>
      <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>${revision}</version>
      </parent>
      <artifactId>child</artifactId>
    </project>
    "#;

    let project = Project::from_pom(Pom::parse(child_xml).unwrap(), resolver).unwrap();
    assert_eq!(project.group_id, "com.example");
    assert_eq!(project.version, "2.0.0");
}

/// Test that BOM imports with ${project.parent.version} are properly interpolated.
/// This is a common pattern used by AWS SDK v2.
#[test]
fn bom_import_with_parent_version_property() {
    let bom_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>internal-bom</artifactId>
      <version>2.0.0</version>
      <packaging>pom</packaging>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.example</groupId>
            <artifactId>core</artifactId>
            <version>2.0.0</version>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    "#;

    let bom = Pom::parse(bom_xml).unwrap();
    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.example".to_string(),
            "internal-bom".to_string(),
            "2.0.0".to_string(),
            "pom".to_string(),
            None,
        ),
        bom,
    );

    struct ParentAndBomResolver {
        parent: Pom,
        boms: HashMap<(String, String, String, String, Option<String>), Pom>,
    }

    impl ParentResolver for ParentAndBomResolver {
        fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
            Ok(Some(self.parent.clone()))
        }

        fn resolve_import_pom(
            &self,
            group_id: &str,
            artifact_id: &str,
            version: &str,
            type_: Option<&str>,
            classifier: Option<&str>,
        ) -> Result<Option<Pom>, PomError> {
            let type_ = type_
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("pom");
            let classifier = classifier
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string());
            let key = (
                group_id.to_string(),
                artifact_id.to_string(),
                version.to_string(),
                type_.to_string(),
                classifier,
            );
            Ok(self.boms.get(&key).cloned())
        }
    }

    let parent_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>parent</artifactId>
      <version>2.0.0</version>
      <packaging>pom</packaging>
    </project>
    "#;

    let parent = Pom::parse(parent_xml).unwrap();
    let resolver = ParentAndBomResolver { parent, boms };

    // Child POM uses ${project.parent.version} for BOM import
    let child_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>2.0.0</version>
      </parent>
      <artifactId>child</artifactId>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.example</groupId>
            <artifactId>internal-bom</artifactId>
            <version>${project.parent.version}</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>core</artifactId>
        </dependency>
      </dependencies>
    </project>
    "#;

    let project = Project::from_pom(Pom::parse(child_xml).unwrap(), resolver).unwrap();
    // The BOM should be resolved and provide the version for 'core'
    assert_eq!(project.dependencies.len(), 1);
    assert_eq!(
        project.dependencies[0].version.as_deref(),
        Some("2.0.0"),
        "BOM import with ${{project.parent.version}} should resolve correctly"
    );
}

#[test]
fn import_coordinate_resolves_from_importer_own_properties() {
    // Maven resolves each import coordinate from the importer's OWN effective
    // properties (parent chain + own `<properties>`). Here the importer itself
    // defines `bom.a.version`, so `${bom.a.version}` resolves and `bom-a` is
    // imported, supplying the managed version for `target`.
    let bom_a_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>bom-a</artifactId>
      <version>1.0</version>
      <packaging>pom</packaging>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.example</groupId>
            <artifactId>target</artifactId>
            <version>4.2.0</version>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    "#;

    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.example".to_string(),
            "bom-a".to_string(),
            "1.0".to_string(),
            "pom".to_string(),
            None,
        ),
        Pom::parse(bom_a_xml).unwrap(),
    );
    let resolver = ParentChainBomResolver {
        parents: HashMap::new(),
        boms,
    };

    let pom_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <properties>
        <bom.a.version>1.0</bom.a.version>
      </properties>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.example</groupId>
            <artifactId>bom-a</artifactId>
            <version>${bom.a.version}</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>target</artifactId>
        </dependency>
      </dependencies>
    </project>
    "#;

    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver).unwrap();
    let target = project
        .dependencies
        .iter()
        .find(|dep| dep.artifact_id == "target")
        .expect("target dependency should exist");
    assert_eq!(
        target.version.as_deref(),
        Some("4.2.0"),
        "import coordinate must resolve from the importer's own properties"
    );
}

#[test]
fn sibling_bom_property_does_not_resolve_import_coordinate() {
    // Per Maven semantics an import coordinate is NOT resolvable from a property
    // contributed by a sibling imported BOM. `bom-b` (declared first) supplies
    // `bom.a.version`; the importer's `bom-a` import uses `${bom.a.version}` but
    // does not define it. The reference must stay unresolved, so under strict
    // BOM resolution the build fails rather than silently importing `bom-a`.
    let bom_a_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>bom-a</artifactId>
      <version>1.0</version>
      <packaging>pom</packaging>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.example</groupId>
            <artifactId>target</artifactId>
            <version>4.2.0</version>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    "#;

    let bom_b_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>bom-b</artifactId>
      <version>1.0</version>
      <packaging>pom</packaging>
      <properties>
        <bom.a.version>1.0</bom.a.version>
      </properties>
    </project>
    "#;

    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.example".to_string(),
            "bom-a".to_string(),
            "1.0".to_string(),
            "pom".to_string(),
            None,
        ),
        Pom::parse(bom_a_xml).unwrap(),
    );
    boms.insert(
        (
            "com.example".to_string(),
            "bom-b".to_string(),
            "1.0".to_string(),
            "pom".to_string(),
            None,
        ),
        Pom::parse(bom_b_xml).unwrap(),
    );
    let resolver = ParentChainBomResolver {
        parents: HashMap::new(),
        boms,
    };

    let pom_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.example</groupId>
            <artifactId>bom-b</artifactId>
            <version>1.0</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
          <dependency>
            <groupId>com.example</groupId>
            <artifactId>bom-a</artifactId>
            <version>${bom.a.version}</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>target</artifactId>
        </dependency>
      </dependencies>
    </project>
    "#;

    let err = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver)
        .expect_err("import coordinate must not resolve from a sibling BOM's property");
    match err {
        PomError::InvalidModel(message) => {
            assert!(
                message.contains("unresolved version"),
                "expected unresolved-version error, got: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn sibling_bom_parent_chain_property_does_not_resolve_import_coordinate() {
    // Same rule for a property reached through a sibling BOM's PARENT chain:
    // `bom-b` inherits `bom.a.version` from `bom-b-parent`, but that property
    // belongs to `bom-b`'s effective model, not the importer's. The importer's
    // `${bom.a.version}` coordinate must stay unresolved.
    let bom_a_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>bom-a</artifactId>
      <version>1.0</version>
      <packaging>pom</packaging>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.example</groupId>
            <artifactId>parent-derived-target</artifactId>
            <version>7.7.7</version>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    "#;

    let bom_b_parent_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>bom-b-parent</artifactId>
      <version>1.0</version>
      <packaging>pom</packaging>
      <properties>
        <bom.a.version>1.0</bom.a.version>
      </properties>
    </project>
    "#;

    let bom_b_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <parent>
        <groupId>com.example</groupId>
        <artifactId>bom-b-parent</artifactId>
        <version>1.0</version>
      </parent>
      <artifactId>bom-b</artifactId>
      <packaging>pom</packaging>
    </project>
    "#;

    let mut parents = HashMap::new();
    parents.insert(
        (
            "com.example".to_string(),
            "bom-b-parent".to_string(),
            "1.0".to_string(),
        ),
        Pom::parse(bom_b_parent_xml).unwrap(),
    );

    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.example".to_string(),
            "bom-a".to_string(),
            "1.0".to_string(),
            "pom".to_string(),
            None,
        ),
        Pom::parse(bom_a_xml).unwrap(),
    );
    boms.insert(
        (
            "com.example".to_string(),
            "bom-b".to_string(),
            "1.0".to_string(),
            "pom".to_string(),
            None,
        ),
        Pom::parse(bom_b_xml).unwrap(),
    );

    let resolver = ParentChainBomResolver { parents, boms };

    let pom_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.example</groupId>
            <artifactId>bom-b</artifactId>
            <version>1.0</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
          <dependency>
            <groupId>com.example</groupId>
            <artifactId>bom-a</artifactId>
            <version>${bom.a.version}</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>parent-derived-target</artifactId>
        </dependency>
      </dependencies>
    </project>
    "#;

    let err = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver)
        .expect_err("import coordinate must not resolve from a sibling BOM's parent property");
    match err {
        PomError::InvalidModel(message) => {
            assert!(
                message.contains("unresolved version"),
                "expected unresolved-version error, got: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn bom_parent_properties_resolve_managed_dependency_versions() {
    // Regression test for Quarkus BOM chain issue:
    // A BOM's parent defines properties that are used in the BOM's own
    // dependencyManagement entries. These property references must be
    // pre-interpolated before the managed deps are returned to the
    // importing project (which doesn't have those properties).
    let bom_parent_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>io.example</groupId>
      <artifactId>parent-bom</artifactId>
      <version>1.0</version>
      <packaging>pom</packaging>
      <properties>
        <servlet.version>6.1.0</servlet.version>
        <mockito.version>5.14.2</mockito.version>
      </properties>
    </project>
    "#;

    let bom_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <parent>
        <groupId>io.example</groupId>
        <artifactId>parent-bom</artifactId>
        <version>1.0</version>
      </parent>
      <artifactId>example-bom</artifactId>
      <packaging>pom</packaging>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>jakarta.servlet</groupId>
            <artifactId>jakarta.servlet-api</artifactId>
            <version>${servlet.version}</version>
          </dependency>
          <dependency>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-core</artifactId>
            <version>${mockito.version}</version>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    "#;

    let mut parents = HashMap::new();
    parents.insert(
        (
            "io.example".to_string(),
            "parent-bom".to_string(),
            "1.0".to_string(),
        ),
        Pom::parse(bom_parent_xml).unwrap(),
    );

    let mut boms = HashMap::new();
    boms.insert(
        (
            "io.example".to_string(),
            "example-bom".to_string(),
            "1.0".to_string(),
            "pom".to_string(),
            None,
        ),
        Pom::parse(bom_xml).unwrap(),
    );

    let resolver = ParentChainBomResolver { parents, boms };

    let pom_xml = r#"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>io.example</groupId>
            <artifactId>example-bom</artifactId>
            <version>1.0</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>jakarta.servlet</groupId>
          <artifactId>jakarta.servlet-api</artifactId>
        </dependency>
        <dependency>
          <groupId>org.mockito</groupId>
          <artifactId>mockito-core</artifactId>
        </dependency>
      </dependencies>
    </project>
    "#;

    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver).unwrap();

    let servlet = project
        .dependencies
        .iter()
        .find(|dep| dep.artifact_id == "jakarta.servlet-api")
        .expect("servlet dependency should exist");
    assert_eq!(
        servlet.version.as_deref(),
        Some("6.1.0"),
        "managed version from BOM parent property should be resolved"
    );

    let mockito = project
        .dependencies
        .iter()
        .find(|dep| dep.artifact_id == "mockito-core")
        .expect("mockito dependency should exist");
    assert_eq!(
        mockito.version.as_deref(),
        Some("5.14.2"),
        "managed version from BOM parent property should be resolved"
    );
}

#[test]
fn bom_import_cycle_detected() {
    let bom_a_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.test</groupId>
      <artifactId>bom-a</artifactId>
      <version>1.0</version>
      <packaging>pom</packaging>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.test</groupId>
            <artifactId>bom-b</artifactId>
            <version>1.0</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    ";
    let bom_b_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.test</groupId>
      <artifactId>bom-b</artifactId>
      <version>1.0</version>
      <packaging>pom</packaging>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.test</groupId>
            <artifactId>bom-a</artifactId>
            <version>1.0</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    ";

    let bom_a = Pom::parse(bom_a_xml).unwrap();
    let bom_b = Pom::parse(bom_b_xml).unwrap();
    let mut boms = HashMap::new();
    boms.insert(
        (
            "com.test".to_string(),
            "bom-a".to_string(),
            "1.0".to_string(),
            "pom".to_string(),
            None,
        ),
        bom_a,
    );
    boms.insert(
        (
            "com.test".to_string(),
            "bom-b".to_string(),
            "1.0".to_string(),
            "pom".to_string(),
            None,
        ),
        bom_b,
    );
    let resolver = BomResolver { boms };

    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>com.test</groupId>
            <artifactId>bom-a</artifactId>
            <version>1.0</version>
            <type>pom</type>
            <scope>import</scope>
          </dependency>
        </dependencies>
      </dependencyManagement>
    </project>
    ";

    let err = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver).unwrap_err();
    match err {
        PomError::InvalidModel(message) => {
            assert!(message.contains("BOM import cycle"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn whitespace_in_group_id_matches_managed_dependency() {
    // Regression test: some POMs have whitespace in <groupId>.
    // The managed dep index must still match after trimming.
    // Real-world example: Quarkus has `<groupId> jakarta.servlet</groupId>`
    let bom_xml = r#"
        <project>
            <modelVersion>4.0.0</modelVersion>
            <groupId>com.example</groupId>
            <artifactId>my-bom</artifactId>
            <version>1.0</version>
            <packaging>pom</packaging>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>jakarta.servlet</groupId>
                        <artifactId>jakarta.servlet-api</artifactId>
                        <version>6.0.0</version>
                    </dependency>
                </dependencies>
            </dependencyManagement>
        </project>
    "#;
    let pom_xml = r#"
        <project>
            <modelVersion>4.0.0</modelVersion>
            <groupId>com.example</groupId>
            <artifactId>my-app</artifactId>
            <version>1.0</version>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>my-bom</artifactId>
                        <version>1.0</version>
                        <type>pom</type>
                        <scope>import</scope>
                    </dependency>
                </dependencies>
            </dependencyManagement>
            <dependencies>
                <dependency>
                    <groupId> jakarta.servlet</groupId>
                    <artifactId>jakarta.servlet-api</artifactId>
                </dependency>
            </dependencies>
        </project>
    "#;
    let resolver = BomResolver {
        boms: HashMap::from([(
            (
                "com.example".to_string(),
                "my-bom".to_string(),
                "1.0".to_string(),
                "pom".to_string(),
                None,
            ),
            Pom::parse(bom_xml).unwrap(),
        )]),
    };
    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), resolver).unwrap();
    let servlet_dep = project
        .dependencies
        .iter()
        .find(|d| d.artifact_id == "jakarta.servlet-api")
        .expect("jakarta.servlet-api dependency should exist");
    assert_eq!(
        servlet_dep.group_id, "jakarta.servlet",
        "group_id should be trimmed"
    );
    assert_eq!(
        servlet_dep.version.as_deref(),
        Some("6.0.0"),
        "version should come from BOM management"
    );
}

// dependencyManagement entries must appear in declaration order.
#[test]
fn dependency_management_preserves_declaration_order() {
    let pom_xml = r#"
        <project>
            <modelVersion>4.0.0</modelVersion>
            <groupId>com.example</groupId>
            <artifactId>my-app</artifactId>
            <version>1.0</version>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.alpha</groupId>
                        <artifactId>alpha</artifactId>
                        <version>1.0</version>
                    </dependency>
                    <dependency>
                        <groupId>org.beta</groupId>
                        <artifactId>beta</artifactId>
                        <version>2.0</version>
                    </dependency>
                    <dependency>
                        <groupId>org.gamma</groupId>
                        <artifactId>gamma</artifactId>
                        <version>3.0</version>
                    </dependency>
                </dependencies>
            </dependencyManagement>
        </project>
    "#;
    struct NoopResolver;
    impl ParentResolver for NoopResolver {
        fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
            Ok(None)
        }
    }
    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), NoopResolver).unwrap();
    let mgmt = &project.dependency_management;
    assert_eq!(mgmt.dependencies.len(), 3);
    assert_eq!(mgmt.dependencies[0].artifact_id, "alpha");
    assert_eq!(mgmt.dependencies[1].artifact_id, "beta");
    assert_eq!(mgmt.dependencies[2].artifact_id, "gamma");
}

// Managed exclusions UNION with dep-level exclusions per Maven semantics; a
// dep without exclusions inherits the managed ones.
#[test]
fn apply_managed_dependency_exclusion_precedence() {
    let own_excl = Exclusion {
        group_id: "org.own".to_string(),
        artifact_id: "own-excl".to_string(),
    };
    let managed_excl = Exclusion {
        group_id: "org.managed".to_string(),
        artifact_id: "managed-excl".to_string(),
    };

    let managed = Dependency {
        group_id: "com.example".to_string(),
        artifact_id: "lib".to_string(),
        version: Some("1.0".to_string()),
        type_: None,
        classifier: None,
        scope: None,
        optional: None,
        exclusions: vec![managed_excl.clone()],
        system_path: None,
    };

    // Dep with its own exclusion: managed exclusion must NOT be appended.
    let mut dep_with_own = Dependency {
        group_id: "com.example".to_string(),
        artifact_id: "lib".to_string(),
        version: None,
        type_: None,
        classifier: None,
        scope: None,
        optional: None,
        exclusions: vec![own_excl.clone()],
        system_path: None,
    };
    apply_managed_dependency(&mut dep_with_own, &managed);
    assert_eq!(
        dep_with_own.exclusions.len(),
        2,
        "managed and dep-level exclusions must be unioned"
    );
    assert_eq!(dep_with_own.exclusions[0].artifact_id, "own-excl");
    assert_eq!(dep_with_own.exclusions[1].artifact_id, "managed-excl");

    // Dep without exclusions: should inherit managed exclusions.
    let mut dep_without = Dependency {
        group_id: "com.example".to_string(),
        artifact_id: "lib".to_string(),
        version: None,
        type_: None,
        classifier: None,
        scope: None,
        optional: None,
        exclusions: vec![],
        system_path: None,
    };
    apply_managed_dependency(&mut dep_without, &managed);
    assert_eq!(
        dep_without.exclusions.len(),
        1,
        "dep without exclusions should inherit managed exclusions"
    );
    assert_eq!(dep_without.exclusions[0].artifact_id, "managed-excl");
}

// A POM that declares a custom repository for hosting its own parent must
// have the repository visible to the resolver BEFORE the parent fetch
// runs. This test simulates that by capturing the order of observations
// vs parent-fetch calls; the hook fires first.
#[test]
fn observe_project_repositories_runs_before_parent_fetch() {
    use std::cell::RefCell;

    #[derive(Default)]
    struct OrderedResolver {
        events: RefCell<Vec<&'static str>>,
    }

    impl ParentResolver for OrderedResolver {
        fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
            self.events.borrow_mut().push("resolve_parent");
            // Return a minimal parent POM with the expected coordinates so
            // inheritance accepts it.
            let parent_xml = r#"<project>
                <groupId>com.base</groupId>
                <artifactId>parent</artifactId>
                <version>2.0.0</version>
            </project>"#;
            Ok(Some(Pom::parse(parent_xml).unwrap()))
        }

        fn observe_project_repositories(&self, _repositories: &[crate::Repository]) {
            self.events.borrow_mut().push("observe_repos");
        }
    }

    let pom_xml = r#"<project>
        <groupId>com.example</groupId>
        <artifactId>child</artifactId>
        <version>1.0.0</version>
        <parent>
            <groupId>com.base</groupId>
            <artifactId>parent</artifactId>
            <version>2.0.0</version>
        </parent>
        <repositories>
            <repository>
                <id>parent-host</id>
                <url>https://example.com/maven</url>
            </repository>
        </repositories>
    </project>"#;

    let resolver = OrderedResolver::default();
    let _project = Project::from_pom(Pom::parse(pom_xml).unwrap(), &resolver).unwrap();
    let events = resolver.events.borrow();
    let observe_idx = events
        .iter()
        .position(|e| *e == "observe_repos")
        .expect("observe_repos must be called");
    let resolve_idx = events
        .iter()
        .position(|e| *e == "resolve_parent")
        .expect("resolve_parent must be called");
    assert!(
        observe_idx < resolve_idx,
        "observe_project_repositories must run before resolve_parent (got events: {events:?})"
    );
}

// A POM without any <repositories> should not invoke the observer hook.
#[test]
fn observe_project_repositories_skipped_when_empty() {
    use std::cell::Cell;

    struct CountingResolver {
        calls: Cell<usize>,
    }

    impl ParentResolver for CountingResolver {
        fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
            Ok(None)
        }

        fn observe_project_repositories(&self, _repositories: &[crate::Repository]) {
            self.calls.set(self.calls.get() + 1);
        }
    }

    let pom_xml = r#"<project>
        <groupId>com.example</groupId>
        <artifactId>child</artifactId>
        <version>1.0.0</version>
    </project>"#;

    let resolver = CountingResolver {
        calls: Cell::new(0),
    };
    let _project = Project::from_pom(Pom::parse(pom_xml).unwrap(), &resolver).unwrap();
    assert_eq!(resolver.calls.get(), 0);
}

#[test]
fn project_prerequisites_maven_interpolates_dependency_versions() {
    struct NoOp;
    impl ParentResolver for NoOp {
        fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
            Ok(None)
        }
    }

    let pom_xml = r#"<project>
        <modelVersion>4.0.0</modelVersion>
        <groupId>com.example</groupId>
        <artifactId>plugin</artifactId>
        <version>1.0.0</version>
        <prerequisites>
            <maven>3.0</maven>
        </prerequisites>
        <dependencies>
            <dependency>
                <groupId>org.apache.maven</groupId>
                <artifactId>maven-plugin-api</artifactId>
                <version>${project.prerequisites.maven}</version>
            </dependency>
            <dependency>
                <groupId>org.apache.maven</groupId>
                <artifactId>maven-core</artifactId>
                <version>${pom.prerequisites.maven}</version>
            </dependency>
        </dependencies>
    </project>"#;

    let project = Project::from_pom(Pom::parse(pom_xml).unwrap(), &NoOp).unwrap();
    assert_eq!(project.dependencies[0].version.as_deref(), Some("3.0"));
    assert_eq!(project.dependencies[1].version.as_deref(), Some("3.0"));
}

#[test]
fn empty_group_id_after_interpolation_is_rejected() {
    struct NoOp;
    impl ParentResolver for NoOp {
        fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
            Ok(None)
        }
    }

    // ${project.groupId} inside <groupId> resolves through the temp_project
    // with an empty group_id; without the empty-coordinate guard, the
    // resulting project would silently carry "" as its groupId.
    let pom_xml = r#"<project>
        <modelVersion>4.0.0</modelVersion>
        <groupId>${project.groupId}</groupId>
        <artifactId>child</artifactId>
        <version>1.0.0</version>
    </project>"#;

    let err = Project::from_pom(Pom::parse(pom_xml).unwrap(), &NoOp).unwrap_err();
    match err {
        PomError::InvalidModel(msg) => {
            assert!(
                msg.contains("groupId"),
                "expected groupId error, got: {msg}"
            );
        }
        other => panic!("expected InvalidModel groupId error, got: {other:?}"),
    }
}

#[test]
fn empty_version_after_interpolation_is_rejected() {
    struct NoOp;
    impl ParentResolver for NoOp {
        fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
            Ok(None)
        }
    }

    let pom_xml = r#"<project>
        <modelVersion>4.0.0</modelVersion>
        <groupId>com.example</groupId>
        <artifactId>child</artifactId>
        <version>${project.version}</version>
    </project>"#;

    let err = Project::from_pom(Pom::parse(pom_xml).unwrap(), &NoOp).unwrap_err();
    match err {
        PomError::InvalidModel(msg) => {
            assert!(
                msg.contains("version"),
                "expected version error, got: {msg}"
            );
        }
        other => panic!("expected InvalidModel version error, got: {other:?}"),
    }
}
