//! Regression tests for Maven-semantics bug fixes.

use rv_maven_model::ParentResolver;
use rv_maven_model::{ActivationContext, Parent, Pom, PomError, Project};

struct EmptyResolver;

impl ParentResolver for EmptyResolver {
    fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
        Ok(None)
    }
}

// An `activeByDefault` profile must be deactivated whenever any other
// profile is activated via an explicit `-P` selection.
#[test]
fn active_by_default_suppressed_by_explicit_p_activation() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <profiles>
        <profile>
          <id>P-default</id>
          <activation>
            <activeByDefault>true</activeByDefault>
          </activation>
          <properties>
            <which>default</which>
          </properties>
        </profile>
        <profile>
          <id>P-extra</id>
          <properties>
            <which>extra</which>
          </properties>
        </profile>
      </profiles>
    </project>
    ";

    let ctx = ActivationContext {
        active_profiles: vec!["P-extra".to_string()],
        ..ActivationContext::default()
    };

    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();

    assert_eq!(
        project.properties.get("which").map(String::as_str),
        Some("extra"),
        "P-default must not contribute properties when P-extra is explicitly activated"
    );
}

// Regression guard: with no explicit -P and no other condition matches,
// activeByDefault still activates the profile.
#[test]
fn active_by_default_still_active_when_no_other_profile_selected() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <profiles>
        <profile>
          <id>P-default</id>
          <activation>
            <activeByDefault>true</activeByDefault>
          </activation>
          <properties>
            <which>default</which>
          </properties>
        </profile>
      </profiles>
    </project>
    ";

    let ctx = ActivationContext::default();
    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();

    assert_eq!(
        project.properties.get("which").map(String::as_str),
        Some("default")
    );
}

// An active profile's dependencyManagement entry overrides a same-GA
// entry in the base project depMgmt (Maven `sourceDominant=true`).
#[test]
fn active_profile_dep_management_overrides_base() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>x</groupId>
            <artifactId>lib</artifactId>
            <version>1.0</version>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>x</groupId>
          <artifactId>lib</artifactId>
        </dependency>
      </dependencies>
      <profiles>
        <profile>
          <id>override</id>
          <activation>
            <property>
              <name>use-new</name>
              <value>true</value>
            </property>
          </activation>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>x</groupId>
                <artifactId>lib</artifactId>
                <version>2.0</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
        </profile>
      </profiles>
    </project>
    ";

    let mut ctx = ActivationContext::default();
    ctx.properties
        .insert("use-new".to_string(), "true".to_string());

    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();

    let resolved = project
        .dependencies
        .iter()
        .find(|d| d.group_id == "x" && d.artifact_id == "lib")
        .expect("dep x:lib not found");
    assert_eq!(
        resolved.version.as_deref(),
        Some("2.0"),
        "active profile depMgmt must override base depMgmt (sourceDominant=true)"
    );
}

// Regression guard: when no profile overrides, base depMgmt still wins.
#[test]
fn base_dep_management_used_when_no_profile_override() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>x</groupId>
            <artifactId>lib</artifactId>
            <version>1.0</version>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>x</groupId>
          <artifactId>lib</artifactId>
        </dependency>
      </dependencies>
    </project>
    ";

    let ctx = ActivationContext::default();
    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();

    let resolved = project
        .dependencies
        .iter()
        .find(|d| d.group_id == "x" && d.artifact_id == "lib")
        .expect("dep x:lib not found");
    assert_eq!(resolved.version.as_deref(), Some("1.0"));
}

// Regression guard: a condition-activated profile also deactivates
// activeByDefault.
#[test]
fn active_by_default_suppressed_by_condition_activation() {
    let pom_xml = r"
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
      <profiles>
        <profile>
          <id>P-default</id>
          <activation>
            <activeByDefault>true</activeByDefault>
          </activation>
          <properties>
            <which>default</which>
          </properties>
        </profile>
        <profile>
          <id>P-cond</id>
          <activation>
            <property>
              <name>feature</name>
              <value>on</value>
            </property>
          </activation>
          <properties>
            <which>cond</which>
          </properties>
        </profile>
      </profiles>
    </project>
    ";

    let mut ctx = ActivationContext::default();
    ctx.properties
        .insert("feature".to_string(), "on".to_string());

    let project =
        Project::from_pom_with_context(Pom::parse(pom_xml).unwrap(), EmptyResolver, &ctx).unwrap();

    assert_eq!(
        project.properties.get("which").map(String::as_str),
        Some("cond"),
        "condition-activated profile must suppress the activeByDefault fallback"
    );
}
