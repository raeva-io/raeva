use crate::activation::Activation;
use crate::dependency::{Dependency, DependencyManagement, deserialize_dependencies};
use crate::pom::deserialize_modules;
use crate::properties::PropertyMap;
use crate::repository::{Repository, deserialize_repositories};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(default = "default_profile_id")]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<Activation>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_dependencies"
    )]
    pub dependencies: Vec<Dependency>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_management: Option<DependencyManagement>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_repositories"
    )]
    pub repositories: Vec<Repository>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_modules"
    )]
    pub modules: Vec<String>,
    #[serde(default, skip_serializing_if = "PropertyMap::is_empty")]
    pub properties: PropertyMap,
    /// Which POM in the inheritance lineage declared this profile: 0 is the
    /// current POM, 1 its parent, and so on. Not part of the XML model;
    /// `apply_inheritance` populates it when merging parent profiles so
    /// `evaluate_profiles` can scope Maven's `activeByDefault` suppression
    /// rule to each POM's own profile set.
    #[serde(skip)]
    pub origin_level: u32,
}

impl Profile {
    /// Returns whether this profile's `<activation>` block, in isolation,
    /// requests activation. Does NOT apply Maven's POM-level suppression of
    /// `activeByDefault` when other profiles activate by explicit condition;
    /// use [`crate::evaluate_profiles`] when you need the effective active
    /// set across all of a POM's profiles.
    pub fn is_active(&self, ctx: &crate::activation::ActivationContext) -> bool {
        self.activation.as_ref().is_some_and(|a| a.is_active(ctx))
    }
}

fn default_profile_id() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("__anonymous_{n}__")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profile() {
        let xml = r"
        <profile>
          <id>dev</id>
          <activation>
            <activeByDefault>true</activeByDefault>
          </activation>
          <dependencies>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>demo</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>com.example</groupId>
                <artifactId>managed</artifactId>
                <version>2.0.0</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
          <properties>
            <flag>on</flag>
          </properties>
          <modules>
            <module>module-a</module>
            <module>nested/module-b</module>
          </modules>
          <repositories>
            <repository>
              <id>central</id>
              <url>https://repo1.maven.org/maven2</url>
            </repository>
          </repositories>
        </profile>
        ";
        let profile: Profile = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(profile.id, "dev");
        assert!(profile.activation.unwrap().active_by_default);
        assert_eq!(profile.dependencies.len(), 1);
        assert_eq!(
            profile
                .dependency_management
                .as_ref()
                .map(|management| management.dependencies.len()),
            Some(1)
        );
        assert_eq!(profile.repositories.len(), 1);
        assert_eq!(profile.modules, ["module-a", "nested/module-b"]);
        assert_eq!(
            profile.properties.get("flag").map(String::as_str),
            Some("on")
        );
    }

    #[test]
    fn parses_profile_without_id() {
        let xml = r"
        <profile>
          <activation>
            <activeByDefault>false</activeByDefault>
          </activation>
          <dependencies>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>demo</artifactId>
              <version>1.0.0</version>
            </dependency>
          </dependencies>
        </profile>
        ";
        let profile: Profile = quick_xml::de::from_str(xml).unwrap();
        assert!(
            profile.id.starts_with("__anonymous_"),
            "expected anonymous profile id, got: {}",
            profile.id
        );
        assert!(!profile.activation.unwrap().active_by_default);
        assert_eq!(profile.dependencies.len(), 1);
    }
}
