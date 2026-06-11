use crate::Scope;
use serde::Deserialize;

/// A dependency exclusion pattern (groupId:artifactId).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Exclusion {
    pub group_id: String,
    pub artifact_id: String,
}

/// A Maven dependency declaration with optional scope, classifier, type, and exclusions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    pub group_id: String,
    pub artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_field"
    )]
    pub optional: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_exclusions"
    )]
    pub exclusions: Vec<Exclusion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_path: Option<String>,
}

/// The `<dependencyManagement>` section of a POM, providing version and scope defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyManagement {
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_dependencies"
    )]
    pub dependencies: Vec<Dependency>,
}

/// Deserialize the `<optional>` field which may contain a boolean literal ("true"/"false"),
/// a property reference like "${flink.markBundledAsOptional}", or any other string.
/// We store the raw string value and resolve it later via property interpolation.
fn deserialize_optional_field<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct OptionalVisitor;

    impl<'de> de::Visitor<'de> for OptionalVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or string")
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(Some(v))
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_any(OptionalVisitor)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        // quick_xml represents XML elements like <optional>true</optional> as maps
        // with a "$value" key containing the text content
        fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut value = None;
            while let Some(key) = map.next_key::<String>()? {
                if key == "$value" || key == "$text" {
                    value = Some(map.next_value::<String>()?);
                } else {
                    let _ = map.next_value::<de::IgnoredAny>()?;
                }
            }
            Ok(value)
        }
    }

    deserializer.deserialize_any(OptionalVisitor)
}

fn deserialize_exclusions<'de, D>(deserializer: D) -> Result<Vec<Exclusion>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(rename = "exclusion", default)]
        items: Vec<Exclusion>,
    }
    Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.items).unwrap_or_default())
}

pub(crate) fn deserialize_dependencies<'de, D>(deserializer: D) -> Result<Vec<Dependency>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(rename = "dependency", default)]
        items: Vec<Dependency>,
    }
    Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.items).unwrap_or_default())
}

impl Dependency {
    pub fn effective_scope(&self) -> Scope {
        match self.scope.as_deref().map(str::trim) {
            None | Some("") => Scope::default(),
            Some(s) => Scope::parse(s),
        }
    }

    /// Returns true if this dependency has import scope.
    pub fn is_import_scope(&self) -> bool {
        self.scope.as_deref().map(str::trim) == Some("import")
    }

    pub fn effective_type(&self) -> &str {
        match self.type_.as_deref() {
            Some("test-jar") => "jar",
            Some("platform") | Some("enforced-platform") => "pom",
            Some(value) if !value.is_empty() => value,
            _ => "jar",
        }
    }

    pub fn effective_classifier(&self) -> Option<&str> {
        if let Some(ref classifier) = self.classifier
            && !classifier.is_empty()
        {
            return Some(classifier.as_str());
        }
        if self.type_.as_deref() == Some("test-jar") {
            return Some("tests");
        }
        None
    }

    pub fn effective_optional(&self) -> bool {
        match self.optional.as_deref() {
            Some(value) => value.eq_ignore_ascii_case("true"),
            None => false,
        }
    }

    /// Validates a `system`-scoped dependency.
    ///
    /// Maven requires a `<systemPath>` for `<scope>system</scope>` dependencies
    /// and that the path is absolute. Without this, downstream consumers
    /// (lockfile writers, exporters) emit garbage entries with no on-disk
    /// location.
    ///
    /// Returns `Ok(())` for any dependency whose effective scope is not
    /// `system`. For system-scoped deps the function returns:
    /// - `Err` describing "missing systemPath" when `system_path` is absent or
    ///   blank.
    /// - `Err` describing "non-absolute systemPath" when the path does not
    ///   start with `/` (POSIX) or a drive letter (Windows). A path that still
    ///   contains an unresolved property reference (`${...}`) is accepted: the
    ///   caller is expected to interpolate properties first.
    pub fn validate_system_scope(&self) -> Result<(), crate::PomError> {
        if self.effective_scope() != Scope::System {
            return Ok(());
        }

        let path = match self.system_path.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => s,
            _ => {
                return Err(crate::PomError::InvalidModel(format!(
                    "system-scoped dependency {}:{} requires a non-empty <systemPath>",
                    self.group_id, self.artifact_id
                )));
            }
        };

        // Defer validation when the path still contains property references;
        // a later interpolation pass owns the absolute-path requirement.
        if path.contains("${") {
            return Ok(());
        }

        if !is_absolute_path(path) {
            return Err(crate::PomError::InvalidModel(format!(
                "system-scoped dependency {}:{} requires an absolute <systemPath> \
                 (got {:?})",
                self.group_id, self.artifact_id, path
            )));
        }

        Ok(())
    }
}

fn is_absolute_path(path: &str) -> bool {
    // A leading `/` only denotes an absolute path on Unix; on Windows
    // it's just a slash that the shell would resolve against the current
    // drive's root. Guard the rule behind cfg(unix) so a `/opt/libs/x.jar`
    // value in a POM authored on Linux is not silently accepted as
    // "absolute" by a Windows build, and conversely so a Windows-only POM
    // is not rejected on Linux just for using backslashes.
    #[cfg(unix)]
    {
        if path.starts_with('/') {
            return true;
        }
    }
    // Windows drive letter (e.g. `C:\path` or `C:/path`). Recognized on
    // every platform because POMs frequently ship paths in this form even
    // when consumed cross-platform; a Linux runner refusing the form would
    // simply mis-diagnose a Windows-authored POM, and the downstream code
    // resolves the path against a Windows local repo anyway.
    let bytes = path.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }
    // UNC paths: `\\server\share\path` (or the forward-slash form
    // `//server/share/path`). These are absolute on Windows and we accept
    // them on every platform for the same cross-platform reasons.
    if bytes.len() >= 2
        && ((bytes[0] == b'\\' && bytes[1] == b'\\') || (bytes[0] == b'/' && bytes[1] == b'/'))
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dependency() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <scope>runtime</scope>
          <optional>true</optional>
          <exclusions>
            <exclusion>
              <groupId>org.bad</groupId>
              <artifactId>bad</artifactId>
            </exclusion>
          </exclusions>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.group_id, "com.example");
        assert_eq!(dep.artifact_id, "demo");
        assert_eq!(dep.version.as_deref(), Some("1.0.0"));
        assert_eq!(dep.scope.as_deref(), Some("runtime"));
        assert_eq!(dep.optional.as_deref(), Some("true"));
        assert_eq!(dep.exclusions.len(), 1);
    }

    #[test]
    fn parses_dependency_type_and_classifier() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <type>war</type>
          <classifier>tests</classifier>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.type_.as_deref(), Some("war"));
        assert_eq!(dep.classifier.as_deref(), Some("tests"));
        assert_eq!(dep.effective_type(), "war");
    }

    #[test]
    fn parses_dependency_without_optional() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.group_id, "com.example");
        assert_eq!(dep.artifact_id, "demo");
        assert_eq!(dep.optional, None);
        assert!(dep.version.is_none());
        assert!(dep.type_.is_none());
        assert!(dep.classifier.is_none());
        assert!(dep.scope.is_none());
        assert!(dep.system_path.is_none());
    }

    #[test]
    fn parses_system_scope_with_path() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>tools</artifactId>
          <version>1.0</version>
          <scope>system</scope>
          <systemPath>${java.home}/lib/tools.jar</systemPath>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.group_id, "com.example");
        assert_eq!(dep.artifact_id, "tools");
        assert_eq!(dep.scope.as_deref(), Some("system"));
        assert_eq!(
            dep.system_path.as_deref(),
            Some("${java.home}/lib/tools.jar")
        );
    }

    #[test]
    fn test_jar_type_normalizes_to_jar() {
        let xml = r"
        <dependency>
          <groupId>org.slf4j</groupId>
          <artifactId>slf4j-api</artifactId>
          <version>2.0.17</version>
          <type>test-jar</type>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.type_.as_deref(), Some("test-jar"));
        // effective_type() should return "jar" for test-jar type
        assert_eq!(dep.effective_type(), "jar");
        // effective_classifier() should return "tests" for test-jar type
        assert_eq!(dep.effective_classifier(), Some("tests"));
    }

    #[test]
    fn test_jar_type_with_explicit_classifier() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <type>test-jar</type>
          <classifier>custom</classifier>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.type_.as_deref(), Some("test-jar"));
        assert_eq!(dep.classifier.as_deref(), Some("custom"));
        // effective_type() should still return "jar"
        assert_eq!(dep.effective_type(), "jar");
        // explicit classifier takes precedence over test-jar implied classifier
        assert_eq!(dep.effective_classifier(), Some("custom"));
    }

    #[test]
    fn effective_classifier_returns_none_for_regular_jar() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.effective_type(), "jar");
        assert_eq!(dep.effective_classifier(), None);
    }

    #[test]
    fn effective_classifier_returns_explicit_classifier() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <classifier>sources</classifier>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.effective_type(), "jar");
        assert_eq!(dep.effective_classifier(), Some("sources"));
    }

    #[test]
    fn parses_optional_property_reference() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <optional>${flink.markBundledAsOptional}</optional>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(
            dep.optional.as_deref(),
            Some("${flink.markBundledAsOptional}")
        );
        // Before property resolution, a property reference is not "true"
        assert!(!dep.effective_optional());
    }

    #[test]
    fn parses_optional_false_string() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <optional>false</optional>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(dep.optional.as_deref(), Some("false"));
        assert!(!dep.effective_optional());
    }

    #[test]
    fn validate_system_scope_rejects_missing_path() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>tools</artifactId>
          <version>1.0</version>
          <scope>system</scope>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        let err = dep
            .validate_system_scope()
            .expect_err("missing systemPath should fail validation");
        match err {
            crate::PomError::InvalidModel(msg) => {
                assert!(msg.contains("non-empty"), "msg = {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn validate_system_scope_rejects_blank_path() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>tools</artifactId>
          <version>1.0</version>
          <scope>system</scope>
          <systemPath>   </systemPath>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert!(dep.validate_system_scope().is_err());
    }

    #[test]
    fn validate_system_scope_rejects_relative_path() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>tools</artifactId>
          <version>1.0</version>
          <scope>system</scope>
          <systemPath>lib/tools.jar</systemPath>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        let err = dep
            .validate_system_scope()
            .expect_err("relative systemPath should fail validation");
        match err {
            crate::PomError::InvalidModel(msg) => {
                assert!(msg.contains("absolute"), "msg = {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn validate_system_scope_accepts_absolute_posix_path() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>tools</artifactId>
          <version>1.0</version>
          <scope>system</scope>
          <systemPath>/opt/lib/tools.jar</systemPath>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        dep.validate_system_scope()
            .expect("system-scope validation should accept");
    }

    #[test]
    fn validate_system_scope_accepts_absolute_windows_path() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>tools</artifactId>
          <version>1.0</version>
          <scope>system</scope>
          <systemPath>C:\lib\tools.jar</systemPath>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        dep.validate_system_scope()
            .expect("system-scope validation should accept");
    }

    /// UNC paths (`\\server\share\...`) are absolute on Windows and the only
    /// way to reach a network share without a drive letter, so
    /// `is_absolute_path` must accept them.
    #[test]
    fn validate_system_scope_accepts_unc_path() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>tools</artifactId>
          <version>1.0</version>
          <scope>system</scope>
          <systemPath>\\fileserver\share\lib\tools.jar</systemPath>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        dep.validate_system_scope()
            .expect("system-scope validation should accept");
    }

    /// The forward-slash UNC form `//server/share/...` is also produced by
    /// tools that normalize Windows paths and must be accepted.
    #[test]
    fn validate_system_scope_accepts_forward_slash_unc_path() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>tools</artifactId>
          <version>1.0</version>
          <scope>system</scope>
          <systemPath>//fileserver/share/lib/tools.jar</systemPath>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        dep.validate_system_scope()
            .expect("system-scope validation should accept");
    }

    /// A leading `/` only means "absolute" on Unix. On Windows it is not,
    /// and accepting it there would mis-route the artifact resolution
    /// against the current drive. Run the platform-gated branch directly.
    #[test]
    #[cfg(windows)]
    fn is_absolute_path_rejects_unix_root_on_windows() {
        assert!(!super::is_absolute_path("/opt/lib/tools.jar"));
    }

    #[test]
    #[cfg(unix)]
    fn is_absolute_path_accepts_unix_root_on_unix() {
        assert!(super::is_absolute_path("/opt/lib/tools.jar"));
    }

    #[test]
    fn validate_system_scope_defers_on_unresolved_property() {
        // When the systemPath still contains a property reference the caller
        // is expected to run property interpolation first; validation should
        // accept the dep at this stage rather than crashing.
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>tools</artifactId>
          <version>1.0</version>
          <scope>system</scope>
          <systemPath>${java.home}/lib/tools.jar</systemPath>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        dep.validate_system_scope()
            .expect("system-scope validation should accept");
    }

    #[test]
    fn validate_system_scope_is_noop_for_non_system_dep() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>tools</artifactId>
          <version>1.0</version>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        dep.validate_system_scope()
            .expect("system-scope validation should accept");
    }

    #[test]
    fn parses_optional_true_case_insensitive() {
        let xml = r"
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0.0</version>
          <optional>True</optional>
        </dependency>
        ";
        let dep: Dependency = quick_xml::de::from_str(xml).unwrap();
        assert!(dep.effective_optional());
    }
}
