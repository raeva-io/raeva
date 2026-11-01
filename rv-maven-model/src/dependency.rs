use crate::Scope;
use rv_maven_types::{bounded, quoted};

/// A dependency exclusion pattern (groupId:artifactId).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Exclusion {
    /// The excluded `groupId`, as written, empty when absent.
    #[serde(default)]
    pub group_id: String,
    /// An empty `artifactId` excludes nothing, as in Maven.
    #[serde(default)]
    pub artifact_id: String,
}

/// A Maven dependency declaration with optional scope, classifier, type, and exclusions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    /// The `<groupId>`, empty when absent, which the effective model refuses.
    #[serde(default)]
    pub group_id: String,
    /// The `<artifactId>`, empty when absent, which the effective model
    /// refuses.
    #[serde(default)]
    pub artifact_id: String,
    /// The `<version>`, a version or a range. `None` when dependency
    /// management is to supply it.
    pub version: Option<String>,
    /// The `<type>` as written; [`Self::effective_type`] maps it to a file
    /// extension.
    #[serde(rename = "type", default)]
    pub type_: Option<String>,
    /// The `<classifier>` as written; [`Self::effective_classifier`] adds
    /// the one a `<type>` implies.
    pub classifier: Option<String>,
    /// The `<scope>` as written; [`Self::effective_scope`] parses it.
    pub scope: Option<String>,
    /// The `<optional>` text, kept as a string so a property reference can
    /// be interpolated first; [`Self::effective_optional`] reads it.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub optional: Option<String>,
    /// The `<exclusions>`, in declaration order.
    #[serde(default, deserialize_with = "deserialize_exclusions")]
    pub exclusions: Vec<Exclusion>,
    /// The `<systemPath>` of a `system`-scoped dependency.
    pub system_path: Option<String>,
}

/// The `<dependencyManagement>` section of a POM, providing version and scope defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct DependencyManagement {
    /// The managed dependencies in declaration order. As parsed, these
    /// include the `import`-scoped BOM entries.
    #[serde(default, deserialize_with = "deserialize_dependencies")]
    pub dependencies: Vec<Dependency>,
}

/// `<optional>` may be a boolean, a `${property}`, or any other string; kept raw until interpolation.
fn deserialize_optional_field<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct OptionalVisitor;

    impl<'de> de::Visitor<'de> for OptionalVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

element_list!(fn deserialize_exclusions, "exclusion", Exclusion);
element_list!(pub(crate) fn deserialize_dependencies, "dependency", Dependency);

impl Dependency {
    /// The parsed `<scope>`: [`Scope::Compile`] when absent or blank, and
    /// compile with a warning when unknown (see [`Scope::parse`]).
    pub fn effective_scope(&self) -> Scope {
        match self.scope.as_deref().map(str::trim) {
            None | Some("") => Scope::default(),
            Some(s) => Scope::parse(s),
        }
    }

    /// Whether `<scope>` is `system` as Maven's validator compares it, case
    /// included.
    fn declares_system_scope(&self) -> bool {
        self.scope.as_deref().map(str::trim) == Some("system")
    }

    pub(crate) fn is_import_scope(&self) -> bool {
        self.scope.as_deref().map(str::trim) == Some("import")
    }

    /// The file extension of the artifact `<type>` names, from Maven 3.9's
    /// artifact handlers: `ejb`, `ejb-client`, `test-jar`, `maven-plugin`,
    /// `java-source` and `javadoc` are jars. Any other type is its own
    /// extension.
    pub fn effective_type(&self) -> &str {
        match self.type_.as_deref() {
            Some(
                "test-jar" | "maven-plugin" | "ejb" | "ejb-client" | "java-source" | "javadoc",
            ) => "jar",
            Some(value) if !value.is_empty() => value,
            _ => "jar",
        }
    }

    /// The declared classifier, or the one Maven's artifact handler for the
    /// `<type>` implies.
    pub fn effective_classifier(&self) -> Option<&str> {
        if let Some(ref classifier) = self.classifier
            && !classifier.is_empty()
        {
            return Some(classifier.as_str());
        }
        match self.type_.as_deref() {
            Some("test-jar") => Some("tests"),
            Some("ejb-client") => Some("client"),
            Some("java-source") => Some("sources"),
            Some("javadoc") => Some("javadoc"),
            _ => None,
        }
    }

    /// Maven's management key `groupId:artifactId:type[:classifier]`, with
    /// the type and classifier as declared. Inheritance, dependency
    /// management and duplicate detection in the model use it, so
    /// `<type>test-jar</type>` and `<classifier>tests</classifier>` stay
    /// apart there although they name the same file, and so do `<type/>`
    /// and an absent type.
    pub(crate) fn management_key(&self) -> (&str, &str, &str, Option<&str>) {
        let type_ = self.type_.as_deref().unwrap_or("jar");
        let classifier = self.classifier.as_deref().filter(|value| !value.is_empty());
        (&self.group_id, &self.artifact_id, type_, classifier)
    }

    /// [`Self::management_key`] with owned strings, for merge maps that need
    /// owned keys.
    pub(crate) fn owned_management_key(&self) -> (String, String, String, Option<String>) {
        let (group_id, artifact_id, type_, classifier) = self.management_key();
        (
            group_id.to_owned(),
            artifact_id.to_owned(),
            type_.to_owned(),
            classifier.map(str::to_owned),
        )
    }

    /// Whether the artifact bundles its own dependencies, so Maven does not
    /// collect them: the `war`, `ear` and `rar` handlers say so.
    pub fn includes_dependencies(&self) -> bool {
        matches!(self.type_.as_deref(), Some("war" | "ear" | "rar"))
    }

    /// Whether `<optional>` is `true` in any case. Anything else, including
    /// an uninterpolated property, is `false`.
    pub fn effective_optional(&self) -> bool {
        match self.optional.as_deref() {
            Some(value) => value.eq_ignore_ascii_case("true"),
            None => false,
        }
    }

    /// Whether resolution follows this dependency when a dependency's POM
    /// declares it, by the values that POM gives it before the project's
    /// management applies: Maven's selectors drop an optional one and one
    /// in `test` or `provided` scope.
    pub fn is_followed_transitively(&self) -> bool {
        !self.effective_optional()
            && !matches!(self.effective_scope(), Scope::Test | Scope::Provided)
    }

    /// Maven's `DefaultModelValidator` check of an effective dependency or
    /// managed dependency: its `groupId` and `artifactId` are ids, a
    /// `<type>` a dependency outside management declares is not empty, and
    /// only a `system` one has a `<systemPath>`.
    pub(crate) fn validate_coordinates(&self, managed: bool) -> Result<(), crate::PomError> {
        let type_ = match managed {
            true => "jar",
            false => self.type_.as_deref().unwrap_or("jar"),
        };
        for (field, value) in [
            ("artifactId", self.artifact_id.as_str()),
            ("groupId", self.group_id.as_str()),
            ("type", type_),
        ] {
            if value.is_empty() {
                return Err(self.missing(managed, field));
            }
            if field != "type" && !rv_maven_types::is_maven_id_text(value) {
                return Err(self.invalid(
                    managed,
                    field,
                    &format!(
                        "with value '{}' does not match a valid id pattern",
                        bounded(value)
                    ),
                ));
            }
        }
        if !self.declares_system_scope()
            && self
                .system_path
                .as_deref()
                .is_some_and(|path| !path.is_empty())
        {
            return Err(self.invalid(
                managed,
                "systemPath",
                "must be omitted. This field may only be specified for a dependency with \
                 system scope",
            ));
        }
        Ok(())
    }

    /// Maven's message for a missing `field` of this dependency.
    pub(crate) fn missing(&self, managed: bool, field: &str) -> crate::PomError {
        self.invalid(managed, field, "is missing")
    }

    fn invalid(&self, managed: bool, field: &str, problem: &str) -> crate::PomError {
        let (group_id, artifact_id, type_, classifier) = self.management_key();
        let classifier = classifier
            .map(|c| format!(":{}", bounded(c)))
            .unwrap_or_default();
        crate::PomError::InvalidModel(format!(
            "'{}dependencies.dependency.{field}' for {}:{}:{}{classifier} {problem}.",
            if managed { "dependencyManagement." } else { "" },
            bounded(group_id),
            bounded(artifact_id),
            bounded(type_),
        ))
    }

    /// Validates a `system`-scoped dependency.
    ///
    /// Maven requires a `<systemPath>` for `<scope>system</scope>` dependencies
    /// and that the path is absolute. Without this, downstream consumers
    /// (lockfile writers, exporters) emit garbage entries with no on-disk
    /// location.
    ///
    /// Returns `Ok(())` for any dependency whose scope is not exactly
    /// `system`. For system-scoped deps the function returns:
    /// - `Err` describing "missing systemPath" when `system_path` is absent or
    ///   blank.
    /// - `Err` describing "non-absolute systemPath" when the path does not
    ///   start with `/` (POSIX) or a drive letter (Windows). A path that
    ///   still names a `java.*`, `user.*` or `env.*` value after
    ///   interpolation is accepted: Maven has a value for it.
    pub(crate) fn validate_system_scope(&self) -> Result<(), crate::PomError> {
        if !self.declares_system_scope() {
            return Ok(());
        }

        let path = match self.system_path.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => s,
            _ => {
                return Err(crate::PomError::InvalidSystemPath(format!(
                    "system-scoped dependency {}:{} requires a non-empty <systemPath>",
                    bounded(&self.group_id),
                    bounded(&self.artifact_id)
                )));
            }
        };

        // Maven checks the interpolated path, where a JDK, user or
        // environment value raeva does not know is always expanded. A path
        // whose remaining `${...}` names only `java.*`, `user.*` or `env.*`
        // is accepted.
        if path.contains("${")
            && path.split("${").skip(1).all(|rest| {
                rest.split_once('}').is_some_and(|(name, _)| {
                    ["java.", "user.", "env."]
                        .iter()
                        .any(|prefix| name.starts_with(prefix))
                })
            })
        {
            return Ok(());
        }

        if !is_absolute_path(path) {
            return Err(crate::PomError::InvalidSystemPath(format!(
                "system-scoped dependency {}:{} requires an absolute <systemPath> \
                 (got {})",
                bounded(&self.group_id),
                bounded(&self.artifact_id),
                quoted(path)
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

    fn dependency(fields: &str) -> Dependency {
        quick_xml::de::from_str(&format!(
            "<dependency><groupId>com.example</groupId><artifactId>demo</artifactId>\
             {fields}</dependency>"
        ))
        .unwrap()
    }

    #[test]
    fn parses_a_dependency_as_written() {
        let dep = dependency(
            "<version>1.0.0</version><scope>runtime</scope><optional>${bundled}</optional>\
             <systemPath>${java.home}/lib/tools.jar</systemPath><exclusions><exclusion>\
             <groupId>org.bad</groupId><artifactId>bad</artifactId></exclusion></exclusions>",
        );
        assert_eq!(
            (dep.group_id.as_str(), dep.artifact_id.as_str()),
            ("com.example", "demo")
        );
        assert_eq!(dep.version.as_deref(), Some("1.0.0"));
        assert_eq!(dep.scope.as_deref(), Some("runtime"));
        assert_eq!(dep.optional.as_deref(), Some("${bundled}"));
        assert_eq!(
            dep.system_path.as_deref(),
            Some("${java.home}/lib/tools.jar")
        );
        assert_eq!(dep.exclusions.len(), 1);
        let bare = dependency("");
        assert!(bare.version.is_none() && bare.type_.is_none() && bare.optional.is_none());
        // Before interpolation, a property reference is not "true".
        for (optional, effective) in [("${bundled}", false), ("false", false), ("True", true)] {
            let dep = dependency(&format!("<optional>{optional}</optional>"));
            assert_eq!(dep.effective_optional(), effective, "{optional}");
        }
    }

    #[test]
    fn types_map_to_maven_artifact_handlers() {
        for (type_, classifier, extension, effective, includes_dependencies) in [
            ("", "", "jar", None, false),
            (
                "",
                "<classifier>sources</classifier>",
                "jar",
                Some("sources"),
                false,
            ),
            ("<type>jar</type>", "", "jar", None, false),
            ("<type>pom</type>", "", "pom", None, false),
            ("<type>ejb</type>", "", "jar", None, false),
            ("<type>ejb-client</type>", "", "jar", Some("client"), false),
            ("<type>test-jar</type>", "", "jar", Some("tests"), false),
            (
                "<type>test-jar</type>",
                "<classifier>custom</classifier>",
                "jar",
                Some("custom"),
                false,
            ),
            ("<type>maven-plugin</type>", "", "jar", None, false),
            (
                "<type>java-source</type>",
                "",
                "jar",
                Some("sources"),
                false,
            ),
            ("<type>javadoc</type>", "", "jar", Some("javadoc"), false),
            (
                "<type>war</type>",
                "<classifier>tests</classifier>",
                "war",
                Some("tests"),
                true,
            ),
            ("<type>ear</type>", "", "ear", None, true),
            ("<type>rar</type>", "", "rar", None, true),
            ("<type>zip</type>", "", "zip", None, false),
        ] {
            let dep = dependency(&format!("{type_}{classifier}"));
            assert_eq!(dep.effective_type(), extension, "{type_}{classifier}");
            assert_eq!(dep.effective_classifier(), effective, "{type_}{classifier}");
            assert_eq!(
                dep.includes_dependencies(),
                includes_dependencies,
                "{type_}"
            );
        }
    }

    /// A system dependency needs an absolute path: a drive or UNC path in
    /// either slash form, or a `/` path on Unix only, where it would
    /// otherwise resolve against the current drive. A path may keep a JDK,
    /// user or environment value raeva does not know, and nothing else.
    #[test]
    fn a_system_dependency_needs_an_absolute_path() {
        for (path, error) in [
            ("", Some("non-empty")),
            ("<systemPath>   </systemPath>", Some("non-empty")),
            ("<systemPath>lib/tools.jar</systemPath>", Some("absolute")),
            ("<systemPath>C:\\lib\\tools.jar</systemPath>", None),
            (
                "<systemPath>\\\\fileserver\\share\\tools.jar</systemPath>",
                None,
            ),
            (
                "<systemPath>//fileserver/share/tools.jar</systemPath>",
                None,
            ),
            ("<systemPath>${java.home}/lib/tools.jar</systemPath>", None),
            ("<systemPath>${env.TOOLS}/tools.jar</systemPath>", None),
            (
                "<systemPath>${missing}/x.jar</systemPath>",
                Some("absolute"),
            ),
            (
                "<systemPath>${java.home}/${missing}/x.jar</systemPath>",
                Some("absolute"),
            ),
        ] {
            let dep = dependency(&format!("<scope>system</scope>{path}"));
            match (dep.validate_system_scope(), error) {
                (Ok(()), None) => {}
                (Err(crate::PomError::InvalidSystemPath(message)), Some(expected)) => {
                    assert!(message.contains(expected), "{path}: {message}");
                }
                (result, _) => panic!("{path}: {result:?}"),
            }
        }
        dependency("").validate_system_scope().unwrap();
        assert_eq!(is_absolute_path("/opt/lib/tools.jar"), cfg!(unix));
    }
}
