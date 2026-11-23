use crate::Scope;
use rv_maven_types::{MavenMode, bounded, quoted};

use crate::ArtifactTypes;

/// The core artifact handlers of Maven 3.9.
static CORE_39: std::sync::LazyLock<ArtifactTypes> =
    std::sync::LazyLock::new(|| ArtifactTypes::core(MavenMode::Maven39));

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
    /// Whether `system_path` was written to start at a directory of the
    /// project. Equality ignores it.
    #[serde(skip)]
    pub system_path_from_project: ProjectDirectory,
    /// For a project's managed entry, and a dependency whose version one
    /// supplied, where the version comes from. Equality ignores it.
    #[serde(skip)]
    pub origin: ManagedOrigin,
}

/// Whether a [`Dependency`]'s `<systemPath>` was written to start at a
/// directory of the project, such as `${project.basedir}`, which Maven
/// holds as an absolute path on every OS. A path that merely reads the
/// same was written for one OS. Set when the dependency is interpolated,
/// and never part of its equality.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProjectDirectory(pub bool);

impl PartialEq for ProjectDirectory {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for ProjectDirectory {}

/// Where a managed version comes from, carried with a [`Dependency`] but
/// never part of its equality: two declarations alike are alike wherever
/// management declares them.
#[derive(Clone, Default)]
pub struct ManagedOrigin(pub Option<std::sync::Arc<rv_maven_types::ManagedSource>>);

impl PartialEq for ManagedOrigin {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for ManagedOrigin {}

impl std::fmt::Debug for ManagedOrigin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
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
    /// The parsed `<scope>`: [`Scope::Compile`] when absent or empty. Maven
    /// keeps a scope it does not know, such as an unresolved property, a
    /// case other than lowercase, the `optional` some POMs write or
    /// `foo:bar`, and so does this ([`Scope::Other`]), also when raeva.lock
    /// cannot record it ([`Scope::recordable`]). The reader trimmed the
    /// POM's text, and Maven trims no interpolated value, so ` compile `
    /// from a property is a scope Maven does not know.
    pub fn effective_scope(&self) -> Scope {
        match self.scope.as_deref() {
            None | Some("") => Scope::default(),
            Some(text) => Scope::declared(text),
        }
    }

    /// Whether `<scope>` is `system` as Maven's validator compares it, case
    /// included.
    pub fn declares_system_scope(&self) -> bool {
        self.scope.as_deref() == Some("system")
    }

    pub(crate) fn is_import_scope(&self) -> bool {
        self.scope.as_deref() == Some("import")
    }

    /// The file extension of the artifact `<type>` names, from Maven 3.9's
    /// core artifact handlers: `ejb`, `ejb-client`, `test-jar`,
    /// `maven-plugin`, `java-source` and `javadoc` are jars. Any other type
    /// is its own extension.
    pub fn effective_type(&self) -> &str {
        self.effective_type_in(&CORE_39)
    }

    /// [`Self::effective_type`] with the artifact handlers `types` holds:
    /// Maven 3.10's `fatjar` is a jar, and a build extension defines its own.
    pub fn effective_type_in<'a>(&'a self, types: &'a ArtifactTypes) -> &'a str {
        match self.type_.as_deref() {
            Some(value) if !value.is_empty() => types.extension(value),
            _ => "jar",
        }
    }

    /// The declared classifier, or the one Maven 3.9's core artifact
    /// handler for the `<type>` implies when none is declared: an empty one
    /// names the main artifact, as in Aether's `DefaultArtifact`.
    pub fn effective_classifier(&self) -> Option<&str> {
        self.effective_classifier_in(&CORE_39)
    }

    /// [`Self::effective_classifier`] with the artifact handlers `types`
    /// holds.
    pub fn effective_classifier_in<'a>(&'a self, types: &'a ArtifactTypes) -> Option<&'a str> {
        match self.classifier.as_deref() {
            Some(classifier) => (!classifier.is_empty()).then_some(classifier),
            None => types.classifier(self.type_.as_deref()?),
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

    /// The key Maven merges, imports and injects managed entries by: unlike
    /// [`Self::management_key`], an empty `<classifier>` is apart from none.
    pub(crate) fn maven_key(&self) -> (&str, &str, &str, Option<&str>) {
        let (group_id, artifact_id, type_, _) = self.management_key();
        (group_id, artifact_id, type_, self.classifier.as_deref())
    }

    /// [`Self::maven_key`] with owned strings.
    pub(crate) fn raw_key(&self) -> (String, String, String, Option<String>) {
        let (group_id, artifact_id, type_, _) = self.owned_management_key();
        (group_id, artifact_id, type_, self.classifier.clone())
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
    /// collect them: the `war`, `ear` and `rar` handlers say so, Maven
    /// 3.10's `fatjar` too, and a build extension's handler may.
    pub fn includes_dependencies_in(&self, types: &ArtifactTypes) -> bool {
        self.type_
            .as_deref()
            .is_some_and(|type_| types.includes_dependencies(type_))
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

    /// Maven's message for a missing `field` of this dependency, a full
    /// path such as a plugin dependency's.
    pub(crate) fn missing_message(&self, field: &str) -> String {
        self.problem(field, "is missing")
    }

    fn invalid(&self, managed: bool, field: &str, problem: &str) -> crate::PomError {
        let prefix = if managed { "dependencyManagement." } else { "" };
        crate::PomError::InvalidModel(
            self.problem(&format!("{prefix}dependencies.dependency.{field}"), problem),
        )
    }

    /// Maven's problem with the `<systemPath>` of this effective plugin
    /// dependency, `prefix` the path of its fields. A path raeva could not
    /// fully interpolate is not judged, as Maven may expand it to another
    /// or to none.
    pub(crate) fn plugin_system_path_problem(
        &self,
        prefix: &str,
        environment: &crate::ModelEnvironment,
    ) -> Option<String> {
        let field = format!("{prefix}.systemPath");
        let path = self.system_path.as_deref().filter(|path| !path.is_empty());
        match (self.declares_system_scope(), path) {
            (true, None) => Some(self.problem(&field, "is missing")),
            (true, Some(path))
                if !path.contains("${") && !self.absolute_system_path(path, environment) =>
            {
                let mut message = self.problem(
                    &field,
                    &format!("must specify an absolute path but is {path}"),
                );
                // Maven ends this one without a period.
                message.pop();
                Some(message + &on_platform(environment))
            }
            (false, Some(path)) if !path.contains("${") => Some(self.problem(
                &field,
                "must be omitted. This field may only be specified for a dependency with \
                 system scope",
            )),
            _ => None,
        }
    }

    /// Maven's message for a `problem` with `field` of this dependency, a
    /// full path.
    pub(crate) fn problem(&self, field: &str, problem: &str) -> String {
        let (group_id, artifact_id, type_, classifier) = self.management_key();
        let classifier = classifier
            .map(|c| format!(":{}", bounded(c)))
            .unwrap_or_default();
        format!(
            "'{}' for {}:{}:{}{classifier} {problem}.",
            bounded(field),
            bounded(group_id),
            bounded(artifact_id),
            bounded(type_),
        )
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
    /// - `Err` describing "non-absolute systemPath" when `java.io.File`
    ///   does not take the path for absolute on the platform of
    ///   `environment`. A path that still names a `java.*`, `user.*` or
    ///   `env.*` value after interpolation is accepted: Maven has a value
    ///   for it.
    pub(crate) fn validate_system_scope(
        &self,
        environment: &crate::ModelEnvironment,
    ) -> Result<(), crate::PomError> {
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
                    let name = rv_maven_types::expression_key(name);
                    ["java.", "user.", "env."]
                        .iter()
                        .any(|prefix| name.starts_with(prefix))
                })
            })
        {
            return Ok(());
        }

        if !self.absolute_system_path(path, environment) {
            return Err(crate::PomError::InvalidSystemPath(format!(
                "system-scoped dependency {}:{} requires an absolute <systemPath> \
                 (got {}){}",
                bounded(&self.group_id),
                bounded(&self.artifact_id),
                quoted(path),
                on_platform(environment)
            )));
        }

        Ok(())
    }

    /// Whether Maven takes `path`, this dependency's interpolated
    /// `<systemPath>`, for absolute on the platform `environment` locks. A
    /// path written to start at a directory of the project, such as
    /// `${project.basedir}/lib/x.jar`, is: raeva expands it to the host's
    /// directory, and Maven to its own, absolute on every OS. Any other
    /// path is judged by [`absolute_on`], also when it reads as a path in
    /// the project on the host, since it was then written for the host's
    /// OS.
    fn absolute_system_path(&self, path: &str, environment: &crate::ModelEnvironment) -> bool {
        self.system_path_from_project.0 || absolute_on(path, environment)
    }
}

/// Whether Maven takes `path` for absolute as `java.io.File` does on the
/// OS of the platform `environment` locks: on Windows by [`windows_absolute`],
/// elsewhere by a leading `/`. Without a platform, either rule will do.
fn absolute_on(path: &str, environment: &crate::ModelEnvironment) -> bool {
    match environment.platform() {
        Some(("windows", _)) => windows_absolute(path),
        Some(_) => path.starts_with('/'),
        None => windows_absolute(path) || path.starts_with('/'),
    }
}

/// `, for the locked platform os-arch`, or nothing without a platform.
fn on_platform(environment: &crate::ModelEnvironment) -> String {
    (environment.platform())
        .map(|(os, arch)| format!(", for the locked platform {os}-{arch}"))
        .unwrap_or_default()
}

/// `java.io.File.isAbsolute` on Windows (WinNTFileSystem): slashes before a
/// drive go, two or more lead a UNC path, and a drive is absolute only with
/// a slash after it.
fn windows_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    let slash = |byte: &u8| matches!(byte, b'/' | b'\\');
    let slashes = bytes.iter().take_while(|byte| slash(byte)).count();
    match &bytes[slashes..] {
        [drive, b':', rest @ ..] if drive.is_ascii_alphabetic() => rest.first().is_some_and(slash),
        _ => slashes >= 2,
    }
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
    fn an_unknown_scope_is_kept() {
        for (scope, effective) in [
            ("", Scope::Compile),
            // The reader trims the POM's text; a value interpolated into it
            // keeps its spaces, as in Maven.
            (" runtime ", Scope::Other(" runtime ")),
            ("weird", Scope::Other("weird")),
            ("compile-only", Scope::CompileOnly),
            // Maven compares scopes with their case, so `SYSTEM` is unknown.
            ("SYSTEM", Scope::Other("SYSTEM")),
            // Some POMs write the invalid <scope>optional</scope>.
            ("optional", Scope::Other("optional")),
            // Kept, though raeva.lock cannot record it.
            ("two words", Scope::Other("two words")),
            ("foo:bar", Scope::Other("foo:bar")),
            ("\u{a0}runtime", Scope::Other("\u{a0}runtime")),
        ] {
            let dep = dependency(&format!("<scope>{scope}</scope>"));
            assert_eq!(dep.effective_scope(), effective, "{scope:?}");
        }
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
                dep.includes_dependencies_in(&ArtifactTypes::core(MavenMode::Maven39)),
                includes_dependencies,
                "{type_}"
            );
        }
    }

    /// A system dependency needs an absolute path: a drive or UNC path in
    /// either slash form on Windows, a `/` path elsewhere, and either
    /// without a platform. A path may keep a JDK, user or environment value
    /// raeva does not know, and nothing else.
    #[test]
    fn a_system_dependency_needs_an_absolute_path() {
        let unknown = crate::ModelEnvironment::builder().build();
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
            match (dep.validate_system_scope(&unknown), error) {
                (Ok(()), None) => {}
                (Err(crate::PomError::InvalidSystemPath(message)), Some(expected)) => {
                    assert!(message.contains(expected), "{path}: {message}");
                }
                (result, _) => panic!("{path}: {result:?}"),
            }
        }
        dependency("").validate_system_scope(&unknown).unwrap();
        for (os, path, absolute) in [
            ("windows", "C:/lib/x.jar", true),
            ("windows", "/opt/x.jar", false),
            ("linux", "/opt/x.jar", true),
            ("linux", "C:/lib/x.jar", false),
            ("linux", "\\\\server\\share\\x.jar", false),
            ("macos", "/opt/x.jar", true),
            ("macos", "C:\\lib\\x.jar", false),
        ] {
            let environment = crate::ModelEnvironment::builder()
                .platform(os, "x86_64")
                .build();
            let dep = dependency(&format!(
                "<scope>system</scope><systemPath>{path}</systemPath>"
            ));
            let result = dep.validate_system_scope(&environment);
            assert_eq!(result.is_ok(), absolute, "{os} {path}");
            if let Err(error) = result {
                let platform = format!("for the locked platform {os}-x86_64");
                assert!(error.to_string().contains(&platform), "{error}");
            }
        }
        for (path, absolute) in [
            ("C:\\lib\\x.jar", true),
            ("C:/lib/x.jar", true),
            ("/C:/lib/x.jar", true),
            ("C:lib/x.jar", false),
            ("//C:lib/x.jar", false),
            ("\\\\server\\share\\x.jar", true),
            ("///server/share/x.jar", true),
            ("/opt/x.jar", false),
            ("lib/x.jar", false),
        ] {
            assert_eq!(windows_absolute(path), absolute, "{path}");
        }
    }
}
