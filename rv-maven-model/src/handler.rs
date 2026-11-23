//! Maven's artifact handlers: what a dependency `<type>` means for the file
//! resolved (its extension and implied classifier) and for the collection
//! (whether its dependencies are walked). Maven 3.9.12 defines the core ones
//! in maven-core's `artifact-handlers.xml`; a build extension adds its own
//! as `org.apache.maven.artifact.handler.ArtifactHandler` components, in
//! `META-INF/plexus/components.xml` or as Sisu `@Named` classes listed in
//! `META-INF/sisu/javax.inject.Named`.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, OnceLock};

use rv_maven_types::MavenMode;

use crate::PomError;

mod class_file;

/// What a type means to the resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactHandler {
    /// The file extension.
    pub extension: String,
    /// The classifier a dependency of the type takes when it declares none.
    pub classifier: Option<String>,
    /// Whether the file carries its dependencies, so the collector does not
    /// walk them (`FatArtifactTraverser`).
    pub includes_dependencies: bool,
    /// Whether the file joins the class paths a build gives its plugins.
    /// Collection does not read it.
    pub added_to_classpath: bool,
}

impl ArtifactHandler {
    /// What Maven's resolver makes of a file it is given by extension
    /// alone, with no type: no classifier, its dependencies walked.
    pub fn plain(extension: &str) -> Self {
        Self {
            extension: extension.to_string(),
            classifier: None,
            includes_dependencies: false,
            added_to_classpath: true,
        }
    }
}

/// Maven 3.9.12's core handlers: type, extension, classifier,
/// `includesDependencies` and `addedToClasspath`.
type CoreHandler = (&'static str, &'static str, Option<&'static str>, bool, bool);

const CORE: &[CoreHandler] = &[
    ("pom", "pom", None, false, false),
    ("jar", "jar", None, false, true),
    ("ejb", "jar", None, false, true),
    ("ejb-client", "jar", Some("client"), false, true),
    ("test-jar", "jar", Some("tests"), false, true),
    ("maven-plugin", "jar", None, false, true),
    ("java-source", "jar", Some("sources"), false, false),
    ("javadoc", "jar", Some("javadoc"), false, true),
    ("war", "war", None, true, false),
    ("ear", "ear", None, true, false),
    ("rar", "rar", None, true, false),
];

/// The handler Maven 3.10 adds.
const FATJAR: CoreHandler = ("fatjar", "jar", None, true, true);

fn core_handler(type_: &str, mode: MavenMode) -> Option<&'static CoreHandler> {
    match type_ {
        "fatjar" => (mode == MavenMode::Maven310).then_some(&FATJAR),
        _ => CORE.iter().find(|handler| handler.0 == type_),
    }
}

/// Whether the core of `mode` defines `type_`, so no extension is asked
/// for it.
pub fn is_core_type(type_: &str, mode: MavenMode) -> bool {
    core_handler(type_, mode).is_some()
}

/// A type an extension defines and its handler, or why raeva cannot read
/// the handler.
pub type DefinedType = (String, Result<ArtifactHandler, String>);

/// The class files the jars of an extension's realm hold at one entry, in
/// the realm's order: one for each content, with the coordinates of the
/// first jar that holds it.
pub type ClassFiles = Vec<(String, Vec<u8>)>;

/// The extensions' handlers by type.
type Handlers = BTreeMap<String, Result<ArtifactHandler, String>>;

/// The handlers one module's resolution reads: the core ones of its Maven
/// line, then those its build extensions define for other types. A type
/// neither defines is its own extension, as Maven's default handler has
/// it. Cheap to clone; a clone sees the handlers [`Self::define`] adds.
#[derive(Debug, Clone, Default)]
pub struct ArtifactTypes {
    mode: MavenMode,
    extensions: Option<Arc<OnceLock<Handlers>>>,
}

impl ArtifactTypes {
    /// The core handlers of `mode`.
    pub fn core(mode: MavenMode) -> Self {
        Self {
            mode,
            extensions: None,
        }
    }

    /// The core handlers of `mode` until [`Self::define`] adds the
    /// extensions'.
    pub fn pending(mode: MavenMode) -> Self {
        Self {
            mode,
            extensions: Some(Arc::default()),
        }
    }

    /// Add `extensions`, once, for this value and its clones. The first
    /// definition of a type counts, as Maven imports the extension realms
    /// in order. A core type keeps its core handler. One an extension
    /// defines otherwise is unreadable, as Maven takes the extension's for
    /// a type no project of the build looked up before.
    pub fn define(&self, extensions: impl IntoIterator<Item = DefinedType>) {
        let Some(cell) = &self.extensions else {
            return;
        };
        let mut map = BTreeMap::new();
        for (type_, handler) in extensions {
            let Some(&(_, extension, classifier, includes, added)) =
                core_handler(&type_, self.mode)
            else {
                map.entry(type_).or_insert(handler);
                continue;
            };
            let core = ArtifactHandler {
                extension: extension.to_string(),
                classifier: classifier.map(str::to_string),
                includes_dependencies: includes,
                added_to_classpath: added,
            };
            let reason = match handler {
                Ok(handler) if handler == core => continue,
                Ok(_) => "a build extension defines it other than Maven's core, and Maven may \
                          take either handler"
                    .to_string(),
                Err(reason) => reason,
            };
            map.entry(type_).or_insert(Err(reason));
        }
        let _ = cell.set(map);
    }

    /// The Maven line.
    pub fn mode(&self) -> MavenMode {
        self.mode
    }

    fn extension_handler(&self, type_: &str) -> Option<&ArtifactHandler> {
        self.extensions.as_ref()?.get()?.get(type_)?.as_ref().ok()
    }

    /// The file extension of `type_`.
    pub fn extension<'a>(&'a self, type_: &'a str) -> &'a str {
        match core_handler(type_, self.mode) {
            Some(handler) => handler.1,
            None => self
                .extension_handler(type_)
                .map_or(type_, |handler| &handler.extension),
        }
    }

    /// The classifier `type_` implies.
    pub fn classifier(&self, type_: &str) -> Option<&str> {
        match core_handler(type_, self.mode) {
            Some(handler) => handler.2,
            None => self.extension_handler(type_)?.classifier.as_deref(),
        }
    }

    /// Whether a file of `type_` carries its dependencies.
    pub fn includes_dependencies(&self, type_: &str) -> bool {
        match core_handler(type_, self.mode) {
            Some(handler) => handler.3,
            None => self
                .extension_handler(type_)
                .is_some_and(|handler| handler.includes_dependencies),
        }
    }

    /// Whether a file of `type_` joins the class paths a build gives its
    /// plugins.
    pub fn added_to_classpath(&self, type_: &str) -> bool {
        match core_handler(type_, self.mode) {
            Some(handler) => handler.4,
            None => self
                .extension_handler(type_)
                .is_some_and(|handler| handler.added_to_classpath),
        }
    }

    /// Why the handler an extension defines for `type_` cannot be read,
    /// or for a core type differs from the core's, when it does.
    pub fn unreadable(&self, type_: &str) -> Option<&str> {
        (self.extensions.as_ref()?.get()?.get(type_)?.as_ref().err()).map(String::as_str)
    }
}

const HANDLER_ROLE: &str = "org.apache.maven.artifact.handler.ArtifactHandler";
const DEFAULT_HANDLER: &str = "org.apache.maven.artifact.handler.DefaultArtifactHandler";

/// The fields of a `DefaultArtifactHandler` as its constructor and Plexus
/// configuration leave them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct HandlerFields {
    type_: Option<String>,
    extension: Option<String>,
    classifier: Option<String>,
    includes_dependencies: bool,
    added_to_classpath: bool,
}

impl HandlerFields {
    fn handler(self) -> Result<ArtifactHandler, String> {
        let extension = (self.extension.or(self.type_))
            .ok_or_else(|| "the handler names neither a type nor an extension".to_string())?;
        Ok(ArtifactHandler {
            extension,
            classifier: self.classifier.filter(|classifier| !classifier.is_empty()),
            includes_dependencies: self.includes_dependencies,
            added_to_classpath: self.added_to_classpath,
        })
    }
}

/// The artifact handlers one jar of an extension's realm defines, by type,
/// in the order raeva reads them: its `components.xml`, then its Sisu
/// index. `read` gives an entry of the jar, `class` the class files the
/// realm's jars hold at an entry. The realm loads a class from the first
/// of its jars that holds it, and raeva does not follow their order, so a
/// class two of them define differently is one raeva cannot read. A
/// handler whose values are in code raeva does not read, or in such a
/// class, is an `Err` with the reason, which counts only when a dependency
/// of that type is met.
pub fn read_artifact_handlers(
    read: &dyn Fn(&str) -> Option<Vec<u8>>,
    class: &dyn Fn(&str) -> ClassFiles,
) -> Result<Vec<DefinedType>, PomError> {
    let mut handlers = Vec::new();
    if let Some(bytes) = read("META-INF/plexus/components.xml") {
        let text = String::from_utf8(bytes)
            .map_err(|_| PomError::InvalidModel("components.xml is not UTF-8".to_string()))?;
        for (hint, implementation, configuration) in parse_handler_components(&text)? {
            let fields = match implementation.as_deref() {
                None | Some(DEFAULT_HANDLER) => Ok(HandlerFields::default()),
                Some(name) => class_file::constructed_fields(class, name),
            };
            let handler = fields.and_then(|mut fields| {
                configuration.apply(&mut fields);
                fields.handler()
            });
            handlers.push((hint, handler));
        }
    }
    if let Some(bytes) = read("META-INF/sisu/javax.inject.Named") {
        let text = String::from_utf8_lossy(&bytes);
        // As Sisu's `IndexedClassFinder` reads it: Java's lines, each up to
        // a `#` and trimmed as Java trims, and each class once.
        let mut seen = HashSet::new();
        let classes = (text.split(['\r', '\n']))
            .map(|line| line.split('#').next().unwrap_or_default())
            .map(|line| line.trim_matches(|c| c <= ' '))
            .filter(|line| !line.is_empty() && seen.insert(*line));
        for name in classes {
            for (name, fields) in class_file::named_handler(class, name) {
                handlers.push((name, fields.and_then(HandlerFields::handler)));
            }
        }
    }
    Ok(handlers)
}

/// The handlers of one extension realm from those each of its jars
/// defines, `jars` in the realm's order with their coordinates: of a type
/// one jar defines twice, the first. Which of two jars Maven takes a type
/// from turns on how Plexus and Sisu rank their components, which raeva
/// does not follow, so a type two jars define differently is an `Err`.
pub fn merge_realm_handlers(
    jars: impl IntoIterator<Item = (String, Vec<DefinedType>)>,
) -> Vec<DefinedType> {
    let mut merged: Vec<DefinedType> = Vec::new();
    let mut first: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for (coord, defined) in jars {
        let mut own = HashSet::new();
        for (type_, handler) in defined {
            if !own.insert(type_.clone()) {
                continue;
            }
            match first.get(&type_) {
                None => {
                    first.insert(type_.clone(), (merged.len(), coord.clone()));
                    merged.push((type_, handler));
                }
                Some((at, other)) if merged[*at].1 != handler => {
                    merged[*at].1 = Err(format!(
                        "{other} and {coord} in one extension realm define it differently"
                    ));
                }
                Some(_) => {}
            }
        }
    }
    merged
}

/// A handler component's `<configuration>`, which Plexus sets on the
/// constructed handler field by field.
#[derive(Debug, Default)]
struct HandlerConfiguration(Vec<(String, String)>);

impl HandlerConfiguration {
    fn apply(&self, fields: &mut HandlerFields) {
        for (name, value) in &self.0 {
            let flag = || value.eq_ignore_ascii_case("true");
            match name.as_str() {
                "type" => fields.type_ = Some(value.clone()),
                "extension" => fields.extension = Some(value.clone()),
                "classifier" => fields.classifier = Some(value.clone()),
                "includesDependencies" => fields.includes_dependencies = flag(),
                "addedToClasspath" => fields.added_to_classpath = flag(),
                _ => {}
            }
        }
    }
}

/// The `ArtifactHandler` components of a `components.xml`: role hint (the
/// type, `default` when absent), implementation class and configuration.
fn parse_handler_components(
    xml: &str,
) -> Result<Vec<(String, Option<String>, HandlerConfiguration)>, PomError> {
    let set = crate::plugin::descriptor_root(xml, "components.xml")?;
    let mut components = Vec::new();
    for component in (set.child("components").into_iter())
        .flat_map(|list| &list.children)
        .filter(|component| component.name == "component")
    {
        if component.child_value("role") != Some(HANDLER_ROLE) {
            continue;
        }
        let hint = component.child_value("role-hint").unwrap_or("default");
        let implementation = component.child_value("implementation").map(str::to_string);
        let configuration = (component.child("configuration").into_iter())
            .flat_map(|configuration| &configuration.children)
            .filter_map(|field| Some((field.name.clone(), field.value.clone()?)))
            .collect();
        components.push((
            hint.to_string(),
            implementation,
            HandlerConfiguration(configuration),
        ));
    }
    Ok(components)
}

#[cfg(test)]
mod tests;
