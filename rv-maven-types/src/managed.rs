//! Which part of a project's dependency management supplied a version.

use std::fmt;

use crate::component::{CoordinateField, MAX_COMPONENT_BYTES, validate_coordinate_component};

/// Where a managed version was declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManagedKind {
    /// A `<dependencyManagement>` entry of the module's POM or of a parent
    /// in its lineage, profiles included.
    Pom,
    /// An entry of a BOM the lineage imports, directly or through the BOMs
    /// that BOM imports.
    Import,
    /// A version written as one property that a parent from a repository
    /// sets: a dependency the lineage declares, an entry of a
    /// `<dependencyManagement>` in the project's own POMs, or one of another
    /// parent's.
    Property,
}

impl ManagedKind {
    /// The name raeva.lock writes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pom => "pom",
            Self::Import => "import",
            Self::Property => "property",
        }
    }

    /// The kind `name` writes, if any.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "pom" => Some(Self::Pom),
            "import" => Some(Self::Import),
            "property" => Some(Self::Property),
            _ => None,
        }
    }
}

/// The source of a version a module's dependency management supplied: the
/// POM that declares the entry, or the BOM the lineage imports, and the
/// property the version is written as; or the parent that sets the one
/// property a version is written as.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManagedSource {
    /// Whether a lineage POM or an imported BOM holds the entry, or a
    /// parent sets the version's property.
    pub kind: ManagedKind,
    /// The `groupId:artifactId` of that POM, BOM or parent. Its version is
    /// left out, so a bump of it changes no row it manages the same.
    pub pom: String,
    /// The property the version is written as when it is exactly one
    /// `${name}`: the entry's own version for [`ManagedKind::Pom`] and
    /// [`ManagedKind::Property`], the import's version for
    /// [`ManagedKind::Import`].
    pub property: Option<String>,
}

impl ManagedSource {
    /// The source for `group:artifact`, with the property `version` names
    /// as written. `None` when the coordinates are not valid Maven ids,
    /// which an unresolved expression leaves.
    pub fn new(
        kind: ManagedKind,
        group: &str,
        artifact: &str,
        version: Option<&str>,
    ) -> Option<Self> {
        validate_coordinate_component(CoordinateField::Group, group).ok()?;
        validate_coordinate_component(CoordinateField::Artifact, artifact).ok()?;
        Some(Self {
            kind,
            pom: format!("{group}:{artifact}"),
            property: version.and_then(single_property).map(str::to_string),
        })
    }

    /// Whether `name` may be written as a property: Maven's id characters,
    /// non-empty and bounded.
    pub fn is_property_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= MAX_COMPONENT_BYTES
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    }
}

impl fmt::Display for ManagedSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.kind.as_str(), self.pom)?;
        match &self.property {
            Some(property) => write!(formatter, " (${{{property}}})"),
            None => Ok(()),
        }
    }
}

/// The property `version` is when it is exactly one `${name}`.
pub fn single_property(version: &str) -> Option<&str> {
    let name = expression_key(version.trim().strip_prefix("${")?.strip_suffix('}')?);
    ManagedSource::is_property_name(name).then_some(name)
}

/// The name the text of a `${...}` expression looks up: Maven's
/// interpolators drop one leading `.` first, so `${.java.home}` reads
/// `java.home`.
pub fn expression_key(written: &str) -> &str {
    written.strip_prefix('.').unwrap_or(written)
}

#[cfg(test)]
mod tests {
    use super::{ManagedKind, ManagedSource};

    #[test]
    fn only_one_whole_property_is_named() {
        let source = |version| ManagedSource::new(ManagedKind::Pom, "g", "a", version);
        for (version, property) in [
            (Some("${guava.version}"), Some("guava.version")),
            (Some(" ${v} "), Some("v")),
            (Some("${.bom.version}"), Some("bom.version")),
            (Some("${.}"), None),
            (Some("1.0"), None),
            (Some("${a}.${b}"), None),
            (Some("${a}-SNAPSHOT"), None),
            (Some("${a b}"), None),
            (Some("${}"), None),
            (None, None),
        ] {
            let source = source(version).unwrap();
            assert_eq!(source.property.as_deref(), property, "{version:?}");
        }
        assert_eq!(source(None).unwrap().pom, "g:a");
        assert!(ManagedSource::new(ManagedKind::Import, "${g}", "a", None).is_none());
        assert!(ManagedSource::new(ManagedKind::Import, "g", "a\tb", None).is_none());
        let shown = ManagedSource::new(ManagedKind::Import, "g", "bom", Some("${v}")).unwrap();
        assert_eq!(shown.to_string(), "import g:bom (${v})");
    }
}
