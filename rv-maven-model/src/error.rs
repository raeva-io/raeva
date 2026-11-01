use rv_maven_types::bounded;
use thiserror::Error;

/// Text from a POM, including what the XML parser quotes from one, reaches
/// a message only through [`bounded`] or
/// [`quoted`](rv_maven_types::quoted). A variant that holds a whole
/// message, such as [`PomError::InvalidModel`], gets the POM text in it
/// bounded where the message is built.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PomError {
    /// The XML did not map onto the POM structure.
    #[error("deserialization error: {}", bounded(&.0.to_string()))]
    Deserialize(#[from] quick_xml::de::DeError),
    /// The XML declaration names an encoding raeva does not decode.
    #[error(
        "the POM declares encoding {}, which raeva does not read; raeva reads UTF-8, UTF-16, ISO-8859-1, US-ASCII and windows-1252",
        bounded(.0)
    )]
    UnsupportedEncoding(String),
    /// The POM starts with `<?xm` in EBCDIC and declares an encoding raeva does
    /// not decode, such as `IBM037`. Maven reads it in that encoding; raeva
    /// refuses it rather than reading other text.
    #[error(
        "the POM is in EBCDIC, declared as {}, which raeva does not read; raeva reads UTF-8, UTF-16, ISO-8859-1, US-ASCII and windows-1252",
        bounded(.0)
    )]
    Ebcdic(String),
    /// The XML declaration names an encoding the JDK that Maven 3.9.11 was
    /// checked on does not know, such as `default`, which Java no longer
    /// reads as US-ASCII. Maven's reader refuses the POM.
    #[error("the POM declares encoding {}, which Java does not read", bounded(.0))]
    UnknownEncoding(String),
    /// A UTF-16 byte order mark before bytes that read as another
    /// encoding, which Maven's reader refuses.
    #[error("the POM starts with a {bom} byte order mark, but the text after it reads as {text}")]
    EncodingMismatch {
        /// The encoding the byte order mark names.
        bom: &'static str,
        /// The encoding the text after it reads as.
        text: &'static str,
    },
    /// An XML declaration with no `>` in the first 4096 bytes, which
    /// Maven's reader refuses.
    #[error("the POM's XML declaration does not end within its first 4096 bytes")]
    UnterminatedDeclaration,
    /// Markup around the root element, or a comment or processing
    /// instruction in it, that Maven's XML parser refuses: text before or
    /// after the root element, a second root element, an XML declaration
    /// anywhere but at the start, and others.
    #[error("the POM is not well-formed XML: {reason} at line {line}")]
    NotWellFormed {
        /// A fixed phrase naming the defect.
        reason: &'static str,
        /// The 1-based line of the decoded POM the scan stopped on.
        line: usize,
    },
    /// The root element is not well-formed XML: a tag, comment or other
    /// markup that is not closed, or an end tag that does not match.
    #[error("the POM is not well-formed XML: {reason} at line {line}, column {column}")]
    Malformed {
        /// The defect, with any element name from the POM bounded.
        reason: String,
        /// The 1-based line of the decoded POM.
        line: usize,
        /// The 1-based column, in characters.
        column: usize,
    },
    /// The model has no `groupId`, `artifactId` or `version`, from the POM
    /// or its parent. The field names which.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// Property interpolation found a cycle; the names are the path around
    /// it.
    #[error("property cycle detected: {}", cycle(.0))]
    PropertyCycle(Vec<String>),
    /// No source has the parent with this group, artifact and version.
    #[error("parent not found: {}:{}:{}", bounded(.0), bounded(.1), bounded(.2))]
    ParentNotFound(String, String, String),
    /// A parent version range without an upper bound, which Maven does not
    /// resolve from a repository.
    #[error(
        "the parent version range {}:{}:{} does not specify an upper bound",
        bounded(.0),
        bounded(.1),
        bounded(.2)
    )]
    UnboundedParentRange(String, String, String),
    /// No source has the imported BOM with this group, artifact and version.
    #[error("BOM not found: {}:{}:{}", bounded(.0), bounded(.1), bounded(.2))]
    ImportNotFound(String, String, String),
    /// A BOM import, named here, whose coordinates keep a `${...}` after
    /// interpolation, and the coordinates as written. Maven looks it up as
    /// it is, which names no published POM, so like a missing BOM it fails
    /// a dependency's model.
    #[error("BOM import {} has an unresolved expression (raw: {})", bounded(.0), bounded(.1))]
    UnresolvedImport(String, String),
    /// A managed dependency, by its management key, whose `<type>` is
    /// empty. Maven validates the model but cannot make an artifact of the
    /// entry, so it fails the build instead of dropping the descriptor.
    #[error("managed dependency {} declares an empty <type>", bounded(.0))]
    EmptyManagedType(String),
    /// A `<parent>` whose coordinates hold a `${...}` expression and that no
    /// local POM declares with the same text. Maven also asks repositories
    /// for the unexpanded text, which names no published POM.
    #[error(
        "parent {} cannot be resolved: no POM at its relativePath declares these coordinates as \
         written, and Maven does not expand properties in <parent> before looking it up",
        bounded(.0)
    )]
    ParentExpression(String),
    /// A [`PomError::ParentExpression`] in a POM fetched from a repository,
    /// which `pom` names. Like a missing parent, it fails a dependency's
    /// model, where most model errors only make it an invalid descriptor.
    #[error("invalid model: {pom}: {}", PomError::ParentExpression(.parent.clone()))]
    FetchedParentExpression {
        /// The fetched POM's coordinates.
        pom: String,
        /// The `<parent>` coordinates as written.
        parent: String,
    },
    /// A fetched parent or imported BOM declares other coordinates than
    /// the ones it was requested by.
    #[error("parent POM coordinate mismatch: {0}")]
    ParentCoordMismatch(Box<ParentCoordMismatch>),
    /// A model error Maven's validation or profile activation reports, with
    /// the whole message.
    #[error("invalid model: {0}")]
    InvalidModel(String),
    /// A `system`-scoped dependency without an absolute `<systemPath>`, an
    /// error in Maven's validation of every model it builds.
    #[error("invalid model: {0}")]
    InvalidSystemPath(String),
    /// A parent or imported BOM that a repository served but that is not
    /// well-formed XML (see [`PomError::is_malformed_xml`]). Maven reports
    /// this as an invalid model, not as an unresolvable one: a project build
    /// fails, and a dependency's descriptor is dropped.
    #[error("{}: {source}", bounded(coord))]
    UnparseablePom {
        /// The coordinates the POM was requested by.
        coord: String,
        /// The parse failure.
        #[source]
        source: Box<PomError>,
    },
}

fn cycle(names: &[String]) -> String {
    const SHOWN: usize = 16;
    let mut out = names
        .iter()
        .take(SHOWN)
        .map(|name| bounded(name).to_string())
        .collect::<Vec<_>>()
        .join(" -> ");
    if names.len() > SHOWN {
        out.push_str(&format!(" -> ... ({} names)", names.len()));
    }
    out
}

impl PomError {
    /// Whether this parse failure means the document is not well-formed XML,
    /// which Maven's reader rejects too: a syntax error, a missing or
    /// mismatched end tag, an entity Maven does not know, a document that
    /// ends early, or markup around the root element that Maven's parser
    /// refuses. A POM in an encoding raeva does not read is not malformed,
    /// so it never stands in for an invalid model.
    pub fn is_malformed_xml(&self) -> bool {
        use quick_xml::de::DeError;
        let malformed = |error: &quick_xml::Error| {
            matches!(
                error,
                quick_xml::Error::Syntax(_)
                    | quick_xml::Error::IllFormed(_)
                    | quick_xml::Error::Escape(_)
            )
        };
        match self {
            PomError::Deserialize(DeError::InvalidXml(error)) => malformed(error),
            PomError::Deserialize(DeError::UnexpectedEof)
            | PomError::EncodingMismatch { .. }
            | PomError::UnknownEncoding(_)
            | PomError::UnterminatedDeclaration
            | PomError::NotWellFormed { .. }
            | PomError::Malformed { .. } => true,
            _ => false,
        }
    }

    /// A serde/quick-xml deserialize failure for the POM document, including
    /// duplicate fields and documents that are not a Maven model. Distinct
    /// from [`Self::is_malformed_xml`]: duplicate tags are well-formed XML.
    pub fn is_deserialize(&self) -> bool {
        matches!(self, PomError::Deserialize(_))
    }
}

#[cfg(test)]
mod tests {
    use crate::Pom;

    /// The parser quotes tag names and values from the document; the error
    /// shows them escaped and cut.
    #[test]
    fn parser_messages_are_bounded() {
        let name = "a".repeat(400);
        let xml = format!("<project><{name}>1</b{name}></project>");
        let message = Pom::parse(&xml).expect_err("mismatched tags").to_string();
        assert!(message.contains(" bytes)"), "{message}");
        assert!(message.len() < 300, "{message}");
    }

    #[test]
    fn a_long_property_cycle_is_cut() {
        let names: Vec<String> = (0..40).map(|i| format!("p{i}\u{1b}")).collect();
        let message = super::PomError::PropertyCycle(names).to_string();
        assert!(
            message.starts_with("property cycle detected: p0\\u{1b} -> p1"),
            "{message}"
        );
        assert!(
            message.ends_with(" -> p15\\u{1b} -> ... (40 names)"),
            "{message}"
        );
        assert!(!message.contains('\u{1b}'), "{message}");
    }

    #[test]
    fn only_documents_that_are_not_well_formed_are_malformed() {
        for xml in [
            "<project><artifactId>lib",
            "<project><broken></project>",
            "<project><artifactId>lib</groupId></project>",
            "Lo<project/>",
            "<?xml version=\"1.0\"?>\n text <project/>",
            "<!-- c --><![CDATA[x]]><project/>",
            "&amp;<project/>",
            "&#32;<project/>",
            "<project/>x",
            "<project/><project/>",
            "  <?xml version=\"1.0\"?><project/>",
        ] {
            let error = Pom::parse(xml).expect_err(xml);
            assert!(error.is_malformed_xml(), "{xml}: {error:?}");
        }
        for xml in [
            "<project><description>&unknownentity;</description></project>",
            "<!DOCTYPE project [<!ENTITY v \"1\">]><project><version>&v;</version></project>",
        ] {
            let error = Pom::parse(xml).expect_err(xml);
            assert!(error.is_malformed_xml(), "{xml}: {error:?}");
        }
        for xml in [
            "<project><description>&copy; &nbsp; &euro;</description></project>",
            "<!DOCTYPE project><project/>",
            "<?xml version=\"1.0\"?>\r\n\t<!-- c --> <?pi x?>\n<project/>",
            "<project/>\n<?pi x?><!-- c --><!DOCTYPE project>\n",
        ] {
            Pom::parse(xml).expect(xml);
        }
        let error = crate::decode_pom(b"<?xml version='1.0' encoding='Big5'?><project/>")
            .expect_err("Big5");
        assert!(!error.is_malformed_xml(), "{error:?}");
    }
}

/// Details for a [`PomError::ParentCoordMismatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParentCoordMismatch {
    /// The requested `groupId`.
    pub expected_group: String,
    /// The requested `artifactId`.
    pub expected_artifact: String,
    /// The requested version.
    pub expected_version: String,
    /// The `groupId` the fetched POM declares, or its `<parent>` groupId
    /// when it declares none.
    pub actual_group: String,
    /// The `artifactId` the fetched POM declares.
    pub actual_artifact: String,
    /// The version the fetched POM declares, or its `<parent>` version
    /// when it declares none.
    pub actual_version: String,
}

impl std::fmt::Display for ParentCoordMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "expected {}:{}:{}, got {}:{}:{}",
            bounded(&self.expected_group),
            bounded(&self.expected_artifact),
            bounded(&self.expected_version),
            bounded(&self.actual_group),
            bounded(&self.actual_artifact),
            bounded(&self.actual_version),
        )
    }
}
