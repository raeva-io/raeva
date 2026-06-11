use thiserror::Error;

#[derive(Debug, Error)]
pub enum PomError {
    #[error("xml error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("deserialization error: {0}")]
    Deserialize(#[from] quick_xml::de::DeError),
    #[error("xml escape error: {0}")]
    Escape(#[from] quick_xml::escape::EscapeError),
    #[error("utf-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid boolean: {0}")]
    InvalidBoolean(String),
    #[error("unexpected end of file while parsing {0}")]
    UnexpectedEof(String),
    #[error("property cycle detected: {}", .0.join(" -> "))]
    PropertyCycle(Vec<String>),
    #[error("parent not found: {0}:{1}:{2}")]
    ParentNotFound(String, String, String),
    #[error("parent POM coordinate mismatch: {0}")]
    ParentCoordMismatch(Box<ParentCoordMismatch>),
    #[error("invalid model: {0}")]
    InvalidModel(String),
}

/// Details for a [`PomError::ParentCoordMismatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentCoordMismatch {
    pub expected_group: String,
    pub expected_artifact: String,
    pub expected_version: String,
    pub actual_group: String,
    pub actual_artifact: String,
    pub actual_version: String,
}

impl std::fmt::Display for ParentCoordMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "expected {}:{}:{}, got {}:{}:{}",
            self.expected_group,
            self.expected_artifact,
            self.expected_version,
            self.actual_group,
            self.actual_artifact,
            self.actual_version,
        )
    }
}
