use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum VersionError {
    #[error("invalid version string: {0}")]
    InvalidVersion(String),
    #[error("invalid version range: {0}")]
    InvalidRange(String),
    #[error("invalid coordinate: {0}")]
    InvalidCoord(String),
    /// A version string contained a `${...}` Maven property placeholder
    /// that never got expanded. Parsing this as a real version would
    /// produce a "soft pin" that can never match a published release.
    #[error("unresolved property in version string: {0}")]
    UnresolvedProperty(String),
}

#[cfg(test)]
mod tests {
    use super::VersionError;

    #[test]
    fn error_equality() {
        assert_eq!(
            VersionError::InvalidVersion("x".into()),
            VersionError::InvalidVersion("x".into())
        );
    }
}
