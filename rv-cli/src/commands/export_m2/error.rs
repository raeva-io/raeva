use std::path::PathBuf;

use thiserror::Error;

use rv_store::StoreError;

use super::link::LinkStrategy;

pub(crate) type Result<T> = std::result::Result<T, ExportError>;

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("store error: {0}")]
    StoreError(#[from] StoreError),
    #[error("link error: {0}")]
    LinkError(#[from] LinkError),
    #[error("unsupported checksum algorithm {algorithm} for {key}")]
    UnsupportedChecksum { key: String, algorithm: String },
    #[error("invalid checksum for {key}: {reason}")]
    InvalidChecksum { key: String, reason: String },
    #[error("missing blob for {key}")]
    MissingBlob { key: String },
    #[error(
        "lockfile pin for {key} ({algorithm}={expected}) does not match the blob in the global store ({actual}); run `rv sync` first"
    )]
    PinMismatch {
        key: String,
        algorithm: String,
        expected: String,
        actual: String,
    },
    #[error(
        "support-POM closure exceeds the limit of {limit} unique POMs; refusing to write an incomplete offline repository. Raise the limit with {variable}=<count>"
    )]
    SupportClosureTooLarge {
        limit: usize,
        variable: &'static str,
    },
    #[error(
        "support POM {coordinate} was recorded during resolution but is missing from the content store; refusing to write an incomplete offline repository. {hint}"
    )]
    MissingSupportPom {
        coordinate: String,
        hint: &'static str,
    },
    #[error(
        "rv.lock pins the POM for {coordinate} to sha256 {digest}, but those bytes are not in the content store; refusing to export a POM this lockfile was not resolved against. {hint}"
    )]
    MissingPinnedPom {
        coordinate: String,
        digest: String,
        hint: &'static str,
    },
    #[error(
        "rv.lock pins the POM for {coordinate} to two different digests ({first}, {second}); Maven has one local-repository path per coordinate, so no export can satisfy both. Run `rv sync` to rewrite rv.lock"
    )]
    ConflictingPinnedPom {
        coordinate: String,
        first: String,
        second: String,
    },
    #[error(
        "rv.lock pins the pom-packaged artifact {coordinate} to sha256 {artifact} but its POM to {pom}; for packaging=pom those are the same Maven file, so no export can write both. Run `rv sync` to rewrite rv.lock"
    )]
    ConflictingPomPackagedPin {
        coordinate: String,
        artifact: String,
        pom: String,
    },
    #[error(
        "{coordinate} is claimed by two different files: {first_source} names sha256 {first}, {second_source} names sha256 {second}; Maven has one local-repository path per coordinate, so no export can write both. Run `rv sync` to rewrite rv.lock"
    )]
    ConflictingExportSources {
        coordinate: String,
        first_source: &'static str,
        first: String,
        second_source: &'static str,
        second: String,
    },
    #[error("invalid coordinate: {0}")]
    InvalidCoordinate(String),
    #[error("path traversal attempt detected: {0}")]
    PathTraversal(PathBuf),
    #[error(
        "destination {path:?} already exists with different bytes than the locked blob for {key} (expected sha256 {expected}, found {actual}); rerun with --overwrite to replace"
    )]
    DestinationMismatch {
        key: String,
        path: PathBuf,
        expected: String,
        actual: String,
    },
}

#[derive(Debug, Error)]
pub enum LinkError {
    #[error("{strategy} failed for {src:?} -> {dest:?}: {source}")]
    IoError {
        strategy: LinkStrategy,
        src: PathBuf,
        dest: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("source missing: {src:?}")]
    SourceMissing { src: PathBuf },
}

#[cfg(test)]
mod tests {
    use super::super::link::LinkStrategy;
    use super::{ExportError, LinkError};
    use std::io;
    use std::path::PathBuf;

    #[test]
    fn link_error_formats_strategy() {
        let err = LinkError::IoError {
            strategy: LinkStrategy::Copy,
            src: PathBuf::from("/tmp/src"),
            dest: PathBuf::from("/tmp/dest"),
            source: io::Error::other("nope"),
        };
        let message = err.to_string();
        assert!(message.contains("copy"));
    }

    #[test]
    fn export_error_formats_missing_blob() {
        let err = ExportError::MissingBlob {
            key: "com.example:demo:1.0.0:jar".to_string(),
        };
        let message = err.to_string();
        assert!(message.contains("missing blob"));
    }
}
