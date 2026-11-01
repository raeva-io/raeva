use std::io;
use std::path::PathBuf;

/// Why a lockfile could not be read, written or used.
///
/// Every variant but [`LockError::Io`] says the file is not a lockfile this
/// raeva can use ([`LockError::is_incompatible_lockfile`]); a plain `raeva sync`
/// replaces such a file instead of failing on it. No message quotes text
/// from the file unescaped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LockError {
    /// The file could not be read or written.
    #[error("{context}: {source}")]
    Io {
        /// What was being done, with the lockfile's path.
        context: String,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The file is not TOML of the lockfile's shape. `message` has every
    /// character that is not safe to print escaped.
    #[error("failed to parse lockfile {}: {message}", path.display())]
    Toml {
        /// The lockfile's path.
        path: PathBuf,
        /// The parser's message, with the byte offset when it has one.
        message: String,
    },
    /// The lockfile has another schema version.
    #[error(
        "unsupported lockfile schema version {found}; this raeva reads schema {expected} only{}",
        if found > expected { ", so upgrade raeva to read it" } else { "" }
    )]
    UnsupportedSchema {
        /// The `schema_version` the file declares.
        found: u32,
        /// [`crate::LOCKFILE_SCHEMA_VERSION`].
        expected: u32,
    },
    /// The file is empty or holds only whitespace, which is what an aborted
    /// first sync or a truncation leaves.
    #[error("lockfile {} is empty", path.display())]
    Empty {
        /// The lockfile's path.
        path: PathBuf,
    },
    /// The file is larger than any lockfile raeva reads.
    #[error("lockfile {} is {size} bytes, which exceeds the {limit} byte limit", path.display())]
    TooLarge {
        /// The lockfile's path.
        path: PathBuf,
        /// The bytes read before stopping, at most `limit + 1`.
        size: u64,
        /// The largest size accepted, in bytes.
        limit: u64,
    },
    /// The lockfile breaks a rule of the schema.
    #[error("invalid lockfile: {0}")]
    Invalid(String),
}

impl LockError {
    /// Whether this error means the file is not a lockfile this raeva can use,
    /// as opposed to one it could not read or write.
    pub fn is_incompatible_lockfile(&self) -> bool {
        !matches!(self, Self::Io { .. })
    }

    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

/// `text` with every character that is not safe to print escaped, so a
/// message can quote a lockfile's text.
pub(crate) fn printable(text: &str) -> String {
    if rv_maven_types::is_terminal_safe(text) {
        return text.to_string();
    }
    text.chars()
        .map(|c| {
            let mut buf = [0u8; 4];
            if rv_maven_types::is_terminal_safe(c.encode_utf8(&mut buf)) {
                c.to_string()
            } else {
                c.escape_unicode().to_string()
            }
        })
        .collect()
}
