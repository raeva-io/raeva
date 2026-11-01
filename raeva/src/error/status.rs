use std::process::ExitCode;

/// The exit status of the `raeva` binary. Every exit code raeva returns comes from
/// this enum; the exit-code table in docs/json-output.md documents the same values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(strum::EnumIter))]
#[repr(u8)]
pub(crate) enum ExitStatus {
    Success = 0,
    Failure = 1,
    /// Bad flags or arguments (clap uses 2 as well), or a `raeva vuln` scan
    /// that failed for a cause with no more specific status.
    Usage = 2,
    /// Configuration, credentials, trust roots or project input, or an
    /// raeva.lock that is missing or invalid.
    Config = 3,
    /// A repository could not be reached: timeout, connection, DNS, a
    /// retried status such as 503.
    Network = 4,
    Resolution = 5,
    /// raeva could not start: runtime or TLS provider setup.
    Startup = 6,
    /// raeva.lock is out of date for the project or configuration, or does not
    /// match a fresh resolution, a download or the store.
    LockMismatch = 7,
    /// Some checks passed and others failed (`raeva doctor`).
    Partial = 8,
    /// A repository served bytes that fail its own published checksum.
    Integrity = 9,
}

impl ExitStatus {
    pub(crate) fn code(self) -> u8 {
        self as u8
    }

    /// The status of a `raeva vuln` scan that failed for a cause of this
    /// status. `raeva vuln` exits 1 for findings, so a cause with no more
    /// specific status exits 2.
    pub(crate) fn of_failed_scan(self) -> Self {
        match self {
            Self::Failure => Self::Usage,
            other => other,
        }
    }
}

impl From<ExitStatus> for ExitCode {
    fn from(status: ExitStatus) -> Self {
        ExitCode::from(status.code())
    }
}

impl serde::Serialize for ExitStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::ExitStatus;
    use strum::IntoEnumIterator;

    #[test]
    fn usage_matches_clap() {
        assert_eq!(ExitStatus::Usage.code(), 2);
    }

    /// The exit-code table in docs/json-output.md lists every status and nothing else,
    /// besides 130 and 143, which `main` returns for Ctrl-C and SIGTERM.
    #[test]
    fn the_docs_list_exactly_the_statuses() {
        let documented = rv_test_support::fixtures::markdown_first_column(
            &rv_test_support::fixtures::workspace_file("docs/json-output.md"),
            "## Exit codes",
        );
        let mut expected: Vec<String> = ExitStatus::iter()
            .map(|status| status.code().to_string())
            .collect();
        expected.extend(["130".to_string(), "143".to_string()]);
        assert_eq!(documented, expected, "docs/json-output.md exit-code table");
    }

    #[test]
    fn codes_are_distinct_and_dense() {
        for (index, status) in ExitStatus::iter().enumerate() {
            assert_eq!(usize::from(status.code()), index, "{status:?}");
        }
    }
}
