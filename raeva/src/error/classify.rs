//! One classification of repository errors, shared by error diagnosis and
//! `raeva doctor`.

use rv_repo::{ErrorClass as RepoClass, IntegritySource, RepoError};

use super::ExitStatus;

/// The classes of [`rv_repo::ErrorClass`] that the CLI tells apart. The
/// operation decides what a class means for the exit status;
/// [`ErrorClass::exit_status`] is the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ErrorClass {
    Auth,
    ProxyAuth,
    /// The network failed: a timeout, a connection failure, a host that did
    /// not resolve, a broken-off transfer, a status the fetch retries (429,
    /// 502, 503, 504), or a TLS failure that is not permanent.
    Network,
    /// TLS refused the server, such as an untrusted certificate. Retrying
    /// does not help; the trust roots or the URL have to change.
    Tls,
    /// The configuration names something raeva refuses to fetch: a bad URL,
    /// snapshots disabled, an origin the configuration does not declare.
    Config,
    Integrity(IntegritySource),
    NotFound,
    Store,
    /// `--offline` and the file is not cached.
    Offline,
    /// raeva.lock cannot be used as written, such as a row without a checksum.
    Lockfile,
    /// Anything else: invalid metadata, a refused redirect, a missing
    /// sidecar, a status or transport failure the fetch does not retry.
    Other,
}

impl ErrorClass {
    pub(crate) fn of(err: &RepoError) -> Self {
        match err.class() {
            RepoClass::Auth => Self::Auth,
            RepoClass::ProxyAuth => Self::ProxyAuth,
            RepoClass::Tls { permanent: true } => Self::Tls,
            RepoClass::Tls { permanent: false }
            | RepoClass::Unreachable
            | RepoClass::Transport { retried: true }
            | RepoClass::Status { retried: true, .. } => Self::Network,
            // A 500 is the server's own failure, not the network's, and the
            // fetch does not retry it.
            RepoClass::Transport { retried: false } | RepoClass::Status { retried: false, .. } => {
                Self::Other
            }
            RepoClass::NotFound => Self::NotFound,
            RepoClass::Integrity(source) => Self::Integrity(source),
            RepoClass::Store => Self::Store,
            RepoClass::Offline => Self::Offline,
            RepoClass::Config => Self::Config,
            RepoClass::Lockfile => Self::Lockfile,
            _ => Self::Other,
        }
    }

    pub(crate) fn exit_status(self) -> ExitStatus {
        match self {
            Self::Auth | Self::ProxyAuth | Self::Tls | Self::Config | Self::Lockfile => {
                ExitStatus::Config
            }
            Self::Network => ExitStatus::Network,
            Self::Integrity(IntegritySource::Sidecar) => ExitStatus::Integrity,
            Self::Integrity(IntegritySource::LockPin) => ExitStatus::LockMismatch,
            Self::Store => ExitStatus::Failure,
            Self::NotFound | Self::Offline | Self::Other => ExitStatus::Resolution,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorClass, ExitStatus};
    use rv_maven_types::{Digest, HashAlgorithm};
    use rv_repo::{IntegritySource, RepoError};

    fn status(err: RepoError) -> ExitStatus {
        ErrorClass::of(&err).exit_status()
    }

    #[test]
    fn a_sidecar_mismatch_is_integrity_and_a_pin_mismatch_is_the_lock() {
        let mismatch = |subject: &str, check| RepoError::ChecksumMismatch {
            subject: subject.into(),
            artifact: None,
            expected: Digest::of_bytes(HashAlgorithm::Sha256, b"a"),
            actual: Digest::of_bytes(HashAlgorithm::Sha256, b"b"),
            check,
        };
        let sidecar = || mismatch("org/example/lib/1.0/lib-1.0.jar", IntegritySource::Sidecar);
        assert_eq!(
            ErrorClass::of(&sidecar()),
            ErrorClass::Integrity(IntegritySource::Sidecar)
        );
        assert_eq!(status(sidecar()), ExitStatus::Integrity);
        assert_eq!(
            status(mismatch(
                "org.example:lib:1.0:jar",
                IntegritySource::LockPin
            )),
            ExitStatus::LockMismatch
        );
    }
}
