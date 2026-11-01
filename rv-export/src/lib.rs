//! Writes the artifacts a `raeva.lock` pins into a Maven local repository.
//!
//! [`Exporter`] copies (or links) each locked artifact and the POMs around it
//! from the content store to `<group>/<artifact>/<version>/` under the
//! destination, with checksum sidecars, `_remote.repositories` markers and
//! snapshot metadata, so `mvn -o` resolves from it. The lock is untrusted
//! input: every path is built from validated coordinates and checked to stay
//! under the destination, and bytes are checked against the lock's pins
//! before they are written.
//!
//! An [`ExportPlan`] is built from the lock and names what to write; an
//! [`Exporter`] writes it. Conditions that do not stop an export come back as
//! [`ExportWarning`] values in [`ExportStats::warnings`], or in
//! [`ExportFailure::warnings`] next to the error that stopped an export; the
//! crate neither prints nor logs them.
//!
//! This crate does not resolve dependencies or contact a repository, and
//! reads no settings from the environment. Every byte it writes must
//! already be in the content store; a caller that wants classifier jars
//! fetches them for the candidates [`ExportPlan::authorize_classifiers`] accepts and passes them to
//! [`Exporter::export_items`]. The support-POM limit override is read by the
//! caller from [`MAX_SUPPORT_POM_NODES_ENV`] and passed to
//! [`Exporter::with_support_pom_limit`].

mod error;
mod export;
mod link;
mod metadata;
mod plan;
mod warning;

pub use error::{ExportError, ExportFailure, LinkError};
pub use export::{ExportOptions, ExportStats, Exporter, MAX_SUPPORT_POM_NODES_ENV};
pub use link::LinkStrategy;
pub use plan::{AuthorizedClassifier, ClassifierCandidate, ExportPlan, ProjectPom, Reactor};
pub use warning::ExportWarning;
