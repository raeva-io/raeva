//! Generates the metadata files of the Maven local repository layout used by
//! `mvn -o`.
//!
//! Two files are written per snapshot artifact group:
//!
//! 1. `<groupId>/<artifactId>/<base-snapshot-version>/maven-metadata-<id>.xml`
//!    pins the timestamp and build number, as the remote repository's
//!    metadata that Maven 3.9 keeps under the id of the repository (or the
//!    mirror) it downloaded from. A `maven-metadata-local.xml` there would
//!    have to say `localCopy`, and Maven 3.9.11 rejects one that also holds
//!    a build number as "corrupted with remote repository data".
//! 2. `<groupId>/<artifactId>/maven-metadata-<id>.xml` lists the versions
//!    the lock takes from repository `<id>`, which is what `mvn -o` reads to
//!    resolve a version range. Only the locked versions are listed, the
//!    artifact's other `maven-metadata-*.xml` files are removed, and every
//!    other id the build may read, `local` among them, gets a list naming
//!    nothing, here and in each SNAPSHOT version directory, so an offline
//!    range or SNAPSHOT cannot pick a version or build the lock did not,
//!    even from a `-Dmaven.repo.local.tail`. In the shared Maven local
//!    repository the lists keep their versions and nothing is removed or
//!    added.
//!
//! The snapshot file is merged with the one already in the destination for
//! the same timestamped build: entries that build already lists stay listed,
//! so a second export pass (`--with-sources` after the main jars) does not
//! drop them. Entries for other builds are dropped.
//!
//! XML is emitted directly via small writers rather than full DOM
//! construction; the documents are short and we keep dependencies minimal.
//! The values come from the lockfile and from the destination file, which
//! any local process may have written, so every textual field is
//! XML-escaped via [`xml_escape`] before being written.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use rv_maven_types::{Version, is_snapshot_timestamp};

use super::error::Result;

/// One entry in the `<snapshotVersions>` list inside a versioned
/// `maven-metadata-<id>.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapshotVersionEntry {
    pub extension: String,
    pub classifier: Option<String>,
    pub value: String,
    /// `YYYYMMDDHHMMSS` format used by Maven for `<updated>`/`<lastUpdated>`.
    pub updated: String,
}

/// Inputs required to generate a versioned snapshot metadata document.
#[derive(Debug, Clone)]
pub(crate) struct VersionedMetadata<'a> {
    pub group_id: &'a str,
    pub artifact_id: &'a str,
    pub base_snapshot_version: &'a str,
    /// `YYYYMMDD.HHMMSS`, the timestamp of the snapshot build.
    pub timestamp: &'a str,
    /// Maven build number for the snapshot (the `N` in `...-N`).
    pub build_number: u32,
    pub last_updated: &'a str,
    pub entries: Vec<SnapshotVersionEntry>,
}

fn element(out: &mut String, indent: usize, name: &str, value: &str) {
    let _ = writeln!(out, "{:indent$}<{name}>{}</{name}>", "", xml_escape(value));
}

const XML_DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n";

pub(crate) fn render_versioned_metadata(meta: &VersionedMetadata<'_>) -> String {
    let mut out = String::from(XML_DECLARATION);
    element(&mut out, 2, "groupId", meta.group_id);
    element(&mut out, 2, "artifactId", meta.artifact_id);
    element(&mut out, 2, "version", meta.base_snapshot_version);
    out.push_str("  <versioning>\n    <snapshot>\n");
    element(&mut out, 6, "timestamp", meta.timestamp);
    element(&mut out, 6, "buildNumber", &meta.build_number.to_string());
    out.push_str("    </snapshot>\n");
    element(&mut out, 4, "lastUpdated", meta.last_updated);
    out.push_str("    <snapshotVersions>\n");
    for entry in &meta.entries {
        out.push_str("      <snapshotVersion>\n");
        if let Some(classifier) = entry.classifier.as_deref() {
            element(&mut out, 8, "classifier", classifier);
        }
        element(&mut out, 8, "extension", &entry.extension);
        element(&mut out, 8, "value", &entry.value);
        element(&mut out, 8, "updated", &entry.updated);
        out.push_str("      </snapshotVersion>\n");
    }
    out.push_str("    </snapshotVersions>\n  </versioning>\n</metadata>\n");
    out
}

/// Inputs required to generate an artifact-level metadata document.
#[derive(Debug, Clone)]
pub(crate) struct ArtifactMetadata<'a> {
    pub group_id: &'a str,
    pub artifact_id: &'a str,
    pub latest: &'a str,
    pub release: Option<&'a str>,
    pub versions: Vec<String>,
    pub last_updated: &'a str,
}

/// Body of `maven-metadata-local.xml`.
pub(crate) fn render_artifact_metadata(meta: &ArtifactMetadata<'_>) -> String {
    let mut out = String::from(XML_DECLARATION);
    element(&mut out, 2, "groupId", meta.group_id);
    element(&mut out, 2, "artifactId", meta.artifact_id);
    out.push_str("  <versioning>\n");
    element(&mut out, 4, "latest", meta.latest);
    if let Some(release) = meta.release {
        element(&mut out, 4, "release", release);
    }
    out.push_str("    <versions>\n");
    for version in &meta.versions {
        element(&mut out, 6, "version", version);
    }
    out.push_str("    </versions>\n");
    element(&mut out, 4, "lastUpdated", meta.last_updated);
    out.push_str("  </versioning>\n</metadata>\n");
    out
}

/// Body of a `maven-metadata-<id>.xml` that lists nothing, at the artifact
/// level or, with `version`, a version's.
pub(crate) fn render_empty_metadata(
    group_id: &str,
    artifact_id: &str,
    version: Option<&str>,
) -> String {
    let mut out = String::from(XML_DECLARATION);
    element(&mut out, 2, "groupId", group_id);
    element(&mut out, 2, "artifactId", artifact_id);
    if let Some(version) = version {
        element(&mut out, 2, "version", version);
    }
    out.push_str("  <versioning>\n  </versioning>\n</metadata>\n");
    out
}

/// Convert a `YYYYMMDD.HHMMSS` timestamp into the `YYYYMMDDHHMMSS` form that
/// Maven uses for `<updated>` and `<lastUpdated>`.
pub(crate) fn compact_updated(timestamp: &str) -> Option<String> {
    is_snapshot_timestamp(timestamp).then(|| timestamp.replace('.', ""))
}

/// Minimal XML 1.0 attribute/text escaping via `quick_xml`, which is the
/// XML library we already use for parsing settings.xml. Wrapping it keeps
/// our XML emission consistent with our XML consumption.
fn xml_escape(s: &str) -> String {
    quick_xml::escape::escape(s).into_owned()
}

/// Atomically write `contents` to `dest`, creating parent directories as
/// needed, and say whether it wrote. A file that already holds `contents`
/// is left alone: rewriting it costs a sync per file on every repeated
/// export.
pub(crate) fn write_atomic(dest: &Path, contents: &str) -> Result<bool> {
    if read_regular_file(dest)
        .ok()
        .flatten()
        .is_some_and(|bytes| bytes == contents.as_bytes())
    {
        return Ok(false);
    }
    let parent = dest.parent().ok_or_else(|| {
        super::error::ExportError::IoError(io::Error::other("destination has no parent directory"))
    })?;
    fs::create_dir_all(parent)?;
    replace_file(dest, contents.as_bytes())?;
    Ok(true)
}

/// Replace `path` with `contents` through a temp file and a rename, so a
/// reader sees the old file or the new one. Nothing is synced: every export
/// compares these files with what they should hold and rewrites one a crash
/// left torn or missing, and a sync per sidecar, marker and metadata file
/// costs a first export on a disk about four syncs per artifact.
pub(crate) fn replace_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = rv_fs::temp_file_in(parent, rv_fs::NewFileAccess::Shared)?;
    io::Write::write_all(temp.as_file_mut(), contents)?;
    temp.persist(path).map_err(|err| err.error)?;
    Ok(())
}

/// The largest destination metadata file an export reads. Maven's own files
/// are a few kilobytes.
const MAX_EXISTING_METADATA_BYTES: u64 = 1 << 20;

/// What a metadata file already in the destination lists.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ExistingMetadata {
    pub versions: Vec<String>,
    pub last_updated: Option<String>,
    pub snapshot_versions: Vec<SnapshotVersionEntry>,
}

#[derive(serde::Deserialize)]
struct MetadataXml {
    versioning: Option<VersioningXml>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersioningXml {
    versions: Option<VersionsXml>,
    last_updated: Option<String>,
    snapshot_versions: Option<SnapshotVersionsXml>,
}

#[derive(serde::Deserialize)]
struct VersionsXml {
    #[serde(default)]
    version: Vec<String>,
}

#[derive(serde::Deserialize)]
struct SnapshotVersionsXml {
    #[serde(default, rename = "snapshotVersion")]
    snapshot_version: Vec<SnapshotVersionXml>,
}

#[derive(serde::Deserialize)]
struct SnapshotVersionXml {
    classifier: Option<String>,
    extension: Option<String>,
    value: Option<String>,
    updated: Option<String>,
}

/// Read the metadata file at `path`. A missing file lists nothing, and so
/// does anything but a regular file (a link is not followed), a file that
/// cannot be read, is larger than [`MAX_EXISTING_METADATA_BYTES`], is not
/// UTF-8 or does not parse as Maven metadata: the export replaces it, as
/// `mvn install` replaces local metadata it cannot read.
pub(crate) fn read_existing_metadata(path: &Path) -> ExistingMetadata {
    read_regular_file(path)
        .ok()
        .flatten()
        .map(|bytes| parse_existing_metadata(&bytes))
        .unwrap_or_default()
}

/// The text of the regular file at `path`, `None` when it is missing, not a
/// regular file, unreadable, too large or not UTF-8.
pub(crate) fn read_regular_text(path: &Path) -> Option<String> {
    String::from_utf8(read_regular_file(path).ok()??).ok()
}

fn read_regular_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    // A FIFO already at the name is not opened, so no writer on it wakes.
    if !fs::symlink_metadata(path)?.is_file() {
        return Ok(None);
    }
    let Some(file) = rv_store::open_unfollowed_regular(path)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(MAX_EXISTING_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= MAX_EXISTING_METADATA_BYTES).then_some(bytes))
}

fn parse_existing_metadata(bytes: &[u8]) -> ExistingMetadata {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return ExistingMetadata::default();
    };
    let Ok(MetadataXml {
        versioning: Some(versioning),
    }) = quick_xml::de::from_str::<MetadataXml>(text)
    else {
        return ExistingMetadata::default();
    };
    // A control character or a noncharacter such as U+FFFE, which a
    // character reference can carry, cannot be written back as XML 1.0, so
    // such a value is dropped.
    let non_empty = |value: Option<String>| {
        value.map(|v| v.trim().to_string()).filter(|v| {
            !v.is_empty()
                && !v
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '\u{FFFE}' | '\u{FFFF}'))
        })
    };
    ExistingMetadata {
        versions: versioning
            .versions
            .map(|versions| versions.version)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|version| non_empty(Some(version)))
            .collect(),
        last_updated: non_empty(versioning.last_updated),
        snapshot_versions: versioning
            .snapshot_versions
            .map(|entries| entries.snapshot_version)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|entry| {
                Some(SnapshotVersionEntry {
                    extension: non_empty(entry.extension)?,
                    classifier: non_empty(entry.classifier),
                    value: non_empty(entry.value)?,
                    updated: non_empty(entry.updated).unwrap_or_default(),
                })
            })
            .collect(),
    }
}

/// `entries` followed by the `existing` entries for a classifier and
/// extension `entries` does not cover, when those existing entries share a
/// `value` this export already listed. The entries being exported win.
/// Existing rows for other timestamped builds are dropped.
pub(crate) fn merge_snapshot_entries(
    entries: &[SnapshotVersionEntry],
    existing: Vec<SnapshotVersionEntry>,
) -> Vec<SnapshotVersionEntry> {
    let values: HashSet<&str> = entries.iter().map(|entry| entry.value.as_str()).collect();
    let mut listed: HashSet<(Option<String>, String)> = entries
        .iter()
        .map(|entry| (entry.classifier.clone(), entry.extension.clone()))
        .collect();
    let mut merged = entries.to_vec();
    for entry in existing {
        if !values.contains(entry.value.as_str()) {
            continue;
        }
        if listed.insert((entry.classifier.clone(), entry.extension.clone())) {
            merged.push(entry);
        }
    }
    merged
}

pub(crate) fn later_stamp(ours: String, existing: Option<String>) -> String {
    match existing {
        Some(existing)
            if existing.len() == 14
                && existing.bytes().all(|b| b.is_ascii_digit())
                && existing > ours =>
        {
            existing
        }
        _ => ours,
    }
}

/// Group key for snapshot metadata aggregation: same group/artifact/base
/// version and repository id share a single `maven-metadata-<id>.xml`.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub(crate) struct SnapshotMetaKey {
    pub group_id: String,
    pub artifact_id: String,
    pub base_version: String,
    pub repo_id: String,
}

/// Group key for artifact-level metadata.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub(crate) struct ArtifactMetaKey {
    pub group_id: String,
    pub artifact_id: String,
}

/// Accumulator that collects per-key entries while iterating lockfile
/// packages, so the exporter can emit one metadata file per logical group.
#[derive(Debug, Default)]
pub(crate) struct MetadataAccumulator {
    /// Snapshot metadata indexed by (group, artifact, base-version).
    pub snapshots: BTreeMap<SnapshotMetaKey, SnapshotMetaState>,
    /// Versions locked per (group, artifact), by the id of the repository
    /// that serves them.
    pub artifacts: BTreeMap<ArtifactMetaKey, BTreeMap<String, ArtifactMetaState>>,
    /// The (group, artifact, `-SNAPSHOT` version) directories that get a
    /// plain `-SNAPSHOT` file whose build the lock does not name.
    pub plain_snapshots: BTreeSet<(String, String, String)>,
    pub replaces_listings: bool,
    /// The ids, `local` among them, that get a version list naming nothing
    /// wherever the lock takes no version from them, so that `mvn -o` does
    /// not read a tail repository's list instead. Empty in the shared
    /// repository.
    pub empty_list_ids: BTreeSet<String>,
    /// The destination is the shared Maven local repository: see
    /// [`crate::ExportOptions::shared`].
    pub shared: bool,
}

#[derive(Debug, Default)]
pub(crate) struct SnapshotMetaState {
    pub timestamp: Option<String>,
    pub build_number: Option<u32>,
    pub last_updated: Option<String>,
    pub entries: Vec<SnapshotVersionEntry>,
    /// Whether the version reads the base `-SNAPSHOT.pom`, which no entry
    /// may name.
    pub pom_base: bool,
}

/// Per-artifact state used to render `<groupId>/<artifactId>/maven-metadata-<id>.xml`.
///
/// The raw strings are rendered verbatim, ordered by Maven's version
/// comparison rather than as text, under which `9.0.0` sorts after `10.0.0`.
#[derive(Debug, Default)]
pub(crate) struct ArtifactMetaState {
    versions: Vec<(Version, String)>,
    listed: HashSet<String>,
    pub last_updated: Option<String>,
}

impl ArtifactMetaState {
    pub(crate) fn add_version(&mut self, version: &str) {
        if !self.listed.insert(version.to_string()) {
            return;
        }
        // A version that does not parse still gets listed, sorted as `0`.
        let parsed = Version::parse(version)
            .or_else(|_| Version::parse("0"))
            .expect("0 parses as a fallback");
        self.versions.push((parsed, version.to_string()));
    }

    /// Sort the versions in ascending Maven order, once, before rendering.
    pub(crate) fn finalize(&mut self) {
        Version::sort_by_key(&mut self.versions, |(version, _)| version);
    }

    pub(crate) fn versions(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.versions.iter().map(|(_, version)| version.as_str())
    }

    /// Maven's `<latest>`. Assumes [`Self::finalize`] has been called.
    pub(crate) fn latest(&self) -> Option<&str> {
        self.versions().next_back()
    }

    /// Maven's `<release>`: the greatest non-SNAPSHOT version. Assumes
    /// [`Self::finalize`] has been called.
    pub(crate) fn release(&self) -> Option<&str> {
        self.versions()
            .rev()
            .find(|v| !rv_maven_types::is_snapshot_version(v))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }
}

/// Accumulates the `_remote.repositories` tracking entries Maven Resolver
/// expects next to every artifact it has materialized in the local
/// repository.
///
/// Maven Resolver (the engine behind `mvn -o`) writes one
/// `_remote.repositories` file per version directory. The file is a Java
/// `.properties` document; each materialized filename gets a line of the
/// form `<filename>><repository-id>=` (the value is always empty). Strict
/// offline resolution consults these markers to decide whether an artifact
/// is considered "available" from the repositories the build is allowed to
/// use; without them `mvn -o` treats freshly-dropped files as not resolvable
/// and fails. See the comment header Maven itself writes into the file.
#[derive(Debug, Default)]
pub(crate) struct RemoteRepositoriesAccumulator {
    /// Version directory -> set of `(filename, repository-id)` entries.
    dirs: BTreeMap<PathBuf, BTreeSet<(String, String)>>,
}

impl RemoteRepositoriesAccumulator {
    /// Record that `filename` was materialized into `dir`, sourced from the
    /// repository identified by `repo_id`. Maven uses `central` as the
    /// canonical id for Maven Central; callers default to it when the
    /// lockfile's repo URL doesn't map to a configured repository.
    pub(crate) fn record(&mut self, dir: &Path, filename: &str, repo_id: &str) {
        self.dirs
            .entry(dir.to_path_buf())
            .or_default()
            .insert((filename.to_string(), repo_id.to_string()));
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.dirs.is_empty()
    }

    /// Write a `_remote.repositories` file into each recorded directory,
    /// MERGING with any entries already on disk.
    ///
    /// As Maven does, a file keeps an entry for every repository id it was
    /// recorded under: a second export pass (e.g. `--with-sources` after the
    /// main jars), or another project's export that reaches the same file
    /// through another repository, adds its entries and drops none, since
    /// strict `mvn -o` refuses a file whose entries do not name one of the
    /// build's repositories. A file whose entries are all there already is
    /// not rewritten.
    pub(crate) fn write_all(&self) -> Result<()> {
        for (dir, entries) in &self.dirs {
            let dest = dir.join("_remote.repositories");
            let existing = match read_regular_file(&dest) {
                Ok(bytes) => bytes.and_then(|bytes| String::from_utf8(bytes).ok()),
                Err(err) if err.kind() == io::ErrorKind::NotFound => None,
                Err(err) => return Err(err.into()),
            };
            let existing = existing.map(|text| parse_remote_repositories(&text));
            if existing
                .as_ref()
                .is_some_and(|existing| entries.is_subset(existing))
            {
                continue;
            }
            let mut merged = existing.unwrap_or_default();
            merged.extend(entries.iter().cloned());
            write_atomic(&dest, &render_remote_repositories(&merged))?;
        }
        Ok(())
    }
}

/// Parse a `_remote.repositories` file back into its `(filename,
/// repository-id)` entries. Inverse of [`render_remote_repositories`]; used to
/// merge a fresh export pass with markers already on disk. Comment and blank
/// lines are skipped; unparseable lines are ignored rather than aborting an
/// export over a hand-edited or foreign file.
pub(crate) fn parse_remote_repositories(contents: &str) -> BTreeSet<(String, String)> {
    let mut entries = BTreeSet::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `<escaped-filename>><repo-id>=`. The repo-id never contains `>`
        // (and `>` is escaped inside the filename), so the LAST `>` is the
        // separator; the trailing `=` carries the always-empty value.
        let Some(body) = line.strip_suffix('=') else {
            continue;
        };
        let Some(sep) = body.rfind('>') else {
            continue;
        };
        let filename = unescape_properties_key(&body[..sep]);
        let repo_id = unescape_properties_key(&body[sep + 1..]);
        if !filename.is_empty() {
            entries.insert((filename, repo_id));
        }
    }
    entries
}

/// Inverse of [`escape_properties_key`]: undo `java.util.Properties` key
/// escaping so a parsed filename round-trips exactly.
fn unescape_properties_key(key: &str) -> String {
    // UTF-16 units, as a `\uXXXX` escape names one and a pair of them
    // names a character outside the Basic Multilingual Plane.
    let mut out: Vec<u16> = Vec::with_capacity(key.len());
    let mut chars = key.chars();
    while let Some(ch) = chars.next() {
        let ch = if ch == '\\' {
            match chars.next() {
                Some('t') => '\t',
                Some('n') => '\n',
                Some('r') => '\r',
                Some('f') => '\u{c}',
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    match u16::from_str_radix(&hex, 16) {
                        Ok(unit) if hex.len() == 4 => out.push(unit),
                        _ => out.extend(format!("\\u{hex}").encode_utf16()),
                    }
                    continue;
                }
                // `\\`, `\=`, `\:`, `\>`, `\ ` all map to the literal char.
                Some(other) => other,
                None => '\\',
            }
        } else {
            ch
        };
        out.extend_from_slice(ch.encode_utf16(&mut [0; 2]));
    }
    String::from_utf16_lossy(&out)
}

/// Render the body of a `_remote.repositories` file from the `(filename,
/// repository-id)` entries collected for a single version directory.
///
/// The output mirrors what Maven Resolver's `TrackingFileManager` produces:
/// a `.properties` document opened by a fixed NOTE comment, a date comment,
/// then one `<filename>><repo-id>=` line per file. We sort the entries so
/// the output is deterministic (Java's `Properties.store` does not, but a
/// stable file keeps re-exports idempotent and tests simple).
pub(crate) fn render_remote_repositories(entries: &BTreeSet<(String, String)>) -> String {
    let mut out = String::with_capacity(128 + entries.len() * 48);
    out.push_str(
        "#NOTE: This is a Maven Resolver internal implementation file, \
its format can be changed without prior notice.\n",
    );
    // A timestamp comment matches Maven's own output. The value is purely
    // informational (Maven ignores it on read), so a stable UTC stamp keeps
    // re-exports byte-identical instead of churning on every run.
    out.push_str("#Thu Jan 01 00:00:00 UTC 1970\n");
    for (filename, repo_id) in entries {
        let _ = writeln!(
            out,
            "{}>{}=",
            escape_properties_key(filename),
            escape_properties_key(repo_id)
        );
    }
    out
}

/// Escape a filename or repository id the way `java.util.Properties`
/// stores a key: Maven allows `=` and spaces in an id, and reads the file
/// as ISO-8859-1, so anything outside printable ASCII is a `\uXXXX`
/// escape. `>` is escaped too, so the separator stays the last one.
fn escape_properties_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for ch in key.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '=' | ':' | '#' | '!' | '>' | ' ' => {
                out.push('\\');
                out.push(ch);
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            other => {
                for unit in other.encode_utf16(&mut [0; 2]) {
                    let _ = write!(out, "\\u{unit:04X}");
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap_entry(extension: &str, classifier: Option<&str>, value: &str) -> SnapshotVersionEntry {
        SnapshotVersionEntry {
            extension: extension.to_string(),
            classifier: classifier.map(str::to_string),
            value: value.to_string(),
            updated: "20240101010101".to_string(),
        }
    }

    #[test]
    fn merge_snapshot_entries_keeps_same_build_and_drops_other_builds() {
        let current = "1.0-20240101.010101-7";
        let older = "1.0-20230101.010101-1";
        let exported = [snap_entry("jar", None, current)];
        let existing = vec![
            snap_entry("jar", Some("sources"), current),
            snap_entry("jar", Some("javadoc"), older),
            snap_entry("pom", None, older),
        ];
        let merged = merge_snapshot_entries(&exported, existing);
        assert_eq!(
            merged,
            vec![
                snap_entry("jar", None, current),
                snap_entry("jar", Some("sources"), current),
            ]
        );
    }

    #[test]
    fn compact_updated_strips_dot() {
        assert_eq!(
            compact_updated("20240101.010101").as_deref(),
            Some("20240101010101")
        );
        assert!(compact_updated("not-a-stamp").is_none());
    }

    #[test]
    fn xml_escape_handles_specials() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn versioned_metadata_round_trip_shape() {
        let xml = render_versioned_metadata(&VersionedMetadata {
            group_id: "com.example",
            artifact_id: "foo",
            base_snapshot_version: "1.0-SNAPSHOT",
            timestamp: "20240101.010101",
            build_number: 7,
            last_updated: "20240101010101",
            entries: vec![
                SnapshotVersionEntry {
                    extension: "jar".to_string(),
                    classifier: None,
                    value: "1.0-20240101.010101-7".to_string(),
                    updated: "20240101010101".to_string(),
                },
                SnapshotVersionEntry {
                    extension: "jar".to_string(),
                    classifier: Some("sources".to_string()),
                    value: "1.0-20240101.010101-7".to_string(),
                    updated: "20240101010101".to_string(),
                },
            ],
        });

        assert!(xml.contains("<groupId>com.example</groupId>"));
        assert!(xml.contains("<artifactId>foo</artifactId>"));
        assert!(xml.contains("<version>1.0-SNAPSHOT</version>"));
        assert!(xml.contains("<timestamp>20240101.010101</timestamp>"));
        assert!(xml.contains("<buildNumber>7</buildNumber>"));
        assert!(!xml.contains("localCopy"));
        assert!(xml.contains("<lastUpdated>20240101010101</lastUpdated>"));
        assert!(xml.contains("<classifier>sources</classifier>"));
        assert!(xml.contains("<extension>jar</extension>"));
        assert!(xml.contains("<value>1.0-20240101.010101-7</value>"));
    }

    #[test]
    fn artifact_metadata_lists_versions() {
        let xml = render_artifact_metadata(&ArtifactMetadata {
            group_id: "com.example",
            artifact_id: "foo",
            latest: "1.0-SNAPSHOT",
            release: Some("1.0"),
            versions: vec!["1.0".to_string(), "1.0-SNAPSHOT".to_string()],
            last_updated: "20240101010101",
        });

        assert!(xml.contains("<latest>1.0-SNAPSHOT</latest>"));
        assert!(xml.contains("<release>1.0</release>"));
        assert!(xml.contains("<version>1.0</version>"));
        assert!(xml.contains("<version>1.0-SNAPSHOT</version>"));
    }

    #[test]
    fn versioned_metadata_xml_parses_with_quick_xml() {
        // Use quick-xml (already a workspace dep) to verify the emitted XML
        // is well-formed and the expected element values are reachable.
        use quick_xml::Reader;
        use quick_xml::escape::unescape;
        use quick_xml::events::Event;

        let xml = render_versioned_metadata(&VersionedMetadata {
            group_id: "com.example",
            artifact_id: "foo",
            base_snapshot_version: "1.0-SNAPSHOT",
            timestamp: "20240101.010101",
            build_number: 7,
            last_updated: "20240101010101",
            entries: vec![SnapshotVersionEntry {
                extension: "jar".to_string(),
                classifier: None,
                value: "1.0-20240101.010101-7".to_string(),
                updated: "20240101010101".to_string(),
            }],
        });

        let mut reader = Reader::from_str(&xml);
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();
        let mut saw_timestamp = false;
        let mut saw_build = false;
        let mut current_tag: Option<String> = None;
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    current_tag = Some(String::from_utf8_lossy(e.name().as_ref()).into_owned());
                }
                Ok(Event::Text(t)) => {
                    if let Some(name) = current_tag.as_deref() {
                        let raw = String::from_utf8_lossy(t.as_ref());
                        let text = unescape(&raw).unwrap().into_owned();
                        if name == "timestamp" && text == "20240101.010101" {
                            saw_timestamp = true;
                        }
                        if name == "buildNumber" && text == "7" {
                            saw_build = true;
                        }
                    }
                }
                Ok(Event::End(_)) => current_tag = None,
                Ok(Event::Eof) => break,
                Err(e) => panic!("xml parse error: {e}"),
                _ => {}
            }
            buf.clear();
        }
        assert!(saw_timestamp);
        assert!(saw_build);
    }

    #[test]
    fn remote_repositories_render_matches_maven_resolver_format() {
        let mut entries = BTreeSet::new();
        entries.insert(("demo-1.0.0.jar".to_string(), "central".to_string()));
        entries.insert(("demo-1.0.0.pom".to_string(), "central".to_string()));
        let body = render_remote_repositories(&entries);

        // Opens with Maven's NOTE comment and a date comment, then one
        // `<filename>><repo-id>=` line per file (sorted, value empty).
        let mut lines = body.lines();
        assert_eq!(
            lines.next().unwrap(),
            "#NOTE: This is a Maven Resolver internal implementation file, \
its format can be changed without prior notice."
        );
        assert!(
            lines.next().unwrap().starts_with('#'),
            "second line must be the date comment"
        );
        assert_eq!(lines.next().unwrap(), "demo-1.0.0.jar>central=");
        assert_eq!(lines.next().unwrap(), "demo-1.0.0.pom>central=");
        assert!(lines.next().is_none());
    }

    #[test]
    fn remote_repositories_render_is_deterministic() {
        // Same inputs in different insertion order must produce identical
        // output so re-exports are idempotent.
        let mut a = BTreeSet::new();
        a.insert(("z.jar".to_string(), "central".to_string()));
        a.insert(("a.pom".to_string(), "central".to_string()));
        let mut b = BTreeSet::new();
        b.insert(("a.pom".to_string(), "central".to_string()));
        b.insert(("z.jar".to_string(), "central".to_string()));
        assert_eq!(
            render_remote_repositories(&a),
            render_remote_repositories(&b)
        );
    }

    #[test]
    fn remote_repositories_render_honours_repo_id() {
        let mut entries = BTreeSet::new();
        entries.insert(("lib-2.0.jar".to_string(), "corp".to_string()));
        let body = render_remote_repositories(&entries);
        assert!(body.contains("lib-2.0.jar>corp="));
    }

    #[test]
    fn properties_key_escaping_guards_structural_chars() {
        // Realistic filenames never contain these, but a hostile coordinate
        // must not be able to break out of the `.properties` key.
        assert_eq!(escape_properties_key("a=b"), "a\\=b");
        assert_eq!(escape_properties_key("a:b"), "a\\:b");
        assert_eq!(escape_properties_key("a>b"), "a\\>b");
        assert_eq!(escape_properties_key("a\\b"), "a\\\\b");
        assert_eq!(escape_properties_key("a b"), "a\\ b");
        assert_eq!(escape_properties_key("demo-1.0.0.jar"), "demo-1.0.0.jar");
    }

    #[test]
    fn remote_repositories_round_trips_through_parse() {
        let mut entries = BTreeSet::new();
        entries.insert(("demo-1.0.0.jar".to_string(), "central".to_string()));
        entries.insert(("demo-1.0.0.pom".to_string(), "central".to_string()));
        // Structural chars in the key must survive the escape -> render ->
        // parse -> unescape round trip.
        entries.insert(("weird>name=1.0.jar".to_string(), "corp".to_string()));
        let rendered = render_remote_repositories(&entries);
        assert_eq!(parse_remote_repositories(&rendered), entries);
    }

    /// The clobber regression: a second pass over the same version directory
    /// (the `--with-sources` case, or a later export-m2 run) must MERGE with
    /// the existing markers, not replace them and drop the main jar's entry.
    #[test]
    fn write_all_merges_with_existing_markers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vdir = dir.path().join("v");

        // Pass 1: main jar + pom.
        let mut first = RemoteRepositoriesAccumulator::default();
        first.record(&vdir, "demo-1.0.jar", "central");
        first.record(&vdir, "demo-1.0.pom", "central");
        first.write_all().expect("write pass 1");

        // Pass 2 (e.g. --with-sources): only the sources jar.
        let mut second = RemoteRepositoriesAccumulator::default();
        second.record(&vdir, "demo-1.0-sources.jar", "central");
        second.write_all().expect("write pass 2");

        let body = fs::read_to_string(vdir.join("_remote.repositories")).expect("read merged");
        assert!(
            body.contains("demo-1.0.jar>central="),
            "main jar marker must survive the second pass: {body}"
        );
        assert!(
            body.contains("demo-1.0.pom>central="),
            "pom marker must survive the second pass: {body}"
        );
        assert!(
            body.contains("demo-1.0-sources.jar>central="),
            "sources marker must be added: {body}"
        );
    }

    /// A file reached through two repository ids keeps an entry for each,
    /// as Maven records them: dropping one fails the `mvn -o` of a project
    /// that names only that repository.
    #[test]
    fn write_all_keeps_every_repository_of_a_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vdir = dir.path().join("v");
        for id in ["other", "probe"] {
            let mut pass = RemoteRepositoriesAccumulator::default();
            pass.record(&vdir, "a-1.0.jar", id);
            pass.write_all().expect("write");
        }
        let body = fs::read_to_string(vdir.join("_remote.repositories")).expect("read");
        assert!(body.contains("a-1.0.jar>other="), "{body}");
        assert!(body.contains("a-1.0.jar>probe="), "{body}");
    }

    /// A repository id is escaped as `java.util.Properties` stores a key,
    /// since Maven allows `=` and spaces in one, and an entry Maven wrote
    /// that way reads back as the id it names.
    #[test]
    fn remote_repositories_escape_ids_as_java_properties() {
        let entries: BTreeSet<(String, String)> = [
            ("lib-1.pom", "corp=releases"),
            ("lib-1.pom", "my repo"),
            ("lib-1.jar", "d\u{e9}p\u{f4}t"),
            ("lib-1.jar", "\u{1F600}"),
        ]
        .into_iter()
        .map(|(file, id)| (file.to_string(), id.to_string()))
        .collect();
        let body = render_remote_repositories(&entries);
        for line in [
            "lib-1.pom>corp\\=releases=",
            "lib-1.pom>my\\ repo=",
            "lib-1.jar>d\\u00E9p\\u00F4t=",
            "lib-1.jar>\\uD83D\\uDE00=",
        ] {
            assert!(
                body.lines().any(|written| written == line),
                "{line} in {body}"
            );
        }
        assert_eq!(parse_remote_repositories(&body), entries);
    }

    #[test]
    fn remote_repositories_accumulator_writes_one_file_per_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_a = dir.path().join("a");
        let dir_b = dir.path().join("b");
        let mut acc = RemoteRepositoriesAccumulator::default();
        assert!(acc.is_empty());
        acc.record(&dir_a, "x-1.0.jar", "central");
        acc.record(&dir_a, "x-1.0.pom", "central");
        acc.record(&dir_b, "y-2.0.pom", "corp");
        assert!(!acc.is_empty());
        acc.write_all().expect("write markers");

        let a = fs::read_to_string(dir_a.join("_remote.repositories")).expect("read a");
        assert!(a.contains("x-1.0.jar>central="));
        assert!(a.contains("x-1.0.pom>central="));
        let b = fs::read_to_string(dir_b.join("_remote.repositories")).expect("read b");
        assert!(b.contains("y-2.0.pom>corp="));
        assert!(!b.contains("central"));
    }

    /// A destination file export cannot read lists nothing, so the export
    /// replaces it rather than failing.
    #[test]
    fn unreadable_destination_metadata_lists_nothing() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("maven-metadata-local.xml");
        let listing = |contents: &[u8]| {
            fs::write(&path, contents).expect("write");
            read_existing_metadata(&path)
        };
        assert_eq!(listing(b"\xff\xfe<metadata>"), ExistingMetadata::default());
        assert_eq!(
            listing(b"<metadata><versioning>"),
            ExistingMetadata::default()
        );
        assert_eq!(
            listing(
                b"<metadata><versioning><versions><version>a&#1;b</version>\
                  <version>c&#xFFFE;</version><version>2</version></versions>\
                  </versioning></metadata>"
            )
            .versions,
            ["2"]
        );
        let mut oversized = b"<metadata><versioning><versions><version>1</version>".to_vec();
        oversized.resize(MAX_EXISTING_METADATA_BYTES as usize + 1, b' ');
        assert_eq!(listing(&oversized), ExistingMetadata::default());
        assert_eq!(
            read_existing_metadata(&dir.path().join("absent.xml")),
            ExistingMetadata::default()
        );
        #[cfg(unix)]
        {
            let target = dir.path().join("elsewhere.xml");
            fs::write(
                &target,
                "<metadata><versioning><versions><version>9</version></versions>\
                 </versioning></metadata>",
            )
            .expect("target");
            assert_eq!(read_existing_metadata(&target).versions, ["9"]);
            let link = dir.path().join("link.xml");
            std::os::unix::fs::symlink(&target, &link).expect("symlink");
            assert_eq!(read_existing_metadata(&link), ExistingMetadata::default());

            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o000)).expect("chmod");
            // Root reads the file anyway.
            if fs::File::open(&target).is_err() {
                assert_eq!(read_existing_metadata(&target), ExistingMetadata::default());
            }
        }
    }

    #[test]
    fn a_link_swapped_in_after_the_type_check_is_refused() {
        let dir = tempfile::tempdir().expect("dir");
        let target = dir.path().join("target.xml");
        fs::write(&target, "<metadata/>").expect("target");
        let link = dir.path().join("maven-metadata-local.xml");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        #[cfg(windows)]
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            // Creating a symbolic link needs Developer Mode or the privilege.
            return;
        }
        assert!(read_regular_file(&link).expect("read").is_none());
        // What the open does with a link that appears after the type check.
        let opened = rv_store::open_unfollowed_regular(&link);
        assert!(!matches!(opened, Ok(Some(_))), "{opened:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_metadata_fifo_is_not_opened() {
        use std::time::Duration;
        let dir = tempfile::tempdir().expect("dir");
        let fifo = dir.path().join("maven-metadata-local.xml");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !made.is_ok_and(|status| status.success()) {
            return;
        }
        let (opened, writer_opened) = std::sync::mpsc::channel();
        let writer_path = fifo.clone();
        let writer = std::thread::spawn(move || {
            let file = fs::OpenOptions::new().write(true).open(&writer_path);
            opened.send(()).expect("send");
            file
        });
        // Let the writer block in its open, waiting for a reader.
        std::thread::sleep(Duration::from_millis(100));
        assert!(read_regular_file(&fifo).expect("read").is_none());
        assert!(
            writer_opened
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        let _reader = fs::File::open(&fifo).expect("reader");
        writer.join().expect("writer").expect("writer open");
    }

    #[test]
    fn the_later_stamp_wins_and_a_malformed_one_loses() {
        let ours = || "20240101000000".to_string();
        assert_eq!(
            later_stamp(ours(), Some("20250101000000".into())),
            "20250101000000"
        );
        assert_eq!(later_stamp(ours(), Some("20230101000000".into())), ours());
        assert_eq!(later_stamp(ours(), Some("99999999999999x".into())), ours());
        assert_eq!(later_stamp(ours(), Some("2025".into())), ours());
        assert_eq!(later_stamp(ours(), None), ours());
    }
}
