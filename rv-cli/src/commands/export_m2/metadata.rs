//! Generates `maven-metadata-local.xml` files for the Maven local repository
//! layout used by `mvn -o`.
//!
//! Two files are written per snapshot artifact group:
//!
//! 1. `<groupId>/<artifactId>/<base-snapshot-version>/maven-metadata-local.xml`
//!    pins the timestamp/buildNumber that Maven offline mode resolves to.
//! 2. `<groupId>/<artifactId>/maven-metadata-local.xml` lists the locked
//!    versions available offline (a single version per coordinate is
//!    sufficient for the offline use case).
//!
//! XML is emitted directly via small writers rather than full DOM
//! construction; the documents are short, every value we write originates
//! from the lockfile (already sanity-checked), and we keep dependencies
//! minimal. All textual fields are XML-escaped via [`xml_escape`] before
//! being written.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

use rv_version::Version;

use super::error::Result;

/// One entry in the `<snapshotVersions>` list inside a versioned
/// `maven-metadata-local.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapshotVersionEntry {
    pub extension: String,
    pub classifier: Option<String>,
    /// The full timestamped version string, e.g. `1.0-20240101.010101-7`.
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
    /// `YYYYMMDD.HHMMSS` (as stored by `LockPackage::snapshot_timestamp`).
    pub timestamp: &'a str,
    /// Maven build number for the snapshot (the `N` in `...-N`).
    pub build_number: u32,
    /// `YYYYMMDDHHMMSS` last-updated value.
    pub last_updated: &'a str,
    /// One entry per packaging/classifier covered by this snapshot.
    pub entries: Vec<SnapshotVersionEntry>,
}

/// Render the versioned snapshot metadata XML.
pub(crate) fn render_versioned_metadata(meta: &VersionedMetadata<'_>) -> String {
    let mut out = String::with_capacity(512);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<metadata>\n");
    let _ = writeln!(out, "  <groupId>{}</groupId>", xml_escape(meta.group_id));
    let _ = writeln!(
        out,
        "  <artifactId>{}</artifactId>",
        xml_escape(meta.artifact_id)
    );
    let _ = writeln!(
        out,
        "  <version>{}</version>",
        xml_escape(meta.base_snapshot_version)
    );
    out.push_str("  <versioning>\n");
    out.push_str("    <snapshot>\n");
    let _ = writeln!(
        out,
        "      <timestamp>{}</timestamp>",
        xml_escape(meta.timestamp)
    );
    let _ = writeln!(
        out,
        "      <buildNumber>{}</buildNumber>",
        meta.build_number
    );
    out.push_str("      <localCopy>true</localCopy>\n");
    out.push_str("    </snapshot>\n");
    let _ = writeln!(
        out,
        "    <lastUpdated>{}</lastUpdated>",
        xml_escape(meta.last_updated)
    );
    out.push_str("    <snapshotVersions>\n");
    for entry in &meta.entries {
        out.push_str("      <snapshotVersion>\n");
        if let Some(classifier) = entry.classifier.as_deref() {
            let _ = writeln!(
                out,
                "        <classifier>{}</classifier>",
                xml_escape(classifier)
            );
        }
        let _ = writeln!(
            out,
            "        <extension>{}</extension>",
            xml_escape(&entry.extension)
        );
        let _ = writeln!(out, "        <value>{}</value>", xml_escape(&entry.value));
        let _ = writeln!(
            out,
            "        <updated>{}</updated>",
            xml_escape(&entry.updated)
        );
        out.push_str("      </snapshotVersion>\n");
    }
    out.push_str("    </snapshotVersions>\n");
    out.push_str("  </versioning>\n");
    out.push_str("</metadata>\n");
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

/// Render the artifact-level `maven-metadata-local.xml`.
pub(crate) fn render_artifact_metadata(meta: &ArtifactMetadata<'_>) -> String {
    let mut out = String::with_capacity(384);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<metadata>\n");
    let _ = writeln!(out, "  <groupId>{}</groupId>", xml_escape(meta.group_id));
    let _ = writeln!(
        out,
        "  <artifactId>{}</artifactId>",
        xml_escape(meta.artifact_id)
    );
    out.push_str("  <versioning>\n");
    let _ = writeln!(out, "    <latest>{}</latest>", xml_escape(meta.latest));
    if let Some(release) = meta.release {
        let _ = writeln!(out, "    <release>{}</release>", xml_escape(release));
    }
    out.push_str("    <versions>\n");
    for v in &meta.versions {
        let _ = writeln!(out, "      <version>{}</version>", xml_escape(v));
    }
    out.push_str("    </versions>\n");
    let _ = writeln!(
        out,
        "    <lastUpdated>{}</lastUpdated>",
        xml_escape(meta.last_updated)
    );
    out.push_str("  </versioning>\n");
    out.push_str("</metadata>\n");
    out
}

/// Parse the `snapshot_timestamp` field as recorded in the lockfile.
///
/// Accepts either:
/// * `YYYYMMDD.HHMMSS` (the form produced by `rv-resolver`), which returns
///   `(timestamp, None)`.
/// * `YYYYMMDD.HHMMSS-N` (the canonical Maven form), which returns
///   `(timestamp, Some(N))`.
///
/// Returns `None` if the value does not match either shape.
pub(crate) fn parse_snapshot_timestamp(raw: &str) -> Option<(String, Option<u32>)> {
    if let Some((ts, build)) = raw.split_once('-') {
        if is_timestamp(ts) {
            let build_number = build.parse::<u32>().ok()?;
            return Some((ts.to_string(), Some(build_number)));
        }
        return None;
    }
    if is_timestamp(raw) {
        return Some((raw.to_string(), None));
    }
    None
}

/// Extract the build number from a timestamped version like
/// `1.0-20240101.010101-7`. Returns None for non-timestamped versions.
pub(crate) fn build_number_from_version(version: &str) -> Option<u32> {
    let mut parts = version.rsplitn(3, '-');
    let build = parts.next()?;
    let timestamp = parts.next()?;
    let _base = parts.next()?;
    if !is_timestamp(timestamp) {
        return None;
    }
    build.parse::<u32>().ok()
}

/// Check whether `value` matches Maven's `YYYYMMDD.HHMMSS` snapshot stamp
/// and is a real calendar instant. Defers to `chrono` for the calendar
/// validity check so we reject `20240230.000000`, `20240101.250000`, etc.
fn is_timestamp(value: &str) -> bool {
    chrono::NaiveDateTime::parse_from_str(value, "%Y%m%d.%H%M%S").is_ok()
}

/// Convert a `YYYYMMDD.HHMMSS` timestamp into the `YYYYMMDDHHMMSS` form that
/// Maven uses for `<updated>` and `<lastUpdated>`.
pub(crate) fn compact_updated(timestamp: &str) -> Option<String> {
    chrono::NaiveDateTime::parse_from_str(timestamp, "%Y%m%d.%H%M%S")
        .ok()
        .map(|dt| dt.format("%Y%m%d%H%M%S").to_string())
}

/// Minimal XML 1.0 attribute/text escaping via `quick_xml`, which is the
/// XML library we already use for parsing settings.xml. Wrapping it keeps
/// our XML emission consistent with our XML consumption.
fn xml_escape(s: &str) -> String {
    quick_xml::escape::escape(s).into_owned()
}

/// Atomically write `contents` to `dest`, creating parent directories as
/// needed. Existing files are replaced. Routes through
/// `tempfile::NamedTempFile::persist` which handles the platform-correct
/// atomic-replace (on Windows that's `MoveFileEx(MOVEFILE_REPLACE_EXISTING)`
/// behind the scenes) and cleans up the temp file on error via `Drop`.
pub(crate) fn write_atomic(dest: &Path, contents: &str) -> Result<()> {
    let parent = dest.parent().ok_or_else(|| {
        super::error::ExportError::IoError(io::Error::other("destination has no parent directory"))
    })?;
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    // Crash-safe: write + sync_all on the temp file BEFORE persist so a
    // power loss between rename and data flush cannot publish a truncated
    // metadata file.
    temp.as_file_mut().write_all(contents.as_bytes())?;
    temp.as_file().sync_all()?;
    temp.persist(dest)
        .map_err(|e| super::error::ExportError::IoError(e.error))?;
    // Persist the rename itself: without an fsync on the parent dir, the new
    // name can be lost on power loss even though the data is durable.
    if let Ok(handle) = fs::File::open(parent) {
        let _ = handle.sync_all();
    }
    Ok(())
}

/// Group key for snapshot metadata aggregation: same group/artifact/base
/// version share a single `maven-metadata-local.xml`.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub(crate) struct SnapshotMetaKey {
    pub group_id: String,
    pub artifact_id: String,
    pub base_version: String,
}

/// Group key for artifact-level metadata: same group/artifact aggregate all
/// versions seen in the lockfile.
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
    /// Versions seen per (group, artifact), used for artifact-level metadata.
    pub artifacts: BTreeMap<ArtifactMetaKey, ArtifactMetaState>,
}

#[derive(Debug, Default)]
pub(crate) struct SnapshotMetaState {
    pub timestamp: Option<String>,
    pub build_number: Option<u32>,
    pub last_updated: Option<String>,
    pub entries: Vec<SnapshotVersionEntry>,
}

/// Per-artifact state used to render `<groupId>/<artifactId>/maven-metadata-local.xml`.
///
/// `versions` keeps the original strings so the rendered XML matches the
/// lockfile verbatim, while `parsed` holds the `rv_version::Version` form
/// used for ordering. Maven's `<latest>` and `<release>` are picked using
/// the parsed comparator, NOT lexicographic order. Under lexicographic order
/// `9.0.0` sorts greater than `10.0.0`.
#[derive(Debug, Default)]
pub(crate) struct ArtifactMetaState {
    /// Insertion-order-preserving distinct list of raw version strings.
    pub versions: Vec<String>,
    /// Parsed forms aligned 1:1 with `versions`. Held separately so we
    /// can re-sort cheaply without re-parsing.
    parsed: Vec<Version>,
    pub last_updated: Option<String>,
}

impl ArtifactMetaState {
    pub fn add_version(&mut self, version: &str) {
        if self.versions.iter().any(|v| v == version) {
            return;
        }
        // Versions that fail to parse (e.g. exotic vendor strings) still
        // get recorded but with a parse-zero sentinel so they don't
        // pollute `latest`. In practice every Maven coordinate parses;
        // this just keeps the function total.
        let parsed = Version::parse(version)
            .or_else(|_| Version::parse("0"))
            .expect("0 parses as a fallback");
        self.versions.push(version.to_string());
        self.parsed.push(parsed);
    }

    /// Sort the stored versions in ascending Maven order. Called once
    /// just before rendering so insertion order doesn't determine output
    /// order.
    fn sort(&mut self) {
        let mut indices: Vec<usize> = (0..self.versions.len()).collect();
        indices.sort_by(|&a, &b| self.parsed[a].cmp(&self.parsed[b]));
        let mut new_versions = Vec::with_capacity(self.versions.len());
        let mut new_parsed = Vec::with_capacity(self.parsed.len());
        for idx in indices {
            new_versions.push(std::mem::take(&mut self.versions[idx]));
            new_parsed.push(self.parsed[idx].clone());
        }
        self.versions = new_versions;
        self.parsed = new_parsed;
    }

    /// Return the Maven `<latest>` value. Assumes `finalize` has been
    /// called.
    pub fn latest(&self) -> Option<&str> {
        self.versions.last().map(String::as_str)
    }

    /// Return the Maven `<release>` value: the greatest non-SNAPSHOT
    /// version. Assumes `finalize` has been called.
    pub fn release(&self) -> Option<&str> {
        self.versions
            .iter()
            .rev()
            .find(|v| !v.ends_with("-SNAPSHOT"))
            .map(String::as_str)
    }

    /// Sort the versions in-place so callers (the renderer and
    /// `latest`/`release`) see a stable order.
    pub fn finalize(&mut self) {
        self.sort();
    }

    pub fn is_empty(&self) -> bool {
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
    dirs: BTreeMap<PathBuf, BTreeMap<String, String>>,
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
            .insert(filename.to_string(), repo_id.to_string());
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.dirs.is_empty()
    }

    /// Write a `_remote.repositories` file into each recorded directory,
    /// MERGING with any entries already on disk.
    ///
    /// `write_atomic` replaces the file wholesale, so without the merge a
    /// second export pass over the same version directory (e.g.
    /// `--with-sources` after the main jars, or a later `rv export-m2` run)
    /// would drop the markers written earlier, including the main jar's,
    /// which then breaks strict `mvn -o`. Merging makes every pass additive.
    pub(crate) fn write_all(&self) -> Result<()> {
        for (dir, entries) in &self.dirs {
            let dest = dir.join("_remote.repositories");
            let mut merged = match fs::read_to_string(&dest) {
                Ok(existing) => parse_remote_repositories(&existing),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
                Err(err) => return Err(err.into()),
            };
            for (filename, repo_id) in entries {
                merged.insert(filename.clone(), repo_id.clone());
            }
            let body = render_remote_repositories(&merged);
            write_atomic(&dest, &body)?;
        }
        Ok(())
    }
}

/// Parse a `_remote.repositories` file back into its `(filename ->
/// repository-id)` entries. Inverse of [`render_remote_repositories`]; used to
/// merge a fresh export pass with markers already on disk. Comment and blank
/// lines are skipped; unparseable lines are ignored rather than aborting an
/// export over a hand-edited or foreign file.
pub(crate) fn parse_remote_repositories(contents: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
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
        let repo_id = body[sep + 1..].to_string();
        if !filename.is_empty() {
            map.insert(filename, repo_id);
        }
    }
    map
}

/// Inverse of [`escape_properties_key`]: undo `java.util.Properties` key
/// escaping so a parsed filename round-trips exactly.
fn unescape_properties_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut chars = key.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                // `\\`, `\=`, `\:`, `\>`, `\ ` all map to the literal char.
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Render the body of a `_remote.repositories` file from the `(filename ->
/// repository-id)` entries collected for a single version directory.
///
/// The output mirrors what Maven Resolver's `TrackingFileManager` produces:
/// a `.properties` document opened by a fixed NOTE comment, a date comment,
/// then one `<filename>><repo-id>=` line per file. We sort the entries so
/// the output is deterministic (Java's `Properties.store` does not, but a
/// stable file keeps re-exports idempotent and tests simple).
pub(crate) fn render_remote_repositories(entries: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(128 + entries.len() * 48);
    out.push_str(
        "#NOTE: This is a Maven Resolver internal implementation file, \
its format can be changed without prior notice.\n",
    );
    // A timestamp comment matches Maven's own output. The value is purely
    // informational (Maven ignores it on read), so a stable UTC stamp keeps
    // re-exports byte-identical instead of churning on every run.
    let _ = writeln!(out, "#{}", properties_date_comment());
    for (filename, repo_id) in entries {
        let _ = writeln!(out, "{}>{}=", escape_properties_key(filename), repo_id);
    }
    out
}

/// Format the date comment line the way `java.util.Properties#store` does,
/// e.g. `Thu Jan 01 00:00:00 UTC 1970`. Maven never parses this line, so we
/// emit a fixed epoch stamp to keep exported files reproducible.
fn properties_date_comment() -> String {
    "Thu Jan 01 00:00:00 UTC 1970".to_string()
}

/// Escape a `.properties` key the way `java.util.Properties` does for the
/// characters that can appear in a Maven artifact filename. Backslashes are
/// the only realistic escape in practice (filenames otherwise contain only
/// `[A-Za-z0-9._-]`), but we also guard the structural `=`, `:`, `>` and
/// whitespace so a hostile coordinate can't break out of the key.
fn escape_properties_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for ch in key.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            ':' => out.push_str("\\:"),
            '>' => out.push_str("\\>"),
            ' ' => out.push_str("\\ "),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_timestamp_with_build_number() {
        let (ts, build) = parse_snapshot_timestamp("20240101.010101-7").unwrap();
        assert_eq!(ts, "20240101.010101");
        assert_eq!(build, Some(7));
    }

    #[test]
    fn parse_timestamp_without_build_number() {
        let (ts, build) = parse_snapshot_timestamp("20240101.010101").unwrap();
        assert_eq!(ts, "20240101.010101");
        assert_eq!(build, None);
    }

    #[test]
    fn parse_timestamp_rejects_garbage() {
        assert!(parse_snapshot_timestamp("not-a-timestamp").is_none());
        assert!(parse_snapshot_timestamp("20240101010101-7").is_none());
    }

    #[test]
    fn build_number_extracted_from_version() {
        assert_eq!(build_number_from_version("1.0-20240101.010101-7"), Some(7));
        assert_eq!(build_number_from_version("1.0-SNAPSHOT"), None);
        assert_eq!(build_number_from_version("1.0"), None);
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
        assert!(xml.contains("<localCopy>true</localCopy>"));
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
        let mut entries = BTreeMap::new();
        entries.insert("demo-1.0.0.jar".to_string(), "central".to_string());
        entries.insert("demo-1.0.0.pom".to_string(), "central".to_string());
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
        let mut a = BTreeMap::new();
        a.insert("z.jar".to_string(), "central".to_string());
        a.insert("a.pom".to_string(), "central".to_string());
        let mut b = BTreeMap::new();
        b.insert("a.pom".to_string(), "central".to_string());
        b.insert("z.jar".to_string(), "central".to_string());
        assert_eq!(
            render_remote_repositories(&a),
            render_remote_repositories(&b)
        );
    }

    #[test]
    fn remote_repositories_render_honours_repo_id() {
        let mut entries = BTreeMap::new();
        entries.insert("lib-2.0.jar".to_string(), "corp".to_string());
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
        let mut entries = BTreeMap::new();
        entries.insert("demo-1.0.0.jar".to_string(), "central".to_string());
        entries.insert("demo-1.0.0.pom".to_string(), "central".to_string());
        // Structural chars in the key must survive the escape -> render ->
        // parse -> unescape round trip.
        entries.insert("weird>name=1.0.jar".to_string(), "corp".to_string());
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
}
