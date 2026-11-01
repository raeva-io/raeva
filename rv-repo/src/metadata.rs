use serde::Deserialize;

use crate::error::{RepoError, Result};

/// A parsed `maven-metadata.xml`, either the artifact-level file that lists
/// versions or the version-level file of a `-SNAPSHOT` that names its
/// timestamped builds.
///
/// The values are server text and are not validated here; callers check a
/// version before they put it in a path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Metadata {
    /// `<version>`, present in version-level snapshot metadata.
    pub version: Option<String>,
    /// `<versioning><latest>`: the newest version, snapshots included.
    pub latest: Option<String>,
    /// `<versioning><release>`: the newest release version.
    pub release: Option<String>,
    /// `<versioning><versions>`, in document order. Empty when absent.
    pub versions: Vec<String>,
    /// `<versioning><lastUpdated>`, which picks among repositories'
    /// `<release>` and `<latest>`, and for legacy snapshot metadata.
    pub last_updated: Option<String>,
    /// `<versioning><snapshot>`: the timestamp and build number of the
    /// latest snapshot build.
    pub snapshot: Option<Snapshot>,
    /// `<versioning><snapshotVersions>`: the timestamped version of each
    /// classifier and extension. Empty when absent.
    pub snapshot_versions: Vec<SnapshotVersion>,
}

/// The `<versioning><snapshot>` element of snapshot metadata. Its fields are
/// private; [`Metadata::snapshot_timestamped_version`] reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub(crate) timestamp: Option<String>,
    #[serde(default, deserialize_with = "build_number")]
    pub(crate) build_number: Option<u32>,
}

/// `<buildNumber>` as Maven's lenient reader takes it: a Java `int` once
/// trimmed as `String.trim` does, and 0 for text that is not one. Only a
/// build above 0 is ever used.
fn build_number<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u32>, D::Error> {
    let text = Option::<String>::deserialize(deserializer)?;
    Ok(text
        .and_then(|text| text.trim_matches(|c| c <= ' ').parse::<i32>().ok())
        .and_then(|build| u32::try_from(build).ok()))
}

/// The version candidate Maven's version resolver takes from one
/// repository's snapshot metadata for one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotCandidate {
    /// A `<snapshotVersion>` of the file.
    Specific,
    /// The legacy `<snapshot>`, naming its build or, without one, the base
    /// version.
    Generic,
    /// None: the base version stands only when no repository has one.
    Absent,
    /// The build raeva.lock pins, found offline in the cache. It stands
    /// over the other repositories' candidates, as it did when locked.
    Pinned,
}

/// One `<snapshotVersion>` entry: the timestamped version published for one
/// classifier and extension. Its fields are private;
/// [`Metadata::snapshot_version_for`] reads them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SnapshotVersion {
    pub(crate) classifier: Option<String>,
    #[serde(default)]
    pub(crate) extension: String,
    #[serde(default)]
    pub(crate) value: String,
    pub(crate) updated: Option<String>,
}

#[derive(Deserialize)]
struct MetadataXml {
    version: Option<String>,
    versioning: Option<VersioningXml>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct VersioningXml {
    latest: Option<String>,
    release: Option<String>,
    versions: Option<VersionsXml>,
    last_updated: Option<String>,
    snapshot: Option<Snapshot>,
    snapshot_versions: Option<SnapshotVersionsXml>,
}

#[derive(Deserialize)]
struct VersionsXml {
    #[serde(default)]
    version: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotVersionsXml {
    #[serde(default)]
    snapshot_version: Vec<SnapshotVersion>,
}

impl Metadata {
    /// Parses `xml`, after dropping a leading UTF-8 byte order mark, which
    /// Nexus 2.x and Artifactory emit.
    ///
    /// # Errors
    ///
    /// [`RepoError::InvalidMetadata`] when the document does not parse. The
    /// message gives only the document's size, never its text.
    pub fn parse(xml: &str) -> Result<Self> {
        let xml = xml.strip_prefix('\u{FEFF}').unwrap_or(xml);
        // The parser's message quotes the document, which is server text, so
        // the error names only its size.
        let parsed: MetadataXml = quick_xml::de::from_str(xml).map_err(|_| {
            RepoError::InvalidMetadata(format!(
                "maven-metadata.xml is not valid Maven metadata ({} bytes)",
                xml.len()
            ))
        })?;
        let versioning = parsed.versioning.unwrap_or_default();
        Ok(Metadata {
            version: trimmed(parsed.version),
            latest: trimmed(versioning.latest),
            release: trimmed(versioning.release),
            versions: versioning
                .versions
                .map(|versions| {
                    versions
                        .version
                        .into_iter()
                        .filter_map(|version| trimmed(Some(version)))
                        .collect()
                })
                .unwrap_or_default(),
            last_updated: trimmed(versioning.last_updated),
            snapshot: versioning.snapshot.map(trim_snapshot),
            snapshot_versions: versioning
                .snapshot_versions
                .map(|versions| {
                    versions
                        .snapshot_version
                        .into_iter()
                        .map(trim_snapshot_version)
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// [`Metadata::parse`] for raw bytes.
    ///
    /// # Errors
    ///
    /// [`RepoError::InvalidMetadata`] when the bytes are not UTF-8 or do not
    /// parse.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let xml = std::str::from_utf8(bytes).map_err(|_| {
            RepoError::InvalidMetadata(format!(
                "maven-metadata.xml is not UTF-8 ({} bytes)",
                bytes.len()
            ))
        })?;
        Self::parse(xml)
    }

    /// The timestamped version that `<version>` and `<snapshot>` name, such
    /// as `1.0-20240101.010101-7`. `None` without a version, a timestamp or a
    /// build number above zero, or when the timestamp is not
    /// `YYYYMMDD.HHMMSS`.
    pub fn snapshot_timestamped_version(&self) -> Option<String> {
        let version = self.version.as_deref()?;
        let snapshot = self.snapshot.as_ref()?;
        let timestamp = snapshot.timestamp.as_deref()?;
        // `DefaultVersionResolver` uses the `<snapshot>` only with a build
        // number above zero.
        let build = snapshot.build_number.filter(|build| *build > 0)?;
        // A malformed `<timestamp>` would round-trip into a filename Maven
        // cannot resolve; the caller falls back to base-version semantics.
        rv_maven_types::is_snapshot_timestamp(timestamp)
            .then(|| rv_maven_types::timestamped_snapshot_version(version, timestamp, build))?
    }

    /// The version to fetch for the file with `classifier` and `extension`:
    /// its `<snapshotVersion>`, else the version `<snapshot>` names, else a
    /// `-SNAPSHOT` `<version>` base version. `None` when none applies.
    ///
    /// As in Maven, `<snapshot>` applies only without `<snapshotVersions>`,
    /// and a file the entries omit, a POM included, keeps the base version.
    pub fn snapshot_version_for(
        &self,
        classifier: Option<&str>,
        extension: &str,
    ) -> Option<String> {
        self.snapshot_entry_for(classifier, extension)
            .map(|entry| entry.value.clone())
            .or_else(|| {
                self.snapshot_versions
                    .is_empty()
                    .then(|| self.snapshot_timestamped_version())
                    .flatten()
            })
            .or_else(|| {
                self.version
                    .clone()
                    .filter(|version| rv_maven_types::resolves_through_snapshot_metadata(version))
            })
    }

    /// The comparison value for the requested snapshot file: its entry's
    /// `<updated>`, or `<lastUpdated>` for the `<snapshot>`.
    pub fn snapshot_updated_for(&self, classifier: Option<&str>, extension: &str) -> Option<&str> {
        match self.snapshot_candidate(classifier, extension) {
            SnapshotCandidate::Specific => self
                .snapshot_entry_for(classifier, extension)
                .and_then(|entry| entry.updated.as_deref()),
            SnapshotCandidate::Generic => self.last_updated.as_deref(),
            SnapshotCandidate::Absent | SnapshotCandidate::Pinned => None,
        }
    }

    /// The candidate of the file with `classifier` and `extension`, as
    /// [`Self::snapshot_version_for`] picks it.
    pub fn snapshot_candidate(
        &self,
        classifier: Option<&str>,
        extension: &str,
    ) -> SnapshotCandidate {
        if self.snapshot_entry_for(classifier, extension).is_some() {
            SnapshotCandidate::Specific
        } else if self.snapshot_versions.is_empty() && self.snapshot.is_some() {
            SnapshotCandidate::Generic
        } else {
            SnapshotCandidate::Absent
        }
    }

    fn snapshot_entry_for(
        &self,
        classifier: Option<&str>,
        extension: &str,
    ) -> Option<&SnapshotVersion> {
        self.snapshot_versions
            .iter()
            .filter(|entry| {
                // Maven skips an entry without a value, and reads an empty
                // classifier as none.
                !entry.value.is_empty()
                    && entry.extension == extension
                    && entry.classifier.as_deref().unwrap_or_default()
                        == classifier.unwrap_or_default()
            })
            .fold(None, |best: Option<&SnapshotVersion>, entry| {
                // As Maven merges entries: a later one replaces the kept one
                // only when its `updated` is greater, a missing one counting
                // as empty.
                let newer = best.is_none_or(|kept| {
                    (entry.updated.as_deref())
                        .is_some_and(|new| new > kept.updated.as_deref().unwrap_or_default())
                });
                if newer { Some(entry) } else { best }
            })
    }
}

/// Maven's metadata reader trims element text, and an empty value counts as
/// absent.
fn trimmed(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn trim_snapshot(mut snapshot: Snapshot) -> Snapshot {
    snapshot.timestamp = trimmed(snapshot.timestamp);
    snapshot
}

fn trim_snapshot_version(mut entry: SnapshotVersion) -> SnapshotVersion {
    entry.classifier = trimmed(entry.classifier);
    entry.extension = entry.extension.trim().to_string();
    entry.value = entry.value.trim().to_string();
    entry.updated = trimmed(entry.updated);
    entry
}

#[cfg(test)]
mod tests {
    use super::{Metadata, SnapshotCandidate, SnapshotVersion};

    #[test]
    fn markers_are_trimmed() {
        let metadata = Metadata::parse(
            "<metadata><versioning><latest> </latest><release>\n 2.0 \n</release>\
             <lastUpdated>\n 20250101000000\n</lastUpdated></versioning></metadata>",
        )
        .unwrap();
        assert_eq!(metadata.latest, None);
        assert_eq!(metadata.release.as_deref(), Some("2.0"));
        assert_eq!(metadata.last_updated.as_deref(), Some("20250101000000"));
    }

    #[test]
    fn parses_snapshot_versions() {
        let xml = "<metadata><version>1.0-SNAPSHOT</version><versioning><snapshotVersions>\
                   <snapshotVersion><classifier>tests</classifier><extension>jar</extension>\
                   <value>1.0-20240101.010101-6</value><updated>20240101010101</updated>\
                   </snapshotVersion><snapshotVersion><extension>jar</extension>\
                   <value>1.0-20240101.010101-7</value></snapshotVersion><snapshotVersion>\
                   <extension>pom</extension><value>1.0-20240101.010101-7</value>\
                   </snapshotVersion></snapshotVersions></versioning></metadata>";
        let metadata = Metadata::parse(xml).unwrap();
        assert_eq!(metadata.snapshot_versions.len(), 3);
        let tests = SnapshotVersion {
            classifier: Some("tests".to_string()),
            extension: "jar".to_string(),
            value: "1.0-20240101.010101-6".to_string(),
            updated: Some("20240101010101".to_string()),
        };
        assert_eq!(metadata.snapshot_versions[0], tests);
        assert_eq!(
            metadata.snapshot_updated_for(Some("tests"), "jar"),
            Some("20240101010101")
        );
        // As in Maven, a file the entries omit keeps the base version.
        assert_eq!(
            metadata
                .snapshot_version_for(Some("linux"), "jar")
                .as_deref(),
            Some("1.0-SNAPSHOT")
        );
        let with_snapshot = xml.replace(
            "<versioning>",
            "<versioning><snapshot><timestamp>20240101.010101</timestamp>\
             <buildNumber>7</buildNumber></snapshot>",
        );
        let without_pom = with_snapshot.replace(
            "<snapshotVersion><extension>pom</extension><value>1.0-20240101.010101-7</value>\
             </snapshotVersion>",
            "",
        );
        assert_ne!(without_pom, with_snapshot);
        let with_snapshot = Metadata::parse(&with_snapshot).unwrap();
        assert_eq!(
            with_snapshot.snapshot_version_for(None, "zip").as_deref(),
            Some("1.0-SNAPSHOT")
        );
        assert_eq!(
            with_snapshot.snapshot_candidate(None, "zip"),
            SnapshotCandidate::Absent
        );
        // A POM the entries omit too, though `<snapshot>` names a build.
        let without_pom = Metadata::parse(&without_pom).unwrap();
        assert_eq!(
            without_pom.snapshot_version_for(None, "pom").as_deref(),
            Some("1.0-SNAPSHOT")
        );
        assert_eq!(
            without_pom.snapshot_candidate(None, "pom"),
            SnapshotCandidate::Absent
        );
        assert!(metadata.snapshot_updated_for(None, "pom").is_none());
        let updated = |xml: &str| {
            let xml = xml.replace(
                "<versioning>",
                "<versioning><lastUpdated>20240102010101</lastUpdated>",
            );
            Metadata::parse(&xml)
                .unwrap()
                .snapshot_updated_for(Some("linux"), "jar")
                .map(str::to_string)
        };
        assert_eq!(updated(xml), None);
        assert_eq!(
            updated(&xml.replace(
                "<versioning>",
                "<versioning><snapshot><timestamp>20240101.010101</timestamp>\
                 <buildNumber>7</buildNumber></snapshot>",
            )),
            None
        );
        for (classifier, extension, value) in [
            (Some("tests"), "jar", "1.0-20240101.010101-6"),
            (None, "jar", "1.0-20240101.010101-7"),
            (None, "pom", "1.0-20240101.010101-7"),
        ] {
            assert_eq!(
                metadata
                    .snapshot_version_for(classifier, extension)
                    .as_deref(),
                Some(value)
            );
        }
    }

    #[test]
    fn an_empty_classifier_is_none() {
        let metadata = Metadata::parse(
            "<metadata><version>1.0-SNAPSHOT</version><versioning><snapshotVersions>\
             <snapshotVersion><classifier></classifier><extension>jar</extension>\
             <value>1.0-20240101.010101-3</value></snapshotVersion>\
             </snapshotVersions></versioning></metadata>",
        )
        .unwrap();
        for classifier in [None, Some("")] {
            assert_eq!(
                metadata.snapshot_version_for(classifier, "jar").as_deref(),
                Some("1.0-20240101.010101-3")
            );
        }
    }

    /// Maven skips a `<snapshotVersion>` without a value, and one without an
    /// extension matches no file; the `<snapshot>` block still stays unused.
    #[test]
    fn a_snapshot_version_without_a_value_is_skipped() {
        for entry in [
            "<extension>jar</extension><value> </value>",
            "<extension>jar</extension>",
            "<value>1.0-20240101.010101-3</value>",
        ] {
            let metadata = Metadata::parse(&format!(
                "<metadata><version>1.0-SNAPSHOT</version><versioning><snapshot>\
                 <timestamp>20240101.010101</timestamp><buildNumber>4</buildNumber></snapshot>\
                 <snapshotVersions><snapshotVersion>{entry}</snapshotVersion>\
                 </snapshotVersions></versioning></metadata>"
            ))
            .unwrap_or_else(|err| panic!("{entry}: {err}"));
            assert_eq!(
                metadata.snapshot_version_for(None, "jar").as_deref(),
                Some("1.0-SNAPSHOT"),
                "{entry}"
            );
            assert_eq!(
                metadata.snapshot_candidate(None, "jar"),
                SnapshotCandidate::Absent,
                "{entry}"
            );
        }
    }

    /// Without `<snapshotVersions>` the `<snapshot>` block names the build;
    /// a non-unique snapshot keeps the base version, and a malformed
    /// timestamp is dropped.
    #[test]
    fn snapshot_versions_fall_back_to_the_snapshot_block() {
        let metadata = |snapshot: &str| {
            Metadata::parse(&format!(
                "<metadata><version>1.2.3-SNAPSHOT</version><versioning><snapshot>{snapshot}\
                 </snapshot></versioning></metadata>"
            ))
            .unwrap()
        };
        let timestamped =
            metadata("<timestamp>20240101.010101</timestamp><buildNumber>7</buildNumber>");
        assert_eq!(
            timestamped.snapshot_timestamped_version().as_deref(),
            Some("1.2.3-20240101.010101-7")
        );
        assert_eq!(
            timestamped.snapshot_version_for(None, "jar").as_deref(),
            Some("1.2.3-20240101.010101-7")
        );
        assert_eq!(
            metadata("<localCopy>true</localCopy>")
                .snapshot_version_for(None, "jar")
                .as_deref(),
            Some("1.2.3-SNAPSHOT")
        );

        let malformed =
            metadata("<timestamp>evil-timestamp</timestamp><buildNumber>3</buildNumber>");
        assert!(malformed.snapshot_timestamped_version().is_none());

        // Maven's lenient reader takes a <buildNumber> that is not an int as
        // 0, and then uses the base version.
        for build in ["", "x", "-1", "2147483648", "1.5", "&#160;3&#160;"] {
            let odd = metadata(&format!(
                "<timestamp>20240101.010101</timestamp><buildNumber>{build}</buildNumber>"
            ));
            assert_eq!(
                odd.snapshot_version_for(None, "jar").as_deref(),
                Some("1.2.3-SNAPSHOT"),
                "{build:?}"
            );
        }
    }

    /// A malformed document's text never reaches the error: it is server
    /// text, and may hold escape sequences or a page meant for a browser.
    #[test]
    fn a_parse_error_names_only_the_size() {
        for bytes in [
            b"<metadata><evil\x1b[31m>1</wrong></metadata>".to_vec(),
            b"<metadata><evilTag>1</wrongTag></metadata>".to_vec(),
            b"\xff\xfe<html>evil</html>".to_vec(),
        ] {
            let message = Metadata::from_bytes(&bytes).unwrap_err().to_string();
            assert!(!message.contains("evil"), "{message}");
            assert!(!message.contains('\x1b'), "{message}");
            assert!(
                message.contains(&format!("({} bytes)", bytes.len())),
                "{message}"
            );
        }
    }
    /// Maven reads an empty listing as no versions.
    #[test]
    fn empty_listings_parse() {
        let metadata = Metadata::parse(
            "<metadata><versioning><release>1.5</release><versions></versions>\
             <snapshotVersions/></versioning></metadata>",
        )
        .unwrap();
        assert!(metadata.versions.is_empty());
        assert!(metadata.snapshot_versions.is_empty());
    }

    /// Maven's metadata reader trims every element. A blank `<version>` drops
    /// out of the listing the same way a blank `<latest>` does.
    #[test]
    fn version_listing_elements_are_trimmed() {
        let metadata = Metadata::parse(
            "<metadata><versioning><versions>\
             <version> 1.0 </version><version>\n2.0\n</version><version>  </version>\
             </versions></versioning></metadata>",
        )
        .unwrap();
        assert_eq!(
            metadata.versions,
            vec!["1.0".to_string(), "2.0".to_string()]
        );
    }

    /// Whitespace around a SNAPSHOT `<version>`, `<timestamp>`, extension, or
    /// value must not change which file the metadata names.
    #[test]
    fn snapshot_metadata_fields_are_trimmed() {
        let metadata = Metadata::parse(
            "<metadata><version> 1.0-SNAPSHOT </version><versioning>\
             <snapshot><timestamp> 20240101.010101 </timestamp>\
             <buildNumber>7</buildNumber></snapshot>\
             <snapshotVersions><snapshotVersion>\
             <extension> jar </extension><value> 1.0-20240101.010101-7 </value>\
             <updated> 20240101010101 </updated>\
             </snapshotVersion></snapshotVersions></versioning></metadata>",
        )
        .unwrap();
        assert_eq!(metadata.version.as_deref(), Some("1.0-SNAPSHOT"));
        assert_eq!(
            metadata.snapshot_version_for(None, "jar").as_deref(),
            Some("1.0-20240101.010101-7")
        );
        assert_eq!(
            metadata.snapshot_timestamped_version().as_deref(),
            Some("1.0-20240101.010101-7")
        );
    }
}
