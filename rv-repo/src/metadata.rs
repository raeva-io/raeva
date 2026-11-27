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
    /// How many of `versions` precede the first blank `<version>`, which
    /// Maven's range resolver lists as the empty version.
    pub blank_version_at: Option<usize>,
    /// `<versioning><lastUpdated>`, which picks among repositories'
    /// `<release>` and `<latest>`, and for legacy snapshot metadata.
    pub last_updated: Option<String>,
    /// `<versioning><snapshot>`: the timestamp and build number of the
    /// latest snapshot build.
    pub snapshot: Option<Snapshot>,
    /// `<versioning><snapshotVersions>`: the timestamped version of each
    /// classifier and extension. Empty when absent.
    pub snapshot_versions: Vec<SnapshotVersion>,
    /// The `<artifactId>` and `<prefix>` of each `<plugins><plugin>`, which
    /// group-level metadata lists. Only Maven 3.10's validation reads them.
    pub plugins: Vec<(Option<String>, Option<String>)>,
}

/// Which Maven 3.10 resolver reads a `maven-metadata.xml`: each takes
/// other fields for invalid when they hold a control character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataReader {
    /// `DefaultVersionRangeResolver`, for a range, `RELEASE` or `LATEST`.
    VersionRange,
    /// `DefaultVersionResolver`, for a `-SNAPSHOT` build.
    Version,
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
    plugins: Option<PluginsXml>,
}

#[derive(Deserialize)]
struct PluginsXml {
    #[serde(default)]
    plugin: Vec<PluginXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginXml {
    artifact_id: Option<String>,
    prefix: Option<String>,
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
        let mut versions = Vec::new();
        let mut blank_version_at = None;
        for version in (versioning.versions.into_iter()).flat_map(|versions| versions.version) {
            match trimmed(Some(version)) {
                Some(version) => versions.push(version),
                None => _ = blank_version_at.get_or_insert(versions.len()),
            }
        }
        Ok(Metadata {
            version: trimmed(parsed.version),
            latest: trimmed(versioning.latest),
            release: trimmed(versioning.release),
            versions,
            blank_version_at,
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
            plugins: (parsed
                .plugins
                .map(|plugins| plugins.plugin)
                .unwrap_or_default())
            .into_iter()
            .map(|plugin| (trimmed(plugin.artifact_id), trimmed(plugin.prefix)))
            .collect(),
        })
    }

    /// `versions` as Maven's range resolver lists them, a blank one in its
    /// place as the empty version.
    pub fn listed_versions(&self) -> impl Iterator<Item = &str> {
        let blank = |at| (self.blank_version_at == Some(at)).then_some("");
        (self.versions.iter().enumerate())
            .flat_map(move |(at, version)| blank(at).into_iter().chain([version.as_str()]))
            .chain(blank(self.versions.len()))
    }

    /// Whether Maven 3.10 takes this metadata for invalid when `reader`
    /// reads it, and so lists nothing from it. Its
    /// `ValidatingMetadataXpp3Reader` refuses `..` and any `/`, `\` or `:`
    /// in the versions, the snapshot timestamp, the snapshot versions and
    /// the plugin names, and each resolver also refuses a control character
    /// in the values it adopts.
    pub fn has_invalid_token(&self, reader: MetadataReader) -> bool {
        let (version, latest, release) = (&self.version, &self.latest, &self.release);
        let versions = self.versions.iter();
        let timestamp = (self.snapshot.as_ref()).and_then(|snapshot| snapshot.timestamp.as_ref());
        let values = (self.snapshot_versions.iter()).map(|entry| &entry.value);
        let plugins = (self.plugins.iter()).flat_map(|(artifact_id, prefix)| [artifact_id, prefix]);
        let path_component = |value: &String| value == ".." || value.contains(['/', '\\', ':']);
        let control = |value: &String| value.chars().any(char::is_control);
        let mut read = (version
            .iter()
            .chain(latest)
            .chain(release)
            .chain(versions.clone()))
        .chain(timestamp)
        .chain(values.clone())
        .chain(plugins.flatten());
        let adopted: Vec<&String> = match reader {
            MetadataReader::VersionRange => versions.chain(latest).chain(release).collect(),
            MetadataReader::Version => latest
                .iter()
                .chain(release)
                .chain(values)
                .chain(timestamp)
                .collect(),
        };
        read.any(path_component) || adopted.into_iter().any(control)
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

    /// The file version `<snapshot>` gives the `SNAPSHOT` version
    /// `version`, as `DefaultVersionResolver` builds it: `version` without
    /// `SNAPSHOT`, then `<timestamp>-<buildNumber>`, so
    /// `1.0-20240101.010101-7` for `1.0-SNAPSHOT`, and JitPack's
    /// `main-0d99b1a098-1` for `main-SNAPSHOT`. Maven reads neither
    /// `<version>` nor the timestamp's shape. `None` without a timestamp or
    /// a build number above zero, or when `version` does not end in
    /// `SNAPSHOT`.
    pub fn snapshot_timestamped_version(&self, version: &str) -> Option<String> {
        let snapshot = self.snapshot.as_ref()?;
        let timestamp = snapshot.timestamp.as_deref()?;
        let build = snapshot.build_number.filter(|build| *build > 0)?;
        rv_maven_types::timestamped_snapshot_version(version, timestamp, build)
    }

    /// The version to fetch for the file with `classifier` and `extension`
    /// of the `SNAPSHOT` version `version`: its `<snapshotVersion>`, else
    /// the version `<snapshot>` names, else `version` itself.
    ///
    /// As in Maven, `<snapshot>` applies only without `<snapshotVersions>`,
    /// and a file the entries omit, a POM included, keeps `version`.
    pub fn snapshot_version_for(
        &self,
        version: &str,
        classifier: Option<&str>,
        extension: &str,
    ) -> String {
        self.snapshot_entry_for(classifier, extension)
            .map(|entry| entry.value.clone())
            .or_else(|| {
                self.snapshot_versions
                    .is_empty()
                    .then(|| self.snapshot_timestamped_version(version))
                    .flatten()
            })
            .unwrap_or_else(|| version.to_string())
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
    use super::{Metadata, MetadataReader, SnapshotCandidate, SnapshotVersion};

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
            metadata.snapshot_version_for("1.0-SNAPSHOT", Some("linux"), "jar"),
            "1.0-SNAPSHOT"
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
            with_snapshot.snapshot_version_for("1.0-SNAPSHOT", None, "zip"),
            "1.0-SNAPSHOT"
        );
        assert_eq!(
            with_snapshot.snapshot_candidate(None, "zip"),
            SnapshotCandidate::Absent
        );
        // A POM the entries omit too, though `<snapshot>` names a build.
        let without_pom = Metadata::parse(&without_pom).unwrap();
        assert_eq!(
            without_pom.snapshot_version_for("1.0-SNAPSHOT", None, "pom"),
            "1.0-SNAPSHOT"
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
                metadata.snapshot_version_for("1.0-SNAPSHOT", classifier, extension),
                value
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
                metadata.snapshot_version_for("1.0-SNAPSHOT", classifier, "jar"),
                "1.0-20240101.010101-3"
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
                metadata.snapshot_version_for("1.0-SNAPSHOT", None, "jar"),
                "1.0-SNAPSHOT",
                "{entry}"
            );
            assert_eq!(
                metadata.snapshot_candidate(None, "jar"),
                SnapshotCandidate::Absent,
                "{entry}"
            );
        }
    }

    /// Without `<snapshotVersions>` the `<snapshot>` block names the build
    /// of the version asked for, whatever `<version>` says and whatever the
    /// timestamp's shape, as Maven 3.9.16's `DefaultVersionResolver` builds
    /// it; a non-unique snapshot keeps the version asked for.
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
            timestamped
                .snapshot_timestamped_version("1.2.3-SNAPSHOT")
                .as_deref(),
            Some("1.2.3-20240101.010101-7")
        );
        assert_eq!(
            timestamped.snapshot_version_for("1.2.3-SNAPSHOT", None, "jar"),
            "1.2.3-20240101.010101-7"
        );
        assert_eq!(
            metadata("<localCopy>true</localCopy>").snapshot_version_for(
                "1.2.3-SNAPSHOT",
                None,
                "jar"
            ),
            "1.2.3-SNAPSHOT"
        );

        // The caller checks the version before it goes in a path.
        let odd_timestamp =
            metadata("<timestamp>evil-timestamp</timestamp><buildNumber>3</buildNumber>");
        assert_eq!(
            odd_timestamp.snapshot_version_for("1.2.3-SNAPSHOT", None, "jar"),
            "1.2.3-evil-timestamp-3"
        );
        // JitPack's branch snapshot: a commit hash for a timestamp, and the
        // build in `<version>`.
        let jitpack = Metadata::parse(
            "<metadata modelVersion=\"1.0.0\"><groupId>com.github.x</groupId>\
             <artifactId>y</artifactId><version>main-0d99b1a098-1</version><versioning>\
             <snapshot><timestamp>0d99b1a098</timestamp><buildNumber>1</buildNumber>\
             </snapshot></versioning></metadata>",
        )
        .unwrap();
        assert_eq!(
            jitpack.snapshot_version_for("main-SNAPSHOT", None, "jar"),
            "main-0d99b1a098-1"
        );
        assert_eq!(
            jitpack.snapshot_candidate(None, "jar"),
            SnapshotCandidate::Generic
        );
        // Without `<version>` or `<snapshot>`, the version asked for.
        let bare = Metadata::parse("<metadata><versioning/></metadata>").unwrap();
        assert_eq!(
            bare.snapshot_version_for("1.2.3-SNAPSHOT", None, "jar"),
            "1.2.3-SNAPSHOT"
        );

        // Maven's lenient reader takes a <buildNumber> that is not an int as
        // 0, and then uses the base version.
        for build in ["", "x", "-1", "2147483648", "1.5", "&#160;3&#160;"] {
            let odd = metadata(&format!(
                "<timestamp>20240101.010101</timestamp><buildNumber>{build}</buildNumber>"
            ));
            assert_eq!(
                odd.snapshot_version_for("1.2.3-SNAPSHOT", None, "jar"),
                "1.2.3-SNAPSHOT",
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
        assert_eq!(
            metadata.listed_versions().collect::<Vec<_>>(),
            ["1.0", "2.0", ""]
        );
        let metadata = Metadata::parse(
            "<metadata><versioning><versions><version/><version>1</version><version> \
             </version><version>2</version></versions></versioning></metadata>",
        )
        .unwrap();
        assert_eq!(
            metadata.listed_versions().collect::<Vec<_>>(),
            ["", "1", "2"]
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
            metadata.snapshot_version_for("1.0-SNAPSHOT", None, "jar"),
            "1.0-20240101.010101-7"
        );
        assert_eq!(
            metadata
                .snapshot_timestamped_version("1.0-SNAPSHOT")
                .as_deref(),
            Some("1.0-20240101.010101-7")
        );
    }

    /// Maven 3.10's readers refuse a value with `..`, `/`, `\` or `:` in
    /// any version field, the timestamp or a plugin name, and each one a
    /// control character in the values it adopts.
    #[test]
    fn maven_310_invalid_tokens_follow_each_reader() {
        use MetadataReader::{Version, VersionRange};
        let invalid = |versioning: &str, plugins: &str| {
            let metadata = Metadata::parse(&format!(
                "<metadata><versioning>{versioning}</versioning>{plugins}</metadata>"
            ))
            .unwrap();
            (
                metadata.has_invalid_token(VersionRange),
                metadata.has_invalid_token(Version),
            )
        };
        let snapshot = |timestamp: &str| {
            format!(
                "<snapshot><timestamp>{timestamp}</timestamp><buildNumber>1</buildNumber></snapshot>"
            )
        };
        let value = |value: &str| {
            format!(
                "<snapshotVersions><snapshotVersion><extension>jar</extension>\
                 <value>{value}</value></snapshotVersion></snapshotVersions>"
            )
        };
        for (versioning, plugins, expected) in [
            (
                "<versions><version>1.0</version><version>1..</version></versions>".to_string(),
                "",
                (false, false),
            ),
            (
                "<versions><version>..</version></versions>".to_string(),
                "",
                (true, true),
            ),
            ("<latest>1/2</latest>".to_string(), "", (true, true)),
            ("<release>c:\\x</release>".to_string(), "", (true, true)),
            ("<release>1&#x9;2</release>".to_string(), "", (true, true)),
            (
                "<versions><version>1&#x9;2</version></versions>".to_string(),
                "",
                (true, false),
            ),
            (snapshot("20240101.010101"), "", (false, false)),
            (snapshot("20240101:010101"), "", (true, true)),
            (snapshot("20240101&#x9;010101"), "", (false, true)),
            (value("1.0-20240101.010101-1"), "", (false, false)),
            (value("../1.0-20240101.010101-1"), "", (true, true)),
            (value("1.0-20240101&#x9;.010101-1"), "", (false, true)),
            (
                String::new(),
                "<plugins><plugin><prefix>a/b</prefix></plugin></plugins>",
                (true, true),
            ),
            (
                String::new(),
                "<plugins><plugin><artifactId>a:b</artifactId></plugin></plugins>",
                (true, true),
            ),
            (
                String::new(),
                "<plugins><plugin><artifactId>p</artifactId><prefix>p</prefix></plugin></plugins>",
                (false, false),
            ),
        ] {
            assert_eq!(
                invalid(&versioning, plugins),
                expected,
                "{versioning}{plugins}"
            );
        }
        let version =
            Metadata::parse("<metadata><version>1.0/SNAPSHOT</version></metadata>").unwrap();
        assert!(version.has_invalid_token(Version) && version.has_invalid_token(VersionRange));
    }
}
