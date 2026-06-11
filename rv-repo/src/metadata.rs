use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::error::{RepoError, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
    pub latest: Option<String>,
    pub release: Option<String>,
    pub versions: Vec<String>,
    pub snapshot: Option<Snapshot>,
    pub snapshot_versions: Vec<SnapshotVersion>,
    pub last_updated: Option<String>,
    /// Precomputed timestamped snapshot version (e.g. `1.0-20240101.010101-7`),
    /// derived from `version` + `snapshot` during [`Metadata::parse`]. This is
    /// a parse-time cache, not an independent input: serializing it would let a
    /// deserialized `Metadata` carry a value inconsistent with its other
    /// fields. `#[serde(skip)]` keeps it out of any serde round-trip so it is
    /// always recomputed by `parse`; the `Serialize`/`Deserialize` derives on
    /// the struct are retained for API stability.
    #[serde(skip)]
    pub snapshot_timestamped: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub(crate) timestamp: Option<String>,
    pub(crate) build_number: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_bool_lenient")]
    pub(crate) local_copy: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotVersion {
    pub(crate) classifier: Option<String>,
    pub(crate) extension: String,
    pub(crate) value: String,
    pub(crate) updated: Option<String>,
}

// Shadow structs for XML parsing
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetadataXml {
    group_id: Option<String>,
    artifact_id: Option<String>,
    version: Option<String>,
    versioning: Option<VersioningXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersioningXml {
    latest: Option<String>,
    release: Option<String>,
    versions: Option<VersionsXml>,
    snapshot: Option<Snapshot>,
    snapshot_versions: Option<SnapshotVersionsXml>,
    last_updated: Option<String>,
}

#[derive(Deserialize)]
struct VersionsXml {
    version: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotVersionsXml {
    snapshot_version: Vec<SnapshotVersion>,
}

fn deserialize_bool_lenient<'de, D>(deserializer: D) -> std::result::Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => {
            if s.eq_ignore_ascii_case("true") {
                Ok(Some(true))
            } else if s.eq_ignore_ascii_case("false") {
                Ok(Some(false))
            } else {
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

/// Returns true iff `s` matches the Maven snapshot timestamp pattern
/// `^\d{8}\.\d{6}$` (e.g. `20240101.010101`). Implemented byte-by-byte to
/// avoid pulling the `regex` crate into the hot path.
fn is_valid_snapshot_timestamp(s: &str) -> bool {
    if s.len() != 15 {
        return false;
    }
    let bytes = s.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        match idx {
            8 => {
                if b != b'.' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_digit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Strip a leading UTF-8 BOM. Nexus 2.x / Artifactory emit it on
/// `maven-metadata.xml` and quick-xml otherwise fails to parse.
fn strip_utf8_bom(s: &str) -> &str {
    s.strip_prefix('\u{FEFF}').unwrap_or(s)
}

impl Metadata {
    pub fn parse(xml: &str) -> Result<Self> {
        let xml = strip_utf8_bom(xml);
        let xml_struct: MetadataXml =
            quick_xml::de::from_str(xml).map_err(|e| RepoError::InvalidMetadata(e.to_string()))?;

        let mut metadata = Metadata {
            group_id: xml_struct.group_id,
            artifact_id: xml_struct.artifact_id,
            version: xml_struct.version,
            ..Default::default()
        };

        if let Some(v) = xml_struct.versioning {
            metadata.latest = v.latest;
            metadata.release = v.release;
            metadata.last_updated = v.last_updated;
            metadata.snapshot = v.snapshot;
            if let Some(versions) = v.versions {
                metadata.versions = versions.version;
            }
            if let Some(sv) = v.snapshot_versions {
                metadata.snapshot_versions = sv.snapshot_version;
            }
        }

        metadata.snapshot_timestamped = metadata.snapshot_timestamped_version();
        Ok(metadata)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let xml = std::str::from_utf8(bytes)
            .with_context(|| "failed to decode maven-metadata.xml as UTF-8")
            .map_err(|err| RepoError::InvalidMetadata(err.to_string()))?;
        Self::parse(xml)
    }

    pub fn snapshot_timestamped_version(&self) -> Option<String> {
        let base_version = self.version.as_deref()?.strip_suffix("-SNAPSHOT")?;
        let snapshot = self.snapshot.as_ref()?;
        let timestamp = snapshot.timestamp.as_deref()?;
        let build = snapshot.build_number?;
        if !is_valid_snapshot_timestamp(timestamp) {
            // A malformed `<timestamp>` (anything other than `YYYYMMDD.HHMMSS`)
            // would round-trip into a filename Maven cannot resolve. Drop the
            // value and let the caller fall back to base-version semantics.
            tracing::warn!(
                timestamp = %timestamp,
                "snapshot timestamp does not match expected YYYYMMDD.HHMMSS format; ignoring"
            );
            return None;
        }
        Some(format!("{base_version}-{timestamp}-{build}"))
    }

    pub fn snapshot_version_for(&self, classifier: Option<&str>, extension: &str) -> Option<&str> {
        let from_versions = self
            .snapshot_versions
            .iter()
            .find(|entry| entry.extension == extension && entry.classifier.as_deref() == classifier)
            .map(|entry| entry.value.as_str());

        if from_versions.is_some() {
            return from_versions;
        }

        if let Some(timestamped) = self.snapshot_timestamped.as_deref() {
            return Some(timestamped);
        }

        let base_version = self.version.as_deref()?;
        if base_version.ends_with("-SNAPSHOT") {
            return Some(base_version);
        }

        None
    }

    pub fn latest_or_release(&self) -> Option<&str> {
        self.latest.as_deref().or(self.release.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::{Metadata, SnapshotVersion};

    #[test]
    fn parses_release_metadata() {
        let xml = r"
        <metadata>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <versioning>
            <latest>2.0.0</latest>
            <release>2.0.0</release>
            <versions>
              <version>1.0.0</version>
              <version>2.0.0</version>
            </versions>
          </versioning>
        </metadata>
        ";
        let metadata = Metadata::parse(xml).unwrap();
        assert_eq!(metadata.group_id.as_deref(), Some("com.example"));
        assert_eq!(metadata.latest.as_deref(), Some("2.0.0"));
        assert_eq!(metadata.versions.len(), 2);
    }

    #[test]
    fn parses_snapshot_metadata() {
        let xml = r"
        <metadata>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.2.3-SNAPSHOT</version>
          <versioning>
            <snapshot>
              <timestamp>20240101.010101</timestamp>
              <buildNumber>7</buildNumber>
            </snapshot>
          </versioning>
        </metadata>
        ";
        let metadata = Metadata::parse(xml).unwrap();
        assert_eq!(
            metadata.snapshot_timestamped_version().as_deref(),
            Some("1.2.3-20240101.010101-7")
        );
    }

    #[test]
    fn parses_snapshot_versions() {
        let xml = r"
        <metadata>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0-SNAPSHOT</version>
          <versioning>
            <snapshot>
              <timestamp>20240101.010101</timestamp>
              <buildNumber>7</buildNumber>
            </snapshot>
            <snapshotVersions>
              <snapshotVersion>
                <classifier>tests</classifier>
                <extension>jar</extension>
                <value>1.0-20240101.010101-7</value>
                <updated>20240101010101</updated>
              </snapshotVersion>
              <snapshotVersion>
                <extension>jar</extension>
                <value>1.0-20240101.010101-7</value>
                <updated>20240101010101</updated>
              </snapshotVersion>
              <snapshotVersion>
                <extension>pom</extension>
                <value>1.0-20240101.010101-7</value>
                <updated>20240101010101</updated>
              </snapshotVersion>
            </snapshotVersions>
          </versioning>
        </metadata>
        ";
        let metadata = Metadata::parse(xml).unwrap();
        assert_eq!(metadata.snapshot_versions.len(), 3);
        assert_eq!(
            metadata.snapshot_versions[0],
            SnapshotVersion {
                classifier: Some("tests".to_string()),
                extension: "jar".to_string(),
                value: "1.0-20240101.010101-7".to_string(),
                updated: Some("20240101010101".to_string()),
            }
        );
        assert_eq!(metadata.snapshot_versions[1].classifier, None);
        assert_eq!(metadata.snapshot_versions[1].extension, "jar");
        assert_eq!(metadata.snapshot_versions[2].extension, "pom");
    }

    #[test]
    fn snapshot_version_for_classifier() {
        let xml = r"
        <metadata>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.0-SNAPSHOT</version>
          <versioning>
            <snapshot>
              <timestamp>20240101.010101</timestamp>
              <buildNumber>7</buildNumber>
            </snapshot>
            <snapshotVersions>
              <snapshotVersion>
                <classifier>tests</classifier>
                <extension>jar</extension>
                <value>1.0-20240101.010101-7</value>
              </snapshotVersion>
              <snapshotVersion>
                <extension>jar</extension>
                <value>1.0-20240101.010101-7</value>
              </snapshotVersion>
            </snapshotVersions>
          </versioning>
        </metadata>
        ";
        let metadata = Metadata::parse(xml).unwrap();
        assert_eq!(
            metadata.snapshot_version_for(Some("tests"), "jar"),
            Some("1.0-20240101.010101-7")
        );
    }

    #[test]
    fn snapshot_version_falls_back_when_missing_snapshot_versions() {
        let xml = r"
        <metadata>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.2.3-SNAPSHOT</version>
          <versioning>
            <snapshot>
              <timestamp>20240101.010101</timestamp>
              <buildNumber>7</buildNumber>
            </snapshot>
          </versioning>
        </metadata>
        ";
        let metadata = Metadata::parse(xml).unwrap();
        assert_eq!(
            metadata.snapshot_version_for(None, "jar"),
            Some("1.2.3-20240101.010101-7")
        );
    }

    #[test]
    fn snapshot_timestamp_is_validated() {
        // A malformed `<timestamp>` field must not produce a bogus filename.
        // The validator drops the value and the caller falls back to base
        // version semantics (handled at the higher `snapshot_version_for`
        // layer).
        let xml = r"
        <metadata>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.2.3-SNAPSHOT</version>
          <versioning>
            <snapshot>
              <timestamp>not-a-timestamp</timestamp>
              <buildNumber>7</buildNumber>
            </snapshot>
          </versioning>
        </metadata>
        ";
        let metadata = Metadata::parse(xml).unwrap();
        assert!(
            metadata.snapshot_timestamped_version().is_none(),
            "malformed timestamp should be rejected"
        );
    }

    #[test]
    fn snapshot_timestamp_validator_rejects_invalid_shapes() {
        use super::is_valid_snapshot_timestamp;
        assert!(is_valid_snapshot_timestamp("20240101.010101"));
        assert!(!is_valid_snapshot_timestamp("20240101"));
        assert!(!is_valid_snapshot_timestamp("20240101-010101"));
        assert!(!is_valid_snapshot_timestamp("2024010.0101011"));
        assert!(!is_valid_snapshot_timestamp("20240101.01010A"));
        assert!(!is_valid_snapshot_timestamp(""));
        assert!(!is_valid_snapshot_timestamp("20240101.0101011"));
    }

    #[test]
    fn parses_metadata_with_utf8_bom() {
        // Nexus 2.x and some Artifactory variants serve maven-metadata.xml
        // with a UTF-8 BOM. Parsing must strip the BOM transparently.
        let xml = "\u{FEFF}<metadata>\
          <groupId>com.example</groupId>\
          <artifactId>demo</artifactId>\
          <versioning>\
            <latest>2.0.0</latest>\
            <release>2.0.0</release>\
            <versions>\
              <version>1.0.0</version>\
              <version>2.0.0</version>\
            </versions>\
          </versioning>\
        </metadata>";
        let metadata = Metadata::parse(xml).expect("BOM-prefixed metadata should parse");
        assert_eq!(metadata.group_id.as_deref(), Some("com.example"));
        assert_eq!(metadata.latest.as_deref(), Some("2.0.0"));
        assert_eq!(metadata.versions.len(), 2);
    }

    #[test]
    fn snapshot_version_falls_back_to_base_version_for_non_unique_snapshots() {
        let xml = r"
        <metadata>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>1.2.3-SNAPSHOT</version>
          <versioning>
            <snapshot>
              <localCopy>true</localCopy>
            </snapshot>
          </versioning>
        </metadata>
        ";
        let metadata = Metadata::parse(xml).unwrap();
        assert_eq!(
            metadata.snapshot_version_for(None, "jar"),
            Some("1.2.3-SNAPSHOT")
        );
    }
}
