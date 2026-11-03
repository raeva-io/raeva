//! The Maven repository path layout, shared by remote requests, the
//! local-repository export and the trusted-checksums file.
//!
//! The formatting functions do not check the parts, so callers that take
//! them from untrusted input validate first (see
//! [`crate::validate_coordinate_component`]).

use crate::ArtifactCoord;

/// `group/as/dirs/artifact/<dir_version>/artifact-<file_version>[-classifier].ext`.
///
/// The two versions differ only for a timestamped snapshot: the directory
/// holds the `-SNAPSHOT` base version and the file name the timestamped one.
pub fn artifact_path_from_parts(
    group: &str,
    artifact: &str,
    dir_version: &str,
    file_version: &str,
    extension: &str,
    classifier: Option<&str>,
) -> String {
    let group_path = group.replace('.', "/");
    let filename = match classifier {
        Some(classifier) => format!("{artifact}-{file_version}-{classifier}.{extension}"),
        None => format!("{artifact}-{file_version}.{extension}"),
    };
    format!("{group_path}/{artifact}/{dir_version}/{filename}")
}

/// [`artifact_path_from_parts`] for a coordinate.
pub fn artifact_path(coord: &ArtifactCoord, dir_version: &str, file_version: &str) -> String {
    artifact_path_from_parts(
        coord.group_id(),
        coord.artifact_id(),
        dir_version,
        file_version,
        coord.extension(),
        coord.classifier(),
    )
}

/// `group/as/dirs/artifact[/version]/maven-metadata.xml`.
pub fn metadata_path(group: &str, artifact: &str, version: Option<&str>) -> String {
    let group_path = group.replace('.', "/");
    match version {
        Some(version) => format!("{group_path}/{artifact}/{version}/maven-metadata.xml"),
        None => format!("{group_path}/{artifact}/maven-metadata.xml"),
    }
}

/// Whether an artifact path names a mutable snapshot file rather than a
/// timestamped build. A classifier does not change the file's version.
pub fn is_mutable_snapshot_path(path: &str) -> bool {
    let mut parts = path.rsplit('/');
    let [Some(file), Some(version), Some(artifact)] = [parts.next(), parts.next(), parts.next()]
    else {
        return false;
    };
    crate::resolves_through_snapshot_metadata(version)
        && file
            .strip_prefix(artifact)
            .and_then(|file| file.strip_prefix('-'))
            .and_then(|file| file.strip_prefix(version))
            .is_some_and(|suffix| suffix.starts_with(['.', '-']))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_path() {
        let coord = ArtifactCoord::new("com.example", "demo", "1.0.0", "jar", None);
        assert_eq!(
            artifact_path(&coord, "1.0.0", "1.0.0"),
            "com/example/demo/1.0.0/demo-1.0.0.jar"
        );
    }

    #[test]
    fn classifier_and_snapshot_path() {
        let coord = ArtifactCoord::new(
            "com.example",
            "demo",
            "1.0-20240101.010101-1",
            "jar",
            Some("tests"),
        );
        assert_eq!(
            artifact_path(&coord, "1.0-SNAPSHOT", coord.version()),
            "com/example/demo/1.0-SNAPSHOT/demo-1.0-20240101.010101-1-tests.jar"
        );
    }

    #[test]
    fn only_non_unique_snapshot_paths_are_mutable() {
        for (version, directory, mutable) in [
            ("1.0", "1.0", false),
            ("1.0-20260101.010101-1", "1.0-SNAPSHOT", false),
            ("1.0-SNAPSHOT", "1.0-SNAPSHOT", true),
            ("1.0SNAPSHOT", "1.0SNAPSHOT", true),
            ("SNAPSHOT", "SNAPSHOT", true),
        ] {
            for classifier in [None, Some("sources"), Some("SNAPSHOT")] {
                let coord = ArtifactCoord::new("g", "a-b", version, "jar", classifier);
                let path = artifact_path(&coord, directory, version);
                assert_eq!(is_mutable_snapshot_path(&path), mutable, "{path}");
            }
        }
    }

    #[test]
    fn metadata_paths() {
        assert_eq!(
            metadata_path("com.example", "demo", None),
            "com/example/demo/maven-metadata.xml"
        );
        assert_eq!(
            metadata_path("com.example", "demo", Some("1.0-SNAPSHOT")),
            "com/example/demo/1.0-SNAPSHOT/maven-metadata.xml"
        );
    }
}
