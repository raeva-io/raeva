//! The Maven repository path layout, shared by remote requests, the
//! local-repository export and the trusted-checksums file.
//!
//! These functions only format. They do not check the parts, so callers that
//! take them from untrusted input validate first (see
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
