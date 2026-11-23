//! The Maven repository path layout, shared by remote requests, the
//! local-repository export, the trusted-checksums file and the plugin trace,
//! which reads coordinates back from paths.
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

/// The coordinate of the release file at `path`, a `/`-separated
/// [`artifact_path`] of it, or `None` for any other path.
///
/// A file name alone is ambiguous when a classifier or an extension holds a
/// dot. A classifier such as `jdk1.8` is more common than such an extension,
/// so the extension is the part after the last dot, or the last two after
/// `tar`, as in `bin.tar.gz`. The result names the file `path` names, so a
/// fetch, a pin and an export address that file.
pub fn parse_artifact_path(path: &str) -> Option<ArtifactCoord> {
    let parts: Vec<&str> = path.split('/').collect();
    let [group @ .., artifact, version, name] = &parts[..] else {
        return None;
    };
    if group.is_empty() || crate::resolves_through_snapshot_metadata(version) {
        return None;
    }
    let rest = name.strip_prefix(&format!("{artifact}-{version}"))?;
    let (classifier, extension) = match rest.strip_prefix('-') {
        Some(tail) => {
            let (stem, last) = tail.rsplit_once('.')?;
            match stem.rsplit_once('.') {
                Some((classifier, "tar")) => (Some(classifier), &tail[classifier.len() + 1..]),
                _ => (Some(stem), last),
            }
        }
        None => (None, rest.strip_prefix('.')?),
    };
    let coordinate = ArtifactCoord::new(&group.join("."), artifact, version, extension, classifier);
    coordinate.validate().ok()?;
    (artifact_path(&coordinate, version, version) == path).then_some(coordinate)
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
    fn release_paths_parse_back() {
        for (path, shown) in [
            ("g/a/1/a-1.jar", Some("g:a:1:jar")),
            ("g/h/a/1.0/a-1.0-tests.jar", Some("g.h:a:1.0:jar:tests")),
            ("g/a/1/a-1-jdk1.8.jar", Some("g:a:1:jar:jdk1.8")),
            ("g/a/1/a-1-bin.tar.gz", Some("g:a:1:tar.gz:bin")),
            ("g/a/1/a-1-jdk1.8.tar.xz", Some("g:a:1:tar.xz:jdk1.8")),
            ("g/a/1/a-1.tar.gz", Some("g:a:1:tar.gz")),
            ("g/a/1/a-1-linux-x64.tar.gz", Some("g:a:1:tar.gz:linux-x64")),
            (
                "io/netty/netty-tcnative/2.0.1/netty-tcnative-2.0.1-linux-x86_64.jar",
                Some("io.netty:netty-tcnative:2.0.1:jar:linux-x86_64"),
            ),
            ("g/a/1/a-1-.jar", None),
            ("g/a/1/a-1-x", None),
            ("g/a/1/a-1", None),
            ("g.h/a/1/a-1.jar", None),
            ("a/1/a-1.jar", None),
            ("g/a/1/b-1.jar", None),
            ("g/a/1-SNAPSHOT/a-1-SNAPSHOT.jar", None),
        ] {
            let parsed = parse_artifact_path(path).map(|coord| coord.to_string());
            assert_eq!(parsed.as_deref(), shown, "{path}");
        }
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
