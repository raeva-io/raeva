use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::Args;

use rv_lock::Lockfile;
use rv_maven_types::{CoordinateField, HashAlgorithm, layout, validate_coordinate_component};

use crate::commands::{path_to_forward_slashes, write_atomic};
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Report};
use crate::session::Session;

#[derive(Debug, Args)]
// The `Commands` variant's doc comment sets `about` and clears
// `long_about`, so the details go in `after_long_help`.
#[command(after_long_help = "\
The files hold the checksums raeva.lock pins: every external artifact, its POM, \
and every parent and imported BOM, in the summary file format of the Trusted \
Checksums of Maven 3.9 and later. Reactor workspace nodes and system-path \
dependencies are skipped.

Maven checks nothing until told to. Pass these properties to mvn, or put them \
in .mvn/maven.config, with the project's absolute path:

  -Daether.artifactResolver.postProcessor.trustedChecksums=true
  -Daether.artifactResolver.postProcessor.trustedChecksums.snapshots=true
  -Daether.artifactResolver.postProcessor.trustedChecksums.checksumAlgorithms=SHA-256
  -Daether.trustedChecksumsSource.summaryFile=true
  -Daether.trustedChecksumsSource.summaryFile.basedir=<project>/.mvn/checksums
  -Daether.trustedChecksumsSource.summaryFile.originAware=false

Without the snapshots property, Maven checks no SNAPSHOT file. Use \
SHA-256,SHA-1 as the algorithms when checksums.sha1 is written. Build \
plugins are not in raeva.lock, so \
-Daether.artifactResolver.postProcessor.trustedChecksums.failIfMissing=true \
also refuses every plugin file Maven resolves. In a reactor, run package or a \
later phase: before package, Maven resolves a sibling module to its \
target/classes directory, and the check fails with \
\"java.io.IOException: Is a directory\".")]
pub(crate) struct ExportChecksumsArgs {}

pub(crate) fn run(_args: &ExportChecksumsArgs, session: &Session) -> Result<Report> {
    let project_root = session.project_root();
    let config = session.config()?;
    let lock = session.fresh_lockfile(&config)?.0;

    let split = build_checksums_files(&lock)?;
    let (sha256_path, sha1_path) = write_checksums_files(project_root, &split)?;
    let mut paths = vec![sha256_path];
    if split.sha1_count > 0 {
        paths.push(sha1_path);
    }
    let maven_properties = maven_properties(&project_root.join(".mvn").join("checksums"), &split);
    Ok(Report::data(ExportChecksumsReport {
        sha256_count: split.sha256_count,
        sha1_count: split.sha1_count,
        paths,
        maven_properties,
    }))
}

/// The `-D` options that make Maven 3.9 check its downloads and its local
/// repository against the files in `basedir`. The summary files say nothing
/// about the repository a file came from, hence `originAware=false`.
fn maven_properties(basedir: &Path, split: &ChecksumFiles) -> Vec<String> {
    let algorithms = if split.sha1_count > 0 {
        "SHA-256,SHA-1"
    } else {
        "SHA-256"
    };
    vec![
        "-Daether.artifactResolver.postProcessor.trustedChecksums=true".to_string(),
        "-Daether.artifactResolver.postProcessor.trustedChecksums.snapshots=true".to_string(),
        format!(
            "-Daether.artifactResolver.postProcessor.trustedChecksums.checksumAlgorithms={algorithms}"
        ),
        "-Daether.trustedChecksumsSource.summaryFile=true".to_string(),
        format!(
            "-Daether.trustedChecksumsSource.summaryFile.basedir={}",
            basedir.display()
        ),
        "-Daether.trustedChecksumsSource.summaryFile.originAware=false".to_string(),
    ]
}

struct ExportChecksumsReport {
    sha256_count: usize,
    sha1_count: usize,
    paths: Vec<PathBuf>,
    maven_properties: Vec<String>,
}

impl CommandOutput for ExportChecksumsReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let paths: Vec<String> = self
            .paths
            .iter()
            .map(|path| path_to_forward_slashes(path))
            .collect();
        Ok(serde_json::json!({
            "count": self.sha256_count + self.sha1_count,
            "sha256_count": self.sha256_count,
            "sha1_count": self.sha1_count,
            "path": paths[0],
            "paths": paths,
            "maven_properties": self.maven_properties,
        }))
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        let mut line = format!("Wrote {} SHA-256", self.sha256_count);
        if self.sha1_count > 0 {
            line.push_str(&format!(" and {} SHA-1", self.sha1_count));
        }
        line.push_str(if self.sha256_count + self.sha1_count == 1 {
            " checksum"
        } else {
            " checksums"
        });
        human.success(line)?;
        human.note("Maven 3.9 checks them when run with:")?;
        for property in &self.maven_properties {
            human.note(format!("  {property}"))?;
        }
        // The paths are the result, on stdout under --quiet too, so
        // `$(raeva --quiet export-checksums)` sees them.
        for path in &self.paths {
            human.line(path.display().to_string())?;
        }
        Ok(())
    }
}

/// Split of checksum entries by algorithm, ready to write to the two
/// Trusted Checksums summary files (`checksums.sha256`, `checksums.sha1`).
struct ChecksumFiles {
    sha256: String,
    sha1: String,
    sha256_count: usize,
    sha1_count: usize,
}

#[derive(Default)]
struct SummaryLines(BTreeMap<String, String>);

impl SummaryLines {
    /// Add `digest` for `path`. Two pins of one path are one line when they
    /// agree; `Lockfile::read` refuses most disagreements, and one that gets
    /// through fails the export rather than picking a side.
    fn add(&mut self, path: String, digest: String) -> Result<()> {
        let existing = self.0.entry(path.clone()).or_insert_with(|| digest.clone());
        if *existing != digest {
            return Err(CliError::LockfileDefect {
                details: format!("it pins {path} to two digests, {existing} and {digest}"),
            });
        }
        Ok(())
    }

    fn render(&self) -> String {
        let mut out = String::new();
        for (path, digest) in &self.0 {
            let _ = writeln!(out, "{digest}  {path}");
        }
        out
    }
}

/// Each line has the GNU coreutils format: `{hex}  {relative/path/to/artifact}`
/// (two spaces between hash and path, path relative to local repository root),
/// sorted by path.
///
/// The files cover every file Maven resolves for the locked graph and
/// `export-m2` writes: each artifact under its pin, each artifact's POM and
/// every parent or imported BOM under their SHA-256 pins, and for a
/// `SNAPSHOT` also the plain `-SNAPSHOT` copies, which Maven resolves when its
/// settings name another repository id than the export's labels. Without the
/// POMs, `failIfMissing` fails on the first one Maven reads. Each entry routes
/// to the file matching its pin's algorithm, so a SHA-1-only repository keeps
/// a complete checksum file rather than losing its SHA-1-pinned packages.
fn build_checksums_files(lock: &Lockfile) -> Result<ChecksumFiles> {
    let mut sha256 = SummaryLines::default();
    let mut sha1 = SummaryLines::default();

    let mut artifacts = BTreeMap::new();
    for platform in &lock.platforms {
        for artifact in &platform.artifacts {
            artifacts.entry(artifact.coord()).or_insert(artifact);
        }
    }

    for artifact in artifacts.into_values() {
        let coordinate = &artifact.coordinate;
        let directory = artifact.directory_version();
        let pom_version = artifact.pom_gav().version().to_string();
        let mut files = vec![artifact.file_version()];
        // Only a row that asks for a `-SNAPSHOT` version gets the plain
        // copies from export-m2.
        if artifact.snapshot.is_some() && coordinate.version() == directory && files[0] != directory
        {
            files.push(directory.clone());
        }
        for file_version in &files {
            if let Some(checksum) = artifact.pin() {
                let path = maven_repo_path_for(
                    coordinate.group_id(),
                    coordinate.artifact_id(),
                    &directory,
                    file_version,
                    coordinate.extension(),
                    coordinate.classifier(),
                )?;
                let lines = match checksum.algorithm() {
                    HashAlgorithm::Sha256 => &mut sha256,
                    HashAlgorithm::Sha1 => &mut sha1,
                    HashAlgorithm::Md5 => unreachable!("raeva.lock refuses md5 checksums"),
                };
                lines.add(path, checksum.hex().to_string())?;
            }
            if let Some(pom) = artifact.pom_sha256.as_ref() {
                let path = maven_repo_path_for(
                    coordinate.group_id(),
                    coordinate.artifact_id(),
                    &directory,
                    if *file_version == directory {
                        file_version
                    } else {
                        &pom_version
                    },
                    "pom",
                    None,
                )?;
                sha256.add(path, pom.as_str().to_string())?;
            }
        }
    }

    // export-m2 writes a parent or BOM under the version its POM text
    // names; Maven online reads the timestamped build.
    for (coordinate, pom) in lock.support_poms() {
        let (Some(file), Some((group, artifact, version))) = (
            pom.file_gav(&coordinate),
            rv_lock::split_support_pom_coord(&coordinate),
        ) else {
            continue;
        };
        let files = BTreeSet::from([version, file.version()]);
        for file_version in files {
            let directory = rv_maven_types::snapshot_base_version(file_version)
                .unwrap_or_else(|| file_version.to_string());
            let path = maven_repo_path_for(group, artifact, &directory, file_version, "pom", None)?;
            sha256.add(path, pom.sha256.as_str().to_string())?;
        }
    }

    Ok(ChecksumFiles {
        sha256: sha256.render(),
        sha1: sha1.render(),
        sha256_count: sha256.0.len(),
        sha1_count: sha1.0.len(),
    })
}

/// Write the checksum files into `<project_root>/.mvn/checksums/`, creating
/// the directories, and return the paths of the SHA-256 and SHA-1 files.
///
/// A cloned repository decides what `.mvn` holds, so a symbolic link (on
/// Windows also a junction) at `.mvn`, `.mvn/checksums` or either file is
/// refused: following it would let the repository point this write at any
/// directory or file the user can write. Each file is replaced by an atomic
/// rename, which never writes through a link at the file's own name.
fn write_checksums_files(project_root: &Path, split: &ChecksumFiles) -> Result<(PathBuf, PathBuf)> {
    let mvn_dir = project_root.join(".mvn");
    let checksums_dir = mvn_dir.join("checksums");
    real_directory(&mvn_dir)?;
    real_directory(&checksums_dir)?;

    // Maven Resolver expects `checksums.<algorithm>` (dot, not dash).
    // The optional repository-scoped form `checksums-<repoId>.<algorithm>`
    // is documented here for future work; raeva does not currently surface
    // a Maven Resolver repo-id through the lockfile. A dash form like
    // `checksums-sha256` is not picked up by Maven, so the Trusted
    // Checksums sidecar would be a silent no-op.
    let sha256_path = checksums_dir.join("checksums.sha256");
    let sha1_path = checksums_dir.join("checksums.sha1");
    regular_file_or_missing(&sha256_path)?;
    regular_file_or_missing(&sha1_path)?;

    write_atomic(&sha256_path, split.sha256.as_bytes())?;

    // A lockfile produced against a SHA-1-only repository legitimately
    // contains SHA-1 pins. Maven's Trusted Checksums read a parallel
    // `checksums.sha1` file, so emit SHA-1-pinned entries there rather
    // than dropping them and shipping a `checksums.sha256` file with
    // missing rows.
    if split.sha1_count > 0 {
        write_atomic(&sha1_path, split.sha1.as_bytes())?;
    } else {
        // Avoid leaving a stale file from a previous run.
        match fs::remove_file(&sha1_path) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => {
                return Err(CliError::io_at(sha1_path)(err));
            }
            _ => {}
        }
    }
    Ok((sha256_path, sha1_path))
}

/// Create `path` as a directory unless it exists, and refuse it unless it is
/// a directory itself rather than a link to one.
fn real_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Err(err) if err.kind() != io::ErrorKind::AlreadyExists => {
            return Err(CliError::io_at(path)(err));
        }
        _ => {}
    }
    let metadata = fs::symlink_metadata(path).map_err(CliError::io_at(path))?;
    if is_link(&metadata) {
        return Err(refuse_link(path));
    }
    if !metadata.is_dir() {
        return Err(CliError::Message(format!(
            "refusing to write checksums: {} is not a directory",
            path.display()
        )));
    }
    Ok(())
}

/// Refuse `path` when it exists as anything but a regular file.
fn regular_file_or_missing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CliError::io_at(path)(source)),
        Ok(metadata) if is_link(&metadata) => Err(refuse_link(path)),
        Ok(metadata) if !metadata.is_file() => Err(CliError::Message(format!(
            "refusing to write checksums: {} is not a regular file",
            path.display()
        ))),
        Ok(_) => Ok(()),
    }
}

/// On Windows `is_symlink` is true for every name-surrogate reparse point,
/// which covers directory junctions as well as symbolic links.
fn is_link(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn refuse_link(path: &Path) -> CliError {
    CliError::Message(format!(
        "refusing to write checksums through {}: it is a symbolic link or junction; \
         remove it and run `raeva export-checksums` again",
        path.display()
    ))
}

fn maven_repo_path_for(
    group_id: &str,
    artifact_id: &str,
    dir_version: &str,
    file_version: &str,
    packaging: &str,
    classifier: Option<&str>,
) -> Result<String> {
    let fields = [
        (CoordinateField::Group, group_id),
        (CoordinateField::Artifact, artifact_id),
        (CoordinateField::Version, dir_version),
        (CoordinateField::Version, file_version),
        (CoordinateField::Extension, packaging),
    ];
    let classifier_field = classifier.map(|classifier| (CoordinateField::Classifier, classifier));
    for (field, value) in fields.into_iter().chain(classifier_field) {
        validate_coordinate_component(field, value).map_err(|err| {
            CliError::Message(format!(
                "refusing to export the checksum of {group_id:?}:{artifact_id:?}:{file_version:?}: {err}"
            ))
        })?;
    }
    Ok(layout::artifact_path_from_parts(
        group_id,
        artifact_id,
        dir_version,
        file_version,
        packaging,
        classifier,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_lock::{LockArtifact, LockPlatform, Lockfile, Platform};
    use rv_maven_types::{ArtifactCoord, Gav};

    fn test_platform(platform: Platform, packages: Vec<LockArtifact>) -> LockPlatform {
        LockPlatform::single_module(
            platform,
            Gav::new("com.example", "root", "1"),
            "pom",
            packages,
        )
    }

    fn test_package(
        group: &str,
        artifact: &str,
        version: &str,
        packaging: &str,
        classifier: Option<&str>,
        sha256: &str,
    ) -> LockArtifact {
        // A short digest stands for a full one: pad it with zeros.
        let sha256 = format!("{sha256:0<64}");
        {
            let mut artifact = LockArtifact::new(
                ArtifactCoord::new(group, artifact, version, packaging, classifier),
                "https://repo1.maven.org/maven2/",
            );
            artifact.checksums = vec![rv_maven_types::Digest::parse("sha256", &sha256).unwrap()];
            artifact
        }
    }

    /// Maven's Trusted Checksums check every file it resolves, POMs too, so
    /// with `failIfMissing` a missing POM line fails the build. A snapshot
    /// row or parent also covers the plain `-SNAPSHOT` copies export-m2
    /// writes, which a row pinning a timestamped version has none of.
    #[test]
    fn build_checksums_covers_poms_support_poms_and_snapshot_copies() {
        let platform = Platform::new("linux", "x86_64").unwrap();
        let mut release = test_package("com.example", "lib", "1.0", "jar", None, "11");
        release.pom_sha256 = Some(format!("{:0<64}", "22").parse().unwrap());
        let mut snapshot = test_package("com.example", "snap", "2.0-SNAPSHOT", "jar", None, "33");
        snapshot.snapshot = rv_maven_types::SnapshotStamp::of_version("2.0-20240101.010101-7");
        snapshot.pom_sha256 = Some(format!("{:0<64}", "44").parse().unwrap());
        snapshot.pom_snapshot = rv_maven_types::SnapshotStamp::of_version("2.0-20240101.010101-6");
        let mut pinned = test_package(
            "com.example",
            "stamp",
            "3.0-20240101.010101-1",
            "jar",
            None,
            "66",
        );
        pinned.snapshot = rv_maven_types::SnapshotStamp::of_version("3.0-20240101.010101-1");
        let mut lock = Lockfile::new();
        lock.platforms = vec![test_platform(platform, vec![release, snapshot, pinned])];
        lock.platforms[0].support_poms.insert(
            "com.example:parent:3".to_string(),
            rv_lock::SupportPom::new(
                "https://repo.example/",
                format!("{:0<64}", "55").parse().unwrap(),
            ),
        );
        let mut parent = rv_lock::SupportPom::new(
            "https://repo.example/",
            format!("{:0<64}", "77").parse().unwrap(),
        );
        parent.snapshot = rv_maven_types::SnapshotStamp::new("20240101.010101", 2);
        lock.platforms[0]
            .support_poms
            .insert("com.example:sparent:4-SNAPSHOT".to_string(), parent.clone());
        lock.platforms[0]
            .support_poms
            .insert("com.example:sparent:5SNAPSHOT".to_string(), parent);

        let split = build_checksums_files(&lock).unwrap();
        let lines: Vec<(&str, &str)> = split
            .sha256
            .lines()
            .map(|line| line.split_once("  ").unwrap())
            .map(|(digest, path)| (&digest[..2], path))
            .collect();
        assert_eq!(
            lines,
            [
                ("11", "com/example/lib/1.0/lib-1.0.jar"),
                ("22", "com/example/lib/1.0/lib-1.0.pom"),
                ("55", "com/example/parent/3/parent-3.pom"),
                (
                    "44",
                    "com/example/snap/2.0-SNAPSHOT/snap-2.0-20240101.010101-6.pom"
                ),
                (
                    "33",
                    "com/example/snap/2.0-SNAPSHOT/snap-2.0-20240101.010101-7.jar"
                ),
                ("33", "com/example/snap/2.0-SNAPSHOT/snap-2.0-SNAPSHOT.jar"),
                ("44", "com/example/snap/2.0-SNAPSHOT/snap-2.0-SNAPSHOT.pom"),
                (
                    "77",
                    "com/example/sparent/4-SNAPSHOT/sparent-4-20240101.010101-2.pom"
                ),
                (
                    "77",
                    "com/example/sparent/4-SNAPSHOT/sparent-4-SNAPSHOT.pom"
                ),
                (
                    "77",
                    "com/example/sparent/520240101.010101-2/sparent-520240101.010101-2.pom"
                ),
                ("77", "com/example/sparent/5SNAPSHOT/sparent-5SNAPSHOT.pom"),
                (
                    "66",
                    "com/example/stamp/3.0-SNAPSHOT/stamp-3.0-20240101.010101-1.jar"
                ),
            ]
        );
        assert_eq!(split.sha256_count, 12);
    }

    fn sha256_split(line_count: usize) -> ChecksumFiles {
        ChecksumFiles {
            sha256: "0".repeat(64) + "  g/a/1/a-1.jar\n",
            sha1: String::new(),
            sha256_count: line_count,
            sha1_count: 0,
        }
    }

    /// Every hostile coordinate the lock reader refuses is refused here too,
    /// so a lock built in code cannot add a line or a path outside the
    /// repository layout to a trusted-checksums file.
    #[test]
    fn hostile_coordinates_never_reach_a_checksums_line() {
        let digest = "a".repeat(64);
        for (group, artifact, version, classifier) in [
            ("g", "a", "1.0\n0000  g/a/1/a-1.jar", None),
            ("g", "a", "../../x", None),
            ("g/../..", "a", "1", None),
            ("g", "a\u{1b}[2J", "1", None),
            ("g", "a", "1", Some("x\ry")),
            ("g", "a", "1:stream", None),
        ] {
            let platform = Platform::new("linux", "x86_64").unwrap();
            let mut lock = Lockfile::new();
            lock.platforms = vec![test_platform(
                platform,
                vec![test_package(
                    group, artifact, version, "jar", classifier, &digest,
                )],
            )];
            let err = match build_checksums_files(&lock) {
                Ok(_) => panic!("{group:?}:{artifact:?}:{version:?} must be refused"),
                Err(err) => err.to_string(),
            };
            assert!(!err.chars().any(char::is_control), "{err:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_directories_and_files() {
        use std::os::unix::fs::symlink;

        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("checksums.sha256");
        fs::write(&victim, "keep").unwrap();

        // `.mvn` links outside the project.
        let project = tempfile::tempdir().unwrap();
        symlink(outside.path(), project.path().join(".mvn")).unwrap();
        let err = write_checksums_files(project.path(), &sha256_split(1)).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");

        // `.mvn/checksums` links outside the project.
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join(".mvn")).unwrap();
        symlink(
            outside.path(),
            project.path().join(".mvn").join("checksums"),
        )
        .unwrap();
        let err = write_checksums_files(project.path(), &sha256_split(1)).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");

        // A dangling `.mvn` link would otherwise be created through.
        let project = tempfile::tempdir().unwrap();
        symlink(outside.path().join("gone"), project.path().join(".mvn")).unwrap();
        write_checksums_files(project.path(), &sha256_split(1)).unwrap_err();
        assert!(!outside.path().join("gone").exists());

        // The target file itself links outside the project.
        let project = tempfile::tempdir().unwrap();
        let checksums = project.path().join(".mvn").join("checksums");
        fs::create_dir_all(&checksums).unwrap();
        symlink(&victim, checksums.join("checksums.sha256")).unwrap();
        let err = write_checksums_files(project.path(), &sha256_split(1)).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");

        // A stale sha1 link is refused before anything is written.
        fs::remove_file(checksums.join("checksums.sha256")).unwrap();
        symlink(&victim, checksums.join("checksums.sha1")).unwrap();
        write_checksums_files(project.path(), &sha256_split(1)).unwrap_err();
        assert!(!checksums.join("checksums.sha256").exists());

        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn refuses_a_junction_at_either_directory() {
        fn junction(link: &Path, target: &Path) {
            rv_test_support::create_junction(link, target).unwrap();
        }

        let outside = tempfile::tempdir().unwrap();

        let project = tempfile::tempdir().unwrap();
        junction(&project.path().join(".mvn"), outside.path());
        let err = write_checksums_files(project.path(), &sha256_split(1)).unwrap_err();
        assert!(err.to_string().contains("junction"), "{err}");

        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join(".mvn")).unwrap();
        junction(
            &project.path().join(".mvn").join("checksums"),
            outside.path(),
        );
        let err = write_checksums_files(project.path(), &sha256_split(1)).unwrap_err();
        assert!(err.to_string().contains("junction"), "{err}");

        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }
}
