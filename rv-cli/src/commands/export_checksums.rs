use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use clap::Args;

use rv_config::{LockPackage, Lockfile, normalize_checksum_algorithm};

use crate::commands::{path_to_forward_slashes, read_lockfile};
use crate::error::{CliError, Result};
use crate::output::{heading, is_json_mode, json_result, quiet_enabled, success};

#[derive(Debug, Args)]
#[command(about = "Export checksums in Maven 4 Trusted Checksums format to .mvn/checksums/")]
pub struct ExportChecksumsArgs {}

pub fn run(_args: &ExportChecksumsArgs, project_root: &Path) -> Result<()> {
    let config = rv_config::Config::load(project_root)?;
    let lock = read_lockfile(&config)?;

    let checksums_dir = project_root.join(".mvn").join("checksums");
    fs::create_dir_all(&checksums_dir).map_err(|e| {
        CliError::Message(format!("failed to create .mvn/checksums/ directory: {}", e))
    })?;

    let split = build_checksums_files(&lock);
    let sha256_count = split.sha256_count;
    let sha1_count = split.sha1_count;

    // Maven Resolver expects `checksums.<algorithm>` (dot, not dash).
    // The optional repository-scoped form `checksums-<repoId>.<algorithm>`
    // is documented here for future work; rv does not currently surface
    // a Maven Resolver repo-id through the lockfile. A dash form like
    // `checksums-sha256` is not picked up by Maven, so the Trusted
    // Checksums sidecar would be a silent no-op.
    let sha256_path = checksums_dir.join("checksums.sha256");
    fs::write(&sha256_path, &split.sha256).map_err(|e| {
        CliError::Message(format!("failed to write {}: {}", sha256_path.display(), e))
    })?;

    // A lockfile produced against a SHA-1-only repository legitimately
    // contains SHA-1 pins. Maven 4 Trusted Checksums supports a parallel
    // `checksums-sha1` file, so emit SHA-1-pinned entries there rather
    // than dropping them and shipping a `checksums-sha256` file with
    // missing rows.
    let sha1_path = checksums_dir.join("checksums.sha1");
    if sha1_count > 0 {
        fs::write(&sha1_path, &split.sha1).map_err(|e| {
            CliError::Message(format!("failed to write {}: {}", sha1_path.display(), e))
        })?;
    } else {
        // Avoid leaving a stale file from a previous run.
        let _ = fs::remove_file(&sha1_path);
    }

    let total = sha256_count + sha1_count;

    if is_json_mode() {
        let sha256_path_str = path_to_forward_slashes(&sha256_path);
        let mut paths = vec![sha256_path_str.clone()];
        if sha1_count > 0 {
            paths.push(path_to_forward_slashes(&sha1_path));
        }
        json_result(
            true,
            serde_json::json!({
                "count": total,
                "sha256_count": sha256_count,
                "sha1_count": sha1_count,
                "path": sha256_path_str,
                "paths": paths,
            }),
        );
    } else {
        // Heading is decorative chatter -> stderr; the artifact path is the
        // machine-readable result -> stdout.
        if !quiet_enabled() {
            eprintln!("{}", heading("export-checksums summary"));
            eprintln!("Wrote {} artifact checksums", total);
            if sha1_count > 0 {
                eprintln!(
                    "  sha256: {} entries, sha1: {} entries",
                    sha256_count, sha1_count
                );
            }
            eprintln!("{}", success("done"));
        }
        // The artifact path is the machine-readable result of the command:
        // emit it on stdout unconditionally so `$(rv --quiet export-checksums)`
        // pipelines still see the path. Decorative output above stays
        // gated on `quiet_enabled()`.
        println!("{}", sha256_path.display());
        if sha1_count > 0 {
            println!("{}", sha1_path.display());
        }
    }

    Ok(())
}

/// Split of checksum entries by algorithm, ready to write to the two
/// Maven 4 Trusted Checksums files (`checksums-sha256`, `checksums-sha1`).
struct ChecksumFiles {
    sha256: String,
    sha1: String,
    sha256_count: usize,
    sha1_count: usize,
}

/// Build the checksum file contents, split by algorithm.
///
/// Each line has the GNU coreutils format: `{hex}  {relative/path/to/artifact}`
/// (two spaces between hash and path, path relative to local repository root).
///
/// Maven 4 Trusted Checksums supports both `checksums-sha256` and
/// `checksums-sha1`, so each entry routes to the file matching the lockfile
/// pin's algorithm. A SHA-1-only repository therefore keeps a complete
/// checksum file rather than losing its SHA-1-pinned packages.
fn build_checksums_files(lock: &Lockfile) -> ChecksumFiles {
    let mut sha256 = String::new();
    let mut sha1 = String::new();
    let mut sha256_count = 0usize;
    let mut sha1_count = 0usize;

    for platform in &lock.platforms {
        for package in &platform.packages {
            if package.system_path.is_some() {
                continue;
            }

            let Some(checksum) = package.checksum.as_ref() else {
                continue;
            };

            let Some(algorithm) = normalize_checksum_algorithm(&checksum.algorithm) else {
                // Anything outside the canonical sha256/sha1 set was
                // already going to fail downstream verification, so drop
                // it loudly via the lockfile schema rather than silently
                // here.
                continue;
            };

            let repo_path = maven_repo_path(package);
            let digest = checksum.digest.trim().to_ascii_lowercase();
            match algorithm {
                "sha256" => {
                    let _ = writeln!(sha256, "{}  {}", digest, repo_path);
                    sha256_count += 1;
                }
                "sha1" => {
                    let _ = writeln!(sha1, "{}  {}", digest, repo_path);
                    sha1_count += 1;
                }
                // `normalize_checksum_algorithm` only returns sha256 / sha1.
                _ => continue,
            }
        }
    }

    ChecksumFiles {
        sha256,
        sha1,
        sha256_count,
        sha1_count,
    }
}

/// Compute the Maven repository-relative path for a locked package.
///
/// E.g., `com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar`
///
/// Snapshots follow the same layout export-m2 writes (see
/// `export_m2::export::safe_artifact_path`): the directory uses the base
/// `-SNAPSHOT` version while the filename keeps the timestamped form, e.g.
/// `g/a/1.0-SNAPSHOT/a-1.0-20240101.010101-7.jar`. Using the raw timestamped
/// version for the directory would make Maven's repo-relative lookup miss
/// every snapshot entry, silently disabling checksum enforcement for them.
fn maven_repo_path(package: &LockPackage) -> String {
    maven_repo_path_for(
        &package.group_id,
        &package.artifact_id,
        &package.base_snapshot_version(),
        &package.version,
        &package.packaging,
        package.classifier.as_deref(),
    )
}

fn maven_repo_path_for(
    group_id: &str,
    artifact_id: &str,
    dir_version: &str,
    file_version: &str,
    packaging: &str,
    classifier: Option<&str>,
) -> String {
    let group_path = group_id.replace('.', "/");
    let filename = match classifier {
        Some(c) => format!("{}-{}-{}.{}", artifact_id, file_version, c, packaging),
        None => format!("{}-{}.{}", artifact_id, file_version, packaging),
    };
    format!(
        "{}/{}/{}/{}",
        group_path, artifact_id, dir_version, filename
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_config::{Checksum, LockPackage, LockPlatform, Lockfile, Platform};

    fn test_package(
        group: &str,
        artifact: &str,
        version: &str,
        packaging: &str,
        classifier: Option<&str>,
        sha256: &str,
    ) -> LockPackage {
        LockPackage {
            group_id: group.to_string(),
            artifact_id: artifact.to_string(),
            version: version.to_string(),
            snapshot_timestamp: None,
            packaging: packaging.to_string(),
            classifier: classifier.map(str::to_string),
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            checksum: Some(Checksum::new("sha256", sha256)),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn maven_repo_path_simple_jar() {
        let pkg = test_package(
            "com.google.code.findbugs",
            "jsr305",
            "3.0.2",
            "jar",
            None,
            "abc123",
        );
        assert_eq!(
            maven_repo_path(&pkg),
            "com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar"
        );
    }

    #[test]
    fn maven_repo_path_with_classifier() {
        let pkg = test_package(
            "org.example",
            "lib",
            "1.0.0",
            "jar",
            Some("sources"),
            "def456",
        );
        assert_eq!(
            maven_repo_path(&pkg),
            "org/example/lib/1.0.0/lib-1.0.0-sources.jar"
        );
    }

    /// Timestamped SNAPSHOT pins must land in the base `-SNAPSHOT` directory
    /// (the layout export-m2 writes and Maven resolves through), keeping the
    /// timestamped filename.
    #[test]
    fn maven_repo_path_timestamped_snapshot_uses_base_snapshot_dir() {
        let pkg = test_package(
            "com.example",
            "demo",
            "1.0-20240101.010101-7",
            "jar",
            None,
            "abc123",
        );
        assert_eq!(
            maven_repo_path(&pkg),
            "com/example/demo/1.0-SNAPSHOT/demo-1.0-20240101.010101-7.jar"
        );
    }

    /// Plain `-SNAPSHOT` versions keep the version verbatim in both
    /// directory and filename.
    #[test]
    fn maven_repo_path_plain_snapshot_is_verbatim() {
        let pkg = test_package("com.example", "demo", "1.0-SNAPSHOT", "jar", None, "abc123");
        assert_eq!(
            maven_repo_path(&pkg),
            "com/example/demo/1.0-SNAPSHOT/demo-1.0-SNAPSHOT.jar"
        );
    }

    /// Snapshot checksum lines written through `build_checksums_files` must
    /// carry the export-m2 layout end to end.
    #[test]
    fn build_checksums_uses_snapshot_layout() {
        let platform = Platform::new("linux", "x86_64").unwrap();
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![test_package(
                "com.example",
                "demo",
                "2.3-20240511.121314-42",
                "jar",
                Some("sources"),
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            )],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let split = build_checksums_files(&lock);
        let lines: Vec<&str> = split.sha256.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0]
                .ends_with("com/example/demo/2.3-SNAPSHOT/demo-2.3-20240511.121314-42-sources.jar"),
            "snapshot line must use the base -SNAPSHOT directory, got {:?}",
            lines[0]
        );
    }

    #[test]
    fn maven_repo_path_pom() {
        let pkg = test_package(
            "org.springframework",
            "spring-core",
            "6.1.0",
            "pom",
            None,
            "aabbcc",
        );
        assert_eq!(
            maven_repo_path(&pkg),
            "org/springframework/spring-core/6.1.0/spring-core-6.1.0.pom"
        );
    }

    #[test]
    fn build_checksums_file_format() {
        let platform = Platform::new("linux", "x86_64").unwrap();
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![
                test_package(
                    "com.google.code.findbugs",
                    "jsr305",
                    "3.0.2",
                    "jar",
                    None,
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                ),
                test_package(
                    "org.example",
                    "lib",
                    "1.0.0",
                    "jar",
                    None,
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                ),
            ],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let split = build_checksums_files(&lock);
        let lines: Vec<&str> = split.sha256.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar"
        );
        assert_eq!(
            lines[1],
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef  org/example/lib/1.0.0/lib-1.0.0.jar"
        );
        assert!(split.sha1.is_empty(), "no sha1 pins → empty sha1 output");
    }

    #[test]
    fn build_checksums_file_skips_system_path() {
        let platform = Platform::new("linux", "x86_64").unwrap();
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.local".to_string(),
                artifact_id: "local-lib".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "".to_string(),
                checksum: Some(Checksum::new("sha256", "aabbcc")),
                system_path: Some("/opt/libs/local.jar".to_string()),
                direct_scope: None,
                extra: std::collections::BTreeMap::new(),
            }],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let split = build_checksums_files(&lock);
        assert!(
            split.sha256.is_empty() && split.sha1.is_empty(),
            "system_path packages should be skipped from both outputs"
        );
    }

    #[test]
    fn build_checksums_file_skips_missing_checksum() {
        let platform = Platform::new("linux", "x86_64").unwrap();
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "no-checksum".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo.example/maven2/".to_string(),
                checksum: None,
                system_path: None,
                direct_scope: None,
                extra: std::collections::BTreeMap::new(),
            }],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let split = build_checksums_files(&lock);
        assert!(
            split.sha256.is_empty() && split.sha1.is_empty(),
            "packages without checksum should be skipped from both outputs"
        );
    }

    /// Regression: a SHA-1-pinned lockfile (legitimately produced by the
    /// default `rv sync` SHA-1-sidecar fallback against a SHA-1-only
    /// repository) must have its entries land in the `checksums-sha1` file
    /// rather than being silently dropped from the export.
    #[test]
    fn build_checksums_routes_sha1_pins_to_sha1_file() {
        let platform = Platform::new("linux", "x86_64").unwrap();
        let mut lock = Lockfile::new();
        let mut sha1_pkg = test_package(
            "org.legacy",
            "old-lib",
            "0.9",
            "jar",
            None,
            "ignored-replaced-below",
        );
        sha1_pkg.checksum = Some(Checksum::new(
            "sha1",
            "0123456789abcdef0123456789abcdef01234567",
        ));
        let sha256_pkg = test_package(
            "org.modern",
            "new-lib",
            "1.0",
            "jar",
            None,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        );
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![sha1_pkg, sha256_pkg],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let split = build_checksums_files(&lock);
        let sha256_lines: Vec<&str> = split.sha256.lines().collect();
        let sha1_lines: Vec<&str> = split.sha1.lines().collect();
        assert_eq!(sha256_lines.len(), 1, "sha256 file: {:?}", split.sha256);
        assert_eq!(sha1_lines.len(), 1, "sha1 file: {:?}", split.sha1);
        assert!(
            sha1_lines[0].starts_with("0123456789abcdef0123456789abcdef01234567"),
            "sha1 line should carry the sha1 digest, got {:?}",
            sha1_lines[0]
        );
        assert!(
            sha1_lines[0].ends_with("org/legacy/old-lib/0.9/old-lib-0.9.jar"),
            "sha1 line should carry the maven path, got {:?}",
            sha1_lines[0]
        );
    }

    /// `path_to_forward_slashes` must replace Windows-style backslashes
    /// with forward slashes so the JSON `"path"` key is cross-platform.
    ///
    /// We construct a `Path` from a string with backslashes rather than from
    /// a Windows-style `PathBuf` (which is only available on Windows) so this
    /// test runs on every platform and still exercises the replacement.
    #[test]
    fn path_to_forward_slashes_replaces_backslashes() {
        // Simulate a Windows-origin path string.
        let windows_path = std::path::Path::new(".mvn\\checksums\\checksums.sha256");
        let result = crate::commands::path_to_forward_slashes(windows_path);
        assert!(
            !result.contains('\\'),
            "output must contain no backslashes, got: {result}"
        );
        assert!(
            result.contains('/'),
            "output must contain forward slashes, got: {result}"
        );
        assert_eq!(result, ".mvn/checksums/checksums.sha256");
    }
}
