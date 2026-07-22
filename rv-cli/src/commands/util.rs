use std::io::Write;
use std::path::Path;

/// Convert a filesystem path to a forward-slash string, regardless of the
/// host OS path separator.
///
/// On POSIX systems this is a no-op. On Windows, `Path::display()` emits
/// backslashes which break cross-platform tooling that consumes JSON `"path"`
/// fields (e.g. shell scripts, Make targets). Replacing backslashes with
/// forward slashes matches what every Maven-adjacent tool expects.
pub fn path_to_forward_slashes(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn write_atomic(path: &Path, contents: &[u8]) -> crate::error::Result<()> {
    use crate::error::CliError;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| CliError::IoWithPath {
            path: path.to_path_buf(),
            source,
        })?;
    temp.as_file_mut()
        .write_all(contents)
        .and_then(|_| temp.as_file().sync_all())
        .map_err(|source| CliError::IoWithPath {
            path: path.to_path_buf(),
            source,
        })?;
    temp.persist(path).map_err(|error| CliError::IoWithPath {
        path: path.to_path_buf(),
        source: error.error,
    })?;
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

pub fn read_lockfile(config: &rv_config::Config) -> crate::error::Result<rv_config::Lockfile> {
    use crate::error::CliError;
    let path = &config.lock_path;
    match path.symlink_metadata() {
        // Path does not exist at all -> classic "missing lockfile" error.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::LockfileMissing { path: path.clone() });
        }
        Err(err) => {
            return Err(CliError::IoWithPath {
                path: path.clone(),
                source: err,
            });
        }
        Ok(meta) => {
            // Resolve symlinks (Lockfile::read also follows them).
            let resolved = if meta.file_type().is_symlink() {
                path.metadata()
            } else {
                Ok(meta)
            };
            match resolved {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    return Err(CliError::LockfileMissing { path: path.clone() });
                }
                Err(err) => {
                    return Err(CliError::IoWithPath {
                        path: path.clone(),
                        source: err,
                    });
                }
                Ok(meta) if !meta.is_file() => {
                    return Err(CliError::LockfileNotAFile { path: path.clone() });
                }
                Ok(_) => {}
            }
        }
    }
    Ok(rv_config::Lockfile::read(&config.lock_path)?)
}

pub fn read_fresh_lockfile(
    config: &rv_config::Config,
) -> crate::error::Result<rv_config::Lockfile> {
    read_fresh_lockfile_with_pom(config).map(|(lock, _)| lock)
}

pub fn read_fresh_lockfile_with_pom(
    config: &rv_config::Config,
) -> crate::error::Result<(rv_config::Lockfile, String)> {
    use crate::error::CliError;

    let lock = read_lockfile(config)?;
    let pom_path = config.project_root.join("pom.xml");
    if !pom_path.is_file() {
        return Err(CliError::ProjectFileMissing { path: pom_path });
    }

    let pom_xml = rv_config::read_project_input_string(&pom_path)?;
    let current_hash =
        crate::commands::sync::compute_config_hash_with_pom(config, &pom_path, &pom_xml)?;
    match lock.config_hash.as_deref() {
        Some(stored_hash) if stored_hash == current_hash => Ok((lock, pom_xml)),
        Some(_) => Err(CliError::LockfileMismatch {
            details: "rv.lock is out of date (pom.xml or resolution inputs changed)".to_string(),
        }),
        None => Err(CliError::LockfileMismatch {
            details: "rv.lock has no config_hash and cannot be checked for staleness".to_string(),
        }),
    }
}

pub fn parse_scope(value: &str) -> Result<rv_maven_model::Scope, String> {
    value
        .parse::<rv_maven_model::Scope>()
        .map_err(|err| err.to_string())
}

pub fn parse_platform(value: &str) -> Result<rv_config::Platform, String> {
    value
        .parse::<rv_config::Platform>()
        .map_err(|err| err.to_string())
}

pub fn select_platform(
    lock: &rv_config::Lockfile,
) -> Result<&rv_config::LockPlatform, crate::error::CliError> {
    let current = rv_config::Platform::current()?;
    if let Some(entry) = lock
        .platforms
        .iter()
        .find(|entry| entry.platform == current)
    {
        return Ok(entry);
    }
    if let Some(first) = lock.platforms.first() {
        // Always surface the platform fallback: routed through
        // `tracing::warn!` so JSON mode picks it up via the
        // WarningCollectorLayer (sec_code key) and human mode prints it.
        // Silently swapping platforms is a footgun that masks "wrong arch
        // jar" outcomes that look fine in JSON output.
        let current_str = current.to_string();
        let fallback_str = first.platform.to_string();
        tracing::warn!(
            sec_code = "PLATFORM_FALLBACK",
            current = %current_str,
            fallback = %fallback_str,
            "platform '{current_str}' not found in lockfile; using '{fallback_str}'"
        );
        if !crate::output::is_json_mode() && !crate::output::quiet_enabled() {
            eprintln!(
                "{}",
                crate::output::warning(format!(
                    "platform '{current_str}' not found in lockfile; using '{fallback_str}'"
                ))
            );
        }
        return Ok(first);
    }
    Err(crate::error::CliError::PlatformMissing {
        platform: current.to_string(),
    })
}

pub struct CommandContext {
    pub config: rv_config::Config,
    pub lock: rv_config::Lockfile,
    pub store: rv_store::Store,
}

impl CommandContext {
    pub async fn load_async(project_root: &Path) -> Result<Self, crate::error::CliError> {
        use crate::error::CliError;

        // `Config::load` reads rv.toml, the user config, and may parse
        // settings.xml, all synchronous fs ops. Off-load to the blocking
        // pool so an async caller doesn't stall a worker thread.
        let project_root_owned = project_root.to_path_buf();
        let config =
            tokio::task::spawn_blocking(move || rv_config::Config::load(&project_root_owned))
                .await
                .map_err(|e| CliError::Message(format!("config load task panicked: {e}")))??;
        let lock_path = config.lock_path.clone();
        let store_dir = config.paths.store_dir.clone();

        let (lock_result, store_result) = tokio::join!(
            tokio::task::spawn_blocking(move || {
                // Mirror the sync `read_lockfile` path: `symlink_metadata`
                // first, then resolve through `metadata` if the entry is
                // a symlink. Using bare `metadata` here would silently
                // follow symlinks and diverge from the sync path on
                // broken-link / not-a-file diagnostics.
                match lock_path.symlink_metadata() {
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        return Err(CliError::LockfileMissing { path: lock_path });
                    }
                    Err(err) => {
                        return Err(CliError::IoWithPath {
                            path: lock_path,
                            source: err,
                        });
                    }
                    Ok(meta) => {
                        let resolved = if meta.file_type().is_symlink() {
                            lock_path.metadata()
                        } else {
                            Ok(meta)
                        };
                        match resolved {
                            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                                return Err(CliError::LockfileMissing { path: lock_path });
                            }
                            Err(err) => {
                                return Err(CliError::IoWithPath {
                                    path: lock_path,
                                    source: err,
                                });
                            }
                            Ok(meta) if !meta.is_file() => {
                                return Err(CliError::LockfileNotAFile { path: lock_path });
                            }
                            Ok(_) => {}
                        }
                    }
                }
                rv_config::Lockfile::read(&lock_path).map_err(CliError::from)
            }),
            tokio::task::spawn_blocking(move || {
                rv_store::Store::open(&store_dir).map_err(CliError::from)
            }),
        );

        let lock = lock_result
            .map_err(|e| CliError::Message(format!("failed to load lockfile: {e}")))??;
        let store =
            store_result.map_err(|e| CliError::Message(format!("failed to open store: {e}")))??;

        Ok(Self {
            config,
            lock,
            store,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{read_lockfile, write_atomic};
    use crate::error::CliError;
    use rv_config::{Config, ResolvedPaths};
    use tempfile::TempDir;

    fn config_for(project_root: &std::path::Path) -> Config {
        let raeva_home = project_root.join(".raeva");
        let paths = ResolvedPaths::from_raeva_home(&raeva_home);
        Config::for_testing_with_repos(project_root.to_path_buf(), paths, Vec::new())
    }

    #[test]
    fn read_lockfile_returns_missing_when_path_absent() {
        let tmp = TempDir::new().expect("tempdir");
        let config = config_for(tmp.path());
        let err = read_lockfile(&config).expect_err("expected LockfileMissing");
        assert!(matches!(err, CliError::LockfileMissing { .. }), "{err:?}");
    }

    #[test]
    fn read_lockfile_returns_not_a_file_when_path_is_directory() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir(tmp.path().join("rv.lock")).expect("mkdir rv.lock");
        let config = config_for(tmp.path());
        let err = read_lockfile(&config).expect_err("expected LockfileNotAFile");
        assert!(
            matches!(err, CliError::LockfileNotAFile { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn write_atomic_replaces_existing_file() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bom.json");
        std::fs::write(&path, "old content").expect("write old content");

        write_atomic(&path, b"new content").expect("atomic write");

        assert_eq!(std::fs::read(&path).unwrap(), b"new content");
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
    }
}
