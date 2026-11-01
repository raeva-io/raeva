//! What every command starts from: the project directory and the paths the
//! configuration chose.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rv_config::Config;
use rv_config::maven_config::CommandLine;
use rv_lock::Lockfile;

use crate::commands::lock_inputs::ReactorModel;
use crate::error::{CliError, HintEnv, Result};
use crate::output::Output;

#[derive(Clone, Debug)]
pub(crate) struct Session(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    project_root: PathBuf,
    offline: bool,
    maven_options: CommandLine,
    output: Output,
    /// What error hints may name from the loaded configuration.
    hints: Mutex<Option<HintEnv>>,
}

impl Session {
    /// `project_root` is made absolute, so the project has a name even when
    /// given as `.`.
    #[cfg(test)]
    pub(crate) fn new(project_root: &Path) -> Result<Self> {
        Self::with_options(
            project_root,
            false,
            CommandLine::default(),
            Output::for_tests(),
        )
    }

    /// `offline` is the global `--offline` flag, and `maven_options` the
    /// global `-D`, `-P` and `-s`.
    pub(crate) fn with_options(
        project_root: &Path,
        offline: bool,
        maven_options: CommandLine,
        output: Output,
    ) -> Result<Self> {
        let project_root =
            std::path::absolute(project_root).map_err(CliError::io_at(project_root))?;
        Ok(Self(Arc::new(Inner {
            project_root,
            offline,
            maven_options,
            output,
            hints: Mutex::new(None),
        })))
    }

    pub(crate) fn project_root(&self) -> &Path {
        &self.0.project_root
    }

    /// Where this run prints.
    pub(crate) fn output(&self) -> &Output {
        &self.0.output
    }

    /// `--offline`: use cached data and file repositories only.
    pub(crate) fn offline(&self) -> bool {
        self.0.offline
    }

    /// Refuse `--offline` for a command whose whole job is a network call.
    pub(crate) fn require_network(&self, command: &str, what: &str) -> Result<()> {
        if self.offline() {
            return Err(CliError::Usage(format!(
                "{} {what} and cannot run with --offline",
                crate::output::command_line(command)
            )));
        }
        Ok(())
    }

    pub(crate) fn project_name(&self) -> String {
        let root = self.project_root();
        let named = match root.file_name() {
            Some(_) => root.to_path_buf(),
            // `absolute` keeps a trailing `..`, which has no file name.
            None => dunce::canonicalize(root).unwrap_or_else(|_| root.to_path_buf()),
        };
        named
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("root")
            .to_string()
    }

    pub(crate) fn config(&self) -> Result<Config> {
        let config = Config::load_with_command_line(self.project_root(), &self.0.maven_options)
            .map_err(config_error)?;
        self.remember_paths(config)
    }

    /// [`Session::config`] for a command that reads only raeva.lock and the
    /// store, which an invalid `.mvn/maven.config` does not stop.
    pub(crate) fn lock_config(&self) -> Result<Config> {
        let config = Config::load_for_lock(self.project_root(), &self.0.maven_options)
            .map_err(config_error)?;
        self.remember_paths(config)
    }

    fn remember_paths(&self, config: Config) -> Result<Config> {
        if let Ok(mut hints) = self.0.hints.lock() {
            *hints = Some(HintEnv::for_config(&config));
        }
        Ok(config)
    }

    /// Read raeva.lock for `config`'s project, refused with exit 7 unless its
    /// configuration matches and its pins still match resolution when the
    /// local reactor model changes, for a command that acts on the project
    /// from the lock alone. Also returns the reactor model of each locked
    /// platform the check discovered, and the repositories a resolution the
    /// check ran trusted. Call on the blocking pool: the check may drive
    /// async resolution through the current runtime.
    pub(crate) fn fresh_lockfile(
        &self,
        config: &Config,
    ) -> Result<(Lockfile, Vec<ReactorModel>, Vec<rv_repo::Repository>)> {
        tokio::runtime::Handle::current().block_on(crate::commands::read_fresh_lockfile(
            config,
            self.offline(),
            self.output(),
        ))
    }

    pub(crate) async fn config_async(&self) -> Result<Config> {
        self.blocking("config load", Self::config).await
    }

    /// Run `work` with this session on the blocking pool, so its std::fs
    /// reads and waits don't park the runtime's IO thread.
    pub(crate) async fn blocking<T, F>(&self, what: &str, work: F) -> Result<T>
    where
        F: FnOnce(&Self) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let session = self.clone();
        tokio::task::spawn_blocking(move || work(&session))
            .await
            .map_err(|err| CliError::task_failed(what, err))?
    }

    /// What error hints may name for this invocation.
    pub(crate) fn hint_env(&self) -> HintEnv {
        (self.0.hints.lock().ok())
            .and_then(|hints| hints.clone())
            .unwrap_or_else(HintEnv::discover)
    }
}

/// A `.mvn/maven.config` error is a project input's, and a `-D` or `-P`
/// value Maven would refuse a usage error.
fn config_error(error: rv_config::ConfigError) -> CliError {
    match error {
        rv_config::ConfigError::Invalid {
            origin: rv_config::ConfigOrigin::MavenConfig(path),
            message,
        } => CliError::InvalidProjectInput {
            path,
            reason: message,
        },
        rv_config::ConfigError::Invalid {
            origin: rv_config::ConfigOrigin::CommandLine,
            message,
        } => CliError::Usage(format!("invalid -D or -P option: {message}")),
        error => error.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::Session;

    #[test]
    fn a_relative_root_becomes_absolute_and_keeps_its_name() {
        let session = Session::new(std::path::Path::new(".")).expect("session");
        assert!(session.project_root().is_absolute());
        let cwd = std::env::current_dir().expect("cwd");
        let expected = cwd
            .file_name()
            .and_then(|name| name.to_str())
            .expect("cwd name");
        assert_eq!(session.project_name(), expected);
    }

    #[test]
    fn a_parent_root_is_named_after_the_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let child = dir.path().join("child");
        std::fs::create_dir(&child).expect("child");
        let session = Session::new(&child.join("..")).expect("session");
        let expected = dunce::canonicalize(dir.path()).expect("canonical");
        assert_eq!(
            session.project_name(),
            expected
                .file_name()
                .and_then(|name| name.to_str())
                .expect("name")
        );
    }
}
