//! The `[plugins]` table of the project's `raeva.toml`: whether
//! `raeva.lock` locks the build's plugins, the goals they are for, and the
//! build `raeva sync` traces.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use crate::{ConfigError, ConfigOrigin};

/// The `[plugins]` settings of a project whose `raeva.toml` sets `lock =
/// true`, all from that file: they decide what `raeva.lock` holds, so every
/// machine reads the same.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginsConfig {
    /// Goals the build is run with, such as `spotless:check`, whose plugins
    /// the tables add to those the POMs bind.
    pub goals: Vec<String>,
    /// The build `raeva sync` runs once to pin what plugins fetch while
    /// they run.
    pub trace: Option<PluginTrace>,
}

/// The build `[plugins] trace` names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginTrace {
    /// Its Maven arguments, at least one.
    pub args: Vec<String>,
    /// The launcher it runs with, as written.
    pub mvn: Option<String>,
}

impl crate::Config {
    /// The build `[plugins] trace` names, when the plugins are locked.
    pub fn plugin_trace(&self) -> Option<&PluginTrace> {
        self.plugins.as_ref()?.trace.as_ref()
    }
}

/// `[plugins]` as written in `raeva.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PluginsConfigToml {
    pub lock: Option<bool>,
    pub goals: Option<Vec<String>>,
    pub trace: Option<Vec<String>>,
    pub mvn: Option<String>,
}

const MAX_ENTRIES: usize = 64;
const MAX_ENTRY_LEN: usize = 1024;

impl PluginTrace {
    /// The launcher of the traced build: `mvn`, a command name looked up on
    /// `PATH`, or a file inside `project_root`. The name was checked as
    /// written when the configuration loaded; a file is also refused when a
    /// link leads it out of the project.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] for a path that resolves outside the
    /// project or to no file.
    pub fn launcher(&self, project_root: &Path) -> Result<PathBuf, ConfigError> {
        self.launcher_on(project_root, cfg!(windows))
    }

    /// Windows appends `.exe` to a launcher without an extension and runs a
    /// batch file only by its own, so there the launcher is the `.cmd` that
    /// Maven and its wrapper ship beside the script.
    fn launcher_on(&self, project_root: &Path, windows: bool) -> Result<PathBuf, ConfigError> {
        let mut mvn = self.mvn.clone().unwrap_or_else(|| "mvn".to_string());
        if windows && Path::new(&mvn).extension().is_none() {
            mvn.push_str(".cmd");
        }
        let mvn = mvn.as_str();
        if !is_project_path(mvn) {
            return Ok(PathBuf::from(mvn));
        }
        let invalid = |message: String| ConfigError::Invalid {
            origin: ConfigOrigin::ProjectConfig(project_root.join("raeva.toml")),
            message,
        };
        let path = project_root.join(mvn);
        let inside = canonical(project_root)
            .and_then(|root| Ok((canonical(&path)?, root)))
            .map(|(file, root)| file.starts_with(root).then_some(file));
        match inside {
            Ok(Some(file)) if file.is_file() => Ok(file),
            Ok(Some(_)) => Err(invalid(format!("plugins.mvn {mvn:?} is not a file"))),
            Ok(None) => Err(invalid(format!(
                "plugins.mvn {mvn:?} leads out of the project directory"
            ))),
            Err(error) => Err(invalid(format!("plugins.mvn {mvn:?}: {error}"))),
        }
    }
}

fn canonical(path: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(path).map(|path| rv_fs::plain_path(&path))
}

/// Whether `mvn` names a file by its path rather than a command on `PATH`.
fn is_project_path(mvn: &str) -> bool {
    mvn.contains(['/', '\\'])
}

/// Why `mvn` is not a launcher a project may name: a command name of ASCII
/// letters, digits, `.`, `_`, `+` and `-`, or a relative path that stays
/// inside the project.
fn launcher_problem(mvn: &str) -> Option<&'static str> {
    if !is_project_path(mvn) {
        let name = !mvn.is_empty()
            && mvn.len() <= MAX_ENTRY_LEN
            && mvn != "."
            && mvn != ".."
            && (mvn.bytes())
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'));
        return (!name).then_some(
            "must be a command name of ASCII letters, digits, '.', '_', '+' and '-', or a \
             relative path inside the project such as \"./mvnw\"",
        );
    }
    if mvn.contains('\\') {
        return Some("separates its path with '/'");
    }
    if mvn.len() > MAX_ENTRY_LEN || mvn.chars().any(char::is_control) {
        return Some("must be a short path without control characters");
    }
    let mut depth = 0usize;
    for component in Path::new(mvn).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir => return Some("leads out of the project directory"),
            Component::RootDir | Component::Prefix(_) => {
                return Some("must be relative to the project directory");
            }
        }
    }
    (depth == 0).then_some("must name a file")
}

/// The `[plugins]` settings of `project`. `user`, from `config.toml`, may
/// not hold any: they are lock inputs.
pub(crate) fn merge_plugins(
    project: Option<PluginsConfigToml>,
    user: Option<PluginsConfigToml>,
    origins: &(ConfigOrigin, ConfigOrigin),
) -> Result<Option<PluginsConfig>, ConfigError> {
    if user.is_some() {
        return Err(ConfigError::Invalid {
            origin: origins.1.clone(),
            message: "[plugins] belongs in the project's raeva.toml, since it decides what \
                      raeva.lock holds"
                .to_string(),
        });
    }
    let Some(project) = project else {
        return Ok(None);
    };
    let invalid = |message: String| ConfigError::Invalid {
        origin: origins.0.clone(),
        message,
    };
    let lock = project.lock.unwrap_or(false);
    for (key, set) in [
        ("goals", project.goals.is_some()),
        ("trace", project.trace.is_some()),
        ("mvn", project.mvn.is_some()),
    ] {
        if set && !lock {
            return Err(invalid(format!("plugins.{key} needs plugins.lock = true")));
        }
    }
    if !lock {
        return Ok(None);
    }
    let goals = project.goals.unwrap_or_default();
    check_entries("goals", &goals, |goal| {
        goal.chars().any(|c| c.is_whitespace() || c.is_control())
    })
    .map_err(invalid)?;
    let trace = match project.trace {
        Some(args) if args.is_empty() => {
            return Err(invalid("plugins.trace names no Maven argument".to_string()));
        }
        Some(args) => {
            // Maven's quote cleaning joins an argument that starts with `"`
            // with those after it, raeva's local repository among them.
            check_entries("trace", &args, |arg| {
                arg.starts_with('"') || arg.chars().any(char::is_control)
            })
            .map_err(invalid)?;
            if let Some(index) = sets_local_repository(&args) {
                return Err(invalid(format!(
                    "plugins.trace entry {} sets maven.repo.local or its tail or head; the \
                     traced build takes its local repository from raeva, which reads what it \
                     downloads there",
                    index + 1
                )));
            }
            if let Some(problem) = project.mvn.as_deref().and_then(launcher_problem) {
                return Err(invalid(format!("plugins.mvn {problem}")));
            }
            Some(PluginTrace {
                args,
                mvn: project.mvn,
            })
        }
        None if project.mvn.is_some() => {
            return Err(invalid("plugins.mvn needs plugins.trace".to_string()));
        }
        None => None,
    };
    Ok(Some(PluginsConfig { goals, trace }))
}

/// The place of the first Maven argument that defines `maven.repo.local` or
/// a `maven.repo.local.tail` or `maven.repo.local.head` property. The traced
/// build would download into that repository, or read from it, instead of
/// the one raeva watches.
fn sets_local_repository(args: &[String]) -> Option<usize> {
    let mut args = args.iter().enumerate().peekable();
    while let Some((index, arg)) = args.next() {
        // commons-cli reads `-D=a=b` as `-D a=b`.
        let define = match arg.as_str() {
            "-D" | "--define" => args.peek().map(|(_, next)| next.as_str()),
            arg => (arg.strip_prefix("--define=")).or_else(|| {
                let define = arg.strip_prefix("-D")?;
                Some(define.strip_prefix('=').unwrap_or(define))
            }),
        };
        // MavenCli trims the name as String.trim does.
        let name = define.map(|define| {
            let name = define.split_once('=').map_or(define, |(name, _)| name);
            name.trim_matches(|c: char| c <= ' ')
        });
        if name.is_some_and(|name| {
            name == "maven.repo.local"
                || ["maven.repo.local.tail", "maven.repo.local.head"]
                    .iter()
                    .any(|chained| name.starts_with(chained))
        }) {
            return Some(index);
        }
    }
    None
}

/// Refuse more than [`MAX_ENTRIES`] entries, and an entry that is empty,
/// longer than [`MAX_ENTRY_LEN`] or `bad`. The message names the entry by
/// its place, never its text, which may hold a secret.
fn check_entries(key: &str, entries: &[String], bad: impl Fn(&str) -> bool) -> Result<(), String> {
    if entries.len() > MAX_ENTRIES {
        return Err(format!("plugins.{key} has more than {MAX_ENTRIES} entries"));
    }
    match (entries.iter())
        .position(|entry| entry.is_empty() || entry.len() > MAX_ENTRY_LEN || bad(entry))
    {
        Some(index) => Err(format!(
            "plugins.{key} entry {} is empty, longer than {MAX_ENTRY_LEN} bytes or holds a \
             character it may not",
            index + 1
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origins() -> (ConfigOrigin, ConfigOrigin) {
        (
            ConfigOrigin::ProjectConfig(PathBuf::from("/p/raeva.toml")),
            ConfigOrigin::UserConfig(PathBuf::from("/home/u/.config/raeva/config.toml")),
        )
    }

    fn parse(text: &str) -> Result<Option<PluginsConfig>, String> {
        #[derive(Deserialize)]
        struct File {
            plugins: Option<PluginsConfigToml>,
        }
        let file: File = toml::from_str(text).map_err(|error| error.to_string())?;
        merge_plugins(file.plugins, None, &origins()).map_err(|error| error.to_string())
    }

    #[test]
    fn reads_the_plugins_table() {
        assert_eq!(parse("").unwrap(), None);
        assert_eq!(parse("[plugins]\n").unwrap(), None);
        assert_eq!(parse("[plugins]\nlock = false\n").unwrap(), None);
        assert_eq!(
            parse("[plugins]\nlock = true\n").unwrap(),
            Some(PluginsConfig::default())
        );
        let config = parse(
            "[plugins]\nlock = true\ngoals = ['spotless:check']\ntrace = ['verify', \
             '-DskipTests']\nmvn = './mvnw'\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(config.goals, ["spotless:check"]);
        let trace = config.trace.unwrap();
        assert_eq!(trace.args, ["verify", "-DskipTests"]);
        assert_eq!(trace.mvn.as_deref(), Some("./mvnw"));
    }

    #[test]
    fn refuses_what_a_project_may_not_set() {
        for (text, expected) in [
            (
                "[plugins]\ntrace = ['verify']\n",
                "plugins.trace needs plugins.lock = true",
            ),
            (
                "[plugins]\nlock = false\ngoals = ['a:b']\n",
                "plugins.goals needs",
            ),
            (
                "[plugins]\nlock = true\ngoals = ['a b']\n",
                "plugins.goals entry 1",
            ),
            (
                "[plugins]\nlock = true\ntrace = []\n",
                "names no Maven argument",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify', \"a\\nb\"]\n",
                "plugins.trace entry 2",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify']\nmvn = '/usr/bin/mvn'\n",
                "relative to the project",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify']\nmvn = '../mvnw'\n",
                "leads out of the project",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify']\nmvn = 'bin/../../mvnw'\n",
                "leads out of the project",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify']\nmvn = 'bin/..'\n",
                "must name a file",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify']\nmvn = 'mvn; rm'\n",
                "must be a command name",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify']\nmvn = '.\\\\mvnw.cmd'\n",
                "with '/'",
            ),
            (
                "[plugins]\nlock = true\nmvn = 'mvnd'\n",
                "plugins.mvn needs plugins.trace",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['-Dmaven.repo.local=/r', 'verify']\n",
                "plugins.trace entry 1 sets maven.repo.local",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify', '-D', 'maven.repo.local=r']\n",
                "plugins.trace entry 2 sets maven.repo.local",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify', '--define=maven.repo.local.tail=r']\n",
                "plugins.trace entry 2 sets maven.repo.local",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['--define', 'maven.repo.local']\n",
                "plugins.trace entry 1 sets maven.repo.local",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify', '-D maven.repo.local.head=r']\n",
                "plugins.trace entry 2 sets maven.repo.local",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['verify', '-D=maven.repo.local.tail=r']\n",
                "plugins.trace entry 2 sets maven.repo.local",
            ),
            (
                "[plugins]\nlock = true\ntrace = ['validate', '\"-Dx=1']\n",
                "plugins.trace entry 2 is empty",
            ),
            ("[plugins]\nlock = true\nextra = 1\n", "unknown field"),
        ] {
            let error = parse(text).unwrap_err();
            assert!(error.contains(expected), "{text}: {error}");
        }
        assert!(parse("[plugins]\nlock = true\ntrace = ['verify']\nmvn = 'sub/../mvnw'\n").is_ok());
        assert!(parse("[plugins]\nlock = true\ntrace = ['verify']\nmvn = 'mvnd'\n").is_ok());
        assert!(
            parse(
                "[plugins]\nlock = true\ntrace = ['verify', '-Dmaven.repo.local.recordReverseTree=true', \
                 '-Dmaven.repo.localx=1', '-D', 'x=maven.repo.local']\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn the_user_config_holds_no_plugin_settings() {
        let error =
            merge_plugins(None, Some(PluginsConfigToml::default()), &origins()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("belongs in the project's raeva.toml"),
            "{error}"
        );
    }

    /// A launcher inside the project runs from there; a directory or a link
    /// that leads out of it is refused, and a command name is left to `PATH`.
    #[test]
    fn a_project_launcher_stays_in_the_project() {
        let root = tempfile::TempDir::new().unwrap();
        let root = canonical(root.path()).unwrap();
        let project = root.join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("mvnw"), "").unwrap();
        std::fs::write(root.join("outside"), "").unwrap();
        let with = |mvn: Option<&str>| PluginTrace {
            mvn: mvn.map(str::to_string),
            ..PluginTrace::default()
        };
        let unix = |mvn| with(mvn).launcher_on(&project, false);
        assert_eq!(unix(None).unwrap(), PathBuf::from("mvn"));
        assert_eq!(unix(Some("./mvnw")).unwrap(), project.join("mvnw"));
        assert!(unix(Some("./missing")).is_err());
        std::fs::create_dir(project.join(".mvn")).unwrap();
        let error = unix(Some("./.mvn")).unwrap_err();
        assert!(error.to_string().contains("is not a file"), "{error}");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("outside"), project.join("link")).unwrap();
            let error = unix(Some("./link")).unwrap_err();
            assert!(
                error.to_string().contains("leads out of the project"),
                "{error}"
            );
        }
    }

    /// On Windows the default and a wrapper script name their `.cmd`.
    #[test]
    fn a_windows_launcher_is_the_batch_file() {
        let project = tempfile::TempDir::new().unwrap();
        let project = canonical(project.path()).unwrap();
        std::fs::write(project.join("mvnw.cmd"), "").unwrap();
        let windows = |mvn: Option<&str>| {
            PluginTrace {
                mvn: mvn.map(str::to_string),
                ..PluginTrace::default()
            }
            .launcher_on(&project, true)
        };
        assert_eq!(windows(None).unwrap(), PathBuf::from("mvn.cmd"));
        assert_eq!(windows(Some("./mvnw")).unwrap(), project.join("mvnw.cmd"));
        assert_eq!(
            windows(Some("./mvnw.cmd")).unwrap(),
            project.join("mvnw.cmd")
        );
        assert_eq!(windows(Some("mvn.bat")).unwrap(), PathBuf::from("mvn.bat"));
    }
}
