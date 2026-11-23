//! The variables `mvn` holds once it has sourced the mavenrc files. raeva
//! does not read the files itself: it has `/bin/sh` (`cmd` on Windows)
//! source them as `mvn` (`mvn.cmd`) does, and then run raeva again
//! ([`DUMP_ARG`]) to write back the environment and the launcher's own
//! shell variables they leave.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The argument that makes raeva write its environment to stdout
/// ([`write_dump`]) and exit, which the shell that sourced the mavenrc
/// files runs.
pub const DUMP_ARG: &str = "--raeva-internal-environment-dump";

/// The variable that names the program the shell runs to write the dump.
const DUMP_PROGRAM: &str = "__RAEVA_DUMP_PROGRAM";

/// The prefix the shell exports `mvn`'s own variables under, set or not,
/// as [`LAUNCHER_SHELL_VARIABLES`] lists them.
const SHELL_PREFIX: &str = "__RAEVA_SHELL_";

const DUMP_START: &[u8] = b"RAEVA-ENVIRONMENT\0";

/// The name the dump gives the directory it ran in, which no variable has:
/// it is not a valid name in the environment of a process.
const DIRECTORY: &str = "=RAEVA-DIRECTORY";

/// How long the mavenrc files may run: `mvn` waits for them however long
/// they take, as for a token they fetch over a slow link.
pub const TIMEOUT: Duration = Duration::from_secs(120);

/// How long the mavenrc files run before raeva says it waits for them.
pub const NOTE_AFTER: Duration = Duration::from_secs(10);

/// The variables `mvn` reads as its own, from its shell, whether or not a
/// mavenrc file exports them.
pub const LAUNCHER_SHELL_VARIABLES: [&str; 11] = [
    "JAVA_HOME",
    "JAVACMD",
    "PATH",
    "MAVEN_OPTS",
    "MAVEN_DEBUG_OPTS",
    "MAVEN_ARGS",
    "MAVEN_BASEDIR",
    "MAVEN_CONFIG",
    "IFS",
    "PWD",
    "HOME",
];

/// `value`, the bytes of a variable as [`Shell`] gives them, as the
/// platform holds them.
pub fn os_string(value: Vec<u8>) -> OsString {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStringExt::from_vec(value)
    }
    #[cfg(not(unix))]
    {
        String::from_utf8_lossy(&value).into_owned().into()
    }
}

fn bytes(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStrExt::as_bytes(value).to_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().into_owned().into_bytes()
    }
}

/// Why raeva cannot tell what `mvn` holds after its mavenrc files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MavenrcError {
    /// The files `mvn` sources.
    pub files: Vec<PathBuf>,
    /// What went wrong when raeva sourced them.
    pub why: String,
}

impl std::fmt::Display for MavenrcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let files: Vec<String> = (self.files.iter())
            .map(|file| file.display().to_string())
            .collect();
        write!(
            f,
            "{}, which mvn sources, {}, so raeva cannot tell what mvn runs with; fix the file, \
             or run both raeva and mvn with MAVEN_SKIP_RC=1",
            files.join(" and "),
            self.why
        )
    }
}

/// The files a [`Shell::capture`] sourced, where, and what it found.
type Captured = (Vec<PathBuf>, PathBuf, Result<Shell, MavenrcError>);

/// The variables of the shell `mvn` starts the JVM from, once it has
/// sourced the mavenrc files.
#[derive(Debug, Clone, Default)]
pub struct Shell {
    /// The files sourced, in order.
    files: Vec<PathBuf>,
    /// This process's environment.
    before: Vec<(OsString, OsString)>,
    /// The environment the JVM gets.
    exported: Vec<(OsString, OsString)>,
    /// [`LAUNCHER_SHELL_VARIABLES`] as the shell holds them.
    shell: HashMap<String, Option<OsString>>,
    /// The directory the shell is in once the files ran, as the dump
    /// gives it.
    directory: Option<PathBuf>,
}

/// The mavenrc files `mvn` sources, where they exist: `/usr/local/etc/mavenrc`,
/// `/etc/mavenrc` and `"$HOME/.mavenrc"`, or `mvn.cmd`'s
/// `"%USERPROFILE%\mavenrc_pre.bat"` and `.cmd`; none with `MAVEN_SKIP_RC`
/// set. The home is joined as the launcher joins it, so an empty `HOME`
/// names `/.mavenrc`.
pub fn mavenrc_paths() -> Vec<PathBuf> {
    if std::env::var_os("MAVEN_SKIP_RC").is_some_and(|skip| !skip.is_empty()) {
        return Vec::new();
    }
    let mut files = candidate_paths();
    files.retain(|file| file.is_file());
    files
}

/// The paths [`mavenrc_paths`] tests.
fn candidate_paths() -> Vec<PathBuf> {
    let joined = |home: &str, name: &str, separator: &str| {
        let mut path = std::env::var_os(home).unwrap_or_default();
        path.push(separator);
        path.push(name);
        PathBuf::from(path)
    };
    if cfg!(windows) {
        vec![
            joined("USERPROFILE", "mavenrc_pre.bat", "\\"),
            joined("USERPROFILE", "mavenrc_pre.cmd", "\\"),
        ]
    } else {
        vec![
            PathBuf::from("/usr/local/etc/mavenrc"),
            PathBuf::from("/etc/mavenrc"),
            joined("HOME", ".mavenrc", "/"),
        ]
    }
}

/// The shell `mvn` runs, as `sh` reads it: the mavenrc part of the 3.9 and
/// 3.10 `bin/mvn` scripts, then the export of the launcher's variables and
/// the dump, with the files' own output dropped.
const SH_SCRIPT: &str = r#"exec 3>&1 >/dev/null 2>&1 </dev/null
if [ -z "$MAVEN_SKIP_RC" ] ; then

  if [ -f /usr/local/etc/mavenrc ] ; then
    . /usr/local/etc/mavenrc
  fi

  if [ -f /etc/mavenrc ] ; then
    . /etc/mavenrc
  fi

  if [ -f "$HOME/.mavenrc" ] ; then
    . "$HOME/.mavenrc"
  fi

fi
for __raeva_name in @NAMES@; do
  eval "case \${$__raeva_name+set} in set) export __RAEVA_SHELL_$__raeva_name=\"\$$__raeva_name\";; esac"
done
exec "$__RAEVA_DUMP_PROGRAM" @DUMP@ >&3
"#;

/// `mvn.cmd`'s mavenrc part, as `cmd` reads it from a file, then the dump.
const CMD_SCRIPT: &str = "@echo off\r\n\
SET INTERNAL_MAVEN_OPTS=\r\n\
if not \"%MAVEN_SKIP_RC%\"==\"\" goto skipRcPre\r\n\
if exist \"%USERPROFILE%\\mavenrc_pre.bat\" call \"%USERPROFILE%\\mavenrc_pre.bat\" >nul 2>&1 <nul\r\n\
if exist \"%USERPROFILE%\\mavenrc_pre.cmd\" call \"%USERPROFILE%\\mavenrc_pre.cmd\" >nul 2>&1 <nul\r\n\
:skipRcPre\r\n\
@\"%__RAEVA_DUMP_PROGRAM%\" @DUMP@\r\n";

impl Shell {
    /// The variables `mvn` (`mvn.cmd` on Windows) holds once it has
    /// sourced its mavenrc files, run in `dir`, where `mvn` runs, with this
    /// process's environment; this process's own when there are none. The
    /// files run once per process and directory.
    ///
    /// # Errors
    ///
    /// When the files do not finish within [`TIMEOUT`], stop the shell
    /// before `mvn` would start Maven, as `exit` does, or cannot be run.
    pub fn capture(dir: &Path) -> Result<Shell, MavenrcError> {
        let shell = Self::capture_anywhere(dir)?;
        match shell.moved_from(dir) {
            Some(why) => Err(MavenrcError {
                files: shell.files,
                why,
            }),
            None => Ok(shell),
        }
    }

    /// [`Shell::capture`], also where the files leave the shell in another
    /// directory, which it refuses: the secrets they hold are hidden before
    /// that refusal is shown.
    ///
    /// # Errors
    ///
    /// As for [`Shell::capture`], but for the directory.
    pub fn capture_anywhere(dir: &Path) -> Result<Shell, MavenrcError> {
        static CAPTURED: std::sync::Mutex<Option<Captured>> = std::sync::Mutex::new(None);
        let files = mavenrc_paths();
        if files.is_empty() {
            return Ok(Self::process());
        }
        let dir = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
        let mut captured = CAPTURED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((sourced, at, shell)) = &*captured
            && *sourced == files
            && *at == dir
        {
            return shell.clone();
        }
        let shell = Self::source(files.clone(), std::env::vars_os().collect(), &dir);
        *captured = Some((files, dir, shell.clone()));
        shell
    }

    /// A variable the files give another value, or leave set or unset,
    /// when they run again in `dir` from the same environment: one they
    /// take anew each time, such as a token.
    ///
    /// # Errors
    ///
    /// As for [`Shell::capture`].
    pub fn varies_in(&self, dir: &Path) -> Result<Option<String>, MavenrcError> {
        let dir = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
        let again = Self::source(self.files.clone(), self.before.clone(), &dir)?;
        Ok((self.exported.iter())
            .chain(&again.exported)
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .find(|name| lookup(&self.exported, name) != lookup(&again.exported, name)))
    }

    /// This process's environment, with no mavenrc file sourced.
    pub fn process() -> Shell {
        Self::for_env(std::env::vars_os().collect())
    }

    /// The environment `env`, with no mavenrc file sourced.
    fn for_env(env: Vec<(OsString, OsString)>) -> Shell {
        let mut shell = Shell {
            files: Vec::new(),
            exported: env.clone(),
            before: env,
            shell: HashMap::new(),
            directory: None,
        };
        shell.shell = (LAUNCHER_SHELL_VARIABLES.iter())
            .map(|name| (name.to_string(), shell.exported(name).map(os_string)))
            .collect();
        shell
    }

    /// A shell for tests: `exported` the environment after the files
    /// `files`, `before` this process's, and `shell` the launcher's own
    /// variables that are set; one of [`LAUNCHER_SHELL_VARIABLES`] or
    /// [`TRACE_SHELL_VARIABLES`] not in `shell` holds its exported value.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_testing(
        files: &[&str],
        before: &[(&str, &str)],
        exported: &[(&str, &str)],
        shell: &[(&str, &str)],
    ) -> Shell {
        let pairs = |vars: &[(&str, &str)]| -> Vec<(OsString, OsString)> {
            (vars.iter())
                .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                .collect()
        };
        let mut built = Shell {
            files: files.iter().map(PathBuf::from).collect(),
            before: pairs(before),
            exported: pairs(exported),
            shell: HashMap::new(),
            directory: None,
        };
        built.shell = (LAUNCHER_SHELL_VARIABLES.iter())
            .chain(&TRACE_SHELL_VARIABLES)
            .map(|name| {
                let set = (shell.iter()).find(|(set, _)| set == name);
                let value = match set {
                    Some((_, value)) => Some(OsString::from(value)),
                    None => built.exported(name).map(os_string),
                };
                (name.to_string(), value)
            })
            .collect();
        built
    }

    /// A shell for tests with no mavenrc file and the environment `env`.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_testing_env(env: Vec<(OsString, OsString)>) -> Shell {
        Self::for_env(env)
    }

    /// The shell after `mavenrc`, as `HOME`'s `.mavenrc`, with the
    /// environment `env` and a `HOME` of its own, as `/bin/sh` leaves the
    /// variables `names` and [`LAUNCHER_SHELL_VARIABLES`].
    #[cfg(all(unix, any(test, feature = "testing")))]
    pub fn sourcing_for_testing(
        env: &[(&str, &str)],
        mavenrc: &str,
        names: &[&str],
    ) -> Result<Shell, MavenrcError> {
        let dir = tempfile_dir().expect("a temporary directory");
        let file = dir.join(".mavenrc");
        std::fs::write(&file, mavenrc).expect("the mavenrc file");
        let mut before: Vec<(OsString, OsString)> = (env.iter())
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect();
        before.push(("HOME".into(), dir.clone().into_os_string()));
        let shell_names =
            (LAUNCHER_SHELL_VARIABLES.iter()).map(|name| format!("{SHELL_PREFIX}{name}"));
        let all: Vec<String> = (names.iter().chain(&LAUNCHER_SHELL_VARIABLES))
            .map(|name| name.to_string())
            .chain(shell_names)
            .collect();
        let dump = format!(
            "-c 'printf \"RAEVA-ENVIRONMENT\\000\"; for n in {}; do eval \"case \\${{$n+set}} in \
             set) printf \\\"%s\\\\000%s\\\\000\\\" $n \\\"\\$$n\\\";; esac\"; done; printf \"\\000\"'",
            all.join(" ")
        );
        let cwd = std::env::current_dir().expect("a working directory");
        let shell = Self::run(
            vec![file],
            before,
            OsString::from("/bin/sh"),
            &dump,
            &cwd,
            TIMEOUT,
        );
        let _ = std::fs::remove_dir_all(dir);
        shell
    }

    fn source(
        files: Vec<PathBuf>,
        env: Vec<(OsString, OsString)>,
        dir: &Path,
    ) -> Result<Shell, MavenrcError> {
        let program = std::env::current_exe().map_err(|err| MavenrcError {
            files: files.clone(),
            why: format!("cannot be run, as raeva cannot name itself: {err}"),
        })?;
        Self::run(files, env, program.into_os_string(), DUMP_ARG, dir, TIMEOUT)
    }

    /// The shell after `files`, sourced in `dir` from the environment
    /// `before`, as `program` with the argument text `arg` dumps it, within
    /// `timeout`.
    fn run(
        files: Vec<PathBuf>,
        before: Vec<(OsString, OsString)>,
        program: OsString,
        arg: &str,
        dir: &Path,
        timeout: Duration,
    ) -> Result<Shell, MavenrcError> {
        let fail = |why: String| MavenrcError {
            files: files.clone(),
            why,
        };
        let names = LAUNCHER_SHELL_VARIABLES.join(" ");
        let mut script_file = None;
        let mut command = if cfg!(windows) {
            let dir = tempfile_dir().map_err(|err| fail(format!("cannot be run: {err}")))?;
            let path = dir.join("mavenrc.cmd");
            std::fs::write(&path, CMD_SCRIPT.replace("@DUMP@", arg))
                .map_err(|err| fail(format!("cannot be run: {err}")))?;
            let mut command = std::process::Command::new("cmd");
            cmd_args(&mut command, &path);
            script_file = Some(dir);
            command
        } else {
            let script = SH_SCRIPT.replace("@NAMES@", &names).replace("@DUMP@", arg);
            let mut command = std::process::Command::new("/bin/sh");
            command.args(["-c", &script, "mvn"]);
            // A group of its own, which a timeout stops whole.
            #[cfg(unix)]
            std::os::unix::process::CommandExt::process_group(&mut command, 0);
            command
        };
        command
            .env_clear()
            .envs(
                (before.iter())
                    .filter(|(name, _)| !name.to_string_lossy().starts_with(SHELL_PREFIX))
                    .map(|(name, value)| (name, value)),
            )
            .env(DUMP_PROGRAM, &program)
            .current_dir(dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        let spawned = command.spawn();
        let result = spawned
            .map_err(|err| fail(format!("cannot be run: {err}")))
            .and_then(|child| read_dump(child, timeout).map_err(fail));
        if let Some(dir) = script_file {
            let _ = std::fs::remove_dir_all(dir);
        }
        Ok(Self::from_vars(
            files,
            before,
            result?,
            &LAUNCHER_SHELL_VARIABLES,
        ))
    }

    /// Why the files leave the shell they were sourced in from `dir` in
    /// another directory, where the launcher then finds the project and
    /// the JVM reads a relative option file, which raeva does not follow.
    /// It does not name the directory, whose path may hold a secret.
    pub fn moved_from(&self, dir: &Path) -> Option<String> {
        let now = self.directory.as_deref()?;
        let same = |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.into());
        (same(now) != same(dir)).then(|| {
            "changes the directory of mvn's shell, from which mvn would then run".to_string()
        })
    }

    /// The shell after `files`, sourced from the environment `before`, as
    /// the dump `vars` gives it, with the shell variables `names` it
    /// exported under [`SHELL_PREFIX`].
    fn from_vars(
        files: Vec<PathBuf>,
        before: Vec<(OsString, OsString)>,
        vars: Vec<(OsString, OsString)>,
        names: &[&str],
    ) -> Shell {
        let mut shell_vars = HashMap::new();
        let mut exported = Vec::new();
        let mut directory = None;
        for (name, value) in vars {
            let text = name.to_string_lossy();
            if name == DIRECTORY {
                directory = Some(PathBuf::from(value));
            } else if let Some(launcher) = text.strip_prefix(SHELL_PREFIX) {
                shell_vars.insert(launcher.to_string(), Some(value));
            } else if !(name == DUMP_PROGRAM
                || (!cfg!(windows) && name == "_")
                // The scripts' own variables, which `set -a` in a file
                // exports.
                || text.starts_with("__raeva_"))
            {
                exported.push((name, value));
            }
        }
        let mut shell = Shell {
            files,
            before,
            exported,
            shell: HashMap::new(),
            directory,
        };
        shell.shell = (names.iter())
            .map(|name| {
                let value = match cfg!(windows) {
                    // Every batch variable is in the environment.
                    true => shell.exported(name).map(os_string),
                    false => shell_vars.remove(*name).flatten(),
                };
                (name.to_string(), value)
            })
            .collect();
        shell
    }

    /// The shell the traced build's wrapper ([`TracedLaunch::Sourced`])
    /// sourced `files` in from the environment `before`, as its dump
    /// `vars` gives it.
    pub fn traced(
        files: Vec<PathBuf>,
        before: Vec<(OsString, OsString)>,
        vars: Vec<(OsString, OsString)>,
    ) -> Shell {
        let names: Vec<&str> = (LAUNCHER_SHELL_VARIABLES.iter())
            .chain(&TRACE_SHELL_VARIABLES)
            .copied()
            .collect();
        Self::from_vars(files, before, vars, &names)
    }

    /// The files sourced, in order.
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// The value of `name` as `mvn` reads it: its own variable, such as
    /// `MAVEN_OPTS`, as its shell holds it, exported or not; any other as
    /// the JVM gets it.
    pub fn shell_value(&self, name: &str) -> Option<Vec<u8>> {
        match self.shell.get(name) {
            Some(value) => value.as_deref().map(bytes),
            None => self.exported(name),
        }
    }

    /// The value of `name` in the environment the JVM `mvn` starts gets.
    pub fn exported(&self, name: &str) -> Option<Vec<u8>> {
        lookup(&self.exported, name).map(bytes)
    }

    /// The environment the JVM `mvn` starts gets.
    pub fn exported_env(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        (self.exported.iter()).map(|(name, value)| (name.as_os_str(), value.as_os_str()))
    }

    /// The launcher's own variables its shell holds without exporting them.
    pub fn unexported(&self) -> impl Iterator<Item = (&str, &OsStr)> {
        (self.shell.iter())
            .filter(|(name, _)| self.exported(name).is_none())
            .filter_map(|(name, value)| Some((name.as_str(), value.as_deref()?)))
    }

    /// A variable this shell, the traced build's, gives `mvn` or its JVM
    /// another value than `first`, raeva's own sourcing of the same files
    /// from the same environment did: one they take anew each time, such as
    /// a token, so the build would not run with the value raeva resolved
    /// with. `SHLVL`, which the shell counts itself, is left out, as is an
    /// exported variable `hidden` names, which no POM reads.
    pub fn varies_from(&self, first: &Shell, hidden: impl Fn(&str) -> bool) -> Option<String> {
        (self.exported.iter())
            .chain(&first.exported)
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .filter(|name| name != "SHLVL" && !hidden(name))
            .find(|name| self.exported(name) != first.exported(name))
            .or_else(|| {
                (LAUNCHER_SHELL_VARIABLES.iter())
                    .find(|name| self.shell_value(name) != first.shell_value(name))
                    .map(|name| name.to_string())
            })
    }

    /// The last mavenrc file, when the files give `mvn` or its JVM another
    /// `name` than this process has.
    pub fn changing(&self, name: &str) -> Option<PathBuf> {
        let now = lookup(&self.before, name).map(bytes);
        let changed = self.shell_value(name) != now || self.exported(name) != now;
        changed.then(|| self.files.last().cloned()).flatten()
    }
}

/// The value of `name` among `vars`, ignoring case on Windows.
fn lookup<'v>(vars: &'v [(OsString, OsString)], name: &str) -> Option<&'v OsStr> {
    (vars.iter())
        .rev()
        .find(|(set, _)| match cfg!(windows) {
            true => set.to_string_lossy().eq_ignore_ascii_case(name),
            false => set == name,
        })
        .map(|(_, value)| value.as_os_str())
}

/// Where raeva keeps what it can recreate, under which it puts the batch
/// script in place of the temporary directory.
static SCRIPT_HOME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Put the batch script that sources the mavenrc files under `dir`, a
/// directory raeva keeps.
pub fn use_script_home(dir: PathBuf) {
    let _ = SCRIPT_HOME.set(dir);
}

/// A new private directory for the batch script, whose path `cmd` would not
/// expand: one with `%` or `!` in it names another file there.
fn tempfile_dir() -> std::io::Result<PathBuf> {
    let readable = |dir: &Path| !dir.to_string_lossy().contains(['%', '!']);
    let Some(base) = (SCRIPT_HOME.get().cloned().into_iter())
        .chain([std::env::temp_dir()])
        .find(|dir| readable(dir))
    else {
        return Err(std::io::Error::other(
            "the temporary directory's path holds % or !, which cmd expands; set RAEVA_HOME to \
             a directory whose path holds neither",
        ));
    };
    std::fs::create_dir_all(&base)?;
    for attempt in 0..100u32 {
        let dir = base.join(format!("raeva-mavenrc-{}-{attempt}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::other("no free temporary directory"))
}

#[cfg(windows)]
fn cmd_args(command: &mut std::process::Command, script: &std::path::Path) {
    use std::os::windows::process::CommandExt;
    // `/s` takes the outer quotes off, so a path with spaces stays one.
    command.raw_arg(format!("/d /s /c \"\"{}\"\"", script.display()));
}

#[cfg(not(windows))]
fn cmd_args(command: &mut std::process::Command, script: &std::path::Path) {
    command.arg("/d").arg("/c").arg(script);
}

/// The variables the dump `child` writes, read until its end, or on Unix
/// until the shell has exited, so a process a file left running cannot hold
/// raeva; the reason it wrote none. A shell still running after `timeout`
/// is stopped, with what it runs.
fn read_dump(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<Vec<(OsString, OsString)>, String> {
    let Some(stdout) = child.stdout.take() else {
        return Err("cannot be run".to_string());
    };
    let mut pipe = DumpPipe::new(stdout).map_err(|err| format!("cannot be run: {err}"))?;
    let timed_out = |child: &mut std::process::Child| {
        stop(child);
        Err(format!(
            "did not finish within {} seconds when raeva sourced it",
            timeout.as_secs()
        ))
    };
    let start = Instant::now();
    let mut noted = false;
    let mut data = Vec::new();
    loop {
        // The dump is the shell itself, so one that has exited has written
        // all it will, which the read after takes.
        let exited = cfg!(unix) && matches!(child.try_wait(), Ok(Some(_)));
        if pipe.read(&mut data) || exited || parse_dump(&data).is_some() {
            break;
        }
        let waited = start.elapsed();
        if waited >= timeout {
            return timed_out(&mut child);
        }
        if !noted && waited >= NOTE_AFTER {
            eprintln!("{}", still_running());
            noted = true;
        }
    }
    let vars = parse_dump(&data);
    // The dump exits once it has written; a shell that stopped before it
    // has exited too.
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(5));
            }
            _ => return timed_out(&mut child),
        }
    }
    vars.ok_or_else(|| {
        "stops mvn's shell before mvn starts Maven, as an exit does, when raeva sources it"
            .to_string()
    })
}

/// Stop `child` and what it runs, which on Unix is its process group, and
/// reap it. Only a shell that ran out of time is stopped so: one that
/// finished may leave a process running, such as an agent, as under `mvn`.
fn stop(child: &mut std::process::Child) {
    kill_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

/// Kill the process group led by `pid`, which a mavenrc shell raeva started
/// has to itself on Unix. Elsewhere the shell has none, and this does
/// nothing.
pub fn kill_group(pid: u32) {
    #[cfg(unix)]
    {
        use rustix::process::{Pid, Signal, kill_process_group};
        if let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) {
            let _ = kill_process_group(pid, Signal::KILL);
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
}

/// The stdout of a shell that writes a dump. On Unix it is read without
/// blocking, so raeva stops once the shell has exited, though a process it
/// left running holds the pipe open; elsewhere a thread reads it.
struct DumpPipe {
    #[cfg(unix)]
    stdout: std::process::ChildStdout,
    #[cfg(not(unix))]
    chunks: std::sync::mpsc::Receiver<Vec<u8>>,
}

/// How long a read of a [`DumpPipe`] waits for more.
const POLL: Duration = Duration::from_millis(5);

impl DumpPipe {
    #[cfg(unix)]
    fn new(stdout: std::process::ChildStdout) -> std::io::Result<Self> {
        rustix::io::ioctl_fionbio(&stdout, true)?;
        Ok(Self { stdout })
    }

    #[cfg(not(unix))]
    fn new(mut stdout: std::process::ChildStdout) -> std::io::Result<Self> {
        let (send, chunks) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut data = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let read = match stdout.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                data.extend_from_slice(&chunk[..read]);
                if send.send(chunk[..read].to_vec()).is_err() || parse_dump(&data).is_some() {
                    break;
                }
            }
        });
        Ok(Self { chunks })
    }

    /// Add what the shell wrote to `data`, waiting up to [`POLL`] when it
    /// wrote nothing new; whether the pipe has ended.
    #[cfg(unix)]
    fn read(&mut self, data: &mut Vec<u8>) -> bool {
        let mut chunk = [0u8; 8192];
        loop {
            match self.stdout.read(&mut chunk) {
                Ok(0) => return true,
                Ok(read) => data.extend_from_slice(&chunk[..read]),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(POLL);
                    return false;
                }
                Err(_) => return true,
            }
        }
    }

    #[cfg(not(unix))]
    fn read(&mut self, data: &mut Vec<u8>) -> bool {
        match self.chunks.recv_timeout(POLL) {
            Ok(chunk) => {
                data.extend(chunk);
                false
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => false,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => true,
        }
    }
}

/// What raeva says when the mavenrc files run for [`NOTE_AFTER`].
pub fn still_running() -> String {
    format!(
        "The mavenrc files mvn sources are still running after {} seconds; raeva waits up to \
         {} seconds for them, as mvn waits",
        NOTE_AFTER.as_secs(),
        TIMEOUT.as_secs()
    )
}

/// Write this process's environment to stdout for [`Shell::capture`]: a
/// start marker, then each name and value ended by a NUL, then an empty
/// name.
pub fn write_dump() -> std::io::Result<()> {
    use std::io::Write;
    let mut out = Vec::from(DUMP_START);
    if let Ok(dir) = std::env::current_dir() {
        out.extend(DIRECTORY.as_bytes());
        out.push(0);
        out.extend(bytes(dir.as_os_str()));
        out.push(0);
    }
    for (name, value) in std::env::vars_os() {
        out.extend(bytes(&name));
        out.push(0);
        out.extend(bytes(&value));
        out.push(0);
    }
    out.push(0);
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&out)?;
    stdout.flush()
}

/// The variables of a whole dump `data`, `None` until its end. What a
/// shell echoes before it, such as `cmd` with `echo on`, is skipped: the
/// start marker holds a NUL, which no variable or echoed line does.
pub fn parse_dump(data: &[u8]) -> Option<Vec<(OsString, OsString)>> {
    let start = (data.windows(DUMP_START.len())).position(|window| window == DUMP_START)?;
    let mut rest = &data[start + DUMP_START.len()..];
    let mut vars = Vec::new();
    loop {
        let end = rest.iter().position(|&byte| byte == 0)?;
        if end == 0 {
            return Some(vars);
        }
        let name = &rest[..end];
        rest = &rest[end + 1..];
        let end = rest.iter().position(|&byte| byte == 0)?;
        vars.push((os_string(name.to_vec()), os_string(rest[..end].to_vec())));
        rest = &rest[end + 1..];
    }
}

/// The variables of the traced build's shell raeva reads besides
/// [`LAUNCHER_SHELL_VARIABLES`]: the one that has the launcher skip the
/// files, and the java launcher's own, which raeva adds to.
pub const TRACE_SHELL_VARIABLES: [&str; 2] = ["MAVEN_SKIP_RC", "JDK_JAVA_OPTIONS"];

/// The mavenrc block `bin/mvn` and the Maven Wrapper scripts that source
/// the files start with, a line at a time, white space collapsed and `] ;`
/// written `];`.
const RC_BLOCK: [&str; 11] = [
    r#"if [ -z "$MAVEN_SKIP_RC" ]; then"#,
    "if [ -f /usr/local/etc/mavenrc ]; then",
    ". /usr/local/etc/mavenrc",
    "fi",
    "if [ -f /etc/mavenrc ]; then",
    ". /etc/mavenrc",
    "fi",
    r#"if [ -f "$HOME/.mavenrc" ]; then"#,
    r#". "$HOME/.mavenrc""#,
    "fi",
    "fi",
];

/// [`RC_BLOCK`] as older Maven Wrapper scripts have it, without
/// `/usr/local/etc/mavenrc`.
const SHORT_RC_BLOCK: [&str; 8] = [
    r#"if [ -z "$MAVEN_SKIP_RC" ]; then"#,
    "if [ -f /etc/mavenrc ]; then",
    ". /etc/mavenrc",
    "fi",
    r#"if [ -f "$HOME/.mavenrc" ]; then"#,
    r#". "$HOME/.mavenrc""#,
    "fi",
    "fi",
];

/// The largest launcher raeva reads to tell whether it sources the files.
const MAX_LAUNCHER: u64 = 1024 * 1024;

/// How the build `[plugins] trace` names starts its launcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracedLaunch {
    /// The launcher itself, as no mavenrc file runs.
    Direct,
    /// The launcher itself, on Windows, where `mvn.cmd` sources `files`
    /// again after raeva did: it takes `MAVEN_SKIP_RC` from the
    /// environment, which the JVM gets, and skips `mavenrc_post` with it.
    Resourced {
        /// The mavenrc files it sources.
        files: Vec<PathBuf>,
    },
    /// `/bin/sh -c script launcher <args>`: the shell sources the mavenrc
    /// files once, as the launcher does first, in its own shell, so the
    /// launcher sees what they leave, exported or not. It then writes the
    /// dump ([`parse_dump`]) to its stdout and reads raeva's word from its
    /// stdin: `run`, or `harden` to add the option it was given to
    /// `JDK_JAVA_OPTIONS`, whether that is exported or not; the files see
    /// neither. With `MAVEN_SKIP_RC` set as a shell variable, it then
    /// sources `launcher`, which has `$0` and the arguments it would have
    /// run with. The build's stdout and stderr both go to the shell's
    /// stderr. With `exec`, it instead exports `MAVEN_SKIP_RC` and runs
    /// `launcher`, which runs a `bin/mvn` of its own that skips the files:
    /// it lacks what they set without exporting it, see
    /// [`EXEC_SHELL_VARIABLES`], and its JVM gets `MAVEN_SKIP_RC`.
    Sourced {
        /// The shell's script.
        script: String,
        /// Whether the shell runs the launcher rather than sourcing it.
        exec: bool,
        /// The launcher, as `$0`.
        launcher: PathBuf,
        /// The mavenrc files it sources.
        files: Vec<PathBuf>,
    },
}

/// Why the traced build cannot source the mavenrc files once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsourcedLauncher {
    /// The mavenrc files that exist.
    pub files: Vec<PathBuf>,
    /// The launcher.
    pub launcher: PathBuf,
}

/// How to start the traced build's `launcher`, a command name on `PATH`
/// or a path, so that the mavenrc files run once, in a shell raeva reads
/// back, with `option` added to `JDK_JAVA_OPTIONS` only after them.
///
/// # Errors
///
/// When mavenrc files exist and the launcher reads them its own way, so
/// that it may not skip them: it names them without `MAVEN_SKIP_RC`, or
/// starts with a mavenrc block that leaves out `/usr/local/etc/mavenrc`,
/// which exists. A launcher that starts with the block of `bin/mvn` or a
/// Maven Wrapper script is sourced in the shell; any other, such as the
/// Wrapper's only-script `mvnw` or Homebrew's `mvn`, which run a `bin/mvn`
/// of their own, is run with `exec`. On Windows the launcher sources them
/// again: see [`TracedLaunch::Resourced`].
pub fn traced_launch(launcher: &Path, option: &str) -> Result<TracedLaunch, UnsourcedLauncher> {
    let files = mavenrc_paths();
    if files.is_empty() {
        return Ok(TracedLaunch::Direct);
    }
    let unsourced = || UnsourcedLauncher {
        files: files.clone(),
        launcher: launcher.to_path_buf(),
    };
    if cfg!(windows) {
        return Ok(TracedLaunch::Resourced { files });
    }
    let path = match launcher.components().count() {
        1 if launcher.is_relative() => on_path(launcher.as_os_str()),
        _ => Some(launcher.to_path_buf()),
    };
    let Some(path) = path else {
        // Not found, so it does not run at all.
        return Ok(TracedLaunch::Direct);
    };
    if !executable(&path) {
        return Ok(TracedLaunch::Direct);
    }
    let mut text = Vec::new();
    let read =
        std::fs::File::open(&path).and_then(|file| file.take(MAX_LAUNCHER).read_to_end(&mut text));
    if read.is_err() {
        return Err(unsourced());
    }
    let exec = match rc_block(&text) {
        Some(false) => false,
        Some(true)
            if !files
                .iter()
                .any(|file| file == Path::new("/usr/local/etc/mavenrc")) =>
        {
            false
        }
        // It reads the files its own way, and may not skip them.
        Some(true) => return Err(unsourced()),
        None if contains(&text, b"mavenrc") && !contains(&text, b"MAVEN_SKIP_RC") => {
            return Err(unsourced());
        }
        None => true,
    };
    assert!(
        (option.bytes()).all(|b| b.is_ascii_alphanumeric() || b"-+:=._".contains(&b)),
        "an option the script holds unquoted"
    );
    let names: Vec<&str> = (LAUNCHER_SHELL_VARIABLES.iter())
        .chain(&TRACE_SHELL_VARIABLES)
        .copied()
        .collect();
    let script = TRACE_SCRIPT
        .replace("@RC@", RC_SNIPPET)
        .replace("@NAMES@", &names.join(" "))
        .replace("@DUMP@", DUMP_ARG)
        .replace("@OPTION@", option)
        .replace(
            "@LAUNCH@",
            match exec {
                true => EXEC_LAUNCHER,
                false => SOURCE_LAUNCHER,
            },
        );
    Ok(TracedLaunch::Sourced {
        script,
        exec,
        launcher: path,
        files,
    })
}

fn contains(text: &[u8], part: &[u8]) -> bool {
    text.windows(part.len()).any(|window| window == part)
}

/// Whether `text`, a launcher, is a `#!/bin/sh` script whose first
/// commands are a mavenrc block: with `false` for [`RC_BLOCK`] and `true`
/// for [`SHORT_RC_BLOCK`], which leaves out `/usr/local/etc/mavenrc`.
fn rc_block(text: &[u8]) -> Option<bool> {
    let text = std::str::from_utf8(text).ok()?;
    let (shebang, rest) = text.split_once('\n')?;
    if shebang.trim_end_matches([' ', '\t']) != "#!/bin/sh" || text.contains('\r') {
        return None;
    }
    let mut code = (rest.lines())
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.replace("] ;", "];"));
    let first: Vec<String> = code.by_ref().take(RC_BLOCK.len()).collect();
    if first == RC_BLOCK {
        Some(false)
    } else if first.get(..SHORT_RC_BLOCK.len())? == SHORT_RC_BLOCK {
        Some(true)
    } else {
        None
    }
}

/// The file `execvp` runs for the command `name`: the first executable
/// file of that name in a directory `PATH` names; `None` where that is
/// none, or where a relative directory comes first that holds one.
fn on_path(name: &OsStr) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let file = dir.join(name);
        if !executable(&file) {
            continue;
        }
        return dir.is_absolute().then_some(file);
    }
    None
}

#[cfg(unix)]
fn executable(file: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(file)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable(file: &Path) -> bool {
    file.is_file()
}

/// The mavenrc block as `bin/mvn` 3.9 and 3.10 have it.
const RC_SNIPPET: &str = r#"if [ -z "$MAVEN_SKIP_RC" ] ; then

  if [ -f /usr/local/etc/mavenrc ] ; then
    . /usr/local/etc/mavenrc
  fi

  if [ -f /etc/mavenrc ] ; then
    . /etc/mavenrc
  fi

  if [ -f "$HOME/.mavenrc" ] ; then
    . "$HOME/.mavenrc"
  fi

fi"#;

/// [`TracedLaunch::Sourced`]'s script. The files run with no input and
/// their output dropped, as raeva's own sourcing of them runs, so what they
/// print stays out of the dump, and with none of the shell's own
/// descriptors, so a process they leave holds none; what raeva adds and
/// reads runs after them, out of reach of their guards and `set -x`.
const TRACE_SCRIPT: &str = r#"__raeva_dump=$__RAEVA_DUMP_PROGRAM
unset __RAEVA_DUMP_PROGRAM
exec 3>&1 4<&0 1>&2 0</dev/null
{
@RC@
} >/dev/null 2>&1 3>&- 4<&-
{
for __raeva_name in @NAMES@; do
  eval "case \${$__raeva_name+set} in set) export __RAEVA_SHELL_$__raeva_name=\"\$$__raeva_name\";; esac"
done
"$__raeva_dump" @DUMP@ >&3 4<&-
for __raeva_name in @NAMES@; do
  unset __RAEVA_SHELL_$__raeva_name
done
} 2>/dev/null
exec 3>&-
read -r __raeva_go <&4 || exit 125
exec 4<&-
case $__raeva_go in
harden) export JDK_JAVA_OPTIONS="${JDK_JAVA_OPTIONS:+$JDK_JAVA_OPTIONS }@OPTION@" ;;
harden-unexported) JDK_JAVA_OPTIONS=@OPTION@; export JDK_JAVA_OPTIONS ;;
run) ;;
*) exit 125 ;;
esac
unset __raeva_go __raeva_name __raeva_dump
@LAUNCH@
"#;

/// How [`TRACE_SCRIPT`] starts a launcher that begins with the mavenrc
/// block: sourced, with `MAVEN_SKIP_RC` a shell variable.
/// Under a `set -a` from the mavenrc files the assignment would export it.
const SOURCE_LAUNCHER: &str = r#"case $- in *a*) set +a; __raeva_a=1 ;; esac
[ -n "${MAVEN_SKIP_RC-}" ] || MAVEN_SKIP_RC=1
[ -z "${__raeva_a-}" ] || { unset __raeva_a; set -a; }
. "$0""#;

/// How [`TRACE_SCRIPT`] starts a launcher that runs a `bin/mvn` of its own.
const EXEC_LAUNCHER: &str = r#"MAVEN_SKIP_RC=${MAVEN_SKIP_RC:-1}
export MAVEN_SKIP_RC
exec "$0" "$@""#;

/// The variables a `bin/mvn` that a launcher of [`TracedLaunch::Sourced`]
/// with `exec` starts reads from its own shell, which no longer holds what
/// the mavenrc files set without exporting it, and the JVM's
/// `JDK_JAVA_OPTIONS`, which raeva then exports.
pub const EXEC_SHELL_VARIABLES: [&str; 9] = [
    "JAVA_HOME",
    "JAVACMD",
    "PATH",
    "MAVEN_OPTS",
    "MAVEN_DEBUG_OPTS",
    "MAVEN_ARGS",
    "MAVEN_BASEDIR",
    "MAVEN_CONFIG",
    "JDK_JAVA_OPTIONS",
];

/// The variables the Maven Wrapper's only-script `mvnw` reads to choose
/// the Maven it runs, before that one sources the mavenrc files.
pub const EXEC_WRAPPER_VARIABLES: [&str; 5] = [
    "MVNW_REPOURL",
    "MVNW_USERNAME",
    "MVNW_PASSWORD",
    "MVNW_VERBOSE",
    "MAVEN_USER_HOME",
];

/// The variable the traced build's shell takes the dump program from.
pub const TRACE_DUMP_PROGRAM: &str = DUMP_PROGRAM;

/// Whether `name` is a variable raeva's shells export for themselves,
/// which the environment it gives them leaves out.
pub fn internal_variable(name: &OsStr) -> bool {
    name.to_string_lossy().starts_with(SHELL_PREFIX)
}

#[cfg(test)]
mod tests;
