use super::*;

/// A dump reads back as written, and not before its end.
#[test]
fn a_dump_reads_back_whole() {
    let mut data = DUMP_START.to_vec();
    data.extend(b"A\0one two\0EMPTY\0\0B\0x=y\0\0");
    let vars = parse_dump(&data).expect("whole");
    let vars: Vec<(String, String)> = (vars.into_iter())
        .map(|(name, value)| (name.into_string().unwrap(), value.into_string().unwrap()))
        .collect();
    assert_eq!(
        vars,
        [("A", "one two"), ("EMPTY", ""), ("B", "x=y")]
            .map(|(name, value)| (name.to_string(), value.to_string()))
    );
    for end in 0..data.len() {
        assert_eq!(parse_dump(&data[..end]), None, "{end}");
    }
    assert_eq!(parse_dump(b"other\0\0"), None);
}

/// `mvn` joins `$HOME` and `/.mavenrc` as text, so an empty `HOME` names
/// `/.mavenrc`, not one in the working directory.
#[cfg(unix)]
#[test]
fn an_empty_home_names_the_root_mavenrc() {
    temp_env::with_var("HOME", Some(""), || {
        assert!(candidate_paths().contains(&PathBuf::from("/.mavenrc")));
    });
}

/// The launcher's variables read as the shell holds them, and the others
/// as the JVM gets them.
#[test]
fn shell_and_jvm_values_stay_apart() {
    let shell = Shell::for_testing(
        &["/rc"],
        &[("PATH", "/bin"), ("KEEP", "k")],
        &[("PATH", "/bin"), ("KEEP", "k"), ("NEW", "n")],
        &[("JAVA_HOME", "/jdk")],
    );
    assert_eq!(shell.shell_value("JAVA_HOME"), Some(b"/jdk".to_vec()));
    assert_eq!(shell.exported("JAVA_HOME"), None);
    assert_eq!(shell.changing("JAVA_HOME"), Some(PathBuf::from("/rc")));
    assert_eq!(shell.changing("KEEP"), None);
    assert_eq!(shell.changing("NEW"), Some(PathBuf::from("/rc")));
    assert_eq!(shell.shell_value("NEW"), Some(b"n".to_vec()));
    let unexported: Vec<&str> = shell.unexported().map(|(name, _)| name).collect();
    assert_eq!(unexported, ["JAVA_HOME"]);
}

/// What `/bin/sh` leaves, as wave 5 found the old reader got wrong:
/// `export` expands every word first, a default takes `~`, and the shell
/// sets `PWD` and `OPTIND` itself; an unexported variable stays the
/// shell's.
#[cfg(unix)]
#[test]
fn the_shell_itself_sources_the_files() {
    let value = |shell: &Shell, name: &str| {
        (shell.shell_value(name)).map(|value| String::from_utf8(value).unwrap())
    };
    let sourced = |env: &[(&str, &str)], text: &str| {
        Shell::sourcing_for_testing(env, text, &["B", "X", "JAVA_TOOL_OPTIONS"]).unwrap()
    };
    let shell = sourced(&[], "export A=1 B=x$A MAVEN_OPTS=\"-Da=$A\"\n");
    assert_eq!(value(&shell, "B").as_deref(), Some("x"));
    assert_eq!(value(&shell, "MAVEN_OPTS").as_deref(), Some("-Da="));
    let shell = sourced(&[], "MAVEN_OPTS=-Dh=${NOPE:-~/mh}\n");
    let home = value(&shell, "HOME").unwrap();
    assert_eq!(value(&shell, "MAVEN_OPTS"), Some(format!("-Dh={home}/mh")));
    let cwd = std::env::current_dir().unwrap();
    let shell = sourced(&[("PWD", "/nowhere")], "MAVEN_OPTS=\"$PWD/$OPTIND\"\n");
    let pwd = value(&shell, "MAVEN_OPTS").unwrap();
    assert_eq!(
        std::fs::canonicalize(pwd.strip_suffix("/1").unwrap()).unwrap(),
        std::fs::canonicalize(&cwd).unwrap()
    );
    let shell = sourced(
        &[],
        "JAVA_HOME=/jdk\nexport JAVA_TOOL_OPTIONS=-Dt=1\nif [ -z \"$X\" ]; then X=2; fi\n",
    );
    assert_eq!(value(&shell, "JAVA_HOME").as_deref(), Some("/jdk"));
    assert_eq!(shell.exported("JAVA_HOME"), None);
    assert_eq!(shell.exported("JAVA_TOOL_OPTIONS"), Some(b"-Dt=1".to_vec()));
    assert_eq!(shell.exported("X"), None);
    // `exit` stops `mvn` before it starts Maven.
    let error = Shell::sourcing_for_testing(&[], "exit 0\n", &[]).unwrap_err();
    assert!(error.to_string().contains(".mavenrc"), "{error}");
}

/// What a shell echoes before the dump, as `cmd` does for each line with
/// `echo on` that a mavenrc file left, is skipped.
#[test]
fn a_dump_after_echoed_lines_reads_back() {
    let mut data = b"\r\nC:\\p>\"C:\\raeva.exe\" --raeva-internal-environment-dump \r\n".to_vec();
    data.extend(DUMP_START);
    data.extend(b"A\0one\0\0C:\\p>");
    let vars = parse_dump(&data).expect("whole");
    assert_eq!(vars, [(OsString::from("A"), OsString::from("one"))]);
    assert_eq!(parse_dump(b"RAEVA-ENVIRONMENT A\0one\0\0"), None);
}

/// The traced build's shell sources a launcher in place of running it
/// only where its first commands are the mavenrc block of `bin/mvn` or a
/// Maven Wrapper script that has it.
#[test]
fn a_launcher_is_sourced_only_where_it_starts_with_the_mavenrc_block() {
    let mvn = "#!/bin/sh\n\n# Licensed\n#   MAVEN_SKIP_RC\n\nif [ -z \"$MAVEN_SKIP_RC\" ] ; then\n\n  \
               if [ -f /usr/local/etc/mavenrc ] ; then\n    . /usr/local/etc/mavenrc\n  fi\n\n  \
               if [ -f /etc/mavenrc ] ; then\n    . /etc/mavenrc\n  fi\n\n  \
               if [ -f \"$HOME/.mavenrc\" ] ; then\n    . \"$HOME/.mavenrc\"\n  fi\n\nfi\n\
               cygwin=false;\nexec \"$JAVACMD\" \"$@\"\n";
    assert_eq!(rc_block(mvn.as_bytes()), Some(false));
    // Wrapper 3.3.4's script type spells `];`.
    assert_eq!(rc_block(mvn.replace("] ;", "];").as_bytes()), Some(false));
    let short = mvn.replace(
        "  if [ -f /usr/local/etc/mavenrc ] ; then\n    . /usr/local/etc/mavenrc\n  fi\n",
        "",
    );
    assert_eq!(rc_block(short.as_bytes()), Some(true));
    for other in [
        mvn.replace("#!/bin/sh", "#!/bin/bash"),
        mvn.replace("#!/bin/sh\n", "#!/bin/sh\nset -e\n"),
        mvn.replace('\n', "\r\n"),
        mvn.replace(". /etc/mavenrc", ". /etc/mavenrc2"),
        // The only-script `mvnw` runs `bin/mvn` as a program of its own.
        "#!/bin/sh\nset -euf\nexec_maven() {\n  exec \"$MAVEN_HOME/bin/mvn\" \"$@\"\n}\n"
            .to_string(),
        // Homebrew's launcher.
        "#!/bin/bash\nJAVA_HOME=\"${JAVA_HOME:-/opt/jdk}\" exec \"/opt/maven/bin/mvn\"  \"$@\"\n"
            .to_string(),
    ] {
        assert_eq!(rc_block(other.as_bytes()), None, "{other}");
    }
}

/// The traced build's shell sources the files once, in its own shell, as
/// the launcher would: `$0` and the arguments are the launcher's, an
/// unexported variable reaches the launcher but not the JVM, and what
/// raeva adds comes after the files, which do not see it.
#[cfg(unix)]
#[test]
fn the_traced_shell_sources_the_files_once_before_the_launcher() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(
        home.join(".mavenrc"),
        "echo \"rc $0 $# ${JDK_JAVA_OPTIONS-unset}\" >> \"$HOME/runs\"\nUNEXPORTED=u\n\
         MAVEN_OPTS=-Dm=1\nexport EXPORTED=e\n",
    )
    .unwrap();
    let launcher = dir.path().join("mvn");
    std::fs::write(
        &launcher,
        "#!/bin/sh\nif [ -z \"$MAVEN_SKIP_RC\" ] ; then\n  if [ -f /usr/local/etc/mavenrc ] ; \
         then\n    . /usr/local/etc/mavenrc\n  fi\n  if [ -f /etc/mavenrc ] ; then\n    . \
         /etc/mavenrc\n  fi\n  if [ -f \"$HOME/.mavenrc\" ] ; then\n    . \"$HOME/.mavenrc\"\n  \
         fi\nfi\necho \"launcher $0 $* $UNEXPORTED $MAVEN_OPTS\" >> \"$HOME/runs\"\n\
         exec /bin/sh -c 'echo \"jvm ${UNEXPORTED-none} $EXPORTED $JDK_JAVA_OPTIONS \
         ${MAVEN_SKIP_RC-none}\" >> \"$HOME/runs\"'\n",
    )
    .unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dump = dir.path().join("dump");
    std::fs::write(&dump, "#!/bin/sh\nenv\n").unwrap();
    std::fs::set_permissions(&dump, std::fs::Permissions::from_mode(0o755)).unwrap();
    temp_env::with_vars(
        [("HOME", Some(home.as_os_str())), ("MAVEN_SKIP_RC", None)],
        || {
            let TracedLaunch::Sourced {
                script, launcher, ..
            } = traced_launch(&launcher, "-XX:-Opt").unwrap()
            else {
                panic!("not sourced");
            };
            let mut child = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .arg(&launcher)
                .args(["a", "b c"])
                .env(DUMP_PROGRAM, &dump)
                .env("JDK_JAVA_OPTIONS", "-Da=1")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            std::io::Write::write_all(child.stdin.as_mut().unwrap(), b"harden\n").unwrap();
            drop(child.stdin.take());
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            let dumped = String::from_utf8_lossy(&output.stdout);
            assert!(!dumped.contains("__RAEVA_SHELL_UNEXPORTED"), "{dumped}");
            assert!(
                dumped.contains("__RAEVA_SHELL_MAVEN_OPTS=-Dm=1"),
                "{dumped}"
            );
            let runs = std::fs::read_to_string(home.join("runs")).unwrap();
            let shown = launcher.display();
            assert_eq!(
                runs,
                format!(
                    "rc {shown} 2 -Da=1\nlauncher {shown} a b c u -Dm=1\n\
                     jvm none e -Da=1 -XX:-Opt none\n"
                )
            );
        },
    );
}

/// A `set -a` in the files does not export the `MAVEN_SKIP_RC` the traced
/// shell sets before it sources the launcher, so the JVM does not get it.
#[cfg(unix)]
#[test]
fn a_set_a_in_the_files_leaves_maven_skip_rc_unexported() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(home.join(".mavenrc"), "set -a\n").unwrap();
    let launcher = dir.path().join("mvn");
    std::fs::write(
        &launcher,
        "#!/bin/sh\nif [ -z \"$MAVEN_SKIP_RC\" ] ; then\n  if [ -f /usr/local/etc/mavenrc ] ; \
         then\n    . /usr/local/etc/mavenrc\n  fi\n  if [ -f /etc/mavenrc ] ; then\n    . \
         /etc/mavenrc\n  fi\n  if [ -f \"$HOME/.mavenrc\" ] ; then\n    . \"$HOME/.mavenrc\"\n  \
         fi\nfi\nexec /bin/sh -c 'echo \"jvm ${MAVEN_SKIP_RC-none}\" >> \"$HOME/runs\"'\n",
    )
    .unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dump = dir.path().join("dump");
    std::fs::write(&dump, "#!/bin/sh\nenv\n").unwrap();
    std::fs::set_permissions(&dump, std::fs::Permissions::from_mode(0o755)).unwrap();
    temp_env::with_vars(
        [("HOME", Some(home.as_os_str())), ("MAVEN_SKIP_RC", None)],
        || {
            let TracedLaunch::Sourced {
                script,
                exec: false,
                launcher,
                ..
            } = traced_launch(&launcher, "-XX:-Opt").unwrap()
            else {
                panic!("not sourced");
            };
            let mut child = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .arg(&launcher)
                .env(DUMP_PROGRAM, &dump)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            std::io::Write::write_all(child.stdin.as_mut().unwrap(), b"run\n").unwrap();
            drop(child.stdin.take());
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            let runs = std::fs::read_to_string(home.join("runs")).unwrap();
            assert_eq!(runs, "jvm none\n");
        },
    );
}

/// A launcher that does not start with the mavenrc block runs with them
/// skipped, unless it names them without `MAVEN_SKIP_RC`, as one that
/// reads them its own way does.
#[cfg(unix)]
#[test]
fn a_launcher_that_reads_the_files_its_own_way_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".mavenrc"), "A=1\n").unwrap();
    let launch = |text: &str| {
        let launcher = dir.path().join("mvn");
        std::fs::write(&launcher, text).unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        temp_env::with_vars(
            [("HOME", Some(dir.path())), ("MAVEN_SKIP_RC", None)],
            || match traced_launch(&launcher, "-XX:-Opt") {
                Ok(TracedLaunch::Sourced { exec, .. }) => Some(exec),
                Ok(other) => panic!("{other:?}"),
                Err(_) => None,
            },
        )
    };
    let only_script = "#!/bin/sh\nset -euf\nexec \"$MAVEN_HOME/bin/mvn\" \"$@\"\n";
    assert_eq!(launch(only_script), Some(true));
    let homebrew = "#!/bin/bash\nJAVA_HOME=\"${JAVA_HOME:-/opt/jdk}\" exec \"/opt/mvn\" \"$@\"\n";
    assert_eq!(launch(homebrew), Some(true));
    assert_eq!(launch("#!/bin/sh\n. \"$HOME/.mavenrc\"\nexec java\n"), None);
    let skips = "#!/bin/sh\n[ -n \"$MAVEN_SKIP_RC\" ] || . \"$HOME/.mavenrc\"\nexec java\n";
    assert_eq!(launch(skips), Some(true));
}

/// The process ids a mavenrc file wrote to `file`, killed once read.
#[cfg(unix)]
fn kill_listed(file: &Path) -> Vec<String> {
    let pids: Vec<String> = (std::fs::read_to_string(file).unwrap_or_default())
        .split_whitespace()
        .map(str::to_string)
        .collect();
    for pid in &pids {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", pid])
            .status();
    }
    pids
}

/// A process a mavenrc file leaves running holds the dump's pipe open, but
/// raeva stops reading once the shell has exited: at once for a file that
/// exits before `mvn` starts Maven, as `mvn` fails at once, and with the
/// dump for one that does not.
#[cfg(unix)]
#[test]
fn a_process_left_running_does_not_hold_raeva() {
    let dir = tempfile::tempdir().unwrap();
    let pids = dir.path().join("pids");
    for (end, fails) in [("exit 1\n", true), ("", false)] {
        let mavenrc = format!("sleep 600 &\necho \"$!\" >> '{}'\n{end}", pids.display());
        let start = Instant::now();
        let shell = Shell::sourcing_for_testing(&[], &mavenrc, &[]);
        let took = start.elapsed();
        assert_eq!(kill_listed(&pids).len(), 1, "{mavenrc}");
        std::fs::remove_file(&pids).unwrap();
        assert!(took < Duration::from_secs(10), "{mavenrc}: {took:?}");
        match shell {
            Err(error) if fails => assert!(
                error
                    .to_string()
                    .contains("stops mvn's shell before mvn starts Maven"),
                "{error}"
            ),
            Ok(_) if !fails => {}
            other => panic!("{mavenrc}: {other:?}"),
        }
    }
}

/// A mavenrc file that runs out of time is stopped with what it runs in
/// the foreground, which would otherwise run on without its shell.
#[cfg(unix)]
#[test]
fn a_mavenrc_out_of_time_is_stopped_whole() {
    let dir = tempfile::tempdir().unwrap();
    let marker = format!("raeva-mavenrc-timeout-{}", std::process::id());
    std::fs::write(
        dir.path().join(".mavenrc"),
        format!("sh -c 'sleep 600; :' {marker}\n"),
    )
    .unwrap();
    let mut env: Vec<(OsString, OsString)> = (std::env::vars_os())
        .filter(|(name, _)| name != "HOME" && name != "MAVEN_SKIP_RC")
        .collect();
    env.push(("HOME".into(), dir.path().into()));
    let running = || {
        let listed = std::process::Command::new("ps")
            .args(["-A", "-o", "args="])
            .output()
            .unwrap();
        String::from_utf8_lossy(&listed.stdout).contains(&marker)
    };
    let start = Instant::now();
    let error = Shell::run(
        vec![dir.path().join(".mavenrc")],
        env,
        OsString::from("/bin/sh"),
        "-c 'printf x'",
        dir.path(),
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(start.elapsed() < Duration::from_secs(10));
    assert!(
        error
            .to_string()
            .contains("did not finish within 1 seconds"),
        "{error}"
    );
    // An orphan its init reaps may show for a moment.
    let gone = (0..100).any(|_| {
        std::thread::sleep(Duration::from_millis(50));
        !running()
    });
    assert!(gone, "{marker} still runs");
}
