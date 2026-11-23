//! Maven's user home is the JVM's `user.home`: the last `-Duser.home` of
//! `.mvn/jvm.config`, `MAVEN_OPTS`, `.mvn/maven.config` and the command
//! line, else the passwd entry's home, never `HOME`. It decides the
//! settings.xml raeva reads and `${user.home}` in it.

use std::fs;
use std::path::Path;

use crate::common::{
    assert_status, assert_success, isolate_maven_user_home, publish, raeva_command,
};

/// A home whose settings.xml sets `libver` to `{n}.0` and adds a
/// repository at `${user.home}/.m2/corp/`, which serves `where:1`
/// depending on `mark-{n}:1`.
fn home(dir: &Path, n: u8) {
    let corp = dir.join(".m2/corp");
    publish(&corp, &format!("org.test:mark-{n}:1"), "");
    publish(
        &corp,
        "org.test:where:1",
        &format!(
            "<dependencies><dependency><groupId>org.test</groupId><artifactId>mark-{n}\
             </artifactId><version>1</version></dependency></dependencies>"
        ),
    );
    fs::write(
        dir.join(".m2/settings.xml"),
        format!(
            "<settings><profiles><profile><id>d</id><properties><libver>{n}.0</libver>\
             </properties><repositories><repository><id>corp</id>\
             <url>file://${{user.home}}/.m2/corp/</url></repository></repositories></profile>\
             </profiles><activeProfiles><activeProfile>d</activeProfile></activeProfiles>\
             </settings>"
        ),
    )
    .unwrap();
}

/// The `n` of the home whose settings.xml the lock followed: `lib:{n}.0`
/// and `mark-{n}`, which `${user.home}` in it decides.
fn locked_home(root: &Path) -> (String, String) {
    let lock = fs::read_to_string(root.join("raeva.lock")).expect("raeva.lock");
    let find = |prefix: &str| {
        let start = lock
            .find(prefix)
            .unwrap_or_else(|| panic!("{prefix}: {lock}"));
        let rest = &lock[start + prefix.len()..];
        rest[..rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len())]
            .to_string()
    };
    (find("org.test:lib:"), find("org.test:mark-"))
}

#[test]
fn maven_user_home_follows_user_home_defines_not_home() {
    let base = tempfile::tempdir().unwrap();
    let defined = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    home(defined.path(), 2);
    home(other.path(), 3);
    let uh = format!("-Duser.home={}", defined.path().display());
    // (case, .mvn/jvm.config, .mvn/maven.config, MAVEN_OPTS, the home the lock follows)
    let cases: [(&str, &str, &str, Option<&str>, &str); 6] = [
        ("a jvm.config", &uh, "", None, "2"),
        ("b MAVEN_OPTS", "", "", Some(&uh), "2"),
        ("c maven.config", "", &uh, Some(""), "2"),
        // MAVEN_OPTS comes after jvm.config on the JVM's command line.
        ("a+b", "-Duser.home=/nowhere", "", Some(&uh), "2"),
        // `HOME` alone is not read; the harness's -Duser.home is.
        ("d HOME", "", "", Some(""), "1"),
        ("command line", "", "-Duser.home=/nowhere", Some(""), "2"),
    ];
    for mode in ["3.9", "3.10"] {
        for (case, jvm_config, maven_config, opts, expected) in cases {
            let project = tempfile::tempdir().unwrap();
            let root = project.path();
            fs::create_dir_all(root.join(".mvn")).unwrap();
            for version in ["1.0", "2.0", "3.0", "9.0"] {
                publish(&root.join("repo"), &format!("org.test:lib:{version}"), "");
            }
            fs::write(
                root.join("pom.xml"),
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>root</artifactId><version>1</version><properties><libver>9.0\
                 </libver></properties><repositories><repository><id>prj</id>\
                 <url>file://${project.basedir}/repo/</url></repository></repositories>\
                 <dependencies><dependency><groupId>org.test</groupId><artifactId>lib\
                 </artifactId><version>${libver}</version></dependency><dependency>\
                 <groupId>org.test</groupId><artifactId>where</artifactId><version>1\
                 </version></dependency></dependencies></project>",
            )
            .unwrap();
            fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n"),
            )
            .unwrap();
            fs::write(root.join(".mvn/jvm.config"), jvm_config).unwrap();
            fs::write(root.join(".mvn/maven.config"), maven_config).unwrap();
            let mut command = raeva_command(root, base.path());
            command.env("HOME", other.path());
            match opts {
                None => {
                    command.env_remove("MAVEN_OPTS");
                }
                // The harness's own -Duser.home, or the case's alone.
                Some("") => isolate_maven_user_home(&mut command, base.path(), ""),
                Some(opts) => {
                    command.env("MAVEN_OPTS", opts);
                }
            }
            let mut args = vec!["sync", "--offline"];
            let define = format!("-Duser.home={}", defined.path().display());
            if case == "command line" {
                args.push(&define);
            }
            let output = command.args(&args).output().expect("run raeva");
            let case = format!("{mode} {case}");
            assert_success(&output, &case);
            let (lib, mark) = locked_home(root);
            assert_eq!(
                (lib.as_str(), mark.as_str()),
                (format!("{expected}.0").as_str(), expected),
                "{case}"
            );
        }
    }
}

/// A `-Duser.home` value that takes an expression, which `MavenCli`
/// expands against the JVM's properties, exits 3; so does one of a JVM
/// channel, which Maven expands where a POM takes `${user.home}`.
#[test]
fn a_user_home_define_raeva_cannot_expand_refuses() {
    let base = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version></project>",
    )
    .unwrap();
    fs::write(
        root.join(".mvn/maven.config"),
        "-Duser.home=${java.io.tmpdir}/h\n",
    )
    .unwrap();
    let output = raeva_command(root, base.path())
        .args(["sync", "--offline"])
        .output()
        .expect("run raeva");
    assert_status(&output, 3, "maven.config -Duser.home=${java.io.tmpdir}/h");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("-Duser.home=${java.io.tmpdir}/h"),
        "{stderr}"
    );
    fs::remove_file(root.join(".mvn/maven.config")).unwrap();
    let output = raeva_command(root, base.path())
        .env("MAVEN_OPTS", "-Duser.home=${java.io.tmpdir}/h")
        .args(["sync", "--offline"])
        .output()
        .expect("run raeva");
    assert_status(&output, 3, "MAVEN_OPTS -Duser.home=${java.io.tmpdir}/h");
}

/// `-s` expands `${user.home}` with Maven's user home, here `MAVEN_OPTS`'s.
#[test]
fn a_settings_option_expands_the_maven_user_home() {
    let base = tempfile::tempdir().unwrap();
    let defined = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    home(defined.path(), 2);
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    for version in ["1.0", "2.0", "9.0"] {
        publish(&root.join("repo"), &format!("org.test:lib:{version}"), "");
    }
    fs::write(
        root.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><properties><libver>9.0\
         </libver></properties><repositories><repository><id>prj</id>\
         <url>file://${project.basedir}/repo/</url></repository></repositories>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>lib\
         </artifactId><version>${libver}</version></dependency><dependency>\
         <groupId>org.test</groupId><artifactId>where</artifactId><version>1\
         </version></dependency></dependencies></project>",
    )
    .unwrap();
    let mut command = raeva_command(root, base.path());
    isolate_maven_user_home(&mut command, defined.path(), "");
    let output = command
        .args(["-s", "${user.home}/.m2/settings.xml", "sync", "--offline"])
        .output()
        .expect("run raeva");
    assert_success(&output, "-s ${user.home}");
    assert_eq!(locked_home(root), ("2.0".to_string(), "2".to_string()));
}

/// A project whose `lib` version and `where` dependency come from the
/// settings.xml of the Maven user home, with `where` left out when
/// `with_where` is false, for a home without settings.
fn user_home_project(root: &Path, with_where: bool) {
    for version in ["1.0", "2.0", "3.0", "9.0"] {
        publish(&root.join("repo"), &format!("org.test:lib:{version}"), "");
    }
    let r#where = if with_where {
        "<dependency><groupId>org.test</groupId><artifactId>where</artifactId>\
         <version>1</version></dependency>"
    } else {
        ""
    };
    fs::write(
        root.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><properties><libver>9.0\
             </libver></properties><repositories><repository><id>prj</id>\
             <url>file://${{project.basedir}}/repo/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib\
             </artifactId><version>${{libver}}</version></dependency>{where}\
             </dependencies></project>"
        ),
    )
    .unwrap();
}

/// A JDK home whose `release` file names `version`.
fn jdk(dir: &Path, version: &str) -> std::path::PathBuf {
    let home = dir.join(format!("jdk-{version}"));
    fs::create_dir_all(&home).unwrap();
    fs::write(
        home.join("release"),
        format!("JAVA_VERSION=\"{version}\"\n"),
    )
    .unwrap();
    home
}

/// The channels the java launcher and HotSpot read besides `mvn`'s
/// command line, as the checkout hunter's cells h to m set them: the JVM
/// reads `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, then `.mvn/jvm.config`,
/// `MAVEN_OPTS` and `MAVEN_DEBUG_OPTS`, then `_JAVA_OPTIONS`, the last
/// `-Duser.home` winning, as Maven 3.9.12 and 3.10.0 take it. A mavenrc
/// that sets `MAVEN_OPTS` sets it for `mvn` (cell g), as the shell
/// leaves it.
#[test]
fn the_jvm_option_variables_decide_the_user_home_as_maven_takes_it() {
    let base = tempfile::tempdir().unwrap();
    let defined = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    home(defined.path(), 2);
    home(other.path(), 3);
    let uh = format!("-Duser.home={}", defined.path().display());
    let oth = format!("-Duser.home={}", other.path().display());
    let java = jdk(base.path(), "21.0.9");
    // mvn sources $HOME/.mavenrc, mvn.cmd %USERPROFILE%\mavenrc_pre.bat.
    let (rc_name, rc_line, rc_conditional) = match cfg!(windows) {
        true => (
            "mavenrc_pre.bat",
            "set \"MAVEN_OPTS={}\"\r\n",
            "if defined RAEVA_COND set \"MAVEN_OPTS=-Xmx2g\"\r\n",
        ),
        false => (
            ".mavenrc",
            "MAVEN_OPTS=\"{}\"\n",
            "[ -n \"$RAEVA_COND\" ] && MAVEN_OPTS=\"-Xmx2g\"\n",
        ),
    };
    let (rc_uh, rc_xmx) = (rc_line.replace("{}", &uh), rc_line.replace("{}", "-Xmx2g"));
    let (base_home, other_home) = (
        base.path().display().to_string(),
        other.path().display().to_string(),
    );
    // (cell, variables, whether the harness's MAVEN_OPTS stays, the mavenrc
    // in the user's home, the home the lock follows or None for exit 3)
    type Case<'a> = (
        &'a str,
        Vec<(&'a str, &'a str)>,
        bool,
        Option<&'a str>,
        Option<&'a str>,
    );
    let cases: Vec<Case<'_>> = vec![
        ("h", vec![("_JAVA_OPTIONS", &uh)], true, None, Some("2")),
        ("i", vec![("JDK_JAVA_OPTIONS", &uh)], false, None, Some("2")),
        (
            "i under MAVEN_OPTS",
            vec![("JDK_JAVA_OPTIONS", &uh)],
            true,
            None,
            Some("1"),
        ),
        (
            "k",
            vec![("JAVA_TOOL_OPTIONS", &uh)],
            false,
            None,
            Some("2"),
        ),
        ("l", vec![("MAVEN_DEBUG_OPTS", &uh)], true, None, Some("2")),
        (
            "m",
            vec![("MAVEN_OPTS", &oth), ("_JAVA_OPTIONS", &uh)],
            false,
            None,
            Some("2"),
        ),
        ("g", vec![], true, Some(&rc_uh), Some("2")),
        // The shell runs a conditional one as mvn does.
        (
            "mavenrc whose condition fails",
            vec![],
            true,
            Some(rc_conditional),
            Some("1"),
        ),
        (
            "mavenrc whose condition holds",
            vec![
                ("RAEVA_COND", "1"),
                (rv_config::PASSWD_HOME_TEST_ENV, &other_home),
            ],
            true,
            Some(rc_conditional),
            Some("3"),
        ),
        // mvn's MAVEN_OPTS is then the mavenrc's, without the inherited
        // -Duser.home.
        (
            "mavenrc MAVEN_OPTS over an inherited user.home",
            vec![(rv_config::PASSWD_HOME_TEST_ENV, &other_home)],
            true,
            Some(&rc_xmx),
            Some("3"),
        ),
        (
            "mavenrc MAVEN_OPTS",
            vec![(rv_config::PASSWD_HOME_TEST_ENV, &base_home)],
            false,
            Some(&rc_xmx),
            Some("1"),
        ),
        ("plain MAVEN_OPTS", vec![], true, None, Some("1")),
    ];
    for (cell, vars, harness, mavenrc, expected) in cases {
        let project = tempfile::tempdir().unwrap();
        let root = project.path();
        user_home_project(root, true);
        let rc_home = tempfile::tempdir().unwrap();
        if let Some(text) = mavenrc {
            fs::write(rc_home.path().join(rc_name), text).unwrap();
        }
        let mut command = raeva_command(root, base.path());
        command
            .env("HOME", rc_home.path())
            .env("USERPROFILE", rc_home.path())
            .env("JAVA_HOME", &java);
        if !harness {
            command.env_remove("MAVEN_OPTS");
        }
        for (name, value) in &vars {
            command.env(name, value);
        }
        let output = command
            .args(["sync", "--offline"])
            .output()
            .expect("run raeva");
        let stderr = String::from_utf8_lossy(&output.stderr);
        match expected {
            Some(expected) => {
                assert_success(&output, cell);
                assert_eq!(
                    locked_home(root),
                    (format!("{expected}.0"), expected.to_string()),
                    "{cell}"
                );
            }
            None => {
                assert_status(&output, 3, cell);
                assert!(stderr.contains(rc_name), "{cell}: {stderr}");
                assert!(stderr.contains("-Duser.home=<dir>"), "{cell}: {stderr}");
                // The remedy it names: a -Duser.home on the command line,
                // which MavenCli sets over every channel.
                let other_home = format!("-Duser.home={}", other.path().display());
                let mut command = raeva_command(root, base.path());
                command
                    .env("HOME", rc_home.path())
                    .env("USERPROFILE", rc_home.path())
                    .env("JAVA_HOME", &java);
                let output = command
                    .args([other_home.as_str(), "sync", "--offline"])
                    .output()
                    .expect("run raeva");
                assert_success(&output, &format!("{cell} with -Duser.home"));
                assert_eq!(
                    locked_home(root),
                    ("3.0".to_string(), "3".to_string()),
                    "{cell}"
                );
            }
        }
    }
}

/// A user without a passwd home, as `docker run -u <uid>` gives (cells e
/// and f): JDK 18 and later take `HOME`, JDK 17 does not, and for a JDK
/// raeva cannot tell the sync refuses. A passwd home stays the home
/// whatever `HOME` says. With no home at all the JVM's is `?`, below the
/// working directory, where `export-m2` refuses to write. macOS takes the
/// home from Foundation instead, and raeva refuses there.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn a_user_without_a_passwd_home_takes_home_as_the_jdk_does() {
    let base = tempfile::tempdir().unwrap();
    let passwd = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    home(passwd.path(), 1);
    home(other.path(), 3);
    let jdks = tempfile::tempdir().unwrap();
    let (jdk_21, jdk_17) = (jdk(jdks.path(), "21.0.9"), jdk(jdks.path(), "17.0.21"));
    // (case, passwd home, JAVA_HOME, HOME, the home the lock follows:
    // a number, "?" for none, or None for exit 3)
    let passwd_home = passwd.path().display().to_string();
    type Case<'a> = (
        &'a str,
        &'a str,
        Option<&'a Path>,
        Option<&'a Path>,
        Option<&'a str>,
    );
    let cases: [Case<'_>; 7] = [
        (
            "e no entry",
            "",
            Some(&jdk_21),
            Some(other.path()),
            Some("3"),
        ),
        (
            "f home /",
            "/",
            Some(&jdk_21),
            Some(other.path()),
            Some("3"),
        ),
        (
            "passwd home",
            &passwd_home,
            Some(&jdk_21),
            Some(other.path()),
            Some("1"),
        ),
        ("JDK 17", "", Some(&jdk_17), Some(other.path()), Some("?")),
        (
            "JDK 17 home /",
            "/",
            Some(&jdk_17),
            Some(other.path()),
            Some("?"),
        ),
        ("no HOME", "", Some(&jdk_21), None, Some("?")),
        ("unknown JDK", "", None, Some(other.path()), None),
    ];
    for (case, entry, java, home_var, expected) in cases {
        let project = tempfile::tempdir().unwrap();
        let root = project.path();
        user_home_project(root, expected != Some("?"));
        let mut command = raeva_command(root, base.path());
        command
            .env_remove("MAVEN_OPTS")
            .env(rv_config::PASSWD_HOME_TEST_ENV, entry)
            .current_dir(root);
        match java {
            Some(java) => command.env("JAVA_HOME", java),
            None => command.env_remove("JAVA_HOME"),
        };
        match home_var {
            Some(home) => command.env("HOME", home),
            None => command.env_remove("HOME"),
        };
        let output = command
            .args(["sync", "--offline"])
            .output()
            .expect("run raeva");
        let stderr = String::from_utf8_lossy(&output.stderr);
        match expected {
            None => {
                assert_status(&output, 3, case);
                assert!(stderr.contains("JDK 18"), "{case}: {stderr}");
            }
            // No settings.xml: the POM's own version, and export-m2 does
            // not write below the checkout. JDK 17 keeps a passwd home of
            // `/`, whose `/.m2` no test writes to.
            Some("?") => {
                assert_success(&output, case);
                let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
                assert!(lock.contains("org.test:lib:9.0"), "{case}: {lock}");
                if entry == "/" {
                    continue;
                }
                let mut export = raeva_command(root, base.path());
                export
                    .env_remove("MAVEN_OPTS")
                    .env(rv_config::PASSWD_HOME_TEST_ENV, entry)
                    .current_dir(root);
                match java {
                    Some(java) => export.env("JAVA_HOME", java),
                    None => export.env_remove("JAVA_HOME"),
                };
                match home_var {
                    Some(home) => export.env("HOME", home),
                    None => export.env_remove("HOME"),
                };
                let output = export
                    .args(["--offline", "export-m2"])
                    .output()
                    .expect("run raeva");
                let what = format!("{case} export-m2");
                assert_status(&output, 3, &what);
                assert!(!root.join("?").exists(), "{what}");
            }
            Some(expected) => {
                assert_success(&output, case);
                assert_eq!(
                    locked_home(root),
                    (format!("{expected}.0"), expected.to_string()),
                    "{case}"
                );
            }
        }
    }
}

/// A sync of the project at `root`, in Maven mode `mode`, without the
/// harness's `MAVEN_OPTS`, after `setup`.
fn sync_with(
    root: &Path,
    base: &Path,
    mode: &str,
    setup: impl FnOnce(&mut std::process::Command),
) -> std::process::Output {
    fs::write(
        root.join("raeva.toml"),
        format!("[lock]\nmaven = \"{mode}\"\n"),
    )
    .unwrap();
    let mut command = raeva_command(root, base);
    command.env_remove("MAVEN_OPTS");
    setup(&mut command);
    command
        .args(["sync", "--offline"])
        .output()
        .expect("run raeva")
}

fn assert_refuses(output: &std::process::Output, case: &str, needle: &str) {
    assert_status(output, 3, case);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(needle), "{case}: {stderr}");
}

/// A1: a byte that is not UTF-8 elsewhere in a JVM option variable leaves
/// its `-Duser.home` as `mvn` passes it, which Maven 3.9.12 and 3.10.0
/// read; 0.6.0 took the variable as unset.
#[cfg(unix)]
#[test]
fn a_user_home_beside_bytes_that_are_not_utf8_is_read() {
    use std::os::unix::ffi::OsStringExt;
    let (base, defined) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    home(base.path(), 1);
    home(defined.path(), 2);
    for name in ["MAVEN_OPTS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"] {
        let project = tempfile::tempdir().unwrap();
        user_home_project(project.path(), true);
        let mut value = b"-Dfoo=\xff -Duser.home=".to_vec();
        value.extend(defined.path().as_os_str().as_encoded_bytes());
        let output = sync_with(project.path(), base.path(), "3.9", |command| {
            command.env(name, std::ffi::OsString::from_vec(value));
        });
        assert_success(&output, name);
        assert_eq!(
            locked_home(project.path()),
            ("2.0".into(), "2".into()),
            "{name}"
        );
    }
}

/// A2: `mvn` splits `.mvn/jvm.config` at space, tab and line breaks, so a
/// no-break space stays in the `-Duser.home` value, as Maven 3.9.12 and
/// 3.10.0 read it under a UTF-8 locale.
#[cfg(unix)]
#[test]
fn jvm_config_keeps_a_no_break_space_in_the_user_home() {
    let base = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    let (spaced, cut) = (base.path().join("h\u{a0}x"), base.path().join("h"));
    for (dir, n) in [(&spaced, 2), (&cut, 3)] {
        fs::create_dir_all(dir.join(".m2")).unwrap();
        home(dir, n);
    }
    for mode in ["3.9", "3.10"] {
        let project = tempfile::tempdir().unwrap();
        let root = project.path();
        user_home_project(root, true);
        fs::create_dir_all(root.join(".mvn")).unwrap();
        fs::write(
            root.join(".mvn/jvm.config"),
            format!("-Duser.home={}\n", spaced.display()),
        )
        .unwrap();
        let output = sync_with(root, base.path(), mode, |command| {
            command.env("LC_ALL", "C.UTF-8");
        });
        assert_success(&output, mode);
        assert_eq!(locked_home(root), ("2.0".into(), "2".into()), "{mode}");
    }
}

/// A3: Maven 3.10's `mvn` writes the project directory into
/// `.mvn/jvm.config` with `sed`, where an `&` stands for the text it
/// replaces: in `p&q`, `$MAVEN_PROJECTBASEDIR/hh` reads
/// `p$MAVEN_PROJECTBASEDIRq/hh`.
#[cfg(unix)]
#[test]
fn maven_310_writes_an_ampersand_directory_in_as_sed_does() {
    let (base, parent) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    home(base.path(), 1);
    let root = parent.path().join("p&q");
    let sed = parent.path().join("p$MAVEN_PROJECTBASEDIRq/hh");
    for (dir, n) in [(&root.join("hh"), 2), (&sed, 3)] {
        fs::create_dir_all(dir.join(".m2")).unwrap();
        home(dir, n);
    }
    user_home_project(&root, true);
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join(".mvn/jvm.config"),
        "-Duser.home=$MAVEN_PROJECTBASEDIR/hh\n",
    )
    .unwrap();
    let output = sync_with(&root, base.path(), "3.10", |_| {});
    assert_success(&output, "p&q");
    assert_eq!(locked_home(&root), ("3.0".into(), "3".into()));
}

/// `mvn` passes `MAVEN_ARGS`, as the mavenrc files leave it, before its
/// own arguments, so a `-s` there chooses the settings file Maven reads,
/// even over the command line's, and raeva reads that file; 0.6.0 refused
/// it even beside the same `-s` on raeva's command line. A `-gs` there
/// refuses.
#[test]
fn a_settings_file_in_maven_args_is_read() {
    let (base, other) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    home(base.path(), 1);
    home(other.path(), 3);
    let settings = other.path().join(".m2/settings.xml");
    let sync = |args: &str, cli: &[&str], rc_home: Option<&Path>| {
        let project = tempfile::tempdir().unwrap();
        user_home_project(project.path(), true);
        let output = sync_with(project.path(), base.path(), "3.9", |command| {
            isolate_maven_user_home(command, base.path(), "");
            command.env("MAVEN_ARGS", args).args(cli);
            if let Some(rc_home) = rc_home {
                command.env_remove("MAVEN_ARGS").env("HOME", rc_home);
            }
        });
        (project, output)
    };
    let base_settings = base.path().join(".m2/settings.xml");
    for (args, cli) in [
        (format!("-s {}", settings.display()), vec![]),
        (format!("--settings={}", settings.display()), vec![]),
        (
            format!("-B -s {}", settings.display()),
            vec!["-s".to_string(), settings.display().to_string()],
        ),
        (
            format!("-s {}", settings.display()),
            vec!["-s".to_string(), base_settings.display().to_string()],
        ),
    ] {
        let cli: Vec<&str> = cli.iter().map(String::as_str).collect();
        let (project, output) = sync(&args, &cli, None);
        assert_success(&output, &args);
        assert_eq!(
            locked_home(project.path()),
            ("3.0".into(), "1".into()),
            "{args}"
        );
    }
    let args = format!("-gs {}", settings.display());
    assert_refuses(&sync(&args, &[], None).1, &args, "MAVEN_ARGS: it holds -gs");
    #[cfg(unix)]
    {
        let rc_home = tempfile::tempdir().unwrap();
        let rc = format!("MAVEN_ARGS=\"-s {}\"\n", settings.display());
        fs::write(rc_home.path().join(".mavenrc"), rc).unwrap();
        let (project, output) = sync("", &[], Some(rc_home.path()));
        assert_success(&output, "mavenrc");
        assert_eq!(locked_home(project.path()), ("3.0".into(), "1".into()));
    }
}

/// A mavenrc file raeva cannot follow may set `MAVEN_ARGS` and the other
/// variables `mvn` reads, and one that changes `IFS` splits `MAVEN_ARGS`
/// otherwise, so both refuse even with `-Duser.home` on the command line.
#[cfg(unix)]
#[test]
fn a_mavenrc_that_stops_mvn_or_changes_ifs_refuses() {
    let base = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    let user_home = format!("-Duser.home={}", base.path().display());
    for (rc, maven_args, needle) in [
        (
            ". /nonexistent/more\n",
            None,
            "stops mvn's shell before mvn starts Maven",
        ),
        ("IFS=,\n", Some("-Dbase=U2,-Ppb"), "changes IFS"),
    ] {
        let (project, rc_home) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        fs::write(rc_home.path().join(".mavenrc"), rc).unwrap();
        user_home_project(project.path(), true);
        let output = sync_with(project.path(), base.path(), "3.9", |command| {
            isolate_maven_user_home(command, base.path(), "");
            command.env("HOME", rc_home.path()).arg(&user_home);
            if let Some(args) = maven_args {
                command.env("MAVEN_ARGS", args);
            }
        });
        assert_refuses(&output, rc, needle);
    }
}

/// A mavenrc file that leaves a process running, which holds raeva's pipe
/// open, and then exits fails the sync as soon as it exits, as `mvn` fails
/// at once, not when raeva's time for the files runs out.
#[cfg(unix)]
#[test]
fn a_mavenrc_that_exits_beside_a_running_process_refuses_at_once() {
    let base = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    let (project, rc_home) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let pid = rc_home.path().join("pid");
    let rc = format!("sleep 600 &\necho \"$!\" >> '{}'\nexit 1\n", pid.display());
    fs::write(rc_home.path().join(".mavenrc"), &rc).unwrap();
    user_home_project(project.path(), true);
    let start = std::time::Instant::now();
    let output = sync_with(project.path(), base.path(), "3.9", |command| {
        isolate_maven_user_home(command, base.path(), "");
        command.env("HOME", rc_home.path());
    });
    let took = start.elapsed();
    for pid in fs::read_to_string(&pid)
        .unwrap_or_default()
        .split_whitespace()
    {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", pid])
            .status();
    }
    assert_refuses(&output, &rc, "stops mvn's shell before mvn starts Maven");
    assert!(took < std::time::Duration::from_secs(60), "{took:?}");
}

/// `mvn` sources the mavenrc files before it reads `MAVEN_ARGS`, and
/// `MavenCli` sets a `-D` there over the JVM's, so the `-Duser.home` a
/// `.mavenrc`'s `MAVEN_ARGS` gives wins over `MAVEN_OPTS`'s.
#[cfg(unix)]
#[test]
fn a_mavenrc_maven_args_user_home_is_the_command_lines() {
    let (base, defined) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    home(base.path(), 1);
    home(defined.path(), 2);
    let (project, rc_home) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let rc = format!(
        "MAVEN_ARGS=\"-B -Duser.home={}\"\n",
        defined.path().display()
    );
    fs::write(rc_home.path().join(".mavenrc"), rc).unwrap();
    user_home_project(project.path(), true);
    let output = sync_with(project.path(), base.path(), "3.9", |command| {
        isolate_maven_user_home(command, base.path(), "");
        command.env("HOME", rc_home.path());
    });
    assert_success(&output, "mavenrc MAVEN_ARGS");
    assert_eq!(locked_home(project.path()), ("2.0".into(), "2".into()));
}

/// A5 and B4: raeva follows the assignments of a `.mavenrc`: one that
/// appends to an inherited `MAVEN_OPTS` keeps its `-Duser.home`, and one
/// that spells `user.home` with an empty variable sets it.
#[cfg(unix)]
#[test]
fn mavenrc_assignments_set_the_user_home() {
    let (base, defined) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    home(base.path(), 1);
    home(defined.path(), 2);
    let base_home = base.path().display().to_string();
    for (case, rc, inherited) in [
        (
            "B4",
            "MAVEN_OPTS=\"$MAVEN_OPTS -Xmx64m\"\n".to_string(),
            true,
        ),
        (
            "a JDK",
            "if [ \"$(uname)\" = Darwin ]; then\n  export JAVA_HOME=$(/usr/libexec/java_home)\nfi\n"
                .to_string(),
            true,
        ),
        (
            "${NOPE}",
            format!(
                "MAVEN_OPTS=\"-Duser.h${{NOPE}}ome={}\"\n",
                defined.path().display()
            ),
            false,
        ),
    ] {
        let project = tempfile::tempdir().unwrap();
        let rc_home = tempfile::tempdir().unwrap();
        fs::write(rc_home.path().join(".mavenrc"), rc).unwrap();
        user_home_project(project.path(), true);
        let output = sync_with(project.path(), base.path(), "3.9", |command| {
            command
                .env("HOME", rc_home.path())
                .env(rv_config::PASSWD_HOME_TEST_ENV, &base_home);
            if inherited {
                isolate_maven_user_home(command, defined.path(), "");
            }
        });
        assert_success(&output, case);
        assert_eq!(
            locked_home(project.path()),
            ("2.0".into(), "2".into()),
            "{case}"
        );
    }
}

/// A6: the JVM decodes a non-ASCII `user.home` in its native encoding,
/// which under the C locale is ASCII, so Maven reads `h??` for `hé`;
/// under a UTF-8 locale it reads `hé`.
#[cfg(unix)]
#[test]
fn a_non_ascii_user_home_needs_a_utf8_locale() {
    let base = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    let accented = base.path().join("h\u{e9}");
    fs::create_dir_all(accented.join(".m2")).unwrap();
    home(&accented, 2);
    let locales: &[(&str, Option<&str>, bool)] = &[
        ("LC_ALL", Some("C"), false),
        ("LANG", Some("POSIX"), false),
        ("LC_ALL", Some("C.UTF-8"), true),
    ];
    let unset = (cfg!(target_os = "macos"), true);
    for (name, value, reads) in locales.iter().copied().chain(
        // macOS's JDK takes UTF-8 when no locale variable is set.
        unset.0.then_some(("LANG", None, unset.1)),
    ) {
        let project = tempfile::tempdir().unwrap();
        user_home_project(project.path(), true);
        let output = sync_with(project.path(), base.path(), "3.9", |command| {
            isolate_maven_user_home(command, &accented, "");
            for variable in ["LC_ALL", "LC_CTYPE", "LANG"] {
                command.env_remove(variable);
            }
            if let Some(value) = value {
                command.env(name, value);
            }
        });
        let case = format!("{name}={value:?}");
        if reads {
            assert_success(&output, &case);
            assert_eq!(
                locked_home(project.path()),
                ("2.0".into(), "2".into()),
                "{case}"
            );
        } else {
            assert_refuses(&output, &case, "is not ASCII");
        }
    }
}

/// A10: `mvn` passes `.mvn/jvm.config` through its `/bin/sh`'s `echo`,
/// which in macOS's shell and dash expands backslash escapes, so
/// `-Dfoo=a\cb -Duser.home=B` ends at `\c`; raeva asks the shell, here a
/// bash that expands them, and refuses.
#[cfg(unix)]
#[test]
fn a_backslash_the_launcher_echo_expands_refuses() {
    if !Path::new("/bin/bash").is_file() {
        return;
    }
    let (base, defined) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    home(base.path(), 1);
    home(defined.path(), 2);
    let shell = base.path().join("xpg-sh");
    fs::write(&shell, "#!/bin/bash\nexec /bin/bash -O xpg_echo \"$@\"\n").unwrap();
    let mut permissions = fs::metadata(&shell).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    fs::set_permissions(&shell, permissions).unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    user_home_project(root, true);
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join(".mvn/jvm.config"),
        format!("-Dfoo=a\\cb -Duser.home={}\n", defined.path().display()),
    )
    .unwrap();
    let output = sync_with(root, base.path(), "3.9", |command| {
        command.env(rv_config::maven_config::LAUNCHER_SHELL_TEST_ENV, &shell);
    });
    assert_refuses(&output, "\\c", "has a backslash");
}

/// B3: Maven 3.9's `mvn` writes nothing into `.mvn/jvm.config`, so
/// `-Duser.home=${MAVEN_PROJECTBASEDIR}/hh` is that relative directory as
/// written; Maven expands it again where a settings.xml there takes
/// `${user.home}`, which raeva does not, so that one refuses.
#[test]
fn a_maven_39_jvm_config_user_home_with_an_expression_is_literal() {
    let base = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    user_home_project(root, false);
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join(".mvn/jvm.config"),
        "-Duser.home=${MAVEN_PROJECTBASEDIR}/hh\n",
    )
    .unwrap();
    let output = sync_with(root, base.path(), "3.9", |command| {
        command.current_dir(root);
    });
    assert_success(&output, "no settings.xml there");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("org.test:lib:9.0"), "{lock}");
    let literal = root.join("${MAVEN_PROJECTBASEDIR}/hh");
    fs::create_dir_all(literal.join(".m2")).unwrap();
    fs::write(
        literal.join(".m2/settings.xml"),
        "<settings><profiles><profile><id>d</id><properties><libver>2.0</libver>\
         </properties></profile></profiles><activeProfiles><activeProfile>d</activeProfile>\
         </activeProfiles></settings>",
    )
    .unwrap();
    let output = sync_with(root, base.path(), "3.9", |command| {
        command.current_dir(root);
    });
    assert_success(&output, "a settings.xml there");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("org.test:lib:2.0"), "{lock}");
    home(&literal, 2);
    let output = sync_with(root, base.path(), "3.9", |command| {
        command.current_dir(root);
    });
    assert_refuses(&output, "one that takes ${user.home}", "expands again");
}

/// A9: with a `..`, macOS resolves `CFFIXED_USER_HOME` through symbolic
/// links, as measured on macOS 27, which raeva does not, so it refuses.
#[cfg(target_os = "macos")]
#[test]
fn a_cffixed_user_home_with_dotdot_through_a_link_refuses() {
    let base = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    let dirs = tempfile::tempdir().unwrap();
    fs::create_dir_all(dirs.path().join("x/real")).unwrap();
    std::os::unix::fs::symlink(dirs.path().join("x/real"), dirs.path().join("x/l")).unwrap();
    let project = tempfile::tempdir().unwrap();
    user_home_project(project.path(), true);
    let output = sync_with(project.path(), base.path(), "3.9", |command| {
        command.env("CFFIXED_USER_HOME", dirs.path().join("x/l/../C"));
    });
    assert_refuses(&output, "x/l/../C", "CFFIXED_USER_HOME");
}

/// A7, A8 and B1: `mvn.cmd` reads `.mvn/jvm.config` with delayed
/// expansion, which drops each `!` and `^`, in the console's code page,
/// and leaves its quotes to java; cmd drops a `^` of `MAVEN_OPTS`. Each
/// refuses, as measured with Maven 3.9.12 and 3.10.0 on Windows 11.
#[cfg(windows)]
#[test]
fn what_mvn_cmd_changes_in_the_user_home_refuses() {
    let base = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    let dir = base.path().display().to_string();
    for (case, jvm_config, maven_opts, needle) in [
        ("!", format!("-Duser.home={dir}\\h!x"), None, "! or ^"),
        ("^", format!("-Duser.home={dir}\\h^x"), None, "! or ^"),
        (
            "é",
            format!("-Duser.home={dir}\\h\u{e9}"),
            None,
            "not ASCII",
        ),
        (
            "quotes",
            format!("-Duser.home=\"{dir}\\a b\""),
            None,
            "quotes",
        ),
        (
            "MAVEN_OPTS ^",
            String::new(),
            Some(format!("-Duser.home={dir}\\h^x")),
            "MAVEN_OPTS",
        ),
    ] {
        let project = tempfile::tempdir().unwrap();
        let root = project.path();
        user_home_project(root, true);
        fs::create_dir_all(root.join(".mvn")).unwrap();
        fs::write(root.join(".mvn/jvm.config"), jvm_config).unwrap();
        let output = sync_with(root, base.path(), "3.9", |command| {
            if let Some(opts) = &maven_opts {
                command.env("MAVEN_OPTS", opts);
            }
        });
        assert_refuses(&output, case, needle);
    }
}

/// A secret a mavenrc file passes through a chain of assignments is
/// registered as the user-home reader evaluates it, so a refusal that
/// quotes the value hides it.
#[cfg(unix)]
#[test]
fn a_secret_through_chained_mavenrc_assignments_stays_hidden() {
    let base = tempfile::tempdir().unwrap();
    home(base.path(), 1);
    let rc_home = tempfile::tempdir().unwrap();
    fs::write(
        rc_home.path().join(".mavenrc"),
        "FIRST=zqSECRETzq\nSECOND=\"$FIRST\"\n\
         MAVEN_OPTS=\"-Dapi.token=$SECOND -Duser.home=$SECOND/\\${java.version}\"\n",
    )
    .unwrap();
    let project = tempfile::tempdir().unwrap();
    user_home_project(project.path(), true);
    let output = sync_with(project.path(), base.path(), "3.9", |command| {
        command.env("HOME", rc_home.path());
    });
    assert_refuses(&output, "chained", "takes an expression");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!said.contains("zqSECRETzq"), "{said}");
}

/// `mvn` sources the mavenrc files before it picks the JDK, so a
/// `JAVA_HOME` one exports is the JDK it runs and the one a POM's
/// `${env.JAVA_HOME}` file activation tests.
#[cfg(unix)]
#[test]
fn a_mavenrc_java_home_is_the_jdk_mvn_runs() {
    let base = tempfile::tempdir().unwrap();
    let jdks = tempfile::tempdir().unwrap();
    let (jdk8, jdk21) = (jdk(jdks.path(), "1.8.0_402"), jdk(jdks.path(), "21.0.9"));
    fs::create_dir_all(jdk8.join("lib")).unwrap();
    fs::write(jdk8.join("lib/jconsole.jar"), "").unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    user_home_project(root, false);
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "</project>",
        "<profiles><profile><id>jconsole</id><activation><file>\
         <exists>${env.JAVA_HOME}/lib/jconsole.jar</exists></file></activation>\
         <properties><libver>3.0</libver></properties></profile></profiles></project>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let rc_home = tempfile::tempdir().unwrap();
    fs::write(
        rc_home.path().join(".mavenrc"),
        format!("export JAVA_HOME={}\n", jdk8.display()),
    )
    .unwrap();
    let output = sync_with(root, base.path(), "3.9", |command| {
        command
            .env("HOME", rc_home.path())
            .env("JAVA_HOME", &jdk21)
            .env(rv_config::PASSWD_HOME_TEST_ENV, base.path());
    });
    assert_success(&output, "a mavenrc JAVA_HOME");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("org.test:lib:3.0"), "{lock}");
    // The shell runs a conditional one, and a `JAVA_HOME` it does not
    // export picks the JDK, but is not the JVM's `env.JAVA_HOME`.
    let sync = |rc: String, cond: bool, java_home: Option<&Path>| {
        fs::write(rc_home.path().join(".mavenrc"), rc).unwrap();
        let _ = fs::remove_file(root.join("raeva.lock"));
        let output = sync_with(root, base.path(), "3.9", |command| {
            command
                .env("HOME", rc_home.path())
                .env_remove("JAVA_HOME")
                .env_remove("RAEVA_COND")
                .env(rv_config::PASSWD_HOME_TEST_ENV, base.path());
            if let Some(java_home) = java_home {
                command.env("JAVA_HOME", java_home);
            }
            if cond {
                command.env("RAEVA_COND", "1");
            }
        });
        assert_success(&output, "a mavenrc JAVA_HOME");
        fs::read_to_string(root.join("raeva.lock")).unwrap()
    };
    let conditional = format!(
        "[ -n \"$RAEVA_COND\" ] && export JAVA_HOME={}\n",
        jdk8.display()
    );
    let lock = sync(conditional.clone(), false, Some(&jdk21));
    assert!(lock.contains("org.test:lib:9.0"), "{lock}");
    let lock = sync(conditional, true, Some(&jdk21));
    assert!(lock.contains("org.test:lib:3.0"), "{lock}");
    let unexported = format!("JAVA_HOME={}\n", jdk8.display());
    let lock = sync(unexported, false, None);
    assert!(lock.contains("org.test:lib:9.0"), "{lock}");
}

/// settings.xml's `${env.X}`, and a profile there activated by `env.X`,
/// read `X` as Maven's JVM has it after the mavenrc files `mvn` sources.
#[test]
fn a_settings_variable_a_mavenrc_sets_is_read_as_mvn_has_it() {
    let base = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    user_home_project(root, false);
    fs::create_dir_all(base.path().join(".m2")).unwrap();
    let settings = |activation: &str| {
        fs::write(
            base.path().join(".m2/settings.xml"),
            format!(
                "<settings><profiles><profile><id>d</id>{activation}<properties>\
                 <libver>${{env.RAEVA_LIBVER}}</libver></properties></profile></profiles>\
                 </settings>"
            ),
        )
        .unwrap();
    };
    let active = "<activation><activeByDefault>true</activeByDefault></activation>";
    let (mavenrc, read, conditional, conditional_on) = if cfg!(windows) {
        (
            "mavenrc_pre.cmd",
            "set RAEVA_LIBVER=3.0\r\n",
            "if defined RAEVA_COND set RAEVA_LIBVER=2.0\r\n",
            "if defined RAEVA_COND set RAEVA_ON=1\r\n",
        )
    } else {
        (
            ".mavenrc",
            "export RAEVA_LIBVER=3.0\n",
            "[ -n \"$RAEVA_COND\" ] && export RAEVA_LIBVER=2.0\n",
            "[ -n \"$RAEVA_COND\" ] && export RAEVA_ON=1\n",
        )
    };
    let sync = |rc: &str, libver: &str, cond: bool| {
        let _ = fs::remove_file(root.join("raeva.lock"));
        fs::write(base.path().join(mavenrc), rc).unwrap();
        let output = sync_with(root, base.path(), "3.9", |command| {
            command
                .env("RAEVA_LIBVER", libver)
                .env_remove("RAEVA_ON")
                .env_remove("RAEVA_COND")
                .env(rv_config::PASSWD_HOME_TEST_ENV, base.path());
            if cond {
                command.env("RAEVA_COND", "1");
            }
        });
        assert_success(&output, rc);
        fs::read_to_string(root.join("raeva.lock")).unwrap()
    };
    settings(active);
    assert!(sync(read, "9.0", false).contains("org.test:lib:3.0"));
    assert!(sync(conditional, "9.0", false).contains("org.test:lib:9.0"));
    assert!(sync(conditional, "9.0", true).contains("org.test:lib:2.0"));
    settings("<activation><property><name>env.RAEVA_ON</name></property></activation>");
    assert!(sync(conditional_on, "2.0", false).contains("org.test:lib:9.0"));
    assert!(sync(conditional_on, "2.0", true).contains("org.test:lib:2.0"));
}

/// A POM's `${env.X}` reads `X` as the mavenrc files `mvn` sources leave
/// it, and `--frozen` goes stale when they change it.
#[test]
fn a_pom_variable_a_mavenrc_sets_is_read_as_mvn_has_it() {
    let base = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    user_home_project(root, false);
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "</project>",
        "<profiles><profile><id>rc</id><activation><property><name>env.RAEVA_LIBVER</name>\
         <value>3</value></property></activation><properties><libver>3.0</libver>\
         </properties></profile></profiles></project>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let (mavenrc, read, conditional) = if cfg!(windows) {
        (
            "mavenrc_pre.cmd",
            "set RAEVA_LIBVER=3\r\n",
            "if defined RAEVA_COND set RAEVA_LIBVER=3\r\n",
        )
    } else {
        (
            ".mavenrc",
            "export RAEVA_LIBVER=3\n",
            "[ -n \"$RAEVA_COND\" ] && export RAEVA_LIBVER=3\n",
        )
    };
    let sync = |allowed: bool, rc: &str| {
        let _ = fs::remove_file(root.join("raeva.lock"));
        let allowlist = if allowed { "\"RAEVA_LIBVER\"" } else { "" };
        fs::write(
            base.path().join("config.toml"),
            format!("[security]\nallow_env_substitution = [{allowlist}]\n"),
        )
        .unwrap();
        fs::write(base.path().join(mavenrc), rc).unwrap();
        sync_with(root, base.path(), "3.9", |command| {
            command
                .env_remove("RAEVA_LIBVER")
                .env_remove("RAEVA_COND")
                .env(rv_config::PASSWD_HOME_TEST_ENV, base.path());
        })
    };
    let lock = || fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert_success(&sync(true, ""), "no mavenrc");
    assert!(lock().contains("org.test:lib:9.0"), "{}", lock());
    assert_success(&sync(true, read), "a mavenrc that sets it");
    assert!(lock().contains("org.test:lib:3.0"), "{}", lock());
    // Outside the allowlist an activation refuses it, set or not.
    assert_status(&sync(false, read), 3, "a variable off the allowlist");
    assert_success(&sync(true, conditional), "a mavenrc whose condition fails");
    assert!(lock().contains("org.test:lib:9.0"), "{}", lock());
    // A lock that reads it goes stale when the files change it.
    assert_success(&sync(true, read), "a mavenrc that sets it");
    fs::write(base.path().join(mavenrc), conditional).unwrap();
    let frozen = |cond: bool| {
        let mut frozen = raeva_command(root, base.path());
        frozen.env_remove("MAVEN_OPTS").env_remove("RAEVA_LIBVER");
        frozen.env_remove("RAEVA_COND");
        if cond {
            frozen.env("RAEVA_COND", "1");
        }
        frozen.env(rv_config::PASSWD_HOME_TEST_ENV, base.path());
        frozen
            .args(["sync", "--frozen", "--offline"])
            .output()
            .unwrap()
    };
    assert_status(&frozen(false), 7, "a frozen check the files make stale");
    assert_success(&frozen(true), "a frozen check the files keep");
}

/// A `user.home` raeva cannot look into holds no settings for it, as for
/// Maven, whose `File.exists` is false there: no settings.xml, and no
/// settings-security.xml for the settings `-s` names, even with an
/// encrypted password in them. `HOME` readable or not, the lock is the one
/// an empty `user.home` gives.
#[cfg(unix)]
#[test]
fn a_user_home_raeva_cannot_look_into_has_no_settings() {
    use std::os::unix::fs::PermissionsExt;
    let base = tempfile::tempdir().unwrap();
    let closed = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let settings = tempfile::tempdir().unwrap();
    fs::create_dir_all(closed.path().join(".m2")).unwrap();
    fs::write(
        closed.path().join(".m2/settings.xml"),
        "<settings><profiles><profile><id>d</id><properties><libver>2.0</libver>\
         </properties></profile></profiles><activeProfiles><activeProfile>d\
         </activeProfile></activeProfiles></settings>",
    )
    .unwrap();
    fs::write(
        closed.path().join(".m2/settings-security.xml"),
        "<settingsSecurity><master>{jSMOWnoPFgsHVpMvz5VrIt5kRbzGpI8u+9EF1iFQyJQ=}</master>\
         </settingsSecurity>",
    )
    .unwrap();
    let explicit = settings.path().join("s.xml");
    fs::write(
        &explicit,
        "<settings><servers><server><id>s</id><username>u</username>\
         <password>{COQLCE6DU6GtcS5P=}</password></server></servers></settings>",
    )
    .unwrap();
    let explicit = explicit.display().to_string();
    let sync = |user_home: &Path, home: &Path, args: &[&str]| {
        let project = tempfile::tempdir().unwrap();
        let root = project.path();
        for version in ["1.0", "2.0"] {
            publish(&root.join("repo"), &format!("org.test:lib:{version}"), "");
        }
        fs::write(
            root.join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><properties><libver>1.0\
             </libver></properties><repositories><repository><id>prj</id>\
             <url>file://${project.basedir}/repo/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib\
             </artifactId><version>${libver}</version></dependency></dependencies></project>",
        )
        .unwrap();
        let mut command = raeva_command(root, base.path());
        command.env("HOME", home);
        isolate_maven_user_home(&mut command, user_home, "");
        let output = command
            .args(["sync", "--offline"])
            .args(args)
            .output()
            .expect("run raeva");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap_or_default();
        (output, lock)
    };
    let mut expected = Vec::new();
    for args in [&[][..], &["-s", &explicit]] {
        let (output, lock) = sync(empty.path(), empty.path(), args);
        assert_success(&output, "an empty user.home");
        expected.push(lock);
    }
    fs::set_permissions(closed.path(), fs::Permissions::from_mode(0o000)).unwrap();
    // A process that may override file modes, such as root in a user
    // namespace, looks in anyway.
    let looks_in = fs::metadata(closed.path().join(".m2")).is_ok();
    let mut results = Vec::new();
    if !looks_in {
        for home in [base.path(), closed.path()] {
            for (args, expected) in [&[][..], &["-s", &explicit]].into_iter().zip(&expected) {
                results.push((
                    home.to_path_buf(),
                    args.len(),
                    sync(closed.path(), home, args),
                    expected,
                ));
            }
        }
    }
    fs::set_permissions(closed.path(), fs::Permissions::from_mode(0o755)).unwrap();
    for (home, args, (output, lock), expected) in results {
        let case = format!("HOME {}, {args} arguments", home.display());
        assert_success(&output, &case);
        assert_eq!(&lock, expected, "{case}");
    }
}
