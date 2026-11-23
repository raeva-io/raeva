use std::collections::HashMap;
use std::path::Path;

use super::*;
use crate::maven_config::CommandLine;

const JDK_21: LauncherJdk = LauncherJdk {
    feature: Some(21),
    openj9: false,
};

/// The `-Duser.home` value for these variables, `.mvn/jvm.config` and
/// `defines`, on `jdk`, or the refusal's message.
fn define(
    vars: &[(&str, &str)],
    jvm_config: Option<&str>,
    defines: &[&str],
    jdk: LauncherJdk,
    mavenrc: &[&str],
) -> Result<Option<String>, String> {
    let vars: HashMap<String, String> = (vars.iter())
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let host = Host {
        shell: shell(vars, mavenrc),
        jdk,
        working_dir: Path::new("/"),
    };
    let defines = CommandLine {
        defines: defines.iter().map(|define| define.to_string()).collect(),
        ..CommandLine::default()
    };
    let options = crate::jvm_options::read(jvm_config, &host).map_err(|error| error.to_string())?;
    user_home_define(&options, &defines, &defines).map_err(|error| error.to_string())
}

/// The shell `mvn` holds for `vars` once `/bin/sh` has sourced `mavenrc`,
/// the text of each file.
fn shell(vars: HashMap<String, String>, mavenrc: &[&str]) -> Shell {
    let vars: Vec<(&str, &str)> = (vars.iter())
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    if mavenrc.is_empty() {
        return Shell::for_testing(&[], &vars, &vars, &[]);
    }
    let names = (vars.iter().map(|(name, _)| *name)).chain([
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "_JAVA_OPTIONS",
        "OPENJ9_JAVA_OPTIONS",
        "IBM_JAVA_OPTIONS",
    ]);
    let names: Vec<&str> = names.collect();
    #[cfg(unix)]
    return Shell::sourcing_for_testing(&vars, &mavenrc.join("\n"), &names)
        .expect("the mavenrc runs");
    #[cfg(not(unix))]
    unreachable!("a mavenrc test runs {names:?} through /bin/sh");
}

/// The JVM reads `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, its command line
/// (`.mvn/jvm.config`, `MAVEN_OPTS`, `MAVEN_DEBUG_OPTS`) and then
/// `_JAVA_OPTIONS`, the last `-Duser.home` winning, as JDK 17, 21 and 27
/// and Maven 3.9.12 and 3.10.0 were measured to; `MavenCli`'s `-D` values
/// override them all.
#[test]
fn each_channel_wins_over_the_ones_the_jvm_reads_before_it() {
    let order = [
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "jvm.config",
        "MAVEN_OPTS",
        "MAVEN_DEBUG_OPTS",
        "_JAVA_OPTIONS",
        "define",
    ];
    for (later, winner) in order.iter().enumerate() {
        for (earlier, loser) in order[..later].iter().enumerate() {
            let mut vars = Vec::new();
            let mut jvm_config = None;
            let mut defines = Vec::new();
            for (index, channel) in [(earlier, loser), (later, winner)] {
                let value = format!("-Duser.home=/h{index}");
                match *channel {
                    "jvm.config" => jvm_config = Some(value),
                    "define" => defines.push(format!("user.home=/h{index}")),
                    name => vars.push((name, value)),
                }
            }
            let vars: Vec<(&str, &str)> = (vars.iter())
                .map(|(name, value)| (*name, value.as_str()))
                .collect();
            let defines: Vec<&str> = defines.iter().map(String::as_str).collect();
            assert_eq!(
                define(&vars, jvm_config.as_deref(), &defines, JDK_21, &[]),
                Ok(Some(format!("/h{later}"))),
                "{winner} over {loser}"
            );
        }
    }
    // Within one channel the last wins, and a bare define is empty.
    let both = [("JAVA_TOOL_OPTIONS", "-Duser.home=/1 -Xmx1g -Duser.home=/2")];
    assert_eq!(define(&both, None, &[], JDK_21, &[]), Ok(Some("/2".into())));
    let bare = [("_JAVA_OPTIONS", "-Duser.home")];
    assert_eq!(
        define(&bare, None, &[], JDK_21, &[]),
        Ok(Some(String::new()))
    );
    let other = [("_JAVA_OPTIONS", "-Duser.homes=/x -Xmx1g")];
    assert_eq!(define(&other, None, &[], JDK_21, &[]), Ok(None));
}

/// JDK 8's launcher reads no `JDK_JAVA_OPTIONS`; for a JDK raeva does not
/// know, a `user.home` there refuses.
#[test]
fn jdk_java_options_count_from_jdk_9() {
    let vars = [("JDK_JAVA_OPTIONS", "-Duser.home=/k")];
    let jdk = |feature| LauncherJdk {
        feature,
        openj9: false,
    };
    assert_eq!(define(&vars, None, &[], jdk(Some(8)), &[]), Ok(None));
    assert_eq!(
        define(&vars, None, &[], jdk(Some(9)), &[]),
        Ok(Some("/k".into()))
    );
    let error = define(&vars, None, &[], jdk(None), &[]).unwrap_err();
    assert!(error.contains("JDK_JAVA_OPTIONS"), "{error}");
}

/// What raeva cannot read exactly refuses, naming the channel; what does
/// not touch `user.home` does not.
#[test]
fn unread_channels_refuse_and_others_pass() {
    let refuses = |vars: &[(&str, &str)], jdk: LauncherJdk, mavenrc: &[&str], channel: &str| {
        let error = define(vars, None, &[], jdk, mavenrc).unwrap_err();
        assert!(error.contains(channel), "{channel}: {error}");
        assert!(error.contains("-Duser.home=<dir>"), "{error}");
    };
    refuses(
        &[("JAVA_TOOL_OPTIONS", "-Duser.home='/a b")],
        JDK_21,
        &[],
        "JAVA_TOOL_OPTIONS",
    );
    assert_eq!(
        define(
            &[("JAVA_TOOL_OPTIONS", "-Duser.home='/a b'")],
            None,
            &[],
            JDK_21,
            &[]
        ),
        Ok(Some("/a b".into()))
    );
    let openj9 = LauncherJdk {
        feature: Some(21),
        openj9: true,
    };
    refuses(
        &[("OPENJ9_JAVA_OPTIONS", "-Duser.home=/j")],
        openj9,
        &[],
        "OPENJ9_JAVA_OPTIONS",
    );
    refuses(
        &[("_JAVA_OPTIONS", "-Duser.home=/j")],
        openj9,
        &[],
        "_JAVA_OPTIONS",
    );
    if !cfg!(windows) {
        // `/` holds no `-Duser.home=` directory, but the working directory
        // matches a pattern in the word's first component.
        refuses(&[("MAVEN_OPTS", "-Duser.home*")], JDK_21, &[], "MAVEN_OPTS");
    }
    refuses(
        &[("MAVEN_OPTS", "@/nonexistent/raeva-argfile")],
        JDK_21,
        &[],
        "cannot be read",
    );
    refuses(
        &[("_JAVA_OPTIONS", "-XX:VMOptionsFile=/nonexistent/raeva-vmo")],
        JDK_21,
        &[],
        "cannot be read",
    );
    // A mavenrc that sets MAVEN_OPTS without user.home, an OpenJ9 variable
    // on HotSpot, and `@` in JAVA_TOOL_OPTIONS, which the JVM refuses
    // itself, pass.
    // Only `/bin/sh` sources a mavenrc file.
    let mavenrc = match cfg!(unix) {
        true => vec!["MAVEN_OPTS=\"-Xmx2g\"\nJAVA_HOME=/opt/jdk"],
        false => vec![],
    };
    for (vars, mavenrc) in [
        (vec![], mavenrc),
        (vec![("OPENJ9_JAVA_OPTIONS", "-Duser.home=/j")], vec![]),
        (
            vec![("JAVA_TOOL_OPTIONS", "@/nonexistent/raeva-argfile")],
            vec![],
        ),
        (vec![("MAVEN_OPTS", "@@literal")], vec![]),
    ] {
        assert_eq!(
            define(&vars, None, &[], JDK_21, &mavenrc),
            Ok(None),
            "{vars:?}"
        );
    }
    // A pattern sh cannot match is passed as written.
    let pattern = [("MAVEN_OPTS", "-Duser.home=/h*/c?dev")];
    assert_eq!(
        define(&pattern, None, &[], JDK_21, &[]),
        Ok(Some("/h*/c?dev".into()))
    );
}

/// An argument file or a VM options file is read in place.
#[test]
fn argument_files_are_read_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let mentions = dir.path().join("mentions");
    let other = dir.path().join("other");
    std::fs::write(&mentions, "-Duser.home=/f\n").unwrap();
    std::fs::write(&other, "-Xmx1g\n").unwrap();
    for (name, token) in [
        ("JDK_JAVA_OPTIONS", "@"),
        ("MAVEN_OPTS", "@"),
        ("MAVEN_DEBUG_OPTS", "@"),
        ("JAVA_TOOL_OPTIONS", "-XX:VMOptionsFile="),
        ("_JAVA_OPTIONS", "-XX:VMOptionsFile="),
    ] {
        let with = |file: &Path| format!("{token}{}", file.display());
        assert_eq!(
            define(&[(name, &with(&mentions))], None, &[], JDK_21, &[]),
            Ok(Some("/f".into())),
            "{name}"
        );
        assert_eq!(
            define(&[(name, &with(&other))], None, &[], JDK_21, &[]),
            Ok(None),
            "{name}"
        );
    }
    // A quote beside the file does not hide it.
    let quoted = format!("-XX:VMOptionsFile={} \"-Dq=a b\"", mentions.display());
    let vars = [
        ("MAVEN_OPTS", "-Duser.home=/m"),
        ("_JAVA_OPTIONS", quoted.as_str()),
    ];
    assert_eq!(define(&vars, None, &[], JDK_21, &[]), Ok(Some("/f".into())));
    let jvm_config = format!("-Xmx1g @{}", mentions.display());
    assert_eq!(
        define(&[], Some(&jvm_config), &[], JDK_21, &[]),
        Ok(Some("/f".into()))
    );
}

/// Found by review: a mavenrc's `MAVEN_OPTS="-Xmx2g"` drops an inherited
/// `-Duser.home`; quotes and backslashes do not hide `user.home`; an
/// argument file may name a VM options file; and the JVM splits its
/// variables at `\r`, while `mvn` passes `\f` in `MAVEN_OPTS` on.
#[cfg(unix)]
#[test]
fn indirect_and_hidden_user_home_refuses() {
    let inherited = [("MAVEN_OPTS", "-Duser.home=/o")];
    let rc = ["MAVEN_OPTS=\"-Xmx2g\""];
    assert_eq!(define(&inherited, None, &[], JDK_21, &rc), Ok(None));
    let other = ["MAVEN_OPTS_EXTRA=1"];
    assert_eq!(
        define(&inherited, None, &[], JDK_21, &other),
        Ok(Some("/o".into()))
    );
    let quoted = [("JAVA_TOOL_OPTIONS", "-D\"user.\"home=/x")];
    assert_eq!(
        define(&quoted, None, &[], JDK_21, &[]),
        Ok(Some("/x".into()))
    );
    for (name, value, home) in [
        ("_JAVA_OPTIONS", "-Duser.home=/a\r-Xmx1g", "/a"),
        ("MAVEN_OPTS", "-Duser.home=/a\x0c", "/a\x0c"),
    ] {
        assert_eq!(
            define(&[(name, value)], None, &[], JDK_21, &[]),
            Ok(Some(home.into())),
            "{name}"
        );
    }
    let rc = ["MAVEN_OPTS=\"-Duser.\"'home=/x'"];
    assert_eq!(define(&[], None, &[], JDK_21, &rc), Ok(Some("/x".into())));

    let dir = tempfile::tempdir().unwrap();
    let outer = dir.path().join("outer");
    let quoted = dir.path().join("quoted");
    let inner = dir.path().join("inner");
    std::fs::write(&outer, format!("-XX:VMOptionsFile={}\n", inner.display())).unwrap();
    std::fs::write(&inner, "-XX:VMOptionsFile=other\n").unwrap();
    std::fs::write(&quoted, "-D\"user.\"home=/x\n").unwrap();
    let at = |file: &Path| [("MAVEN_OPTS", format!("@{}", file.display()))];
    let vars = at(&outer);
    let vars: Vec<(&str, &str)> = vars.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let error = define(&vars, None, &[], JDK_21, &[]).unwrap_err();
    assert!(error.contains("VM options file"), "{error}");
    let vars = at(&quoted);
    let vars: Vec<(&str, &str)> = vars.iter().map(|(n, v)| (*n, v.as_str())).collect();
    assert_eq!(define(&vars, None, &[], JDK_21, &[]), Ok(Some("/x".into())));
}

/// A `-Duser.home` on the command line, `MAVEN_ARGS`'s included, is the
/// remedy every refusal names: `MavenCli` sets it over every channel, also
/// beside a mavenrc file raeva cannot follow, whose `MAVEN_ARGS`
/// `Config::load` refuses.
#[test]
fn a_command_line_user_home_skips_the_refusals() {
    let host = Host {
        shell: Shell::for_testing(
            &["/etc/mavenrc"],
            &[],
            &[("JAVA_TOOL_OPTIONS", "-Duser.home='/q'")],
            &[],
        ),
        jdk: JDK_21,
        working_dir: Path::new("/"),
    };
    let with = |defines: &[&str]| CommandLine {
        defines: defines.iter().map(|define| define.to_string()).collect(),
        ..CommandLine::default()
    };
    let (merged, cli) = (
        with(&["user.home=/cfg", "user.home=/cli"]),
        with(&["user.home=/cli"]),
    );
    let read = |host: &Host<'_>| crate::jvm_options::read(None, host).unwrap();
    assert_eq!(
        user_home_define(&read(&host), &merged, &cli).unwrap(),
        Some("/cli".into())
    );
    let host = Host {
        shell: Shell::for_testing(
            &["/etc/mavenrc"],
            &[],
            &[],
            &[("MAVEN_OPTS", "-Duser.home=/rc")],
        ),
        ..host
    };
    assert_eq!(
        user_home_define(&read(&host), &merged, &cli).unwrap(),
        Some("/cli".into())
    );
    let config_only = with(&["user.home=/cfg"]);
    assert_eq!(
        user_home_define(&read(&host), &config_only, &with(&[])).unwrap(),
        Some("/cfg".into())
    );
}

/// A1: a byte that is not UTF-8 beside the `-Duser.home` of a variable
/// leaves the value as it is; one inside it refuses.
#[cfg(unix)]
#[test]
fn a_variable_that_is_not_utf8_beside_user_home_is_read() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    for (bytes, expected) in [
        (
            &b"-Dfoo=\xff -Duser.home=/b"[..],
            Ok(Some("/b".to_string())),
        ),
        (b"-Duser.home=/\xffb", Err(())),
    ] {
        for name in [
            "MAVEN_OPTS",
            "MAVEN_DEBUG_OPTS",
            "_JAVA_OPTIONS",
            "JAVA_TOOL_OPTIONS",
            "JDK_JAVA_OPTIONS",
        ] {
            let value = OsString::from_vec(bytes.to_vec());
            let shell = Shell::for_testing_env(vec![(OsString::from(name), value)]);
            let host = Host {
                shell,
                jdk: JDK_21,
                working_dir: Path::new("/"),
            };
            let none = CommandLine::default();
            let options = crate::jvm_options::read(None, &host).unwrap();
            let got = user_home_define(&options, &none, &none).map_err(|error| {
                assert!(error.to_string().contains(name), "{error}");
            });
            assert_eq!(got, expected, "{name}");
        }
    }
}

/// A5 and B4: what a mavenrc sets is read as `/bin/sh` leaves it.
#[cfg(unix)]
#[test]
fn mavenrc_assignments_are_followed() {
    let inherited = [("MAVEN_OPTS", "-Duser.home=/o"), ("H", "/h")];
    for (rc, expected) in [
        // B4
        ("MAVEN_OPTS=\"$MAVEN_OPTS -Xmx64m\"", Some("/o")),
        ("export MAVEN_OPTS=\"${MAVEN_OPTS} -Xmx64m\"", Some("/o")),
        ("MAVEN_OPTS=\"-Duser.h${NOPE}ome=$H/b\"", Some("/h/b")),
        ("MAVEN_OPTS='-Duser.home=$H'", Some("$H")),
        ("X=-Duser.home=/x; MAVEN_OPTS=$X", Some("/x")),
        ("unset MAVEN_OPTS", None),
        (
            "export JAVA_HOME=$(/usr/libexec/java_home -v 17)\n# note",
            Some("/o"),
        ),
        (
            "JAVA_HOME=`/usr/libexec/java_home`; export JAVA_HOME",
            Some("/o"),
        ),
        (
            "if [ -z \"$JAVA_HOME\" ]; then\n  JAVA_HOME=/opt/jdk\nfi",
            Some("/o"),
        ),
        (
            "if [ \"$(uname)\" = Darwin ]; then\n  export JAVA_HOME=$(/usr/libexec/java_home)\nfi",
            Some("/o"),
        ),
        ("MAVEN_OPTS=\"${MAVEN_OPTS:-} -Xmx64m\"", Some("/o")),
        // Not exported, so the JVM does not see it.
        ("JAVA_TOOL_OPTIONS=-Duser.home=/t", Some("/o")),
        ("export JAVA_TOOL_OPTIONS=-Duser.home=/t", Some("/o")),
        ("export _JAVA_OPTIONS=-Duser.home=/j", Some("/j")),
    ] {
        assert_eq!(
            define(&inherited, None, &[], JDK_21, &[rc]),
            Ok(expected.map(str::to_string)),
            "{rc}"
        );
    }
    // Shapes the old reader of the files refused.
    for (rc, expected) in [
        ("[ -n \"$CI\" ] && MAVEN_OPTS=-Duser.home=/c", Some("/o")),
        ("eval \"MAVEN_OPTS=-Duser.home=/e\"", Some("/e")),
        ("MAVEN_OPTS=\"-Xmx1g\n -Duser.home=/x\"", Some("/x")),
        ("export A=/a MAVEN_OPTS=\"-Duser.home=x$A\"", Some("x")),
        ("umask 022\nMAVEN_OPTS=-Xmx1g", None),
    ] {
        assert_eq!(
            define(&inherited, None, &[], JDK_21, &[rc]),
            Ok(expected.map(str::to_string)),
            "{rc}"
        );
    }
    // `mvn` splits at the `IFS` the files leave, which raeva does not.
    let error = define(&inherited, None, &[], JDK_21, &["IFS=:"]).unwrap_err();
    assert!(error.contains(".mavenrc"), "{error}");
}
