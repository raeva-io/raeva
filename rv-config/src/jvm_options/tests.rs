use std::path::Path;

use super::*;
use crate::paths::LauncherJdk;

const JDK_21: LauncherJdk = LauncherJdk {
    feature: Some(21),
    openj9: false,
};

fn read_with(vars: &[(&str, &str)], jvm_config: Option<&str>, dir: &Path) -> JvmOptions {
    let host = Host {
        shell: crate::user_home::Shell::for_testing(&[], vars, vars, &[]),
        jdk: JDK_21,
        working_dir: dir,
    };
    read(jvm_config, &host).expect("the options read")
}

fn value(options: &JvmOptions, name: &str) -> Option<String> {
    (options.properties())
        .find(|(found, _, _)| *found == name)
        .map(|(_, value, channel)| format!("{value} from {channel}"))
}

/// Every `-D` reads as the JVM takes it: `JAVA_TOOL_OPTIONS`, then
/// `JDK_JAVA_OPTIONS`, `.mvn/jvm.config`, `MAVEN_OPTS`, `MAVEN_DEBUG_OPTS`
/// and `_JAVA_OPTIONS`, the last winning; the JVM splits its variables at
/// C white space, `mvn` its own at `IFS` only.
#[test]
fn the_last_channel_the_jvm_reads_wins() {
    let dir = Path::new("/");
    let options = read_with(
        &[
            ("JAVA_TOOL_OPTIONS", "-Da=tool -Db=tool"),
            ("MAVEN_OPTS", "-Da=opts -Dc"),
        ],
        Some("-Da=config -Db=config"),
        dir,
    );
    assert_eq!(
        value(&options, "a").as_deref(),
        Some("opts from MAVEN_OPTS")
    );
    assert_eq!(
        value(&options, "b").as_deref(),
        Some("config from .mvn/jvm.config")
    );
    assert_eq!(value(&options, "c").as_deref(), Some(" from MAVEN_OPTS"));
    let options = read_with(
        &[
            ("_JAVA_OPTIONS", "-Da=1\x0b-Db=2"),
            ("MAVEN_OPTS", "-Dv=1\x0b-Dw=2"),
        ],
        None,
        dir,
    );
    assert_eq!(
        value(&options, "b").as_deref(),
        Some("2 from _JAVA_OPTIONS")
    );
    assert_eq!(
        value(&options, "v").as_deref(),
        Some("1\x0b-Dw=2 from MAVEN_OPTS")
    );
}

/// Quotes and option files read as the JVM reads them; a pattern the shell
/// may expand marks only the name it sets, until a later channel sets one
/// exactly.
#[test]
fn an_unread_channel_marks_the_names_it_may_set() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("args"), "-Dfile=1 -Xmx1g\n").unwrap();
    std::fs::write(dir.path().join("quoted"), "# note\n-Dq=\"a b\"\n").unwrap();
    std::fs::write(dir.path().join("vm"), "-Dvm=1 \"-Dw=a b\"\n").unwrap();
    let options = read_with(
        &[
            ("JAVA_TOOL_OPTIONS", "-Dx='a b' -Dy=1"),
            ("MAVEN_OPTS", "-Dy=2 @args @quoted -Dz=* -Dlater=*"),
            ("JDK_JAVA_OPTIONS", "\"-Dl=a b\" @args"),
            ("_JAVA_OPTIONS", "-XX:VMOptionsFile=vm -Dlater=3"),
        ],
        None,
        dir.path(),
    );
    let read = |name| value(&options, name);
    assert_eq!(read("x").as_deref(), Some("a b from JAVA_TOOL_OPTIONS"));
    assert_eq!(read("y").as_deref(), Some("2 from MAVEN_OPTS"));
    assert_eq!(read("file").as_deref(), Some("1 from MAVEN_OPTS"));
    assert_eq!(read("l").as_deref(), Some("a b from JDK_JAVA_OPTIONS"));
    assert_eq!(read("q").as_deref(), Some("a b from MAVEN_OPTS"));
    assert_eq!(read("w").as_deref(), Some("a b from _JAVA_OPTIONS"));
    assert_eq!(read("later").as_deref(), Some("3 from _JAVA_OPTIONS"));
    // `mvn.cmd` does not glob, and the JVM keeps a `*` of a `-D` as written
    // (measured with mvn.cmd 3.9.12 on JDK 17).
    match cfg!(windows) {
        true => assert_eq!(read("z").as_deref(), Some("* from MAVEN_OPTS")),
        false => assert!((options.unread("z")).is_some_and(|why| why.contains("MAVEN_OPTS"))),
    }
    assert_eq!(options.unread("y"), None);
    assert_eq!(options.unread("other"), None);
}

/// What raeva stops reading refuses where it may name an option file,
/// whose options could set any name: a pattern the shell may expand to one,
/// `JDK_JAVA_OPTIONS` for a JDK raeva cannot tell, an OpenJ9 variable; and
/// so do an option file that cannot be read or is not a regular file, a
/// quote the JVM finds open, and a VM options file that names another.
#[test]
fn a_skipped_option_file_refuses() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("inner"), "-XX:VMOptionsFile=other\n").unwrap();
    std::fs::write(dir.path().join("v"), "-Dv=1\n").unwrap();
    let refuses = |vars: &[(&str, &str)], jdk: LauncherJdk, why: &str| {
        let host = Host {
            shell: crate::user_home::Shell::for_testing(&[], vars, vars, &[]),
            jdk,
            working_dir: dir.path(),
        };
        let error = read(None, &host).unwrap_err().to_string();
        assert!(error.contains(why), "{vars:?}: {error}");
    };
    let unknown = LauncherJdk {
        feature: None,
        openj9: false,
    };
    let openj9 = LauncherJdk {
        feature: Some(21),
        openj9: true,
    };
    if cfg!(windows) {
        // `mvn.cmd` does not glob: the JVM fails to open the file `*`, and
        // `-D*` sets the property `*`.
        refuses(&[("MAVEN_OPTS", "@*")], JDK_21, "* cannot be read");
        let options = read_with(&[("MAVEN_OPTS", "-D*")], None, dir.path());
        assert_eq!(value(&options, "*").as_deref(), Some(" from MAVEN_OPTS"));
        assert_eq!(options.unread("*"), None);
    } else {
        refuses(&[("MAVEN_OPTS", "@*")], JDK_21, "pattern");
        refuses(&[("MAVEN_OPTS", "-D*")], JDK_21, "pattern");
    }
    refuses(
        &[("JDK_JAVA_OPTIONS", "\"@f\"")],
        unknown,
        "names an option file",
    );
    refuses(
        &[("JAVA_TOOL_OPTIONS", "-XX:VMOptionsFile=v")],
        openj9,
        "option file",
    );
    refuses(&[("MAVEN_OPTS", "@missing")], JDK_21, "cannot be read");
    refuses(&[("MAVEN_OPTS", "@.")], JDK_21, "not a regular file");
    refuses(&[("_JAVA_OPTIONS", "-Dq='open")], JDK_21, "does not close");
    refuses(
        &[("_JAVA_OPTIONS", "-XX:VMOptionsFile=inner")],
        JDK_21,
        "VM options file",
    );
    // A pattern whose words can set no option raeva reads passes.
    let options = read_with(&[("MAVEN_OPTS", "-Xlog:gc* -Dn=1")], None, dir.path());
    assert_eq!(value(&options, "n").as_deref(), Some("1 from MAVEN_OPTS"));
}

/// The words of an argument file and of a JVM variable, as measured with
/// `java @file` and the variables on JDK 17, 21 and 27.
#[test]
fn option_words_split_as_the_java_launcher_and_hotspot_split_them() {
    let words = |words: Vec<Vec<u8>>| -> Vec<String> {
        (words.into_iter())
            .map(|word| String::from_utf8(word).unwrap())
            .collect()
    };
    let file = "-Da=x#y -Db=1\n -De=1#2 -Df='s t'\"u\"\n -Ds='s t'\"u\"\n-Dg=\"a'b\" -Dh=x\"y #z\"w\n\
                -Di=\"ab\\\n   cd\" -Dj=\x0bk -Dk=\"#\" \"-Dl\" -Dm=1\x0c-Dn=2\r-Do=3 #c\n\
                -Dp=\"p\\nq\\\\u\\\"v\\x\" -Dd=o\\np\n-Dq=\"x\n-Dr=y\"";
    assert_eq!(
        words(argument_file_words(file.as_bytes())),
        [
            "-Da=x",
            "-De=1",
            "-Ds=s tu",
            "-Dg=a'b",
            "-Dh=xy #zw",
            "-Di=abcd",
            "-Dj=\x0bk",
            "-Dk=#",
            "-Dl",
            "-Dm=1",
            "-Dn=2",
            "-Do=3",
            "-Dp=p\nq\\u\"vx",
            "-Dd=o\\np",
            "-Dq=x",
            "-Dr=y",
        ]
    );
    let variable = "-Da=x\"y z\"w '-Db=1 2' -Dc=p\\q -Dd=#e -De=\"\"\x0b-Df=1\r-Dg";
    assert_eq!(
        words(jvm_words(variable.as_bytes()).unwrap()),
        [
            "-Da=xy zw",
            "-Db=1 2",
            "-Dc=p\\q",
            "-Dd=#e",
            "-De=",
            "-Df=1",
            "-Dg"
        ]
    );
    assert_eq!(jvm_words(b"-Da=\"open"), None);
}

/// `.mvn/jvm.config`'s own `-D` values, split as the shell splits `mvn`'s
/// unquoted `$MAVEN_OPTS`, the last of a name winning, stay whatever a
/// later channel sets; a pattern the shell may glob is kept as written.
#[test]
fn jvm_config_keeps_its_own_values() {
    let dir = tempfile::tempdir().unwrap();
    let options = read_with(
        &[("MAVEN_OPTS", "-Dvalue=opts")],
        Some(
            "-Xmx256m\n-Dflag -Dempty=\t-Dvalue=one=two\r\n-Dsplit=one=two -Dvalue=last -ea -Dglob=*.jar",
        ),
        dir.path(),
    );
    let own: Vec<(&str, &str)> = (options.jvm_config().iter())
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<std::collections::BTreeMap<_, _>>()
        .into_iter()
        .collect();
    assert_eq!(
        own,
        [
            ("empty", ""),
            ("flag", ""),
            ("glob", "*.jar"),
            ("split", "one=two"),
            ("value", "last"),
        ]
    );
    assert_eq!(
        value(&options, "value").as_deref(),
        Some("opts from MAVEN_OPTS")
    );
}

/// A2: the shell splits `mvn`'s unquoted `$MAVEN_OPTS` at space, tab and
/// newline only, so a no-break space, an ideographic space, a vertical tab
/// or a form feed stays in a `.mvn/jvm.config` value.
#[test]
fn jvm_config_values_keep_other_white_space() {
    let dir = tempfile::tempdir().unwrap();
    for space in ["\u{a0}", "\u{3000}", "\x0b", "\x0c"] {
        let text = format!("-Duser.home=/h{space}x -Dz=1");
        let options = read_with(&[], Some(&text), dir.path());
        assert_eq!(
            options.jvm_config()["user.home"],
            format!("/h{space}x"),
            "{space:?}"
        );
        assert_eq!(options.jvm_config()["z"], "1");
    }
}

/// The argument and VM options files `.mvn/jvm.config` names give its own
/// values too, as the java launcher and HotSpot read them.
#[test]
fn jvm_config_takes_the_option_files_it_names() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("opts"),
        "-Da=\"from file\"\n-XX:VMOptionsFile=vm\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("vm"), "-Db=vm").unwrap();
    let options = read_with(&[("JDK_JAVA_OPTIONS", "-Dd=4")], Some("@opts"), dir.path());
    let own = options.jvm_config();
    assert_eq!(own.get("a").map(String::as_str), Some("from file"));
    assert_eq!(own.get("b").map(String::as_str), Some("vm"));
    assert_eq!(own.get("d"), None);
}
