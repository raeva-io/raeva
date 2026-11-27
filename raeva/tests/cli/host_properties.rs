//! The JVM system properties Maven 3.9.12 and 3.10.0 see: those the JVM,
//! `mvn` and `MavenCli` set, as profile activation, settings.xml
//! interpolation and `-D`/`-P` expansion read them. raeva expands the ones
//! it answers and records them, and refuses the ones it does not read with
//! exit 3 wherever they decide the lock.

use std::fs;
use std::path::Path;

use crate::common::{assert_status, assert_success};
use crate::offline_project::Project;

const MODES: [&str; 2] = ["3.9", "3.10"];

/// A profile `id` with `activation` that adds `org.test:{artifact}:1.0`.
fn profile(id: &str, activation: &str, artifact: &str) -> String {
    format!(
        "<profile><id>{id}</id><activation>{activation}</activation><dependencies><dependency>\
         <groupId>org.test</groupId><artifactId>{artifact}</artifactId><version>1.0</version>\
         </dependency></dependencies></profile>"
    )
}

/// The project POM with `profiles` and `extra`, reading its own repository.
fn pom(profiles: &str, extra: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>project-local</id><url>file://${{project.basedir}}/repository/</url></repository>\
         </repositories>{extra}<profiles>{profiles}</profiles></project>"
    )
}

/// A project with `org.test:p1:1.0` to `p4` published and `pom` written.
fn project(pom_text: &str) -> Project {
    let project = Project::with(&[]);
    for artifact in ["p1", "p2", "p3", "p4"] {
        project.publish(&format!("org.test:{artifact}:1.0"), "");
    }
    fs::write(project.root().join("pom.xml"), pom_text).unwrap();
    project
}

fn set_mode(root: &Path, mode: &str) {
    fs::write(
        root.join("raeva.toml"),
        format!("[lock]\nmaven = \"{mode}\"\n"),
    )
    .unwrap();
    let _ = fs::remove_file(root.join("raeva.lock"));
}

/// The artifact ids the first platform of raeva.lock holds, sorted.
fn locked(root: &Path) -> Vec<String> {
    let text = fs::read_to_string(root.join("raeva.lock")).expect("read lock");
    let lock: toml::Value = toml::from_str(&text).expect("parse lock");
    let mut ids: Vec<String> = (lock["platforms"][0]["artifacts"].as_array())
        .into_iter()
        .flatten()
        .map(|row| row["coordinate"]["artifact"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A JDK `version` below `jdks`, with an empty `java` and a `release` file
/// naming the version. Returns its home.
fn fake_jdk(jdks: &Path, version: &str) -> String {
    let home = jdks.join(version);
    let bin = home.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let java = bin.join(if cfg!(windows) { "java.exe" } else { "java" });
    fs::write(&java, "").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&java, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(
        home.join("release"),
        format!("JAVA_VERSION=\"{version}\"\n"),
    )
    .unwrap();
    home.to_str().unwrap().to_string()
}

/// Maven 3.10.0's `bin/mvn` and `mvn.cmd` pass `-Dlibrary.jline.path=
/// $MAVEN_HOME/lib/jline-native` and
/// `-Dorg.jline.terminal.exec.redirectPipeCreationMode=native,reflection`;
/// 3.9.12's pass neither. A presence test and the constant value hold in
/// the 3.10 mode, a path that reads the Maven home refuses, as
/// `${maven.home}` does, and a dependency POM's own value loses to the
/// launcher's, which always ends in `lib/jline-native`.
#[test]
fn the_maven_310_launcher_sets_the_jline_properties() {
    let profiles = profile(
        "presence",
        "<property><name>library.jline.path</name></property>",
        "p1",
    ) + &profile(
        "value",
        "<property><name>org.jline.terminal.exec.redirectPipeCreationMode</name>\
         <value>native,reflection</value></property>",
        "p2",
    );
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>dep</artifactId><version>1.0</version></dependency>\
                      </dependencies>";
    let project = project(&pom(&profiles, dependency));
    let root = project.root();
    project.publish(
        "org.test:dep:1.0",
        &format!(
            "<properties><library.jline.path>own</library.jline.path></properties><profiles>{}\
             </profiles>",
            profile(
                "own",
                "<property><name>library.jline.path</name><value>own</value></property>",
                "p3"
            )
        ),
    );
    for mode in MODES {
        set_mode(&root, mode);
        assert_success(&project.raeva(&["sync", "--offline"]), mode);
        let expected: &[&str] = match mode {
            "3.9" => &["dep"],
            _ => &["dep", "p1", "p2"],
        };
        assert_eq!(locked(&root), expected, "{mode}");
        assert_success(&project.raeva(&["sync", "--frozen", "--offline"]), mode);
    }
    let file = profile(
        "file",
        "<file><exists>${library.jline.path}</exists></file>",
        "p4",
    );
    fs::write(root.join("pom.xml"), pom(&file, "")).unwrap();
    set_mode(&root, "3.9");
    assert_success(&project.raeva(&["sync", "--offline"]), "3.9 file");
    assert_eq!(locked(&root), Vec::<String>::new());
    set_mode(&root, "3.10");
    let output = project.raeva(&["sync", "--offline"]);
    assert_status(&output, 3, "3.10 file");
    assert!(
        stderr(&output).contains("depends on library.jline.path, which raeva does not read"),
        "{}",
        stderr(&output)
    );
}

/// `MavenCli.populateProperties` sets `maven.version` and
/// `maven.build.version` over a `.mvn/jvm.config` value, so the JVM option
/// changes nothing; a command-line `-D` still wins, as a user property.
#[test]
fn jvm_config_cannot_set_the_maven_version() {
    let profiles = profile(
        "version",
        "<property><name>maven.version</name><value>V</value></property>",
        "p1",
    ) + &profile(
        "build",
        "<property><name>maven.build.version</name><value>W</value></property>",
        "p2",
    );
    let project = project(&pom(&profiles, ""));
    let root = project.root();
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join(".mvn/jvm.config"),
        "-Dmaven.version=V -Dmaven.build.version=W\n",
    )
    .unwrap();
    for mode in MODES {
        set_mode(&root, mode);
        assert_success(&project.raeva(&["sync", "--offline"]), mode);
        assert_eq!(locked(&root), Vec::<String>::new(), "{mode} jvm.config");
        let defines = [
            "sync",
            "--offline",
            "-Dmaven.version=V",
            "-Dmaven.build.version=W",
        ];
        assert_success(&project.raeva(&defines), mode);
        assert_eq!(locked(&root), ["p1", "p2"], "{mode} -D");
    }
}

/// `MavenCli` expands a `-D` value against every system property. A value
/// that takes one raeva does not read, such as `${java.vendor}`, refuses
/// once a profile compares it, alone or beside an `activeByDefault`
/// profile it would turn off, and a presence test still holds.
#[test]
fn a_define_that_takes_an_unread_jvm_property_refuses_where_it_decides() {
    let compared = profile(
        "x",
        "<property><name>x</name><value>Arch Linux</value></property>",
        "p1",
    );
    let fallback = profile("d", "<activeByDefault>true</activeByDefault>", "p2");
    let present = profile("x", "<property><name>x</name></property>", "p1");
    let project = project(&pom(&compared, ""));
    let root = project.root();
    let vendor = ["sync", "--offline", "-Dx=${java.vendor}"];
    for mode in MODES {
        for (case, profiles) in [
            ("compared", compared.clone()),
            ("beside a default", compared.clone() + &fallback),
        ] {
            fs::write(root.join("pom.xml"), pom(&profiles, "")).unwrap();
            set_mode(&root, mode);
            let output = project.raeva(&vendor);
            assert_status(&output, 3, &format!("{mode} {case}"));
            assert!(
                stderr(&output).contains("depends on java.vendor, which raeva does not read"),
                "{mode} {case}: {}",
                stderr(&output)
            );
            let set = [&vendor[..], &["-Djava.vendor=Arch Linux"]].concat();
            assert_success(&project.raeva(&set), &format!("{mode} {case} -D"));
            assert_eq!(locked(&root), ["p1"], "{mode} {case} -D");
        }
        fs::write(root.join("pom.xml"), pom(&present, "")).unwrap();
        set_mode(&root, mode);
        assert_success(&project.raeva(&vendor), mode);
        assert_eq!(locked(&root), ["p1"], "{mode} presence");
        fs::create_dir_all(root.join(".mvn")).unwrap();
        fs::write(root.join(".mvn/maven.config"), "-Dx=${user.name}\n").unwrap();
        fs::write(root.join("pom.xml"), pom(&compared, "")).unwrap();
        set_mode(&root, mode);
        let output = project.raeva(&["sync", "--offline"]);
        assert_status(&output, 3, &format!("{mode} maven.config"));
        assert!(
            stderr(&output).contains("depends on user.name"),
            "{}",
            stderr(&output)
        );
        fs::remove_file(root.join(".mvn/maven.config")).unwrap();
    }
}

/// A `-D` value that takes `${java.home}` or `${java.version}` takes the
/// JDK's, which raeva.lock records without the path: another JDK makes
/// `--frozen` exit 7 and a plain sync follows it. A `-P` value expands
/// too, and one that takes a property raeva does not read refuses.
#[test]
fn a_define_or_profile_option_takes_the_jdk() {
    let project = Project::with(&[]);
    let root = project.root();
    let jdks = root.parent().unwrap().join("jdks");
    let (jdk21, jdk17) = (fake_jdk(&jdks, "21"), fake_jdk(&jdks, "17"));
    for artifact in ["p1", "p2", "p3"] {
        project.publish(&format!("org.test:{artifact}:1.0"), "");
    }
    let profiles = profile(
        "home",
        &format!("<property><name>x</name><value>{jdk21}</value></property>"),
        "p1",
    ) + &profile(
        "j-21",
        "<property><name>nothing.sets.this</name></property>",
        "p2",
    );
    fs::write(root.join("pom.xml"), pom(&profiles, "")).unwrap();
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join(".mvn/maven.config"),
        "-Dx=${java.home}\n-Pj-${java.specification.version}\n",
    )
    .unwrap();
    let on = |jdk: &str| [("JAVA_HOME", jdk.to_string())];
    let run = |jdk: &str, args: &[&str]| {
        let env = on(jdk);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        project.raeva_with(&env, args)
    };
    let frozen = ["sync", "--frozen", "--offline"];
    for mode in MODES {
        set_mode(&root, mode);
        assert_success(&run(&jdk21, &["sync", "--offline"]), mode);
        assert_eq!(locked(&root), ["p1", "p2"], "{mode} JDK 21");
        let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(!text.contains(&*jdks.to_string_lossy()), "{text}");
        assert_success(&run(&jdk21, &frozen), mode);
        assert_status(&run(&jdk17, &frozen), 7, mode);
        assert_success(&run(&jdk17, &["sync", "--offline"]), mode);
        assert_eq!(locked(&root), Vec::<String>::new(), "{mode} JDK 17");
        assert_success(&run(&jdk17, &frozen), mode);
        let user = ["sync", "--offline", "-Pp-${user.name}"];
        let output = run(&jdk21, &user);
        assert_status(&output, 3, &format!("{mode} -P"));
        assert!(stderr(&output).contains("user.name"), "{}", stderr(&output));
    }
}

/// Maven's settings builder interpolates settings.xml with every system
/// property. A profile property or activation value that takes one raeva
/// answers holds the target platform's or the JDK's value, and raeva.lock
/// records it; one that takes a property raeva does not read refuses where
/// a profile compares it, and so does an `<activeProfile>` naming one.
#[test]
fn settings_xml_takes_the_jvm_properties() {
    let project = Project::with(&[]);
    let root = project.root();
    let jdks = root.parent().unwrap().join("jdks");
    let (jdk21, jdk17) = (fake_jdk(&jdks, "21"), fake_jdk(&jdks, "17"));
    for artifact in ["p1", "p2", "p3"] {
        project.publish(&format!("org.test:{artifact}:1.0"), "");
    }
    let settings = |profiles: &str, active: &str| {
        fs::write(
            project.m2_settings(),
            format!(
                "<settings><profiles>{profiles}</profiles><activeProfiles>{active}\
                 </activeProfiles></settings>"
            ),
        )
        .unwrap();
    };
    let run = |jdk: &str, args: &[&str]| project.raeva_with(&[("JAVA_HOME", jdk)], args);
    let profiles = profile(
        "os",
        "<property><name>sv</name><value>Linux</value></property>",
        "p1",
    ) + &profile(
        "jdk",
        "<property><name>sj</name><value>21</value></property>",
        "p2",
    ) + &profile("act", "<property><name>sa</name></property>", "p3");
    fs::write(root.join("pom.xml"), pom(&profiles, "")).unwrap();
    settings(
        "<profile><id>sp</id><properties><sv>${os.name}</sv><sj>${java.version}</sj>\
         </properties></profile><profile><id>sq</id><activation><property><name>xq</name>\
         <value>${java.version}</value></property></activation><properties><sa>1</sa>\
         </properties></profile>",
        "<activeProfile>sp</activeProfile>",
    );
    let linux = [
        "sync",
        "--offline",
        "--platforms",
        "linux-x86_64",
        "-Dxq=21",
    ];
    let windows = [
        "sync",
        "--offline",
        "--platforms",
        "windows-x86_64",
        "-Dxq=21",
    ];
    let frozen = [&linux[..], &["--frozen"]].concat();
    for mode in MODES {
        // Each Windows release reports its own `os.name`.
        set_mode(&root, mode);
        let output = run(&jdk21, &windows);
        assert_status(&output, 3, mode);
        assert!(
            stderr(&output).contains("depends on os.name"),
            "{}",
            stderr(&output)
        );
        set_mode(&root, mode);
        assert_success(&run(&jdk21, &linux), mode);
        assert_eq!(locked(&root), ["p1", "p2", "p3"], "{mode} linux");
        assert_success(&run(&jdk21, &frozen), mode);
        assert_status(&run(&jdk17, &frozen), 7, mode);
        assert_success(&run(&jdk17, &linux), mode);
        assert_eq!(locked(&root), ["p1"], "{mode} JDK 17");
        assert_success(&run(&jdk17, &frozen), mode);
    }
    settings(
        "<profile><id>sp</id><properties><sv>${java.vendor}</sv></properties></profile>",
        "<activeProfile>sp</activeProfile>",
    );
    for mode in MODES {
        set_mode(&root, mode);
        let output = run(&jdk21, &linux);
        assert_status(&output, 3, mode);
        assert!(
            stderr(&output).contains("depends on java.vendor"),
            "{}",
            stderr(&output)
        );
    }
    settings("", "<activeProfile>p-${os.name}</activeProfile>");
    for mode in MODES {
        set_mode(&root, mode);
        let output = run(&jdk21, &linux);
        assert_status(&output, 3, mode);
        assert!(stderr(&output).contains("os.name"), "{}", stderr(&output));
    }
}

/// `MavenCli` expands a `-D` value before settings.xml reads it, so a
/// settings value that takes `${sep}` from `-Dsep=${file.separator}` holds
/// each locked platform's separator, and an `<activeProfile>` that takes an
/// unread property through one refuses as one that names it does. A
/// settings.xml condition that compares such a `-D` value refuses too.
#[test]
fn settings_xml_reads_a_define_of_a_jvm_property_per_platform() {
    let project = project(&pom(
        &(profile(
            "unix",
            "<property><name>sp</name><value>/</value></property>",
            "p1",
        ) + &profile(
            "windows",
            "<property><name>sp</name><value>\\</value></property>",
            "p2",
        ) + &profile("vm", "<property><name>sv</name></property>", "p3")),
        "",
    ));
    let root = project.root();
    let settings = |text: &str| fs::write(project.m2_settings(), text).unwrap();
    let sync = |platform: &str, define: &str| {
        project.raeva(&["sync", "--offline", "--platforms", platform, define])
    };
    settings(
        "<settings><profiles><profile><id>s</id><properties><sp>${sep}</sp></properties>\
         </profile></profiles><activeProfiles><activeProfile>s</activeProfile>\
         </activeProfiles></settings>",
    );
    for mode in MODES {
        for (platform, expected) in [("linux-x86_64", "p1"), ("windows-x86_64", "p2")] {
            set_mode(&root, mode);
            assert_success(&sync(platform, "-Dsep=${file.separator}"), mode);
            assert_eq!(locked(&root), [expected], "{mode} {platform}");
        }
    }
    settings(
        "<settings><activeProfiles><activeProfile>p-${x}</activeProfile></activeProfiles>\
         </settings>",
    );
    for mode in MODES {
        set_mode(&root, mode);
        let output = sync("linux-x86_64", "-Dx=${java.vendor}");
        assert_status(&output, 3, mode);
        assert!(
            stderr(&output).contains("java.vendor"),
            "{}",
            stderr(&output)
        );
    }
    settings(
        "<settings><profiles><profile><id>s</id><activation><property><name>x</name>\
         <value>OpenJDK 64-Bit Server VM</value></property></activation><properties>\
         <sv>1</sv></properties></profile></profiles></settings>",
    );
    for mode in MODES {
        set_mode(&root, mode);
        let output = sync("linux-x86_64", "-Dx=${java.vm.name}");
        assert_status(&output, 3, mode);
        assert!(
            stderr(&output).contains("depends on java.vm.name"),
            "{}",
            stderr(&output)
        );
    }
}

/// `MavenCli` expands the `-D` values with `.mvn/jvm.config`'s
/// `maven.version` and only then sets its own, which raeva does not follow,
/// so a `-D` value that takes it refuses unless a `-D` sets it.
#[test]
fn a_define_of_the_maven_version_jvm_config_sets_refuses() {
    let project = project(&pom(
        &profile(
            "v",
            "<property><name>x</name><value>V</value></property>",
            "p1",
        ),
        "",
    ));
    let root = project.root();
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/jvm.config"), "-Dmaven.version=V\n").unwrap();
    fs::write(root.join(".mvn/maven.config"), "-Dx=${maven.version}\n").unwrap();
    for mode in MODES {
        set_mode(&root, mode);
        let output = project.raeva(&["sync", "--offline"]);
        assert_status(&output, 3, mode);
        assert!(
            stderr(&output).contains("maven.version"),
            "{}",
            stderr(&output)
        );
        set_mode(&root, mode);
        assert_success(
            &project.raeva(&["sync", "--offline", "-Dmaven.version=V"]),
            mode,
        );
        assert_eq!(locked(&root), ["p1"], "{mode}");
    }
    // Through another jvm.config value, which the -D value expands.
    fs::write(
        root.join(".mvn/jvm.config"),
        "-Dmaven.version=V -Dalias=${maven.version}\n",
    )
    .unwrap();
    fs::write(root.join(".mvn/maven.config"), "-Dx=${alias}\n").unwrap();
    for mode in MODES {
        set_mode(&root, mode);
        let output = project.raeva(&["sync", "--offline"]);
        assert_status(&output, 3, mode);
        assert!(
            stderr(&output).contains("${maven.version} through ${alias}"),
            "{}",
            stderr(&output)
        );
    }
}

/// `MavenCli` expands `${maven.multiModuleProjectDirectory}` in a `-D`
/// value with a `-D` of that name, where it sets one, as any other system
/// property. settings.xml does not take `.mvn/jvm.config` values, but one
/// with a secret's name in a repository URL still refuses.
#[test]
fn a_define_sets_the_launcher_directory_values_expand() {
    let project = project(&pom(
        &profile(
            "over",
            "<property><name>x</name><value>/override</value></property>",
            "p1",
        ),
        "",
    ));
    let root = project.root();
    let args = [
        "--offline",
        "-Dmaven.multiModuleProjectDirectory=/override",
        "-Dx=${maven.multiModuleProjectDirectory}",
    ];
    for mode in MODES {
        set_mode(&root, mode);
        assert_success(&project.raeva(&[&["sync"][..], &args].concat()), mode);
        assert_eq!(locked(&root), ["p1"], "{mode}");
    }
    fs::create_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join(".mvn/jvm.config"), "-Drepo.token=s3cr3tvalue\n").unwrap();
    fs::write(
        project.m2_settings(),
        "<settings><profiles><profile><id>s</id><repositories><repository><id>jrepo</id>\
         <url>file:///srv/${repo.token}/</url></repository></repositories></profile>\
         </profiles><activeProfiles><activeProfile>s</activeProfile></activeProfiles>\
         </settings>",
    )
    .unwrap();
    for mode in MODES {
        set_mode(&root, mode);
        let output = project.raeva(&[&["sync"][..], &args].concat());
        assert_status(&output, 3, mode);
        assert!(
            !stderr(&output).contains("s3cr3tvalue"),
            "{}",
            stderr(&output)
        );
    }
}

/// A POM condition that compares the jline pipe mode with
/// `${org.jline.terminal.exec.redirectPipeCreationMode}` holds where 3.10's
/// `mvn` sets it, as Maven interpolates the value with it.
#[test]
fn activation_interpolates_the_jline_pipe_mode() {
    let name = "org.jline.terminal.exec.redirectPipeCreationMode";
    let project = project(&pom(
        &profile(
            "jline",
            &format!("<property><name>{name}</name><value>${{{name}}}</value></property>"),
            "p1",
        ),
        "",
    ));
    let root = project.root();
    for (mode, expected) in [("3.9", &[][..]), ("3.10", &["p1"][..])] {
        set_mode(&root, mode);
        assert_success(&project.raeva(&["sync", "--offline"]), mode);
        assert_eq!(locked(&root), expected, "{mode}");
    }
}

/// Exit 3 naming `name`, in both modes, for `project` as it stands.
fn refuses_in_both_modes(project: &Project, env: &[(&str, &str)], args: &[&str], name: &str) {
    for mode in MODES {
        set_mode(&project.root(), mode);
        let output = project.raeva_with(env, args);
        assert_status(&output, 3, &format!("{mode} {name}"));
        assert!(
            stderr(&output).contains(name),
            "{mode}: {}",
            stderr(&output)
        );
    }
}

/// Some JDKs keep their own value of `java.vendor.version` (Temurin) and
/// `java.specification.maintenance.version` (17) over a `.mvn/jvm.config`
/// `-D`, so a profile that tests one refuses. Another name's value stands.
#[test]
fn a_jvm_config_value_of_a_jvm_owned_name_refuses() {
    for name in [
        "java.vendor.version",
        "java.specification.maintenance.version",
    ] {
        let activation = format!("<property><name>{name}</name><value>V</value></property>");
        let project = project(&pom(&profile("p", &activation, "p1"), ""));
        fs::create_dir_all(project.root().join(".mvn")).unwrap();
        fs::write(
            project.root().join(".mvn/jvm.config"),
            format!("-D{name}=V\n"),
        )
        .unwrap();
        refuses_in_both_modes(&project, &[], &["sync", "--offline"], name);
    }
    {
        // Nor does a `-D` value that takes one expand to it.
        let activation = "<property><name>x</name><value>UTF-8</value></property>";
        let project = project(&pom(&profile("p", activation, "p1"), ""));
        fs::create_dir_all(project.root().join(".mvn")).unwrap();
        fs::write(
            project.root().join(".mvn/jvm.config"),
            "-Dfile.encoding=COMPAT\n",
        )
        .unwrap();
        fs::write(
            project.root().join(".mvn/maven.config"),
            "-Dx=${file.encoding}\n",
        )
        .unwrap();
        refuses_in_both_modes(&project, &[], &["sync", "--offline"], "file.encoding");
    }
    {
        // A command-line `-D` of the same value is the build's own, in a
        // dependency's model too.
        let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                          <artifactId>dep</artifactId><version>1.0</version></dependency>\
                          </dependencies>";
        let project = project(&pom("", dependency));
        project.publish(
            "org.test:dep:1.0",
            &format!(
                "<profiles>{}</profiles>",
                profile(
                    "en",
                    "<property><name>user.language</name><value>en</value></property>",
                    "p1"
                )
            ),
        );
        fs::create_dir_all(project.root().join(".mvn")).unwrap();
        fs::write(
            project.root().join(".mvn/jvm.config"),
            "-Duser.language=en\n",
        )
        .unwrap();
        for mode in MODES {
            set_mode(&project.root(), mode);
            let args = ["sync", "--offline", "-Duser.language=en"];
            assert_success(&project.raeva(&args), mode);
            assert_eq!(locked(&project.root()), ["dep", "p1"], "{mode}");
        }
    }
    {
        let activation = "<property><name>own</name><value>V</value></property>";
        let project = project(&pom(&profile("p", activation, "p1"), ""));
        fs::create_dir_all(project.root().join(".mvn")).unwrap();
        fs::write(project.root().join(".mvn/jvm.config"), "-Down=V\n").unwrap();
        for mode in MODES {
            set_mode(&project.root(), mode);
            assert_success(&project.raeva(&["sync", "--offline"]), mode);
            assert_eq!(locked(&project.root()), ["p1"], "{mode}");
        }
    }
}

/// Maven expands settings.xml with the `-D` values of `.mvn/maven.config`
/// and the command line, and then the `.mvn/jvm.config` ones, as raeva
/// does: each case locks what Maven 3.9.12 and 3.10.0 resolve. A
/// `.mvn/jvm.config` value of a name the JVM sets refuses, as some JDKs
/// keep their own.
#[test]
fn settings_xml_takes_the_project_defines_as_maven_does() {
    let property = |name: &str, value: &str| {
        format!("<property><name>{name}</name><value>{value}</value></property>")
    };
    let setting = "<profiles><profile><id>sp</id><properties><sv>${x}</sv></properties>\
                   </profile></profiles><activeProfiles><activeProfile>sp</activeProfile>\
                   </activeProfiles>";
    let activation = "<profiles><profile><id>sp</id><activation><property><name>q</name>\
                      <value>${x}</value></property></activation><properties><sv>V</sv>\
                      </properties></profile></profiles>";
    let marked = "<profiles><profile><id>sp</id><activation><file><exists>${project.basedir}/\
                  ${mark}</exists></file></activation><properties><sv>1</sv></properties>\
                  </profile></profiles>";
    // (case, POM activation, settings.xml, .mvn file, its -D, extra
    // argument, what Maven locks)
    type Case<'a> = (
        &'a str,
        String,
        &'a str,
        &'a str,
        &'a str,
        Option<&'a str>,
        &'a [&'a str],
    );
    let cases: [Case<'_>; 7] = [
        (
            "F8a",
            property("sv", "V"),
            setting,
            "maven.config",
            "-Dx=V",
            None,
            &["p1"],
        ),
        (
            "F8b",
            "<property><name>nope</name></property>".to_string(),
            "<activeProfiles><activeProfile>${x}</activeProfile></activeProfiles>",
            "maven.config",
            "-Dx=p",
            None,
            &["p1"],
        ),
        (
            "F8c",
            property("sv", "V"),
            activation,
            "maven.config",
            "-Dx=V",
            Some("-Dq=V"),
            &["p1"],
        ),
        (
            "F8d",
            property("sv", "V"),
            setting,
            "jvm.config",
            "-Dx=V",
            None,
            &["p1"],
        ),
        (
            "REG1y",
            property("sv", "1"),
            marked,
            "maven.config",
            "-Dmark=present",
            None,
            &["p1"],
        ),
        (
            "REG1n",
            property("sv", "1"),
            marked,
            "maven.config",
            "-Dmark=absent",
            None,
            &[],
        ),
        (
            "S-c",
            property("sv", "1"),
            marked,
            "maven.config",
            "",
            Some("-Dmark=present"),
            &["p1"],
        ),
    ];
    for (case, pom_activation, settings, file, define, extra, expected) in cases {
        let project = project(&pom(&profile("p", &pom_activation, "p1"), ""));
        fs::write(project.root().join("present"), "").unwrap();
        fs::write(
            project.m2_settings(),
            format!("<settings>{settings}</settings>"),
        )
        .unwrap();
        fs::create_dir_all(project.root().join(".mvn")).unwrap();
        fs::write(
            project.root().join(".mvn").join(file),
            format!("{define}\n"),
        )
        .unwrap();
        let mut args = vec!["sync", "--offline"];
        args.extend(extra);
        for mode in MODES {
            set_mode(&project.root(), mode);
            assert_success(&project.raeva(&args), &format!("{mode} {case}"));
            assert_eq!(locked(&project.root()), expected, "{mode} {case}");
        }
    }
    let project = project(&pom(&profile("p", &property("sv", "V"), "p1"), ""));
    fs::write(
        project.m2_settings(),
        format!(
            "<settings>{}</settings>",
            setting.replace("${x}", "${java.vendor.version}")
        ),
    )
    .unwrap();
    fs::create_dir_all(project.root().join(".mvn")).unwrap();
    fs::write(
        project.root().join(".mvn/jvm.config"),
        "-Djava.vendor.version=V\n",
    )
    .unwrap();
    refuses_in_both_modes(
        &project,
        &[],
        &["sync", "--offline"],
        "${java.vendor.version}",
    );
}

/// A Windows JVM sets `sun.cpu.isalist`, `sun.os.patch.level`,
/// `user.script` and `user.variant`, which a Linux one does not, and each
/// Windows release reports its own `os.name`, so a Windows lock refuses a
/// profile that reads one. `<os><family>` and `<arch>` hold on all of them.
#[test]
fn windows_only_jvm_names_and_the_windows_os_name_refuse() {
    let windows = ["sync", "--offline", "--platforms", "windows-x86_64"];
    for (activation, name) in [
        (
            "<property><name>sun.cpu.isalist</name></property>",
            "sun.cpu.isalist",
        ),
        (
            "<property><name>sun.cpu.isalist</name><value>amd64</value></property>",
            "sun.cpu.isalist",
        ),
        (
            "<file><missing>marker${sun.os.patch.level}</missing></file>",
            "sun.os.patch.level",
        ),
        (
            "<file><exists>marker${user.script}</exists></file>",
            "user.script",
        ),
        (
            "<property><name>user.variant</name><value>x</value></property>",
            "user.variant",
        ),
        (
            "<property><name>os.name</name><value>Windows 11</value></property>",
            "os.name",
        ),
        ("<os><name>Windows 10</name></os>", "os.name"),
    ] {
        let project = project(&pom(&profile("p", activation, "p1"), ""));
        fs::write(project.root().join("marker"), "").unwrap();
        refuses_in_both_modes(&project, &[], &windows, name);
    }
    // A test every Windows edition's `os.name` answers alike holds: Maven
    // locks p4 on Windows 10, 11 and Server.
    let profiles = profile("family", "<os><family>windows</family></os>", "p1")
        + &profile("arch", "<os><arch>amd64</arch></os>", "p2")
        + &profile("linux", "<os><name>Linux</name></os>", "p3")
        + &profile(
            "w7",
            "<file><missing>marker-${os.name}</missing></file>",
            "p4",
        );
    let project = project(&pom(&profiles, ""));
    fs::write(project.root().join("marker"), "").unwrap();
    for mode in MODES {
        set_mode(&project.root(), mode);
        assert_success(&project.raeva(&windows), mode);
        assert_eq!(locked(&project.root()), ["p1", "p2", "p4"], "{mode}");
        assert_success(
            &project.raeva(&[&windows[..], &["--frozen"]].concat()),
            mode,
        );
    }
    // Where one edition's file exists, the editions differ.
    fs::write(project.root().join("marker-Windows 10"), "").unwrap();
    refuses_in_both_modes(&project, &[], &windows, "os.name");
}

/// A `[lock] jdks` entry names a feature release: every 21.x host's
/// `java.version` is its own, so a test or a read of the full version
/// refuses, and one every 21.x answers alike holds, as
/// `java.specification.version` does. A `-D` of `java.version` decides it.
#[test]
fn a_jdks_entry_answers_only_what_every_patch_release_shares() {
    let property = |name: &str, value: &str| {
        format!("<property><name>{name}</name><value>{value}</value></property>")
    };
    let full = "21.0.13.0.3";
    let settings = "<settings><profiles><profile><id>sp</id><properties><sv>${java.version}\
                    </sv></properties></profile></profiles><activeProfiles><activeProfile>sp\
                    </activeProfile></activeProfiles></settings>";
    // (case, activation, settings.xml, extra argument)
    let cases: [(&str, String, &str, Option<&str>); 8] = [
        ("full", property("java.version", full), "<settings/>", None),
        ("short", property("java.version", "21"), "<settings/>", None),
        (
            "jdkpre",
            "<jdk>21.0.13</jdk>".to_string(),
            "<settings/>",
            None,
        ),
        ("setprop", property("sv", full), settings, None),
        (
            "define",
            property("x", full),
            "<settings/>",
            Some("-Dx=${java.version}"),
        ),
        (
            "between",
            "<jdk>[21.0.11,21.0.12]</jdk>".to_string(),
            "<settings/>",
            None,
        ),
        (
            "lz",
            "<jdk>[021.0.11,021.0.12]</jdk>".to_string(),
            "<settings/>",
            None,
        ),
        (
            "plus",
            "<jdk>[+21.0.11,+21.0.12]</jdk>".to_string(),
            "<settings/>",
            None,
        ),
    ];
    for (case, activation, settings, extra) in cases {
        let project = project(&pom(&profile("p", &activation, "p1"), ""));
        let jdk = fake_jdk(&project.root().parent().unwrap().join("jdks"), full);
        fs::write(project.m2_settings(), settings).unwrap();
        let mut args = vec!["sync", "--offline"];
        args.extend(extra);
        for mode in MODES {
            fs::write(
                project.root().join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\njdks = [\"21\"]\n"),
            )
            .unwrap();
            let output = project.raeva_with(&[("JAVA_HOME", &jdk)], &args);
            assert_status(&output, 3, &format!("{mode} {case}"));
            assert!(
                stderr(&output).contains("java.version"),
                "{case}: {}",
                stderr(&output)
            );
        }
    }
    let profiles = profile("feature", "<jdk>21</jdk>", "p1")
        + &profile("range", "<jdk>[17,22)</jdk>", "p2")
        + &profile("spec", &property("java.specification.version", "21"), "p3")
        + &profile("defined", "<jdk>21.0.13</jdk>", "p4");
    let project = project(&pom(&profiles, ""));
    let jdk = fake_jdk(&project.root().parent().unwrap().join("jdks"), full);
    for mode in MODES {
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\njdks = [\"21\"]\n"),
        )
        .unwrap();
        let args = ["sync", "--offline", "-Djava.version=21.0.13"];
        assert_success(&project.raeva_with(&[("JAVA_HOME", &jdk)], &args), mode);
        assert_eq!(locked(&project.root()), ["p1", "p2", "p3", "p4"], "{mode}");
        let output = project.raeva_with(&[("JAVA_HOME", &jdk)], &["sync", "--offline"]);
        assert_status(&output, 3, mode);
        fs::write(
            project.root().join("pom.xml"),
            pom(&profiles.replace("<jdk>21.0.13</jdk>", "<jdk>99</jdk>"), ""),
        )
        .unwrap();
        assert_success(
            &project.raeva_with(&[("JAVA_HOME", &jdk)], &["sync", "--offline"]),
            mode,
        );
        assert_eq!(locked(&project.root()), ["p1", "p2", "p3"], "{mode}");
        fs::write(project.root().join("pom.xml"), pom(&profiles, "")).unwrap();
    }
}

/// A dependency coordinate that reads a JVM property the lock does not fix
/// exits 3, naming it: the Windows `os.name`, and the full `java.version`
/// under `[lock] jdks`.
#[test]
fn a_coordinate_reading_an_unfixed_jvm_property_refuses() {
    let classifier = |text: &str| {
        format!(
            "<dependencies><dependency><groupId>org.test</groupId><artifactId>p1</artifactId>\
             <version>1.0</version><classifier>{text}</classifier></dependency></dependencies>"
        )
    };
    let windows_project = project(&pom("", &classifier("${os.name}")));
    let windows = ["sync", "--offline", "--platforms", "windows-x86_64"];
    refuses_in_both_modes(&windows_project, &[], &windows, "os.name");
    let project = project(&pom("", &classifier("${java.version}")));
    let jdk = fake_jdk(&project.root().parent().unwrap().join("jdks"), "21.0.13");
    for mode in MODES {
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\njdks = [\"21\"]\n"),
        )
        .unwrap();
        let output = project.raeva_with(&[("JAVA_HOME", &jdk)], &["sync", "--offline"]);
        assert_status(&output, 3, mode);
        assert!(
            stderr(&output).contains("java.version"),
            "{}",
            stderr(&output)
        );
    }
}

/// `${java.version}` in plugin configuration does not change the lock, so
/// it does not refuse, with or without `[lock] jdks`.
#[test]
fn jvm_reads_outside_the_lock_do_not_refuse() {
    let extra = "<build><plugins><plugin><groupId>org.apache.maven.plugins</groupId>\
                 <artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version>\
                 <configuration><release>${java.version}</release></configuration></plugin>\
                 </plugins></build>";
    let project = project(&pom("", extra));
    let jdk = fake_jdk(&project.root().parent().unwrap().join("jdks"), "21.0.13");
    for jdks in ["", "jdks = [\"21\"]\n"] {
        for mode in MODES {
            fs::write(
                project.root().join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n{jdks}"),
            )
            .unwrap();
            let _ = fs::remove_file(project.root().join("raeva.lock"));
            let output = project.raeva_with(&[("JAVA_HOME", &jdk)], &["sync", "--offline"]);
            assert_success(&output, &format!("{mode} {jdks}"));
        }
    }
}

/// raeva tells the names JVMs set from Maven runs on Linux, macOS and
/// Windows JDKs: one only some set, such as macOS' `http.nonProxyHosts` or
/// JDK 8's `awt.toolkit`, refuses; one every JVM sets alike is answered;
/// one none sets is unset, whatever namespace it is in.
#[test]
fn jvm_names_follow_the_measured_jvms() {
    for (activation, name) in [
        (
            "<property><name>http.nonProxyHosts</name></property>",
            "http.nonProxyHosts",
        ),
        (
            "<property><name>!socksNonProxyHosts</name></property>",
            "socksNonProxyHosts",
        ),
        (
            "<property><name>awt.toolkit</name><value>sun.awt.X11.XToolkit</value></property>",
            "awt.toolkit",
        ),
        (
            "<file><missing>${awt.toolkit}</missing></file>",
            "awt.toolkit",
        ),
        (
            "<property><name>sun.stdout.encoding</name></property>",
            "sun.stdout.encoding",
        ),
    ] {
        let project = project(&pom(&profile("p", activation, "p1"), ""));
        refuses_in_both_modes(&project, &[], &["sync", "--offline"], name);
    }
    let profiles = profile(
        "spec",
        "<property><name>java.specification.vendor</name><value>Oracle Corporation</value>\
         </property>",
        "p1",
    ) + &profile(
        "jdkversion",
        "<property><name>jdk.version</name></property>",
        "p2",
    ) + &profile(
        "javafoo",
        "<property><name>!java.foo</name></property>",
        "p3",
    );
    let project = project(&pom(&profiles, ""));
    for mode in MODES {
        set_mode(&project.root(), mode);
        assert_success(&project.raeva(&["sync", "--offline"]), mode);
        assert_eq!(locked(&project.root()), ["p1", "p3"], "{mode}");
    }
}

/// Every update of JDK 8 reports a `java.version` starting `1.8.0`, so a
/// `1.8` entry answers `<jdk>1.8.0</jdk>` and refuses nothing it decides.
#[test]
fn a_jdk_8_entry_answers_its_update_prefix() {
    let profiles = profile("pre", "<jdk>1.8.0</jdk>", "p1")
        + &profile(
            "eq",
            "<property><name>java.version</name><value>1.8</value></property>",
            "p2",
        )
        + &profile("open", "<jdk>(1.8.0,1.9)</jdk>", "p3");
    let project = project(&pom(&profiles, ""));
    for mode in MODES {
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\njdks = [\"1.8\"]\n"),
        )
        .unwrap();
        assert_success(&project.raeva(&["sync", "--offline"]), mode);
        assert_eq!(locked(&project.root()), ["p1"], "{mode}");
    }
}

/// raeva knows the host JDK's `java.home` and `JAVA_HOME`, not another's:
/// under `[lock] jdks` a path that takes either refuses unless the lock
/// lists the host's JDK alone, even with `JAVA_HOME` in
/// `allow_env_substitution`, which 0.6.0 read for every JDK.
#[test]
fn java_home_under_jdks_is_the_hosts_only_for_its_own_jdk() {
    let config = |allowed: bool| match allowed {
        true => "[security]\nallow_env_substitution = [\"JAVA_HOME\"]\n",
        false => "",
    };
    for (home, allowed) in [
        ("${java.home}/..", false),
        ("${env.JAVA_HOME}", false),
        ("${env.JAVA_HOME}", true),
    ] {
        let activation = format!("<file><missing>{home}/lib/tools.jar</missing></file>");
        let project = project(&pom(&profile("p", &activation, "p1"), ""));
        let jdk = fake_jdk(&project.root().parent().unwrap().join("jdks"), "21.0.13");
        fs::write(project.raeva_home().join("config.toml"), config(allowed)).unwrap();
        for mode in MODES {
            for (jdks, refused) in [
                ("\"21\"", false),
                ("\"1.8\"", true),
                ("\"17\", \"21\"", true),
            ] {
                fs::write(
                    project.root().join("raeva.toml"),
                    format!("[lock]\nmaven = \"{mode}\"\njdks = [{jdks}]\n"),
                )
                .unwrap();
                let output = project.raeva_with(&[("JAVA_HOME", &jdk)], &["sync", "--offline"]);
                let case = format!("{home} {allowed} {mode} {jdks}");
                if refused {
                    assert_status(&output, 3, &case);
                    let said = stderr(&output);
                    assert!(said.contains("list that JDK alone"), "{case}: {said}");
                    assert!(!said.contains("allow_env_substitution"), "{case}: {said}");
                } else {
                    assert_success(&output, &case);
                    assert_eq!(locked(&project.root()), ["p1"], "{case}");
                }
            }
        }
    }
}

/// druid 1.2.7's `jconsole` profile tests `${env.JAVA_HOME}/lib/jconsole.jar`,
/// which `JAVA_HOME`, the JDK `mvn` runs, holds before JDK 9 and not after.
/// Maven 3.9.12 activates it by that file, and 3.10.0 never activates a
/// dependency's `<file>` profile, as Maven shows on OpenJDK 17 and 21 and on
/// a home with `lib/jconsole.jar`. Under `[lock] jdks` naming another JDK
/// that home is unknown in the 3.9 mode, as `java.home` is.
#[test]
fn a_dependency_jconsole_profile_reads_the_jdk_home() {
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>druid</artifactId><version>1.0</version></dependency>\
                      </dependencies>";
    let project = project(&pom("", dependency));
    let activation = "<file><exists>${env.JAVA_HOME}/lib/jconsole.jar</exists></file>";
    project.publish(
        "org.test:druid:1.0",
        &format!(
            "<profiles>{}</profiles>",
            profile("jconsole", activation, "p1")
        ),
    );
    let jdks = project.root().parent().unwrap().join("jdks");
    let modern = fake_jdk(&jdks, "21.0.13");
    let old = fake_jdk(&jdks, "1.8.0_442");
    fs::create_dir_all(Path::new(&old).join("lib")).unwrap();
    fs::write(Path::new(&old).join("lib/jconsole.jar"), "").unwrap();
    for (mode, home, locks) in [
        ("3.9", &modern, &["druid"][..]),
        ("3.9", &old, &["druid", "p1"]),
        ("3.10", &modern, &["druid"]),
        ("3.10", &old, &["druid"]),
    ] {
        set_mode(&project.root(), mode);
        let output = project.raeva_with(&[("JAVA_HOME", home)], &["sync", "--offline"]);
        assert_success(&output, &format!("{mode} {home}"));
        assert_eq!(locked(&project.root()), locks, "{mode} {home}");
    }
    // The lock records what the path tested, so a home of the same JDK
    // release that holds the file is a change.
    let other = jdks.join("other");
    copy_dir(Path::new(&modern), &other);
    fs::create_dir_all(other.join("lib")).unwrap();
    fs::write(other.join("lib/jconsole.jar"), "").unwrap();
    let sync = |home: &Path, args: &[&str]| {
        project.raeva_with(&[("JAVA_HOME", home.to_str().unwrap())], args)
    };
    set_mode(&project.root(), "3.9");
    assert_success(&sync(Path::new(&modern), &["sync", "--offline"]), "lock");
    let frozen = ["sync", "--offline", "--frozen"];
    assert_success(&sync(Path::new(&modern), &frozen), "frozen");
    assert_status(&sync(&other, &frozen), 7, "frozen with jconsole.jar");
    for (mode, refused) in [("3.9", true), ("3.10", false)] {
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\njdks = [\"17\"]\n"),
        )
        .unwrap();
        let output = sync(Path::new(&modern), &["sync", "--offline"]);
        if refused {
            assert_status(&output, 3, "3.9 jdks 17");
            assert!(
                stderr(&output).contains("env.JAVA_HOME"),
                "{}",
                stderr(&output)
            );
        } else {
            assert_success(&output, "3.10 jdks 17");
        }
    }
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A dependency's `${env.JAVA_HOME}` `<file>` path reads the JDK's home,
/// not the hidden variable, and the lock keeps what the path tested: with
/// `JAVA_HOME` set and not in `allow_env_substitution`, a second plain sync
/// finds the lock up to date without resolving, and a home where the path
/// holds changes the lock hash, so export-m2 and `--frozen` refuse the lock
/// and a plain sync resolves again.
#[test]
fn a_jdk_home_file_path_keeps_the_lock_up_to_date() {
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>druid</artifactId><version>1.0</version></dependency>\
                      </dependencies>";
    let project = project(&pom("", dependency));
    let activation = "<file><exists>${env.JAVA_HOME}/lib/jconsole.jar</exists></file>";
    project.publish(
        "org.test:druid:1.0",
        &format!(
            "<profiles>{}</profiles>",
            profile("jconsole", activation, "p1")
        ),
    );
    let jdks = project.root().parent().unwrap().join("jdks");
    let modern = fake_jdk(&jdks, "21.0.13");
    let old = fake_jdk(&jdks, "1.8.0_442");
    fs::create_dir_all(Path::new(&old).join("lib")).unwrap();
    fs::write(Path::new(&old).join("lib/jconsole.jar"), "").unwrap();
    set_mode(&project.root(), "3.9");
    let modern = [("JAVA_HOME", modern.as_str())];
    assert_success(&project.raeva_with(&modern, &["sync"]), "lock");
    let lock = fs::read_to_string(project.root().join("raeva.lock")).unwrap();
    assert!(lock.contains("\"user-property:env.JAVA_HOME\""), "{lock}");
    let output = project.raeva_with(&modern, &["sync"]);
    assert_success(&output, "second sync");
    let said = stderr(&output) + &String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains("Checked") && said.contains("up to date") && !said.contains("Resolved"),
        "{said}"
    );
    let old = [("JAVA_HOME", old.as_str())];
    let m2 = project.root().join("m2");
    let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
    for args in [&export[..], &["sync", "--frozen"]] {
        assert_status(&project.raeva_with(&old, args), 7, &format!("{args:?}"));
    }
    assert_success(&project.raeva_with(&old, &["sync"]), "jconsole.jar");
    assert_eq!(locked(&project.root()), ["druid", "p1"]);
}

/// A project whose dependency `org.test:druid:1.0` tests druid's
/// `${env.JAVA_HOME}/lib/jconsole.jar` (`p1`) and the legacy
/// `${java.home}/../lib/tools.jar` (`p2`), and whose own POM tests both too
/// (`p3` while jconsole.jar is missing, `p4` with tools.jar), since Maven
/// 3.10 tests only the project's `<file>` paths. Also returns where JDKs go.
fn jdk_home_paths_project() -> (Project, std::path::PathBuf) {
    let files = [
        ("exists", "${env.JAVA_HOME}/lib/jconsole.jar"),
        ("exists", "${java.home}/../lib/tools.jar"),
        ("missing", "${env.JAVA_HOME}/lib/jconsole.jar"),
        ("exists", "${java.home}/../lib/tools.jar"),
    ];
    let profiles: Vec<String> = (files.iter().enumerate())
        .map(|(index, (test, path))| {
            let id = format!("p{}", index + 1);
            profile(&id, &format!("<file><{test}>{path}</{test}></file>"), &id)
        })
        .collect();
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>druid</artifactId><version>1.0</version></dependency>\
                      </dependencies>";
    let project = project(&pom(&profiles[2..].concat(), dependency));
    let published = format!("<profiles>{}</profiles>", profiles[..2].concat());
    project.publish("org.test:druid:1.0", &published);
    let jdks = project.root().parent().unwrap().join("jdks");
    (project, jdks)
}

/// One JDK, named by `JAVA_HOME` on one host and found on `PATH` with
/// `JAVA_HOME` unset on the other, as on a developer machine against CI.
/// Maven tests the same paths false on both, and so does the lock: it is up
/// to date either way, and a plain sync keeps its bytes.
#[test]
fn a_jdk_home_file_path_holds_for_one_jdk_by_java_home_or_path() {
    let (project, jdks) = jdk_home_paths_project();
    let root = project.root();
    let jdk = fake_jdk(&jdks, "17.0.2");
    let bin = Path::new(&jdk).join("bin").to_string_lossy().into_owned();
    let home = ("JAVA_HOME", jdk.as_str());
    let path = (rv_maven_model::JAVA_PATH_TEST_ENV, bin.as_str());
    for mode in MODES {
        for (first, second) in [(home, path), (path, home)] {
            set_mode(&root, mode);
            let label = format!("{mode}, locked with {}", first.0);
            let sync = ["sync", "--offline"];
            assert_success(&project.raeva_with(&[first], &sync), &label);
            assert_eq!(locked(&root), ["druid", "p3"], "{label}");
            let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
            for args in [
                &["sync", "--offline", "--frozen"][..],
                &["--offline", "sbom"],
                &["--offline", "export-checksums"],
            ] {
                let output = project.raeva_with(&[second], args);
                assert_success(&output, &format!("{label}: {args:?} with {}", second.0));
            }
            assert_success(&project.raeva_with(&[second], &sync), &label);
            let after = fs::read_to_string(root.join("raeva.lock")).unwrap();
            assert_eq!(lock, after, "{label}: a plain sync with {}", second.0);
        }
    }
}

/// On a host without Java, `sbom`, `export-checksums` and `vuln` run on a
/// lock whose `<file>` paths read the JDK's home, as they do for a `<jdk>`
/// condition: each path keeps the name as written, which tests as on a JDK
/// without the file. A lock made on a home where a path of the project's
/// own POM holds is stale there, as where the stand-in 17 flips a `<jdk>`
/// condition there.
#[test]
fn the_reports_of_a_jdk_home_file_path_run_without_java() {
    let (project, jdks) = jdk_home_paths_project();
    let root = project.root();
    let modern = fake_jdk(&jdks, "17.0.2");
    let old = fake_jdk(&jdks, "1.8.0_442");
    fs::create_dir_all(Path::new(&old).join("lib")).unwrap();
    fs::write(Path::new(&old).join("lib/jconsole.jar"), "").unwrap();
    // One result for each of druid and p3.
    let body = r#"{"results":[{"vulns":[]},{"vulns":[]}]}"#;
    let (osv_url, _osv) = crate::common::spawn_osv(200, body);
    let osv = [("RAEVA_OSV_BASE_URL", osv_url.as_str())];
    let reports = [
        (&[][..], &["--offline", "sbom"][..]),
        (&[], &["--offline", "export-checksums"]),
        (&osv, &["vuln"]),
    ];
    for mode in MODES {
        set_mode(&root, mode);
        let sync = ["sync", "--offline"];
        assert_success(&project.raeva_with(&[("JAVA_HOME", &modern)], &sync), mode);
        for (env, args) in reports {
            let label = format!("{mode}: {args:?} without Java");
            assert_success(&project.raeva_with(env, args), &label);
        }
        assert_success(&project.raeva_with(&[("JAVA_HOME", &old)], &sync), mode);
        let expected = if mode == "3.9" {
            &["druid", "p1"][..]
        } else {
            &["druid"]
        };
        assert_eq!(locked(&root), expected, "{mode} jconsole.jar");
        let output = project.raeva_with(&[], &["--offline", "sbom"]);
        assert_status(&output, 7, &format!("{mode}: sbom of a jconsole.jar lock"));
    }
}

/// A dependency's `<file>` path on the JDK's home that held where the lock
/// was made, as druid's `jconsole.jar` on a JDK 8, cannot be tested again
/// on a host with no JDK home, so there the reports take it as the lock
/// has it. `sync --frozen` still finds the lock stale, and so do the
/// reports on a JDK home where the path is missing.
#[test]
fn the_reports_take_a_held_jdk_home_file_path_from_the_lock_without_java() {
    let (project, jdks) = jdk_home_paths_project();
    let root = project.root();
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>druid</artifactId><version>1.0</version></dependency>\
                      </dependencies>";
    fs::write(root.join("pom.xml"), pom("", dependency)).unwrap();
    // Maven 3.10 tests no dependency's `<file>` path.
    set_mode(&root, "3.9");
    let modern = fake_jdk(&jdks, "17.0.2");
    let old = fake_jdk(&jdks, "1.8.0_442");
    fs::create_dir_all(Path::new(&old).join("lib")).unwrap();
    fs::write(Path::new(&old).join("lib/jconsole.jar"), "").unwrap();
    let sync = ["sync", "--offline"];
    assert_success(&project.raeva_with(&[("JAVA_HOME", &old)], &sync), "sync");
    assert_eq!(locked(&root), ["druid", "p1"]);
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    // One result for each of druid and p1.
    let body = r#"{"results":[{"vulns":[]},{"vulns":[]}]}"#;
    let (osv_url, _osv) = crate::common::spawn_osv(200, body);
    let osv = ("RAEVA_OSV_BASE_URL", osv_url.as_str());
    let reports = [
        &["--offline", "sbom"][..],
        &["--offline", "export-checksums"],
        &["vuln"],
    ];
    for args in reports {
        let output = project.raeva_with(&[osv], args);
        assert_success(&output, &format!("{args:?} without Java"));
        let output = project.raeva_with(&[osv, ("JAVA_HOME", &modern)], args);
        assert_status(
            &output,
            7,
            &format!("{args:?} on a JDK without jconsole.jar"),
        );
    }
    let output = project.raeva(&["sync", "--offline", "--frozen"]);
    assert_status(&output, 7, "--frozen without Java");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
}

/// `user.home` differs from host to host whatever sets it, so a project's
/// test of it refuses with a fix that works where `MAVEN_OPTS` sets it
/// already, and a `-Duser.home` on the command line answers it.
#[test]
fn a_user_home_test_names_the_fix_that_locks_it() {
    let activation = "<file><exists>${user.home}/marker</exists></file>";
    let project = project(&pom(&profile("p", activation, "p1"), ""));
    let home = project.root().join("home");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("marker"), "").unwrap();
    let opts = format!("-Duser.home={}", home.display());
    for mode in MODES {
        set_mode(&project.root(), mode);
        let output = project.raeva_with(&[("MAVEN_OPTS", &opts)], &["sync", "--offline"]);
        assert_status(&output, 3, mode);
        let message = stderr(&output);
        assert!(
            message.contains("command line of both raeva and mvn")
                && message.contains("MAVEN_OPTS or another JVM option is each host's own"),
            "{message}"
        );
        let define = format!("-Duser.home={}", home.display());
        let output = project.raeva_with(&[("MAVEN_OPTS", &opts)], &["sync", "--offline", &define]);
        assert_success(&output, mode);
        assert_eq!(locked(&project.root()), ["p1"], "{mode}");
    }
}

/// A POM's `${java.home}` stays as written, so a system path that takes it
/// refuses, saying why.
#[test]
fn a_system_path_taking_java_home_says_why_it_refuses() {
    let dependency = "<dependencies><dependency><groupId>com.sun</groupId>\
                      <artifactId>tools</artifactId><version>1.8</version><scope>system</scope>\
                      <systemPath>${java.home}/../lib/tools.jar</systemPath></dependency>\
                      </dependencies>";
    let project = project(&pom("", dependency));
    for mode in MODES {
        set_mode(&project.root(), mode);
        let output = project.raeva(&["sync", "--offline"]);
        assert_status(&output, 3, mode);
        let message = stderr(&output);
        assert!(
            message.contains("raeva does not expand ${java.home} in a POM")
                && !message.contains("has no value"),
            "{message}"
        );
    }
}

/// A JVM that sets a name only some set keeps its value over a dependency
/// POM's own, so Maven 3.10 activating that POM's profile by it differs
/// from host to host.
#[test]
fn a_dependency_property_does_not_stand_in_for_an_unevenly_set_jvm_name() {
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>carrier</artifactId><version>1.0</version><type>pom</type>\
                      </dependency></dependencies>";
    let carrier = project(&pom("", dependency));
    let name = "java.specification.maintenance.version";
    let activation = format!("<property><name>{name}</name><value>fallback</value></property>");
    carrier.publish(
        "org.test:carrier:1.0",
        &format!(
            "<packaging>pom</packaging><properties><{name}>fallback</{name}></properties>\
             <profiles>{}</profiles>",
            profile("p", &activation, "p1")
        ),
    );
    set_mode(&carrier.root(), "3.10");
    let output = carrier.raeva(&["sync", "--offline"]);
    // A dependency's model raeva cannot lock refuses as the project's does.
    assert_status(&output, 3, "3.10");
    assert!(stderr(&output).contains(name), "{}", stderr(&output));
    // Maven 3.9 leaves it off on every host, which raeva does not tell
    // apart; and the project's own value refuses in both lines.
    set_mode(&carrier.root(), "3.9");
    assert_status(&carrier.raeva(&["sync", "--offline"]), 3, "3.9");
    let own = format!("<properties><{name}>fallback</{name}></properties>");
    let own_project = project(&pom(&profile("p", &activation, "p1"), &own));
    refuses_in_both_modes(&own_project, &[], &["sync", "--offline"], name);
}

/// A settings.xml `<file>` path that takes `java.home` under `[lock] jdks`
/// listing another JDK refuses rather than lose the reference to a `..`.
#[test]
fn a_settings_file_path_taking_another_jdks_home_refuses() {
    let project = project(&pom(
        &profile(
            "p",
            "<property><name>enabled</name><value>yes</value></property>",
            "p1",
        ),
        "",
    ));
    let jdk = fake_jdk(&project.root().parent().unwrap().join("jdks"), "21.0.13");
    fs::write(
        project.m2_settings(),
        "<settings><profiles><profile><id>tools</id><activation><file><exists>\
         ${java.home}/../lib/tools.jar</exists></file></activation><properties>\
         <enabled>yes</enabled></properties></profile></profiles></settings>",
    )
    .unwrap();
    for mode in MODES {
        fs::write(
            project.root().join("raeva.toml"),
            format!("[lock]\nmaven = \"{mode}\"\njdks = [\"1.8\", \"21\"]\n"),
        )
        .unwrap();
        let output = project.raeva_with(&[("JAVA_HOME", &jdk)], &["sync", "--offline"]);
        assert_status(&output, 3, mode);
        assert!(stderr(&output).contains("java.home"), "{}", stderr(&output));
    }
}

/// `${.os.name}` reads `os.name` as `${os.name}` does, on every Windows
/// edition alike.
#[test]
fn a_dotted_os_name_reference_holds_on_every_windows_edition() {
    let activation = "<property><name>os.name</name><value>${.os.name}</value></property>";
    let project = project(&pom(&profile("p", activation, "p1"), ""));
    let windows = ["sync", "--offline", "--platforms", "windows-x86_64"];
    for mode in MODES {
        set_mode(&project.root(), mode);
        assert_success(&project.raeva(&windows), mode);
        assert_eq!(locked(&project.root()), ["p1"], "{mode}");
    }
}

/// JDK 8 and 11 take a `.mvn/jvm.config` `-Djava.specification.version`
/// and JDK 17 and newer keep their own, as Maven 3.9.12 and 3.10.0 on
/// Temurin 8 and 11 and OpenJDK 17 show. The sync refuses unless
/// `[lock] jdks` lists only JDKs that keep their own, and an empty
/// `-Djava.vendor`, which JDK 8 takes, so that a presence test fails
/// there, refuses too.
#[test]
fn a_jvm_config_value_some_jdks_take_refuses_unless_the_jdks_keep_their_own() {
    let activation =
        "<property><name>java.specification.version</name><value>21</value></property>";
    let project = project(&pom(&profile("p", activation, "p1"), ""));
    let root = project.root();
    let jdk = fake_jdk(&root.parent().unwrap().join("jdks"), "21.0.13");
    fs::create_dir_all(root.join(".mvn")).unwrap();
    // The artifacts locked where the sync passes, by the JDK's own
    // `java.specification.version`.
    let on: &[&str] = &["p1"];
    for (jvm_config, jdks, locks) in [
        ("-Djava.specification.version=21", "", None),
        (
            "-Djava.specification.version=21",
            "jdks = [\"1.8\"]\n",
            None,
        ),
        ("-Djava.specification.version=21", "jdks = [\"11\"]\n", None),
        (
            "-Djava.specification.version=21",
            "jdks = [\"11\", \"21\"]\n",
            None,
        ),
        ("-Djava.specification.name=X", "", None),
        ("-Djava.vendor=", "", None),
        ("-Djava.vendor=", "jdks = [\"11\"]\n", Some(&[][..])),
        ("-Djava.vendor=X", "", Some(on)),
        (
            "-Djava.specification.version=21",
            "jdks = [\"17\"]\n",
            Some(&[][..]),
        ),
        (
            "-Djava.specification.version=17",
            "jdks = [\"21\"]\n",
            Some(on),
        ),
    ] {
        fs::write(root.join(".mvn/jvm.config"), format!("{jvm_config}\n")).unwrap();
        for mode in MODES {
            fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n{jdks}"),
            )
            .unwrap();
            let output = project.raeva_with(&[("JAVA_HOME", &jdk)], &["sync", "--offline"]);
            let case = format!("{mode} {jvm_config} {jdks}");
            match locks {
                Some(locks) => {
                    assert_success(&output, &case);
                    assert_eq!(locked(&root), locks, "{case}");
                }
                None => {
                    assert_status(&output, 3, &case);
                    let name = jvm_config
                        .trim_start_matches("-D")
                        .split('=')
                        .next()
                        .unwrap();
                    assert!(
                        stderr(&output).contains(&format!(".mvn/jvm.config sets -D{name}")),
                        "{case}: {}",
                        stderr(&output)
                    );
                }
            }
        }
    }
}

/// Maven parses a `<jdk>` range's bounds with `Integer.parseInt`, which
/// reads `[２１,)` as `[21,)` (Maven 3.9.12 and 3.10.0 activate it on JDK
/// 21) and takes more scripts' digits on newer JDKs, so such a range
/// refuses with or without `[lock] jdks`.
#[test]
fn a_jdk_range_that_is_not_ascii_refuses() {
    let project = project(&pom(&profile("p", "<jdk>[２１,)</jdk>", "p1"), ""));
    let root = project.root();
    let jdk = fake_jdk(&root.parent().unwrap().join("jdks"), "21.0.13");
    for jdks in ["", "jdks = [\"21\"]\n"] {
        for mode in MODES {
            fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{mode}\"\n{jdks}"),
            )
            .unwrap();
            let output = project.raeva_with(&[("JAVA_HOME", &jdk)], &["sync", "--offline"]);
            assert_status(&output, 3, &format!("{mode} {jdks}"));
            assert!(
                stderr(&output).contains("the <jdk> range [２１,) of profile p holds a character"),
                "{}",
                stderr(&output)
            );
        }
    }
}

/// CXF 3.x's parent POM, a dependency's, turns on its `ibmjdk` profile
/// where `java.vendor` is `IBM Corporation`. raeva takes the vendor of the
/// JDK `mvn` runs from its `release` file, from JDK 11 on, and raeva.lock
/// records what the test gave, not the vendor: another vendor with the same
/// outcome keeps the lock, one with another makes `--frozen` exit 7, also
/// under `[lock] jdks`, and on a JDK 8, whose `release` file does not tell
/// its `java.vendor`, `--frozen` exits 7 and a sync refuses as before
/// unless `-Djava.vendor` sets it.
#[test]
fn a_dependency_parent_profile_on_java_vendor_takes_the_host_jdk() {
    let project = Project::with(&[]);
    let root = project.root();
    let jdks = root.parent().unwrap().join("jdks");
    let jdk = |dir: &str, version: &str, implementor: &str| {
        let home = fake_jdk(&jdks.join(dir), version);
        fs::write(
            Path::new(&home).join("release"),
            format!("JAVA_VERSION=\"{version}\"\nIMPLEMENTOR=\"{implementor}\"\n"),
        )
        .unwrap();
        home
    };
    let temurin = jdk("temurin", "21.0.9", "Eclipse Adoptium");
    let corretto = jdk("corretto", "17.0.13", "Amazon.com Inc.");
    let semeru = jdk("semeru", "17.0.13", "IBM Corporation");
    let temurin8 = jdk("temurin8", "1.8.0_472", "Eclipse Adoptium");
    project.publish("org.test:p1:1.0", "");
    let ibm = profile(
        "ibmjdk",
        "<property><name>java.vendor</name><value>IBM Corporation</value></property>",
        "p1",
    );
    project.publish(
        "org.test:parent:1.0",
        &format!("<packaging>pom</packaging><profiles>{ibm}</profiles>"),
    );
    project.publish(
        "org.test:dep:1.0",
        "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
         <version>1.0</version></parent>",
    );
    let dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                      <artifactId>dep</artifactId><version>1.0</version></dependency>\
                      </dependencies>";
    fs::write(root.join("pom.xml"), pom("", dependency)).unwrap();
    let run = |jdk: &str, args: &[&str]| project.raeva_with(&[("JAVA_HOME", jdk)], args);
    let (sync, frozen) = (["sync", "--offline"], ["sync", "--frozen", "--offline"]);
    let condition = |holds: bool| format!("property:java.vendor=IBM Corporation is {holds}");
    for mode in MODES {
        for jdks in ["", "jdks = [\"17\", \"21\"]\n"] {
            let case = format!("{mode} {jdks}");
            set_mode(&root, mode);
            let toml = fs::read_to_string(root.join("raeva.toml")).unwrap();
            fs::write(root.join("raeva.toml"), toml + jdks).unwrap();
            assert_success(&run(&temurin, &sync), &case);
            assert_eq!(locked(&root), ["dep"], "{case} Temurin");
            let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
            assert!(
                lock.contains(&condition(false)) && !lock.contains("Adoptium"),
                "{case}: {lock}"
            );
            assert_success(&run(&corretto, &frozen), &format!("{case} Corretto"));
            assert_status(&run(&semeru, &frozen), 7, &format!("{case} Semeru"));
            assert_success(&run(&semeru, &sync), &format!("{case} Semeru"));
            assert_eq!(locked(&root), ["dep", "p1"], "{case} Semeru");
            let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
            assert!(lock.contains(&condition(true)), "{case}: {lock}");
        }
        assert_status(&run(&temurin8, &frozen), 7, &format!("{mode} JDK 8"));
        let output = run(&temurin8, &sync);
        assert_status(&output, 3, &format!("{mode} JDK 8"));
        assert!(
            stderr(&output).contains("depends on java.vendor")
                && stderr(&output).contains("-Djava.vendor="),
            "{mode}: {}",
            stderr(&output)
        );
        let defined = [&sync[..], &["-Djava.vendor=Temurin"]].concat();
        assert_success(&run(&temurin8, &defined), &format!("{mode} JDK 8 -D"));
        assert_eq!(locked(&root), ["dep"], "{mode} JDK 8 -D");
    }
}
