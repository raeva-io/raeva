//! `[plugins] lock = true` in raeva.toml: a sync writes the plugin tables of
//! raeva.lock with the build's plugins and core extensions, `raeva export-m2`
//! writes their files, and `sync --frozen` holds them to their pins and to
//! the settings.

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{
    assert_status, assert_success, pom, raeva_command, run_raeva, serve_sha256, sha256_hex,
    sha256_repository, stderr, write_with_sha256,
};

/// An empty zip: a jar with no descriptor in it.
const JAR: &[u8] = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// The empty jar with a one-byte comment: other bytes of a valid jar.
const OTHER_JAR: &[u8] = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0x";

/// A repository that serves a POM for every `g/a/v/a-v.pom`, the empty jar
/// for every `.jar`, and their SHA-256 sidecars.
fn repository() -> StubServer {
    repository_where(|_| false)
}

/// [`repository`], with a wrong SHA-256 sidecar for each file `wrong` holds.
fn repository_where(wrong: fn(&str) -> bool) -> StubServer {
    repository_with(None, |_| (JAR, true), wrong)
}

/// [`repository`], serving for the jar of each artifact id the bytes
/// `jar` gives, with a sidecar when it says so.
fn repository_serving(
    jar: impl Fn(&str) -> (&'static [u8], bool) + Send + Sync + 'static,
) -> StubServer {
    repository_with(None, jar, |_| false)
}

fn repository_with(
    authorization: Option<&'static str>,
    jar: impl Fn(&str) -> (&'static [u8], bool) + Send + Sync + 'static,
    wrong: fn(&str) -> bool,
) -> StubServer {
    StubServer::start(move |request| serve(request, authorization, &jar, wrong))
}

/// [`repository_with`]'s answer to `request`.
fn serve(
    request: &rv_test_support::http::Request,
    authorization: Option<&str>,
    jar: impl Fn(&str) -> (&'static [u8], bool),
    wrong: fn(&str) -> bool,
) -> Response {
    if authorization.is_some_and(|expected| request.header("authorization") != Some(expected)) {
        return Response::new(401, "");
    }
    let path = request.path.trim_start_matches('/');
    let (path, sidecar) = match path.strip_suffix(".sha256") {
        Some(path) => (path, true),
        None => (path, false),
    };
    let parts: Vec<&str> = path.split('/').collect();
    let [group @ .., artifact, version, file] = parts.as_slice() else {
        return Response::new(404, "");
    };
    let body = if *file == format!("{artifact}-{version}.pom") {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>\
             <packaging>maven-plugin</packaging></project>",
            group.join(".")
        )
        .into_bytes()
    } else if *file == format!("{artifact}-{version}.jar") {
        match jar(artifact) {
            (_, false) if sidecar => return Response::new(404, ""),
            (bytes, _) => bytes.to_vec(),
        }
    } else {
        return Response::new(404, "");
    };
    match sidecar {
        true if wrong(path) => Response::new(200, "0".repeat(64)),
        true => Response::new(200, sha256_hex(&body)),
        false => Response::new(200, body),
    }
}

/// A project whose POM binds `t:demo-maven-plugin:1` and whose
/// `.mvn/extensions.xml` loads `t:ext` at the version `.mvn/maven.config`
/// gives, with a home whose settings.xml mirrors everything to `url`.
fn plugin_project(url: &str) -> (TempDir, TempDir) {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>*</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
             <artifactId>demo-maven-plugin</artifactId><version>1</version><executions>\
             <execution><phase>validate</phase><goals><goal>run</goal></goals></execution>\
             </executions></plugin></plugins></build>",
        ),
    )
    .unwrap();
    fs::create_dir_all(project.path().join(".mvn")).unwrap();
    fs::write(
        project.path().join(".mvn/extensions.xml"),
        "<extensions><extension><groupId>t</groupId><artifactId>ext</artifactId>\
         <version>${ext.version}</version></extension></extensions>",
    )
    .unwrap();
    fs::write(
        project.path().join(".mvn/maven.config"),
        "-Dext.version=2\n",
    )
    .unwrap();
    (project, home)
}

/// The mavenrc block `bin/mvn` 3.9 starts with, which a traced launcher
/// must start with for the build to run where mavenrc files exist.
#[cfg(unix)]
const MVN_RC_BLOCK: &str = "if [ -z \"$MAVEN_SKIP_RC\" ] ; then\n\n  \
    if [ -f /usr/local/etc/mavenrc ] ; then\n    . /usr/local/etc/mavenrc\n  fi\n\n  \
    if [ -f /etc/mavenrc ] ; then\n    . /etc/mavenrc\n  fi\n\n  \
    if [ -f \"$HOME/.mavenrc\" ] ; then\n    . \"$HOME/.mavenrc\"\n  fi\n\nfi\n";

/// A `./mvnw` in `root` that downloads `t:tool:1` from the mirror, and
/// notes each run in `ran`. It sources the mavenrc files as `bin/mvn` does.
#[cfg(unix)]
fn fake_mvnw(root: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    fs::write(root.join("tool.jar"), JAR).unwrap();
    let launcher = root.join("mvnw");
    fs::write(
        &launcher,
        "#!/bin/sh\n".to_string()
            + MVN_RC_BLOCK
            + "for a in \"$@\"; do case $a in -Dmaven.repo.local=*) \
         m2=${a#-Dmaven.repo.local=};; esac; done\necho run >> \"$(dirname \"$0\")/ran\"\n\
         mkdir -p \"$m2/t/tool/1\"\ncp \"$(dirname \"$0\")/tool.jar\" \"$m2/t/tool/1/tool-1.jar\"\n\
         printf 'tool-1.jar>stub=\\n' > \"$m2/t/tool/1/_remote.repositories\"\n",
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
    launcher
}

/// A settings.xml property that a `-D` value overrides is no input of the
/// plugin tables, though `.mvn/extensions.xml` reads its name.
#[test]
fn an_overridden_settings_property_leaves_the_plugin_tables_current() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    fs::write(
        project.path().join("raeva.toml"),
        "[plugins]\nlock = true\n",
    )
    .unwrap();
    let settings = home.path().join(".m2/settings.xml");
    let mirrored = fs::read_to_string(&settings).unwrap();
    let with_version = |version: &str| {
        let profile = format!(
            "<profiles><profile><id>ext</id><properties><ext.version>{version}\
             </ext.version></properties></profile></profiles><activeProfiles>\
             <activeProfile>ext</activeProfile></activeProfiles></settings>"
        );
        fs::write(&settings, mirrored.replace("</settings>", &profile)).unwrap();
    };
    let raeva = |args: &[&str]| run_raeva(project.path(), home.path(), args);
    with_version("8");
    assert_success(&raeva(&["sync"]), "sync");
    assert!(
        fs::read_to_string(project.path().join("raeva.lock"))
            .unwrap()
            .contains("t:ext:2")
    );
    with_version("9");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
}

/// `mvn` loads the core extensions of `.mvn/extensions.xml` in its project
/// directory, here above the project, at the version that directory's
/// `.mvn/maven.config` gives, and so does the lock.
#[test]
fn core_extensions_are_read_where_the_launcher_finds_mvn() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let sub = project.path().join("sub");
    fs::create_dir(&sub).unwrap();
    fs::rename(project.path().join("pom.xml"), sub.join("pom.xml")).unwrap();
    fs::write(sub.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(&sub, home.path(), &["sync"]), "sync");
    let tables = fs::read_to_string(sub.join("raeva.lock")).unwrap();
    assert!(tables.contains("t:ext:2"), "{tables}");
}

/// A sync with plugin locking pins a declared plugin and a core extension
/// whose version `.mvn/extensions.xml` takes from a `-D` value in
/// `.mvn/maven.config`, as Maven expands it; the export writes both.
/// Changing `[plugins]` makes `--frozen` refuse, and dropping it drops the
/// tables.
#[test]
fn a_sync_locks_plugins_and_interpolated_core_extensions() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let settings = project.path().join("raeva.toml");
    fs::write(&settings, "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(project.path(), home.path(), args);
    let lock_path = project.path().join("raeva.lock");
    assert_success(&raeva(&["sync"]), "sync");
    let tables = fs::read_to_string(&lock_path).unwrap();
    assert!(tables.contains("[platforms.plugins]"), "{tables}");
    for coordinate in ["t:demo-maven-plugin:1", "t:ext:2"] {
        assert!(tables.contains(coordinate), "{coordinate}: {tables}");
    }
    let document: toml::Value = toml::from_str(&tables).unwrap();
    crate::schemas::assert_schema_valid(
        &crate::schemas::validator(crate::schemas::RAEVA_LOCK_SCHEMA),
        &serde_json::to_value(document).unwrap(),
    );
    let m2 = home.path().join("m2");
    assert_success(
        &raeva(&["export-m2", "--m2-path", m2.to_str().unwrap()]),
        "export",
    );
    for file in [
        "t/demo-maven-plugin/1/demo-maven-plugin-1.jar",
        "t/ext/2/ext-2.jar",
    ] {
        assert_eq!(fs::read(m2.join(file)).unwrap(), JAR, "{file}");
    }
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    // Only the `-D` values the resolution read are inputs: not an unused
    // one, the export's destination, or another JVM option.
    fs::write(project.path().join(".mvn/jvm.config"), "-Xmx2g\n").unwrap();
    let frozen = raeva(&["-DskipTests", "sync", "--frozen"]);
    assert_success(&frozen, "frozen sync with an unused -D");
    let local = home.path().join("local");
    let define = format!("-Dmaven.repo.local={}", local.display());
    assert_success(
        &raeva(&[&define, "export-m2"]),
        "export to -Dmaven.repo.local",
    );
    assert!(local.join("t/ext/2/ext-2.jar").is_file());
    fs::remove_file(project.path().join(".mvn/jvm.config")).unwrap();
    let frozen = raeva(&["-Dext.version=3", "sync", "--frozen"]);
    assert!(
        stderr(&frozen).contains("resolved from other inputs"),
        "{}",
        stderr(&frozen)
    );

    // Fresh tables are not resolved again.
    let again = raeva(&["sync"]);
    assert_success(&again, "second sync");
    assert!(
        !stderr(&again).contains("Resolving plugins") && stderr(&again).contains("up to date"),
        "{}",
        stderr(&again)
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), tables);

    // On another machine a sync of the lock puts the plugin files in the
    // store, so the export has them.
    let other = TempDir::new().unwrap();
    fs::create_dir_all(other.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        other.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let elsewhere = |args: &[&str]| {
        (raeva_command(project.path(), other.path()))
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&elsewhere(&["sync"]), "sync on another machine");
    let m2 = other.path().join("m2");
    assert_success(
        &elsewhere(&["export-m2", "--m2-path", m2.to_str().unwrap()]),
        "export on another machine",
    );
    assert_eq!(fs::read(m2.join("t/ext/2/ext-2.jar")).unwrap(), JAR);
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), tables);

    // A pin no resolution gives fails --frozen.
    let pin = sha256_hex(JAR);
    let tampered = tables.replacen(&pin, &"0".repeat(64), 1);
    assert_ne!(tampered, tables);
    fs::write(&lock_path, &tampered).unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert!(!frozen.status.success(), "{}", stderr(&frozen));
    fs::write(&lock_path, &tables).unwrap();

    // A plugin file recorded as served by a repository the resolution does
    // not read it from fails --frozen before any request goes there.
    let moved = tables.replace(
        "repo_url = \"https://repo.maven.apache.org/maven2/\"",
        "repo_url = \"https://elsewhere.example/maven2/\"",
    );
    assert_ne!(moved, tables);
    fs::write(&lock_path, &moved).unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    assert!(
        stderr(&frozen).contains("differs from a resolution of the same inputs"),
        "{}",
        stderr(&frozen)
    );
    fs::write(&lock_path, &tables).unwrap();

    // Other goals are other inputs.
    fs::write(
        &settings,
        "[plugins]\nlock = true\ngoals = ['t:demo-maven-plugin:1:run']\n",
    )
    .unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert!(
        stderr(&frozen).contains("resolved from other inputs"),
        "{}",
        stderr(&frozen)
    );
    fs::write(&settings, "[plugins]\nlock = true\n").unwrap();

    // The extension's version comes from a property no POM reads.
    fs::write(
        project.path().join(".mvn/maven.config"),
        "-Dext.version=3\n",
    )
    .unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert!(
        stderr(&frozen).contains("resolved from other inputs"),
        "{}",
        stderr(&frozen)
    );
    let before = project.path().join("before.lock");
    fs::write(&before, &tables).unwrap();
    assert_success(&raeva(&["sync"]), "sync after the property changed");
    let tables = fs::read_to_string(&lock_path).unwrap();
    assert!(tables.contains("t:ext:3"), "{tables}");
    let diff = raeva(&["lock", "diff", before.to_str().unwrap()]);
    assert_success(&diff, "lock diff");
    let diff = String::from_utf8_lossy(&diff.stdout);
    assert!(diff.contains("core extension t:ext: 2 -> 3"), "{diff}");

    // Without `[plugins]`, --frozen refuses the tables and a sync drops
    // them and their rows.
    fs::remove_file(&settings).unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert!(
        stderr(&frozen).contains("raeva.toml does not ask for"),
        "{}",
        stderr(&frozen)
    );
    assert_success(&raeva(&["sync"]), "sync dropping the tables");
    let tables = fs::read_to_string(&lock_path).unwrap();
    assert!(!tables.contains("[platforms.plugins]"), "{tables}");
    assert!(!tables.contains("t:ext"), "{tables}");
    fs::write(&settings, "[plugins]\nlock = true\n").unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert!(
        stderr(&frozen).contains("raeva.lock has no plugin tables"),
        "{}",
        stderr(&frozen)
    );
}

/// A frozen check of one platform of the lock a sync of two wrote leaves
/// the other recorded, so a plain sync of both keeps the lock unchecked.
#[test]
fn a_check_of_one_platform_keeps_the_record_of_another() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    let both = "linux-x86_64,macos-aarch64";
    assert_success(&raeva(&["sync", "--platforms", both]), "sync");
    assert_success(
        &raeva(&["sync", "--frozen", "--platforms", "linux-x86_64"]),
        "frozen sync of one platform",
    );
    let plain = raeva(&["sync", "--platforms", both]);
    assert_success(&plain, "plain sync");
    assert!(
        !stderr(&plain).contains("Checking plugins"),
        "{}",
        stderr(&plain)
    );
}

/// A sync of some platforms keeps another only with plugin tables that
/// hold, so `--frozen` accepts every platform the lock it writes records:
/// one without tables, once `[plugins]` asks for them, and one whose tables
/// other goals made stale are dropped.
#[test]
fn a_partial_sync_keeps_a_platform_only_with_tables_that_hold() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let settings = project.path().join("raeva.toml");
    let raeva = |args: &[&str]| run_raeva(project.path(), home.path(), args);
    let lock_path = project.path().join("raeva.lock");
    let both = "linux-x86_64,macos-aarch64";
    let recorded = || {
        let lock: toml::Value = toml::from_str(&fs::read_to_string(&lock_path).unwrap()).unwrap();
        let mut targets: Vec<String> = (lock["platforms"].as_array().unwrap().iter())
            .flat_map(|entry| entry["targets"].as_array().unwrap())
            .map(|target| target.as_str().unwrap().to_string())
            .collect();
        targets.sort();
        targets.join(",")
    };
    let partial = |what: &str| {
        let output = raeva(&["sync", "--platforms", "linux-x86_64"]);
        assert_success(&output, what);
        assert_success(
            &raeva(&["sync", "--frozen", "--platforms", &recorded()]),
            what,
        );
        assert!(
            stderr(&output).contains("PLATFORM_DROPPED"),
            "{what}: {}",
            stderr(&output)
        );
        assert_eq!(recorded(), "linux-x86_64", "{what}");
    };
    assert_success(
        &raeva(&["sync", "--platforms", both]),
        "sync without tables",
    );
    fs::write(&settings, "[plugins]\nlock = true\n").unwrap();
    partial("a platform without tables");
    assert_success(&raeva(&["sync", "--platforms", both]), "sync with tables");
    assert_success(&raeva(&["sync", "--frozen", "--platforms", both]), "frozen");
    fs::write(
        &settings,
        "[plugins]\nlock = true\ngoals = ['t:demo-maven-plugin:1:run']\n",
    )
    .unwrap();
    partial("a platform with stale tables");
}

/// A partial sync drops an unselected platform whose trace raeva.toml no
/// longer asks for, which `--frozen` refuses.
#[cfg(unix)]
#[test]
fn a_partial_sync_drops_a_platform_with_a_trace_no_longer_asked_for() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    let settings = root.join("raeva.toml");
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    fs::write(
        &settings,
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    // The trace is the host's, and the platform the partial sync keeps.
    let host = rv_lock::Platform::current().unwrap().os_arch();
    let other = match host.as_str() {
        "linux-x86_64" => "macos-aarch64",
        _ => "linux-x86_64",
    };
    let both = format!("{host},{other}");
    assert_success(&raeva(&["sync", "--platforms", &both]), "traced sync");
    fs::write(&settings, "[plugins]\nlock = true\n").unwrap();
    let partial = raeva(&["sync", "--platforms", other]);
    assert_success(&partial, "partial sync without the trace");
    assert!(
        stderr(&partial).contains("PLATFORM_DROPPED"),
        "{}",
        stderr(&partial)
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!lock.contains(&format!("\"{host}\"")), "{lock}");
    assert_success(
        &raeva(&["sync", "--frozen", "--platforms", other]),
        "frozen",
    );
}

/// A partial sync traces the build on what it synced: the export the
/// build runs on holds the platforms it selected, so a fresh home needs no
/// plugin file only another platform pins.
#[cfg(unix)]
#[test]
fn a_partial_sync_traces_on_the_platforms_it_synced() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let host = rv_lock::Platform::current().unwrap().os_arch();
    let (other, activation) = match host.as_str() {
        "linux-x86_64" => ("macos-aarch64", "<os><family>mac</family></os>"),
        _ => ("linux-x86_64", "<os><name>linux</name></os>"),
    };
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
                 <artifactId>demo-maven-plugin</artifactId><version>1</version><executions>\
                 <execution><phase>validate</phase><goals><goal>run</goal></goals>\
                 </execution></executions></plugin></plugins></build><profiles><profile>\
                 <id>other</id><activation>{activation}</activation><build><plugins><plugin>\
                 <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                 <version>1</version><dependencies><dependency><groupId>t</groupId>\
                 <artifactId>only</artifactId><version>1</version></dependency>\
                 </dependencies></plugin></plugins></build></profile></profiles>"
            ),
        ),
    )
    .unwrap();
    let both = format!("{host},{other}");
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--platforms", &both]),
        "traced sync",
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:only:1"), "{lock}");
    let fresh = TempDir::new().unwrap();
    fs::create_dir_all(fresh.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        fresh.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let update = ["sync", "--platforms", &host, "--update"];
    assert_success(&run_raeva(root, fresh.path(), &update), "partial update");
    let ran = (fs::read_to_string(root.join("ran")).unwrap())
        .lines()
        .count();
    assert_eq!(ran, 2);
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:only:1"), "{lock}");
    assert_success(
        &run_raeva(
            root,
            home.path(),
            &["sync", "--frozen", "--platforms", &both],
        ),
        "frozen sync",
    );
}

/// A partial traced update of the host keeps the lists of the lock it
/// exports for the build to the platform it traces: a repository and a
/// property only another platform's profile reads are in none of them.
#[cfg(unix)]
#[test]
fn a_partial_traced_update_exports_without_another_platforms_repository() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['validate']\nmvn = './mvnw'\n",
    )
    .unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    let host = rv_lock::Platform::current().unwrap().os_arch();
    let (other, activation) = match host.as_str() {
        "linux-x86_64" => ("macos-aarch64", "<os><family>mac</family></os>"),
        _ => ("linux-x86_64", "<os><name>linux</name></os>"),
    };
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
                 <artifactId>demo-maven-plugin</artifactId><version>1</version><executions>\
                 <execution><phase>validate</phase><goals><goal>run</goal></goals>\
                 </execution></executions></plugin></plugins></build><profiles><profile>\
                 <id>other</id><activation>{activation}</activation><repositories>\
                 <repository><id>other-repo</id><url>{url}${{other.path}}</url></repository>\
                 </repositories></profile></profiles>"
            ),
        ),
    )
    .unwrap();
    fs::write(
        root.join(".mvn/maven.config"),
        "-Dext.version=2\n-Dother.path=other/\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    let both = format!("{host},{other}");
    assert_success(&raeva(&["sync", "--platforms", &both]), "traced sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("other-repo"), "{lock}");
    assert!(lock.contains("other.path"), "{lock}");
    assert_success(
        &raeva(&["sync", "--update", "--platforms", &host]),
        "partial update",
    );
    assert_success(
        &raeva(&["sync", "--frozen", "--platforms", &both]),
        "frozen",
    );
}

/// A POM the trace read that only another platform's dependencies pin is
/// recorded for the traced platform too, so it outlives that platform.
#[cfg(unix)]
#[test]
fn a_traced_pom_another_platform_pins_outlives_that_platform() {
    use std::os::unix::fs::PermissionsExt;

    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(
        root.join("dep.pom"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>dep</artifactId><version>1</version>\
         <packaging>maven-plugin</packaging></project>",
    )
    .unwrap();
    let launcher = root.join("mvnw");
    fs::write(
        &launcher,
        "#!/bin/sh\nfor a in \"$@\"; do case $a in -Dmaven.repo.local=*) \
         m2=${a#-Dmaven.repo.local=};; esac; done\nmkdir -p \"$m2/t/dep/1\"\n\
         cp \"$(dirname \"$0\")/dep.pom\" \"$m2/t/dep/1/dep-1.pom\"\n\
         printf 'dep-1.pom>stub=\\n' > \"$m2/t/dep/1/_remote.repositories\"\n",
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['validate']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let host = rv_lock::Platform::current().unwrap().os_arch();
    let (other, activation) = match host.as_str() {
        "linux-x86_64" => ("macos-aarch64", "<os><family>mac</family></os>"),
        _ => ("linux-x86_64", "<os><name>linux</name></os>"),
    };
    let project_pom = |dependencies: &str| {
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
                 <artifactId>demo-maven-plugin</artifactId><version>1</version><executions>\
                 <execution><phase>validate</phase><goals><goal>run</goal></goals>\
                 </execution></executions></plugin></plugins></build><profiles><profile>\
                 <id>other</id><activation>{activation}</activation>\
                 <dependencies>{dependencies}</dependencies></profile></profiles>"
            ),
        )
    };
    fs::write(
        root.join("pom.xml"),
        project_pom(
            "<dependency><groupId>t</groupId><artifactId>dep</artifactId>\
             <version>1</version></dependency>",
        ),
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    let both = format!("{host},{other}");
    assert_success(&raeva(&["sync", "--platforms", &both]), "traced sync");
    fs::write(root.join("pom.xml"), project_pom("")).unwrap();
    let partial = raeva(&["sync", "--platforms", &host]);
    assert_success(&partial, "partial sync");
    assert!(
        stderr(&partial).contains("PLATFORM_DROPPED"),
        "{}",
        stderr(&partial)
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:dep:1"), "{lock}");
    let m2 = TempDir::new().unwrap();
    let m2_path = m2.path().to_str().unwrap();
    assert_success(&raeva(&["export-m2", "--m2-path", m2_path]), "export");
    assert!(m2.path().join("t/dep/1/dep-1.pom").is_file());
}

/// A POM the trace read from a plugin repository, for a dependency the
/// modules hold without one, is a support POM beside that row, as the
/// plugin tables pin one: `mvn -o` reads it where the online build did.
#[cfg(unix)]
/// As Maven 3.10 reads it: the Maven 3.9 mode refuses it, as a module reads a dependency without a POM.
#[test]
fn a_traced_pom_of_a_dependency_without_one_is_a_support_pom() {
    use std::os::unix::fs::PermissionsExt;

    let central = StubServer::start(|request| match request.path.as_str() {
        "/t/lib/1.0/lib-1.0.pom" | "/t/lib/1.0/lib-1.0.pom.sha256" => Response::new(404, ""),
        _ => serve(request, None, |_| (JAR, true), |_| false),
    });
    let plugins = repository();
    let url = format!("http://{}/", central.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><pluginRepositories><pluginRepository><id>r2</id>\
                 <url>http://{}/</url></pluginRepository></pluginRepositories>\
                 <dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
                 <version>1.0</version></dependency></dependencies><build><plugins><plugin>\
                 <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                 <version>1</version><executions><execution><phase>validate</phase><goals>\
                 <goal>run</goal></goals></execution></executions></plugin></plugins></build>",
                plugins.addr()
            ),
        ),
    )
    .unwrap();
    fs::write(
        root.join("lib.pom"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>lib</artifactId><version>1.0</version>\
         <packaging>maven-plugin</packaging></project>",
    )
    .unwrap();
    let launcher = root.join("mvnw");
    fs::write(
        &launcher,
        "#!/bin/sh\nfor a in \"$@\"; do case $a in -Dmaven.repo.local=*) \
         m2=${a#-Dmaven.repo.local=};; esac; done\nmkdir -p \"$m2/t/lib/1.0\"\n\
         cp \"$(dirname \"$0\")/lib.pom\" \"$m2/t/lib/1.0/lib-1.0.pom\"\n\
         printf 'lib-1.0.pom>r2=\\nlib-1.0.jar>stub=\\n' > \"$m2/t/lib/1.0/_remote.repositories\"\n",
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\ntrace = ['validate']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "traced sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let support = lock.split("[[platforms.support_poms]]").skip(1);
    assert!(
        support
            .clone()
            .any(|pom| pom.contains("coordinate = \"t:lib:1.0\"")),
        "{lock}"
    );
    let m2 = TempDir::new().unwrap();
    let m2_path = m2.path().to_str().unwrap();
    assert_success(&raeva(&["export-m2", "--m2-path", m2_path]), "export");
    let dir = m2.path().join("t/lib/1.0");
    assert!(dir.join("lib-1.0.pom").is_file());
    let markers = fs::read_to_string(dir.join("_remote.repositories")).unwrap();
    assert!(markers.contains("lib-1.0.pom>r2="), "{markers}");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen");
    assert_success(&raeva(&["sync", "--update"]), "update");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen after the update");
}

/// A partial sync whose platform reads a name no kept platform reads keeps
/// the other platforms' plugin tables current under the lock's new
/// configuration hash.
#[test]
fn a_partial_sync_that_reads_a_new_name_keeps_the_other_plugin_tables() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
             <artifactId>demo-maven-plugin</artifactId><version>1</version>\
             </plugin></plugins></build><profiles><profile><id>windows</id><activation>\
             <os><family>windows</family></os></activation><dependencies><dependency>\
             <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
             <version>${windows.version}</version></dependency></dependencies>\
             </profile></profiles>",
        ),
    )
    .unwrap();
    let raeva = |args: &[&str]| {
        (raeva_command(root, home.path()))
            .arg("-Dwindows.version=1")
            .args(args)
            .output()
            .expect("run raeva")
    };
    let both = "linux-x86_64,macos-aarch64";
    assert_success(&raeva(&["sync", "--platforms", both]), "sync");
    let partial = raeva(&["sync", "--platforms", "windows-x86_64"]);
    assert_success(&partial, "partial sync");
    assert!(
        !stderr(&partial).contains("PLATFORM_DROPPED"),
        "{}",
        stderr(&partial)
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("windows.version"), "{lock}");
    let all = format!("{both},windows-x86_64");
    assert_success(&raeva(&["sync", "--frozen", "--platforms", &all]), "frozen");
}

/// A plugin file raeva.lock pins keeps its pin when a plain sync resolves
/// the plugin tables again: other bytes from the repository fail the sync,
/// as they do for a dependency, and only `--update` takes them.
#[test]
fn a_resolving_sync_refuses_other_bytes_for_a_pinned_plugin() {
    let swapped = Arc::new(AtomicBool::new(false));
    let server = repository_serving({
        let swapped = Arc::clone(&swapped);
        move |artifact| match swapped.load(Ordering::SeqCst) && artifact == "demo-maven-plugin" {
            true => (OTHER_JAR, true),
            false => (JAR, true),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(
        &raeva_command(root, home.path())
            .arg("sync")
            .output()
            .unwrap(),
        "sync",
    );
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    assert!(locked.contains(&sha256_hex(JAR)), "{locked}");

    // The mirror now serves other bytes: a check on another machine
    // refuses them.
    swapped.store(true, Ordering::SeqCst);
    let other = TempDir::new().unwrap();
    fs::create_dir_all(other.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        other.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let sync = |args: &[&str]| {
        (raeva_command(root, other.path()))
            .args(args)
            .output()
            .expect("run raeva")
    };
    let refused = |output: std::process::Output| {
        assert_eq!(output.status.code(), Some(7), "{}", stderr(&output));
        assert!(
            stderr(&output).contains(&sha256_hex(OTHER_JAR)),
            "{}",
            stderr(&output)
        );
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
    };
    refused(sync(&["sync", "--frozen"]));
    // An edit of the POM makes the tables stale, so a sync resolves them
    // again, and still refuses the bytes.
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    let edited = pom.replacen("<build>", "<properties><x>1</x></properties><build>", 1);
    assert_ne!(edited, pom);
    fs::write(root.join("pom.xml"), edited).unwrap();
    refused(sync(&["sync"]));
    // `--update` takes them, also for tables whose inputs did not change.
    fs::write(root.join("pom.xml"), &pom).unwrap();
    refused(sync(&["sync"]));
    assert_success(&sync(&["sync", "--update"]), "sync --update");
    let updated = fs::read_to_string(&lock_path).unwrap();
    assert!(updated.contains(&sha256_hex(OTHER_JAR)), "{updated}");
    assert_success(&sync(&["sync", "--frozen"]), "frozen sync of the new bytes");
}

/// A plugin file that `--allow-missing-checksums` accepted without a
/// checksum file is marked so in raeva.lock, as a dependency's is, and
/// `--frozen` warns about it.
#[test]
fn a_plugin_file_without_a_checksum_file_is_marked() {
    let server = repository_serving(|artifact| (JAR, artifact != "demo-maven-plugin"));
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    let refused = raeva(&["sync"]);
    assert!(!refused.status.success(), "{}", stderr(&refused));
    assert_success(
        &raeva(&["sync", "--allow-missing-checksums"]),
        "sync accepting the file",
    );
    let marked = || {
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert_eq!(lock.matches("missing_checksum = true").count(), 1, "{lock}");
    };
    marked();
    // Tables resolved again on a sync that reuses the dependencies keep it.
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ngoals = ['t:demo-maven-plugin:1:run']\n",
    )
    .unwrap();
    assert_success(
        &raeva(&["sync", "--allow-missing-checksums"]),
        "sync resolving the tables again",
    );
    marked();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_success(&frozen, "frozen sync");
    assert!(
        stderr(&frozen).contains("t/demo-maven-plugin/1/demo-maven-plugin-1.jar"),
        "{}",
        stderr(&frozen)
    );
}

/// A project whose `./mvnw` sources the mavenrc files as `bin/mvn` does
/// and writes `MAVEN_OPTS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|JAVA_TOOL_OPTIONS`
/// as it has them to `opts`, traced on a JDK 21.
#[cfg(unix)]
struct MavenrcTrace {
    _server: StubServer,
    project: TempDir,
    home: TempDir,
}

#[cfg(unix)]
impl MavenrcTrace {
    fn new() -> Self {
        let server = repository();
        let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
        let root = project.path();
        let launcher = fake_mvnw(root);
        let script = fs::read_to_string(&launcher).unwrap();
        let shown = "printf '%s|%s|%s|%s' \"$MAVEN_OPTS\" \"$_JAVA_OPTIONS\" \
                     \"$JDK_JAVA_OPTIONS\" \"$JAVA_TOOL_OPTIONS\" > \"$(dirname \"$0\")/opts\"\n";
        let sourcing = script.replacen(MVN_RC_BLOCK, &format!("{MVN_RC_BLOCK}{shown}"), 1);
        fs::write(&launcher, sourcing).unwrap();
        fs::write(
            root.join("raeva.toml"),
            "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
        )
        .unwrap();
        let jdk = home.path().join("jdk-21");
        fs::create_dir_all(&jdk).unwrap();
        fs::write(jdk.join("release"), "JAVA_VERSION=\"21.0.9\"\n").unwrap();
        Self {
            _server: server,
            project,
            home,
        }
    }

    /// A sync with `mavenrc` as `~/.mavenrc`, which also notes each run in
    /// `runs`.
    fn trace(&self, mavenrc: &str) -> std::process::Output {
        let (root, home) = (self.project.path(), self.home.path());
        fs::write(
            home.join(".mavenrc"),
            format!("echo run >> \"$HOME/runs\"\n{mavenrc}"),
        )
        .unwrap();
        for file in [
            root.join("raeva.lock"),
            root.join("opts"),
            home.join("runs"),
        ] {
            let _ = fs::remove_file(file);
        }
        let mut command = raeva_command(root, home);
        crate::common::isolate_maven_user_home(&mut command, home, "-Xmx1g");
        let command = (command.env("JAVA_HOME", home.join("jdk-21")))
            .env_remove("_JAVA_OPTIONS")
            .env_remove("JAVA_TOOL_OPTIONS")
            .env_remove("JDK_JAVA_OPTIONS");
        command.arg("sync").output().expect("run raeva")
    }

    /// What the launcher had, if it ran.
    fn opts(&self) -> Option<String> {
        fs::read_to_string(self.project.path().join("opts")).ok()
    }
}

/// A traced build whose launcher sources the mavenrc files as `bin/mvn`
/// does has them sourced once, in a shell raeva reads back, and then the
/// launcher with them skipped: a `MAVEN_OPTS` one sets unexported is the
/// build's, and `-XX:-UseBASE64Intrinsics` goes into `JDK_JAVA_OPTIONS`.
/// A file that turns the intrinsic back on, where the JVM reads it after,
/// refuses the trace before the build runs.
#[cfg(unix)]
#[test]
fn the_traced_mvn_sources_its_mavenrc_and_keeps_the_option() {
    let traced = MavenrcTrace::new();
    let home = traced.home.path();
    let base = format!("-Xmx2g -Duser.home={}", home.display());
    let output = traced.trace(&format!("MAVEN_OPTS='{base}'\n"));
    assert_success(&output, "traced sync");
    let opts = traced.opts().unwrap();
    assert_eq!(opts, format!("{base}||-XX:-UseBASE64Intrinsics|"));
    assert!(
        stderr(&output).contains("-XX:-UseBASE64Intrinsics added to JDK_JAVA_OPTIONS"),
        "{}",
        stderr(&output)
    );
    // Once for the lock, once for the build.
    let runs = fs::read_to_string(home.join("runs")).unwrap();
    assert_eq!(runs, "run\nrun\n");
    for back_on in [
        "export _JAVA_OPTIONS=\"$_JAVA_OPTIONS -XX:+UseBASE64Intrinsics\"\n",
        "MAVEN_OPTS=\"$MAVEN_OPTS -XX:+UseBASE64Intrinsics\"\n",
    ] {
        let output = traced.trace(back_on);
        assert_status(&output, 3, back_on);
        let said = stderr(&output);
        assert!(
            said.contains(".mavenrc") && said.contains("-XX:+UseBASE64Intrinsics"),
            "{said}"
        );
        assert_eq!(traced.opts(), None, "{back_on}");
    }
}

/// A mavenrc file that sets `_JAVA_OPTIONS`, which the JVM reads after
/// `JDK_JAVA_OPTIONS`, leaves the intrinsic off unless it turns it on, so
/// the trace runs with the file's value.
#[cfg(unix)]
#[test]
fn a_mavenrc_java_options_leave_the_traced_build_hardened() {
    let traced = MavenrcTrace::new();
    for (mavenrc, java_options) in [
        ("export _JAVA_OPTIONS=-Xmx512m\n", "-Xmx512m"),
        (
            "export _JAVA_OPTIONS=\"$_JAVA_OPTIONS -Xss2m\"\n",
            " -Xss2m",
        ),
        ("unset _JAVA_OPTIONS\n", ""),
    ] {
        assert_success(&traced.trace(mavenrc), mavenrc);
        let opts = traced.opts().unwrap();
        let ending = format!("|{java_options}|-XX:-UseBASE64Intrinsics|");
        assert!(opts.ends_with(&ending), "{mavenrc}: {opts}");
    }
}

/// A guard on a JVM variable in a mavenrc file sees none raeva sets, as
/// with the user's `mvn`, and the option goes after what the file leaves;
/// a value the shell holds unexported is not the JVM's.
#[cfg(unix)]
#[test]
fn a_mavenrc_guard_sees_no_option_raeva_adds() {
    let traced = MavenrcTrace::new();
    let guards = "if [ -z \"$JAVA_TOOL_OPTIONS\" ]; then export JAVA_TOOL_OPTIONS=-Dg=1; fi\n\
                  if [ -z \"$JDK_JAVA_OPTIONS\" ]; then export JDK_JAVA_OPTIONS=-Dh=1; fi\n";
    assert_success(&traced.trace(guards), "guards");
    let opts = traced.opts().unwrap();
    assert!(
        opts.ends_with("||-Dh=1 -XX:-UseBASE64Intrinsics|-Dg=1"),
        "{opts}"
    );
    assert_success(&traced.trace("JDK_JAVA_OPTIONS=-Dh=1\n"), "unexported");
    let opts = traced.opts().unwrap();
    assert!(opts.ends_with("||-XX:-UseBASE64Intrinsics|"), "{opts}");
}

/// A launcher that runs a `bin/mvn` of its own, as the Maven Wrapper's
/// only-script `mvnw` does, runs after the shell sourced the mavenrc files
/// once, with `MAVEN_SKIP_RC` exported, so that `bin/mvn` skips them: what
/// they export is the build's. One they set without exporting it, which
/// only that `bin/mvn` would have, refuses the trace, as `MAVEN_SKIP_RC`
/// in `allow_env_substitution` does, which the build would then see.
#[cfg(unix)]
#[test]
fn a_launcher_that_runs_its_own_mvn_traces_with_the_files_skipped() {
    let traced = MavenrcTrace::new();
    let (root, home) = (traced.project.path(), traced.home.path());
    let inner = root.join("dist/bin");
    fs::create_dir_all(&inner).unwrap();
    fs::rename(root.join("mvnw"), inner.join("mvn")).unwrap();
    fs::rename(root.join("tool.jar"), inner.join("tool.jar")).unwrap();
    fs::write(
        root.join("mvnw"),
        "#!/bin/sh\nset -euf\nexec \"$(dirname \"$0\")/dist/bin/mvn\" \"$@\"\n",
    )
    .unwrap();
    let executable = std::os::unix::fs::PermissionsExt::from_mode(0o755);
    fs::set_permissions(root.join("mvnw"), executable).unwrap();
    let opts = || fs::read_to_string(inner.join("opts")).ok();
    let base = format!("-Xmx2g -Duser.home={}", home.display());
    let output = traced.trace(&format!("export MAVEN_OPTS='{base}'\n"));
    assert_success(&output, "traced sync");
    assert_eq!(
        opts().unwrap(),
        format!("{base}||-XX:-UseBASE64Intrinsics|")
    );
    // Once for the lock, once for the build, not again in its bin/mvn.
    let runs = fs::read_to_string(home.join("runs")).unwrap();
    assert_eq!(runs, "run\nrun\n");
    fs::remove_file(inner.join("opts")).unwrap();
    // The environment exports MAVEN_OPTS, so only a new variable can be
    // unexported.
    let output = traced.trace("MAVEN_DEBUG_OPTS=-Dd=1\n");
    assert_status(&output, 3, "unexported");
    let said = stderr(&output);
    assert!(
        said.contains("set MAVEN_DEBUG_OPTS without exporting it"),
        "{said}"
    );
    assert_eq!(opts(), None);
    fs::write(
        home.join("config.toml"),
        "[security]\nallow_env_substitution = [\"MAVEN_SKIP_RC\"]\n",
    )
    .unwrap();
    let output = traced.trace(&format!("export MAVEN_OPTS='{base}'\n"));
    assert_status(&output, 3, "allowed");
    let said = stderr(&output);
    assert!(said.contains("env.MAVEN_SKIP_RC"), "{said}");
    assert_eq!(opts(), None);
}

/// On Windows `mvn.cmd` sources `mavenrc_pre` again after raeva read it,
/// so a file that reads `JDK_JAVA_OPTIONS`, where raeva gives the traced
/// build `-XX:-UseBASE64Intrinsics`, refuses the trace before the build
/// runs, as one that turns the intrinsic back on does, and one that gives
/// a variable another value each run, which raeva could not hide.
#[cfg(windows)]
#[test]
fn a_mavenrc_pre_that_may_drop_the_option_refuses_the_trace() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let (root, home) = (project.path(), home.path());
    fs::write(
        root.join("mvnw.cmd"),
        "@echo off\r\necho run>> \"%~dp0ran\"\r\n",
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let jdk = home.join("jdk-21");
    fs::create_dir_all(&jdk).unwrap();
    fs::write(jdk.join("release"), "JAVA_VERSION=\"21.0.9\"\n").unwrap();
    for (mavenrc, said) in [
        ("set JDK_JAVA_OPTIONS=-Dx=1\r\n", "reads JDK_JAVA_OPTIONS"),
        (
            "if not defined JDK_JAVA_OPTIONS set \"MAVEN_OPTS=%MAVEN_OPTS% -Dg=1\"\r\n",
            "reads JDK_JAVA_OPTIONS",
        ),
        (
            "set REPO_TOKEN=%RANDOM%%RANDOM%%TIME%\r\n",
            "gives REPO_TOKEN another value each time",
        ),
        (
            "set \"MAVEN_OPTS=%MAVEN_OPTS% -XX:+UseBASE64Intrinsics\"\r\n",
            "-XX:+UseBASE64Intrinsics",
        ),
    ] {
        fs::write(
            home.join("mavenrc_pre.bat"),
            format!("@echo off\r\n{mavenrc}"),
        )
        .unwrap();
        let mut command = raeva_command(root, home);
        crate::common::isolate_maven_user_home(&mut command, home, "-Xmx1g");
        let command = (command.env("JAVA_HOME", &jdk))
            .env_remove("_JAVA_OPTIONS")
            .env_remove("JAVA_TOOL_OPTIONS")
            .env_remove("JDK_JAVA_OPTIONS");
        let output = command.arg("sync").output().expect("run raeva");
        assert_status(&output, 3, mavenrc);
        let says = stderr(&output);
        assert!(
            says.contains("mavenrc_pre.bat") && says.contains(said),
            "{says}"
        );
        assert!(!root.join("ran").exists(), "{mavenrc}");
    }
}

/// `MAVEN_ARGS` reaches the traced build's launcher as the user's, so a
/// mavenrc file that tests it does as for the user's `mvn`.
#[cfg(unix)]
#[test]
fn the_traced_build_keeps_maven_args() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    let shown = "printf '%s' \"$MAVEN_ARGS\" > \"$(dirname \"$0\")/args\"\n";
    let shown = script.replacen(MVN_RC_BLOCK, &format!("{MVN_RC_BLOCK}{shown}"), 1);
    fs::write(&launcher, shown).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    fs::write(
        home.path().join(".mavenrc"),
        "if [ -z \"$MAVEN_ARGS\" ]; then MAVEN_ARGS=-Dfrom.rc=1; fi\n",
    )
    .unwrap();
    let output = raeva_command(root, home.path())
        .env("MAVEN_ARGS", "-Dz=1")
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&output, "traced sync");
    assert_eq!(fs::read_to_string(root.join("args")).unwrap(), "-Dz=1");
}

/// The traced build would run only the modules a reactor selection of
/// `MAVEN_ARGS`, `.mvn/maven.config` or a `MAVEN_CONFIG` a wrapper script
/// passes picks, so the trace refuses (exit
/// 3), naming the option, before the build runs; `--frozen`, which runs
/// no build, takes it.
#[cfg(unix)]
#[test]
fn a_reactor_selection_refuses_the_trace() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |maven_args: &str, args: &[&str]| {
        raeva_command(root, home.path())
            .env("MAVEN_ARGS", maven_args)
            .args(args)
            .output()
            .expect("run raeva")
    };
    for (maven_args, named) in [("-B -pl app -am", "-pl"), ("--also-make", "-am")] {
        let output = raeva(maven_args, &["sync"]);
        assert_status(&output, 3, maven_args);
        let said = stderr(&output);
        assert!(
            said.contains("MAVEN_ARGS")
                && said.contains(named)
                && said.contains("would not build the whole reactor"),
            "{maven_args}: {said}"
        );
        assert!(!root.join("ran").exists(), "{maven_args}");
    }
    let maven_config = root.join(".mvn/maven.config");
    fs::write(&maven_config, "-Dext.version=2\n-N\n").unwrap();
    let output = raeva("", &["sync"]);
    assert_status(&output, 3, "maven.config -N");
    let said = stderr(&output);
    assert!(
        said.contains(".mvn/maven.config") && said.contains("-N"),
        "{said}"
    );
    assert!(!root.join("ran").exists());
    fs::write(&maven_config, "-Dext.version=2\n").unwrap();
    // A Maven Wrapper script of the `script` type passes `MAVEN_CONFIG`.
    let mvnw = root.join("mvnw");
    let script = fs::read_to_string(&mvnw).unwrap();
    fs::write(
        &mvnw,
        format!("{script}# ${{WRAPPER_LAUNCHER}} $MAVEN_CONFIG\n"),
    )
    .unwrap();
    let output = raeva_command(root, home.path())
        .env("MAVEN_CONFIG", "-pl app")
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_status(&output, 3, "MAVEN_CONFIG -pl");
    let said = stderr(&output);
    assert!(
        said.contains("MAVEN_CONFIG") && said.contains("would not build the whole reactor"),
        "{said}"
    );
    assert!(!root.join("ran").exists());
    assert_success(&raeva("", &["sync"]), "traced sync");
    assert_success(
        &raeva("-pl app -am", &["sync", "--frozen"]),
        "frozen sync with MAVEN_ARGS -pl",
    );
}

/// A process a mavenrc file leaves running holds the traced build's output
/// open, as it does a terminal's; the sync ends when the build has.
#[cfg(unix)]
#[test]
fn a_process_a_mavenrc_leaves_does_not_hold_the_trace() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let pids = home.path().join("pids");
    fs::write(
        home.path().join(".mavenrc"),
        format!("sleep 120 &\necho $! >> '{}'\n", pids.display()),
    )
    .unwrap();
    let started = std::time::Instant::now();
    let output = raeva_command(root, home.path())
        .arg("sync")
        .output()
        .expect("run raeva");
    let took = started.elapsed();
    for pid in fs::read_to_string(&pids).unwrap_or_default().lines() {
        let _ = std::process::Command::new("kill").arg(pid.trim()).status();
    }
    assert_success(&output, "traced sync");
    assert!(took < std::time::Duration::from_secs(60), "{took:?}");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:tool:1"), "{lock}");
}

/// A mavenrc file that fetches a token anew each time it runs, as for
/// CodeArtifact, in a variable named like a secret, traces the build, and
/// raeva shows nothing the build prints of it.
#[cfg(unix)]
#[test]
fn a_token_a_mavenrc_fetches_anew_traces_the_build() {
    let count = "n=$(cat \"$HOME/n\" 2>/dev/null || echo 0); echo $((n+1)) > \"$HOME/n\"\n";
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    fs::write(
        home.path().join(".mavenrc"),
        format!("{count}export CODEARTIFACT_AUTH_TOKEN=\"zqNEW${{n}}zq\"\n"),
    )
    .unwrap();
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    fs::write(
        &launcher,
        format!("{script}echo \"token=$CODEARTIFACT_AUTH_TOKEN\" >&2\n"),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let output = raeva_command(root, home.path())
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&output, "traced sync");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
    assert!(!said.contains("zqNEW"), "{said}");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:tool:1"), "{lock}");
}

/// A mavenrc file that gives a value anew each time it runs, such as a
/// JVM option, quoted or in an argument file it writes, or a settings.xml
/// password, fails the sync before the traced build starts: the build
/// would not run with the value raeva resolved with and keyed the trace
/// by. Neither value is shown.
#[cfg(unix)]
#[test]
fn a_value_a_mavenrc_makes_anew_refuses_the_trace() {
    let count = "n=$(cat \"$HOME/n\" 2>/dev/null || echo 0); echo $((n+1)) > \"$HOME/n\"\n";
    let cases = [
        (
            "quoted",
            "export JDK_JAVA_OPTIONS=\"-Dbuild.value='zqNEW${n}zq'\"\n",
            "JDK_JAVA_OPTIONS",
        ),
        (
            "unexported",
            "MAVEN_OPTS=\"-Dbuild.value=zqNEW${n}zq\"\n",
            "MAVEN_OPTS",
        ),
        (
            "argument file",
            "printf '%s\\n' \"-Dbuild.value=zqNEW${n}zq\" > \"$HOME/session.jvm\"\n\
             export JDK_JAVA_OPTIONS=\"@$HOME/session.jvm\"\n",
            "the option file JDK_JAVA_OPTIONS names",
        ),
        (
            "jvm.config",
            "mkdir -p .mvn; printf '%s\\n' \"-Dbuild.value=zqNEW${n}zq\" > .mvn/jvm.config\n",
            ".mvn/jvm.config",
        ),
        (
            "new jvm.config",
            "[ \"$n\" -ge 1 ] && { mkdir -p .mvn; printf '%s\\n' -Dx=1 > .mvn/jvm.config; }\n",
            ".mvn/jvm.config",
        ),
        (
            "settings",
            "printf '<!-- %s -->\\n' \"zqNEW${n}zq\" >> \"$HOME/.m2/settings.xml\"\n",
            "a settings file",
        ),
    ];
    for (case, set, named) in cases {
        let server = repository();
        let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
        fs::write(home.path().join(".mavenrc"), format!("{count}{set}")).unwrap();
        let root = project.path();
        let launcher = fake_mvnw(root);
        let script = fs::read_to_string(&launcher).unwrap();
        fs::write(&launcher, format!("{script}echo BUILD-RAN\n")).unwrap();
        fs::write(
            root.join("raeva.toml"),
            "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
        )
        .unwrap();
        let jdk = home.path().join("jdk-21");
        fs::create_dir_all(&jdk).unwrap();
        fs::write(jdk.join("release"), "JAVA_VERSION=\"21.0.9\"\n").unwrap();
        let user_home = format!("-Duser.home={}", home.path().display());
        let output = raeva_command(root, home.path())
            .env("JAVA_HOME", &jdk)
            .args([&user_home, "sync"])
            .output()
            .expect("run raeva");
        assert_status(&output, 3, case);
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            stderr(&output)
        );
        assert!(
            said.contains(&format!("gives {named} another value each time it runs")),
            "{case}: {said}"
        );
        assert!(
            !said.contains("zqNEW") && !said.contains("BUILD-RAN"),
            "{case}: {said}"
        );
    }
}

/// A value the mavenrc files make anew, print and unset does not refuse the
/// trace, and a `set -a` they leave on exports none of raeva's own
/// variables, which would: the build runs, and raeva shows nothing it or
/// the files print.
#[cfg(unix)]
#[test]
fn the_mavenrc_files_print_and_export_nothing_into_a_trace() {
    let mavenrc = "n=$(cat \"$HOME/n\" 2>/dev/null || echo 0); echo $((n+1)) > \"$HOME/n\"\n\
                   TOKEN=\"zqPRINTED${n}zq\"; printf '%s\\n' \"$TOKEN\"; unset TOKEN n\n\
                   set -a\nBUILD_VALUE=stable\n\
                   JDK_JAVA_OPTIONS='-XshowSettings:properties -Dbuild.value=zqSTABLEzq'\n";
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    fs::write(home.path().join(".mavenrc"), mavenrc).unwrap();
    let settings = home.path().join(".m2/settings.xml");
    let text = fs::read_to_string(&settings).unwrap().replace(
        "<mirrors>",
        "<servers><server><id>stub</id><username>u</username>\
         <password>prefix-${build.value}</password></server></servers><mirrors>",
    );
    fs::write(&settings, text).unwrap();
    let jdk = home.path().join("jdk-21");
    fs::create_dir_all(&jdk).unwrap();
    fs::write(jdk.join("release"), "JAVA_VERSION=\"21.0.9\"\n").unwrap();
    // As the JVM prints its system properties.
    let echo = "eval \"set -- $JDK_JAVA_OPTIONS\"; for a; do case $a in -D*) \
                v=${a#-D}; echo \"    ${v%%=*} = ${v#*=}\";; esac; done";
    let jdk = jdk.display().to_string();
    let said = failed_trace(&project, &home, "['verify']", echo, &[("JAVA_HOME", &jdk)]);
    for marker in ["zqPRINTED", "zqSTABLE"] {
        assert!(!said.contains(marker), "{marker}: {said}");
    }
}

/// A part of a password in the settings file `.mvn/maven.config` names
/// with `-s`, here quoted with a space in it, which a JVM option variable's
/// `-D` gives, is not shown where the JVM prints its system properties.
#[cfg(unix)]
#[test]
fn a_credential_part_in_the_settings_maven_config_names_is_not_shown() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    fs::write(
        home.path().join(".mavenrc"),
        "export JDK_JAVA_OPTIONS='-XshowSettings:properties -Dbuild.value=zqPARTzq'\n",
    )
    .unwrap();
    let root = project.path();
    let text = fs::read_to_string(home.path().join(".m2/settings.xml"))
        .unwrap()
        .replace(
            "<mirrors>",
            "<servers><server><id>stub</id><username>u</username>\
         <password>prefix-${build.value}</password></server></servers><mirrors>",
        );
    let custom = root.join("team settings.xml");
    fs::write(&custom, text).unwrap();
    let config = root.join(".mvn/maven.config");
    let held = fs::read_to_string(&config).unwrap_or_default();
    fs::write(&config, format!("{held}-s\n\"{}\"\n", custom.display())).unwrap();
    let jdk = home.path().join("jdk-21");
    fs::create_dir_all(&jdk).unwrap();
    fs::write(jdk.join("release"), "JAVA_VERSION=\"21.0.9\"\n").unwrap();
    let echo = "eval \"set -- $JDK_JAVA_OPTIONS\"; for a; do case $a in -D*) \
                v=${a#-D}; echo \"    ${v%%=*} = ${v#*=}\";; esac; done";
    let jdk = jdk.display().to_string();
    let said = failed_trace(&project, &home, "['verify']", echo, &[("JAVA_HOME", &jdk)]);
    assert!(!said.contains("zqPART"), "{said}");
}

/// `.mvn/jvm.config` naming an argument file by a relative path, which
/// raeva reads from the directory it runs in, as `mvn -f` does, refuses the
/// trace when that is not the project directory the traced `mvn` runs in.
#[cfg(unix)]
#[test]
fn a_relative_option_file_refuses_a_trace_from_another_directory() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let elsewhere = root.join("elsewhere");
    for dir in [root.to_path_buf(), elsewhere.clone()] {
        fs::create_dir_all(dir.join(".mvn")).unwrap();
        fs::write(dir.join(".mvn/x.args"), "-Dx=1\n").unwrap();
    }
    fs::write(root.join(".mvn/jvm.config"), "@.mvn/x.args\n").unwrap();
    let mut command = raeva_command(root, home.path());
    let refused = command
        .current_dir(&elsewhere)
        .arg("sync")
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(3), "{}", stderr(&refused));
    let said = stderr(&refused);
    assert!(
        said.contains("gives a path relative to the directory raeva runs in"),
        "{said}"
    );
    let mut command = raeva_command(root, home.path());
    let traced = command.current_dir(root).arg("sync").output().unwrap();
    assert!(
        !stderr(&traced).contains("by a path relative"),
        "{}",
        stderr(&traced)
    );
}

/// A `plugins.mvn` command name that is on no `PATH` is a configuration
/// error of raeva.toml that names the setting.
#[test]
fn a_plugins_mvn_that_is_not_found_is_a_configuration_error() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = 'no-such-mvn-xyz'\n",
    )
    .unwrap();
    let output = run_raeva(root, home.path(), &["sync"]);
    assert_status(&output, 3, "a plugins.mvn on no PATH");
    let said = stderr(&output);
    assert!(said.contains("plugins.mvn"), "{said}");
    assert!(said.contains("no-such-mvn-xyz is not found"), "{said}");
}

/// A file the traced build downloaded is fetched as the sync's are:
/// `--allow-missing-checksums` accepts one without a checksum file, and
/// raeva.lock marks it.
#[cfg(unix)]
#[test]
fn a_traced_file_without_a_checksum_file_is_marked() {
    let server = repository_serving(|artifact| (JAR, artifact != "tool"));
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    let refused = raeva(&["sync"]);
    assert!(!refused.status.success(), "{}", stderr(&refused));
    let accepted = raeva(&["sync", "--allow-missing-checksums"]);
    assert_success(&accepted, "sync accepting the traced file");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:tool:1"), "{lock}");
    assert_eq!(lock.matches("missing_checksum = true").count(), 1, "{lock}");
}

/// A build the traced one runs, here a test like maven-resolver's demos,
/// fills a local repository of its own below the project. It keeps what it
/// took from a repository the build has, but not a signature, which Maven
/// fetches without a checksum, nor a file its marker names by a key that
/// is no key of the build's repositories: that of a repository in the
/// project's sources, or Maven 3.10's `<id>-<sha1 of the URL>` for a URL
/// the build does not reach the id at, as for Central's by the demos.
/// Maven 3.10's key of the mirror or of a repository the build reaches
/// unmirrored is the build's, and so are two ids at one URL.
#[cfg(unix)]
#[test]
fn a_trace_pins_only_what_a_nested_build_took_from_the_builds_repositories() {
    use std::os::unix::fs::PermissionsExt;

    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let settings = home.path().join(".m2/settings.xml");
    let central = fs::read_to_string(&settings)
        .unwrap()
        .replace("<mirrorOf>*</mirrorOf>", "<mirrorOf>central</mirrorOf>");
    fs::write(&settings, central).unwrap();
    let declared = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        &format!(
            "<repositories><repository><id>plugins</id><url>{url}</url></repository>\
             <repository><id>releases</id><url>{}</url></repository></repositories><build>",
            url.trim_end_matches('/')
        ),
    );
    fs::write(root.join("pom.xml"), declared).unwrap();
    let launcher = root.join("mvnw");
    let pom = |artifact: &str, extra: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>n</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version>\
             <packaging>maven-plugin</packaging></project>{extra}"
        )
    };
    // Maven 3.10 keys a download by the id and the SHA-1 of the URL as the
    // settings and the POM spell it, here with a `/` and without.
    let hashed = |id: &str, url: &str| format!("{id}-{}", crate::common::sha1_hex(url.as_bytes()));
    let mirror = hashed("stub", &url);
    let releases = hashed("releases", url.trim_end_matches('/'));
    let demos = hashed("central", "https://repo.maven.apache.org/maven2/");
    let mut script = String::from("#!/bin/sh\nr=\"$(dirname \"$0\")/target/repo/n\"\n");
    for (artifact, extra, files, id) in [
        ("lib", "", "lib-1.jar.asc lib-1.pom", "stub"),
        ("ten", "", "ten-1.pom", mirror.as_str()),
        ("tenrel", "", "tenrel-1.pom", releases.as_str()),
        ("demo", "", "demo-1.pom", demos.as_str()),
        (
            "maven-metadata-api",
            "",
            "maven-metadata-api-1.pom",
            "releases",
        ),
        (
            "own",
            "<!-- own -->",
            "own-1.pom",
            "remote-e9c8912e88022ae6b134fcf0db4bae5296625e3a",
        ),
        (
            "far",
            "",
            "far-1.pom",
            "stub-0aeeb43004cebeccad6fdf0fec27084167d5880a",
        ),
    ] {
        script.push_str(&format!(
            "mkdir -p \"$r/{artifact}/1\"\nprintf '%s' '{}' > \"$r/{artifact}/1/{artifact}-1.pom\"\n\
             echo sig > \"$r/{artifact}/1/{artifact}-1.jar.asc\"\n",
            pom(artifact, extra)
        ));
        for file in files.split(' ') {
            script.push_str(&format!(
                "printf '{file}>{id}=\\n' >> \"$r/{artifact}/1/_remote.repositories\"\n"
            ));
        }
    }
    fs::write(&launcher, script).unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let traced = run_raeva(root, home.path(), &["sync"]);
    assert_success(&traced, "traced sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for kept in ["n:lib:1", "n:maven-metadata-api:1", "n:ten:1", "n:tenrel:1"] {
        assert!(lock.contains(kept), "{kept}: {lock}");
    }
    for left in ["n:own:1", "n:far:1", "n:demo:1", "asc"] {
        assert!(!lock.contains(left), "{left}: {lock}");
    }
}

/// `[plugins] trace` runs the build once on a plain online sync with the
/// project's launcher, and pins what it downloaded; `--frozen`, `--offline`
/// and the export never run it, and `--frozen` refuses a lock whose trace
/// another build or launcher made.
#[cfg(unix)]
#[test]
fn a_sync_traces_the_build_the_settings_name() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let settings = root.join("raeva.toml");
    let traced = |args: &str| format!("[plugins]\nlock = true\ntrace = [{args}]\nmvn = './mvnw'\n");
    fs::write(&settings, traced("'verify'")).unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    let runs = || {
        fs::read_to_string(root.join("ran"))
            .unwrap_or_default()
            .lines()
            .count()
    };
    let lock_path = root.join("raeva.lock");
    let first = raeva(&["sync"]);
    assert_success(&first, "traced sync");
    // The export the build runs on prints nothing of its own.
    for inner in ["is up to date", "Exporting artifacts"] {
        assert!(
            !stderr(&first).contains(inner),
            "{inner}: {}",
            stderr(&first)
        );
    }
    assert_eq!(runs(), 1);
    let tables = fs::read_to_string(&lock_path).unwrap();
    assert!(tables.contains("role = \"trace\""), "{tables}");
    assert!(tables.contains("t:tool:1"), "{tables}");
    assert_success(&raeva(&["sync"]), "sync with the trace current");
    let m2 = home.path().join("m2");
    assert_success(
        &raeva(&["export-m2", "--m2-path", m2.to_str().unwrap()]),
        "export",
    );
    assert_eq!(fs::read(m2.join("t/tool/1/tool-1.jar")).unwrap(), JAR);
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    assert_eq!(
        runs(),
        1,
        "a current trace, a check and an export run nothing"
    );

    // Other arguments make the trace stale: --frozen refuses it and runs
    // nothing, an offline sync keeps it for the trace that replaces it, a
    // plain sync traces again and says it updated raeva.lock.
    fs::write(&settings, traced("'verify', '-DskipTests'")).unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert!(
        stderr(&frozen).contains("holds a trace for platform")
            && stderr(&frozen).contains("of another build"),
        "{}",
        stderr(&frozen)
    );
    let offline = raeva(&["--offline", "sync"]);
    assert_success(&offline, "offline sync");
    assert!(
        stderr(&offline).contains("runs online only"),
        "{}",
        stderr(&offline)
    );
    let tables = fs::read_to_string(&lock_path).unwrap();
    assert!(tables.contains("t:tool:1"), "{tables}");
    let frozen = raeva(&["sync", "--frozen"]);
    assert!(
        stderr(&frozen).contains("of another build"),
        "{}",
        stderr(&frozen)
    );
    assert_eq!(runs(), 1);
    let again = raeva(&["sync"]);
    assert_success(&again, "sync tracing again");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&again.stdout),
        stderr(&again)
    );
    assert!(
        said.contains("updated raeva.lock") && said.contains("plugin trace added"),
        "{said}"
    );
    assert_eq!(runs(), 2);
    assert_success(
        &raeva(&["sync", "--frozen"]),
        "frozen sync of the new trace",
    );

    // A launcher a link leads out of the project is refused although the
    // trace of its name is current, by --frozen too.
    fs::rename(&launcher, root.join("mvnw.real")).unwrap();
    std::os::unix::fs::symlink("/bin/sh", &launcher).unwrap();
    for args in [&["sync"][..], &["sync", "--frozen"]] {
        let refused = raeva(args);
        assert!(
            stderr(&refused).contains("leads out of the project"),
            "{args:?}: {}",
            stderr(&refused)
        );
    }
    fs::remove_file(&launcher).unwrap();
    fs::rename(root.join("mvnw.real"), &launcher).unwrap();

    // Without `trace`, --frozen refuses the trace and a sync drops it.
    fs::write(&settings, "[plugins]\nlock = true\n").unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert!(
        stderr(&frozen).contains("holds a trace"),
        "{}",
        stderr(&frozen)
    );
    assert_success(&raeva(&["sync"]), "sync dropping the trace");
    let tables = fs::read_to_string(&lock_path).unwrap();
    assert!(!tables.contains("t:tool:1"), "{tables}");
    assert_eq!(runs(), 2);

    // A launcher outside the project is refused before anything runs.
    for mvn in ["/bin/sh", "../mvnw"] {
        fs::write(
            &settings,
            format!("[plugins]\nlock = true\ntrace = ['verify']\nmvn = '{mvn}'\n"),
        )
        .unwrap();
        let refused = raeva(&["sync"]);
        assert!(!refused.status.success(), "{mvn}");
        assert!(
            stderr(&refused).contains("plugins.mvn"),
            "{}",
            stderr(&refused)
        );
    }
    let link = root.join("link");
    std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
    fs::write(&settings, traced("'verify'").replace("./mvnw", "./link")).unwrap();
    let refused = raeva(&["sync"]);
    assert!(
        stderr(&refused).contains("leads out of the project"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(runs(), 2);
}

/// A `[plugins] trace` added after the sync leaves raeva.lock without the
/// trace: the commands that check freshness refuse it as `--frozen` does,
/// and a plain sync traces the build.
#[cfg(unix)]
#[test]
fn a_trace_asked_for_after_the_sync_fails_the_freshness_check() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    let settings = root.join("raeva.toml");
    fs::write(&settings, "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "untraced sync");
    fs::write(
        &settings,
        "[plugins]\nlock = true\ntrace = ['validate']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let m2 = home.path().join("m2");
    for args in [
        &["sync", "--frozen"][..],
        &["export-m2", "--m2-path", m2.to_str().unwrap()],
        &["export-checksums"],
        &["sbom"],
    ] {
        let refused = raeva(args);
        assert_status(&refused, 7, &format!("{args:?}"));
        assert!(
            stderr(&refused).contains("raeva.lock has no trace for")
                && stderr(&refused).contains("of the build [plugins] trace and mvn"),
            "{args:?}: {}",
            stderr(&refused)
        );
    }
    assert!(!m2.exists());
    assert!(!root.join("ran").exists());
    assert_success(&raeva(&["sync"]), "traced sync");
    assert_success(
        &raeva(&["export-m2", "--m2-path", m2.to_str().unwrap()]),
        "export of the traced lock",
    );
}

/// The traced build's JVM gets `-XX:-UseBASE64Intrinsics` in
/// `JDK_JAVA_OPTIONS` when the JDK's release file names 11 or later, and
/// none for a JDK 8, which refuses the option, or one only `JAVA_VERSION`
/// names. `MAVEN_OPTS` stays the user's.
#[cfg(unix)]
#[test]
fn the_traced_jvm_turns_off_base64_intrinsics_only_on_a_jdk_that_has_them() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    let logged = script.replacen(
        '\n',
        "\nprintf '%s|%s|%s' \"$MAVEN_OPTS\" \"$JDK_JAVA_OPTIONS\" \"$JAVA_TOOL_OPTIONS\" \
         > \"$(dirname \"$0\")/opts\"\n",
        1,
    );
    fs::write(&launcher, logged).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let jdk = |name: &str, version: &str| {
        let jdk = home.path().join(name);
        fs::create_dir_all(&jdk).unwrap();
        fs::write(jdk.join("release"), format!("JAVA_VERSION=\"{version}\"\n")).unwrap();
        jdk
    };
    let (jdk21, jdk8) = (jdk("jdk-21", "21.0.9"), jdk("jdk-8", "1.8.0_442"));
    let trace = |env: &[(&str, &std::path::Path)]| {
        let _ = fs::remove_file(root.join("raeva.lock"));
        let mut command = raeva_command(root, home.path());
        crate::common::isolate_maven_user_home(&mut command, home.path(), "-Xmx1g");
        command
            .env_remove("JDK_JAVA_OPTIONS")
            .env_remove("JAVA_TOOL_OPTIONS");
        for (name, value) in env {
            command.env(name, value);
        }
        let output = command.arg("sync").output().expect("run raeva");
        assert_success(&output, "traced sync");
        (
            fs::read_to_string(root.join("opts")).unwrap(),
            stderr(&output),
        )
    };
    let base = format!("-Xmx1g -Duser.home={}", home.path().display());
    let (opts, said) = trace(&[("JAVA_HOME", &jdk21)]);
    assert_eq!(opts, format!("{base}|-XX:-UseBASE64Intrinsics|"));
    assert!(
        said.contains("from raeva.toml, -XX:-UseBASE64Intrinsics added to JDK_JAVA_OPTIONS\n"),
        "{said}"
    );
    let (opts, said) = trace(&[("JAVA_HOME", &jdk8)]);
    assert_eq!(opts, format!("{base}||"));
    assert!(!said.contains("UseBASE64Intrinsics"), "{said}");
    let (opts, _) = trace(&[("JAVA_VERSION", std::path::Path::new("21"))]);
    assert_eq!(opts, format!("{base}||"));
}

/// A JVM that does not know `-XX:-UseBASE64Intrinsics`, such as a JDK 8 a
/// launcher switches to, refuses to start with it: raeva traces once more
/// without it and says so. Any other failure ends the sync.
#[cfg(unix)]
#[test]
fn a_trace_whose_jvm_rejects_the_option_runs_again_without_it() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    let refusing = script.replacen(
        '\n',
        "\nprintf '%s\\n' \"$JDK_JAVA_OPTIONS\" >> \"$(dirname \"$0\")/opts\"\n\
         case \"$JDK_JAVA_OPTIONS\" in *UseBASE64Intrinsics*) \
         echo \"Unrecognized VM option 'UseBASE64Intrinsics'\" >&2; \
         echo 'Error: Could not create the Java Virtual Machine.' >&2; \
         echo 'Error: A fatal exception has occurred. Program will exit.' >&2; exit 1;; esac\n",
        1,
    );
    fs::write(&launcher, &refusing).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let jdk = home.path().join("jdk-21");
    fs::create_dir_all(&jdk).unwrap();
    fs::write(jdk.join("release"), "JAVA_VERSION=\"21.0.9\"\n").unwrap();
    let mut command = raeva_command(root, home.path());
    crate::common::isolate_maven_user_home(&mut command, home.path(), "-Xmx1g");
    command.env("JDK_JAVA_OPTIONS", "-Xss2m");
    let output = (command.env("JAVA_HOME", &jdk).arg("sync").output()).expect("run raeva");
    assert_success(&output, "traced sync");
    let opts = fs::read_to_string(root.join("opts")).unwrap();
    assert_eq!(opts, "-Xss2m -XX:-UseBASE64Intrinsics\n-Xss2m\n");
    let said = stderr(&output);
    let notes =
        (said.lines()).filter(|line| line.contains("does not know -XX:-UseBASE64Intrinsics"));
    assert_eq!(notes.count(), 1, "{said}");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:tool:1"), "{lock}");

    // A build that fails otherwise is not run again.
    fs::remove_file(root.join("opts")).unwrap();
    fs::remove_file(root.join("raeva.lock")).unwrap();
    let failing = refusing.replace("Unrecognized VM option", "Some other failure of");
    fs::write(&launcher, failing).unwrap();
    let output = raeva_command(root, home.path())
        .env("JAVA_HOME", &jdk)
        .env_remove("JDK_JAVA_OPTIONS")
        .arg("sync")
        .output()
        .expect("run raeva");
    assert!(!output.status.success(), "{}", stderr(&output));
    assert_eq!(
        fs::read_to_string(root.join("opts"))
            .unwrap()
            .lines()
            .count(),
        1
    );
}

/// The traced build runs with raeva's `-D` and `-P` options and the
/// profiles raeva.toml selects and deselects, as the resolution did, and
/// the trace is keyed by them, so a sync with other options traces again.
#[cfg(unix)]
#[test]
fn a_trace_runs_with_the_profiles_and_properties_of_the_resolution() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    let logged = script.replacen('\n', "\necho \"$*\" >> \"$(dirname \"$0\")/args\"\n", 1);
    fs::write(&launcher, logged).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "active_profiles = ['on']\ninactive_profiles = ['off']\n\n[plugins]\nlock = true\n\
         trace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    let runs = || {
        (fs::read_to_string(root.join("args"))
            .unwrap_or_default()
            .lines())
        .map(|line| line.split(' ').map(str::to_string).collect::<Vec<_>>())
        .collect::<Vec<_>>()
    };
    let options = ["sync", "-Pcli", "-Dflag=1"];
    let traced = raeva(&options);
    assert_success(&traced, "traced sync with options");
    let said = stderr(&traced);
    assert!(
        said.contains("mvnw with 1 argument from raeva.toml and 4 -P or -D options\n"),
        "{said}"
    );
    // The build's local repository comes after the forwarded `-D` and the
    // arguments of raeva.toml, as Maven takes the last.
    let ran = runs();
    let at = |arg: &str| (ran[0].iter()).position(|ran| ran == arg);
    for option in ["-Dflag=1", "-Pcli", "-Pon", "-P!off", "verify"] {
        assert!(at(option).is_some(), "{option}: {ran:?}");
    }
    // No tail or head from .mvn/maven.config, settings.xml or MAVEN_OPTS
    // chains another local repository to the build's.
    let [.., repository, tail, head] = &ran[0][..] else {
        panic!("{ran:?}");
    };
    assert!(repository.starts_with("-Dmaven.repo.local="), "{ran:?}");
    assert_eq!(
        [tail, head],
        ["-Dmaven.repo.local.tail=", "-Dmaven.repo.local.head="]
    );
    assert_success(&raeva(&options), "sync with the trace current");
    assert_eq!(runs().len(), 1);
    let frozen = raeva(&["sync", "--frozen", "-Pcli"]);
    assert!(!frozen.status.success(), "{}", stderr(&frozen));
    let quiet = raeva(&["--quiet", "sync", "-Pcli"]);
    assert_success(&quiet, "quiet sync tracing again");
    assert!(!stderr(&quiet).contains("Tracing"), "{}", stderr(&quiet));
    let ran = runs();
    assert_eq!(ran.len(), 2);
    assert!(!ran[1].iter().any(|arg| arg.contains("flag=1")), "{ran:?}");
    assert_success(&raeva(&["sync", "--frozen", "-Pcli"]), "frozen sync");

    // So is a tail given to raeva, which is no other build.
    let tail = ["sync", "-Pcli", "-Dmaven.repo.local.tail=/elsewhere"];
    assert_success(&raeva(&tail), "sync with a tail");
    assert_eq!(runs().len(), 2);
    assert_success(
        &raeva(&[&tail[..], &["-Dflag=2"]].concat()),
        "sync with a tail",
    );
    let ran = runs();
    let at = |arg: &str| (ran[2].iter()).rposition(|ran| ran == arg);
    assert!(
        at("-Dmaven.repo.local.tail=") > at("-Dmaven.repo.local.tail=/elsewhere"),
        "{ran:?}"
    );

    // An id the build cannot be given as the resolution read it is refused
    // before anything runs.
    fs::write(
        root.join("raeva.toml"),
        "inactive_profiles = ['a,b']\n\n[plugins]\nlock = true\ntrace = ['verify']\n\
         mvn = './mvnw'\n",
    )
    .unwrap();
    let refused = raeva(&["sync"]);
    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("profile id \"a,b\""),
        "{}",
        stderr(&refused)
    );
    assert_eq!(runs().len(), 3);
}

/// The `-D` and `-P` options of `.mvn/maven.config`, which Maven reads as
/// options of its command line, key the trace as the same options given to
/// raeva do: one the file changes makes it stale, and moving one between
/// the file and the command line keeps it.
#[cfg(unix)]
#[test]
fn the_options_of_maven_config_key_the_trace_as_the_command_lines_do() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let maven_config = root.join(".mvn/maven.config");
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    fs::write(&maven_config, "-Dext.version=2\n-Dmy.prop=1\n-Pon\n").unwrap();
    assert_success(&raeva(&["sync"]), "traced sync");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    fs::write(&maven_config, "-Dext.version=2\n-Dmy.prop=2\n-Pon\n").unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    assert!(
        stderr(&frozen).contains("holds a trace"),
        "{}",
        stderr(&frozen)
    );
    // The command line's value wins, as in Maven.
    assert_success(
        &raeva(&["sync", "--frozen", "-Dmy.prop=1"]),
        "frozen sync with the -D the trace ran with",
    );
    fs::write(&maven_config, "-Dext.version=2\n").unwrap();
    assert_success(
        &raeva(&["sync", "--frozen", "-Dmy.prop=1", "-Pon"]),
        "frozen sync with the options on the command line",
    );
    fs::write(&maven_config, "-Dext.version=2\n-Dmy.prop=1\n").unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    let ran = (fs::read_to_string(root.join("ran")).unwrap())
        .lines()
        .count();
    assert_eq!(ran, 1);
}

/// The `-D` options of `.mvn/jvm.config`, which Maven's JVM reads as system
/// properties, key the trace too; its other JVM options do not.
#[cfg(unix)]
#[test]
fn the_system_properties_of_jvm_config_key_the_trace() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let jvm_config = root.join(".mvn/jvm.config");
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    fs::write(&jvm_config, "-Xmx256m -Dmy.prop=1\n").unwrap();
    assert_success(&raeva(&["sync"]), "traced sync");
    fs::write(&jvm_config, "-Xmx512m\n-Dmy.prop=1 -ea\n").unwrap();
    assert_success(
        &raeva(&["sync", "--frozen"]),
        "frozen sync with other JVM options",
    );
    fs::write(&jvm_config, "-Xmx256m -Dmy.prop=2\n").unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    assert!(
        stderr(&frozen).contains("holds a trace"),
        "{}",
        stderr(&frozen)
    );
    let ran = || {
        (fs::read_to_string(root.join("ran")).unwrap())
            .lines()
            .count()
    };
    assert_eq!(ran(), 1);
    // Maven sets its user properties as system properties too, so a `-D`
    // of the name hides the file's value from the build.
    assert_success(&raeva(&["sync", "-Dmy.prop=9"]), "traced sync with -D");
    fs::write(&jvm_config, "-Xmx256m -Dmy.prop=3\n").unwrap();
    assert_success(
        &raeva(&["sync", "--frozen", "-Dmy.prop=9"]),
        "frozen sync with the -D that hides the file's value",
    );
    assert_eq!(ran(), 2);
}

/// The `-D` options of an argument file `.mvn/jvm.config` names key the
/// trace as its own do, through a VM options file that one names too.
#[cfg(unix)]
#[test]
fn the_argument_files_of_jvm_config_key_the_trace() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    // The traced `mvn` reads a relative option file from the project.
    let raeva = |args: &[&str]| {
        let mut command = raeva_command(root, home.path());
        command.current_dir(root).args(args).output().unwrap()
    };
    fs::write(root.join(".mvn/jvm.config"), "@.mvn/opts\n").unwrap();
    let opts = root.join(".mvn/opts");
    fs::write(&opts, "-Dartifact=junit:junit:4.13.1\n").unwrap();
    assert_success(&raeva(&["sync"]), "traced sync");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    fs::write(&opts, "-Dartifact=junit:junit:4.13.2\n").unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    fs::write(&opts, "-XX:VMOptionsFile=.mvn/vm\n").unwrap();
    fs::write(root.join(".mvn/vm"), "-Dartifact=junit:junit:4.13.1\n").unwrap();
    assert_success(
        &raeva(&["sync", "--frozen"]),
        "frozen sync with the value in a VM options file",
    );
    fs::write(root.join(".mvn/vm"), "-Dartifact=junit:junit:4.13.2\n").unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
}

/// The `-D` options of `MAVEN_OPTS` key the trace too, as plugins read
/// them, such as `-Dartifact` for `dependency:get`; the local repository's,
/// the JDK's own and SLF4J's, which CI templates set, do not.
#[cfg(unix)]
#[test]
fn the_system_properties_of_maven_opts_key_the_trace() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |opts: &str, args: &[&str]| {
        let mut command = raeva_command(root, home.path());
        crate::common::isolate_maven_user_home(&mut command, home.path(), opts);
        command.args(args).output().unwrap()
    };
    assert_success(
        &raeva("-Dartifact=junit:junit:4.13.1", &["sync"]),
        "traced sync",
    );
    let ci = "-Dartifact=junit:junit:4.13.1 -Dhttps.protocols=TLSv1.2 \
              -Dmaven.repo.local=.m2/repository -Dorg.slf4j.simpleLogger.showDateTime=true \
              -Djava.awt.headless=true -Dmaven.wagon.http.retryHandler.count=3 \
              -Dmaven.wagon.http.pool=false -Dstyle.color=always -Xmx1g";
    assert_success(
        &raeva(ci, &["sync", "--frozen"]),
        "frozen sync with a CI template's MAVEN_OPTS",
    );
    // The message names only what keys the trace, not the local repository.
    let opts = "-Dartifact=junit:junit:4.13.2 -Dmaven.repo.local=.m2/repository";
    let frozen = raeva(opts, &["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    let said = stderr(&frozen);
    assert!(said.contains("-Dartifact in MAVEN_OPTS"), "{said}");
    assert!(!said.contains("maven.repo.local"), "{said}");
    let frozen = raeva("", &["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
}

/// A `-D` in `MAVEN_OPTS` whose name only starts like one the JVM owns,
/// such as os-maven-plugin's `os.detected.classifier`, which picks a
/// native artifact, or a POM's `java.source.version`, keys the trace; the
/// JVM's own `os.*`, `user.*`, `file.*`, `java.*`, `javax.*` and `http.*`
/// names do not.
#[cfg(unix)]
#[test]
fn a_property_beside_the_jvms_own_keys_the_trace() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |opts: &str, args: &[&str]| {
        let mut command = raeva_command(root, home.path());
        crate::common::isolate_maven_user_home(&mut command, home.path(), opts);
        command.args(args).output().unwrap()
    };
    let x86 = "-Dos.detected.classifier=linux-x86_64";
    assert_success(&raeva(x86, &["sync"]), "traced sync");
    let jvm = format!(
        "{x86} -Duser.timezone=UTC -Duser.language=en -Duser.country.format=GB \
         -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8"
    );
    assert_success(
        &raeva(&jvm, &["sync", "--frozen"]),
        "frozen sync with the JVM's own properties",
    );
    let frozen = raeva(
        "-Dos.detected.classifier=linux-aarch_64",
        &["sync", "--frozen"],
    );
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    let said = stderr(&frozen);
    assert!(
        said.contains("-Dos.detected.classifier in MAVEN_OPTS") && said.contains(".mvn/jvm.config"),
        "{said}"
    );
    // Nor do the JDK's own names under `java.`, `javax.` and `http.`, or the
    // resolver's lock factory, but a POM's own names there do, such as a
    // `java.source.version` a plugin's configuration reads.
    let tuned = format!(
        "{x86} -Djava.awt.headless=true -Djava.net.preferIPv4Stack=true \
         -Djava.security.egd=file:/dev/./urandom -Djava.io.tmpdir=/tmp -Djavax.net.debug=ssl \
         -Dhttp.keepAlive=false -Daether.syncContext.named.factory=file-lock"
    );
    assert_success(
        &raeva(&tuned, &["sync", "--frozen"]),
        "frozen sync with the JDK's tuning",
    );
    for name in [
        "java.source.version",
        "javax.annotation-api.version",
        "http.port",
    ] {
        let frozen = raeva(&format!("{x86} -D{name}=1"), &["sync", "--frozen"]);
        assert_eq!(frozen.status.code(), Some(7), "{name}: {}", stderr(&frozen));
        assert!(stderr(&frozen).contains(&format!("-D{name} in MAVEN_OPTS")));
    }
}

/// A `-D` in `MAVEN_OPTS` of the JDK's own names or in a namespace the
/// JDK, the transport or the console tunes keys the trace when a POM of the
/// project defines the name or reads it as `${name}`, such as a
/// `jdk.javadoc.doclet.version` or `os.version` a plugin's configuration
/// reads; one no POM names does not.
#[cfg(unix)]
#[test]
fn a_tuning_namespace_name_a_pom_reads_keys_the_trace() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><properties><com.sun.xml.bind.version>4\
             </com.sun.xml.bind.version></properties><build><plugins><plugin>\
             <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId><version>1</version>\
             <configuration><doclet>${jdk.javadoc.doclet.version}</doclet><os>${os.version}</os>\
             </configuration>\
             <executions><execution><phase>validate</phase><goals><goal>run</goal></goals>\
             </execution></executions></plugin></plugins></build>",
        ),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |opts: &str, args: &[&str]| {
        let mut command = raeva_command(root, home.path());
        crate::common::isolate_maven_user_home(&mut command, home.path(), opts);
        command.args(args).output().unwrap()
    };
    let doclet = "-Djdk.javadoc.doclet.version=2.3.1 -Dcom.sun.xml.bind.version=4 -Dos.version=1";
    assert_success(&raeva(doclet, &["sync"]), "traced sync");
    let tuned = format!(
        "{doclet} -Djdk.tls.client.protocols=TLSv1.2 -Dhttps.protocols=TLSv1.2 \
         -Djavax.net.ssl.trustStore=/etc/ssl/certs/java/cacerts -Dstyle.color=never \
         -Djansi.passthrough=true -Dsun.net.client.defaultReadTimeout=60000 \
         -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn \
         -Dmaven.wagon.httpconnectionManager.ttlSeconds=25"
    );
    assert_success(
        &raeva(&tuned, &["sync", "--frozen"]),
        "frozen sync with tuning no POM reads",
    );
    for changed in [
        "-Djdk.javadoc.doclet.version=2.3.2 -Dcom.sun.xml.bind.version=4 -Dos.version=1",
        "-Djdk.javadoc.doclet.version=2.3.1 -Dcom.sun.xml.bind.version=5 -Dos.version=1",
        "-Djdk.javadoc.doclet.version=2.3.1 -Dcom.sun.xml.bind.version=4 -Dos.version=2",
    ] {
        let frozen = raeva(changed, &["sync", "--frozen"]);
        assert_eq!(
            frozen.status.code(),
            Some(7),
            "{changed}: {}",
            stderr(&frozen)
        );
    }
    let frozen = raeva(
        "-Djdk.javadoc.doclet.version=2.3.2 -Dos.version=1",
        &["sync", "--frozen"],
    );
    let said = stderr(&frozen);
    assert!(
        said.contains("-Djdk.javadoc.doclet.version in MAVEN_OPTS"),
        "{said}"
    );
}

/// A host-owned name keys the trace when a module whose path the root
/// interpolates reads it, or a POM reads it through a character reference,
/// as Maven finds and reads both. When raeva cannot list the POMs a build
/// may read, such as a module an inactive profile names through a
/// property, every host-owned name keys it, and `--frozen` names that
/// module.
#[cfg(unix)]
#[test]
fn a_read_in_an_interpolated_module_or_a_reference_keys_the_trace() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    let root_pom = |profile_module: &str| {
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><properties><module.path>child</module.path>\
                 </properties><modules><module>${{module.path}}</module></modules>\
                 <profiles><profile><id>off</id><modules><module>{profile_module}</module>\
                 </modules></profile></profiles><build><plugins><plugin>\
                 <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                 <version>1</version><configuration><a>&#36;{{jdk.entity.version}}</a>\
                 </configuration><executions><execution><phase>validate</phase><goals>\
                 <goal>run</goal></goals></execution></executions></plugin></plugins></build>"
            ),
        )
    };
    fs::write(root.join("pom.xml"), root_pom("extra")).unwrap();
    fs::create_dir_all(root.join("extra")).unwrap();
    fs::write(root.join("extra/pom.xml"), pom("extra", "")).unwrap();
    fs::create_dir_all(root.join("child")).unwrap();
    fs::write(
        root.join("child/pom.xml"),
        pom(
            "child",
            "<packaging>pom</packaging><description>${jdk.module.version}</description>",
        ),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |opts: &str, args: &[&str]| {
        let mut command = raeva_command(root, home.path());
        crate::common::isolate_maven_user_home(&mut command, home.path(), opts);
        command.args(args).output().unwrap()
    };
    let traced = "-Djdk.entity.version=1 -Djdk.module.version=1 -Djdk.tls.client.protocols=TLSv1.2";
    assert_success(&raeva(traced, &["sync"]), "traced sync");
    assert_success(
        &raeva(
            "-Djdk.entity.version=1 -Djdk.module.version=1",
            &["sync", "--frozen"],
        ),
        "frozen sync without tuning no POM reads",
    );
    let unread = "as raeva cannot read the project's files";
    let codes: Vec<Option<i32>> = ["-Djdk.entity.version=2", "-Djdk.module.version=2"]
        .iter()
        .map(|changed| {
            let frozen = raeva(&format!("{traced} {changed}"), &["sync", "--frozen"]);
            assert!(!stderr(&frozen).contains(unread), "{}", stderr(&frozen));
            frozen.status.code()
        })
        .collect();
    assert_eq!(codes, [Some(7), Some(7)]);
    fs::write(root.join("pom.xml"), root_pom("${module.path}")).unwrap();
    assert_success(&raeva(traced, &["sync"]), "traced sync");
    let frozen = raeva(
        "-Djdk.entity.version=1 -Djdk.module.version=1",
        &["sync", "--frozen"],
    );
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    let said = stderr(&frozen);
    assert!(
        said.contains("-Djdk.entity.version in MAVEN_OPTS"),
        "{said}"
    );
    let why = format!("{unread}: module `${{module.path}}` declared by pom.xml");
    assert!(said.contains(&why), "{said}");
}

/// A host-owned name keys the trace when a `-D` value of
/// `.mvn/maven.config` or of the trace's arguments reads it as `${name}`,
/// which Maven expands where a POM reads that value; one nothing reads does
/// not.
#[cfg(unix)]
#[test]
fn a_read_in_maven_config_or_the_trace_arguments_keys_the_trace() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join(".mvn/maven.config"),
        "-Dext.version=2\n-Dlibrary.version=${jdk.config.version}\n",
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify', '-Dother=${jdk.args.version}']\n\
         mvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |opts: &str, args: &[&str]| {
        let mut command = raeva_command(root, home.path());
        crate::common::isolate_maven_user_home(&mut command, home.path(), opts);
        command.args(args).output().unwrap()
    };
    let traced = "-Djdk.config.version=1 -Djdk.args.version=1 -Djdk.tls.client.protocols=TLSv1.2";
    assert_success(&raeva(traced, &["sync"]), "traced sync");
    assert_success(
        &raeva(
            "-Djdk.config.version=1 -Djdk.args.version=1",
            &["sync", "--frozen"],
        ),
        "frozen sync without tuning nothing reads",
    );
    let codes: Vec<Option<i32>> = ["-Djdk.config.version=2", "-Djdk.args.version=2"]
        .iter()
        .map(|changed| {
            let frozen = raeva(&format!("{traced} {changed}"), &["sync", "--frozen"]);
            frozen.status.code()
        })
        .collect();
    assert_eq!(codes, [Some(7), Some(7)]);
}

/// A host-owned name keys the trace when a POM reads it through an
/// expression that names it inside, such as
/// `${session.systemProperties(name)}`, as Maven may evaluate an
/// expression raeva does not, and when it reads a runtime switch such as
/// `user.language` or `https.protocols` as `${name}`. An element named
/// after a switch or a `-D` option that sets it, as surefire's
/// `systemPropertyVariables` and an `argLine` do, and a comment do not.
#[cfg(unix)]
#[test]
fn a_name_a_pom_holds_in_any_expression_keys_the_trace() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    let write_pom = |more: &str| {
        let configuration = format!(
            "<a>${{session.systemProperties(jdk.library.version)}}</a>\
             <b>${{session.userProperties(jdk.user.version)}}</b>\
             <c>${{session.request.systemProperties(jdk.request.version)}}</c>\
             <d>${{project.properties('jdk.project.version')}}</d><!-- jdk.comment.version -->\
             <e><java.awt.headless>true</java.awt.headless></e>\
             <f>-Dfile.encoding=UTF-8 -Djdk.self.version=${{jdk.self.version}}</f>\
             <classifier>${{user.language}}</classifier>\
             <g>${{https.protocols}} ${{org.slf4j.simpleLogger.showDateTime}}</g>{more}"
        );
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<packaging>pom</packaging><build><plugins><plugin>\
                     <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                     <version>1</version><configuration>{configuration}</configuration>\
                     <executions><execution><phase>validate</phase><goals><goal>run</goal>\
                     </goals></execution></executions></plugin></plugins></build>"
                ),
            ),
        )
        .unwrap();
    };
    write_pom("");
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |opts: &str, args: &[&str]| {
        let mut command = raeva_command(root, home.path());
        crate::common::isolate_maven_user_home(&mut command, home.path(), opts);
        command.args(args).output().unwrap()
    };
    let names = [
        "jdk.library.version",
        "jdk.user.version",
        "jdk.request.version",
        "jdk.project.version",
        "jdk.self.version",
        "user.language",
        "https.protocols",
        "org.slf4j.simpleLogger.showDateTime",
    ];
    let options = |changed: &str| {
        (names.iter())
            .map(|name| format!("-D{name}={}", if *name == changed { 2 } else { 1 }))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let traced = format!("{} -Djdk.tls.client.protocols=TLSv1.2", options(""));
    assert_success(&raeva(&traced, &["sync"]), "traced sync");
    assert_success(
        &raeva(&options(""), &["sync", "--frozen"]),
        "frozen sync without tuning no POM names",
    );
    let switches = format!(
        "{} -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djdk.comment.version=1",
        options("")
    );
    assert_success(
        &raeva(&switches, &["sync", "--frozen"]),
        "frozen sync with names the POM only sets or comments on",
    );
    let codes: Vec<Option<i32>> = (names.iter())
        .map(|name| raeva(&options(name), &["sync", "--frozen"]).status.code())
        .collect();
    assert_eq!(codes, [Some(7); 8]);
    write_pom("<skip>${java.awt.headless}</skip>");
    let traced = format!("{} -Djava.awt.headless=true", options(""));
    assert_success(&raeva(&traced, &["sync"]), "traced sync");
    let frozen = raeva(
        &format!("{} -Djava.awt.headless=false", options("")),
        &["sync", "--frozen"],
    );
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
}

/// The trace is keyed by the profile ids the build selects, as Maven
/// reads its `-P` options, not by how they are spelled.
#[cfg(unix)]
#[test]
fn another_spelling_of_the_profiles_is_the_same_trace() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync", "-Pa,b", "-P!c"]), "traced sync");
    for spelled in [&["-Pa", "-Pb", "-P-c"][..], &["-P a,,+b", "-P!c,a"]] {
        let frozen = raeva(&[&["sync", "--frozen"][..], spelled].concat());
        assert_success(&frozen, &format!("frozen sync with {spelled:?}"));
    }
    let frozen = raeva(&["sync", "--frozen", "-Pa,b", "-Pc"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    let ran = || {
        (fs::read_to_string(root.join("ran")).unwrap())
            .lines()
            .count()
    };
    assert_eq!(ran(), 1);
    // Nor by how its `-D` options are spelled and ordered: Maven takes the
    // last value of a name, `true` for none.
    assert_success(
        &raeva(&["sync", "-Pa,b", "-P!c", "-Dx", "-Dy=1"]),
        "sync with -D",
    );
    assert_eq!(ran(), 2);
    for spelled in [&["-Dy=1", "-Dx=true"][..], &["-Dy=0", "-Dx", "-D y=1"]] {
        let frozen = raeva(&[&["sync", "--frozen", "-Pa,b", "-P!c"][..], spelled].concat());
        assert_success(&frozen, &format!("frozen sync with {spelled:?}"));
    }
    let frozen = raeva(&["sync", "--frozen", "-Pa,b", "-P!c", "-Dx", "-Dy=2"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    assert_success(&raeva(&["sync", "-Pa,b", "-P!c"]), "sync without -D");
    assert_eq!(ran(), 3);
    // `-P+!c` selects a profile named `!c`; it does not deselect `c`.
    assert_success(&raeva(&["sync", "-P!c"]), "sync deselecting c");
    assert_eq!(ran(), 4);
    assert_success(&raeva(&["sync", "-P+!c"]), "sync selecting !c");
    assert_eq!(ran(), 5);
}

/// A traced build that fails on `--update` leaves raeva.lock as the sync
/// found it, with the trace it held.
#[cfg(unix)]
#[test]
fn a_failed_update_keeps_the_lock_it_found() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    fs::write(
        &launcher,
        format!("{script}if [ -f \"$(dirname \"$0\")/fail\" ]; then exit 1; fi\n"),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "traced sync");
    let lock_path = root.join("raeva.lock");
    let traced = fs::read(&lock_path).unwrap();
    fs::write(root.join("fail"), "").unwrap();
    let failed = raeva(&["sync", "--update"]);
    assert!(!failed.status.success(), "{}", stderr(&failed));
    assert_eq!(
        String::from_utf8(fs::read(&lock_path).unwrap()).unwrap(),
        String::from_utf8(traced).unwrap()
    );
    assert!(
        stderr(&failed).contains("so raeva.lock is as it was before this sync. raeva")
            && stderr(&failed).contains(
                "Make the build pass in this checkout, where raeva.toml and raeva.lock may be \
                 new files to it, then run 'raeva sync --update' again"
            ),
        "{}",
        stderr(&failed)
    );
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
}

/// A trace that replaces a stale one keeps a POM the build read that no
/// row pins, such as a parent's, which the trace it replaces pinned too.
#[cfg(unix)]
#[test]
fn a_new_trace_keeps_a_pom_the_stale_one_pinned() {
    use std::os::unix::fs::PermissionsExt;

    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
               <artifactId>par</artifactId><version>1</version>\
               <packaging>maven-plugin</packaging></project>";
    fs::write(root.join("par.pom"), pom).unwrap();
    let launcher = root.join("mvnw");
    fs::write(
        &launcher,
        "#!/bin/sh\nfor a in \"$@\"; do case $a in -Dmaven.repo.local=*) \
         m2=${a#-Dmaven.repo.local=};; esac; done\nmkdir -p \"$m2/t/par/1\"\n\
         cp \"$(dirname \"$0\")/par.pom\" \"$m2/t/par/1/par-1.pom\"\n\
         printf 'par-1.pom>stub=\\n' > \"$m2/t/par/1/_remote.repositories\"\n",
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    let traced = |goals: &str| {
        fs::write(
            root.join("raeva.toml"),
            format!("[plugins]\nlock = true\ntrace = [{goals}]\nmvn = './mvnw'\n"),
        )
        .unwrap();
        assert_success(&raeva(&["sync"]), goals);
        fs::read_to_string(root.join("raeva.lock")).unwrap()
    };
    let lock = traced("'verify'");
    assert!(lock.contains("t:par:1"), "{lock}");
    let lock = traced("'verify', '-q'");
    assert!(lock.contains("t:par:1"), "{lock}");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
}

/// A trace on `--update` that cannot record what the build read, such as
/// a SNAPSHOT build, says that raeva.lock is as the sync found it.
#[cfg(unix)]
#[test]
fn an_unrecorded_update_says_the_lock_is_as_it_was() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    fs::write(
        &launcher,
        format!(
            "{script}if [ -f \"$(dirname \"$0\")/snap\" ]; then d=\"$m2/t/tool/1.0-SNAPSHOT\"\n\
             mkdir -p \"$d\"; echo x > \"$d/tool-1.0-20250101.000000-1.jar\"\n\
             printf 'tool-1.0-20250101.000000-1.jar>stub=\\n' > \"$d/_remote.repositories\"; fi\n"
        ),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "traced sync");
    let lock_path = root.join("raeva.lock");
    let traced = fs::read(&lock_path).unwrap();
    fs::write(root.join("snap"), "").unwrap();
    let failed = raeva(&["sync", "--update"]);
    assert_eq!(failed.status.code(), Some(5), "{}", stderr(&failed));
    assert_eq!(fs::read(&lock_path).unwrap(), traced);
    assert!(
        stderr(&failed).contains("raeva.lock is as it was before this sync"),
        "{}",
        stderr(&failed)
    );
}

/// A failed trace on `--update` that changed nothing leaves a raeva.lock
/// that is a link as it is.
#[cfg(unix)]
#[test]
fn a_failed_update_keeps_a_linked_lock() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    fs::write(&launcher, format!("{script}exit 1\n")).unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&raeva(&["sync"]), "sync");
    let (lock_path, target) = (root.join("raeva.lock"), root.join("locked.toml"));
    fs::rename(&lock_path, &target).unwrap();
    std::os::unix::fs::symlink("locked.toml", &lock_path).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let failed = raeva(&["sync", "--update"]);
    assert!(
        stderr(&failed).contains("the traced build failed"),
        "{}",
        stderr(&failed)
    );
    assert!(fs::symlink_metadata(&lock_path).unwrap().is_symlink());
}

/// A `sync --update` stopped by SIGTERM while its traced build runs leaves
/// raeva.lock as the sync found it, with the trace it held.
#[cfg(unix)]
#[test]
fn a_terminated_update_keeps_the_lock_it_found() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    let hang = "if [ -f \"$(dirname \"$0\")/hang\" ]; then echo $$ > \"$(dirname \"$0\")/pid\"; \
                : > \"$(dirname \"$0\")/started\"; exec sleep 30; fi\n";
    fs::write(&launcher, script.replacen('\n', &format!("\n{hang}"), 1)).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "traced sync");
    let lock_path = root.join("raeva.lock");
    let traced = fs::read_to_string(&lock_path).unwrap();
    fs::write(root.join("hang"), "").unwrap();
    let mut update = (raeva_command(root, home.path()))
        .args(["sync", "--update"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("run raeva");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !root.join("started").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the traced build never started"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let killed = std::process::Command::new("kill")
        .args(["-TERM", &update.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    assert_eq!(update.wait().unwrap().code(), Some(143));
    // The build's shell became the `sleep`, so its pid names the build.
    let pid = fs::read_to_string(root.join("pid")).unwrap();
    let alive = || {
        std::process::Command::new("kill")
            .args(["-0", pid.trim()])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while alive() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(!alive(), "the traced build outlived the sync");
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(lock == traced, "raeva.lock is not as the sync found it");
}

/// [`plugin_project`] with a trace whose build fails while the project
/// holds a `fail` file, and a dependency on `org.test:snapshot:1.0-SNAPSHOT`
/// from a repository with a daily update policy. The server serves its newer
/// build while the flag is set, and gives `on_request` each path.
#[cfg(unix)]
fn snapshot_trace_project(
    on_request: impl Fn(&str) + Send + Sync + 'static,
) -> (StubServer, Arc<AtomicBool>, TempDir, TempDir) {
    let advanced = Arc::new(AtomicBool::new(false));
    let state = Arc::clone(&advanced);
    let server = StubServer::start(move |request| {
        on_request(&request.path);
        if request.path.starts_with("/org/test/") {
            let advanced = state.load(Ordering::SeqCst);
            return serve_sha256(&request.path, |path| {
                crate::reactor_sync::snapshot_route(path, advanced)
            });
        }
        serve(request, None, |_| (JAR, true), |_| false)
    });
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replacen(
        "<build>",
        "<repositories><repository><id>snapshots</id><url>http://unused.invalid/</url>\
         <snapshots><enabled>true</enabled><updatePolicy>daily</updatePolicy></snapshots>\
         </repository></repositories><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>snapshot</artifactId><version>1.0-SNAPSHOT</version></dependency>\
         </dependencies><build>",
        1,
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    fs::write(
        &launcher,
        format!("{script}if [ -f \"$(dirname \"$0\")/fail\" ]; then exit 1; fi\n"),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    (server, advanced, project, home)
}

/// A POM that no longer parses once `sync --update` wrote raeva.lock does
/// not stop a failed trace from putting back the lock the sync found: the
/// trace takes the models the resolution read. The POM breaks as the sync
/// fetches the jar of the plugin version the update moves to, after the
/// plugin resolution read the POM.
#[cfg(unix)]
#[test]
fn a_failed_update_keeps_the_lock_when_a_pom_breaks_meanwhile() {
    let broken: Arc<std::sync::Mutex<Option<std::path::PathBuf>>> = Arc::default();
    let breaks = Arc::clone(&broken);
    let (_server, _advanced, project, home) = snapshot_trace_project(move |path| {
        if path.contains("/demo-maven-plugin-2.jar")
            && let Some(pom) = breaks.lock().unwrap().take()
        {
            fs::write(pom, "not a POM").unwrap();
        }
    });
    let root = project.path();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "traced sync");
    let lock_path = root.join("raeva.lock");
    let traced = fs::read_to_string(&lock_path).unwrap();
    let pom_path = root.join("pom.xml");
    let pom = fs::read_to_string(&pom_path).unwrap().replacen(
        "<artifactId>demo-maven-plugin</artifactId><version>1</version>",
        "<artifactId>demo-maven-plugin</artifactId><version>2</version>",
        1,
    );
    fs::write(&pom_path, pom).unwrap();
    *broken.lock().unwrap() = Some(pom_path);
    fs::write(root.join("fail"), "").unwrap();
    let failed = raeva(&["sync", "--update"]);
    assert!(!failed.status.success(), "{}", stderr(&failed));
    assert!(
        broken.lock().unwrap().is_none(),
        "the plugin was not fetched"
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), traced);
}

/// A failed `--update` trace that puts back the lock the sync found records
/// no SNAPSHOT check for it, so a plain sync looks for newer builds once the
/// update policy of the check before it expires.
#[cfg(unix)]
#[test]
fn a_failed_update_records_no_snapshot_check() {
    let (_server, advanced, project, home) = snapshot_trace_project(|_| {});
    let root = project.path();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "traced sync");
    let lock_path = root.join("raeva.lock");
    let traced = fs::read_to_string(&lock_path).unwrap();
    crate::reactor_sync::age_snapshot_checks(
        home.path(),
        &lock_path,
        crate::reactor_sync::TWO_DAYS,
    );
    advanced.store(true, Ordering::SeqCst);
    fs::write(root.join("fail"), "").unwrap();
    let failed = raeva(&["sync", "--update"]);
    assert!(!failed.status.success(), "{}", stderr(&failed));
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), traced);
    fs::remove_file(root.join("fail")).unwrap();
    assert_success(&raeva(&["sync"]), "plain sync");
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(lock.contains("timestamp = \"20240202.020202\""), "{lock}");
}

/// A failed trace of a sync with no lock to put back keeps the SNAPSHOT
/// check of the lock the sync wrote, so the next sync reuses that lock
/// within the update policy instead of resolving again.
#[cfg(unix)]
#[test]
fn a_failed_trace_keeps_the_snapshot_check_of_a_new_lock() {
    let (_server, _advanced, project, home) = snapshot_trace_project(|_| {});
    let root = project.path();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    fs::write(root.join("fail"), "").unwrap();
    assert!(!raeva(&["sync"]).status.success(), "the trace fails");
    fs::remove_file(root.join("fail")).unwrap();
    let sync = raeva(&["sync"]);
    assert_success(&sync, "sync tracing again");
    assert!(
        !stderr(&sync).contains("Resolving dependencies"),
        "{}",
        stderr(&sync)
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("role = \"trace\""), "{lock}");
}

/// A trace leaves raeva.lock alone when another write changed it while the
/// build ran, and the next sync traces again.
#[cfg(unix)]
#[test]
fn a_trace_keeps_a_lock_written_while_the_build_ran() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    fs::write(
        &launcher,
        format!(
            "{script}if [ -f \"$(dirname \"$0\")/edit\" ]; then echo '# edited' >> \
             \"$(dirname \"$0\")/raeva.lock\"; fi\n"
        ),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    fs::write(root.join("edit"), "").unwrap();
    let raced = raeva(&["sync"]);
    assert!(!raced.status.success(), "{}", stderr(&raced));
    assert!(
        stderr(&raced).contains("changed while the traced build ran"),
        "{}",
        stderr(&raced)
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.ends_with("# edited\n"), "{lock}");
    assert!(!lock.contains("role = \"trace\""), "{lock}");
    fs::remove_file(root.join("edit")).unwrap();
    assert_success(&raeva(&["sync"]), "sync tracing again");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("role = \"trace\""), "{lock}");
}

/// A failed trace names the plugin, goal and module Maven's failure line
/// selects among those raeva holds, in raeva's own names, a goal only as
/// the plugin's descriptor spells it; never the execution, a coordinate,
/// goal or project raeva does not hold, or what follows. It shows and
/// keeps none of the build's output, and says how to see it.
#[cfg(unix)]
#[test]
fn a_failed_trace_names_only_the_goal_and_module_raeva_holds() {
    let descriptor: &'static [u8] = Box::leak(
        plugin_jar("<plugin><mojos><mojo><goal>run</goal></mojo></mojos></plugin>")
            .into_boxed_slice(),
    );
    let server = repository_serving(move |artifact| match artifact {
        "demo-maven-plugin" => (descriptor, true),
        _ => (JAR, true),
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let cases = [
        (
            "t:demo-maven-plugin:1:run (zqEXECzq) on project app: zqTOKENzq",
            " in t:demo-maven-plugin:1:run on project app (exit status: 1),",
        ),
        (
            "t:demo-maven-plugin:1:zqGOALzq (x) on project app: e",
            " in t:demo-maven-plugin:1 on project app (exit status: 1),",
        ),
        (
            "t:zqCOORDzq:1:run (x) on project zqPROJECTzq: e",
            " (exit status: 1),",
        ),
        (
            "org.apache.rat:apache-rat-plugin:0.18:check (rat-check) on project demo: e",
            " (exit status: 1),",
        ),
    ];
    for (line, named) in cases {
        let failing = format!("{script}echo '[ERROR] Failed to execute goal {line}'\nexit 1\n");
        fs::write(&launcher, failing).unwrap();
        let failed = run_raeva(root, home.path(), &["sync"]);
        assert_eq!(failed.status.code(), Some(1), "{}", stderr(&failed));
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&failed.stdout),
            stderr(&failed)
        );
        for part in [
            &format!("the traced build failed{named} so raeva.lock holds no trace of it"),
            "raeva does not show or keep the build's output: to see it, run ",
            "/mvnw with the arguments of [plugins] trace in the project directory; raeva ran \
             it with -B, -s with the settings file raeva read, -Dmaven.repo.local with a new \
             local repository",
        ] {
            assert!(said.contains(part), "{part}\n{said}");
        }
        let shown: Vec<String> = crate::common::markers_in(&said).collect();
        assert!(shown.is_empty(), "{shown:?}\n{said}");
        assert_eq!(trace_leftovers(home.path()), Vec::<String>::new());
    }
    // The options raeva forwards are named without their values.
    let failed = run_raeva(root, home.path(), &["sync", "-Pzz", "-Dflavor=zqVALUEzq"]);
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&failed.stdout),
        stderr(&failed)
    );
    assert!(
        said.contains("raeva ran it with -B, -Dflavor, -Pzz, -s with the settings file"),
        "{said}"
    );
    let shown: Vec<String> = crate::common::markers_in(&said).collect();
    assert!(shown.is_empty(), "{shown:?}\n{said}");
}

/// The failures a traced build's output shows by a fixed pattern, each
/// told in raeva's words, without the build's.
#[cfg(unix)]
#[test]
fn a_failed_trace_names_the_failures_its_output_shows() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let echo = "echo 'Error: Could not create the Java Virtual Machine. zqJVMzq'\n\
                echo '[ERROR] Plugin t:zqPLUGINzq:1 or one of its dependencies could not be \
                resolved: zqWHYzq' >&2\n\
                echo '[ERROR]   Non-resolvable parent POM for zqPOMzq'\n\
                echo '[ERROR] Could not transfer artifact t:p:pom:1 from/to r (zqURLzq): status \
                code: 403, reason phrase: Forbidden (403)'";
    let said = failed_trace(&project, &home, "['verify']", echo, &[]);
    assert!(
        said.contains(
            "(exit status: 1): a JVM could not start; a plugin could not be resolved; a POM \
             could not be read or built; a repository refused access (401 or 403), so"
        ),
        "{said}"
    );
    let shown: Vec<String> = crate::common::markers_in(&said).collect();
    assert!(shown.is_empty(), "{shown:?}\n{said}");
}

/// A trace that runs again holds the files the old trace pinned to their
/// pins: other bytes fail the sync, and only `--update` takes them.
#[cfg(unix)]
#[test]
fn a_trace_run_again_refuses_other_bytes_for_a_traced_file() {
    let swapped = Arc::new(AtomicBool::new(false));
    let server = repository_serving({
        let swapped = Arc::clone(&swapped);
        move |artifact| match swapped.load(Ordering::SeqCst) && artifact == "tool" {
            true => (OTHER_JAR, true),
            false => (JAR, true),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    let traced = |args: &str| format!("[plugins]\nlock = true\ntrace = [{args}]\nmvn = './mvnw'\n");
    fs::write(root.join("raeva.toml"), traced("'verify'")).unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "traced sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    assert!(locked.contains("t:tool:1"), "{locked}");

    // The mirror, and so the build, now has other bytes for the tool, and
    // other arguments make the trace stale.
    swapped.store(true, Ordering::SeqCst);
    fs::write(root.join("tool.jar"), OTHER_JAR).unwrap();
    fs::write(root.join("raeva.toml"), traced("'verify', '-DskipTests'")).unwrap();
    let refused = |output: std::process::Output| {
        assert_eq!(output.status.code(), Some(7), "{}", stderr(&output));
        assert!(
            stderr(&output).contains(&sha256_hex(OTHER_JAR)),
            "{}",
            stderr(&output)
        );
        assert!(
            !fs::read_to_string(&lock_path)
                .unwrap()
                .contains(&sha256_hex(OTHER_JAR))
        );
    };
    refused(raeva(&["sync"]));
    // The refused trace leaves its rows, so a sync run again still refuses,
    // also once a POM edit resolves the tables again.
    refused(raeva(&["sync"]));
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    let edited = pom.replacen("<build>", "<properties><x>1</x></properties><build>", 1);
    assert_ne!(edited, pom);
    fs::write(root.join("pom.xml"), edited).unwrap();
    refused(raeva(&["sync"]));
    assert_success(&raeva(&["sync", "--update"]), "sync --update");
    let updated = fs::read_to_string(&lock_path).unwrap();
    assert!(updated.contains(&sha256_hex(OTHER_JAR)), "{updated}");
}

/// A conflicted lock keeps the pins of its traces: the trace that replaces
/// them refuses other bytes for a traced file, as it does on a lock that
/// reads, also after the lock it regenerated is written.
#[cfg(unix)]
#[test]
fn a_conflicted_lock_keeps_the_pins_of_its_traces() {
    let swapped = Arc::new(AtomicBool::new(false));
    let server = repository_serving({
        let swapped = Arc::clone(&swapped);
        move |artifact| match swapped.load(Ordering::SeqCst) && artifact == "tool" {
            true => (OTHER_JAR, true),
            false => (JAR, true),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    let traced = |args: &str| format!("[plugins]\nlock = true\ntrace = [{args}]\nmvn = './mvnw'\n");
    fs::write(root.join("raeva.toml"), traced("'verify'")).unwrap();
    let raeva = |args: &[&str]| {
        (raeva_command(root, home.path()))
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&raeva(&["sync"]), "traced sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    assert!(locked.contains("t:tool:1"), "{locked}");
    // Each side holds a trace, of another build.
    fs::write(root.join("raeva.toml"), traced("'verify', '-q'")).unwrap();
    assert_success(&raeva(&["sync"]), "trace another build");
    let theirs = fs::read_to_string(&lock_path).unwrap();
    assert_ne!(theirs, locked);
    let conflict = format!("<<<<<<< HEAD\n{locked}=======\n{theirs}>>>>>>> theirs\n");

    // Our side's trace is of the build raeva.toml names; theirs is stale.
    swapped.store(true, Ordering::SeqCst);
    fs::write(root.join("tool.jar"), OTHER_JAR).unwrap();
    fs::write(root.join("raeva.toml"), traced("'verify'")).unwrap();
    let refused = |output: std::process::Output| {
        assert_eq!(output.status.code(), Some(7), "{}", stderr(&output));
        assert!(
            stderr(&output).contains(&sha256_hex(OTHER_JAR)),
            "{}",
            stderr(&output)
        );
        let lock = fs::read_to_string(&lock_path).unwrap();
        assert!(!lock.contains(&sha256_hex(OTHER_JAR)), "{lock}");
    };
    fs::write(&lock_path, &conflict).unwrap();
    refused(raeva(&["sync"]));
    // The regenerated lock, written before the trace ran, keeps both as one
    // stale trace.
    let regenerated = fs::read_to_string(&lock_path).unwrap();
    assert_eq!(
        regenerated.matches("role = \"trace\"").count(),
        1,
        "{regenerated}"
    );
    refused(raeva(&["sync"]));
    assert_success(&raeva(&["sync", "--update"]), "sync --update");
    let updated = fs::read_to_string(&lock_path).unwrap();
    assert_eq!(updated.matches("role = \"trace\"").count(), 1, "{updated}");
    assert!(updated.contains(&sha256_hex(OTHER_JAR)), "{updated}");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
}

/// `--update` traces again a trace that is still current, and takes the
/// bytes the build reads now.
#[cfg(unix)]
#[test]
fn an_update_traces_again() {
    let swapped = Arc::new(AtomicBool::new(false));
    let server = repository_serving({
        let swapped = Arc::clone(&swapped);
        move |artifact| match swapped.load(Ordering::SeqCst) && artifact == "tool" {
            true => (OTHER_JAR, true),
            false => (JAR, true),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "traced sync");
    swapped.store(true, Ordering::SeqCst);
    fs::write(root.join("tool.jar"), OTHER_JAR).unwrap();
    assert_success(&raeva(&["sync", "--update"]), "sync --update");
    let updated = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(updated.contains(&sha256_hex(OTHER_JAR)), "{updated}");
    assert_eq!(
        (fs::read_to_string(root.join("ran")).unwrap())
            .lines()
            .count(),
        2
    );
}

/// `--update` that traces again and writes the bytes raeva.lock held says
/// raeva.lock is up to date, not that it replaced the trace.
#[cfg(unix)]
#[test]
fn an_update_that_traces_the_same_files_changes_nothing() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "traced sync");
    let lock = fs::read(root.join("raeva.lock")).unwrap();
    let update = raeva(&["sync", "--update"]);
    assert_success(&update, "sync --update");
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), lock);
    assert!(
        stderr(&update).contains("raeva.lock is up to date")
            && !stderr(&update).contains("plugin trace"),
        "{}",
        stderr(&update)
    );
}

/// A lock of two JDKs holds one trace, from the host's JDK, which a
/// --frozen check on either accepts.
#[cfg(unix)]
#[test]
fn one_trace_serves_every_jdk_the_lock_holds() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[lock]\njdks = ['17', '21']\n\n[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |jdk: &str, args: &[&str]| {
        (raeva_command(root, home.path()))
            .env("JAVA_VERSION", jdk)
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&raeva("21", &["sync"]), "traced sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert_eq!(lock.matches("role = \"trace\"").count(), 1, "{lock}");
    for jdk in ["21", "17"] {
        assert_success(
            &raeva(jdk, &["sync", "--frozen"]),
            &format!("frozen sync on {jdk}"),
        );
    }
    assert_success(&raeva("17", &["sync"]), "sync on the other JDK");
    let ran = || {
        (fs::read_to_string(root.join("ran")).unwrap())
            .lines()
            .count()
    };
    assert_eq!(ran(), 1);
    // A trace made stale and run again on the other JDK replaces the one
    // the first JDK's platform holds.
    fs::write(
        root.join("raeva.toml"),
        "[lock]\njdks = ['17', '21']\n\n[plugins]\nlock = true\ntrace = ['verify', '-q']\nmvn = './mvnw'\n",
    )
    .unwrap();
    assert_success(&raeva("17", &["sync"]), "trace again on the other JDK");
    assert_eq!(ran(), 2);
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert_eq!(lock.matches("role = \"trace\"").count(), 1, "{lock}");
    for jdk in ["21", "17"] {
        assert_success(
            &raeva(jdk, &["sync", "--frozen"]),
            &format!("frozen sync on {jdk} of the new trace"),
        );
    }
    // A JDK the lock does not list traces the build on a listed JDK's
    // tables, which only an export of this machine's build refuses.
    fs::write(
        root.join("raeva.toml"),
        "[lock]\njdks = ['17', '21']\n\n[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    assert_success(&raeva("25", &["sync"]), "trace on an unlisted JDK");
    assert_eq!(ran(), 3);
    assert_success(&raeva("21", &["sync", "--frozen"]), "frozen sync on 21");
}

/// The password of the settings.xml `<server>` the private plugin
/// repository takes, and the header it makes.
const PLUGIN_PASSWORD: &str = "pl4gin-s3cret";
const PLUGIN_AUTHORIZATION: &str = "Basic ZGVwbG95OnBsNGdpbi1zM2NyZXQ=";

/// A settings.xml whose `extra` holds its profiles, with the `<server>`
/// of the id `corp-plugins`.
fn settings_with(home: &std::path::Path, extra: &str) {
    fs::write(
        home.join(".m2/settings.xml"),
        format!(
            "<settings><servers><server><id>corp-plugins</id><username>deploy</username>\
             <password>{PLUGIN_PASSWORD}</password></server></servers>{extra}</settings>"
        ),
    )
    .unwrap();
}

/// A plugin repository that a settings.xml profile declares, active by its
/// `<activation>`, serves the build's plugins with its `<server>`'s
/// credential, as Maven reads it: the lock records it, `--frozen` and
/// another machine's sync fetch from it, and the export labels its files
/// with its id. A change to it makes the tables stale.
#[test]
fn a_settings_profile_plugin_repository_serves_the_plugins() {
    // The plugin has a parent, which the tables pin as a support POM.
    const PARENT: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
        <artifactId>plugin-parent</artifactId><version>1</version><packaging>pom</packaging>\
        </project>";
    let server = StubServer::start(|request| {
        let authorized = request.header("authorization") == Some(PLUGIN_AUTHORIZATION);
        let plugin = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
            <artifactId>plugin-parent</artifactId><version>1</version></parent>\
            <artifactId>demo-maven-plugin</artifactId><packaging>maven-plugin</packaging>\
            </project>";
        let body = match request.path.trim_end_matches(".sha256") {
            "/t/plugin-parent/1/plugin-parent-1.pom" => PARENT,
            "/t/demo-maven-plugin/1/demo-maven-plugin-1.pom" => plugin,
            _ => {
                return serve(
                    request,
                    Some(PLUGIN_AUTHORIZATION),
                    |_| (JAR, true),
                    |_| false,
                );
            }
        };
        match (authorized, request.path.ends_with(".sha256")) {
            (false, _) => Response::new(401, ""),
            (true, true) => Response::new(200, sha256_hex(body.as_bytes())),
            (true, false) => Response::new(200, body),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let profile = |url: &str| {
        format!(
            "<profiles><profile><id>corp</id><activation><property><name>!no.corp</name>\
             </property></activation><pluginRepositories><pluginRepository>\
             <id>corp-plugins</id><url>{url}</url><snapshots><enabled>false</enabled>\
             </snapshots></pluginRepository></pluginRepositories></profile></profiles>"
        )
    };
    settings_with(home.path(), &profile(&url));
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = (raeva_command(root, home))
            .args(args)
            .output()
            .expect("run raeva");
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            stderr(&output)
        );
        assert!(!printed.contains(PLUGIN_PASSWORD), "{printed}");
        output
    };
    let lock_path = root.join("raeva.lock");
    assert_success(&run(home.path(), &["sync"]), "sync");
    let tables = fs::read_to_string(&lock_path).unwrap();
    assert!(!tables.contains(PLUGIN_PASSWORD));
    let document: toml::Value = toml::from_str(&tables).unwrap();
    let platform = &document["platforms"][0];
    let row = (platform["artifacts"].as_array().unwrap().iter())
        .find(|row| row["coordinate"]["artifact"].as_str() == Some("demo-maven-plugin"))
        .unwrap_or_else(|| panic!("{tables}"));
    assert_eq!(row["repo_url"].as_str(), Some(url.as_str()), "{tables}");
    let repo_ids = platform["plugins"]["repo_ids"].as_str().unwrap();
    assert!(
        repo_ids.contains(&format!("{url}\tcorp-plugins")),
        "{tables}"
    );
    let m2 = home.path().join("m2");
    assert_success(
        &run(
            home.path(),
            &["export-m2", "--m2-path", m2.to_str().unwrap()],
        ),
        "export",
    );
    let jar = m2.join("t/demo-maven-plugin/1");
    assert_eq!(fs::read(jar.join("demo-maven-plugin-1.jar")).unwrap(), JAR);
    let remote = fs::read_to_string(jar.join("_remote.repositories")).unwrap();
    assert!(
        remote.contains("demo-maven-plugin-1.jar>corp-plugins="),
        "{remote}"
    );
    assert_success(&run(home.path(), &["sync", "--frozen"]), "frozen sync");
    // `lock verify --download` repairs a plugin's parent, then its jar,
    // from it for a module.
    for bytes in [PARENT.as_bytes(), JAR] {
        let blob = walkdir(home.path())
            .into_iter()
            .find(|path| path.file_name() == Some(sha256_hex(bytes).as_ref()))
            .expect("the blob");
        fs::remove_file(blob).unwrap();
        let repair = ["lock", "verify", "--download", "--module", "pom.xml"];
        assert_success(&run(home.path(), &repair), "module repair");
        let verify = ["lock", "verify", "--module", "pom.xml"];
        assert_success(&run(home.path(), &verify), "verify after repair");
    }

    let other = TempDir::new().unwrap();
    fs::create_dir_all(other.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        other.path().join(".m2/settings.xml"),
    )
    .unwrap();
    assert_success(&run(other.path(), &["sync"]), "sync elsewhere");
    let m2 = other.path().join("m2");
    assert_success(
        &run(
            other.path(),
            &["export-m2", "--m2-path", m2.to_str().unwrap()],
        ),
        "export elsewhere",
    );
    assert_eq!(
        fs::read(m2.join("t/demo-maven-plugin/1/demo-maven-plugin-1.jar")).unwrap(),
        JAR
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), tables);

    // The repository is an input of the lock.
    settings_with(home.path(), &profile(&format!("{url}other/")));
    let frozen = run(home.path(), &["sync", "--frozen"]);
    assert!(
        stderr(&frozen).contains("the configuration changed"),
        "{}",
        stderr(&frozen)
    );
}

/// An offline `lock verify --download` into an empty home, which cannot
/// resolve the plugins again, reports the plugin's parent POM missing, as
/// it does the plugin's jar, rather than fail on the plugin repository that
/// serves it, which the dependencies do not search. The sync the hint names
/// fills the home.
#[test]
fn an_offline_repair_reports_a_plugin_parent_missing() {
    const PARENT: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
        <artifactId>plugin-parent</artifactId><version>1</version><packaging>pom</packaging>\
        </project>";
    let server = StubServer::start(|request| {
        let plugin = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
            <artifactId>plugin-parent</artifactId><version>1</version></parent>\
            <artifactId>demo-maven-plugin</artifactId><packaging>maven-plugin</packaging>\
            </project>";
        let body = match request.path.trim_end_matches(".sha256") {
            "/t/plugin-parent/1/plugin-parent-1.pom" => PARENT,
            "/t/demo-maven-plugin/1/demo-maven-plugin-1.pom" => plugin,
            _ => return serve(request, None, |_| (JAR, true), |_| false),
        };
        match request.path.ends_with(".sha256") {
            true => Response::new(200, sha256_hex(body.as_bytes())),
            false => Response::new(200, body),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let settings = format!(
        "<settings><profiles><profile><id>corp</id><pluginRepositories><pluginRepository>\
         <id>corp-plugins</id><url>{url}</url></pluginRepository></pluginRepositories>\
         </profile></profiles><activeProfiles><activeProfile>corp</activeProfile>\
         </activeProfiles></settings>"
    );
    fs::write(home.path().join(".m2/settings.xml"), &settings).unwrap();
    let run = |home: &std::path::Path, args: &[&str]| {
        (raeva_command(root, home))
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&run(home.path(), &["sync"]), "sync");

    let fresh = TempDir::new().unwrap();
    fs::create_dir_all(fresh.path().join(".m2")).unwrap();
    fs::write(fresh.path().join(".m2/settings.xml"), &settings).unwrap();
    let offline = ["--offline", "--json", "lock", "verify", "--download"];
    let repair = run(fresh.path(), &offline);
    assert_status(&repair, 7, "offline repair into an empty home");
    let envelope = crate::common::envelope(&repair);
    assert_eq!(envelope["code"], "LOCKFILE_MISMATCH", "{envelope}");
    let missing = envelope["data"]["missing_artifacts"].to_string();
    assert!(missing.contains("t:plugin-parent:1"), "{envelope}");
    assert!(
        envelope["hints"].to_string().contains("'raeva sync'"),
        "{envelope}"
    );
    assert_success(&run(fresh.path(), &["sync"]), "the sync the hint names");
    assert_success(&run(fresh.path(), &offline), "offline repair after it");
}

/// A mirror of `external:*` but `central` serves a plugin repository of a
/// profile `<activeProfiles>` names, for the project's plugins and for the
/// core extensions, which Maven resolves from its request's plugin
/// repositories alone. The lock records the repository, and the export
/// labels its files with both ids. So it does for a `symlink+file:` URL in
/// the Maven 3.10 mode, which the mirror pattern reads as written although
/// the lock records the directory.
#[test]
fn a_mirror_serves_a_settings_plugin_repository() {
    let plugins = TempDir::new().unwrap();
    let directory = url::Url::from_directory_path(plugins.path()).unwrap();
    let linked = format!("symlink+{directory}");
    let https = "https://plugins.corp.invalid/maven/";
    for (origin, maven310) in [(https, false), (https, true), (&linked, true)] {
        mirrored_settings_plugin_repository(origin, maven310);
    }
}

fn mirrored_settings_plugin_repository(origin: &str, maven310: bool) {
    let server = repository();
    let mirror = format!("http://{}/", server.addr());
    let (project, home) = plugin_project("unused");
    let root = project.path();
    let mode = if maven310 {
        "[lock]\nmaven = \"3.10\"\n"
    } else {
        ""
    };
    fs::write(
        root.join("raeva.toml"),
        format!("[plugins]\nlock = true\n{mode}"),
    )
    .unwrap();
    settings_with(
        home.path(),
        &format!(
            "<mirrors><mirror><id>corp-mirror</id><url>{mirror}</url>\
             <mirrorOf>external:*,!central</mirrorOf></mirror></mirrors>\
             <profiles><profile><id>corp</id><pluginRepositories><pluginRepository>\
             <id>corp-plugins</id><url>{origin}</url></pluginRepository>\
             </pluginRepositories></profile></profiles>\
             <activeProfiles><activeProfile>corp</activeProfile></activeProfiles>"
        ),
    );
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), &format!("sync, {origin} {mode}"));
    let tables = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for coordinate in ["t:demo-maven-plugin:1", "t:ext:2"] {
        assert!(tables.contains(coordinate), "{coordinate}: {tables}");
    }
    let recorded = match origin.strip_prefix("symlink+") {
        Some(url) => crate::common::recorded_origin(root, url),
        None => origin.to_string(),
    };
    assert!(tables.contains(&format!("\"{recorded}")), "{tables}");
    assert!(!tables.contains(&mirror), "{tables}");
    let m2 = home.path().join("m2");
    assert_success(
        &raeva(&["export-m2", "--m2-path", m2.to_str().unwrap()]),
        &format!("export, {origin} {mode}"),
    );
    for (dir, file) in [
        ("t/demo-maven-plugin/1", "demo-maven-plugin-1.jar"),
        ("t/ext/2", "ext-2.jar"),
    ] {
        let remote = fs::read_to_string(m2.join(dir).join("_remote.repositories")).unwrap();
        for id in ["corp-mirror", "corp-plugins"] {
            assert!(
                remote.contains(&format!("{file}>{id}=")),
                "{origin}: {remote}"
            );
        }
    }
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
}

/// As [`a_mirror_serves_a_settings_plugin_repository`] for a `symlink+file:`
/// plugin repository the project's POM declares, in a project whose
/// dependency comes from a repository only its remote parent declares, so
/// the export checks the lock with a resolution of its own.
#[test]
fn a_mirror_serves_a_pom_plugin_repository_beside_a_remote_parents() {
    let remote = StubServer::start(|request| serve(request, None, |_| (JAR, true), |_| false));
    let parent = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>corp-parent</artifactId><version>1</version><packaging>pom</packaging>\
         <repositories><repository><id>remote</id><url>http://{}/</url></repository>\
         </repositories></project>",
        remote.addr()
    );
    let server = StubServer::start(move |request| {
        let path = request.path.as_str();
        if path.starts_with("/t/corp-parent/1/corp-parent-1.pom") {
            let pom = "/t/corp-parent/1/corp-parent-1.pom";
            return serve_sha256(path, |path| (path == pom).then_some(parent.as_bytes()));
        }
        if path.starts_with("/t/dep/") {
            return Response::new(404, "");
        }
        serve(request, None, |_| (JAR, true), |_| false)
    });
    let mirror = format!("http://{}/", server.addr());
    let plugins = TempDir::new().unwrap();
    let directory = url::Url::from_directory_path(plugins.path()).unwrap();
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_file(root.join(".mvn/extensions.xml")).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\n[lock]\nmaven = \"3.10\"\n",
    )
    .unwrap();
    fs::write(
        home.path().join("config.toml"),
        format!(
            "[security]\ntransitive_repository_allowlist = [\"http://{}/\"]\n",
            remote.addr()
        ),
    )
    .unwrap();
    fs::write(
        root.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
             <artifactId>corp-parent</artifactId><version>1</version><relativePath/></parent>\
             <artifactId>app</artifactId><packaging>pom</packaging>\
             <repositories><repository><id>deps</id><url>https://deps.corp.invalid/</url>\
             </repository></repositories><pluginRepositories><pluginRepository>\
             <id>corp-plugins</id><url>symlink+{directory}</url></pluginRepository>\
             </pluginRepositories><dependencies><dependency><groupId>t</groupId>\
             <artifactId>dep</artifactId><version>1</version></dependency></dependencies>\
             <build><plugins><plugin><groupId>t</groupId>\
             <artifactId>demo-maven-plugin</artifactId><version>1</version><executions>\
             <execution><phase>validate</phase><goals><goal>run</goal></goals></execution>\
             </executions></plugin></plugins></build></project>"
        ),
    )
    .unwrap();
    settings_with(
        home.path(),
        &format!(
            "<mirrors><mirror><id>corp-mirror</id><url>{mirror}</url>\
             <mirrorOf>external:*,!central</mirrorOf></mirror></mirrors>"
        ),
    );
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    let sync = raeva(&["sync"]);
    assert_success(&sync, "sync");
    // `external:*` passes over the loopback repository without a warning.
    assert!(
        !stderr(&sync).contains("SETTING_IGNORED"),
        "{}",
        stderr(&sync)
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:demo-maven-plugin:1"), "{lock}");
    let recorded = crate::common::recorded_origin(root, directory.as_str());
    assert!(lock.contains(&format!("\"{recorded}")), "{lock}");
    assert!(
        lock.contains(&format!("http://{}/", remote.addr())),
        "{lock}"
    );
    let m2 = home.path().join("m2");
    assert_success(
        &raeva(&["export-m2", "--m2-path", m2.to_str().unwrap()]),
        "export",
    );
    let marker = m2.join("t/demo-maven-plugin/1/_remote.repositories");
    let remote_ids = fs::read_to_string(marker).unwrap();
    for id in ["corp-mirror", "corp-plugins"] {
        let line = format!("demo-maven-plugin-1.jar>{id}=");
        assert!(remote_ids.contains(&line), "{remote_ids}");
    }
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
}

/// A lock whose plugin rows come from a settings.xml plugin repository
/// names only configured origins, so after another machine's sync restored
/// it, an export there, offline too, asks for nothing: it does not resolve
/// the dependency range again.
#[test]
fn an_export_trusts_a_settings_plugin_repository_origin() {
    let metadata = "<metadata><groupId>t</groupId><artifactId>lib</artifactId><versioning>\
                    <versions><version>1</version></versions></versioning></metadata>";
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/t/lib/maven-metadata.xml" => Response::new(200, metadata),
        "/t/lib/maven-metadata.xml.sha256" => Response::new(200, sha256_hex(metadata.as_bytes())),
        _ => serve(request, None, |_| (JAR, true), |_| false),
    });
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
             <version>[1,2)</version></dependency></dependencies><build><plugins><plugin>\
             <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId><version>1</version>\
             </plugin></plugins></build>",
        ),
    )
    .unwrap();
    let settings = format!(
        "<settings><mirrors><mirror><id>corp-mirror</id><url>http://{}/</url>\
         <mirrorOf>*</mirrorOf></mirror></mirrors><profiles><profile><id>corp</id>\
         <pluginRepositories><pluginRepository><id>corp-plugins</id>\
         <url>https://plugins.corp.invalid/maven/</url></pluginRepository>\
         </pluginRepositories></profile></profiles>\
         <activeProfiles><activeProfile>corp</activeProfile></activeProfiles></settings>",
        server.addr()
    );
    fs::write(home.path().join(".m2/settings.xml"), &settings).unwrap();
    assert_success(
        &(raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .unwrap(),
        "sync",
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(
        lock.contains("https://plugins.corp.invalid/maven/"),
        "{lock}"
    );

    let other = TempDir::new().unwrap();
    fs::create_dir_all(other.path().join(".m2")).unwrap();
    fs::write(other.path().join(".m2/settings.xml"), &settings).unwrap();
    let elsewhere = |args: &[&str]| {
        (raeva_command(root, other.path()))
            .args(args)
            .output()
            .expect("run raeva")
    };
    let asked = |before: usize| -> Vec<String> {
        (server.requests()[before..].iter())
            .map(|request| request.path.clone())
            .collect()
    };
    let before = server.requests().len();
    assert_success(&elsewhere(&["sync"]), "sync on another machine");
    let restored = asked(before);
    assert!(
        restored.contains(&"/t/lib/1/lib-1.jar".to_string()),
        "{restored:?}"
    );
    let before = server.requests().len();
    let m2 = other.path().join("m2");
    for offline in [true, false] {
        let mut args = vec!["export-m2", "--m2-path", m2.to_str().unwrap()];
        if offline {
            args.push("--offline");
        }
        assert_success(&elsewhere(&args), "export");
    }
    assert_eq!(asked(before), Vec::<String>::new());
}

/// A settings.xml plugin repository may be a directory, as a configured
/// one may: another machine's sync fetches the plugin the lock pins from it.
/// The plugin's exact version reads no version list, so the export writes
/// none, under no id.
#[test]
fn a_settings_plugin_repository_directory_serves_another_machine() {
    let server = repository();
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let files = TempDir::new().unwrap();
    let dir = files.path().join("t/demo-maven-plugin/1");
    fs::create_dir_all(&dir).unwrap();
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
               <artifactId>demo-maven-plugin</artifactId><version>1</version>\
               <packaging>maven-plugin</packaging></project>";
    for (name, body) in [
        ("demo-maven-plugin-1.pom", pom.as_bytes()),
        ("demo-maven-plugin-1.jar", JAR),
    ] {
        write_with_sha256(&dir.join(name), body);
    }
    let directory = url::Url::from_directory_path(files.path()).unwrap();
    let settings = format!(
        "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
         <mirrorOf>central</mirrorOf></mirror></mirrors><profiles><profile><id>files</id>\
         <pluginRepositories><pluginRepository><id>files</id><url>{directory}</url>\
         </pluginRepository></pluginRepositories></profile><profile><id>spare</id>\
         <pluginRepositories><pluginRepository><id>spare-plugins</id>\
         <url>https://spare.example.invalid/</url></pluginRepository></pluginRepositories>\
         </profile></profiles>\
         <activeProfiles><activeProfile>files</activeProfile></activeProfiles></settings>",
        server.addr()
    );
    fs::write(home.path().join(".m2/settings.xml"), &settings).unwrap();
    assert_success(
        &(raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .unwrap(),
        "sync",
    );
    let tables = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let origin = crate::common::recorded_origin(root, directory.as_str());
    assert!(tables.contains(&format!("\"{origin}")), "{tables}");

    let other = TempDir::new().unwrap();
    fs::create_dir_all(other.path().join(".m2")).unwrap();
    fs::write(other.path().join(".m2/settings.xml"), &settings).unwrap();
    let elsewhere = |args: &[&str]| {
        (raeva_command(root, other.path()))
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&elsewhere(&["sync"]), "sync on another machine");
    let m2 = other.path().join("m2");
    assert_success(
        &elsewhere(&["export-m2", "--m2-path", m2.to_str().unwrap()]),
        "export on another machine",
    );
    assert_eq!(fs::read(dir.join("demo-maven-plugin-1.jar")).unwrap(), JAR);
    assert_eq!(
        fs::read(m2.join("t/demo-maven-plugin/1/demo-maven-plugin-1.jar")).unwrap(),
        JAR
    );
    let lists = (fs::read_dir(m2.join("t/demo-maven-plugin"))
        .unwrap()
        .flatten())
    .filter(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .starts_with("maven-metadata")
    })
    .count();
    assert_eq!(lists, 0);
}

/// A settings.xml plugin repository in a directory under the project keys
/// the plugin tables by its place in the project, so a lock written in one
/// checkout passes `--frozen` in a copy at another path, whose settings.xml
/// names the directory there.
#[test]
fn a_settings_plugin_repository_in_the_project_holds_in_another_checkout() {
    let server = repository();
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let dir = root.join("plugins/t/demo-maven-plugin/1");
    fs::create_dir_all(&dir).unwrap();
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
               <artifactId>demo-maven-plugin</artifactId><version>1</version>\
               <packaging>maven-plugin</packaging></project>";
    for (name, body) in [
        ("demo-maven-plugin-1.pom", pom.as_bytes()),
        ("demo-maven-plugin-1.jar", JAR),
    ] {
        write_with_sha256(&dir.join(name), body);
    }
    let settings = |root: &std::path::Path| {
        let directory = url::Url::from_directory_path(root.join("plugins")).unwrap();
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors><profiles><profile><id>files</id>\
             <pluginRepositories><pluginRepository><id>files</id><url>{directory}</url>\
             </pluginRepository></pluginRepositories></profile></profiles>\
             <activeProfiles><activeProfile>files</activeProfile></activeProfiles></settings>",
            server.addr()
        )
    };
    fs::write(home.path().join(".m2/settings.xml"), settings(root)).unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");

    let other = TempDir::new().unwrap();
    let copy = other.path().join("checkout");
    copy_tree(root, &copy);
    let fresh = TempDir::new().unwrap();
    fs::create_dir_all(fresh.path().join(".m2")).unwrap();
    fs::write(fresh.path().join(".m2/settings.xml"), settings(&copy)).unwrap();
    let frozen = run_raeva(&copy, fresh.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "frozen sync in another checkout");
}

/// Copy the directory `from` to `to`, which does not exist.
fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        match entry.file_type().unwrap().is_dir() {
            true => copy_tree(&entry.path(), &target),
            false => {
                fs::copy(entry.path(), &target).unwrap();
            }
        }
    }
}

/// A POM's plugin repository is admitted as its repositories are: one over
/// external HTTP, which Maven's HTTP blocker refuses, is not searched and
/// raeva.lock does not record it, and one whose URL may hold a secret is
/// refused.
#[test]
fn a_pom_plugin_repository_is_screened_as_a_pom_repository() {
    let server = repository();
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        "<pluginRepositories><pluginRepository><id>plain</id>\
         <url>http://plain.example.invalid/maven/</url></pluginRepository>\
         <pluginRepository><id>keyed</id><url>https://keyed.example.invalid/maven/?k=v</url>\
         </pluginRepository></pluginRepositories><build>",
    );
    fs::write(root.join("pom.xml"), &pom).unwrap();
    let sync = || {
        (raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .expect("run raeva")
    };
    let refused = sync();
    assert_status(&refused, 3, "a plugin repository URL with a query");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("plugin repository 'keyed'"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let keyed = "<pluginRepository><id>keyed</id><url>https://keyed.example.invalid/maven/?k=v</url>\
                 </pluginRepository>";
    assert!(pom.contains(keyed));
    fs::write(root.join("pom.xml"), pom.replace(keyed, "")).unwrap();
    assert_success(&sync(), "sync");
    let tables = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(tables.contains("t:demo-maven-plugin:1"), "{tables}");
    assert!(!tables.contains("plain.example.invalid"), "{tables}");
}

/// A repository the project's POM declares is admitted as a sync admits it
/// before the plugin tables fetch from it: one over external HTTP, which
/// Maven's HTTP blocker refuses, serves no plugin the lock names it for,
/// and the sync resolves the plugins again.
#[test]
fn a_blocked_pom_repository_serves_no_locked_plugin() {
    let server = repository();
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let blocked = "http://plain.example.invalid/maven/";
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        &format!(
            "<repositories><repository><id>plain</id><url>{blocked}</url></repository>\
             </repositories><build>"
        ),
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let sync = |home: &std::path::Path| {
        (raeva_command(root, home))
            .arg("sync")
            .output()
            .expect("run raeva")
    };
    assert_success(&sync(home.path()), "sync");
    let lock_path = root.join("raeva.lock");
    let tables = fs::read_to_string(&lock_path).unwrap();
    let central = "https://repo.maven.apache.org/maven2/";
    assert!(tables.contains(central), "{tables}");
    let named = tables
        .replace(central, blocked)
        .replace("\\tcentral", "\\tplain");
    fs::write(&lock_path, named).unwrap();
    let other = TempDir::new().unwrap();
    fs::create_dir_all(other.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        other.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let resolved = sync(other.path());
    assert_success(&resolved, "sync of a lock naming the blocked repository");
    assert!(
        stderr(&resolved).contains("HTTP_REPO_BLOCKED"),
        "{}",
        stderr(&resolved)
    );
    assert!(fs::read_to_string(&lock_path).unwrap() == tables);
}

/// A settings.xml profile's `<repositories>` serve the dependencies and its
/// `<pluginRepositories>` the plugins, each list only its own.
#[test]
fn settings_repositories_and_plugin_repositories_stay_apart() {
    let (dependencies, plugins) = (repository(), repository());
    let deps_url = format!("http://{}/", dependencies.addr());
    let plugins_url = format!("http://{}/", plugins.addr());
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><profiles><profile><id>corp</id><repositories><repository>\
             <id>corp-deps</id><url>{deps_url}</url></repository></repositories>\
             <pluginRepositories><pluginRepository><id>corp-plugins</id><url>{plugins_url}</url>\
             </pluginRepository></pluginRepositories></profile></profiles>\
             <activeProfiles><activeProfile>corp</activeProfile></activeProfiles></settings>"
        ),
    )
    .unwrap();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
         <version>1</version></dependency></dependencies><build>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let output = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&output, "sync");
    let tables = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let document: toml::Value = toml::from_str(&tables).unwrap();
    let rows = document["platforms"][0]["artifacts"].as_array().unwrap();
    let origin = |artifact: &str| {
        (rows.iter())
            .find(|row| row["coordinate"]["artifact"].as_str() == Some(artifact))
            .and_then(|row| row["repo_url"].as_str())
            .unwrap_or_else(|| panic!("{artifact}: {tables}"))
            .to_string()
    };
    assert_eq!(origin("lib"), deps_url, "{tables}");
    assert_eq!(origin("demo-maven-plugin"), plugins_url, "{tables}");
}

/// `--frozen` accepts the plugin tables a sync just wrote for a module
/// whose dependencies raeva.lock orders otherwise than the resolution:
/// `t:lib-extra` sorts before `t:lib` as text, after it by artifact id.
#[test]
fn frozen_accepts_the_tables_of_dependencies_the_lock_reorders() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
         <version>1</version></dependency><dependency><groupId>t</groupId>\
         <artifactId>lib-extra</artifactId><version>1</version></dependency>\
         </dependencies><build>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
}

/// `--frozen` accepts the plugin tables a sync just wrote for a reactor
/// whose modules raeva.lock orders otherwise than the resolution: the
/// module `a` sorts before the root's `pom.xml`.
#[test]
fn frozen_accepts_the_tables_of_modules_the_lock_reorders() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let parent = fs::read_to_string(root.join("pom.xml"))
        .unwrap()
        .replace("<build>", "<modules><module>a</module></modules><build>");
    fs::write(root.join("pom.xml"), parent).unwrap();
    fs::create_dir_all(root.join("a")).unwrap();
    fs::write(
        root.join("a/pom.xml"),
        pom(
            "a",
            "<parent><groupId>t</groupId><artifactId>app</artifactId><version>1</version>\
             </parent><dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
             <version>1</version></dependency></dependencies>",
        ),
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
}

/// A `<pluginRepository>` the project's own POM declares in its directory
/// is the project's, as its `<repositories>` are: it serves the plugin it
/// holds, and raeva.lock records it as the project's directory.
#[test]
fn a_pom_plugin_repository_in_the_project_serves_its_plugins() {
    let server = repository();
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let dir = root.join("repo/t/demo-maven-plugin/1");
    fs::create_dir_all(&dir).unwrap();
    let plugin_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                      <artifactId>demo-maven-plugin</artifactId><version>1</version>\
                      <packaging>maven-plugin</packaging></project>";
    for (name, body) in [
        ("demo-maven-plugin-1.pom", plugin_pom.as_bytes()),
        ("demo-maven-plugin-1.jar", JAR),
    ] {
        write_with_sha256(&dir.join(name), body);
    }
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        "<pluginRepositories><pluginRepository><id>in-project</id>\
         <url>file://${project.basedir}/repo</url></pluginRepository>\
         </pluginRepositories><build>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let output = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&output, "sync");
    let tables = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let document: toml::Value = toml::from_str(&tables).unwrap();
    let row = (document["platforms"][0]["artifacts"]
        .as_array()
        .unwrap()
        .iter())
    .find(|row| row["coordinate"]["artifact"].as_str() == Some("demo-maven-plugin"))
    .unwrap_or_else(|| panic!("{tables}"));
    assert_eq!(row["repo_url"].as_str(), Some("./repo/"), "{tables}");
}

/// A jar a dependency repository and a plugin repository both serve is one
/// row with the dependency's origin; the export labels it with both ids,
/// since `mvn -o` takes a plugin's file only under a repository the plugin
/// searches, and `sync --frozen` holds the plugin's origin.
#[test]
fn a_file_dependencies_and_plugins_share_is_labelled_with_both_repositories() {
    let server = repository();
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let shared = pom("shared", "");
    let plugin = pom(
        "demo-maven-plugin",
        "<packaging>maven-plugin</packaging><dependencies><dependency><groupId>t</groupId>\
         <artifactId>shared</artifactId><version>1</version></dependency></dependencies>",
    );
    for (repo, artifact, body) in [
        ("deps", "shared", &shared),
        ("plugins", "shared", &shared),
        ("plugins", "demo-maven-plugin", &plugin),
    ] {
        let dir = root.join(format!("{repo}/t/{artifact}/1"));
        fs::create_dir_all(&dir).unwrap();
        write_with_sha256(&dir.join(format!("{artifact}-1.pom")), body.as_bytes());
        write_with_sha256(&dir.join(format!("{artifact}-1.jar")), JAR);
    }
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        "<repositories><repository><id>deps</id><url>file://${project.basedir}/deps</url>\
         </repository></repositories><pluginRepositories><pluginRepository><id>plugins</id>\
         <url>file://${project.basedir}/plugins</url></pluginRepository></pluginRepositories>\
         <dependencies><dependency><groupId>t</groupId><artifactId>shared</artifactId>\
         <version>1</version></dependency></dependencies><build>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--frozen"]),
        "frozen",
    );
    let m2 = home.path().join("m2");
    let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
    assert_success(&run_raeva(root, home.path(), &export), "export");
    let markers = fs::read_to_string(m2.join("t/shared/1/_remote.repositories")).unwrap();
    for line in ["shared-1.jar>deps=", "shared-1.jar>plugins="] {
        assert!(markers.lines().any(|found| found == line), "{markers}");
    }
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let without: String = (lock.lines())
        .filter(|line| !line.starts_with("shared_origins = "))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_ne!(without, lock);
    fs::write(root.join("raeva.lock"), without).unwrap();
    let stale = run_raeva(root, home.path(), &["sync", "--frozen"]);
    assert_status(&stale, 7, "a lock without the plugin's origin");
}

/// A plugin repository URL that takes an allowlisted variable's value is
/// reported once the plugin tables are in raeva.lock, as a dependency
/// repository's is, and the warning does not show the value.
#[test]
fn an_allowlisted_value_in_a_plugin_repository_url_is_reported() {
    const VALUE: &str = "corp-plugins-4711";
    let server = repository();
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_env_substitution = [\"CORP_DIR\"]\n",
    )
    .unwrap();
    let dir = root.join(VALUE).join("t/demo-maven-plugin/1");
    fs::create_dir_all(&dir).unwrap();
    let plugin_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                      <artifactId>demo-maven-plugin</artifactId><version>1</version>\
                      <packaging>maven-plugin</packaging></project>";
    for (name, body) in [
        ("demo-maven-plugin-1.pom", plugin_pom.as_bytes()),
        ("demo-maven-plugin-1.jar", JAR),
    ] {
        write_with_sha256(&dir.join(name), body);
    }
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        "<pluginRepositories><pluginRepository><id>corp</id>\
         <url>file://${project.basedir}/${env.CORP_DIR}</url></pluginRepository>\
         </pluginRepositories><build>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let output = (raeva_command(root, home.path()))
        .env("CORP_DIR", VALUE)
        .args(["--json", "sync"])
        .output()
        .expect("run raeva");
    assert_success(&output, "sync");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(VALUE), "{stdout}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("JSON");
    let mut fields: Vec<_> = (envelope["data"]["warnings"]
        .as_array()
        .into_iter()
        .flatten())
    .filter(|warning| warning["code"] == "ENV_VALUE_IN_LOCKFILE")
    .map(|warning| {
        let context = &warning["context"];
        assert_eq!(context["env_var"], "CORP_DIR", "{warning}");
        format!("{} of {}", context["field"], context["row"])
    })
    .collect();
    fields.sort();
    assert!(
        fields
            .iter()
            .any(|field| field.contains("demo-maven-plugin"))
            && fields.iter().any(|field| field.contains("plugin set"))
            && fields
                .iter()
                .any(|field| field.contains("plugins.repo_ids")),
        "{fields:?}"
    );
}

/// The test engine surefire takes from the project's repositories comes
/// from those its POM may name: one over external HTTP, which Maven's HTTP
/// blocker refuses, is not searched, and raeva.lock does not record it.
#[test]
fn a_test_engine_skips_a_blocked_pom_repository() {
    let server = repository();
    let root = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    fs::write(root.path().join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        root.path().join("pom.xml"),
        pom(
            "app",
            "<repositories><repository><id>plain</id>\
             <url>http://plain.example.invalid/maven/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.junit.jupiter</groupId>\
             <artifactId>junit-jupiter-api</artifactId><version>5.10.0</version>\
             <scope>test</scope></dependency><dependency>\
             <groupId>org.junit.platform</groupId><artifactId>junit-platform-commons</artifactId>\
             <version>1.10.0</version><scope>test</scope></dependency></dependencies>",
        ),
    )
    .unwrap();
    let output = (raeva_command(root.path(), home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&output, "sync");
    let tables = fs::read_to_string(root.path().join("raeva.lock")).unwrap();
    assert!(tables.contains("junit-jupiter-engine"), "{tables}");
    assert!(!tables.contains("plain.example.invalid"), "{tables}");
}

/// Surefire takes the Jupiter API, whose version gives the engine it adds,
/// from a map by `groupId:artifactId` of the test class path in Maven's
/// order, so the last of two classifiers wins: the declared order decides,
/// a dependency's own after it and before the next. Where the lock and the
/// POMs cannot tell the order, and it matters, the sync refuses.
#[test]
fn the_engine_follows_the_last_jupiter_api_of_the_test_class_path() {
    let api = |version: &str, classifier: &str| {
        format!(
            "<dependency><groupId>org.junit.jupiter</groupId>\
             <artifactId>junit-jupiter-api</artifactId><version>{version}</version>\
             {classifier}<scope>test</scope></dependency>"
        )
    };
    let on = |artifact: &str| {
        format!(
            "<dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version><scope>test</scope></dependency>"
        )
    };
    let (main, sources) = (
        api("5.11.0", ""),
        api("5.9.3", "<classifier>sources</classifier>"),
    );
    let poms = [
        ("t/params/1/params-1.pom", main.clone()),
        ("t/src/1/src-1.pom", sources.clone()),
        ("t/both/1/both-1.pom", format!("{main}{}", on("src"))),
        ("t/deep/1/deep-1.pom", on("params")),
    ]
    .map(|(path, dependencies)| {
        let artifact = path.split('/').nth(1).unwrap().to_string();
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version>\
             <dependencies>{}</dependencies></project>",
            dependencies.replace("<scope>test</scope>", "")
        );
        (path.to_string(), pom)
    });
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let pom = (poms.iter()).find(|(pom, _)| path.trim_end_matches(".sha256") == pom);
        match pom {
            Some((_, pom)) => serve_sha256(path, |_| Some(pom.as_bytes())),
            None if path.trim_end_matches(".sha256").ends_with("-sources.jar") => {
                serve_sha256(path, |_| Some(JAR))
            }
            None => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let commons = "<dependency><groupId>org.junit.platform</groupId>\
                   <artifactId>junit-platform-commons</artifactId><version>1.11.0</version>\
                   <scope>test</scope></dependency>";
    let sync = |dependencies: &[&str]| {
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<dependencies>{}{commons}</dependencies><build><plugins><plugin>\
                     <artifactId>maven-surefire-plugin</artifactId><version>3.2.5</version>\
                     </plugin></plugins></build>",
                    dependencies.concat()
                ),
            ),
        )
        .unwrap();
        run_raeva(root, home.path(), &["sync"])
    };
    let engine = |version: &str| format!("org.junit.jupiter:junit-jupiter-engine:jar:{version}");
    for (dependencies, taken, other) in [
        (&[main.as_str(), &sources][..], "5.9.3", "5.11.0"),
        (&[&sources, &main], "5.11.0", "5.9.3"),
        (&[&on("params"), &sources], "5.9.3", "5.11.0"),
        (&[&sources, &on("params")], "5.11.0", "5.9.3"),
        // Maven puts the API under the nearer `t:params`, after the
        // sources.
        (&[&on("deep"), &sources, &on("params")], "5.11.0", "5.9.3"),
    ] {
        let output = sync(dependencies);
        assert_success(&output, taken);
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(lock.contains(&engine(taken)), "{taken}: {lock}");
        assert!(!lock.contains(&engine(other)), "{taken}: {lock}");
        let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
        assert_success(&frozen, taken);
    }
    // Under `t:both` the order is that of its POM, which the lock does not
    // keep.
    let refused = sync(&[&on("both")]);
    assert_eq!(refused.status.code(), Some(5), "{}", stderr(&refused));
    let said = stderr(&refused);
    assert!(
        said.contains("org.junit.jupiter:junit-jupiter-api"),
        "{said}"
    );
}

/// A goal run from the command line takes the configuration of its
/// execution, else its plugin's, from the build plugins or their
/// management, as Maven configures it: managed `groups` give Failsafe the
/// JUnit 4.7 provider, and an execution of the goal's id keeps its own.
/// Another goal of the plugin, or a goal of a build plugin beside its
/// lifecycle runs, is a run of its own with its own provider.
#[test]
fn a_goal_takes_the_configuration_that_picks_its_test_provider() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_file(root.join(".mvn/extensions.xml")).unwrap();
    let lock = |goals: &[&str], executions: &str, managed: bool| {
        let (open, close) = match managed {
            true => ("<pluginManagement>", "</pluginManagement>"),
            false => ("", ""),
        };
        fs::write(
            root.join("raeva.toml"),
            format!("[plugins]\nlock = true\ngoals = {goals:?}\n"),
        )
        .unwrap();
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<packaging>pom</packaging><dependencies><dependency><groupId>junit\
                     </groupId><artifactId>junit</artifactId><version>4.13.2</version>\
                     <scope>test</scope></dependency></dependencies><build>{open}\
                     <plugins><plugin>\
                     <artifactId>maven-failsafe-plugin</artifactId><version>3.5.0</version>\
                     <configuration><groups>it</groups></configuration>{executions}\
                     </plugin></plugins>{close}</build>"
                ),
            ),
        )
        .unwrap();
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        fs::read_to_string(root.join("raeva.lock")).unwrap()
    };
    let goal = "org.apache.maven.plugins:maven-failsafe-plugin:integration-test";
    let tables = lock(&[goal], "", true);
    assert!(tables.contains("surefire-junit47:3.5.0"), "{tables}");
    let own = "<executions><execution><id>plain</id><configuration combine.self=\"override\">\
               </configuration></execution></executions>";
    let plain = format!("{goal}@plain");
    let tables = lock(&[&plain], own, true);
    assert!(tables.contains("surefire-junit4:3.5.0"), "{tables}");
    assert!(!tables.contains("surefire-junit47"), "{tables}");
    let tables = lock(&[&plain, goal], own, true);
    assert!(tables.contains("surefire-junit47:3.5.0"), "{tables}");
    assert!(tables.contains("surefire-junit4:3.5.0"), "{tables}");
    let lifecycle = "<executions><execution><id>it</id><goals><goal>integration-test</goal>\
                     </goals><configuration combine.self=\"override\"></configuration>\
                     </execution></executions>";
    let tables = lock(&[goal], lifecycle, false);
    assert!(tables.contains("surefire-junit47:3.5.0"), "{tables}");
    assert!(tables.contains("surefire-junit4:3.5.0"), "{tables}");
}

/// A processor path and a test engine resolve from the project's
/// repositories as Maven 3.9 and 3.10 list them, the POM's before Central:
/// the POM's repository serves the processor jar Central also has, and each
/// set records that order.
#[test]
fn processor_paths_and_test_engines_search_the_pom_repositories_first() {
    let central = repository();
    let own = StubServer::start(|request| match request.path.starts_with("/t/proc/") {
        true => serve(request, None, |_| (OTHER_JAR, true), |_| false),
        false => Response::new(404, ""),
    });
    let root = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            central.addr()
        ),
    )
    .unwrap();
    fs::write(root.path().join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let own_url = format!("http://{}/", own.addr());
    fs::write(
        root.path().join("pom.xml"),
        pom(
            "app",
            &format!(
                "<repositories><repository><id>own</id><url>{own_url}</url></repository>\
                 </repositories><dependencies><dependency><groupId>org.junit.jupiter</groupId>\
                 <artifactId>junit-jupiter-api</artifactId><version>5.10.0</version>\
                 <scope>test</scope></dependency><dependency>\
                 <groupId>org.junit.platform</groupId>\
                 <artifactId>junit-platform-commons</artifactId><version>1.10.0</version>\
                 <scope>test</scope></dependency></dependencies><build><plugins><plugin>\
                 <artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version>\
                 <configuration><annotationProcessorPaths><path><groupId>t</groupId>\
                 <artifactId>proc</artifactId><version>1</version></path>\
                 </annotationProcessorPaths></configuration></plugin></plugins></build>"
            ),
        ),
    )
    .unwrap();
    let output = (raeva_command(root.path(), home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&output, "sync");
    let lock = fs::read_to_string(root.path().join("raeva.lock")).unwrap();
    assert!(lock.contains(&sha256_hex(OTHER_JAR)), "{lock}");
    for coordinate in [
        "t:proc:jar:1",
        "org.junit.jupiter:junit-jupiter-engine:jar:5.10.0",
    ] {
        let set = format!(
            "coordinates = [\"{coordinate}\"]\nrepo_urls = [\n    \"{own_url}\",\n    \
             \"https://repo1.maven.org/maven2/\",\n]\n"
        );
        assert!(lock.contains(&set), "{set}\n{lock}");
    }
}

/// maven-compiler-plugin before 3.9.0 roots its legacy processor path
/// request at the first path. When the reactor builds that one, its POM's
/// dependencies still come in beside the other paths, as Maven 3.9.12 puts
/// `pdep` on the `-processorpath`, and neither its own jar nor that of a
/// reactor module it depends on is locked.
#[test]
fn a_legacy_processor_path_rooted_in_the_reactor_takes_its_pom_dependencies() {
    let central = central();
    let jar = |artifact: &str| (format!("/t/{artifact}/1/{artifact}-1.jar"), JAR.to_vec());
    let library = |artifact: &str, dependencies: &str| {
        (
            format!("/t/{artifact}/1/{artifact}-1.pom"),
            pom(artifact, dependencies).into_bytes(),
        )
    };
    let odep = "<dependencies><dependency><groupId>t</groupId><artifactId>odep</artifactId>\
                <version>1</version></dependency></dependencies>";
    let own = sha256_repository([
        library("pdep", ""),
        jar("pdep"),
        library("odep", ""),
        jar("odep"),
        library("other", odep),
        jar("other"),
    ]);
    let root = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            central.addr()
        ),
    )
    .unwrap();
    fs::write(root.path().join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let parent = "<parent><groupId>t</groupId><artifactId>app</artifactId><version>1</version>\
                  </parent>";
    fs::write(
        root.path().join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><modules><module>api</module><module>proc</module>\
                 <module>user</module></modules><repositories><repository><id>own</id><url>http://{}/</url>\
                 </repository></repositories>",
                own.addr()
            ),
        ),
    )
    .unwrap();
    let path = |artifact: &str| {
        format!(
            "<path><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version></path>"
        )
    };
    for (name, body) in [
        (
            "proc",
            format!(
                "{parent}<dependencies><dependency><groupId>t</groupId><artifactId>pdep\
                 </artifactId><version>1</version></dependency><dependency>\
                 <groupId>t</groupId><artifactId>api</artifactId><version>1</version>\
                 </dependency></dependencies>"
            ),
        ),
        ("api", parent.to_string()),
        (
            "user",
            format!(
                "{parent}<build><plugins><plugin><artifactId>maven-compiler-plugin</artifactId>\
                 <version>3.8.1</version><configuration><annotationProcessorPaths>{}{}\
                 </annotationProcessorPaths></configuration></plugin></plugins></build>",
                path("proc"),
                path("other")
            ),
        ),
    ] {
        fs::create_dir_all(root.path().join(name)).unwrap();
        fs::write(root.path().join(name).join("pom.xml"), pom(name, &body)).unwrap();
    }
    assert_success(&run_raeva(root.path(), home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.path().join("raeva.lock")).unwrap();
    let document: toml::Value = toml::from_str(&lock).unwrap();
    let sets = document["platforms"][0]["plugins"]["sets"]
        .as_array()
        .unwrap();
    let paths: Vec<_> = (sets.iter())
        .filter(|set| set["role"].as_str() == Some("processor-path"))
        .collect();
    assert_eq!(paths.len(), 1, "{lock}");
    assert_eq!(
        paths[0]["artifacts"].as_str(),
        Some("t:odep:1\tjar\nt:other:1\tjar\nt:pdep:1\tjar"),
        "{lock}"
    );
}

/// A POM `central` on another URL that the mirror of Central does not
/// match keeps Central beside it, as Maven compares the ids mirrors give
/// them: a processor path searches the POM's first, then Central.
#[test]
fn a_processor_path_keeps_central_beside_a_pom_central_the_mirror_skips() {
    let central = repository();
    let own = StubServer::start(|request| match request.path.starts_with("/t/proc/") {
        true => serve(request, None, |_| (OTHER_JAR, true), |_| false),
        false => Response::new(404, ""),
    });
    let root = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>external:*</mirrorOf></mirror></mirrors></settings>",
            central.addr()
        ),
    )
    .unwrap();
    fs::write(root.path().join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let own_url = format!("http://{}/", own.addr());
    let path = |artifact: &str| {
        format!(
            "<path><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version></path>"
        )
    };
    fs::write(
        root.path().join("pom.xml"),
        pom(
            "app",
            &format!(
                "<repositories><repository><id>central</id><url>{own_url}</url></repository>\
                 </repositories><build><plugins><plugin>\
                 <artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version>\
                 <configuration><annotationProcessorPaths>{}{}</annotationProcessorPaths>\
                 </configuration></plugin></plugins></build>",
                path("proc"),
                path("only")
            ),
        ),
    )
    .unwrap();
    let output = (raeva_command(root.path(), home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&output, "sync");
    let lock = fs::read_to_string(root.path().join("raeva.lock")).unwrap();
    assert!(lock.contains(&sha256_hex(OTHER_JAR)), "{lock}");
    let set = format!(
        "coordinates = [\n    \"t:proc:jar:1\",\n    \"t:only:jar:1\",\n]\nrepo_urls = [\n    \
         \"{own_url}\",\n    \"https://repo1.maven.org/maven2/\",\n]\n"
    );
    assert!(lock.contains(&set), "{set}\n{lock}");
}

/// A settings.xml plugin repository at the URL and id of a repository keeps
/// its own policy when another machine fetches the plugins locked from it:
/// the repository takes no releases, the plugin repository does.
#[test]
fn a_plugin_repository_keeps_its_policy_beside_a_repository_of_its_id() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let settings = format!(
        "<settings><profiles><profile><id>corp</id><repositories><repository><id>corp</id>\
         <url>{url}</url><releases><enabled>false</enabled></releases></repository>\
         </repositories><pluginRepositories><pluginRepository><id>corp</id><url>{url}</url>\
         </pluginRepository></pluginRepositories></profile></profiles>\
         <activeProfiles><activeProfile>corp</activeProfile></activeProfiles></settings>"
    );
    fs::write(home.path().join(".m2/settings.xml"), &settings).unwrap();
    let sync = |home: &std::path::Path| {
        (raeva_command(root, home))
            .arg("sync")
            .output()
            .expect("run raeva")
    };
    assert_success(&sync(home.path()), "sync");
    let tables = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let other = TempDir::new().unwrap();
    fs::create_dir_all(other.path().join(".m2")).unwrap();
    fs::write(other.path().join(".m2/settings.xml"), &settings).unwrap();
    assert_success(&sync(other.path()), "sync on another machine");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), tables);
}

/// A plugin repository behind a blocked mirror gets no request, and the
/// plugin's version is read from the next plugin repository, as Maven
/// moves on past a blocked one.
#[test]
fn a_plugin_version_is_read_past_a_blocked_repository() {
    const METADATA: &str = "<metadata><groupId>t</groupId>\
        <artifactId>demo-maven-plugin</artifactId><versioning><latest>1</latest>\
        <release>1</release><versions><version>1</version></versions></versioning></metadata>";
    const PREFIXES: &str = "<metadata><plugins><plugin><name>demo</name><prefix>demo</prefix>\
        <artifactId>demo-maven-plugin</artifactId></plugin></plugins></metadata>";
    let server = StubServer::start(|request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        let body = match path {
            "/t/demo-maven-plugin/maven-metadata.xml" => METADATA,
            "/t/maven-metadata.xml" => PREFIXES,
            _ => return serve(request, None, |_| (JAR, true), |_| false),
        };
        match sidecar {
            true => Response::new(200, sha256_hex(body.as_bytes())),
            false => Response::new(200, body),
        }
    });
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>walled-off</id><url>http://0.0.0.0/</url>\
             <mirrorOf>walled</mirrorOf><blocked>true</blocked></mirror><mirror><id>stub</id>\
             <url>http://{}/</url><mirrorOf>*,!walled</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><pluginRepositories><pluginRepository><id>walled</id>\
             <url>https://walled.example/</url></pluginRepository></pluginRepositories>\
             <build><plugins><plugin><groupId>t</groupId>\
             <artifactId>demo-maven-plugin</artifactId><executions><execution>\
             <phase>validate</phase><goals><goal>run</goal></goals></execution></executions>\
             </plugin></plugins></build>",
        ),
    )
    .unwrap();
    // The version, and then the plugin of the goal's prefix too.
    for toml in ["", "goals = [\"demo:run\"]\n"] {
        fs::write(
            project.path().join("raeva.toml"),
            format!("[plugins]\nlock = true\n{toml}"),
        )
        .unwrap();
        let output = (raeva_command(project.path(), home.path()))
            .arg("sync")
            .output()
            .expect("run raeva");
        assert_success(&output, toml);
        let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
        assert!(lock.contains("t:demo-maven-plugin:1"), "{lock}");
    }
}

/// Maven resolves a core extension's class path without the jars Maven
/// core exports, and a plugin's without those a build extension exports by
/// artifactId or groupId:artifactId, but with what they depend on: raeva
/// resolves none of the exported jars, or a plugin's `provided` ones, and
/// never asks for them, so a seed of the lock restores everything an
/// offline frozen check reads.
#[test]
fn exported_artifacts_are_not_downloaded() {
    let dependency = |coordinate: &str| {
        let (coordinate, scope) = coordinate
            .split_once(' ')
            .unwrap_or((coordinate, "compile"));
        let [group, artifact, version] = coordinate.split(':').collect::<Vec<_>>()[..] else {
            panic!("{coordinate}");
        };
        format!(
            "<dependency><groupId>{group}</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version><scope>{scope}</scope></dependency>"
        )
    };
    let project_pom = |coordinate: &str, dependencies: &[&str]| {
        let [group, artifact, version] = coordinate.split(':').collect::<Vec<_>>()[..] else {
            panic!("{coordinate}");
        };
        let dependencies: String = dependencies.iter().map(|d| dependency(d)).collect();
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>{group}</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>\
             <dependencies>{dependencies}</dependencies></project>"
        )
    };
    let mut files = std::collections::HashMap::new();
    for (coordinate, dependencies) in [
        (
            "t:ext:1",
            &["org.apache.maven:maven-model:3.9.12", "t:own:1"][..],
        ),
        ("org.apache.maven:maven-model:3.9.12", &["t:child:1"]),
        (
            "t:demo-maven-plugin:1",
            &["t:shared:1", "t:prov:1 provided"],
        ),
        ("t:prov:1", &[]),
        ("t:shared:1", &["t:below-shared:1"]),
        ("t:child:1", &[]),
        ("t:own:1", &[]),
        ("t:below-shared:1", &[]),
        ("t:bext:1", &[]),
    ] {
        let [group, artifact, version] = coordinate.split(':').collect::<Vec<_>>()[..] else {
            panic!("{coordinate}");
        };
        let file = format!(
            "/{}/{artifact}/{version}/{artifact}-{version}",
            group.replace('.', "/")
        );
        files.insert(
            format!("{file}.pom"),
            project_pom(coordinate, dependencies).into_bytes(),
        );
        let jar = match artifact {
            "bext" => jar_with(
                "META-INF/maven/extension.xml",
                "<extension><exportedArtifacts><exportedArtifact>shared</exportedArtifact>\
                 </exportedArtifacts></extension>",
            ),
            _ => JAR.to_vec(),
        };
        files.insert(format!("{file}.jar"), jar);
    }
    let server = StubServer::start(move |request| {
        match files.contains_key(request.path.trim_end_matches(".sha256")) {
            true => serve_sha256(&request.path, |path| files.get(path)),
            false => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fs::remove_file(root.join(".mvn/maven.config")).unwrap();
    fs::write(
        root.join(".mvn/extensions.xml"),
        "<extensions><extension><groupId>t</groupId><artifactId>ext</artifactId>\
         <version>1</version></extension></extensions>",
    )
    .unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><build><extensions><extension><groupId>t</groupId>\
             <artifactId>bext</artifactId><version>1</version></extension></extensions>\
             <plugins><plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
             <version>1</version><executions><execution><phase>validate</phase><goals>\
             <goal>run</goal></goals></execution></executions></plugin></plugins></build>",
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let unwanted_asked = || {
        let asked: Vec<_> = (server.requests().into_iter())
            .map(|request| request.path)
            .filter(|path| {
                ["/maven-model-3.9.12.jar", "/shared-1.jar", "/prov-1.jar"]
                    .iter()
                    .any(|jar| path.ends_with(jar))
            })
            .collect();
        assert!(asked.is_empty(), "{asked:?}");
    };
    // Maven 3.10 collects breadth first.
    let maven_310 = TempDir::new().unwrap();
    fs::create_dir_all(maven_310.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        maven_310.path().join(".m2/settings.xml"),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n",
    )
    .unwrap();
    assert_success(&run_raeva(root, maven_310.path(), &["sync"]), "3.10 sync");
    unwanted_asked();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    unwanted_asked();
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for jar in ["t:child:1\\tjar", "t:below-shared:1\\tjar", "t:own:1\\tjar"] {
        assert!(lock.contains(jar), "{jar}: {lock}");
    }
    for jar in ["maven-model:3.9.12\\tjar", "t:shared:1\\tjar"] {
        assert!(!lock.contains(jar), "{jar}: {lock}");
    }
    let seed = home.path().join("seed");
    let saved = run_raeva(root, home.path(), &["seed", "save", seed.to_str().unwrap()]);
    assert_success(&saved, "seed save");
    let restored_home = TempDir::new().unwrap();
    fs::create_dir_all(restored_home.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        restored_home.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let restore = ["seed", "restore", seed.to_str().unwrap()];
    assert_success(
        &run_raeva(root, restored_home.path(), &restore),
        "seed restore",
    );
    let offline = ["--offline", "sync", "--frozen"];
    assert_success(
        &run_raeva(root, restored_home.path(), &offline),
        "offline frozen sync",
    );
}

/// Maven reads a plugin's version metadata, and the group metadata of a
/// goal's prefix, past a plugin repository that refuses or fails the
/// request, as raeva reads a dependency's versions. An offline frozen check
/// on the same home, which has nothing cached from that repository, holds.
#[test]
fn a_plugin_version_and_prefix_are_read_past_a_failing_repository() {
    const METADATA: &str = "<metadata><groupId>t</groupId>\
        <artifactId>demo-maven-plugin</artifactId><versioning><latest>2</latest>\
        <release>2</release><versions><version>1</version><version>2</version></versions>\
        </versioning></metadata>";
    const PREFIXES: &str = "<metadata><plugins><plugin><name>demo</name><prefix>demo</prefix>\
        <artifactId>demo-maven-plugin</artifactId></plugin></plugins></metadata>";
    let server = StubServer::start(|request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        let body = match path {
            "/t/demo-maven-plugin/maven-metadata.xml" => METADATA,
            "/t/maven-metadata.xml" => PREFIXES,
            _ => return serve(request, None, |_| (JAR, true), |_| false),
        };
        match sidecar {
            true => Response::new(200, sha256_hex(body.as_bytes())),
            false => Response::new(200, body),
        }
    });
    for status in [401, 403, 500] {
        let failing = StubServer::start(move |_| Response::new(status, ""));
        let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
        fs::remove_dir_all(project.path().join(".mvn")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><pluginGroups><pluginGroup>t</pluginGroup></pluginGroups>\
                 <mirrors><mirror><id>stub</id><url>http://{}/</url>\
                 <mirrorOf>*,!corp-private</mirrorOf></mirror></mirrors></settings>",
                server.addr()
            ),
        )
        .unwrap();
        let declared = "<build><plugins><plugin><groupId>t</groupId>\
            <artifactId>demo-maven-plugin</artifactId><executions><execution>\
            <phase>validate</phase><goals><goal>run</goal></goals></execution></executions>\
            </plugin></plugins></build>";
        // The version of a declared plugin, then the plugin of a goal's
        // prefix and its version.
        for (build, toml) in [(declared, ""), ("", "goals = [\"demo:run\"]\n")] {
            fs::write(
                project.path().join("pom.xml"),
                pom(
                    "app",
                    &format!(
                        "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                         <id>corp-private</id><url>http://{}/</url></pluginRepository>\
                         </pluginRepositories>{build}",
                        failing.addr()
                    ),
                ),
            )
            .unwrap();
            fs::write(
                project.path().join("raeva.toml"),
                format!("[plugins]\nlock = true\n{toml}"),
            )
            .unwrap();
            let output = (raeva_command(project.path(), home.path()))
                .arg("sync")
                .output()
                .expect("run raeva");
            assert_success(&output, &format!("{status} {toml}"));
            let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
            assert!(
                lock.contains("t:demo-maven-plugin:2"),
                "{status} {toml}: {lock}"
            );
            assert!(
                stderr(&output).contains("without repository 'corp-private'"),
                "{status} {toml}: {}",
                stderr(&output)
            );
            let frozen = (raeva_command(project.path(), home.path()))
                .args(["--offline", "sync", "--frozen"])
                .output()
                .expect("run raeva");
            assert_success(&frozen, &format!("{status} {toml} offline frozen"));
        }
    }
}

/// The export's freshness check holds the plugin tables to raeva.toml as
/// `--frozen` does: tables of other goals, and tables raeva.toml does not
/// ask for, are stale.
#[test]
fn an_export_refuses_plugin_tables_raeva_toml_does_not_give() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let settings = project.path().join("raeva.toml");
    fs::write(&settings, "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(project.path(), home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let m2 = home.path().join("m2");
    let export = || raeva(&["export-m2", "--m2-path", m2.to_str().unwrap()]);
    for (settings_text, expected) in [
        (
            Some("[plugins]\nlock = true\ngoals = ['t:demo-maven-plugin:1:run']\n"),
            "resolved from other inputs",
        ),
        (None, "raeva.toml does not ask for"),
    ] {
        match settings_text {
            Some(text) => fs::write(&settings, text).unwrap(),
            None => fs::remove_file(&settings).unwrap(),
        }
        let output = export();
        assert_eq!(output.status.code(), Some(7), "{}", stderr(&output));
        assert!(stderr(&output).contains(expected), "{}", stderr(&output));
        assert!(!m2.exists(), "a stale lock exports nothing");
    }
}

/// `raeva doctor` follows `[plugins] lock = true`: before a sync it says
/// the sync locks the plugins and probes the settings.xml plugin
/// repository, after one it finds the tables, and once raeva.toml drops
/// `[plugins]` it warns that the tables are stale.
#[test]
fn doctor_follows_the_plugin_tables() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>*</mirrorOf></mirror></mirrors><profiles><profile><id>corp</id>\
             <pluginRepositories><pluginRepository><id>corp-plugins</id>\
             <url>https://plugins.example.com/maven2/</url></pluginRepository>\
             </pluginRepositories></profile></profiles>\
             <activeProfiles><activeProfile>corp</activeProfile></activeProfiles></settings>"
        ),
    )
    .unwrap();
    let settings = project.path().join("raeva.toml");
    fs::write(&settings, "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(project.path(), home.path(), args);
    let checks = || {
        let output = raeva(&["--json", "doctor"]);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let value: serde_json::Value = serde_json::from_str(&stdout).expect(&stdout);
        (value["data"]["checks"].as_array().cloned()).expect(&stdout)
    };
    // The plugins row, as its status and code, and its details.
    let plugins = |checks: &[serde_json::Value]| {
        let row = (checks.iter())
            .find(|row| row["check"] == "plugins")
            .expect("a plugins row");
        let code = row["code"].as_str().unwrap_or("-");
        let details = row["details"].as_str().unwrap_or_default();
        (
            format!("{} {code}", row["status"].as_str().unwrap()),
            details.to_string(),
        )
    };
    let before = checks();
    let (status, details) = plugins(&before);
    assert_eq!(status, "info -", "{details}");
    assert!(details.contains("raeva sync locks"), "{details}");
    let probe = "corp-plugins (plugin repository, via mirror stub)";
    assert!(before.iter().any(|row| row["check"] == probe), "{before:?}");

    assert_success(&raeva(&["sync"]), "sync");
    assert_eq!(plugins(&checks()).0, "ok -");

    fs::remove_file(&settings).unwrap();
    assert_eq!(plugins(&checks()).0, "warn PLUGIN_TABLES_STALE");
}

/// A fresh home that a plain sync or `lock verify --download` filled holds
/// what an offline `sync --frozen` reads to resolve the plugins again: the
/// plain sync caches each plugin POM the tables pin, and the verify
/// resolves the plugins as `sync --frozen` does.
#[test]
fn a_fresh_home_caches_what_an_offline_frozen_plugin_check_reads() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    fs::write(
        project.path().join("raeva.toml"),
        "[plugins]\nlock = true\n",
    )
    .unwrap();
    let raeva = |home: &std::path::Path, args: &[&str]| {
        (raeva_command(project.path(), home))
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&raeva(home.path(), &["sync"]), "sync");
    for fill in [&["sync"][..], &["lock", "verify", "--download"]] {
        let fresh = TempDir::new().unwrap();
        fs::create_dir_all(fresh.path().join(".m2")).unwrap();
        fs::copy(
            home.path().join(".m2/settings.xml"),
            fresh.path().join(".m2/settings.xml"),
        )
        .unwrap();
        let filled = raeva(fresh.path(), fill);
        assert_success(&filled, &fill.join(" "));
        assert!(
            !stderr(&filled).contains("FROZEN_RESOLUTION_FAILED"),
            "{}",
            stderr(&filled)
        );
        assert_success(
            &raeva(fresh.path(), &["--offline", "sync", "--frozen"]),
            &format!("offline frozen after {}", fill.join(" ")),
        );
    }
}

/// A POM edit that leaves the dependencies but moves a plugin makes the
/// plugin tables stale, for export-m2 as for `sync --frozen`.
#[test]
fn an_export_refuses_plugin_tables_a_pom_edit_moved() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    fs::write(
        project.path().join("raeva.toml"),
        "[plugins]\nlock = true\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(project.path(), home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let pom_path = project.path().join("pom.xml");
    let text = fs::read_to_string(&pom_path).unwrap();
    let moved = text.replace(
        "<artifactId>demo-maven-plugin</artifactId><version>1</version>",
        "<artifactId>demo-maven-plugin</artifactId><version>2</version>",
    );
    assert_ne!(text, moved);
    fs::write(&pom_path, moved).unwrap();
    let m2 = home.path().join("m2");
    let output = raeva(&["export-m2", "--m2-path", m2.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(7), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("differ from a resolution of the same inputs"),
        "{}",
        stderr(&output)
    );
    assert!(!m2.exists(), "a stale lock exports nothing");
}

/// `sync --update` resolves the plugins again, as it does the dependencies,
/// so a plugin the POM names without a version moves to the new release.
#[test]
fn a_sync_update_moves_a_plugin_to_its_new_release() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, Ordering};
    let release = Arc::new(AtomicU8::new(1));
    let seen = Arc::clone(&release);
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        if path == "t/demo-maven-plugin/maven-metadata.xml" {
            let r = seen.load(Ordering::SeqCst);
            return Response::new(
                200,
                format!(
                    "<metadata><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                     <versioning><release>{r}</release><versions><version>1</version>\
                     <version>2</version></versions><lastUpdated>2026010{r}000000</lastUpdated>\
                     </versioning></metadata>"
                ),
            );
        }
        let parts: Vec<&str> = path.split('/').collect();
        let [group @ .., artifact, version, file] = parts.as_slice() else {
            return Response::new(404, "");
        };
        if *file == format!("{artifact}-{version}.pom") {
            Response::new(
                200,
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                     <artifactId>{artifact}</artifactId><version>{version}</version>\
                     <packaging>maven-plugin</packaging></project>",
                    group.join(".")
                ),
            )
        } else if *file == format!("{artifact}-{version}.jar") {
            Response::new(200, JAR.to_vec())
        } else {
            Response::new(404, "")
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    fs::write(
        project.path().join("raeva.toml"),
        "[plugins]\nlock = true\n",
    )
    .unwrap();
    let pom_path = project.path().join("pom.xml");
    let text = fs::read_to_string(&pom_path).unwrap().replace(
        "<artifactId>demo-maven-plugin</artifactId><version>1</version>",
        "<artifactId>demo-maven-plugin</artifactId>",
    );
    fs::write(&pom_path, text).unwrap();
    let raeva = |args: &[&str]| run_raeva(project.path(), home.path(), args);
    let locked = |version: &str| {
        let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
        lock.contains(&format!("t:demo-maven-plugin:{version}\\t"))
    };
    assert_success(&raeva(&["sync", "--allow-missing-checksums"]), "sync");
    assert!(locked("1"));
    release.store(2, Ordering::SeqCst);
    let update = raeva(&["sync", "--update", "--allow-missing-checksums"]);
    assert_success(&update, "sync --update");
    assert!(locked("2") && !locked("1"), "{}", stderr(&update));
}

/// Two plugins that share a dependency both pin the parent POM that
/// dependency's model reads, whichever set builds the model first, so
/// every sync writes one lock and `--frozen` accepts it.
#[test]
fn plugins_sharing_a_dependency_each_pin_its_parent() {
    let server = StubServer::start(|request| {
        let path = request.path.trim_start_matches('/');
        let (path, sidecar) = match path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (path, false),
        };
        let project = |artifact: &str, body: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>{artifact}</artifactId><version>1</version>{body}</project>"
            )
        };
        let shared = "<dependencies><dependency><groupId>t</groupId>\
                      <artifactId>shared</artifactId><version>1</version></dependency>\
                      </dependencies>";
        let body = match path {
            "t/a-maven-plugin/1/a-maven-plugin-1.pom" => project(
                "a-maven-plugin",
                &format!("<packaging>maven-plugin</packaging>{shared}"),
            ),
            "t/b-maven-plugin/1/b-maven-plugin-1.pom" => project(
                "b-maven-plugin",
                "<packaging>maven-plugin</packaging><dependencies><dependency>\
                 <groupId>t</groupId><artifactId>slow</artifactId><version>1</version>\
                 </dependency></dependencies>",
            ),
            // The other set builds the shared model first.
            "t/slow/1/slow-1.pom" if !sidecar => {
                return Response::new(200, project("slow", shared))
                    .delayed(std::time::Duration::from_millis(500));
            }
            "t/slow/1/slow-1.pom" => project("slow", shared),
            "t/shared/1/shared-1.pom" => "<project><modelVersion>4.0.0</modelVersion>\
                 <parent><groupId>t</groupId><artifactId>shared-parent</artifactId>\
                 <version>1</version></parent><artifactId>shared</artifactId></project>"
                .to_string(),
            "t/shared-parent/1/shared-parent-1.pom" => {
                project("shared-parent", "<packaging>pom</packaging>")
            }
            "t/c-maven-plugin/1/c-maven-plugin-1.pom" => {
                project("c-maven-plugin", "<packaging>maven-plugin</packaging>")
            }
            _ if path.ends_with(".jar") => {
                return Response::new(
                    200,
                    if sidecar {
                        sha256_hex(JAR).into_bytes()
                    } else {
                        JAR.to_vec()
                    },
                );
            }
            // Maven's own plugins, with a POM each.
            _ if path.ends_with(".pom") && !path.starts_with("t/") => {
                let parts: Vec<&str> = path.split('/').collect();
                let [group @ .., artifact, version, _] = parts.as_slice() else {
                    return Response::new(404, "");
                };
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                     <artifactId>{artifact}</artifactId><version>{version}</version>\
                     <packaging>maven-plugin</packaging></project>",
                    group.join(".")
                )
            }
            _ => return Response::new(404, ""),
        };
        match sidecar {
            true => Response::new(200, sha256_hex(body.as_bytes())),
            false => Response::new(200, body),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    let plugin = |artifact: &str| {
        format!(
            "<plugin><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>1</version><executions><execution><phase>validate</phase>\
             <goals><goal>run</goal></goals></execution></executions></plugin>"
        )
    };
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><build><plugins>{}{}{}</plugins></build>",
                plugin("a-maven-plugin"),
                plugin("b-maven-plugin"),
                plugin("c-maven-plugin")
            ),
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let sync = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&sync, "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let document: toml::Value = toml::from_str(&lock).unwrap();
    let sets = document["platforms"][0]["plugins"]["sets"]
        .as_array()
        .unwrap();
    for artifact in ["a-maven-plugin", "b-maven-plugin"] {
        let coordinate = format!("t:{artifact}:1");
        let set = sets
            .iter()
            .find(|set| set["coordinates"][0].as_str() == Some(coordinate.as_str()))
            .unwrap_or_else(|| panic!("no set for {coordinate}: {lock}"));
        let poms = set.get("support_poms").and_then(toml::Value::as_str);
        assert!(
            poms.is_some_and(|poms| poms.lines().any(|pom| pom == "t:shared-parent:1")),
            "{coordinate}: {lock}"
        );
    }
    // Each sync writes these bytes, and --frozen accepts them.
    for run in 0..5 {
        fs::remove_file(root.join("raeva.lock")).unwrap();
        let again = (raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .expect("run raeva");
        assert_success(&again, "sync again");
        assert_eq!(
            fs::read_to_string(root.join("raeva.lock")).unwrap(),
            lock,
            "run {run}"
        );
        let frozen = (raeva_command(root, home.path()))
            .args(["sync", "--frozen"])
            .output()
            .expect("run raeva");
        assert_success(&frozen, &format!("frozen run {run}"));
    }
}

/// A plugin dependency of a type with an implied classifier takes the main
/// jar with an empty `<classifier/>` and the classifier's jar without one,
/// as Maven 3.9.12 and 3.10.0 download both, so two modules that differ
/// only by the empty classifier lock a set each.
#[test]
fn an_empty_plugin_dependency_classifier_keys_a_set_of_its_own() {
    const TESTS_JAR: &[u8] = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x05\0tests";
    // The plugins as [`repository`] serves them, and helper's two jars.
    let server = StubServer::start(|request| {
        let path = request.path.trim_start_matches("/t/helper/1/");
        match path.trim_end_matches(".sha256") {
            "helper-1.jar" => serve_sha256(path, |_| Some(OTHER_JAR)),
            "helper-1-tests.jar" => serve_sha256(path, |_| Some(TESTS_JAR)),
            _ => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
        ),
    )
    .unwrap();
    for (name, classifier) in [("a", ""), ("b", "<classifier/>")] {
        fs::create_dir_all(root.join(name)).unwrap();
        let body = format!(
            "<parent><groupId>t</groupId><artifactId>app</artifactId><version>1</version>\
             </parent><packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
             <artifactId>h-maven-plugin</artifactId><version>1</version><executions>\
             <execution><phase>validate</phase><goals><goal>run</goal></goals></execution>\
             </executions><dependencies><dependency><groupId>t</groupId>\
             <artifactId>helper</artifactId><version>1</version><type>test-jar</type>\
             {classifier}</dependency></dependencies></plugin></plugins></build>"
        );
        fs::write(root.join(name).join("pom.xml"), pom(name, &body)).unwrap();
    }
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let document: toml::Value = toml::from_str(&lock).unwrap();
    let sets = document["platforms"][0]["plugins"]["sets"]
        .as_array()
        .unwrap();
    let mut helpers: Vec<&str> = (sets.iter())
        .filter_map(|set| set["artifacts"].as_str())
        .flat_map(str::lines)
        .filter(|line| line.starts_with("t:helper:"))
        .collect();
    helpers.sort_unstable();
    assert_eq!(
        helpers,
        ["t:helper:1\tjar", "t:helper:1\tjar:tests"],
        "{lock}"
    );
    let m2 = TempDir::new().unwrap();
    let export = ["export-m2", "--m2-path", m2.path().to_str().unwrap()];
    assert_success(&run_raeva(root, home.path(), &export), "export-m2");
    for (file, bytes) in [
        ("helper-1.jar", OTHER_JAR),
        ("helper-1-tests.jar", TESTS_JAR),
    ] {
        let exported = fs::read(m2.path().join("t/helper/1").join(file)).unwrap();
        assert_eq!(exported, bytes, "{file}");
    }
    let clean = TempDir::new().unwrap();
    fs::create_dir_all(clean.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        clean.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let frozen = run_raeva(root, clean.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "frozen on a clean home");
}

/// A repository that serves the POM `poms` gives the body of, by
/// artifactId, for every `g/a/v/a-v.pom` (an empty one for any other), the
/// empty jar for every `.jar` but those of `missing`, and their SHA-256
/// sidecars.
fn repository_of(poms: fn(&str) -> String, missing: &'static [&'static str]) -> StubServer {
    StubServer::start(move |request| {
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            let parts: Vec<&str> = path.split('/').collect();
            let [group @ .., artifact, version, file] = parts.as_slice() else {
                return None;
            };
            let body = if *file == format!("{artifact}-{version}.pom") {
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                 <artifactId>{artifact}</artifactId><version>{version}</version>{}</project>",
                    group.join("."),
                    poms(artifact)
                )
                .into_bytes()
            } else if *file == format!("{artifact}-{version}.jar") && !missing.contains(artifact) {
                JAR.to_vec()
            } else {
                return None;
            };
            Some(body)
        })
    })
}

/// `<dependency>` elements for `group:artifact:version[:scope]` lines.
fn dependencies(coordinates: &[&str]) -> String {
    (coordinates.iter())
        .map(|coordinate| {
            let parts: Vec<&str> = coordinate.split(':').collect();
            let scope =
                (parts.get(3)).map_or(String::new(), |scope| format!("<scope>{scope}</scope>"));
            format!(
                "<dependency><groupId>{}</groupId><artifactId>{}</artifactId>\
                 <version>{}</version>{scope}</dependency>",
                parts[0], parts[1], parts[2]
            )
        })
        .collect()
}

/// A project binding `t:<artifact>:1`, with a home mirroring to `url`.
fn binding_project(url: &str, artifact: &str) -> (TempDir, TempDir) {
    let (project, home) = plugin_project(url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
                 <artifactId>{artifact}</artifactId><version>1</version><executions>\
                 <execution><phase>validate</phase><goals><goal>run</goal></goals></execution>\
                 </executions></plugin></plugins></build>"
            ),
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    (project, home)
}

/// Below a Maven 2 core artifact a plugin's wagon providers are dropped
/// with what they bring, as Maven's WagonExcluder drops them; the plugin's
/// own wagon dependency stays.
#[test]
fn wagons_below_a_maven_2_core_artifact_are_not_locked() {
    let server = repository_of(
        |artifact| {
            let declared: &[&str] = match artifact {
                "w-maven-plugin" => &[
                    "org.apache.maven:maven-project:2.0.6",
                    "org.apache.maven.wagon:wagon-file:1",
                ],
                "maven-project" => &["org.apache.maven.wagon:wagon-ssh:1", "t:kept:1"],
                "wagon-ssh" => &["t:jsch:1"],
                _ => &[],
            };
            format!("<dependencies>{}</dependencies>", dependencies(declared))
        },
        &[],
    );
    let url = format!("http://{}/", server.addr());
    let (project, home) = binding_project(&url, "w-maven-plugin");
    let root = project.path();
    let sync = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&sync, "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for kept in ["maven-project", "wagon-file", "kept"] {
        assert!(
            lock.contains(&format!("artifact = \"{kept}\"")),
            "{kept}: {lock}"
        );
    }
    for dropped in ["wagon-ssh", "jsch"] {
        assert!(!lock.contains(dropped), "{dropped}: {lock}");
    }
    let paths: Vec<_> = (server.requests().into_iter())
        .map(|request| request.path)
        .collect();
    assert!(
        !paths.iter().any(|path| path.contains("wagon-ssh")),
        "{paths:?}"
    );
}

/// A dependency the plugin's management makes `provided` or `test` is
/// collected, its POM kept, but its jar is not locked and need not exist,
/// as Maven's plugin class path filter drops it. One below it that
/// management makes `compile` is locked.
#[test]
fn provided_and_test_plugin_dependencies_are_not_locked() {
    let server = repository_of(
        |artifact| match artifact {
            "s-maven-plugin" => format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
                 <dependencies>{}</dependencies>",
                dependencies(&["t:leaf:1:provided", "t:probe:1:test", "t:kept:1:compile"]),
                dependencies(&["t:bridge:1"])
            ),
            "bridge" => format!(
                "<dependencies>{}</dependencies>",
                dependencies(&["t:leaf:1", "t:probe:1"])
            ),
            "leaf" => format!(
                "<dependencies>{}</dependencies>",
                dependencies(&["t:kept:1"])
            ),
            _ => String::new(),
        },
        &["leaf", "probe"],
    );
    let url = format!("http://{}/", server.addr());
    let (project, home) = binding_project(&url, "s-maven-plugin");
    let root = project.path();
    let sync = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&sync, "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for kept in ["bridge", "kept"] {
        assert!(
            lock.contains(&format!("artifact = \"{kept}\"")),
            "{kept}: {lock}"
        );
    }
    for dropped in ["leaf", "probe"] {
        assert!(
            !lock.contains(&format!("artifact = \"{dropped}\"")),
            "{dropped}: {lock}"
        );
        assert!(
            lock.contains(&format!("t:{dropped}:1")),
            "{dropped} POM: {lock}"
        );
    }
}

/// maven-compiler-plugin resolves `annotationProcessorPaths` as its
/// version does, as Maven 3.9.12 and 3.10.0 run it. Before 3.9.0 one legacy
/// request is rooted at the first path: its POM's optional dependency and
/// management count, the second path's `c:2` loses to the first's `c:1`.
/// 3.9.0 to 3.10.1 resolve each path alone, so both `c` stay. 3.11 and
/// later collect them together, under the project's management when 3.12
/// and later is told to use it. Modules with the same paths share no set.
#[test]
fn processor_paths_resolve_as_the_compiler_plugin_version_does() {
    let server = repository_of(
        |artifact| match artifact {
            "pa" => "<dependencyManagement><dependencies><dependency><groupId>t</groupId>\
                     <artifactId>d</artifactId><version>2</version></dependency></dependencies>\
                     </dependencyManagement><dependencies><dependency><groupId>t</groupId>\
                     <artifactId>c</artifactId><version>1</version></dependency><dependency>\
                     <groupId>t</groupId><artifactId>o</artifactId><version>1</version>\
                     <optional>true</optional></dependency><dependency><groupId>t</groupId>\
                     <artifactId>tst</artifactId><version>1</version><scope>test</scope>\
                     </dependency></dependencies>"
                .to_string(),
            "pb" => format!("<dependencies>{}</dependencies>", dependencies(&["t:c:2"])),
            "c" => format!("<dependencies>{}</dependencies>", dependencies(&["t:d:1"])),
            "o" => format!("<dependencies>{}</dependencies>", dependencies(&["t:q:1"])),
            _ => String::new(),
        },
        &[],
    );
    let url = format!("http://{}/", server.addr());
    let (project, home) = binding_project(&url, "unused");
    let root = project.path();
    let cases = [
        ("3.8.1", ["pa", "pb"], false, "c:1 d:2 o:1 pa:1 pb:1 q:1"),
        ("3.8.1", ["pb", "pa"], false, "c:2 d:1 pa:1 pb:1"),
        (
            "3.10.1",
            ["pa", "pb"],
            false,
            "c:1 d:2 o:1 pa:1 q:1 c:2 d:1 pb:1",
        ),
        ("3.11.0", ["pa", "pb"], true, "c:1 d:1 pa:1 pb:1"),
        ("3.13.0", ["pa", "pb"], true, "c:3 d:3 pa:1 pb:1"),
    ];
    let mut modules = String::new();
    for (i, (version, paths, use_dep_mgmt, _)) in cases.iter().enumerate() {
        modules.push_str(&format!("<module>m{i}</module>"));
        let paths: String = (paths.iter())
            .map(|artifact| {
                format!(
                    "<path><groupId>t</groupId><artifactId>{artifact}</artifactId>\
                     <version>1</version></path>"
                )
            })
            .collect();
        fs::create_dir_all(root.join(format!("m{i}"))).unwrap();
        fs::write(
            root.join(format!("m{i}/pom.xml")),
            pom(
                &format!("m{i}"),
                &format!(
                    "<packaging>pom</packaging><dependencyManagement><dependencies>{}\
                     </dependencies></dependencyManagement><build><plugins><plugin>\
                     <artifactId>maven-compiler-plugin</artifactId><version>{version}\
                     </version><configuration><annotationProcessorPathsUseDepMgmt>\
                     {use_dep_mgmt}</annotationProcessorPathsUseDepMgmt>\
                     <annotationProcessorPaths>{paths}</annotationProcessorPaths>\
                     </configuration></plugin></plugins></build>",
                    dependencies(&["t:c:3", "t:d:3"])
                ),
            ),
        )
        .unwrap();
    }
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!("<packaging>pom</packaging><modules>{modules}</modules>"),
        ),
    )
    .unwrap();
    let output = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&output, "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let sets: Vec<(&str, String)> = (lock.split("[[platforms.plugins.sets]]"))
        .filter(|set| set.contains("role = \"processor-path\""))
        .map(|set| {
            let rows = &set[set.find("artifacts = \"\"\"\n").unwrap() + 16..];
            let rows = (rows[..rows.find("\"\"\"").unwrap()].lines())
                .map(|row| row.split("\\t").next().unwrap().trim_start_matches("t:"))
                .collect::<Vec<_>>()
                .join(" ");
            let modules = &set[set.find("modules = ").unwrap()..];
            (
                &modules[..modules.find("\n\n").unwrap_or(modules.len())],
                rows,
            )
        })
        .collect();
    assert_eq!(sets.len(), cases.len(), "{lock}");
    for (i, (version, paths, _, files)) in cases.iter().enumerate() {
        let module = format!("\"m{i}/pom.xml\"");
        let found = sets.iter().find(|(modules, _)| modules.contains(&module));
        assert_eq!(
            found.map(|(_, rows)| rows.as_str()),
            Some(*files),
            "{version} {paths:?}"
        );
    }
}

/// A processor path without a version takes the project's management
/// before the reactor is asked for it, as maven-compiler-plugin 3.12 and
/// later do: the reactor builds `t:pa:2`, so the managed `t:pa:1` is
/// locked.
#[test]
fn a_managed_processor_path_is_not_the_reactor_module_of_another_version() {
    let server = repository_of(|_| String::new(), &[]);
    let url = format!("http://{}/", server.addr());
    let (project, home) = binding_project(&url, "unused");
    let root = project.path();
    for (module, body) in [
        (
            "m",
            format!(
                "<packaging>pom</packaging><dependencyManagement><dependencies>{}\
                 </dependencies></dependencyManagement><build><plugins><plugin>\
                 <artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version>\
                 <configuration><annotationProcessorPaths><path><groupId>t</groupId>\
                 <artifactId>pa</artifactId></path></annotationProcessorPaths>\
                 </configuration></plugin></plugins></build>",
                dependencies(&["t:pa:1"])
            ),
        ),
        ("pa", String::new()),
    ] {
        fs::create_dir_all(root.join(module)).unwrap();
        let text = pom(module, &body);
        let text = match module {
            "pa" => text.replacen("<version>1</version>", "<version>2</version>", 1),
            _ => text,
        };
        fs::write(root.join(format!("{module}/pom.xml")), text).unwrap();
    }
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><modules><module>m</module><module>pa</module></modules>",
        ),
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:pa:1\\t"), "{lock}");
}

/// A goal that names another compiler version resolves the module's
/// processor paths as that version does, beside the module's own: 3.11.0
/// leaves the project's management out, 3.13.0 is told to use it.
#[test]
fn a_goal_compiler_resolves_the_processor_paths_as_its_version_does() {
    let server = repository_of(
        |artifact| match artifact {
            "pa" => format!("<dependencies>{}</dependencies>", dependencies(&["t:c:1"])),
            "c" => format!("<dependencies>{}</dependencies>", dependencies(&["t:d:1"])),
            _ => String::new(),
        },
        &[],
    );
    let url = format!("http://{}/", server.addr());
    let (project, home) = binding_project(&url, "unused");
    let root = project.path();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><dependencyManagement><dependencies>{}\
                 </dependencies></dependencyManagement><build><plugins><plugin>\
                 <artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version>\
                 <configuration><annotationProcessorPathsUseDepMgmt>true\
                 </annotationProcessorPathsUseDepMgmt><annotationProcessorPaths><path>\
                 <groupId>t</groupId><artifactId>pa</artifactId><version>1</version></path>\
                 </annotationProcessorPaths></configuration></plugin></plugins></build>",
                dependencies(&["t:c:3", "t:d:3"])
            ),
        ),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ngoals = [\"org.apache.maven.plugins:maven-compiler-plugin:\
         3.11.0:compile\"]\n",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let mut sets: Vec<String> = (lock.split("[[platforms.plugins.sets]]"))
        .filter(|set| set.contains("role = \"processor-path\""))
        .map(|set| {
            let rows = &set[set.find("artifacts = \"\"\"\n").unwrap() + 16..];
            (rows[..rows.find("\"\"\"").unwrap()].lines())
                .map(|row| row.split("\\t").next().unwrap().trim_start_matches("t:"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    sets.sort();
    assert_eq!(sets, ["c:1 d:1 pa:1", "c:3 d:3 pa:1"], "{lock}");
}

/// A compile goal run from the command line takes the processor paths of
/// its execution, `default-cli` or the one it names after `@`, though that
/// execution lists no goals, as Maven 3.9.12 does.
#[test]
fn a_compile_goal_takes_the_processor_paths_of_its_execution() {
    let server = repository_of(|_| String::new(), &[]);
    let url = format!("http://{}/", server.addr());
    let (project, home) = binding_project(&url, "unused");
    let root = project.path();
    let execution = |id: &str, artifact: &str| {
        format!(
            "<execution><id>{id}</id><configuration><annotationProcessorPaths><path>\
             <groupId>t</groupId><artifactId>{artifact}</artifactId><version>1</version>\
             </path></annotationProcessorPaths></configuration></execution>"
        )
    };
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><build><plugins><plugin>\
                 <artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version>\
                 <executions>{}{}{}</executions></plugin></plugins></build>",
                execution("default-cli", "pa"),
                execution("named:main", "pb"),
                execution("unused", "pc")
            ),
        ),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ngoals = [\"org.apache.maven.plugins:maven-compiler-plugin:\
         3.11.0:compile\", \"org.apache.maven.plugins:maven-compiler-plugin:3.13.0:\
         testCompile@named:main\"]\n",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:pa:1\\t"), "{lock}");
    assert!(lock.contains("t:pb:1\\t"), "{lock}");
    assert!(!lock.contains("t:pc:1"), "{lock}");
}

/// A goal's compiler version resolves only its execution's processor paths,
/// not the lifecycle's of the module's version, and takes that execution
/// from the managed compiler when the build declares none, as Maven 3.9.12
/// does.
#[test]
fn a_goal_compiler_keeps_to_its_own_execution() {
    let server = repository_of(|_| String::new(), &[]);
    let url = format!("http://{}/", server.addr());
    let paths = |artifact: &str| {
        format!(
            "<configuration><annotationProcessorPaths><path><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId></path></annotationProcessorPaths>\
             </configuration>"
        )
    };
    let compiler = |executions: String| {
        format!(
            "<plugins><plugin><artifactId>maven-compiler-plugin</artifactId>\
             <version>3.13.0</version><executions>{executions}</executions></plugin></plugins>"
        )
    };
    // 3.11.0 would refuse the lifecycle's versionless `pa`; 3.13.0 takes
    // its managed version.
    let lifecycle = format!(
        "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
         <build>{}</build>",
        dependencies(&["t:pa:1", "t:pb:1"]),
        compiler(format!(
            "<execution><id>default-compile</id><goals><goal>compile</goal></goals>{}\
             </execution><execution><id>default-cli</id>{}</execution>",
            paths("pa"),
            paths("pb").replace("</artifactId>", "</artifactId><version>1</version>")
        ))
    );
    let managed = format!(
        "<build><pluginManagement>{}</pluginManagement></build>",
        compiler(format!(
            "<execution><id>default-cli</id>{}</execution>",
            paths("pb").replace("</artifactId>", "</artifactId><version>1</version>")
        ))
    );
    for (body, goal, locked) in [
        (
            lifecycle,
            "3.11.0:testCompile",
            &["t:pa:1\\t", "t:pb:1\\t"][..],
        ),
        (managed, "3.13.0:compile", &["t:pb:1\\t"][..]),
    ] {
        let (project, home) = binding_project(&url, "unused");
        let root = project.path();
        let text = pom("app", &format!("<packaging>pom</packaging>{body}"));
        fs::write(root.join("pom.xml"), text).unwrap();
        fs::write(
            root.join("raeva.toml"),
            format!(
                "[plugins]\nlock = true\ngoals = [\"org.apache.maven.plugins:\
                 maven-compiler-plugin:{goal}\"]\n"
            ),
        )
        .unwrap();
        assert_success(&run_raeva(root, home.path(), &["sync"]), goal);
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        for row in locked {
            assert!(lock.contains(row), "{goal} {row}: {lock}");
        }
    }
}

/// Each compiler execution that runs `compile` or `testCompile` resolves
/// its own `annotationProcessorPaths` with its own setting, as Maven 3.9.12
/// and 3.10.0 run them: the union would give `testCompile` `ex`'s `ed:1`.
#[test]
fn each_compiler_execution_resolves_its_own_processor_paths() {
    let server = repository_of(
        |artifact| match artifact {
            "ex" => format!("<dependencies>{}</dependencies>", dependencies(&["t:ed:1"])),
            "ey" => format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
                 <dependencies>{}</dependencies>",
                dependencies(&["t:ed:4"]),
                dependencies(&["t:em:1"])
            ),
            "em" => format!("<dependencies>{}</dependencies>", dependencies(&["t:ed:2"])),
            _ => String::new(),
        },
        &[],
    );
    let url = format!("http://{}/", server.addr());
    let (project, home) = binding_project(&url, "unused");
    let root = project.path();
    let paths = |artifact: &str| {
        format!(
            "<annotationProcessorPaths><path><groupId>t</groupId><artifactId>{artifact}\
             </artifactId><version>1</version></path></annotationProcessorPaths>"
        )
    };
    let execution = |goal: &str, configuration: &str| {
        format!(
            "<execution><id>{goal}-run</id><goals><goal>{goal}</goal></goals>\
             <configuration>{configuration}</configuration></execution>"
        )
    };
    let on = "<annotationProcessorPathsUseDepMgmt>true</annotationProcessorPathsUseDepMgmt>";
    let cases = [
        (
            "3.13.0",
            String::new(),
            execution("compile", &paths("ex")) + &execution("testCompile", &paths("ey")),
            ["ed:1 ex:1", "ed:2 em:1 ey:1"],
        ),
        (
            "3.13.0",
            paths("ey"),
            execution("compile", on) + &execution("testCompile", ""),
            ["ed:2 em:1 ey:1", "ed:3 em:1 ey:1"],
        ),
        (
            "3.8.1",
            String::new(),
            execution("compile", &paths("ex")) + &execution("testCompile", &paths("ey")),
            ["ed:1 ex:1", "ed:4 em:1 ey:1"],
        ),
    ];
    let mut modules = String::new();
    for (i, (version, configuration, executions, _)) in cases.iter().enumerate() {
        modules.push_str(&format!("<module>m{i}</module>"));
        fs::create_dir_all(root.join(format!("m{i}"))).unwrap();
        fs::write(
            root.join(format!("m{i}/pom.xml")),
            pom(
                &format!("m{i}"),
                &format!(
                    "<packaging>pom</packaging><dependencyManagement><dependencies>{}\
                     </dependencies></dependencyManagement><build><plugins><plugin>\
                     <artifactId>maven-compiler-plugin</artifactId><version>{version}\
                     </version><configuration>{configuration}</configuration><executions>\
                     {executions}</executions></plugin></plugins></build>",
                    dependencies(&["t:ed:3"])
                ),
            ),
        )
        .unwrap();
    }
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!("<packaging>pom</packaging><modules>{modules}</modules>"),
        ),
    )
    .unwrap();
    let output = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&output, "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for (i, (version, .., files)) in cases.iter().enumerate() {
        let module = format!("m{i}/pom.xml");
        let mut found: Vec<String> = (lock.split("[[platforms.plugins.sets]]"))
            .filter(|set| set.contains("role = \"processor-path\""))
            .filter(|set| {
                let modules = &set[set.find("modules = ").unwrap()..];
                let modules = &modules[..modules.find("\n\n").unwrap_or(modules.len())];
                (modules.split(['"', '\n'])).any(|line| line == module)
            })
            .map(|set| {
                let rows = &set[set.find("artifacts = \"\"\"\n").unwrap() + 16..];
                let mut rows: Vec<&str> = (rows[..rows.find("\"\"\"").unwrap()].lines())
                    .map(|row| row.split("\\t").next().unwrap().trim_start_matches("t:"))
                    .collect();
                rows.sort_unstable();
                rows.join(" ")
            })
            .collect();
        found.sort_unstable();
        assert_eq!(found, files, "m{i} {version}\n{lock}");
    }
}

/// maven-compiler-plugin 3.10.1 resolves each processor path in turn in
/// one session: `pb`'s `z` takes its parent `p`, which only the repository
/// `pa` declares serves, from the model cache reading `pa` filled. With
/// `pb` first, nothing has read `p` yet, and Maven's legacy resolver fails
/// on a missing parent. `c:1`, which `pa` brings, loses below `pb`; its
/// file pins its POM, so the set pins it no second time.
#[test]
fn processor_paths_read_in_turn_share_the_model_cache() {
    let own = Arc::new(std::sync::OnceLock::<String>::new());
    let address = Arc::clone(&own);
    let server = StubServer::start(move |request| {
        let url = address.get().expect("address");
        let (rx, path) = match request.path.strip_prefix("/rx/") {
            Some(path) => (true, path),
            None => (false, request.path.trim_start_matches('/')),
        };
        serve_sha256(path, |path| {
            let parts: Vec<&str> = path.split('/').collect();
            let [group @ .., artifact, version, file] = parts.as_slice() else {
                return None;
            };
            if (*artifact == "p") != rx {
                return None;
            }
            let body = match *artifact {
                "pa" => format!(
                    "<parent><groupId>t</groupId><artifactId>p</artifactId><version>1\
                     </version></parent><repositories><repository><id>rx</id>\
                     <url>http://{url}/rx/</url></repository></repositories>\
                     <dependencies>{}</dependencies>",
                    dependencies(&["t:c:1"])
                ),
                "pb" => format!(
                    "<dependencies>{}</dependencies>",
                    dependencies(&["t:z:1", "t:c:2"])
                ),
                "z" => format!(
                    "<parent><groupId>t</groupId><artifactId>p</artifactId><version>1\
                     </version></parent><dependencies>{}</dependencies>",
                    dependencies(&["t:c:1"])
                ),
                "p" => "<packaging>pom</packaging>".to_string(),
                _ => String::new(),
            };
            if *file == format!("{artifact}-{version}.pom") {
                let group = group.join(".");
                Some(
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><groupId>{group}</groupId>\
                         <artifactId>{artifact}</artifactId><version>{version}</version>{body}\
                         </project>"
                    )
                    .into_bytes(),
                )
            } else if *file == format!("{artifact}-{version}.jar") {
                Some(JAR.to_vec())
            } else {
                None
            }
        })
    });
    own.set(server.addr().to_string()).unwrap();
    let url = format!("http://{}/", server.addr());
    let (project, home) = binding_project(&url, "unused");
    let root = project.path();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>*,!rx</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_transitive_repositories = true\n",
    )
    .unwrap();
    let sync = |paths: [&str; 2]| {
        let paths: String = (paths.iter())
            .map(|artifact| {
                format!(
                    "<path><groupId>t</groupId><artifactId>{artifact}</artifactId>\
                     <version>1</version></path>"
                )
            })
            .collect();
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<packaging>pom</packaging><build><plugins><plugin>\
                     <artifactId>maven-compiler-plugin</artifactId><version>3.10.1\
                     </version><configuration><annotationProcessorPaths>{paths}\
                     </annotationProcessorPaths></configuration></plugin></plugins></build>"
                ),
            ),
        )
        .unwrap();
        (raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .expect("run raeva")
    };
    let output = sync(["pb", "pa"]);
    assert!(
        stderr(&output).contains("Parent POM not found: t:p:1"),
        "{}",
        stderr(&output)
    );
    assert_success(&sync(["pa", "pb"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let set = (lock.split("[[platforms.plugins.sets]]"))
        .find(|set| set.contains("role = \"processor-path\""))
        .expect("a processor path set");
    for file in ["t:pa:1", "t:z:1", "t:c:1", "t:c:2"] {
        assert!(set.contains(&format!("{file}\\t")), "{file}: {set}");
    }
    let poms = &set[set.find("support_poms = ").unwrap()..];
    let poms = &poms[..poms.find("modules = ").unwrap()];
    assert!(poms.contains("t:p:1") && !poms.contains("t:c:"), "{set}");
}

/// A jar holding `plugin.xml`, stored.
fn plugin_jar(descriptor: &str) -> Vec<u8> {
    jar_with("META-INF/maven/plugin.xml", descriptor)
}

/// A jar of one stored entry, `name` holding `text`.
fn jar_with(name: &str, text: &str) -> Vec<u8> {
    let name = name.as_bytes();
    let data = text.as_bytes();
    let size = (data.len() as u32).to_le_bytes();
    let mut jar = Vec::new();
    jar.extend_from_slice(b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0");
    jar.extend_from_slice(&size);
    jar.extend_from_slice(&size);
    jar.extend_from_slice(&(name.len() as u16).to_le_bytes());
    jar.extend_from_slice(&[0, 0]);
    jar.extend_from_slice(name);
    jar.extend_from_slice(data);
    let directory = jar.len() as u32;
    jar.extend_from_slice(b"PK\x01\x02\x14\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0");
    jar.extend_from_slice(&size);
    jar.extend_from_slice(&size);
    jar.extend_from_slice(&(name.len() as u16).to_le_bytes());
    jar.extend_from_slice(&[0; 12]);
    jar.extend_from_slice(&0u32.to_le_bytes());
    jar.extend_from_slice(name);
    let directory_size = jar.len() as u32 - directory;
    jar.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    jar.extend_from_slice(&directory_size.to_le_bytes());
    jar.extend_from_slice(&directory.to_le_bytes());
    jar.extend_from_slice(&[0, 0]);
    jar
}

/// A plugin the POM gives no version takes the newest version whose
/// prerequisites the Maven of the locked line meets: its POM's,
/// interpolated. Maven reads no `requiredMavenVersion` from plugin.xml,
/// checks nothing of a version whose jar has no descriptor naming it, and
/// passes over a version whose POM does not build: not XML, no POM, or of a
/// parent no repository has. The tables record the version taken as the
/// `<release>` export-m2 writes.
#[test]
fn a_plugin_version_meets_the_prerequisites_of_the_maven_line() {
    let server = StubServer::start(|request| {
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            let parts: Vec<&str> = path.split('/').collect();
            let [group @ .., artifact, version, file] = parts.as_slice() else {
                return None;
            };
            let body = if *file == "maven-metadata.xml" {
                let artifact = *version;
                if !["a-", "b-", "c-", "d-", "e-", "f-", "g-", "h-"]
                    .iter()
                    .any(|prefix| artifact.starts_with(prefix))
                {
                    return None;
                }
                format!(
                    "<metadata><groupId>t</groupId><artifactId>{artifact}</artifactId><versioning>\
                 <release>2</release><versions><version>1</version><version>2</version>\
                 </versions><lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
                )
                .into_bytes()
            } else if *file == format!("{artifact}-{version}.pom") {
                let broken = match (*artifact, *version) {
                    ("d-maven-plugin", "2") => Some("not a pom"),
                    ("e-maven-plugin", "2") => Some("<project><groupId>t</groupId>"),
                    ("f-maven-plugin", "2") => Some(
                        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t\
                         </groupId><artifactId>gone</artifactId><version>1</version></parent>\
                         <artifactId>f-maven-plugin</artifactId><version>2</version></project>",
                    ),
                    _ => None,
                };
                if let Some(broken) = broken {
                    return Some(broken.as_bytes().to_vec());
                }
                if *artifact == "gone" {
                    return None;
                }
                let prerequisites = match (*artifact, *version) {
                    ("b-maven-plugin", "2") => {
                        "<prerequisites><maven>3.10.0</maven></prerequisites>"
                    }
                    ("c-maven-plugin", "2") => {
                        "<prerequisites><maven>${project.version}</maven></prerequisites>"
                    }
                    ("g-maven-plugin" | "h-maven-plugin", "2") => {
                        "<prerequisites><maven>99</maven></prerequisites>"
                    }
                    _ => "",
                };
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                 <artifactId>{artifact}</artifactId><version>{version}</version>\
                 <packaging>maven-plugin</packaging>{prerequisites}</project>",
                    group.join(".")
                )
                .into_bytes()
            } else if *file == format!("{artifact}-{version}.jar") {
                let descriptor = |artifact: &str, extra: &str| {
                    plugin_jar(&format!(
                        "<plugin><groupId>t</groupId><artifactId>{artifact}</artifactId>\
                         <version>{version}</version>{extra}</plugin>"
                    ))
                };
                match (*artifact, *version) {
                    ("a-maven-plugin", "2") => descriptor(
                        artifact,
                        "<requiredMavenVersion>3.10.0</requiredMavenVersion>",
                    ),
                    ("g-maven-plugin", _) => JAR.to_vec(),
                    ("h-maven-plugin", _) => descriptor("other-maven-plugin", ""),
                    _ => descriptor(artifact, ""),
                }
            } else {
                return None;
            };
            Some(body)
        })
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    let plugin = |artifact: &str| {
        format!(
            "<plugin><groupId>t</groupId><artifactId>{artifact}</artifactId><executions>\
             <execution><phase>validate</phase><goals><goal>run</goal></goals></execution>\
             </executions></plugin>"
        )
    };
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><build><plugins>{}</plugins></build>",
                ["a", "b", "c", "d", "e", "f", "g", "h"]
                    .map(|name| plugin(&format!("{name}-maven-plugin")))
                    .concat()
            ),
        ),
    )
    .unwrap();
    for (line, version) in [("3.9", "1"), ("3.10", "2")] {
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{line}\"\n\n[plugins]\nlock = true\n"),
        )
        .unwrap();
        let sync = (raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .expect("run raeva");
        assert_success(&sync, line);
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        for (artifact, version) in [
            ("a-maven-plugin", "2"),
            ("b-maven-plugin", version),
            ("c-maven-plugin", "2"),
            ("d-maven-plugin", "1"),
            ("e-maven-plugin", "1"),
            ("f-maven-plugin", "1"),
            ("g-maven-plugin", "2"),
            ("h-maven-plugin", "2"),
        ] {
            assert!(
                lock.contains(&format!("t:{artifact}:{version}")),
                "{line} {artifact}: {lock}"
            );
            // The export's `<release>` is the version taken, not the `2`
            // passed over.
            assert!(
                lock.contains(&format!("t:{artifact}\\trelease\\t{version}")),
                "{line} {artifact}: {lock}"
            );
        }
    }
}

/// Maven reads a plugin's metadata from every plugin repository that
/// enables releases or snapshots: with no `<release>` anywhere, the
/// `<latest>` `2.0-SNAPSHOT` of a snapshots-only repository wins over the
/// `1.0` a releases-only one lists. The tables pin no SNAPSHOT build, so
/// the sync refuses that plugin as it does one the POM names, rather than
/// write tables a frozen check cannot reproduce.
#[test]
fn a_plugin_without_a_version_reads_a_snapshots_only_repository() {
    let server = StubServer::start(|request| serve(request, None, |_| (JAR, true), |_| false));
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let root = project.path();
    let put = |path: &str, body: &[u8]| {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
        fs::write(
            path.with_extension(format!(
                "{}.sha256",
                path.extension().unwrap().to_str().unwrap()
            )),
            sha256_hex(body),
        )
        .unwrap();
    };
    let plugin_pom = |version: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>echo-maven-plugin</artifactId><version>{version}</version>\
             <packaging>maven-plugin</packaging></project>"
        )
    };
    let metadata = |markers: &str, version: &str, stamp: &str| {
        format!(
            "<metadata><groupId>t</groupId><artifactId>echo-maven-plugin</artifactId><versioning>\
             {markers}<versions><version>{version}</version></versions>\
             <lastUpdated>{stamp}</lastUpdated></versioning></metadata>"
        )
    };
    put(
        "R/t/echo-maven-plugin/1.0/echo-maven-plugin-1.0.pom",
        plugin_pom("1.0").as_bytes(),
    );
    put("R/t/echo-maven-plugin/1.0/echo-maven-plugin-1.0.jar", JAR);
    put(
        "R/t/echo-maven-plugin/maven-metadata.xml",
        metadata("", "1.0", "20240101000000").as_bytes(),
    );
    let build = "S/t/echo-maven-plugin/2.0-SNAPSHOT/echo-maven-plugin-2.0-20250101.000000-1";
    put(
        &format!("{build}.pom"),
        plugin_pom("2.0-SNAPSHOT").as_bytes(),
    );
    put(&format!("{build}.jar"), JAR);
    put(
        "S/t/echo-maven-plugin/2.0-SNAPSHOT/maven-metadata.xml",
        b"<metadata><groupId>t</groupId><artifactId>echo-maven-plugin</artifactId>\
          <version>2.0-SNAPSHOT</version><versioning><snapshot><timestamp>20250101.000000\
          </timestamp><buildNumber>1</buildNumber></snapshot>\
          <lastUpdated>20250101000000</lastUpdated></versioning></metadata>",
    );
    put(
        "S/t/echo-maven-plugin/maven-metadata.xml",
        metadata(
            "<latest>2.0-SNAPSHOT</latest>",
            "2.0-SNAPSHOT",
            "20250101000000",
        )
        .as_bytes(),
    );
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    for version in ["", "<version>2.0-SNAPSHOT</version>"] {
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<packaging>pom</packaging><pluginRepositories>\
                     <pluginRepository><id>rel</id><url>file://${{project.basedir}}/R/</url>\
                     <snapshots><enabled>false</enabled></snapshots></pluginRepository>\
                     <pluginRepository><id>snap</id><url>file://${{project.basedir}}/S/</url>\
                     <releases><enabled>false</enabled></releases></pluginRepository>\
                     </pluginRepositories><build><plugins><plugin><groupId>t</groupId>\
                     <artifactId>echo-maven-plugin</artifactId>{version}<executions><execution>\
                     <phase>validate</phase><goals><goal>run</goal></goals></execution>\
                     </executions></plugin></plugins></build>"
                ),
            ),
        )
        .unwrap();
        let sync = (raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .expect("run raeva");
        assert_eq!(sync.status.code(), Some(5), "{}", stderr(&sync));
        assert!(
            stderr(&sync).contains("t:echo-maven-plugin:2.0-SNAPSHOT"),
            "{}",
            stderr(&sync)
        );
        assert!(!root.join("raeva.lock").exists());
    }
}

/// A plugin the POM gives no version keeps the version the tables took in
/// a frozen check after its `<release>` moved, while the repository still
/// lists it, as a dependency's RELEASE does. The check never reads the
/// newer version, whose descriptor would add a host input.
#[test]
fn frozen_holds_a_plugin_without_a_version_at_the_one_the_tables_took() {
    let moved = Arc::new(AtomicBool::new(false));
    let server = StubServer::start({
        let moved = Arc::clone(&moved);
        move |request| {
            let path = request.path.trim_start_matches('/');
            // The new release reads the JDK, which the held one does not.
            if path.starts_with("t/v-maven-plugin/2/v-maven-plugin-2.jar") {
                return serve_sha256(path, |_| {
                    Some(plugin_jar(
                        "<plugin><groupId>t</groupId><artifactId>v-maven-plugin</artifactId>\
                         <version>2</version><requiredJavaVersion>1.8</requiredJavaVersion>\
                         </plugin>",
                    ))
                });
            }
            if !path.starts_with("t/v-maven-plugin/maven-metadata.xml") {
                return serve(request, None, |_| (JAR, true), |_| false);
            }
            let (release, versions) = match moved.load(Ordering::SeqCst) {
                true => ("2", "<version>1</version><version>2</version>"),
                false => ("1", "<version>1</version>"),
            };
            serve_sha256(path, |_| {
                Some(format!(
                    "<metadata><groupId>t</groupId><artifactId>v-maven-plugin</artifactId>\
                     <versioning><release>{release}</release><versions>{versions}</versions>\
                     <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
                ))
            })
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
             <artifactId>v-maven-plugin</artifactId><executions><execution>\
             <phase>validate</phase><goals><goal>run</goal></goals></execution>\
             </executions></plugin></plugins></build>",
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let sync = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&sync, "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    assert!(
        locked.contains("t:v-maven-plugin\\trelease\\t1"),
        "{locked}"
    );

    moved.store(true, Ordering::SeqCst);
    let other = TempDir::new().unwrap();
    fs::create_dir_all(other.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        other.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let frozen = (raeva_command(root, other.path()))
        .args(["sync", "--frozen"])
        .output()
        .expect("run raeva");
    assert_success(&frozen, "frozen after the release moved");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
}

/// A repository whose `t:v-maven-plugin` listing has `<release>` 1 until
/// `moved`, then 2, and that serves every other file as [`repository`].
fn moving_release(moved: &Arc<AtomicBool>) -> StubServer {
    let moved = Arc::clone(moved);
    StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        if !path.starts_with("t/v-maven-plugin/maven-metadata.xml") {
            return serve(request, None, |_| (JAR, true), |_| false);
        }
        let (release, versions) = match moved.load(Ordering::SeqCst) {
            true => ("2", "<version>1</version><version>2</version>"),
            false => ("1", "<version>1</version>"),
        };
        serve_sha256(path, |_| {
            Some(format!(
                "<metadata><groupId>t</groupId><artifactId>v-maven-plugin</artifactId>\
                 <versioning><release>{release}</release><versions>{versions}</versions>\
                 <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
            ))
        })
    })
}

/// A reactor of `mod-a`, which binds `t:v-maven-plugin` without a version
/// and adds `extra` to its build plugins, and `mod-b`, which binds it at
/// `b_version` when given, with a home whose settings.xml mirrors
/// everything to `url`.
fn release_reactor(
    url: &str,
    maven: &str,
    extra: &str,
    b_version: Option<&str>,
) -> (TempDir, TempDir) {
    let (project, home) = plugin_project(url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "root",
            "<packaging>pom</packaging><modules><module>mod-a</module><module>mod-b</module>\
             </modules>",
        ),
    )
    .unwrap();
    write_release_module(root, "mod-a", None, extra);
    write_release_module(root, "mod-b", b_version, "");
    fs::write(
        root.join("raeva.toml"),
        format!("[lock]\nmaven = \"{maven}\"\n\n[plugins]\nlock = true\n"),
    )
    .unwrap();
    (project, home)
}

fn write_release_module(root: &std::path::Path, module: &str, version: Option<&str>, extra: &str) {
    let version = version.map_or_else(String::new, |version| {
        format!("<version>{version}</version>")
    });
    fs::create_dir_all(root.join(module)).unwrap();
    fs::write(
        root.join(module).join("pom.xml"),
        pom(
            module,
            &format!(
                "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
                 <artifactId>v-maven-plugin</artifactId>{version}<executions><execution>\
                 <phase>validate</phase><goals><goal>run</goal></goals></execution>\
                 </executions></plugin></plugins></build>{extra}"
            ),
        ),
    )
    .unwrap();
}

/// A home with no caches, whose settings.xml is `home`'s.
fn fresh_home(home: &std::path::Path) -> TempDir {
    let other = TempDir::new().unwrap();
    fs::create_dir_all(other.path().join(".m2")).unwrap();
    fs::copy(
        home.join(".m2/settings.xml"),
        other.path().join(".m2/settings.xml"),
    )
    .unwrap();
    other
}

/// The tables hold a plugin without a version at the version they took
/// only while the inputs match. Once `mod-b` drops the version it gave
/// the plugin after the `<release>` moved, a plain sync, as Maven 3.9.12
/// and 3.10.0, takes the new release for both modules, so `--frozen`
/// refuses the lock it would change.
#[test]
fn frozen_refuses_a_plugin_version_a_pom_edit_frees() {
    for maven in ["3.9", "3.10"] {
        let moved = Arc::new(AtomicBool::new(false));
        let server = moving_release(&moved);
        let url = format!("http://{}/", server.addr());
        let (project, home) = release_reactor(&url, maven, "", Some("1"));
        let root = project.path();
        let raeva = |home: &std::path::Path, args: &[&str]| run_raeva(root, home, args);
        assert_success(&raeva(home.path(), &["sync"]), maven);
        let lock_path = root.join("raeva.lock");
        let locked = fs::read_to_string(&lock_path).unwrap();
        assert!(
            locked.contains("t:v-maven-plugin:1\\t"),
            "{maven}: {locked}"
        );

        moved.store(true, Ordering::SeqCst);
        let control = raeva(fresh_home(home.path()).path(), &["sync", "--frozen"]);
        assert_success(&control, &format!("{maven}: frozen on the unedited POMs"));
        write_release_module(root, "mod-b", None, "");
        let frozen = raeva(fresh_home(home.path()).path(), &["sync", "--frozen"]);
        assert_status(&frozen, 7, &format!("{maven}: frozen after the edit"));
        assert!(
            stderr(&frozen).contains("the plugin sets differ"),
            "{maven}: {}",
            stderr(&frozen)
        );
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked, "{maven}");
        let plain = raeva(fresh_home(home.path()).path(), &["sync"]);
        assert_success(&plain, &format!("{maven}: plain sync after the edit"));
        let synced = fs::read_to_string(&lock_path).unwrap();
        assert!(
            synced.contains("t:v-maven-plugin:2\\t") && !synced.contains("t:v-maven-plugin:1\\t"),
            "{maven}: {synced}"
        );
        assert_success(
            &raeva(fresh_home(home.path()).path(), &["sync", "--frozen"]),
            &format!("{maven}: frozen after the plain sync"),
        );
    }
}

/// The `[[platforms]]` block of `lock` for `target`, with `edit` applied
/// when given.
fn platform_block(lock: &str, target: &str, edit: Option<(&str, &str)>) -> (String, String) {
    let marker = format!("[[platforms]]\ntargets = [\"{target}\"]\n");
    let start = lock.find(&marker).expect("the platform's block");
    let end = (lock[start + marker.len()..].find("\n[[platforms]]\n")).map_or_else(
        || lock.find("\n[metadata]\n").unwrap(),
        |end| start + marker.len() + end,
    );
    let block = lock[start..end].to_string();
    let edited = match edit {
        Some((from, to)) => {
            assert!(block.contains(from), "{block}");
            format!(
                "{}{}{}",
                &lock[..start],
                block.replace(from, to),
                &lock[end..]
            )
        }
        None => lock.to_string(),
    };
    (block, edited)
}

/// A plain sync of a lock this home neither wrote nor checked keeps the
/// plugin tables of each platform that passes the frozen check: one
/// platform's drifted tables are resolved again, and the other's keep the
/// version they took after the `<release>` moved.
#[test]
fn a_platform_whose_plugin_tables_drifted_leaves_the_others_held() {
    let windows = "<profiles><profile><id>w</id><activation><os><family>windows</family></os>\
                   </activation><build><plugins><plugin><groupId>t</groupId>\
                   <artifactId>w-maven-plugin</artifactId><version>1</version><executions>\
                   <execution><phase>validate</phase><goals><goal>run</goal></goals>\
                   </execution></executions></plugin></plugins></build></profile></profiles>";
    let both = "linux-x86_64,windows-x86_64";
    let release = |version: &str| format!("t:v-maven-plugin\\trelease\\t{version}");
    for maven in ["3.9", "3.10"] {
        let moved = Arc::new(AtomicBool::new(false));
        let server = moving_release(&moved);
        let url = format!("http://{}/", server.addr());
        let (project, home) = release_reactor(&url, maven, windows, None);
        let root = project.path();
        let raeva = |home: &std::path::Path, args: &[&str]| run_raeva(root, home, args);
        assert_success(&raeva(home.path(), &["sync", "--platforms", both]), maven);
        let lock_path = root.join("raeva.lock");
        let locked = fs::read_to_string(&lock_path).unwrap();
        let (linux, _) = platform_block(&locked, "linux-x86_64", None);
        assert!(linux.contains(&release("1")), "{maven}: {locked}");
        assert!(!linux.contains("w-maven-plugin"), "{maven}: {linux}");

        moved.store(true, Ordering::SeqCst);
        let (_, edited) = platform_block(
            &locked,
            "windows-x86_64",
            Some((&release("1"), &release("0"))),
        );
        fs::write(&lock_path, &edited).unwrap();
        let frozen = |platform: &str| {
            let args = ["sync", "--frozen", "--platforms", platform];
            raeva(fresh_home(home.path()).path(), &args)
        };
        assert_success(&frozen("linux-x86_64"), &format!("{maven}: linux"));
        assert_status(&frozen("windows-x86_64"), 7, &format!("{maven}: windows"));
        let plain = raeva(fresh_home(home.path()).path(), &["sync"]);
        assert_success(&plain, &format!("{maven}: plain sync"));
        let synced = fs::read_to_string(&lock_path).unwrap();
        assert_eq!(
            platform_block(&synced, "linux-x86_64", None).0,
            linux,
            "{maven}"
        );
        let (windows, _) = platform_block(&synced, "windows-x86_64", None);
        assert!(windows.contains(&release("2")), "{maven}: {windows}");
    }
}

/// Maven records a 404 for a plugin's version list under the repository
/// id, as for a dependency's, so the module that reads the id first fixes
/// the version for both: 1 in the order `a`, `b` and 2 in `b`, `a`, in
/// Maven 3.9.12 and 3.10.0. With `r` answering 404 at `a`'s URL and listing
/// 1 and 2 at `b`'s, raeva refuses, where it locked `a` on 1 and `b` on 2.
#[test]
fn a_plugin_repository_id_without_a_listing_at_one_url_is_refused() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    for maven in ["3.9", "3.10"] {
        let (project, home) = plugin_project(&url);
        let root = project.path();
        fs::remove_dir_all(root.join(".mvn")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
                 <mirrorOf>central</mirrorOf></mirror></mirrors></settings>"
            ),
        )
        .unwrap();
        let publish = |repo: &str, versions: &[&str]| {
            let dir = root.join(repo).join("q/p-maven-plugin");
            for version in versions {
                let pom = format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>q</groupId>\
                     <artifactId>p-maven-plugin</artifactId><version>{version}</version>\
                     <packaging>maven-plugin</packaging></project>"
                );
                let file = dir.join(format!("{version}/p-maven-plugin-{version}"));
                write_with_sha256(&file.with_extension("pom"), pom.as_bytes());
                write_with_sha256(&file.with_extension("jar"), JAR);
            }
            let listed: String = (versions.iter())
                .map(|version| format!("<version>{version}</version>"))
                .collect();
            let metadata = format!(
                "<metadata><groupId>q</groupId><artifactId>p-maven-plugin</artifactId>\
                 <versioning><release>{}</release><versions>{listed}</versions>\
                 <lastUpdated>20240101000000</lastUpdated></versioning></metadata>",
                versions.last().unwrap()
            );
            write_with_sha256(&dir.join("maven-metadata.xml"), metadata.as_bytes());
        };
        publish("c", &["1"]);
        publish("u2", &["1", "2"]);
        fs::create_dir_all(root.join("u1")).unwrap();
        let file_url = |repo: &str| {
            url::Url::from_directory_path(root.join(repo))
                .unwrap()
                .to_string()
        };
        fs::write(
            root.join("pom.xml"),
            pom(
                "root",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                 </modules>",
            ),
        )
        .unwrap();
        for (module, own) in [("a", "u1"), ("b", "u2")] {
            fs::create_dir_all(root.join(module)).unwrap();
            let body = format!(
                "<packaging>pom</packaging><pluginRepositories><pluginRepository><id>r</id>\
                 <url>{}</url></pluginRepository><pluginRepository><id>c</id><url>{}</url>\
                 </pluginRepository></pluginRepositories><build><plugins><plugin>\
                 <groupId>q</groupId><artifactId>p-maven-plugin</artifactId><executions>\
                 <execution><phase>validate</phase><goals><goal>run</goal></goals>\
                 </execution></executions></plugin></plugins></build>",
                file_url(own),
                file_url("c"),
            );
            fs::write(root.join(module).join("pom.xml"), pom(module, &body)).unwrap();
        }
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{maven}\"\n\n[plugins]\nlock = true\n"),
        )
        .unwrap();
        let output = run_raeva(root, home.path(), &["sync"]);
        assert_status(&output, 5, maven);
        let said = stderr(&output);
        for expected in [
            "repository id r",
            "q:p-maven-plugin",
            &file_url("u1"),
            &file_url("u2"),
        ] {
            assert!(said.contains(expected), "{maven}: {expected}: {said}");
        }
        assert!(!root.join("raeva.lock").exists(), "{maven}");
    }
}

/// Two modules take a plugin without a version from different repositories,
/// `10.0` and `2.0`, and the tables record both. A frozen check of the
/// unchanged project holds each module at the version it took, as Maven
/// resolves the version for each project's repositories, also once
/// Central marks `10.0` too and still lists `2.0`.
#[test]
fn frozen_holds_plugins_taken_from_different_repositories() {
    let published = Arc::new(AtomicBool::new(false));
    let server = StubServer::start({
        let published = Arc::clone(&published);
        move |request| {
            let full = request.path.trim_start_matches('/');
            let (repo, path) = full.split_once('/').unwrap_or((full, ""));
            if path.starts_with("t/maven-metadata.xml") {
                return serve_sha256(path, |_| {
                    Some(
                        "<metadata><plugins><plugin><prefix>v</prefix>\
                         <artifactId>v-maven-plugin</artifactId></plugin></plugins></metadata>"
                            .to_string(),
                    )
                });
            }
            if !path.starts_with("t/v-maven-plugin/maven-metadata.xml") {
                let mut request = request.clone();
                request.path = format!("/{path}");
                return serve(&request, None, |_| (JAR, true), |_| false);
            }
            let (version, listed, stamp) = match repo {
                "a" => ("10.0", "<version>10.0</version>", "20250101000000"),
                _ if published.load(Ordering::SeqCst) => (
                    "10.0",
                    "<version>2.0</version><version>10.0</version>",
                    "20240202000000",
                ),
                _ => ("2.0", "<version>2.0</version>", "20240101000000"),
            };
            serve_sha256(path, |_| {
                Some(format!(
                    "<metadata><groupId>t</groupId><artifactId>v-maven-plugin</artifactId>\
                 <versioning><release>{version}</release><versions>{listed}</versions>\
                 <lastUpdated>{stamp}</lastUpdated></versioning></metadata>"
                ))
            })
        }
    });
    let url = format!("http://{}", server.addr());
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}/central/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    let root = project.path();
    let plugin = "<build><plugins><plugin><groupId>t</groupId>\
                  <artifactId>v-maven-plugin</artifactId><executions><execution>\
                  <phase>validate</phase><goals><goal>run</goal></goals></execution>\
                  </executions></plugin></plugins></build>";
    let module = |name: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
             <artifactId>app</artifactId><version>1</version></parent>\
             <artifactId>{name}</artifactId><packaging>pom</packaging>{body}{plugin}</project>"
        )
    };
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            // Managed, so a goal finds its prefix in group `t`.
            "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>\
             <build><pluginManagement><plugins><plugin><groupId>t</groupId>\
             <artifactId>v-maven-plugin</artifactId></plugin></plugins></pluginManagement>\
             </build>",
        ),
    )
    .unwrap();
    for (name, body) in [
        (
            "a",
            format!(
                "<pluginRepositories><pluginRepository><id>a</id><url>{url}/a/</url>\
                 </pluginRepository></pluginRepositories>"
            ),
        ),
        ("b", String::new()),
    ] {
        fs::create_dir_all(root.join(name)).unwrap();
        fs::write(root.join(name).join("pom.xml"), module(name, &body)).unwrap();
    }
    // Also with a goal that names `10.0` itself, which module b runs
    // beside the `2.0` it took.
    // And with the plugin as a build extension too, which resolves before
    // the goals do.
    for (goals, extensions) in [
        ("", false),
        ("goals = ['t:v-maven-plugin:10.0:run']\n", false),
        ("goals = ['v:10.0:run']\n", false),
        ("goals = ['t:v-maven-plugin:10.0:run']\n", true),
    ] {
        for name in ["a", "b"].into_iter().filter(|_| extensions) {
            let path = root.join(name).join("pom.xml");
            let pom = fs::read_to_string(&path).unwrap().replacen(
                "</artifactId><executions>",
                "</artifactId><extensions>true</extensions><executions>",
                1,
            );
            fs::write(path, pom).unwrap();
        }
        published.store(false, Ordering::SeqCst);
        let _ = fs::remove_file(root.join("raeva.lock"));
        let toml = format!("[plugins]\nlock = true\n{goals}");
        fs::write(root.join("raeva.toml"), toml).unwrap();
        let raeva = |home: &std::path::Path, args: &[&str]| {
            (raeva_command(root, home))
                .args(args)
                .output()
                .expect("run raeva")
        };
        assert_success(&raeva(home.path(), &["sync"]), "sync");
        let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
        for version in ["10.0", "2.0"] {
            assert!(
                locked.contains(&format!("t:v-maven-plugin\\trelease\\t{version}")),
                "{locked}"
            );
        }
        assert_success(
            &raeva(home.path(), &["sync", "--frozen"]),
            "frozen of the unchanged project",
        );
        published.store(true, Ordering::SeqCst);
        let other = TempDir::new().unwrap();
        fs::create_dir_all(other.path().join(".m2")).unwrap();
        fs::copy(
            home.path().join(".m2/settings.xml"),
            other.path().join(".m2/settings.xml"),
        )
        .unwrap();
        let frozen = raeva(other.path(), &["sync", "--frozen"]);
        assert_success(
            &frozen,
            &format!("frozen after Central marked 10.0 {goals}"),
        );
        assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), locked);
    }
}

/// A plugin repository listing `t:j-maven-plugin` 1 and 2, version 2's
/// plugin.xml requiring Java 21.
fn java_prerequisite_repository() -> StubServer {
    java_prerequisite_repository_with(Arc::new(AtomicBool::new(true)))
}

/// [`java_prerequisite_repository`], whose metadata lists version 2 only
/// once `published`.
fn java_prerequisite_repository_with(published: Arc<AtomicBool>) -> StubServer {
    StubServer::start(move |request| {
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            if path == "t/j-maven-plugin/maven-metadata.xml" {
                let metadata = match published.load(Ordering::SeqCst) {
                    true => {
                        "<release>2</release><versions><version>1</version>\
                             <version>2</version></versions>"
                    }
                    false => "<release>1</release><versions><version>1</version></versions>",
                };
                return Some(
                    format!(
                        "<metadata><groupId>t</groupId><artifactId>j-maven-plugin</artifactId>\
                         <versioning>{metadata}</versioning></metadata>"
                    )
                    .into_bytes(),
                );
            }
            let parts: Vec<&str> = path.split('/').collect();
            let [group @ .., artifact, version, file] = parts.as_slice() else {
                return None;
            };
            if *file == format!("{artifact}-{version}.pom") {
                Some(
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                         <artifactId>{artifact}</artifactId><version>{version}</version>\
                         <packaging>maven-plugin</packaging></project>",
                        group.join(".")
                    )
                    .into_bytes(),
                )
            } else if *file == format!("{artifact}-{version}.jar") {
                Some(match (*artifact, *version) {
                    ("j-maven-plugin", "2") => plugin_jar(
                        "<plugin><groupId>t</groupId><artifactId>j-maven-plugin</artifactId>\
                         <version>2</version><requiredJavaVersion>21</requiredJavaVersion>\
                         </plugin>",
                    ),
                    _ => JAR.to_vec(),
                })
            } else {
                None
            }
        })
    })
}

/// A plugin the POM gives no version takes the newest version whose
/// plugin.xml `requiredJavaVersion` the JDK `mvn` runs meets, the `java` on
/// `PATH` here, and the tables record that they read its version.
#[test]
fn a_plugin_version_meets_the_java_prerequisite_of_the_host_jdk() {
    let server = java_prerequisite_repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
             <artifactId>j-maven-plugin</artifactId><executions><execution>\
             <phase>validate</phase><goals><goal>run</goal></goals></execution>\
             </executions></plugin></plugins></build>",
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let jdks = TempDir::new().unwrap();
    let jdk = |version: &str| {
        let bin = jdks.path().join(version).join("bin");
        fs::create_dir_all(&bin).unwrap();
        let java = bin.join(if cfg!(windows) { "java.exe" } else { "java" });
        fs::write(&java, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&java, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let release = format!("JAVA_VERSION=\"{version}\"\n");
        fs::write(jdks.path().join(version).join("release"), release).unwrap();
        bin.to_str().unwrap().to_string()
    };
    let (jdk17, jdk21) = (jdk("17.0.2"), jdk("21.0.4"));
    let raeva = |path: &str, args: &[&str]| {
        (raeva_command(root, home.path()))
            .env(rv_maven_model::JAVA_PATH_TEST_ENV, path)
            .args(args)
            .output()
            .expect("run raeva")
    };
    for (path, version) in [(&jdk17, "1"), (&jdk21, "2")] {
        let sync = raeva(path, &["sync"]);
        assert_success(&sync, version);
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(
            lock.contains(&format!("t:j-maven-plugin:{version}")),
            "{lock}"
        );
        // On 17 the check holds version 1 and skips 2, which the sync read
        // the JDK for.
        assert_success(&raeva(path, &["sync", "--frozen"]), version);
    }
    let frozen = raeva(&jdk17, &["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
}

/// A frozen check holds a plugin without a version at the one the lock
/// took when a newer one the JDK rejects is released since: it reads
/// nothing of the JDK the lock does not record.
#[test]
fn a_frozen_sync_holds_a_plugin_version_past_a_newer_one_the_jdk_rejects() {
    let published = Arc::new(AtomicBool::new(false));
    let server = java_prerequisite_repository_with(Arc::clone(&published));
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
             <artifactId>j-maven-plugin</artifactId><executions><execution>\
             <phase>validate</phase><goals><goal>run</goal></goals></execution>\
             </executions></plugin></plugins></build>",
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| {
        (raeva_command(root, home.path()))
            .env("JAVA_VERSION", "17")
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:j-maven-plugin:1"), "{lock}");
    assert!(!lock.contains("java.version"), "{lock}");
    published.store(true, Ordering::SeqCst);
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
}

/// A plugin repository listing `t:p-maven-plugin` 1 and 2, version 2's POM
/// with the prerequisite `maven`, each jar with a descriptor naming it.
fn prerequisite_repository(maven: &'static str) -> StubServer {
    prerequisite_repository_with(maven, "")
}

/// [`prerequisite_repository`], version 2's POM inheriting from
/// `t:p-parent:1`, with the content `parent`, when that is not empty.
fn prerequisite_repository_with(maven: &'static str, parent: &'static str) -> StubServer {
    StubServer::start(move |request| {
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            let body = match path {
                "t/p-maven-plugin/maven-metadata.xml" => "<metadata><groupId>t</groupId>\
                 <artifactId>p-maven-plugin</artifactId><versioning><release>2</release>\
                 <versions><version>1</version><version>2</version></versions></versioning>\
                 </metadata>"
                    .to_string()
                    .into_bytes(),
                "t/p-parent/1/p-parent-1.pom" if !parent.is_empty() => format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                     <artifactId>p-parent</artifactId><version>1</version>\
                     <packaging>pom</packaging>{parent}</project>"
                )
                .into_bytes(),
                "t/p-maven-plugin/1/p-maven-plugin-1.pom"
                | "t/p-maven-plugin/2/p-maven-plugin-2.pom" => {
                    let version = &path["t/p-maven-plugin/".len()..][..1];
                    let prerequisites = match version {
                        "2" if parent.is_empty() => {
                            format!("<prerequisites><maven>{maven}</maven></prerequisites>")
                        }
                        "2" => format!(
                            "<parent><groupId>t</groupId><artifactId>p-parent</artifactId>\
                             <version>1</version></parent>\
                             <prerequisites><maven>{maven}</maven></prerequisites>"
                        ),
                        _ => String::new(),
                    };
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                     <artifactId>p-maven-plugin</artifactId><version>{version}</version>\
                     <packaging>maven-plugin</packaging>{prerequisites}</project>"
                    )
                    .into_bytes()
                }
                "t/p-maven-plugin/1/p-maven-plugin-1.jar"
                | "t/p-maven-plugin/2/p-maven-plugin-2.jar" => {
                    let version = &path["t/p-maven-plugin/".len()..][..1];
                    plugin_jar(&format!(
                        "<plugin><groupId>t</groupId><artifactId>p-maven-plugin</artifactId>\
                         <version>{version}</version></plugin>"
                    ))
                }
                _ => return None,
            };
            Some(body)
        })
    })
}

/// A frozen check holds a plugin without a version at the one the lock
/// took, so it skips the newer one Maven rejects, whose parent POM reads a
/// property the sync recorded; another value of that property is still
/// refused.
#[test]
fn a_frozen_sync_skips_what_a_rejected_plugin_version_reads() {
    let server = prerequisite_repository_with(
        "4.0.0",
        "<profiles><profile><id>staging</id><activation><property>\
         <name>t.staging</name></property></activation><repositories><repository>\
         <id>staging</id><url>https://staging.example.com/</url></repository>\
         </repositories></profile></profiles>",
    );
    let central = repository();
    let url = format!("http://{}/", central.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>central</mirrorOf></mirror><mirror><id>to-a</id>\
             <url>http://{}/</url><mirrorOf>a</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><pluginRepositories><pluginRepository><id>a</id>\
             <url>https://a.example.com/</url></pluginRepository></pluginRepositories>\
             <build><plugins><plugin><groupId>t</groupId>\
             <artifactId>p-maven-plugin</artifactId><executions><execution>\
             <phase>validate</phase><goals><goal>run</goal></goals></execution>\
             </executions></plugin></plugins></build>",
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:p-maven-plugin:1"), "{lock}");
    assert!(!lock.contains("t:p-maven-plugin:2"), "{lock}");
    assert!(lock.contains("user-property:t.staging"), "{lock}");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
    assert_success(&raeva(&["sync"]), "second sync");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
    let staged = raeva(&["-Dt.staging=1", "sync", "--frozen"]);
    assert_eq!(staged.status.code(), Some(7), "{}", stderr(&staged));
}

/// Two modules whose plugin repositories give the same plugin version other
/// prerequisites each take the version their own repository allows.
#[test]
fn each_module_checks_prerequisites_in_its_plugin_repositories() {
    let central = repository();
    let (newer, older) = (
        prerequisite_repository("4.0.0"),
        prerequisite_repository("3.0"),
    );
    let url = format!("http://{}/", central.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>central</mirrorOf></mirror><mirror><id>to-a</id>\
             <url>http://{}/</url><mirrorOf>a</mirrorOf></mirror><mirror><id>to-b</id>\
             <url>http://{}/</url><mirrorOf>b</mirrorOf></mirror></mirrors></settings>",
            newer.addr(),
            older.addr()
        ),
    )
    .unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
        ),
    )
    .unwrap();
    for module in ["a", "b"] {
        fs::create_dir_all(root.join(module)).unwrap();
        fs::write(
            root.join(module).join("pom.xml"),
            pom(
                module,
                &format!(
                    "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                     <id>{module}</id><url>https://{module}.example.com/</url>\
                     </pluginRepository></pluginRepositories><build><plugins><plugin>\
                     <groupId>t</groupId><artifactId>p-maven-plugin</artifactId><executions>\
                     <execution><phase>validate</phase><goals><goal>run</goal></goals>\
                     </execution></executions></plugin></plugins></build>"
                ),
            ),
        )
        .unwrap();
    }
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let sync = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&sync, "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for version in ["1", "2"] {
        assert!(
            lock.contains(&format!("t:p-maven-plugin:{version}")),
            "{version}: {lock}"
        );
    }
}

/// A plugin dependency that fails below another one names the module and
/// the path to it, on one line and in the JSON location.
#[test]
fn a_plugin_dependency_failure_names_its_path() {
    let server = repository_of(
        |artifact| {
            let declared: &[&str] = match artifact {
                "f-maven-plugin" => &["t:bridge:1"],
                "bridge" => &["t:leaf:1"],
                _ => &[],
            };
            format!("<dependencies>{}</dependencies>", dependencies(declared))
        },
        &["leaf"],
    );
    let url = format!("http://{}/", server.addr());
    let (project, home) = binding_project(&url, "f-maven-plugin");
    let root = project.path();
    let sync = |json: bool| {
        let mut command = raeva_command(root, home.path());
        if json {
            command.arg("--json");
        }
        command.arg("sync").output().expect("run raeva")
    };
    let text = sync(false);
    assert_eq!(text.status.code(), Some(5), "{}", stderr(&text));
    assert!(
        stderr(&text).contains("\n  In pom.xml, through t:bridge:1\n"),
        "{}",
        stderr(&text)
    );
    let envelope = crate::common::envelope(&sync(true));
    assert_eq!(
        envelope["location"],
        serde_json::json!({"module": "pom.xml", "via": ["t:bridge:1"]}),
        "{envelope}"
    );
}

/// A link to an endless device at `.mvn/extensions.xml` is no regular
/// file, which Maven 3.9.12 and 3.10.0 skip, as measured, so raeva reads
/// it as no extensions file without opening it: the check fails until a
/// sync records that.
#[cfg(unix)]
#[test]
fn an_endless_extensions_file_reads_as_none() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let extensions = root.join(".mvn/extensions.xml");
    fs::remove_file(&extensions).unwrap();
    std::os::unix::fs::symlink("/dev/zero", &extensions).unwrap();
    let stale = raeva(&["sync", "--frozen"]);
    assert_eq!(stale.status.code(), Some(7), "{}", stderr(&stale));
    assert!(
        stderr(&stale).contains("other inputs"),
        "{}",
        stderr(&stale)
    );
    assert_success(&raeva(&["sync"]), "sync without extensions");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen without extensions");
}

/// A checkout that gives `.mvn` files CRLF line endings keeps the plugin
/// tables fresh, as it keeps the POMs.
#[test]
fn crlf_mvn_files_keep_the_plugin_tables_fresh() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read(root.join("raeva.lock")).unwrap();
    for file in [".mvn/extensions.xml", ".mvn/maven.config"] {
        let text = fs::read_to_string(root.join(file)).unwrap();
        fs::write(root.join(file), text.replace('\n', "\r\n")).unwrap();
    }
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    assert_success(&raeva(&["sync"]), "sync");
    assert_eq!(fs::read(root.join("raeva.lock")).unwrap(), lock);
}

/// The plugin jars a sync stored serve later runs, offline too: no plugin
/// file is asked of the repository again.
#[test]
fn locked_plugin_jars_come_from_the_store() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let jars = || {
        (server.requests().iter())
            .filter(|request| request.path.ends_with(".jar"))
            .count()
    };
    let fetched = jars();
    assert_success(
        &raeva(&["--offline", "sync", "--frozen"]),
        "offline frozen sync",
    );
    fs::remove_file(root.join("raeva.lock")).unwrap();
    assert_success(&raeva(&["sync"]), "sync from the store");
    assert_eq!(jars(), fetched);
}

/// An offline `sync --frozen` counts the files the plugin tables pin among
/// those it says are in the store, as `raeva lock verify` hashes them.
#[test]
fn an_offline_frozen_sync_counts_the_plugin_files() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let frozen = raeva(&["--offline", "sync", "--frozen"]);
    assert_success(&frozen, "offline frozen sync");
    let verify = raeva(&["--json", "lock", "verify"]);
    assert_success(&verify, "lock verify");
    let verified: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    let verified = &verified["data"]["verified"];
    assert!(
        verified.as_u64().is_some_and(|files| files > 0),
        "{verified}"
    );
    assert!(
        stderr(&frozen).contains(&format!("its {verified} pinned files are in the store")),
        "{verified}: {}",
        stderr(&frozen)
    );
}

/// A traced file whose repository serves it with a wrong checksum fails
/// the sync as an integrity failure.
#[cfg(unix)]
#[test]
fn a_traced_file_with_a_wrong_checksum_exits_9() {
    let server = repository_where(|path| path == "t/tool/1/tool-1.jar");
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let output = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_eq!(output.status.code(), Some(9), "{}", stderr(&output));
}

/// SIGTERM during the traced build stops the sync at once with 143, and
/// the build with it.
#[cfg(unix)]
#[test]
fn sigterm_stops_a_sync_during_the_traced_build() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = root.join("mvnw");
    fs::write(
        &launcher,
        "#!/bin/sh\n: > \"$(dirname \"$0\")/started\"\nsleep 30\n",
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let child = raeva_command(root, home.path())
        .arg("sync")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sync");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !root.join("started").exists() {
        assert!(Instant::now() < deadline, "the traced build never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    let sent = Instant::now();
    let kill = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success());
    let output = child.wait_with_output().expect("wait for sync");
    assert_eq!(output.status.code(), Some(143), "{}", stderr(&output));
    assert!(
        sent.elapsed() < Duration::from_secs(10),
        "{:?}",
        sent.elapsed()
    );
}

/// A plugin repository whose policy refuses the version is passed over, as
/// Maven's artifact resolver does, and the plugin comes from the next one.
#[test]
fn a_plugin_repository_without_releases_is_passed_over() {
    let server = repository();
    let snapshots = StubServer::start(|_| Response::new(404, ""));
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                 <id>snaps</id><url>http://{}/</url><releases><enabled>false</enabled>\
                 </releases></pluginRepository></pluginRepositories>",
                snapshots.addr()
            ),
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let sync = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&sync, "sync");
    assert!(
        snapshots.requests().is_empty(),
        "{:?}",
        snapshots.requests()
    );
}

/// A sync fetches again a plugin jar whose stored file went missing, so an
/// offline export still writes it.
#[test]
fn a_sync_fetches_a_plugin_jar_missing_from_the_store() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let blob = walkdir(home.path())
        .into_iter()
        .find(|path| path.file_name().unwrap() == sha256_hex(JAR).as_str())
        .expect("the stored jar");
    fs::remove_file(blob).unwrap();
    assert_success(&raeva(&["sync"]), "sync again");
    let m2 = home.path().join("m2");
    assert_success(
        &raeva(&["--offline", "export-m2", "--m2-path", m2.to_str().unwrap()]),
        "offline export",
    );
    assert_eq!(fs::read(m2.join("t/ext/2/ext-2.jar")).unwrap(), JAR);
}

fn walkdir(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        match path.is_dir() {
            true => files.extend(walkdir(&path)),
            false => files.push(path),
        }
    }
    files
}

/// A prefix that group metadata gives one plugin and a managed plugin's
/// descriptor another names the managed plugin in Maven 3.10.0, which asks
/// the project's plugins first, and the listed one in Maven 3.9.12.
#[test]
fn a_prefix_names_a_project_plugin_first_in_maven_3_10_0() {
    let server = StubServer::start(|request| {
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            let parts: Vec<&str> = path.split('/').collect();
            let body = match parts.as_slice() {
                ["org", "apache", "maven", "plugins", "maven-metadata.xml"] => {
                    "<metadata><plugins><plugin><prefix>demo</prefix>\
                 <artifactId>maven-demo-plugin</artifactId></plugin></plugins></metadata>"
                        .as_bytes()
                        .to_vec()
                }
                [.., "maven-demo-plugin", "maven-metadata.xml"] => {
                    "<metadata><versioning><release>1</release><versions><version>1</version>\
                 </versions></versioning></metadata>"
                        .as_bytes()
                        .to_vec()
                }
                [group @ .., artifact, version, file]
                    if *file == format!("{artifact}-{version}.pom") =>
                {
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                     <artifactId>{artifact}</artifactId><version>{version}</version>\
                     <packaging>maven-plugin</packaging></project>",
                        group.join(".")
                    )
                    .into_bytes()
                }
                ["t", "demo-maven-plugin", "1", "demo-maven-plugin-1.jar"] => plugin_jar(
                    "<plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                     <version>1</version><goalPrefix>demo</goalPrefix></plugin>",
                ),
                [.., artifact, version, file] if *file == format!("{artifact}-{version}.jar") => {
                    JAR.to_vec()
                }
                _ => return None,
            };
            Some(body)
        })
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><build><pluginManagement><plugins><plugin>\
             <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
             <version>1</version></plugin></plugins></pluginManagement></build>",
        ),
    )
    .unwrap();
    for (line, listed) in [("3.9", true), ("3.10", false)] {
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{line}\"\n\n[plugins]\nlock = true\ngoals = ['demo:run']\n"),
        )
        .unwrap();
        let sync = (raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .expect("run raeva");
        assert_success(&sync, line);
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert_eq!(
            lock.contains("org.apache.maven.plugins:maven-demo-plugin:1"),
            listed,
            "{line}: {lock}"
        );
        assert_eq!(
            lock.contains("t:demo-maven-plugin:1"),
            !listed,
            "{line}: {lock}"
        );
    }
}

/// A project plugin without a version takes one from the plugin
/// repositories' metadata before its descriptor is asked for the prefix,
/// in Maven 3.9.12 once no group metadata lists the prefix and in 3.10.0
/// first.
#[test]
fn a_prefix_names_a_project_plugin_without_a_version() {
    let server = StubServer::start(|request| {
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            let parts: Vec<&str> = path.split('/').collect();
            let body = match parts.as_slice() {
                ["t", "demo-maven-plugin", "maven-metadata.xml"] => {
                    "<metadata><versioning><release>1</release><versions><version>1</version>\
                 </versions></versioning></metadata>"
                        .as_bytes()
                        .to_vec()
                }
                [group @ .., artifact, version, file]
                    if *file == format!("{artifact}-{version}.pom") =>
                {
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                     <artifactId>{artifact}</artifactId><version>{version}</version>\
                     <packaging>maven-plugin</packaging></project>",
                        group.join(".")
                    )
                    .into_bytes()
                }
                ["t", "demo-maven-plugin", "1", "demo-maven-plugin-1.jar"] => plugin_jar(
                    "<plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                     <version>1</version><goalPrefix>demo</goalPrefix></plugin>",
                ),
                [.., artifact, version, file] if *file == format!("{artifact}-{version}.jar") => {
                    JAR.to_vec()
                }
                _ => return None,
            };
            Some(body)
        })
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><build><plugins><plugin>\
             <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
             </plugin></plugins></build>",
        ),
    )
    .unwrap();
    for line in ["3.9", "3.10"] {
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{line}\"\n\n[plugins]\nlock = true\ngoals = ['demo:run']\n"),
        )
        .unwrap();
        let sync = (raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .expect("run raeva");
        assert_success(&sync, line);
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(lock.contains("t:demo-maven-plugin:1"), "{line}: {lock}");
    }
}

/// A plugin whose descriptor names other coordinates than its own is
/// skipped for a prefix, as Maven's descriptor check rejects it, and the
/// next one with the prefix is taken.
#[test]
fn a_prefix_skips_a_descriptor_of_other_coordinates() {
    let server = StubServer::start(|request| {
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            let parts: Vec<&str> = path.split('/').collect();
            let body = match parts.as_slice() {
                [group @ .., artifact, version, file]
                    if *file == format!("{artifact}-{version}.pom") =>
                {
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                     <artifactId>{artifact}</artifactId><version>{version}</version>\
                     <packaging>maven-plugin</packaging></project>",
                        group.join(".")
                    )
                    .into_bytes()
                }
                [
                    "t",
                    "demo-copy-maven-plugin",
                    "1",
                    "demo-copy-maven-plugin-1.jar",
                ] => plugin_jar(
                    "<plugin><groupId>org.apache.maven.plugins</groupId>\
                     <artifactId>maven-antrun-plugin</artifactId><version>3.2.0</version>\
                     <goalPrefix>demo</goalPrefix></plugin>",
                ),
                ["t", "demo-maven-plugin", "1", "demo-maven-plugin-1.jar"] => plugin_jar(
                    "<plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                     <version>1</version><goalPrefix>demo</goalPrefix></plugin>",
                ),
                [.., artifact, version, file] if *file == format!("{artifact}-{version}.jar") => {
                    JAR.to_vec()
                }
                _ => return None,
            };
            Some(body)
        })
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><build><pluginManagement><plugins>\
             <plugin><groupId>t</groupId><artifactId>demo-copy-maven-plugin</artifactId>\
             <version>1</version></plugin>\
             <plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
             <version>1</version></plugin></plugins></pluginManagement></build>",
        ),
    )
    .unwrap();
    for line in ["3.9", "3.10"] {
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{line}\"\n\n[plugins]\nlock = true\ngoals = ['demo:run']\n"),
        )
        .unwrap();
        let sync = (raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .expect("run raeva");
        assert_success(&sync, line);
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(lock.contains("t:demo-maven-plugin:1"), "{line}: {lock}");
        assert!(
            !lock.contains("t:demo-copy-maven-plugin:1"),
            "{line}: {lock}"
        );
    }
}

/// A prefix resolves in the settings.xml `<pluginGroups>` before the default
/// groups, as Maven searches them, and a changed list makes `--frozen`
/// refuse the plugin tables.
#[test]
fn a_prefix_resolves_in_the_settings_plugin_groups() {
    let server = StubServer::start(|request| {
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            let parts: Vec<&str> = path.split('/').collect();
            let body = match parts.as_slice() {
                ["com", "example", "maven-metadata.xml"] => "<metadata><plugins><plugin>\
                 <prefix>ex</prefix><artifactId>ex-maven-plugin</artifactId></plugin>\
                 </plugins></metadata>"
                    .as_bytes()
                    .to_vec(),
                [.., "ex-maven-plugin", "maven-metadata.xml"] => {
                    "<metadata><versioning><release>1</release><versions><version>1</version>\
                 </versions></versioning></metadata>"
                        .as_bytes()
                        .to_vec()
                }
                [group @ .., artifact, version, file]
                    if *file == format!("{artifact}-{version}.pom") =>
                {
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                     <artifactId>{artifact}</artifactId><version>{version}</version>\
                     <packaging>maven-plugin</packaging></project>",
                        group.join(".")
                    )
                    .into_bytes()
                }
                [.., artifact, version, file] if *file == format!("{artifact}-{version}.jar") => {
                    JAR.to_vec()
                }
                _ => return None,
            };
            Some(body)
        })
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = binding_project(&url, "demo-maven-plugin");
    let root = project.path();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ngoals = ['ex:run']\n",
    )
    .unwrap();
    let settings = |groups: &str| {
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><pluginGroups>{groups}</pluginGroups><mirrors><mirror><id>stub</id>\
                 <url>{url}</url><mirrorOf>*</mirrorOf></mirror></mirrors></settings>"
            ),
        )
        .unwrap();
    };
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    settings("<pluginGroup>com.example</pluginGroup>");
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("com.example:ex-maven-plugin:1"), "{lock}");
    settings("<pluginGroup>com.example</pluginGroup><pluginGroup>org.other</pluginGroup>");
    let frozen = raeva(&["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
}

/// In a reactor each module resolves a prefix from its own plugins: a
/// module that manages a plugin of a default group with the prefix takes
/// it in the 3.10 mode, the others the plugin group metadata lists.
#[test]
fn each_module_resolves_a_prefix_from_its_own_plugins() {
    let server = StubServer::start(|request| {
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            let parts: Vec<&str> = path.split('/').collect();
            let body = match parts.as_slice() {
                ["org", "apache", "maven", "plugins", "maven-metadata.xml"] => {
                    "<metadata><plugins><plugin><prefix>demo</prefix>\
                 <artifactId>maven-demo-plugin</artifactId></plugin></plugins></metadata>"
                        .as_bytes()
                        .to_vec()
                }
                [.., "maven-demo-plugin", "maven-metadata.xml"] => {
                    "<metadata><versioning><release>1</release><versions><version>1</version>\
                 </versions></versioning></metadata>"
                        .as_bytes()
                        .to_vec()
                }
                [group @ .., artifact, version, file]
                    if *file == format!("{artifact}-{version}.pom") =>
                {
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                     <artifactId>{artifact}</artifactId><version>{version}</version>\
                     <packaging>maven-plugin</packaging></project>",
                        group.join(".")
                    )
                    .into_bytes()
                }
                [
                    "org",
                    "codehaus",
                    "mojo",
                    "demo-maven-plugin",
                    "1",
                    "demo-maven-plugin-1.jar",
                ] => plugin_jar(
                    "<plugin><groupId>org.codehaus.mojo</groupId>\
                         <artifactId>demo-maven-plugin</artifactId><version>1</version>\
                         <goalPrefix>demo</goalPrefix></plugin>",
                ),
                [.., artifact, version, file] if *file == format!("{artifact}-{version}.jar") => {
                    JAR.to_vec()
                }
                _ => return None,
            };
            Some(body)
        })
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
        ),
    )
    .unwrap();
    let parent = "<parent><groupId>t</groupId><artifactId>app</artifactId><version>1</version>\
                  </parent><packaging>pom</packaging>";
    for (module, build) in [
        (
            "a",
            "<build><pluginManagement><plugins><plugin><groupId>org.codehaus.mojo</groupId>\
             <artifactId>demo-maven-plugin</artifactId><version>1</version></plugin></plugins>\
             </pluginManagement></build>",
        ),
        ("b", ""),
    ] {
        fs::create_dir_all(root.join(module)).unwrap();
        fs::write(
            root.join(module).join("pom.xml"),
            pom(module, &format!("{parent}{build}")),
        )
        .unwrap();
    }
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\ngoals = ['demo:run']\n",
    )
    .unwrap();
    let sync = (raeva_command(root, home.path()))
        .arg("sync")
        .output()
        .expect("run raeva");
    assert_success(&sync, "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for coordinate in [
        "org.codehaus.mojo:demo-maven-plugin:1",
        "org.apache.maven.plugins:maven-demo-plugin:1",
    ] {
        assert!(lock.contains(coordinate), "{coordinate}: {lock}");
    }
}

/// The project's own `<prerequisites><maven>` is read for no plugin, so a
/// property it names is not recorded as an input of raeva.lock.
#[test]
fn a_project_prerequisite_is_no_lock_input() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let root = project.path();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><prerequisites><maven>${maven.min}</maven>\
             </prerequisites>",
        ),
    )
    .unwrap();
    let sync = (raeva_command(root, home.path()))
        .args(["sync", "--offline"])
        .output()
        .expect("run raeva");
    assert_success(&sync, "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!lock.contains("maven.min"), "{lock}");
}

/// A plugin version whose jar no repository serves is passed over for the
/// one before it, as Maven passes over a version whose descriptor does not
/// load, also when a blocked mirror stands among the plugin repositories.
#[test]
fn a_plugin_version_without_a_jar_is_passed_over_past_a_blocked_repository() {
    const METADATA: &str = "<metadata><groupId>t</groupId>\
        <artifactId>demo-maven-plugin</artifactId><versioning><latest>2</latest>\
        <release>2</release><versions><version>1</version><version>2</version></versions>\
        </versioning></metadata>";
    let server = StubServer::start(|request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        let body = match path {
            "/t/demo-maven-plugin/maven-metadata.xml" => METADATA,
            "/t/demo-maven-plugin/2/demo-maven-plugin-2.jar" => return Response::new(404, ""),
            _ => return serve(request, None, |_| (JAR, true), |_| false),
        };
        match sidecar {
            true => Response::new(200, sha256_hex(body.as_bytes())),
            false => Response::new(200, body),
        }
    });
    // Without the blocked repository, then with it.
    let walled = "<pluginRepositories><pluginRepository><id>walled</id>\
                  <url>https://walled.example/</url></pluginRepository></pluginRepositories>";
    let blocker = "<mirror><id>walled-off</id><url>http://0.0.0.0/</url>\
                   <mirrorOf>walled</mirrorOf><blocked>true</blocked></mirror>";
    for (repositories, blocked) in [("", ""), (walled, blocker)] {
        let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors>{blocked}<mirror><id>stub</id><url>http://{}/</url>\
                 <mirrorOf>*,!walled</mirrorOf></mirror></mirrors></settings>",
                server.addr()
            ),
        )
        .unwrap();
        fs::write(
            project.path().join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<packaging>pom</packaging>{repositories}<build><plugins><plugin>\
                     <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                     <executions><execution><phase>validate</phase><goals><goal>run</goal>\
                     </goals></execution></executions></plugin></plugins></build>"
                ),
            ),
        )
        .unwrap();
        fs::write(
            project.path().join("raeva.toml"),
            "[plugins]\nlock = true\n",
        )
        .unwrap();
        let output = (raeva_command(project.path(), home.path()))
            .arg("sync")
            .output()
            .expect("run raeva");
        assert_success(&output, blocked);
        let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
        assert!(lock.contains("t:demo-maven-plugin:1"), "{blocked}: {lock}");
    }
}

/// A plugin repository whose policy refuses the plugin's version is passed
/// over though the store holds the jar from its URL, which it served while
/// its policy took the version: the home an earlier sync filled locks what
/// a fresh home locks.
#[test]
fn a_plugin_repository_that_refuses_the_version_is_passed_over_in_the_store() {
    let (central, corp) = (repository(), repository());
    let (url, corp) = (
        format!("http://{}/", central.addr()),
        format!("http://{}/", corp.addr()),
    );
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let settings = |releases: bool| {
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url><mirrorOf>central</mirrorOf>\
             </mirror></mirrors><profiles><profile><id>corp</id><pluginRepositories>\
             <pluginRepository><id>corp</id><url>{corp}</url><releases><enabled>{releases}\
             </enabled></releases></pluginRepository></pluginRepositories></profile></profiles>\
             <activeProfiles><activeProfile>corp</activeProfile></activeProfiles></settings>"
        )
    };
    let sync = |home: &std::path::Path| {
        let output = (raeva_command(root, home))
            .arg("sync")
            .output()
            .expect("run raeva");
        assert_success(&output, "sync");
        fs::read_to_string(root.join("raeva.lock")).unwrap()
    };
    fs::write(home.path().join(".m2/settings.xml"), settings(true)).unwrap();
    let served_by_corp = format!("repo_url = \"{corp}\"");
    assert!(sync(home.path()).contains(&served_by_corp));
    fs::write(home.path().join(".m2/settings.xml"), settings(false)).unwrap();
    let warm = sync(home.path());
    let fresh = TempDir::new().unwrap();
    fs::create_dir_all(fresh.path().join(".m2")).unwrap();
    fs::write(fresh.path().join(".m2/settings.xml"), settings(false)).unwrap();
    fs::remove_file(root.join("raeva.lock")).unwrap();
    assert_eq!(warm, sync(fresh.path()));
    assert!(!warm.contains(&served_by_corp), "{warm}");
}

/// A plugin version from a host value, as Maven interpolates it at build
/// time: `.mvn/jvm.config`, a settings.xml profile property or the JDK's
/// `java.version`. A plain sync after the value changed locks the plugin
/// that value names, and `--frozen` on a host with another value refuses
/// the tables and names what the versions read. A host value only a
/// plugin's `<configuration>` reads is not an input.
#[test]
fn a_plugin_version_from_a_host_value_follows_it() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    fs::write(
        project.path().join("raeva.toml"),
        "[plugins]\nlock = true\n",
    )
    .unwrap();
    let pom_path = project.path().join("pom.xml");
    let pom_text = fs::read_to_string(&pom_path).unwrap();
    let raeva = |java: &str, args: &[&str]| {
        (raeva_command(project.path(), home.path()))
            .env("JAVA_VERSION", java)
            .args(args)
            .output()
            .expect("run raeva")
    };
    let locked = |version: &str| {
        let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
        lock.contains(&format!("t:demo-maven-plugin:{version}\\t"))
    };
    let plugin = "<artifactId>demo-maven-plugin</artifactId><version>1</version>";
    let profile = |value: &str| {
        format!(
            "<mirrors><mirror><id>stub</id><url>{url}</url><mirrorOf>*</mirrorOf></mirror>\
             </mirrors><profiles><profile><id>v</id><properties><demo.version>{value}\
             </demo.version></properties></profile></profiles><activeProfiles>\
             <activeProfile>v</activeProfile></activeProfiles>"
        )
    };
    let jvm_config = project.path().join(".mvn/jvm.config");
    type Set<'a> = &'a dyn Fn(&str);
    let cases: [(&str, Set<'_>); 3] = [
        (".mvn/jvm.config", &|value| {
            fs::write(&jvm_config, format!("-Ddemo.version={value}\n")).unwrap();
        }),
        ("settings-property:demo.version", &|value| {
            settings_with(home.path(), &profile(value));
        }),
        ("java.version", &|_| {}),
    ];
    for (source, set) in cases {
        let version = match source {
            "java.version" => "${java.version}",
            _ => "${demo.version}",
        };
        let configured = format!(
            "<artifactId>demo-maven-plugin</artifactId><version>{version}</version>\
             <configuration><jdk>${{java.version}}</jdk></configuration>"
        );
        fs::write(&pom_path, pom_text.replace(plugin, &configured)).unwrap();
        let (first, second) = match source {
            "java.version" => ("17", "21"),
            _ => ("1", "2"),
        };
        set(first);
        assert_success(&raeva("17", &["sync"]), source);
        assert!(locked(first), "{source}");
        if source != "java.version" {
            // The JDK only the configuration reads changes nothing.
            assert_success(&raeva("21", &["sync", "--frozen"]), source);
        }
        set(second);
        let java = if source == "java.version" {
            second
        } else {
            "17"
        };
        let frozen = raeva(java, &["sync", "--frozen"]);
        assert_eq!(
            frozen.status.code(),
            Some(7),
            "{source}: {}",
            stderr(&frozen)
        );
        let sync = raeva(java, &["sync"]);
        assert_success(&sync, source);
        assert!(
            locked(second) && !locked(first),
            "{source}: {}",
            stderr(&sync)
        );
        assert_success(&raeva(java, &["sync", "--frozen"]), source);
        let _ = fs::remove_file(&jvm_config);
        settings_with(
            home.path(),
            &profile(first).replace("<activeProfile>v</activeProfile>", ""),
        );
        fs::remove_file(project.path().join("raeva.lock")).unwrap();
    }
}

/// What the plugin resolution reads from the host besides the plugins'
/// own coordinates is an input too: `.mvn/extensions.xml` takes
/// `.mvn/jvm.config` values, and the compiler plugin's processor paths are
/// resolved from its configuration, `annotationProcessorPathsUseDepMgmt`
/// too. A managed plugin the build does not run reads nothing it resolves.
#[test]
fn what_the_plugin_resolution_reads_from_the_host_is_an_input() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    fs::write(
        project.path().join("raeva.toml"),
        "[plugins]\nlock = true\n",
    )
    .unwrap();
    let raeva = |java: &str, args: &[&str]| {
        (raeva_command(project.path(), home.path()))
            .env("JAVA_VERSION", java)
            .args(args)
            .output()
            .expect("run raeva")
    };
    let locked = |coordinate: &str| {
        let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
        lock.contains(&format!("{coordinate}\\t"))
    };
    fs::remove_file(project.path().join(".mvn/maven.config")).unwrap();
    let jvm_config = project.path().join(".mvn/jvm.config");
    fs::write(&jvm_config, "-Dext.version=1\n").unwrap();
    let pom_path = project.path().join("pom.xml");
    let pom_text = fs::read_to_string(&pom_path).unwrap();
    let managed = "<pluginManagement><plugins><plugin><groupId>t</groupId>\
                   <artifactId>unused-maven-plugin</artifactId><version>${java.version}</version>\
                   </plugin></plugins></pluginManagement>";
    fs::write(
        &pom_path,
        pom_text.replace(
            "</plugins></build>",
            &format!("</plugins>{managed}</build>"),
        ),
    )
    .unwrap();
    assert_success(&raeva("17", &["sync"]), "sync");
    assert!(locked("t:ext:1"));
    assert_success(&raeva("21", &["sync", "--frozen"]), "frozen on 21");
    fs::write(&jvm_config, "-Dext.version=2\n").unwrap();
    assert_success(&raeva("17", &["sync"]), "sync after jvm.config");
    assert!(locked("t:ext:2") && !locked("t:ext:1"));
    fs::write(&jvm_config, "-Dext.version=${java.version}\n").unwrap();
    assert_success(&raeva("17", &["sync"]), "sync with the JDK's extension");
    assert!(locked("t:ext:17"));
    let frozen = raeva("21", &["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    fs::write(&jvm_config, "-Dext.version=2\n").unwrap();

    let compiler = "<plugin><artifactId>maven-compiler-plugin</artifactId><version>3</version>\
                    <configuration><release>${java.version}</release><annotationProcessorPaths>\
                    <path><groupId>t</groupId><artifactId>proc</artifactId>\
                    <version>${java.version}</version></path></annotationProcessorPaths>\
                    </configuration></plugin>";
    fs::write(
        &pom_path,
        pom_text.replace(
            "</plugins></build>",
            &format!("{compiler}</plugins>{managed}</build>"),
        ),
    )
    .unwrap();
    assert_success(&raeva("17", &["sync"]), "sync with processor paths");
    assert!(locked("t:proc:17"));
    let frozen = raeva("21", &["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    assert_success(&raeva("21", &["sync"]), "sync on 21");
    assert!(locked("t:proc:21") && !locked("t:proc:17"));

    let compiler = "<plugin><artifactId>maven-compiler-plugin</artifactId><version>3.13.0\
                    </version><configuration><annotationProcessorPathsUseDepMgmt>${dm}\
                    </annotationProcessorPathsUseDepMgmt><annotationProcessorPaths><path>\
                    <groupId>t</groupId><artifactId>proc</artifactId><version>1</version>\
                    </path></annotationProcessorPaths></configuration></plugin>";
    let profile = "<properties><dm>false</dm></properties><profiles><profile><id>j21</id>\
                   <activation><jdk>21</jdk></activation><properties><dm>true</dm></properties>\
                   </profile></profiles><build>";
    fs::write(
        &pom_path,
        (pom_text.replacen("<build>", profile, 1)).replace(
            "</plugins></build>",
            &format!("{compiler}</plugins></build>"),
        ),
    )
    .unwrap();
    assert_success(&raeva("17", &["sync"]), "sync without management");
    let frozen = raeva("21", &["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
}

/// A profile the JDK activates and that adds a plugin is an input of the
/// plugin tables: a plain sync on the JDK that activates it locks the
/// plugin, and `--frozen` on another JDK refuses the tables. One that only
/// configures a plugin the build declares anyway is not.
#[test]
fn a_jdk_profile_that_adds_a_plugin_is_an_input() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    fs::write(
        project.path().join("raeva.toml"),
        "[plugins]\nlock = true\n",
    )
    .unwrap();
    let pom_path = project.path().join("pom.xml");
    let pom_text = fs::read_to_string(&pom_path).unwrap();
    let profile = |id: &str, plugin: &str| {
        format!(
            "<profile><id>{id}</id><activation><jdk>[21,)</jdk></activation><build><plugins>\
             <plugin><groupId>t</groupId><artifactId>{plugin}</artifactId>{}</plugin>\
             </plugins></build></profile>",
            match plugin {
                "demo-maven-plugin" => "<configuration><release>21</release></configuration>",
                _ =>
                    "<version>1</version><executions><execution><phase>validate</phase>\
                      <goals><goal>run</goal></goals></execution></executions>",
            }
        )
    };
    let with_profiles = |profiles: &[String]| {
        let profiles = format!("</build><profiles>{}</profiles>", profiles.concat());
        fs::write(&pom_path, pom_text.replace("</build>", &profiles)).unwrap();
    };
    let raeva = |java: &str, args: &[&str]| {
        (raeva_command(project.path(), home.path()))
            .env("JAVA_VERSION", java)
            .args(args)
            .output()
            .expect("run raeva")
    };
    let lock = || fs::read_to_string(project.path().join("raeva.lock")).unwrap();

    with_profiles(&[profile("configure", "demo-maven-plugin")]);
    assert_success(&raeva("17", &["sync"]), "sync on 17");
    assert!(!lock().contains("jdk:"), "{}", lock());
    assert_success(&raeva("21", &["sync", "--frozen"]), "frozen on 21");

    with_profiles(&[
        profile("configure", "demo-maven-plugin"),
        profile("add", "jdk-maven-plugin"),
    ]);
    assert_success(&raeva("17", &["sync"]), "sync on 17");
    assert!(!lock().contains("jdk-maven-plugin"), "{}", lock());
    let frozen = raeva("21", &["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));
    assert!(
        stderr(&frozen).contains("jdk:[21,) is false"),
        "{}",
        stderr(&frozen)
    );
    assert_success(&raeva("21", &["sync"]), "sync on 21");
    assert!(lock().contains("t:jdk-maven-plugin:1"), "{}", lock());
    assert_success(&raeva("21", &["sync", "--frozen"]), "frozen on 21");
    let frozen = raeva("17", &["sync", "--frozen"]);
    assert_eq!(frozen.status.code(), Some(7), "{}", stderr(&frozen));

    // Each JDK `[lock] jdks` lists gets its own tables, which hold on any host.
    fs::write(
        project.path().join("raeva.toml"),
        "[lock]\njdks = ['17', '21']\n\n[plugins]\nlock = true\n",
    )
    .unwrap();
    assert_success(&raeva("17", &["sync"]), "sync of both JDKs on 17");
    assert!(lock().contains("t:jdk-maven-plugin:1"), "{}", lock());
    assert!(!lock().contains("jdk:[21,)"), "{}", lock());
    assert_success(&raeva("21", &["sync", "--frozen"]), "frozen on 21");
    assert_success(&raeva("17", &["sync", "--frozen"]), "frozen on 17");
}

/// A traced file that a POM repository and Central both serve with Maven's
/// bytes is pinned at the repository Maven's marker names, Central through
/// its mirror here, though the POM's comes first: `mvn -o` accepts an
/// exported file only under the id of a repository the build asks for it.
#[cfg(unix)]
#[test]
fn a_traced_file_takes_the_repository_maven_names() {
    let server = repository();
    let other = repository();
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fake_mvnw(root);
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        &format!(
            "<repositories><repository><id>x</id><url>http://{0}/</url></repository>\
             </repositories><pluginRepositories><pluginRepository><id>x</id>\
             <url>http://{0}/</url></pluginRepository></pluginRepositories><build>",
            other.addr()
        ),
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| {
        (raeva_command(root, home.path()))
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(&raeva(&["sync"]), "traced sync");
    let tables = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let row = tables
        .split("[[platforms.plugins.artifacts]]")
        .find(|row| row.contains("artifact = \"tool\""))
        .unwrap_or_else(|| panic!("{tables}"));
    assert!(
        row.contains("repo_url = \"https://repo.maven.apache.org/maven2/\""),
        "{row}"
    );
    let m2 = home.path().join("m2");
    assert_success(
        &raeva(&["export-m2", "--m2-path", m2.to_str().unwrap()]),
        "export",
    );
    let marker = fs::read_to_string(m2.join("t/tool/1/_remote.repositories")).unwrap();
    assert!(marker.contains("tool-1.jar>stub="), "{marker}");
    assert!(!marker.contains(">x="), "{marker}");
}

/// A goal that names its plugin's version runs that version, as Maven
/// keeps a goal's own version over the project's declaration, so the
/// tables lock it beside the bound one.
#[test]
fn a_goal_locks_the_version_it_names() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ngoals = ['t:demo-maven-plugin:2:run']\n",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for coordinate in ["t:demo-maven-plugin:1", "t:demo-maven-plugin:2"] {
        assert!(lock.contains(coordinate), "{coordinate}: {lock}");
    }
}

/// A module of the reactor serves a plugin only at its own version: a
/// released version of the same plugin comes from the repository, as
/// Maven's reactor reader matches the version too.
#[test]
fn a_reactor_plugin_of_another_version_is_locked() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom.replacen(
            "<build>",
            "<modules><module>plugin</module></modules><build>",
            1,
        ),
    )
    .unwrap();
    fs::create_dir_all(root.join("plugin")).unwrap();
    fs::write(
        root.join("plugin/pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>demo-maven-plugin</artifactId><version>5</version>\
         <packaging>maven-plugin</packaging></project>",
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:demo-maven-plugin:1"), "{lock}");
}

/// A plugin that names no version takes one from the plugin repositories'
/// metadata though a module of the reactor has its coordinates, as Maven's
/// plugin version resolver reads no reactor: with no metadata the sync
/// fails, as Maven 3.10.0 does.
#[test]
fn a_versionless_plugin_the_reactor_builds_takes_a_repository_version() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    let pom = pom.replacen("<version>1</version><executions>", "<executions>", 1);
    let pom = pom.replacen(
        "<build>",
        "<modules><module>plugin</module></modules><build>",
        1,
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    fs::create_dir_all(root.join("plugin")).unwrap();
    fs::write(
        root.join("plugin/pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>demo-maven-plugin</artifactId><version>5</version>\
         <packaging>maven-plugin</packaging></project>",
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let sync = run_raeva(root, home.path(), &["sync"]);
    assert!(!sync.status.success(), "sync succeeded: {}", stderr(&sync));
    assert!(
        stderr(&sync).contains("demo-maven-plugin"),
        "{}",
        stderr(&sync)
    );
}

/// A plugin whose POM relocates locks the plugin it relocates to, as
/// Maven's plugin dependencies resolver takes the artifact its descriptor
/// names.
#[test]
fn a_relocated_plugin_locks_its_target() {
    let server = StubServer::start(|request| {
        let relocating = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>old-plugin</artifactId><version>1</version><distributionManagement>\
             <relocation><artifactId>demo-maven-plugin</artifactId></relocation>\
             </distributionManagement></project>";
        match request.path.strip_prefix("/t/old-plugin/1/old-plugin-1.") {
            Some("pom") => Response::new(200, relocating),
            Some("pom.sha256") => Response::new(200, sha256_hex(relocating.as_bytes())),
            Some(_) => Response::new(404, ""),
            None => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    let pom = pom.replacen("demo-maven-plugin", "old-plugin", 1);
    fs::write(root.join("pom.xml"), pom).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:demo-maven-plugin:1"), "{lock}");
    let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "sync --frozen");
}

/// `lock verify` hashes the files the plugin tables pin, as it does the
/// dependencies': a plugin jar gone from the store fails it, and
/// `--download` fetches it again.
#[test]
fn lock_verify_checks_the_plugin_files() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    assert_success(
        &run_raeva(root, home.path(), &["lock", "verify"]),
        "lock verify",
    );
    let blob = walkdir(home.path())
        .into_iter()
        .find(|path| path.file_name() == Some(sha256_hex(JAR).as_ref()))
        .expect("the plugin jar's blob");
    fs::remove_file(blob).unwrap();
    let verify = run_raeva(root, home.path(), &["lock", "verify"]);
    assert_eq!(verify.status.code(), Some(7), "{}", stderr(&verify));
    assert!(
        stderr(&verify).contains("demo-maven-plugin"),
        "{}",
        stderr(&verify)
    );
    assert_success(
        &run_raeva(root, home.path(), &["lock", "verify", "--download"]),
        "lock verify --download",
    );
    assert_success(
        &run_raeva(root, home.path(), &["lock", "verify"]),
        "lock verify after the download",
    );
}

/// A seed of a project with plugin locking carries what an offline plugin
/// resolution reads: a jar the project and a plugin both use is taken, as
/// Maven 3.9's plugin side names Central, from a route the dependency's row
/// does not record. A restored home then passes `sync --frozen --offline`
/// with no request.
#[test]
fn a_restored_seed_resolves_the_plugins_offline() {
    let server = StubServer::start(|request| {
        let plugin = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>demo-maven-plugin</artifactId><version>1</version>\
             <packaging>maven-plugin</packaging><dependencies><dependency><groupId>t</groupId>\
             <artifactId>shared</artifactId><version>1</version></dependency></dependencies>\
             </project>";
        match request
            .path
            .strip_prefix("/t/demo-maven-plugin/1/demo-maven-plugin-1.pom")
        {
            Some("") => Response::new(200, plugin),
            Some(".sha256") => Response::new(200, sha256_hex(plugin.as_bytes())),
            _ => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<dependencies><dependency><groupId>t</groupId><artifactId>shared</artifactId>\
             <version>1</version></dependency></dependencies><build><plugins><plugin>\
             <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId><version>1</version>\
             <executions><execution><phase>validate</phase><goals><goal>run</goal></goals>\
             </execution></executions></plugin></plugins></build>",
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let seed = home.path().join("seed");
    let save = ["seed", "save", seed.to_str().unwrap()];
    assert_success(&run_raeva(root, home.path(), &save), "seed save");

    let restored = TempDir::new().unwrap();
    fs::create_dir_all(restored.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        restored.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let restore = ["seed", "restore", seed.to_str().unwrap()];
    assert_success(&run_raeva(root, restored.path(), &restore), "seed restore");
    let before = server.requests().len();
    let offline = run_raeva(root, restored.path(), &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline frozen sync after restore");
    let after: Vec<_> = (server.requests().into_iter().skip(before))
        .map(|request| request.path)
        .collect();
    assert!(after.is_empty(), "requests after restore: {after:?}");
}

/// A lock written behind a `*` mirror records each plugin file, its POM and
/// its parent POM under the empty plugin repository a POM lists before
/// Central, which the mirror served them for. A machine that mirrors only
/// Central fetches them from Central in `sync --frozen`, as Maven would ask
/// it next, and a seed saved there carries them all and restores offline.
#[test]
fn a_seed_saved_after_a_frozen_check_carries_the_plugin_poms() {
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>demo-parent</artifactId><version>1</version><packaging>pom</packaging>\
         </project>";
    let plugin = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
         <artifactId>demo-parent</artifactId><version>1</version></parent>\
         <artifactId>demo-maven-plugin</artifactId><packaging>maven-plugin</packaging>\
         </project>";
    let server = StubServer::start(move |request| {
        let path = request.path.as_str();
        for (file, body) in [
            ("/t/demo-parent/1/demo-parent-1.pom", parent),
            ("/t/demo-maven-plugin/1/demo-maven-plugin-1.pom", plugin),
        ] {
            match path.strip_prefix(file) {
                Some("") => return Response::new(200, body),
                Some(".sha256") => return Response::new(200, sha256_hex(body.as_bytes())),
                _ => {}
            }
        }
        serve(request, None, |_| (JAR, true), |_| false)
    });
    let empty = StubServer::start(|_| Response::new(404, ""));
    let url = format!("http://{}/", server.addr());
    let settings = |home: &std::path::Path, mirror_of: &str| {
        fs::create_dir_all(home.join(".m2")).unwrap();
        fs::write(
            home.join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
                 <mirrorOf>{mirror_of}</mirrorOf></mirror></mirrors></settings>"
            ),
        )
        .unwrap();
    };
    let project = TempDir::new().unwrap();
    let root = project.path();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><pluginRepositories><pluginRepository><id>first</id>\
                 <url>http://{}/</url></pluginRepository></pluginRepositories><build><plugins>\
                 <plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                 <version>1</version><executions><execution><phase>validate</phase><goals>\
                 <goal>run</goal></goals></execution></executions></plugin></plugins></build>",
                empty.addr()
            ),
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let locked = TempDir::new().unwrap();
    settings(locked.path(), "*");
    assert_success(&run_raeva(root, locked.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let first = format!("repo_url = \"http://{}/\"", empty.addr());
    assert!(lock.contains(&first), "{lock}");

    let ci = TempDir::new().unwrap();
    settings(ci.path(), "central");
    let frozen = run_raeva(root, ci.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "frozen sync with only Central mirrored");
    let seed = ci.path().join("seed");
    let save = ["seed", "save", seed.to_str().unwrap()];
    assert_success(&run_raeva(root, ci.path(), &save), "seed save");

    let restored = TempDir::new().unwrap();
    settings(restored.path(), "central");
    let restore = ["seed", "restore", seed.to_str().unwrap()];
    assert_success(&run_raeva(root, restored.path(), &restore), "seed restore");
    let before = server.requests().len();
    let offline = run_raeva(root, restored.path(), &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline frozen sync after restore");
    let after: Vec<_> = (server.requests().into_iter().skip(before))
        .map(|request| request.path)
        .collect();
    assert!(after.is_empty(), "requests after restore: {after:?}");
}

/// A project that runs `t:j-maven-plugin`, whose newest version the JDK
/// 17 that raeva.toml locks for rejects, with its plugins locked.
fn java_prerequisite_project(server: &StubServer) -> (TempDir, TempDir) {
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><build><plugins><plugin><groupId>t</groupId>\
             <artifactId>j-maven-plugin</artifactId><executions><execution>\
             <phase>validate</phase><goals><goal>run</goal></goals></execution>\
             </executions></plugin></plugins></build>",
        ),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\njdks = [\"17\"]\n\n[plugins]\nlock = true\n",
    )
    .unwrap();
    (project, home)
}

/// Run raeva on the JDK 17 the project's `[lock] jdks` lists.
fn run_on_17(
    root: &std::path::Path,
    home: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    (raeva_command(root, home))
        .env("JAVA_VERSION", "17")
        .args(args)
        .output()
        .expect("run raeva")
}

/// An offline `--frozen` sync on a home that lacks what the plugin check
/// reads says how to make the home ready; a missing dependency file gets
/// the usual hint. A plain sync of a lock the home did not write checks the
/// plugins, which makes it ready.
#[test]
fn an_offline_frozen_sync_says_how_to_ready_the_plugin_check() {
    let server = java_prerequisite_repository();
    let (project, home) = java_prerequisite_project(&server);
    let root = project.path();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    let dependency = "<packaging>pom</packaging><dependencies><dependency><groupId>t</groupId>\
                      <artifactId>d</artifactId><version>1</version></dependency></dependencies>";
    let pom = pom.replace("<packaging>pom</packaging>", dependency);
    fs::write(root.join("pom.xml"), pom).unwrap();
    assert_success(&run_on_17(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let fresh = TempDir::new().unwrap();
    fs::create_dir_all(fresh.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        fresh.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let offline = || run_on_17(root, fresh.path(), &["--offline", "sync", "--frozen"]);
    let hint = "or restore a seed, to make this home ready offline";

    let empty = offline();
    let stderr = String::from_utf8_lossy(&empty.stderr);
    assert_eq!(empty.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("t/d/1/"), "{stderr}");
    assert!(!stderr.contains(hint), "{stderr}");

    assert_success(&run_on_17(root, fresh.path(), &["sync"]), "plain sync");
    assert_success(&offline(), "offline frozen sync after a plain sync");
    // Without the version listings the check reads, the home is not ready.
    let cache = rusqlite::Connection::open(fresh.path().join("metadata.db")).unwrap();
    cache
        .execute("DELETE FROM version_list_cache_v4", [])
        .unwrap();
    drop(cache);
    let plain = offline();
    let stderr = String::from_utf8_lossy(&plain.stderr);
    assert_eq!(plain.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("maven-metadata.xml"), "{stderr}");
    assert!(stderr.contains(hint), "{stderr}");

    assert_success(
        &run_on_17(root, fresh.path(), &["sync", "--frozen"]),
        "frozen sync",
    );
    let before = server.requests().len();
    assert_success(&offline(), "offline frozen sync after a frozen sync");
    let after: Vec<_> = (server.requests().into_iter().skip(before))
        .map(|request| request.path)
        .collect();
    assert!(after.is_empty(), "requests offline: {after:?}");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
}

/// A version-less plugin whose newest version the JDK rejects resolves
/// offline from a restored seed: Maven reads that version's jar to see its
/// `requiredJavaVersion`, and offline, as `mvn -o` does, skips a version
/// whose jar it cannot resolve. The lock pins only the version taken.
#[test]
fn a_seed_resolves_offline_past_a_plugin_version_the_jdk_rejects() {
    let server = java_prerequisite_repository();
    let (project, home) = java_prerequisite_project(&server);
    let root = project.path();
    assert_success(&run_on_17(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:j-maven-plugin:1"), "{lock}");
    assert!(!lock.contains("t:j-maven-plugin:2"), "{lock}");
    let seed = home.path().join("seed");
    let save = ["seed", "save", seed.to_str().unwrap()];
    assert_success(&run_on_17(root, home.path(), &save), "seed save");

    let restored = TempDir::new().unwrap();
    fs::create_dir_all(restored.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        restored.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let restore = ["seed", "restore", seed.to_str().unwrap()];
    assert_success(&run_on_17(root, restored.path(), &restore), "seed restore");
    let before = server.requests().len();
    let offline = run_on_17(root, restored.path(), &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline frozen sync after restore");
    let after: Vec<_> = (server.requests().into_iter().skip(before))
        .map(|request| request.path)
        .collect();
    assert!(after.is_empty(), "requests after restore: {after:?}");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
}

/// A file a plugin reads from a repository a POM of its closure declares,
/// which the project's dependencies read from their own repository, is
/// carried by a seed for that repository too: a restored home resolves the
/// plugin offline, with no request.
#[test]
fn a_seed_carries_a_plugin_file_from_a_transitive_repository() {
    let x_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>x</artifactId><version>1</version></project>";
    let x = [
        ("/t/x/1/x-1.pom", x_pom.as_bytes()),
        ("/t/x/1/x-1.jar", JAR),
    ];
    let (own, transitive) = (sha256_repository(x), sha256_repository(x));
    let declared = format!("http://{}/", transitive.addr());
    let central = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        if path.starts_with("t/x/") {
            return Response::new(404, "");
        }
        if !path.starts_with("t/") {
            return serve(request, None, |_| (JAR, true), |_| false);
        }
        serve_sha256(path, |path| match path {
            "t/p-maven-plugin/1/p-maven-plugin-1.pom" => Some(
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>p-maven-plugin</artifactId><version>1</version>\
                 <packaging>maven-plugin</packaging><dependencies><dependency>\
                 <groupId>t</groupId><artifactId>y</artifactId><version>1</version>\
                 </dependency></dependencies></project>"
                    .as_bytes()
                    .to_vec(),
            ),
            "t/y/1/y-1.pom" => Some(
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                     <artifactId>y</artifactId><version>1</version><repositories>\
                     <repository><id>t-repo</id><url>{declared}</url></repository>\
                     </repositories><dependencies><dependency><groupId>t</groupId>\
                     <artifactId>x</artifactId><version>1</version></dependency>\
                     </dependencies></project>"
                )
                .into_bytes(),
            ),
            "t/p-maven-plugin/1/p-maven-plugin-1.jar" | "t/y/1/y-1.jar" => Some(JAR.to_vec()),
            _ => None,
        })
    });
    let home = TempDir::new().unwrap();
    let project = TempDir::new().unwrap();
    let root = project.path();
    let settings = |home: &std::path::Path| {
        fs::create_dir_all(home.join(".m2")).unwrap();
        fs::write(
            home.join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
                 <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
                central.addr()
            ),
        )
        .unwrap();
        fs::write(
            home.join("config.toml"),
            "[security]\nallow_transitive_repositories = true\n",
        )
        .unwrap();
    };
    settings(home.path());
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><repositories><repository><id>own</id>\
                 <url>http://{}/</url></repository>\
                 </repositories><dependencies><dependency><groupId>t</groupId>\
                 <artifactId>x</artifactId><version>1</version></dependency></dependencies>\
                 <build><plugins><plugin><groupId>t</groupId>\
                 <artifactId>p-maven-plugin</artifactId><version>1</version><executions>\
                 <execution><phase>validate</phase><goals><goal>run</goal></goals>\
                 </execution></executions></plugin></plugins></build>",
                own.addr()
            ),
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:x:1"), "{lock}");
    let seed = home.path().join("seed");
    let save = ["seed", "save", seed.to_str().unwrap()];
    assert_success(&run_raeva(root, home.path(), &save), "seed save");

    let restored = TempDir::new().unwrap();
    settings(restored.path());
    let restore = ["seed", "restore", seed.to_str().unwrap()];
    assert_success(&run_raeva(root, restored.path(), &restore), "seed restore");
    let requests = || {
        [&central, &own, &transitive]
            .map(|server| server.requests().len())
            .iter()
            .sum::<usize>()
    };
    let before = requests();
    let offline = run_raeva(root, restored.path(), &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline frozen sync after restore");
    assert_eq!(requests(), before);

    // Other bytes for the POM the plugin read from that repository, after
    // the seed was saved, refuse the whole seed.
    let listed = seed.join("seed.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&listed).unwrap()).unwrap();
    let transitive_scope = transitive.addr().to_string();
    let row = (manifest["metadata"].as_array_mut().unwrap().iter_mut())
        .find(|row| {
            row["path"] == "t/x/1/x-1.pom"
                && (row["scope"].as_str()).is_some_and(|scope| scope.contains(&transitive_scope))
        })
        .expect("the row of the POM the plugin read");
    let other = x_pom.replace("</version>", "</version><name>other</name>");
    let changed = sha256_hex(other.as_bytes());
    fs::write(seed.join("metadata").join(&changed), &other).unwrap();
    row["sha256"] = changed.into();
    fs::write(&listed, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let fresh = TempDir::new().unwrap();
    settings(fresh.path());
    let refused = run_raeva(root, fresh.path(), &restore);
    assert_eq!(refused.status.code(), Some(7), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("other bytes than raeva.lock pins"),
        "{}",
        stderr(&refused)
    );
}

/// A report reads a lock whose plugin rows come from the super POM's
/// `central`, or from a POM's `<pluginRepository>`, as it reads one without
/// them: it resolves nothing again, so it opens no metadata cache.
#[test]
fn a_report_on_a_plugin_locked_lock_resolves_nothing() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let corp = "<pluginRepositories><pluginRepository><id>corp-plugins</id>\
                <url>https://plugins.example.test/</url></pluginRepository>\
                </pluginRepositories>";
    for (repositories, origin) in [
        ("", "https://repo.maven.apache.org/maven2/"),
        (corp, "https://plugins.example.test/"),
    ] {
        let (project, home) = plugin_project(&url);
        let root = project.path();
        fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
        let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
        let pom = pom.replace("<build>", &format!("{repositories}<build>"));
        fs::write(root.join("pom.xml"), pom).unwrap();
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(lock.contains(origin), "{lock}");
        let unused = home.path().join("unused");
        let sbom = (raeva_command(root, home.path()))
            .env("RAEVA_HOME", &unused)
            .arg("sbom")
            .output()
            .expect("run raeva");
        assert_success(&sbom, "sbom");
        assert!(
            !unused.join("metadata.db").exists(),
            "{origin}: the report resolved again"
        );
    }
}

/// A `<pluginRepository>` of the project's POM gets the credential of its
/// id when a sync that keeps the plugin tables fetches a locked plugin file
/// from it again, as the resolution that locked it did.
#[test]
fn a_pom_plugin_repository_takes_its_credential_for_a_locked_file() {
    let server = repository_with(Some(PLUGIN_AUTHORIZATION), |_| (JAR, true), |_| false);
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    settings_with(home.path(), "");
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        &format!(
            "<pluginRepositories><pluginRepository><id>corp-plugins</id><url>{url}</url>\
             </pluginRepository></pluginRepositories><build>"
        ),
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let blob = walkdir(home.path())
        .into_iter()
        .find(|path| path.file_name() == Some(sha256_hex(JAR).as_ref()))
        .expect("the plugin jar's blob");
    fs::remove_file(blob).unwrap();
    let again = run_raeva(root, home.path(), &["sync"]);
    assert_success(&again, "sync again");
    assert!(
        !stderr(&again).contains(PLUGIN_PASSWORD),
        "{}",
        stderr(&again)
    );
}

/// Offline, `lock verify --download` reports a plugin file gone from the
/// store as missing, not as a file of an untrusted origin.
#[test]
fn an_offline_verify_names_a_missing_plugin_file_missing() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let blob = walkdir(home.path())
        .into_iter()
        .find(|path| path.file_name() == Some(sha256_hex(JAR).as_ref()))
        .expect("the plugin jar's blob");
    fs::remove_file(blob).unwrap();
    let verify = run_raeva(
        root,
        home.path(),
        &["--offline", "lock", "verify", "--download"],
    );
    assert_eq!(verify.status.code(), Some(7), "{}", stderr(&verify));
    let printed = stderr(&verify);
    assert!(printed.contains("missing"), "{printed}");
    assert!(!printed.contains("untrusted"), "{printed}");
}

/// Discovery reads the POMs' plugin repositories for the checks that run
/// without resolution only: without plugin locking, a host value a plugin
/// repository's URL reads is no input of raeva.lock, and reading it warns
/// of nothing.
#[test]
fn a_plugin_repository_url_is_no_input_without_plugin_locking() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        "<pluginRepositories><pluginRepository><id>corp-plugins</id>\
         <url>https://plugins.example.test/${java.version}/</url></pluginRepository>\
         </pluginRepositories><build>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let sync = run_raeva(root, home.path(), &["sync"]);
    assert_success(&sync, "sync");
    assert!(!stderr(&sync).contains("JAVA_VERSION"), "{}", stderr(&sync));
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!lock.contains("java.version"), "{lock}");
}

/// A build extension or plugin without a version takes the `<release>` of
/// its plugin repositories' metadata, which raeva.lock records only with
/// plugin locking. Without it the export would list there the version
/// another module locks, which `mvn -o` would load instead, so it refuses.
#[test]
fn export_refuses_a_plugin_without_a_version_that_a_module_locks() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let root = project.path();
    for version in ["1.0", "2.0"] {
        crate::common::publish(&root.join("repo"), &format!("t:ext:{version}"), "");
    }
    write_with_sha256(
        &root.join("repo/t/ext/maven-metadata.xml"),
        b"<metadata><groupId>t</groupId><artifactId>ext</artifactId><versioning>\
          <release>1.0</release><versions><version>1.0</version><version>2.0</version>\
          </versions><lastUpdated>20240101000000</lastUpdated></versioning></metadata>",
    );
    let repositories = "<repositories><repository><id>local-repo</id>\
         <url>file://${project.basedir}/../repo/</url></repository></repositories>\
         <pluginRepositories><pluginRepository><id>local-repo</id>\
         <url>file://${project.basedir}/../repo/</url></pluginRepository></pluginRepositories>";
    let module = |name: &str, body: &str| {
        fs::create_dir_all(root.join(name)).unwrap();
        let parent = "<parent><groupId>t</groupId><artifactId>root</artifactId>\
                      <version>1</version></parent><packaging>pom</packaging>";
        let text = pom(name, &format!("{parent}{repositories}{body}"));
        fs::write(root.join(name).join("pom.xml"), text).unwrap();
    };
    let modules =
        "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>";
    fs::write(root.join("pom.xml"), pom("root", modules)).unwrap();
    let m2 = TempDir::new().unwrap();
    let export = ["export-m2", "--m2-path", m2.path().to_str().unwrap()];
    let ga = "<groupId>t</groupId><artifactId>ext</artifactId>";
    let extension = format!("<extensions><extension>{ga}</extension></extensions>");
    // A `LATEST` records only the `<latest>`, which Maven reads after the
    // `<release>`.
    for (build, locked, refused) in [
        (extension.clone(), "2.0", true),
        (
            format!("<plugins><plugin>{ga}</plugin></plugins>"),
            "2.0",
            true,
        ),
        (extension.clone(), "LATEST", true),
        (
            format!("<extensions><extension>{ga}<version>1.0</version></extension></extensions>"),
            "2.0",
            false,
        ),
    ] {
        module("a", &format!("<build>{build}</build>"));
        module(
            "b",
            &format!(
                "<dependencies><dependency>{ga}<version>{locked}</version></dependency></dependencies>"
            ),
        );
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        let exported = run_raeva(root, home.path(), &export);
        if refused {
            assert_eq!(exported.status.code(), Some(3), "{}", stderr(&exported));
            let text = stderr(&exported);
            assert!(
                text.contains("t:ext is a build plugin or extension"),
                "{text}"
            );
            assert!(text.contains("[plugins] lock = true"), "{text}");
        } else {
            assert_success(&exported, "export-m2");
        }
    }
    // An extension a remote parent declares counts as one a module does.
    let corp = pom(
        "corp",
        &format!("<packaging>pom</packaging><build>{extension}</build>"),
    );
    let parents = StubServer::start(move |request| {
        serve_sha256(&request.path, |path| {
            (path == "/t/corp/1/corp-1.pom").then(|| corp.clone())
        })
    });
    let root_pom = format!(
        "<parent><groupId>t</groupId><artifactId>corp</artifactId><version>1</version>\
         <relativePath/></parent>{modules}<repositories><repository><id>corp</id>\
         <url>http://{}/</url></repository></repositories>",
        parents.addr()
    );
    fs::write(root.join("pom.xml"), pom("root", &root_pom)).unwrap();
    module("a", "");
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let exported = run_raeva(root, home.path(), &export);
    assert_eq!(exported.status.code(), Some(3), "{}", stderr(&exported));
    fs::write(root.join("pom.xml"), pom("root", modules)).unwrap();
    // A home that holds the locked files but not the metadata cache the
    // models read from still exports, with a warning.
    let boms = StubServer::start(|request| {
        serve_sha256(&request.path, |path| {
            (path == "/t/bom/1/bom-1.pom").then(|| pom("bom", "<packaging>pom</packaging>"))
        })
    });
    let a = pom(
        "a",
        &format!(
            "<parent><groupId>t</groupId><artifactId>root</artifactId><version>1</version>\
             </parent><packaging>pom</packaging><repositories><repository><id>boms</id>\
             <url>http://{}/</url></repository></repositories><build>{extension}</build>\
             <dependencyManagement><dependencies><dependency><groupId>t</groupId>\
             <artifactId>bom</artifactId><version>1</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>",
            boms.addr()
        ),
    );
    fs::write(root.join("a/pom.xml"), a).unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    for entry in fs::read_dir(home.path()).unwrap() {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("metadata.db")
        {
            fs::remove_file(path).unwrap();
        }
    }
    let exported = run_raeva(root, home.path(), &export);
    assert_success(&exported, "export-m2");
    assert!(
        stderr(&exported).contains("could not read the build plugins"),
        "{}",
        stderr(&exported)
    );
}

/// A stub repository that serves under `/our-org/` and `/attacker-org/`
/// what [`repository`] serves, `jar` as the demo plugin's jar.
fn org_repository(jar: &'static [u8]) -> StubServer {
    StubServer::start(move |request| {
        let mut inner = request.clone();
        let Some(rest) = ["/our-org/", "/attacker-org/"]
            .iter()
            .find_map(|prefix| request.path.strip_prefix(prefix))
        else {
            return Response::new(404, "");
        };
        inner.path = format!("/{rest}");
        let jar = move |artifact: &str| match artifact {
            "demo-maven-plugin" => (jar, true),
            _ => (JAR, true),
        };
        serve(&inner, None, jar, |_| false)
    })
}

/// A fake credential, only ever compared.
const FAKE_PASSWORD: &str = "FAKE-test-only-pw";

/// [`plugin_project`] locking its plugins, with a home whose settings.xml
/// mirrors Central to `/our-org/` of `server` under the id `gh`, which a
/// `<server>` gives a credential, and whose config.toml is `config`.
fn org_project(server: &StubServer, config: &str) -> (TempDir, TempDir) {
    let (project, home) = plugin_project("unused");
    fs::write(
        project.path().join("raeva.toml"),
        "[plugins]\nlock = true\n",
    )
    .unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><servers><server><id>gh</id><username>alice</username>\
             <password>{FAKE_PASSWORD}</password></server></servers><mirrors><mirror>\
             <id>gh</id><url>http://{}/our-org/</url><mirrorOf>central</mirrorOf></mirror>\
             </mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    fs::write(home.path().join("config.toml"), config).unwrap();
    (project, home)
}

/// `lock` with the demo plugin's row moved to `url`, recorded under `id`
/// when there is one, and pinned to `jar` when there is one: what an edit
/// of raeva.lock alone can do.
fn tampered(lock: &str, url: &str, id: Option<&str>, jar: Option<&[u8]>) -> String {
    let at = lock
        .find("artifact = \"demo-maven-plugin\"")
        .expect("the plugin row");
    let row = lock[..at].rfind("repo_url = \"").expect("its repo_url");
    let end = row + lock[row..].find('\n').unwrap();
    let mut tampered = format!("{}repo_url = \"{url}\"{}", &lock[..row], &lock[end..]);
    if let Some(jar) = jar {
        let at = tampered.find("artifact = \"demo-maven-plugin\"").unwrap();
        let digest = at + tampered[at..].find("digest = \"").unwrap() + "digest = \"".len();
        tampered.replace_range(digest..digest + 64, &sha256_hex(jar));
    }
    if let Some(id) = id {
        let ids = "repo_ids = \"\"\"\n";
        assert!(tampered.contains(ids), "{tampered}");
        tampered = tampered.replacen(ids, &format!("{ids}{url}\t{id}\n"), 1);
    }
    assert_ne!(tampered, lock);
    tampered
}

/// A plugin row raeva.lock alone moves to an origin no configuration or
/// POM names, with or without an id, makes no request there: `--frozen`
/// refuses the lock, and a plain sync resolves the plugins again and writes
/// the lock it had, or, when the edit pins other bytes too, refuses those
/// as it refuses a republished file. A transitive repository policy that
/// admits any URL does not change that.
#[test]
fn a_recorded_repository_gains_nothing_by_being_recorded() {
    let ours = org_repository(JAR);
    let (project, home) = org_project(&ours, "[security]\nallow_transitive_repositories = true\n");
    let root = project.path();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for (id, jar) in [
        (Some("gh"), None),
        (None, None),
        (Some("gh"), Some(OTHER_JAR)),
    ] {
        let theirs = org_repository(jar.unwrap_or(JAR));
        let url = format!("http://{}/attacker-org/", theirs.addr());
        fs::write(root.join("raeva.lock"), tampered(&lock, &url, id, jar)).unwrap();
        let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
        assert_status(&frozen, 7, "frozen sync of the edited lock");
        let plain = run_raeva(root, home.path(), &["sync"]);
        let requests: Vec<_> = (theirs.requests().into_iter())
            .map(|request| request.path)
            .collect();
        let repinned = jar.is_some();
        assert!(requests.is_empty(), "{id:?} {repinned}: {requests:?}");
        if repinned {
            assert_status(&plain, 7, "sync of the edited lock and pin");
            assert!(
                stderr(&plain).contains("(the raeva.lock pin)"),
                "{}",
                stderr(&plain)
            );
            continue;
        }
        assert_success(&plain, "sync of the edited lock");
        let written = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(written == lock, "{id:?}: {written}");
    }
}

/// A plugin row raeva.lock alone moves to another path of the configured
/// origin gets no request there, so neither the credential of the id it
/// records nor an `[[auth]]` entry without an id reaches that path.
#[test]
fn a_lock_only_path_on_a_configured_origin_gets_no_credential() {
    let default_auth = format!("[[auth]]\nusername = \"alice\"\npassword = \"{FAKE_PASSWORD}\"\n");
    for (config, id) in [("", Some("gh")), (default_auth.as_str(), None)] {
        let server = org_repository(JAR);
        let (project, home) = org_project(&server, config);
        let root = project.path();
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        let url = format!("http://{}/attacker-org/", server.addr());
        fs::write(root.join("raeva.lock"), tampered(&lock, &url, id, None)).unwrap();
        let plain = run_raeva(root, home.path(), &["sync"]);
        let other: Vec<_> = (server.requests().into_iter())
            .filter(|request| !request.path.starts_with("/our-org/"))
            .map(|request| {
                (
                    request.path.clone(),
                    request.header("authorization").is_some(),
                )
            })
            .collect();
        assert!(other.is_empty(), "{id:?}: {other:?}");
        assert_success(&plain, "sync of the edited lock");
        let written = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(written == lock, "{id:?}: {written}");
    }
}

/// A sync that resolves the dependencies again, here because raeva.lock
/// moves a dependency row to an origin nothing names too, keeps no plugin
/// row the edit moved there either, and makes no request there.
#[test]
fn a_resolving_sync_keeps_no_plugin_row_only_the_lock_names() {
    let ours = org_repository(JAR);
    let theirs = org_repository(JAR);
    let (project, home) = org_project(&ours, "[security]\nallow_transitive_repositories = true\n");
    let root = project.path();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
         <version>1</version></dependency></dependencies><build>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let url = format!("http://{}/attacker-org/", theirs.addr());
    let edit = tampered(&lock, &url, Some("gh"), None);
    let at = edit.find("artifact = \"lib\"").expect("the dependency row");
    let row = edit[..at].rfind("repo_url = \"").unwrap();
    let end = row + edit[row..].find('\n').unwrap();
    let edit = format!("{}repo_url = \"{url}\"{}", &edit[..row], &edit[end..]);
    fs::write(root.join("raeva.lock"), edit).unwrap();
    let plain = run_raeva(root, home.path(), &["sync"]);
    let requests: Vec<_> = (theirs.requests().into_iter())
        .map(|request| request.path)
        .collect();
    assert!(requests.is_empty(), "{requests:?}");
    assert_success(&plain, "sync of the edited lock");
    let written = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(written == lock, "{written}");
}

/// A traced row raeva.lock alone moves to an origin nothing names makes no
/// request there: `--frozen` refuses it, and a plain sync drops the trace
/// and traces the build again.
#[cfg(unix)]
#[test]
fn a_traced_row_only_the_lock_names_is_fetched_from_nowhere() {
    let ours = org_repository(JAR);
    let theirs = org_repository(JAR);
    let (project, home) = org_project(&ours, "[security]\nallow_transitive_repositories = true\n");
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "traced sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("role = \"trace\""), "{lock}");
    let url = format!("http://{}/attacker-org/", theirs.addr());
    let at = lock.find("artifact = \"tool\"").expect("the traced row");
    let row = lock[..at].rfind("repo_url = \"").unwrap();
    let end = row + lock[row..].find('\n').unwrap();
    let edit = format!("{}repo_url = \"{url}\"{}", &lock[..row], &lock[end..]);
    let ids = "repo_ids = \"\"\"\n";
    let edit = match edit.contains(ids) {
        true => edit.replacen(ids, &format!("{ids}{url}\tgh\n"), 1),
        false => edit,
    };
    let requests = || -> Vec<String> {
        (theirs.requests().into_iter())
            .map(|request| request.path)
            .collect()
    };
    for args in [&["sync", "--frozen"][..], &["sync"]] {
        let blob = home.path().join("store");
        if blob.exists() {
            fs::remove_dir_all(&blob).unwrap();
        }
        fs::write(root.join("raeva.lock"), &edit).unwrap();
        let synced = run_raeva(root, home.path(), args);
        assert!(requests().is_empty(), "{args:?}: {:?}", requests());
        match args.len() {
            2 => {
                assert_status(&synced, 7, "frozen sync of the edited lock");
                let said = stderr(&synced);
                assert!(said.contains("names the plugin repository"), "{said}");
            }
            _ => assert_success(&synced, "sync of the edited lock"),
        }
    }
    let written = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(written == lock, "{written}");
}

/// A project whose remote parent `t:corp:1` declares the plugin repository
/// `/our-org/` of `plugins`, with a home that mirrors Central to `/our-org/`
/// of a server that holds that parent and what [`repository`] serves.
fn remote_parent_project(plugins: &StubServer) -> (TempDir, TempDir, StubServer) {
    let corp = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>corp</artifactId><version>1</version><packaging>pom</packaging>\
         <pluginRepositories><pluginRepository><id>corp-plugins</id>\
         <url>http://{}/our-org/</url></pluginRepository></pluginRepositories></project>",
        plugins.addr()
    );
    let ours = StubServer::start(move |request| match request.path.as_str() {
        "/our-org/t/corp/1/corp-1.pom" => Response::new(200, corp.clone()),
        "/our-org/t/corp/1/corp-1.pom.sha256" => Response::new(200, sha256_hex(corp.as_bytes())),
        path => match path.strip_prefix("/our-org") {
            Some(rest) => {
                let mut inner = request.clone();
                inner.path = rest.to_string();
                serve(&inner, None, |_| (JAR, true), |_| false)
            }
            None => Response::new(404, ""),
        },
    });
    let (project, home) = org_project(&ours, "[security]\nallow_transitive_repositories = true\n");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<packaging>pom</packaging>",
        "<parent><groupId>t</groupId><artifactId>corp</artifactId><version>1</version>\
         <relativePath/></parent><packaging>pom</packaging>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    (project, home, ours)
}

/// Plugin rows from a plugin repository only a remote parent declares are
/// resolved again by each sync, which the configuration and the project's
/// own POMs cannot vouch for, and the sync that finds them as they were
/// says raeva.lock is up to date and leaves it as it is.
#[test]
fn a_remote_parent_plugin_repository_keeps_the_lock_as_it_is() {
    let plugins = org_repository(JAR);
    let (project, home, _ours) = remote_parent_project(&plugins);
    let root = project.path();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let origin = format!("http://{}/our-org/", plugins.addr());
    assert!(lock.contains(&format!("repo_url = \"{origin}\"")), "{lock}");
    let again = run_raeva(root, home.path(), &["sync"]);
    assert_success(&again, "sync again");
    for said in ["Resolving plugins", "raeva.lock is up to date"] {
        assert!(stderr(&again).contains(said), "{said}: {}", stderr(&again));
    }
    assert!(fs::read_to_string(root.join("raeva.lock")).unwrap() == lock);
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--frozen"]),
        "frozen sync",
    );
}

/// A trace finds what the build fetched in a plugin repository only a
/// remote parent declares, which the resolution of the plugins reads.
#[cfg(unix)]
#[test]
fn a_trace_finds_its_files_in_a_remote_parent_plugin_repository() {
    let plugins = org_repository(JAR);
    let (project, home, _ours) = remote_parent_project(&plugins);
    let root = project.path();
    fake_mvnw(root);
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "traced sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let at = lock.find("artifact = \"tool\"").expect("the traced row");
    let row = &lock[lock[..at].rfind("repo_url = \"").unwrap()..at];
    let origin = format!("http://{}/our-org/", plugins.addr());
    assert!(row.contains(&origin), "{lock}");
}

/// A trace of the host's platform, which a partial sync leaves out, finds
/// what the build fetched in a plugin repository the project's POM
/// declares.
#[cfg(unix)]
#[test]
fn a_trace_of_a_platform_left_out_finds_its_files_in_a_pom_plugin_repository() {
    let central = org_repository(JAR);
    let plugins = org_repository(JAR);
    let (project, home) = org_project(&central, "");
    let root = project.path();
    fake_mvnw(root);
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    let origin = format!("http://{}/our-org/", plugins.addr());
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        &format!(
            "<pluginRepositories><pluginRepository><id>tools</id><url>{origin}</url>\
             </pluginRepository></pluginRepositories><build>"
        ),
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let host = rv_lock::Platform::current().unwrap().os_arch();
    let other = match host.as_str() {
        "linux-x86_64" => "macos-aarch64",
        _ => "linux-x86_64",
    };
    let both = format!("{host},{other}");
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--platforms", &both]),
        "sync",
    );
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let partial = run_raeva(root, home.path(), &["sync", "--platforms", other]);
    assert_success(&partial, "partial traced sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let at = lock.find("artifact = \"tool\"").expect("the traced row");
    let row = &lock[lock[..at].rfind("repo_url = \"").unwrap()..at];
    assert!(row.contains(&origin), "{lock}");
}

/// A remote parent's plugin repository that serves none of the plugin rows,
/// as Apache's parent POM names its snapshot repository, leaves a plain
/// sync reusing raeva.lock without resolving the plugins again.
#[test]
fn a_plugin_repository_that_serves_no_row_keeps_the_lock_reused() {
    let empty = StubServer::start(|_| Response::new(404, ""));
    let (project, home, _ours) = remote_parent_project(&empty);
    let root = project.path();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let listed = format!("http://{}/our-org/", empty.addr());
    assert!(lock.contains(&listed), "{lock}");
    let again = run_raeva(root, home.path(), &["sync"]);
    assert_success(&again, "sync again");
    let said = stderr(&again);
    assert!(!said.contains("Resolving plugins"), "{said}");
    assert!(said.contains("raeva.lock is up to date"), "{said}");
}

/// A trace of the host's platform, which a partial sync leaves out, whose
/// plugins resolve from a repository only a remote parent declares is not
/// recorded: without that platform's model nothing checks the repository,
/// and the trace could take another one for a file.
#[cfg(unix)]
#[test]
fn a_trace_of_a_platform_left_out_records_nothing_it_cannot_check() {
    let plugins = org_repository(JAR);
    let (project, home, _ours) = remote_parent_project(&plugins);
    let root = project.path();
    fake_mvnw(root);
    let host = rv_lock::Platform::current().unwrap().os_arch();
    let other = match host.as_str() {
        "linux-x86_64" => "macos-aarch64",
        _ => "linux-x86_64",
    };
    let both = format!("{host},{other}");
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--platforms", &both]),
        "sync",
    );
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let partial = run_raeva(root, home.path(), &["sync", "--platforms", other]);
    assert_success(&partial, "partial traced sync");
    let said = stderr(&partial);
    assert!(said.contains("has no trace of platform"), "{said}");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(!lock.contains("artifact = \"tool\""), "{lock}");
}

/// A plugin's parent that a remote repository filter keeps from the one
/// plugin repository that serves it fails the plugin pass, as in Maven, and
/// the error names the filter for that repository.
#[test]
fn a_plugin_parent_the_filter_keeps_out_names_the_filter() {
    let server = StubServer::start(|request| {
        let plugin = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>u</groupId>\
            <artifactId>plugin-parent</artifactId><version>1</version></parent>\
            <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
            <packaging>maven-plugin</packaging></project>";
        let body = match request.path.trim_end_matches(".sha256") {
            "/t/demo-maven-plugin/1/demo-maven-plugin-1.pom" => plugin,
            _ => return serve(request, None, |_| (JAR, true), |_| false),
        };
        match request.path.ends_with(".sha256") {
            true => Response::new(200, sha256_hex(body.as_bytes())),
            false => Response::new(200, body),
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::create_dir_all(root.join(".mvn/rrf")).unwrap();
    fs::write(
        root.join(".mvn/maven.config"),
        "-Daether.remoteRepositoryFilter.groupId=true\n\
         -Daether.remoteRepositoryFilter.groupId.basedir=${session.rootDirectory}/.mvn/rrf/\n",
    )
    .unwrap();
    fs::write(
        root.join(".mvn/rrf/groupId-corp-plugins.txt"),
        "t\norg.apache.maven.plugins\n",
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><profiles><profile><id>corp</id><pluginRepositories><pluginRepository>\
             <id>corp-plugins</id><url>{url}</url></pluginRepository></pluginRepositories>\
             </profile></profiles><activeProfiles><activeProfile>corp</activeProfile>\
             </activeProfiles></settings>"
        ),
    )
    .unwrap();
    let sync = (raeva_command(root, home.path()))
        .args(["--json", "sync"])
        .output()
        .expect("run raeva");
    let envelope = crate::common::envelope(&sync);
    let error = envelope["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("Parent POM not found: u:plugin-parent:1")
            && error.contains(&format!(
                "{url} (not allowed by the remote repository filters)"
            ))
            && !error.contains("None of the repositories the plugin pass searched"),
        "{envelope}"
    );
    assert!(
        envelope["hints"]
            .to_string()
            .contains("aether.remoteRepositoryFilter"),
        "{envelope}"
    );
    assert!(
        !(server.requests().iter()).any(|request| request.path.starts_with("/u/")),
        "{:?}",
        server.requests()
    );
}

/// Behind a `<mirrorOf>*</mirrorOf>` mirror the plugin rows record the
/// first repository searched, a POM's that lacks the files, as the
/// dependencies' rows do. Without that mirror the files come from Central:
/// `--frozen` accepts the lock, whose pins agree, and a plain sync on
/// another machine fetches them past the repository that lacks them, for
/// the export to write. The plugin's dependencies are a row the module
/// uses too and one the core extension reads from Central alone, its
/// parent POM is a support POM, and the goal names it by a prefix.
#[test]
fn a_lock_written_behind_a_star_mirror_holds_without_it() {
    let server = StubServer::start(|request| {
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            let parts: Vec<&str> = path.split('/').collect();
            let [group @ .., artifact, version, file] = parts.as_slice() else {
                return (path == "t/maven-metadata.xml").then(|| {
                    b"<metadata><plugins><plugin><prefix>demo</prefix>\
                      <artifactId>demo-maven-plugin</artifactId></plugin></plugins></metadata>"
                        .to_vec()
                });
            };
            let body = match *artifact {
                "demo-maven-plugin" => {
                    "<parent><groupId>t</groupId><artifactId>parent\
                                        </artifactId><version>1</version></parent>\
                                        <packaging>maven-plugin</packaging>"
                }
                "parent" => "<packaging>pom</packaging>",
                _ => "",
            };
            if *file == format!("{artifact}-{version}.pom") {
                let group = group.join(".");
                Some(
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><groupId>{group}</groupId>\
                         <artifactId>{artifact}</artifactId><version>{version}</version>\
                         {body}</project>"
                    )
                    .into_bytes(),
                )
            } else {
                (*file == format!("{artifact}-{version}.jar")).then(|| JAR.to_vec())
            }
        })
    });
    let empty = StubServer::start(|_| Response::new(404, ""));
    let first = format!("http://{}/", empty.addr());
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    let settings = |home: &std::path::Path, mirror_of: &str| {
        fs::create_dir_all(home.join(".m2")).unwrap();
        fs::write(
            home.join(".m2/settings.xml"),
            format!(
                "<settings><pluginGroups><pluginGroup>t</pluginGroup></pluginGroups><mirrors>\
                 <mirror><id>stub</id><url>http://{}/</url><mirrorOf>{mirror_of}</mirrorOf>\
                 </mirror></mirrors></settings>",
                server.addr()
            ),
        )
        .unwrap();
    };
    settings(home.path(), "*");
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ngoals = ['demo:run']\n",
    )
    .unwrap();
    let declared = format!(
        "<repositories><repository><id>first</id><url>{first}</url></repository>\
         </repositories><pluginRepositories><pluginRepository><id>first</id>\
         <url>{first}</url></pluginRepository></pluginRepositories>\
         <dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
         <version>1</version></dependency></dependencies><build>"
    );
    let pom = (fs::read_to_string(root.join("pom.xml")).unwrap())
        .replace("<build>", &declared)
        .replace(
            "<executions>",
            "<dependencies><dependency><groupId>t</groupId><artifactId>ext</artifactId>\
             <version>2</version></dependency><dependency><groupId>t</groupId>\
             <artifactId>lib</artifactId><version>1</version></dependency></dependencies>\
             <executions>",
        );
    fs::write(root.join("pom.xml"), pom).unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync behind *");
    let lock_path = root.join("raeva.lock");
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(lock.contains(&format!("repo_url = \"{first}\"")), "{lock}");
    assert!(lock.contains("t:parent:1"), "{lock}");
    let prefix = format!("t\\tdemo\\tdemo-maven-plugin\\t{first}");
    assert!(lock.contains(&prefix), "{lock}");
    for frozen in [true, false] {
        let other = TempDir::new().unwrap();
        settings(other.path(), "central");
        let args: &[&str] = if frozen {
            &["sync", "--frozen"]
        } else {
            &["sync"]
        };
        let output = run_raeva(root, other.path(), args);
        assert_success(&output, &format!("{args:?} without the * mirror"));
        assert!(fs::read_to_string(&lock_path).unwrap() == lock, "{args:?}");
        let m2 = other.path().join("m2");
        let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
        assert_success(&run_raeva(root, other.path(), &export), "export");
        for file in [
            "t/demo-maven-plugin/1/demo-maven-plugin-1.jar",
            "t/ext/2/ext-2.jar",
            "t/lib/1/lib-1.jar",
        ] {
            assert_eq!(fs::read(m2.join(file)).unwrap(), JAR, "{args:?} {file}");
        }
    }
}

/// Publish `t:<artifact>:1` to the directory `repo` of `root`: its jar,
/// and its POM with `body` unless `body` is `None`, with their sidecars.
fn publish_to(root: &std::path::Path, repo: &str, artifact: &str, body: Option<&str>) {
    let dir = root.join(format!("{repo}/t/{artifact}/1"));
    fs::create_dir_all(&dir).unwrap();
    write_with_sha256(&dir.join(format!("{artifact}-1.jar")), JAR);
    if let Some(body) = body {
        let pom = pom(artifact, body);
        write_with_sha256(&dir.join(format!("{artifact}-1.pom")), pom.as_bytes());
    }
}

/// The `_remote.repositories` lines of `t:<artifact>:1` in `m2`.
fn remote_lines(m2: &std::path::Path, artifact: &str) -> Vec<String> {
    let markers = m2.join(format!("t/{artifact}/1/_remote.repositories"));
    (fs::read_to_string(markers).unwrap().lines())
        .filter(|line| !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// A repository that serves what [`repository`] serves but the group `t`.
fn central() -> StubServer {
    StubServer::start(|request| match request.path.starts_with("/t/") {
        true => Response::new(404, ""),
        false => serve(request, None, |_| (JAR, true), |_| false),
    })
}

/// A plugin `<dependency>` on `t:shared:1`.
const SHARED: &str = "<dependencies><dependency><groupId>t</groupId><artifactId>shared\
                      </artifactId><version>1</version></dependency></dependencies>";

/// One jar two plugins read, with its POM from the repository of one and
/// without from the other's, which lacks it: Maven builds both, the POM's
/// dependency only for the plugin whose repository has the POM. The lock
/// pins the POM with the origin that served it, `--frozen` holds it, and
/// the export labels the jar with both ids and the POM with that one. As
/// Maven 3.10 reads it: the 3.9 mode refuses it.
#[test]
fn a_pom_one_plugin_repository_lacks_is_pinned_from_the_other() {
    let server = central();
    let (project, home) = binding_project(&format!("http://{}/", server.addr()), "unused");
    let root = project.path();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n",
    )
    .unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let plugin = format!("<packaging>maven-plugin</packaging>{SHARED}");
    publish_to(root, "A", "one-maven-plugin", Some(&plugin));
    publish_to(root, "B", "two-maven-plugin", Some(&plugin));
    let needs = "<dependencies><dependency><groupId>t</groupId><artifactId>needed</artifactId>\
                 <version>1</version></dependency></dependencies>";
    publish_to(root, "A", "shared", Some(needs));
    publish_to(root, "A", "needed", Some(""));
    publish_to(root, "B", "shared", None);
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
        ),
    )
    .unwrap();
    for (module, repo, plugin) in [("a", "A", "one"), ("b", "B", "two")] {
        fs::create_dir_all(root.join(module)).unwrap();
        let url = format!("file://{}/{repo}/", root.display());
        fs::write(
            root.join(format!("{module}/pom.xml")),
            pom(
                module,
                &format!(
                    "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                     <id>{repo}</id><url>{url}</url></pluginRepository></pluginRepositories>\
                     <build><plugins><plugin><groupId>t</groupId>\
                     <artifactId>{plugin}-maven-plugin</artifactId><version>1</version>\
                     <executions><execution><phase>validate</phase><goals><goal>run</goal>\
                     </goals></execution></executions></plugin></plugins></build>"
                ),
            ),
        )
        .unwrap();
    }
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    assert_success(&raeva(&["sync"]), "second sync");
    assert!(fs::read_to_string(root.join("raeva.lock")).unwrap() == lock);
    let m2 = home.path().join("m2");
    let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
    assert_success(&raeva(&export), "export");
    let mut lines = remote_lines(&m2, "shared");
    lines.sort();
    assert_eq!(
        lines,
        ["shared-1.jar>A=", "shared-1.jar>B=", "shared-1.pom>A="],
        "{lock}"
    );
}

/// Codex's item 4: the module reads `t:shared:1` with its POM, whose
/// parent in `dep` adds `t:needed:1`; the plugin reads the same jar from
/// `plug`, which serves no POM for it. Maven 3.10.0 builds it, the plugin
/// without `needed`: the lock records `plug` as a shared origin without
/// the POM, `--frozen` holds it, and the export labels the POM with `dep`
/// alone, as `mvn -o` then builds it. The 3.9 mode refuses it.
#[test]
fn a_plugin_reads_a_module_file_without_its_pom() {
    for maven in ["3.10", "3.9"] {
        let server = central();
        let (project, home) = binding_project(&format!("http://{}/", server.addr()), "unused");
        let root = project.path();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
                 <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
                server.addr()
            ),
        )
        .unwrap();
        let needs = "<dependencies><dependency><groupId>t</groupId>\
                     <artifactId>needed</artifactId><version>1</version></dependency>\
                     </dependencies>";
        publish_to(
            root,
            "dep",
            "parent",
            Some(&format!("<packaging>pom</packaging>{needs}")),
        );
        let parent = "<parent><groupId>t</groupId><artifactId>parent</artifactId>\
                      <version>1</version></parent>";
        publish_to(root, "dep", "shared", Some(parent));
        publish_to(root, "dep", "needed", Some(""));
        let plugin = format!("<packaging>maven-plugin</packaging>{SHARED}");
        publish_to(root, "plug", "one-maven-plugin", Some(&plugin));
        publish_to(root, "plug", "shared", None);
        publish_to(root, "plug", "needed", Some(""));
        let url = |repo: &str| format!("file://{}/{repo}/", root.display());
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<repositories><repository><id>dep</id><url>{}</url></repository>\
                     </repositories><pluginRepositories><pluginRepository><id>plug</id>\
                     <url>{}</url></pluginRepository></pluginRepositories><dependencies>\
                     <dependency><groupId>t</groupId><artifactId>shared</artifactId>\
                     <version>1</version></dependency></dependencies><build><plugins><plugin>\
                     <groupId>t</groupId><artifactId>one-maven-plugin</artifactId>\
                     <version>1</version><executions><execution><phase>validate</phase>\
                     <goals><goal>run</goal></goals></execution></executions></plugin>\
                     </plugins></build>",
                    url("dep"),
                    url("plug")
                ),
            ),
        )
        .unwrap();
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{maven}\"\n\n[plugins]\nlock = true\n"),
        )
        .unwrap();
        let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
        if maven == "3.9" {
            let output = raeva(&["--json", "sync"]);
            assert_status(&output, 5, maven);
            let text = crate::common::envelope(&output).to_string();
            assert!(text.contains("has a different POM, or none"), "{text}");
            continue;
        }
        assert_success(&raeva(&["sync"]), maven);
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(
            lock.contains("shared_without_pom = \"t:shared:1\\tjar\\t./plug/\""),
            "{lock}"
        );
        assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
        assert_success(&raeva(&["sync"]), "second sync");
        assert!(fs::read_to_string(root.join("raeva.lock")).unwrap() == lock);
        let m2 = home.path().join("m2");
        let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
        assert_success(&raeva(&export), "export");
        let mut lines = remote_lines(&m2, "shared");
        lines.sort();
        assert_eq!(
            lines,
            [
                "shared-1.jar>dep=",
                "shared-1.jar>plug=",
                "shared-1.pom>dep="
            ],
            "{lock}"
        );
        let mut lines = remote_lines(&m2, "needed");
        lines.sort();
        assert_eq!(lines, ["needed-1.jar>dep=", "needed-1.pom>dep="], "{lock}");
        // Without the record, the export would label the POM for the plugin.
        let edited: String = (lock.lines())
            .filter(|line| !line.starts_with("shared_without_pom = "))
            .map(|line| format!("{line}\n"))
            .collect();
        fs::write(root.join("raeva.lock"), edited).unwrap();
        assert_status(
            &raeva(&["sync", "--frozen"]),
            7,
            "frozen without the record",
        );
    }
}

/// agy's MF-06 with a plugin: on windows a profile adds `B`, which serves
/// `t:shared:1` with a POM that adds `t:needed:1`; on linux `A` serves
/// the jar alone, and the linux row takes the POM windows read. The
/// plugin reads the jar from `plug` without a POM beside that row: refused
/// (exit 5).
#[test]
fn a_plugin_beside_a_pom_another_platform_read_is_refused() {
    let server = central();
    let (project, home) = binding_project(&format!("http://{}/", server.addr()), "unused");
    let root = project.path();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let needs = "<dependencies><dependency><groupId>t</groupId><artifactId>needed</artifactId>\
                 <version>1</version></dependency></dependencies>";
    publish_to(root, "A", "shared", None);
    publish_to(root, "B", "shared", Some(needs));
    publish_to(root, "B", "needed", Some(""));
    let plugin = format!("<packaging>maven-plugin</packaging>{SHARED}");
    publish_to(root, "plug", "one-maven-plugin", Some(&plugin));
    publish_to(root, "plug", "shared", None);
    publish_to(root, "plug", "needed", Some(""));
    let url = |repo: &str| format!("file://{}/{repo}/", root.display());
    let profile = |family: &str, repo: &str| {
        format!(
            "<profile><id>{repo}</id><activation><os><family>{family}</family></os>\
             </activation><repositories><repository><id>{repo}</id><url>{}</url>\
             </repository></repositories></profile>",
            url(repo)
        )
    };
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<pluginRepositories><pluginRepository><id>plug</id><url>{}</url>\
                 </pluginRepository></pluginRepositories>{SHARED}<build><plugins><plugin>\
                 <groupId>t</groupId><artifactId>one-maven-plugin</artifactId>\
                 <version>1</version><executions><execution><phase>validate</phase>\
                 <goals><goal>run</goal></goals></execution></executions></plugin>\
                 </plugins></build><profiles>{}{}</profiles>",
                url("plug"),
                profile("unix", "A"),
                profile("windows", "B")
            ),
        ),
    )
    .unwrap();
    let both = [
        "--json",
        "sync",
        "--platforms",
        "linux-x86_64,windows-x86_64",
    ];
    let output = run_raeva(root, home.path(), &both);
    assert_status(&output, 5, "sync");
    let text = crate::common::envelope(&output).to_string();
    assert!(text.contains("has a different POM, or none"), "{text}");
    assert!(!root.join("raeva.lock").exists());
}

/// `t:<artifact>:<version>` in `root/<repo>`, with a POM of `body` when
/// there is one.
fn publish_version(
    root: &std::path::Path,
    repo: &str,
    artifact: &str,
    version: &str,
    body: Option<&str>,
) {
    let dir = root.join(format!("{repo}/t/{artifact}/{version}"));
    fs::create_dir_all(&dir).unwrap();
    write_with_sha256(&dir.join(format!("{artifact}-{version}.jar")), JAR);
    if let Some(body) = body {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        );
        write_with_sha256(
            &dir.join(format!("{artifact}-{version}.pom")),
            pom.as_bytes(),
        );
    }
}

/// `<dependency>` elements on `t:<artifact>:<version>`, each given as
/// `artifact:version`.
fn t_dependencies(dependencies: &[&str]) -> String {
    let each: String = (dependencies.iter())
        .map(|dependency| {
            let (artifact, version) = dependency.split_once(':').unwrap();
            format!(
                "<dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
                 <version>{version}</version></dependency>"
            )
        })
        .collect();
    format!("<dependencies>{each}</dependencies>")
}

/// A project whose modules resolve from `dep` with `dependencies`, and
/// whose plugin `t:one-maven-plugin:1`, bound at `validate` and declaring
/// `plugin`, resolves from `plug`. Raeva resolves as Maven 3.9.
fn borrowing_project(dependencies: &str, plugin: &str) -> (StubServer, TempDir, TempDir) {
    let server = central();
    let (project, home) = binding_project(&format!("http://{}/", server.addr()), "unused");
    let root = project.path();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let body = format!("<packaging>maven-plugin</packaging>{plugin}");
    publish_to(root, "plug", "one-maven-plugin", Some(&body));
    let url = |repo: &str| format!("file://{}/{repo}/", root.display());
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<repositories><repository><id>dep</id><url>{}</url></repository>\
                 </repositories><pluginRepositories><pluginRepository><id>plug</id>\
                 <url>{}</url></pluginRepository></pluginRepositories>{dependencies}\
                 <build><plugins><plugin><groupId>t</groupId>\
                 <artifactId>one-maven-plugin</artifactId><version>1</version><executions>\
                 <execution><phase>validate</phase><goals><goal>run</goal></goals>\
                 </execution></executions></plugin></plugins></build>",
                url("dep"),
                url("plug")
            ),
        ),
    )
    .unwrap();
    (server, project, home)
}

/// As Maven 3.9 reads them, a file the modules read one way and a build
/// plugin, a build extension or a plugin with `<extensions>true</extensions>`
/// another, with or without a POM, an empty one too, as a row or as a BOM
/// or a losing version's POM, is refused (exit 5) by both names. Maven 3.9 keeps one
/// descriptor per file for the session, which the first to read it decides
/// for everyone, in the order of the build: a module collected after an
/// extension's realm takes the extension's reading, as a plugin run after
/// the modules takes theirs.
#[test]
fn a_file_the_modules_and_a_realm_read_two_ways_is_refused() {
    let shared = t_dependencies(&["shared:1"]);
    let extension = "<extensions><extension><groupId>t</groupId><artifactId>ext</artifactId>\
                     <version>1</version></extension></extensions>";
    let bom = "<dependencyManagement><dependencies><dependency><groupId>t</groupId>\
               <artifactId>shared</artifactId><version>1</version><type>pom</type>\
               <scope>import</scope></dependency></dependencies></dependencyManagement>";
    // (case, the modules' dependencies, the plugin's, what the build adds,
    // whether `dep` serves shared's POM and `plug` none, the realm named)
    let cases: [(&str, String, &str, &str, bool, &str); 7] = [
        (
            "plugin",
            shared.clone(),
            &shared,
            "",
            true,
            "plugin t:one-maven-plugin:1",
        ),
        (
            "empty POM",
            shared.clone(),
            &shared,
            "",
            true,
            "plugin t:one-maven-plugin:1",
        ),
        (
            "extension",
            shared.clone(),
            "",
            extension,
            true,
            "build-extension t:ext:1",
        ),
        (
            "extensions true",
            shared.clone(),
            &shared,
            "",
            true,
            "t:one-maven-plugin:1",
        ),
        (
            "plugin with the POM",
            shared.clone(),
            &shared,
            "",
            false,
            "plugin t:one-maven-plugin:1",
        ),
        (
            "BOM",
            format!("{bom}{}", t_dependencies(&["needed:1"])),
            &shared,
            "",
            true,
            "plugin",
        ),
        (
            "losing version",
            t_dependencies(&["shared:2", "helper:1"]),
            &shared,
            "",
            true,
            "plugin",
        ),
    ];
    for (case, dependencies, plugin, build, in_dep, realm) in cases {
        let (_server, project, home) = borrowing_project(&dependencies, plugin);
        let root = project.path();
        let needs = t_dependencies(&["needed:1"]);
        let (with, without) = match in_dep {
            true => ("dep", "plug"),
            false => ("plug", "dep"),
        };
        let packaging = match case {
            "BOM" => format!(
                "<packaging>pom</packaging><dependencyManagement>{needs}</dependencyManagement>"
            ),
            "empty POM" => String::new(),
            _ => needs,
        };
        publish_version(root, with, "shared", "1", Some(&packaging));
        publish_version(root, without, "shared", "1", None);
        publish_version(root, "dep", "shared", "2", Some(""));
        publish_version(root, "dep", "helper", "1", Some(&shared));
        for repo in ["dep", "plug"] {
            publish_version(root, repo, "needed", "1", Some(""));
        }
        publish_version(
            root,
            "plug",
            "ext",
            "1",
            Some(&format!("<packaging>jar</packaging>{shared}")),
        );
        let mut pom = fs::read_to_string(root.join("pom.xml"))
            .unwrap()
            .replace("<build>", &format!("<build>{build}"));
        if case == "extensions true" {
            pom = pom.replace(
                "<version>1</version><executions>",
                "<version>1</version><extensions>true</extensions><executions>",
            );
        }
        fs::write(root.join("pom.xml"), pom).unwrap();
        let output = run_raeva(root, home.path(), &["--json", "sync"]);
        assert_status(&output, 5, case);
        let text = crate::common::envelope(&output).to_string();
        assert!(
            text.contains("RESOLUTION")
                && text.contains("t:shared:1")
                && text.contains("has a different POM, or none, for module pom.xml")
                && text.contains(realm),
            "{case}: {text}"
        );
        assert!(!root.join("raeva.lock").exists(), "{case}");
    }
}

/// An extension `t:ext` that reads `t:shared:1` with its POM, which adds
/// `t:needed:1`, from the plugin repository `plugin_id` at `plug`, beside
/// the project's repository `repository_id` at `dep`, which serves the jar
/// without a POM; the module depends on `t:shared:1`. A core extension
/// takes its plugin repository from settings.xml, a build extension from
/// the POM. `toml` is raeva.toml.
fn split_id_project(
    core: bool,
    plugin_id: &str,
    repository_id: &str,
    toml: &str,
) -> (TempDir, TempDir, StubServer) {
    let server = central();
    let (project, home) = binding_project(&format!("http://{}/", server.addr()), "unused");
    let root = project.path();
    let url = |repo: &str| format!("file://{}/{repo}/", root.display());
    let plugin_repository = format!(
        "<pluginRepositories><pluginRepository><id>{plugin_id}</id><url>{}</url>\
         </pluginRepository></pluginRepositories>",
        url("plug")
    );
    let profile = match core {
        true => format!(
            "<profiles><profile><id>p</id>{plugin_repository}</profile></profiles>\
             <activeProfiles><activeProfile>p</activeProfile></activeProfiles>"
        ),
        false => String::new(),
    };
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors>{profile}</settings>",
            server.addr()
        ),
    )
    .unwrap();
    let needs = "<dependencies><dependency><groupId>t</groupId>\
                 <artifactId>needed</artifactId><version>1</version></dependency>\
                 </dependencies>";
    publish_to(root, "plug", "ext", Some(SHARED));
    publish_to(root, "plug", "shared", Some(needs));
    publish_to(root, "plug", "needed", Some(""));
    publish_to(root, "dep", "shared", None);
    publish_to(root, "dep", "needed", Some(""));
    let extension = "<extension><groupId>t</groupId><artifactId>ext</artifactId>\
                     <version>1</version></extension>";
    let build = match core {
        true => {
            fs::create_dir_all(root.join(".mvn")).unwrap();
            fs::write(
                root.join(".mvn/extensions.xml"),
                format!("<extensions>{extension}</extensions>"),
            )
            .unwrap();
            String::new()
        }
        false => format!("{plugin_repository}<build><extensions>{extension}</extensions></build>"),
    };
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><repositories><repository><id>{repository_id}</id>\
                 <url>{}</url></repository></repositories><dependencies><dependency>\
                 <groupId>t</groupId><artifactId>shared</artifactId><version>1</version>\
                 </dependency></dependencies>{build}",
                url("dep")
            ),
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), toml).unwrap();
    (project, home, server)
}

/// Wave 4 F1: an extension reads `t:shared:1` with its POM under the id
/// `plug`, and the module reads the jar from its own repository `plug`,
/// which serves no POM. Maven 3.10.0 gives the module the POM the extension
/// read, by the id, so `t:needed:1` too; the 3.10 mode refuses it (exit 5)
/// as two readings of one POM, for a build and a core extension.
#[test]
fn a_pom_an_extension_read_under_the_modules_repository_id_is_refused() {
    for core in [false, true] {
        let toml = "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n";
        let (project, home, _server) = split_id_project(core, "plug", "plug", toml);
        let sync = run_raeva(project.path(), home.path(), &["sync"]);
        assert_status(&sync, 5, &format!("core {core}"));
        assert!(
            stderr(&sync)
                .contains("t:shared:1:jar has one POM for module pom.xml and another, or none"),
            "{}",
            stderr(&sync)
        );
    }
}

/// The same without plugin tables, where raeva does not see what the
/// extension reads: Maven 3.9.12 and 3.10.0 both give the module
/// `t:needed:1`, as they do for a plugin of an earlier module, so sync
/// refuses the shared id (exit 3) in either mode. With an id of its own
/// the module's repository is no trigger.
#[test]
fn an_extension_beside_a_split_repository_id_is_refused_without_plugin_tables() {
    for (core, maven) in [(false, "3.9"), (true, "3.10")] {
        let toml = format!("[lock]\nmaven = \"{maven}\"\n");
        let (project, home, _server) = split_id_project(core, "plug", "plug", &toml);
        let sync = run_raeva(project.path(), home.path(), &["sync"]);
        assert_status(&sync, 3, maven);
        let text = stderr(&sync);
        assert!(
            text.contains("the repository id 'plug' names") && text.contains("[plugins] lock"),
            "{text}"
        );
        let (project, home, _server) = split_id_project(core, "plug", "dep", &toml);
        assert_success(&run_raeva(project.path(), home.path(), &["sync"]), maven);
    }
}

/// A release plugin whose parent is a SNAPSHOT build that the repository
/// serves only under its timestamped name: Maven builds it, and the lock
/// pins the parent with its build, which `--frozen` on an empty home and
/// the export fetch by that name.
#[test]
fn a_plugin_parent_pins_its_snapshot_build() {
    let central = central();
    let build = "1-20240101.120000-1";
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
        <artifactId>parent</artifactId><version>1-SNAPSHOT</version><packaging>pom</packaging>\
        </project>";
    let plugin = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
        <artifactId>parent</artifactId><version>1-SNAPSHOT</version></parent>\
        <artifactId>demo-maven-plugin</artifactId><version>1</version>\
        <packaging>maven-plugin</packaging></project>";
    let metadata = format!(
        "<metadata><groupId>t</groupId><artifactId>parent</artifactId>\
         <version>1-SNAPSHOT</version><versioning><snapshot><timestamp>20240101.120000\
         </timestamp><buildNumber>1</buildNumber></snapshot><lastUpdated>20240101120000\
         </lastUpdated><snapshotVersions><snapshotVersion><extension>pom</extension>\
         <value>{build}</value><updated>20240101120000</updated></snapshotVersion>\
         </snapshotVersions></versioning></metadata>"
    );
    let snapshots = sha256_repository([
        (
            "/t/parent/1-SNAPSHOT/maven-metadata.xml".to_string(),
            metadata.into_bytes(),
        ),
        (
            format!("/t/parent/1-SNAPSHOT/parent-{build}.pom"),
            parent.into(),
        ),
        (
            "/t/demo-maven-plugin/1/demo-maven-plugin-1.pom".to_string(),
            plugin.into(),
        ),
        (
            "/t/demo-maven-plugin/1/demo-maven-plugin-1.jar".to_string(),
            JAR.to_vec(),
        ),
    ]);
    let (project, home) =
        binding_project(&format!("http://{}/", central.addr()), "demo-maven-plugin");
    let root = project.path();
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        &format!(
            "<pluginRepositories><pluginRepository><id>snaps</id><url>http://{}/</url>\
             <snapshots><enabled>true</enabled></snapshots></pluginRepository>\
             </pluginRepositories><build>",
            snapshots.addr()
        ),
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    settings_with(
        home.path(),
        &format!(
            "<mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors>",
            central.addr()
        ),
    );
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let document: toml::Value = toml::from_str(&lock).unwrap();
    let parents: Vec<_> = (document["platforms"][0]["support_poms"]
        .as_array()
        .unwrap()
        .iter())
    .filter(|pom| pom["coordinate"].as_str() == Some("t:parent:1-SNAPSHOT"))
    .collect();
    assert_eq!(parents.len(), 1, "{lock}");
    assert_eq!(
        parents[0]["snapshot"]["timestamp"].as_str(),
        Some("20240101.120000"),
        "{lock}"
    );
    let empty = TempDir::new().unwrap();
    fs::create_dir_all(empty.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        empty.path().join(".m2/settings.xml"),
    )
    .unwrap();
    assert_success(
        &run_raeva(root, empty.path(), &["sync", "--frozen"]),
        "frozen sync on an empty home",
    );
    let m2 = empty.path().join("m2");
    let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
    assert_success(&run_raeva(root, empty.path(), &export), "export");
    assert_eq!(
        fs::read(m2.join(format!("t/parent/1-SNAPSHOT/parent-{build}.pom"))).unwrap(),
        parent.as_bytes()
    );
}

/// One plugin reads a jar from a repository without its POM, another the
/// tests jar of the same coordinate with the POM from its own: Maven
/// builds both, and its local repository holds the one POM, under the
/// repository that served it. The lock pins that POM for both files from
/// that repository, `--frozen` and a second sync keep it, and the export
/// labels the POM with that repository's id only.
/// As Maven 3.10 reads it: the Maven 3.9 mode refuses it, as one plugin reads the jar without a POM.
#[test]
fn a_pom_one_file_of_a_coordinate_lacks_is_pinned_from_another() {
    let server = central();
    let (project, home) = binding_project(&format!("http://{}/", server.addr()), "unused");
    let root = project.path();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n",
    )
    .unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let plugin = |dependency: &str| {
        format!(
            "<packaging>maven-plugin</packaging><dependencies><dependency><groupId>t\
             </groupId><artifactId>shared</artifactId><version>1</version>{dependency}\
             </dependency></dependencies>"
        )
    };
    publish_to(root, "A", "one-maven-plugin", Some(&plugin("")));
    publish_to(
        root,
        "B",
        "two-maven-plugin",
        Some(&plugin("<type>test-jar</type>")),
    );
    publish_to(root, "A", "shared", None);
    publish_to(root, "B", "shared", Some(""));
    fs::remove_file(root.join("B/t/shared/1/shared-1.jar")).unwrap();
    write_with_sha256(&root.join("B/t/shared/1/shared-1-tests.jar"), OTHER_JAR);
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
        ),
    )
    .unwrap();
    for (module, repo, plugin) in [("a", "A", "one"), ("b", "B", "two")] {
        fs::create_dir_all(root.join(module)).unwrap();
        let url = format!("file://{}/{repo}/", root.display());
        fs::write(
            root.join(format!("{module}/pom.xml")),
            pom(
                module,
                &format!(
                    "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                     <id>{repo}</id><url>{url}</url></pluginRepository></pluginRepositories>\
                     <build><plugins><plugin><groupId>t</groupId>\
                     <artifactId>{plugin}-maven-plugin</artifactId><version>1</version>\
                     <executions><execution><phase>validate</phase><goals><goal>run</goal>\
                     </goals></execution></executions></plugin></plugins></build>"
                ),
            ),
        )
        .unwrap();
    }
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    assert_success(&raeva(&["sync"]), "second sync");
    assert!(fs::read_to_string(root.join("raeva.lock")).unwrap() == lock);
    let m2 = home.path().join("m2");
    let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
    assert_success(&raeva(&export), "export");
    let lines = remote_lines(&m2, "shared");
    assert!(
        lines.contains(&"shared-1.pom>B=".to_string()),
        "{lines:?} {lock}"
    );
    assert!(
        !lines.contains(&"shared-1.pom>A=".to_string()),
        "{lines:?} {lock}"
    );
    assert!(
        lines.contains(&"shared-1.jar>A=".to_string()),
        "{lines:?} {lock}"
    );
}

/// A jar a dependency repository serves without its POM and a plugin's
/// with it: Maven reads the POM for the plugin. The lock pins it for the
/// plugin, leaving the dependency's row as the dependencies resolve it,
/// `--frozen` and a second sync keep the lock, and the export writes the
/// POM under the plugin repository's id. As Maven 3.10 reads it: the 3.9
/// mode refuses it.
#[test]
fn a_pom_a_dependency_repository_lacks_is_pinned_for_the_plugin() {
    let server = central();
    let (project, home) =
        binding_project(&format!("http://{}/", server.addr()), "one-maven-plugin");
    let root = project.path();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n",
    )
    .unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .unwrap();
    let plugin = format!("<packaging>maven-plugin</packaging>{SHARED}");
    publish_to(root, "A", "one-maven-plugin", Some(&plugin));
    publish_to(root, "A", "shared", Some(""));
    publish_to(root, "B", "shared", None);
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        &format!(
            "<repositories><repository><id>B</id><url>file://{0}/B/</url></repository>\
             </repositories><pluginRepositories><pluginRepository><id>A</id>\
             <url>file://{0}/A/</url></pluginRepository></pluginRepositories>{1}<build>",
            root.display(),
            SHARED
        ),
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    assert_success(&raeva(&["sync"]), "second sync");
    assert!(fs::read_to_string(root.join("raeva.lock")).unwrap() == lock);
    let m2 = home.path().join("m2");
    let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
    assert_success(&raeva(&export), "export");
    let mut lines = remote_lines(&m2, "shared");
    lines.sort();
    assert_eq!(
        lines,
        ["shared-1.jar>A=", "shared-1.jar>B=", "shared-1.pom>A="],
        "{lock}"
    );
}

/// A repository that lists `t:demo-maven-plugin` `version` as its only
/// release, with the version's POM and jar.
fn release_repository(version: &'static str) -> StubServer {
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
         <artifactId>demo-maven-plugin</artifactId><version>{version}</version>\
         <packaging>maven-plugin</packaging></project>"
    );
    let metadata = format!(
        "<metadata><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
         <versioning><release>{version}</release><versions><version>{version}</version>\
         </versions></versioning></metadata>"
    );
    let plugin = format!("t/demo-maven-plugin/{version}/demo-maven-plugin-{version}");
    sha256_repository([
        (
            "/t/demo-maven-plugin/maven-metadata.xml".to_string(),
            metadata.into_bytes(),
        ),
        (format!("/{plugin}.pom"), pom.into_bytes()),
        (format!("/{plugin}.jar"), JAR.to_vec()),
    ])
}

/// Two modules list the same plugin repositories, one with the second
/// turned off, and build a plugin without a version: Maven takes each
/// module's version from the repositories it enables, whatever the order
/// of the modules. The lock records each, `--frozen` holds them, and the
/// export, which writes one `<release>` for the plugin, refuses.
#[test]
fn a_plugin_without_a_version_takes_each_modules_repository_policy() {
    let central = central();
    let (one, two) = (release_repository("1"), release_repository("2"));
    for modules in [["a", "b"], ["b", "a"]] {
        let (project, home) =
            binding_project(&format!("http://{}/", central.addr()), "demo-maven-plugin");
        let root = project.path();
        settings_with(
            home.path(),
            &format!(
                "<mirrors><mirror><id>stub</id><url>http://{}/</url>\
                 <mirrorOf>central</mirrorOf></mirror></mirrors>",
                central.addr()
            ),
        );
        let listed: String = (modules.iter())
            .map(|module| format!("<module>{module}</module>"))
            .collect();
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                &format!("<packaging>pom</packaging><modules>{listed}</modules>"),
            ),
        )
        .unwrap();
        for (module, enabled) in [("a", false), ("b", true)] {
            fs::create_dir_all(root.join(module)).unwrap();
            fs::write(
                root.join(format!("{module}/pom.xml")),
                pom(
                    module,
                    &format!(
                        "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                         <id>one</id><url>http://{}/</url></pluginRepository>\
                         <pluginRepository><id>two</id><url>http://{}/</url><releases>\
                         <enabled>{enabled}</enabled></releases><snapshots><enabled>false\
                         </enabled></snapshots></pluginRepository>\
                         </pluginRepositories><build><plugins><plugin><groupId>t</groupId>\
                         <artifactId>demo-maven-plugin</artifactId><executions><execution>\
                         <phase>validate</phase><goals><goal>run</goal></goals></execution>\
                         </executions></plugin></plugins></build>",
                        one.addr(),
                        two.addr()
                    ),
                ),
            )
            .unwrap();
        }
        let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
        assert_success(&raeva(&["sync"]), "sync");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        let document: toml::Value = toml::from_str(&lock).unwrap();
        let sets = document["platforms"][0]["plugins"]["sets"]
            .as_array()
            .unwrap();
        let modules_of = |version: &str| {
            let coordinate = format!("t:demo-maven-plugin:{version}");
            (sets.iter())
                .find(|set| set["coordinates"][0].as_str() == Some(&coordinate))
                .map(|set| set["modules"].as_str().unwrap().trim().to_string())
        };
        assert_eq!(modules_of("1").as_deref(), Some("a/pom.xml"), "{lock}");
        assert_eq!(modules_of("2").as_deref(), Some("b/pom.xml"), "{lock}");
        assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
        let m2 = home.path().join("m2");
        let exported = raeva(&["export-m2", "--m2-path", m2.to_str().unwrap()]);
        assert_status(&exported, 3, "export of two releases");
        assert!(
            stderr(&exported).contains("raeva.lock records two release versions"),
            "{}",
            stderr(&exported)
        );
    }
}

/// Two modules list one plugin repository by the same id and URL, one
/// with it turned off, and run a plugin whose dependency is a range: each
/// module's plugin takes the range's versions from the repositories it
/// enables, whatever the order of the modules, as in Maven.
#[test]
fn a_plugin_set_keeps_each_modules_repository_policy() {
    let helper = |version: &str| {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>helper</artifactId><version>{version}</version></project>"
        );
        let metadata = format!(
            "<metadata><groupId>t</groupId><artifactId>helper</artifactId><versioning>\
             <versions><version>{version}</version></versions></versioning></metadata>"
        );
        let file = format!("/t/helper/{version}/helper-{version}");
        [
            (
                "/t/helper/maven-metadata.xml".to_string(),
                metadata.into_bytes(),
            ),
            (format!("{file}.pom"), pom.into_bytes()),
            (format!("{file}.jar"), JAR.to_vec()),
        ]
    };
    let plugin = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
        <artifactId>gen-maven-plugin</artifactId><version>1</version>\
        <packaging>maven-plugin</packaging><dependencies><dependency><groupId>t</groupId>\
        <artifactId>helper</artifactId><version>[1,3)</version></dependency></dependencies>\
        </project>";
    let mut files: std::collections::HashMap<String, Vec<u8>> = helper("1").into();
    files.insert(
        "/t/gen-maven-plugin/1/gen-maven-plugin-1.pom".into(),
        plugin.into(),
    );
    files.insert(
        "/t/gen-maven-plugin/1/gen-maven-plugin-1.jar".into(),
        JAR.to_vec(),
    );
    let central = StubServer::start(move |request| match request.path.starts_with("/t/") {
        true => serve_sha256(&request.path, |path| files.get(path)),
        false => serve(request, None, |_| (JAR, true), |_| false),
    });
    let shared = sha256_repository(helper("2"));
    for modules in [["a", "b"], ["b", "a"]] {
        let (project, home) =
            binding_project(&format!("http://{}/", central.addr()), "gen-maven-plugin");
        let root = project.path();
        settings_with(
            home.path(),
            &format!(
                "<mirrors><mirror><id>stub</id><url>http://{}/</url>\
                 <mirrorOf>central</mirrorOf></mirror></mirrors>",
                central.addr()
            ),
        );
        let listed: String = (modules.iter())
            .map(|module| format!("<module>{module}</module>"))
            .collect();
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                &format!("<packaging>pom</packaging><modules>{listed}</modules>"),
            ),
        )
        .unwrap();
        for (module, enabled) in [("a", false), ("b", true)] {
            fs::create_dir_all(root.join(module)).unwrap();
            fs::write(
                root.join(format!("{module}/pom.xml")),
                pom(
                    module,
                    &format!(
                        "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                         <id>shared</id><url>http://{}/</url><releases><enabled>{enabled}\
                         </enabled></releases></pluginRepository></pluginRepositories>\
                         <build><plugins><plugin><groupId>t</groupId>\
                         <artifactId>gen-maven-plugin</artifactId><version>1</version>\
                         <executions><execution><phase>validate</phase><goals>\
                         <goal>run</goal></goals></execution></executions></plugin>\
                         </plugins></build>",
                        shared.addr()
                    ),
                ),
            )
            .unwrap();
        }
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        let document: toml::Value = toml::from_str(&lock).unwrap();
        let sets = document["platforms"][0]["plugins"]["sets"]
            .as_array()
            .unwrap();
        let helper_of = |module: &str| {
            (sets.iter())
                .filter(|set| set["coordinates"][0].as_str() == Some("t:gen-maven-plugin:1"))
                .filter(|set| {
                    let modules = set["modules"].as_str().unwrap();
                    modules
                        .lines()
                        .any(|line| line == format!("{module}/pom.xml"))
                })
                .filter_map(|set| set["artifacts"].as_str())
                .flat_map(str::lines)
                .filter(|line| line.starts_with("t:helper:"))
                .collect::<Vec<_>>()
        };
        assert_eq!(helper_of("a"), ["t:helper:1\tjar"], "{modules:?} {lock}");
        assert_eq!(helper_of("b"), ["t:helper:2\tjar"], "{modules:?} {lock}");
        assert_success(
            &run_raeva(root, home.path(), &["sync", "--frozen"]),
            "frozen",
        );
    }
}

/// [`repository`] for the paths that start with `prefix`, serving a
/// sources jar for every jar too.
fn sources_repository(prefix: &'static str) -> StubServer {
    StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        if !path.starts_with(prefix) {
            return Response::new(404, "");
        }
        if path.trim_end_matches(".sha256").ends_with("-sources.jar") {
            return serve_sha256(path, |_| Some(JAR));
        }
        serve(request, None, |_| (JAR, true), |_| false)
    })
}

/// `export-m2 --with-sources` takes the sources of the plugin rows from the
/// repositories they came from, which the project declares: Maven's
/// `central` and a POM's `<pluginRepositories>`.
#[test]
fn an_export_takes_plugin_sources_from_the_plugin_repositories() {
    let (central, plugins) = (sources_repository(""), sources_repository("t/"));
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    settings_with(
        home.path(),
        &format!(
            "<mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors>",
            central.addr()
        ),
    );
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        &format!(
            "<pluginRepositories><pluginRepository><id>plugins</id><url>http://{}/</url>\
             </pluginRepository></pluginRepositories><build>",
            plugins.addr()
        ),
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let clean = "org.apache.maven.plugins:maven-clean-plugin:";
    let at = lock.find(clean).expect("the clean plugin");
    let version = lock[at + clean.len()..].split(['\\', '"']).next().unwrap();
    let m2 = home.path().join("m2");
    let export = [
        "export-m2",
        "--with-sources",
        "--m2-path",
        m2.to_str().unwrap(),
    ];
    let exported = raeva(&export);
    assert_success(&exported, "export with sources");
    assert!(
        !stderr(&exported).contains("UNTRUSTED_CLASSIFIER_ORIGIN"),
        "{}",
        stderr(&exported)
    );
    for file in [
        "t/demo-maven-plugin/1/demo-maven-plugin-1-sources.jar".to_string(),
        format!(
            "org/apache/maven/plugins/maven-clean-plugin/{version}/\
             maven-clean-plugin-{version}-sources.jar"
        ),
    ] {
        assert!(m2.join(&file).is_file(), "{file}: {}", stderr(&exported));
    }
}

/// Two modules each build a plugin from their own plugin repository, A
/// or B (with ids `ids`), both reading `t:shared:1` with its POM, which
/// the modules' repository D serves without one, as Maven 3.10 reads it:
/// the 3.9 mode refuses it.
fn two_plugin_repositories(ids: [&str; 2]) -> (StubServer, TempDir, TempDir) {
    let server = central();
    let (project, home) = binding_project(&format!("http://{}/", server.addr()), "unused");
    let root = project.path();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n",
    )
    .unwrap();
    settings_with(
        home.path(),
        &format!(
            "<mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors>",
            server.addr()
        ),
    );
    let plugin = format!("<packaging>maven-plugin</packaging>{SHARED}");
    publish_to(root, "A", "one-maven-plugin", Some(&plugin));
    publish_to(root, "B", "two-maven-plugin", Some(&plugin));
    publish_to(root, "A", "shared", Some(""));
    publish_to(root, "B", "shared", Some(""));
    publish_to(root, "D", "shared", None);
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
        ),
    )
    .unwrap();
    for (module, repo, id, plugin) in [("a", "A", ids[0], "one"), ("b", "B", ids[1], "two")] {
        fs::create_dir_all(root.join(module)).unwrap();
        fs::write(
            root.join(format!("{module}/pom.xml")),
            pom(
                module,
                &format!(
                    "<packaging>pom</packaging><repositories><repository><id>D</id>\
                     <url>file://{0}/D/</url></repository></repositories>\
                     <pluginRepositories><pluginRepository><id>{id}</id>\
                     <url>file://{0}/{repo}/</url></pluginRepository></pluginRepositories>\
                     {SHARED}<build><plugins><plugin><groupId>t</groupId>\
                     <artifactId>{plugin}-maven-plugin</artifactId><version>1</version>\
                     <executions><execution><phase>validate</phase><goals><goal>run</goal>\
                     </goals></execution></executions></plugin></plugins></build>",
                    root.display()
                ),
            ),
        )
        .unwrap();
    }
    (server, project, home)
}

/// A POM two plugins read from two repositories, neither of which both
/// search, for a jar the modules read without its POM, is refused: the
/// lock records one repository for such a POM, and `mvn -o` would read it
/// for the plugin that searches the other one only where Maven does not.
#[test]
fn a_pom_the_modules_lack_from_two_plugin_repositories_is_refused() {
    let (_server, project, home) = two_plugin_repositories(["A", "B"]);
    let sync = run_raeva(project.path(), home.path(), &["sync"]);
    assert_status(&sync, 5, "sync");
    assert!(
        stderr(&sync).contains("plugins read the POM of t:shared:1:jar from other repositories"),
        "{}",
        stderr(&sync)
    );
}

/// The same with one id for both plugin repositories: `mvn -o` takes the
/// POM under that id for both plugins, so the lock pins it once.
#[test]
fn a_pom_the_modules_lack_from_two_repositories_of_one_id_is_pinned() {
    let (_server, project, home) = two_plugin_repositories(["plugins", "plugins"]);
    let root = project.path();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    let m2 = home.path().join("m2");
    let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
    assert_success(&raeva(&export), "export");
    let mut lines = remote_lines(&m2, "shared");
    lines.sort();
    assert_eq!(
        lines,
        [
            "shared-1.jar>D=",
            "shared-1.jar>plugins=",
            "shared-1.pom>plugins="
        ]
    );
}

/// A traced file the modules use, which raeva.lock is edited to say the
/// build read from a repository nothing declares, fails `--frozen`, as
/// does an id the edit gives a repository it is not declared with: the
/// export would label the file with them, and `mvn -o` take it there.
#[cfg(unix)]
#[test]
fn a_trace_origin_or_id_an_edit_adds_fails_frozen() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        "<dependencies><dependency><groupId>t</groupId><artifactId>tool</artifactId>\
         <version>1</version></dependency></dependencies><build>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let traced = lock.replacen(
        "role = \"trace\"\n",
        "role = \"trace\"\nartifacts = \"t:tool:1\\tjar\"\n",
        1,
    );
    let origin = traced.replacen(
        "host_inputs = [\"user-property:ext.version\"]\n",
        "host_inputs = [\"user-property:ext.version\"]\n\
         shared_origins = \"t:tool:1\\tjar\\thttps://evil.example/maven2/\"\n",
        1,
    );
    let id = traced.replacen(
        "https://repo1.maven.org/maven2/\\tcentral\"\"\"",
        "https://repo1.maven.org/maven2/\\tcentral\nhttps://repo1.maven.org/maven2/\\tevil\"\"\"",
        1,
    );
    for (edited, what) in [(origin, "evil.example"), (id, "repository ids")] {
        assert_ne!(edited, traced, "{lock}");
        fs::write(root.join("raeva.lock"), &edited).unwrap();
        let frozen = raeva(&["sync", "--frozen"]);
        assert_status(&frozen, 7, what);
        assert!(stderr(&frozen).contains(what), "{}", stderr(&frozen));
        // A plain sync traces again rather than keep the edited trace, and
        // the next one keeps the lock it wrote without checking it.
        assert_success(&raeva(&["sync"]), what);
        let again = raeva(&["sync"]);
        assert_success(&again, what);
        assert!(
            !stderr(&again).contains("Checking plugins"),
            "{}",
            stderr(&again)
        );
        assert_success(&raeva(&["sync", "--frozen"]), what);
    }
}

/// A conflicted lock whose traces an edit gave an id their repository is
/// not declared with regenerates to a lock `--frozen` accepts once a plain
/// sync keeps it.
#[cfg(unix)]
#[test]
fn a_conflicted_lock_drops_a_trace_id_an_edit_adds() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fake_mvnw(root);
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replace(
        "<build>",
        "<dependencies><dependency><groupId>t</groupId><artifactId>tool</artifactId>\
         <version>1</version></dependency></dependencies><build>",
    );
    fs::write(root.join("pom.xml"), pom).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let edited = lock.replacen(
        "https://repo1.maven.org/maven2/\\tcentral\"\"\"",
        "https://repo1.maven.org/maven2/\\tcentral\nhttps://repo1.maven.org/maven2/\\tevil\"\"\"",
        1,
    );
    assert_ne!(edited, lock);
    let conflict = format!("<<<<<<< HEAD\n{edited}=======\n{edited}>>>>>>> theirs\n");
    fs::write(root.join("raeva.lock"), conflict).unwrap();
    assert_success(&raeva(&["sync"]), "sync of the conflicted lock");
    let regenerated = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert_eq!(
        regenerated.matches("role = \"trace\"").count(),
        1,
        "{regenerated}"
    );
    assert!(!regenerated.contains("\\tevil"), "{regenerated}");
    assert_success(&raeva(&["sync"]), "plain sync");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
}

/// Maven resolves a module's build extensions as it builds the project,
/// before its reactor reader serves the reactor's modules, so an extension
/// takes `t:lib` from the repository: the `1` its listing gives the range
/// `[1,3)`, though the reactor builds `t:lib:2`, and the repository's own
/// jar and POM of an exact `t:lib:2`, which it does not list, also when the
/// extension is `t:lib:2` itself, and it fails when the repository lacks
/// that. The module's own range takes the reactor's `t:lib:2`.
/// As Maven 3.10 reads it: the Maven 3.9 mode refuses it, as a build extension reads a reactor module's coordinate from a repository.
#[test]
fn build_extensions_take_no_reactor_module() {
    let release = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let depends = |version: &str| {
        format!(
            "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
             <version>{version}</version></dependency></dependencies>"
        )
    };
    let files: std::collections::HashMap<String, Vec<u8>> = [
        (
            "t/ranged/1/ranged-1.pom",
            release("ranged", "1", &depends("[1,3)")).into_bytes(),
        ),
        (
            "t/exact/1/exact-1.pom",
            release("exact", "1", &depends("2")).into_bytes(),
        ),
        ("t/lib/1/lib-1.pom", release("lib", "1", "").into_bytes()),
        (
            "t/lib/2/lib-2.pom",
            release(
                "lib",
                "2",
                "<dependencies><dependency><groupId>t</groupId><artifactId>dep</artifactId>\
                 <version>1</version></dependency></dependencies>",
            )
            .into_bytes(),
        ),
        ("t/dep/1/dep-1.pom", release("dep", "1", "").into_bytes()),
        ("t/dep/1/dep-1.jar", JAR.to_vec()),
        ("t/lib/1/lib-1.jar", JAR.to_vec()),
        ("t/lib/2/lib-2.jar", OTHER_JAR.to_vec()),
        (
            "t/lib/maven-metadata.xml",
            b"<metadata><groupId>t</groupId><artifactId>lib</artifactId><versioning>\
              <versions><version>1</version></versions></versioning>\
              </metadata>"
                .to_vec(),
        ),
    ]
    .into_iter()
    .map(|(path, body)| (path.to_string(), body))
    .collect();
    let gone = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let lib_gone = gone.clone();
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (file, sidecar) = match path.strip_suffix(".sha256") {
            Some(file) => (file, true),
            None => (path, false),
        };
        if file.starts_with("t/lib/2/") && lib_gone.load(std::sync::atomic::Ordering::SeqCst) {
            return Response::new(404, "");
        }
        match files.get(file) {
            Some(body) if sidecar => Response::new(200, sha256_hex(body)),
            Some(body) => Response::new(200, body.clone()),
            None => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let new_home = || {
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
                 <mirrorOf>*</mirrorOf></mirror></mirrors></settings>"
            ),
        )
        .unwrap();
        home
    };
    let home = new_home();
    let extension = |artifact: &str, version: &str| {
        format!(
            "<extension><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version></extension>"
        )
    };
    let extensions = format!(
        "<build><extensions>{}{}{}</extensions></build>",
        extension("ranged", "1"),
        extension("exact", "1"),
        extension("lib", "2")
    );
    let root = "<packaging>pom</packaging><modules><module>lib</module><module>app</module>\
                </modules>";
    for (path, text) in [
        ("pom.xml", release("root", "1", root)),
        ("lib/pom.xml", release("lib", "2", "")),
        (
            "app/pom.xml",
            release("app", "1", &format!("{}{extensions}", depends("[1,3)"))),
        ),
        (
            "raeva.toml",
            "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n".to_string(),
        ),
    ] {
        let path = project.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let output = run_raeva(project.path(), home.path(), &["sync"]);
    assert_success(&output, "sync");
    let lock: toml::Value =
        toml::from_str(&fs::read_to_string(project.path().join("raeva.lock")).unwrap()).unwrap();
    let platform = &lock["platforms"][0];
    let set = |extension: &str| {
        let sets = platform["plugins"]["sets"].as_array().unwrap();
        let set = (sets.iter())
            .find(|set| set["coordinates"][0].as_str() == Some(extension))
            .unwrap_or_else(|| panic!("{extension}: {sets:?}"));
        assert_eq!(set["role"].as_str(), Some("build-extension"), "{set:?}");
        set["artifacts"].as_str().unwrap().to_string()
    };
    let ranged = set("t:ranged:1");
    assert!(
        ranged.lines().any(|line| line == "t:lib:1\tjar"),
        "{ranged}"
    );
    // The repository's POM of `t:lib:2` gives its dependencies, not the
    // module's.
    for extension in ["t:exact:1", "t:lib:2"] {
        let set = set(extension);
        for artifact in ["t:lib:2\tjar", "t:dep:1\tjar"] {
            assert!(set.lines().any(|line| line == artifact), "{set}");
        }
    }
    let app = (platform["modules"].as_array().unwrap().iter())
        .find(|module| module["path"].as_str() == Some("app/pom.xml"))
        .unwrap();
    let packages = app["packages"].as_str().unwrap();
    assert!(
        packages
            .lines()
            .any(|line| line == "t:lib:2\tjar\tcompile\t\t\tlib/pom.xml"),
        "{packages}"
    );
    let m2 = home.path().join("m2");
    let export = run_raeva(
        project.path(),
        home.path(),
        &["export-m2", "--m2-path", m2.to_str().unwrap()],
    );
    assert_success(&export, "export");
    assert_eq!(fs::read(m2.join("t/lib/1/lib-1.jar")).unwrap(), JAR);
    assert_eq!(fs::read(m2.join("t/lib/2/lib-2.jar")).unwrap(), OTHER_JAR);
    // The ranged extension's `[1,3)` took `1`, all the list names; the
    // others pin `2` exactly. Maven 3.9.12 and 3.10.0 load the ranged
    // extension with `t:lib:1` online, and `mvn -o` does on the export only
    // where no list names `2`.
    // The stub mirrors Central, which the lock records by its own URL.
    let central = "https://repo.maven.apache.org/maven2/";
    let ranges = platform["plugins"]["range_versions"].as_str();
    assert_eq!(ranges, Some(format!("t:lib\t1\t{central}").as_str()));
    let lists = (fs::read_dir(m2.join("t/lib")).unwrap().flatten())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("maven-metadata-")
        })
        .map(|entry| fs::read_to_string(entry.path()).unwrap())
        .collect::<Vec<_>>();
    assert!(
        lists
            .iter()
            .any(|list| list.contains("<version>1</version>"))
            && !lists
                .iter()
                .any(|list| list.contains("<version>2</version>")),
        "{lists:?}"
    );
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--frozen"]),
        "frozen sync",
    );

    // A hand edit of the version a range took is refused.
    let lock_path = project.path().join("raeva.lock");
    let held = fs::read_to_string(&lock_path).unwrap();
    let line = format!("range_versions = \"t:lib\\t1\\t{central}\"");
    assert!(held.contains(&line), "{held}");
    fs::write(
        &lock_path,
        held.replace(&line, &line.replace("\\t1\\t", "\\t2\\t")),
    )
    .unwrap();
    let frozen = run_raeva(project.path(), home.path(), &["sync", "--frozen"]);
    assert!(!frozen.status.success(), "{}", stderr(&frozen));
    assert!(
        stderr(&frozen).contains("ranges took differ"),
        "{}",
        stderr(&frozen)
    );
    fs::write(&lock_path, &held).unwrap();

    // The extension-only row of `t:lib:2` keeps its exact origins.
    let tampered = tamper_pom_origin(&held, "lib", "2");
    fs::write(&lock_path, &tampered).unwrap();
    let frozen = run_raeva(project.path(), home.path(), &["sync", "--frozen"]);
    assert!(!frozen.status.success(), "{}", stderr(&frozen));
    assert!(
        stderr(&frozen).contains("the plugin file t:lib:2"),
        "{}",
        stderr(&frozen)
    );

    let home = new_home();
    gone.store(true, std::sync::atomic::Ordering::SeqCst);
    fs::remove_file(&lock_path).unwrap();
    fs::write(
        project.path().join("app/pom.xml"),
        release(
            "app",
            "1",
            &format!(
                "{}<build><extensions>{}</extensions></build>",
                depends("[1,3)"),
                extension("lib", "2")
            ),
        ),
    )
    .unwrap();
    let output = run_raeva(project.path(), home.path(), &["sync"]);
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("t:lib:2"), "{}", stderr(&output));
}

/// A module may name `t:lib:2` both as a build extension and as a system
/// dependency: Maven takes the extension from the repository and the
/// dependency from its path, also when the reactor builds `t:lib:2`.
/// As Maven 3.10 reads it: the Maven 3.9 mode refuses it, as a build extension reads a reactor module's coordinate from a repository.
#[test]
fn a_build_extension_may_share_a_system_dependencys_coordinates() {
    let release = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let files: std::collections::HashMap<String, Vec<u8>> = [
        ("t/lib/2/lib-2.pom", release("lib", "2", "").into_bytes()),
        ("t/lib/2/lib-2.jar", OTHER_JAR.to_vec()),
    ]
    .into_iter()
    .map(|(path, body)| (path.to_string(), body))
    .collect();
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (file, sidecar) = match path.strip_suffix(".sha256") {
            Some(file) => (file, true),
            None => (path, false),
        };
        match files.get(file) {
            Some(body) if sidecar => Response::new(200, sha256_hex(body)),
            Some(body) => Response::new(200, body.clone()),
            None => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let url = format!("http://{}/", server.addr());
    for reactor_version in ["2", "9"] {
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
                 <mirrorOf>*</mirrorOf></mirror></mirrors></settings>"
            ),
        )
        .unwrap();
        let app = "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
                   <version>2</version><scope>system</scope>\
                   <systemPath>${project.basedir}/vendor/lib.jar</systemPath></dependency>\
                   </dependencies><build><extensions><extension><groupId>t</groupId>\
                   <artifactId>lib</artifactId><version>2</version></extension></extensions>\
                   </build>";
        let root = "<packaging>pom</packaging><modules><module>lib</module><module>app</module>\
                    </modules>";
        for (path, text) in [
            ("pom.xml", release("root", "1", root)),
            ("lib/pom.xml", release("lib", reactor_version, "")),
            ("app/pom.xml", release("app", "1", app)),
            (
                "raeva.toml",
                "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n".to_string(),
            ),
        ] {
            let path = project.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        fs::create_dir_all(project.path().join("app/vendor")).unwrap();
        fs::write(project.path().join("app/vendor/lib.jar"), JAR).unwrap();
        assert_success(
            &run_raeva(project.path(), home.path(), &["sync"]),
            &format!("sync, reactor t:lib:{reactor_version}"),
        );
        let lock: toml::Value =
            toml::from_str(&fs::read_to_string(project.path().join("raeva.lock")).unwrap())
                .unwrap();
        let platform = &lock["platforms"][0];
        let sets = platform["plugins"]["sets"].as_array().unwrap();
        let set = (sets.iter())
            .find(|set| set["coordinates"][0].as_str() == Some("t:lib:2"))
            .unwrap_or_else(|| panic!("{sets:?}"));
        assert_eq!(set["artifacts"].as_str(), Some("t:lib:2\tjar"), "{set:?}");
        let app = (platform["modules"].as_array().unwrap().iter())
            .find(|module| module["path"].as_str() == Some("app/pom.xml"))
            .unwrap();
        let packages = app["packages"].as_str().unwrap();
        assert!(
            (packages.lines()).any(|line| line.starts_with("t:lib:2\tjar\tsystem\t")
                && line.contains("app/vendor/lib.jar")),
            "{packages}"
        );
        let m2 = home.path().join("m2");
        let export = run_raeva(
            project.path(),
            home.path(),
            &["export-m2", "--m2-path", m2.to_str().unwrap()],
        );
        assert_success(&export, "export");
        assert_eq!(fs::read(m2.join("t/lib/2/lib-2.jar")).unwrap(), OTHER_JAR);
        assert_success(
            &run_raeva(project.path(), home.path(), &["sync", "--frozen"]),
            "frozen sync",
        );
    }
}

/// The module `t:lib:2` asks for `t:lib:[2,2]`, which Maven takes from the
/// repository with the module's own model, and another module's build
/// extension `t:lib:2` reads the repository's POM and jar. The shared row
/// pins that POM, so frozen sync and export hold for both.
/// As Maven 3.10 reads it: the Maven 3.9 mode refuses it, as a build extension reads a reactor module's coordinate from a repository.
#[test]
fn a_module_shares_its_own_row_with_an_extension() {
    let release = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let depends = |artifact: &str, version: &str| {
        format!(
            "<dependencies><dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version></dependency></dependencies>"
        )
    };
    let lib_pom = release("lib", "2", &depends("dep", "1"));
    let files: std::collections::HashMap<String, Vec<u8>> = [
        ("t/lib/2/lib-2.pom", lib_pom.clone().into_bytes()),
        ("t/lib/2/lib-2.jar", OTHER_JAR.to_vec()),
        ("t/dep/1/dep-1.pom", release("dep", "1", "").into_bytes()),
        ("t/dep/1/dep-1.jar", JAR.to_vec()),
    ]
    .into_iter()
    .map(|(path, body)| (path.to_string(), body))
    .collect();
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (file, sidecar) = match path.strip_suffix(".sha256") {
            Some(file) => (file, true),
            None => (path, false),
        };
        match files.get(file) {
            Some(body) if sidecar => Response::new(200, sha256_hex(body)),
            Some(body) => Response::new(200, body.clone()),
            None => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>*</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    let extension = "<build><extensions><extension><groupId>t</groupId><artifactId>lib</artifactId>\
                     <version>2</version></extension></extensions></build>";
    let root = "<packaging>pom</packaging><modules><module>lib</module><module>app</module>\
                </modules>";
    for (path, text) in [
        ("pom.xml", release("root", "1", root)),
        ("lib/pom.xml", release("lib", "2", &depends("lib", "[2,2]"))),
        ("app/pom.xml", release("app", "1", extension)),
        (
            "raeva.toml",
            "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n".to_string(),
        ),
    ] {
        let path = project.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let lock: toml::Value =
        toml::from_str(&fs::read_to_string(project.path().join("raeva.lock")).unwrap()).unwrap();
    let platform = &lock["platforms"][0];
    let lib = (platform["modules"].as_array().unwrap().iter())
        .find(|module| module["path"].as_str() == Some("lib/pom.xml"))
        .unwrap();
    // The module's model names no `t:dep`, the repository's POM does.
    assert_eq!(
        lib["packages"].as_str(),
        Some("t:lib:2\tjar\tcompile"),
        "{lib:?}"
    );
    let row = (platform["artifacts"].as_array().unwrap().iter())
        .find(|row| {
            row["coordinate"]["artifact"].as_str() == Some("lib")
                && row["coordinate"]["packaging"].as_str() == Some("jar")
        })
        .unwrap();
    assert_eq!(
        row["pom_sha256"].as_str(),
        Some(sha256_hex(lib_pom.as_bytes()).as_str()),
        "{row:?}"
    );
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--frozen"]),
        "frozen sync",
    );
    let m2 = home.path().join("m2");
    let export = run_raeva(
        project.path(),
        home.path(),
        &["export-m2", "--m2-path", m2.to_str().unwrap()],
    );
    assert_success(&export, "export");
    assert_eq!(fs::read(m2.join("t/lib/2/lib-2.jar")).unwrap(), OTHER_JAR);
    assert_eq!(
        fs::read_to_string(m2.join("t/lib/2/lib-2.pom")).unwrap(),
        lib_pom
    );
}

/// The module `t:lib:2` asks for `t:lib:[2,2]`, whose jar its repository
/// serves while answering `status` for the POM, and another module's build
/// extension `t:lib:2` reads the POM and jar from a plugin repository.
/// Maven 3.9.12 and 3.10.0 build this and never read the module's
/// repository POM. The lock pins the extension's POM for the extension, so
/// frozen sync and export hold.
/// As Maven 3.10 reads it: the Maven 3.9 mode refuses it, as a build extension reads a reactor module's coordinate from a repository.
fn shares_its_own_row_when_its_repository_has_no_pom(status: u16) {
    let release = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let depends = |artifact: &str, version: &str| {
        format!(
            "<dependencies><dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version></dependency></dependencies>"
        )
    };
    let lib_pom = release("lib", "2", &depends("dep", "1"));
    let files: std::collections::HashMap<String, Vec<u8>> = [
        ("t/lib/2/lib-2.pom", lib_pom.clone().into_bytes()),
        ("t/lib/2/lib-2.jar", OTHER_JAR.to_vec()),
        ("t/dep/1/dep-1.pom", release("dep", "1", "").into_bytes()),
        ("t/dep/1/dep-1.jar", JAR.to_vec()),
    ]
    .into_iter()
    .map(|(path, body)| (path.to_string(), body))
    .collect();
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (repo, path) = path.split_once('/').unwrap_or(("", path));
        let (file, sidecar) = match path.strip_suffix(".sha256") {
            Some(file) => (file, true),
            None => (path, false),
        };
        if repo == "deps" && file == "t/lib/2/lib-2.pom" {
            return Response::new(status, "");
        }
        match files.get(file) {
            _ if repo == "central" && file.starts_with("t/") => Response::new(404, ""),
            None if repo == "central" => serve(request, None, |_| (JAR, true), |_| false),
            Some(body) if sidecar => Response::new(200, sha256_hex(body)),
            Some(body) => Response::new(200, body.clone()),
            None => Response::new(404, ""),
        }
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}central/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    let repositories = format!(
        "<repositories><repository><id>deps</id><url>{url}deps/</url></repository>\
         </repositories><pluginRepositories><pluginRepository><id>plugins</id>\
         <url>{url}plugins/</url></pluginRepository></pluginRepositories>"
    );
    let extension = "<build><extensions><extension><groupId>t</groupId><artifactId>lib</artifactId>\
                     <version>2</version></extension></extensions></build>";
    let root = format!(
        "<packaging>pom</packaging><modules><module>lib</module><module>app</module>\
         </modules>{repositories}"
    );
    let parent = "<parent><groupId>t</groupId><artifactId>root</artifactId><version>1</version>\
                  </parent>";
    for (path, text) in [
        ("pom.xml", release("root", "1", &root)),
        (
            "lib/pom.xml",
            release("lib", "2", &format!("{parent}{}", depends("lib", "[2,2]"))),
        ),
        (
            "app/pom.xml",
            release("app", "1", &format!("{parent}{extension}")),
        ),
        (
            "raeva.toml",
            "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n".to_string(),
        ),
    ] {
        let path = project.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    // A module's own repository file leaves the lock current.
    let again = run_raeva(project.path(), home.path(), &["sync"]);
    assert_success(&again, "sync again");
    assert!(
        !stderr(&again).contains("Resolving dependencies"),
        "{}",
        stderr(&again)
    );
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--frozen"]),
        "frozen sync",
    );
    let m2 = home.path().join("m2");
    let export = run_raeva(
        project.path(),
        home.path(),
        &["export-m2", "--m2-path", m2.to_str().unwrap()],
    );
    assert_success(&export, "export");
    assert_eq!(fs::read(m2.join("t/lib/2/lib-2.jar")).unwrap(), OTHER_JAR);
    assert_eq!(
        fs::read_to_string(m2.join("t/lib/2/lib-2.pom")).unwrap(),
        lib_pom
    );
    // Maven reads the jar from both repositories and the POM, for the
    // extension only, from the plugin repository.
    let markers = fs::read_to_string(m2.join("t/lib/2/_remote.repositories")).unwrap();
    let markers: Vec<&str> = (markers.lines())
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(
        markers,
        [
            "lib-2.jar>deps=",
            "lib-2.jar>plugins=",
            "lib-2.pom>plugins="
        ]
    );
}

#[test]
fn a_module_shares_its_own_row_when_its_repository_has_no_pom() {
    shares_its_own_row_when_its_repository_has_no_pom(404);
}

#[test]
fn a_module_shares_its_own_row_when_its_repository_refuses_the_pom() {
    shares_its_own_row_when_its_repository_has_no_pom(403);
}

/// What a module takes of its own coordinates resolves offline as it did
/// online: `t:selfn:1` asks for its jar, which the repository has without a
/// POM, and `t:selfp:1` for its POM, which only the module has. Maven
/// 3.9.12 and 3.10.0 build both.
#[test]
fn a_module_resolves_its_own_coordinates_offline() {
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        match path {
            "t/selfn/1/selfn-1.jar" => Response::new(200, JAR.to_vec()),
            "t/selfn/1/selfn-1.jar.sha256" => Response::new(200, sha256_hex(JAR)),
            _ if path.starts_with("t/self") => Response::new(404, ""),
            _ => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>*</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    let module = |artifact: &str, extra: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version><dependencies>\
             <dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>[1,1]</version>{extra}</dependency></dependencies></project>"
        )
    };
    for (path, text) in [
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>n</module><module>p</module></modules></project>"
                .to_string(),
        ),
        ("n/pom.xml", module("selfn", "")),
        ("p/pom.xml", module("selfp", "<type>pom</type>")),
    ] {
        let path = project.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let online = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    assert!(online.contains("artifact = \"selfn\""), "{online}");
    // Resolved again from the cache alone.
    fs::remove_file(project.path().join("raeva.lock")).unwrap();
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--offline"]),
        "offline sync",
    );
    let offline = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    assert_eq!(offline, online);
}

/// A module that asks for its own POM, a release `t:selfz:1` or a SNAPSHOT
/// `t:selfs:1-SNAPSHOT`, takes it from the module, as Maven 3.9.12 and
/// 3.10.0 do, though the repository refuses every request for it, and
/// offline with an empty home.
#[test]
fn a_module_serves_its_own_pom_without_a_repository() {
    let server = StubServer::start(move |request| {
        match request.path.trim_start_matches('/').starts_with("t/self") {
            true => Response::new(403, ""),
            false => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let url = format!("http://{}/", server.addr());
    let home = |project: &std::path::Path| {
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
                 <mirrorOf>*</mirrorOf></mirror></mirrors></settings>"
            ),
        )
        .unwrap();
        let _ = project;
        home
    };
    let module = |artifact: &str, version: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>\
             <repositories><repository><id>own</id><url>https://own.example/</url>\
             <snapshots><enabled>true</enabled></snapshots></repository></repositories>\
             <dependencies><dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>[{version}]</version><type>pom</type></dependency></dependencies>\
             </project>"
        )
    };
    let project = TempDir::new().unwrap();
    for (path, text) in [
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>z</module><module>s</module></modules></project>"
                .to_string(),
        ),
        ("z/pom.xml", module("selfz", "1")),
        ("s/pom.xml", module("selfs", "1-SNAPSHOT")),
    ] {
        let path = project.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let online = home(project.path());
    assert_success(&run_raeva(project.path(), online.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    fs::remove_file(project.path().join("raeva.lock")).unwrap();
    let empty = home(project.path());
    assert_success(
        &run_raeva(project.path(), empty.path(), &["sync", "--offline"]),
        "offline sync with an empty home",
    );
    assert_eq!(
        fs::read_to_string(project.path().join("raeva.lock")).unwrap(),
        lock
    );
}

/// `t:snap:1-SNAPSHOT` from repositories `a`, with only a non-unique build,
/// `b`, which answers 503, and `c`, with a timestamped build. Maven 3.9.12
/// and 3.10.0 pass over `b` and take `c`'s build. raeva refuses a SNAPSHOT
/// whose newest build a failing repository may hold, and does so for the
/// module `t:snap` asking for its own jar as for another module asking for
/// it, rather than lock `a`'s build.
fn sync_a_snapshot_behind_a_failing_repository(own: bool) -> std::process::Output {
    let stamp = "20240101.010101";
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
               <artifactId>snap</artifactId><version>1-SNAPSHOT</version></project>";
    let files: std::collections::HashMap<String, Vec<u8>> = [
        (
            "a/t/snap/1-SNAPSHOT/maven-metadata.xml".to_string(),
            "<metadata><groupId>t</groupId><artifactId>snap</artifactId>\
             <version>1-SNAPSHOT</version><versioning><lastUpdated>20200101010101</lastUpdated>\
             </versioning></metadata>"
                .to_string()
                .into_bytes(),
        ),
        (
            "a/t/snap/1-SNAPSHOT/snap-1-SNAPSHOT.pom".to_string(),
            pom.as_bytes().to_vec(),
        ),
        (
            "a/t/snap/1-SNAPSHOT/snap-1-SNAPSHOT.jar".to_string(),
            JAR.to_vec(),
        ),
        (
            "c/t/snap/1-SNAPSHOT/maven-metadata.xml".to_string(),
            format!(
                "<metadata><groupId>t</groupId><artifactId>snap</artifactId>\
                 <version>1-SNAPSHOT</version><versioning><snapshot><timestamp>{stamp}</timestamp>\
                 <buildNumber>1</buildNumber></snapshot><lastUpdated>20240101010101</lastUpdated>\
                 <snapshotVersions><snapshotVersion><extension>jar</extension>\
                 <value>1-{stamp}-1</value><updated>20240101010101</updated></snapshotVersion>\
                 <snapshotVersion><extension>pom</extension><value>1-{stamp}-1</value>\
                 <updated>20240101010101</updated></snapshotVersion></snapshotVersions>\
                 </versioning></metadata>"
            )
            .into_bytes(),
        ),
        (
            format!("c/t/snap/1-SNAPSHOT/snap-1-{stamp}-1.pom"),
            pom.as_bytes().to_vec(),
        ),
        (
            format!("c/t/snap/1-SNAPSHOT/snap-1-{stamp}-1.jar"),
            OTHER_JAR.to_vec(),
        ),
    ]
    .into_iter()
    .collect();
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (file, sidecar) = match path.strip_suffix(".sha256") {
            Some(file) => (file, true),
            None => (path, false),
        };
        match files.get(file) {
            _ if path.starts_with("b/") => Response::new(503, ""),
            Some(body) if sidecar => Response::new(200, sha256_hex(body)),
            Some(body) => Response::new(200, body.clone()),
            None if path.starts_with("central/") => {
                serve(request, None, |_| (JAR, true), |_| false)
            }
            None => Response::new(404, ""),
        }
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}central/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    let repositories: String = ["a", "b", "c"]
        .map(|id| {
            format!(
                "<repository><id>{id}</id><url>{url}{id}/</url>\
                 <snapshots><enabled>true</enabled></snapshots></repository>"
            )
        })
        .concat();
    let (artifact, version) = if own {
        ("snap", "1-SNAPSHOT")
    } else {
        ("app", "1")
    };
    fs::write(
        project.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>\
             <repositories>{repositories}</repositories><dependencies><dependency>\
             <groupId>t</groupId><artifactId>snap</artifactId><version>[1-SNAPSHOT]</version>\
             </dependency></dependencies></project>"
        ),
    )
    .unwrap();
    let sync = (raeva_command(project.path(), home.path()))
        .env("RAEVA_RETRIES", "0")
        .arg("sync")
        .output()
        .unwrap();
    assert!(!project.path().join("raeva.lock").exists());
    sync
}

#[test]
fn a_module_refuses_its_own_snapshot_behind_a_failing_repository() {
    let own = sync_a_snapshot_behind_a_failing_repository(true);
    let other = sync_a_snapshot_behind_a_failing_repository(false);
    assert_ne!(other.status.code(), Some(0));
    assert_eq!(
        own.status.code(),
        other.status.code(),
        "{}",
        String::from_utf8_lossy(&own.stderr)
    );
    assert!(String::from_utf8_lossy(&own.stderr).contains("503"));
}

/// Every pair of the ways a build uses `t:lib:2`, in one module and across
/// two, which Maven 3.9.12 and 3.10.0 both build: `R` a reactor module
/// another module depends on, `S` a system dependency, `E` a build
/// extension, `P` a plugin's dependency, `A` an annotation processor path,
/// `O` the module `t:lib:2` asking for `t:lib:[2,2]`, its repository
/// artifact, and `D` a dependency no module builds. Each pair syncs, holds
/// frozen and exports the repository's jar exactly where Maven reads it.
/// As Maven 3.10 reads it: the Maven 3.9 mode refuses it, as a build extension reads a reactor module's coordinate from a repository.
#[test]
fn every_pair_of_uses_of_one_coordinate_builds() {
    let release = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let files: std::collections::HashMap<String, Vec<u8>> = [
        ("t/lib/2/lib-2.pom", release("lib", "2", "").into_bytes()),
        ("t/lib/2/lib-2.jar", OTHER_JAR.to_vec()),
        (
            "t/lib/maven-metadata.xml",
            b"<metadata><groupId>t</groupId><artifactId>lib</artifactId><versioning>\
              <versions><version>2</version></versions></versioning></metadata>"
                .to_vec(),
        ),
    ]
    .into_iter()
    .map(|(path, body)| (path.to_string(), body))
    .collect();
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (file, sidecar) = match path.strip_suffix(".sha256") {
            Some(file) => (file, true),
            None => (path, false),
        };
        match files.get(file) {
            Some(body) if sidecar => Response::new(200, sha256_hex(body)),
            Some(body) => Response::new(200, body.clone()),
            None => serve(request, None, |_| (JAR, true), |_| false),
        }
    });
    let url = format!("http://{}/", server.addr());
    let lib = |version: &str, extra: &str| {
        format!(
            "<groupId>t</groupId><artifactId>lib</artifactId><version>{version}</version>{extra}"
        )
    };
    // A module's POM body for the uses in `kinds`.
    let body = |kinds: &[char]| {
        let (mut dependencies, mut extensions, mut plugins) = (String::new(), "", String::new());
        for kind in kinds {
            match kind {
                'R' | 'D' => dependencies += &format!("<dependency>{}</dependency>", lib("2", "")),
                'O' => dependencies += &format!("<dependency>{}</dependency>", lib("[2,2]", "")),
                'S' => {
                    dependencies += &format!(
                        "<dependency>{}</dependency>",
                        lib(
                            "2",
                            "<scope>system</scope>\
                             <systemPath>${project.basedir}/vendor/lib.jar</systemPath>"
                        )
                    )
                }
                'E' => {
                    extensions = "<extensions><extension><groupId>t</groupId>\
                                     <artifactId>lib</artifactId><version>2</version>\
                                     </extension></extensions>"
                }
                'P' => {
                    plugins += &format!(
                        "<plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                         <version>1</version><executions><execution><phase>validate</phase>\
                         <goals><goal>run</goal></goals></execution></executions>\
                         <dependencies><dependency>{}</dependency></dependencies></plugin>",
                        lib("2", "")
                    )
                }
                'A' => {
                    plugins += &format!(
                        "<plugin><artifactId>maven-compiler-plugin</artifactId>\
                         <version>3.13.0</version><configuration><annotationProcessorPaths>\
                         <path>{}</path></annotationProcessorPaths></configuration></plugin>",
                        lib("2", "")
                    )
                }
                _ => unreachable!(),
            }
        }
        format!(
            "<dependencies>{dependencies}</dependencies><build>{extensions}<plugins>{plugins}\
             </plugins></build>"
        )
    };
    let kinds = ['R', 'S', 'E', 'P', 'A', 'O', 'D'];
    let mut cases = Vec::new();
    for (i, &first) in kinds.iter().enumerate() {
        for &second in &kinds[i + 1..] {
            let pair = [first, second];
            let has = |kind| pair.contains(&kind);
            if has('D') && (has('R') || has('O')) {
                continue;
            }
            for across in [false, true] {
                // One module cannot declare `t:lib` twice.
                let twice = [['R', 'O'], ['S', 'O'], ['S', 'D']]
                    .iter()
                    .any(|twice| twice.iter().all(|kind| has(*kind)));
                if !across && twice {
                    continue;
                }
                cases.push((pair, across));
            }
        }
    }
    assert_eq!(cases.len(), 35);
    for (pair, across) in cases {
        let name = format!(
            "{}{}-{}",
            pair[0],
            pair[1],
            if across { "across" } else { "same" }
        );
        let mut uses: Vec<(&str, Vec<char>)> = match across {
            true => vec![("app1", vec![pair[0]]), ("app2", vec![pair[1]])],
            // The reactor builds `t:lib:2`, which the module declares system.
            false if pair == ['R', 'S'] => vec![("app1", vec!['S'])],
            false => vec![("app1", pair.to_vec())],
        };
        // `O` is declared by the module `t:lib:2` itself.
        let own: Vec<char> = (uses.iter())
            .filter(|(_, kinds)| kinds.contains(&'O'))
            .flat_map(|(_, kinds)| kinds.clone())
            .collect();
        uses.retain(|(_, kinds)| !kinds.contains(&'O'));
        let reactor = pair.contains(&'R') || pair.contains(&'O');
        let modules: String = (reactor.then_some("lib").into_iter())
            .chain(uses.iter().map(|(module, _)| *module))
            .map(|module| format!("<module>{module}</module>"))
            .collect();
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
                 <mirrorOf>*</mirrorOf></mirror></mirrors></settings>"
            ),
        )
        .unwrap();
        let mut poms = vec![
            (
                "pom.xml".to_string(),
                release(
                    "root",
                    "1",
                    &format!("<packaging>pom</packaging><modules>{modules}</modules>"),
                ),
            ),
            (
                "raeva.toml".to_string(),
                "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n".to_string(),
            ),
        ];
        if reactor {
            poms.push(("lib/pom.xml".to_string(), release("lib", "2", &body(&own))));
        }
        for (module, kinds) in &uses {
            poms.push((
                format!("{module}/pom.xml"),
                release(module, "1", &body(kinds)),
            ));
            if kinds.contains(&'S') {
                fs::create_dir_all(project.path().join(module).join("vendor")).unwrap();
                fs::write(project.path().join(module).join("vendor/lib.jar"), JAR).unwrap();
            }
        }
        for (path, text) in poms {
            let path = project.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        assert_success(&run_raeva(project.path(), home.path(), &["sync"]), &name);
        assert_success(
            &run_raeva(project.path(), home.path(), &["sync", "--frozen"]),
            &format!("{name} frozen"),
        );
        let m2 = home.path().join("m2");
        let export = run_raeva(
            project.path(),
            home.path(),
            &["export-m2", "--m2-path", m2.to_str().unwrap()],
        );
        assert_success(&export, &format!("{name} export"));
        // A plugin's dependency and a processor path take the reactor's
        // module; an extension, `O` and `D` take the repository's file.
        let repository = pair.iter().any(|kind| "EOD".contains(*kind))
            || (!reactor && pair.iter().any(|kind| "PA".contains(*kind)));
        let exported = fs::read(m2.join("t/lib/2/lib-2.jar")).ok();
        assert_eq!(
            exported.as_deref(),
            repository.then_some(OTHER_JAR),
            "{name}"
        );
    }
}

/// `lock` with an origin added to the POM of the `t:{artifact}:{version}` jar.
fn tamper_pom_origin(lock: &str, artifact: &str, version: &str) -> String {
    let row = format!("group = \"t\"\nartifact = \"{artifact}\"\nversion = \"{version}\"\n");
    let chunks: Vec<String> = (lock.split("[[platforms.artifacts]]\n"))
        .map(|chunk| {
            if !chunk.contains(&row) {
                return chunk.to_string();
            }
            let (head, tail) = chunk.split_once('\n').unwrap();
            let (head, tail) = match tail.split_once("pom_sha256") {
                Some((before, after)) => {
                    let (line, rest) = after.split_once('\n').unwrap();
                    (
                        format!("{head}\n{before}pom_sha256{line}"),
                        rest.to_string(),
                    )
                }
                None => (head.to_string(), tail.to_string()),
            };
            format!("{head}\npom_repo_urls = [\"https://other.example/\"]\n{tail}")
        })
        .collect();
    let tampered = chunks.join("[[platforms.artifacts]]\n");
    assert_ne!(tampered, lock, "no row of t:{artifact}:{version}");
    tampered
}

/// A trace row raeva.lock is edited to add with a reactor module's
/// coordinates is a repository file the modules do not read: `--frozen`
/// checks its origins and its pins as any traced file's. `shared_origins`
/// may name only a row the modules read, and a support POM no plugin set
/// names is left to the dependencies' check. The jar of the edited row
/// is served last, so its POM's mismatch finishes first: the error still
/// names the jar, the row's first file.
#[cfg(unix)]
#[test]
fn a_traced_row_of_a_reactor_modules_coordinates_is_checked() {
    let server = StubServer::start(|request| {
        let response = serve(request, None, |_| (JAR, true), |_| false);
        match request.path.as_str() {
            "/t/lib/2/lib-2.jar" => response.delayed(std::time::Duration::from_millis(300)),
            _ => response,
        }
    });
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fake_mvnw(root);
    let release = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let modules = "<packaging>pom</packaging><modules><module>lib</module>\
                   <module>app</module></modules>";
    let app = "<dependencies><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
               <version>2</version></dependency></dependencies>";
    for (path, text) in [
        ("pom.xml", release("root", "1", modules)),
        ("lib/pom.xml", release("lib", "2", "")),
        ("app/pom.xml", release("app", "1", app)),
        (
            "raeva.toml",
            "[plugins]\nlock = true\ntrace = ['validate']\nmvn = './mvnw'\n".to_string(),
        ),
    ] {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let edit = |pom_origin: &str| {
        let tool = lock.find("artifact = \"tool\"").expect("the traced row");
        let at = lock[..tool].rfind("[[platforms.artifacts]]\n").unwrap();
        let row = format!(
            "[[platforms.artifacts]]\nrepo_url = \"https://repo.maven.apache.org/maven2/\"\n\
             pom_sha256 = \"{}\"\npom_repo_urls = [\"{pom_origin}\"]\n\n\
             [platforms.artifacts.coordinate]\ngroup = \"t\"\nartifact = \"lib\"\n\
             version = \"2\"\npackaging = \"jar\"\n\n\
             [[platforms.artifacts.checksums]]\nalgorithm = \"sha256\"\ndigest = \"{}\"\n\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        let edited = format!("{}{row}{}", &lock[..at], &lock[at..]).replacen(
            "role = \"trace\"\nartifacts = \"t:tool:1\\tjar\"\n",
            "role = \"trace\"\nartifacts = \"\"\"\nt:lib:2\\tjar\nt:tool:1\\tjar\"\"\"\n",
            1,
        );
        assert!(edited.contains("t:lib:2\\tjar\nt:tool"), "{edited}");
        edited
    };
    // An origin nothing declares is refused before any request.
    fs::write(root.join("raeva.lock"), edit("https://undeclared.example/")).unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_status(&frozen, 7, "frozen sync of an undeclared origin");
    assert!(
        stderr(&frozen).contains("undeclared.example"),
        "{}",
        stderr(&frozen)
    );
    // Pins the repository's files do not match are refused too.
    fs::write(
        root.join("raeva.lock"),
        edit("https://repo.maven.apache.org/maven2/"),
    )
    .unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_status(&frozen, 7, "frozen sync of other pins");
    assert!(
        stderr(&frozen).contains("checksum mismatch for t:lib:2:jar"),
        "{}",
        stderr(&frozen)
    );

    // A build that takes `t:lib:2` from the repository traces it, and
    // `--frozen` fetches it again into an empty store.
    let launcher = fs::read_to_string(root.join("mvnw")).unwrap().replace(
        "printf 'tool-1.jar>stub=\\n'",
        "mkdir -p \"$m2/t/lib/2\"\ncp \"$(dirname \"$0\")/tool.jar\" \"$m2/t/lib/2/lib-2.jar\"\n\
         printf 'lib-2.jar>stub=\\n' > \"$m2/t/lib/2/_remote.repositories\"\n\
         printf 'tool-1.jar>stub=\\n'",
    );
    assert!(launcher.contains("lib-2.jar>stub"), "{launcher}");
    fs::write(root.join("mvnw"), launcher).unwrap();
    fs::remove_file(root.join("raeva.lock")).unwrap();
    assert_success(&raeva(&["sync"]), "traced sync of t:lib:2");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:lib:2\\tjar\nt:tool:1\\tjar"), "{lock}");
    fs::remove_dir_all(home.path().join("store")).unwrap();
    let asked = server.requests().len();
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    let paths: Vec<String> = (server.requests().into_iter().skip(asked))
        .map(|request| request.path)
        .collect();
    assert!(
        paths.iter().any(|path| path == "/t/lib/2/lib-2.jar"),
        "{paths:?}"
    );
    // Only a row the modules read records the origins the sets add to it.
    let shared = lock.replacen(
        "[[platforms.plugins.sets]]\n",
        &format!("shared_origins = \"t:lib:2\\tjar\\t{url}\"\n\n[[platforms.plugins.sets]]\n"),
        1,
    );
    fs::write(root.join("raeva.lock"), shared).unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_status(&frozen, 3, "frozen sync of a set-only row's shared origin");
    assert!(
        stderr(&frozen).contains("shared_origins"),
        "{}",
        stderr(&frozen)
    );
    // A support POM of a reactor module's coordinates that nothing reads is
    // no plugin's, so the dependencies' check finds it.
    let orphan = lock.replacen(
        "[platforms.plugins]\n",
        &format!(
            "[[platforms.support_poms]]\ncoordinate = \"t:root:1\"\n\
             repo_url = \"https://undeclared.example/\"\nsha256 = \"{}\"\n\n\
             [platforms.plugins]\n",
            "a".repeat(64)
        ),
        1,
    );
    assert_ne!(orphan, lock);
    fs::write(root.join("raeva.lock"), orphan).unwrap();
    let frozen = raeva(&["sync", "--frozen"]);
    assert_status(&frozen, 7, "frozen sync of an unread support POM");
    assert!(
        stderr(&frozen).contains("support POM removed for t:root:1"),
        "{}",
        stderr(&frozen)
    );
}

/// Maven keeps one version list per repository id for a plugin without a
/// version too: modules that declare plugin repository `p` at two URLs
/// listing other versions are refused, and the same list at both syncs.
#[test]
fn one_plugin_repository_id_listing_other_versions_at_two_urls_is_refused() {
    for equal in [false, true] {
        let server = StubServer::start(move |request| {
            let full = request.path.trim_start_matches('/');
            let (repo, path) = full.split_once('/').unwrap_or((full, ""));
            if !path.starts_with("t/v-maven-plugin/maven-metadata.xml") {
                let mut request = request.clone();
                request.path = format!("/{path}");
                return serve(&request, None, |_| (JAR, true), |_| false);
            }
            let (release, listed) = match repo {
                "u1" if !equal => ("1", "<version>1</version>"),
                "u1" | "u2" => ("2", "<version>1</version><version>2</version>"),
                _ => return Response::new(404, ""),
            };
            serve_sha256(path, |_| {
                Some(format!(
                    "<metadata><groupId>t</groupId><artifactId>v-maven-plugin</artifactId>\
                     <versioning><release>{release}</release><versions>{listed}</versions>\
                     <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
                ))
            })
        });
        let url = format!("http://{}", server.addr());
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>stub</id><url>{url}/central/</url>\
                 <mirrorOf>central</mirrorOf></mirror></mirrors></settings>"
            ),
        )
        .unwrap();
        let root = project.path();
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                 </modules>",
            ),
        )
        .unwrap();
        for (name, dir) in [("a", "u1"), ("b", "u2")] {
            let module = format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
                 <artifactId>app</artifactId><version>1</version></parent>\
                 <artifactId>{name}</artifactId><packaging>pom</packaging>\
                 <pluginRepositories><pluginRepository><id>p</id><url>{url}/{dir}/</url>\
                 </pluginRepository></pluginRepositories><build><plugins><plugin>\
                 <groupId>t</groupId><artifactId>v-maven-plugin</artifactId><executions>\
                 <execution><phase>validate</phase><goals><goal>run</goal></goals>\
                 </execution></executions></plugin></plugins></build></project>"
            );
            fs::create_dir_all(root.join(name)).unwrap();
            fs::write(root.join(name).join("pom.xml"), module).unwrap();
        }
        fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
        let sync = (raeva_command(root, home.path()))
            .arg("sync")
            .output()
            .expect("run raeva");
        if equal {
            assert_success(&sync, "sync");
            continue;
        }
        assert_eq!(sync.status.code(), Some(5), "{}", stderr(&sync));
        for expected in [
            "repository id p",
            "t:v-maven-plugin",
            &format!("{url}/u1/ and {url}/u2/"),
        ] {
            assert!(stderr(&sync).contains(expected), "{}", stderr(&sync));
        }
        assert!(!root.join("raeva.lock").exists());
    }
}

/// A settings.xml plugin repository at the URL of one the POM declares
/// under another id: the export labels the plugin's files with both ids,
/// so `mvn -o` finds them through either. Another id for it on the machine
/// that exports is another configuration, which `--frozen` and the export
/// refuse until a sync.
#[test]
fn an_export_labels_plugins_with_the_settings_and_the_pom_plugin_repository_ids() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project("unused");
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            &format!(
                "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                 <id>dev-plugins</id><url>{url}</url></pluginRepository></pluginRepositories>\
                 <build><plugins><plugin><groupId>t</groupId>\
                 <artifactId>demo-maven-plugin</artifactId><version>1</version></plugin>\
                 </plugins></build>"
            ),
        ),
    )
    .unwrap();
    let settings = |id: &str| {
        let settings = format!(
            "<settings><profiles><profile><id>p</id><pluginRepositories><pluginRepository>\
             <id>{id}</id><url>{url}</url></pluginRepository></pluginRepositories>\
             </profile></profiles><activeProfiles><activeProfile>p</activeProfile>\
             </activeProfiles></settings>"
        );
        fs::write(home.path().join(".m2/settings.xml"), settings).unwrap();
    };
    settings("ci-plugins");
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    let m2 = home.path().join("m2");
    let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
    assert_success(&raeva(&export), "export");
    let remote = m2.join("t/demo-maven-plugin/1/_remote.repositories");
    let remote = fs::read_to_string(remote).unwrap();
    for id in ["ci-plugins", "dev-plugins"] {
        assert!(
            remote.contains(&format!("demo-maven-plugin-1.jar>{id}=")),
            "{remote}"
        );
    }

    settings("other-plugins");
    for args in [&["sync", "--frozen"][..], &export] {
        let output = raeva(args);
        assert_status(&output, 7, &args.join(" "));
        assert!(
            stderr(&output).contains("the configuration changed"),
            "{}",
            stderr(&output)
        );
    }
}

/// Removes the metadata cache from the raeva home `home`, as a CI cache
/// that keeps only the store would.
fn remove_metadata_cache(home: &std::path::Path) {
    for entry in fs::read_dir(home).unwrap() {
        let path = entry.unwrap().path();
        if (path.file_name().unwrap().to_string_lossy()).starts_with("metadata.db") {
            fs::remove_file(path).unwrap();
        }
    }
}

/// A lock whose plugin tables pin a build extension's remote parent at the
/// coordinates of a reactor module is replayed offline by `sbom` and
/// `export-m2` once the metadata cache is gone, as `sync --frozen` checks
/// it: the plugin tables are not the dependencies' graph.
/// As Maven 3.10 reads it: the Maven 3.9 mode refuses it, as the extension reads a reactor module's coordinate from a repository.
#[test]
fn an_extension_parent_at_a_reactor_gav_is_replayed_offline() {
    let parent = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                  <artifactId>ext-parent</artifactId><version>1</version>\
                  <packaging>pom</packaging></project>";
    let extension = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
                     <artifactId>ext-parent</artifactId><version>1</version></parent>\
                     <artifactId>my-ext</artifactId></project>";
    let server = StubServer::start(move |request| {
        let body = match request.path.trim_end_matches(".sha256") {
            "/t/ext-parent/1/ext-parent-1.pom" => parent,
            "/t/my-ext/1/my-ext-1.pom" => extension,
            _ => return serve(request, None, |_| (JAR, true), |_| false),
        };
        match request.path.ends_with(".sha256") {
            true => Response::new(200, sha256_hex(body.as_bytes())),
            false => Response::new(200, body),
        }
    });
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fs::remove_dir_all(root.join(".mvn")).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n",
    )
    .unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "ext-parent",
            "<packaging>pom</packaging><build><extensions><extension><groupId>t</groupId>\
             <artifactId>my-ext</artifactId><version>1</version></extension></extensions>\
             </build>",
        ),
    )
    .unwrap();
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(lock.contains("t:ext-parent:1"), "{lock}");
    remove_metadata_cache(home.path());
    let m2 = home.path().join("m2");
    for args in [
        &["--offline", "sbom"][..],
        &["--offline", "export-m2", "--m2-path", m2.to_str().unwrap()],
    ] {
        assert_success(&raeva(args), &args.join(" "));
    }
    assert!(m2.join("t/my-ext/1/my-ext-1.jar").is_file());
}

/// A frozen sync, an SBOM or an export checks plugin rows from a plugin
/// repository only a remote parent declares offline, once metadata.db is
/// lost, from the POMs the store holds, whether Central or a repository
/// the project's POM declares serves that parent, and refuses them from
/// another repository.
#[test]
fn an_offline_export_replays_a_remote_parent_plugin_repository() {
    for declared in [false, true] {
        let plugins = org_repository(JAR);
        let (project, home, ours) = remote_parent_project(&plugins);
        let root = project.path();
        let none = StubServer::start(|_| Response::new(404, ""));
        if declared {
            let pom = fs::read_to_string(root.join("pom.xml")).unwrap().replacen(
                "<packaging>pom</packaging>",
                &format!(
                    "<packaging>pom</packaging><repositories><repository><id>corp</id>\
                     <url>http://{}/our-org/</url></repository></repositories>",
                    ours.addr()
                ),
                1,
            );
            fs::write(root.join("pom.xml"), pom).unwrap();
            fs::write(
                home.path().join(".m2/settings.xml"),
                format!(
                    "<settings><mirrors><mirror><id>none</id><url>http://{}/</url>\
                     <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
                    none.addr()
                ),
            )
            .unwrap();
        }
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        let forget_metadata = || {
            for entry in fs::read_dir(home.path()).unwrap() {
                let path = entry.unwrap().path();
                if (path.file_name().unwrap().to_string_lossy()).starts_with("metadata.db") {
                    fs::remove_file(path).unwrap();
                }
            }
        };
        let m2 = root.join("m2");
        let export = ["export-m2", "--offline", "--m2-path", m2.to_str().unwrap()];
        let frozen = ["sync", "--frozen", "--offline"];
        for args in [&frozen[..], &["sbom", "--offline"][..], &export[..]] {
            forget_metadata();
            let output = run_raeva(root, home.path(), args);
            assert_success(&output, &format!("{args:?}, parent declared: {declared}"));
        }
        // Another repository, one that serves the same bytes among them,
        // fails online and offline, with metadata.db and without.
        let origin = format!("http://{}/our-org/", plugins.addr());
        let attacker = format!("http://{}/attacker-org/", plugins.addr());
        for edited in ["https://evil.example/", attacker.as_str()] {
            fs::write(root.join("raeva.lock"), lock.replace(&origin, edited)).unwrap();
            for args in [&["sync", "--frozen"][..], &frozen[..]] {
                let output = run_raeva(root, home.path(), args);
                assert_status(&output, 7, &format!("{args:?} of the lock naming {edited}"));
                assert!(
                    stderr(&output).contains("the plugin sets differ"),
                    "{}",
                    stderr(&output)
                );
            }
            for args in [&frozen[..], &export[..]] {
                forget_metadata();
                let output = run_raeva(root, home.path(), args);
                assert!(!output.status.success(), "{args:?}: {}", stderr(&output));
            }
        }
    }
}

/// Two modules that reach one plugin repository URL under two ids, each
/// mirrored to its own server, check their plugins offline once
/// metadata.db is lost: each POM is cached for the id that served it.
#[test]
fn an_offline_frozen_check_reads_each_id_of_a_plugin_repository() {
    let (first, second) = (org_repository(JAR), org_repository(JAR));
    let central = StubServer::start(|request| serve(request, None, |_| (JAR, true), |_| false));
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let root = project.path();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
        ),
    )
    .unwrap();
    for (module, plugin) in [("a", "demo-maven-plugin"), ("b", "other-maven-plugin")] {
        fs::create_dir_all(root.join(module)).unwrap();
        fs::write(
            root.join(module).join("pom.xml"),
            pom(
                module,
                &format!(
                    "<pluginRepositories><pluginRepository><id>repo-{module}</id>\
                     <url>https://plugins.example/</url></pluginRepository>\
                     </pluginRepositories><build><plugins><plugin><groupId>t</groupId>\
                     <artifactId>{plugin}</artifactId><version>1</version><executions>\
                     <execution><phase>validate</phase><goals><goal>run</goal></goals>\
                     </execution></executions></plugin></plugins></build>"
                ),
            ),
        )
        .unwrap();
    }
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>mirror-a</id><url>http://{}/our-org/</url>\
             <mirrorOf>repo-a</mirrorOf></mirror><mirror><id>mirror-b</id>\
             <url>http://{}/our-org/</url><mirrorOf>repo-b</mirrorOf></mirror><mirror>\
             <id>central-stub</id><url>http://{}/</url><mirrorOf>central</mirrorOf></mirror>\
             </mirrors></settings>",
            first.addr(),
            second.addr(),
            central.addr()
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    for entry in fs::read_dir(home.path()).unwrap() {
        let path = entry.unwrap().path();
        if (path.file_name().unwrap().to_string_lossy()).starts_with("metadata.db") {
            fs::remove_file(path).unwrap();
        }
    }
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--frozen", "--offline"]),
        "offline frozen sync without metadata.db",
    );
}

/// A Central for `home`, mirrored in its settings.xml, that serves the
/// lifecycle plugins and none of the `t` group, which the project's own
/// repositories hold.
fn stub_central(home: &std::path::Path) -> StubServer {
    let central = StubServer::start(|request| match request.path.starts_with("/t/") {
        true => Response::new(404, ""),
        false => serve(request, None, |_| (JAR, true), |_| false),
    });
    fs::create_dir_all(home.join(".m2")).unwrap();
    fs::write(
        home.join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>http://{}/</url>\
             <mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            central.addr()
        ),
    )
    .unwrap();
    central
}

/// A frozen check replays the versions the plugin tables took: a version
/// published since raeva.lock was written moves no parent range, range or
/// `RELEASE` of a plugin's own dependencies, nor the `<release>` a build
/// extension without a version took, nor another spelling of the version
/// marked since, also where a spelling listed before the locked one hides
/// it. An update takes it.
#[test]
fn a_frozen_check_holds_the_versions_a_plugin_closure_took() {
    for (artifact, newer, before) in [
        ("par", "1.1", &[][..]),
        ("sub", "1.0.1", &[]),
        ("rel", "1.1", &[]),
        ("ext", "2", &[]),
        ("rel", "1.0-ga", &[]),
        ("ext", "1-ga", &[]),
        ("ext", "1-final", &["1-ga"]),
    ] {
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let root = project.path();
        let repo = root.join("repo");
        let publish = |artifact: &str, version: &str, listed: &[&str]| {
            let (body, jar) = match artifact {
                "par" => ("<packaging>pom</packaging>", false),
                "demo-maven-plugin" => (
                    "<parent><groupId>t</groupId><artifactId>par</artifactId>\
                     <version>[1,2)</version></parent><packaging>maven-plugin</packaging>\
                     <dependencies><dependency><groupId>t</groupId><artifactId>sub</artifactId>\
                     <version>[1.0,2.0)</version></dependency><dependency><groupId>t</groupId>\
                     <artifactId>rel</artifactId><version>RELEASE</version></dependency>\
                     </dependencies>",
                    true,
                ),
                _ => ("", true),
            };
            crate::common::publish(&repo, &format!("t:{artifact}:{version}"), body);
            let dir = repo.join("t").join(artifact);
            if jar {
                let file = format!("{version}/{artifact}-{version}.jar");
                write_with_sha256(&dir.join(file), JAR);
            }
            let versions: String = (listed.iter())
                .map(|version| format!("<version>{version}</version>"))
                .collect();
            write_with_sha256(
                &dir.join("maven-metadata.xml"),
                format!(
                    "<metadata><groupId>t</groupId><artifactId>{artifact}</artifactId>\
                     <versioning><release>{version}</release><versions>{versions}</versions>\
                     <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
                )
                .as_bytes(),
            );
        };
        publish("demo-maven-plugin", "1", &["1"]);
        for (each, version) in [("par", "1"), ("sub", "1.0"), ("rel", "1.0"), ("ext", "1")] {
            let listed = [if each == artifact { before } else { &[] }, &[version]].concat();
            publish(each, version, &listed);
        }
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                 <id>local-repo</id><url>file://${project.basedir}/repo/</url>\
                 </pluginRepository></pluginRepositories><build><extensions><extension>\
                 <groupId>t</groupId><artifactId>ext</artifactId></extension></extensions>\
                 <plugins><plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                 <version>1</version><executions><execution><phase>validate</phase><goals>\
                 <goal>run</goal></goals></execution></executions></plugin></plugins></build>",
            ),
        )
        .unwrap();
        fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
        let _central = stub_central(home.path());
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        let locked = |version: &str| format!("t:{artifact}:{version}");
        let old =
            (fs::read_to_string(repo.join("t").join(artifact).join("maven-metadata.xml"))).unwrap();
        let old = &old[old.find("<release>").unwrap() + 9..old.find("</release>").unwrap()];
        assert!(lock.contains(&locked(old)), "{artifact}: {lock}");
        publish(artifact, newer, &[before, &[old, newer]].concat());
        let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
        assert_success(&frozen, &format!("frozen sync after t:{artifact}:{newer}"));
        assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
        assert_success(
            &run_raeva(root, home.path(), &["sync", "--update"]),
            "update",
        );
        let updated = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(updated.contains(&locked(newer)), "{artifact}: {updated}");
    }
}

/// A plugin row whose plugin repository has no POM takes the one the
/// traced build read from a project repository, and `--frozen` accepts the
/// lock that sync wrote.
#[cfg(unix)]
/// As Maven 3.10 reads it: the Maven 3.9 mode refuses it, as a plugin reads a dependency without a POM.
#[test]
fn frozen_accepts_the_pom_a_trace_gave_a_row_without_one() {
    use std::os::unix::fs::PermissionsExt;

    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let _central = stub_central(home.path());
    let root = project.path();
    let helper = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                  <artifactId>helper</artifactId><version>1.0</version></project>";
    crate::common::publish(
        &root.join("P"),
        "t:demo-maven-plugin:1",
        "<packaging>maven-plugin</packaging><dependencies><dependency><groupId>t</groupId>\
         <artifactId>helper</artifactId><version>1.0</version></dependency></dependencies>",
    );
    write_with_sha256(
        &root.join("P/t/demo-maven-plugin/1/demo-maven-plugin-1.jar"),
        JAR,
    );
    write_with_sha256(&root.join("P/t/helper/1.0/helper-1.0.jar"), JAR);
    write_with_sha256(
        &root.join("D/t/helper/1.0/helper-1.0.pom"),
        helper.as_bytes(),
    );
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><repositories><repository><id>D</id>\
             <url>file://${project.basedir}/D/</url></repository></repositories>\
             <pluginRepositories><pluginRepository><id>P</id>\
             <url>file://${project.basedir}/P/</url></pluginRepository></pluginRepositories>\
             <build><plugins><plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
             <version>1</version><executions><execution><phase>validate</phase><goals>\
             <goal>run</goal></goals></execution></executions></plugin></plugins></build>",
        ),
    )
    .unwrap();
    // The build's plugin reads the helper's POM through the project's
    // repositories.
    let launcher = root.join("mvnw");
    fs::write(
        &launcher,
        format!(
            "#!/bin/sh\nfor a in \"$@\"; do case $a in -Dmaven.repo.local=*) \
             m2=${{a#-Dmaven.repo.local=}};; esac; done\nmkdir -p \"$m2/t/helper/1.0\"\n\
             printf '%s' '{helper}' > \"$m2/t/helper/1.0/helper-1.0.pom\"\n\
             printf 'helper-1.0.pom>D=\\n' > \"$m2/t/helper/1.0/_remote.repositories\"\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "traced sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let digest = sha256_hex(helper.as_bytes());
    assert!(lock.contains(&digest), "{lock}");
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--frozen"]),
        "frozen sync",
    );
}

/// `--frozen` holds a row only plugins use to every checksum it records,
/// as `lock verify` does: a SHA-1 added beside the SHA-256 pin is refused.
#[test]
fn frozen_refuses_a_checksum_added_to_a_plugin_row() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let row = lock.find("artifact = \"demo-maven-plugin\"").unwrap();
    let at = row
        + lock[row..]
            .find("[[platforms.artifacts.checksums]]")
            .unwrap();
    let sha1 = format!(
        "[[platforms.artifacts.checksums]]\nalgorithm = \"sha1\"\ndigest = \"{}\"\n\n",
        "0".repeat(40)
    );
    fs::write(
        root.join("raeva.lock"),
        format!("{}{sha1}{}", &lock[..at], &lock[at..]),
    )
    .unwrap();
    let verify = run_raeva(root, home.path(), &["lock", "verify"]);
    assert_status(&verify, 7, "lock verify");
    let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
    assert_status(&frozen, 7, "frozen sync");
    assert!(
        stderr(&frozen).contains("the plugin file t:demo-maven-plugin:1"),
        "{}",
        stderr(&frozen)
    );
    // A plain sync does not keep it, so the next frozen check passes.
    assert_success(&run_raeva(root, home.path(), &["sync"]), "plain sync");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--frozen"]),
        "frozen",
    );
}

/// A plain sync keeps the plugin tables of a lock this home wrote or
/// checked without checking them again; one another home wrote is checked
/// once, and one edited by hand fails the check and is written again, so
/// `--frozen` passes after it.
#[test]
fn a_plain_sync_checks_the_plugin_tables_of_a_lock_it_did_not_write_or_check() {
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let plain = |home: &std::path::Path, checks: bool| {
        let plain = run_raeva(root, home, &["sync"]);
        assert_success(&plain, "plain sync");
        assert_eq!(
            stderr(&plain).contains("Checking plugins"),
            checks,
            "{}",
            stderr(&plain)
        );
        assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
    };
    plain(home.path(), false);
    let other = TempDir::new().unwrap();
    fs::create_dir_all(other.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        other.path().join(".m2/settings.xml"),
    )
    .unwrap();
    plain(other.path(), true);
    plain(other.path(), false);
    // A `lock verify` that resolves the lock as `--frozen` does checks it too.
    let third = TempDir::new().unwrap();
    fs::create_dir_all(third.path().join(".m2")).unwrap();
    fs::copy(
        home.path().join(".m2/settings.xml"),
        third.path().join(".m2/settings.xml"),
    )
    .unwrap();
    let verify = run_raeva(root, third.path(), &["lock", "verify", "--download"]);
    assert_success(&verify, "lock verify");
    plain(third.path(), false);
    // Drop the clean plugin's set and its row: the inputs stay as they were.
    let blocks: Vec<&str> = lock.split("\n\n").collect();
    let clean = |block: &str| block.contains("artifact = \"maven-clean-plugin\"");
    let edited: Vec<&str> = (blocks.iter().enumerate())
        .filter(|&(at, block)| {
            let next = blocks.get(at + 1).copied().unwrap_or("");
            let before = if at > 0 { blocks[at - 1] } else { "" };
            !((block.starts_with("[[platforms.artifacts]]") && clean(next))
                || (block.starts_with("[platforms.artifacts.coordinate]") && clean(block))
                || (block.starts_with("[[platforms.artifacts.checksums]]") && clean(before))
                || (block.starts_with("[[platforms.plugins.sets]]")
                    && block.contains("maven-clean-plugin")))
        })
        .map(|(_, block)| *block)
        .collect();
    let edited = edited.join("\n\n");
    assert_ne!(edited, lock);
    fs::write(root.join("raeva.lock"), &edited).unwrap();
    let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
    assert_status(&frozen, 7, "frozen sync of a dropped plugin set");
    let plain = run_raeva(root, home.path(), &["sync"]);
    assert_success(&plain, "plain sync of a dropped plugin set");
    assert!(
        stderr(&plain).contains("Checking plugins"),
        "{}",
        stderr(&plain)
    );
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--frozen"]),
        "frozen",
    );
}

/// The plugins read the POM of a row the modules take without one from
/// their own repository, which raeva.lock pins as a support POM there.
/// `--frozen` refuses that support POM recorded under another repository
/// the plugins search, which never served it. As Maven 3.10 reads it.
#[test]
fn frozen_refuses_a_plugin_support_pom_moved_to_another_repository() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let _central = stub_central(home.path());
    let root = project.path();
    crate::common::publish(&root.join("plugins"), "t:lib:2", "");
    write_with_sha256(&root.join("plugins/t/lib/2/lib-2.jar"), JAR);
    write_with_sha256(&root.join("deps/t/lib/2/lib-2.jar"), JAR);
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><repositories><repository><id>deps</id>\
             <url>file://${project.basedir}/deps/</url></repository></repositories>\
             <pluginRepositories><pluginRepository><id>plugins</id>\
             <url>file://${project.basedir}/plugins/</url></pluginRepository>\
             </pluginRepositories><dependencies><dependency><groupId>t</groupId>\
             <artifactId>lib</artifactId><version>2</version></dependency></dependencies>\
             <build><extensions><extension><groupId>t</groupId><artifactId>lib</artifactId>\
             <version>2</version></extension></extensions></build>",
        ),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--frozen"]),
        "frozen",
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    // A plain sync keeps the lock, offline too once the metadata cache is
    // gone.
    for offline in [false, false, true] {
        if offline {
            remove_metadata_cache(home.path());
        }
        let args: &[&str] = if offline {
            &["sync", "--offline"]
        } else {
            &["sync"]
        };
        let plain = run_raeva(root, home.path(), args);
        assert_success(&plain, "plain sync of the lock as written");
        assert!(
            stderr(&plain).contains("raeva.lock is up to date"),
            "{}",
            stderr(&plain)
        );
        assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
    }
    let pinned = "coordinate = \"t:lib:2\"\nrepo_url = \"./plugins/\"\n";
    assert!(lock.contains(pinned), "{lock}");
    let edited = lock.replacen(
        pinned,
        "coordinate = \"t:lib:2\"\nrepo_url = \"https://repo.maven.apache.org/maven2/\"\n",
        1,
    );
    fs::write(root.join("raeva.lock"), edited).unwrap();
    let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
    assert_status(&frozen, 7, "frozen sync of a moved plugin support POM");
    assert!(stderr(&frozen).contains("t:lib:2"), "{}", stderr(&frozen));
    // A plain sync does not keep it, so the next frozen check passes.
    assert_success(&run_raeva(root, home.path(), &["sync"]), "plain sync");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--frozen"]),
        "frozen",
    );
}

/// A plain sync checks the plugin tables of a lock another home wrote as
/// `--frozen` does, at the SNAPSHOT builds raeva.lock pins: a newer build
/// of a parent the plugins read leaves the lock as it is. As Maven 3.10
/// reads it.
#[test]
fn a_plain_sync_checks_plugin_tables_at_the_snapshot_builds_they_pin() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let _central = stub_central(home.path());
    let root = project.path();
    let snapshot = |build: &str, timestamp: &str, number: &str| {
        let dir = root.join("plugins/t/parent/1-SNAPSHOT");
        write_with_sha256(
            &dir.join(format!("parent-{build}.pom")),
            b"<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
              <artifactId>parent</artifactId><version>1-SNAPSHOT</version>\
              <packaging>pom</packaging></project>",
        );
        write_with_sha256(
            &dir.join("maven-metadata.xml"),
            format!(
                "<metadata><groupId>t</groupId><artifactId>parent</artifactId>\
                 <version>1-SNAPSHOT</version><versioning><snapshot><timestamp>{timestamp}\
                 </timestamp><buildNumber>{number}</buildNumber></snapshot><lastUpdated>\
                 20240101120000</lastUpdated><snapshotVersions><snapshotVersion>\
                 <extension>pom</extension><value>{build}</value><updated>20240101120000\
                 </updated></snapshotVersion></snapshotVersions></versioning></metadata>"
            )
            .as_bytes(),
        );
    };
    snapshot("1-20240101.120000-1", "20240101.120000", "1");
    crate::common::publish(
        &root.join("plugins"),
        "t:lib:2",
        "<parent><groupId>t</groupId><artifactId>parent</artifactId>\
         <version>1-SNAPSHOT</version></parent>",
    );
    write_with_sha256(&root.join("plugins/t/lib/2/lib-2.jar"), JAR);
    write_with_sha256(&root.join("deps/t/lib/2/lib-2.jar"), JAR);
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><repositories><repository><id>deps</id>\
             <url>file://${project.basedir}/deps/</url></repository></repositories>\
             <pluginRepositories><pluginRepository><id>plugins</id>\
             <url>file://${project.basedir}/plugins/</url><snapshots><enabled>true</enabled>\
             <updatePolicy>always</updatePolicy></snapshots></pluginRepository>\
             </pluginRepositories><dependencies><dependency><groupId>t</groupId>\
             <artifactId>lib</artifactId><version>2</version></dependency></dependencies>\
             <build><extensions><extension><groupId>t</groupId><artifactId>lib</artifactId>\
             <version>2</version></extension></extensions></build>",
        ),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[lock]\nmaven = \"3.10\"\n\n[plugins]\nlock = true\n",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(
        lock.contains("coordinate = \"t:parent:1-SNAPSHOT\""),
        "{lock}"
    );
    assert!(
        lock.contains("coordinate = \"t:lib:2\"\nrepo_url = \"./plugins/\""),
        "{lock}"
    );
    snapshot("1-20240102.120000-2", "20240102.120000", "2");
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--frozen"]),
        "frozen sync after a newer build",
    );
    let other = TempDir::new().unwrap();
    let _central = stub_central(other.path());
    let plain = run_raeva(root, other.path(), &["sync"]);
    assert_success(&plain, "plain sync after a newer build");
    assert!(
        stderr(&plain).contains("Checking plugins"),
        "{}",
        stderr(&plain)
    );
    assert!(
        stderr(&plain).contains("raeva.lock is up to date"),
        "{}",
        stderr(&plain)
    );
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
}

/// `shared_origins` names only a row a module reads from a repository: a
/// system file of the plugin's coordinates is none, so a line for it is
/// refused.
#[test]
fn shared_origins_of_a_system_file_are_refused() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let _central = stub_central(home.path());
    let root = project.path();
    crate::common::publish(&root.join("P"), "t:ext:1", "");
    write_with_sha256(&root.join("P/t/ext/1/ext-1.jar"), JAR);
    crate::common::publish(&root.join("extra"), "t:other:1", "");
    fs::create_dir_all(root.join("lib")).unwrap();
    fs::write(root.join("lib/ext-1.jar"), JAR).unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "app",
            "<packaging>pom</packaging><pluginRepositories><pluginRepository><id>P</id>\
             <url>file://${project.basedir}/P/</url></pluginRepository><pluginRepository>\
             <id>extra</id><url>file://${project.basedir}/extra/</url></pluginRepository>\
             </pluginRepositories><dependencies><dependency><groupId>t</groupId>\
             <artifactId>ext</artifactId><version>1</version><scope>system</scope>\
             <systemPath>${project.basedir}/lib/ext-1.jar</systemPath></dependency>\
             </dependencies><build><extensions><extension><groupId>t</groupId>\
             <artifactId>ext</artifactId><version>1</version></extension></extensions>\
             </build>",
        ),
    )
    .unwrap();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    assert_success(
        &run_raeva(root, home.path(), &["sync", "--frozen"]),
        "frozen",
    );
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let edited = lock.replacen(
        "[[platforms.plugins.sets]]\n",
        "shared_origins = \"t:ext:1\\tjar\\t./extra/\"\n\n[[platforms.plugins.sets]]\n",
        1,
    );
    assert_ne!(edited, lock);
    fs::write(root.join("raeva.lock"), edited).unwrap();
    let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
    assert_status(&frozen, 3, "frozen sync of a system file's shared origin");
    assert!(
        stderr(&frozen).contains("shared_origins"),
        "{}",
        stderr(&frozen)
    );
}

/// A plugin range replays the spelling it took among equal ones,
/// `1.0-alpha-1` and `1.0-a1`, when versions listed since change their order
/// in Maven's hash map, and reads the POM of the other as it did.
#[test]
fn a_frozen_plugin_range_replays_its_tie_once_the_listing_reorders_it() {
    let fillers: Vec<String> = (1..=9).map(|minor| format!("0.{minor}")).collect();
    let fillers: Vec<&str> = fillers.iter().map(String::as_str).collect();
    let tied = [&["1.0-alpha-1", "1.0-a1"][..], &fillers].concat();
    let more = [&tied[..], &["3.1", "3.2"]].concat();
    for maven in ["3.9", "3.10"] {
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let _central = stub_central(home.path());
        let root = project.path();
        let repo = root.join("repo");
        crate::common::publish(
            &repo,
            "t:demo-maven-plugin:1",
            "<packaging>maven-plugin</packaging><dependencies><dependency>\
             <groupId>t</groupId><artifactId>sub</artifactId>\
             <version>[1.0-alpha-1,2.0)</version></dependency></dependencies>",
        );
        for version in ["1.0-alpha-1", "1.0-a1"] {
            crate::common::publish(&repo, &format!("t:sub:{version}"), "");
        }
        let list = |listed: &[&str]| {
            let versions: String = (listed.iter())
                .map(|version| format!("<version>{version}</version>"))
                .collect();
            write_with_sha256(
                &repo.join("t/sub/maven-metadata.xml"),
                format!(
                    "<metadata><groupId>t</groupId><artifactId>sub</artifactId>\
                     <versioning><versions>{versions}</versions>\
                     <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
                )
                .as_bytes(),
            );
        };
        list(&tied);
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                 <id>local-repo</id><url>file://${project.basedir}/repo/</url>\
                 </pluginRepository></pluginRepositories><build><plugins><plugin>\
                 <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                 <version>1</version><executions><execution><phase>validate</phase>\
                 <goals><goal>run</goal></goals></execution></executions></plugin>\
                 </plugins></build>",
            ),
        )
        .unwrap();
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{maven}\"\n\n[plugins]\nlock = true\n"),
        )
        .unwrap();
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        list(&more);
        let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
        assert_success(&frozen, &format!("frozen sync after 3.1 and 3.2, {maven}"));
        assert_success(
            &run_raeva(root, home.path(), &["sync"]),
            "sync after 3.1 and 3.2",
        );
        assert_eq!(
            fs::read_to_string(root.join("raeva.lock")).unwrap(),
            lock,
            "{maven}"
        );
    }
}

/// A plugin's parent range replays the spelling it took among equal ones,
/// `1.0-alpha-1`, when versions listed since change their order in Maven's
/// hash map, as Maven 3.9.12 and 3.10.0 took it then, though the plugin
/// tables also hold the other, `1.0-a1`, which a dependency names: a
/// `--frozen` check agrees with the plain sync that keeps the lock.
#[test]
fn a_frozen_plugin_parent_range_replays_its_tie_once_the_listing_reorders_it() {
    let fillers: Vec<String> = (1..=9).map(|minor| format!("0.{minor}")).collect();
    let fillers: Vec<&str> = fillers.iter().map(String::as_str).collect();
    let tied = [&["1.0-alpha-1", "1.0-a1"][..], &fillers].concat();
    let more = [&tied[..], &["3.1", "3.2"]].concat();
    for maven in ["3.9", "3.10"] {
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let _central = stub_central(home.path());
        let root = project.path();
        let repo = root.join("repo");
        crate::common::publish(
            &repo,
            "t:demo-maven-plugin:1",
            "<packaging>maven-plugin</packaging><parent><groupId>t</groupId>\
             <artifactId>sub</artifactId><version>[1.0-alpha-1,2.0)</version></parent>\
             <dependencies><dependency><groupId>t</groupId><artifactId>sub</artifactId>\
             <version>1.0-a1</version><type>pom</type></dependency></dependencies>",
        );
        for version in ["1.0-alpha-1", "1.0-a1"] {
            crate::common::publish(
                &repo,
                &format!("t:sub:{version}"),
                "<packaging>pom</packaging>",
            );
        }
        let list = |listed: &[&str]| {
            let versions: String = (listed.iter())
                .map(|version| format!("<version>{version}</version>"))
                .collect();
            write_with_sha256(
                &repo.join("t/sub/maven-metadata.xml"),
                format!(
                    "<metadata><groupId>t</groupId><artifactId>sub</artifactId>\
                     <versioning><versions>{versions}</versions>\
                     <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
                )
                .as_bytes(),
            );
        };
        list(&tied);
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                 <id>local-repo</id><url>file://${project.basedir}/repo/</url>\
                 </pluginRepository></pluginRepositories><build><plugins><plugin>\
                 <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                 <version>1</version><executions><execution><phase>validate</phase>\
                 <goals><goal>run</goal></goals></execution></executions></plugin>\
                 </plugins></build>",
            ),
        )
        .unwrap();
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{maven}\"\n\n[plugins]\nlock = true\n"),
        )
        .unwrap();
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(
            lock.contains("support_poms = \"t:sub:1.0-alpha-1\""),
            "{lock}"
        );
        list(&more);
        let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
        assert_success(&frozen, &format!("frozen sync after 3.1 and 3.2, {maven}"));
        assert_success(
            &run_raeva(root, home.path(), &["sync"]),
            "sync after 3.1 and 3.2",
        );
        assert_eq!(
            fs::read_to_string(root.join("raeva.lock")).unwrap(),
            lock,
            "{maven}"
        );
    }
}

/// Two modules whose plugin repositories list other spellings of one
/// version each take their own: the spelling a range of one took among
/// equal ones does not refuse the other's on a frozen check.
#[test]
fn frozen_keeps_each_repositorys_spelling_of_a_plugin_range() {
    for (only, maven) in [
        ("1.0", "3.9"),
        ("1.0-ga", "3.9"),
        ("1.0", "3.10"),
        ("1.0-ga", "3.10"),
    ] {
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let _central = stub_central(home.path());
        let root = project.path();
        let list = |repo: &str, artifact: &str, listed: &[&str]| {
            let repo = root.join(repo);
            for version in listed {
                crate::common::publish(&repo, &format!("t:{artifact}:{version}"), "");
            }
            let versions: String = (listed.iter())
                .map(|version| format!("<version>{version}</version>"))
                .collect();
            write_with_sha256(
                &repo.join(format!("t/{artifact}/maven-metadata.xml")),
                format!(
                    "<metadata><groupId>t</groupId><artifactId>{artifact}</artifactId>\
                     <versioning><versions>{versions}</versions>\
                     <lastUpdated>20240101000000</lastUpdated></versioning></metadata>"
                )
                .as_bytes(),
            );
        };
        for (repo, listed) in [("repo-a", &["1.0", "1.0-ga"][..]), ("repo-b", &[only])] {
            crate::common::publish(
                &root.join(repo),
                "t:demo-maven-plugin:1",
                "<packaging>maven-plugin</packaging><dependencies><dependency>\
                 <groupId>t</groupId><artifactId>sub</artifactId>\
                 <version>[1.0,2.0)</version></dependency><dependency><groupId>t</groupId>\
                 <artifactId>other</artifactId><version>[1,3)</version></dependency>\
                 </dependencies>",
            );
            list(repo, "sub", listed);
            list(repo, "other", &["1"]);
        }
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                 </modules>",
            ),
        )
        .unwrap();
        for module in ["a", "b"] {
            fs::create_dir_all(root.join(module)).unwrap();
            fs::write(
                root.join(module).join("pom.xml"),
                pom(
                    module,
                    &format!(
                        "<pluginRepositories><pluginRepository><id>repo-{module}</id>\
                         <url>file://${{project.basedir}}/../repo-{module}/</url>\
                         </pluginRepository></pluginRepositories><build><plugins><plugin>\
                         <groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                         <version>1</version><executions><execution><phase>validate</phase>\
                         <goals><goal>run</goal></goals></execution></executions></plugin>\
                         </plugins></build>"
                    ),
                ),
            )
            .unwrap();
        }
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{maven}\"\n\n[plugins]\nlock = true\n"),
        )
        .unwrap();
        assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
        assert_success(
            &frozen,
            &format!("frozen sync, repo-b lists {only}, {maven}"),
        );
        assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
        // A version published since moves no range on a frozen check, and a
        // plain sync agrees the lock is current.
        for repo in ["repo-a", "repo-b"] {
            list(repo, "other", &["1", "2"]);
        }
        let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
        assert_success(
            &frozen,
            &format!("frozen sync after t:other:2, repo-b lists {only}, {maven}"),
        );
        assert_success(
            &run_raeva(root, home.path(), &["sync"]),
            "sync after t:other:2",
        );
        assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
    }
}

/// A plugin, its dependency and a build extension through a mirror of a
/// POM `<pluginRepository>` whose URL raeva.lock cannot record take the
/// empty origin, as a dependency row does: a cold `--frozen`, a seed
/// restored into a fresh home with an offline `--frozen`, one without the
/// metadata cache, and export-m2 all read them through that mirror. A
/// version range listed through such a repository is still refused.
#[test]
fn plugins_through_a_mirror_of_a_plugin_repository_raeva_cannot_record_lock() {
    let server = StubServer::start(|request| {
        if request.path.starts_with("/t/pdep/maven-metadata.xml") {
            let metadata = "<metadata><groupId>t</groupId><artifactId>pdep</artifactId>\
                            <versioning><versions><version>1.0</version></versions>\
                            </versioning></metadata>";
            return match request.path.ends_with(".sha256") {
                true => Response::new(200, sha256_hex(metadata.as_bytes())),
                false => Response::new(200, metadata),
            };
        }
        serve(request, None, |_| (JAR, true), |_| false)
    });
    let stub = format!("http://{}/", server.addr());
    let settings = format!(
        "<settings><mirrors><mirror><id>mp</id><url>{stub}</url><mirrorOf>corpp</mirrorOf>\
         </mirror><mirror><id>stub</id><url>{stub}</url><mirrorOf>*</mirrorOf></mirror>\
         </mirrors></settings>"
    );
    let home = || {
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(home.path().join(".m2/settings.xml"), &settings).unwrap();
        home
    };
    for (url, version) in [
        ("./placeholder", "1.0"),
        ("http://[::1", "1.0"),
        ("${undefined.prop}/p", "1.0"),
        ("./placeholder", "[1.0,2.0)"),
    ] {
        let case = format!("{url} {version}");
        let project = TempDir::new().unwrap();
        let root = project.path();
        fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                &format!(
                    "<packaging>pom</packaging><pluginRepositories><pluginRepository>\
                     <id>corpp</id><url>{url}</url></pluginRepository></pluginRepositories>\
                     <build><extensions><extension><groupId>t</groupId><artifactId>ext\
                     </artifactId><version>2</version></extension></extensions><plugins>\
                     <plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                     <version>1</version><dependencies><dependency><groupId>t</groupId>\
                     <artifactId>pdep</artifactId><version>{version}</version></dependency>\
                     </dependencies><executions><execution><phase>validate</phase><goals>\
                     <goal>run</goal></goals></execution></executions></plugin></plugins>\
                     </build>"
                ),
            ),
        )
        .unwrap();
        let synced = home();
        let output = run_raeva(root, synced.path(), &["sync"]);
        if version.starts_with('[') {
            assert_status(&output, 3, &case);
            assert!(stderr(&output).contains("cannot record"), "{case}");
            continue;
        }
        assert_success(&output, &case);
        let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
        let files = lock.platforms[0].plugin_files().expect("plugin tables");
        for coordinate in ["t:demo-maven-plugin:1", "t:ext:2", "t:pdep:1.0"] {
            let row = (files.artifacts.iter())
                .find(|row| row.coordinate.to_string().starts_with(coordinate))
                .unwrap_or_else(|| panic!("{case}: {coordinate}"));
            assert_eq!(row.repo_url, "", "{case}: {coordinate}");
        }
        let text = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(
            !text.contains(&stub) && !text.contains("placeholder"),
            "{text}"
        );
        let cold = home();
        assert_success(
            &run_raeva(root, cold.path(), &["sync", "--frozen"]),
            &format!("{case} cold frozen"),
        );
        let seed = project.path().join("seed");
        let seed = seed.to_str().unwrap();
        assert_success(
            &run_raeva(root, cold.path(), &["seed", "save", seed]),
            &case,
        );
        let restored = home();
        let output = run_raeva(root, restored.path(), &["seed", "restore", seed]);
        assert_success(&output, &format!("{case} seed restore"));
        let output = run_raeva(root, restored.path(), &["--offline", "sync", "--frozen"]);
        assert_success(&output, &format!("{case} offline frozen from the seed"));
        fs::remove_file(cold.path().join("metadata.db")).expect("the metadata cache");
        for database in ["metadata.db-wal", "metadata.db-shm"] {
            let _ = fs::remove_file(cold.path().join(database));
        }
        let output = run_raeva(root, cold.path(), &["--offline", "sync", "--frozen"]);
        assert_success(&output, &format!("{case} offline frozen without metadata"));
        let m2 = project.path().join("m2");
        assert_success(
            &run_raeva(
                root,
                restored.path(),
                &["--offline", "export-m2", "--m2-path", m2.to_str().unwrap()],
            ),
            &format!("{case} export"),
        );
        for file in [
            "t/demo-maven-plugin/1/demo-maven-plugin-1.jar",
            "t/ext/2/ext-2.jar",
            "t/pdep/1.0/pdep-1.0.jar",
        ] {
            assert!(m2.join(file).exists(), "{case}: {file}");
        }
        #[cfg(unix)]
        {
            // A traced build that took a file through the same repository.
            let launcher = fake_mvnw(root);
            let marker = fs::read_to_string(&launcher)
                .unwrap()
                .replace(">stub=", ">corpp=");
            fs::write(&launcher, marker).unwrap();
            fs::write(
                root.join("raeva.toml"),
                "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
            )
            .unwrap();
            assert_success(
                &run_raeva(root, synced.path(), &["sync"]),
                &format!("{case} trace"),
            );
            let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
            let files = lock.platforms[0].plugin_files().expect("plugin tables");
            let tool = (files.artifacts.iter())
                .find(|row| row.coordinate.to_string().starts_with("t:tool:1"))
                .unwrap_or_else(|| panic!("{case}: the traced file"));
            assert_eq!(tool.repo_url, "", "{case}");
            let traced = project.path().join("traced-m2");
            let export = ["export-m2", "--m2-path", traced.to_str().unwrap()];
            assert_success(&run_raeva(root, synced.path(), &export), &case);
            let remote = fs::read_to_string(traced.join("t/tool/1/_remote.repositories")).unwrap();
            for id in ["corpp", "mp"] {
                assert!(
                    remote.contains(&format!("tool-1.jar>{id}=")),
                    "{case}: {remote}"
                );
            }
            let fresh = home();
            assert_success(
                &run_raeva(root, fresh.path(), &["sync", "--frozen"]),
                &format!("{case} traced frozen"),
            );
        }
    }
}

/// A plugin and a build extension through a mirror of an active
/// settings.xml profile's `<pluginRepository>` whose URL raeva.lock cannot
/// record take the empty origin, as through a POM's, and export-m2 places
/// them under the mirror's id, online and offline.
#[test]
fn plugins_through_a_mirror_of_a_settings_plugin_repository_raeva_cannot_record_export() {
    let server = StubServer::start(|request| serve(request, None, |_| (JAR, true), |_| false));
    let stub = format!("http://{}/", server.addr());
    for url in ["./placeholder", "bundle://corp/plugins"] {
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>mp</id><url>{stub}</url><mirrorOf>corpp\
                 </mirrorOf></mirror><mirror><id>stub</id><url>{stub}</url><mirrorOf>*\
                 </mirrorOf></mirror></mirrors><profiles><profile><id>corp</id>\
                 <pluginRepositories><pluginRepository><id>corpp</id><url>{url}</url>\
                 </pluginRepository></pluginRepositories></profile></profiles>\
                 <activeProfiles><activeProfile>corp</activeProfile></activeProfiles>\
                 </settings>"
            ),
        )
        .unwrap();
        let project = TempDir::new().unwrap();
        let root = project.path();
        fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
        fs::write(
            root.join("pom.xml"),
            pom(
                "app",
                "<packaging>pom</packaging><build><extensions><extension><groupId>t</groupId>\
                 <artifactId>ext</artifactId><version>2</version></extension></extensions>\
                 <plugins><plugin><groupId>t</groupId><artifactId>demo-maven-plugin\
                 </artifactId><version>1</version><executions><execution><phase>validate\
                 </phase><goals><goal>run</goal></goals></execution></executions></plugin>\
                 </plugins></build>",
            ),
        )
        .unwrap();
        assert_success(&run_raeva(root, home.path(), &["sync"]), url);
        let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
        let files = lock.platforms[0].plugin_files().expect("plugin tables");
        let plugin = (files.artifacts.iter())
            .find(|row| (row.coordinate.to_string()).starts_with("t:demo-maven-plugin:1"))
            .unwrap_or_else(|| panic!("{url}"));
        assert_eq!(plugin.repo_url, "", "{url}");
        assert_success(
            &run_raeva(root, home.path(), &["sync", "--frozen"]),
            &format!("{url} frozen"),
        );
        for offline in [false, true] {
            let m2 = project.path().join(format!("m2-{offline}"));
            let mut export = vec!["export-m2", "--m2-path", m2.to_str().unwrap()];
            if offline {
                export.insert(0, "--offline");
            }
            let case = format!("{url} export, offline {offline}");
            assert_success(&run_raeva(root, home.path(), &export), &case);
            let plugin = m2.join("t/demo-maven-plugin/1");
            assert!(plugin.join("demo-maven-plugin-1.jar").exists(), "{case}");
            assert!(m2.join("t/ext/2/ext-2.jar").exists(), "{case}");
            let remote = fs::read_to_string(plugin.join("_remote.repositories")).unwrap();
            assert!(
                remote.contains("demo-maven-plugin-1.jar>mp="),
                "{case}: {remote}"
            );
        }
    }
}

/// Plugin files read through two `<pluginRepository>` declarations whose
/// URLs raeva.lock cannot record, behind different mirrors, are refused, as
/// dependency rows are: the empty origin cannot tell them apart. Such a
/// `<repository>` beside one is not, since plugin resolution does not read
/// it.
#[test]
fn plugin_files_through_two_repositories_raeva_cannot_record_are_refused() {
    let one = StubServer::start(|request| serve(request, None, |_| (JAR, true), |_| false));
    let two = StubServer::start(|request| serve(request, None, |_| (OTHER_JAR, true), |_| false));
    let settings = format!(
        "<settings><mirrors><mirror><id>m1</id><url>http://{}/</url><mirrorOf>corpp</mirrorOf>\
         </mirror><mirror><id>m2</id><url>http://{}/</url><mirrorOf>corpq</mirrorOf></mirror>\
         <mirror><id>stub</id><url>http://{}/</url><mirrorOf>*,!corpp,!corpq</mirrorOf>\
         </mirror></mirrors></settings>",
        one.addr(),
        two.addr(),
        one.addr()
    );
    let plugin = "<pluginRepository><id>corpp</id><url>./a</url></pluginRepository>";
    for (declared, refused) in [
        (
            format!(
                "<pluginRepositories><pluginRepository><id>corpq</id><url>./b</url>\
                 </pluginRepository>{plugin}</pluginRepositories>"
            ),
            true,
        ),
        (
            format!(
                "<pluginRepositories>{plugin}</pluginRepositories><repositories><repository>\
                 <id>corpq</id><url>./b</url></repository></repositories>"
            ),
            false,
        ),
    ] {
        let home = TempDir::new().unwrap();
        fs::create_dir_all(home.path().join(".m2")).unwrap();
        fs::write(home.path().join(".m2/settings.xml"), &settings).unwrap();
        let project = TempDir::new().unwrap();
        let root = project.path();
        fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
        let body = format!(
            "<packaging>pom</packaging>{declared}<build><plugins><plugin><groupId>t</groupId>\
             <artifactId>demo-maven-plugin</artifactId><version>1</version><executions>\
             <execution><phase>validate</phase><goals><goal>run</goal></goals></execution>\
             </executions></plugin></plugins></build>"
        );
        fs::write(root.join("pom.xml"), pom("app", &body)).unwrap();
        let output = run_raeva(root, home.path(), &["sync"]);
        if refused {
            assert_status(&output, 3, &declared);
            assert!(
                stderr(&output).contains("several repositories"),
                "{declared}"
            );
            continue;
        }
        assert_success(&output, &declared);
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(lock.contains(&sha256_hex(JAR)), "{lock}");
        assert_success(
            &run_raeva(root, home.path(), &["sync", "--frozen"]),
            &declared,
        );
    }
}

/// A traced build that reads a file through a mirror of a repository whose
/// URL raeva.lock cannot record is refused when the plugin tables may hold
/// the empty origin for another such repository: here the plugin comes
/// through `pA`'s mirror and the traced tool through `dB`'s.
#[cfg(unix)]
#[test]
fn a_trace_through_one_of_two_repositories_raeva_cannot_record_is_refused() {
    let one = StubServer::start(|request| serve(request, None, |_| (JAR, true), |_| false));
    let two = StubServer::start(|request| serve(request, None, |_| (JAR, true), |_| false));
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let root = project.path();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>m1</id><url>http://{}/</url><mirrorOf>pA</mirrorOf>\
             </mirror><mirror><id>m2</id><url>http://{}/</url><mirrorOf>dB</mirrorOf></mirror>\
             <mirror><id>stub</id><url>http://{}/</url><mirrorOf>*,!pA,!dB</mirrorOf></mirror>\
             </mirrors></settings>",
            one.addr(),
            two.addr(),
            one.addr()
        ),
    )
    .unwrap();
    let body = "<packaging>pom</packaging><pluginRepositories><pluginRepository><id>pA</id>\
                <url>./a</url></pluginRepository></pluginRepositories><repositories>\
                <repository><id>dB</id><url>./b</url></repository></repositories><build>\
                <plugins><plugin><groupId>t</groupId><artifactId>demo-maven-plugin</artifactId>\
                <version>1</version><executions><execution><phase>validate</phase><goals>\
                <goal>run</goal></goals></execution></executions></plugin></plugins></build>";
    fs::write(root.join("pom.xml"), pom("app", body)).unwrap();
    let launcher = fake_mvnw(root);
    let marker = fs::read_to_string(&launcher)
        .unwrap()
        .replace(">stub=", ">dB=");
    fs::write(&launcher, marker).unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let output = run_raeva(root, home.path(), &["sync"]);
    assert_status(&output, 3, "traced sync");
    assert!(
        stderr(&output).contains("several repositories"),
        "{}",
        stderr(&output)
    );
}

/// A traced build's output may show what raeva hides: the secret-named
/// `-D` values of the JVM options, and the passwords, passphrases, private
/// keys and master password of the settings, decrypted too, which no file
/// or output raeva writes holds, at any `-v`.
#[cfg(unix)]
#[test]
fn a_failed_trace_shows_no_secret_raeva_took() {
    let server = repository();
    let url = format!("http://{}/", server.addr());
    let (project, home) = plugin_project(&url);
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    // Each secret as Maven would print it decrypted, spelled apart here so
    // the launcher's own text holds none.
    let echoed = "echo \"$MAVEN_OPTS|$_JAVA_OPTIONS|$JAVA_TOOL_OPTIONS\"\n\
                  echo \"$JDK_JAVA_OPTIONS|$*\"\n\
                  cat \"$HOME/.m2/settings.xml\" \"$HOME/.m2/settings-security.xml\"\n\
                  printf 'zq%szq\\n' DEC DUP EPHRASE PROXY MASTER FILE RCVAR\n\
                  printf 'zqLATIN\\351zq\\nzqPCT%%5e%%C3%%A9zq\\nzqLEFT\\nRIGHTzq\\n'\n\
                  echo '[ERROR] Failed to execute goal t:demo-maven-plugin:1:run (x) on project app'\n\
                  exit 1\n";
    fs::write(&launcher, format!("{script}{echoed}")).unwrap();
    let m2 = home.path().join(".m2");
    let settings = m2.join("settings.xml");
    let security = m2.join("settings-security.xml");
    let servers = "<servers><server><id>deploy</id><username>u</username>\
        <password>{/ZlgAyUnP3cH7RcoRlOXLmRcnGYuwsW+j6zua30xyG4=}</password></server>\
        <server><id>deploy</id><password>{y5W/hNLGG08HWiQdBpb1Dp+SYs9uNuXa/YN6KzXoa6I=}</password>\
        </server><server><id>scp</id><passphrase>zqPHRASEzq</passphrase>\
        <privateKey>/keys/zqPKEYzq</privateKey></server><server><id>sftp</id>\
        <passphrase>{ST/+5Luo8zYHhplRLE0d/6xOlcXASn82Rl0l7xJLFC8=}</passphrase></server>\
        <server><id>latin</id><password>zqLATINézq</password></server>\
        <server><id>pct</id><password>zqPCT^ézq</password></server>\
        <server><id>lines</id><passphrase>zqLEFT&#10;RIGHTzq</passphrase></server></servers>\
        <proxies><proxy><id>off</id><active>false</active><host>proxy.invalid</host>\
        <password>{KDLZhV7I+G0HDkTgQOndYMqp/PZ9cXslWPjbbG/NF7Y=}</password></proxy></proxies>";
    let mirrored = fs::read_to_string(&settings).unwrap();
    fs::write(
        &settings,
        mirrored.replace("</settings>", &format!("{servers}</settings>")),
    )
    .unwrap();
    fs::write(
        &security,
        "<settingsSecurity><master>{nQGguKF/p1EHisYgvMy6SRm+for0r9JyCNN3hjtxqqE=}</master>\
         </settingsSecurity>",
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify', '-D', 'api.token=zqTRACEzq']\n\
         mvn = './mvnw'\n",
    )
    .unwrap();
    // An argument file, and a mavenrc file's variable.
    let options = home.path().join("options");
    fs::write(&options, "-Dfile.token=zqFILEzq\n").unwrap();
    fs::write(
        home.path().join(".mavenrc"),
        "V=zqRCVARzq\nMAVEN_OPTS=\"$MAVEN_OPTS -Drc.token=$V\"\n",
    )
    .unwrap();
    let mut command = raeva_command(root, home.path());
    let opts = format!("-Dapi.key=zqOPTSzq @{}", options.display());
    crate::common::isolate_maven_user_home(&mut command, home.path(), &opts);
    let user_home = format!("-Duser.home={}", home.path().display());
    let failed = command
        .env("_JAVA_OPTIONS", "-Ddeploy.token='zqJAVAOPTzq'")
        .env("JAVA_TOOL_OPTIONS", "-Xss1m -Dmy.secret=zqTOOLzq")
        .env(
            "JDK_JAVA_OPTIONS",
            "-D\"sign.key\"=zqQUOTEDzq \"-Dapi.secret=abc zqSPACEzq\"",
        )
        .args(["-vv", &user_home, "sync"])
        .output()
        .expect("run raeva");
    assert!(!failed.status.success(), "{}", stderr(&failed));
    let said = stderr(&failed);
    assert!(said.contains("the traced build failed"), "{said}");
    for part in ["zqLATIN", "zqPCT", "zqLEFT", "RIGHTzq"] {
        assert!(!said.contains(part), "{part}: {said}");
    }
    let mut leaks: Vec<String> = crate::common::markers_in(&said)
        .chain(crate::common::markers_in(&String::from_utf8_lossy(
            &failed.stdout,
        )))
        .collect();
    let rc = home.path().join(".mavenrc");
    leaks.extend(crate::common::markers_under(
        root,
        &[&root.join("raeva.toml")],
    ));
    leaks.extend(crate::common::markers_under(
        home.path(),
        &[&settings, &security, &rc, &options],
    ));
    assert!(leaks.is_empty(), "{leaks:#?}\n{said}");
}

/// What raeva shows of a traced build that runs `echo` before it fails,
/// stdout and stderr, which keeps nothing. `trace` is raeva.toml's
/// `[plugins] trace`.
#[cfg(unix)]
fn failed_trace(
    project: &TempDir,
    home: &TempDir,
    trace: &str,
    echo: &str,
    env: &[(&str, &str)],
) -> String {
    let root = project.path();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    fs::write(&launcher, format!("{script}{echo}\nexit 1\n")).unwrap();
    fs::write(
        root.join("raeva.toml"),
        format!("[plugins]\nlock = true\ntrace = {trace}\nmvn = './mvnw'\n"),
    )
    .unwrap();
    let mut command = raeva_command(root, home.path());
    for (name, value) in env {
        command.env(name, value);
    }
    // So that no JVM option decides the Maven user home.
    let user_home = format!("-Duser.home={}", home.path().display());
    let failed = command
        .args([&user_home, "sync"])
        .output()
        .expect("run raeva");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&failed.stdout),
        stderr(&failed)
    );
    assert!(said.contains("the traced build failed"), "{said}");
    assert_eq!(trace_leftovers(home.path()), Vec::<String>::new());
    said
}

/// The `plugin-trace-*` directories and `trace.log` files under `dir`.
#[cfg(unix)]
fn trace_leftovers(dir: &std::path::Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy();
            if name.starts_with("plugin-trace-") || name == "trace.log" {
                found.push(path.display().to_string());
            } else if path.is_dir() && !path.is_symlink() {
                dirs.push(path);
            }
        }
    }
    found
}

/// Whether `bytes` hold `marker` as ASCII, UTF-16LE or UTF-16BE.
#[cfg(unix)]
fn holds_marker(bytes: &[u8], marker: &str) -> bool {
    let wide = |high: bool| -> Vec<u8> {
        (marker.bytes())
            .flat_map(|b| match high {
                true => [0, b],
                false => [b, 0],
            })
            .collect()
    };
    [marker.as_bytes().to_vec(), wide(false), wide(true)]
        .iter()
        .any(|form| {
            bytes
                .windows(form.len())
                .any(|part| part == form.as_slice())
        })
}

/// The files under `dir` that hold `marker` ([`holds_marker`]).
#[cfg(unix)]
fn files_holding(dir: &std::path::Path, marker: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_symlink() {
                continue;
            } else if path.is_dir() {
                dirs.push(path);
            } else if holds_marker(&fs::read(&path).unwrap_or_default(), marker) {
                found.push(path.display().to_string());
            }
        }
    }
    found
}

/// No byte of the traced build's stdout or stderr reaches anything raeva
/// prints, `--json` and `-vvv` included, or any file under the project,
/// raeva's home, `HOME` or the temporary directory, whether the build
/// passes, fails, runs again without the option its JVM refuses, or is
/// stopped by Ctrl-C. The build prints a marker made anew each run as
/// ASCII, among bytes that are not UTF-8, as UTF-16 both ways, in each
/// line raeva matches, in a line longer than raeva reads, and without a
/// final newline; no file holds the marker whole before it runs.
#[cfg(unix)]
#[test]
fn no_byte_of_the_traced_builds_output_reaches_raeva() {
    use std::hash::{BuildHasher, Hasher};

    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH))
            .unwrap()
            .as_nanos(),
    );
    let mut seed = hasher.finish();
    let letters: String = (0..12)
        .map(|_| {
            let letter = char::from(b'A' + (seed % 26) as u8);
            seed /= 26;
            letter
        })
        .collect();
    let marker = format!("zq{letters}zq");
    let (front, back) = marker.split_at(7);
    let server = repository();
    let (project, home) = plugin_project(&format!("http://{}/", server.addr()));
    let root = project.path();
    let tmp = TempDir::new().unwrap();
    let launcher = fake_mvnw(root);
    let script = fs::read_to_string(&launcher).unwrap();
    let here = "\"$(dirname \"$0\")\"";
    let printing = format!(
        "{script}m='{front}'; m=\"${{m}}{back}\"\n\
         le=$(printf '%s' \"$m\" | sed 's/./&\\\\000/g')\n\
         be=$(printf '%s' \"$m\" | sed 's/./\\\\000&/g')\n\
         case \"$JDK_JAVA_OPTIONS\" in *UseBASE64Intrinsics*) \
         echo \"Unrecognized VM option 'UseBASE64Intrinsics' $m\" >&2; \
         echo \"Error: Could not create the Java Virtual Machine. $m\" >&2; exit 1;; esac\n\
         if [ -f {here}/hang ]; then echo \"$m\"; echo \"$m\" >&2; : > {here}/started; \
         exec sleep 30; fi\n\
         echo \"[INFO] $m\"; echo \"$m\" >&2\n\
         printf '\\377\\376%s\\200\\n' \"$m\"; printf '\\377%s\\376\\n' \"$m\" >&2\n\
         printf \"\\377\\376$le\\n\"; printf \"\\376\\377$be\\n\" >&2\n\
         echo \"[ERROR] Failed to execute goal t:demo-maven-plugin:1:$m ($m) on project $m: $m\"\n\
         echo \"[ERROR] Failed to execute goal t:$m:1:run (x) on project app: e\"\n\
         echo \"[ERROR] Plugin t:$m:1 or one of its dependencies could not be resolved: $m\"\n\
         echo \"[ERROR] Could not transfer artifact $m from/to $m: status code: 401, $m\" >&2\n\
         echo \"Error: Could not create the Java Virtual Machine. $m\"\n\
         printf '%9000s%s\\n' '' \"$m\"; printf '%9000s%s\\n' '' \"$m\" >&2\n\
         printf '%s' \"$m\" >&2\n\
         [ -f {here}/fail ] && exit 1\n\
         printf '%s' \"$m\"\n"
    );
    fs::write(&launcher, printing).unwrap();
    assert!(!holds_marker(&fs::read(&launcher).unwrap(), &marker));
    fs::write(
        root.join("raeva.toml"),
        "[plugins]\nlock = true\ntrace = ['verify']\nmvn = './mvnw'\n",
    )
    .unwrap();
    let jdk = home.path().join("jdk-21");
    fs::create_dir_all(&jdk).unwrap();
    fs::write(jdk.join("release"), "JAVA_VERSION=\"21.0.9\"\n").unwrap();
    let command = |args: &[&str], jdk: Option<&std::path::Path>| {
        let _ = fs::remove_file(root.join("raeva.lock"));
        let mut command = raeva_command(root, home.path());
        command
            .env("TMPDIR", tmp.path())
            .env_remove("JDK_JAVA_OPTIONS");
        if let Some(jdk) = jdk {
            command.env("JAVA_HOME", jdk);
        }
        command.args(args);
        command
    };
    let mut runs = Vec::new();
    let run = |args: &[&str], jdk, fail: bool| {
        match fail {
            true => fs::write(root.join("fail"), "").unwrap(),
            false => {
                let _ = fs::remove_file(root.join("fail"));
            }
        }
        (command(args, jdk).output()).expect("run raeva")
    };
    runs.push(("passing", run(&["sync"], None, false), Some(0)));
    runs.push(("failing", run(&["-vvv", "sync"], None, true), Some(1)));
    runs.push(("json", run(&["--json", "sync"], None, true), Some(1)));
    runs.push((
        "retried",
        run(&["-vvv", "sync"], Some(&jdk), false),
        Some(0),
    ));
    runs.push((
        "retried and failing",
        run(&["sync"], Some(&jdk), true),
        Some(1),
    ));
    fs::write(root.join("hang"), "").unwrap();
    let child = (command(&["-vvv", "sync"], None))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run raeva");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !root.join("started").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the build never started"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let killed = std::process::Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    runs.push(("interrupted", child.wait_with_output().unwrap(), Some(130)));
    for (case, output, code) in &runs {
        assert_eq!(output.status.code(), *code, "{case}: {}", stderr(output));
        for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            assert!(
                !holds_marker(bytes, &marker),
                "{case}: {stream}: {}",
                stderr(output)
            );
        }
    }
    let said = stderr(&runs[3].1);
    assert!(
        said.contains("does not know -XX:-UseBASE64Intrinsics"),
        "{said}"
    );
    let said = stderr(&runs[1].1);
    assert!(
        said.contains(
            "the traced build failed in t:demo-maven-plugin:1 (exit status: 1): a JVM could not \
             start; a plugin could not be resolved; a repository refused access (401 or 403), so"
        ),
        "{said}"
    );
    let mut files = Vec::new();
    for dir in [root, home.path(), tmp.path()] {
        files.extend(files_holding(dir, &marker));
    }
    assert_eq!(files, Vec::<String>::new());
    assert_eq!(trace_leftovers(home.path()), Vec::<String>::new());
    assert_eq!(trace_leftovers(tmp.path()), Vec::<String>::new());
}

/// A processor path names reactor module `proc`, whose POM gives its
/// dependencies: `x:1` and `y`, at the `2` the project's management gives.
/// `x:1` depends on `y:1` and `z:1`, and the project manages `z` to `2`.
/// maven-compiler-plugin 3.11 and later collect the paths under no
/// management, so the `-processorpath` takes `z:1` and Maven reads the POM
/// of the losing `y:1`; 3.9.0 to 3.10.1 root a legacy request
/// at the path, under its management. The set pins those files in both Maven
/// modes, as Maven 3.10.0 reads them. Error Prone Support's
/// `documentation-support` path reads `guava-33.5.0-jre.pom` this way.
#[test]
fn a_processor_path_the_reactor_builds_takes_its_dependencies() {
    let server = repository_of(
        |artifact| match artifact {
            "x" => format!(
                "<dependencies>{}</dependencies>",
                dependencies(&["t:y:1", "t:z:1"])
            ),
            _ => String::new(),
        },
        &[],
    );
    let cases = [
        ("3.16.0", "t:x:1\tjar\nt:y:2\tjar\nt:z:1\tjar", true),
        ("3.10.1", "t:x:1\tjar\nt:y:2\tjar\nt:z:2\tjar", false),
    ];
    for maven in ["3.9", "3.10"] {
        for (compiler, artifacts, loser) in cases {
            let case = format!("Maven {maven}, compiler {compiler}");
            let url = format!("http://{}/", server.addr());
            let (project, home) = binding_project(&url, "unused");
            let root = project.path();
            fs::write(
                root.join("raeva.toml"),
                format!("[lock]\nmaven = \"{maven}\"\n\n[plugins]\nlock = true\n"),
            )
            .unwrap();
            let parent = "<parent><groupId>t</groupId><artifactId>app</artifactId>\
                          <version>1</version></parent>";
            fs::write(
                root.join("pom.xml"),
                pom(
                    "app",
                    &format!(
                        "<packaging>pom</packaging><modules><module>proc</module>\
                         <module>user</module></modules><dependencyManagement><dependencies>\
                         {}</dependencies></dependencyManagement>",
                        dependencies(&["t:y:2", "t:z:2"])
                    ),
                ),
            )
            .unwrap();
            for (module, body) in [
                (
                    "proc",
                    format!(
                        "{parent}<dependencies>{}<dependency><groupId>t</groupId>\
                         <artifactId>y</artifactId></dependency></dependencies>",
                        dependencies(&["t:x:1"])
                    ),
                ),
                (
                    "user",
                    format!(
                        "{parent}<build><plugins><plugin><artifactId>maven-compiler-plugin\
                         </artifactId><version>{compiler}</version><configuration>\
                         <annotationProcessorPaths><path><groupId>t</groupId>\
                         <artifactId>proc</artifactId><version>1</version></path>\
                         </annotationProcessorPaths></configuration></plugin></plugins>\
                         </build>"
                    ),
                ),
            ] {
                fs::create_dir_all(root.join(module)).unwrap();
                fs::write(root.join(module).join("pom.xml"), pom(module, &body)).unwrap();
            }
            let processor_path = || {
                let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
                let document: toml::Value = toml::from_str(&lock).unwrap();
                let sets = document["platforms"][0]["plugins"]["sets"]
                    .as_array()
                    .unwrap();
                let paths: Vec<_> = (sets.iter())
                    .filter(|set| set["role"].as_str() == Some("processor-path"))
                    .cloned()
                    .collect();
                assert_eq!(paths.len(), 1, "{case}\n{lock}");
                let field =
                    |key: &str| (paths[0].get(key)).map_or("", |rows| rows.as_str().unwrap());
                (
                    field("artifacts").to_string(),
                    field("support_poms").to_string(),
                )
            };
            assert_success(&run_raeva(root, home.path(), &["sync"]), &case);
            let (rows, poms) = processor_path();
            assert_eq!(rows, artifacts, "{case}");
            assert_eq!(poms.lines().any(|line| line == "t:y:1"), loser, "{case}");
            assert_success(&run_raeva(root, home.path(), &["sync", "--frozen"]), &case);
            // The set follows the reactor POM: without `x`, only `y:2` is left.
            fs::write(
                root.join("proc/pom.xml"),
                pom(
                    "proc",
                    &format!(
                        "{parent}<dependencies><dependency><groupId>t</groupId>\
                         <artifactId>y</artifactId></dependency></dependencies>"
                    ),
                ),
            )
            .unwrap();
            let frozen = run_raeva(root, home.path(), &["sync", "--frozen"]);
            assert!(!frozen.status.success(), "{case}: {}", stderr(&frozen));
            assert_success(&run_raeva(root, home.path(), &["sync"]), &case);
            assert_eq!(
                processor_path(),
                ("t:y:2\tjar".to_string(), String::new()),
                "{case}"
            );
        }
    }
}
